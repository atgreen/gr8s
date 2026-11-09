;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; gr8s-facing entry point for the per-endpoint egress guard: JIT-compile the
;;;; Whistler program held in src/egress-guard-program.lisp, in-process, with no
;;;; ELF.  The CNI policy installer will build on this (podster-7q2.5b); for now
;;;; it is the compile step the migration and its tests share with the socket LB
;;;; via the generic compile-whistler-program helper in src/service-lb.lisp.

(in-package #:gr8s.network)

(defun compile-egress-guard (&key service-packets)
  "JIT-compile the per-endpoint egress guard. Returns (values map-specs
prog-specs), the same shape as compile-service-lb."
  (compile-whistler-program
   (append *egress-guard-map-forms*
           (when service-packets
             (append (service-packet-map-forms) (list *service-packet-stage-map-form*))))
   (if service-packets (service-packet-guard-forms) *egress-guard-program-forms*)))

;;; ---------------------------------------------------------------------------
;;; In-process policy object for the CNI installer.
;;;
;;; install-cni-policy (src/cni.lisp) was written against an ELF object with
;;; open/load/map/program/close operations.  This provides the same shape backed
;;; by in-process JIT: compile the program, create the maps (reusing any
;;; already-pinned fds so counters survive repeated ADD), load the program with
;;; map-fd relocations, and expose its maps and program.  No ELF is read.

(defstruct (egress-policy-object (:constructor %make-egress-policy-object (map-specs program-specs)))
  map-specs
  program-specs
  (maps nil)        ; alist (map name . map-info), populated by load
  (programs nil))   ; alist (program name . prog-info), populated by load

(defvar *egress-guard-specs* nil
  "The compiled (map-specs . program-specs). The guard's source is fixed in the image
and per-Pod state lives in its maps, so every Pod loads the same program.")

(defvar *service-egress-guard-specs* nil
  "The separately cached guard variant that binds to shared Service maps.")

(defvar *egress-guard-specs-lock* (bt:make-lock "gr8s egress guard compile"))

(defun egress-guard-specs (&key service-packets)
  "Return shared relocatable specs. Native builds prepare both variants before
dumping the image; source-based runs compile lazily on first use."
  (bt:with-lock-held (*egress-guard-specs-lock*)
    (if service-packets
        (or *service-egress-guard-specs*
            (setf *service-egress-guard-specs*
                  (multiple-value-call #'cons (compile-egress-guard :service-packets t))))
        (or *egress-guard-specs*
            (setf *egress-guard-specs*
                  (multiple-value-call #'cons (compile-egress-guard)))))))

(defun compile-egress-policy-object (&rest ignored)
  "Make a policy object for the compiled egress guard. The specs are shared: loading
patches map fds into a copy of the instructions (session-load-progs). IGNORED absorbs
the ELF path the CNI installer still passes; there is no ELF to open."
  (declare (ignore ignored))
  (destructuring-bind (map-specs . program-specs)
      (egress-guard-specs :service-packets *cni-service-packets*)
    (%make-egress-policy-object map-specs program-specs)))

(defun load-egress-policy-object
    (object replacements
     &key (create-map #'whistler/loader::create-map)
          (update #'whistler/loader:map-update)
          (load-programs #'whistler/loader::session-load-progs)
          (publish-stages t))
  "Create the egress maps and load the program.  REPLACEMENTS is an alist of
(map-name . fd) for maps already pinned on bpffs; those fds are reused so their
counters persist, and only the remaining maps are created fresh.  CREATE-MAP and
LOAD-PROGRAMS are injected so the orchestration is testable without CAP_BPF.
With PUBLISH-STAGES NIL, loading does not change the live continuation table;
the upgrade path publishes only after both directions are quiescent."
  (when (find "gr8s_pkt_forward" (egress-policy-object-map-specs object)
              :key (lambda (spec) (getf spec :name)) :test #'equal)
    (dolist (spec (service-packet-map-specs))
      (unless (assoc (first spec) replacements :test #'equal)
        (invalid-cni "shared Service map ~A is unavailable" (first spec)))))
  (let ((maps (loop for spec in (egress-policy-object-map-specs object)
                    for name = (getf spec :name)
                    for fd = (cdr (assoc name replacements :test #'string=))
                    for info = (whistler/loader::make-map-info
                                :name name
                                :type (whistler/compiler:resolve-map-type (getf spec :type))
                                :key-size (getf spec :key-size)
                                :value-size (getf spec :value-size)
                                :max-entries (getf spec :max-entries)
                                :flags (getf spec :flags))
                    do (if fd
                           (setf (whistler/loader:map-info-fd info) fd)
                           (funcall create-map info))
                    collect (cons name info))))
    (setf (egress-policy-object-maps object) maps
          (egress-policy-object-programs object)
          (funcall load-programs (egress-policy-object-program-specs object) maps))
    (when publish-stages
      (publish-egress-policy-stages object :update update))
    object))

(defun publish-egress-policy-stages (object &key (update #'whistler/loader:map-update))
  "Publish a fully loaded object's policy/NAT continuations. Caller quiesces
retained legacy writers before updating a table already used by live programs."
  (let ((stages (cdr (assoc "gr8s_pkt_stages" (egress-policy-object-maps object) :test #'equal))))
    (when stages
      ;; Validate the whole object before the first write.
      (let ((programs
              (loop for name in '("gr8s_packet_forward" "gr8s_egress_policy" "gr8s_packet_reverse")
                    for program = (cdr (assoc name (egress-policy-object-programs object) :test #'equal))
                    do (unless program (invalid-cni "Service guard stage ~A is missing" name))
                    collect program)))
        (loop for program in programs for index from 0
              do (funcall update stages (service-lb-bytes index 4)
                          (service-lb-bytes (whistler/loader:prog-info-fd program) 4)))))))

(defun egress-policy-object-find-map (object name)
  "Return the map-info named NAME, or NIL."
  (cdr (assoc name (egress-policy-object-maps object) :test #'string=)))

(defun egress-policy-object-find-program (object name)
  "Return the loaded program NAME's prog-info (gr8s_egress_guard or gr8s_ingress_guard), or NIL."
  (cdr (assoc name (egress-policy-object-programs object) :test #'string=)))

(defun close-egress-policy-object (object &key (close-fd #'sb-posix:close))
  "Close every program fd and map fd the object holds."
  (dolist (entry (egress-policy-object-programs object))
    (let ((fd (whistler/loader:prog-info-fd (cdr entry))))
      (when (and fd (plusp fd)) (ignore-errors (funcall close-fd fd)))))
  (dolist (entry (egress-policy-object-maps object))
    (let ((fd (whistler/loader:map-info-fd (cdr entry))))
      (when (and fd (plusp fd)) (ignore-errors (funcall close-fd fd))))))
