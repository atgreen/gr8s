;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; gr8s-facing entry point for the per-endpoint egress guard: JIT-compile the
;;;; Whistler program held in src/egress-guard-program.lisp, in-process, with no
;;;; ELF.  The CNI policy installer will build on this (podster-7q2.5b); for now
;;;; it is the compile step the migration and its tests share with the socket LB
;;;; via the generic compile-whistler-program helper in src/service-lb.lisp.

(in-package #:gr8s)

(defun compile-egress-guard ()
  "JIT-compile the per-endpoint egress guard. Returns (values map-specs
prog-specs), the same shape as compile-service-lb."
  (compile-whistler-program *egress-guard-map-forms* *egress-guard-program-forms*))

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

(defvar *egress-guard-specs-lock* (bt:make-lock "gr8s egress guard compile"))

(defun egress-guard-specs ()
  "Compile the egress guard on first use; it takes about 0.5s on a test VM."
  (bt:with-lock-held (*egress-guard-specs-lock*)
    (or *egress-guard-specs*
        (setf *egress-guard-specs*
              (multiple-value-call #'cons (compile-egress-guard))))))

(defun compile-egress-policy-object (&rest ignored)
  "Make a policy object for the compiled egress guard. The specs are shared: loading
patches map fds into a copy of the instructions (session-load-progs). IGNORED absorbs
the ELF path the CNI installer still passes; there is no ELF to open."
  (declare (ignore ignored))
  (destructuring-bind (map-specs . program-specs) (egress-guard-specs)
    (%make-egress-policy-object map-specs program-specs)))

(defun load-egress-policy-object
    (object replacements
     &key (create-map #'whistler/loader::create-map)
          (load-programs #'whistler/loader::session-load-progs))
  "Create the egress maps and load the program.  REPLACEMENTS is an alist of
(map-name . fd) for maps already pinned on bpffs; those fds are reused so their
counters persist, and only the remaining maps are created fresh.  CREATE-MAP and
LOAD-PROGRAMS are injected so the orchestration is testable without CAP_BPF."
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
    object))

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
