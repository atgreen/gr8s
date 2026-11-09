;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Own the node-local lifecycle of the ClusterIP socket load balancer: JIT the
;;;; Whistler connect4, sendmsg4 and recvmsg4 programs in-process, create and pin
;;;; their maps on bpffs, load the programs, and attach them to the node cgroup so
;;;; every Pod's connect(2) and unconnected UDP sendmsg(2) is steered in-kernel.  No ELF is produced; the full compiler is
;;;; already in the image (see src/service-lb-program.lisp).  Populating the
;;;; maps from Service/EndpointSlice state, and retiring the userspace proxy,
;;;; belong to the controller layer that drives this manager.
;;;;
;;;; Compilation and map encoding are pure userspace; creating maps, pinning,
;;;; loading, and attaching require CAP_BPF and a cgroup2 mount.  Every kernel
;;;; operation is injected as a keyword argument so the orchestration is tested
;;;; without privileges, mirroring the CNI policy installer in src/cni.lisp.

(in-package #:gr8s.network)

(defstruct (service-lb-dataplane (:constructor %make-service-lb-dataplane))
  "A loaded and attached ClusterIP socket load balancer on one node."
  cgroup-path
  pin-directory
  (reopened-p nil) ; retained pins require inventory before controller reconciliation
  maps        ; alist of (name . map-info), e.g. "gr8s_service_v4"
  program     ; prog-info for gr8s_service_lb, the connect4 hook
  programs    ; alist of (name . prog-info) for every hook, connect4 first
  (gc-cursors (make-hash-table :test #'equal)) ; next unprocessed key per flow map
  (gc-compatible-p nil)
  (gc-warning nil)
  (gc-scanned 0)
  (gc-reclaimed 0)
  (gc-deferred 0)
  (gc-failures 0)
  attachment  ; the cgroup attachment handles returned by attach-cgroup, one per hook
  (lock (bt:make-lock "gr8s service LB dataplane")))

(defparameter +bpf-cgroup-udp4-recvmsg+ 19
  "BPF_CGROUP_UDP4_RECVMSG, which Whistler's loader does not name.")

(defparameter +bpf-cgroup-udp6-recvmsg+ 20
  "BPF_CGROUP_UDP6_RECVMSG, which Whistler's loader does not name.")

(defun service-lb-attach-type (section)
  "The cgroup attach type of the socket address hook at SECTION."
  (cond ((equal section "cgroup/connect4") whistler/loader:+bpf-cgroup-inet4-connect+)
        ((equal section "cgroup/sendmsg4") whistler/loader:+bpf-cgroup-udp4-sendmsg+)
        ((equal section "cgroup/recvmsg4") +bpf-cgroup-udp4-recvmsg+)
        ((equal section "cgroup/connect6") whistler/loader:+bpf-cgroup-inet6-connect+)
        ((equal section "cgroup/sendmsg6") whistler/loader:+bpf-cgroup-udp6-sendmsg+)
        ((equal section "cgroup/recvmsg6") +bpf-cgroup-udp6-recvmsg+)
        (t (error "No socket address hook for section ~S" section))))

(defun load-service-lb-programs
    (specs maps &key (load-program #'whistler/loader::load-program) (close-fd #'sb-posix:close))
  "Load the compiled program SPECS against MAPS, as Whistler's session loader does, but
with each hook's attach type chosen here: that loader cannot place a recvmsg4 program.
Returns an alist of (name . prog-info)."
  (let ((descriptors (mapcar (lambda (entry) (cons (car entry) (whistler/loader:map-info-fd (cdr entry)))) maps))
        (loaded nil) (succeeded nil))
    (unwind-protect
         (prog1
             (mapcar
     (lambda (spec)
       (let* ((instructions (copy-seq (getf spec :insns))) (section (getf spec :section)) (name (getf spec :name))
             (maintenance (equal name "gr8s_packet_gc")))
         ;; Each relocation is (instruction-offset map-index): a BPF_LD_IMM64 whose source
         ;; register becomes BPF_PSEUDO_MAP_FD and whose immediate the map's descriptor.
         (loop for (offset index) in (getf spec :relocs)
               for descriptor = (cdr (assoc (car (nth index maps)) descriptors :test #'string=))
               do (setf (aref instructions (+ offset 1)) (logior (logand (aref instructions (+ offset 1)) #x0f) (ash 1 4)))
                  (loop for byte from 0 below 4
                        do (setf (aref instructions (+ offset 4 byte)) (ldb (byte 8 (* 8 byte)) descriptor))))
         (cons name (whistler/loader::make-prog-info
                     :name name :section-name section
                     :type (if maintenance whistler/loader::+bpf-prog-type-sched-cls+
                               whistler/loader:+bpf-prog-type-cgroup-sock-addr+) :insns instructions
                     :fd (let ((fd (funcall load-program instructions
                                     (if maintenance whistler/loader::+bpf-prog-type-sched-cls+
                                         whistler/loader:+bpf-prog-type-cgroup-sock-addr+)
                                     (getf spec :license)
                                     :expected-attach-type (if maintenance 0 (service-lb-attach-type section)))))
                           (push fd loaded)
                           fd)))))
               specs)
           (setf succeeded t))
      (unless succeeded
        (dolist (fd loaded) (ignore-errors (funcall close-fd fd)))))))

(defun service-lb-pin-directory (state-directory)
  "The bpffs directory under STATE-DIRECTORY that holds the pinned LB maps."
  (namestring
   (merge-pathnames "containerd/bpf/service-lb/" (uiop:ensure-directory-pathname state-directory))))

(defun service-lb-map (dataplane name)
  "Return the map-info named NAME (an underscored map name) in DATAPLANE, or NIL."
  (cdr (assoc name (service-lb-dataplane-maps dataplane) :test #'string=)))

(defun service-lb-service-table (dataplane &optional (family :ipv4))
  "The family-specific Service map: VIP:port -> (backend count, base slot)."
  (service-lb-map dataplane (ecase family
                              (:ipv4 "gr8s_service_v4")
                              (:ipv6 "gr8s_service_v6"))))

(defun service-lb-backend-table (dataplane &optional (family :ipv4))
  "The family-specific backend map: slot -> (backend address, port)."
  (service-lb-map dataplane (ecase family
                              (:ipv4 "gr8s_backend_v4")
                              (:ipv6 "gr8s_backend_v6"))))

(defun service-lb-pin-map (map-info path &key (pin #'whistler/loader:pin-bpf-object))
  "Pin MAP-INFO's fd at PATH on bpffs."
  (funcall pin (whistler/loader:map-info-fd map-info) (namestring path)))

(defun service-lb-pinned-map-info (fd spec &key (object-info #'bpf-object-kernel-info))
  "Return map metadata for pinned FD after validating it against compiled SPEC.
Reject stale pins whose kernel schema no longer matches the program that will
use them; BPF map operations trust the kernel's sizes, not the caller's buffers."
  (let* ((info (funcall object-info fd))
         (name (getf spec :name))
         (type (whistler/compiler:resolve-map-type (getf spec :type)))
         (key-size (getf spec :key-size))
         (value-size (getf spec :value-size))
         (max-entries (getf spec :max-entries))
         (flags (getf spec :flags)))
    (unless (and (>= (length info) 24)
                 (= type (netlink-read-integer info 0 4))
                 (= key-size (netlink-read-integer info 8 4))
                 (= value-size (netlink-read-integer info 12 4))
                 (= max-entries (netlink-read-integer info 16 4))
                 (= flags (netlink-read-integer info 20 4)))
      (error "Pinned Service LB map ~A has an incompatible schema" name))
    (whistler/loader::make-map-info
     :name name :type type :key-size key-size :value-size value-size
     :max-entries max-entries :flags flags :fd fd)))

(defun start-service-lb-dataplane
    (cgroup-path pin-directory
     &key (compile #'compile-service-lb)
          packet-services
          (create-maps (lambda (specs) (whistler/loader::session-create-maps specs)))
          (load-programs #'load-service-lb-programs)
          (ensure-directory #'ensure-directories-exist)
          (path-exists-p #'probe-file)
          (open-pinned #'whistler/loader:open-pinned-object)
          (validate-map #'service-lb-pinned-map-info)
          (pin-map #'service-lb-pin-map)
          (remove-path #'uiop:delete-file-if-exists)
          (attach (lambda (program-fd cgroup attach-type)
                    (whistler/loader:attach-cgroup program-fd cgroup attach-type))))
  "Compile, create, pin, load, and attach the socket LB on this node.
CGROUP-PATH is the cgroup2 directory whose subtree the program governs (the
node's Pod cgroup root).  PIN-DIRECTORY is a bpffs directory for the map pins.
Returns a SERVICE-LB-DATAPLANE.  Signals through any kernel error; the caller
decides whether a dataplane failure is fatal to the node."
  (multiple-value-bind (map-specs program-specs)
      (if packet-services (funcall compile :packet-services t) (funcall compile))
    (let ((maps nil) (opened nil) (pinned nil))
      (handler-case
          (progn
            (funcall ensure-directory (merge-pathnames ".keep" (uiop:ensure-directory-pathname pin-directory)))
            ;; A crash leaves the maps pinned and their Service state intact.
            ;; Reopen and validate them before relocating replacement programs;
            ;; create and pin only maps that do not exist yet (for example, a
            ;; newly added map after an upgrade).
            (let ((missing nil))
              (dolist (spec map-specs)
                (let* ((name (getf spec :name))
                       (path (merge-pathnames name (uiop:ensure-directory-pathname pin-directory))))
                  (if (funcall path-exists-p path)
                      (let ((fd (funcall open-pinned path)))
                        (push fd opened)
                        (push (cons name (funcall validate-map fd spec)) maps))
                      (push spec missing))))
              (when missing
                (dolist (entry (funcall create-maps (nreverse missing)))
                  (let ((path (merge-pathnames (car entry) (uiop:ensure-directory-pathname pin-directory))))
                    (funcall pin-map (cdr entry) path)
                    (push (namestring path) pinned)
                    (push entry maps))))
              (setf maps
                    (mapcar (lambda (spec)
                              (assoc (getf spec :name) maps :test #'string=))
                            map-specs)))
            (let* ((programs (funcall load-programs program-specs maps))
                   (attachments nil))
              (handler-bind ((error (lambda (condition)
                                      (declare (ignore condition))
                                      ;; Detach what did attach, and close every program.
                                      (dolist (attachment attachments)
                                        (ignore-errors (whistler/loader:detach attachment)))
                                      (dolist (entry programs)
                                        (let ((fd (whistler/loader:prog-info-fd (cdr entry))))
                                          (when (and (integerp fd) (plusp fd)) (ignore-errors (sb-posix:close fd))))))))
                (dolist (entry programs)
                  (unless (equal (car entry) "gr8s_packet_gc")
                    (push (funcall attach (whistler/loader:prog-info-fd (cdr entry)) cgroup-path
                                 (service-lb-attach-type (whistler/loader::prog-info-section-name (cdr entry))))
                        attachments))))
              (%make-service-lb-dataplane
               :cgroup-path cgroup-path
               :pin-directory (namestring (uiop:ensure-directory-pathname pin-directory))
               :maps maps :reopened-p (not (null opened)) :program (cdr (first programs)) :programs programs
               :attachment (nreverse attachments))))
        (error (condition)
          ;; Roll back pins and map fds so a half-start leaves nothing behind.
          (dolist (path pinned) (ignore-errors (funcall remove-path path)))
          (dolist (fd (remove-duplicates
                       (append opened
                               (mapcar (lambda (entry)
                                         (whistler/loader:map-info-fd (cdr entry)))
                                       maps))))
            (ignore-errors (sb-posix:close fd)))
          (error condition))))))

(defun try-start-service-lb-dataplane (cgroup-path pin-directory &key (log *error-output*) packet-services)
  "Attempt to bring up the socket LB.  On any failure (no CAP_BPF, no bpffs, an
unattachable cgroup, a kernel too old for cgroup/connect4), log and return NIL so
the caller can fall back to the userspace Service proxy."
  (handler-case (start-service-lb-dataplane cgroup-path pin-directory :packet-services packet-services)
    (error (condition)
      (format log "~&gr8s: eBPF Service load balancer unavailable, using the userspace proxy: ~A~%"
              condition)
      nil)))

(defun service-lb-write-service
    (dataplane address port base-slot backends
     &key (update #'whistler/loader:map-update))
  "Write one ClusterIP ADDRESS:PORT and its BACKENDS into the LB maps.
BACKENDS is a list of (ip . target-port); they occupy consecutive slots from
BASE-SLOT.  The service entry is written last so the program never reads a VIP
whose backend slots are not yet present."
  (multiple-value-bind (vip-key service-value backend-entries index-entries)
      (service-lb-entries address port base-slot backends)
    (let ((family (if (find #\: address) :ipv6 :ipv4)))
      (dolist (entry backend-entries)
        (funcall update (service-lb-backend-table dataplane family) (car entry) (cdr entry)))
      (let ((index (service-lb-map dataplane
                                   (if (eq family :ipv4) "gr8s_backend_index_v4"
                                       "gr8s_backend_index_v6"))))
        (when index
          (dolist (entry index-entries)
            (funcall update index (car entry) (cdr entry)))))
      (funcall update (service-lb-service-table dataplane family) vip-key service-value))))

(defun stop-service-lb-dataplane
    (dataplane &key (remove-pins t)
                    (detach #'whistler/loader:detach)
                    (remove-path #'uiop:delete-file-if-exists))
  "Detach the program and release its fds.  When REMOVE-PINS is true (the
default), also remove the pinned maps; pass NIL to keep them across a restart."
  (bt:with-lock-held ((service-lb-dataplane-lock dataplane))
    (let ((attachments (service-lb-dataplane-attachment dataplane)))
      (dolist (attachment (if (listp attachments) attachments (list attachments)))
        (ignore-errors (funcall detach attachment))))
    (setf (service-lb-dataplane-attachment dataplane) nil)
    (dolist (program (remove-duplicates
                      (remove nil (cons (service-lb-dataplane-program dataplane)
                                        (mapcar #'cdr (service-lb-dataplane-programs dataplane))))))
      (let ((fd (whistler/loader:prog-info-fd program)))
        (when (and fd (plusp fd)) (ignore-errors (sb-posix:close fd)))))
    (setf (service-lb-dataplane-program dataplane) nil
          (service-lb-dataplane-programs dataplane) nil)
    (dolist (entry (service-lb-dataplane-maps dataplane))
      (let ((fd (whistler/loader:map-info-fd (cdr entry))))
        (when (and fd (plusp fd)) (ignore-errors (sb-posix:close fd))))
      (when remove-pins
        (funcall remove-path
                 (namestring (merge-pathnames (car entry)
                                              (uiop:ensure-directory-pathname
                                               (service-lb-dataplane-pin-directory dataplane)))))))
    (setf (service-lb-dataplane-maps dataplane) nil))
  nil)
