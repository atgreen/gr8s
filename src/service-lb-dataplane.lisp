;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Own the node-local lifecycle of the ClusterIP socket load balancer: JIT the
;;;; Whistler cgroup/connect4 program in-process, create and pin its maps on
;;;; bpffs, load the program, and attach it to the node cgroup so every Pod's
;;;; connect(2) is steered in-kernel.  No ELF is produced; the full compiler is
;;;; already in the image (see src/service-lb-program.lisp).  Populating the
;;;; maps from Service/EndpointSlice state, and retiring the userspace proxy,
;;;; belong to the controller layer that drives this manager.
;;;;
;;;; Compilation and map encoding are pure userspace; creating maps, pinning,
;;;; loading, and attaching require CAP_BPF and a cgroup2 mount.  Every kernel
;;;; operation is injected as a keyword argument so the orchestration is tested
;;;; without privileges, mirroring the CNI policy installer in src/cni.lisp.

(in-package #:gr8s)

(defstruct (service-lb-dataplane (:constructor %make-service-lb-dataplane))
  "A loaded and attached ClusterIP socket load balancer on one node."
  cgroup-path
  pin-directory
  maps        ; alist of (name . map-info), e.g. "gr8s_service_v4"
  program     ; prog-info for gr8s_service_lb
  attachment  ; cgroup attachment handle returned by attach-cgroup
  (lock (bt:make-lock "gr8s service LB dataplane")))

(defun service-lb-pin-directory (state-directory)
  "The bpffs directory under STATE-DIRECTORY that holds the pinned LB maps."
  (namestring
   (merge-pathnames "containerd/bpf/service-lb/" (uiop:ensure-directory-pathname state-directory))))

(defun service-lb-map (dataplane name)
  "Return the map-info named NAME (an underscored map name) in DATAPLANE, or NIL."
  (cdr (assoc name (service-lb-dataplane-maps dataplane) :test #'string=)))

(defun service-lb-service-table (dataplane)
  "The gr8s_service_v4 map-info: VIP:port -> (backend count, base slot)."
  (service-lb-map dataplane "gr8s_service_v4"))

(defun service-lb-backend-table (dataplane)
  "The gr8s_backend_v4 map-info: slot -> (backend addr, port)."
  (service-lb-map dataplane "gr8s_backend_v4"))

(defun service-lb-pin-map (map-info path &key (pin #'whistler/loader:pin-bpf-object))
  "Pin MAP-INFO's fd at PATH on bpffs."
  (funcall pin (whistler/loader:map-info-fd map-info) (namestring path)))

(defun start-service-lb-dataplane
    (cgroup-path pin-directory
     &key (compile #'compile-service-lb)
          (create-maps (lambda (specs) (whistler/loader::session-create-maps specs)))
          (load-programs (lambda (specs maps) (whistler/loader::session-load-progs specs maps)))
          (ensure-directory #'ensure-directories-exist)
          (pin-map #'service-lb-pin-map)
          (remove-path #'uiop:delete-file-if-exists)
          (attach (lambda (program-fd cgroup)
                    (whistler/loader:attach-cgroup
                     program-fd cgroup whistler/loader:+bpf-cgroup-inet4-connect+))))
  "Compile, create, pin, load, and attach the socket LB on this node.
CGROUP-PATH is the cgroup2 directory whose subtree the program governs (the
node's Pod cgroup root).  PIN-DIRECTORY is a bpffs directory for the map pins.
Returns a SERVICE-LB-DATAPLANE.  Signals through any kernel error; the caller
decides whether a dataplane failure is fatal to the node."
  (multiple-value-bind (map-specs program-specs) (funcall compile)
    (let ((maps (funcall create-maps map-specs))
          (pinned nil))
      (handler-case
          (progn
            ;; Pin every map before loading so a failed load still leaves the
            ;; maps discoverable (and removable) on bpffs.
            (funcall ensure-directory (merge-pathnames ".keep" (uiop:ensure-directory-pathname pin-directory)))
            (dolist (entry maps)
              (let ((path (merge-pathnames (car entry) (uiop:ensure-directory-pathname pin-directory))))
                (funcall pin-map (cdr entry) path)
                (push (namestring path) pinned)))
            (let* ((programs (funcall load-programs program-specs maps))
                   (program (cdr (first programs)))
                   (attachment (funcall attach (whistler/loader:prog-info-fd program) cgroup-path)))
              (%make-service-lb-dataplane
               :cgroup-path cgroup-path
               :pin-directory (namestring (uiop:ensure-directory-pathname pin-directory))
               :maps maps :program program :attachment attachment)))
        (error (condition)
          ;; Roll back pins and map fds so a half-start leaves nothing behind.
          (dolist (path pinned) (ignore-errors (funcall remove-path path)))
          (dolist (entry maps)
            (ignore-errors (sb-posix:close (whistler/loader:map-info-fd (cdr entry)))))
          (error condition))))))

(defun service-lb-write-service
    (dataplane address port base-slot backends
     &key (update #'whistler/loader:map-update))
  "Write one ClusterIP ADDRESS:PORT and its BACKENDS into the LB maps.
BACKENDS is a list of (ip . target-port); they occupy consecutive slots from
BASE-SLOT.  The service entry is written last so the program never reads a VIP
whose backend slots are not yet present."
  (multiple-value-bind (vip-key service-value backend-entries)
      (service-lb-entries address port base-slot backends)
    (dolist (entry backend-entries)
      (funcall update (service-lb-backend-table dataplane) (car entry) (cdr entry)))
    (funcall update (service-lb-service-table dataplane) vip-key service-value)))

(defun stop-service-lb-dataplane
    (dataplane &key (remove-pins t)
                    (detach #'whistler/loader:detach)
                    (remove-path #'uiop:delete-file-if-exists))
  "Detach the program and release its fds.  When REMOVE-PINS is true (the
default), also remove the pinned maps; pass NIL to keep them across a restart."
  (bt:with-lock-held ((service-lb-dataplane-lock dataplane))
    (when (service-lb-dataplane-attachment dataplane)
      (ignore-errors (funcall detach (service-lb-dataplane-attachment dataplane)))
      (setf (service-lb-dataplane-attachment dataplane) nil))
    (when (service-lb-dataplane-program dataplane)
      (let ((fd (whistler/loader:prog-info-fd (service-lb-dataplane-program dataplane))))
        (when (and fd (plusp fd)) (ignore-errors (sb-posix:close fd))))
      (setf (service-lb-dataplane-program dataplane) nil))
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
