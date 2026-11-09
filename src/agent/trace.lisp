;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0

(in-package #:gr8s.agent)

(defconstant +trace-max-source-bytes+ (* 64 1024))
(defconstant +trace-default-duration-milliseconds+ 30000)
(defconstant +trace-max-duration-milliseconds+ 300000)
(defconstant +trace-max-pods+ 256)
(defconstant +trace-max-programs+ 128)
(defparameter *trace-max-output-bytes* (* 16 1024 1024))

(defparameter +trace-allowed-probe-kinds+
  '(:kprobe :kretprobe :tracepoint :kfunc :kretfunc :profile :interval))

(defvar *trace-cgroup-id-function* nil)
(defvar *trace-compile-function* nil)
(defvar *trace-run-function* nil)

(defun trace-request-error (control &rest arguments)
  (error 'runtime-error :message (apply #'format nil control arguments)))

(defun validate-trace-request (source duration-milliseconds)
  "Validate scalar limits that must hold before compiling a trace."
  (unless (stringp source)
    (trace-request-error "Trace source must be a string"))
  (let ((source-bytes
          (length (babel:string-to-octets source :encoding :utf-8))))
    (when (> source-bytes +trace-max-source-bytes+)
      (trace-request-error "Trace source is ~D bytes; the limit is ~D bytes"
                           source-bytes +trace-max-source-bytes+)))
  (unless (and (integerp duration-milliseconds)
               (plusp duration-milliseconds)
               (<= duration-milliseconds
                   +trace-max-duration-milliseconds+))
    (trace-request-error "Trace duration must be between 1 and ~D milliseconds"
                         +trace-max-duration-milliseconds+)))

(defun validate-trace-probes (ast)
  "Reject probe kinds that cannot be safely scoped to selected Pods."
  (dolist (top (rest ast))
    (when (and (consp top) (eq (first top) :probe))
      (dolist (spec (getf (rest top) :specs))
        (unless (member (first spec) +trace-allowed-probe-kinds+)
          (trace-request-error "Probe kind ~A is not available to Pod traces"
                               (first spec)))))))

(defun enforce-trace-program-limit (generated)
  "Reject GENERATED output that would load too many BPF programs."
  (let ((count (+ (length (getf generated :progs))
                  (length (getf generated :user-probes)))))
    (when (> count +trace-max-programs+)
      (trace-request-error "Trace generates ~D programs; the limit is ~D"
                           count +trace-max-programs+))
    generated))

(defun cgroup-directory-inode (directory)
  "Return the cgroup v2 ID for DIRECTORY. Kernel cgroup IDs are its inode numbers."
  (sb-posix:stat-ino (sb-posix:stat directory)))

(defun resolve-trace-cgroup-ids
    (pods pod-uids cadvisor-entries &key (inode-function #'cgroup-directory-inode))
  "Resolve POD-UIDS to every live sandbox/container cgroup represented by CADVISOR-ENTRIES."
  (let ((uids (remove-duplicates pod-uids :test #'equal)))
    (unless (and uids (every #'stringp uids))
      (trace-request-error "A trace requires at least one Pod UID"))
    (when (> (length uids) +trace-max-pods+)
      (trace-request-error "Trace selects ~D Pods; the limit is ~D"
                           (length uids) +trace-max-pods+))
    (let ((selected
            (mapcar
             (lambda (uid)
               (or (find uid pods :key #'pod-uid :test #'equal)
                   (trace-request-error "Pod UID ~A is not assigned to this node" uid)))
             uids)))
      (let ((directories
              (remove-duplicates
               (loop for entry in cadvisor-entries
                     when (some
                           (lambda (pod)
                             (and (equal (pod-name pod)
                                         (gr8s.kubelet::cadvisor-entry-pod entry))
                                  (equal (pod-namespace pod)
                                         (gr8s.kubelet::cadvisor-entry-namespace entry))))
                           selected)
                       collect (gr8s.kubelet::cadvisor-entry-directory entry))
               :test #'equal)))
        (unless directories
          (trace-request-error "No running cgroups were found for the selected Pods"))
        (remove-duplicates
         (mapcar
          (lambda (directory)
            (or (ignore-errors (funcall inode-function directory))
                (trace-request-error "The Pod cgroup ~A is no longer available"
                                     directory)))
          directories)
         :test #'=)))))

(defun trace-cgroup-predicate (cgroup-ids)
  "Return a bpftrace AST predicate matching exactly one of CGROUP-IDS."
  (unless (and cgroup-ids
               (every (lambda (id) (and (integerp id) (plusp id))) cgroup-ids))
    (error 'runtime-error :message "A trace requires at least one valid Pod cgroup"))
  (reduce
   (lambda (left right) `(:bin :op :|\|\|| :lhs ,left :rhs ,right))
   (mapcar (lambda (id)
             `(:bin :op :== :lhs (:builtin :cgroup) :rhs (:int ,id)))
           (remove-duplicates cgroup-ids :test #'=))))

(defun scope-trace-ast-to-cgroups (ast cgroup-ids)
  "AND every probe in normalized bpftrace AST with the exact CGROUP-IDS predicate."
  (let ((scope (trace-cgroup-predicate cgroup-ids)))
    (cons
     :script
     (loop for top in (rest ast)
           collect
           (if (and (consp top) (eq (first top) :probe))
               (let ((existing (getf (rest top) :predicate)))
                 (list :probe
                       :specs (getf (rest top) :specs)
                       :predicate (if existing
                                      `(:bin :op :&& :lhs ,existing :rhs ,scope)
                                      scope)
                       :body (getf (rest top) :body)))
               top)))))

(defun compile-cgroup-scoped-trace
    (source cgroup-ids
     &key (duration-milliseconds +trace-default-duration-milliseconds+))
  "Compile bpftrace SOURCE after restricting every probe to CGROUP-IDS."
  (validate-trace-request source duration-milliseconds)
  (let* ((tree (whistler/bpftrace::parse-script source))
         (ast (whistler/bpftrace::normalize tree))
         (scoped (scope-trace-ast-to-cgroups ast cgroup-ids)))
    (validate-trace-probes ast)
    (enforce-trace-program-limit
     (whistler/bpftrace::generate scoped))))

(defclass trace-output-stream (sb-gray:fundamental-character-output-stream)
  ((operation :initarg :operation :reader trace-output-operation)
   (channel :initarg :channel :reader trace-output-channel)))

(defmethod sb-gray:stream-write-char ((stream trace-output-stream) character)
  (sb-gray:stream-write-string stream (string character))
  character)

(defmethod sb-gray:stream-write-string
    ((stream trace-output-stream) string &optional (start 0) end)
  (let* ((text (subseq string start (or end (length string))))
         (data (babel:string-to-octets text :encoding :utf-8))
         (operation (trace-output-operation stream)))
    (when (plusp (length data))
      (bt:with-lock-held ((node-exec-operation-lock operation))
        (when (> (+ (node-exec-operation-output-bytes operation) (length data))
                 (node-exec-operation-max-output-bytes operation))
          (trace-request-error "Trace output exceeds the ~D-byte node limit"
                               (node-exec-operation-max-output-bytes operation)))
        (incf (node-exec-operation-output-bytes operation) (length data)))
      (when (wait-for-node-exec-output-window operation (length data))
        (emit-node-exec-stream operation (trace-output-channel stream) data))))
  string)

(defmethod sb-gray:stream-force-output ((stream trace-output-stream))
  (declare (ignore stream))
  nil)

(defmethod sb-gray:stream-finish-output ((stream trace-output-stream))
  (declare (ignore stream))
  nil)

(defun node-trace-cgroup-ids (node-runtime request)
  (resolve-trace-cgroup-ids
   (list-pods (node-runtime-store node-runtime))
   (slot-value request 'gr8s.node.v1::trace-pod-uids)
   (runtime-cadvisor-entries (node-runtime-runtime node-runtime))))

(defun run-whistler-trace (generated attached cancelled-p)
  (declare (ignore cancelled-p))
  (let ((whistler/bpftrace:*post-attach-hook* attached))
    (whistler/bpftrace::run-generated generated)))

(unless *trace-cgroup-id-function*
  (setf *trace-cgroup-id-function* #'node-trace-cgroup-ids))
(unless *trace-compile-function*
  (setf *trace-compile-function* #'compile-cgroup-scoped-trace))
(unless *trace-run-function*
  (setf *trace-run-function* #'run-whistler-trace))

(defun trace-operation-cancelled-p (operation)
  (bt:with-lock-held ((node-exec-operation-lock operation))
    (node-exec-operation-cancel-requested-p operation)))

(defun request-node-trace-stop (operation &optional error)
  "Ask a trace to stop; its worker emits the terminal response after Whistler cleans up."
  (bt:with-lock-held ((node-exec-operation-lock operation))
    (unless (node-exec-operation-cancel-requested-p operation)
      (setf (node-exec-operation-cancel-requested-p operation) t
            (node-exec-operation-cancellation-error operation) error)))
  (setf whistler/bpftrace::*bpftrace-running* nil)
  operation)

(defun acknowledge-node-trace-output (operation input)
  "Apply a coordinator's output acknowledgement without interpreting it as exec input."
  (bt:with-lock-held ((node-exec-operation-lock operation))
    (let ((acknowledged (slot-value input 'gr8s.node.v1::acknowledged-bytes)))
      (when (plusp acknowledged)
        (setf (node-exec-operation-unacknowledged-output operation)
              (max 0 (- (node-exec-operation-unacknowledged-output operation)
                        acknowledged)))
        (bt:condition-notify (node-exec-operation-output-window operation)))))
  operation)

(defun live-node-trace-p (node-runtime)
  (bt:with-lock-held ((node-runtime-operations-lock node-runtime))
    (loop for operation being the hash-values of (node-runtime-operations node-runtime)
          thereis (node-exec-operation-trace-p operation))))

(defun run-node-trace-operation (operation generated duration-milliseconds runner)
  (let* ((accepted-p nil)
         (timer
           (sb-ext:make-timer
            (lambda () (request-node-trace-stop operation))
            :name "gr8s trace deadline")))
    (flet ((attached ()
             (unless accepted-p
               (setf accepted-p t)
               (emit-node-exec-response
                operation gr8s.node.v1::+operationstatus-operation_status_accepted+))))
      (unwind-protect
           (handler-case
               (progn
                 (sb-ext:schedule-timer timer (/ duration-milliseconds 1000.0))
                 (let ((*standard-output*
                         (make-instance 'trace-output-stream :operation operation
                       :channel gr8s.node.v1::+streamchannel-stream_channel_stdout+))
                       (*error-output*
                         (make-instance 'trace-output-stream :operation operation
                       :channel gr8s.node.v1::+streamchannel-stream_channel_stderr+)))
                   (funcall runner generated #'attached
                            (lambda () (trace-operation-cancelled-p operation))))
                 (unless accepted-p
                   (trace-request-error "Whistler did not attach any trace probes"))
                 (finish-node-exec-operation
                  operation :error (node-exec-operation-cancellation-error operation)))
             (error (condition)
               (finish-node-exec-operation operation :error (princ-to-string condition))))
        (sb-ext:unschedule-timer timer)))))

(defun start-node-trace-operation (node-runtime request emit)
  (when (live-node-trace-p node-runtime)
    (trace-request-error "A trace session is already running on this node"))
  (let* ((duration (slot-value request 'gr8s.node.v1::trace-duration-milliseconds))
         (cgroup-ids (funcall *trace-cgroup-id-function* node-runtime request))
         (generated
           (funcall *trace-compile-function*
                    (slot-value request 'gr8s.node.v1::trace-source)
                    cgroup-ids :duration-milliseconds duration))
         (operation (make-node-exec-operation node-runtime request nil nil emit)))
    (setf (node-exec-operation-trace-p operation) t
          (node-exec-operation-max-output-bytes operation) *trace-max-output-bytes*)
    (remember-node-exec-operation node-runtime operation)
    (setf (node-exec-operation-thread operation)
          (bt:make-thread
           (let ((runner *trace-run-function*))
             (lambda () (run-node-trace-operation operation generated duration runner)))
           :name "gr8s Whistler trace"))
    operation))
