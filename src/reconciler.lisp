(in-package #:gr8s)

(defstruct (reconciler (:constructor make-reconciler (store runtime)))
  store
  runtime
  (lock (bt:make-lock "gr8s reconciler"))
  active-convergence
  (convergence-lock (bt:make-lock "gr8s running convergence ownership")))

(define-condition pod-reconciliation-superseded (serious-condition) ()
  (:documentation "Unwind obsolete creation without translating cancellation into a Pod failure."))

(defstruct running-pod-convergence
  "A narrowly owned, cancellable running-Pod operation; deletion never registers here."
  thread uid finished-p)

(defun cancel-running-pod-convergence (reconciler)
  "Yield blocked creation to durable urgent deletion without interrupting deletion itself."
  (let ((operation (bt:with-lock-held ((reconciler-convergence-lock reconciler))
                     (reconciler-active-convergence reconciler))))
    (when operation
      (ignore-errors
        (bt:interrupt-thread
         (running-pod-convergence-thread operation)
         (lambda ()
           ;; This callback runs in the owner. A late callback must not escape
           ;; after that operation's unwind-protect has released ownership.
           ;; Only the owner changes this flag. Do not acquire an ownership
           ;; mutex here: an asynchronous interrupt may arrive while its
           ;; target is inside that same mutex.
           (unless (running-pod-convergence-finished-p operation)
             (error 'pod-reconciliation-superseded)))))))
  nil)

(defun converge-cancellable-running-pod (reconciler pod)
  "Register cancellation only around running convergence and recheck durable deletion first."
  (let ((operation (make-running-pod-convergence :thread (bt:current-thread)
                                                :uid (pod-uid pod))))
    (unwind-protect
         (progn
           (bt:with-lock-held ((reconciler-convergence-lock reconciler))
             (setf (reconciler-active-convergence reconciler) operation))
           ;; Urgent snapshot projection uses the store lock, never this global
           ;; reconciler lock. Register before checking so its cancellation
           ;; cannot miss the gap between reading a Pod and entering CRI.
           (let ((current (get-pod (reconciler-store reconciler)
                                   (pod-namespace pod) (pod-name pod))))
             (unless (and (equal (pod-uid current) (pod-uid pod))
                          (not (deletion-requested-p current)))
               (error 'pod-reconciliation-superseded)))
           (converge-running-pod reconciler pod))
      (flet ((release-ownership ()
               (bt:with-lock-held ((reconciler-convergence-lock reconciler))
                 (setf (running-pod-convergence-finished-p operation) t)
                 (when (eq operation (reconciler-active-convergence reconciler))
                   (setf (reconciler-active-convergence reconciler) nil)))))
        ;; Cancellation must not interrupt its own ownership release halfway.
        #+sbcl (sb-sys:without-interrupts (release-ownership))
        #-sbcl (release-ownership)))))

(defun deletion-requested-p (pod)
  (nth-value 1
             (gethash "deletionTimestamp"
                      (gethash "metadata" (pod-to-object pod)))))

(defun pod-status (phase &key reason message)
  (let ((status (make-hash-table :test #'equal)))
    (setf (gethash "phase" status) phase)
    (when reason
      (setf (gethash "reason" status) reason))
    (when message
      (setf (gethash "message" status) message))
    status))

(defun observed-status (runtime-pod)
  (let ((status (if (runtime-pod-status runtime-pod)
                    (com.inuoe.jzon:parse (com.inuoe.jzon:stringify (runtime-pod-status runtime-pod)))
                    (pod-status (runtime-pod-phase runtime-pod)))))
    (setf (gethash "phase" status) (runtime-pod-phase runtime-pod))
    (unless (string= "" (runtime-pod-pod-ip runtime-pod))
      (setf (gethash "podIP" status) (runtime-pod-pod-ip runtime-pod)
            (gethash "podIPs" status) (vector (json-object "ip" (runtime-pod-pod-ip runtime-pod)))))
    status))

(defun converge-running-pod (reconciler pod)
  (let* ((runtime (reconciler-runtime reconciler))
         (observed (runtime-observe runtime (pod-uid pod))))
    (when (and observed (runtime-pod-spec-fingerprint observed)
               (equal (runtime-pod-spec-fingerprint observed) (pod-runtime-spec-fingerprint pod)))
      ;; Metadata updates advance API resourceVersion but do not change the
      ;; running workload. The durable runtime fingerprint proves adoption.
      (setf (runtime-pod-resource-version observed) (pod-resource-version pod)))
    (if (or (null observed)
            (not (string= (runtime-pod-resource-version observed)
                          (pod-resource-version pod))))
        (setf observed (runtime-ensure runtime pod))
        (setf observed (runtime-reconcile-containers runtime pod observed)))
    (let ((status (observed-status observed)))
      (when (equal (pod-resource-version pod) (runtime-pod-resource-version observed))
        (setf (gethash "observedGeneration" status)
              (gethash "generation" (gethash "metadata" (pod-to-object pod)) 1)))
      status)))

(defun converge-deleting-pod (reconciler pod)
  (if (runtime-delete-pod (reconciler-runtime reconciler) pod)
      (progn
        (remove-pod (reconciler-store reconciler)
                    (pod-namespace pod) (pod-name pod))
        (pod-status "Succeeded" :reason "Deleted"))
      (let* ((runtime (reconciler-runtime reconciler))
             (observed (handler-case (runtime-observe runtime (pod-uid pod))
                         ;; Concurrent container removal may invalidate a CRI
                         ;; status lookup. The deletion remains accepted.
                         (runtime-error () nil)))
             (status (if observed (observed-status observed) (pod-status "Unknown"))))
        ;; Shutdown intent does not prove that a still-running container has
        ;; become unready. Keep actual container observations during grace;
        ;; the Service controller separately excludes terminating endpoints.
        (when (and observed (runtime-pod-spec-fingerprint observed)
                   (equal (runtime-pod-spec-fingerprint observed) (pod-runtime-spec-fingerprint pod)))
          (setf (gethash "observedGeneration" status)
                (gethash "generation" (gethash "metadata" (pod-to-object pod)) 1)))
        (setf (gethash "reason" status) "Terminating")
        status)))

(defun reconcile-pod (reconciler namespace name)
  (bt:with-lock-held ((reconciler-lock reconciler))
    (let ((pod (get-pod (reconciler-store reconciler) namespace name)))
      (handler-case
          (add-pod-status-conditions
           (reconciler-store reconciler) pod
           (if (deletion-requested-p pod)
               (converge-deleting-pod reconciler pod)
               (converge-cancellable-running-pod reconciler pod)))
        (runtime-error (error)
          (format *error-output* "gr8s Pod ~A/~A runtime error: ~A~%" namespace name (runtime-error-message error))
          (add-pod-status-conditions
           (reconciler-store reconciler) pod
           (pod-status "Pending"
                       :reason "RuntimeError"
                       :message (runtime-error-message error))))))))

(defun delete-reconciled-pod (reconciler namespace name &key uid resource-version
                                                      (grace-period nil grace-supplied-p)
                                                      dry-run)
  (bt:with-lock-held ((reconciler-lock reconciler))
    (let ((pod (apply #'mark-pod-deleting (reconciler-store reconciler) namespace name
                      :uid uid :resource-version resource-version :dry-run dry-run
                      (when grace-supplied-p (list :grace-period grace-period)))))
      (values (unless dry-run
                (add-pod-status-conditions (reconciler-store reconciler) pod
                                          (converge-deleting-pod reconciler pod))) pod))))

(defun reconcile-all (reconciler &key observer)
  (loop for pod in (list-pods (reconciler-store reconciler))
        append (handler-case
                   (let ((status (reconcile-pod reconciler (pod-namespace pod) (pod-name pod))))
                     (when observer (funcall observer pod status))
                     (list status))
                 (pod-reconciliation-superseded () nil))))

(defun reconciler-logs (reconciler uid container &key tail)
  (bt:with-lock-held ((reconciler-lock reconciler))
    (runtime-logs (reconciler-runtime reconciler)
                  uid container :tail tail)))

(defun reconciler-exec-url
    (reconciler uid container command &key stdin stdout stderr tty)
  (bt:with-lock-held ((reconciler-lock reconciler))
    (runtime-exec-url
     (reconciler-runtime reconciler) uid container command
     :stdin stdin :stdout stdout :stderr stderr :tty tty)))

(defun reconciler-exec-sync
    (reconciler uid container command &key (timeout 30))
  (bt:with-lock-held ((reconciler-lock reconciler))
    (runtime-exec-sync
     (reconciler-runtime reconciler) uid container command :timeout timeout)))

(defun reconciler-start-exec-session
    (reconciler uid container command &key stdin stdout stderr tty)
  (bt:with-lock-held ((reconciler-lock reconciler))
    (runtime-start-exec-session
     (reconciler-runtime reconciler) uid container command
     :stdin stdin :stdout stdout :stderr stderr :tty tty)))

(defun reconciler-send-exec-session-input
    (reconciler session channel data &key rows columns eof)
  (runtime-send-exec-session-input
   (reconciler-runtime reconciler) session channel data
   :rows rows :columns columns :eof eof))

(defun reconciler-next-exec-session-output
    (reconciler session cursor &key timeout)
  (runtime-next-exec-session-output
   (reconciler-runtime reconciler) session cursor :timeout timeout))

(defun reconciler-exec-session-exit-code (reconciler session)
  (runtime-exec-session-exit-code (reconciler-runtime reconciler) session))

(defun reconciler-cancel-exec-session (reconciler session reason)
  (runtime-cancel-exec-session
   (reconciler-runtime reconciler) session reason))

(defun reconciler-release-exec-session (reconciler session)
  (runtime-release-exec-session (reconciler-runtime reconciler) session))
