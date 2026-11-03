(in-package #:gr8s)

(defstruct (reconciler (:constructor make-reconciler (store runtime)))
  store
  runtime
  (lock (bt:make-lock "gr8s reconciler")))

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
    (when (or (null observed)
              (not (string= (runtime-pod-resource-version observed)
                            (pod-resource-version pod)))
              (and (string= "Always" (pod-restart-policy pod))
                   (not (string= "Running" (runtime-pod-phase observed)))))
      (setf observed (runtime-ensure runtime pod)))
    (observed-status observed)))

(defun converge-deleting-pod (reconciler pod)
  (runtime-delete (reconciler-runtime reconciler) (pod-uid pod))
  (remove-pod (reconciler-store reconciler)
              (pod-namespace pod)
              (pod-name pod))
  (pod-status "Succeeded" :reason "Deleted"))

(defun reconcile-pod (reconciler namespace name)
  (bt:with-lock-held ((reconciler-lock reconciler))
    (let ((pod (get-pod (reconciler-store reconciler) namespace name)))
      (handler-case
          (if (deletion-requested-p pod)
              (converge-deleting-pod reconciler pod)
              (converge-running-pod reconciler pod))
        (runtime-error (error)
          (pod-status "Pending"
                      :reason "RuntimeError"
                      :message (runtime-error-message error)))))))

(defun delete-reconciled-pod (reconciler namespace name &key uid)
  (bt:with-lock-held ((reconciler-lock reconciler))
    (mark-pod-deleting (reconciler-store reconciler) namespace name :uid uid)
    (converge-deleting-pod
     reconciler
     (get-pod (reconciler-store reconciler) namespace name))))

(defun reconcile-all (reconciler &key observer)
  (loop for pod in (list-pods (reconciler-store reconciler))
        for status = (reconcile-pod reconciler (pod-namespace pod) (pod-name pod))
        do (when observer (funcall observer pod status))
        collect status))

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
