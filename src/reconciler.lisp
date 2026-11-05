(in-package #:gr8s)

(defstruct (reconciler (:constructor make-reconciler (store runtime)))
  store
  runtime
  (lock (bt:make-lock "gr8s reconciler"))
  active-convergence
  (urgent-deletions (make-hash-table :test #'equal))
  (convergence-lock (bt:make-lock "gr8s running convergence ownership"))
  ;; Pod UID to the universal time its local storage was last measured.
  (storage-measurements (make-hash-table :test #'equal))
  ;; Pod UID to when a NoExecute taint with a finite toleration was first noticed.
  (taint-timers (make-hash-table :test #'equal)))

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

(defun prioritize-reconciler-deletions (reconciler uids)
  "Reserve creation capacity for durable urgent UIDs until their physical cleanup completes."
  (bt:with-lock-held ((reconciler-convergence-lock reconciler))
    (dolist (uid uids) (setf (gethash uid (reconciler-urgent-deletions reconciler)) t)))
  (cancel-running-pod-convergence reconciler))

(defun finish-reconciler-urgent-deletion (reconciler uid)
  "Release UID's creation fence only after its actual runtime cleanup has completed."
  (bt:with-lock-held ((reconciler-convergence-lock reconciler))
    (remhash uid (reconciler-urgent-deletions reconciler))))

(defun prune-reconciler-urgent-deletions (reconciler)
  "Discard finished exact UIDs without treating a new Pod sharing its name as old ownership."
  (let ((uids (mapcar #'pod-uid (list-pods (reconciler-store reconciler)))))
    (bt:with-lock-held ((reconciler-convergence-lock reconciler))
      (maphash (lambda (uid ignored)
                 (declare (ignore ignored))
                 (unless (member uid uids :test #'equal)
                   (remhash uid (reconciler-urgent-deletions reconciler))))
               (reconciler-urgent-deletions reconciler)))))

(defun converge-cancellable-running-pod (reconciler pod)
  "Register cancellation only around running convergence and recheck durable deletion first."
  (let ((operation (make-running-pod-convergence :thread (bt:current-thread)
                                                :uid (pod-uid pod))))
    (unwind-protect
         (progn
           (prune-reconciler-urgent-deletions reconciler)
           (bt:with-lock-held ((reconciler-convergence-lock reconciler))
             (setf (reconciler-active-convergence reconciler) operation)
             ;; New or retried creation must not grab the global lock while a
             ;; finite urgent cleanup job still needs its completion observed.
             (when (plusp (hash-table-count (reconciler-urgent-deletions reconciler)))
               (error 'pod-reconciliation-superseded)))
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

(defun pod-active-deadline-exceeded-p (pod)
  "Return whether POD has outlived spec.activeDeadlineSeconds, counted from its creation."
  (let* ((object (pod-to-object pod))
         (deadline (gethash "activeDeadlineSeconds" (gethash "spec" object)))
         (created (gethash "creationTimestamp" (gethash "metadata" object))))
    (and deadline created
         (>= (funcall *pod-deletion-clock*) (+ (pod-deletion-time created) deadline)))))

(defun fail-pod-past-deadline (runtime pod)
  "Stop an expired Pod's containers and report the terminal status a kubelet reports."
  (runtime-delete runtime (pod-uid pod))
  (pod-status "Failed" :reason "DeadlineExceeded"
                       :message "Pod was active on the node longer than the specified deadline"))

(defparameter +ephemeral-storage-check-seconds+ 10
  "How often a node measures Pods that declare ephemeral-storage limits, like the kubelet's eviction loop.")

(defun pod-ephemeral-limit-p (pod)
  "Return whether any container of POD declares an ephemeral-storage limit."
  (let ((spec (gethash "spec" (pod-to-object pod))))
    (or (some (lambda (container) (gethash "ephemeral-storage" (container-resource-map container "limits")))
              (concatenate 'vector (gethash "initContainers" spec #()) (gethash "containers" spec)))
        (some #'pod-disk-empty-dir-limit (gethash "volumes" spec #())))))

(defun pod-disk-empty-dir-limit (volume)
  "Return the byte limit of a disk-backed emptyDir VOLUME, or NIL."
  (let* ((source (gethash "emptyDir" volume))
         (limit (and source (not (equal "Memory" (gethash "medium" source))) (gethash "sizeLimit" source))))
    (unless (member limit '(nil 0 "0") :test #'equal)
      (storage-quantity limit "emptyDir.sizeLimit"))))

(defun pod-empty-dir-violation (pod volume-usage)
  "Return why a disk-backed emptyDir in the (NAME . BYTES) list VOLUME-USAGE exceeds its limit, or NIL."
  (loop for volume across (gethash "volumes" (gethash "spec" (pod-to-object pod)) #())
        for limit = (pod-disk-empty-dir-limit volume)
        for used = (cdr (assoc (gethash "name" volume) volume-usage :test #'equal))
        when (and limit used (> used limit))
          return (format nil "Usage of EmptyDir volume ~S exceeds the limit ~S."
                         (gethash "name" volume) (gethash "sizeLimit" (gethash "emptyDir" volume)))))

(defun pod-ephemeral-violation (pod layers volume-bytes)
  "Return why measured LAYERS and VOLUME-BYTES exceed POD's ephemeral-storage limits, or NIL."
  (let ((spec (gethash "spec" (pod-to-object pod))))
    (or (loop for container across (concatenate 'vector (gethash "initContainers" spec #()) (gethash "containers" spec))
              for name = (gethash "name" container)
              for limit = (gethash "ephemeral-storage" (container-resource-map container "limits"))
              when (and limit (> (or (cdr (assoc name layers :test #'equal)) 0) (policy-value limit)))
                return (format nil "Container ~A exceeded its local ephemeral storage limit ~S." name limit))
        (let ((limit (gethash "ephemeral-storage" (nth-value 1 (pod-spec-resource-totals spec)))))
          (when (and limit (> (+ volume-bytes (reduce #'+ layers :key #'cdr)) limit))
            (format nil "Pod ephemeral local storage usage exceeds the total limit of containers ~A."
                    (policy-value-string limit :binary)))))))

(defun pod-storage-eviction-message (reconciler pod)
  "Measure POD when due and return the eviction message for an exceeded limit, or NIL."
  (when (pod-ephemeral-limit-p pod)
    (let ((table (reconciler-storage-measurements reconciler))
          (now (funcall *pod-deletion-clock*)))
      (when (>= (- now (gethash (pod-uid pod) table 0)) +ephemeral-storage-check-seconds+)
        (setf (gethash (pod-uid pod) table) now)
        ;; A failed measurement says nothing about the Pod; the next one decides.
        (handler-case
            (multiple-value-bind (layers volume-bytes volume-usage)
                (runtime-ephemeral-usage (reconciler-runtime reconciler) pod)
              (when volume-bytes
                (or (pod-empty-dir-violation pod volume-usage)
                    (pod-ephemeral-violation pod layers volume-bytes))))
          (error (condition)
            (format *error-output* "gr8s Pod ~A/~A storage measurement failed: ~A~%"
                    (pod-namespace pod) (pod-name pod) condition)
            nil))))))

(defun evict-pod-for-storage (reconciler pod message)
  "Stop POD and durably record the eviction, so reconciliation never starts it again."
  (remhash (pod-uid pod) (reconciler-storage-measurements reconciler))
  (runtime-delete (reconciler-runtime reconciler) (pod-uid pod))
  (let ((status (pod-status "Failed" :reason "Evicted" :message message)))
    (save-pod-observation (reconciler-store reconciler) pod status)
    status))

(defun pod-recorded-eviction (reconciler pod)
  "Return POD's durable eviction status, if a previous pass evicted it."
  (let ((status (pod-observed-status (reconciler-store reconciler) pod)))
    (when (and status (equal "Failed" (gethash "phase" status)) (equal "Evicted" (gethash "reason" status)))
      (copy-core-object status))))

(defun converge-running-pod (reconciler pod)
  (when (runtime-runs-containers-p (reconciler-runtime reconciler))
    (when (pod-active-deadline-exceeded-p pod)
      (return-from converge-running-pod (fail-pod-past-deadline (reconciler-runtime reconciler) pod)))
    (let ((evicted (pod-recorded-eviction reconciler pod)))
      (when evicted (return-from converge-running-pod evicted))))
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
    (when (runtime-runs-containers-p runtime)
      (let ((message (pod-storage-eviction-message reconciler pod)))
        (when message
          (return-from converge-running-pod (evict-pod-for-storage reconciler pod message)))))
    (let ((status (observed-status observed)))
      (when (equal (pod-resource-version pod) (runtime-pod-resource-version observed))
        (setf (gethash "observedGeneration" status)
              (gethash "generation" (gethash "metadata" (pod-to-object pod)) 1)))
      status)))

(defun converge-deleting-pod (reconciler pod)
  (when (or (pod-finalizers-present-p pod) (pod-finalization-state (reconciler-store reconciler) pod))
    (return-from converge-deleting-pod (converge-finalized-pod-deletion reconciler pod)))
  (if (runtime-delete-pod (reconciler-runtime reconciler) pod)
      (progn
        (runtime-forget-pod-finalization (reconciler-runtime reconciler) (pod-uid pod))
        (finish-reconciler-urgent-deletion reconciler (pod-uid pod))
        (remove-pod (reconciler-store reconciler)
                    (pod-namespace pod) (pod-name pod) :uid (pod-uid pod))
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
           (or (when (deletion-requested-p pod)
                 (let ((state (pod-finalization-state (reconciler-store reconciler) pod)))
                   (when state (gethash "status" state))))
               (pod-status "Pending"
                           :reason "RuntimeError"
                           :message (runtime-error-message error)))))))))

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
  (loop for pod in (stable-sort (copy-list (list-pods (reconciler-store reconciler)))
                                ;; Finish deletions first, then place the most important Pods.
                                (lambda (left right)
                                  (let ((left-deleting (deletion-requested-p left))
                                        (right-deleting (deletion-requested-p right)))
                                    (if (eq (not left-deleting) (not right-deleting))
                                        (> (pod-spec-priority left) (pod-spec-priority right))
                                        left-deleting))))
        append (handler-case
                   (let ((status (reconcile-pod reconciler (pod-namespace pod) (pod-name pod))))
                     (when observer (funcall observer pod status))
                     (list status))
                 (pod-reconciliation-superseded () nil))))

(defun reconciler-logs (reconciler uid container &key tail previous)
  (bt:with-lock-held ((reconciler-lock reconciler))
    (runtime-logs (reconciler-runtime reconciler)
                  uid container :tail tail :previous previous)))

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

(defun reconciler-start-attach-session (reconciler uid container &key stdin stdout stderr tty)
  (runtime-start-attach-session (reconciler-runtime reconciler) uid container
                                :stdin stdin :stdout stdout :stderr stderr :tty tty))

(defun reconciler-attach-url (reconciler uid container &key stdin stdout stderr tty)
  (runtime-attach-url (reconciler-runtime reconciler) uid container
                      :stdin stdin :stdout stdout :stderr stderr :tty tty))

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
