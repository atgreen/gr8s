;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Run container lifecycle hooks against exact CRI attempts. A postStart hook
;;;; runs outside reconciliation while its container reports waiting; a failure
;;;; stops that attempt so restart policy applies. preStop hooks consume the Pod's
;;;; grace before the signal, and application containers stop before restartable
;;;; init sidecars, which then stop one at a time in reverse declaration order.

(in-package #:gr8s)

(defstruct container-hook-manager
  "Own the background hook and sidecar shutdown jobs of one native runtime."
  (jobs (make-hash-table :test #'equal))
  (lock (bt:make-lock "native container hooks")))

(defstruct container-hook-job
  "Track one running postStart hook by its exact container, or a Pod's sidecar shutdown."
  uid container-id thread)

(defun record-container-lifecycle-event (runtime uid name occurrence reason message &optional (type "Normal"))
  "Queue one Event about container NAME's OCCURRENCE, sent with this Pod's next status report."
  (let* ((manager (ensure-container-probe-manager runtime))
         (now (current-timestamp (floor (funcall (container-probe-manager-clock manager)))))
         (event (core-object "id" (format nil "lifecycle-~A-~A-~A" name occurrence reason)
                             "kind" "lifecycle" "container" name "reason" reason "type" type
                             "message" (bounded-probe-event-message message) "count" 1
                             "firstTimestamp" now "lastTimestamp" now)))
    (bt:with-lock-held ((container-probe-manager-lock manager))
      (retain-container-probe-event manager uid event))))

(defun validate-container-lifecycle-handler (handler context)
  "Validate one lifecycle handler: exactly one of exec, httpGet and sleep."
  (drop-null-fields (require-object handler context))
  (reject-unsupported-fields handler '("exec" "httpGet" "sleep") context)
  (unless (= 1 (hash-table-count handler))
    (invalid-pod "~A requires exactly one handler" context))
  (let ((sleep (gethash "sleep" handler)))
    (if sleep
        (progn
          (drop-null-fields (require-object sleep "sleep"))
          (reject-unsupported-fields sleep '("seconds") "sleep")
          (unless (typep (gethash "seconds" sleep) '(integer 0 9223372036854775807))
            (invalid-pod "~A.sleep.seconds must be a nonnegative int64" context)))
        (maphash (lambda (kind action)
                   (validate-probe-action kind (require-object action kind)))
                 handler))))

(defun validate-container-lifecycle (container)
  "Validate CONTAINER's optional postStart and preStop handlers."
  (when (eq (gethash "lifecycle" container) 'null) (remhash "lifecycle" container))
  (let ((lifecycle (gethash "lifecycle" container)))
    (when lifecycle
      (drop-null-fields (require-object lifecycle "lifecycle"))
      (reject-unsupported-fields lifecycle '("postStart" "preStop") "lifecycle")
      (dolist (kind '("postStart" "preStop"))
        (when (gethash kind lifecycle)
          (validate-container-lifecycle-handler (gethash kind lifecycle) (format nil "lifecycle.~A" kind)))))))

(defun container-lifecycle-handler (object kind)
  "Return container OBJECT's lifecycle handler of KIND, or NIL."
  (let ((lifecycle (gethash "lifecycle" object)))
    (and lifecycle (gethash kind lifecycle))))

(defun run-container-hook (runtime container container-id pod-ip handler)
  "Run HANDLER once against the exact attempt, returning success and a message."
  (handler-case
      (cond
        ((gethash "exec" handler)
         (let ((result (cri-exec-sync (containerd-runtime-socket-path runtime) container-id
                                      (expand-static-probe-command container (gethash "command" (gethash "exec" handler)))
                                      :timeout 0)))
           (values (zerop (runtime-exec-result-exit-code result))
                   (format nil "command exited with ~D: ~A" (runtime-exec-result-exit-code result)
                           (container-probe-exec-output result)))))
        ((gethash "httpGet" handler)
         (let* ((action (gethash "httpGet" handler))
                (host (gethash "host" action ""))
                (port (resolve-container-probe-port container (gethash "port" action))))
           (sb-sys:with-deadline (:seconds 30)
             (run-http-container-probe action (if (equal "" host) pod-ip host) port 30))))
        ((gethash "sleep" handler)
         (sleep (gethash "seconds" (gethash "sleep" handler)))
         (values t "slept"))
        (t (values nil "lifecycle handler has no action")))
    (sb-sys:deadline-timeout (condition) (values nil (princ-to-string condition)))
    (error (condition) (values nil (princ-to-string condition)))))

(defun container-hook-manager-busy-p (runtime)
  "Return whether any hook or sidecar shutdown is still running on RUNTIME."
  (let ((manager (containerd-runtime-hooks runtime)))
    (bt:with-lock-held ((container-hook-manager-lock manager))
      (plusp (hash-table-count (container-hook-manager-jobs manager))))))

(defun forget-container-hook-job (manager key)
  "Drop a finished job so its container or Pod no longer counts as busy."
  (bt:with-lock-held ((container-hook-manager-lock manager))
    (remhash key (container-hook-manager-jobs manager))))

(defun start-container-post-start-hook (runtime pod spec container-id sandbox-id)
  "Start SPEC's postStart hook, if any, without holding up other Pods on this node."
  (let* ((container (pod-runtime-container-object pod spec))
         (handler (container-lifecycle-handler container "postStart")))
    (when handler
      (let ((manager (containerd-runtime-hooks runtime))
            (job (make-container-hook-job :uid (pod-uid pod) :container-id container-id))
            (grace (gethash "terminationGracePeriodSeconds" (gethash "spec" (pod-to-object pod)) 30))
            (address (containerd-sandbox-address runtime pod sandbox-id)))
        (bt:with-lock-held ((container-hook-manager-lock manager))
          (setf (gethash container-id (container-hook-manager-jobs manager)) job
                (container-hook-job-thread job)
                (bt:make-thread
                 (lambda ()
                   (unwind-protect
                        (multiple-value-bind (success message)
                            (run-container-hook runtime container container-id address handler)
                          (unless success
                            (record-container-lifecycle-event
                             runtime (pod-uid pod) (container-spec-name spec) container-id "FailedPostStartHook"
                             (format nil "PostStartHook failed: ~A" message) "Warning")
                            (ignore-errors
                             (cri-stop-container (containerd-runtime-socket-path runtime) container-id
                                                 :grace-period grace))))
                     (forget-container-hook-job manager container-id)))
                 :name (format nil "postStart ~A/~A" (pod-name pod) (container-spec-name spec)))))))))

(defun container-post-start-pending-p (runtime container-id)
  "Return whether CONTAINER-ID's postStart hook is still running."
  (let ((manager (containerd-runtime-hooks runtime)))
    (bt:with-lock-held ((container-hook-manager-lock manager))
      (not (null (gethash container-id (container-hook-manager-jobs manager)))))))

(defun pod-post-start-pending-p (runtime uid)
  "Return whether any postStart hook of UID is running, which holds back its next container."
  (let ((manager (containerd-runtime-hooks runtime)))
    (bt:with-lock-held ((container-hook-manager-lock manager))
      (loop for job being the hash-values of (container-hook-manager-jobs manager)
            thereis (and (equal uid (container-hook-job-uid job))
                         (container-hook-job-container-id job) t)))))

(defun mask-post-start-containers (runtime infos)
  "Show attempts whose postStart hook is unfinished as not yet started, as a kubelet reports them."
  (mapcar (lambda (info)
            (if (and (= (cri-container-info-state info) gr8s.cri.v1::+containerstate-container_running+)
                     (container-post-start-pending-p runtime (cri-container-info-id info)))
                (let ((copy (copy-cri-container-info info)))
                  (setf (cri-container-info-state copy) gr8s.cri.v1::+containerstate-container_created+)
                  copy)
                info))
          infos))

(defun containerd-pod-sandbox-address (runtime pod)
  "Return POD's address, from its node or its current sandbox, or an empty string without one."
  (if (containerd-pod-host-network-p runtime pod)
      (containerd-node-address runtime)
      (let ((sandbox (containerd-owned-sandbox runtime (pod-uid pod))))
        (if sandbox
            (cri-pod-sandbox-ip (containerd-runtime-socket-path runtime) (cri-pod-sandbox-info-id sandbox))
            ""))))

(defun run-container-pre-stop-hook (runtime pod info deadline address)
  "Run INFO's preStop hook until it finishes, DEADLINE passes, or a shorter grace replaces this job."
  (let* ((container (find (cri-container-info-name info)
                          (pod-all-container-objects pod) :test #'equal
                          :key (lambda (object) (gethash "name" object))))
         (handler (and container (container-lifecycle-handler container "preStop")))
         (cancelled nil))
    (when (and handler (plusp (- deadline (funcall *pod-deletion-clock*))))
      (register-runtime-deletion-cancel (lambda () (setf cancelled t)))
      (let ((thread (bt:make-thread
                     (lambda ()
                       (multiple-value-bind (success message)
                           (run-container-hook runtime container (cri-container-info-id info) address handler)
                         (unless success
                           (record-container-lifecycle-event
                            runtime (pod-uid pod) (cri-container-info-name info) (cri-container-info-id info)
                            "FailedPreStopHook" (format nil "PreStopHook failed: ~A" message) "Warning"))))
                     :name (format nil "preStop ~A/~A" (pod-name pod) (cri-container-info-name info)))))
        ;; A hook that outlives its grace is abandoned; stopping the container ends it.
        (loop while (and (bt:thread-alive-p thread) (not cancelled)
                         (plusp (- deadline (funcall *pod-deletion-clock*))))
              do (sleep 0.1))))))

(defun stop-container-with-pre-stop (runtime pod info deadline address)
  "Run INFO's preStop hook, then signal the container with whatever grace remains."
  (record-container-lifecycle-event runtime (pod-uid pod) (cri-container-info-name info) (cri-container-info-id info)
                                    "Killing" (format nil "Stopping container ~A" (cri-container-info-name info)))
  (run-container-pre-stop-hook runtime pod info deadline address)
  (cri-stop-container (containerd-runtime-socket-path runtime) (cri-container-info-id info)
                      :grace-period (max 0 (ceiling (- deadline (funcall *pod-deletion-clock*))))))

(defun stop-containers-concurrently (runtime pod infos deadline address)
  "Stop INFOS together against one DEADLINE, propagating the first failure after all finish."
  (let* ((register *runtime-deletion-register-cancel*)
         (failures (make-array (length infos) :initial-element nil))
         (threads
           (loop for info in infos for index from 0
                 collect (let ((current info) (slot index))
                           (bt:make-thread
                            (lambda ()
                              (let ((*runtime-deletion-register-cancel* register))
                                (handler-case (stop-container-with-pre-stop runtime pod current deadline address)
                                  (error (condition) (setf (aref failures slot) condition)))))
                            :name "gr8s stop container with preStop")))))
    (mapc #'bt:join-thread threads)
    (loop for failure across failures when failure do (error failure))))

(defun pod-all-container-objects (pod)
  "Return the JSON declarations of POD's init, application and ephemeral containers."
  (let ((spec (gethash "spec" (pod-to-object pod))))
    (concatenate 'list (gethash "initContainers" spec #()) (gethash "containers" spec #())
                 (gethash "ephemeralContainers" spec #()))))

(defun pod-sidecar-names (pod)
  "Return the names of POD's restartable init containers in declaration order."
  (loop for container across (gethash "initContainers" (gethash "spec" (pod-to-object pod)) #())
        when (equal "Always" (gethash "restartPolicy" container))
          collect (gethash "name" container)))

(defun running-pod-container-infos (runtime sandbox)
  "Return the actual status of every running container in SANDBOX."
  (let ((socket (containerd-runtime-socket-path runtime)))
    (remove-if-not
     (lambda (info) (= (cri-container-info-state info) gr8s.cri.v1::+containerstate-container_running+))
     (mapcar (lambda (summary) (cri-container-status socket (cri-container-summary-id summary)))
             (containerd-containers runtime sandbox)))))

(defun stop-pod-sidecars-in-reverse (runtime pod infos deadline address)
  "Stop running sidecars among INFOS one at a time, last declared first."
  (dolist (name (reverse (pod-sidecar-names pod)))
    (let ((info (find name infos :test #'equal :key #'cri-container-info-name)))
      (when info (stop-container-with-pre-stop runtime pod info deadline address)))))

(defun stop-pod-containers-in-order (runtime pod deadline)
  "Run preStop hooks and stop application containers, then sidecars, before physical removal."
  (let* ((objects (pod-all-container-objects pod))
         (sidecars (pod-sidecar-names pod)))
    ;; A container with a readiness probe is stopped here too, while its probes still run, so
    ;; it shows as unready once it leaves service instead of when it is removed.
    (when (or sidecars (some (lambda (object) (container-lifecycle-handler object "preStop")) objects)
              (some (lambda (object) (gethash "readinessProbe" object)) objects))
      (let ((sandbox (containerd-owned-sandbox runtime (pod-uid pod))))
        (when sandbox
          (let ((infos (running-pod-container-infos runtime sandbox))
                (address (containerd-pod-sandbox-address runtime pod)))
            (stop-containers-concurrently
             runtime pod
             (remove-if (lambda (info) (member (cri-container-info-name info) sidecars :test #'equal)) infos)
             deadline address)
            (stop-pod-sidecars-in-reverse runtime pod infos deadline address)))))))

(defun start-finished-pod-sidecar-shutdown (runtime pod sandbox)
  "Stop the sidecars of a Pod whose applications have finished, outside reconciliation."
  (let* ((manager (containerd-runtime-hooks runtime))
         (key (format nil "sidecars/~A" (pod-uid pod)))
         (deadline (+ (funcall *pod-deletion-clock*)
                      (gethash "terminationGracePeriodSeconds" (gethash "spec" (pod-to-object pod)) 30))))
    (bt:with-lock-held ((container-hook-manager-lock manager))
      (unless (gethash key (container-hook-manager-jobs manager))
        (let ((job (make-container-hook-job :uid (pod-uid pod))))
          (setf (gethash key (container-hook-manager-jobs manager)) job
                (container-hook-job-thread job)
                (bt:make-thread
                 (lambda ()
                   (unwind-protect
                        (handler-case
                            (let ((infos (running-pod-container-infos runtime sandbox)))
                              (when infos
                                (stop-pod-sidecars-in-reverse
                                 runtime pod infos deadline
                                 (containerd-sandbox-address runtime pod (cri-pod-sandbox-info-id sandbox)))))
                          (error (condition)
                            (format *error-output* "gr8s sidecar shutdown of ~A/~A failed: ~A~%"
                                    (pod-namespace pod) (pod-name pod) condition)))
                     (forget-container-hook-job manager key)))
                 :name (format nil "sidecar shutdown ~A" (pod-name pod)))))))))
