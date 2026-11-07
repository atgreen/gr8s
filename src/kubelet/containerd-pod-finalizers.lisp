;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Preserve actual native terminal observations before CRI objects disappear
;;;; for Pods retained by API finalizers. Shutdown still removes native tasks,
;;;; sandboxes and shims; only exact-UID terminal history survives until release.

(in-package #:gr8s.kubelet)

(defun capture-containerd-finalized-pod (runtime pod deadline)
  "Stop real containers concurrently and persist their exits before physical removal."
  (let* ((uid (pod-uid pod)) (socket (containerd-runtime-socket-path runtime))
         (sandbox (containerd-owned-sandbox runtime uid)))
    (when sandbox
      (let* ((containers (containerd-containers runtime sandbox))
             (failures (make-array (length containers) :initial-element nil))
             (register *runtime-deletion-register-cancel*)
             (threads
               (loop for container in containers for index from 0
                     collect (let ((id (cri-container-summary-id container)) (slot index))
                               (bt:make-thread
                                (lambda ()
                                  (let ((*runtime-deletion-register-cancel* register))
                                    (handler-case
                                        (cri-stop-container socket id :grace-period (max 0 (- deadline (funcall *pod-deletion-clock*))))
                                      (error (condition) (setf (aref failures slot) condition)))))
                                :name "gr8s stop finalized Pod container")))))
        (mapc #'bt:join-thread threads)
        (loop for failure across failures when failure do (error failure))
        ;; This also rejects a superseded job between Stop and checkpointing.
        (register-runtime-deletion-cancel (lambda () nil))
        (let* ((state (load-container-lifecycle-state runtime uid))
               (infos (current-container-infos
                       (mapcar (lambda (container) (cri-container-status socket (cri-container-summary-id container))) containers) state))
               (statuses (coerce (mapcar #'containerd-container-status-object infos) 'vector)))
          (unless (every (lambda (status) (gethash "terminated" (gethash "state" status))) statuses)
            (error 'runtime-error :message "Finalized Pod still has nonterminal containers after StopContainer"))
          (setf (gethash "podIP" state) (cri-pod-sandbox-ip socket (cri-pod-sandbox-info-id sandbox))
                (gethash "terminalShutdown" state) t)
          (remember-container-lifecycle-statuses state statuses)
          (loop for status across statuses
                for entry = (gethash (gethash "name" status) (gethash "containers" state))
                do (setf (gethash "restartSuppressed" entry) t))
          (save-container-lifecycle-state runtime uid state))))))

(defmethod runtime-forget-pod-finalization ((runtime containerd-runtime) uid)
  "Retire exact-UID native history once the finalizer-retained API object can disappear."
  (forget-container-lifecycle-state runtime uid))
