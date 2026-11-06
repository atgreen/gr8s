;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; The RestartAllContainers restart rule action (RestartAllContainersOnContainerExits,
;;;; beta and on by default since v1.36). When an init, sidecar or application
;;;; container exits with a code such a rule matches, the node stops every other
;;;; container and runs the Pod again in its existing sandbox: init containers in
;;;; order, then sidecars and applications, each as its next attempt with the exit it
;;;; was stopped with as its last state. Ephemeral containers are left alone.

(in-package #:gr8s)

(defun restart-all-containers-trigger (pod current state)
  "Return the exited attempt in CURRENT whose restart rules restart all of POD's containers, or NIL.
An attempt that already did so, or that the restart itself stopped, never triggers another."
  (let ((handled (coerce (gethash "restartAllHandled" state #()) 'list)))
    (find-if (lambda (info)
               (and (= (cri-container-info-state info) gr8s.cri.v1::+containerstate-container_exited+)
                    (not (member (cri-container-info-id info) handled :test #'equal))
                    (pod-container-declaration pod (cri-container-info-name info))
                    (container-exit-restarts-all-p pod (cri-container-info-name info)
                                                   (cri-container-info-exit-code info))))
             current)))

(defun restart-all-pod-containers (runtime pod current state trigger)
  "Stop every non-ephemeral container in CURRENT and remove its attempt, so the next pass runs the Pod
from its first init container again. Each container keeps its attempt count and its last exit."
  (let* ((socket (containerd-runtime-socket-path runtime))
         (uid (pod-uid pod))
         (grace (gethash "terminationGracePeriodSeconds" (gethash "spec" (pod-to-object pod)) 30))
         (targets (remove-if-not (lambda (info) (pod-container-declaration pod (cri-container-info-name info)))
                                 current))
         (entries (gethash "containers" state)))
    (record-container-lifecycle-event
     runtime uid (cri-container-info-name trigger) (cri-container-info-attempt trigger) "RestartingAllContainers"
     (format nil "Container ~A exited with code ~D; restarting all containers"
             (cri-container-info-name trigger) (cri-container-info-exit-code trigger)))
    (stop-container-probes runtime uid)
    ;; Every container is stopped together, each within the Pod's grace period.
    (mapc #'bt:join-thread
          (loop for info in targets
                unless (= (cri-container-info-state info) gr8s.cri.v1::+containerstate-container_exited+)
                  collect (let ((id (cri-container-info-id info)))
                            (bt:make-thread (lambda () (ignore-errors (cri-stop-container socket id :grace-period grace)))
                                            :name "gr8s restart all containers"))))
    (dolist (info targets)
      (let* ((name (cri-container-info-name info))
             (final (or (ignore-errors (cri-container-status socket (cri-container-info-id info))) info))
             (termination (gethash "terminated" (gethash "state" (containerd-container-status-object final))))
             (entry (or (gethash name entries) (core-object))))
        (setf (gethash "highestKnownAttempt" entry) (max (cri-container-info-attempt info) (known-container-attempt entry)))
        (when termination (setf (gethash "lastTermination" entry) (copy-core-object termination)))
        ;; The next attempt starts at once, and nothing recorded about this one holds it back.
        (dolist (key '("lastStatus" "restartSuppressed" "nextStart" "nextAttempt" "lastAttempt" "lastExitID"
                       "probeRestart" "backoff" "lastFailureTime"))
          (remhash key entry))
        (setf (gethash name entries) entry)))
    ;; Only an attempt whose removal failed can be seen again, so a short memory is enough.
    (setf (gethash "restartAllHandled" state)
          (coerce (let ((handled (cons (cri-container-info-id trigger) (coerce (gethash "restartAllHandled" state #()) 'list))))
                    (subseq handled 0 (min 16 (length handled))))
                  'vector))
    (save-container-lifecycle-state runtime uid state)
    ;; Removing the stopped attempts makes the sandbox run the Pod's containers from the start.
    (dolist (info targets)
      (cri-delete-container socket (cri-container-info-id info)))))
