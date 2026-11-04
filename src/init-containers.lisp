;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Execute ordinary Kubernetes init containers in declaration order, deriving
;;;; initialization and application admission from real CRI exit observations.
;;;; Persist declarations alongside attempt history so read-only observations
;;;; and process recovery keep init statuses separate from application status.

(in-package #:gr8s)

(defun parse-init-container (object)
  "Validate an ordinary init container without admitting unsupported sidecar or probe semantics."
  (require-object object "init container")
  (dolist (key '("startupProbe" "readinessProbe" "livenessProbe"))
    (when (nth-value 1 (gethash key object))
      (invalid-pod "ordinary init containers cannot define ~A" key)))
  (parse-container object))

(defun pod-init-container-p (pod name)
  "Find NAME among POD's ordered init declarations."
  (find name (pod-init-containers pod) :test #'equal :key #'container-spec-name))

(defun container-effective-restart-policy (pod name)
  "Successful ordinary init containers never restart under a Pod's Always policy."
  (if (and (pod-init-container-p pod name) (equal "Always" (pod-restart-policy pod)))
      "OnFailure"
      (pod-restart-policy pod)))

(defun init-container-succeeded-p (status)
  "Require an observed zero exit, never an absent container or a running process."
  (let ((termination (and status (gethash "terminated" (gethash "state" status)))))
    (and termination (eql 0 (gethash "exitCode" termination)))))

(defun pod-initialization-complete-p (pod status)
  "Require one successful status for every declared ordinary init container."
  (loop for spec across (pod-init-containers pod)
        always (init-container-succeeded-p
                (find (container-spec-name spec) (gethash "initContainerStatuses" status)
                      :test #'equal :key (lambda (item) (gethash "name" item))))))

(defun remember-init-container-declarations (state pod)
  "Checkpoint name and image declarations before any init or application CRI work."
  (when (plusp (length (pod-init-containers pod)))
    (labels ((declarations (specs)
               (map 'vector (lambda (spec) (core-object "name" (container-spec-name spec)
                                                       "image" (container-spec-image spec))) specs)))
      (setf (gethash "initDeclarations" state) (declarations (pod-init-containers pod))
            (gethash "appDeclarations" state) (declarations (pod-containers pod))
            (gethash "restartPolicy" state) (pod-restart-policy pod))))
  state)

(defun initializing-container-status (declaration)
  "Represent a declared container that has not yet been allowed to start."
  (core-object "name" (gethash "name" declaration) "image" (gethash "image" declaration)
               "imageID" "" "restartCount" 0 "ready" nil "started" nil
               "state" (core-object "waiting" (core-object "reason" "PodInitializing"))))

(defun apply-init-container-observation (observed state)
  "Separate actual init exits and keep application statuses waiting until all init work succeeds."
  (when (and observed (gethash "initDeclarations" state))
    (let* ((status (runtime-pod-status observed))
           (all (concatenate 'vector (gethash "containerStatuses" status #())
                              (gethash "initContainerStatuses" status #())))
           (inits (map 'vector
                       (lambda (decl)
                         (let ((item (or (find (gethash "name" decl) all :test #'equal
                                               :key (lambda (item) (gethash "name" item)))
                                         (initializing-container-status decl))))
                           (setf (gethash "ready" item) (not (null (init-container-succeeded-p item))))
                           item))
                       (gethash "initDeclarations" state)))
           (complete (every #'init-container-succeeded-p inits))
           (failed (some (lambda (item)
                           (let ((exit (gethash "terminated" (gethash "state" item))))
                             (and exit (not (eql 0 (gethash "exitCode" exit)))))) inits))
           (apps (map 'vector
                      (lambda (decl)
                        (or (find (gethash "name" decl) all :test #'equal :key (lambda (item) (gethash "name" item)))
                            (initializing-container-status decl)))
                      (gethash "appDeclarations" state))))
      (setf (gethash "initContainerStatuses" status) inits
            (gethash "containerStatuses" status) apps)
      (setf (runtime-pod-phase observed)
            (cond
              ((gethash "terminalShutdown" state)
               ;; Finalizer retention must not leave a physically stopped
               ;; Always Pod Pending merely because init was interrupted.
               (if (and complete (every (lambda (item) (gethash "terminated" (gethash "state" item))) apps))
                   (container-lifecycle-phase apps t)
                   "Failed"))
              (complete
               (container-lifecycle-phase apps (not (equal "Unknown" (runtime-pod-phase observed)))))
              (t (if (and failed (equal "Never" (gethash "restartPolicy" state))) "Failed" "Pending"))))))
  observed)

(defun container-lifecycle-all-statuses (observed)
  "Collect both real status arrays when persisting native attempt history."
  (let ((status (runtime-pod-status observed)))
    (concatenate 'vector (gethash "containerStatuses" status #()) (gethash "initContainerStatuses" status #()))))

(defun next-pod-container-specs (pod current state)
  "Admit just the first incomplete init container, or all apps after genuine init success."
  (let ((statuses (container-lifecycle-statuses current state)))
    (loop for spec across (pod-init-containers pod)
          for status = (find (container-spec-name spec) statuses :test #'equal
                             :key (lambda (item) (gethash "name" item)))
          unless (init-container-succeeded-p status)
            do (return-from next-pod-container-specs
                 (if (and (equal "Never" (pod-restart-policy pod)) status
                          (gethash "terminated" (gethash "state" status)))
                     #()
                     (vector spec)))))
  (pod-containers pod))

(defun retained-init-failure-terminal-p (pod state)
  "Preserve a Never Pod's actual failed initialization after its CRI sandbox disappears."
  (and (equal "Never" (pod-restart-policy pod))
       (loop with statuses = (container-lifecycle-statuses nil state)
             for spec across (pod-init-containers pod)
             for status = (find (container-spec-name spec) statuses :test #'equal
                                :key (lambda (item) (gethash "name" item)))
             for terminated = (and status (gethash "terminated" (gethash "state" status)))
             thereis (and terminated (not (eql 0 (gethash "exitCode" terminated)))))))

(defun reset-init-containers-for-new-sandbox (state pod)
  "Reexecute initialization on a replacement sandbox while preserving consumed attempt numbers."
  (loop for spec across (pod-init-containers pod)
        for entry = (gethash (container-spec-name spec) (gethash "containers" state))
        when entry do (dolist (key '("lastStatus" "lastTermination" "restartSuppressed" "nextStart" "lastExitID"))
                        (remhash key entry)))
  state)
