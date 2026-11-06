;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Execute ordinary Kubernetes init containers in declaration order, deriving
;;;; initialization and application admission from real CRI exit observations.
;;;; Persist declarations alongside attempt history so read-only observations
;;;; and process recovery keep init statuses separate from application status.

(in-package #:gr8s)

(defun parse-init-container (object)
  "Validate an init container: only a restartable sidecar may define probes or lifecycle hooks.
As validateInitContainerRestartPolicy allows with ContainerRestartRules, an ordinary init container
may override the Pod's policy with OnFailure or Never and restart rules of its own."
  (require-object object "init container")
  (when (eq (gethash "restartPolicy" object) 'null) (remhash "restartPolicy" object))
  (unless (equal "Always" (gethash "restartPolicy" object))
    (dolist (key '("startupProbe" "readinessProbe" "livenessProbe" "lifecycle"))
      (when (nth-value 1 (gethash key object))
        (invalid-pod "ordinary init containers cannot define ~A" key))))
  (parse-container object))

(defun pod-init-container-p (pod name)
  "Find NAME among POD's ordered init declarations."
  (find name (pod-init-containers pod) :test #'equal :key #'container-spec-name))

(defun pod-sidecar-p (pod name)
  "Return whether NAME is one of POD's restartable init containers."
  (member name (pod-sidecar-names pod) :test #'equal))

(defun validate-container-restart-rules (container)
  "Validate an application container's restartPolicy and restartPolicyRules, which override the
Pod's restartPolicy for it (ContainerRestartRules, beta in v1.36). Only the Restart action exists here."
  (dolist (field '("restartPolicy" "restartPolicyRules"))
    (when (eq (gethash field container) 'null) (remhash field container)))
  (let ((policy (gethash "restartPolicy" container))
        (rules (optional-vector container "restartPolicyRules" "container")))
    (when (and policy (not (member policy '("Always" "OnFailure" "Never") :test #'equal)))
      (invalid-pod "container restartPolicy ~S must be Always, OnFailure or Never" policy))
    (when (and (plusp (length rules)) (null policy))
      (invalid-pod "container restartPolicy: Required value: must specify restartPolicy when restart rules are used"))
    (when (> (length rules) 20)
      (invalid-pod "container restartPolicyRules: Too many: must have at most 20 items"))
    (loop for rule across rules
          do (drop-null-fields (require-object rule "restartPolicyRule"))
             (reject-unsupported-fields rule '("action" "exitCodes") "restartPolicyRule")
             ;; RestartAllContainersOnContainerExits is beta and on by default since v1.36.
             (unless (member (gethash "action" rule) '("Restart" "RestartAllContainers") :test #'equal)
               (invalid-pod "restartPolicyRules.action: Unsupported value: ~S: supported values: \"Restart\", \"RestartAllContainers\""
                            (gethash "action" rule)))
             (let ((codes (gethash "exitCodes" rule)))
               (unless codes (invalid-pod "restartPolicyRules.exitCodes: Required value: must be specified"))
               (drop-null-fields (require-object codes "restartPolicyRules.exitCodes"))
               (reject-unsupported-fields codes '("operator" "values") "restartPolicyRules.exitCodes")
               (unless (member (gethash "operator" codes) '("In" "NotIn") :test #'equal)
                 (invalid-pod "restartPolicyRules.exitCodes.operator ~S must be In or NotIn" (gethash "operator" codes)))
               (let ((values (optional-vector codes "values" "restartPolicyRules.exitCodes")))
                 (when (> (length values) 255)
                   (invalid-pod "restartPolicyRules.exitCodes.values: Too many: must have at most 255 items"))
                 (unless (every (lambda (value) (typep value '(signed-byte 32))) values)
                   (invalid-pod "restartPolicyRules.exitCodes.values must be int32 exit codes")))))))

(defun pod-container-declaration (pod name)
  "Return the JSON declaration of POD's application or init container NAME, or NIL."
  (let ((spec (gethash "spec" (pod-to-object pod))))
    (find name (concatenate 'vector (gethash "containers" spec #()) (gethash "initContainers" spec #()))
          :test #'equal :key (lambda (object) (gethash "name" object)))))

(defun container-exit-rule (pod name exit-code)
  "Return the first of container NAME's restartPolicyRules matching EXIT-CODE, or NIL."
  (let ((declaration (pod-container-declaration pod name)))
    (and declaration
         (find-if (lambda (rule)
                    (let* ((codes (gethash "exitCodes" rule))
                           (member (member exit-code (coerce (gethash "values" codes #()) 'list))))
                      (if (equal "In" (gethash "operator" codes)) member (not member))))
                  (gethash "restartPolicyRules" declaration #())))))

(defun container-exit-restarts-all-p (pod name exit-code)
  "Return whether container NAME exiting with EXIT-CODE restarts every container of POD in place."
  (let ((rule (container-exit-rule pod name exit-code)))
    (and rule (equal "RestartAllContainers" (gethash "action" rule)))))

(defun container-restarts-after-exit-p (pod name exit-code &optional killed)
  "Decide, as a kubelet does, whether container NAME of POD runs again after exiting with EXIT-CODE.
KILLED marks an exit the node caused, such as a failed liveness probe, which counts as a failure.
An application container's restartPolicyRules are tried in order, then its own restartPolicy,
then the Pod's."
  (let* ((declaration (pod-container-declaration pod name))
         (rule (container-exit-rule pod name exit-code))
         (policy (or (and declaration (gethash "restartPolicy" declaration))
                     (container-effective-restart-policy pod name))))
    (cond (rule (equal "Restart" (gethash "action" rule)))
          ((equal "Always" policy) t)
          ((equal "OnFailure" policy) (or killed (not (eql 0 exit-code))))
          (t nil))))

(defun container-effective-restart-policy (pod name)
  "Sidecars always restart, ephemeral containers never do; finished init containers never restart under Always."
  (cond ((pod-sidecar-p pod name) "Always")
        ((find name (pod-ephemeral-containers pod) :test #'equal :key #'container-spec-name) "Never")
        ((and (pod-init-container-p pod name) (equal "Always" (pod-restart-policy pod))) "OnFailure")
        (t (pod-restart-policy pod))))

(defun init-container-succeeded-p (status)
  "Require an observed zero exit, never an absent container or a running process."
  (let ((termination (and status (gethash "terminated" (gethash "state" status)))))
    (and termination (eql 0 (gethash "exitCode" termination)))))

(defun container-status-started-p (status)
  "Return whether a sidecar's STATUS shows it running with any startup probe passed."
  (and status (hash-table-p (gethash "state" status)) (gethash "running" (gethash "state" status))
       (eq t (gethash "started" status))))

(defun container-status-ever-ran-p (status)
  "Return whether STATUS shows a container that has been started at all."
  (and status (hash-table-p (gethash "state" status))
       (or (gethash "running" (gethash "state" status)) (gethash "terminated" (gethash "state" status)))
       t))

(defun init-container-complete-p (status sidecar applications-started)
  "An ordinary init container must succeed; a sidecar must start, and once applications run it has."
  (if sidecar
      (or applications-started (container-status-started-p status))
      (init-container-succeeded-p status)))

(defun pod-initialization-complete-p (pod status)
  "Require every declared init container to have finished its part of initialization."
  (let ((started (some #'container-status-ever-ran-p (gethash "containerStatuses" status #()))))
    (loop for spec across (pod-init-containers pod)
          for name = (container-spec-name spec)
          always (init-container-complete-p
                  (find name (gethash "initContainerStatuses" status)
                        :test #'equal :key (lambda (item) (gethash "name" item)))
                  (pod-sidecar-p pod name) started))))

(defun remember-init-container-declarations (state pod)
  "Checkpoint name and image declarations before any init or application CRI work."
  (when (plusp (length (pod-init-containers pod)))
    (labels ((declarations (specs)
               (map 'vector (lambda (spec)
                              (let* ((name (container-spec-name spec))
                                     (declaration (core-object "name" name "image" (container-spec-image spec)))
                                     (object (pod-container-declaration pod name)))
                                (when (pod-sidecar-p pod name)
                                  (setf (gethash "sidecar" declaration) t))
                                ;; Read-only observations decide init failure from these.
                                (dolist (field '("restartPolicy" "restartPolicyRules"))
                                  (when (and object (gethash field object))
                                    (setf (gethash field declaration) (copy-core-object (gethash field object)))))
                                declaration))
                    specs)))
      (setf (gethash "initDeclarations" state) (declarations (pod-init-containers pod))
            (gethash "appDeclarations" state) (declarations (pod-containers pod))
            (gethash "restartPolicy" state) (pod-restart-policy pod))))
  state)

(defun init-declaration-exit-continues-p (declaration pod-policy exit-code)
  "Return whether an ordinary init container DECLARATION runs again, or restarts every container,
after EXIT-CODE: any matching restart rule acts, then its own restartPolicy, then the Pod's POD-POLICY,
under which Always restarts a failed init container as OnFailure does."
  (let ((rule (find-if (lambda (rule)
                         (let* ((codes (gethash "exitCodes" rule))
                                (member (member exit-code (coerce (gethash "values" codes #()) 'list))))
                           (if (equal "In" (gethash "operator" codes)) member (not member))))
                       (gethash "restartPolicyRules" declaration #())))
        (policy (or (gethash "restartPolicy" declaration) (if (equal "Always" pod-policy) "OnFailure" pod-policy))))
    (cond (rule t)
          ((equal "Always" policy) t)
          ((equal "OnFailure" policy) (not (eql 0 exit-code)))
          (t nil))))

(defun initializing-container-status (declaration)
  "Represent a declared container that has not yet been allowed to start."
  (core-object "name" (gethash "name" declaration) "image" (gethash "image" declaration)
               "imageID" "" "restartCount" 0 "ready" nil "started" nil
               "state" (core-object "waiting" (core-object "reason" "PodInitializing"))))

(defun apply-init-container-observation (observed state)
  "Separate actual init exits and keep application statuses waiting until all init work succeeds."
  ;; The control plane turns this report into the Pod's own condition.
  (when (and observed (gethash "resizePending" state))
    (setf (gethash "conditions" (runtime-pod-status observed))
          (vector (copy-core-object (gethash "resizePending" state)))))
  (when (and observed (gethash "initDeclarations" state))
    (let* ((status (runtime-pod-status observed))
           (all (concatenate 'vector (gethash "containerStatuses" status #())
                              (gethash "initContainerStatuses" status #())))
           (declarations (gethash "initDeclarations" state))
           (inits (map 'vector
                       (lambda (decl)
                         (let ((item (or (find (gethash "name" decl) all :test #'equal
                                               :key (lambda (item) (gethash "name" item)))
                                         (initializing-container-status decl))))
                           (unless (gethash "sidecar" decl)
                             (setf (gethash "ready" item) (not (null (init-container-succeeded-p item)))))
                           item))
                       declarations))
           (apps (map 'vector
                      (lambda (decl)
                        (or (find (gethash "name" decl) all :test #'equal :key (lambda (item) (gethash "name" item)))
                            (initializing-container-status decl)))
                      (gethash "appDeclarations" state)))
           (started (some #'container-status-ever-ran-p apps))
           (complete (every (lambda (item decl)
                              (init-container-complete-p item (gethash "sidecar" decl) started))
                            inits declarations))
           (failed (some (lambda (item decl)
                           (let ((exit (gethash "terminated" (gethash "state" item))))
                             (and exit (not (gethash "sidecar" decl)) (not (eql 0 (gethash "exitCode" exit)))
                                  (not (init-declaration-exit-continues-p decl (gethash "restartPolicy" state)
                                                                          (gethash "exitCode" exit))))))
                         inits declarations))
           (sidecar-running (some (lambda (item decl)
                                    (and (gethash "sidecar" decl) (gethash "running" (gethash "state" item))))
                                  inits declarations)))
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
               (let ((phase (container-lifecycle-phase apps (not (equal "Unknown" (runtime-pod-phase observed))))))
                 ;; The Pod is not finished until its sidecars have stopped too.
                 (if (and sidecar-running (member phase '("Succeeded" "Failed") :test #'equal)) "Running" phase)))
              (t (if (and failed (not sidecar-running)) "Failed" "Pending"))))))
  observed)

(defun container-lifecycle-all-statuses (observed)
  "Collect both real status arrays when persisting native attempt history."
  (let ((status (runtime-pod-status observed)))
    (concatenate 'vector (gethash "containerStatuses" status #()) (gethash "initContainerStatuses" status #())
                 (gethash "ephemeralContainerStatuses" status #()))))

(defun pod-applications-finished-p (pod statuses)
  "Return whether every application container in STATUSES has finished for good."
  (loop for spec across (pod-containers pod)
        for status = (find (container-spec-name spec) statuses :test #'equal
                           :key (lambda (item) (gethash "name" item)))
        for terminated = (and status (gethash "terminated" (gethash "state" status)))
        always (and terminated
                    (not (container-restarts-after-exit-p
                          pod (container-spec-name spec) (gethash "exitCode" terminated))))))

(defun pod-sidecar-progress-required-p (pod status)
  "Return whether a sidecar should be restarted, or stopped because the Pod has nothing left to run."
  (let ((finished (or (pod-applications-finished-p pod (gethash "containerStatuses" status #()))
                      (pod-init-failed-for-good-p pod (gethash "initContainerStatuses" status #())))))
    (loop for name in (pod-sidecar-names pod)
          for item = (find name (gethash "initContainerStatuses" status #()) :test #'equal
                           :key (lambda (entry) (gethash "name" entry)))
          for running = (and item (gethash "running" (gethash "state" item)))
          thereis (if finished running (not running)))))

(defun next-pod-container-specs (pod current state &optional runtime)
  "Admit started sidecars and the first incomplete init container, or all apps after genuine init success.
Sidecars stay admitted so they restart; nothing is started again once applications have finished."
  (let* ((statuses (container-lifecycle-statuses current state))
         (sidecars (pod-sidecar-names pod))
         (admitted nil))
    (when (and sidecars runtime)
      ;; A sidecar's startup probe decides when the next container may start.
      (apply-container-probe-observation
       runtime (make-runtime-pod :uid (pod-uid pod) :status (core-object "containerStatuses" statuses))))
    (when (and sidecars (or (pod-applications-finished-p pod statuses)
                            (pod-init-failed-for-good-p pod statuses)))
      (return-from next-pod-container-specs #()))
    ;; Ephemeral containers are only ever started beside a workload already underway.
    (setf statuses (separate-ephemeral-statuses statuses state))
    (let ((applications-started
            (some (lambda (status)
                    (and (container-status-ever-ran-p status)
                         (find (gethash "name" status) (pod-containers pod) :test #'equal :key #'container-spec-name)))
                  statuses)))
      (loop for spec across (pod-init-containers pod)
            for name = (container-spec-name spec)
            for status = (find name statuses :test #'equal
                               :key (lambda (item) (gethash "name" item)))
            for sidecar = (member name sidecars :test #'equal)
            do (when sidecar (push spec admitted))
               (unless (init-container-complete-p status sidecar applications-started)
                 (return-from next-pod-container-specs
                   (cond (sidecar (coerce (reverse admitted) 'vector))
                         ;; An exit that won't be retried ends initialization here.
                         ((and status (gethash "terminated" (gethash "state" status))
                               (not (container-restarts-after-exit-p
                                     pod name (gethash "exitCode" (gethash "terminated" (gethash "state" status))))))
                          (coerce (reverse admitted) 'vector))
                         (t (coerce (reverse (cons spec admitted)) 'vector)))))))
    (concatenate 'vector (reverse admitted) (pod-containers pod) (pod-ephemeral-containers pod))))

(defun pod-init-failed-for-good-p (pod statuses)
  "Return whether an ordinary init container in STATUSES failed a Pod that will never retry it.
A sidecar's own exit does not count: its restartPolicy restarts it whatever the Pod's says. Nor does
an exit its restart rules answer, by restarting it or every container."
  (loop with sidecars = (pod-sidecar-names pod)
        for spec across (pod-init-containers pod)
        for name = (container-spec-name spec)
        for status = (find name statuses :test #'equal :key (lambda (item) (gethash "name" item)))
        for terminated = (and status (gethash "terminated" (gethash "state" status)))
        for code = (and terminated (gethash "exitCode" terminated))
        thereis (and terminated (not (eql 0 code))
                     (not (member name sidecars :test #'equal))
                     (not (container-restarts-after-exit-p pod name code))
                     (not (container-exit-restarts-all-p pod name code)))))

(defun retained-init-failure-terminal-p (pod state)
  "Preserve a Never Pod's actual failed initialization after its CRI sandbox disappears."
  (pod-init-failed-for-good-p pod (container-lifecycle-statuses nil state)))

(defun reset-init-containers-for-new-sandbox (state pod)
  "Reexecute initialization on a replacement sandbox while preserving consumed attempt numbers."
  (loop for spec across (pod-init-containers pod)
        for entry = (gethash (container-spec-name spec) (gethash "containers" state))
        when entry do (dolist (key '("lastStatus" "lastTermination" "restartSuppressed" "nextStart" "lastExitID"))
                        (remhash key entry)))
  state)
