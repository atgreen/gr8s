;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Reconcile native containers independently, retaining sandbox identity and
;;;; healthy siblings. Checkpoint retry deadlines and last termination state
;;;; before starting another attempt, and recover from ambiguous CRI replies.

(in-package #:gr8s)

(defun container-lifecycle-now ()
  "Return wall time with subsecond precision for durable CRI restart deadlines."
  #+sbcl (multiple-value-bind (seconds microseconds) (sb-ext:get-time-of-day)
           (+ 2208988800 seconds (/ microseconds 1000000d0)))
  #-sbcl (get-universal-time))

(defparameter *container-lifecycle-clock* #'container-lifecycle-now
  "Wall clock for durable restart deadlines; bound by lifecycle regression tests.")

(defun container-attempt-log-path (name attempt)
  "Keep the first log path compatible and separate subsequent container attempts."
  (if (zerop attempt) (format nil "~A.log" name) (format nil "~A.~D.log" name attempt)))

(defun container-lifecycle-path (runtime uid)
  "Return UID's private durable native lifecycle checkpoint."
  (merge-pathnames "lifecycle.json" (containerd-pod-log-directory runtime uid)))

(defun load-container-lifecycle-state (runtime uid)
  "Load only a checkpoint belonging to UID; absent checkpoints start empty."
  (let* ((path (container-lifecycle-path runtime uid))
         (state (if (probe-file path) (com.inuoe.jzon:parse path)
                    (core-object "version" 1 "uid" uid "containers" (core-object)))))
    (unless (and (hash-table-p state) (eql 1 (gethash "version" state))
                 (equal uid (gethash "uid" state)) (hash-table-p (gethash "containers" state)))
      (error 'runtime-error :message "Invalid native container lifecycle checkpoint"))
    state))

(defun %save-container-lifecycle-state (runtime uid state)
  "Atomically replace retry state while the caller holds the lifecycle write lock."
  (let* ((path (container-lifecycle-path runtime uid))
         (temporary (make-pathname :name (format nil "lifecycle-~36R" (random (expt 36 10)))
                                   :type "tmp" :defaults path)))
    (ensure-directories-exist path)
    (unwind-protect
         (progn
           (with-open-file (out temporary :direction :output :if-exists :supersede :if-does-not-exist :create)
             (com.inuoe.jzon:stringify state :stream out))
           (uiop:rename-file-overwriting-target temporary path))
      (when (probe-file temporary) (delete-file temporary))))
  state)

(defun save-container-lifecycle-state (runtime uid state)
  "Serialize checkpoint replacement with deletion and shutdown Event preservation."
  (bt:with-lock-held ((containerd-runtime-lifecycle-lock runtime))
    (%save-container-lifecycle-state runtime uid state)))

(defun forget-container-lifecycle-state (runtime uid)
  "Remove retry state after UID's runtime sandbox is actually gone."
  (bt:with-lock-held ((containerd-runtime-lifecycle-lock runtime))
    (let ((path (container-lifecycle-path runtime uid)))
      (when (probe-file path) (delete-file path)))))

(defun known-container-attempt (entry)
  "Return the highest consumed attempt known from a checkpoint, or -1 before initial creation."
  (if entry
      (max (gethash "highestKnownAttempt" entry -1)
           (gethash "lastAttempt" entry -1)
           (1- (gethash "nextAttempt" entry 0))
           (gethash "restartCount" (gethash "lastStatus" entry (core-object)) -1))
      -1))

(defun retained-container-log-attempts (runtime uid)
  "Recover consumed attempts from the actual log files, including rotated names."
  (let ((attempts (make-hash-table :test #'equal)))
    (dolist (path (directory (merge-pathnames "*.*" (containerd-pod-log-directory runtime uid))))
      (let* ((parts (uiop:split-string (file-namestring path) :separator '(#\.)))
             (name (first parts))
             (attempt
               (cond
                 ((equal "log" (second parts)) 0)
                 ((and (equal "log" (third parts)) (second parts)
                       (plusp (length (second parts))) (every #'digit-char-p (second parts)))
                  (parse-integer (second parts))))))
        (when (and attempt (dns-label-p name))
          (setf (gethash name attempts) (max attempt (gethash name attempts -1))))))
    attempts))

(defun incorporate-container-log-history (runtime uid state)
  "Add real retained log evidence to an in-memory checkpoint; readers do not persist it."
  (maphash
   (lambda (name attempt)
     (let ((entry (or (gethash name (gethash "containers" state)) (core-object))))
       (setf (gethash "highestKnownAttempt" entry) (max attempt (known-container-attempt entry))
             (gethash name (gethash "containers" state)) entry)))
   (retained-container-log-attempts runtime uid))
  state)

(defun remember-container-lifecycle-statuses (state statuses)
  "Retain actual observed attempts and states without overwriting them with synthesized waiting states."
  (loop for status across statuses
        for name = (gethash "name" status)
        for attempt = (gethash "restartCount" status -1)
        for entry = (or (gethash name (gethash "containers" state)) (core-object))
        when (and (stringp name) (integerp attempt) (<= 0 attempt)
                  ;; A declared PodInitializing placeholder has consumed no
                  ;; CRI attempt. Counting it would skip attempt zero when a
                  ;; later init container is finally admitted.
                  (or (let ((id (gethash "containerID" status)))
                        (and (stringp id) (plusp (length id))))
                      (<= 0 (known-container-attempt entry)))
                  (>= attempt (known-container-attempt entry)))
          do (setf (gethash "highestKnownAttempt" entry) attempt)
             (when (or (gethash "running" (gethash "state" status (core-object)))
                       (gethash "terminated" (gethash "state" status (core-object))))
               (setf (gethash "lastStatus" entry) (copy-core-object status)))
             (setf (gethash name (gethash "containers" state)) entry))
  state)

(defun checkpoint-container-lifecycle-observation (runtime uid observed)
  "Persist an actual reconciliation observation, leaving read-only runtime/log operations side-effect free."
  (let* ((state (load-container-lifecycle-state runtime uid))
         (before (copy-core-object state)))
    (incorporate-container-log-history runtime uid state)
    (remember-container-lifecycle-statuses state (container-lifecycle-all-statuses observed))
    (unless (equalp before state) (save-container-lifecycle-state runtime uid state))
    state))

(defun current-container-infos (infos state)
  "Exclude old predecessors when a newer consumed attempt has lost its CRI metadata."
  (remove-if
   (lambda (info)
     (< (cri-container-info-attempt info)
        (known-container-attempt (gethash (cri-container-info-name info) (gethash "containers" state)))))
   (latest-container-infos infos)))

(defun retained-container-status (name entry)
  "Return an actual retained terminal status, or truthful waiting status when metadata is missing."
  (let* ((saved (gethash "lastStatus" entry))
         (saved-termination (and saved (gethash "terminated" (gethash "state" saved (core-object)))))
         (termination (or saved-termination (gethash "lastTermination" entry)))
         (attempt (known-container-attempt entry))
         (saved-attempt (if saved (gethash "restartCount" saved -1)
                            (gethash "lastAttempt" entry (1- (gethash "nextAttempt" entry 0)))))
         (terminal-current (and termination (or saved-termination (null saved)) (= saved-attempt attempt)))
         (status (if saved (copy-core-object saved)
                     (core-object "name" name "image" "" "imageID" "" "ready" nil "started" nil)))
         (waiting (and terminal-current (not (gethash "restartSuppressed" entry))
                       (gethash "nextStart" entry)
                       (equal (gethash "containerID" termination)
                              (format nil "containerd://~A" (gethash "lastExitID" entry))))))
    (cond
      ((and terminal-current (not waiting))
       (setf (gethash "state" status) (core-object "terminated" (copy-core-object termination))))
      (t
       (setf (gethash "state" status)
             (core-object "waiting" (core-object "reason" (if waiting "CrashLoopBackOff" "ContainerStatusUnknown"))))
       (when (gethash "lastTermination" entry)
         (setf (gethash "lastState" status) (core-object "terminated" (copy-core-object (gethash "lastTermination" entry)))))))
    (setf (gethash "restartCount" status) (max 0 attempt)
          (gethash "ready" status) nil (gethash "started" status) nil)
    status))

(defun container-lifecycle-statuses (infos state)
  "Combine current CRI observations with actual checkpoint/history for missing container names."
  (let* ((current (current-container-infos infos state))
         (statuses (mapcar (lambda (info) (container-lifecycle-status info state)) current)))
    (maphash
     (lambda (name entry)
       (unless (find name current :test #'equal :key #'cri-container-info-name)
         (when (or (gethash "lastStatus" entry) (gethash "lastTermination" entry)
                   (<= 0 (known-container-attempt entry)))
           (push (retained-container-status name entry) statuses))))
     (gethash "containers" state))
    (coerce (sort statuses #'string< :key (lambda (status) (gethash "name" status))) 'vector)))

(defun container-lifecycle-phase (statuses sandbox-ready-p)
  "Derive phase from actual retained exits even after the old sandbox becomes unavailable."
  (cond
    ((and (plusp (length statuses))
          (every (lambda (status) (gethash "terminated" (gethash "state" status))) statuses))
     (if (some (lambda (status) (not (zerop (gethash "exitCode" (gethash "terminated" (gethash "state" status)))))) statuses)
         "Failed" "Succeeded"))
    ((not sandbox-ready-p) "Unknown")
    ((some (lambda (status) (gethash "running" (gethash "state" status))) statuses) "Running")
    ((some (lambda (status) (equal "CrashLoopBackOff" (gethash "reason" (gethash "waiting" (gethash "state" status) (core-object))))) statuses)
     "Running")
    (t "Pending")))

(defun missing-container-restart-suppressed-p (pod entry &optional name)
  "Preserve completed policy decisions and a failed probe's exact-attempt intent."
  (let* ((saved (and entry (gethash "lastStatus" entry)))
         (terminated (and saved (gethash "terminated" (gethash "state" saved (core-object)))))
         (policy (container-effective-restart-policy pod (or name (and saved (gethash "name" saved)))))
         (probe (and entry (gethash "probeRestart" entry)))
         (probe-killed (and probe saved (equal (gethash "containerID" saved)
                                               (concatenate 'string "containerd://" (gethash "containerID" probe))))))
    (and entry
         (or (gethash "restartSuppressed" entry)
             (and probe-killed (equal "Never" policy))
             (and terminated (= (gethash "restartCount" saved 0) (known-container-attempt entry))
                  (or (equal "Never" policy)
                      (and (equal "OnFailure" policy)
                           (not probe-killed) (zerop (gethash "exitCode" terminated)))))))))

(defun latest-container-infos (infos)
  "Select one current CRI attempt per container name, independently of list order."
  (let ((latest (make-hash-table :test #'equal)))
    (dolist (info infos)
      (let* ((name (cri-container-info-name info)) (old (gethash name latest)))
        (when (or (null old)
                  (> (cri-container-info-attempt info) (cri-container-info-attempt old))
                  (and (= (cri-container-info-attempt info) (cri-container-info-attempt old))
                       (> (cri-container-info-started-at info) (cri-container-info-started-at old))))
          (setf (gethash name latest) info))))
    (sort (loop for info being the hash-values of latest collect info)
          #'string< :key #'cri-container-info-name)))

(defun container-lifecycle-status (info state)
  "Attach durable last termination state to a real current CRI observation."
  (let* ((status (containerd-container-status-object info))
         (entry (gethash (cri-container-info-name info) (gethash "containers" state)))
         (previous (and entry (gethash "lastTermination" entry))))
    (when (and previous (not (equal (cri-container-info-id info) (gethash "lastExitID" entry))))
      (setf (gethash "lastState" status) (core-object "terminated" (copy-core-object previous))))
    status))

(defun container-restart-eligible-p (pod info &optional state)
  "Apply policy to actual exits, including a completed probe-requested stop."
  (let ((policy (container-effective-restart-policy pod (and info (cri-container-info-name info)))))
    (and info (= (cri-container-info-state info) gr8s.cri.v1::+containerstate-container_exited+)
       (or (equal "Always" policy)
           (and (equal "OnFailure" policy)
                (or (not (zerop (cri-container-info-exit-code info)))
                    (let* ((entry (and state (gethash (cri-container-info-name info) (gethash "containers" state))))
                           (request (and entry (gethash "probeRestart" entry))))
                      (and request (equal (cri-container-info-id info) (gethash "containerID" request))))))))))

(defun native-container-progress-required-p (pod observed)
  "Avoid repeated CRI work for complete healthy or deliberately terminal observations."
  (when (and (plusp (length (pod-init-containers pod)))
             (not (pod-initialization-complete-p pod (runtime-pod-status observed))))
    (return-from native-container-progress-required-p
      (not (equal "Failed" (runtime-pod-phase observed)))))
  (when (equal "Unknown" (runtime-pod-phase observed))
    (return-from native-container-progress-required-p t))
  (let ((statuses (gethash "containerStatuses" (runtime-pod-status observed))))
    (loop for spec across (pod-containers pod)
          for status = (find (container-spec-name spec) statuses :test #'equal
                             :key (lambda (item) (gethash "name" item)))
          for state = (and status (gethash "state" status))
          for terminated = (and state (gethash "terminated" state))
          thereis (or (null state) (gethash "waiting" state)
                      (and terminated
                           (or (equal "Always" (pod-restart-policy pod))
                               (and (equal "OnFailure" (pod-restart-policy pod))
                                    (not (zerop (gethash "exitCode" terminated))))))))))

(defun prepare-container-restart (state info now)
  "Record an exit once and return its durable retry deadline and next attempt."
  (let* ((entries (gethash "containers" state)) (name (cri-container-info-name info))
         (old (gethash name entries)))
    (unless (and old (equal (gethash "lastExitID" old) (cri-container-info-id info)))
      (let* ((finished (+ 2208988800 (/ (cri-container-info-finished-at info) 1000000000d0)))
             (duration (/ (- (cri-container-info-finished-at info) (cri-container-info-started-at info)) 1000000000))
             (reset (or (null old) (null (gethash "lastFailureTime" old)) (>= duration 600)
                        (> (- now (gethash "lastFailureTime" old now)) 600)))
             ;; Like upstream doBackOff/Backoff.Next, the first retry creates
             ;; the backoff entry; subsequent short runs wait 10,20,...,300s.
             (delay (if reset 0 (gethash "backoff" old 10)))
             (entry (core-object "highestKnownAttempt" (max (cri-container-info-attempt info) (known-container-attempt old))
                                 "lastStatus" (containerd-container-status-object info)
                                 "lastExitID" (cri-container-info-id info)
                                 "lastFailureTime" now
                                 "nextAttempt" (1+ (cri-container-info-attempt info))
                                 "backoff" (if reset 10 (min 300 (* 2 delay)))
                                 "nextStart" (+ (if (plusp (cri-container-info-finished-at info)) finished now) delay)
                                 "lastTermination" (gethash "terminated" (gethash "state" (containerd-container-status-object info))))))
        (dolist (key '("probeState" "probeRestart"))
          (when (and old (gethash key old)) (setf (gethash key entry) (copy-core-object (gethash key old)))))
        (setf (gethash name entries) entry)))
    (gethash name entries)))

(defun containerd-sandbox-config (runtime pod)
  "Build the sandbox configuration used for initial and subsequent container attempts."
  (multiple-value-bind (servers searches options) (containerd-pod-dns-configuration runtime pod)
    (make-cri-pod-sandbox-config
     (pod-name pod) (pod-uid pod) (pod-namespace pod) 0
     (namestring (containerd-pod-log-directory runtime (pod-uid pod)))
     (containerd-runtime-host-network runtime)
     :resource-version (pod-resource-version pod) :spec-fingerprint (pod-runtime-spec-fingerprint pod)
     :privileged (pod-requests-privileged-container-p pod)
     :hostname (pod-runtime-hostname pod)
     :security (containerd-pod-sandbox-security pod)
     :dns-servers servers :dns-searches searches :dns-options options)))

(defun containerd-start-sandbox (runtime pod)
  "Create the native sandbox once; partial container creation never withdraws it."
  (multiple-value-bind (servers searches options) (containerd-pod-dns-configuration runtime pod)
    (let ((directory (containerd-pod-log-directory runtime (pod-uid pod))))
      (ensure-directories-exist directory)
      (make-cri-pod-sandbox-info
       :id (cri-run-pod-sandbox
            (containerd-runtime-socket-path runtime)
            :name (pod-name pod) :uid (pod-uid pod) :namespace (pod-namespace pod)
            :log-directory (namestring directory) :host-network (containerd-runtime-host-network runtime)
            :resource-version (pod-resource-version pod) :spec-fingerprint (pod-runtime-spec-fingerprint pod)
            :privileged (pod-requests-privileged-container-p pod)
            :hostname (pod-runtime-hostname pod)
            :security (containerd-pod-sandbox-security pod)
            :runtime-handler (pod-runtime-handler pod)
            :dns-servers servers :dns-searches searches :dns-options options)))))

(defun containerd-prune-old-attempts (runtime infos &optional created-names)
  "Keep the latest attempt and one predecessor per name, bounding dead CRI objects."
  (let ((counts (make-hash-table :test #'equal)))
    (dolist (info (stable-sort (copy-list infos) #'> :key #'cri-container-info-attempt))
      (when (and (> (incf (gethash (cri-container-info-name info) counts 0))
                    (if (member (cri-container-info-name info) created-names :test #'equal) 1 2))
                 (= (cri-container-info-state info) gr8s.cri.v1::+containerstate-container_exited+))
        (cri-delete-container (containerd-runtime-socket-path runtime) (cri-container-info-id info))))))

(defun containerd-stop-unknown-attempts (runtime infos)
  "Resolve only current Unknown attempts through a real stop/status before applying restart policy."
  (let ((socket (containerd-runtime-socket-path runtime)))
    (mapcar (lambda (info)
              (if (= (cri-container-info-state info) gr8s.cri.v1::+containerstate-container_unknown+)
                  (progn
                    (cri-stop-container socket (cri-container-info-id info))
                    (cri-container-status socket (cri-container-info-id info)))
                  info))
            infos)))

(defun containerd-capture-dead-sandbox (runtime pod sandbox state)
  "Retain actual stopped attempts and their policy before replacing a failed sandbox."
  (let ((socket (containerd-runtime-socket-path runtime))
        (now (funcall *container-lifecycle-clock*))
        (infos nil))
    (setf (gethash "resourceVersion" state)
          (or (cdr (assoc +gr8s-resource-version-label+ (cri-pod-sandbox-info-labels sandbox) :test #'equal)) "")
          (gethash "specFingerprint" state)
          (cdr (assoc +gr8s-spec-fingerprint-label+ (cri-pod-sandbox-info-labels sandbox) :test #'equal)))
    (dolist (summary (containerd-containers runtime sandbox))
      (let ((info (cri-container-status socket (cri-container-summary-id summary))))
        (unless (= (cri-container-info-state info) gr8s.cri.v1::+containerstate-container_exited+)
          (cri-stop-container socket (cri-container-info-id info))
          (setf info (cri-container-status socket (cri-container-info-id info))))
        (push info infos)))
    (dolist (info (current-container-infos infos state))
      (let* ((name (cri-container-info-name info))
             (old (gethash name (gethash "containers" state)))
             (eligible (container-restart-eligible-p pod info state))
             (entry (if eligible (prepare-container-restart state info now) (or old (core-object))))
             (status (containerd-container-status-object info)))
        (setf (gethash "lastAttempt" entry) (cri-container-info-attempt info)
              (gethash "highestKnownAttempt" entry)
              (max (if old (gethash "highestKnownAttempt" old 0) 0)
                   (gethash "highestKnownAttempt" entry 0) (cri-container-info-attempt info))
              (gethash "lastStatus" entry) status)
        (when (and (not eligible) (= (cri-container-info-state info) gr8s.cri.v1::+containerstate-container_exited+))
          (setf (gethash "restartSuppressed" entry) t
                (gethash "lastExitID" entry) (cri-container-info-id info)
                (gethash "lastTermination" entry) (gethash "terminated" (gethash "state" status))))
        (setf (gethash name (gethash "containers" state)) entry)))
    (save-container-lifecycle-state runtime (pod-uid pod) state)
    infos))

(defun lifecycle-all-containers-suppressed-p (pod state)
  "Require retained real terminal observations before treating the whole Pod as finished."
  (loop for spec across (pod-containers pod)
        for entry = (gethash (container-spec-name spec) (gethash "containers" state))
        always (and entry (gethash "restartSuppressed" entry) (gethash "lastTermination" entry))))

(defun converge-containerd-containers (runtime pod)
  "Converge each declared container while retaining its unchanged sandbox and siblings."
  (let* ((uid (pod-uid pod)) (socket (containerd-runtime-socket-path runtime))
         (sandbox (containerd-owned-sandbox runtime uid))
         (state (incorporate-container-log-history runtime uid (load-container-lifecycle-state runtime uid))))
    (when (and sandbox
               (not (equal (pod-runtime-spec-fingerprint pod)
                           (cdr (assoc +gr8s-spec-fingerprint-label+ (cri-pod-sandbox-info-labels sandbox) :test #'equal)))))
      ;; A changed specification recreates containers, not the Pod: emptyDirs persist.
      (containerd-replace-uid runtime uid)
      (setf sandbox nil state (load-container-lifecycle-state runtime uid)))
    (when sandbox (refresh-pod-projected-volumes runtime pod))
    (incorporate-container-log-history runtime uid state)
    (remember-init-container-declarations state pod)
    (setf (gethash "resourceVersion" state) (pod-resource-version pod)
          (gethash "specFingerprint" state) (pod-runtime-spec-fingerprint pod))
    (when (and sandbox (/= gr8s.cri.v1::+podsandboxstate-sandbox_ready+ (cri-pod-sandbox-info-state sandbox)))
      (let ((prior (containerd-capture-dead-sandbox runtime pod sandbox state)))
        (when (or (lifecycle-all-containers-suppressed-p pod state)
                  (and (equal "Never" (pod-restart-policy pod))
                       (or prior (plusp (hash-table-count (gethash "containers" state))))))
          (return-from converge-containerd-containers (runtime-observe runtime uid)))
        (containerd-delete-uid runtime uid (funcall *pod-deletion-clock*) :preserve-lifecycle t)
        (setf sandbox nil)))
    (when (and (null sandbox) (lifecycle-all-containers-suppressed-p pod state))
      (return-from converge-containerd-containers (runtime-observe runtime uid)))
    (when (and (null sandbox) (retained-init-failure-terminal-p pod state))
      (return-from converge-containerd-containers (runtime-observe runtime uid)))
    (unless sandbox
      (reset-init-containers-for-new-sandbox state pod)
      (save-container-lifecycle-state runtime uid state)
      (setf sandbox (containerd-start-sandbox runtime pod)))
    (let* ((config (containerd-sandbox-config runtime pod))
           (infos (mapcar (lambda (summary) (cri-container-status socket (cri-container-summary-id summary)))
                          (containerd-containers runtime sandbox)))
           (current (containerd-stop-unknown-attempts runtime (current-container-infos infos state)))
           (now (funcall *container-lifecycle-clock*))
           (waiting (make-hash-table :test #'equal)) (restarting nil) (created-names nil))
      (remember-container-lifecycle-statuses state
        (map 'vector (lambda (info) (container-lifecycle-status info state)) current))
      (save-container-lifecycle-state runtime uid state)
      (loop for spec across (next-pod-container-specs pod current state)
            for name = (container-spec-name spec)
            for info = (find name current :key #'cri-container-info-name :test #'equal)
            do (cond
                 ((null info)
                  (let ((entry (gethash name (gethash "containers" state))))
                    (cond
                      ((missing-container-restart-suppressed-p pod entry name)
                       (setf (gethash "restartSuppressed" entry) t)
                       (save-container-lifecycle-state runtime uid state))
                      ((and entry (< now (gethash "nextStart" entry 0)))
                       (setf (gethash name waiting) entry restarting t))
                      (t
                       (let ((attempt (max (if entry (gethash "nextAttempt" entry 0) 0)
                                           (1+ (known-container-attempt entry)))))
                         (containerd-create-container runtime pod (cri-pod-sandbox-info-id sandbox) config spec :attempt attempt)
                         (setf entry (or entry (core-object))
                               (gethash "highestKnownAttempt" entry) attempt
                               (gethash name (gethash "containers" state)) entry)
                         (save-container-lifecycle-state runtime uid state)
                         (push name created-names))))))
                 ((= (cri-container-info-state info) gr8s.cri.v1::+containerstate-container_created+)
                  ;; An interrupted or ambiguous StartContainer must reuse the
                  ;; already created attempt instead of allocating another.
                  (cri-start-container socket (cri-container-info-id info)))
                 ((container-restart-eligible-p pod info state)
                  (let ((entry (prepare-container-restart state info now)))
                    (save-container-lifecycle-state runtime uid state)
                    (setf restarting t)
                    (if (< now (gethash "nextStart" entry))
                        (setf (gethash name waiting) entry)
                        (progn
                          (containerd-create-container runtime pod (cri-pod-sandbox-info-id sandbox) config spec
                                                       :attempt (gethash "nextAttempt" entry))
                          (setf (gethash "highestKnownAttempt" entry) (gethash "nextAttempt" entry))
                          (save-container-lifecycle-state runtime uid state)
                          (push name created-names)))))))
      (containerd-prune-old-attempts runtime infos created-names)
      (let* ((observed (runtime-observe runtime uid))
             (statuses (container-lifecycle-all-statuses observed)))
        (remember-container-lifecycle-statuses state (container-lifecycle-all-statuses observed))
        (save-container-lifecycle-state runtime uid state)
        (loop for status across statuses
              for entry = (gethash (gethash "name" status) waiting)
              when entry do
                (setf (gethash "state" status) (core-object "waiting" (core-object "reason" "CrashLoopBackOff"))
                      (gethash "lastState" status) (core-object "terminated" (copy-core-object (gethash "lastTermination" entry)))
                      (gethash "ready" status) nil (gethash "started" status) nil))
        (when (and restarting (pod-initialization-complete-p pod (runtime-pod-status observed)))
          (setf (runtime-pod-phase observed) "Running"))
        ;; An existing sandbox's creation revision may be older than a metadata
        ;; update. Reconciliation adopted the exact desired workload above.
        (setf (runtime-pod-resource-version observed) (pod-resource-version pod))
        observed))))
