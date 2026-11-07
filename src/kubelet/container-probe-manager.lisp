;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Run each container probe outside reconciliation, retaining exact attempt
;;;; identity, startup suppression, consecutive-result thresholds and bounded
;;;; periods. Reconciliation checkpoints real outcomes and requested stop
;;;; deadlines before asynchronously stopping only the failed native attempt.

(in-package #:gr8s.kubelet)

(defvar *container-probe-stop-owner* nil
  "The probe worker or stop job whose catch this thread is inside, bound only within that catch.")

(defmacro with-container-probe-stop ((owner) &body body)
  "Run BODY until STOP-CONTAINER-PROBE-THREAD throws out of it for OWNER, then return NIL.
Cancellation unwinds an owned probe operation without being converted to Failure."
  (let ((tag (gensym "OWNER")))
    `(let ((,tag ,owner))
       (catch ,tag
         (let ((*container-probe-stop-owner* ,tag))
           ,@body)))))

(defun stop-container-probe-thread (thread owner)
  "Unwind THREAD out of its WITH-CONTAINER-PROBE-STOP for OWNER. One that has left it ignores this.
Throw instead of signalling: the target may be inside %SIGNAL for another error, where SBCL
has rebound the handler clusters and an ERROR finds no handler and kills the thread
(podster-uqb.114). A throw also passes the handlers that record probe failures."
  (ignore-errors
    (bt:interrupt-thread thread (lambda ()
                                 (when (eq *container-probe-stop-owner* owner)
                                   (throw owner nil))))))

(defstruct container-probe-manager
  "Own probe targets and stop jobs for one native runtime."
  (targets (make-hash-table :test #'equal))
  (jobs (make-hash-table :test #'equal))
  (lock (bt:make-lock "native container probes"))
  (shutdown-lock (bt:make-lock "native probe shutdown"))
  (clock #'container-lifecycle-now)
  (executor #'execute-container-probe)
  (event-outbox (make-hash-table :test #'equal))
  (event-cursors (make-hash-table :test #'equal))
  stopping-p)

(defstruct container-probe-target
  "Bind all probes to one actual container ID and its authoritative declaration.
TERMINATING-P is set once the Pod is being deleted: only readiness still probes."
  uid name id container pod-ip started-at workers stopping-p terminating-p pod-name namespace)

(defstruct container-probe-worker
  "Track one probe kind's consecutive results independently of its siblings.
SUCCESSES, FAILURES and the latency of successful probes feed the kubelet's prober metrics."
  kind spec result last-result (count 0) (runs 0) next-due message
  failed-p on-hold-p inflight-p thread started-p finished-p
  (events (make-hash-table :test #'equal))
  (successes 0) (failures 0) (latencies nil))

(defstruct container-probe-stop-job
  "Own the asynchronous CRI stop of one exact failed container, running any preStop hook first."
  uid id pod deadline thread started-p finished-p failure cancelled-p)

(defun ensure-container-probe-manager (runtime)
  "Lazily allocate the native runtime's private asynchronous probe state."
  (or (containerd-runtime-probes runtime)
      (setf (containerd-runtime-probes runtime) (make-container-probe-manager))))

(defun probe-target-key (target)
  "Return the UID/name identity whose current attempt owns TARGET."
  (list (container-probe-target-uid target) (container-probe-target-name target)))

(defun current-probe-target-p (manager target)
  "Require exact target ownership before running or publishing a probe result."
  (and (not (container-probe-manager-stopping-p manager))
       (not (container-probe-target-stopping-p target))
       (eq target (gethash (probe-target-key target) (container-probe-manager-targets manager)))))

(defun probe-target-started-p (target)
  "Suppress liveness/readiness until the current startup worker has succeeded."
  (let ((startup (find "startupProbe" (container-probe-target-workers target) :test #'equal :key #'container-probe-worker-kind)))
    (or (null startup) (container-probe-worker-result startup))))

(defun bounded-probe-event-message (text)
  "Keep Event text within1024 UTF8 bytes without quadratic truncation work."
  (loop with bytes = 0 for character across text for end from 0
        for width = (let ((code (char-code character))) (cond ((< code 128) 1) ((< code 2048) 2) ((< code 65536) 3) (t 4)))
        when (> (+ bytes width) 1024) return (subseq text 0 end)
        do (incf bytes width)
        finally (return text)))

(defun record-container-probe-event (worker reason message now)
  "Count one final outcome Event independently of threshold state."
  (let ((entry (or (gethash reason (container-probe-worker-events worker))
                   (core-object "id" (generate-uid) "count" 0 "firstTimestamp" (current-timestamp (floor now))))))
    (setf (gethash "reason" entry) reason (gethash "message" entry) (bounded-probe-event-message message)
          (gethash "lastTimestamp" entry) (current-timestamp (floor now))
          (gethash "count" entry) (min 2147483647 (1+ (gethash "count" entry)))
          (gethash reason (container-probe-worker-events worker)) entry)))

(defun container-probe-worker-type (worker)
  "Return kubelet's display name for one worker's probe kind."
  (string-capitalize (subseq (container-probe-worker-kind worker) 0 (- (length (container-probe-worker-kind worker)) 5))))

(defun record-container-probe-error (worker message now result)
  "Publish the final prober error without changing consecutive results or thresholds."
  (record-container-probe-event worker "Unhealthy"
    (format nil "~A probe errored and resulted in ~A state: ~A" (container-probe-worker-type worker)
            (if (eq result :failure) "Failure" "Unknown") message) now))

(defun record-container-probe-result (worker success message &optional (now (container-lifecycle-now)) result-kind)
  "Apply consecutive success/failure thresholds without prematurely changing readiness."
  (when (or (not success) (eq result-kind :warning))
    (record-container-probe-event worker (if success "ProbeWarning" "Unhealthy")
      (format nil "~A probe ~A: ~A" (container-probe-worker-type worker) (if success "warning" "failed") message) now))
  (incf (container-probe-worker-runs worker))
  (setf (container-probe-worker-message worker) message)
  (if (eql success (container-probe-worker-last-result worker))
      (incf (container-probe-worker-count worker))
      (setf (container-probe-worker-last-result worker) success (container-probe-worker-count worker) 1))
  (when (>= (container-probe-worker-count worker)
            (gethash (if success "successThreshold" "failureThreshold") (container-probe-worker-spec worker)))
    (setf (container-probe-worker-result worker) success)
    (when (or (equal "startupProbe" (container-probe-worker-kind worker))
              (and (not success) (equal "livenessProbe" (container-probe-worker-kind worker))))
      (setf (container-probe-worker-on-hold-p worker) t
            (container-probe-worker-failed-p worker) (not success)))))

(defun execute-container-probe-with-retries (manager runtime target worker)
  "Retry only prober errors three times; real success/failure ends the current check."
  (loop for attempt below 3
        do (multiple-value-bind (success message kind result)
               (funcall (container-probe-manager-executor manager) runtime (container-probe-target-container target)
                        (container-probe-target-id target) (container-probe-target-pod-ip target) (container-probe-worker-spec worker))
             (when (or (not (eq kind :error)) (= attempt 2))
               (return (values success message kind result))))))

(defun step-container-probe (manager runtime target worker)
  "Run a due probe without holding the manager or reconciliation lock during I/O."
  (let ((run nil) (now (funcall (container-probe-manager-clock manager))))
    (bt:with-lock-held ((container-probe-manager-lock manager))
      (when (and (current-probe-target-p manager target)
                 (not (container-probe-worker-inflight-p worker))
                 (not (container-probe-worker-on-hold-p worker))
                 (or (equal "startupProbe" (container-probe-worker-kind worker)) (probe-target-started-p target))
                 (>= now (container-probe-worker-next-due worker)))
        (setf run t (container-probe-worker-inflight-p worker) t
              (container-probe-worker-next-due worker) (+ now (gethash "periodSeconds" (container-probe-worker-spec worker))))))
    (when run
      (unwind-protect
           (let ((began (get-internal-real-time)))
             (multiple-value-bind (success message result-kind error-result)
                 (execute-container-probe-with-retries manager runtime target worker)
               (bt:with-lock-held ((container-probe-manager-lock manager))
                 (when (and (current-probe-target-p manager target)
                            ;; A result that finishes after deletion began cannot fail a terminating container.
                            (not (and (container-probe-target-terminating-p target)
                                      (not (equal "readinessProbe" (container-probe-worker-kind worker))))))
                   (let ((completed (funcall (container-probe-manager-clock manager))))
                     (if (eq result-kind :error)
                         ;; As upstream's worker does, a prober error is no result and isn't counted.
                         (record-container-probe-error worker message completed error-result)
                         (progn
                           (if success
                               (progn (incf (container-probe-worker-successes worker))
                                      (observe-histogram
                                       (or (container-probe-worker-latencies worker)
                                           (setf (container-probe-worker-latencies worker)
                                                 (make-bucketed-histogram +prometheus-default-buckets+)))
                                       (/ (- (get-internal-real-time) began) internal-time-units-per-second)))
                               (incf (container-probe-worker-failures worker)))
                           (record-container-probe-result worker (not (null success)) message completed result-kind))))))))
        (bt:with-lock-held ((container-probe-manager-lock manager))
          (setf (container-probe-worker-inflight-p worker) nil))))))

(defun run-container-probe-worker (manager runtime target worker)
  "Keep an exact-attempt probe alive until ownership or runtime shutdown ends."
  (unwind-protect
       (with-container-probe-stop (worker)
         (bt:with-lock-held ((container-probe-manager-lock manager))
           (setf (container-probe-worker-started-p worker) t))
         (loop while (bt:with-lock-held ((container-probe-manager-lock manager)) (current-probe-target-p manager target))
               do (handler-case (step-container-probe manager runtime target worker)
                    (serious-condition (condition)
                      (format *error-output* "gr8s probe worker ~A/~A ~A failed: ~A~%"
                              (container-probe-target-uid target) (container-probe-target-name target)
                              (container-probe-worker-kind worker) condition)))
                  (sleep .05)))
    (setf (container-probe-worker-finished-p worker) t))
  nil)

(defun stop-container-probe-target (target)
  "Join already-retired probe workers; cancellation bypasses recoverable probe failures."
  (dolist (worker (container-probe-target-workers target))
    (let ((thread (container-probe-worker-thread worker)))
      (when (and thread (not (eq thread (bt:current-thread))))
        (when (and (container-probe-worker-started-p worker) (bt:thread-alive-p thread))
          (stop-container-probe-thread thread worker))
        (bt:join-thread thread))))
  nil)

(defparameter *container-probe-event-capacity* 4096
  "Bound cumulative retained occurrences across all Pod UIDs in one native runtime.")

(defun probe-event-live-p (event now)
  "Expire occurrences by their actual last occurrence, never by replay time."
  (handler-case
      (< now (+ (pod-deletion-time (gethash "lastTimestamp" event)) *event-ttl-seconds*))
    (error () nil)))

(defun retain-container-probe-event (manager uid event)
  "Coalesce exact UID/EventID records; caller holds the manager ownership lock."
  (let* ((key (list uid (gethash "id" event)))
         (old (gethash key (container-probe-manager-event-outbox manager))))
    (when (or (null old) (> (gethash "count" event) (gethash "count" old)))
      (setf (gethash key (container-probe-manager-event-outbox manager)) (copy-core-object event)))))

(defun retain-target-probe-events (manager target)
  "Retain an attempt's real occurrences independently of its probe ownership."
  (dolist (worker (container-probe-target-workers target))
    (maphash (lambda (reason event)
               (declare (ignore reason))
               (let ((copy (copy-core-object event)))
                 (setf (gethash "container" copy) (container-probe-target-name target)
                       (gethash "kind" copy) (container-probe-worker-kind worker))
                 (retain-container-probe-event manager (container-probe-target-uid target) copy)))
             (container-probe-worker-events worker))))

(defun prune-container-probe-events (manager now)
  "Bound outbox memory and expire old UIDs/cursors under the manager lock."
  (let ((outbox (container-probe-manager-event-outbox manager)) (entries nil)
        (uids (make-hash-table :test #'equal)))
    (maphash (lambda (key event)
               (if (probe-event-live-p event now) (push (cons key event) entries) (remhash key outbox))) outbox)
    ;; Overflow discards oldest occurrences first; Event delivery is best effort
    ;; under sustained pressure, and never allocates an unbounded retry queue.
    (when (> (length entries) *container-probe-event-capacity*)
      (setf entries (sort entries #'string< :key (lambda (entry) (gethash "lastTimestamp" (cdr entry)))))
      (loop repeat (- (length entries) *container-probe-event-capacity*)
            for entry in entries do (remhash (car entry) outbox)))
    (maphash (lambda (key event) (declare (ignore event)) (setf (gethash (first key) uids) t)) outbox)
    (maphash (lambda (uid cursor) (declare (ignore cursor))
               (unless (gethash uid uids) (remhash uid (container-probe-manager-event-cursors manager))))
             (container-probe-manager-event-cursors manager))))

(defun collect-container-probe-events (manager uid saved)
  "Merge durable and live occurrences and return UID's bounded cumulative map."
  (bt:with-lock-held ((container-probe-manager-lock manager))
    (when (hash-table-p saved)
      (maphash (lambda (id event) (declare (ignore id)) (retain-container-probe-event manager uid event)) saved))
    (maphash (lambda (key target) (declare (ignore key)) (retain-target-probe-events manager target))
             (container-probe-manager-targets manager))
    (prune-container-probe-events manager (funcall (container-probe-manager-clock manager)))
    (let ((result (core-object)))
      (maphash (lambda (key event)
                 (when (equal uid (first key)) (setf (gethash (second key) result) (copy-core-object event))))
               (container-probe-manager-event-outbox manager))
      result)))

(defun retire-container-probe-targets (manager predicate)
  "Withdraw matching target ownership atomically before cancellation or replacement."
  (let ((retired nil))
    (bt:with-lock-held ((container-probe-manager-lock manager))
      (maphash (lambda (key target)
                 (when (funcall predicate target)
                   (retain-target-probe-events manager target)
                   (setf (container-probe-target-stopping-p target) t)
                   (remhash key (container-probe-manager-targets manager))
                   (push target retired)))
               (container-probe-manager-targets manager))
      (prune-container-probe-events manager (funcall (container-probe-manager-clock manager))))
    (dolist (target retired) (stop-container-probe-target target))))

(defun make-native-probe-target (pod container status observed state)
  "Restore only actual same-attempt results and reset counters for a replacement."
  (let* ((name (gethash "name" container)) (id (subseq (gethash "containerID" status) (length "containerd://")))
         (saved (gethash "probeState" (gethash name (gethash "containers" state) (core-object))))
         (same (and saved (equal id (gethash "containerID" saved))))
         (detail (find id (runtime-pod-container-details observed) :test #'equal :key #'cri-container-info-id))
         (started (if (and detail (plusp (cri-container-info-started-at detail)))
                      (+ 2208988800 (/ (cri-container-info-started-at detail) 1000000000d0))
                      (pod-deletion-time (gethash "startedAt" (gethash "running" (gethash "state" status))))))
         (target (make-container-probe-target :uid (pod-uid pod) :name name :id id :container container
                                              :pod-ip (runtime-pod-pod-ip observed) :started-at started
                                              :pod-name (pod-name pod) :namespace (pod-namespace pod))))
    (setf (container-probe-target-workers target)
          (loop for kind in '("startupProbe" "livenessProbe" "readinessProbe") for spec = (gethash kind container)
                when spec
                  collect (make-container-probe-worker
                           :kind kind :spec spec :next-due (+ started (gethash "initialDelaySeconds" spec))
                           :result (cond ((equal kind "livenessProbe") t)
                                         ((equal kind "startupProbe") (and same (gethash "startupSucceeded" saved)))
                                         (t (and same (gethash "readinessSucceeded" saved))))
                           :on-hold-p (and (equal kind "startupProbe") same (gethash "startupSucceeded" saved)))))
    target))

(defun pod-probed-container-objects (pod)
  "Return the declarations that may have probes: POD's sidecars and applications."
  (let ((spec (gethash "spec" (pod-to-object pod))))
    (append (remove-if-not (lambda (object) (equal "Always" (gethash "restartPolicy" object)))
                           (coerce (gethash "initContainers" spec #()) 'list))
            (coerce (gethash "containers" spec) 'list))))

(defun sync-container-probe-targets (runtime pod observed &key (start-workers t))
  "Attach declared probes to actual running IDs; retire all stale attempt workers."
  (let* ((manager (ensure-container-probe-manager runtime))
         (state (load-container-lifecycle-state runtime (pod-uid pod)))
         (current nil) (created nil))
    (loop for container in (pod-probed-container-objects pod)
          for name = (gethash "name" container)
          for status = (find name (container-lifecycle-all-statuses observed) :test #'equal :key (lambda (value) (gethash "name" value)))
          when (and status (gethash "running" (gethash "state" status))
                    (some (lambda (kind) (gethash kind container)) '("startupProbe" "readinessProbe" "livenessProbe")))
            do (push (cons name (subseq (gethash "containerID" status) (length "containerd://"))) current))
    (retire-container-probe-targets manager
      (lambda (target)
        (and (equal (pod-uid pod) (container-probe-target-uid target))
             (not (equal (container-probe-target-id target) (cdr (assoc (container-probe-target-name target) current :test #'equal)))))))
    (dolist (entry current)
      (let* ((key (list (pod-uid pod) (car entry)))
             (existing (bt:with-lock-held ((container-probe-manager-lock manager)) (gethash key (container-probe-manager-targets manager)))))
        (unless existing
          (let* ((container (find (car entry) (pod-probed-container-objects pod) :test #'equal :key (lambda (item) (gethash "name" item))))
                 (status (find (car entry) (container-lifecycle-all-statuses observed) :test #'equal :key (lambda (item) (gethash "name" item))))
                 (target (make-native-probe-target pod container status observed state)))
            (bt:with-lock-held ((container-probe-manager-lock manager))
              (unless (container-probe-manager-stopping-p manager)
                (setf (gethash key (container-probe-manager-targets manager)) target) (push target created)))))))
    (when start-workers
      (dolist (target created)
        (dolist (worker (container-probe-target-workers target))
          (bt:with-lock-held ((container-probe-manager-lock manager))
            (when (current-probe-target-p manager target)
              (setf (container-probe-worker-thread worker)
                    (bt:make-thread (lambda () (run-container-probe-worker manager runtime target worker))
                                    :name (format nil "probe ~A/~A ~A" (container-probe-target-uid target) (container-probe-target-name target) (container-probe-worker-kind worker)))))))))
    manager))

(defun snapshot-container-probes (manager uid)
  "Copy actual thresholded results and stop requests under their ownership lock."
  (let ((snapshots nil))
    (bt:with-lock-held ((container-probe-manager-lock manager))
      (maphash
       (lambda (key target)
         (declare (ignore key))
         (when (and (equal uid (container-probe-target-uid target)) (current-probe-target-p manager target))
           (let* ((workers (container-probe-target-workers target))
                  (readiness (find "readinessProbe" workers :test #'equal :key #'container-probe-worker-kind))
                  (failure (find-if #'container-probe-worker-failed-p workers)))
             (push (list target
                         (core-object "containerID" (container-probe-target-id target)
                                      "startupSucceeded" (not (null (probe-target-started-p target)))
                                      "readinessConfigured" (not (null readiness))
                                      "readinessSucceeded" (or (null readiness) (container-probe-worker-result readiness)))
                         (when failure (list (container-probe-worker-kind failure) (container-probe-worker-spec failure)
                                             (container-probe-worker-message failure)))) snapshots))))
       (container-probe-manager-targets manager)))
    snapshots))

(defun checkpoint-container-probes (runtime pod manager)
  "Persist real probe state and an absolute failed-attempt stop deadline before CRI stop."
  (let* ((uid (pod-uid pod)) (state (load-container-lifecycle-state runtime uid))
         (before (copy-core-object state)) (now (funcall (container-probe-manager-clock manager))))
    (dolist (snapshot (snapshot-container-probes manager uid))
      (destructuring-bind (target results failure) snapshot
        (let* ((name (container-probe-target-name target)) (entry (or (gethash name (gethash "containers" state)) (core-object)))
               (old (gethash "probeRestart" entry)))
          (setf (gethash "probeState" entry) results)
          (when (and old (not (equal (gethash "containerID" old) (container-probe-target-id target))))
            (remhash "probeRestart" entry) (setf old nil))
          (when (and failure (null old))
            (destructuring-bind (kind spec message) failure
              (setf (gethash "probeRestart" entry)
                    (core-object "containerID" (container-probe-target-id target) "kind" kind "message" message
                                 "deadline" (+ now (gethash "terminationGracePeriodSeconds" spec
                                                            (gethash "terminationGracePeriodSeconds" (gethash "spec" (pod-to-object pod)) 30)))))))
          (setf (gethash name (gethash "containers" state)) entry))))
    (setf (gethash "probeEvents" state)
          (collect-container-probe-events manager uid (gethash "probeEvents" state)))
    (unless (equalp before state) (save-container-lifecycle-state runtime uid state))
    state))

(defun run-container-probe-stop (runtime manager job)
  "Stop a failed exact attempt outside reconciliation, retaining its actual terminal status."
  (unwind-protect
       (with-container-probe-stop (job)
         (handler-case
             (progn
               (bt:with-lock-held ((container-probe-manager-lock manager))
                 (when (container-probe-stop-job-cancelled-p job) (return-from run-container-probe-stop nil))
                 (setf (container-probe-stop-job-started-p job) t))
               (let ((pod (container-probe-stop-job-pod job)))
                 (when pod
                   (run-container-pre-stop-hook
                    runtime pod
                    (cri-container-status (containerd-runtime-socket-path runtime) (container-probe-stop-job-id job))
                    (container-probe-stop-job-deadline job)
                    (containerd-pod-sandbox-address runtime pod))))
               (cri-stop-container (containerd-runtime-socket-path runtime) (container-probe-stop-job-id job)
                                   :grace-period (max 0 (ceiling (- (container-probe-stop-job-deadline job) (funcall (container-probe-manager-clock manager)))))))
           (serious-condition (condition) (setf (container-probe-stop-job-failure job) condition))))
    (setf (container-probe-stop-job-finished-p job) t))
  nil)

(defun ensure-container-probe-stops (runtime pod observed manager state)
  "Resume durable failed-probe stops, including after an agent restart."
  (maphash
   (lambda (name entry)
     (let* ((request (gethash "probeRestart" entry))
            (id (and request (gethash "containerID" request)))
            (status (find name (container-lifecycle-all-statuses observed) :test #'equal :key (lambda (item) (gethash "name" item)))))
       (when (and id status (gethash "running" (gethash "state" status))
                  (equal (gethash "containerID" status) (concatenate 'string "containerd://" id)))
         (let ((job nil))
           (bt:with-lock-held ((container-probe-manager-lock manager))
             (let ((old (gethash id (container-probe-manager-jobs manager))))
               (unless (or (container-probe-manager-stopping-p manager)
                           (and old (not (container-probe-stop-job-finished-p old))))
                 (setf job (make-container-probe-stop-job :uid (pod-uid pod) :id id :pod pod :deadline (gethash "deadline" request))
                       (gethash id (container-probe-manager-jobs manager)) job))))
           (when job
             (bt:with-lock-held ((container-probe-manager-lock manager))
               (unless (or (container-probe-stop-job-cancelled-p job) (container-probe-manager-stopping-p manager))
                 (setf (container-probe-stop-job-thread job)
                       (bt:make-thread (lambda () (run-container-probe-stop runtime manager job)) :name "failed probe container stop")))))))))
   (gethash "containers" state)))

(defun apply-container-probe-observation (runtime observed)
  "Overlay only same-attempt probe facts onto actual running container observations."
  (when observed
    (let* ((uid (runtime-pod-uid observed))
           (manager (containerd-runtime-probes runtime))
           (snapshots (when manager (snapshot-container-probes manager uid)))
           (state (load-container-lifecycle-state runtime uid)))
      (loop for status across (container-lifecycle-all-statuses observed)
            when (gethash "running" (gethash "state" status))
              do (let* ((name (gethash "name" status))
                        (snapshot (find name snapshots :test #'equal :key (lambda (value) (container-probe-target-name (first value)))))
                        (results (if snapshot (second snapshot) (gethash "probeState" (gethash name (gethash "containers" state) (core-object))))))
                   (when (and results (equal (gethash "containerID" status) (concatenate 'string "containerd://" (gethash "containerID" results))))
                     (setf (gethash "started" status) (gethash "startupSucceeded" results)
                           (gethash "ready" status) (and (gethash "startupSucceeded" results) (gethash "readinessSucceeded" results))))))))
  observed)

(defun reconcile-container-probes (runtime pod observed)
  "Register actual attempts, persist completed checks and launch requested targeted stops."
  (when observed
    (let* ((manager (sync-container-probe-targets runtime pod observed))
           (state (checkpoint-container-probes runtime pod manager)))
      (ensure-container-probe-stops runtime pod observed manager state)))
  (apply-container-probe-observation runtime observed))

(defun container-probe-restart-required-p (runtime pod observed)
  "Request reconciliation for actual exits killed by probes even when they exit zero."
  (let ((state (load-container-lifecycle-state runtime (pod-uid pod))))
    (loop for status across (container-lifecycle-all-statuses observed)
          for request = (gethash "probeRestart" (gethash (gethash "name" status) (gethash "containers" state) (core-object)))
          thereis (and request (gethash "terminated" (gethash "state" status))
                       (or (equal "update" (gethash "kind" request))
                           (container-restarts-after-exit-p
                            pod (gethash "name" status) (gethash "exitCode" (gethash "terminated" (gethash "state" status))) t))
                            (equal (gethash "containerID" status) (concatenate 'string "containerd://" (gethash "containerID" request)))))))

(defun preserve-stopped-container-probe-events (runtime manager)
  "Merge retired Events only into existing checkpoints, serialized with deletion."
  (let ((uids nil))
    (bt:with-lock-held ((container-probe-manager-lock manager))
      (maphash (lambda (key event) (declare (ignore event)) (pushnew (first key) uids :test #'equal))
               (container-probe-manager-event-outbox manager)))
    (dolist (uid uids)
      ;; Lifecycle writes take this lock at the public save/forget boundary.
      ;; Here the read/existence check and private save form one transaction,
      ;; so a concurrent deletion cannot be undone by an outbox flush.
      (bt:with-lock-held ((containerd-runtime-lifecycle-lock runtime))
        (when (probe-file (container-lifecycle-path runtime uid))
          (let* ((state (load-container-lifecycle-state runtime uid))
                 (events (collect-container-probe-events manager uid (gethash "probeEvents" state))))
            (unless (equalp events (gethash "probeEvents" state))
              (setf (gethash "probeEvents" state) events)
              (%save-container-lifecycle-state runtime uid state))))))))

(defun begin-terminating-container-probes (runtime uid)
  "Stop UID's liveness and startup probes, counting them as passed, as a kubelet does once a Pod is
being deleted. Readiness keeps probing, so a container that leaves service during its grace period
shows as unready; the probes stop for good when its containers are removed."
  (let ((manager (containerd-runtime-probes runtime)))
    (when manager
      (bt:with-lock-held ((container-probe-manager-lock manager))
        (maphash (lambda (key target)
                   (declare (ignore key))
                   (when (and (equal uid (container-probe-target-uid target))
                              (not (container-probe-target-terminating-p target)))
                     (setf (container-probe-target-terminating-p target) t)
                     (dolist (worker (container-probe-target-workers target))
                       (unless (equal "readinessProbe" (container-probe-worker-kind worker))
                         (setf (container-probe-worker-result worker) t
                               (container-probe-worker-failed-p worker) nil
                               (container-probe-worker-on-hold-p worker) t)))))
                 (container-probe-manager-targets manager))))))

(defun stop-container-probes (runtime &optional uid)
  "Withdraw and join probes; full shutdown persists owned Events then releases its manager."
  (let ((manager (containerd-runtime-probes runtime)))
    (when manager
      ;; Serialize retirement/join as well as release: a concurrent stop must
      ;; not publish a fresh manager while another caller is still joining.
      (bt:with-lock-held ((container-probe-manager-shutdown-lock manager))
        (unless uid
          (bt:with-lock-held ((container-probe-manager-lock manager))
            (setf (container-probe-manager-stopping-p manager) t)))
        (retire-container-probe-targets manager (lambda (target) (or (null uid) (equal uid (container-probe-target-uid target)))))
        (let ((jobs nil))
          (bt:with-lock-held ((container-probe-manager-lock manager))
            (maphash (lambda (id job)
                       (when (or (null uid) (equal uid (container-probe-stop-job-uid job)))
                         (setf (container-probe-stop-job-cancelled-p job) t)
                         (remhash id (container-probe-manager-jobs manager)) (push job jobs)))
                     (container-probe-manager-jobs manager)))
          (dolist (job jobs)
            (let ((thread (container-probe-stop-job-thread job)))
              (when thread
                (when (and (container-probe-stop-job-started-p job) (bt:thread-alive-p thread))
                  (stop-container-probe-thread thread job))
                (bt:join-thread thread)))))
        (unless uid
          (preserve-stopped-container-probe-events runtime manager)
          (when (eq manager (containerd-runtime-probes runtime))
            (setf (containerd-runtime-probes runtime) nil))))))
  nil)

(defmethod runtime-events ((runtime containerd-runtime) uid)
  "Send fair bounded cumulative pages, including retired and reconstructed attempts."
  (let* ((manager (ensure-container-probe-manager runtime))
         (state (load-container-lifecycle-state runtime uid))
         (records (collect-container-probe-events manager uid (gethash "probeEvents" state)))
         (events (sort (loop for event being the hash-values of records collect event)
                       #'string< :key (lambda (event) (gethash "id" event))))
         (count (length events)))
    (when (plusp count)
      (bt:with-lock-held ((container-probe-manager-lock manager))
        (let* ((offset (mod (gethash uid (container-probe-manager-event-cursors manager) 0) count))
               (page (loop for index below (min 64 count) collect (nth (mod (+ offset index) count) events))))
          (setf (gethash uid (container-probe-manager-event-cursors manager)) (mod (+ offset (length page)) count))
          (coerce page 'vector))))))
