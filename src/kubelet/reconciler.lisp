;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; The per-node Pod reconciler: it drives each Pod's observed runtime state toward
;;;; its stored spec and derives the status gr8s publishes, the way a kubelet's sync
;;;; loop does.
;;;;
;;;; A reconciler pairs a store with a container RUNTIME, which may run containers
;;;; itself or delegate to nodes. Running Pods converge under a cancellable
;;;; operation so a durable urgent deletion can preempt blocked creation:
;;;; cancellation throws to a per-operation catch tag rather than signalling, so it
;;;; survives an interrupt that lands inside SBCL's %SIGNAL (podster-uqb.114), and
;;;; deletions themselves never register as cancellable and fence creation capacity
;;;; on the node until their physical cleanup completes (podster-uqb.123). Phase and
;;;; container-status derivation mirror the kubelet (getPhase, the exit-137
;;;; ContainerStatusUnknown, and the stickiness of a terminal phase and of
;;;; terminated container statuses) so clients never see a Pod forget a container or
;;;; revert a terminal phase. When the runtime is down, synchronization is skipped
;;;; and the last observation is reported rather than a fabricated Pending. Exec,
;;;; attach, logs, and port-forward are thin pass-throughs to the runtime,
;;;; serialized under the reconciler lock only when the runtime runs containers in
;;;; this process.

(in-package #:gr8s.kubelet)

(defstruct (reconciler (:constructor make-reconciler (store runtime)))
  store
  runtime
  (lock (bt:make-lock "gr8s reconciler"))
  active-convergence
  (urgent-deletions (make-hash-table :test #'equal))
  ;; Internal real time since when URGENT-DELETIONS has been non-empty, and of the
  ;; last report that creation is waiting on them.
  urgent-since
  urgent-reported
  (convergence-lock (bt:make-lock "gr8s running convergence ownership"))
  ;; Pod UID to the universal time its local storage was last measured.
  (storage-measurements (make-hash-table :test #'equal))
  ;; Pod UID to when a NoExecute taint with a finite toleration was first noticed.
  (taint-timers (make-hash-table :test #'equal))
  ;; Internal real time since available memory first fell below the soft eviction
  ;; threshold, or NIL while it is above it. A soft threshold only evicts once it
  ;; has stayed crossed for the grace period, so a brief dip does not kill a Pod.
  memory-soft-pressure-since
  ;; The memory threshold a run of evictions is reclaiming past, or NIL when not
  ;; evicting. Once eviction starts it continues until available rises a minimum
  ;; margin above this, so eviction does not thrash one Pod at a time at the edge.
  memory-eviction-active-threshold)

(define-condition pod-reconciliation-superseded (serious-condition) ()
  (:documentation "Unwind obsolete creation without translating cancellation into a Pod failure."))

(define-condition node-snapshot-incomplete (runtime-error) ()
  (:documentation "Every other Pod was applied, but a Pod's assignment isn't durable, so this revision can't be acknowledged."))

(defstruct running-pod-convergence
  "A narrowly owned, cancellable running-Pod operation; deletion never registers here.
It is also the catch tag that cancellation throws to."
  thread uid)

(defun cancel-running-pod-convergence (reconciler)
  "Yield blocked creation to durable urgent deletion without interrupting deletion itself."
  (let ((operation (bt:with-lock-held ((reconciler-convergence-lock reconciler))
                     (reconciler-active-convergence reconciler))))
    (when operation
      (ignore-errors
        (bt:interrupt-thread
         (running-pod-convergence-thread operation)
         (lambda ()
           ;; This callback runs in the owner. A late one finds the binding gone
           ;; and does nothing, so it can't escape into the owner's cleanup or
           ;; later work. Throw instead of signalling: the owner may be inside
           ;; %SIGNAL for another error, where SBCL has rebound the handler
           ;; clusters and an ERROR finds no handler and kills the thread
           ;; (podster-uqb.114). Do not acquire an ownership mutex here: an
           ;; asynchronous interrupt may arrive while its target is inside it.
           (when (eq *running-pod-convergence* operation)
             (if *running-pod-cancellation-deferred*
                 (setf *running-pod-cancellation-pending* t)
                 (throw operation :superseded))))))))
  nil)

(defvar *held-creation-report-seconds* 60
  "How long creation may wait on unfinished deletions before each report of it.")

(defvar *held-creation-dump* 'dump-thread-backtraces
  "Called with no arguments to record every thread's stack at the first such report.")

(defun note-urgent-deletions-changed (reconciler)
  "Start or end the period creation waits on urgent deletions. The caller holds the convergence lock."
  (if (zerop (hash-table-count (reconciler-urgent-deletions reconciler)))
      (setf (reconciler-urgent-since reconciler) nil
            (reconciler-urgent-reported reconciler) nil)
      (unless (reconciler-urgent-since reconciler)
        (setf (reconciler-urgent-since reconciler) (get-internal-real-time)))))

(defun report-held-creation (reconciler)
  "Say which deletions creation has waited on for too long, with every thread's stack the first time.
Each deletion holds back every creation on the node until it finishes, so one that never
finishes stops the node starting Pods, and nothing else reports it (podster-uqb.123)."
  (let ((now (get-internal-real-time)) (report nil) (first nil))
    (bt:with-lock-held ((reconciler-convergence-lock reconciler))
      (let ((since (reconciler-urgent-since reconciler))
            (reported (reconciler-urgent-reported reconciler))
            (interval (* *held-creation-report-seconds* internal-time-units-per-second)))
        (when (and since (>= (- now since) interval)
                   (or (null reported) (>= (- now reported) interval)))
          (setf first (null reported)
                (reconciler-urgent-reported reconciler) now
                report (list (round (- now since) internal-time-units-per-second)
                             (loop for uid being the hash-keys of (reconciler-urgent-deletions reconciler)
                                   collect uid))))))
    (when report
      (format *error-output* "gr8s Pod creation has waited ~Ds for unfinished deletions of ~{~A~^, ~}~%"
              (first report) (second report))
      (when first (funcall *held-creation-dump*)))))

(defun prioritize-reconciler-deletions (reconciler uids)
  "Reserve creation capacity for durable urgent UIDs until their physical cleanup completes."
  (bt:with-lock-held ((reconciler-convergence-lock reconciler))
    (dolist (uid uids) (setf (gethash uid (reconciler-urgent-deletions reconciler)) t))
    (note-urgent-deletions-changed reconciler))
  (cancel-running-pod-convergence reconciler))

(defun finish-reconciler-urgent-deletion (reconciler uid)
  "Release UID's creation fence only after its actual runtime cleanup has completed."
  (bt:with-lock-held ((reconciler-convergence-lock reconciler))
    (remhash uid (reconciler-urgent-deletions reconciler))
    (note-urgent-deletions-changed reconciler)))

(defun prune-reconciler-urgent-deletions (reconciler)
  "Discard finished exact UIDs without treating a new Pod sharing its name as old ownership."
  (let ((uids (mapcar #'pod-uid (list-pods (reconciler-store reconciler)))))
    (bt:with-lock-held ((reconciler-convergence-lock reconciler))
      (maphash (lambda (uid ignored)
                 (declare (ignore ignored))
                 (unless (member uid uids :test #'equal)
                   (remhash uid (reconciler-urgent-deletions reconciler))))
               (reconciler-urgent-deletions reconciler))
      (note-urgent-deletions-changed reconciler))))

(defun converge-cancellable-running-pod (reconciler pod)
  "Register cancellation only around running convergence and recheck durable deletion first."
  (let ((operation (make-running-pod-convergence :thread (bt:current-thread)
                                                :uid (pod-uid pod)))
        (cancelled t)
        (held nil)
        (status nil))
    (unwind-protect
         ;; The catch is established before the operation is registered, so a
         ;; cancellation always has it to throw to.
         (catch operation
           (let ((*running-pod-convergence* operation))
             (prune-reconciler-urgent-deletions reconciler)
             (bt:with-lock-held ((reconciler-convergence-lock reconciler))
               (setf (reconciler-active-convergence reconciler) operation)
               ;; New or retried creation must not grab the global lock while a
               ;; finite urgent cleanup job still needs its completion observed.
               (when (plusp (hash-table-count (reconciler-urgent-deletions reconciler)))
                 (setf held t)))
             (when held
               (report-held-creation reconciler)
               (error 'pod-reconciliation-superseded))
             ;; Urgent snapshot projection uses the store lock, never this global
             ;; reconciler lock. Register before checking so its cancellation
             ;; cannot miss the gap between reading a Pod and entering CRI.
             (let ((current (get-pod (reconciler-store reconciler)
                                     (pod-namespace pod) (pod-name pod))))
               (unless (and (equal (pod-uid current) (pod-uid pod))
                            (not (deletion-requested-p current)))
                 (error 'pod-reconciliation-superseded)))
             (setf status (converge-running-pod reconciler pod)
                   cancelled nil)))
      (flet ((release-ownership ()
               (bt:with-lock-held ((reconciler-convergence-lock reconciler))
                 (when (eq operation (reconciler-active-convergence reconciler))
                   (setf (reconciler-active-convergence reconciler) nil)))))
        ;; Cancellation must not interrupt its own ownership release halfway.
        #+sbcl (sb-sys:without-interrupts (release-ownership))
        #-sbcl (release-ownership)))
    ;; Signalled here, by the owner itself, once the cancellation has unwound.
    (when cancelled
      (error 'pod-reconciliation-superseded))
    status))

(defun deletion-requested-p (pod)
  "Return whether POD's metadata has a deletionTimestamp set -- true once its
   deletion has been requested (the key's presence, even if its value is null)."
  (nth-value 1
             (gethash "deletionTimestamp"
                      (gethash "metadata" (pod-to-object pod)))))

(defun pod-status (phase &key reason message)
  "Return a fresh status object carrying PHASE and, when supplied, REASON and MESSAGE."
  (let ((status (make-hash-table :test #'equal)))
    (setf (gethash "phase" status) phase)
    (when reason
      (setf (gethash "reason" status) reason))
    (when message
      (setf (gethash "message" status) message))
    status))

(defun observed-status (runtime-pod)
  "Return the status object for an observed RUNTIME-POD: its reported status (or a
   bare phase when it has none), with the phase overwritten from the observation and
   podIP/podIPs added when it has a Pod IP."
  (let ((status (if (runtime-pod-status runtime-pod)
                    (com.inuoe.jzon:parse (com.inuoe.jzon:stringify (runtime-pod-status runtime-pod)))
                    (pod-status (runtime-pod-phase runtime-pod)))))
    (setf (gethash "phase" status) (runtime-pod-phase runtime-pod))
    (unless (string= "" (runtime-pod-pod-ip runtime-pod))
      (let ((addresses (runtime-pod-pod-ips runtime-pod)))
        (setf (gethash "podIP" status) (runtime-pod-pod-ip runtime-pod)
              (gethash "podIPs" status)
              (map 'vector #'(lambda (address) (json-object "ip" address))
                   (if (plusp (length addresses)) addresses
                       (vector (runtime-pod-pod-ip runtime-pod)))))))
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
  ;; Recorded first, as a kubelet's eviction manager does, and kept until the next status report.
  (gr8s.runtime:runtime-record-pod-event (reconciler-runtime reconciler) (pod-uid pod) "Evicted" message "Warning")
  (runtime-delete (reconciler-runtime reconciler) (pod-uid pod))
  (let ((status (pod-status "Failed" :reason "Evicted" :message message)))
    (save-pod-observation (reconciler-store reconciler) pod status)
    status))

(defparameter +memory-eviction-threshold-bytes+ (* 100 1024 1024)
  "Minimum free node memory before node-pressure eviction reclaims, matching the
kubelet's default memory.available eviction threshold (100Mi).")

(defun pod-memory-eviction-rank (pod)
  "Sort key for node-pressure eviction (lower evicts first): BestEffort before
Burstable, and within a class the lower-priority Pod first, so the least-critical
workloads are sacrificed first -- Guaranteed Pods are excluded by the caller."
  (let ((qos (pod-spec-qos-class (gethash "spec" (pod-to-object pod)))))
    (list (if (equal qos "BestEffort") 0 1) (pod-spec-priority pod))))

(defun select-memory-eviction-pod (pods)
  "Choose the local Pod to evict first to relieve node memory pressure, or NIL when
only Guaranteed Pods remain (never sacrificed for memory pressure alone; the
per-QoS oom_score_adj leaves them to the kernel as a last resort)."
  (let ((candidates (remove "Guaranteed" pods
                            :key (lambda (pod) (pod-spec-qos-class (gethash "spec" (pod-to-object pod))))
                            :test #'equal)))
    (first (stable-sort (copy-list candidates)
                        (lambda (a b)
                          (let ((ra (pod-memory-eviction-rank a)) (rb (pod-memory-eviction-rank b)))
                            (or (< (first ra) (first rb))
                                (and (= (first ra) (first rb)) (< (second ra) (second rb))))))))))

(defun node-memory-available-bytes ()
  "Available node memory in bytes from /proc/meminfo MemAvailable, or NIL."
  (ignore-errors
    (let ((available (cdr (assoc "MemAvailable" (read-key-value-file "/proc/meminfo") :test #'equal))))
      (when available (* 1024 (parse-integer available :junk-allowed t))))))

(defparameter *node-memory-available-fn* #'node-memory-available-bytes
  "Reader for available node memory in bytes; injectable for tests.")

(defparameter +memory-soft-eviction-threshold-bytes+ (* 300 1024 1024)
  "Available node memory below which a soft eviction begins its grace period; above
the hard threshold so a sustained squeeze is relieved before it becomes critical.")

(defparameter +memory-soft-eviction-grace-seconds+ 90
  "Seconds available memory must stay below the soft threshold before the soft
eviction fires, matching a typical kubelet eviction-soft-grace-period.")

(defparameter *node-pressure-clock-fn* #'get-internal-real-time
  "Monotonic clock (internal real time units) for soft-eviction grace; injectable for tests.")

(defparameter +memory-eviction-minimum-reclaim-bytes+ (* 100 1024 1024)
  "Once a memory eviction starts, keep evicting until available memory has risen
this far above the crossed threshold, matching the kubelet's eviction-minimum-reclaim
so eviction does not thrash one Pod at a time right at the boundary.")

(defparameter +disk-eviction-threshold-bytes+ (* 1024 1024 1024)
  "Minimum free node-filesystem bytes before DiskPressure, matching the kubelet's
default nodefs.available eviction threshold (roughly 10%, 1Gi here as a floor).")

(defparameter +disk-eviction-threshold-inodes+ 10000
  "Minimum free node-filesystem inodes before DiskPressure.")

(defparameter *node-nodefs-path* "/var/lib/kubelet/"
  "The node filesystem whose free space backs the DiskPressure signal.")

(defun node-disk-available ()
  "Return available bytes and free inodes; NIL means that measurement is unavailable.
Filesystems such as Btrfs report zero total inodes because they have no fixed pool."
  (let ((statistics (ignore-errors (filesystem-statistics *node-nodefs-path*))))
    (if statistics
        (values (second statistics)
                (when (plusp (fourth statistics)) (fifth statistics)))
        (values nil nil))))

(defparameter *node-disk-available-fn* #'node-disk-available
  "Reader for (values available-bytes free-inodes) of the node filesystem; injectable for tests.")

(defun node-pid-usage ()
  "(values used-pids max-pids) for the node, or (values NIL NIL). The fourth
/proc/loadavg field is runnable/total processes; /proc/sys/kernel/pid_max is the
ceiling the kernel will allocate to."
  (ignore-errors
    (let* ((loadavg (with-open-file (in "/proc/loadavg") (read-line in)))
           (field (fourth (remove "" (uiop:split-string loadavg :separator '(#\Space)) :test #'equal)))
           (total (and field (parse-integer (subseq field (1+ (position #\/ field))) :junk-allowed t)))
           (maximum (with-open-file (in "/proc/sys/kernel/pid_max")
                      (parse-integer (read-line in) :junk-allowed t))))
      (if (and total maximum) (values total maximum) (values nil nil)))))

(defparameter *node-pid-usage-fn* #'node-pid-usage
  "Reader for (values used-pids max-pids); injectable for tests.")

(defun node-memory-eviction-threshold (reconciler available)
  "Decide whether memory pressure should evict this pass, tracking the soft
threshold's grace period and the minimum-reclaim margin on RECONCILER. Returns the
crossed threshold in bytes to cite, or NIL to wait. Below the hard threshold evicts
at once; below the soft threshold evicts only after AVAILABLE has stayed there for
the grace period; and once eviction has started it continues until AVAILABLE has
risen the minimum-reclaim margin above the threshold, so it does not thrash at the
edge. Above that margin (or with no reading) the timers reset."
  (let ((primary
          (cond
            ((null available)
             (setf (reconciler-memory-soft-pressure-since reconciler) nil)
             nil)
            ((< available +memory-eviction-threshold-bytes+)
             (setf (reconciler-memory-soft-pressure-since reconciler) nil)
             +memory-eviction-threshold-bytes+)
            ((< available +memory-soft-eviction-threshold-bytes+)
             (let ((now (funcall *node-pressure-clock-fn*))
                   (since (reconciler-memory-soft-pressure-since reconciler)))
               (unless since
                 (setf (reconciler-memory-soft-pressure-since reconciler) now
                       since now))
               (when (>= (- now since)
                         (* +memory-soft-eviction-grace-seconds+ internal-time-units-per-second))
                 +memory-soft-eviction-threshold-bytes+)))
            (t (setf (reconciler-memory-soft-pressure-since reconciler) nil)
               nil))))
    (cond
      (primary
       ;; Eviction is (still) triggered; remember the threshold to reclaim past.
       (setf (reconciler-memory-eviction-active-threshold reconciler) primary)
       primary)
      ((let ((active (reconciler-memory-eviction-active-threshold reconciler)))
         (and available active
              (< available (+ active +memory-eviction-minimum-reclaim-bytes+))))
       ;; Not newly triggered, but memory has not yet recovered the minimum-reclaim
       ;; margin above the threshold a prior pass evicted on: keep going.
       (reconciler-memory-eviction-active-threshold reconciler))
      (t
       ;; Recovered past the margin, or no reading: stop and clear the run.
       (setf (reconciler-memory-eviction-active-threshold reconciler) nil)
       nil))))

(defun node-pressure-evict (reconciler)
  "When free node memory is low, gracefully evict the least-critical local Pod
(BestEffort/Burstable, lowest priority first), one per pass so pressure is relieved
incrementally rather than by a mass kill. The hard threshold evicts at once; the
soft threshold evicts only after memory has stayed below it for the grace period.
Returns the evicted Pod, or NIL. This replaces relying solely on the kernel OOM
killer."
  (when (runtime-runs-containers-p (reconciler-runtime reconciler))
    (let* ((available (funcall *node-memory-available-fn*))
           (threshold (node-memory-eviction-threshold reconciler available)))
      (when threshold
        (let ((pod (select-memory-eviction-pod
                    (remove-if #'deletion-requested-p (list-pods (reconciler-store reconciler))))))
          (when pod
            (evict-pod-for-storage
             reconciler pod
             (format nil "The node was low on resource: memory. Threshold ~D bytes, ~D available."
                     threshold available))
            pod))))))

(defun pod-recorded-eviction (reconciler pod)
  "Return POD's durable eviction status, if a previous pass evicted it."
  (let ((status (pod-observed-status (reconciler-store reconciler) pod)))
    (when (and status (equal "Failed" (gethash "phase" status)) (member (gethash "reason" status) '("Evicted" "TopologyAffinityError" "OutOfcpu") :test #'equal))
      (copy-core-object status))))

(defun converge-running-pod (reconciler pod)
  "Converge a running (non-deleting) POD one pass and return the status to publish.
   On a runtime that runs containers, a Pod past its active deadline is stopped and
   failed, and a Pod already recorded evicted keeps that status. Otherwise the
   containers are observed and, when the stored resourceVersion differs from what
   runs, ensured, else reconciled in place -- adoption is proved by the durable
   spec fingerprint, so a metadata-only revision bump does not re-ensure; a Pod over
   its ephemeral-storage limit is evicted. The returned status carries
   observedGeneration once the observation matches the Pod's resourceVersion."
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

(defparameter +pod-status-container-fields+
  '("initContainerStatuses" "containerStatuses" "ephemeralContainerStatuses"))

(defun container-status-state-p (status state)
  "Return whether container STATUS is in STATE, \"running\", \"terminated\" or \"waiting\"."
  (and (hash-table-p status) (hash-table-p (gethash "state" status))
       (hash-table-p (gethash state (gethash "state" status)))))

(defun vanished-container-status (status)
  "Report a container last seen running whose Pod's containers are now gone, as a kubelet does.
The kubelet calls it ContainerStatusUnknown with exit code 137; any other STATUS is kept."
  (if (container-status-state-p status "running")
      (let ((copy (copy-core-object status)))
        (setf (gethash "state" copy)
              (core-object "terminated"
                           (core-object "exitCode" 137 "reason" "ContainerStatusUnknown"
                                        "message" "The container could not be located when the pod was terminated"))
              (gethash "ready" copy) nil
              (gethash "started" copy) nil)
        copy)
      status))

(defun terminating-container-statuses (current last gone)
  "Merge CURRENT container statuses with the LAST ones reported for a Pod that is shutting down.
Nothing restarts during shutdown, so a container last seen terminated stays terminated and one
the runtime no longer lists keeps its last status. When GONE, no container runs any more."
  (let ((merged (map 'list (lambda (item)
                             (let ((before (find (gethash "name" item) last :test #'equal
                                                 :key (lambda (entry) (gethash "name" entry)))))
                               (if (and (container-status-state-p before "terminated")
                                        (not (container-status-state-p item "terminated")))
                                   before item)))
                     (remove-if-not #'hash-table-p current))))
    (loop for entry across last
          unless (find (gethash "name" entry) merged :test #'equal :key (lambda (item) (gethash "name" item)))
            do (setf merged (append merged (list entry))))
    (coerce (if gone (mapcar #'vanished-container-status merged) merged) 'vector)))

(defun add-gone-declared-container-statuses (pod status)
  "List every declared container of a Pod whose containers are gone, waiting where none was seen.
The kubelet reports a container that never started as waiting, PodInitializing when init containers come first."
  (let ((reason (if (plusp (length (pod-init-containers pod))) "PodInitializing" "ContainerCreating")))
    (loop for (field specs) in (list (list "initContainerStatuses" (pod-init-containers pod))
                                     (list "containerStatuses" (pod-containers pod)))
          for reported = (gethash field status #())
          when (plusp (length specs))
            do (setf (gethash field status)
                     (map 'vector
                          (lambda (spec)
                            (or (find (container-spec-name spec) reported :test #'equal
                                      :key (lambda (item) (and (hash-table-p item) (gethash "name" item))))
                                (core-object "name" (container-spec-name spec) "image" (container-spec-image spec)
                                             "imageID" "" "restartCount" 0 "ready" nil "started" nil
                                             "state" (core-object "waiting" (core-object "reason" reason)))))
                          specs))))
  status)

(defun kubelet-pod-phase (pod status terminal)
  "Derive POD's phase from container STATUS as the kubelet's getPhase does, TERMINAL once it has stopped.
A failed init container that won't run again fails the Pod; a container yet to start keeps it Pending."
  (flet ((entry (field name)
           (find name (gethash field status #()) :test #'equal
                 :key (lambda (item) (and (hash-table-p item) (gethash "name" item)))))
         (exit-code (item)
           (let ((exit (or (and (container-status-state-p item "terminated") (gethash "terminated" (gethash "state" item)))
                           (and (container-status-state-p item "waiting")
                                (hash-table-p (gethash "lastState" item))
                                (gethash "terminated" (gethash "lastState" item))))))
             (and (hash-table-p exit) (gethash "exitCode" exit 0)))))
    (let ((pending-init 0) (pending-sidecars 0) (init-failed nil)
          (running 0) (waiting 0) (stopped 0) (restartable 0) (succeeded 0) (unknown 0))
      (loop for spec across (pod-init-containers pod)
            for name = (container-spec-name spec)
            for item = (entry "initContainerStatuses" name)
            do (cond ((pod-sidecar-p pod name)
                      (cond ((null item) (incf unknown) (incf pending-sidecars))
                            ((container-status-state-p item "running") (incf running))
                            ((exit-code item))
                            (t (incf pending-sidecars) (incf waiting))))
                     ((or (null item) (container-status-state-p item "running") (null (exit-code item)))
                      (incf pending-init))
                     ((and (/= 0 (exit-code item)) (not (container-restarts-after-exit-p pod name (exit-code item))))
                      (setf init-failed t))))
      (loop for spec across (pod-containers pod)
            for name = (container-spec-name spec)
            for item = (entry "containerStatuses" name)
            for code = (and item (exit-code item))
            do (cond ((null item) (incf unknown))
                     ((container-status-state-p item "running") (incf running))
                     (code (incf stopped)
                           (when (container-restarts-after-exit-p pod name code) (incf restartable))
                           (when (and (zerop code) (container-status-state-p item "terminated")) (incf succeeded)))
                     (t (incf waiting))))
      (cond (init-failed "Failed")
            ((or (plusp pending-init) (plusp waiting)
                 (and (plusp pending-sidecars)
                      (notany #'container-status-ever-ran-p (gethash "containerStatuses" status #()))))
             "Pending")
            ((and (plusp running) (zerop unknown)) "Running")
            ((and (zerop running) (plusp stopped) (zerop unknown))
             (cond ((and (not terminal) (plusp restartable)) "Running")
                   ((= stopped succeeded) "Succeeded")
                   (t "Failed")))
            (t "Pending")))))

(defun terminating-pod-status (pod current last &key gone)
  "Return the status of POD while it shuts down, from the CURRENT observation and the LAST status reported.
Shutdown never forgets a container or reverts a terminal phase. Once the containers are GONE, as when
the runtime finds none or has removed them, the status is the terminal one a kubelet sends last."
  (let ((status (copy-core-object (or current last (pod-status "Pending")))))
    (when (or current last)
      (dolist (field +pod-status-container-fields+)
        (let ((merged (terminating-container-statuses (gethash field (or current status) #())
                                                      (if last (gethash field last #()) #()) gone)))
          (if (plusp (length merged)) (setf (gethash field status) merged) (remhash field status)))))
    (when gone (add-gone-declared-container-statuses pod status))
    (let ((previous (and last (gethash "phase" last))))
      (cond ((member previous '("Succeeded" "Failed") :test #'equal)
             (setf (gethash "phase" status) previous))
            ((or gone (member (gethash "phase" status) '(nil "Unknown") :test #'equal))
             (setf (gethash "phase" status) (kubelet-pod-phase pod status gone)))))
    status))

(defun retain-terminated-container-statuses (store pod status)
  "Keep each container clients last saw terminated terminated, unless a new attempt of it now exists,
and a terminal phase terminal. The kubelet's status manager refuses both transitions too: a report
without the container, or one still describing the exited attempt, can't make it waiting or running."
  (let ((published (with-store-lock (store) (gethash (pod-uid pod) (pod-store-pod-published-statuses store)))))
    (when (hash-table-p published)
      (when (and (member (gethash "phase" published) '("Succeeded" "Failed") :test #'equal)
                 (not (member (gethash "phase" status) '("Succeeded" "Failed") :test #'equal)))
        (setf (gethash "phase" status) (gethash "phase" published)))
      (dolist (field +pod-status-container-fields+)
        (let ((before (gethash field published)) (current (gethash field status)))
          (when (and (vectorp before) (not (stringp before)) (vectorp current) (not (stringp current)))
            (setf (gethash field status)
                  (map 'vector
                       (lambda (item)
                         (let ((old (and (hash-table-p item)
                                         (find (gethash "name" item) before :test #'equal
                                               :key (lambda (entry) (and (hash-table-p entry) (gethash "name" entry)))))))
                           (if (and old (container-status-state-p old "terminated")
                                    (not (container-status-state-p item "terminated"))
                                    (member (gethash "containerID" item "") (list "" (gethash "containerID" old ""))
                                            :test #'equal))
                               (copy-core-object old)
                               item)))
                       current)))))))
  status)

(defun pod-published-status (store pod)
  "Return the status clients last saw for POD, or NIL."
  (with-store-lock (store)
    (copy-pod-status-value (gethash (pod-uid pod) (pod-store-pod-published-statuses store)))))

(defun deleted-pod-final-status (reconciler pod last)
  "Return the status to publish for POD as it is removed, or NIL.
A runtime that stops containers itself reports what it last saw, with its containers gone. A
delegating one publishes its node's last report over what clients last saw, as an API server keeps
the kubelet's last status write: with the containers gone once the node acknowledged removal, and
unchanged when the deletion needed no acknowledgement. Neither forgets a container or reverts a
terminal phase clients saw, even when a node rebuilt its acknowledgement from less."
  (let ((store (reconciler-store reconciler)))
    (cond ((runtime-runs-containers-p (reconciler-runtime reconciler))
           (terminating-pod-status pod nil last :gone t))
          (last
           (terminating-pod-status pod last (pod-published-status store pod)
                                   :gone (and (equal "Deleted" (gethash "reason" last))
                                              (equal (pod-resource-version pod)
                                                     (pod-observed-resource-version store pod))))))))

(defun converge-deleting-pod (reconciler pod)
  "Converge a deleting POD one pass and return the status to publish. When the Pod
   has finalizers or an in-flight finalization, this delegates to the finalized-
   deletion path. Otherwise it advances runtime shutdown: once the runtime reports
   deletion complete it publishes the terminal status clients last saw, forgets the
   runtime's finalization record, releases the Pod's urgent-deletion fence, removes
   the Pod from the store, and returns a status reasoned \"Deleted\"; while shutdown
   is still in progress it returns the current terminating status reasoned
   \"Terminating\", keeping real container observations and observedGeneration
   through the grace period."
  (when (or (pod-finalizers-present-p pod) (pod-finalization-state (reconciler-store reconciler) pod))
    (return-from converge-deleting-pod (converge-finalized-pod-deletion reconciler pod)))
  (let* ((store (reconciler-store reconciler))
         (runtime (reconciler-runtime reconciler))
         (last (pod-observed-status store pod)))
    (if (runtime-delete-pod runtime pod)
        (let ((final (deleted-pod-final-status reconciler pod last)))
          (runtime-forget-pod-finalization runtime (pod-uid pod))
          (finish-reconciler-urgent-deletion reconciler (pod-uid pod))
          ;; Clients watching the Pod see the terminal status before it goes, as a kubelet's
          ;; last status update precedes its removal.
          (when final
            (let ((published (copy-core-object final)))
              (remhash "reason" published)
              (add-pod-status-conditions store pod published)))
          (remove-pod store (pod-namespace pod) (pod-name pod) :uid (pod-uid pod))
          (let ((status (or final (pod-status "Succeeded"))))
            (setf (gethash "reason" status) "Deleted")
            status))
        (let* ((failed nil)
               (observed (handler-case (runtime-observe runtime (pod-uid pod))
                           ;; Concurrent container removal may invalidate a CRI
                           ;; status lookup. The deletion remains accepted.
                           (runtime-error () (setf failed t) nil)))
               (status (cond ((runtime-runs-containers-p runtime)
                              ;; A runtime that finds no sandbox has no container left running.
                              (terminating-pod-status pod (and observed (observed-status observed)) last
                                                      :gone (not (or observed failed))))
                             ;; A delegating runtime reports what its node did.
                             (observed (observed-status observed))
                             (t (pod-status "Unknown")))))
          ;; Shutdown intent does not prove that a still-running container has
          ;; become unready. Keep actual container observations during grace;
          ;; the Service controller separately excludes terminating endpoints.
          (when (and observed (runtime-pod-spec-fingerprint observed)
                     (equal (runtime-pod-spec-fingerprint observed) (pod-runtime-spec-fingerprint pod)))
            (setf (gethash "observedGeneration" status)
                  (gethash "generation" (gethash "metadata" (pod-to-object pod)) 1)))
          (setf (gethash "reason" status) "Terminating")
          status))))

(defun reconcile-pod (reconciler namespace name)
  "Reconcile the Pod named NAMESPACE/NAME one pass under the reconciler lock and
   return the status produced, with its status conditions added. Converges a
   deletion or a running Pod as appropriate. If the runtime is unavailable,
   synchronization is skipped and the Pod's last observed status is reported (or
   Pending/ContainerRuntimeUnavailable when there is none), as a kubelet does with a
   dead runtime; a runtime error that is not an outage yields a Pending/RuntimeError
   status, or the retained finalization status for a deleting Pod."
  (bt:with-lock-held ((reconciler-lock reconciler))
    (let ((pod (get-pod (reconciler-store reconciler) namespace name)))
      (handler-case
          (handler-bind
              ((runtime-error
                 (lambda (error)
                   ;; A call that failed because the runtime died is an outage, not a Pod error.
                   (unless (typep error 'runtime-unavailable)
                     (let ((down (runtime-unavailable-message (reconciler-runtime reconciler))))
                       (when down (error 'runtime-unavailable :message down)))))))
            (let ((down (runtime-unavailable-message (reconciler-runtime reconciler))))
              (when down (error 'runtime-unavailable :message down)))
            (add-pod-status-conditions
             (reconciler-store reconciler) pod
             (if (deletion-requested-p pod)
                 (converge-deleting-pod reconciler pod)
                 (converge-cancellable-running-pod reconciler pod))))
        (runtime-unavailable (error)
          ;; Like kubelet with a dead runtime, skip synchronization and keep
          ;; reporting the last observation rather than a fabricated Pending.
          (add-pod-status-conditions
           (reconciler-store reconciler) pod
           (let ((status (pod-observed-status (reconciler-store reconciler) pod)))
             (if status
                 (copy-core-object status)
                 (pod-status "Pending" :reason "ContainerRuntimeUnavailable"
                                       :message (runtime-error-message error))))))
        (gr8s.runtime:resource-admission-error (error)
          (let ((status (pod-status "Failed" :reason (gr8s.runtime:resource-admission-error-reason error)
                                            :message (runtime-error-message error))))
            (save-pod-observation (reconciler-store reconciler) pod status)
            (add-pod-status-conditions (reconciler-store reconciler) pod status)))
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

(defun reconcile-written-pod (reconciler pod &key (reconcile #'reconcile-pod))
  "Reconcile POD, which a request has just written, for that request's response.
A write that releases the last finalizer of a deleting Pod lets any reconciliation
retire it, and another one can win the reconciler lock first. The write still
succeeded, so answer as if this request had retired the Pod itself. In HA, a
follower-authored whole-index proposal can briefly be displaced by an earlier
committed snapshot; wait for this write's committed view instead of returning a
spurious 404 from the same request that created the Pod."
  (let ((store (reconciler-store reconciler))
        (deadline (+ (get-internal-real-time) (* 2 internal-time-units-per-second))))
    (loop
      (handler-case
          (return (funcall reconcile reconciler (pod-namespace pod) (pod-name pod)))
        (kubernetes-error (condition)
          (cond
            ((and (= 404 (kubernetes-error-status-code condition)) (deletion-requested-p pod)
                  (not (pod-finalizers-present-p pod)))
             (return (pod-status "Succeeded" :reason "Deleted")))
            ((and (= 404 (kubernetes-error-status-code condition))
                  (pod-store-consensus-commit-fn store)
                  (< (get-internal-real-time) deadline))
             (sleep 0.01))
            (t (error condition))))))))

(defun delete-reconciled-pod (reconciler namespace name &key uid resource-version
                                                      (grace-period nil grace-supplied-p)
                                                      dry-run)
  "Mark the Pod NAMESPACE/NAME for deletion and converge that deletion one pass,
   under the reconciler lock. Returns (values STATUS POD): the published deletion
   status (NIL on DRY-RUN) and the marked Pod. UID, RESOURCE-VERSION, and
   GRACE-PERIOD are passed through to MARK-POD-DELETING as deletion preconditions."
  (bt:with-lock-held ((reconciler-lock reconciler))
    (let ((pod (apply #'mark-pod-deleting (reconciler-store reconciler) namespace name
                      :uid uid :resource-version resource-version :dry-run dry-run
                      (when grace-supplied-p (list :grace-period grace-period)))))
      (values (unless dry-run
                (add-pod-status-conditions (reconciler-store reconciler) pod
                                          (converge-deleting-pod reconciler pod))) pod))))

(defun reconcile-all (reconciler &key observer)
  "Reconcile every Pod in the store one pass -- deletions first, then by descending
   spec priority -- and return the list of statuses produced. A no-op returning NIL
   while the runtime is unavailable. A superseded creation is dropped silently; any
   other per-Pod error is logged and skipped so one Pod cannot starve the rest.
   OBSERVER, when given, is called with each Pod and its status."
  ;; kubelet skips Pod synchronization while its runtime is down; the runtime
  ;; supervisor reports the outage once instead of every Pod failing each pass.
  (when (runtime-unavailable-message (reconciler-runtime reconciler))
    (return-from reconcile-all nil))
  ;; Relieve node memory pressure by gracefully evicting a low-QoS Pod before the
  ;; pass, rather than leaving the node to the kernel OOM killer.
  (ignore-errors (node-pressure-evict reconciler))
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
                 (pod-reconciliation-superseded () nil)
                 ;; One Pod's failure must not starve the Pods sorted after it on every pass.
                 (error (condition)
                   (format *error-output* "gr8s Pod ~A/~A reconciliation failed: ~A~%"
                           (pod-namespace pod) (pod-name pod) condition)
                   nil))))

(defun call-with-runtime-serialized (reconciler function)
  "Call FUNCTION under the reconciler lock when the runtime runs containers itself and so shares
its state with reconciliation. A runtime that delegates to nodes only exchanges messages with
them, and a node operation's wait, as long as a log read or an exec, must not stall every Pod
read and write behind it."
  (if (runtime-runs-containers-p (reconciler-runtime reconciler))
      (bt:with-lock-held ((reconciler-lock reconciler)) (funcall function))
      (funcall function)))

(defun reconciler-logs (reconciler uid container &key tail previous)
  "Return CONTAINER's logs for the Pod UID from the runtime -- TAIL lines, or the
   PREVIOUS instance -- serialized under the reconciler lock when the runtime runs
   containers in this process."
  (call-with-runtime-serialized
   reconciler
   (lambda ()
     (runtime-logs (reconciler-runtime reconciler)
                   uid container :tail tail :previous previous))))

(defun reconciler-send-logs (reconciler uid container function
                             &rest selection &key previous tail-lines since start-offset)
  "Call FUNCTION with CONTAINER's log for the Pod UID a piece at a time, as
RUNTIME-SEND-LOGS does. Only finding a log file is serialized under the reconciler lock:
a slow reader must not hold up every Pod's reconciliation."
  (declare (ignore tail-lines since start-offset))
  (let* ((runtime (reconciler-runtime reconciler))
         (path (and (runtime-runs-containers-p runtime)
                    (call-with-runtime-serialized
                     reconciler (lambda () (runtime-log-file runtime uid container :previous previous))))))
    (if path
        (apply #'send-log-file path function
               (loop for (key value) on selection by #'cddr unless (eq key :previous) collect key and collect value))
        (call-with-runtime-serialized
         reconciler (lambda () (apply #'runtime-send-logs runtime uid container function selection))))))

(defun reconciler-exec-url
    (reconciler uid container command &key stdin stdout stderr tty)
  "Return a one-time streaming exec URL for running COMMAND in CONTAINER of the Pod
   UID, with the requested stdin/stdout/stderr/tty streams, from the runtime;
   serialized under the reconciler lock when the runtime runs containers in-process."
  (call-with-runtime-serialized
   reconciler
   (lambda ()
     (runtime-exec-url
      (reconciler-runtime reconciler) uid container command
      :stdin stdin :stdout stdout :stderr stderr :tty tty))))

(defun reconciler-start-exec-session
    (reconciler uid container command &key stdin stdout stderr tty)
  "Start an interactive exec of COMMAND in CONTAINER of the Pod UID and return its
   session, with the requested streams; serialized under the reconciler lock when
   the runtime runs containers in-process."
  (call-with-runtime-serialized
   reconciler
   (lambda ()
     (runtime-start-exec-session
      (reconciler-runtime reconciler) uid container command
      :stdin stdin :stdout stdout :stderr stderr :tty tty))))

(defun reconciler-start-attach-session (reconciler uid container &key stdin stdout stderr tty)
  "Start an interactive attach to CONTAINER of the Pod UID and return its session,
   with the requested streams, delegating straight to the runtime."
  (runtime-start-attach-session (reconciler-runtime reconciler) uid container
                                :stdin stdin :stdout stdout :stderr stderr :tty tty))

(defun reconciler-attach-url (reconciler uid container &key stdin stdout stderr tty)
  "Return a one-time streaming attach URL for CONTAINER of the Pod UID, with the
   requested streams, from the runtime."
  (runtime-attach-url (reconciler-runtime reconciler) uid container
                      :stdin stdin :stdout stdout :stderr stderr :tty tty))

(defun reconciler-send-exec-session-input
    (reconciler session channel data &key rows columns eof)
  "Send DATA on CHANNEL of exec SESSION to the runtime, optionally resizing to ROWS
   by COLUMNS or signalling EOF on the channel."
  (runtime-send-exec-session-input
   (reconciler-runtime reconciler) session channel data
   :rows rows :columns columns :eof eof))

(defun reconciler-next-exec-session-output
    (reconciler session cursor &key timeout)
  "Return the next output from exec SESSION after CURSOR from the runtime, waiting
   up to TIMEOUT."
  (runtime-next-exec-session-output
   (reconciler-runtime reconciler) session cursor :timeout timeout))

(defun reconciler-exec-session-exit-code (reconciler session)
  "Return the exit code of exec SESSION from the runtime."
  (runtime-exec-session-exit-code (reconciler-runtime reconciler) session))

(defun reconciler-cancel-exec-session (reconciler session reason)
  "Cancel exec SESSION with REASON through the runtime."
  (runtime-cancel-exec-session
   (reconciler-runtime reconciler) session reason))

(defun reconciler-release-exec-session (reconciler session)
  "Release exec SESSION's resources through the runtime."
  (runtime-release-exec-session (reconciler-runtime reconciler) session))
