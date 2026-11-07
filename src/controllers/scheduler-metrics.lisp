;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Measure scheduling as kube-scheduler v1.37 does, for the API server's /metrics:
;;;; scheduler_schedule_attempts_total and scheduler_scheduling_attempt_duration_seconds
;;;; by result for the default-scheduler profile, scheduler_scheduling_algorithm_duration_seconds,
;;;; scheduler_pod_scheduling_sli_duration_seconds by attempts, and scheduler_pending_pods
;;;; by queue. gr8s schedules each unbound Pod on every reconcile pass rather than from
;;;; a queue with backoff, so each pass is an attempt, a Pod that failed one is in the
;;;; unschedulable queue, and the backoff queue is always empty. The attempt table holds
;;;; only Pods still waiting.

(in-package #:gr8s.controllers)

(defparameter +scheduler-attempt-buckets+ (exponential-buckets 0.001d0 2 15)
  "Attempt and algorithm latency bounds, ExponentialBuckets(0.001, 2, 15).")

(defparameter +scheduler-sli-buckets+ (exponential-buckets 0.01d0 2 20)
  "Pod scheduling SLI bounds, ExponentialBuckets(0.01, 2, 20).")

(defparameter +scheduler-attempt-table-limit+ 16384
  "Waiting Pods whose attempts are counted before the table starts over.")

(defstruct (scheduler-metrics (:constructor make-scheduler-metrics))
  "Attempt counts and latencies by result, algorithm latency, SLI latency by attempts, and each
waiting Pod's attempt count."
  (attempts (make-hash-table :test #'equal))
  (attempt-latencies (make-hash-table :test #'equal))
  (algorithm (make-bucketed-histogram +scheduler-attempt-buckets+))
  (sli (make-hash-table :test #'equal))
  (pods (make-hash-table :test #'equal))
  (lock (bt:make-lock "gr8s scheduler metrics")))

(defvar *scheduler-metrics* (make-scheduler-metrics)
  "This process's scheduling measurements.")

(defun note-scheduling-attempt (uid created result attempt-seconds algorithm-seconds
                                &key (metrics *scheduler-metrics*) (now (get-universal-time)))
  "Record one attempt to schedule Pod UID, created at universal time CREATED, ending in RESULT
(\"scheduled\", \"unschedulable\" or \"error\")."
  (bt:with-lock-held ((scheduler-metrics-lock metrics))
    (incf (gethash result (scheduler-metrics-attempts metrics) 0))
    (observe-histogram (or (gethash result (scheduler-metrics-attempt-latencies metrics))
                           (setf (gethash result (scheduler-metrics-attempt-latencies metrics))
                                 (make-bucketed-histogram +scheduler-attempt-buckets+)))
                       attempt-seconds)
    (when algorithm-seconds (observe-histogram (scheduler-metrics-algorithm metrics) algorithm-seconds))
    (let* ((pods (scheduler-metrics-pods metrics))
           (attempts (1+ (gethash uid pods 0))))
      (cond ((equal result "scheduled")
             (remhash uid pods)
             (let ((label (princ-to-string attempts)))
               (observe-histogram (or (gethash label (scheduler-metrics-sli metrics))
                                      (setf (gethash label (scheduler-metrics-sli metrics))
                                            (make-bucketed-histogram +scheduler-sli-buckets+)))
                                  (max 0 (- now (or created now))))))
            (t (when (>= (hash-table-count pods) +scheduler-attempt-table-limit+) (clrhash pods))
               (setf (gethash uid pods) attempts))))))

(defun scheduler-pending-pod-counts (store &key (metrics *scheduler-metrics*))
  "Count unbound, unfinished Pods by the queue kube-scheduler would hold them in, forgetting the
attempts of Pods no longer waiting."
  (let ((counts (list :active 0 :backoff 0 :gated 0 :unschedulable 0)) (waiting (make-hash-table :test #'equal)))
    (dolist (pod (list-pods store nil))
      (let ((object (pod-to-object pod)))
        (unless (or (pod-node-name pod) (deletion-requested-p pod)
                    (member (table-get object "status" "phase") '("Succeeded" "Failed") :test #'equal))
          (setf (gethash (pod-uid pod) waiting) t)
          (incf (getf counts (cond ((plusp (length (or (table-get object "spec" "schedulingGates") #()))) :gated)
                                   ((bt:with-lock-held ((scheduler-metrics-lock metrics))
                                      (gethash (pod-uid pod) (scheduler-metrics-pods metrics)))
                                    :unschedulable)
                                   (t :active)))))))
    (bt:with-lock-held ((scheduler-metrics-lock metrics))
      (loop for uid being the hash-keys of (scheduler-metrics-pods metrics)
            unless (gethash uid waiting) do (remhash uid (scheduler-metrics-pods metrics))))
    counts))

(defun scheduler-metrics-text (store &key (metrics *scheduler-metrics*))
  "Render the scheduler families, in name order."
  (let ((pending (and store (scheduler-pending-pod-counts store :metrics metrics))))
    (bt:with-lock-held ((scheduler-metrics-lock metrics))
      (with-output-to-string (out)
        (when pending
          (write-prometheus-family
           out "scheduler_pending_pods"
           "[STABLE] Number of pending pods, by the queue type. 'active' means number of pods in activeQ; 'backoff' means number of pods in backoffQ; 'unschedulable' means number of pods in unschedulableEntities that the scheduler attempted to schedule and failed; 'gated' is the number of unschedulable pods that the scheduler never attempted to schedule because they are gated; 'incomplete' means number of pods in incompletePodGroupPods; 'pending' means number of pods in pendingPodGroupPods."
           "gauge" (loop for (queue count) on pending by #'cddr
                         collect (list (list (cons "queue" (string-downcase (symbol-name queue)))) count))))
        (write-prometheus-histograms
         out "scheduler_pod_scheduling_sli_duration_seconds"
         "[BETA] E2e latency for a pod being scheduled, from the time the pod enters the scheduling queue and might involve multiple scheduling attempts."
         (loop for attempts being the hash-keys of (scheduler-metrics-sli metrics) using (hash-value histogram)
               collect (cons (list (cons "attempts" attempts)) histogram)))
        (write-prometheus-family
         out "scheduler_schedule_attempts_total"
         "[STABLE] Number of attempts to schedule pods, by the result. 'unschedulable' means a pod could not be scheduled, while 'error' means an internal scheduler problem."
         "counter" (loop for result being the hash-keys of (scheduler-metrics-attempts metrics) using (hash-value count)
                         collect (list (list (cons "profile" "default-scheduler") (cons "result" result)) count)))
        (when (plusp (histogram-count (scheduler-metrics-algorithm metrics)))
          (write-prometheus-histograms out "scheduler_scheduling_algorithm_duration_seconds"
                                       "[BETA] Scheduling algorithm latency in seconds"
                                       (list (cons nil (scheduler-metrics-algorithm metrics)))))
        (write-prometheus-histograms
         out "scheduler_scheduling_attempt_duration_seconds"
         "[STABLE] Scheduling attempt latency in seconds (scheduling algorithm + binding)"
         (loop for result being the hash-keys of (scheduler-metrics-attempt-latencies metrics) using (hash-value histogram)
               collect (cons (list (cons "profile" "default-scheduler") (cons "result" result)) histogram)))))))
