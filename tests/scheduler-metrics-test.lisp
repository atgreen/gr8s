;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Verify the scheduler's metrics: attempts and their latency by result for the
;;;; default-scheduler profile, algorithm latency for placed Pods, the SLI histogram by
;;;; attempts, and pending Pods by queue, with departed Pods forgotten.

(in-package #:gr8s/tests)

(def-suite scheduler-metrics :in gr8s)
(in-suite scheduler-metrics)

(test scheduling-attempts-render-as-kube-scheduler-does
  (with-temporary-store (store path)
    (values path)
    (let ((metrics (gr8s::make-scheduler-metrics))
          (pod (create-pod store (parse-pod *valid-pod-json*))))
      (is (null (gr8s::pod-node-name pod)))
      ;; Never attempted, it waits in the active queue.
      (is (= 1 (getf (gr8s::scheduler-pending-pod-counts store :metrics metrics) :active)))
      (gr8s::note-scheduling-attempt (pod-uid pod) 1000 "unschedulable" 0.002 nil :metrics metrics :now 1003)
      (gr8s::note-scheduling-attempt (pod-uid pod) 1000 "unschedulable" 0.002 nil :metrics metrics :now 1004)
      (let ((pending (gr8s::scheduler-pending-pod-counts store :metrics metrics)))
        (is (= 1 (getf pending :unschedulable)))
        (is (= 0 (getf pending :active)))
        (is (= 0 (getf pending :backoff))))
      (gr8s::note-scheduling-attempt (pod-uid pod) 1000 "scheduled" 0.0015 0.0004 :metrics metrics :now 1005)
      (let ((text (gr8s::scheduler-metrics-text store :metrics metrics)))
        (is (search (format nil "scheduler_schedule_attempts_total{profile=\"default-scheduler\",result=\"unschedulable\"} 2~%") text))
        (is (search (format nil "scheduler_schedule_attempts_total{profile=\"default-scheduler\",result=\"scheduled\"} 1~%") text))
        (is (search (format nil "scheduler_scheduling_attempt_duration_seconds_bucket{profile=\"default-scheduler\",result=\"scheduled\",le=\"0.001\"} 0~%scheduler_scheduling_attempt_duration_seconds_bucket{profile=\"default-scheduler\",result=\"scheduled\",le=\"0.002\"} 1~%") text))
        (is (search (format nil "scheduler_scheduling_algorithm_duration_seconds_count 1~%") text))
        ;; Three attempts, five seconds after creation.
        (is (search (format nil "scheduler_pod_scheduling_sli_duration_seconds_bucket{attempts=\"3\",le=\"5.12\"} 1~%") text))
        (is (search (format nil "scheduler_pod_scheduling_sli_duration_seconds_bucket{attempts=\"3\",le=\"2.56\"} 0~%") text))
        (is (search "# HELP scheduler_pending_pods [STABLE] Number of pending pods, by the queue type." text))
        (is (search (format nil "scheduler_pending_pods{queue=\"gated\"} 0~%") text)))
      ;; A scheduled Pod's attempts are forgotten.
      (is (zerop (hash-table-count (gr8s::scheduler-metrics-pods metrics)))))))

(test departed-pods-are-forgotten
  (with-temporary-store (store path)
    (values path)
    (let ((metrics (gr8s::make-scheduler-metrics)))
      (gr8s::note-scheduling-attempt "gone" 1000 "unschedulable" 0.001 nil :metrics metrics)
      (gr8s::scheduler-pending-pod-counts store :metrics metrics)
      (is (zerop (hash-table-count (gr8s::scheduler-metrics-pods metrics)))))))
