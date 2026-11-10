;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Controller-loop execution and observed workload generations answer different
;;;; operational questions. Keep both local, with fixed labels and no payload
;;;; encoding; a normally returned pass alone does not establish workload readiness.

(in-package #:gr8s.server)

(defun call-with-reconciliation-metrics (worker function)
  "Observe one leader-admitted pass without changing its values or unwinding.
Aborted passes count as failures. Duration includes patch-domain admission waits."
  (let ((started (get-internal-real-time)) (completed nil))
    (bt:with-lock-held ((reconciliation-worker-lock worker))
      (incf (reconciliation-worker-metrics-attempts worker))
      (incf (reconciliation-worker-metrics-in-flight worker)))
    (unwind-protect
         (multiple-value-prog1 (funcall function) (setf completed t))
      (let ((finished (get-internal-real-time)))
        (bt:with-lock-held ((reconciliation-worker-lock worker))
          (let ((elapsed (max 0 (- finished started))))
            (decf (reconciliation-worker-metrics-in-flight worker))
            (incf (reconciliation-worker-metrics-duration-total worker) elapsed)
            (setf (reconciliation-worker-metrics-duration-last worker) elapsed
                  (reconciliation-worker-metrics-duration-max worker)
                  (max elapsed (reconciliation-worker-metrics-duration-max worker)))
            (if completed
                (progn (incf (reconciliation-worker-metrics-completed worker))
                       (setf (reconciliation-worker-metrics-last-success worker) finished))
                (incf (reconciliation-worker-metrics-failures worker)))))))))

(defun reconciliation-worker-metrics-text (worker)
  "Copy a local worker sample under its mutex and render outside it. NIL omits it."
  (unless worker (return-from reconciliation-worker-metrics-text ""))
  (destructuring-bind (attempts completed failures in-flight total last maximum success running)
      (bt:with-lock-held ((reconciliation-worker-lock worker))
        (list (reconciliation-worker-metrics-attempts worker)
              (reconciliation-worker-metrics-completed worker)
              (reconciliation-worker-metrics-failures worker)
              (reconciliation-worker-metrics-in-flight worker)
              (reconciliation-worker-metrics-duration-total worker)
              (reconciliation-worker-metrics-duration-last worker)
              (reconciliation-worker-metrics-duration-max worker)
              (reconciliation-worker-metrics-last-success worker)
              (if (and (not (reconciliation-worker-stop-requested worker))
                       (reconciliation-worker-thread worker)
                       (bt:thread-alive-p (reconciliation-worker-thread worker))) 1 0)))
    (with-output-to-string (out)
      (flet ((emit (name help type value)
               (gr8s.kubelet::write-prometheus-family
                out (concatenate 'string "gr8s_reconciliation_" name) help type (list (list nil value))))
             (seconds (ticks) (/ ticks internal-time-units-per-second 1d0)))
        (emit "attempts_total" "Leader-admitted controller pass attempts." "counter" attempts)
        (emit "completed_total" "Controller passes that returned normally; not proof of workload readiness." "counter" completed)
        (emit "failures_total" "Controller passes that failed or unwound abnormally." "counter" failures)
        (emit "in_flight" "Controller passes currently executing or waiting for patch-domain admission." "gauge" in-flight)
        (emit "worker_running" "One while the reconciliation thread is alive and not stopping." "gauge" running)
        (emit "duration_seconds_total" "Elapsed controller-pass time, including failed attempts." "counter" (seconds total))
        (emit "duration_seconds_last" "Elapsed time of the latest controller pass." "gauge" (seconds last))
        (emit "duration_seconds_max" "Longest elapsed controller-pass time since worker creation." "gauge" (seconds maximum))
        (when success
          (emit "last_success_age_seconds" "Monotonic age of the latest normally returned controller pass." "gauge"
                (seconds (max 0 (- (get-internal-real-time) success)))))))))

(defun workload-generation-metrics-text (&optional store)
  "Count fixed workload kinds whose desired generation is not observed locally.
Read scalar metadata under the raw store mutex; never encode or copy payloads."
  (unless store (return-from workload-generation-metrics-text ""))
  (let* ((kinds '("deployments" "replicasets" "replicationcontrollers" "statefulsets" "daemonsets"))
         (totals (make-array 5 :initial-element 0))
         (lagging (make-array 5 :initial-element 0)))
    (bt:with-lock-held ((pod-store-lock store))
      (maphash
       (lambda (key object)
         (let ((index (position (first key) kinds :test #'equal)))
           (when index
             (incf (aref totals index))
             (let* ((metadata (gethash "metadata" object)) (status (gethash "status" object))
                    (desired (and (hash-table-p metadata) (gethash "generation" metadata)))
                    (observed (and (hash-table-p status) (gethash "observedGeneration" status))))
               (unless (and (typep observed '(integer 0 *))
                            (>= observed (if (typep desired '(integer 0 *)) desired 1)))
                 (incf (aref lagging index)))))))
       (pod-store-resources store)))
    (with-output-to-string (out)
      (loop for (name help counts) in
              (list (list "gr8s_workload_objects" "Local workload objects by fixed kind." totals)
                    (list "gr8s_workload_generation_lag_objects" "Local workloads whose desired generation is not observed; not a readiness count." lagging))
            do (gr8s.kubelet::write-prometheus-family
                out name help "gauge"
                (loop for kind in kinds for index from 0
                      collect (list (list (cons "kind" kind)) (aref counts index))))))))
