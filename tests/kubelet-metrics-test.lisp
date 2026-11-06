;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Verify the kubelet's own instrumentation: CRI method names map to the kubelet's
;;;; operation types, runtime operations and errors are counted with the kubelet's
;;;; buckets, Pod syncs are typed and Pod start latency observed once, departed Pods are
;;;; forgotten, and the process collector reads this process.

(in-package #:gr8s/tests)

(def-suite kubelet-metrics :in gr8s)
(in-suite kubelet-metrics)

(test cri-methods-map-to-kubelet-operation-types
  (loop for (method type) in '(("/runtime.v1.RuntimeService/ListPodSandbox" "list_podsandbox")
                               ("/runtime.v1.RuntimeService/RunPodSandbox" "run_podsandbox")
                               ("/runtime.v1.RuntimeService/PodSandboxStatus" "podsandbox_status")
                               ("/runtime.v1.RuntimeService/ListPodSandboxStats" "list_podsandbox_stats")
                               ("/runtime.v1.RuntimeService/CreateContainer" "create_container")
                               ("/runtime.v1.RuntimeService/ListContainerStats" "list_container_stats")
                               ("/runtime.v1.RuntimeService/ExecSync" "exec_sync")
                               ("/runtime.v1.RuntimeService/UpdateContainerResources" "update_container")
                               ("/runtime.v1.RuntimeService/Version" "version")
                               ("/runtime.v1.ImageService/PullImage" "pull_image")
                               ("/runtime.v1.ImageService/ImageFsInfo" "image_fs_info")
                               ("/gr8s.node.v1.NodeService/Connect" nil))
        do (is (equal type (gr8s::cri-operation-type method)) "~A" method)))

(test runtime-operations-and-pod-latencies-render-as-the-kubelet-does
  (let ((metrics (gr8s::make-kubelet-instrumentation)))
    (gr8s::note-runtime-operation "list_containers" 0.003 nil :metrics metrics)
    (gr8s::note-runtime-operation "list_containers" 0.02 t :metrics metrics)
    (is (equal "create" (gr8s::note-pod-sync "u1" "5" nil 0.2 :metrics metrics)))
    (is (equal "sync" (gr8s::note-pod-sync "u1" "5" nil 0.1 :metrics metrics)))
    (is (equal "update" (gr8s::note-pod-sync "u1" "6" nil 0.1 :metrics metrics)))
    (is (equal "kill" (gr8s::note-pod-sync "u1" "6" t 0.1 :metrics metrics)))
    (let ((first-seen (first (gethash "u1" (gr8s::kubelet-instrumentation-pods metrics)))))
      (gr8s::note-pod-phase "u1" "Pending" :metrics metrics :now (+ first-seen 1))
      (gr8s::note-pod-phase "u1" "Running" :metrics metrics :now (+ first-seen 7))
      ;; Only the first Running counts.
      (gr8s::note-pod-phase "u1" "Running" :metrics metrics :now (+ first-seen 70)))
    (let ((text (gr8s::kubelet-instrumentation-text :metrics metrics)))
      (is (search (format nil "kubelet_runtime_operations_total{operation_type=\"list_containers\"} 2~%") text))
      (is (search (format nil "kubelet_runtime_operations_errors_total{operation_type=\"list_containers\"} 1~%") text))
      (is (search "# HELP kubelet_runtime_operations_duration_seconds [ALPHA] Duration in seconds of runtime operations. Broken down by operation type." text))
      (is (search (format nil "kubelet_runtime_operations_duration_seconds_bucket{operation_type=\"list_containers\",le=\"0.005\"} 1~%") text))
      (is (search (format nil "kubelet_runtime_operations_duration_seconds_bucket{operation_type=\"list_containers\",le=\"0.03125\"} 2~%") text))
      (is (search (format nil "kubelet_runtime_operations_duration_seconds_count{operation_type=\"list_containers\"} 2~%") text))
      (is (search (format nil "kubelet_pod_start_duration_seconds_bucket{le=\"6\"} 0~%kubelet_pod_start_duration_seconds_bucket{le=\"8\"} 1~%") text))
      (is (search (format nil "kubelet_pod_start_duration_seconds_count 1~%") text))
      (is (search (format nil "kubelet_pod_worker_duration_seconds_count{operation_type=\"create\"} 1~%") text))
      (is (search (format nil "kubelet_pod_worker_duration_seconds_count{operation_type=\"kill\"} 1~%") text)))
    (gr8s::forget-unassigned-pod-records (make-hash-table :test #'equal) :metrics metrics)
    (is (zerop (hash-table-count (gr8s::kubelet-instrumentation-pods metrics))))))

(test cri-calls-are-counted-through-the-grpc-layer
  (let ((gr8s::*kubelet-instrumentation* (gr8s::make-kubelet-instrumentation))
        (gr8s::*upstream-grpc-call-unary* (lambda (&rest arguments) (declare (ignore arguments)) (error "transport failed"))))
    ;; The stubs call ag-grpc:call-unary, which is the instrumented call.
    (is (eq #'gr8s::instrumented-grpc-call-unary (symbol-function 'ag-grpc:call-unary)))
    (signals error (ag-grpc:call-unary nil "/runtime.v1.RuntimeService/Version" nil))
    (signals error (ag-grpc:call-unary nil "/gr8s.node.v1.NodeService/Connect" nil))
    (let ((text (gr8s::kubelet-instrumentation-text)))
      (is (search "kubelet_runtime_operations_total{operation_type=\"version\"} 1" text))
      (is (search "kubelet_runtime_operations_errors_total{operation_type=\"version\"} 1" text))
      (is (not (search "Connect" text))))))

(test process-collector-reads-this-process
  (let ((text (gr8s::process-metrics-text)))
    (is (search "# TYPE process_cpu_seconds_total counter" text))
    (is (search "# HELP process_resident_memory_bytes Resident memory size in bytes." text))
    (is (search "process_open_fds " text))
    (is (search "process_max_fds " text))
    (is (search "process_virtual_memory_bytes " text))
    (is (search "process_start_time_seconds " text))))
