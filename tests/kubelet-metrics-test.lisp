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
        do (is (equal type (gr8s.kubelet::cri-operation-type method)) "~A" method)))

(test runtime-operations-and-pod-latencies-render-as-the-kubelet-does
  (let ((metrics (gr8s.kubelet::make-kubelet-instrumentation)))
    (gr8s.kubelet::note-runtime-operation "list_containers" 0.003 nil :metrics metrics)
    (gr8s.kubelet::note-runtime-operation "list_containers" 0.02 t :metrics metrics)
    (is (equal "create" (gr8s.kubelet::note-pod-sync "u1" "5" nil 0.2 :metrics metrics)))
    (is (equal "sync" (gr8s.kubelet::note-pod-sync "u1" "5" nil 0.1 :metrics metrics)))
    (is (equal "update" (gr8s.kubelet::note-pod-sync "u1" "6" nil 0.1 :metrics metrics)))
    (is (equal "kill" (gr8s.kubelet::note-pod-sync "u1" "6" t 0.1 :metrics metrics)))
    (let ((first-seen (first (gethash "u1" (gr8s.kubelet::kubelet-instrumentation-pods metrics)))))
      (gr8s.kubelet::note-pod-phase "u1" "Pending" :metrics metrics :now (+ first-seen 1))
      (gr8s.kubelet::note-pod-phase "u1" "Running" :metrics metrics :now (+ first-seen 7))
      ;; Only the first Running counts.
      (gr8s.kubelet::note-pod-phase "u1" "Running" :metrics metrics :now (+ first-seen 70)))
    (let ((text (gr8s.kubelet::kubelet-instrumentation-text :metrics metrics)))
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
    (gr8s.kubelet::forget-unassigned-pod-records (make-hash-table :test #'equal) :metrics metrics)
    (is (zerop (hash-table-count (gr8s.kubelet::kubelet-instrumentation-pods metrics))))))

(test cri-calls-are-counted-through-the-grpc-layer
  (let ((gr8s.kubelet::*kubelet-instrumentation* (gr8s.kubelet::make-kubelet-instrumentation))
        (gr8s.kubelet::*upstream-grpc-call-unary* (lambda (&rest arguments) (declare (ignore arguments)) (error "transport failed"))))
    ;; The stubs call ag-grpc:call-unary, which is the instrumented call.
    (is (eq #'gr8s.kubelet::instrumented-grpc-call-unary (symbol-function 'ag-grpc:call-unary)))
    (signals error (ag-grpc:call-unary nil "/runtime.v1.RuntimeService/Version" nil))
    (signals error (ag-grpc:call-unary nil "/gr8s.node.v1.NodeService/Connect" nil))
    (let ((text (gr8s.kubelet::kubelet-instrumentation-text)))
      (is (search "kubelet_runtime_operations_total{operation_type=\"version\"} 1" text))
      (is (search "kubelet_runtime_operations_errors_total{operation_type=\"version\"} 1" text))
      (is (not (search "Connect" text))))))

(test process-collector-reads-this-process
  (let ((text (gr8s.kubelet::process-metrics-text)))
    (is (search "# TYPE process_cpu_seconds_total counter" text))
    (is (search "# HELP process_resident_memory_bytes Resident memory size in bytes." text))
    (is (search "process_open_fds " text))
    (is (search "process_max_fds " text))
    (is (search "process_virtual_memory_bytes " text))
    (is (search "process_start_time_seconds " text))))

(test claim-volumes-report-kubelet-volume-stats-until-their-pod-is-cleaned-up
  (with-temporary-store (store directory)
    (let* ((runtime (gr8s.runtime.containerd::%make-containerd-runtime :log-root (merge-pathnames "logs/" directory) :resource-store store))
           (backing (merge-pathnames "backing/" directory)))
      (gr8s.resources::create-core-resource store "persistentvolumes" (storage-test-volume "provided" backing) nil)
      (gr8s.resources::create-core-resource store "persistentvolumeclaims" (storage-test-claim "data") "default")
      (gr8s.resources::reconcile-storage-bindings store)
      (let* ((pod (create-pod store (storage-test-pod "consumer" "data")))
             (volume (aref (gethash "volumes" (gethash "spec" (pod-to-object pod))) 0))
             (path (gr8s.kubelet::materialize-pod-volume runtime pod volume)))
        (is (equal (namestring backing) (namestring path)))
        (is (equal (list (list "default" "data" (namestring backing))) (gr8s.kubelet::runtime-claim-volume-paths runtime)))
        ;; The record is on disk, so a restarted agent still reports a consumer it didn't restart.
        (is (equal (list (list "default" "data" (namestring backing)))
                   (gr8s.kubelet::runtime-claim-volume-paths
                    (gr8s.runtime.containerd::%make-containerd-runtime :log-root (merge-pathnames "logs/" directory)))))
        ;; A second Pod on the same claim, and a path that can't be measured, add no series.
        (let ((text (gr8s.kubelet::kubelet-volume-stats-text
                     (append (gr8s.kubelet::runtime-claim-volume-paths runtime)
                             (list (list "default" "data" (namestring backing))
                                   (list "default" "gone" (namestring (merge-pathnames "missing/" directory))))))))
          (dolist (family '("capacity_bytes" "available_bytes" "used_bytes" "inodes" "inodes_free" "inodes_used"))
            (is (search (format nil "# TYPE kubelet_volume_stats_~A gauge" family) text))
            (is (= 1 (count-matches (cl-ppcre:quote-meta-chars
                                    (format nil "kubelet_volume_stats_~A{namespace=\"default\",persistentvolumeclaim=\"data\"} " family))
                                   text))
                "~A" family))
          (is (not (search "gone" text))))
        (destructuring-bind (capacity available used inodes free-inodes used-inodes)
            (gr8s.kubelet::filesystem-statistics (namestring backing))
          (is (<= available capacity))
          (is (<= used capacity))
          (is (= inodes (+ free-inodes used-inodes))))
        (is (search "kubelet_volume_stats_used_bytes{namespace=\"default\",persistentvolumeclaim=\"data\"}"
                    (gr8s.apiserver::kubelet-own-metrics-text nil "node-a" (gr8s.kubelet::runtime-claim-volume-paths runtime))))
        (gr8s.kubelet::cleanup-pod-volumes runtime (pod-uid pod))
        (is (null (gr8s.kubelet::runtime-claim-volume-paths runtime)))
        (is (equal "" (gr8s.kubelet::kubelet-volume-stats-text nil)))))))
