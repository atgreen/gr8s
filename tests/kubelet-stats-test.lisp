;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Verify the kubelet stats that metrics-server and kubectl read: how CRI listings
;;;; join into Pods, how the node's cgroup and /proc files become usage, and the exact
;;;; /metrics/resource text and /stats/summary JSON rendered from them.

(in-package #:gr8s/tests)

(def-suite kubelet-stats :in gr8s)
(in-suite kubelet-stats)

(test prometheus-floats-render-as-go-shortest-g
  (loop for (value text) in '((0 "0") (1 "1") (357.35d0 "357.35") (26066944 "2.6066944e+07")
                              (123456 "123456") (1000000 "1e+06") (0.00012d0 "0.00012")
                              (1.5d-5 "1.5e-05") (1.633253812d9 "1.633253812e+09") (-2.5d0 "-2.5"))
        do (is (equal text (gr8s::prometheus-float-string value)))))

(defun kubelet-test-usage (time cpu memory)
  "Return a container measurement taken at TIME nanoseconds."
  (gr8s::make-kubelet-usage :time time :cpu-core-nanoseconds cpu :memory-working-set memory))

(test cri-listings-join-into-pods-of-running-containers
  (let ((pods (gr8s::assemble-kubelet-pod-stats
               '(("s1" "web" "default" "u1" 1700000000000000000)
                 ("s2" "idle" "kube-system" "u2" 1700000001000000000))
               '(("c1" "s1" "app" t 1700000002000000000)
                 ("c2" "s1" "sidecar" t 1700000003000000000)
                 ("c3" "s1" "old" nil 1600000000000000000)
                 ("c4" "gone" "orphan" t 1700000000000000000))
               (list (list "c1" (kubelet-test-usage 1700000010000000000 3000000000 1000) 4096 7)
                     (list "c2" (kubelet-test-usage 1700000011000000000 500000000 24) nil nil)
                     (list "c3" (kubelet-test-usage 1700000011000000000 9 9) nil nil)
                     (list "c4" (kubelet-test-usage 1700000011000000000 9 9) nil nil)))))
    ;; Sorted by namespace then name; a ready sandbox without running containers still counts.
    (is (equal '("web" "idle") (mapcar #'gr8s::kubelet-pod-stats-name pods)))
    (let ((web (first pods)))
      (is (equal "u1" (gr8s::kubelet-pod-stats-uid web)))
      (is (= 1700000000 (gr8s::kubelet-pod-stats-start-time web)))
      ;; Exited containers and containers of unknown sandboxes are left out.
      (is (equal '("app" "sidecar") (mapcar #'gr8s::kubelet-container-stats-name (gr8s::kubelet-pod-stats-containers web))))
      (is (= 4096 (gr8s::kubelet-container-stats-rootfs-used-bytes (first (gr8s::kubelet-pod-stats-containers web)))))
      (let ((usage (gr8s::kubelet-pod-stats-usage web)))
        (is (= 3500000000 (gr8s::kubelet-usage-cpu-core-nanoseconds usage)))
        (is (= 1024 (gr8s::kubelet-usage-memory-working-set usage)))
        (is (= 1700000011000000000 (gr8s::kubelet-usage-time usage)))
        (is (null (gr8s::kubelet-usage-memory-rss usage)))))
    (is (null (gr8s::kubelet-usage-cpu-core-nanoseconds (gr8s::kubelet-pod-stats-usage (second pods)))))))

(test node-usage-reads-the-root-cgroup-and-proc
  (let ((directory (uiop:ensure-directory-pathname
                    (format nil "/tmp/gr8s-kubelet-stats-~D/" (random 1000000000)))))
    (unwind-protect
         (progn
           (ensure-directories-exist directory)
           (flet ((put (name text) (with-open-file (out (merge-pathnames name directory) :direction :output)
                                     (write-string text out))))
             (put "cpu.stat" (format nil "usage_usec 2500000~%user_usec 2000000~%"))
             (put "meminfo" (format nil "MemTotal:       4000 kB~%MemFree:        1000 kB~%Inactive(file):  999 kB~%"))
             (put "memory.stat" (format nil "anon 1048576~%inactive_file 1024000~%pgfault 10~%pgmajfault 2~%"))
             (put "stat" (format nil "cpu  1 2 3 4 5 6 7 8~%btime 1700000000~%")))
           (let ((gr8s::*node-cpu-previous-sample* nil))
             (let ((usage (gr8s::measure-node-usage :cgroup-root directory :proc-root directory)))
               (is (= 2500000000 (gr8s::kubelet-usage-cpu-core-nanoseconds usage)))
               (is (null (gr8s::kubelet-usage-cpu-nano-cores usage)))
               (is (= (* 3000 1024) (gr8s::kubelet-usage-memory-usage usage)))
               ;; The root memory.stat's inactive file pages win over /proc/meminfo's.
               (is (= (- (* 3000 1024) 1024000) (gr8s::kubelet-usage-memory-working-set usage)))
               (is (= (- (* 4000 1024) (- (* 3000 1024) 1024000)) (gr8s::kubelet-usage-memory-available usage)))
               (is (= 1048576 (gr8s::kubelet-usage-memory-rss usage)))
               (is (= 2 (gr8s::kubelet-usage-major-page-faults usage))))
             ;; A second reading gives a rate.
             (setf gr8s::*node-cpu-previous-sample*
                   (cons (- (gr8s::unix-time-nanoseconds) 1000000000) 1500000000))
             (let ((cores (gr8s::kubelet-usage-cpu-nano-cores
                           (gr8s::measure-node-usage :cgroup-root directory :proc-root directory))))
               (is (< 900000000 cores 1000000001))))
           (is (= 1700000000 (gr8s::node-boot-time (merge-pathnames "stat" directory))))
           ;; Without cpu.stat, /proc/stat's busy ticks are used: user nice system irq softirq steal.
           (delete-file (merge-pathnames "cpu.stat" directory))
           (is (= (* (+ 1 2 3 6 7 8) 10000000)
                  (gr8s::kubelet-usage-cpu-core-nanoseconds
                   (gr8s::measure-node-usage :cgroup-root directory :proc-root directory)))))
      (uiop:delete-directory-tree directory :validate t :if-does-not-exist :ignore))))

(defun kubelet-test-node-stats ()
  "Return a node with one two-container Pod, as a scrape measures it."
  (gr8s::make-kubelet-node-stats
   :name "node-a" :start-time 1700000000
   :usage (gr8s::make-kubelet-usage :time 1700000020123456789 :cpu-core-nanoseconds 357350000000
                                    :cpu-nano-cores 250000000 :memory-working-set 1468006400
                                    :memory-usage 2000000000 :memory-available 2000000000)
   :pods (list (gr8s::make-kubelet-pod-stats
                :name "web" :namespace "default" :uid "u1" :start-time 1700000000
                :containers (list (gr8s::make-kubelet-container-stats
                                   :name "app" :start-time 1700000002
                                   :usage (kubelet-test-usage 1700000010000000000 3000000000 26066944))
                                  (gr8s::make-kubelet-container-stats
                                   :name "sidecar" :start-time 1700000003
                                   :usage (kubelet-test-usage 1700000011000000000 500000000 1024)))
                :usage (kubelet-test-usage 1700000011000000000 3500000000 26067968)))))

(test resource-metrics-match-the-kubelet-text
  (is (equal (format nil "~
# HELP container_cpu_usage_seconds_total [STABLE] Cumulative cpu time consumed by the container in core-seconds
# TYPE container_cpu_usage_seconds_total counter
container_cpu_usage_seconds_total{container=\"app\",namespace=\"default\",pod=\"web\"} 3 1700000010000
container_cpu_usage_seconds_total{container=\"sidecar\",namespace=\"default\",pod=\"web\"} 0.5 1700000011000
# HELP container_memory_working_set_bytes [STABLE] Current working set of the container in bytes
# TYPE container_memory_working_set_bytes gauge
container_memory_working_set_bytes{container=\"app\",namespace=\"default\",pod=\"web\"} 2.6066944e+07 1700000010000
container_memory_working_set_bytes{container=\"sidecar\",namespace=\"default\",pod=\"web\"} 1024 1700000011000
# HELP container_start_time_seconds [STABLE] Start time of the container since unix epoch in seconds
# TYPE container_start_time_seconds gauge
container_start_time_seconds{container=\"app\",namespace=\"default\",pod=\"web\"} 1.700000002e+09
container_start_time_seconds{container=\"sidecar\",namespace=\"default\",pod=\"web\"} 1.700000003e+09
# HELP node_cpu_usage_seconds_total [STABLE] Cumulative cpu time consumed by the node in core-seconds
# TYPE node_cpu_usage_seconds_total counter
node_cpu_usage_seconds_total 357.35 1700000020123
# HELP node_memory_working_set_bytes [STABLE] Current working set of the node in bytes
# TYPE node_memory_working_set_bytes gauge
node_memory_working_set_bytes 1.4680064e+09 1700000020123
# HELP pod_cpu_usage_seconds_total [STABLE] Cumulative cpu time consumed by the pod in core-seconds
# TYPE pod_cpu_usage_seconds_total counter
pod_cpu_usage_seconds_total{namespace=\"default\",pod=\"web\"} 3.5 1700000011000
# HELP pod_memory_working_set_bytes [STABLE] Current working set of the pod in bytes
# TYPE pod_memory_working_set_bytes gauge
pod_memory_working_set_bytes{namespace=\"default\",pod=\"web\"} 2.6067968e+07 1700000011000
# HELP resource_scrape_error [STABLE] 1 if there was an error while getting container metrics, 0 otherwise
# TYPE resource_scrape_error gauge
resource_scrape_error 0
")
             (gr8s::kubelet-resource-metrics-text (kubelet-test-node-stats))))
  ;; A failed measurement reports only the error, as the kubelet's collector does.
  (is (equal (format nil "~
# HELP resource_scrape_error [STABLE] 1 if there was an error while getting container metrics, 0 otherwise
# TYPE resource_scrape_error gauge
resource_scrape_error 1
")
             (gr8s::kubelet-resource-metrics-text nil :error t)))
  ;; Label values are escaped.
  (is (search "pod=\"a\\\"b\\\\c\""
              (gr8s::kubelet-resource-metrics-text
               (gr8s::make-kubelet-node-stats
                :usage (gr8s::make-kubelet-usage)
                :pods (list (gr8s::make-kubelet-pod-stats :name "a\"b\\c" :namespace "n" :containers nil
                                                          :usage (kubelet-test-usage 1 1 1))))))))

(test stats-summary-has-the-kubelet-shape
  (let* ((summary (gr8s::kubelet-stats-summary-object (kubelet-test-node-stats)))
         (node (gethash "node" summary))
         (pod (aref (gethash "pods" summary) 0))
         (container (aref (gethash "containers" pod) 0)))
    (is (equal "node-a" (gethash "nodeName" node)))
    (is (equal "2023-11-14T22:13:20Z" (gethash "startTime" node)))
    (is (= 357350000000 (gr8s::table-get node "cpu" "usageCoreNanoSeconds")))
    (is (= 250000000 (gr8s::table-get node "cpu" "usageNanoCores")))
    (is (equal "2023-11-14T22:13:40Z" (gr8s::table-get node "cpu" "time")))
    (is (= 1468006400 (gr8s::table-get node "memory" "workingSetBytes")))
    (is (= 2000000000 (gr8s::table-get node "memory" "availableBytes")))
    ;; Unmeasured fields are omitted, as the kubelet's omitempty tags do.
    (is (null (nth-value 1 (gethash "rssBytes" (gethash "memory" node)))))
    (is (equal '("default" "web" "u1")
               (list (gr8s::table-get pod "podRef" "namespace") (gr8s::table-get pod "podRef" "name")
                     (gr8s::table-get pod "podRef" "uid"))))
    (is (= 3500000000 (gr8s::table-get pod "cpu" "usageCoreNanoSeconds")))
    (is (equal "app" (gethash "name" container)))
    (is (equal "2023-11-14T22:13:22Z" (gethash "startTime" container)))
    (is (= 26066944 (gr8s::table-get container "memory" "workingSetBytes")))
    ;; It serializes as JSON a client can read back.
    (is (= 2 (length (gethash "containers"
                              (aref (gethash "pods" (com.inuoe.jzon:parse (com.inuoe.jzon:stringify summary))) 0)))))))
