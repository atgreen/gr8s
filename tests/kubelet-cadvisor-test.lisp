;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Verify /metrics/cadvisor as cAdvisor renders it for containerd: cgroup v2 files
;;;; become CPU, CFS, memory, block I/O and spec series with the six base labels; a
;;;; sandbox reports network statistics; and device and net/dev parsing follow cAdvisor.

(in-package #:gr8s/tests)

(def-suite kubelet-cadvisor :in gr8s)
(in-suite kubelet-cadvisor)

(defmacro with-cgroup-fixture ((directory files) &body body)
  "Run BODY with DIRECTORY holding FILES, an alist of name to text."
  `(let ((,directory (uiop:ensure-directory-pathname
                      (sb-posix:mkdtemp (namestring (merge-pathnames "gr8s-cgroup-XXXXXX" (uiop:temporary-directory)))))))
     (unwind-protect
          (progn
            (loop for (name . text) in ,files
                  do (with-open-file (out (merge-pathnames name ,directory) :direction :output) (write-string text out)))
            ,@body)
       (uiop:delete-directory-tree ,directory :validate t :if-does-not-exist :ignore))))

(test net-dev-and-io-stat-parse-as-cadvisor-reads-them
  (let ((interfaces (gr8s.kubelet::parse-net-dev (format nil "~
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo:     100       2    0    0    0     0          0         0      100       2    0    0    0     0       0          0
  eth0:    5000      40    1    2    0     0          0         0     7000      50    3    4    0     0       0          0
vethabc:    999       9    0    0    0     0          0         0      999       9    0    0    0     0       0          0
"))))
    (is (equal '(("eth0" 5000 40 1 2 7000 50 3 4)) interfaces)))
  (is (equal '(("/dev/vda" 4096 8192 2 3))
             (gr8s.kubelet::parse-io-stat (format nil "252:0 rbytes=4096 wbytes=8192 rios=2 wios=3 dbytes=0 dios=0~%9:9 rbytes=1~%")
                                  :namer (lambda (device) (and (equal device "252:0") "/dev/vda"))))))

(test container-cgroup-renders-cadvisor-series
  (with-cgroup-fixture (directory '(("cpu.stat" . "usage_usec 2500000
user_usec 2000000
system_usec 500000
nr_periods 40
nr_throttled 7
throttled_usec 350000
")
                                    ("cpu.max" . "30000 100000
")
                                    ("cpu.weight" . "4
")
                                    ("memory.current" . "10485760
")
                                    ("memory.stat" . "anon 4194304
file 6291456
file_mapped 1048576
inactive_file 2097152
pgfault 30
pgmajfault 2
")
                                    ("memory.max" . "max
")
                                    ("memory.peak" . "12582912
")
                                    ("memory.events" . "low 0
high 0
max 5
oom 0
")))
    (let* ((entry (gr8s.kubelet::make-cadvisor-entry :id "/k8s.io/abc" :name "abc" :image "busybox:1.36" :pod "web"
                                             :namespace "default" :container "app" :directory (namestring directory)
                                             :started 1700000002000000000 :fs-used 8192 :fs-device "/dev/vda3"))
           (text (gr8s.kubelet::kubelet-cadvisor-metrics-text (list entry) :root-p nil :now 1700000010000000000))
           (labels "container=\"app\",id=\"/k8s.io/abc\",image=\"busybox:1.36\",name=\"abc\",namespace=\"default\",pod=\"web\""))
      (flet ((has (line) (search (format nil "~A~%" line) text)))
        (is (has "# HELP container_cpu_usage_seconds_total Cumulative cpu time consumed in seconds."))
        (is (has (format nil "container_cpu_usage_seconds_total{container=\"app\",cpu=\"total\",id=\"/k8s.io/abc\",image=\"busybox:1.36\",name=\"abc\",namespace=\"default\",pod=\"web\"} 2.5 1700000010000")))
        (is (has (format nil "container_cpu_user_seconds_total{~A} 2 1700000010000" labels)))
        (is (has (format nil "container_cpu_cfs_periods_total{~A} 40 1700000010000" labels)))
        (is (has (format nil "container_cpu_cfs_throttled_periods_total{~A} 7 1700000010000" labels)))
        (is (has (format nil "container_cpu_cfs_throttled_seconds_total{~A} 0.35 1700000010000" labels)))
        (is (has (format nil "container_memory_usage_bytes{~A} 1.048576e+07 1700000010000" labels)))
        (is (has (format nil "container_memory_working_set_bytes{~A} 8.388608e+06 1700000010000" labels)))
        (is (has (format nil "container_memory_rss{~A} 4.194304e+06 1700000010000" labels)))
        (is (has (format nil "container_memory_cache{~A} 6.291456e+06 1700000010000" labels)))
        (is (has (format nil "container_memory_mapped_file{~A} 1.048576e+06 1700000010000" labels)))
        (is (has (format nil "container_memory_max_usage_bytes{~A} 1.2582912e+07 1700000010000" labels)))
        (is (has (format nil "container_memory_failcnt{~A} 5 1700000010000" labels)))
        (is (has (format nil "container_memory_swap{~A} 0 1700000010000" labels)))
        (is (has (format nil "container_memory_failures_total{container=\"app\",failure_type=\"pgmajfault\",id=\"/k8s.io/abc\",image=\"busybox:1.36\",name=\"abc\",namespace=\"default\",pod=\"web\",scope=\"hierarchy\"} 2 1700000010000")))
        (is (has (format nil "container_fs_usage_bytes{container=\"app\",device=\"/dev/vda3\",id=\"/k8s.io/abc\",image=\"busybox:1.36\",name=\"abc\",namespace=\"default\",pod=\"web\"} 8192 1700000010000")))
        ;; Spec and start time carry no timestamp; an unlimited memory.max is 0.
        (is (has (format nil "container_spec_cpu_quota{~A} 30000" labels)))
        (is (has (format nil "container_spec_cpu_period{~A} 100000" labels)))
        (is (has (format nil "container_spec_cpu_shares{~A} 80" labels)))
        (is (has (format nil "container_spec_memory_limit_bytes{~A} 0" labels)))
        (is (has (format nil "container_start_time_seconds{~A} 1.700000002e+09" labels)))
        (is (has (format nil "container_last_seen{~A} 1.70000001e+09 1700000010000" labels)))
        ;; An application container reports no network statistics.
        (is (not (search "container_network" text)))))))

(test oom-kills-and-pressure-stalls-render-as-cadvisor-names-them
  (with-cgroup-fixture (directory '(("cpu.stat" . "usage_usec 1000000
")
                                    ("memory.current" . "1048576
")
                                    ("memory.stat" . "anon 1048576
")
                                    ("memory.events" . "low 0
high 2
max 5
oom 3
oom_kill 2
oom_group_kill 0
")
                                    ("cpu.pressure" . "some avg10=1.50 avg60=0.40 avg300=0.10 total=2500000
full avg10=0.00 avg60=0.00 avg300=0.00 total=500000
")
                                    ("memory.pressure" . "some avg10=0.00 avg60=0.00 avg300=0.00 total=1200000
full avg10=0.00 avg60=0.00 avg300=0.00 total=800000
")
                                    ;; An older kernel's cpu.pressure has no full line.
                                    ("io.pressure" . "some avg10=0.00 avg60=0.00 avg300=0.00 total=300000
")))
    (let* ((entry (gr8s.kubelet::make-cadvisor-entry :id "/k8s.io/abc" :name "abc" :image "busybox:1.36" :pod "web"
                                                     :namespace "default" :container "app" :directory (namestring directory)
                                                     :started 1700000002000000000))
           (text (gr8s.kubelet::kubelet-cadvisor-metrics-text (list entry) :root-p nil :now 1700000010000000000))
           (labels "container=\"app\",id=\"/k8s.io/abc\",image=\"busybox:1.36\",name=\"abc\",namespace=\"default\",pod=\"web\""))
      (flet ((has (line) (search (format nil "~A~%" line) text)))
        (is (has "# TYPE container_oom_events_total counter"))
        (is (has (format nil "container_oom_events_total{~A} 2 1700000010000" labels)) "oom_kill, not oom")
        (is (has (format nil "container_pressure_cpu_waiting_seconds_total{~A} 2.5 1700000010000" labels)))
        (is (has (format nil "container_pressure_cpu_stalled_seconds_total{~A} 0.5 1700000010000" labels)))
        (is (has (format nil "container_pressure_memory_waiting_seconds_total{~A} 1.2 1700000010000" labels)))
        (is (has (format nil "container_pressure_memory_stalled_seconds_total{~A} 0.8 1700000010000" labels)))
        (is (has (format nil "container_pressure_io_waiting_seconds_total{~A} 0.3 1700000010000" labels)))
        (is (not (search "container_pressure_io_stalled_seconds_total{" text)) "no full line, no series")))))

(test pressure-files-parse-as-the-kernel-writes-them
  (is (equal '(2500000 500000)
             (multiple-value-list
              (gr8s.kubelet::parse-pressure-totals
               (format nil "some avg10=1.50 avg60=0.40 avg300=0.10 total=2500000~%full avg10=0.00 avg60=0.00 avg300=0.00 total=500000~%")))))
  (is (equal '(nil nil) (multiple-value-list (gr8s.kubelet::parse-pressure-totals nil))) "no file, no PSI")
  (is (equal '(7 nil) (multiple-value-list (gr8s.kubelet::parse-pressure-totals (format nil "some total=7~%garbage~%"))))))

(test sandbox-reports-network-and-unthrottled-cgroups-no-cfs
  (with-cgroup-fixture (directory '(("cpu.stat" . "usage_usec 1000
nr_periods 0
")
                                    ("cpu.max" . "max 100000
")
                                    ("cgroup.procs" . "1
")))
    (let ((text (gr8s.kubelet::kubelet-cadvisor-metrics-text
                 (list (gr8s.kubelet::make-cadvisor-entry :id "/k8s.io/s1" :name "s1" :image "registry.k8s.io/pause:3.10"
                                                  :pod "web" :namespace "default" :container ""
                                                  :directory (namestring directory) :network-p t))
                 :root-p nil)))
      (is (not (search "container_cpu_cfs_periods_total" text)))
      (is (not (search "container_spec_cpu_quota" text)))
      ;; PID 1's network namespace stands in for the sandbox's here.
      (is (search "container_network_receive_bytes_total{container=\"\",id=\"/k8s.io/s1\",image=\"registry.k8s.io/pause:3.10\",interface=" text)))))

(test root-cgroup-and-machine-are-reported
  (let ((text (gr8s.kubelet::kubelet-cadvisor-metrics-text nil)))
    (is (search "container_cpu_usage_seconds_total{container=\"\",cpu=\"total\",id=\"/\",image=\"\",name=\"\",namespace=\"\",pod=\"\"}" text))
    (is (search "container_memory_working_set_bytes{container=\"\",id=\"/\"" text))
    (is (search "# TYPE machine_cpu_cores gauge" text))
    (is (search "machine_memory_bytes{boot_id=" text))))

(test filesystem-devices-come-from-the-mount-table
  (with-cgroup-fixture (directory '(("mountinfo" . "22 1 0:21 / / rw - btrfs /dev/vda3 rw,subvol=/root
25 22 0:23 / /var rw - btrfs /dev/vda4 rw
26 25 0:24 / /var/tmp/x rw - tmpfs tmpfs rw
")))
    (let ((table (namestring (merge-pathnames "mountinfo" directory))))
      (is (equal "/dev/vda4" (gr8s.kubelet::mountinfo-device "/var/lib/containerd/snapshots" table)))
      (is (equal "/dev/vda3" (gr8s.kubelet::mountinfo-device "/etc" table)))
      ;; A tmpfs has no block device, so the enclosing one's device is not claimed for it either.
      (is (null (gr8s.kubelet::mountinfo-device "/var/tmp/x/y" table))))))
