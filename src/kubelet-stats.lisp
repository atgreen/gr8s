;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Measure what a node and its running containers use, as the kubelet's stats
;;;; provider does, and render it as the kubelet's /metrics/resource Prometheus text
;;;; and /stats/summary JSON. Containers come from CRI ListContainerStats, named by
;;;; their sandboxes; the node comes from the root cgroup and /proc. Each scrape reads
;;;; afresh and keeps only the previous node CPU sample, so measuring costs no memory
;;;; that grows with time. gr8s gives Pods no cgroup of their own, so a Pod's usage is
;;;; the sum of its running containers'.

(in-package #:gr8s)

(defstruct kubelet-usage
  "One measurement: TIME in Unix nanoseconds, CPU as cumulative core-nanoseconds and
nanocores, memory in bytes. A slot left NIL was not measured."
  time
  cpu-core-nanoseconds
  cpu-nano-cores
  memory-working-set
  memory-usage
  memory-rss
  memory-available
  page-faults
  major-page-faults)

(defstruct kubelet-container-stats
  "A running container: its Pod-spec NAME, START-TIME in Unix seconds, USAGE and writable layer."
  name
  start-time
  usage
  rootfs-used-bytes
  rootfs-inodes-used)

(defstruct kubelet-pod-stats
  "A Pod with a ready sandbox on this node and the stats of its running containers."
  name
  namespace
  uid
  start-time
  containers
  usage)

(defstruct kubelet-node-stats
  "Everything one scrape measured: the node itself and each of its Pods."
  name
  start-time
  usage
  pods)

;;; Containers, from the CRI runtime

(defun cri-optional-value (wrapper)
  "Return the number inside a CRI UInt64Value, or NIL when the runtime sent none."
  (and wrapper (gr8s.cri.v1::value wrapper)))

(defun cri-container-usage (stats)
  "Translate one CRI ContainerStats message into a KUBELET-USAGE."
  (let ((cpu (gr8s.cri.v1::cpu stats)) (memory (gr8s.cri.v1::memory stats)))
    (make-kubelet-usage
     :time (max (or (and cpu (gr8s.cri.v1::timestamp cpu)) 0) (or (and memory (gr8s.cri.v1::timestamp memory)) 0))
     :cpu-core-nanoseconds (and cpu (cri-optional-value (gr8s.cri.v1::usage-core-nano-seconds cpu)))
     :cpu-nano-cores (and cpu (cri-optional-value (gr8s.cri.v1::usage-nano-cores cpu)))
     :memory-working-set (and memory (cri-optional-value (gr8s.cri.v1::working-set-bytes memory)))
     :memory-usage (and memory (cri-optional-value (gr8s.cri.v1::usage-bytes memory)))
     :memory-rss (and memory (cri-optional-value (gr8s.cri.v1::rss-bytes memory)))
     :memory-available (and memory (cri-optional-value (gr8s.cri.v1::available-bytes memory)))
     :page-faults (and memory (cri-optional-value (gr8s.cri.v1::page-faults memory)))
     :major-page-faults (and memory (cri-optional-value (gr8s.cri.v1::major-page-faults memory))))))

(defun sum-kubelet-usage (usages)
  "Add container USAGES into their Pod's, leaving a measure NIL unless some container has it."
  (flet ((total (reader)
           (let ((values (remove nil (mapcar reader usages))))
             (and values (reduce #'+ values)))))
    (make-kubelet-usage :time (or (total #'kubelet-usage-time) 0)
                        :cpu-core-nanoseconds (total #'kubelet-usage-cpu-core-nanoseconds)
                        :cpu-nano-cores (total #'kubelet-usage-cpu-nano-cores)
                        :memory-working-set (total #'kubelet-usage-memory-working-set)
                        :memory-usage (total #'kubelet-usage-memory-usage)
                        :memory-rss (total #'kubelet-usage-memory-rss)
                        :page-faults (total #'kubelet-usage-page-faults)
                        :major-page-faults (total #'kubelet-usage-major-page-faults))))

(defun finish-kubelet-pod-usage (pod)
  "Give POD the sum of its containers' usage, timed by the newest of their measurements."
  (let ((usages (mapcar #'kubelet-container-stats-usage (kubelet-pod-stats-containers pod))))
    (setf (kubelet-pod-stats-usage pod)
          (let ((sum (sum-kubelet-usage usages)))
            (setf (kubelet-usage-time sum)
                  (reduce #'max usages :key (lambda (usage) (or (kubelet-usage-time usage) 0)) :initial-value 0))
            sum))
    pod))

(defun assemble-kubelet-pod-stats (sandboxes containers stats)
  "Join decoded CRI listings into Pod stats.
SANDBOXES are (id name namespace uid created-at-nanos) of ready sandboxes, CONTAINERS
are (id sandbox-id name running-p created-at-nanos), and STATS are (container-id . usage)
with optional writable-layer bytes and inodes as (container-id usage bytes inodes)."
  (let ((pods (make-hash-table :test #'equal)) (by-id (make-hash-table :test #'equal)))
    (loop for (id name namespace uid created) in sandboxes
          do (setf (gethash id pods)
                   (make-kubelet-pod-stats :name name :namespace namespace :uid uid
                                           :start-time (and created (plusp created) (floor created 1000000000)))))
    (dolist (container containers)
      (setf (gethash (first container) by-id) container))
    (loop for (id usage bytes inodes) in stats
          for container = (gethash id by-id)
          for pod = (and container (fourth container) (gethash (second container) pods))
          when pod
            do (push (make-kubelet-container-stats
                      :name (third container) :usage usage
                      :start-time (let ((created (fifth container)))
                                    (and created (plusp created) (/ created 1000000000)))
                      :rootfs-used-bytes bytes :rootfs-inodes-used inodes)
                     (kubelet-pod-stats-containers pod)))
    (let ((result nil))
      (maphash (lambda (id pod)
                 (declare (ignore id))
                 (setf (kubelet-pod-stats-containers pod)
                       (sort (kubelet-pod-stats-containers pod) #'string< :key #'kubelet-container-stats-name))
                 (push (finish-kubelet-pod-usage pod) result))
               pods)
      (sort result (lambda (left right)
                     (or (string< (kubelet-pod-stats-namespace left) (kubelet-pod-stats-namespace right))
                         (and (string= (kubelet-pod-stats-namespace left) (kubelet-pod-stats-namespace right))
                              (string< (kubelet-pod-stats-name left) (kubelet-pod-stats-name right)))))))))

(defun cri-kubelet-pod-stats (socket-path &key (timeout 10))
  "Measure every running gr8s container with three CRI listings on one connection."
  (let ((channel (make-unix-grpc-channel socket-path :timeout timeout))
        (managed (list (cons +gr8s-managed-label+ "true"))))
    (unwind-protect
         (let* ((stub (gr8s.cri.v1::make-runtime-service-stub channel))
                (sandboxes
                  (multiple-value-bind (response status)
                      (gr8s.cri.v1::runtime-service-list-pod-sandbox
                       stub (make-instance 'gr8s.cri.v1::list-pod-sandbox-request
                                           :filter (make-instance 'gr8s.cri.v1::pod-sandbox-filter
                                                                  :label-selector managed))
                       :timeout timeout)
                    (ensure-cri-status "ListPodSandbox" status)
                    (loop for sandbox in (gr8s.cri.v1::items response)
                          for metadata = (gr8s.cri.v1::metadata sandbox)
                          when (and metadata (= (cri-protobuf-state sandbox) gr8s.cri.v1::+podsandboxstate-sandbox_ready+))
                            collect (list (gr8s.cri.v1::id sandbox) (gr8s.cri.v1::name metadata)
                                          (gr8s.cri.v1::namespace metadata) (gr8s.cri.v1::uid metadata)
                                          (gr8s.cri.v1::created-at sandbox)))))
                (containers
                  (multiple-value-bind (response status)
                      (gr8s.cri.v1::runtime-service-list-containers
                       stub (make-instance 'gr8s.cri.v1::list-containers-request
                                           :filter (make-instance 'gr8s.cri.v1::container-filter
                                                                  :label-selector managed))
                       :timeout timeout)
                    (ensure-cri-status "ListContainers" status)
                    (loop for container in (gr8s.cri.v1::containers response)
                          for metadata = (gr8s.cri.v1::metadata container)
                          collect (list (gr8s.cri.v1::id container) (gr8s.cri.v1::pod-sandbox-id container)
                                        (or (cdr (assoc +gr8s-container-label+ (gr8s.cri.v1::labels container)
                                                        :test #'string=))
                                            (and metadata (gr8s.cri.v1::name metadata)))
                                        (= (cri-protobuf-state container) gr8s.cri.v1::+containerstate-container_running+)
                                        (gr8s.cri.v1::created-at container)))))
                (stats
                  (multiple-value-bind (response status)
                      (gr8s.cri.v1::runtime-service-list-container-stats
                       stub (make-instance 'gr8s.cri.v1::list-container-stats-request
                                           :filter (make-instance 'gr8s.cri.v1::container-stats-filter
                                                                  :label-selector managed))
                       :timeout timeout)
                    (ensure-cri-status "ListContainerStats" status)
                    (loop for entry in (gr8s.cri.v1::stats response)
                          for attributes = (gr8s.cri.v1::attributes entry)
                          for layer = (gr8s.cri.v1::writable-layer entry)
                          when attributes
                            collect (list (gr8s.cri.v1::id attributes) (cri-container-usage entry)
                                          (and layer (cri-optional-value (gr8s.cri.v1::used-bytes layer)))
                                          (and layer (cri-optional-value (gr8s.cri.v1::inodes-used layer))))))))
           (assemble-kubelet-pod-stats sandboxes containers stats))
      (ag-grpc:channel-close channel))))

(defgeneric runtime-kubelet-pod-stats (runtime)
  (:documentation "Return KUBELET-POD-STATS for each Pod RUNTIME runs, for the kubelet's stats endpoints."))

(defmethod runtime-kubelet-pod-stats ((runtime t))
  "A runtime without containers to measure reports no Pods."
  (declare (ignore runtime))
  nil)

(defmethod runtime-kubelet-pod-stats ((runtime containerd-runtime))
  "Ask the CRI runtime for its containers' statistics."
  (call-containerd-runtime
   (lambda () (cri-kubelet-pod-stats (containerd-runtime-socket-path runtime)))))

;;; The node, from the root cgroup and /proc

(defun read-key-value-file (path)
  "Return PATH's \"key value\" lines, as cgroup stat files and /proc/meminfo hold them, as an alist."
  (with-open-file (in path :if-does-not-exist nil)
    (when in
      (loop for line = (read-line in nil)
            while line
            for parts = (remove "" (uiop:split-string line :separator '(#\Space #\Tab #\:)) :test #'equal)
            when (and (second parts) (every #'digit-char-p (second parts)))
              collect (cons (first parts) (parse-integer (second parts)))))))

(defun proc-stat-cpu-nanoseconds (stat-text)
  "Return the CPU time /proc/stat's aggregate line counts as busy, in nanoseconds."
  (let ((line (find-if (lambda (line) (uiop:string-prefix-p "cpu " line))
                       (uiop:split-string stat-text :separator '(#\Newline)))))
    (when line
      (let ((fields (mapcar #'parse-integer (rest (remove "" (uiop:split-string line :separator '(#\Space)) :test #'equal)))))
        ;; user nice system idle iowait irq softirq steal: idle and iowait are not use.
        (* (+ (nth 0 fields) (nth 1 fields) (nth 2 fields) (or (nth 5 fields) 0) (or (nth 6 fields) 0) (or (nth 7 fields) 0))
           (/ 1000000000 100))))))

(defun node-boot-time (&optional (stat-path "/proc/stat"))
  "Return when this host booted, in Unix seconds, or NIL."
  (cdr (assoc "btime" (read-key-value-file stat-path) :test #'equal)))

(defun node-memory-usage (meminfo memory-stat)
  "Return the node's memory as the kubelet's cAdvisor reads the root cgroup: usage is all but
free memory, and the working set leaves out inactive file pages. MEMINFO and MEMORY-STAT are
alists of /proc/meminfo in kB and the root memory.stat in bytes."
  (flet ((info (key) (let ((kb (cdr (assoc key meminfo :test #'equal)))) (and kb (* 1024 kb))))
         (stat (key) (cdr (assoc key memory-stat :test #'equal))))
    (let* ((total (info "MemTotal")) (free (info "MemFree"))
           (usage (and total free (- total free)))
           (inactive (or (stat "inactive_file") (info "Inactive(file)") 0))
           (working (and usage (max 0 (- usage inactive)))))
      (when usage
        (make-kubelet-usage :memory-usage usage :memory-working-set working
                            :memory-available (max 0 (- total working))
                            :memory-rss (or (stat "anon") (info "AnonPages"))
                            :page-faults (stat "pgfault") :major-page-faults (stat "pgmajfault"))))))

(defvar *node-cpu-previous-sample* nil
  "The last node CPU reading as (unix-nanoseconds . core-nanoseconds), from which nanocores follow.")

(defun unix-time-nanoseconds ()
  "Return the current wall-clock time in Unix nanoseconds."
  (multiple-value-bind (seconds microseconds) (sb-ext:get-time-of-day)
    (+ (* seconds 1000000000) (* microseconds 1000))))

(defun node-cpu-nano-cores (now used)
  "Return the node's CPU rate since the previous reading, remembering this one."
  (let ((previous *node-cpu-previous-sample*))
    (setf *node-cpu-previous-sample* (cons now used))
    (when (and previous (> now (car previous)) (>= used (cdr previous)))
      (round (* 1000000000 (- used (cdr previous))) (- now (car previous))))))

(defun measure-node-usage (&key (cgroup-root "/sys/fs/cgroup/") (proc-root "/proc/"))
  "Measure the whole node's CPU and memory now."
  (let* ((now (unix-time-nanoseconds))
         (cpu-stat (read-key-value-file (merge-pathnames "cpu.stat" cgroup-root)))
         (used (let ((microseconds (cdr (assoc "usage_usec" cpu-stat :test #'equal))))
                 (if microseconds
                     (* 1000 microseconds)
                     (let ((text (ignore-errors (uiop:read-file-string (merge-pathnames "stat" proc-root)))))
                       (and text (proc-stat-cpu-nanoseconds text))))))
         (usage (or (node-memory-usage (read-key-value-file (merge-pathnames "meminfo" proc-root))
                                       (read-key-value-file (merge-pathnames "memory.stat" cgroup-root)))
                    (make-kubelet-usage))))
    (setf (kubelet-usage-time usage) now
          (kubelet-usage-cpu-core-nanoseconds usage) used
          (kubelet-usage-cpu-nano-cores usage) (and used (node-cpu-nano-cores now used)))
    usage))

(defun collect-kubelet-node-stats (runtime node-name)
  "Measure NODE-NAME and every Pod RUNTIME runs on it."
  (make-kubelet-node-stats :name node-name :start-time (node-boot-time)
                           :usage (measure-node-usage)
                           :pods (runtime-kubelet-pod-stats runtime)))

;;; Prometheus text, as the kubelet's registry gathers /metrics/resource

(defun prometheus-float-string (value)
  "Render VALUE as Go's strconv 'g' with shortest precision, which Prometheus text uses."
  (let ((value (coerce value 'double-float)))
    (cond
      ((zerop value) "0")
      ((minusp value) (concatenate 'string "-" (prometheus-float-string (- value))))
      (t
       (multiple-value-bind (point digits) (sb-impl::flonum-to-digits value)
         (let ((exponent (1- point)) (count (length digits)))
           (if (or (< exponent -4) (>= exponent 6))
               (format nil "~A~@[.~A~]e~:[+~;-~]~2,'0D" (char digits 0)
                       (and (> count 1) (subseq digits 1)) (minusp exponent) (abs exponent))
               (cond
                 ((<= point 0)
                  (format nil "0.~A~A" (make-string (- point) :initial-element #\0) digits))
                 ((>= point count)
                  (format nil "~A~A" digits (make-string (- point count) :initial-element #\0)))
                 (t (format nil "~A.~A" (subseq digits 0 point) (subseq digits point)))))))))))

(defun prometheus-label-value (value)
  "Escape a label value as the Prometheus text format requires."
  (with-output-to-string (out)
    (loop for char across value
          do (case char
               (#\\ (write-string "\\\\" out))
               (#\" (write-string "\\\"" out))
               (#\Newline (write-string "\\n" out))
               (t (write-char char out))))))

(defun write-prometheus-family (out name help type samples)
  "Write one metric family. SAMPLES are (labels value timestamp-ms), labels an alist already
sorted by name; a family without samples is left out, as a Prometheus registry gathers it."
  (when samples
    (format out "# HELP ~A ~A~%# TYPE ~A ~A~%" name help name type)
    (dolist (sample (sort (copy-list samples) #'string<
                          :key (lambda (sample) (format nil "~{~A~^,~}" (mapcar #'cdr (first sample))))))
      (destructuring-bind (labels value &optional timestamp) sample
        (format out "~A~@[{~A}~] ~A~@[ ~D~]~%" name
                (and labels (format nil "~{~A~^,~}"
                                    (mapcar (lambda (label)
                                              (format nil "~A=\"~A\"" (car label) (prometheus-label-value (cdr label))))
                                            labels)))
                (prometheus-float-string value) timestamp)))))

(defun nanoseconds-to-milliseconds (nanoseconds)
  "Return a Unix nanosecond time in the milliseconds Prometheus timestamps use, or NIL."
  (and nanoseconds (plusp nanoseconds) (floor nanoseconds 1000000)))

(defun kubelet-resource-metrics-text (stats &key error)
  "Render STATS as the kubelet's /metrics/resource. With ERROR true, only the scrape error is reported."
  (let ((families (make-hash-table :test #'equal)))
    (flet ((add (name labels value time)
             (when value
               (push (list labels value (nanoseconds-to-milliseconds time)) (gethash name families)))))
      (unless error
        (let ((node (kubelet-node-stats-usage stats)))
          (add "node_cpu_usage_seconds_total" nil
               (let ((used (kubelet-usage-cpu-core-nanoseconds node))) (and used (/ used 1d9)))
               (kubelet-usage-time node))
          (add "node_memory_working_set_bytes" nil (kubelet-usage-memory-working-set node) (kubelet-usage-time node)))
        (dolist (pod (kubelet-node-stats-pods stats))
          (let ((pod-labels (list (cons "namespace" (kubelet-pod-stats-namespace pod))
                                  (cons "pod" (kubelet-pod-stats-name pod)))))
            (dolist (container (kubelet-pod-stats-containers pod))
              (let ((labels (cons (cons "container" (kubelet-container-stats-name container)) pod-labels))
                    (usage (kubelet-container-stats-usage container)))
                (let ((start (kubelet-container-stats-start-time container)))
                  (when (and start (plusp start))
                    (push (list labels start nil) (gethash "container_start_time_seconds" families))))
                (add "container_cpu_usage_seconds_total" labels
                     (let ((used (kubelet-usage-cpu-core-nanoseconds usage))) (and used (/ used 1d9)))
                     (kubelet-usage-time usage))
                (add "container_memory_working_set_bytes" labels
                     (kubelet-usage-memory-working-set usage) (kubelet-usage-time usage))))
            (let ((usage (kubelet-pod-stats-usage pod)))
              (when usage
                (add "pod_cpu_usage_seconds_total" pod-labels
                     (let ((used (kubelet-usage-cpu-core-nanoseconds usage))) (and used (/ used 1d9)))
                     (kubelet-usage-time usage))
                (add "pod_memory_working_set_bytes" pod-labels
                     (kubelet-usage-memory-working-set usage) (kubelet-usage-time usage)))))))
      (push (list nil (if error 1 0) nil) (gethash "resource_scrape_error" families)))
    (with-output-to-string (out)
      (loop for (name help type)
              in '(("container_cpu_usage_seconds_total"
                    "[STABLE] Cumulative cpu time consumed by the container in core-seconds" "counter")
                   ("container_memory_working_set_bytes"
                    "[STABLE] Current working set of the container in bytes" "gauge")
                   ("container_start_time_seconds"
                    "[STABLE] Start time of the container since unix epoch in seconds" "gauge")
                   ("node_cpu_usage_seconds_total"
                    "[STABLE] Cumulative cpu time consumed by the node in core-seconds" "counter")
                   ("node_memory_working_set_bytes"
                    "[STABLE] Current working set of the node in bytes" "gauge")
                   ("pod_cpu_usage_seconds_total"
                    "[STABLE] Cumulative cpu time consumed by the pod in core-seconds" "counter")
                   ("pod_memory_working_set_bytes"
                    "[STABLE] Current working set of the pod in bytes" "gauge")
                   ("resource_scrape_error"
                    "[STABLE] 1 if there was an error while getting container metrics, 0 otherwise" "gauge"))
            do (write-prometheus-family out name help type (gethash name families))))))

;;; The stats summary, as the kubelet's /stats/summary JSON

(defun unix-nanoseconds-timestamp (nanoseconds)
  "Render Unix NANOSECONDS as a Kubernetes timestamp."
  (rfc3339-from-unix (floor (or nanoseconds 0) 1000000000)))

(defun kubelet-summary-cpu (usage)
  "Return USAGE's CPUStats object, or NIL when it has no CPU measure."
  (when (and usage (kubelet-usage-cpu-core-nanoseconds usage))
    (let ((object (core-object "time" (unix-nanoseconds-timestamp (kubelet-usage-time usage)))))
      (when (kubelet-usage-cpu-nano-cores usage)
        (setf (gethash "usageNanoCores" object) (kubelet-usage-cpu-nano-cores usage)))
      (setf (gethash "usageCoreNanoSeconds" object) (kubelet-usage-cpu-core-nanoseconds usage))
      object)))

(defun kubelet-summary-memory (usage)
  "Return USAGE's MemoryStats object, or NIL when it has no memory measure."
  (when (and usage (kubelet-usage-memory-working-set usage))
    (let ((object (core-object "time" (unix-nanoseconds-timestamp (kubelet-usage-time usage)))))
      (loop for (key reader) in '(("availableBytes" kubelet-usage-memory-available)
                                  ("usageBytes" kubelet-usage-memory-usage)
                                  ("workingSetBytes" kubelet-usage-memory-working-set)
                                  ("rssBytes" kubelet-usage-memory-rss)
                                  ("pageFaults" kubelet-usage-page-faults)
                                  ("majorPageFaults" kubelet-usage-major-page-faults))
            for value = (funcall reader usage)
            when value do (setf (gethash key object) value))
      object)))

(defun add-kubelet-usage-fields (object usage)
  "Set OBJECT's cpu and memory from USAGE where they were measured."
  (let ((cpu (kubelet-summary-cpu usage)) (memory (kubelet-summary-memory usage)))
    (when cpu (setf (gethash "cpu" object) cpu))
    (when memory (setf (gethash "memory" object) memory))
    object))

(defun kubelet-stats-summary-object (stats &key cpu-and-memory-only)
  "Return STATS as the kubelet's stats Summary. CPU-AND-MEMORY-ONLY leaves out filesystem use,
as only_cpu_and_memory=true asks."
  (let ((node (kubelet-node-stats-usage stats)))
    (core-object
     "node" (add-kubelet-usage-fields
             (core-object "nodeName" (kubelet-node-stats-name stats)
                          "startTime" (rfc3339-from-unix (or (kubelet-node-stats-start-time stats) 0)))
             node)
     "pods" (map 'vector
                 (lambda (pod)
                   (add-kubelet-usage-fields
                    (core-object
                     "podRef" (core-object "name" (kubelet-pod-stats-name pod)
                                           "namespace" (kubelet-pod-stats-namespace pod)
                                           "uid" (kubelet-pod-stats-uid pod))
                     "startTime" (rfc3339-from-unix (or (kubelet-pod-stats-start-time pod) 0))
                     "containers"
                     (map 'vector
                          (lambda (container)
                            (let ((object (add-kubelet-usage-fields
                                           (core-object "name" (kubelet-container-stats-name container)
                                                        "startTime" (rfc3339-from-unix
                                                                     (floor (or (kubelet-container-stats-start-time container) 0))))
                                           (kubelet-container-stats-usage container))))
                              (when (and (not cpu-and-memory-only) (kubelet-container-stats-rootfs-used-bytes container))
                                (let ((rootfs (core-object "time" (unix-nanoseconds-timestamp
                                                                   (kubelet-usage-time (kubelet-container-stats-usage container)))
                                                           "usedBytes" (kubelet-container-stats-rootfs-used-bytes container))))
                                  (when (kubelet-container-stats-rootfs-inodes-used container)
                                    (setf (gethash "inodesUsed" rootfs) (kubelet-container-stats-rootfs-inodes-used container)))
                                  (setf (gethash "rootfs" object) rootfs)))
                              object))
                          (kubelet-pod-stats-containers pod)))
                    (kubelet-pod-stats-usage pod)))
                 (kubelet-node-stats-pods stats)))))
