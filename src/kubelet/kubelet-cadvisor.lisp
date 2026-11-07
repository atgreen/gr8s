;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Render the kubelet's /metrics/cadvisor as cAdvisor v0.60 (vendored by kubelet
;;;; v1.37) does for a containerd node: each running container's and each sandbox's
;;;; cgroup v2 statistics, labelled container, id, image, name, namespace and pod, plus
;;;; the root cgroup and the machine. The values are read on each scrape from the cgroup
;;;; files cAdvisor's libcontainer handler reads, and the labels come from CRI listings.
;;;; As with containerd under cAdvisor, a sandbox has container="" and the pause image,
;;;; and only sandboxes and the root report network statistics. Nothing is kept between
;;;; scrapes except the container-to-cgroup directory map and the pause image's name.

(in-package #:gr8s.kubelet)

(defparameter *cgroup-root* "/sys/fs/cgroup/"
  "Where the unified cgroup hierarchy is mounted.")

(defvar *cadvisor-cgroup-directories* (make-hash-table :test #'equal)
  "Container ID to its cgroup directory relative to the root, found once per container.")

(defvar *cadvisor-cgroup-lock* (bt:make-lock "gr8s cadvisor cgroup map"))

(defvar *cadvisor-pause-image* nil
  "The pinned sandbox image, as CRI lists it, once found.")

(defstruct cadvisor-entry
  "One cgroup cAdvisor reports: its base labels, where its files are, and what else applies."
  id name image pod namespace container directory network-p started fs-used fs-device)

(defun cgroup-file-alist (directory file)
  "Read a cgroup \"key value\" FILE under DIRECTORY as an alist, or NIL when it is absent."
  (read-key-value-file (merge-pathnames file (uiop:ensure-directory-pathname directory))))

(defun cgroup-file-value (directory file)
  "Read a cgroup file holding one number, or NIL when absent or \"max\"."
  (let ((text (ignore-errors (uiop:read-file-string (merge-pathnames file (uiop:ensure-directory-pathname directory))))))
    (and text (let ((word (string-trim '(#\Space #\Newline) text)))
                (and (plusp (length word)) (every #'digit-char-p word) (parse-integer word))))))

(defun find-container-cgroup (id)
  "Return ID's cgroup directory, e.g. \"/k8s.io/<id>\", looking under the root's first two levels once."
  (or (bt:with-lock-held (*cadvisor-cgroup-lock*) (gethash id *cadvisor-cgroup-directories*))
      (let ((found
              (or (and (probe-file (format nil "~Ak8s.io/~A/" *cgroup-root* id)) (format nil "/k8s.io/~A" id))
                  (loop for first in (ignore-errors (uiop:subdirectories *cgroup-root*))
                        for relative = (enough-namestring first *cgroup-root*)
                        thereis (and (probe-file (merge-pathnames (format nil "~A/" id) first))
                                     (format nil "/~A~A" relative id))))))
        (when found
          (bt:with-lock-held (*cadvisor-cgroup-lock*)
            (setf (gethash id *cadvisor-cgroup-directories*) found)))
        found)))

(defun forget-departed-cgroups (ids)
  "Drop map entries for containers no longer listed, so the map stays the size of the node."
  (bt:with-lock-held (*cadvisor-cgroup-lock*)
    (loop for id being the hash-keys of *cadvisor-cgroup-directories*
          unless (member id ids :test #'equal) do (remhash id *cadvisor-cgroup-directories*))))

(defun block-device-name (major-minor)
  "Return \"/dev/<name>\" for a MAJOR:MINOR block device, as cAdvisor names devices, or NIL."
  (let ((uevent (ignore-errors (uiop:read-file-string (format nil "/sys/dev/block/~A/uevent" major-minor)))))
    (when uevent
      (loop for line in (uiop:split-string uevent :separator '(#\Newline))
            when (uiop:string-prefix-p "DEVNAME=" line)
              return (concatenate 'string "/dev/" (subseq line 8))))))

(defun parse-io-stat (text &key (namer #'block-device-name))
  "Parse cgroup v2 io.stat TEXT into (device rbytes wbytes rios wios) per device NAMER names."
  (loop for line in (uiop:split-string (or text "") :separator '(#\Newline))
        for fields = (remove "" (uiop:split-string line :separator '(#\Space)) :test #'equal)
        for device = (and fields (funcall namer (first fields)))
        when device
          collect (flet ((field (key)
                           (let ((pair (find-if (lambda (field) (uiop:string-prefix-p (format nil "~A=" key) field))
                                                (rest fields))))
                             (if pair (parse-integer pair :start (1+ (position #\= pair)) :junk-allowed t) 0))))
                    (list device (field "rbytes") (field "wbytes") (field "rios") (field "wios")))))

(defun parse-net-dev (text)
  "Parse /proc/<pid>/net/dev TEXT into (interface rx-bytes rx-packets rx-errors rx-dropped
tx-bytes tx-packets tx-errors tx-dropped), leaving out the devices cAdvisor ignores."
  (loop for line in (cddr (uiop:split-string (or text "") :separator '(#\Newline)))
        for colon = (position #\: line)
        for name = (and colon (string-trim " " (subseq line 0 colon)))
        for values = (and colon (mapcar #'parse-integer
                                        (remove "" (uiop:split-string (subseq line (1+ colon)) :separator '(#\Space))
                                                :test #'equal)))
        when (and name (>= (length values) 12)
                  (not (or (equal name "lo")
                           (some (lambda (prefix) (uiop:string-prefix-p prefix name)) '("veth" "docker" "nerdctl")))))
          collect (list name (nth 0 values) (nth 1 values) (nth 2 values) (nth 3 values)
                        (nth 8 values) (nth 9 values) (nth 10 values) (nth 11 values))))

(defun cgroup-first-pid (directory)
  "Return a process in the cgroup at DIRECTORY, whose network namespace is the sandbox's."
  (let ((text (ignore-errors (uiop:read-file-string (merge-pathnames "cgroup.procs" (uiop:ensure-directory-pathname directory))))))
    (and text (let ((line (first (uiop:split-string (string-trim '(#\Newline) text) :separator '(#\Newline)))))
                (and line (plusp (length line)) (every #'digit-char-p line) (parse-integer line))))))

(defun cri-pause-image (stub timeout)
  "Return the pinned sandbox image's tag, which a sandbox's cAdvisor image label names."
  (or *cadvisor-pause-image*
      (multiple-value-bind (response status)
          (gr8s.cri.v1::image-service-list-images stub (make-instance 'gr8s.cri.v1::list-images-request) :timeout timeout)
        (ensure-cri-status "ListImages" status)
        (let ((pinned (find-if (lambda (image) (and (gr8s.cri.v1::pinned image) (gr8s.cri.v1::repo-tags image)))
                               (gr8s.cri.v1::images response))))
          (setf *cadvisor-pause-image* (or (and pinned (first (gr8s.cri.v1::repo-tags pinned))) ""))))))

(defun mountinfo-device (path &optional (mountinfo "/proc/self/mountinfo"))
  "Return the source device of the mount holding PATH, as cAdvisor's device label names it, or NIL.
The device comes from the mount table, not stat, because btrfs reports anonymous devices."
  (let ((best nil) (best-length -1))
    (with-open-file (in mountinfo :if-does-not-exist nil)
      (when in
        (loop for line = (read-line in nil)
              while line
              do (let* ((fields (uiop:split-string line :separator '(#\Space)))
                        (mount (fifth fields))
                        (separator (position "-" fields :test #'equal))
                        (source (and separator (nth (+ separator 2) fields))))
                   (when (and mount source
                              (or (equal mount "/") (equal path mount)
                                  (uiop:string-prefix-p (concatenate 'string mount "/") path))
                              (> (length mount) best-length))
                     (setf best source best-length (length mount)))))))
    ;; The deepest mount decides: one without a block device, such as a tmpfs, has none.
    (and best (uiop:string-prefix-p "/dev/" best) best)))

(defun cri-cadvisor-entries (socket-path &key (timeout 10))
  "List the cgroups cAdvisor would report for gr8s's running containers and ready sandboxes."
  (let ((channel (make-unix-grpc-channel socket-path :timeout timeout))
        (managed (list (cons +gr8s-managed-label+ "true")))
        (entries nil))
    (unwind-protect
         (let* ((stub (gr8s.cri.v1::make-runtime-service-stub channel))
                (pause (ignore-errors (cri-pause-image (gr8s.cri.v1::make-image-service-stub channel) timeout)))
                (sandboxes (make-hash-table :test #'equal))
                (layers (make-hash-table :test #'equal)))
           (multiple-value-bind (response status)
               (gr8s.cri.v1::runtime-service-list-pod-sandbox
                stub (make-instance 'gr8s.cri.v1::list-pod-sandbox-request
                                    :filter (make-instance 'gr8s.cri.v1::pod-sandbox-filter :label-selector managed))
                :timeout timeout)
             (ensure-cri-status "ListPodSandbox" status)
             (dolist (sandbox (gr8s.cri.v1::items response))
               (let ((metadata (gr8s.cri.v1::metadata sandbox)))
                 (when (and metadata (= (cri-protobuf-state sandbox) gr8s.cri.v1::+podsandboxstate-sandbox_ready+))
                   (setf (gethash (gr8s.cri.v1::id sandbox) sandboxes) metadata)
                   (push (make-cadvisor-entry :name (gr8s.cri.v1::id sandbox) :image (or pause "")
                                              :pod (gr8s.cri.v1::name metadata)
                                              :namespace (gr8s.cri.v1::namespace metadata) :container ""
                                              :network-p t :started (gr8s.cri.v1::created-at sandbox))
                         entries)))))
           (multiple-value-bind (response status)
               (gr8s.cri.v1::runtime-service-list-container-stats
                stub (make-instance 'gr8s.cri.v1::list-container-stats-request
                                    :filter (make-instance 'gr8s.cri.v1::container-stats-filter :label-selector managed))
                :timeout timeout)
             (ensure-cri-status "ListContainerStats" status)
             (dolist (stats (gr8s.cri.v1::stats response))
               (let ((attributes (gr8s.cri.v1::attributes stats)) (layer (gr8s.cri.v1::writable-layer stats)))
                 (when (and attributes layer)
                   (setf (gethash (gr8s.cri.v1::id attributes) layers)
                         (cons (cri-optional-value (gr8s.cri.v1::used-bytes layer))
                               (let ((fs (gr8s.cri.v1::fs-id layer)))
                                 (and fs (plusp (length (gr8s.cri.v1::mountpoint fs)))
                                      (mountinfo-device (gr8s.cri.v1::mountpoint fs))))))))))
           (multiple-value-bind (response status)
               (gr8s.cri.v1::runtime-service-list-containers
                stub (make-instance 'gr8s.cri.v1::list-containers-request
                                    :filter (make-instance 'gr8s.cri.v1::container-filter :label-selector managed))
                :timeout timeout)
             (ensure-cri-status "ListContainers" status)
             (dolist (container (gr8s.cri.v1::containers response))
               (let ((sandbox (gethash (gr8s.cri.v1::pod-sandbox-id container) sandboxes))
                     (layer (gethash (gr8s.cri.v1::id container) layers)))
                 (when (and sandbox (= (cri-protobuf-state container) gr8s.cri.v1::+containerstate-container_running+))
                   (push (make-cadvisor-entry
                          :name (gr8s.cri.v1::id container)
                          :image (let ((image (gr8s.cri.v1::image container))) (if image (gr8s.cri.v1::image image) ""))
                          :pod (gr8s.cri.v1::name sandbox) :namespace (gr8s.cri.v1::namespace sandbox)
                          :container (or (cdr (assoc +gr8s-container-label+ (gr8s.cri.v1::labels container) :test #'string=))
                                         (let ((metadata (gr8s.cri.v1::metadata container)))
                                           (if metadata (gr8s.cri.v1::name metadata) "")))
                          :started (gr8s.cri.v1::created-at container)
                          :fs-used (car layer) :fs-device (cdr layer))
                         entries))))))
      (ag-grpc:channel-close channel))
    (forget-departed-cgroups (mapcar #'cadvisor-entry-name entries))
    (dolist (entry entries)
      (let ((relative (find-container-cgroup (cadvisor-entry-name entry))))
        (setf (cadvisor-entry-id entry) relative
              (cadvisor-entry-directory entry) (and relative (concatenate 'string (string-right-trim "/" *cgroup-root*) relative "/")))))
    (remove nil entries :key #'cadvisor-entry-directory)))

(defgeneric runtime-cadvisor-entries (runtime)
  (:documentation "Return the CADVISOR-ENTRY list of RUNTIME's containers and sandboxes."))

(defmethod runtime-cadvisor-entries ((runtime t))
  "A runtime without containers reports none."
  (declare (ignore runtime))
  nil)

(defmethod runtime-cadvisor-entries ((runtime containerd-runtime))
  "Ask the CRI runtime what it runs."
  (call-containerd-runtime (lambda () (cri-cadvisor-entries (containerd-runtime-socket-path runtime)))))

;;; Rendering

(defparameter +cadvisor-families+
  '(("container_cpu_cfs_periods_total" "Number of elapsed enforcement period intervals." "counter")
    ("container_cpu_cfs_throttled_periods_total" "Number of throttled period intervals." "counter")
    ("container_cpu_cfs_throttled_seconds_total" "Total time duration the container has been throttled." "counter")
    ("container_cpu_system_seconds_total" "Cumulative system cpu time consumed in seconds." "counter")
    ("container_cpu_usage_seconds_total" "Cumulative cpu time consumed in seconds." "counter")
    ("container_cpu_user_seconds_total" "Cumulative user cpu time consumed in seconds." "counter")
    ("container_fs_reads_bytes_total" "Cumulative count of bytes read" "counter")
    ("container_fs_reads_total" "Cumulative count of reads completed" "counter")
    ("container_fs_usage_bytes" "Number of bytes that are consumed by the container on this filesystem." "gauge")
    ("container_fs_writes_bytes_total" "Cumulative count of bytes written" "counter")
    ("container_fs_writes_total" "Cumulative count of writes completed" "counter")
    ("container_last_seen" "Last time a container was seen by the exporter" "gauge")
    ("container_memory_cache" "Number of bytes of page cache memory." "gauge")
    ("container_memory_failcnt" "Number of memory usage hits limits" "counter")
    ("container_memory_failures_total" "Cumulative count of memory allocation failures." "counter")
    ("container_memory_mapped_file" "Size of memory mapped files in bytes." "gauge")
    ("container_memory_max_usage_bytes" "Maximum memory usage recorded in bytes" "gauge")
    ("container_memory_rss" "Size of RSS in bytes." "gauge")
    ("container_memory_swap" "Container swap usage in bytes." "gauge")
    ("container_memory_usage_bytes" "Current memory usage in bytes, including all memory regardless of when it was accessed" "gauge")
    ("container_memory_working_set_bytes" "Current working set in bytes." "gauge")
    ("container_network_receive_bytes_total" "Cumulative count of bytes received" "counter")
    ("container_network_receive_errors_total" "Cumulative count of errors encountered while receiving" "counter")
    ("container_network_receive_packets_dropped_total" "Cumulative count of packets dropped while receiving" "counter")
    ("container_network_receive_packets_total" "Cumulative count of packets received" "counter")
    ("container_network_transmit_bytes_total" "Cumulative count of bytes transmitted" "counter")
    ("container_network_transmit_errors_total" "Cumulative count of errors encountered while transmitting" "counter")
    ("container_network_transmit_packets_dropped_total" "Cumulative count of packets dropped while transmitting" "counter")
    ("container_network_transmit_packets_total" "Cumulative count of packets transmitted" "counter")
    ("container_spec_cpu_period" "CPU period of the container." "gauge")
    ("container_spec_cpu_quota" "CPU quota of the container." "gauge")
    ("container_spec_cpu_shares" "CPU share of the container." "gauge")
    ("container_spec_memory_limit_bytes" "Memory limit for the container." "gauge")
    ("container_start_time_seconds" "Start time of the container since unix epoch in seconds." "gauge")
    ("machine_cpu_cores" "Number of logical CPU cores." "gauge")
    ("machine_memory_bytes" "Amount of memory installed on the machine." "gauge"))
  "Each family /metrics/cadvisor reports, with cAdvisor's HELP and type, in name order.")

(defun sorted-labels (labels)
  "Order LABELS, an alist, by name, as the Prometheus registry renders them."
  (sort (copy-list labels) #'string< :key #'car))

(defun cpu-weight-to-shares (weight)
  "Convert cgroup v2 cpu.weight back to v1 shares, as runc's fs2 conversion does."
  (and weight (+ 2 (floor (* (- weight 1) 262142) 9999))))

(defun add-cadvisor-cgroup-samples (add labels directory now &key memory-from-meminfo network-pid)
  "Add the cgroup statistics at DIRECTORY with base LABELS through ADD (family labels value time)."
  (let* ((cpu (cgroup-file-alist directory "cpu.stat"))
         (memory (cgroup-file-alist directory "memory.stat"))
         (usage (if memory-from-meminfo
                    (kubelet-usage-memory-usage memory-from-meminfo)
                    (cgroup-file-value directory "memory.current")))
         (quota-text (ignore-errors (uiop:read-file-string (merge-pathnames "cpu.max" (uiop:ensure-directory-pathname directory)))))
         (quota-fields (and quota-text (uiop:split-string (string-trim '(#\Newline) quota-text) :separator '(#\Space))))
         (quota (and quota-fields (every #'digit-char-p (first quota-fields)) (parse-integer (first quota-fields))))
         (period (and (second quota-fields) (parse-integer (second quota-fields) :junk-allowed t))))
    (flet ((stat (alist key) (cdr (assoc key alist :test #'equal)))
           (seconds (microseconds) (and microseconds (/ microseconds 1d6))))
      (funcall add "container_cpu_usage_seconds_total" (cons (cons "cpu" "total") labels) (seconds (stat cpu "usage_usec")) now)
      (funcall add "container_cpu_user_seconds_total" labels (seconds (stat cpu "user_usec")) now)
      (funcall add "container_cpu_system_seconds_total" labels (seconds (stat cpu "system_usec")) now)
      (when (and quota (plusp quota))
        (funcall add "container_cpu_cfs_periods_total" labels (stat cpu "nr_periods") now)
        (funcall add "container_cpu_cfs_throttled_periods_total" labels (stat cpu "nr_throttled") now)
        (funcall add "container_cpu_cfs_throttled_seconds_total" labels (seconds (stat cpu "throttled_usec")) now))
      (when usage
        (let ((inactive (or (stat memory "inactive_file") 0)))
          (funcall add "container_memory_usage_bytes" labels usage now)
          (funcall add "container_memory_working_set_bytes" labels (max 0 (- usage inactive)) now)))
      (funcall add "container_memory_rss" labels (stat memory "anon") now)
      (funcall add "container_memory_cache" labels (stat memory "file") now)
      (funcall add "container_memory_mapped_file" labels (stat memory "file_mapped") now)
      (unless memory-from-meminfo
        (funcall add "container_memory_swap" labels (or (cgroup-file-value directory "memory.swap.current") 0) now)
        (funcall add "container_memory_max_usage_bytes" labels (cgroup-file-value directory "memory.peak") now)
        (funcall add "container_memory_failcnt" labels (or (stat (cgroup-file-alist directory "memory.events") "max") 0) now))
      (loop for (type key) in '(("pgfault" "pgfault") ("pgmajfault" "pgmajfault"))
            for value = (stat memory key)
            when value
              do (dolist (scope '("container" "hierarchy"))
                   (funcall add "container_memory_failures_total"
                            (list* (cons "failure_type" type) (cons "scope" scope) labels) value now)))
      (unless memory-from-meminfo
        (dolist (device (parse-io-stat (ignore-errors (uiop:read-file-string
                                                       (merge-pathnames "io.stat" (uiop:ensure-directory-pathname directory))))))
          (destructuring-bind (name rbytes wbytes rios wios) device
            (let ((labels (cons (cons "device" name) labels)))
              (funcall add "container_fs_reads_bytes_total" labels rbytes now)
              (funcall add "container_fs_writes_bytes_total" labels wbytes now)
              (funcall add "container_fs_reads_total" labels rios now)
              (funcall add "container_fs_writes_total" labels wios now))))
        (when (and quota (plusp quota))
          (funcall add "container_spec_cpu_quota" labels quota nil))
        (when period (funcall add "container_spec_cpu_period" labels period nil))
        (funcall add "container_spec_cpu_shares" labels (cpu-weight-to-shares (cgroup-file-value directory "cpu.weight")) nil)
        (funcall add "container_spec_memory_limit_bytes" labels
                 (let ((limit (cgroup-file-value directory "memory.max"))) (if (and limit (< limit (expt 2 62))) limit 0))
                 nil))
      (when network-pid
        (dolist (interface (parse-net-dev (ignore-errors (uiop:read-file-string (format nil "/proc/~D/net/dev" network-pid)))))
          (destructuring-bind (name rx-bytes rx-packets rx-errors rx-dropped tx-bytes tx-packets tx-errors tx-dropped) interface
            (let ((labels (cons (cons "interface" name) labels)))
              (loop for (family value) in `(("container_network_receive_bytes_total" ,rx-bytes)
                                            ("container_network_receive_packets_total" ,rx-packets)
                                            ("container_network_receive_errors_total" ,rx-errors)
                                            ("container_network_receive_packets_dropped_total" ,rx-dropped)
                                            ("container_network_transmit_bytes_total" ,tx-bytes)
                                            ("container_network_transmit_packets_total" ,tx-packets)
                                            ("container_network_transmit_errors_total" ,tx-errors)
                                            ("container_network_transmit_packets_dropped_total" ,tx-dropped))
                    do (funcall add family labels value now)))))))))

(defun machine-identity-labels ()
  "Return the machine collector's labels: machine_id, system_uuid and boot_id."
  (flet ((read-id (path) (or (ignore-errors (string-trim '(#\Space #\Newline) (uiop:read-file-string path))) "")))
    (list (cons "boot_id" (read-id "/proc/sys/kernel/random/boot_id"))
          (cons "machine_id" (read-id "/etc/machine-id"))
          (cons "system_uuid" (read-id "/sys/class/dmi/id/product_uuid")))))

(defun kubelet-cadvisor-metrics-text (entries &key (root-p t) (now (unix-time-nanoseconds)))
  "Render ENTRIES and, with ROOT-P, the root cgroup and machine, as /metrics/cadvisor."
  (let ((families (make-hash-table :test #'equal))
        (stamp (nanoseconds-to-milliseconds now)))
    (flet ((add (family labels value time)
             (when value
               (push (list (sorted-labels labels) value (and time stamp)) (gethash family families)))))
      (dolist (entry entries)
        (let ((labels (list (cons "container" (or (cadvisor-entry-container entry) ""))
                            (cons "id" (cadvisor-entry-id entry))
                            (cons "image" (or (cadvisor-entry-image entry) ""))
                            (cons "name" (or (cadvisor-entry-name entry) ""))
                            (cons "namespace" (or (cadvisor-entry-namespace entry) ""))
                            (cons "pod" (or (cadvisor-entry-pod entry) "")))))
          (add-cadvisor-cgroup-samples
           #'add labels (cadvisor-entry-directory entry) t
           :network-pid (and (cadvisor-entry-network-p entry) (cgroup-first-pid (cadvisor-entry-directory entry))))
          (when (cadvisor-entry-fs-used entry)
            (add "container_fs_usage_bytes" (cons (cons "device" (or (cadvisor-entry-fs-device entry) "")) labels)
                 (cadvisor-entry-fs-used entry) t))
          (add "container_last_seen" labels (floor now 1000000000) t)
          (let ((started (cadvisor-entry-started entry)))
            (when (and started (plusp started))
              (add "container_start_time_seconds" labels (/ started 1d9) nil)))))
      (when root-p
        (let ((labels (list (cons "container" "") (cons "id" "/") (cons "image" "") (cons "name" "")
                            (cons "namespace" "") (cons "pod" "")))
              (meminfo (node-memory-usage (read-key-value-file "/proc/meminfo")
                                          (read-key-value-file (merge-pathnames "memory.stat" *cgroup-root*)))))
          (add-cadvisor-cgroup-samples #'add labels *cgroup-root* t :memory-from-meminfo meminfo :network-pid 1)
          (add "container_last_seen" labels (floor now 1000000000) t)
          (let ((machine (machine-identity-labels)))
            (add "machine_cpu_cores" machine
                 (count-if (lambda (line) (uiop:string-prefix-p "processor" line))
                           (uiop:split-string (or (ignore-errors (uiop:read-file-string "/proc/cpuinfo")) "")
                                              :separator '(#\Newline)))
                 t)
            (let ((total (cdr (assoc "MemTotal" (read-key-value-file "/proc/meminfo") :test #'equal))))
              (add "machine_memory_bytes" machine (and total (* 1024 total)) t))))))
    (with-output-to-string (out)
      (loop for (name help type) in +cadvisor-families+
            do (write-prometheus-family out name help type (gethash name families))))))
