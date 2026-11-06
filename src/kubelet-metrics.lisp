;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Instrument the node agent as kubelet v1.37's /metrics does: CRI runtime
;;;; operations by snake_case operation type (counts, errors, latency), how long Pods
;;;; take from the agent first seeing them to running, how long each Pod sync takes, and
;;;; the process collector's process_* series. Histograms keep fixed buckets and the Pod
;;;; table holds only Pods currently assigned, so memory stays bounded by the node.

(in-package #:gr8s)

;;; Histograms, rendered as the Prometheus client renders them

(defstruct (histogram (:constructor %make-histogram (bounds counts)))
  "Cumulative bucket counts for fixed BOUNDS, with the sum and count of what was observed."
  bounds counts (sum 0) (count 0))

(defun make-bucketed-histogram (bounds)
  "Return an empty histogram with BOUNDS, the bucket upper limits."
  (%make-histogram bounds (make-array (length bounds) :initial-element 0)))

(defun observe-histogram (histogram value)
  "Record VALUE in HISTOGRAM."
  (loop for bound in (histogram-bounds histogram) for index from 0
        when (<= value bound) do (incf (aref (histogram-counts histogram) index)))
  (incf (histogram-sum histogram) value)
  (incf (histogram-count histogram))
  histogram)

(defun exponential-buckets (start factor count)
  "Return COUNT bounds from START, each FACTOR times the last, as Go's ExponentialBuckets does."
  (loop repeat count for bound = (coerce start 'double-float) then (* bound factor) collect bound))

(defparameter +prometheus-default-buckets+ '(0.005d0 0.01d0 0.025d0 0.05d0 0.1d0 0.25d0 0.5d0 1 2.5d0 5 10)
  "The Prometheus client's default bounds, for histograms that define none.")

(defun write-prometheus-histograms (out name help series)
  "Write histogram family NAME. SERIES is a list of (labels . histogram), labels a name-sorted alist."
  (when series
    (format out "# HELP ~A ~A~%# TYPE ~A histogram~%" name help name)
    (flet ((label-text (labels &optional le)
             (format nil "~{~A~^,~}"
                     (append (mapcar (lambda (label) (format nil "~A=\"~A\"" (car label) (prometheus-label-value (cdr label))))
                                     labels)
                             (and le (list (format nil "le=\"~A\"" le)))))))
      (loop for (labels . histogram) in (sort (copy-list series) #'string< :key (lambda (entry) (label-text (car entry))))
            for text = (label-text labels)
            do (loop for bound in (histogram-bounds histogram) for index from 0
                     do (format out "~A_bucket{~A} ~D~%" name (label-text labels (prometheus-float-string bound))
                                (aref (histogram-counts histogram) index)))
               (format out "~A_bucket{~A} ~D~%" name (label-text labels "+Inf") (histogram-count histogram))
               (format out "~A_sum~@[{~A}~] ~A~%" name (and (plusp (length text)) text)
                       (prometheus-float-string (histogram-sum histogram)))
               (format out "~A_count~@[{~A}~] ~D~%" name (and (plusp (length text)) text) (histogram-count histogram))))))

;;; The agent's measurements

(defparameter +kubelet-runtime-operation-buckets+ (exponential-buckets 0.005d0 2.5d0 14)
  "kubelet_runtime_operations_duration_seconds bounds, ExponentialBuckets(.005, 2.5, 14).")

(defparameter +kubelet-pod-start-buckets+
  '(0.5d0 1 2 3 4 5 6 8 10 20 30 45 60 120 180 240 300 360 480 600 900 1200 1800 2700 3600)
  "kubelet_pod_start_duration_seconds bounds.")

(defstruct (kubelet-instrumentation (:constructor make-kubelet-instrumentation))
  "Runtime operation counts, errors and latencies by operation type; Pod start and sync latency;
and when each assigned Pod was first seen and at what version, until it first runs."
  (operations (make-hash-table :test #'equal))
  (errors (make-hash-table :test #'equal))
  (latencies (make-hash-table :test #'equal))
  (pod-start (make-bucketed-histogram +kubelet-pod-start-buckets+))
  (pod-workers (make-hash-table :test #'equal))
  (pods (make-hash-table :test #'equal))
  (lock (bt:make-lock "gr8s kubelet metrics")))

(defvar *kubelet-instrumentation* (make-kubelet-instrumentation)
  "This process's node agent measurements.")

(defun cri-operation-type (method)
  "Map a CRI method path such as /runtime.v1.RuntimeService/ListPodSandbox to the kubelet's
operation_type, list_podsandbox, or NIL for anything that isn't a CRI call."
  (let ((slash (position #\/ method :from-end t)))
    (when (and slash (or (uiop:string-prefix-p "/runtime.v1.RuntimeService/" method)
                         (uiop:string-prefix-p "/runtime.v1.ImageService/" method)))
      (let ((name (subseq method (1+ slash))))
        (cond ((equal name "UpdateContainerResources") "update_container")
              ((equal name "ImageFsInfo") "image_fs_info")
              (t (let ((name (cl-ppcre:regex-replace-all "PodSandbox" name "Podsandbox")))
                   (string-downcase (cl-ppcre:regex-replace-all "(?<=[a-z0-9])([A-Z])" name "_\\1")))))))))

(defun note-runtime-operation (operation seconds failed &key (metrics *kubelet-instrumentation*))
  "Count one runtime OPERATION that took SECONDS, and an error when FAILED."
  (bt:with-lock-held ((kubelet-instrumentation-lock metrics))
    (incf (gethash operation (kubelet-instrumentation-operations metrics) 0))
    (when failed (incf (gethash operation (kubelet-instrumentation-errors metrics) 0)))
    (observe-histogram (or (gethash operation (kubelet-instrumentation-latencies metrics))
                           (setf (gethash operation (kubelet-instrumentation-latencies metrics))
                                 (make-bucketed-histogram +kubelet-runtime-operation-buckets+)))
                       seconds)))

(defvar *upstream-grpc-call-unary* (symbol-function 'ag-grpc:call-unary)
  "The dependency's unary call, captured once, which the instrumented one wraps.")

(defun instrumented-grpc-call-unary (channel method request &rest options)
  "Make a unary gRPC call, counting it as a kubelet runtime operation when it is a CRI call."
  (let ((operation (cri-operation-type method)))
    (if (null operation)
        (apply *upstream-grpc-call-unary* channel method request options)
        (let ((started (get-internal-real-time)) (call nil))
          (unwind-protect (setf call (apply *upstream-grpc-call-unary* channel method request options))
            (ignore-errors
             (note-runtime-operation operation (/ (- (get-internal-real-time) started) internal-time-units-per-second)
                                     (or (null call) (/= (ag-grpc:call-status call) ag-grpc:+grpc-status-ok+)))))
          call))))

(setf (symbol-function 'ag-grpc:call-unary) #'instrumented-grpc-call-unary)

(defun note-pod-sync (uid version deleting seconds &key (metrics *kubelet-instrumentation*))
  "Record one sync of Pod UID at VERSION that took SECONDS, typed as the kubelet's pod workers type it."
  (bt:with-lock-held ((kubelet-instrumentation-lock metrics))
    (let* ((pods (kubelet-instrumentation-pods metrics))
           (known (gethash uid pods))
           (type (cond (deleting "kill") ((null known) "create")
                       ((not (equal version (second known))) "update") (t "sync"))))
      (if known
          (setf (second known) version)
          (setf (gethash uid pods) (list (get-universal-time) version nil)))
      (observe-histogram (or (gethash type (kubelet-instrumentation-pod-workers metrics))
                             (setf (gethash type (kubelet-instrumentation-pod-workers metrics))
                                   (make-bucketed-histogram +prometheus-default-buckets+)))
                         seconds)
      type)))

(defun note-pod-phase (uid phase &key (metrics *kubelet-instrumentation*) (now (get-universal-time)))
  "Observe Pod UID's start latency the first time its PHASE is Running."
  (when (equal phase "Running")
    (bt:with-lock-held ((kubelet-instrumentation-lock metrics))
      (let ((known (gethash uid (kubelet-instrumentation-pods metrics))))
        (when (and known (not (third known)))
          (setf (third known) t)
          (observe-histogram (kubelet-instrumentation-pod-start metrics) (max 0 (- now (first known)))))))))

(defun forget-unassigned-pod-records (uids &key (metrics *kubelet-instrumentation*))
  "Keep Pod records only for UIDS, the Pods still assigned to this node."
  (bt:with-lock-held ((kubelet-instrumentation-lock metrics))
    (let ((pods (kubelet-instrumentation-pods metrics)))
      (loop for uid being the hash-keys of pods
            unless (gethash uid uids) do (remhash uid pods)))))

(defun kubelet-instrumentation-text (&key (metrics *kubelet-instrumentation*))
  "Render the runtime operation and Pod latency families."
  (bt:with-lock-held ((kubelet-instrumentation-lock metrics))
    (with-output-to-string (out)
      (flet ((counts (table)
               (loop for operation being the hash-keys of table using (hash-value count)
                     collect (list (list (cons "operation_type" operation)) count))))
        (write-prometheus-histograms out "kubelet_pod_start_duration_seconds"
                                     "[ALPHA] Duration in seconds from kubelet seeing a pod for the first time to the pod starting to run"
                                     (list (cons nil (kubelet-instrumentation-pod-start metrics))))
        (write-prometheus-histograms out "kubelet_pod_worker_duration_seconds"
                                     "[ALPHA] Duration in seconds to sync a single pod. Broken down by operation type: create, update, or sync"
                                     (loop for type being the hash-keys of (kubelet-instrumentation-pod-workers metrics)
                                           using (hash-value histogram)
                                           collect (cons (list (cons "operation_type" type)) histogram)))
        (write-prometheus-histograms out "kubelet_runtime_operations_duration_seconds"
                                     "[ALPHA] Duration in seconds of runtime operations. Broken down by operation type."
                                     (loop for operation being the hash-keys of (kubelet-instrumentation-latencies metrics)
                                           using (hash-value histogram)
                                           collect (cons (list (cons "operation_type" operation)) histogram)))
        (write-prometheus-family out "kubelet_runtime_operations_errors_total"
                                 "[ALPHA] Cumulative number of runtime operation errors by operation type." "counter"
                                 (counts (kubelet-instrumentation-errors metrics)))
        (write-prometheus-family out "kubelet_runtime_operations_total"
                                 "[ALPHA] Cumulative number of runtime operations by operation type." "counter"
                                 (counts (kubelet-instrumentation-operations metrics)))))))

;;; What the runtime runs

(defun cri-container-state-counts (socket-path &key (timeout 10))
  "Return the number of ready gr8s sandboxes and an alist of container state to count."
  (let ((channel (make-unix-grpc-channel socket-path :timeout timeout))
        (managed (list (cons +gr8s-managed-label+ "true"))))
    (unwind-protect
         (let ((stub (gr8s.cri.v1::make-runtime-service-stub channel)))
           (values
            (multiple-value-bind (response status)
                (gr8s.cri.v1::runtime-service-list-pod-sandbox
                 stub (make-instance 'gr8s.cri.v1::list-pod-sandbox-request
                                     :filter (make-instance 'gr8s.cri.v1::pod-sandbox-filter :label-selector managed))
                 :timeout timeout)
              (ensure-cri-status "ListPodSandbox" status)
              (count gr8s.cri.v1::+podsandboxstate-sandbox_ready+ (gr8s.cri.v1::items response) :key #'cri-protobuf-state))
            (multiple-value-bind (response status)
                (gr8s.cri.v1::runtime-service-list-containers
                 stub (make-instance 'gr8s.cri.v1::list-containers-request
                                     :filter (make-instance 'gr8s.cri.v1::container-filter :label-selector managed))
                 :timeout timeout)
              (ensure-cri-status "ListContainers" status)
              (let ((counts nil))
                (dolist (container (gr8s.cri.v1::containers response) counts)
                  (let ((state (case (cri-protobuf-state container) (0 "created") (1 "running") (2 "exited") (t "unknown"))))
                    (incf (getf counts (intern state :keyword) 0))))
                (loop for (state count) on counts by #'cddr collect (cons (string-downcase (symbol-name state)) count))))))
      (ag-grpc:channel-close channel))))

(defgeneric runtime-container-state-counts (runtime)
  (:documentation "Return RUNTIME's ready sandbox count and an alist of container state to count."))

(defmethod runtime-container-state-counts ((runtime t))
  "A runtime without containers runs none."
  (declare (ignore runtime))
  (values 0 nil))

(defmethod runtime-container-state-counts ((runtime containerd-runtime))
  "Ask the CRI runtime what it runs."
  (call-containerd-runtime (lambda () (cri-container-state-counts (containerd-runtime-socket-path runtime)))))

(defgeneric runtime-claim-volume-paths (runtime)
  (:documentation "Return (namespace claim host-path) for each claim volume RUNTIME's containers mount."))

(defmethod runtime-claim-volume-paths ((runtime t))
  "A runtime without containers mounts no claims."
  (declare (ignore runtime))
  nil)

(defmethod runtime-claim-volume-paths ((runtime containerd-runtime))
  "Report the claim volumes recorded as the runtime's containers mounted them."
  (loop for record in (directory (merge-pathnames "*/volumes/.claims/*.*" (containerd-runtime-log-root runtime)))
        for entry = (ignore-errors (coerce (com.inuoe.jzon:parse (uiop:read-file-string record)) 'list))
        when (and (= 3 (length entry)) (every #'stringp entry)) collect entry))

(defun filesystem-statistics (path)
  "Measure the filesystem holding PATH as the kubelet's statfs metrics do: capacity, available
and used bytes, then inodes, free inodes and used inodes. NIL when it cannot be measured."
  (sb-alien:with-alien ((fields (array sb-alien:unsigned-long 32)))
    (when (zerop (sb-alien:alien-funcall
                  (sb-alien:extern-alien "statvfs" (function sb-alien:int sb-alien:c-string (* t)))
                  path (sb-alien:addr fields)))
      ;; struct statvfs: f_bsize, f_frsize, f_blocks, f_bfree, f_bavail, f_files, f_ffree.
      (let ((size (sb-alien:deref fields 1)) (blocks (sb-alien:deref fields 2))
            (free (sb-alien:deref fields 3)) (available (sb-alien:deref fields 4))
            (inodes (sb-alien:deref fields 5)) (free-inodes (sb-alien:deref fields 6)))
        (list (* blocks size) (* available size) (* (- blocks free) size)
              inodes free-inodes (- inodes free-inodes))))))

(defun kubelet-volume-stats-text (volumes)
  "Render kubelet_volume_stats_* for VOLUMES, (namespace claim host-path) lists. As upstream,
a claim several Pods mount is reported once, and one that can't be measured is left out."
  (let ((seen nil) (rows nil))
    (loop for (namespace claim path) in volumes
          for key = (cons namespace claim)
          unless (member key seen :test #'equal)
            do (let ((statistics (filesystem-statistics path)))
                 (when statistics
                   (push key seen)
                   (push (cons (list (cons "namespace" namespace) (cons "persistentvolumeclaim" claim)) statistics) rows))))
    (with-output-to-string (out)
      (loop for (suffix help) in '(("available_bytes" "Number of available bytes in the volume")
                                   ("capacity_bytes" "Capacity in bytes of the volume")
                                   ("inodes" "Maximum number of inodes in the volume")
                                   ("inodes_free" "Number of free inodes in the volume")
                                   ("inodes_used" "Number of used inodes in the volume")
                                   ("used_bytes" "Number of used bytes in the volume"))
            for index = (position suffix '("capacity_bytes" "available_bytes" "used_bytes" "inodes" "inodes_free" "inodes_used")
                                  :test #'equal)
            do (write-prometheus-family out (concatenate 'string "kubelet_volume_stats_" suffix)
                                        (concatenate 'string "[ALPHA] " help) "gauge"
                                        (mapcar (lambda (row) (list (car row) (nth index (cdr row)))) rows))))))

;;; The process collector

(defun process-metrics-text ()
  "Render the Prometheus process collector's series for this process from /proc/self."
  (let* ((stat (ignore-errors (uiop:read-file-string "/proc/self/stat")))
         (fields (and stat (uiop:split-string (subseq stat (+ 2 (position #\) stat :from-end t))) :separator '(#\Space))))
         (ticks 100) (page 4096)
         (boot (node-boot-time))
         (limits (ignore-errors (uiop:read-file-lines "/proc/self/limits")))
         (max-fds (let ((line (find-if (lambda (line) (uiop:string-prefix-p "Max open files" line)) limits)))
                    (and line (parse-integer (first (remove "" (uiop:split-string (subseq line 14) :separator '(#\Space))
                                                            :test #'equal))
                                             :junk-allowed t))))
         (open-fds (length (ignore-errors (uiop:directory-files "/proc/self/fd/")))))
    (flet ((field (n) (and fields (parse-integer (nth (- n 3) fields) :junk-allowed t))))
      (with-output-to-string (out)
        (when fields
          (write-prometheus-family out "process_cpu_seconds_total" "Total user and system CPU time spent in seconds." "counter"
                                   (list (list nil (/ (+ (field 14) (field 15)) ticks 1d0)))))
        (when max-fds
          (write-prometheus-family out "process_max_fds" "Maximum number of open file descriptors." "gauge"
                                   (list (list nil max-fds))))
        (write-prometheus-family out "process_open_fds" "Number of open file descriptors." "gauge"
                                 (list (list nil open-fds)))
        (when fields
          (write-prometheus-family out "process_resident_memory_bytes" "Resident memory size in bytes." "gauge"
                                   (list (list nil (* page (field 24)))))
          (when boot
            (write-prometheus-family out "process_start_time_seconds" "Start time of the process since unix epoch in seconds." "gauge"
                                     (list (list nil (+ boot (/ (field 22) ticks 1d0))))))
          (write-prometheus-family out "process_virtual_memory_bytes" "Virtual memory size in bytes." "gauge"
                                   (list (list nil (field 23)))))))))
