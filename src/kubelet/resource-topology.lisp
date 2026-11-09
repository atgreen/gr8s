;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;; Discover Linux CPU/NUMA topology and represent CPU sets without shell commands.
(in-package #:gr8s.kubelet)

(defparameter *cpu-topology-directory* #P"/sys/devices/system/cpu/")
(defparameter *numa-topology-directory* #P"/sys/devices/system/node/")

(defun parse-cpu-set (text)
  "Parse canonical cpulist ranges, rejecting duplicates, negatives and huge expansions."
  (unless (stringp text) (error "CPU set must be a string"))
  (let ((result nil) (text (string-trim '(#\Space #\Newline #\Tab) text)))
    (unless (equal text "")
      (dolist (part (uiop:split-string text :separator '(#\,)))
        (unless (cl-ppcre:scan "^[0-9]+(-[0-9]+)?$" part) (error "Invalid CPU set ~S" text))
        (let* ((dash (position #\- part))
               (low (parse-integer part :end dash)) (high (if dash (parse-integer part :start (1+ dash)) low)))
          (unless (<= 0 low high 1048575) (error "CPU set range is invalid"))
          (loop for cpu from low to high do (when (member cpu result) (error "CPU set contains duplicates")) (push cpu result)))))
    (sort result #'<)))

(defun format-cpu-set (cpus)
  "Render a sorted CPU set with compact inclusive ranges."
  (let ((remaining (sort (remove-duplicates (copy-list cpus)) #'<)) (parts nil))
    (loop while remaining
          do (let* ((first (pop remaining)) (last first))
               (loop while (and remaining (= (car remaining) (1+ last))) do (setf last (pop remaining)))
               (push (if (= first last) (write-to-string first) (format nil "~D-~D" first last)) parts)))
    (format nil "~{~A~^,~}" (nreverse parts))))

(defun read-sysfs-integer (path &optional default)
  "Read an integer sysfs attribute; DEFAULT is used only when the file is absent."
  (if (probe-file path) (parse-integer (string-trim '(#\Space #\Newline #\Tab) (uiop:read-file-string path))) default))

(defun discover-resource-topology ()
  "Read online CPUs, physical cores, NUMA memory and each node's HugeTLB pools."
  (let* ((online (parse-cpu-set (uiop:read-file-string (merge-pathnames "online" *cpu-topology-directory*))))
         (nodes nil) (cpus (core-object)))
    (dolist (directory (ignore-errors (uiop:subdirectories *numa-topology-directory*)))
      (let ((name (car (last (pathname-directory directory)))))
        (when (cl-ppcre:scan "^node[0-9]+$" name)
          (let* ((id (parse-integer name :start 4))
                 (members (intersection online (parse-cpu-set (uiop:read-file-string (merge-pathnames "cpulist" directory)))))
                 (info (uiop:read-file-string (merge-pathnames "meminfo" directory)))
                 (memory (multiple-value-bind (match groups) (cl-ppcre:scan-to-strings "MemTotal:[ \\t]+([0-9]+) kB" info)
                           (unless match (error "Missing NUMA memory capacity in ~A" directory))
                           (* 1024 (parse-integer (aref groups 0)))))
                 (gr8s::*hugepage-sysfs-directory* (merge-pathnames "hugepages/" directory))
                 (pages (node-hugepage-capacity)))
            (push (core-object "id" id "cpus" (coerce (sort members #'<) 'vector) "memory" memory "hugepages" pages) nodes)))))
    (unless nodes (setf nodes (list (core-object "id" 0 "cpus" (coerce online 'vector)
                                                 "memory" (node-allocatable-memory) "hugepages" (node-hugepage-capacity)))))
    (dolist (cpu online)
      (let* ((node (find-if (lambda (node) (find cpu (gethash "cpus" node))) nodes))
             (path (merge-pathnames (format nil "cpu~D/topology/" cpu) *cpu-topology-directory*)))
        (setf (gethash (write-to-string cpu) cpus)
              (core-object "node" (gethash "id" node) "core" (read-sysfs-integer (merge-pathnames "core_id" path) cpu)
                           "socket" (read-sysfs-integer (merge-pathnames "physical_package_id" path) 0)))))
    (core-object "online" (coerce online 'vector) "cpus" cpus "nodes" (coerce (sort nodes #'< :key (lambda (node) (gethash "id" node))) 'vector))))

(defun topology-node-ids (topology)
  "Return the ordered NUMA node IDs of TOPOLOGY."
  (map 'list (lambda (node) (gethash "id" node)) (gethash "nodes" topology)))

(defun topology-node-cpus (topology node)
  "Return logical CPUs physically local to NODE."
  (coerce (gethash "cpus" (find node (gethash "nodes" topology) :key (lambda (entry) (gethash "id" entry)))) 'list))

(defun topology-node-memory (topology node resource)
  "Return a node's allocatable ordinary memory or preallocated hugepage capacity."
  (let* ((entry (find node (gethash "nodes" topology) :key (lambda (entry) (gethash "id" entry))))
         (pages (gethash "hugepages" entry)))
    (if (equal resource "memory")
        (max 0 (- (gethash "memory" entry) (loop for value being the hash-values of pages sum (parse-integer value))))
        (parse-integer (gethash resource pages "0")))))
