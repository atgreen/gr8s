;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Measure what a node really has and decide whether a Pod's declared requests
;;;; fit on it. An agent reports its capacity in its session hello; the Node API,
;;;; the downward API and the scheduler all read these same values. gr8s reserves
;;;; nothing for system daemons, so allocatable equals capacity.

(in-package #:gr8s)

(defparameter +node-max-pods+ 110
  "Pods one node accepts, the kubelet's default maxPods.")

(defun node-allocatable-cpu ()
  "Return this node's online CPU count."
  (sb-alien:alien-funcall
   (sb-alien:extern-alien "sysconf" (function sb-alien:long sb-alien:int)) 84))

(defun node-allocatable-memory ()
  "Return this node's total memory in bytes."
  (with-open-file (in #P"/proc/meminfo")
    (loop for line = (read-line in nil) while line
          when (uiop:string-prefix-p "MemTotal:" line)
            return (* 1024 (parse-integer line :start (length "MemTotal:") :junk-allowed t))
          finally (error 'runtime-error :message "Could not read node memory"))))

(defun local-node-capacity ()
  "Return this host's capacity as the (resource . quantity) pairs an agent's hello carries."
  (list (cons "cpu" (write-to-string (node-allocatable-cpu)))
        (cons "memory" (format nil "~DKi" (floor (node-allocatable-memory) 1024)))
        (cons "pods" (write-to-string +node-max-pods+))))

(defun pod-container-requests (container)
  "Return CONTAINER's requested millicores and memory bytes as two values."
  (let ((cpu (container-resource-quantity container "requests" "cpu"))
        (memory (container-resource-quantity container "requests" "memory")))
    (values (if cpu (container-milli-cpu cpu) 0)
            (if memory (container-quantity-integer memory) 0))))

(defun pod-effective-requests (pod)
  "Return POD's requested millicores and memory bytes as two values.
Init containers run one at a time and before the regular ones, which run together,
so a Pod needs the larger of their largest request and its regular containers' sum."
  (let* ((spec (gethash "spec" (pod-to-object pod))) (cpu 0) (memory 0) (init-cpu 0) (init-memory 0))
    (loop for container across (gethash "containers" spec #())
          do (multiple-value-bind (c m) (pod-container-requests container)
               (incf cpu c) (incf memory m)))
    (loop for container across (gethash "initContainers" spec #())
          do (multiple-value-bind (c m) (pod-container-requests container)
               (setf init-cpu (max init-cpu c) init-memory (max init-memory m))))
    (values (max cpu init-cpu) (max memory init-memory))))

(defun node-capacity-amount (node name)
  "Return NODE's reported capacity of resource NAME in the unit requests use, or NIL if unreported."
  (let* ((capacity (node-record-capacity node)) (text (and capacity (gethash name capacity))))
    (when text
      (let ((quantity (parse-container-quantity text)))
        (if (equal name "cpu") (container-milli-cpu quantity) (container-quantity-integer quantity))))))

(defun node-pod-fit-failures (store pod node)
  "Return why POD's requests do not fit in NODE's remaining capacity, as Kubernetes words it.
A resource the node's agent has not reported is not constrained; an agent reports
before its node can become ready. Call with STORE's lock held."
  (multiple-value-bind (cpu memory) (pod-effective-requests pod)
    (let ((used-cpu 0) (used-memory 0) (used-pods 0))
      (loop for other being the hash-values of (pod-store-pods store)
            do (when (and (equal (node-record-name node) (pod-node-name other))
                          (not (equal (pod-uid other) (pod-uid pod)))
                          (not (terminal-pod-phase-p
                                (gethash (pod-uid other) (pod-store-pod-observed-phases store) ""))))
                 (multiple-value-bind (c m) (pod-effective-requests other)
                   (incf used-cpu c) (incf used-memory m) (incf used-pods))))
      (let ((failures nil))
        (loop for (name requested used message) in
              (list (list "memory" memory used-memory "Insufficient memory")
                    (list "cpu" cpu used-cpu "Insufficient cpu")
                    (list "pods" 1 used-pods "Too many pods"))
              do (let ((amount (node-capacity-amount node name)))
                   (when (and amount (plusp requested) (> (+ requested used) amount))
                     (push message failures))))
        failures))))

(defun pod-unschedulable-message (store pod)
  "Explain why no node accepts POD, in the Kubernetes scheduler's form. Call with STORE's lock held."
  (let ((nodes (loop for node being the hash-values of (pod-store-nodes store) collect node))
        (counts nil))
    (dolist (node nodes)
      (dolist (failure (or (node-pod-fit-failures store pod node)
                           (unless (node-record-ready-p node) '("node(s) not ready"))
                           (unless (pod-node-selector-matches-p pod node)
                             '("node(s) didn't match Pod's node affinity/selector"))))
        (let ((entry (assoc failure counts :test #'equal)))
          (if entry (incf (cdr entry)) (push (cons failure 1) counts)))))
    (format nil "0/~D nodes are available~@[: ~{~A~^, ~}~]."
            (length nodes)
            (mapcar (lambda (entry) (format nil "~D ~A" (cdr entry) (car entry)))
                    (sort counts #'string< :key #'car)))))
