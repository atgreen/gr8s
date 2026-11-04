;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Measure what a node really has and decide whether a Pod's declared requests
;;;; fit on it. An agent reports its capacity in its session hello; the Node API,
;;;; the downward API and the scheduler all read these same values. gr8s reserves
;;;; nothing for system daemons, so allocatable equals capacity. A Pod that named
;;;; its own node bypasses the scheduler, so the same check refuses it at admission.

(in-package #:gr8s)

(defparameter +node-max-pods+ 110
  "Pods one node accepts, the kubelet's default maxPods.")

(defparameter +host-port-failure+ "node(s) didn't have free ports for the requested pod ports"
  "The scheduler's words for a Pod whose host ports are taken.")

(defparameter +pod-admission-reasons+
  `(("Insufficient cpu" . "OutOfcpu") ("Insufficient memory" . "OutOfmemory")
    ("Too many pods" . "OutOfpods") (,+host-port-failure+ . "NodePorts"))
  "The status reason a kubelet gives a Pod it refuses, for each kind of fit failure.")

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

(defun pod-host-ports (pod)
  "Return the (ip . port) host ports POD's containers claim; an unset ip means every address."
  (loop for container across (gethash "containers" (gethash "spec" (pod-to-object pod)) #())
        append (loop for port across (gethash "ports" container #())
                     for number = (gethash "hostPort" port 0)
                     when (and (integerp number) (plusp number))
                       collect (let ((ip (gethash "hostIP" port "")))
                                 (cons (if (equal ip "0.0.0.0") "" ip) number)))))

(defun host-ports-conflict-p (left right)
  "Return whether two (ip . port) claims overlap, where an unset ip overlaps every address."
  (and (= (cdr left) (cdr right))
       (or (equal (car left) (car right)) (equal "" (car left)) (equal "" (car right)))))

(defun pod-admitted-before-p (store other pod)
  "Return whether a node would have reached OTHER first: it has reported on OTHER, or OTHER is older."
  (or (gethash (pod-uid other) (pod-store-pod-observed-phases store))
      (flet ((age (candidate)
               (format nil "~A/~A" (gethash "creationTimestamp" (gethash "metadata" (pod-to-object candidate)) "")
                       (pod-name candidate))))
        (string< (age other) (age pod)))))

(defun node-pod-fit-failures (store pod node &key admission)
  "Return why POD does not fit in NODE's remaining capacity and free ports, as Kubernetes words it.
A resource the node's agent has not reported is not constrained; an agent reports
before its node can become ready. Under ADMISSION, a Pod only competes with Pods the
node reaches before it. Call with STORE's lock held."
  (multiple-value-bind (cpu memory) (pod-effective-requests pod)
    (let ((used-cpu 0) (used-memory 0) (used-pods 0) (wanted (pod-host-ports pod)) (taken nil))
      (loop for other being the hash-values of (pod-store-pods store)
            do (when (and (equal (node-record-name node) (pod-node-name other))
                          (not (equal (pod-uid other) (pod-uid pod)))
                          (or (not admission) (pod-admitted-before-p store other pod))
                          (not (terminal-pod-phase-p
                                (gethash (pod-uid other) (pod-store-pod-observed-phases store) ""))))
                 (multiple-value-bind (c m) (pod-effective-requests other)
                   (incf used-cpu c) (incf used-memory m) (incf used-pods))
                 (when wanted (setf taken (append (pod-host-ports other) taken)))))
      (let ((failures (when (some (lambda (claim) (find claim taken :test #'host-ports-conflict-p)) wanted)
                        (list +host-port-failure+))))
        (loop for (name requested used message) in
              (list (list "memory" memory used-memory "Insufficient memory")
                    (list "cpu" cpu used-cpu "Insufficient cpu")
                    (list "pods" 1 used-pods "Too many pods"))
              do (let ((amount (node-capacity-amount node name)))
                   (when (and amount (plusp requested) (> (+ requested used) amount))
                     (push message failures))))
        failures))))

(defun pod-admission-rejected-p (store pod)
  "Return whether POD was refused by its node. Call with STORE's lock held."
  (let ((status (gethash (pod-uid pod) (pod-store-pod-observed-statuses store))))
    (and status (equal "Failed" (gethash "phase" status))
         (find (gethash "reason" status) +pod-admission-reasons+ :key #'cdr :test #'equal)
         t)))

(defun admit-assigned-pod (store pod)
  "Decide whether POD, assigned to a node, may start there, and record a refusal as a kubelet does.
The scheduler already avoided conflicts, so this catches a Pod that named its node
itself. A Pod the node has reported on is past admission, however full the node is now."
  (let ((failure
          (with-store-lock (store)
            (cond
              ((pod-admission-rejected-p store pod) (return-from admit-assigned-pod nil))
              ((or (deletion-requested-p pod) (gethash (pod-uid pod) (pod-store-pod-observed-phases store)))
               (return-from admit-assigned-pod t))
              (t (let ((node (get-node-unlocked store (pod-node-name pod))))
                   (and node (first (node-pod-fit-failures store pod node :admission t)))))))))
    (when failure
      (save-pod-observation
       store pod
       (core-object "phase" "Failed"
                    "reason" (cdr (assoc failure +pod-admission-reasons+ :test #'equal))
                    "message" (format nil "Pod was rejected: ~A" failure))))
    (null failure)))

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
