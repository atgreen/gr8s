;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Decide what a node refuses, in the Kubernetes scheduler's words. The scheduler
;;;; avoids a node whose host ports are taken. A Pod that named its own node bypasses
;;;; the scheduler, so the same resource and port checks refuse it at admission, with
;;;; the Failed status a kubelet gives it, and it never reaches the node's agent.

(in-package #:gr8s.resources)

(defparameter +host-port-failure+ "node(s) didn't have free ports for the requested pod ports"
  "The scheduler's words for a Pod whose host ports are taken.")

(defun pod-host-ports (pod)
  "Return the (protocol ip . port) host ports POD's containers claim; an unset ip means every address."
  (loop for container across (gethash "containers" (gethash "spec" (pod-to-object pod)) #())
        append (loop for port across (gethash "ports" container #())
                     for number = (gethash "hostPort" port 0)
                     when (and (integerp number) (plusp number))
                       collect (let ((ip (gethash "hostIP" port "")))
                                 (list* (gethash "protocol" port "TCP") (if (equal ip "0.0.0.0") "" ip) number)))))

(defun host-ports-conflict-p (left right)
  "Return whether two (protocol ip . port) claims overlap, where an unset ip overlaps every address."
  (and (equal (car left) (car right))
       (= (cddr left) (cddr right))
       (or (equal (cadr left) (cadr right)) (equal "" (cadr left)) (equal "" (cadr right)))))

(defun pod-host-ports-free-p (store pod node)
  "Return whether none of POD's host ports is claimed on NODE. Call with STORE's lock held."
  (let ((wanted (pod-host-ports pod)))
    (or (null wanted)
        (let ((taken (loop for other in (node-charged-pods-unlocked store (node-record-name node))
                           unless (equal (pod-uid other) (pod-uid pod))
                             append (pod-host-ports other))))
          (notany (lambda (claim) (find claim taken :test #'host-ports-conflict-p)) wanted)))))

(defun pod-admitted-before-p (store other pod)
  "Return whether a node would have reached OTHER first: it has reported on OTHER, or OTHER is older."
  (or (gethash (pod-uid other) (pod-store-pod-observed-phases store))
      (flet ((age (candidate)
               (format nil "~A/~A" (gethash "creationTimestamp" (gethash "metadata" (pod-to-object candidate)) "")
                       (pod-name candidate))))
        (string< (age other) (age pod)))))

(defun node-pod-fit-failures (store pod node &key admission)
  "Return why POD does not fit NODE, each as (message . kubelet-reason).
Under ADMISSION, a Pod only competes with Pods the node reaches before it, and with
no reservation; otherwise it competes as the scheduler charges it. Call with STORE's lock held."
  (let* ((name (node-record-name node))
         (others (remove-if (lambda (other)
                              (or (equal (pod-uid other) (pod-uid pod))
                                  (and admission (not (pod-admitted-before-p store other pod)))))
                            (append (node-charged-pods-unlocked store name)
                                    (unless admission (nominated-pods-unlocked store name pod)))))
         (allocatable (node-allocatable-table node))
         (requests (pod-requests-table pod))
         (limit (gethash "pods" allocatable))
         (failures nil))
    (when (and limit (> (1+ (length others)) limit))
      (push (cons "Too many pods" "OutOfpods") failures))
    ;; The Pod count is reported above, so each resource is judged on its own.
    (remhash "pods" allocatable)
    (maphash (lambda (resource amount)
               (unless (resource-fit-p (core-object resource amount) allocatable others)
                 (push (cons (format nil "Insufficient ~A" resource) (format nil "OutOf~A" resource)) failures)))
             requests)
    (let ((wanted (pod-host-ports pod))
          (taken (loop for other in others append (pod-host-ports other))))
      (when (some (lambda (claim) (find claim taken :test #'host-ports-conflict-p)) wanted)
        (push (cons +host-port-failure+ "NodePorts") failures)))
    failures))

(defun pod-admission-rejected-p (store pod)
  "Return whether POD was refused by its node. Call with STORE's lock held."
  (let* ((status (gethash (pod-uid pod) (pod-store-pod-observed-statuses store)))
         (reason (and status (gethash "reason" status))))
    (and (equal "Failed" (and status (gethash "phase" status))) (stringp reason)
         (or (member reason '("NodePorts" "SysctlForbidden" "AppArmor" "PodOSNotSupported") :test #'equal)
             (uiop:string-prefix-p "OutOf" reason)))))

(defun admit-assigned-pod (store pod)
  "Decide whether POD, assigned to a node, may start there, and record a refusal as a kubelet does.
A Pod the node has reported on is past admission, however full the node is now."
  (let ((failure
          (with-store-lock (store)
            (cond
              ((pod-admission-rejected-p store pod) (return-from admit-assigned-pod nil))
              ((or (deletion-requested-p pod) (gethash (pod-uid pod) (pod-store-pod-observed-phases store)))
               (return-from admit-assigned-pod t))
              (t (or (pod-os-failure pod)
                     (pod-forbidden-sysctl-failure pod)
                     (pod-apparmor-failure pod)
                     (let ((node (get-node-unlocked store (pod-node-name pod))))
                       (and node (first (node-pod-fit-failures store pod node :admission t))))))))))
    (when failure
      (save-pod-observation
       store pod
       (core-object "phase" "Failed" "reason" (cdr failure)
                    "message" (format nil "Pod was rejected: ~A" (car failure))
                    ;; The node judged this generation of the Pod.
                    "observedGeneration" (gethash "generation" (gethash "metadata" (pod-to-object pod)) 1))))
    (null failure)))

(defun pod-unschedulable-message (store pod)
  "Explain why no node accepts POD, in the Kubernetes scheduler's form. Call with STORE's lock held."
  (let ((nodes (loop for node being the hash-values of (pod-store-nodes store) collect node))
        (counts nil))
    (dolist (node nodes)
      (dolist (failure (or (mapcar #'car (node-pod-fit-failures store pod node))
                           (unless (node-record-runtime-ready-p node) '("node(s) not ready"))
                           (when (node-record-unschedulable node) '("node(s) were unschedulable"))
                           (unless (pod-node-taints-allow-p pod node) '("node(s) had untolerated taints"))
                           (unless (and (pod-node-selector-matches-p pod node) (pod-node-affinity-matches-p pod node))
                             '("node(s) didn't match Pod's node affinity/selector"))
                           (let ((failure (or (pod-affinity-failure-unlocked store pod node)
                                              (pod-topology-spread-failure-unlocked store pod node)
                                              (pod-node-storage-failure store pod node))))
                             (when failure (list failure)))))
        (let ((entry (assoc failure counts :test #'equal)))
          (if entry (incf (cdr entry)) (push (cons failure 1) counts)))))
    (format nil "0/~D nodes are available~@[: ~{~A~^, ~}~]."
            (length nodes)
            (mapcar (lambda (entry) (format nil "~D ~A" (cdr entry) (car entry)))
                    (sort counts #'string< :key #'car)))))
