;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Serve the Pod status subresource, Pod collection deletion and each Pod's host
;;;; address. A client's terminal phase, message, reason and custom conditions stay
;;;; until replaced.
;;;; Conditions gr8s derives itself appear only in the write's response, because
;;;; the next observation overwrites them, as a kubelet's next status sync does.

(in-package #:gr8s)

(defparameter *pod-system-condition-types*
  '("PodScheduled" "Initialized" "ContainersReady" "Ready" "PodResizeInProgress")
  "Conditions recomputed from actual observations on every reconciliation.")

(defvar *local-primary-ipv4* nil "This host's primary IPv4 address, once discovered.")

(defun discover-local-primary-ipv4 ()
  "Return the source address of the default route, or NIL without one. Sends nothing."
  (ignore-errors
   (let ((socket (make-instance 'sb-bsd-sockets:inet-socket :type :datagram :protocol :udp)))
     (unwind-protect
          (progn
            (sb-bsd-sockets:socket-connect socket #(192 0 2 1) 9)
            (format nil "~{~D~^.~}" (coerce (sb-bsd-sockets:socket-name socket) 'list)))
       (sb-bsd-sockets:socket-close socket)))))

(defun node-reported-address (node)
  "Return NODE's address. Only the local agent lacks an underlay, so it is this host's."
  (let ((address (node-record-underlay-address node)))
    (if (plusp (length address))
        address
        (or *local-primary-ipv4* (setf *local-primary-ipv4* (discover-local-primary-ipv4))))))

(defun containerd-node-address (runtime)
  "Return the address this runtime's node is reached at, which hostNetwork Pods share."
  (or (containerd-runtime-host-address runtime)
      *local-primary-ipv4*
      (setf *local-primary-ipv4* (discover-local-primary-ipv4))
      ""))

(defun add-pod-host-address (store pod status)
  "Publish the assigned node's address while STORE's lock is held; agents have no node table.
A hostNetwork Pod has no address of its own, so it reports its node's as its Pod IP."
  (let* ((node (and (pod-node-name pod) (gethash (pod-node-name pod) (pod-store-nodes store))))
         (address (and node (node-reported-address node))))
    (when address
      (setf (gethash "hostIP" status) address
            (gethash "hostIPs" status) (vector (core-object "ip" address)))
      (when (and (pod-host-network-p pod) (not (equal "Pending" (gethash "phase" status))))
        (setf (gethash "podIP" status) address
              (gethash "podIPs" status) (vector (core-object "ip" address)))))
    status))

(defun decode-pod-status-protobuf (bytes)
  "Decode the client-writable PodStatus fields; the server owns everything else."
  (let ((fields (core-protobuf-fields bytes)) (status (core-object)))
    (loop for (number name) in '((1 "phase") (3 "message") (4 "reason"))
          for value = (core-protobuf-string fields number)
          when (plusp (length value)) do (setf (gethash name status) value))
    (let ((conditions
            (loop for field in fields
                  when (= 2 (first field))
                    collect (let ((entry (core-protobuf-fields (third field))) (condition (core-object)))
                              (loop for (number name) in '((1 "type") (2 "status") (5 "reason") (6 "message"))
                                    for value = (core-protobuf-string entry number)
                                    when (plusp (length value)) do (setf (gethash name condition) value))
                              condition))))
      (when conditions (setf (gethash "conditions" status) (coerce conditions 'vector))))
    status))

(defun apply-pod-client-status (store pod status)
  "Overlay POD's persisted client terminal phase, message, reason and custom conditions onto STATUS."
  (let ((client (gethash (pod-uid pod) (pod-store-pod-client-statuses store))))
    (when client
      (when (gethash "phase" client) (setf (gethash "phase" status) (gethash "phase" client)))
      (dolist (field '("message" "reason"))
        (when (and (gethash field client) (not (gethash field status)))
          (setf (gethash field status) (gethash field client))))
      (let ((conditions (gethash "conditions" status #())))
        (setf (gethash "conditions" status)
              (concatenate 'vector conditions
                           (remove-if (lambda (condition)
                                        (find-pod-condition conditions (gethash "type" condition)))
                                      (gethash "conditions" client #())))))))
  status)

(defparameter *pod-status-patch-schema*
  (let ((keyed (lambda (key) (core-object "x-kubernetes-patch-strategy" "merge" "x-kubernetes-patch-merge-key" key
                                            "items" (core-object)))))
    (core-object "properties"
                 (core-object "status"
                              (core-object "properties"
                                           (core-object "conditions" (funcall keyed "type")
                                                        "podIPs" (funcall keyed "ip")
                                                        "hostIPs" (funcall keyed "ip"))))))
  "The strategic merge keys of PodStatus lists, as Kubernetes declares them: a status patch
   naming one condition changes that condition and keeps the others.")

(defun pod-status-write-input (current method)
  "Return the requested Pod object from a typed or JSON PUT, or a patch applied to CURRENT."
  (if (eq method :put)
      (let ((*pod-status-write* t)) (core-resource-request-object "Pod"))
      (let* ((content-type (first (uiop:split-string (or (hunchentoot:header-in* :content-type) "")
                                                     :separator '(#\;))))
             (applied (equal content-type "application/apply-patch+yaml"))
             (patch (unless applied (com.inuoe.jzon:parse (hunchentoot:raw-post-data :force-text t)))))
        (cond (applied (apply-pod-patched-object (copy-json-object current) "status"))
              ((equal content-type "application/json-patch+json") (apply-core-json-patch current patch))
              ((equal content-type "application/merge-patch+json")
               (merge-json-object (copy-json-object current) (require-object patch "patch")))
              ((equal content-type "application/strategic-merge-patch+json")
               (template-strategic-merge (copy-json-object current) (require-object patch "patch")
                                         *pod-status-patch-schema*))
              (t (core-resource-error 415 "UnsupportedMediaType" "Unsupported Pod status patch format"))))))

(defun pod-client-status-from (status)
  "Select the parts of a written STATUS that survive reconciliation."
  (let ((client (core-object)))
    (dolist (field '("message" "reason"))
      (let ((value (gethash field status)))
        (when (and (stringp value) (plusp (length value))) (setf (gethash field client) value))))
    ;; A terminal phase is a verdict controllers act on, as when a kubelet reports it.
    (when (member (gethash "phase" status) '("Failed" "Succeeded") :test #'equal)
      (setf (gethash "phase" client) (gethash "phase" status)))
    (let ((custom (remove-if (lambda (condition)
                               (member (gethash "type" condition) *pod-system-condition-types* :test #'equal))
                             (gethash "conditions" status #()))))
      (when (plusp (length custom)) (setf (gethash "conditions" client) custom)))
    client))

(defun save-pod-client-status (store pod client)
  "Checkpoint CLIENT, a selection from a status write, for POD's exact identity."
  (with-store-lock (store)
    (when (current-status-pod-p store pod)
      (persist-pod-status-state store pod :client client)
      (setf (gethash (pod-uid pod) (pod-store-pod-client-statuses store)) client))))

(defun update-pod-status-metadata (store pod metadata)
  "Apply label and annotation changes from a status write, leaving the spec alone."
  (let* ((object (copy-json-object (pod-to-object pod))) (stored (gethash "metadata" object)) (changed nil))
    (dolist (field '("labels" "annotations"))
      (multiple-value-bind (value present) (gethash field metadata)
        (when (and present (not (eq value 'null)) (not (equalp value (gethash field stored))))
          (setf (gethash field stored) value changed t))))
    (if changed
        (update-pod store (parse-pod object) (pod-resource-version pod))
        pod)))

(defun write-pod-status-response (store reconciler name namespace method)
  "Apply a status write and answer with what the client wrote over the observed status."
  (let* ((*pod-patch-subresource* "status")
         (pod (get-pod store namespace name))
         (current (pod-response-object pod (reconcile-pod reconciler namespace name)))
         (input (admit-subresource-write store "pods" "status" namespace name
                                         (require-object (pod-status-write-input current method) "Pod") current
                                         :dry-run (core-resource-dry-run-p)))
         (metadata (require-object (gethash "metadata" input) "metadata"))
         (status (require-object (gethash "status" input (core-object)) "status"))
         (expected (gethash "resourceVersion" metadata))
         (dry-run (core-resource-dry-run-p)))
    (when (and (gethash "name" metadata) (not (equal name (gethash "name" metadata))))
      (core-resource-error 400 "BadRequest" "metadata.name does not match request name"))
    (when (and (gethash "uid" metadata) (not (equal (gethash "uid" metadata) (pod-uid pod))))
      (core-resource-error 409 "Conflict" "UID precondition does not match"))
    (when (and (stringp expected) (plusp (length expected))
               (not (pod-revision-satisfied-p store expected (pod-resource-version pod))))
      (core-resource-error 409 "Conflict" "Pod resourceVersion has changed"))
    (loop for condition across (gethash "conditions" status #())
          do (unless (and (hash-table-p condition) (stringp (gethash "type" condition))
                          (member (gethash "status" condition) '("True" "False" "Unknown") :test #'equal))
               (invalid-pod "status.conditions entries need a type and a True, False or Unknown status")))
    (let ((client (pod-client-status-from status)))
      (unless dry-run
        (setf pod (update-pod-status-metadata store pod metadata))
        (save-pod-client-status store pod client))
      (let* ((observed (if dry-run
                           (gethash "status" current)
                           (reconcile-pod reconciler namespace name)))
             (answer (pod-response-object pod (copy-json-object observed)))
             (shown (gethash "status" answer)))
        (dolist (field '("phase" "message" "reason"))
          (when (gethash field client) (setf (gethash field shown) (gethash field client))))
        ;; The written form of a derived condition is visible only here.
        (setf (gethash "conditions" shown)
              (let ((written (gethash "conditions" status #())))
                (concatenate 'vector
                             (remove-if (lambda (condition) (find-pod-condition written (gethash "type" condition)))
                                        (gethash "conditions" shown #()))
                             written)))
        (json-response answer)))))

(defun delete-pod-collection-response (store reconciler namespace)
  "Delete matching Pods in NAMESPACE, each with the request's shutdown options."
  (let ((matches (pod-watch-predicate namespace (or (hunchentoot:parameter "labelSelector") "")
                                      (or (hunchentoot:parameter "fieldSelector") "")))
        (arguments (multiple-value-bind (arguments foreground) (pod-delete-request-arguments)
                     (when foreground (invalid-pod "Pod collection deletion does not support Foreground propagation"))
                     arguments)))
    (dolist (pod (list-pods store namespace))
      (when (funcall matches (with-store-lock (store) (pod-published-view store pod)))
        (admit-pod-delete store namespace (pod-name pod) nil)
        (handler-case (apply #'delete-reconciled-pod reconciler namespace (pod-name pod)
                             :uid (pod-uid pod) (loop for (key value) on arguments by #'cddr
                                                      unless (member key '(:uid :resource-version))
                                                        append (list key value)))
          (kubernetes-error (condition)
            (unless (member (kubernetes-error-status-code condition) '(404 409)) (error condition))))))
    (status-response "Success" "Deleted" "Pods deleted" 200)))
