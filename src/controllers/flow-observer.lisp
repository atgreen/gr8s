;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Observe the cluster's flow events from the control plane (podster-e9a.2). Each
;;;; node streams its own over the session its agent opened, so the control plane
;;;; merges every node's stream with no relay of its own, as Hubble Relay would.
;;;; The control plane also knows every Pod and NetworkPolicy, so it names the
;;;; peer of each flow, and for a policy drop, the policies that isolate the Pod.

(in-package #:gr8s.controllers)

(defstruct (flow-context (:constructor %make-flow-context (pods policies &optional host-pods)))
  "What enrichment reads: every addressed Pod, the host-network ones apart, and every
NetworkPolicy as an np-spec."
  pods policies host-pods)

(defun host-network-pod-object-p (object)
  "Whether Pod OBJECT is on its node's network, so its address is the node's, shared."
  (eq t (gethash "hostNetwork" (gethash "spec" object (core-object)))))

(defun make-flow-context (store)
  "A flow context from STORE. A host-network Pod's address names its node, not the Pod,
so enrichment never names one by address."
  (let ((host-network (loop for pod in (list-pods store)
                            when (host-network-pod-object-p (pod-to-object pod))
                              collect (cons (pod-namespace pod) (pod-name pod))))
        (pods (gr8s.network::network-policy-cluster-pods store)))
    (flet ((host-p (pod) (member (cons (gr8s.network::np-pod-namespace pod) (gr8s.network::np-pod-name pod))
                                 host-network :test #'equal)))
      (%make-flow-context
       (remove-if #'host-p pods)
       (gr8s.network::network-policy-specs-from-objects (list-core-resources store "networkpolicies"))
       (remove-if-not #'host-p pods)))))

(defun make-flow-context-from-objects (pods policies)
  "A flow context from Pod and NetworkPolicy objects as the Kubernetes API lists them."
  (%make-flow-context
   (remove nil (map 'list #'gr8s.network::pod-object-np-pod
                    (remove-if #'host-network-pod-object-p pods)))
   (gr8s.network::network-policy-specs-from-objects (coerce policies 'list))
   (remove nil (map 'list #'gr8s.network::pod-object-np-pod
                    (remove-if-not #'host-network-pod-object-p pods)))))

(defun flow-context-namespace-pod-at (context namespace address)
  "The one Pod in NAMESPACE at ADDRESS, host-network or not, or NIL when there are none or
several. A host-network Pod's address is its node's, but a namespace usually has one
Pod on a node; a flow whose namespace is known (a Gateway's backend) can name it."
  (let ((found (and namespace address
                    (remove-if-not (lambda (pod)
                                     (and (equal namespace (gr8s.network::np-pod-namespace pod))
                                          (member address (gr8s.network::np-pod-addresses pod) :test #'equal)))
                                   (append (flow-context-pods context) (flow-context-host-pods context))))))
    (and found (null (rest found)) (first found))))

(defun flow-context-pod-at (context address)
  "The np-pod with ADDRESS, or NIL."
  (and address
       (find-if (lambda (pod) (member address (gr8s.network::np-pod-addresses pod) :test #'equal))
                (flow-context-pods context))))

(defun flow-isolating-policies (context namespace name direction)
  "Names of the NetworkPolicies that isolate Pod NAMESPACE/NAME for DIRECTION, \"egress\" or
\"ingress\". A packet the Pod's policies don't allow was dropped because these select it."
  (let ((pod (find-if (lambda (pod) (and (equal namespace (gr8s.network::np-pod-namespace pod))
                                          (equal name (gr8s.network::np-pod-name pod))))
                      (flow-context-pods context)))
        (type (if (equal direction "egress") "Egress" "Ingress")))
    (when pod
      (sort (loop for spec in (flow-context-policies context)
                  when (and (gr8s.network::np-spec-selects-pod-p spec pod)
                            (member type (gr8s.network::np-spec-policy-types spec) :test #'string=))
                    collect (gr8s.network::np-spec-name spec))
            #'string<))))

(defun enrich-flow (context flow)
  "Add FLOW's Pod labels, its peer Pod and labels, and for a policy drop, the policies
isolating its Pod. A flow whose node couldn't name its Pod (a Gateway's, whose backend
may be on another node) gets it here."
  (unless (gethash "pod" flow)
    (let ((own (or (flow-context-pod-at context (gethash "podAddress" flow))
                   (flow-context-namespace-pod-at context (gethash "namespace" flow) (gethash "podAddress" flow)))))
      (when own
        (setf (gethash "namespace" flow) (gr8s.network::np-pod-namespace own)
              (gethash "pod" flow) (gr8s.network::np-pod-name own)))))
  (let ((pod (find-if (lambda (pod) (and (equal (gethash "namespace" flow) (gr8s.network::np-pod-namespace pod))
                                         (equal (gethash "pod" flow) (gr8s.network::np-pod-name pod))))
                      (append (flow-context-pods context) (flow-context-host-pods context))))
        (peer (flow-context-pod-at context (gethash "peerAddress" flow))))
    (when pod
      (setf (gethash "podLabels" flow) (gr8s.network::np-pod-labels pod)))
    (when peer
      (setf (gethash "peerNamespace" flow) (gr8s.network::np-pod-namespace peer)
            (gethash "peerPod" flow) (gr8s.network::np-pod-name peer)
            (gethash "peerLabels" flow) (gr8s.network::np-pod-labels peer))))
  (when (and (equal "policy" (gethash "reason" flow)) (gethash "pod" flow))
    (setf (gethash "policies" flow)
          (coerce (flow-isolating-policies context (gethash "namespace" flow) (gethash "pod" flow)
                                           (gethash "direction" flow))
                  'vector)))
  flow)

(defun flow-session-lines (runtime session function stop-p)
  "Call FUNCTION with each complete line SESSION's node sends, until it ends or STOP-P."
  (let ((partial (make-array 0 :element-type '(unsigned-byte 8) :adjustable t :fill-pointer 0))
        (cursor 0))
    (loop until (funcall stop-p)
          do (multiple-value-bind (message next done)
                 ;; Waiting signals when its timeout passes. That only means nothing has
                 ;; happened yet: a node that fails ends the operation, which ends the loop.
                 (handler-case (runtime-next-exec-session-output runtime session cursor :timeout 0.5)
                   (runtime-error () (values nil cursor nil)))
               (setf cursor next)
               (when done (return))
               (when message
                 (loop for octet across (slot-value message 'gr8s.node.v1::data)
                       do (if (= octet 10)
                              (progn
                                (funcall function (coerce partial '(simple-array (unsigned-byte 8) (*))))
                                (setf (fill-pointer partial) 0))
                              (vector-push-extend octet partial))))))))

(defun observe-cluster-flows (runtime function &key follow nodes (stop-p (constantly nil)))
  "Call FUNCTION with each flow event, as a JSON object, from every node in NODES (by default
every node that runs workloads): their recent events, then with FOLLOW new ones until STOP-P
answers true. FUNCTION is never called from two threads at once. A node that can't stream
is reported once to FUNCTION as an object with \"node\" and \"error\"."
  (let* ((store (control-plane-runtime-store runtime))
         (names (or nodes (loop for node in (list-nodes store)
                                unless (node-record-api-only node) collect (node-record-name node))))
         (lock (bt:make-lock "gr8s flow observer"))
         (context (make-flow-context store))
         (context-time (get-internal-real-time)))
    (flet ((deliver (object)
             (bt:with-lock-held (lock)
               ;; Pods and policies change while a follower watches; look again now and then.
               (when (> (- (get-internal-real-time) context-time) (* 5 internal-time-units-per-second))
                 (setf context (make-flow-context store) context-time (get-internal-real-time)))
               (funcall function (if (gethash "error" object) object (enrich-flow context object))))))
      (let ((threads
              (loop for name in names
                    collect (let ((name name))
                              (bt:make-thread
                               (lambda ()
                                 (let ((session nil))
                                   (handler-case
                                       (progn
                                         (setf session (start-control-plane-flows-session runtime name :follow follow))
                                         (flow-session-lines
                                          runtime session
                                          (lambda (line)
                                            (let ((object (ignore-errors (com.inuoe.jzon:parse line))))
                                              (when (hash-table-p object) (deliver object))))
                                          stop-p)
                                         ;; A node that refused, or failed, reports why.
                                         (runtime-exec-session-exit-code runtime session))
                                     (error (condition)
                                       (deliver (core-object "node" name "error" (princ-to-string condition)))))
                                   (when session
                                     (ignore-errors (runtime-cancel-exec-session runtime session "observer finished"))
                                     (ignore-errors (runtime-release-exec-session runtime session)))))
                               :name "gr8s flow observer")))))
        (mapc #'bt:join-thread threads)
        (length names)))))
