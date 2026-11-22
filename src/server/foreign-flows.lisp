;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Read flow events on a foreign cluster (podster-e9a.7), where gr8s-net runs as a
;;;; DaemonSet and nothing serves /apis/gr8s.io/v1/flows. Each net-agent serves its
;;;; node's events on a loopback port; this reaches every one through the cluster
;;;; API's pods/portforward, in the kubelet's WebSocket channel protocol, so a reader
;;;; needs only the Kubernetes permission to port-forward to those Pods. The Pods and
;;;; NetworkPolicies the API lists then name each flow's peer and, for a policy drop,
;;;; its isolating policies, as the gr8s control plane does for its own nodes.

(in-package #:gr8s.server)

(defparameter +net-agent-pod-selector+ "app.kubernetes.io/name=gr8s-net"
  "The labels of the gr8s-net chart's agent Pods.")

(defparameter +port-forward-channel-protocol+ "v4.channel.k8s.io"
  "The kubelet's WebSocket port-forward: per port, channel 0 for data and 1 for errors.")

(defun net-agent-flow-request (follow)
  "The line asking a net-agent for its recent flow events, and with FOLLOW, new ones."
  (trivial-utf-8:string-to-utf-8-bytes (if follow (format nil "{\"follow\":true}~%") (format nil "{}~%"))))

(defun read-port-forward-flow-lines (stream function write-frame)
  "Call FUNCTION with each line a net-agent sends over the port-forward on STREAM, until
its empty last line or the port-forward ends. Each channel opens with the port, two
bytes, that isn't data. WRITE-FRAME answers pings. Signal what the error channel says."
  (let ((partial (make-array 0 :element-type '(unsigned-byte 8) :adjustable t :fill-pointer 0))
        (errors (make-array 0 :element-type '(unsigned-byte 8) :adjustable t :fill-pointer 0))
        (opened (list nil nil)))
    (flet ((failed ()
             (when (plusp (length errors))
               (error "~A" (trivial-utf-8:utf-8-bytes-to-string (coerce errors '(vector (unsigned-byte 8))))))))
      (loop
        (multiple-value-bind (opcode payload) (gr8s.protocol:read-websocket-frame stream)
          (case opcode
            (2 (when (plusp (length payload))
                 (let* ((channel (aref payload 0))
                        (start (if (and (< channel 2) (not (nth channel opened)))
                                   (progn (setf (nth channel opened) t) 3)
                                   1)))
                   (case channel
                     (0 (loop for index from start below (length payload)
                              for octet = (aref payload index)
                              do (cond ((/= octet 10) (vector-push-extend octet partial))
                                       ((zerop (length partial)) (failed) (return-from read-port-forward-flow-lines))
                                       (t (funcall function (coerce partial '(simple-array (unsigned-byte 8) (*))))
                                          (setf (fill-pointer partial) 0)))))
                     (1 (loop for index from start below (length payload)
                              do (vector-push-extend (aref payload index) errors)))))))
            (8 (failed) (return))
            (9 (funcall write-frame 10 payload))
            (10)
            (otherwise (error "the port-forward sent an unsupported WebSocket frame"))))))))

(defun call-with-net-agent-flow-lines (config namespace pod port follow function &key on-open)
  "Call FUNCTION with each flow line of net-agent Pod NAMESPACE/POD, reached on its loopback
PORT through the cluster API's port-forward. ON-OPEN receives a function that ends it."
  (multiple-value-bind (stream socket)
      (open-debug-websocket config (format nil "/api/v1/namespaces/~A/pods/~A/portforward?ports=~D"
                                           namespace pod port)
                            :protocol +port-forward-channel-protocol+)
    (unwind-protect
         (let ((lock (bt:make-lock "gr8s port-forward writer")))
           (flet ((write-frame (opcode payload)
                    (bt:with-lock-held (lock)
                      (gr8s.protocol::write-websocket-frame stream opcode payload :masked-p t))))
             (when on-open
               (funcall on-open (lambda () (ignore-errors (usocket:socket-shutdown socket :io)))))
             (let ((request (net-agent-flow-request follow)))
               (write-frame 2 (concatenate '(vector (unsigned-byte 8)) #(0) request)))
             (read-port-forward-flow-lines stream function #'write-frame)))
      (ignore-errors (close stream))
      (ignore-errors (usocket:socket-close socket)))))

(defun net-agent-pods (config)
  "(namespace name node) of each running gr8s-net agent Pod."
  (loop for pod across (gethash "items" (debug-api-get-json
                                         config (format nil "/api/v1/pods?labelSelector=~A"
                                                        (drakma:url-encode +net-agent-pod-selector+ :utf-8)))
                                #())
        for metadata = (gethash "metadata" pod)
        when (equal "Running" (gethash "phase" (gethash "status" pod)))
          collect (list (gethash "namespace" metadata) (gethash "name" metadata)
                        (gethash "nodeName" (gethash "spec" pod)))))

(defun api-flow-context (config)
  "A flow context from the cluster's Pods and NetworkPolicies."
  (gr8s.controllers::make-flow-context-from-objects
   (gethash "items" (debug-api-get-json config "/api/v1/pods") #())
   (gethash "items" (debug-api-get-json config "/apis/networking.k8s.io/v1/networkpolicies") #())))

(defun call-with-net-agent-flows (config namespace follow function
                                  &key on-open (port gr8s.agent::+default-flow-listener-port+))
  "Call FUNCTION with each flow line, as JSON octets, from every gr8s-net agent, named
and limited to NAMESPACE as the flows API would. A node that can't stream is reported
once as a line with \"node\" and \"error\". FUNCTION is never called from two threads at
once. ON-OPEN receives a function that ends every stream."
  (let* ((agents (or (net-agent-pods config)
                     (error "this cluster serves no gr8s flow events: it is not gr8s and runs no gr8s-net agents")))
         (lock (bt:make-lock "gr8s foreign flows"))
         (context (api-flow-context config))
         (context-time (get-internal-real-time))
         (stoppers nil) (stopped nil))
    (when on-open
      (funcall on-open (lambda ()
                         (bt:with-lock-held (lock)
                           (setf stopped t)
                           (mapc #'funcall stoppers)))))
    (flet ((deliver (flow)
             (bt:with-lock-held (lock)
               (unless (gethash "error" flow)
                 ;; Pods and policies change while a follower watches; look again now and then.
                 (when (> (- (get-internal-real-time) context-time) (* 5 internal-time-units-per-second))
                   (setf context (or (ignore-errors (api-flow-context config)) context)
                         context-time (get-internal-real-time)))
                 (gr8s.controllers::enrich-flow context flow))
               (when (or (gethash "error" flow) (gr8s.apiserver::flow-in-namespace-p flow namespace))
                 (funcall function (gr8s.resources:stringify-to-utf-8-bytes flow))))))
      (mapc #'bt:join-thread
            (loop for (agent-namespace name node) in agents
                  collect (let ((agent-namespace agent-namespace) (name name) (node node))
                            (bt:make-thread
                             (lambda ()
                               (handler-case
                                   (call-with-net-agent-flow-lines
                                    config agent-namespace name port follow
                                    (lambda (line)
                                      (let ((flow (ignore-errors (com.inuoe.jzon:parse line))))
                                        (when (hash-table-p flow) (deliver flow))))
                                    :on-open (lambda (stop)
                                               (bt:with-lock-held (lock)
                                                 (if stopped (funcall stop) (push stop stoppers)))))
                                 (error (condition)
                                   (unless stopped
                                     (deliver (gr8s.resources::core-object
                                               "node" (or node name) "error" (princ-to-string condition)))))))
                             :name "gr8s foreign flows"))))
      (length agents))))
