;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; The control plane's implementation of the RUNTIME protocol.
;;;;
;;;; The same RUNTIME generic interface the node agent implements with real
;;;; containers is implemented here by the control plane, which runs none: it
;;;; schedules each Pod to a node and publishes that node's desired-state
;;;; snapshot over the node gRPC server, then observes the agent's reported
;;;; status. A Pod read before its agent has reported it (RUNTIME-ENSURE) is the
;;;; hot path, so a snapshot is published only when the node does not already
;;;; carry the Pod's exact revision -- otherwise listing N Pending Pods would cost
;;;; O(N^2) in Pod JSON to discover nothing changed. Snapshots are authoritative:
;;;; omitting a Pod is how a node is told to stop it, and a graceful deletion
;;;; keeps its assignment until the node acknowledges the exact revision Deleted.
;;;; Logs, exec, attach and port-forward are proxied to the owning node as node
;;;; operations.

(in-package #:gr8s.controllers)

(defstruct (control-plane-runtime
             (:constructor make-control-plane-runtime (store node-server)))
  store
  node-server
  (resource-metrics-summaries #())
  (container-metrics (make-hash-table :test #'equal))
  (resource-metrics-at 0)
  (resource-metrics-lock (bt:make-lock "control-plane resource metrics")))

(defun control-plane-pod-by-uid (runtime uid)
  "Return the Pod with UID from RUNTIME's store, or NIL when none matches."
  (find uid (list-pods (control-plane-runtime-store runtime))
        :key #'pod-uid :test #'string=))

(defun pod-assignment (pod &optional store)
  "Build the node-protocol POD-ASSIGNMENT for POD: its namespace, name, uid and
   resource version, the Pod serialized as JSON, its deleting flag, and -- only
   when STORE is given and the Pod is not being deleted -- the JSON of the
   resources it references."
  (make-instance
   'gr8s.node.v1::pod-assignment
   :namespace (pod-namespace pod)
   :name (pod-name pod)
   :uid (pod-uid pod)
   :resource-version (pod-resource-version pod)
   :pod-json
   (trivial-utf-8:string-to-utf-8-bytes
    (with-output-to-string (stream)
      (com.inuoe.jzon:stringify (pod-to-object pod) :stream stream)))
   :deleting (deletion-requested-p pod)
   :resource-objects-json
   (when (and store (not (deletion-requested-p pod)))
     (mapcar (lambda (object)
               (trivial-utf-8:string-to-utf-8-bytes (com.inuoe.jzon:stringify object)))
             (pod-referenced-resource-objects store pod)))))

(defun node-desired-state-snapshot (store node-name &key excluded-uid)
  "Build NODE-NAME's desired-state snapshot from STORE: the service-discovery
   projection and a POD-ASSIGNMENT for each admitted Pod assigned to NODE-NAME,
   skipping EXCLUDED-UID, ordered by namespace/name."
  (make-instance
   'gr8s.node.v1::desired-state-snapshot
   :service-discovery-objects-json (service-discovery-projection store)
   :pods
   (mapcar
    (lambda (pod) (pod-assignment pod store))
    (sort
     (remove-if
      (lambda (pod)
        (or (not (equal node-name (pod-node-name pod)))
            (and excluded-uid (string= excluded-uid (pod-uid pod)))
            (not (admit-assigned-pod store pod))))
      (list-pods store))
     #'string< :key (lambda (pod) (format nil "~A/~A" (pod-namespace pod) (pod-name pod)))))))

(defun publish-node-snapshot (runtime node-name &key excluded-uid)
  "Build NODE-NAME's desired-state snapshot and publish it to that agent over the
   node server, deduplicating against the last snapshot sent."
  (publish-node-desired-state
   (control-plane-runtime-node-server runtime)
   node-name
   (node-desired-state-snapshot
    (control-plane-runtime-store runtime) node-name
    :excluded-uid excluded-uid)
   :deduplicate t))

(defun publish-service-discovery-snapshots (runtime)
  "Deliver public DNS changes even when every running Pod revision is unchanged."
  (dolist (node (list-nodes (control-plane-runtime-store runtime)))
    (publish-node-snapshot runtime (node-record-name node))))

(defun control-plane-observation (runtime pod)
  "Build the RUNTIME-POD observation for POD from RUNTIME's store: its observed
   resource version, scheduling phase, status, and podIP (\"\" when none)."
  (make-runtime-pod
   :uid (pod-uid pod)
   :resource-version (pod-observed-resource-version (control-plane-runtime-store runtime) pod)
   :phase (pod-scheduling-phase (control-plane-runtime-store runtime) pod)
   :status (pod-observed-status (control-plane-runtime-store runtime) pod)
   :pod-ip (let ((status (pod-observed-status (control-plane-runtime-store runtime) pod)))
             (if status (gethash "podIP" status "") ""))))

(defmethod runtime-runs-containers-p ((runtime control-plane-runtime))
  "The assigned node's agent enforces container lifetimes; the control plane only observes them."
  nil)

(defmethod runtime-observe ((runtime control-plane-runtime) uid)
  (let ((pod (control-plane-pod-by-uid runtime uid)))
    ;; An unscheduled Pod must remain absent from the runtime view so that the
    ;; reconciliation worker retries scheduling when a node becomes Ready.
    (and pod (pod-node-name pod) (control-plane-observation runtime pod))))

(defun node-snapshot-carries-pod-p (runtime node-name pod)
  "Return whether NODE-NAME's latest published snapshot already assigns POD's exact revision."
  (let* ((server (control-plane-runtime-node-server runtime))
         (snapshot (bt:with-lock-held ((node-grpc-server-lock server))
                     (gethash node-name (node-grpc-server-snapshots server))))
         (assignment (and snapshot
                          (find (pod-uid pod) (slot-value snapshot 'gr8s.node.v1::pods)
                                :key (lambda (item) (slot-value item 'gr8s.node.v1::uid))
                                :test #'equal))))
    (and assignment
         (equal (pod-resource-version pod)
                (slot-value assignment 'gr8s.node.v1::resource-version)))))

(defmethod runtime-ensure ((runtime control-plane-runtime) pod)
  (let ((node (schedule-pod (control-plane-runtime-store runtime) pod)))
    ;; Every read of a Pod the agent has not yet reported lands here. Building a
    ;; snapshot costs every Pod's JSON, so a list of N Pending Pods would cost N^2
    ;; just to find nothing changed. A Pod the node already has needs no snapshot;
    ;; changes to the objects it references go out on publish-service-discovery-snapshots.
    (when (and node (not (node-snapshot-carries-pod-p runtime (node-record-name node) pod)))
      (publish-node-snapshot runtime (node-record-name node)))
    (control-plane-observation runtime pod)))

(defmethod runtime-delete ((runtime control-plane-runtime) uid)
  (let ((pod (control-plane-pod-by-uid runtime uid)))
    (when (and pod (pod-node-name pod))
      ;; Snapshots are authoritative. Omitting the Pod tells the node agent to
      ;; stop it before the control-plane record is removed.
      (publish-node-snapshot runtime (pod-node-name pod) :excluded-uid uid)))
  nil)

(defmethod runtime-delete-pod ((runtime control-plane-runtime) pod)
  "Keep a graceful deletion assigned until its exact revision is acknowledged Deleted."
  (let* ((store (control-plane-runtime-store runtime))
         (status (pod-observed-status store pod)))
    (when (pod-finalizers-present-p pod)
      ;; Even grace=0 must wait for physical cleanup when the API retains the
      ;; Pod. Keep its assignment until the finalizers have actually cleared.
      (let ((finalization (pod-finalization-state store pod)))
        (if (or (not (pod-node-name pod)) (and finalization (gethash "runtimeDeleted" finalization)))
            (return-from runtime-delete-pod t)
            (progn (publish-node-snapshot runtime (pod-node-name pod))
                   (return-from runtime-delete-pod nil)))))
    (cond
      ;; A refused Pod never reached its agent, which therefore has nothing to confirm.
      ((with-store-lock (store) (pod-admission-rejected-p store pod)) t)
      ((or (not (pod-node-name pod))
           (zerop (gethash "deletionGracePeriodSeconds" (gethash "metadata" (pod-to-object pod)) 0))
           (and (equal (pod-resource-version pod) (pod-observed-resource-version store pod))
                (equal "Deleted" (and status (gethash "reason" status)))))
       (runtime-delete runtime (pod-uid pod))
       t)
      (t
       (publish-node-snapshot runtime (pod-node-name pod))
       nil))))

(defmethod runtime-logs ((runtime control-plane-runtime) uid container &key tail previous)
  (declare (ignore tail))
  (let ((pod (control-plane-pod-by-uid runtime uid)))
    (unless (and pod (pod-node-name pod))
      (error 'runtime-error :message "Pod is not assigned to a node"))
    (let* ((request
             (make-instance
              'gr8s.node.v1::operation-request
              :operation-id (generate-uid)
              :kind gr8s.node.v1::+operationkind-operation_kind_logs+
              :namespace (pod-namespace pod)
              :pod (pod-name pod)
              :pod-uid uid
              :container container
              :stdout t
              :previous (not (null previous))))
           (operation
             (request-node-operation
              (control-plane-runtime-node-server runtime)
              (pod-node-name pod) request)))
      (with-output-to-string (output)
        (dolist (message
                 (pending-node-operation-stream-messages operation))
          (when (= (slot-value message 'gr8s.node.v1::channel)
                   gr8s.node.v1::+streamchannel-stream_channel_stdout+)
            (write-string
             (trivial-utf-8:utf-8-bytes-to-string
              (slot-value message 'gr8s.node.v1::data))
             output)))))))

(defmethod runtime-exec-url
    ((runtime control-plane-runtime) uid container command
     &key stdin stdout stderr tty)
  (declare (ignore runtime uid container command stdin stdout stderr tty))
  (error 'runtime-error
         :message "Node-agent exec proxying is not implemented yet"))

(defun node-operation-channel-data (operation channel)
  "Collect every byte OPERATION streamed on CHANNEL into one adjustable octet
   vector, in arrival order."
  (let ((output
          (make-array 0 :element-type '(unsigned-byte 8)
                        :adjustable t :fill-pointer 0)))
    (dolist (message (pending-node-operation-stream-messages operation))
      (when (= channel (slot-value message 'gr8s.node.v1::channel))
        (loop for octet across (slot-value message 'gr8s.node.v1::data)
              do (vector-push-extend octet output))))
    output))

(defmethod runtime-exec-sync
    ((runtime control-plane-runtime) uid container command &key (timeout 10))
  (let ((pod (control-plane-pod-by-uid runtime uid)))
    (unless (and pod (pod-node-name pod))
      (error 'runtime-error :message "Pod is not assigned to a node"))
    (let* ((request
             (make-instance
              'gr8s.node.v1::operation-request
              :operation-id (generate-uid)
              :kind gr8s.node.v1::+operationkind-operation_kind_exec+
              :namespace (pod-namespace pod)
              :pod (pod-name pod)
              :pod-uid uid
              :container container
              :command command
              :stdout t
              :stderr t))
           (operation
             (request-node-operation
              (control-plane-runtime-node-server runtime)
              (pod-node-name pod) request :timeout timeout))
           (response (pending-node-operation-response operation)))
      (make-runtime-exec-result
       :stdout
       (node-operation-channel-data
        operation gr8s.node.v1::+streamchannel-stream_channel_stdout+)
       :stderr
       (node-operation-channel-data
        operation gr8s.node.v1::+streamchannel-stream_channel_stderr+)
       :exit-code (slot-value response 'gr8s.node.v1::exit-code)))))

(defstruct (control-plane-exec-session
             (:constructor make-control-plane-exec-session
                 (operation)))
  "One exec or attach on a node. Its output is acknowledged as the client takes it, so a slow
client holds the node back instead of its output piling up here."
  operation
  (input-sequence 0)
  ;; Output bytes returned by the last NEXT call, acknowledged by the one after it.
  (delivered 0)
  (lock (bt:make-lock "gr8s control-plane exec session")))

(defun start-control-plane-stream-session
    (runtime uid container kind command &key stdin stdout stderr tty)
  "Ask the Pod's node to open a streaming operation of KIND and return its session."
  (let ((pod (control-plane-pod-by-uid runtime uid)))
    (unless (and pod (pod-node-name pod))
      (error 'runtime-error :message "Pod is not assigned to a node"))
    (make-control-plane-exec-session
     (queue-node-operation
      (control-plane-runtime-node-server runtime)
      (pod-node-name pod)
      (make-instance
       'gr8s.node.v1::operation-request
       :operation-id (generate-uid)
       :kind kind
       :namespace (pod-namespace pod)
       :pod (pod-name pod)
       :pod-uid uid
       :container container
       :command command
       :stdin stdin :stdout stdout :stderr stderr :tty tty
       :acknowledges-output t)))))

(defmethod runtime-start-exec-session
    ((runtime control-plane-runtime) uid container command
     &key stdin stdout stderr tty)
  (start-control-plane-stream-session
   runtime uid container gr8s.node.v1::+operationkind-operation_kind_exec+ command
   :stdin stdin :stdout stdout :stderr stderr :tty tty))

(defmethod runtime-start-attach-session
    ((runtime control-plane-runtime) uid container &key stdin stdout stderr tty)
  (start-control-plane-stream-session
   runtime uid container gr8s.node.v1::+operationkind-operation_kind_attach+ nil
   :stdin stdin :stdout stdout :stderr stderr :tty tty))

(defstruct (control-plane-port-forward
             (:constructor make-control-plane-port-forward (operation)))
  "One forwarded connection. Unlike a terminal's, its output is consumed as it goes, and each
direction waits for acknowledgements, so a long download neither piles up here nor on the node."
  operation
  (input-sequence 0)
  ;; Bytes sent to the Pod and not yet acknowledged by the node.
  (in-flight 0)
  ;; Bytes returned by the last NEXT call, acknowledged by the one after it.
  (delivered 0)
  (lock (bt:make-lock "gr8s control-plane port-forward"))
  (window (bt:make-condition-variable :name "gr8s port-forward window")))

(defun send-control-plane-port-forward-input (runtime session &key data eof (acknowledged 0))
  "Send the node a piece of input. A node operation takes one message at a time from here."
  (let ((operation (control-plane-port-forward-operation session)))
    (send-node-operation-input
     (control-plane-runtime-node-server runtime) operation
     (make-instance
      'gr8s.node.v1::operation-input
      :operation-id (operation-request-id (pending-node-operation-request operation))
      :sequence (bt:with-lock-held ((control-plane-port-forward-lock session))
                  (incf (control-plane-port-forward-input-sequence session)))
      :channel gr8s.node.v1::+streamchannel-stream_channel_stdin+
      :data (or data (make-array 0 :element-type '(unsigned-byte 8)))
      :eof eof :acknowledged-bytes acknowledged))))

(defmethod runtime-start-port-forward ((runtime control-plane-runtime) uid port)
  (let ((pod (control-plane-pod-by-uid runtime uid)))
    (unless (and pod (pod-node-name pod))
      (error 'runtime-error :message "Pod is not assigned to a node"))
    (make-control-plane-port-forward
     (queue-node-operation
      (control-plane-runtime-node-server runtime)
      (pod-node-name pod)
      (make-instance
       'gr8s.node.v1::operation-request
       :operation-id (generate-uid)
       :kind gr8s.node.v1::+operationkind-operation_kind_port_forward+
       :namespace (pod-namespace pod)
       :pod (pod-name pod)
       :pod-uid uid
       :port port)))))

(defmethod runtime-port-forward-send
    ((runtime control-plane-runtime) (session control-plane-port-forward) data &key eof)
  (let ((operation (control-plane-port-forward-operation session)))
    (bt:with-lock-held ((control-plane-port-forward-lock session))
      (loop while (and (>= (control-plane-port-forward-in-flight session) +port-forward-window-bytes+)
                       (not (pending-node-operation-done-p operation)))
            ;; NEXT notices the operation ending, but it may be busy writing to a slow client.
            do (bt:condition-wait (control-plane-port-forward-window session)
                                  (control-plane-port-forward-lock session) :timeout 0.2))
      (incf (control-plane-port-forward-in-flight session) (length data)))
    (send-control-plane-port-forward-input runtime session :data data :eof eof)))

(defmethod runtime-port-forward-next ((runtime control-plane-runtime) (session control-plane-port-forward))
  (let ((operation (control-plane-port-forward-operation session))
        (delivered (control-plane-port-forward-delivered session)))
    (when (plusp delivered)
      (setf (control-plane-port-forward-delivered session) 0)
      ;; The operation may just have ended, and then nobody needs to know.
      (ignore-errors (send-control-plane-port-forward-input runtime session :acknowledged delivered)))
    (loop
      (multiple-value-bind (message done) (take-next-node-operation-message operation)
        (when done
          (return (values nil t (pending-node-operation-error operation))))
        (let ((acknowledged (slot-value message 'gr8s.node.v1::acknowledged-bytes))
              (data (slot-value message 'gr8s.node.v1::data)))
          (when (plusp acknowledged)
            (bt:with-lock-held ((control-plane-port-forward-lock session))
              (decf (control-plane-port-forward-in-flight session) acknowledged)
              (bt:condition-notify (control-plane-port-forward-window session))))
          (when (plusp (length data))
            (setf (control-plane-port-forward-delivered session) (length data))
            (return (values data nil nil))))))))

(defmethod runtime-cancel-port-forward
    ((runtime control-plane-runtime) (session control-plane-port-forward) reason)
  (let ((operation (control-plane-port-forward-operation session)))
    (ignore-errors
     (cancel-node-operation (control-plane-runtime-node-server runtime) operation reason))
    ;; Whatever the node says now, nothing here waits any longer.
    (finish-node-operation operation :error reason)))

(defmethod runtime-release-port-forward
    ((runtime control-plane-runtime) (session control-plane-port-forward))
  (release-node-operation
   (control-plane-runtime-node-server runtime)
   (control-plane-port-forward-operation session)))

(defun refresh-control-plane-resource-metrics (runtime)
  "Refresh RUNTIME's shared metrics cache from every agent at most once every five seconds.
An older agent's cumulative-container report still feeds HPA, while a current agent's
kubelet summary feeds both HPA and metrics.k8s.io."
  (bt:with-lock-held ((control-plane-runtime-resource-metrics-lock runtime))
    (let ((now (get-universal-time)))
      (when (>= (- now (control-plane-runtime-resource-metrics-at runtime)) 5)
        (let ((summaries nil) (metrics (make-hash-table :test #'equal)))
          (dolist (node (list-nodes (control-plane-runtime-store runtime)))
            (unless (node-record-api-only node)
              (handler-case
                  (let* ((operation
                           (request-node-operation
                            (control-plane-runtime-node-server runtime) (node-record-name node)
                            (make-instance 'gr8s.node.v1::operation-request
                                           :operation-id (generate-uid)
                                           :kind gr8s.node.v1::+operationkind-operation_kind_metrics+)
                            :timeout 5))
                         (report (node-operation-channel-data
                                  operation gr8s.node.v1::+streamchannel-stream_channel_stdout+))
                         (object (and (plusp (length report))
                                      (com.inuoe.jzon:parse
                                       (trivial-utf-8:utf-8-bytes-to-string
                                        (coerce report '(vector (unsigned-byte 8))))))))
                    (when object
                      (if (and (gethash "node" object) (gethash "pods" object))
                          (progn
                            (push object summaries)
                            (maphash (lambda (uid containers) (setf (gethash uid metrics) containers))
                                     (gr8s.apiserver::container-metrics-from-summary object)))
                          (maphash (lambda (uid containers) (setf (gethash uid metrics) containers)) object))))
                (error (condition)
                  (format *error-output* "gr8s resource metrics from ~A: ~A~%"
                          (node-record-name node) condition)))))
          (setf (control-plane-runtime-resource-metrics-summaries runtime)
                (coerce (nreverse summaries) 'vector)
                (control-plane-runtime-container-metrics runtime) metrics
                (control-plane-runtime-resource-metrics-at runtime) now))))
    runtime))

(defmethod runtime-container-metrics ((runtime control-plane-runtime))
  "Return the cached per-container view, refreshing the shared node snapshot when stale."
  (control-plane-runtime-container-metrics (refresh-control-plane-resource-metrics runtime)))

(defmethod runtime-resource-metrics ((runtime control-plane-runtime))
  "Return the cached kubelet summary from every reporting node."
  (control-plane-runtime-resource-metrics-summaries
   (refresh-control-plane-resource-metrics runtime)))

(defmethod runtime-send-exec-session-input
    ((runtime control-plane-runtime) (session control-plane-exec-session)
     channel data &key (rows 0) (columns 0) eof (acknowledged 0))
  (let ((operation (control-plane-exec-session-operation session)))
    ;; The node refuses input out of order, and input and acknowledgements come from two
    ;; threads, so each takes its sequence number and goes out under the lock.
    (bt:with-lock-held ((control-plane-exec-session-lock session))
      (send-node-operation-input
       (control-plane-runtime-node-server runtime) operation
       (make-instance
        'gr8s.node.v1::operation-input
        :operation-id
        (operation-request-id (pending-node-operation-request operation))
        :sequence (incf (control-plane-exec-session-input-sequence session))
        :channel channel :data data
        :rows rows :columns columns :eof eof :acknowledged-bytes acknowledged)))))

(defmethod runtime-next-exec-session-output
    ((runtime control-plane-runtime) (session control-plane-exec-session)
     cursor &key timeout)
  "Return the next output, consuming it: an exec's output can be far too long to hold.
Asking for more means the last output reached the client, so it is acknowledged first."
  (let ((delivered (control-plane-exec-session-delivered session)))
    (when (plusp delivered)
      (setf (control-plane-exec-session-delivered session) 0)
      ;; An older node ignores this: empty input without an end writes nothing. The
      ;; operation may just have ended, and then nobody needs to know.
      (ignore-errors
       (runtime-send-exec-session-input
        runtime session gr8s.node.v1::+streamchannel-stream_channel_stdin+
        (make-array 0 :element-type '(unsigned-byte 8)) :acknowledged delivered))))
  (multiple-value-bind (message done-p)
      (take-next-node-operation-message
       (control-plane-exec-session-operation session) :timeout timeout)
    (if done-p
        (values nil cursor t)
        (progn
          (setf (control-plane-exec-session-delivered session)
                (length (slot-value message 'gr8s.node.v1::data)))
          (values message (1+ cursor) nil)))))

(defmethod runtime-exec-session-exit-code
    ((runtime control-plane-runtime) (session control-plane-exec-session))
  (declare (ignore runtime))
  (let ((operation (control-plane-exec-session-operation session)))
    (when (pending-node-operation-error operation)
      (error 'runtime-error :message (pending-node-operation-error operation)))
    (let ((response (pending-node-operation-response operation)))
      (unless response
        (error 'runtime-error :message "Node exec ended without a response"))
      (slot-value response 'gr8s.node.v1::exit-code))))

(defmethod runtime-cancel-exec-session
    ((runtime control-plane-runtime) (session control-plane-exec-session) reason)
  (cancel-node-operation
   (control-plane-runtime-node-server runtime)
   (control-plane-exec-session-operation session) reason))

(defmethod runtime-release-exec-session
    ((runtime control-plane-runtime) (session control-plane-exec-session))
  (release-node-operation
   (control-plane-runtime-node-server runtime)
   (control-plane-exec-session-operation session)))

(defmethod runtime-forget-pod-finalization ((runtime control-plane-runtime) uid)
  "Withdraw the node's private desired projection only after public finalizers release UID."
  (runtime-delete runtime uid))
