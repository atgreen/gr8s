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
  (gateway-dirty (make-hash-table :test #'equal))
  (gateway-change-sequence 0)
  (gateway-dirty-lock (bt:make-lock "gr8s Gateway committed changes"))
  (resource-metrics-summaries #())
  (container-metrics (make-hash-table :test #'equal))
  (resource-metrics-at 0)
  (resource-metrics-refreshing nil)
  (resource-metrics-refreshed (bt:make-condition-variable :name "control-plane resource metrics"))
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
               (gr8s.resources:stringify-to-utf-8-bytes object))
             (pod-referenced-resource-objects store pod)))))

(defun node-desired-state-snapshot (store node-name &key excluded-uid)
  "Build NODE-NAME's desired-state snapshot from STORE: the service-discovery
   projection and a POD-ASSIGNMENT for each admitted Pod assigned to NODE-NAME,
   skipping EXCLUDED-UID, ordered by namespace/name."
  (multiple-value-bind (discovery dependency-revision) (service-discovery-projection store)
    (make-instance
   'gr8s.node.v1::desired-state-snapshot
   :service-discovery-objects-json discovery
   :gateway-dependency-revision dependency-revision
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
     #'string< :key (lambda (pod) (format nil "~A/~A" (pod-namespace pod) (pod-name pod))))))))

(defun publish-node-snapshot (runtime node-name &key excluded-uid)
  "Build NODE-NAME's desired-state snapshot and publish it to that agent over the
   node server, deduplicating against the last snapshot sent."
  (gr8s.apiserver::call-with-node-publication
   (control-plane-runtime-node-server runtime) node-name
   (lambda ()
    (publish-node-desired-state
   (control-plane-runtime-node-server runtime)
   node-name
   (node-desired-state-snapshot
    (control-plane-runtime-store runtime) node-name
    :excluded-uid excluded-uid)
   :deduplicate t))))

(defun publish-service-discovery-snapshots (runtime)
  "Deliver discovery and advance the two-phase v2 Service publication grant."
  (let ((watermark (gateway-dirty-watermark runtime)))
    (gr8s.apiserver::refresh-cluster-service-risk-grant
     (control-plane-runtime-node-server runtime))
    (dolist (node (list-nodes (control-plane-runtime-store runtime)))
      (publish-node-snapshot runtime (node-record-name node)))
    (clear-gateway-dirty-through runtime watermark)))

(defun control-plane-observation (runtime pod)
  "Build the RUNTIME-POD observation for POD from RUNTIME's store: its observed
   resource version, scheduling phase, status, and all Pod IPs."
  (let* ((store (control-plane-runtime-store runtime))
         (status (pod-observed-status store pod))
         (primary (if status (gethash "podIP" status "") ""))
         (reported (and status (gethash "podIPs" status)))
         (addresses
           (if (and (vectorp reported) (plusp (length reported)))
               (map 'vector (lambda (item) (gethash "ip" item)) reported)
               (if (string= primary "") #() (vector primary)))))
    (make-runtime-pod
     :uid (pod-uid pod)
     :resource-version (pod-observed-resource-version store pod)
     :phase (pod-scheduling-phase store pod)
     :status status :pod-ip primary :pod-ips addresses)))

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
  (let* ((store (control-plane-runtime-store runtime))
         (_ (reconcile-pod-resource-claims store pod))
         (node (schedule-pod store pod)))
    (declare (ignore _))
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

(defparameter *node-log-output-timeout-seconds* 30
  "How long a log read waits for the node's next piece before giving up on it.")

(defmethod runtime-send-logs ((runtime control-plane-runtime) uid container function
                              &key previous tail-lines since (start-offset 0))
  "Ask the Pod's node for the log, a piece at a time, acknowledging each once FUNCTION
has taken it. An older node ignores the selection and sends its whole file, saying
nothing of where its pieces begin: they begin at its start, and what precedes
START-OFFSET is dropped here."
  (let ((pod (control-plane-pod-by-uid runtime uid)))
    (unless (and pod (pod-node-name pod))
      (error 'runtime-error :message "Pod is not assigned to a node"))
    (let* ((request (make-instance
                     'gr8s.node.v1::operation-request
                     :operation-id (generate-uid)
                     :kind gr8s.node.v1::+operationkind-operation_kind_logs+
                     :namespace (pod-namespace pod) :pod (pod-name pod) :pod-uid uid
                     :container container :stdout t :previous (not (null previous))
                     :acknowledges-output t
                     :log-tail (not (null tail-lines)) :log-tail-lines (or tail-lines 0)
                     :log-since-unix-seconds (if since (- since (encode-universal-time 0 0 0 1 1 1970 0)) 0)
                     :log-start-offset start-offset))
           (session (make-control-plane-exec-session
                     (queue-node-operation (control-plane-runtime-node-server runtime) (pod-node-name pod) request)))
           ;; Where the next byte begins in the file, once the node has sent any.
           (position nil)
           (done nil))
      (unwind-protect
           (loop for cursor = 0 then next
                 for (message next finished) = (multiple-value-list
                                                (runtime-next-exec-session-output
                                                 runtime session cursor :timeout *node-log-output-timeout-seconds*))
                 until finished
                 do (let* ((data (slot-value message 'gr8s.node.v1::data))
                           (offset (if (slot-value message 'gr8s.node.v1::log-positioned)
                                       (slot-value message 'gr8s.node.v1::log-offset)
                                       (or position 0)))
                           (skip (if (slot-value message 'gr8s.node.v1::log-positioned)
                                     0
                                     (min (length data) (max 0 (- start-offset offset))))))
                      (setf position (+ offset (length data)))
                      (when (or (slot-value message 'gr8s.node.v1::log-positioned) (< skip (length data)))
                        (funcall function (if (plusp skip) (subseq data skip) data) (+ offset skip))))
                 finally (runtime-exec-session-exit-code runtime session)
                         (setf done t)
                         (return (or position start-offset)))
        (unless done
          (ignore-errors (runtime-cancel-exec-session runtime session "log reader finished")))
        (runtime-release-exec-session runtime session)))))

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

(defun start-control-plane-flows-session (runtime node-name &key follow)
  "Ask NODE-NAME for its recent flow events, and with FOLLOW its new ones, returning an exec
session whose STDOUT carries one JSON object per line."
  (make-control-plane-exec-session
   (queue-node-operation
    (control-plane-runtime-node-server runtime)
    node-name
    (make-instance
     'gr8s.node.v1::operation-request
     :operation-id (generate-uid)
     :kind gr8s.node.v1::+operationkind-operation_kind_flows+
     :flows-follow follow
     :acknowledges-output t))))

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

(defmethod runtime-start-dial ((runtime control-plane-runtime) node-name address port)
  (make-control-plane-port-forward
   (queue-node-operation
    (control-plane-runtime-node-server runtime)
    node-name
    (make-instance
     'gr8s.node.v1::operation-request
     :operation-id (generate-uid)
     :kind gr8s.node.v1::+operationkind-operation_kind_dial+
     :dial-address address
     :port port))))

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

(defun collect-control-plane-resource-metrics (runtime)
  "Ask every agent for its metrics report. Returns (values SUMMARIES CONTAINER-METRICS):
the kubelet summaries of current agents, and the per-container view of every agent --
an older agent's cumulative-container report still feeds HPA. A node that does not
answer costs its whole timeout."
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
                                 (coerce report '(vector (unsigned-byte 8)))))))
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
    (values (coerce (nreverse summaries) 'vector) metrics)))

(defparameter *resource-metrics-wait-seconds* 2
  "How long a reader waits for a metrics collection in flight before it is served
what is already cached.")

(defun refresh-control-plane-resource-metrics (runtime)
  "Bring RUNTIME's shared metrics cache up to date when it is more than five seconds
old, and return RUNTIME. Collection runs on its own thread, one at a time, and a
reader waits for it only briefly: a silent node holds collection for its whole
timeout, and the readers are API requests holding a store lease -- which a
checkpoint must drain before it can proceed -- and the HPA pass (podster-9o6).
A reader that stops waiting is served the previous collection."
  (let ((lock (control-plane-runtime-resource-metrics-lock runtime)))
    (bt:with-lock-held (lock)
      (when (and (not (control-plane-runtime-resource-metrics-refreshing runtime))
                 (>= (- (get-universal-time) (control-plane-runtime-resource-metrics-at runtime)) 5))
        (setf (control-plane-runtime-resource-metrics-refreshing runtime) t)
        (bt:make-thread
         (lambda ()
           (unwind-protect
                (multiple-value-bind (summaries metrics)
                    (collect-control-plane-resource-metrics runtime)
                  (bt:with-lock-held (lock)
                    (setf (control-plane-runtime-resource-metrics-summaries runtime) summaries
                          (control-plane-runtime-container-metrics runtime) metrics
                          ;; Stamped on completion: a collection slowed by a silent
                          ;; node must not be stale the moment it lands.
                          (control-plane-runtime-resource-metrics-at runtime) (get-universal-time))))
             (bt:with-lock-held (lock)
               (setf (control-plane-runtime-resource-metrics-refreshing runtime) nil)
               (sb-thread:condition-broadcast
                (control-plane-runtime-resource-metrics-refreshed runtime)))))
         :name "gr8s resource metrics"))
      (loop with deadline = (+ (get-internal-real-time)
                               (* *resource-metrics-wait-seconds* internal-time-units-per-second))
            while (control-plane-runtime-resource-metrics-refreshing runtime)
            for remaining = (/ (- deadline (get-internal-real-time)) internal-time-units-per-second)
            while (plusp remaining)
            do (bt:condition-wait (control-plane-runtime-resource-metrics-refreshed runtime) lock
                                  :timeout (float remaining 1d0))))
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
