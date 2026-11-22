;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0

(in-package #:gr8s.apiserver)

(defconstant +trace-max-cluster-sessions+ 8)

(defstruct trace-event
  node
  stream
  (data #())
  status
  error)

(defstruct (trace-coordinator
             (:constructor %make-trace-coordinator
                 (server operations duration-milliseconds)))
  server
  operations
  duration-milliseconds
  (events nil)
  (remaining 0)
  (cancelled-p nil)
  (slot-released-p nil)
  (lock (bt:make-lock "gr8s trace coordinator"))
  (changed (bt:make-condition-variable :name "gr8s trace coordinator output")))

(defvar *active-trace-coordinators* 0)
(defvar *active-trace-coordinators-lock*
  (bt:make-lock "gr8s cluster trace session limit"))

(defun trace-requester-name ()
  (if *authenticated-api-identity*
      (api-identity-username *authenticated-api-identity*)
      "system:local-admin"))

(defun audit-trace-session (phase requester namespace selector nodes started-at status)
  "Record trace metadata without recording the potentially sensitive program or output."
  (format *error-output*
          "~&Audit trace ~A requester=~S namespace=~S selector=~S nodes=~S started=~D ended=~D status=~A~%"
          phase requester namespace selector nodes started-at (get-universal-time) status))

(defun trace-api-group ()
  (core-object "apiVersion" "v1" "kind" "APIGroup" "name" "gr8s.io"
               "versions" (vector (core-object "groupVersion" "gr8s.io/v1" "version" "v1"))
               "preferredVersion" (core-object "groupVersion" "gr8s.io/v1" "version" "v1")))

(defun trace-resources-response ()
  (json-response
   (core-object "apiVersion" "v1" "kind" "APIResourceList"
                "groupVersion" "gr8s.io/v1"
                "resources" (vector (core-object "name" "traces" "singularName" "trace"
                                                  "namespaced" t "kind" "Trace"
                                                  "verbs" #("create"))
                                    (core-object "name" "flows" "singularName" "flow"
                                                 "namespaced" t "kind" "Flow"
                                                 "verbs" #("list" "watch"))
                                    (core-object "name" "patchrollouts" "singularName" "patchrollout"
                                                 "namespaced" nil "kind" "PatchRollout"
                                                 "verbs" #("create" "get" "list"))
                                    (core-object "name" "controlplanemembers"
                                                 "singularName" "controlplanemember"
                                                 "namespaced" nil "kind" "ControlPlaneMember"
                                                 "verbs" #("get" "list" "delete"))
                                    (core-object "name" "controlplanemembers/leadership"
                                                 "singularName" ""
                                                 "namespaced" nil "kind" "ControlPlaneMember"
                                                 "verbs" #("create"))))))

(defun release-trace-coordinator-slot (coordinator)
  "Return COORDINATOR's cluster-wide session slot exactly once."
  (let ((release-p nil))
    (bt:with-lock-held ((trace-coordinator-lock coordinator))
      (unless (trace-coordinator-slot-released-p coordinator)
        (setf (trace-coordinator-slot-released-p coordinator) t
              release-p t)))
    (when release-p
      (bt:with-lock-held (*active-trace-coordinators-lock*)
        (decf *active-trace-coordinators*))))
  coordinator)

(defun invalid-trace-request (control &rest arguments)
  (error 'kubernetes-error :status-code 422 :reason "Invalid"
         :message (apply #'format nil control arguments)))

(defun parse-trace-request-frame (payload)
  "Parse and validate the first trace WebSocket frame into a request plist."
  (when (> (length payload) (+ (* 64 1024) 4096))
    (invalid-trace-request "Trace request frame is too large"))
  (let* ((object
           (handler-case
               (com.inuoe.jzon:parse payload)
             (error (condition)
               (invalid-trace-request "Invalid trace request JSON: ~A" condition))))
         (source (and (hash-table-p object) (gethash "source" object)))
         (selector (and (hash-table-p object) (gethash "selector" object)))
         (duration (and (hash-table-p object)
                        (gethash "durationMilliseconds" object 30000))))
    (unless (and (stringp source) (plusp (length source)))
      (invalid-trace-request "source is required"))
    (when (> (length (babel:string-to-octets source :encoding :utf-8)) (* 64 1024))
      (invalid-trace-request "source exceeds 65536 UTF-8 bytes"))
    (unless (stringp selector)
      (invalid-trace-request "selector must be a string"))
    ;; Compile it now so malformed selectors fail before any node operation starts.
    (core-selector-predicate selector)
    (unless (and (integerp duration) (plusp duration) (<= duration 300000))
      (invalid-trace-request "durationMilliseconds must be between 1 and 300000"))
    (list :source source :selector selector :duration-milliseconds duration)))

(defun running-pod-p (pod)
  (and (pod-node-name pod)
       (let ((status (gethash "status" (pod-object pod))))
         (or (null status)
             (member (gethash "phase" status) '(nil "Running") :test #'equal)))))

(defun trace-node-groups (store namespace selector)
  "Return sorted (node-name . Pod-UID-list) groups selected for a trace."
  (let ((matches (core-selector-predicate selector))
        (groups (make-hash-table :test #'equal)))
    (dolist (pod (list-pods store namespace))
      (when (and (running-pod-p pod)
                 (funcall matches (pod-to-object pod)))
        (push (pod-uid pod) (gethash (pod-node-name pod) groups))))
    (sort
     (loop for node being the hash-keys of groups using (hash-value uids)
           collect (cons node (sort (remove-duplicates uids :test #'equal) #'string<)))
     #'string< :key #'car)))

(defun make-trace-operation-request (source pod-uids duration-milliseconds node index)
  (make-instance
   'gr8s.node.v1::operation-request
   ;; A CSPRNG id, not cl:random: an operation id must be unguessable so another
   ;; node cannot forge a response/stream against it.
   :operation-id (format nil "trace-~36R-~D-~A"
                         (reduce (lambda (acc byte) (+ (ash acc 8) byte))
                                 (secure-random-octets 16) :initial-value 0)
                         index node)
   :kind gr8s.node.v1::+operationkind-operation_kind_trace+
   :trace-source source
   :trace-pod-uids pod-uids
   :trace-duration-milliseconds duration-milliseconds
   :acknowledges-output t))

(defun push-trace-event (coordinator event)
  (bt:with-lock-held ((trace-coordinator-lock coordinator))
    (setf (trace-coordinator-events coordinator)
          (nconc (trace-coordinator-events coordinator) (list event)))
    (bt:condition-notify (trace-coordinator-changed coordinator))))

(defun finish-trace-node (coordinator operation node)
  (let ((error nil) (status :complete))
    (bt:with-lock-held ((pending-node-operation-lock operation))
      (setf error (pending-node-operation-error operation))
      (when error (setf status :failed)))
    (push-trace-event coordinator
                      (make-trace-event :node node :status status :error error))
    (release-node-operation (trace-coordinator-server coordinator) operation)
    (bt:with-lock-held ((trace-coordinator-lock coordinator))
      (decf (trace-coordinator-remaining coordinator))
      (bt:condition-notify (trace-coordinator-changed coordinator)))
    (when (zerop (trace-coordinator-remaining coordinator))
      (release-trace-coordinator-slot coordinator))))

(defun drain-trace-node (coordinator node operation)
  (handler-case
      (loop
        (multiple-value-bind (message done-p)
            (take-next-node-operation-message
             operation :timeout (+ 5 (/ (trace-coordinator-duration-milliseconds coordinator)
                                         1000.0)))
          (when done-p (return))
          (push-trace-event
           coordinator
           (make-trace-event
            :node node
            :stream (case (slot-value message 'gr8s.node.v1::channel)
                      (#.gr8s.node.v1::+streamchannel-stream_channel_stderr+ :stderr)
                      (otherwise :stdout))
            :data (slot-value message 'gr8s.node.v1::data)))
          (handler-case
              (send-node-operation-input
               (trace-coordinator-server coordinator) operation
               (make-instance
                'gr8s.node.v1::operation-input
                :operation-id (operation-request-id
                               (pending-node-operation-request operation))
                :sequence (slot-value message 'gr8s.node.v1::proto-sequence)
                :channel (slot-value message 'gr8s.node.v1::channel)
                :acknowledged-bytes
                (length (slot-value message 'gr8s.node.v1::data))))
            (error () nil))))
    (error (condition)
      (finish-node-operation operation :error (princ-to-string condition))))
  (finish-trace-node coordinator operation node))

(defun start-trace-coordinator
    (server store namespace selector source duration-milliseconds)
  "Select Pods, start one HA-routed node trace per node, and return its coordinator."
  (let ((groups (trace-node-groups store namespace selector)))
    (unless groups
      (error 'runtime-error :message "The trace selector matched no running scheduled Pods"))
    (bt:with-lock-held (*active-trace-coordinators-lock*)
      (when (>= *active-trace-coordinators* +trace-max-cluster-sessions+)
        (error 'runtime-error :message "The cluster trace session limit has been reached"))
      (incf *active-trace-coordinators*))
    (let ((operations nil))
      (handler-case
        (let* ((operations
                 (loop for (node . uids) in groups for index from 0
                       do (push (cons node
                                      (queue-node-operation
                                       server node
                                       (make-trace-operation-request
                                        source uids duration-milliseconds node index)))
                                operations)
                       finally (return (nreverse operations))))
               (coordinator
                 (%make-trace-coordinator server operations duration-milliseconds)))
          (setf (trace-coordinator-remaining coordinator) (length operations))
          (dolist (entry operations)
            (bt:make-thread
             (lambda () (drain-trace-node coordinator (car entry) (cdr entry)))
             :name (format nil "gr8s trace fan-in ~A" (car entry))))
          coordinator)
          (error (condition)
            (dolist (entry operations)
              (ignore-errors
                (cancel-node-operation server (cdr entry)
                                       "Trace fan-out did not start"))
              (ignore-errors (release-node-operation server (cdr entry))))
            (bt:with-lock-held (*active-trace-coordinators-lock*)
              (decf *active-trace-coordinators*))
            (error condition))))))

(defun next-trace-event (coordinator &key timeout)
  "Return the next TRACE-EVENT, or NIL after every node has terminated."
  (let ((deadline (and timeout (+ (get-internal-real-time)
                                  (* timeout internal-time-units-per-second)))))
    (bt:with-lock-held ((trace-coordinator-lock coordinator))
      (loop
        (when (trace-coordinator-events coordinator)
          (return (pop (trace-coordinator-events coordinator))))
        (when (zerop (trace-coordinator-remaining coordinator))
          (return nil))
        (if deadline
            (let ((remaining (/ (- deadline (get-internal-real-time))
                                internal-time-units-per-second)))
              (when (<= remaining 0)
                (error 'runtime-error :message "Timed out waiting for trace output"))
              (bt:condition-wait (trace-coordinator-changed coordinator)
                                 (trace-coordinator-lock coordinator)
                                 :timeout remaining))
            (bt:condition-wait (trace-coordinator-changed coordinator)
                               (trace-coordinator-lock coordinator)))))))

(defun cancel-trace-coordinator (coordinator reason)
  "Cancel every unfinished child operation. Safe to call more than once."
  (unless (trace-coordinator-cancelled-p coordinator)
    (setf (trace-coordinator-cancelled-p coordinator) t)
    (dolist (entry (trace-coordinator-operations coordinator))
      (unless (pending-node-operation-done-p (cdr entry))
        (handler-case
            (cancel-node-operation (trace-coordinator-server coordinator)
                                   (cdr entry) reason)
          (error (condition)
            (finish-node-operation (cdr entry) :error (princ-to-string condition)))))))
  coordinator)

(defun trace-event-object (event)
  (let ((object (core-object "node" (trace-event-node event))))
    (when (trace-event-stream event)
      (setf (gethash "stream" object) (string-downcase (trace-event-stream event))
            (gethash "data" object)
            (trivial-utf-8:utf-8-bytes-to-string (trace-event-data event))))
    (when (trace-event-status event)
      (setf (gethash "status" object) (string-downcase (trace-event-status event))))
    (when (trace-event-error event)
      (setf (gethash "error" object) (trace-event-error event)))
    object))

(defun trace-json-bytes (object)
  (trivial-utf-8:string-to-utf-8-bytes
   (with-output-to-string (stream)
     (com.inuoe.jzon:stringify object :stream stream))))

(defun begin-trace-websocket ()
  (let ((key (hunchentoot:header-in* :sec-websocket-key)))
    (unless (and key (plusp (length key)))
      (bad-exec-request "Trace requires Sec-WebSocket-Key"))
    (setf (hunchentoot:return-code*) 101
          (hunchentoot:content-type*) nil
          (hunchentoot:header-out :connection) "Upgrade"
          (hunchentoot:header-out :upgrade) "websocket"
          (hunchentoot:header-out :sec-websocket-accept) (websocket-accept-value key)
          (hunchentoot:header-out :sec-websocket-protocol) "gr8s.trace.v1")
    (let ((stream (hunchentoot::start-output 101 nil)))
      (finish-output stream)
      (extend-api-connection-idle-timeout 360)
      stream)))

(defun read-trace-request (stream)
  (multiple-value-bind (opcode payload fin-p masked-p)
      (read-websocket-frame stream)
    (unless (and fin-p masked-p (member opcode '(1 2)))
      (invalid-trace-request "The first trace frame must be one masked text or binary frame"))
    (parse-trace-request-frame payload)))

(defun forward-trace-control (coordinator stream write-lock finished-p)
  (handler-case
      (with-exec-input-reader-stop
        (loop until (funcall finished-p)
              do (multiple-value-bind (opcode payload fin-p masked-p)
                     (read-websocket-frame stream)
                   (declare (ignore fin-p))
                   (unless masked-p
                     (error 'runtime-error :message "WebSocket client frames must be masked"))
                   (case opcode
                     (8 (cancel-trace-coordinator coordinator "Trace client disconnected")
                        (return))
                     (9 (bt:with-lock-held (write-lock)
                          (write-websocket-frame stream 10 payload)))
                     (10)
                     (otherwise
                      (error 'runtime-error :message "Trace accepts no frames after its request"))))))
    (error (condition)
      (unless (funcall finished-p)
        (cancel-trace-coordinator coordinator (princ-to-string condition))))))

(defun serve-trace-websocket (store reconciler namespace)
  "Run one authenticated, namespaced fan-out trace over a WebSocket."
  (unless (upgrade-request-p)
    (bad-exec-request "Trace requires an upgraded connection"))
  (let* ((runtime (reconciler-runtime reconciler)))
    (unless (typep runtime 'control-plane-runtime)
      (error 'runtime-error :message "Cluster traces require a control-plane runtime"))
    (let* ((client (begin-trace-websocket))
           (request (read-trace-request client))
           (coordinator (start-trace-coordinator
                         (gr8s.controllers::control-plane-runtime-node-server runtime) store namespace
                         (getf request :selector) (getf request :source)
                         (getf request :duration-milliseconds)))
           (write-lock (bt:make-lock "gr8s trace websocket writer"))
           (finished-lock (bt:make-lock "gr8s trace websocket finished"))
           (finished-p nil)
           (normal-completion-p nil)
           (input-thread nil)
           (complete 0)
           (failed 0)
           (requester (trace-requester-name))
           (started-at (get-universal-time))
           (nodes (mapcar #'car (trace-coordinator-operations coordinator))))
      (audit-trace-session :started requester namespace (getf request :selector)
                           nodes started-at :running)
      ;; The trace runs for its whole duration; the store was only needed to start it.
      (gr8s.store::release-store-request)
      (labels ((finished-p () (bt:with-lock-held (finished-lock) finished-p))
               (mark-finished () (bt:with-lock-held (finished-lock) (setf finished-p t))))
        (unwind-protect
             (progn
               (setf input-thread
                     (bt:make-thread
                      (lambda () (forward-trace-control coordinator client write-lock #'finished-p))
                      :name "gr8s trace websocket control"))
               (loop for event = (next-trace-event coordinator)
                     while event
                     do (case (trace-event-status event)
                          (:complete (incf complete))
                          (:failed (incf failed)))
                        (bt:with-lock-held (write-lock)
                          (write-websocket-frame client 1
                                                 (trace-json-bytes (trace-event-object event)))))
               (bt:with-lock-held (write-lock)
                 (write-websocket-frame
                  client 1 (trace-json-bytes
                            (core-object "status" "complete" "completedNodes" complete
                                         "failedNodes" failed)))
                 (write-websocket-frame client 8
                                        (make-array 2 :element-type '(unsigned-byte 8)
                                                      :initial-contents '(3 232))))
               (setf normal-completion-p t)
               (mark-finished))
          (mark-finished)
          (cancel-trace-coordinator coordinator "Trace API stream ended")
          (when input-thread (stop-exec-input-reader input-thread))
          (when input-thread (ignore-errors (bt:join-thread input-thread)))
          (audit-trace-session :ended requester namespace (getf request :selector)
                               nodes started-at
                               (cond ((plusp failed) :failed)
                                     (normal-completion-p :complete)
                                     (t :disconnected))))))))
