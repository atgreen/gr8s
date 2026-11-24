;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Expose an explicitly authorized, lifetime-bound Slynk byte tunnel to one
;;;; exact node agent or one exact HA control-plane member.

(in-package #:gr8s.apiserver)

(defparameter +slynk-websocket-protocol+ "gr8s.slynk.v1")

(defstruct member-slynk-operation
  id session socket stream emit
  (sequence 0)
  (unacknowledged-output 0)
  (input nil)
  (finished-p nil)
  writer
  (lock (bt:make-lock "gr8s member Slynk operation"))
  (changed (bt:make-condition-variable :name "gr8s member Slynk input"))
  (output-window (bt:make-condition-variable :name "gr8s member Slynk output window")))

(defvar *member-slynk-operations* (make-hash-table :test #'equal))
(defvar *member-slynk-operations-lock* (bt:make-lock "gr8s member Slynk operations"))

(defun finish-member-slynk-operation (operation &key error)
  (let ((finish-p nil))
    (bt:with-lock-held ((member-slynk-operation-lock operation))
      (unless (member-slynk-operation-finished-p operation)
        (setf (member-slynk-operation-finished-p operation) t finish-p t)))
    (when finish-p
      (bt:with-lock-held (*member-slynk-operations-lock*)
        (remhash (member-slynk-operation-id operation) *member-slynk-operations*))
      (ignore-errors (usocket:socket-shutdown (member-slynk-operation-socket operation) :io))
      (ignore-errors (usocket:socket-close (member-slynk-operation-socket operation)))
      (bt:condition-notify (member-slynk-operation-changed operation))
      (bt:condition-notify (member-slynk-operation-output-window operation))
      (stop-on-demand-debug-session (member-slynk-operation-session operation))
      (funcall (member-slynk-operation-emit operation) :operation-response
               (make-instance 'gr8s.node.v1::operation-response
                              :operation-id (member-slynk-operation-id operation)
                              :status (if error
                                          gr8s.node.v1::+operationstatus-operation_status_failed+
                                          gr8s.node.v1::+operationstatus-operation_status_complete+)
                              :exit-code (if error 1 0) :error-message (or error ""))))))

(defun run-member-slynk-reader (operation)
  (let ((buffer (make-array 65536 :element-type '(unsigned-byte 8)))
        (fd (sb-bsd-sockets:socket-file-descriptor
             (usocket::socket (member-slynk-operation-socket operation)))))
    (handler-case
        (loop for count = (sb-sys:with-pinned-objects (buffer)
                            (or (sb-unix:unix-read fd (sb-sys:vector-sap buffer) (length buffer)) 0))
              while (plusp count)
              do (progn
                   (bt:with-lock-held ((member-slynk-operation-lock operation))
                     (loop while (and (>= (member-slynk-operation-unacknowledged-output operation)
                                           gr8s.runtime::+exec-output-window-bytes+)
                                      (not (member-slynk-operation-finished-p operation)))
                           do (bt:condition-wait (member-slynk-operation-output-window operation)
                                                 (member-slynk-operation-lock operation) :timeout 0.2))
                     (when (member-slynk-operation-finished-p operation)
                       (return))
                     (incf (member-slynk-operation-unacknowledged-output operation) count))
                   (let ((sequence
                         (bt:with-lock-held ((member-slynk-operation-lock operation))
                           (incf (member-slynk-operation-sequence operation)))))
                   (funcall (member-slynk-operation-emit operation) :operation-stream
                            (make-instance 'gr8s.node.v1::operation-stream
                                           :operation-id (member-slynk-operation-id operation)
                                           :sequence sequence
                                           :channel gr8s.node.v1::+streamchannel-stream_channel_stdout+
                                           :data (subseq buffer 0 count)))))
              finally (finish-member-slynk-operation operation))
      (error (condition)
        (finish-member-slynk-operation operation :error (princ-to-string condition))))))

(defparameter *member-slynk-origin-probe-seconds* 10
  "How often a member's Slynk operation asks the member that started it whether it still
holds it. That member may restart, or give the operation up when a relay fails, and no
cancel comes then; three asks it doesn't take end the operation, which frees this
process's one Slynk session for the next client.")

(defun member-slynk-origin-holds-p (operation)
  "Whether the member that started OPERATION still holds it: that member takes an empty
output frame, which shows its client nothing, only while it does."
  (ignore-errors
   (funcall (member-slynk-operation-emit operation) :operation-stream
            (make-instance 'gr8s.node.v1::operation-stream
                           :operation-id (member-slynk-operation-id operation)
                           :channel gr8s.node.v1::+streamchannel-stream_channel_stdout+))))

(defun run-member-slynk-writer (operation)
  "Write queued client input without blocking the member mTLS relay handler, and end
OPERATION once the member that started it no longer holds it."
  (handler-case
      (let ((misses 0) (probe-at 0))
        (flet ((next-probe ()
                 (setf probe-at (+ (get-internal-real-time)
                                   (* *member-slynk-origin-probe-seconds* internal-time-units-per-second)))))
          (next-probe)
          (loop
            (multiple-value-bind (entry finished-p)
                (bt:with-lock-held ((member-slynk-operation-lock operation))
                  (loop until (or (member-slynk-operation-input operation)
                                  (member-slynk-operation-finished-p operation)
                                  (>= (get-internal-real-time) probe-at))
                        do (bt:condition-wait (member-slynk-operation-changed operation)
                                              (member-slynk-operation-lock operation) :timeout 0.2))
                  (values (pop (member-slynk-operation-input operation))
                          (member-slynk-operation-finished-p operation)))
              (cond
                (entry
                 (destructuring-bind (data . eof) entry
                   (when (plusp (length data))
                     (write-sequence data (member-slynk-operation-stream operation))
                     (finish-output (member-slynk-operation-stream operation)))
                   (when eof
                     (ignore-errors (usocket:socket-shutdown
                                     (member-slynk-operation-socket operation) :output))
                     (return))))
                (finished-p (return))
                (t
                 (next-probe)
                 (if (member-slynk-origin-holds-p operation)
                     (setf misses 0)
                     (when (>= (incf misses) 3)
                       (finish-member-slynk-operation
                        operation :error "the member that started this Slynk session no longer holds it")
                       (return)))))))))
    (error (condition)
      (finish-member-slynk-operation operation :error (princ-to-string condition)))))

(defun dispatch-member-slynk-operation (state-directory store reconciler origin variant payload emit-router)
  "Handle one member-mTLS operation frame in the selected control-plane process."
  (declare (ignore origin))
  (let ((id (slot-value payload 'gr8s.node.v1::operation-id)))
    (case variant
      (:operation-request
       (unless (= (slot-value payload 'gr8s.node.v1::kind)
                  gr8s.node.v1::+operationkind-operation_kind_slynk+)
         (return-from dispatch-member-slynk-operation nil))
       (let ((session (start-on-demand-debug-session state-directory :store store :reconciler reconciler)))
         (handler-case
             (multiple-value-bind (stream socket) (open-on-demand-debug-stream session)
               (let ((operation (make-member-slynk-operation
                                 :id id :session session :socket socket :stream stream
                                 :emit emit-router)))
                 (bt:with-lock-held (*member-slynk-operations-lock*)
                   (when (gethash id *member-slynk-operations*) (error "member debug operation exists"))
                   (setf (gethash id *member-slynk-operations*) operation))
                 (funcall emit-router :operation-response
                          (make-instance 'gr8s.node.v1::operation-response
                                         :operation-id id
                                         :status gr8s.node.v1::+operationstatus-operation_status_accepted+))
                 (bt:make-thread (lambda () (run-member-slynk-reader operation))
                                 :name "gr8s member Slynk relay reader")
                 (setf (member-slynk-operation-writer operation)
                       (bt:make-thread (lambda () (run-member-slynk-writer operation))
                                       :name "gr8s member Slynk relay writer"))
                 t))
           (error (condition)
             (stop-on-demand-debug-session session)
             (error condition)))))
      (:operation-input
       (let ((operation (bt:with-lock-held (*member-slynk-operations-lock*)
                          (gethash id *member-slynk-operations*))))
         (when operation
           (let ((data (slot-value payload 'gr8s.node.v1::data))
                 (eof (slot-value payload 'gr8s.node.v1::eof))
                 (acknowledged (slot-value payload 'gr8s.node.v1::acknowledged-bytes)))
             (bt:with-lock-held ((member-slynk-operation-lock operation))
               (when (plusp acknowledged)
                 (setf (member-slynk-operation-unacknowledged-output operation)
                       (max 0 (- (member-slynk-operation-unacknowledged-output operation)
                                 acknowledged)))
                 (bt:condition-notify (member-slynk-operation-output-window operation)))
               (when (or eof (plusp (length data)))
                 (setf (member-slynk-operation-input operation)
                       (nconc (member-slynk-operation-input operation)
                              (list (cons data eof))))
                 (bt:condition-notify (member-slynk-operation-changed operation)))))
           t)))
      (:operation-cancel
       (let ((operation (bt:with-lock-held (*member-slynk-operations-lock*)
                          (gethash id *member-slynk-operations*))))
         (when operation
           (finish-member-slynk-operation operation :error "Slynk client disconnected")
           t)))
      (otherwise nil))))

(defun install-member-slynk-handler (node-server state-directory store reconciler)
  "Install this process's authenticated member-operation endpoint."
  (setf (node-grpc-server-member-operation-handler node-server)
        (lambda (origin variant payload)
          (let ((router (node-grpc-server-operation-router node-server)))
            (dispatch-member-slynk-operation
             state-directory store reconciler origin variant payload
             (lambda (reply-variant reply)
               (funcall router reply-variant origin "@control-plane/reply" reply))))))
  node-server)

(defun validate-slynk-websocket-request ()
  (unless (upgrade-request-p)
    (bad-exec-request "Slynk debugging requires a WebSocket upgrade"))
  (let ((key (hunchentoot:header-in* :sec-websocket-key))
        (offered (hunchentoot:header-in* :sec-websocket-protocol)))
    (unless (and key offered
                 (member +slynk-websocket-protocol+
                         (mapcar (lambda (value) (string-trim " " value))
                                 (uiop:split-string offered :separator '(#\,)))
                         :test #'equal))
      (bad-exec-request "Slynk debugging requires protocol gr8s.slynk.v1"))
    key))

(defun begin-slynk-websocket ()
  (let ((key (validate-slynk-websocket-request)))
    (setf (hunchentoot:return-code*) 101
          (hunchentoot:content-type*) nil
          (hunchentoot:header-out :connection) "Upgrade"
          (hunchentoot:header-out :upgrade) "websocket"
          (hunchentoot:header-out :sec-websocket-accept) (websocket-accept-value key)
          (hunchentoot:header-out :sec-websocket-protocol) +slynk-websocket-protocol+)
    (let ((stream (hunchentoot::start-output 101 nil)))
      (finish-output stream)
      (extend-api-connection-idle-timeout)
      stream)))

(defun start-node-slynk-tunnel (runtime node-name)
  (unless (typep runtime 'gr8s.controllers::control-plane-runtime)
    (core-resource-error 503 "ServiceUnavailable" "node operation routing is unavailable"))
  (gr8s.controllers::make-control-plane-port-forward
   (queue-node-operation
    (gr8s.controllers::control-plane-runtime-node-server runtime) node-name
    (make-instance 'gr8s.node.v1::operation-request
                   :operation-id (generate-uid)
                   :kind gr8s.node.v1::+operationkind-operation_kind_slynk+))))

(defun start-member-slynk-tunnel (runtime member-id)
  (gr8s.controllers::make-control-plane-port-forward
   (queue-member-operation
    (gr8s.controllers::control-plane-runtime-node-server runtime) member-id
    (make-instance 'gr8s.node.v1::operation-request
                   :operation-id (generate-uid)
                   :kind gr8s.node.v1::+operationkind-operation_kind_slynk+))))

(defun forward-websocket-to-node-slynk (runtime session client finished-p)
  (handler-case
      (loop until (funcall finished-p)
            do (multiple-value-bind (opcode payload fin-p masked-p)
                   (read-websocket-frame client)
                 (unless (and fin-p masked-p)
                   (error "Slynk WebSocket frames must be complete and masked"))
                 (case opcode
                   (2 (runtime-port-forward-send runtime session payload))
                   (8 (return))
                   (9 (write-websocket-frame client 10 payload))
                   (10)
                   (otherwise (error "Slynk accepts only binary WebSocket frames")))))
    (error () nil)))

(defun serve-operation-slynk-websocket (runtime session)
  (let* (
         (client (begin-slynk-websocket))
         (finished nil)
         (lock (bt:make-lock "gr8s node Slynk websocket"))
         (input nil))
    (labels ((finished-p () (bt:with-lock-held (lock) finished))
             (finish-it () (bt:with-lock-held (lock) (setf finished t))))
      (unwind-protect
           (progn
             (setf input (bt:make-thread
                          (lambda ()
                            (unwind-protect
                                 (forward-websocket-to-node-slynk
                                  runtime session client #'finished-p)
                              ;; EOF, a close frame, or a malformed frame on
                              ;; the client side must wake NEXT and tear down
                              ;; the remote operation. Otherwise its Slynk
                              ;; session remains owned forever.
                              (unless (finished-p)
                                (finish-it)
                                (runtime-cancel-port-forward
                                 runtime session "Slynk client disconnected"))))
                          :name "gr8s node Slynk websocket input"))
             (loop
               (multiple-value-bind (data done error)
                   (runtime-port-forward-next runtime session)
                 (when error (error 'runtime-error :message error))
                 (when done (return))
                 (when data (write-websocket-frame client 2 data))))
             (write-websocket-frame client 8
                                    (make-array 2 :element-type '(unsigned-byte 8)
                                                  :initial-contents '(3 232))))
        (finish-it)
        (runtime-cancel-port-forward runtime session "Slynk client disconnected")
        (when input (stop-exec-input-reader input))
        (when input (ignore-errors (bt:join-thread input)))
        (runtime-release-port-forward runtime session)))))

(defun serve-node-slynk-websocket (runtime node-name)
  (validate-slynk-websocket-request)
  (serve-operation-slynk-websocket runtime (start-node-slynk-tunnel runtime node-name)))

(defun serve-member-slynk-websocket (runtime member-id)
  (validate-slynk-websocket-request)
  (serve-operation-slynk-websocket
   runtime (handler-case (start-member-slynk-tunnel runtime member-id)
             (runtime-error (condition)
               (core-resource-error 503 "ServiceUnavailable" "~A" condition)))))

(defun relay-local-slynk-output (socket client)
  (let ((buffer (make-array 65536 :element-type '(unsigned-byte 8)))
        (fd (sb-bsd-sockets:socket-file-descriptor (usocket::socket socket))))
    (loop for count = (sb-sys:with-pinned-objects (buffer)
                        (or (sb-unix:unix-read fd (sb-sys:vector-sap buffer) (length buffer)) 0))
          while (plusp count)
          do (write-websocket-frame client 2 (subseq buffer 0 count)))))

(defun serve-local-slynk-websocket (state-directory store reconciler)
  (let ((session (start-on-demand-debug-session state-directory :store store :reconciler reconciler))
        (socket nil))
    (unwind-protect
         (multiple-value-bind (remote-stream remote-socket) (open-on-demand-debug-stream session)
           (setf socket remote-socket)
           (let* ((client (begin-slynk-websocket))
                  (input (bt:make-thread
                          (lambda ()
                            (unwind-protect
                                 (handler-case
                                     (loop
                                       (multiple-value-bind (opcode payload fin-p masked-p)
                                           (read-websocket-frame client)
                                         (unless (and fin-p masked-p) (error "invalid WebSocket frame"))
                                         (case opcode
                                           (2 (write-sequence payload remote-stream)
                                              (finish-output remote-stream))
                                           (8 (return))
                                           (9 (write-websocket-frame client 10 payload)))))
                                   (error () nil))
                              ;; Wake RELAY-LOCAL-SLYNK-OUTPUT on every client
                              ;; termination path so its unwind cleanup runs.
                              (ignore-errors
                               (usocket:socket-shutdown remote-socket :io))))
                          :name "gr8s member Slynk websocket input")))
             (unwind-protect (relay-local-slynk-output remote-socket client)
               (ignore-errors (usocket:socket-shutdown remote-socket :io))
               (stop-exec-input-reader input)
               (ignore-errors (bt:join-thread input)))))
      (when socket (ignore-errors (usocket:socket-close socket)))
      (stop-on-demand-debug-session session))))

(defun serve-slynk-websocket (store runtime reconciler path)
  "Authorize and serve the exact target encoded by PATH."
  (unless *authenticated-api-identity*
    (core-resource-error 403 "Forbidden" "Slynk debugging requires authenticated Kubernetes API access"))
  (let* ((parts (remove "" (uiop:split-string path :separator '(#\/)) :test #'equal))
         (kind (fourth parts))
         (name (fifth parts))
         (acceptor (hunchentoot:request-acceptor hunchentoot:*request*)))
    (unless (path-segment-name-p name)
      (core-resource-error 400 "BadRequest" "invalid Slynk debug target"))
    ;; Reject a malformed upgrade before allocating a process-local or remote
    ;; debugger session.
    (validate-slynk-websocket-request)
    (cond
      ((equal kind "nodes") (serve-node-slynk-websocket runtime name))
      ((equal kind "controlplanemembers")
       (let ((resolver (acceptor-debug-member-resolver acceptor)))
         (unless resolver
           (core-resource-error 404 "NotFound" "this cluster has no HA control-plane members"))
         (multiple-value-bind (local-p api-url exists-p) (funcall resolver name)
           (declare (ignore api-url))
           (unless exists-p (core-resource-error 404 "NotFound" "control-plane member ~A was not found" name))
           (if local-p
               (handler-case
                   (serve-local-slynk-websocket
                    (acceptor-debug-state-directory acceptor) store reconciler)
                 (debug-session-conflict ()
                   (core-resource-error 409 "Conflict"
                                        "this control-plane member already has an active Slynk session")))
               (serve-member-slynk-websocket runtime name)))))
      (t (core-resource-error 404 "NotFound" "unknown Slynk target kind")))))
