;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; The node-session protocol: the long-lived bidirectional gRPC stream between
;;;; the control plane and each node agent, both ends of it in one file.
;;;;
;;;; The control-plane side (NODE-GRPC-SERVER) accepts an agent's Connect stream,
;;;; authenticates the peer, and keeps that node converged on a desired-state
;;;; SNAPSHOT: a revision-numbered projection of the node's Pods, overlay topology
;;;; and service discovery. Snapshots carry a monotonic revision; the server may
;;;; send a DELTA against what a session last delivered (podster-uqb.139), so a
;;;; delta is computed under the session's send lock and never reordered ahead of
;;;; its base. The same stream relays node operations (exec/attach-style
;;;; request/input/cancel/stream/response), carries agent heartbeats that renew
;;;; the node lease, and enrolls new nodes (CSR signing + Pod-CIDR allocation).
;;;;
;;;; The agent side (AGENT-NODE-SESSION) dials the control plane -- rotating over
;;;; the HA members on reconnect (podster-c2d.7.4) -- applies each snapshot in
;;;; revision order on a dedicated worker, and persists lastAppliedRevision BEFORE
;;;; acking so a crash never claims work it did not persist. Two invariants are
;;;; load-bearing and easy to break:
;;;;
;;;;   * Revision monotonicity across restarts. A restarted control plane rebuilds
;;;;     revisions from durable state (PREPARE-NODE-CONNECT-SNAPSHOT bumps past both
;;;;     the agent's last-applied and the in-memory counter) so it can never strand
;;;;     an agent ahead of its new server.
;;;;   * Cooperative thread wakeups. Closing a socket does not reliably wake a
;;;;     thread blocked in poll(2) or a flow-controlled send, so the session's
;;;;     helper threads (heartbeat monitor, status reporter, watchdog, outbox) are
;;;;     unwound by a THROW to a catch tag, and the reading/owner thread never sends
;;;;     directly -- it hands sends to the outbox so it alone reads frames.

(in-package #:gr8s)

(defstruct (node-grpc-server
             (:constructor %make-node-grpc-server
                 (&key store grpc-server thread port heartbeat-timeout-seconds
                       pki cluster-pod-cidr node-prefix)))
  store
  grpc-server
  thread
  port
  heartbeat-timeout-seconds
  pki
  cluster-pod-cidr
  node-prefix
  (revisions (make-hash-table :test #'equal))
  (snapshots (make-hash-table :test #'equal))
  (statuses (make-hash-table :test #'equal))
  (acknowledged-revisions (make-hash-table :test #'equal))
  (operations (make-hash-table :test #'equal))
  (operation-queues (make-hash-table :test #'equal))
  (sessions (make-hash-table :test #'equal))
  ;; (VARIANT TARGET-MEMBER NODE-NAME PAYLOAD) -> accepting member id or NIL.
  ;; HA installs this peer relay; single-node servers leave it NIL.
  operation-router
  (lock (bt:make-lock "gr8s node sessions"))
  monitor-thread
  (stopping-p nil))

(defstruct (node-agent-session
             (:constructor make-node-agent-session (stream)))
  stream
  (lock (bt:make-lock "gr8s node agent session"))
  (last-envelope-time (get-universal-time))
  (evicted-p nil)
  ;; Whether the agent applies desired-state deltas, and the last snapshot this
  ;; session delivered, which the next delta changes (podster-uqb.139).
  deltas-p
  delivered)

(defparameter +desired-state-delta-capability+ "desired-state-delta"
  "The NodeHello capability of an agent that rebuilds snapshots from deltas.")

(defun same-pod-assignment-p (left right)
  "Return whether two PodAssignments deliver the same desired Pod and objects."
  (and (string= (slot-value left 'gr8s.node.v1::uid) (slot-value right 'gr8s.node.v1::uid))
       (string= (slot-value left 'gr8s.node.v1::resource-version)
                (slot-value right 'gr8s.node.v1::resource-version))
       (string= (slot-value left 'gr8s.node.v1::namespace) (slot-value right 'gr8s.node.v1::namespace))
       (string= (slot-value left 'gr8s.node.v1::name) (slot-value right 'gr8s.node.v1::name))
       (eq (not (slot-value left 'gr8s.node.v1::deleting)) (not (slot-value right 'gr8s.node.v1::deleting)))
       (equalp (slot-value left 'gr8s.node.v1::pod-json) (slot-value right 'gr8s.node.v1::pod-json))
       (equalp (slot-value left 'gr8s.node.v1::resource-objects-json)
               (slot-value right 'gr8s.node.v1::resource-objects-json))))

(defun node-snapshot-delta (base snapshot)
  "Return a delta that turns BASE, the last snapshot a session delivered, into SNAPSHOT."
  (let ((base-pods (make-hash-table :test #'equal))
        (current (make-hash-table :test #'equal))
        (service-discovery-changed
          (not (equalp (slot-value base 'gr8s.node.v1::service-discovery-objects-json)
                       (slot-value snapshot 'gr8s.node.v1::service-discovery-objects-json)))))
    (dolist (pod (slot-value base 'gr8s.node.v1::pods))
      (setf (gethash (slot-value pod 'gr8s.node.v1::uid) base-pods) pod))
    (dolist (pod (slot-value snapshot 'gr8s.node.v1::pods))
      (setf (gethash (slot-value pod 'gr8s.node.v1::uid) current) t))
    (make-instance
     'gr8s.node.v1::desired-state-snapshot
     :revision (slot-value snapshot 'gr8s.node.v1::revision)
     :base-revision (slot-value base 'gr8s.node.v1::revision)
     :network (slot-value snapshot 'gr8s.node.v1::network)
     :routes (slot-value snapshot 'gr8s.node.v1::routes)
     :pods (remove-if (lambda (pod)
                        (let ((old (gethash (slot-value pod 'gr8s.node.v1::uid) base-pods)))
                          (and old (same-pod-assignment-p old pod))))
                      (slot-value snapshot 'gr8s.node.v1::pods))
     :removed-pod-uids (loop for uid being the hash-keys of base-pods
                             unless (gethash uid current) collect uid)
     :service-discovery-changed service-discovery-changed
     :service-discovery-objects-json
     (when service-discovery-changed
       (slot-value snapshot 'gr8s.node.v1::service-discovery-objects-json)))))

(defun deliver-node-snapshot (session snapshot)
  "Send SNAPSHOT on SESSION, as a delta when the agent takes them, unless it already has a newer one.
Deltas are computed against what this session delivered, under its send lock, so
concurrent publications cannot reorder a delta ahead of its base."
  (bt:with-lock-held ((node-agent-session-lock session))
    (let ((delivered (node-agent-session-delivered session)))
      (unless (and delivered (<= (slot-value snapshot 'gr8s.node.v1::revision)
                                 (slot-value delivered 'gr8s.node.v1::revision)))
        (ag-grpc:stream-send
         (node-agent-session-stream session)
         (make-server-envelope :desired-state
                               (if (and delivered (node-agent-session-deltas-p session))
                                   (node-snapshot-delta delivered snapshot)
                                   snapshot)
                               :sequence 0))
        (setf (node-agent-session-delivered session) snapshot)))))

(defvar *node-session-stall-seconds* 30
  "Silence after which either end of a node session treats it as wedged.")

(defun log-node-session-stall (message &rest arguments)
  "Report a wedged session with every thread's stack, which is otherwise lost."
  (format *error-output* "gr8s node session stalled: ~?~%" message arguments)
  ;; Threads that cannot answer take seconds each, and recovery must not wait
  ;; for all of them. A late report is still printed.
  (let* ((output *error-output*)
         (report (bt:make-thread
                  (lambda ()
                    (let ((*standard-output* output))
                      (ignore-errors (debug-backtraces "" 2)))
                    (finish-output output))
                  :name "gr8s node session stall report")))
    (sb-thread:join-thread report :default nil :timeout 5)))

(defstruct (pending-node-operation
             (:constructor make-pending-node-operation (node-name request)))
  node-name
  request
  session
  ;; On the API member, the peer that owns the agent session. On that peer,
  ;; ORIGIN-MEMBER names the member to which agent output must be returned.
  remote-member
  origin-member
  response
  (stream-messages nil)
  error
  (done-p nil)
  (lock (bt:make-lock "gr8s node operation"))
  (finished (bt:make-condition-variable :name "gr8s node operation finished")))

(defun operation-request-id (request)
  "The operation-id string identifying REQUEST."
  (slot-value request 'gr8s.node.v1::operation-id))

(defun send-node-agent-envelope (session envelope)
  "Send ENVELOPE to the agent over SESSION's stream, serialized with the session
   send lock so concurrent publications and operations never interleave frames."
  (bt:with-lock-held ((node-agent-session-lock session))
    (ag-grpc:stream-send (node-agent-session-stream session) envelope)))

(defun remove-queued-node-operation (server operation)
  "Remove OPERATION from its node's local delivery queue.
SERVER's lock must already be held."
  (let* ((node-name (pending-node-operation-node-name operation))
         (queue (delete operation
                        (gethash node-name
                                 (node-grpc-server-operation-queues server))
                        :test #'eq)))
    (if queue
        (setf (gethash node-name (node-grpc-server-operation-queues server)) queue)
        (remhash node-name (node-grpc-server-operation-queues server)))))

(defun send-pending-node-operation (operation session)
  "Deliver OPERATION's request to SESSION, finishing it if the send fails."
  (handler-case
      (send-node-agent-envelope
       session
       (make-server-envelope
        :operation-request (pending-node-operation-request operation) :sequence 0))
    (error (condition)
      (finish-node-operation operation :error (princ-to-string condition)))))

(defun retry-node-operation-route (server operation)
  "Retry peer discovery for a locally queued OPERATION until a peer accepts it,
a local agent session appears, or the operation is released. Routing happens
outside SERVER's lock because a peer RPC may take seconds."
  (let ((operation-id
          (operation-request-id (pending-node-operation-request operation)))
        (node-name (pending-node-operation-node-name operation))
        (router (node-grpc-server-operation-router server)))
    (loop
      (sleep 0.05)
      (let ((session nil)
            (active-p nil))
        ;; Remove the operation from the local queue before dropping the lock.
        ;; Otherwise a concurrent Connect could deliver it while peer routing
        ;; is accepting the same request.
        (bt:with-lock-held ((node-grpc-server-lock server))
          (setf active-p
                (and (not (node-grpc-server-stopping-p server))
                     (eq operation
                         (gethash operation-id
                                  (node-grpc-server-operations server)))))
          (when active-p
            (setf session (gethash node-name
                                   (node-grpc-server-sessions server)))
            (remove-queued-node-operation server operation)
            (when session
              (setf (pending-node-operation-session operation) session))))
        (unless active-p (return))
        (when session
          (send-pending-node-operation operation session)
          (return))
        (let ((owner (funcall router :operation-request nil node-name
                              (pending-node-operation-request operation))))
          (when owner
            (bt:with-lock-held ((node-grpc-server-lock server))
              (when (eq operation
                        (gethash operation-id
                                 (node-grpc-server-operations server)))
                (setf (pending-node-operation-remote-member operation) owner)))
            (return)))
        ;; Peer discovery ran without the server lock, so session ownership may
        ;; have changed. Recheck locally before exposing the operation to the
        ;; next Connect and routing attempt.
        (bt:with-lock-held ((node-grpc-server-lock server))
          (setf active-p
                (and (not (node-grpc-server-stopping-p server))
                     (eq operation
                         (gethash operation-id
                                  (node-grpc-server-operations server)))))
          (when active-p
            (setf session (gethash node-name
                                   (node-grpc-server-sessions server))
                  (pending-node-operation-session operation) session)
            (unless session
              (setf (gethash node-name
                             (node-grpc-server-operation-queues server))
                    (nconc (gethash node-name
                                    (node-grpc-server-operation-queues server))
                           (list operation))))))
        (unless active-p (return))
        (when session
          (send-pending-node-operation operation session)
          (return))))))

(defun start-node-operation-route-retry (server operation)
  (bt:make-thread
   (lambda () (retry-node-operation-route server operation))
   :name (format nil "gr8s route node operation ~A"
                 (operation-request-id
                  (pending-node-operation-request operation)))))

(defun queue-node-operation (server node-name request)
  "Register REQUEST as a pending operation for NODE-NAME and deliver it to that
   node's live agent session, or hold it in the node's queue until the agent
   connects. Errors if NODE-NAME is unknown (GET-NODE) or an operation with the
   same id is already registered. If the immediate send fails, the operation is
   finished with that error. Returns the PENDING-NODE-OPERATION."
  (get-node (node-grpc-server-store server) node-name)
  (let* ((operation (make-pending-node-operation node-name request))
         (operation-id (operation-request-id request))
         (session nil)
         (router (node-grpc-server-operation-router server)))
    (bt:with-lock-held ((node-grpc-server-lock server))
      (when (gethash operation-id (node-grpc-server-operations server))
        (error "Node operation ~A already exists" operation-id))
      (setf (gethash operation-id (node-grpc-server-operations server))
            operation
            session (gethash node-name (node-grpc-server-sessions server))
            (pending-node-operation-session operation) session))
    (cond
      (session
       (send-pending-node-operation operation session))
      ((and router
            (let ((owner (funcall router :operation-request nil node-name request)))
              (when owner
                (setf (pending-node-operation-remote-member operation) owner)
                t))))
      (t
       ;; Peer discovery ran without the server lock. Recheck local ownership
       ;; before queueing so a concurrent Connect cannot strand the operation.
       (bt:with-lock-held ((node-grpc-server-lock server))
         (setf session (gethash node-name (node-grpc-server-sessions server))
               (pending-node-operation-session operation) session)
         (unless session
           (setf (gethash node-name (node-grpc-server-operation-queues server))
                 (nconc (gethash node-name
                                 (node-grpc-server-operation-queues server))
                        (list operation)))))
       (when session
         (send-pending-node-operation operation session))
       (unless session
         (when router
           (start-node-operation-route-retry server operation)))))
    operation))

(defun accept-routed-node-operation (server origin-member node-name variant payload)
  "Accept a peer's routed operation frame when this member owns NODE-NAME's live
agent session. REQUEST creates a shadow operation bound to ORIGIN-MEMBER; INPUT
and CANCEL follow that operation's local agent session. Returns true only when
the frame was accepted here."
  (ecase variant
    (:operation-request
     (let* ((operation-id (operation-request-id payload))
            (operation (make-pending-node-operation node-name payload))
            (session nil))
       (bt:with-lock-held ((node-grpc-server-lock server))
         (setf session (gethash node-name (node-grpc-server-sessions server)))
         (when session
           (when (gethash operation-id (node-grpc-server-operations server))
             (return-from accept-routed-node-operation nil))
           (setf (pending-node-operation-session operation) session
                 (pending-node-operation-origin-member operation) origin-member
                 (gethash operation-id (node-grpc-server-operations server)) operation)))
       (when session
         (handler-case
             (send-node-agent-envelope
              session (make-server-envelope :operation-request payload :sequence 0))
           (error (condition)
             (finish-node-operation operation :error (princ-to-string condition))
             (release-node-operation server operation)
             (return-from accept-routed-node-operation nil)))
         t)))
    ((:operation-input :operation-cancel)
     (let* ((operation-id (slot-value payload 'gr8s.node.v1::operation-id))
            (operation (find-node-operation server operation-id)))
       (when (and operation
                  (equal origin-member (pending-node-operation-origin-member operation)))
         (send-node-operation-envelope server operation variant payload operation-id)
         t)))))

(defun deliver-routed-node-operation (server variant payload)
  "Deliver an agent STREAM or RESPONSE relayed by the owning member to the API
member that originated it. Returns true when the operation is still registered."
  (let ((operation
          (find-node-operation server
                               (slot-value payload 'gr8s.node.v1::operation-id))))
    (when operation
      (ecase variant
        (:operation-stream (record-node-operation-stream operation payload))
        (:operation-response (record-node-operation-response operation payload)))
      t)))

(defun take-node-operations (server node-name)
  "Atomically remove and return NODE-NAME's list of queued (not-yet-delivered)
   operations."
  (bt:with-lock-held ((node-grpc-server-lock server))
    (prog1 (gethash node-name (node-grpc-server-operation-queues server))
      (remhash node-name (node-grpc-server-operation-queues server)))))

(defun find-node-operation (server operation-id)
  "The registered PENDING-NODE-OPERATION for OPERATION-ID, or NIL."
  (bt:with-lock-held ((node-grpc-server-lock server))
    (gethash operation-id (node-grpc-server-operations server))))

(defun finish-node-operation (operation &key response error)
  "Mark OPERATION complete with RESPONSE and/or ERROR and wake its waiters.
   Idempotent: a second call on an already-finished operation is a no-op, so the
   first terminal outcome wins. Returns OPERATION."
  (bt:with-lock-held ((pending-node-operation-lock operation))
    (unless (pending-node-operation-done-p operation)
      (setf (pending-node-operation-response operation) response
            (pending-node-operation-error operation) error
            (pending-node-operation-done-p operation) t)
      (bt:condition-notify (pending-node-operation-finished operation))))
  operation)

(defun release-node-operation (server operation)
  "Remove OPERATION from the server's registry, but only while it is still the one
   registered under its id (a replacement is left alone). Returns OPERATION."
  (let ((operation-id
          (operation-request-id
           (pending-node-operation-request operation))))
    (bt:with-lock-held ((node-grpc-server-lock server))
      (when (eq operation
                (gethash operation-id (node-grpc-server-operations server)))
        (remhash operation-id (node-grpc-server-operations server))
        (remove-queued-node-operation server operation))))
  operation)

(defun wait-for-next-node-operation-message
    (operation cursor &key timeout)
  "Block until OPERATION has a stream message at index CURSOR, or the operation
   finishes. Returns (values message (1+ cursor) nil) for a message, or
   (values nil cursor t) once it is done with nothing more. Messages are retained
   (CURSOR indexes them), unlike TAKE-NEXT-NODE-OPERATION-MESSAGE. With TIMEOUT
   seconds and nothing arriving, signals a RUNTIME-ERROR."
  (let ((deadline
          (and timeout
               (+ (get-internal-real-time)
                  (* timeout internal-time-units-per-second)))))
    (bt:with-lock-held ((pending-node-operation-lock operation))
      (loop
        (let ((message
                (nth cursor
                     (pending-node-operation-stream-messages operation))))
          (when message
            (return (values message (1+ cursor) nil)))
          (when (pending-node-operation-done-p operation)
            (return (values nil cursor t))))
        (if deadline
            (let ((remaining
                    (/ (- deadline (get-internal-real-time))
                       internal-time-units-per-second)))
              (when (<= remaining 0)
                (error 'runtime-error
                       :message "Timed out waiting for node operation output"))
              (bt:condition-wait
               (pending-node-operation-finished operation)
               (pending-node-operation-lock operation)
               :timeout remaining))
            (bt:condition-wait
             (pending-node-operation-finished operation)
             (pending-node-operation-lock operation)))))))

(defun take-next-node-operation-message (operation &key timeout)
  "Wait for OPERATION's next message and remove it, returning it, or (values NIL T) at the end.
What was consumed isn't kept, for streams too long to hold in memory. With TIMEOUT seconds and
nothing yet, signal a RUNTIME-ERROR as WAIT-FOR-NEXT-NODE-OPERATION-MESSAGE does."
  (let ((deadline (and timeout (+ (get-internal-real-time) (* timeout internal-time-units-per-second)))))
    (bt:with-lock-held ((pending-node-operation-lock operation))
      (loop
        (when (pending-node-operation-stream-messages operation)
          (return (values (pop (pending-node-operation-stream-messages operation)) nil)))
        (when (pending-node-operation-done-p operation)
          (return (values nil t)))
        (if deadline
            (let ((remaining (/ (- deadline (get-internal-real-time)) internal-time-units-per-second)))
              (when (<= remaining 0)
                (error 'runtime-error :message "Timed out waiting for node operation output"))
              (bt:condition-wait (pending-node-operation-finished operation)
                                 (pending-node-operation-lock operation) :timeout remaining))
            (bt:condition-wait (pending-node-operation-finished operation)
                               (pending-node-operation-lock operation)))))))

(defun wait-for-node-operation (server operation &key (timeout 10))
  "Block until OPERATION completes or TIMEOUT seconds pass, marking it timed-out on
   expiry. Releases it from the server registry, then signals a RUNTIME-ERROR if it
   ended in error. Returns OPERATION on success."
  (let ((deadline (+ (get-internal-real-time)
                     (* timeout internal-time-units-per-second))))
    (bt:with-lock-held ((pending-node-operation-lock operation))
      (loop until (pending-node-operation-done-p operation)
            for remaining = (/ (- deadline (get-internal-real-time))
                               internal-time-units-per-second)
            when (<= remaining 0)
              do (setf (pending-node-operation-error operation)
                       "Node operation timed out"
                       (pending-node-operation-done-p operation) t)
                 (loop-finish)
            do (bt:condition-wait
                (pending-node-operation-finished operation)
                (pending-node-operation-lock operation)
                :timeout remaining)))
    (release-node-operation server operation)
    (when (pending-node-operation-error operation)
      (error 'runtime-error
             :message (pending-node-operation-error operation)))
    operation))

(defun request-node-operation (server node-name request &key (timeout 10))
  "Queue REQUEST to NODE-NAME and block for its result: QUEUE-NODE-OPERATION then
   WAIT-FOR-NODE-OPERATION. Returns the finished operation, or signals its error or
   a timeout."
  (wait-for-node-operation
   server (queue-node-operation server node-name request) :timeout timeout))

(defun live-node-operation-session (server operation operation-id)
  "Return OPERATION's live agent session, after checking OPERATION-ID matches it,
   it is still registered, and it has not finished. Signals a RUNTIME-ERROR on any
   of those, or when it has no live session."
  (unless (string= operation-id
                   (operation-request-id
                    (pending-node-operation-request operation)))
    (error 'runtime-error :message "Node operation ID does not match"))
  (unless (eq operation (find-node-operation server operation-id))
    (error 'runtime-error :message "Node operation is no longer active"))
  (bt:with-lock-held ((pending-node-operation-lock operation))
    (when (pending-node-operation-done-p operation)
      (error 'runtime-error :message "Node operation is already complete"))
    (or (pending-node-operation-session operation)
        (error 'runtime-error :message "Node operation has no live session"))))

(defun send-node-operation-envelope (server operation variant payload operation-id)
  "Send (VARIANT . PAYLOAD) to OPERATION's live session (verified by OPERATION-ID).
   On a send failure, finishes the operation with the error and re-signals it.
   Returns OPERATION."
  (let ((remote (pending-node-operation-remote-member operation)))
    (if remote
        (progn
          (unless (and (string= operation-id
                                (operation-request-id
                                 (pending-node-operation-request operation)))
                       (eq operation (find-node-operation server operation-id))
                       (not (pending-node-operation-done-p operation)))
            (error 'runtime-error :message "Node operation is no longer active"))
          (let ((router (node-grpc-server-operation-router server)))
            (unless (and router
                         (funcall router variant remote
                                  (pending-node-operation-node-name operation) payload))
              (finish-node-operation operation :error "Remote node operation owner is unavailable")
              (error 'runtime-error :message "Remote node operation owner is unavailable"))))
        (let ((session (live-node-operation-session server operation operation-id)))
          (handler-case
              (send-node-agent-envelope
               session (make-server-envelope variant payload :sequence 0))
            (error (condition)
              (finish-node-operation operation :error (princ-to-string condition))
              (error condition))))))
  operation)

(defun send-node-operation-input (server operation input)
  "Forward INPUT (stdin/resize for a running operation) to the session of the
   operation named by INPUT's own operation-id."
  (send-node-operation-envelope
   server operation :operation-input input
   (slot-value input 'gr8s.node.v1::operation-id)))

(defun cancel-node-operation (server operation reason)
  "Ask the agent to cancel OPERATION, sending an OPERATION-CANCEL carrying REASON."
  (let ((operation-id
          (operation-request-id (pending-node-operation-request operation))))
    (send-node-operation-envelope
     server operation :operation-cancel
     (make-instance 'gr8s.node.v1::operation-cancel
                    :operation-id operation-id :reason reason)
     operation-id)))

(defun record-node-operation-stream (operation message)
  "Append MESSAGE to OPERATION locally and wake its output waiter."
  (bt:with-lock-held ((pending-node-operation-lock operation))
    (setf (pending-node-operation-stream-messages operation)
          (nconc (pending-node-operation-stream-messages operation)
                 (list message)))
    (bt:condition-notify (pending-node-operation-finished operation)))
  operation)

(defun note-node-operation-stream (server message)
  "Append MESSAGE locally, or return it to the peer that originated a routed
operation. No-op when no operation matches MESSAGE's id."
  (let ((operation
          (find-node-operation
           server (slot-value message 'gr8s.node.v1::operation-id))))
    (when operation
      (let ((origin (pending-node-operation-origin-member operation)))
        (if origin
            (let ((router (node-grpc-server-operation-router server)))
              (unless (and router
                           (funcall router :operation-stream origin
                                    (pending-node-operation-node-name operation) message))
                (finish-node-operation operation :error "Operation origin is unavailable")))
            (record-node-operation-stream operation message))))))

(defun record-node-operation-response (operation response)
  "Record terminal RESPONSE on OPERATION. Returns true for a terminal response."
  (when (member (slot-value response 'gr8s.node.v1::status)
                (list gr8s.node.v1::+operationstatus-operation_status_complete+
                      gr8s.node.v1::+operationstatus-operation_status_failed+))
    (finish-node-operation
     operation :response response
     :error (when (= (slot-value response 'gr8s.node.v1::status)
                     gr8s.node.v1::+operationstatus-operation_status_failed+)
              (slot-value response 'gr8s.node.v1::error-message)))
    t))

(defun note-node-operation-response (server response)
  "Finish the matching operation when RESPONSE is terminal (complete or failed),
   carrying the response and, on failure, its error message. No-op for a
   non-terminal status or an unknown operation id."
  (let ((operation
          (find-node-operation
           server (slot-value response 'gr8s.node.v1::operation-id))))
    (when operation
      (let ((origin (pending-node-operation-origin-member operation)))
        (if origin
            (let ((terminal
                    (member (slot-value response 'gr8s.node.v1::status)
                            (list gr8s.node.v1::+operationstatus-operation_status_complete+
                                  gr8s.node.v1::+operationstatus-operation_status_failed+)))
                  (router (node-grpc-server-operation-router server)))
              (unless (and router
                           (funcall router :operation-response origin
                                    (pending-node-operation-node-name operation) response))
                (finish-node-operation operation :error "Operation origin is unavailable"))
              (when terminal (release-node-operation server operation)))
            (record-node-operation-response operation response))))))

(defun fail-node-session-operations (server session)
  "Finish every still-pending operation bound to SESSION with \"Node disconnected\".
   Called as a session tears down so no caller waits on a dead agent."
  (let ((operations nil))
    (bt:with-lock-held ((node-grpc-server-lock server))
      (maphash
       (lambda (operation-id operation)
         (declare (ignore operation-id))
         (when (eq session (pending-node-operation-session operation))
           (push operation operations)))
       (node-grpc-server-operations server)))
    (dolist (operation operations)
      (unless (pending-node-operation-done-p operation)
        (finish-node-operation operation :error "Node disconnected")))))

(defun node-envelope-payload (envelope variant)
  "The payload ENVELOPE carries for VARIANT. Errors unless ENVELOPE's active payload
   case is exactly VARIANT."
  (unless (eq variant (slot-value envelope 'gr8s.node.v1::payload-case))
    (error "Expected node-session payload ~S, received ~S"
           variant (slot-value envelope 'gr8s.node.v1::payload-case)))
  (slot-value envelope (find-symbol (symbol-name variant) :gr8s.node.v1)))

(defun assigned-node-network (server node-name)
  "The NodeNetworkConfig for NODE-NAME: the cluster and this node's Pod CIDRs, the
   cluster DNS address, the node's underlay address, and the fixed overlay VNI 42
   and MTU 1450. Errors if NODE-NAME is unknown."
  (let ((node (get-node (node-grpc-server-store server) node-name)))
    (make-instance 'gr8s.node.v1::node-network-config
                   :cluster-pod-cidr (node-grpc-server-cluster-pod-cidr server)
                   :node-pod-cidr (node-record-pod-cidr node)
                   :dns-address +dns-pod-server-address+
                   :underlay-address (node-record-underlay-address node)
                   :vni 42 :mtu 1450)))

(defun assigned-node-routes (server node-name)
  "The overlay routes from NODE-NAME to every OTHER node that has both an underlay
   address and a Pod CIDR, ordered by node name. NIL until this node itself has an
   underlay address."
  (when (string= "" (node-record-underlay-address
                     (get-node (node-grpc-server-store server) node-name)))
    (return-from assigned-node-routes nil))
  (loop for node in (sort (copy-list (list-nodes (node-grpc-server-store server)))
                         #'string< :key #'node-record-name)
        unless (or (string= node-name (node-record-name node))
                   (string= "" (node-record-underlay-address node))
                   (string= "" (node-record-pod-cidr node)))
          collect (make-instance 'gr8s.node.v1::node-route
                                 :node-id (node-record-id node)
                                 :pod-cidr (node-record-pod-cidr node)
                                 :underlay-address (node-record-underlay-address node))))

(defun attach-node-topology (server node-name snapshot)
  "Fill SNAPSHOT's network and routes slots for NODE-NAME from the store, in place,
   and return SNAPSHOT."
  (setf (slot-value snapshot 'gr8s.node.v1::network)
        (assigned-node-network server node-name)
        (slot-value snapshot 'gr8s.node.v1::routes)
        (assigned-node-routes server node-name))
  snapshot)

(defun same-node-snapshot-topology-p (left right)
  "Whether LEFT and RIGHT are non-NIL and carry byte-identical network and route
   topology (LEFT must have a network). Compares serialized proto bytes."
  (and left right
       (slot-value left 'gr8s.node.v1::network)
       (equalp (ag-proto:serialize-to-bytes (slot-value left 'gr8s.node.v1::network))
               (ag-proto:serialize-to-bytes (slot-value right 'gr8s.node.v1::network)))
       (equalp (mapcar #'ag-proto:serialize-to-bytes
                       (slot-value left 'gr8s.node.v1::routes))
               (mapcar #'ag-proto:serialize-to-bytes
                       (slot-value right 'gr8s.node.v1::routes)))))

(defun refresh-node-peer-topology (server changed-node)
  "After CHANGED-NODE's topology changed, recompute every OTHER node's snapshot and
   republish it to any node whose topology now differs, so peers learn the new route
   set. Skips CHANGED-NODE itself."
  (dolist (node (list-nodes (node-grpc-server-store server)))
    (let ((name (node-record-name node)))
      (unless (string= name changed-node)
        (let ((snapshot (attach-node-topology
                         server name
                         (node-desired-state-snapshot (node-grpc-server-store server) name))))
          (unless (same-node-snapshot-topology-p
                   (current-node-snapshot server name) snapshot)
            (publish-node-desired-state server name snapshot)))))))

(defun prepare-node-connect-snapshot (server node-name last-applied)
  "The desired-state snapshot a (re)connecting agent whose last applied revision is
   LAST-APPLIED should receive, reusing the published one when its content is
   unchanged and its revision is at least LAST-APPLIED, else assigning a revision
   strictly above both LAST-APPLIED and the in-memory counter and recording it.
   Guarantees a restarted control plane never hands back a revision an agent has
   already moved past."
  ;; Rebuild from durable desired state after a control-plane restart. Revision
  ;; counters in memory must never strand an agent ahead of its new server.
  (let ((snapshot (node-desired-state-snapshot
                   (node-grpc-server-store server) node-name)))
    (attach-node-topology server node-name snapshot)
    (bt:with-lock-held ((node-grpc-server-lock server))
      (let ((existing (gethash node-name (node-grpc-server-snapshots server))))
        (if (and (same-node-desired-content-p existing snapshot)
                 (>= (slot-value existing 'gr8s.node.v1::revision) last-applied))
            existing
          (let ((revision (1+ (max last-applied
                                   (gethash node-name
                                            (node-grpc-server-revisions server) 0)))))
            (setf (slot-value snapshot 'gr8s.node.v1::revision) revision
                  (gethash node-name (node-grpc-server-revisions server)) revision
                  (gethash node-name (node-grpc-server-snapshots server)) snapshot)))))))

(defun current-node-snapshot (server node-name)
  "The snapshot currently published to NODE-NAME, or a fresh empty
   DesiredStateSnapshot when none has been published yet."
  (bt:with-lock-held ((node-grpc-server-lock server))
    (or (gethash node-name (node-grpc-server-snapshots server))
        (make-instance 'gr8s.node.v1::desired-state-snapshot))))

(defun note-node-snapshot-ack (server node-name ack)
  "Record NODE-NAME's acknowledged revision from ACK when it advances convergence:
   only when ACK is applied, its revision exceeds the last ack, and does not run
   ahead of what the server has published. Old or impossible acks are ignored."
  (let ((revision (slot-value ack 'gr8s.node.v1::revision)))
    (when (slot-value ack 'gr8s.node.v1::applied)
      (bt:with-lock-held ((node-grpc-server-lock server))
        (let ((published (gethash node-name
                                  (node-grpc-server-revisions server) 0))
              (acknowledged
                (gethash node-name
                         (node-grpc-server-acknowledged-revisions server) 0)))
          ;; Old acks cannot move convergence backwards, and an agent cannot
          ;; acknowledge a revision the server has never published.
          (when (and (> revision acknowledged) (<= revision published))
            (setf (gethash node-name
                           (node-grpc-server-acknowledged-revisions server))
                  revision)))))))

(defun handle-node-agent-envelope (server node-name envelope)
  "Dispatch one inbound envelope from NODE-NAME's agent after checking its protocol
   version. A heartbeat renews the node's readiness and lease and records runtime
   health; a snapshot-ack advances the acked revision; a status report updates CSI
   registrations, each Pod's observed status, runtime events and finalization, and
   any PodCertificateRequests -- each wrapped so one failure never drops the rest of
   the report or ends the session; operation responses and streams are routed to
   their pending operation. Errors on any other payload."
  (ensure-node-protocol-version
   (slot-value envelope 'gr8s.node.v1::protocol-version))
  (case (slot-value envelope 'gr8s.node.v1::payload-case)
    (:heartbeat
     (let ((now (get-universal-time)))
       (mark-node-ready (node-grpc-server-store server)
                        node-name now
                        :lease-duration (node-grpc-server-heartbeat-timeout-seconds server))
       (note-node-runtime-health
        (node-grpc-server-store server) node-name
        (slot-value (slot-value envelope 'gr8s.node.v1::heartbeat)
                    'gr8s.node.v1::runtime-down-message))
       (note-node-heartbeat-lease (node-grpc-server-store server) node-name now)))
    (:snapshot-ack
     (note-node-snapshot-ack
      server node-name
      (slot-value envelope 'gr8s.node.v1::snapshot-ack)))
    (:status
     (let ((status (slot-value envelope 'gr8s.node.v1::status)))
       (bt:with-lock-held ((node-grpc-server-lock server))
         (setf (gethash node-name (node-grpc-server-statuses server)) status))
       (handler-case
           (update-node-csi-registrations (node-grpc-server-store server) node-name
                                          (slot-value status 'gr8s.node.v1::csi-drivers))
         (kubernetes-error (condition)
           (format *error-output* "gr8s CSINode ~A update failed: ~A~%" node-name condition)))
       (loop for pod-status in (slot-value status 'gr8s.node.v1::pods)
             for pod = (handler-case
                           (get-pod (node-grpc-server-store server)
                                    (slot-value pod-status 'gr8s.node.v1::namespace)
                                    (slot-value pod-status 'gr8s.node.v1::name))
                         (kubernetes-error () nil))
             when (and pod (equal node-name (pod-node-name pod))
                       (string= (slot-value pod-status 'gr8s.node.v1::uid) (pod-uid pod))
                       (string= (slot-value pod-status 'gr8s.node.v1::resource-version)
                                (pod-resource-version pod)))
               do (handler-case
                      (let* ((bytes (slot-value pod-status 'gr8s.node.v1::status-json))
                             (object (handler-case
                                         (when (plusp (length bytes))
                                           (com.inuoe.jzon:parse
                                            (trivial-utf-8:utf-8-bytes-to-string bytes)))
                                       (error () nil))))
                        (unless (hash-table-p object) (setf object (make-hash-table :test #'equal)))
                        (setf (gethash "phase" object) (slot-value pod-status 'gr8s.node.v1::phase))
                        (unless (string= "" (slot-value pod-status 'gr8s.node.v1::pod-ip))
                          (setf (gethash "podIP" object) (slot-value pod-status 'gr8s.node.v1::pod-ip)
                                (gethash "podIPs" object)
                                (vector (json-object "ip" (slot-value pod-status 'gr8s.node.v1::pod-ip)))))
                        (let ((events (gethash "gr8sRuntimeEvents" object)))
                          (remhash "gr8sRuntimeEvents" object)
                          (update-pod-observed-status (node-grpc-server-store server) pod object)
                          (record-node-runtime-events (node-grpc-server-store server) pod node-name events)
                          ;; Cleanup is distinct from phase and API finalizer retention.
                          ;; The authenticated peer still owns this exact UID/RV.
                          (when (and (deletion-requested-p pod) (slot-value pod-status 'gr8s.node.v1::runtime-deleted))
                            (save-pod-finalization-state (node-grpc-server-store server) pod object t))))
                    ;; The next status report retries this Pod. Failing here would
                    ;; lose the rest of this report and end the session of every Pod.
                    (error (condition)
                      (format *error-output* "gr8s Pod ~A/~A status update failed: ~A~%"
                              (pod-namespace pod) (pod-name pod) condition))))
       (loop for claim in (slot-value status 'gr8s.node.v1::pod-certificate-requests)
             do (handler-case
                    (ensure-pod-certificate-request-from-claim
                     (node-grpc-server-store server) node-name claim)
                  (error (condition)
                    (format *error-output* "gr8s PodCertificateRequest ~A/~A from node ~A failed: ~A~%"
                            (slot-value claim 'gr8s.node.v1::namespace)
                            (slot-value claim 'gr8s.node.v1::name) node-name condition))))))
    (:operation-response
     (note-node-operation-response
      server (slot-value envelope 'gr8s.node.v1::operation-response)))
    (:operation-stream
     (note-node-operation-stream
      server (slot-value envelope 'gr8s.node.v1::operation-stream)))
    (otherwise
     (error "Unexpected node-session payload ~S"
            (slot-value envelope 'gr8s.node.v1::payload-case)))))

(defun send-node-protocol-error (stream condition &optional envelope)
  "Best-effort: send STREAM a protocol-error describing CONDITION (echoing
   ENVELOPE's received protocol version when given). Swallows any send failure."
  (ignore-errors
    (ag-grpc:stream-send
     stream
     (make-server-envelope
      :protocol-error
      (make-instance
       'gr8s.node.v1::protocol-error
       :supported-version +node-protocol-version+
       :received-version
       (if envelope
           (slot-value envelope 'gr8s.node.v1::protocol-version)
           0)
       :message (princ-to-string condition))
      :sequence 1))))

(defun handle-node-connect-internal (server context stream)
  "Serve one agent Connect stream end to end: read and authenticate the NodeHello,
   update the node's underlay address/capacity/kubelet port, build its connect
   snapshot, then -- holding the session send lock so nothing races the handshake --
   register the session, send ServerHello and the initial complete snapshot, and
   flush any queued operations. Then loop handling inbound envelopes until the stream
   ends. On exit deregisters the session and fails its pending operations. Refreshes
   peer topology when this node's underlay address changed."
  (let ((first (ag-grpc:stream-recv stream)))
    (unless first (error "Node session ended before its hello"))
    (ensure-node-protocol-version (slot-value first 'gr8s.node.v1::protocol-version))
    (let* ((hello (node-envelope-payload first :hello))
           (node-name (slot-value hello 'gr8s.node.v1::node-name))
           (authenticated (authenticate-node-peer (node-grpc-server-pki server) context node-name))
           (node (get-node (node-grpc-server-store server) node-name))
           (topology-changed
             (update-node-underlay-address
              (node-grpc-server-store server) node-name
              (slot-value hello 'gr8s.node.v1::underlay-address)))
           (snapshot (prepare-node-connect-snapshot
                      server node-name
                      (slot-value hello 'gr8s.node.v1::last-applied-revision)))
           (session (progn
                      (update-node-capacity (node-grpc-server-store server) node-name
                                            (node-capacity-from-entries (slot-value hello 'gr8s.node.v1::capacity)))
                      (update-node-kubelet-port (node-grpc-server-store server) node-name
                                                (or (slot-value hello 'gr8s.node.v1::kubelet-port) 0))
                      (let ((session (make-node-agent-session stream)))
                        (setf (node-agent-session-deltas-p session)
                              (member +desired-state-delta-capability+
                                      (slot-value hello 'gr8s.node.v1::capabilities)
                                      :test #'equal))
                        session)))
           (heartbeat-interval
             (max 1 (floor (node-grpc-server-heartbeat-timeout-seconds server) 2))))
      (declare (ignore authenticated))
      (unwind-protect
           (progn
             ;; Register and drain queued work atomically; hold the send lock
             ;; through the handshake so a concurrent publication or operation
             ;; cannot arrive before ServerHello and the initial snapshot.
             (bt:with-lock-held ((node-agent-session-lock session))
               (let ((operations nil))
                 (bt:with-lock-held ((node-grpc-server-lock server))
                   (setf (gethash node-name (node-grpc-server-sessions server)) session
                         snapshot (gethash node-name (node-grpc-server-snapshots server) snapshot)
                         operations (gethash node-name (node-grpc-server-operation-queues server)))
                   (remhash node-name (node-grpc-server-operation-queues server)))
                 (ag-grpc:stream-send
                  stream (make-server-envelope
                          :hello (make-instance 'gr8s.node.v1::server-hello
                                                :node-id (node-record-id node)
                                                :heartbeat-interval-seconds heartbeat-interval
                                                :assigned-pod-cidr (node-record-pod-cidr node))
                          :sequence 1))
                 ;; Every session starts from a complete snapshot.
                 (ag-grpc:stream-send
                  stream (make-server-envelope :desired-state snapshot :sequence 2))
                 (setf (node-agent-session-delivered session) snapshot)
                 (loop for operation in operations for sequence from 3
                       do (setf (pending-node-operation-session operation) session)
                          (ag-grpc:stream-send
                           stream (make-server-envelope
                                   :operation-request (pending-node-operation-request operation)
                                   :sequence sequence)))))
             (when topology-changed (refresh-node-peer-topology server node-name))
             (loop for envelope = (ag-grpc:stream-recv stream)
                   while envelope
                   do (setf (node-agent-session-last-envelope-time session) (get-universal-time))
                      (handle-node-agent-envelope server node-name envelope)
                      (setf (node-agent-session-last-envelope-time session) (get-universal-time))))
        (bt:with-lock-held ((node-grpc-server-lock server))
          (when (eq session (gethash node-name (node-grpc-server-sessions server)))
            (remhash node-name (node-grpc-server-sessions server))))
        (fail-node-session-operations server session)))))

(defun handle-node-connect (server context stream)
  "Run HANDLE-NODE-CONNECT-INTERNAL, turning any error into a protocol-error sent
   back on STREAM so only this RPC ends; the listener and other sessions are
   untouched."
  (handler-case
      (handle-node-connect-internal server context stream)
    (error (condition)
      ;; A malformed peer gets a protocol-level explanation and only its RPC
      ;; stream ends. The listener and other node sessions remain untouched.
      (send-node-protocol-error stream condition))))

(defun evict-silent-node-sessions (server now)
  "Close sessions whose peer or handler has gone quiet, so a live agent reconnects."
  ;; An agent can keep sending into a connection whose handler is stuck, and
  ;; cannot tell from its side. Readiness alone would stay false forever.
  (let ((silent (bt:with-lock-held ((node-grpc-server-lock server))
                  (loop for node-name being the hash-keys of (node-grpc-server-sessions server)
                          using (hash-value session)
                        when (and (not (node-agent-session-evicted-p session))
                                  (> (- now (node-agent-session-last-envelope-time session))
                                     (max *node-session-stall-seconds*
                                          (* 2 (node-grpc-server-heartbeat-timeout-seconds server)))))
                          collect (cons node-name session)))))
    (loop for (node-name . session) in silent
          do (setf (node-agent-session-evicted-p session) t)
             (log-node-session-stall "no envelope handled from node ~A; closing its session" node-name)
             (let ((stream (node-agent-session-stream session)))
               (when (typep stream 'ag-grpc::grpc-server-call-stream)
                 (ignore-errors
                  (ag-http2:connection-close (ag-grpc::server-stream-connection stream))))))))

(defun monitor-node-heartbeats (server)
  "Until SERVER is stopping, every 50ms expire node leases past the heartbeat
   timeout and evict sessions that have gone silent."
  (loop until (node-grpc-server-stopping-p server)
        do (let ((now (get-universal-time)))
             (expire-node-heartbeats
              (node-grpc-server-store server)
              (- now (node-grpc-server-heartbeat-timeout-seconds server)) :now now)
             (evict-silent-node-sessions server now))
           (sleep 0.05)))

(defun handle-node-enrollment (server request context)
  "Enroll the node named in REQUEST: validate its join token and sign its CSR,
   allocate a node id and a Pod CIDR, register the node, and return an EnrollResponse
   with the signed node certificate and the cluster CA. Errors when enrollment is
   disabled (no PKI)."
  (declare (ignore context))
  (let ((pki (node-grpc-server-pki server)))
    (unless pki
      (error "Node enrollment is disabled"))
    (ensure-node-protocol-version
     (slot-value request 'gr8s.node.v1::protocol-version))
    (let* ((store (node-grpc-server-store server))
           (node-name (slot-value request 'gr8s.node.v1::node-name))
           (token (slot-value request 'gr8s.node.v1::join-token))
           (csr (slot-value request 'gr8s.node.v1::certificate-request))
           (certificate
             (enroll-node-csr pki node-name token
                              (cluster-pki-ca-fingerprint pki) csr))
           ;; A forwarded registration can commit before its gRPC response is
           ;; lost to a leadership change.  A new name-bound token plus the
           ;; agent's persisted key must recover that committed record rather
           ;; than manufacture a conflicting node identity. A new HA enrollment
           ;; is itself a Raft operation, so its ID and CIDR are added against
           ;; the log-ordered node index rather than a follower's stale snapshot.
           (node
             (or (handler-case (get-node store node-name)
                   (kubernetes-error () nil))
                 (let ((commit (pod-store-consensus-commit-fn store)))
                   (if commit
                       (let ((payload
                               (list (generate-uid) node-name
                                     (node-grpc-server-cluster-pod-cidr server)
                                     (node-grpc-server-node-prefix server)
                                     (current-timestamp))))
                         (funcall commit :node-enrollment payload)
                         ;; A leader returns its apply result directly. A follower's
                         ;; forwarding RPC can return just before the commit heartbeat
                         ;; reaches this replica, so briefly wait for local apply.
                         (or (loop repeat 200
                                   for enrolled = (handler-case (get-node store node-name)
                                                    (kubernetes-error () nil))
                                   when enrolled return enrolled
                                   do (sleep 0.05))
                             (error "Committed enrollment for node ~A was not applied locally"
                                    node-name)))
                       (register-node
                        store
                        (make-node-record
                         :id (generate-uid) :name node-name
                         :pod-cidr
                         (allocate-node-pod-cidr
                          store
                          (node-grpc-server-cluster-pod-cidr server)
                          (node-grpc-server-node-prefix server)))))))))
      (make-instance
       'gr8s.node.v1::enroll-response
       :protocol-version +node-protocol-version+
       :node-id (node-record-id node)
       :node-certificate (pki-ascii-octets certificate)
       :ca-certificate
       (pki-ascii-octets
        (uiop:read-file-string (cluster-pki-ca-certificate-path pki)))))))

(defun start-node-grpc-server (store &key (host "127.0.0.1") (port 0)
                                            (heartbeat-timeout-seconds 15)
                                            pki
                                            (cluster-pod-cidr +default-cluster-pod-cidr+)
                                            (node-prefix +default-node-pod-prefix+))
  "Create and start the node control-plane gRPC server on HOST:PORT: register the
   Connect service (and the Enrollment service when PKI is given), spawn its accept
   thread and the heartbeat monitor, and block until it is listening. Errors on a
   non-positive heartbeat timeout or if the listener never comes up. Returns the
   NODE-GRPC-SERVER (with its actual bound port)."
  (unless (plusp heartbeat-timeout-seconds)
    (error "Heartbeat timeout must be positive"))
  (let* ((grpc-server (apply #'ag-grpc:make-grpc-server port :host host
                             (node-server-tls-options pki)))
         (server (%make-node-grpc-server
                  :store store
                  :grpc-server grpc-server
                  :port port
                  :heartbeat-timeout-seconds heartbeat-timeout-seconds
                  :pki pki
                  :cluster-pod-cidr cluster-pod-cidr
                  :node-prefix node-prefix)))
    (gr8s.node.v1::register-node-service-service
     grpc-server
     :connect-handler (lambda (context stream)
                        (handle-node-connect server context stream)))
    (when pki
      (gr8s.node.v1::register-enrollment-service-service
       grpc-server
       :enroll-handler (lambda (request context)
                         (handle-node-enrollment server request context))))
    (setf (node-grpc-server-thread server)
          (bt:make-thread
           (lambda () (ag-grpc:server-start grpc-server))
           :name "gr8s node gRPC server"))
    (loop repeat 500
          until (and (eql :running (ag-grpc:server-state grpc-server))
                     (ag-grpc::server-socket grpc-server))
          do (sleep 0.01))
    (unless (ag-grpc::server-socket grpc-server)
      (error "Node gRPC server failed to start listening"))
    (setf (node-grpc-server-port server)
          (usocket:get-local-port (ag-grpc::server-socket grpc-server))
          (node-grpc-server-monitor-thread server)
          (bt:make-thread (lambda () (monitor-node-heartbeats server))
                          :name "gr8s node heartbeat monitor"))
    server))

(defun stop-node-grpc-server (server)
  "Stop SERVER: signal its loops to stop, stop the gRPC server, and join its monitor
   and accept threads with a bounded wait, destroying a thread still wedged in
   accept(2) as the last resort. Returns SERVER."
  (setf (node-grpc-server-stopping-p server) t)
  (ignore-errors (ag-grpc:server-stop (node-grpc-server-grpc-server server)))
  (dolist (thread (list (node-grpc-server-monitor-thread server)
                        (node-grpc-server-thread server)))
    ;; Some usocket backends do not wake a thread already blocked in ACCEPT
    ;; when another thread closes the listener. Never let shutdown inherit
    ;; that platform quirk as an unbounded join.
    (when thread
      (loop repeat 100
            while (bt:thread-alive-p thread)
            do (sleep 0.01))
      (when (bt:thread-alive-p thread)
        ;; On SBCL/Linux a thread blocked in ACCEPT can retain the listening
        ;; file descriptor even after another thread closes its socket object.
        ;; The server has already closed every active connection, so ending
        ;; this otherwise-unwakeable acceptor is the final shutdown step.
        (ignore-errors (bt:destroy-thread thread)))
      (ignore-errors (bt:join-thread thread))))
  server)

(defun same-node-desired-content-p (left right)
  "Compare workload assignments and topology independently of envelope revision."
  (and left right (same-node-snapshot-topology-p left right)
       (equalp (slot-value left 'gr8s.node.v1::service-discovery-objects-json)
               (slot-value right 'gr8s.node.v1::service-discovery-objects-json))
       (= (length (slot-value left 'gr8s.node.v1::pods)) (length (slot-value right 'gr8s.node.v1::pods)))
       (every #'same-pod-assignment-p (slot-value left 'gr8s.node.v1::pods) (slot-value right 'gr8s.node.v1::pods))))

(defun publish-node-desired-state (server node-name snapshot &key deduplicate)
  "Publish SNAPSHOT as NODE-NAME's new desired state: attach topology, assign the
   next revision, store it, and deliver it to the live session if any (fail-soft).
   With DEDUPLICATE, returns the existing revision unchanged when the content is
   identical. Errors if NODE-NAME is unknown or SNAPSHOT is not a
   DesiredStateSnapshot. Returns the resulting revision."
  (get-node (node-grpc-server-store server) node-name)
  (unless (typep snapshot 'gr8s.node.v1::desired-state-snapshot)
    (error "Desired state must be a DesiredStateSnapshot"))
  (attach-node-topology server node-name snapshot)
  (let ((revision nil)
        (session nil))
    (bt:with-lock-held ((node-grpc-server-lock server))
      (let ((existing (gethash node-name (node-grpc-server-snapshots server))))
        (when (and deduplicate (same-node-desired-content-p existing snapshot))
          (return-from publish-node-desired-state (slot-value existing 'gr8s.node.v1::revision))))
      (setf revision
            (1+ (gethash node-name (node-grpc-server-revisions server) 0)))
      (setf (slot-value snapshot 'gr8s.node.v1::revision) revision
            (gethash node-name (node-grpc-server-revisions server)) revision
            (gethash node-name (node-grpc-server-snapshots server)) snapshot
            session (gethash node-name (node-grpc-server-sessions server))))
    (when session
      (handler-case (deliver-node-snapshot session snapshot)
        (error () nil)))
    revision))

(defun node-session-acknowledged-revision (server node-name)
  "The highest desired-state revision NODE-NAME has acknowledged applying, or 0."
  (bt:with-lock-held ((node-grpc-server-lock server))
    (gethash node-name (node-grpc-server-acknowledged-revisions server) 0)))

(defun ascii-octets-to-string (octets)
  "OCTETS decoded as ASCII, one CODE-CHAR per byte."
  (map 'string #'code-char octets))

(defun verify-enrollment-ca-pin (ca-pem expected-fingerprint)
  "Signal PKI-FAIL unless the certificate in CA-PEM has fingerprint
   EXPECTED-FINGERPRINT; returns NIL on a match."
  (let* ((certificate (certificate-from-pem ca-pem))
         (fingerprint
           (octets-to-hex (pure-tls:certificate-fingerprint certificate))))
    (unless (string-equal fingerprint expected-fingerprint)
      (pki-fail "ca-pin-mismatch"
                "Enrollment response CA fingerprint does not match"))))

(defun enroll-node-over-grpc (host port node-name token ca-fingerprint
                              private-key-path certificate-path ca-certificate-path)
  "Agent-side enrollment: generate NODE-NAME's key and CSR (written to
   PRIVATE-KEY-PATH), dial HOST:PORT with the server cert pinned to CA-FINGERPRINT,
   send the join TOKEN and CSR, verify the returned CA against the same pin, and
   write the issued node certificate and CA certificate atomically. Returns the
   server-assigned node id."
  (let* ((csr (generate-node-key-and-csr node-name private-key-path))
         (channel (make-node-tls-channel host port :timeout 10 :ca-pin ca-fingerprint)))
    (unwind-protect
         (let* ((stub (gr8s.node.v1::make-enrollment-service-stub channel))
                (request
                  (make-instance
                   'gr8s.node.v1::enroll-request
                   :protocol-version +node-protocol-version+
                   :node-name node-name
                   :join-token token
                   :certificate-request csr)))
           (multiple-value-bind (response status call)
               (gr8s.node.v1::enrollment-service-enroll
                stub request :timeout 10)
             (declare (ignore status call))
             (ensure-node-protocol-version
              (slot-value response 'gr8s.node.v1::protocol-version))
             (let ((certificate
                     (ascii-octets-to-string
                      (slot-value response 'gr8s.node.v1::node-certificate)))
                   (ca-certificate
                     (ascii-octets-to-string
                      (slot-value response 'gr8s.node.v1::ca-certificate))))
               (verify-enrollment-ca-pin ca-certificate ca-fingerprint)
               (write-private-text-atomically certificate-path certificate)
               (write-private-text-atomically ca-certificate-path ca-certificate)
               (slot-value response 'gr8s.node.v1::node-id))))
      (ignore-errors (ag-grpc:channel-close channel)))))

(defun enroll-node-over-endpoints (endpoints node-name token ca-fingerprint
                                   private-key-path certificate-path ca-certificate-path)
  "Enroll NODE-NAME through the first reachable control-plane in ENDPOINTS.
   Each endpoint is (HOST PORT).  Failed attempts retain the generated private
   key and move to the next member; if none succeeds, re-signal the last error."
  (unless endpoints (error "Node enrollment requires at least one control-plane endpoint"))
  (let ((last-error nil))
    (dolist (endpoint endpoints)
      (destructuring-bind (host port) endpoint
        (handler-case
            (return-from enroll-node-over-endpoints
              (enroll-node-over-grpc host port node-name token ca-fingerprint
                                     private-key-path certificate-path ca-certificate-path))
          (error (condition)
            (format *error-output* "gr8s node enrollment through ~A:~D failed: ~A~%"
                    host port condition)
            (setf last-error condition)))))
    (error last-error)))

(defun make-agent-identity (node-name &key (node-id "") (revision 0))
  "A fresh agent-identity hash-table for NODE-NAME holding nodeName, nodeId and
   lastAppliedRevision."
  (let ((identity (make-hash-table :test #'equal)))
    (setf (gethash "nodeName" identity) node-name
          (gethash "nodeId" identity) node-id
          (gethash "lastAppliedRevision" identity) revision)
    identity))

(defun load-agent-identity (path node-name)
  "Load the persisted agent identity at PATH, or a fresh one for NODE-NAME when
   absent. Errors if the stored identity belongs to another node."
  (if (probe-file path)
      (let ((identity (com.inuoe.jzon:parse path)))
        (unless (string= node-name (gethash "nodeName" identity ""))
          (error "Agent identity belongs to node ~S, not ~S"
                 (gethash "nodeName" identity) node-name))
        identity)
      (make-agent-identity node-name)))

(defun persist-agent-identity (path identity)
  "Write IDENTITY to PATH as JSON, atomically and with private permissions."
  (write-private-text-atomically
   path
   (with-output-to-string (stream)
     (com.inuoe.jzon:stringify identity :stream stream))))

(defun require-server-envelope (envelope variant)
  "The payload ENVELOPE carries for VARIANT, after checking its protocol version.
   Errors if ENVELOPE is NIL (the session closed while awaiting VARIANT)."
  (unless envelope
    (error "Node session closed while waiting for ~S" variant))
  (ensure-node-protocol-version
   (slot-value envelope 'gr8s.node.v1::protocol-version))
  (node-envelope-payload envelope variant))

(defstruct (agent-node-session
             (:constructor make-agent-node-session (stream)))
  stream
  (sequence 0)
  (send-lock (bt:make-lock "gr8s agent node session send"))
  ;; The thread reading this session, once other threads may be sending on it.
  ;; It alone sees the window updates a full send waits for, so it never sends itself.
  owner
  (outbox nil)
  (outbox-lock (bt:make-lock "gr8s agent node session outbox"))
  (outbox-changed (bt:make-condition-variable :name "gr8s agent node session outbox"))
  ;; The last complete snapshot received, which the server's next delta changes.
  received)

(defun pod-assignment-sort-key (pod)
  "POD's \"namespace/name\", the stable key agent and server sort assignments by."
  (format nil "~A/~A" (slot-value pod 'gr8s.node.v1::namespace) (slot-value pod 'gr8s.node.v1::name)))

(defun assemble-node-snapshot (session snapshot)
  "Return the complete snapshot SNAPSHOT describes, rebuilding a delta from the last one SESSION received.
A delta that does not follow that snapshot ends the session; the server sends a
complete snapshot to the next one."
  (let ((base-revision (slot-value snapshot 'gr8s.node.v1::base-revision))
        (base (agent-node-session-received session)))
    (setf (agent-node-session-received session)
          (if (zerop base-revision)
              snapshot
              (progn
                (unless (and base (= base-revision (slot-value base 'gr8s.node.v1::revision)))
                  (error "Desired-state delta changes revision ~D, but the session last received ~:[none~;~:*~D~]"
                         base-revision (and base (slot-value base 'gr8s.node.v1::revision))))
                (let ((replaced (make-hash-table :test #'equal)))
                  (dolist (uid (slot-value snapshot 'gr8s.node.v1::removed-pod-uids))
                    (setf (gethash uid replaced) t))
                  (dolist (pod (slot-value snapshot 'gr8s.node.v1::pods))
                    (setf (gethash (slot-value pod 'gr8s.node.v1::uid) replaced) t))
                  (make-instance
                   'gr8s.node.v1::desired-state-snapshot
                   :revision (slot-value snapshot 'gr8s.node.v1::revision)
                   :network (slot-value snapshot 'gr8s.node.v1::network)
                   :routes (slot-value snapshot 'gr8s.node.v1::routes)
                   :service-discovery-objects-json
                   (slot-value (if (slot-value snapshot 'gr8s.node.v1::service-discovery-changed) snapshot base)
                               'gr8s.node.v1::service-discovery-objects-json)
                   ;; The server's own order, so the rebuilt snapshot is the one it holds.
                   :pods (stable-sort
                          (append (remove-if (lambda (pod) (gethash (slot-value pod 'gr8s.node.v1::uid) replaced))
                                             (slot-value base 'gr8s.node.v1::pods))
                                  (copy-list (slot-value snapshot 'gr8s.node.v1::pods)))
                          #'string< :key #'pod-assignment-sort-key))))))))

(defun accept-agent-server-hello (identity identity-path hello)
  "Validate HELLO against the persisted IDENTITY and record its allocation. Errors
   if the server's node id or assigned Pod CIDR changed from what was persisted, if
   the node id is empty, or if the CIDR is invalid. On success persists the node id
   and Pod CIDR to IDENTITY-PATH, even when this reconnect brings no newer snapshot."
  (let ((node-id (slot-value hello 'gr8s.node.v1::node-id))
        (cidr (slot-value hello 'gr8s.node.v1::assigned-pod-cidr))
        (persisted-node-id (gethash "nodeId" identity ""))
        (persisted-cidr (gethash "assignedPodCIDR" identity "")))
    (when (and (plusp (length persisted-node-id))
               (not (string= persisted-node-id node-id)))
      (error "Server node identity changed from ~S to ~S" persisted-node-id node-id))
    (when (zerop (length node-id)) (error "Server assigned an empty node identity"))
    (validate-network-cidr cidr)
    (when (and (plusp (length persisted-cidr)) (not (string= persisted-cidr cidr)))
      (error "Server Pod CIDR changed from ~S to ~S" persisted-cidr cidr))
    ;; Persist the allocation even when this reconnect has no newer snapshot.
    (setf (gethash "nodeId" identity) node-id
          (gethash "assignedPodCIDR" identity) cidr)
    (persist-agent-identity identity-path identity)))

(defun write-agent-session-envelope (session variant payload)
  (bt:with-lock-held ((agent-node-session-send-lock session))
    (ag-grpc:stream-send
     (agent-node-session-stream session)
     (make-agent-envelope
      variant payload :sequence (incf (agent-node-session-sequence session))))))

(defun send-agent-session-envelope (session variant payload)
  "Send on SESSION, leaving it to the outbox if this thread is the one that must keep reading."
  (if (eq (bt:current-thread) (agent-node-session-owner session))
      (bt:with-lock-held ((agent-node-session-outbox-lock session))
        (setf (agent-node-session-outbox session)
              (nconc (agent-node-session-outbox session) (list (cons variant payload))))
        (bt:condition-notify (agent-node-session-outbox-changed session)))
      (write-agent-session-envelope session variant payload)))

(defun run-agent-session-outbox (session finished-p finish-session)
  "Send what the session's reading thread has left, in order, until the session finishes."
  (handler-case
      (loop
        (let ((entry (bt:with-lock-held ((agent-node-session-outbox-lock session))
                       (loop until (or (agent-node-session-outbox session) (funcall finished-p))
                             do (bt:condition-wait (agent-node-session-outbox-changed session)
                                                   (agent-node-session-outbox-lock session) :timeout 0.2))
                       (pop (agent-node-session-outbox session)))))
          (unless entry (return))
          (write-agent-session-envelope session (car entry) (cdr entry))))
    (error (condition)
      (format *error-output* "gr8s node session send failed: ~A~%" condition)
      (funcall finish-session))))

(defun wake-agent-session-senders (channel)
  "End CHANNEL's connection for senders waiting on its flow control, which nothing else wakes."
  (let ((connection (ag-grpc:channel-connection channel)))
    (when connection
      (setf (ag-http2:connection-state connection) :closed)
      (bt2:with-lock-held ((ag-http2::connection-flow-control-lock connection))
        (bt2:condition-broadcast (ag-http2::connection-flow-control-cv connection))))))

(defun close-agent-session-connection (channel)
  "Close CHANNEL's connection but leave it on the channel while the session unwinds.
AG-GRPC:CHANNEL-CLOSE forgets it, and the reading thread's next read then fails with no
applicable method for NIL rather than finding a closed connection."
  (let ((connection (ag-grpc:channel-connection channel)))
    (when connection (ag-http2:connection-close connection))))

(defun validate-node-snapshot-identity (identity snapshot)
  "Reject another node allocation before an arrival observer can persist any deletion intent."
  (let ((network (slot-value snapshot 'gr8s.node.v1::network))
        (assigned (gethash "assignedPodCIDR" identity)))
    (when (and network assigned
               (not (string= assigned (slot-value network 'gr8s.node.v1::node-pod-cidr))))
      (error "Snapshot Pod CIDR does not match the durable node allocation"))))

(defun apply-node-snapshot-and-respond
    (session identity identity-path snapshot apply-snapshot &key replay)
  "Apply SNAPSHOT when its revision is newer than the last applied (or equal, when
   REPLAY), persist the new lastAppliedRevision BEFORE acking so a crash never acks
   unpersisted work, send any Pod statuses APPLY-SNAPSHOT returned, and always send a
   snapshot-ack for the revision. Rejects a snapshot whose Pod CIDR contradicts the
   durable node allocation."
  (let ((revision (slot-value snapshot 'gr8s.node.v1::revision))
        (last-applied (gethash "lastAppliedRevision" identity 0))
        (statuses nil))
    (validate-node-snapshot-identity identity snapshot)
    (when (or (> revision last-applied) (and replay (= revision last-applied)))
      ;; A restarted agent can have completed deletion after its last durable
      ;; snapshot ack but before the final status reached the server. Reapply
      ;; the authoritative initial snapshot to rebuild that acknowledgement;
      ;; ordinary duplicate envelopes within a session still remain no-ops.
      (let ((result (funcall apply-snapshot snapshot)))
        ;; Snapshot applicators written before status reporting commonly
        ;; return an incidental value. Only an explicit status list is sent.
        (when (and (listp result)
                   (every (lambda (status)
                            (typep status
                                   'gr8s.node.v1::pod-observed-status))
                          result))
          (setf statuses result)))
      (setf (gethash "lastAppliedRevision" identity) revision)
      ;; Durable state precedes the ack: after a crash, the agent may repeat
      ;; an ack but never claims work it did not persist.
      (persist-agent-identity identity-path identity))
    (when statuses
      (send-agent-session-envelope
       session :status
       (make-instance 'gr8s.node.v1::node-status :pods statuses)))
    (send-agent-session-envelope
     session :snapshot-ack
     (make-instance 'gr8s.node.v1::snapshot-ack
                    :revision revision :applied t))))

(defun handle-node-server-envelope
    (session envelope identity identity-path apply-snapshot operation-handler &optional snapshot-worker)
  "Agent-side dispatch of one server ENVELOPE after a protocol-version check: a
   desired-state is assembled (a delta rebuilt against the last snapshot) and either
   queued to SNAPSHOT-WORKER or applied inline; an operation request/input/cancel is
   handed to OPERATION-HANDLER with a reply sink; a protocol-error is raised. Errors
   on any other payload, or on an operation payload without a handler."
  (ensure-node-protocol-version
   (slot-value envelope 'gr8s.node.v1::protocol-version))
  (case (slot-value envelope 'gr8s.node.v1::payload-case)
    (:desired-state
     (let ((snapshot (assemble-node-snapshot session (slot-value envelope 'gr8s.node.v1::desired-state))))
       (if snapshot-worker
           (queue-agent-snapshot-work snapshot-worker snapshot)
           (apply-node-snapshot-and-respond session identity identity-path snapshot apply-snapshot))))
    ((:operation-request :operation-input :operation-cancel)
     (unless operation-handler
       (error "Agent has no operation handler"))
     (let ((variant (slot-value envelope 'gr8s.node.v1::payload-case)))
       (funcall
        operation-handler variant
        (slot-value envelope (find-symbol (symbol-name variant) :gr8s.node.v1))
        (lambda (reply-variant reply-payload)
          (send-agent-session-envelope session reply-variant reply-payload)))))
    (:protocol-error
     (error "Node server rejected the session: ~A"
            (slot-value
             (slot-value envelope 'gr8s.node.v1::protocol-error)
             'gr8s.node.v1::message)))
    (otherwise
     (error "Unexpected server payload ~S"
            (slot-value envelope 'gr8s.node.v1::payload-case)))))

(defstruct (node-session-control
             (:constructor %make-node-session-control))
  context
  cancel-function
  (lock (bt:make-lock "gr8s node session cancellation")))

(defun make-node-session-control ()
  "A NODE-SESSION-CONTROL wrapping a fresh cancellable context, for cancelling a
   running node session."
  (multiple-value-bind (context cancel-function)
      (cl-cancel:with-cancel (cl-cancel:background))
    (%make-node-session-control
     :context context :cancel-function cancel-function)))

(defun cancel-node-session (control)
  "Cancel CONTROL's session, calling its cancel function once and clearing it so a
   repeat call is a no-op. Returns NIL."
  (let ((cancel-function nil))
    (bt:with-lock-held ((node-session-control-lock control))
      (setf cancel-function (node-session-control-cancel-function control)
            (node-session-control-cancel-function control) nil))
    (when cancel-function
      (funcall cancel-function)))
  nil)

(defun node-session-cancelled-p (control)
  "Whether CONTROL's session has been cancelled."
  (cl-cancel:done-p (node-session-control-context control)))

(defvar *node-session-interruption-tag* nil
  "The catch tag of the WITH-NODE-SESSION-INTERRUPTION this thread is inside, if any.")

(defmacro with-node-session-interruption ((tag) &body body)
  "Run BODY, returning :INTERRUPTED if INTERRUPT-NODE-SESSION-THREAD unwinds it.
The binding sits inside the CATCH, so a thread that sees TAG bound still has the
catch to throw to."
  (let ((value (gensym "TAG")))
    `(let ((,value ,tag))
       (catch ,value
         (let ((*node-session-interruption-tag* ,value))
           ,@body)))))

(defun interrupt-node-session-thread (thread tag)
  "Unwind THREAD out of its WITH-NODE-SESSION-INTERRUPTION of TAG. A thread that has
left it ignores this, so its cleanup outside runs to completion.
Throw instead of signalling: the target may already be inside %SIGNAL for another
error, where SBCL has rebound the handler clusters and an ERROR finds no handler
and kills the thread. A throw also passes runtime wrappers that handle errors."
  (when (and thread (bt:thread-alive-p thread))
    (ignore-errors
      (bt:interrupt-thread
       thread
       (lambda ()
         (when (eq *node-session-interruption-tag* tag)
           (throw tag :interrupted)))))))

(defun agent-session-status-reporter (session heartbeat-interval finished-p status-provider tag)
  "Report status on its own thread: a slow provider must not delay the heartbeat."
  (with-node-session-interruption (tag)
    (loop until (funcall finished-p)
          do (handler-case
                 (let ((status (funcall status-provider)))
                   (when status
                     (unless (typep status 'gr8s.node.v1::node-status)
                       (error "node status provider returned an invalid message"))
                     (send-agent-session-envelope session :status status)))
               (error (condition)
                 (format *error-output* "gr8s status reporting failed: ~A~%" condition)))
             (let ((deadline (+ (get-internal-real-time)
                                (* (funcall heartbeat-interval) internal-time-units-per-second))))
               (loop until (or (funcall finished-p) (>= (get-internal-real-time) deadline))
                     do (sleep 0.05))))))

(defun agent-session-watchdog (finished-p last-progress on-stall)
  "Call ON-STALL once LAST-PROGRESS, in internal time, is too long ago."
  (loop until (funcall finished-p)
        do (when (> (- (get-internal-real-time) (funcall last-progress))
                    (* *node-session-stall-seconds* internal-time-units-per-second))
             (funcall on-stall)
             (return))
           (sleep 0.25)))

(defun agent-runtime-health (runtime-health)
  "Return why the node's runtime is down, as RUNTIME-HEALTH reports, or the empty string."
  (or (and runtime-health (ignore-errors (funcall runtime-health))) ""))

(defun agent-heartbeat (runtime-health &optional (message (agent-runtime-health runtime-health)))
  "Return a heartbeat carrying MESSAGE, why the node's runtime is down."
  (make-instance 'gr8s.node.v1::heartbeat :runtime-down-message message))

(defun agent-session-monitor
    (session control session-thread heartbeat-interval
     stop-predicate finished-p finish-session note-progress tag &optional runtime-health)
  "The agent's heartbeat-and-cancellation loop, on its own thread: until FINISHED-P,
   send a heartbeat each HEARTBEAT-INTERVAL (or at once when runtime health changes)
   and NOTE-PROGRESS; on cancellation or STOP-PREDICATE, cancel the session, finish
   it, and interrupt the owning SESSION-THREAD so it unwinds through normal gRPC
   cleanup. Always finishes the session on exit."
  (let ((next-heartbeat
          (+ (get-internal-real-time)
             (* (funcall heartbeat-interval) internal-time-units-per-second)))
        (reported-health (agent-runtime-health runtime-health)))
    (handler-case
        (with-node-session-interruption (tag)
          (loop until (funcall finished-p)
                do (when (or (node-session-cancelled-p control)
                             (funcall stop-predicate))
                     (cancel-node-session control)
                     (funcall finish-session)
                     ;; POSIX does not require close(2) or shutdown(2) in one
                     ;; thread to wake another thread already blocked in poll(2).
                     ;; Interrupt the owner so it unwinds through the ordinary
                     ;; gRPC cleanup path instead of destroying the thread.
                     (interrupt-node-session-thread session-thread tag)
                     (return))
                   ;; A runtime outage or recovery is reported at once, not at the next beat.
                   (when (or (>= (get-internal-real-time) next-heartbeat)
                             (not (equal reported-health (agent-runtime-health runtime-health))))
                     (setf reported-health (agent-runtime-health runtime-health))
                     (send-agent-session-envelope
                      session :heartbeat (agent-heartbeat runtime-health reported-health))
                     (funcall note-progress)
                     (setf next-heartbeat
                           (+ (get-internal-real-time)
                              (* (funcall heartbeat-interval)
                                 internal-time-units-per-second))))
                   (sleep 0.05)))
      (error (condition)
        (format *error-output* "gr8s node session heartbeat failed: ~A~%" condition)))
    (funcall finish-session)))

(defstruct (agent-snapshot-worker (:constructor %make-agent-snapshot-worker))
  "Apply snapshots serially while the session owner continues receiving operations."
  function
  receive-snapshot
  finish-session
  thread
  pending
  (highest-revision -1)
  replay-revision
  failure
  stopping-p
  started-p
  (lock (bt:make-lock "gr8s snapshot work"))
  (changed (bt:make-condition-variable :name "gr8s snapshot work changed")))

(defun retry-agent-snapshot-work (worker work &key (delay .1))
  "Retry an incomplete latest projection without growing a queue or acknowledging it."
  (bt:with-lock-held ((agent-snapshot-worker-lock worker))
    (when (and (not (agent-snapshot-worker-stopping-p worker))
               (null (agent-snapshot-worker-pending worker))
               (= (slot-value (car work) 'gr8s.node.v1::revision)
                  (agent-snapshot-worker-highest-revision worker)))
      (setf (agent-snapshot-worker-pending worker) (list work))
      ;; Async runtime deletion needs a later observation before admission can
      ;; resume. Yield instead of spinning; new snapshots and stop wake us.
      (bt:condition-wait (agent-snapshot-worker-changed worker)
                         (agent-snapshot-worker-lock worker) :timeout delay))))

(defun run-agent-snapshot-work (worker)
  "Apply ordered work and close the session on failure without acknowledging pending revisions."
  (with-node-session-interruption (worker)
    ;; Readiness is signalled only after the stop catch is established. It also
    ;; covers the application error handler below.
    (bt:with-lock-held ((agent-snapshot-worker-lock worker))
      (setf (agent-snapshot-worker-started-p worker) t)
      (bt:condition-notify (agent-snapshot-worker-changed worker)))
    (handler-case
        (loop
          (let ((work
                  (bt:with-lock-held ((agent-snapshot-worker-lock worker))
                    (loop while (and (null (agent-snapshot-worker-pending worker))
                                     (not (agent-snapshot-worker-stopping-p worker)))
                          do (bt:condition-wait (agent-snapshot-worker-changed worker)
                                               (agent-snapshot-worker-lock worker)))
                    (when (agent-snapshot-worker-stopping-p worker)
                      (return-from run-agent-snapshot-work nil))
                    (pop (agent-snapshot-worker-pending worker)))))
            (handler-case
                (progn
                  (funcall (agent-snapshot-worker-function worker) (car work) (cdr work))
                  (bt:with-lock-held ((agent-snapshot-worker-lock worker))
                    (when (eql (slot-value (car work) 'gr8s.node.v1::revision)
                               (agent-snapshot-worker-replay-revision worker))
                      (setf (agent-snapshot-worker-replay-revision worker) nil))))
              ;; Durable urgent intent superseded this application.
              ;; Its revision was not applied and must not be acked.
              (pod-reconciliation-superseded () (retry-agent-snapshot-work worker work))
              ;; The other Pods were applied. Waiting on one Pod's runtime
              ;; isn't a reason to end a session they all depend on.
              (node-snapshot-incomplete () (retry-agent-snapshot-work worker work :delay 1)))))
      (error (condition)
        (format *error-output* "gr8s node snapshot application failed: ~A~%" condition)
        (bt:with-lock-held ((agent-snapshot-worker-lock worker))
          (setf (agent-snapshot-worker-failure worker) condition
                (agent-snapshot-worker-stopping-p worker) t
                (agent-snapshot-worker-pending worker) nil))
        (funcall (agent-snapshot-worker-finish-session worker))))))

(defun start-agent-snapshot-worker (function finish-session &key receive-snapshot)
  "Start a session-owned ordered snapshot executor."
  (let ((worker (%make-agent-snapshot-worker :function function :finish-session finish-session
                                             :receive-snapshot receive-snapshot))
        (ready nil))
    (unwind-protect
         (progn
           (flet ((spawn ()
                    (setf (agent-snapshot-worker-thread worker)
                          (bt:make-thread (lambda () (run-agent-snapshot-work worker))
                                          :name "gr8s agent snapshot work"))))
             ;; The session monitor can cancel this owner at any instruction.
             ;; Retain the created thread handle before delivering that signal.
             #+sbcl (sb-sys:without-interrupts (spawn))
             #-sbcl (spawn))
           (bt:with-lock-held ((agent-snapshot-worker-lock worker))
             (loop until (agent-snapshot-worker-started-p worker)
                   do (bt:condition-wait (agent-snapshot-worker-changed worker)
                                        (agent-snapshot-worker-lock worker))))
           (setf ready t)
           worker)
      (unless ready (stop-agent-snapshot-worker worker)))))

(defun queue-agent-snapshot-work (worker snapshot &key replay)
  "Retain only the newest unapplied full snapshot; skipped revisions are never acknowledged."
  (let ((revision (slot-value snapshot 'gr8s.node.v1::revision)))
    (bt:with-lock-held ((agent-snapshot-worker-lock worker))
      (unless (or (agent-snapshot-worker-stopping-p worker)
                  (< revision (agent-snapshot-worker-highest-revision worker)))
        (when (agent-snapshot-worker-receive-snapshot worker)
          (funcall (agent-snapshot-worker-receive-snapshot worker) snapshot))
        ;; Every envelope is a complete projection. An intermediate queued
        ;; projection has no independent effect to preserve. Keep the current
        ;; application ordered, and replace only work which has not started.
        (when replay (setf (agent-snapshot-worker-replay-revision worker) revision))
        (setf (agent-snapshot-worker-highest-revision worker) revision
              (agent-snapshot-worker-pending worker)
              (list (cons snapshot (or replay (eql revision (agent-snapshot-worker-replay-revision worker))))))
        (bt:condition-notify (agent-snapshot-worker-changed worker)))))
  worker)

(defun stop-agent-snapshot-worker (worker)
  "Cancel and join application before a disconnected session can be replaced."
  (when worker
    (let ((started-p nil)
          (thread (agent-snapshot-worker-thread worker)))
      (bt:with-lock-held ((agent-snapshot-worker-lock worker))
        (setf (agent-snapshot-worker-stopping-p worker) t
              (agent-snapshot-worker-pending worker) nil
              started-p (agent-snapshot-worker-started-p worker))
        (bt:condition-notify (agent-snapshot-worker-changed worker)))
      (when (and thread (not (eq thread (bt:current-thread))))
        (when started-p
          ;; Runtime wrappers catch ERROR and translate it to Pending. This must
          ;; unwind the whole application so shutdown cannot continue to another
          ;; blocked Pod or persist an ack.
          (interrupt-node-session-thread thread worker))
        (bt:join-thread thread))))
  nil)

(defun loopback-host-p (host)
  "Return whether HOST names this machine's loopback interface."
  (or (member host '("localhost" "::1") :test #'string-equal)
      (uiop:string-prefix-p "127." host)))

(defun node-channel-underlay-address (channel)
  "CHANNEL's local IPv4 address in canonical underlay form, or \"\" when it is a
   loopback or non-IPv4 socket (so the server does not learn a useless address)."
  (let* ((connection (ag-grpc::channel-connection channel))
         (socket (ag-http2::connection-socket connection))
         (address (usocket:get-local-address socket)))
    (if (and (= 4 (length address)) (/= 127 (aref address 0)))
        (canonical-node-underlay-address (format nil "~{~D~^.~}" (coerce address 'list)))
        "")))

(defun run-one-node-session
    (host port node-name identity-path apply-snapshot operation-handler
     one-shot-p control stop-predicate underlay-address status-provider
     ca-certificate-path certificate-path private-key-path &optional snapshot-observer (kubelet-port 0)
                                                                     runtime-health)
  "Run one agent session to the control plane at HOST:PORT from connect to close:
   dial (TLS when a CA path is given), send the hello and first heartbeat, perform
   the ServerHello handshake, then apply the initial and subsequent snapshots in
   revision order (inline in ONE-SHOT-P mode, else on a snapshot worker) and dispatch
   operations until the stream ends or CONTROL/STOP-PREDICATE fire. Spawns and tears
   down the heartbeat, status, watchdog and outbox threads. Returns :INTERRUPTED when
   unwound by cancellation, otherwise NIL."
  (let* ((identity (load-agent-identity identity-path node-name))
         (session-thread (bt:current-thread))
         (session-timeout (and one-shot-p 5))
         (channel (if ca-certificate-path
                      (make-node-tls-channel host port :timeout session-timeout
                                             :ca-certificate-path ca-certificate-path
                                             :certificate-path certificate-path
                                             :private-key-path private-key-path)
                      (ag-grpc:make-channel host port :timeout session-timeout)))
         (monitor-thread nil)
         (status-thread nil)
         (watchdog-thread nil)
         (outbox-thread nil)
         (snapshot-worker nil)
         (heartbeat-interval 1)
         (operation-session-p nil)
         (session-finished-p nil)
         (session-tag (list :node-session))
         (last-progress (get-internal-real-time))
         (finish-lock (bt:make-lock "gr8s agent node session finish")))
    (labels ((recover-stalled-session ()
               (log-node-session-stall "no heartbeat sent to ~A:~A; reconnecting" host port)
               (finish-session)
               ;; Closing does not reliably wake a thread already in poll(2) or a
               ;; blocking write. Cleanup itself must run to completion, so it
               ;; runs outside the owner's interruption scope.
               (interrupt-node-session-thread monitor-thread session-tag)
               (interrupt-node-session-thread status-thread session-tag)
               (interrupt-node-session-thread session-thread session-tag))
             (finished-p ()
               (bt:with-lock-held (finish-lock) session-finished-p))
             (finish-session ()
               (let ((close-p nil))
                 (bt:with-lock-held (finish-lock)
                   (unless session-finished-p
                     (setf session-finished-p t
                           close-p t)))
                 (when close-p
                   (ignore-errors (close-agent-session-connection channel))
                   (ignore-errors (wake-agent-session-senders channel))
                   ;; Closing does not wake the owner from poll(2), and while it sits
                   ;; there the kernel holds the socket open, so the peer sees nothing
                   ;; and nothing else ends the session until the server's idle timeout.
                   (unless (eq (bt:current-thread) session-thread)
                     (interrupt-node-session-thread session-thread session-tag))))))
    (cl-cancel:with-cancellable
        (session-context (node-session-control-context control))
      (declare (ignore session-context))
      (unwind-protect
         (with-node-session-interruption (session-tag)
           (let* ((stub (gr8s.node.v1::make-node-service-stub channel))
                  (stream (let ((ag-grpc::*grpc-accept-encoding*
                                  ;; Compressing what never leaves the host only costs CPU.
                                  (if (loopback-host-p host) "identity" ag-grpc::*grpc-accept-encoding*)))
                            (gr8s.node.v1::node-service-connect
                             stub :timeout session-timeout)))
                  (session (make-agent-node-session stream)))
             (send-agent-session-envelope
              session :hello
               (make-instance 'gr8s.node.v1::node-hello
                              :node-name node-name
                              :boot-id (generate-uid)
                              :agent-version "gr8s"
                              :underlay-address
                              (or underlay-address (node-channel-underlay-address channel))
                              :capabilities (list +desired-state-delta-capability+)
                              :capacity (node-reported-capacity-entries)
                              :kubelet-port kubelet-port
                              :last-applied-revision
                              (gethash "lastAppliedRevision" identity 0)))
             (send-agent-session-envelope
              session :heartbeat (agent-heartbeat runtime-health))
             ;; Cancellation must also cover a peer that stalls before its
             ;; ServerHello, not only sessions that finished the handshake.
             (unless one-shot-p
               ;; From here this thread reads, and a sender short of flow-control window
               ;; waits for what it reads. A sender reading too would race it for frames.
               (setf (ag-http2:connection-reader-thread-active-p (ag-grpc:channel-connection channel)) t
                     (agent-node-session-owner session) session-thread
                     outbox-thread
                     (bt:make-thread
                      (lambda () (run-agent-session-outbox session #'finished-p #'finish-session))
                      :name "gr8s agent session outbox"))
               (setf monitor-thread
                     (bt:make-thread
                      (lambda ()
                        (agent-session-monitor
                         session control session-thread
                         (lambda () heartbeat-interval)
                         stop-predicate #'finished-p #'finish-session
                         (lambda () (setf last-progress (get-internal-real-time)))
                         session-tag runtime-health))
                      :name "gr8s agent session heartbeat"))
               (when status-provider
                 (setf status-thread
                       (bt:make-thread
                        (lambda ()
                          (agent-session-status-reporter
                           session (lambda () heartbeat-interval) #'finished-p
                           (lambda () (when operation-session-p (funcall status-provider)))
                           session-tag))
                        :name "gr8s agent session status")))
               (setf watchdog-thread
                     (bt:make-thread
                      (lambda ()
                        (agent-session-watchdog
                         #'finished-p (lambda () last-progress) #'recover-stalled-session))
                      :name "gr8s agent session watchdog")))
             (let ((server-hello
                     (require-server-envelope
                      (ag-grpc:stream-read-message stream) :hello)))
               (accept-agent-server-hello identity identity-path server-hello)
               (setf heartbeat-interval
                     (max 1 (slot-value server-hello
                                        'gr8s.node.v1::heartbeat-interval-seconds)))
               (let* ((snapshot
                        (assemble-node-snapshot
                         session
                         (require-server-envelope
                          (ag-grpc:stream-read-message stream) :desired-state))))
                 (if one-shot-p
                     (progn
                       (validate-node-snapshot-identity identity snapshot)
                       (when snapshot-observer (funcall snapshot-observer snapshot))
                       (apply-node-snapshot-and-respond
                        session identity identity-path snapshot apply-snapshot :replay t)
                       (setf operation-session-p t)
                       (ag-grpc:stream-close-send stream)
                       (loop while (ag-grpc:stream-read-message stream)))
                     (progn
                       (setf snapshot-worker
                             (start-agent-snapshot-worker
                              (lambda (snapshot replay)
                                (apply-node-snapshot-and-respond
                                 session identity identity-path snapshot apply-snapshot :replay replay))
                              #'finish-session
                              :receive-snapshot
                              (lambda (snapshot)
                                (validate-node-snapshot-identity identity snapshot)
                                (when snapshot-observer (funcall snapshot-observer snapshot)))))
                       (queue-agent-snapshot-work snapshot-worker snapshot :replay t)
                       (setf operation-session-p t)
                       (loop for envelope = (ag-grpc:stream-read-message stream)
                             while envelope
                             do (handle-node-server-envelope
                                 session envelope identity identity-path
                                 apply-snapshot operation-handler snapshot-worker))))))))
      (finish-session)
      (stop-agent-snapshot-worker snapshot-worker)
      (when (and operation-session-p operation-handler)
        ;; Operation emitters close over this gRPC session.  Give the agent a
        ;; lifecycle edge on every disconnect so it can close upstream
        ;; streams without trying to reply through a dead callback.
        (ignore-errors
          (funcall operation-handler :session-closed nil nil)))
      (when monitor-thread
        (ignore-errors (bt:join-thread monitor-thread)))
      (when outbox-thread
        (ignore-errors (bt:join-thread outbox-thread)))
      ;; The status thread is not joined: a provider blocked on a runtime lock
      ;; must not hold up the replacement session. It exits once it returns.
      (when watchdog-thread
        (ignore-errors (bt:join-thread watchdog-thread)))
      (ignore-errors (ag-grpc:channel-close channel)))))))

(defun run-node-session (host port node-name identity-path apply-snapshot
                         &key max-sessions (reconnect-delay 1) endpoints
                           operation-handler underlay-address status-provider snapshot-observer
                           ca-certificate-path certificate-path private-key-path
                           control (kubelet-port 0) runtime-health
                           (stop-predicate (constantly nil)))
  "Maintain the agent's session to the control plane, reconnecting on loss. With
   ENDPOINTS (a list of (host port)) the agent rotates through the control-plane
   members on each reconnect, so it finds the new leader after an HA failover
   (podster-c2d.7.4); without it, it reconnects to HOST:PORT as before."
  (let* ((completed 0)
         (control (or control (make-node-session-control)))
         (targets (or endpoints (list (list host port))))
         (attempt 0))
    (loop until (or (node-session-cancelled-p control)
                    (funcall stop-predicate))
          do (destructuring-bind (try-host try-port)
                 (nth (mod attempt (length targets)) targets)
               (handler-case
                   ;; An interrupted session was abandoned, so it does not count.
                   (if (eq :interrupted
                           (run-one-node-session try-host try-port node-name identity-path
                                                 apply-snapshot operation-handler
                                                 (not (null max-sessions)) control stop-predicate
                                                 underlay-address status-provider
                                                 ca-certificate-path certificate-path private-key-path
                                                 snapshot-observer kubelet-port runtime-health))
                       (unless (or (node-session-cancelled-p control) (funcall stop-predicate))
                         (format *error-output* "gr8s node session to ~A:~A ended; reconnecting~%"
                                 try-host try-port))
                       (progn
                         (incf completed)
                         (when (and max-sessions (>= completed max-sessions))
                           (return completed))))
                 (error (condition)
                   (when max-sessions
                     (error condition))
                   (unless (node-session-cancelled-p control)
                     (format *error-output* "gr8s node session to ~A:~A ended: ~A; reconnecting~%"
                             try-host try-port condition))))
               (incf attempt)
               (unless (or (node-session-cancelled-p control)
                           (funcall stop-predicate))
                 (sleep reconnect-delay))))
    completed))
