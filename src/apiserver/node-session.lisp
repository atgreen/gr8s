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

(in-package #:gr8s.apiserver)

(defstruct (node-grpc-server
             (:constructor %make-node-grpc-server
                 (&key store grpc-server thread port heartbeat-timeout-seconds
                       pki cluster-pod-cidr node-prefix cluster-pod-cidrs node-prefixes overlay-backend
                       wireguard-listen-port image-tracker)))
  store
  grpc-server
  thread
  port
  heartbeat-timeout-seconds
  pki
  cluster-pod-cidr
  node-prefix
  cluster-pod-cidrs
  node-prefixes
  (overlay-backend "vxlan")
  (wireguard-listen-port 51820)
  (image-tracker (gr8s.image-distribution::make-image-tracker))
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
   A remote send gets one retry so a relay connection dropped between operation
   frames can be replaced. On a send failure, finishes the operation with the error
   and re-signals it.
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
                         (loop repeat 2
                               thereis
                               (and (eq operation (find-node-operation server operation-id))
                                    (not (pending-node-operation-done-p operation))
                                    (funcall router variant remote
                                             (pending-node-operation-node-name operation)
                                             payload))))
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
                   :cluster-pod-cidrs (copy-list (node-grpc-server-cluster-pod-cidrs server))
                   :node-pod-cidrs (coerce (node-record-all-pod-cidrs node) 'list)
                   :dns-address +dns-pod-server-address+
                   :underlay-address (node-record-underlay-address node)
                   :overlay-backend (node-grpc-server-overlay-backend server)
                   :wireguard-listen-port
                   (if (string= "wireguard" (node-grpc-server-overlay-backend server))
                       (node-grpc-server-wireguard-listen-port server)
                       0)
                   :vni 42
                   :mtu (if (string= "wireguard"
                                    (node-grpc-server-overlay-backend server))
                            1420 1450))))

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
                   (string= "" (node-record-pod-cidr node))
                   (and (string= "wireguard" (node-grpc-server-overlay-backend server))
                        (/= 32 (length (node-record-wireguard-public-key node)))))
          collect (make-instance 'gr8s.node.v1::node-route
                                 :node-id (node-record-id node)
                                 :pod-cidr (node-record-pod-cidr node)
                                 :pod-cidrs (coerce (node-record-all-pod-cidrs node) 'list)
                                 :underlay-address (node-record-underlay-address node)
                                 :wireguard-public-key
                                 (if (string= "wireguard" (node-grpc-server-overlay-backend server))
                                     (node-record-wireguard-public-key node)
                                     #())
                                 :wireguard-listen-port
                                 (if (string= "wireguard" (node-grpc-server-overlay-backend server))
                                     (node-grpc-server-wireguard-listen-port server)
                                     0))))

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

(defun credential-token-response (store node-name request)
  "Mint the credential-provider token REQUEST after binding it to NODE-NAME's exact Pod."
  (let* ((namespace (slot-value request 'gr8s.node.v1::namespace))
         (pod-name (slot-value request 'gr8s.node.v1::pod-name))
         (pod (get-pod store namespace pod-name))
         (pod-object (pod-to-object pod))
         (service-account-name (slot-value request 'gr8s.node.v1::service-account-name)))
    (unless (and (equal node-name (pod-node-name pod))
                 (equal (pod-uid pod) (slot-value request 'gr8s.node.v1::pod-uid)))
      (error "Credential token request does not name this node's exact Pod"))
    (unless (equal service-account-name
                   (gethash "serviceAccountName" (gethash "spec" pod-object) "default"))
      (error "Credential token request names another ServiceAccount"))
    (let* ((account (get-core-resource store "serviceaccounts" namespace service-account-name))
           (metadata (gethash "metadata" account))
           (source (gethash "annotations" metadata (core-object)))
           (annotations (core-object)))
      (dolist (key (slot-value request 'gr8s.node.v1::required-annotation-keys))
        (multiple-value-bind (value present) (gethash key source)
          (unless present (error "Required ServiceAccount annotation ~A is absent" key))
          (setf (gethash key annotations) value)))
      (dolist (key (slot-value request 'gr8s.node.v1::optional-annotation-keys))
        (multiple-value-bind (value present) (gethash key source)
          (when present (setf (gethash key annotations) value))))
      (multiple-value-bind (token expiry)
          (mint-service-account-token
           store account :audiences (list (slot-value request 'gr8s.node.v1::audience))
           :binding (list "pod" (pod-name pod) (pod-uid pod)))
        (declare (ignore expiry))
        (make-instance
         'gr8s.node.v1::credential-token-response
         :request-id (slot-value request 'gr8s.node.v1::request-id)
         :token token :service-account-annotations annotations
         :service-account-uid (gethash "uid" metadata))))))

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
    (:credential-token-request
     (let* ((request (slot-value envelope 'gr8s.node.v1::credential-token-request))
            (response
              (handler-case
                  (credential-token-response (node-grpc-server-store server) node-name request)
                (error (condition)
                  (make-instance
                   'gr8s.node.v1::credential-token-response
                   :request-id (slot-value request 'gr8s.node.v1::request-id)
                   :error-message (princ-to-string condition))))))
       (bt:with-lock-held ((node-grpc-server-lock server))
         (let ((session (gethash node-name (node-grpc-server-sessions server))))
           (when session
             (send-node-agent-envelope
              session (make-server-envelope :credential-token-response response :sequence 0)))))))
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
           (wireguard-public-key
             (slot-value hello 'gr8s.node.v1::wireguard-public-key))
           (node (get-node (node-grpc-server-store server) node-name))
           (topology-changed
             (progn
               ;; Validate before either durable write so a malformed hello
               ;; cannot partially change this authenticated node's topology.
               (unless (or (zerop (length wireguard-public-key))
                           (= 32 (length wireguard-public-key)))
                 (error "WireGuard public keys must be empty or exactly 32 bytes"))
               (when (and (string= "wireguard" (node-grpc-server-overlay-backend server))
                          (zerop (length wireguard-public-key)))
                 (error "WireGuard overlay requires a node public key"))
               (let ((address-changed
                       (update-node-underlay-address
                        (node-grpc-server-store server) node-name
                        (slot-value hello 'gr8s.node.v1::underlay-address)))
                     (key-changed
                       (update-node-wireguard-public-key
                        (node-grpc-server-store server) node-name
                        wireguard-public-key)))
                 (or address-changed key-changed))))
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
                                               :assigned-pod-cidr (node-record-pod-cidr node)
                                               :assigned-pod-cidrs
                                               (coerce (node-record-all-pod-cidrs node) 'list))
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
                                     (node-grpc-server-cluster-pod-cidrs server)
                                     (node-grpc-server-node-prefixes server)
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
                       (let ((pod-cidrs
                               (allocate-node-pod-cidrs
                                store
                                (node-grpc-server-cluster-pod-cidrs server)
                                (node-grpc-server-node-prefixes server))))
                         (register-node
                          store
                          (make-node-record
                           :id (generate-uid) :name node-name
                           :pod-cidr (aref pod-cidrs 0) :pod-cidrs pod-cidrs))))))))
      (make-instance
       'gr8s.node.v1::enroll-response
       :protocol-version +node-protocol-version+
       :node-id (node-record-id node)
       :node-certificate (pki-ascii-octets certificate)
       :ca-certificate
       (pki-ascii-octets
        (uiop:read-file-string (cluster-pki-ca-certificate-path pki)))))))

(defun image-tracker-peer-message (peer)
  (make-instance
   'gr8s.node.v1::image-tracker-peer
   :node-name (gr8s.image-distribution::tracker-peer-node-name peer)
   :address (gr8s.image-distribution::tracker-peer-address peer)
   :port (gr8s.image-distribution::tracker-peer-port peer)
   :peer-id (gr8s.image-distribution::tracker-peer-peer-id peer)
   :complete (gr8s.image-distribution::tracker-peer-complete-p peer)))

(defun image-tracker-view-response (view)
  (make-instance
   'gr8s.node.v1::image-tracker-response
   :status (string-downcase
            (symbol-name (gr8s.image-distribution::tracker-view-status view)))
   :expires-at (or (gr8s.image-distribution::tracker-view-origin-expires-at view) 0)
   :metainfo (or (gr8s.image-distribution::tracker-view-metainfo view) #())
   :infohash (or (gr8s.image-distribution::tracker-view-infohash view) #())
   :peers (mapcar #'image-tracker-peer-message
                  (gr8s.image-distribution::tracker-view-peers view))))

(defun handle-image-tracker-request (server request context)
  "Execute one tracker operation for the node identity authenticated by mTLS."
  (let* ((node-name (slot-value request 'gr8s.node.v1::node-name))
         (tracker (node-grpc-server-image-tracker server))
         (digest (slot-value request 'gr8s.node.v1::digest)))
    ;; This is deliberately before dispatch: no tracker state is observable or
    ;; mutable until the claimed node name matches the client certificate.
    (authenticate-node-peer (node-grpc-server-pki server) context node-name)
    (flet ((response (status &key token expires-at infohash)
             (make-instance 'gr8s.node.v1::image-tracker-response
                            :status status :lease-token (or token #())
                            :expires-at (or expires-at 0)
                            :infohash (or infohash #()))))
      (let ((action (slot-value request 'gr8s.node.v1::action)))
        (cond
          ((string= action "lookup")
           (image-tracker-view-response
            (gr8s.image-distribution::tracker-lookup tracker digest node-name)))
          ((string= action "acquire")
           (multiple-value-bind (status token expires-at owner)
               (gr8s.image-distribution::tracker-acquire-origin
                tracker digest node-name)
             (declare (ignore owner))
             (response (string-downcase (symbol-name status))
                       :token token :expires-at expires-at)))
          ((string= action "renew")
           (response
            "ok" :expires-at
            (gr8s.image-distribution::tracker-renew-origin
             tracker digest node-name
             (slot-value request 'gr8s.node.v1::lease-token))))
          ((string= action "publish")
           (response
            "ok" :infohash
            (gr8s.image-distribution::tracker-publish-swarm
             tracker digest node-name
             (slot-value request 'gr8s.node.v1::lease-token)
             (slot-value request 'gr8s.node.v1::metainfo)
             (slot-value request 'gr8s.node.v1::peer-address)
             (slot-value request 'gr8s.node.v1::peer-port)
             (slot-value request 'gr8s.node.v1::peer-id))))
          ((string= action "announce")
           (gr8s.image-distribution::tracker-announce-peer
            tracker digest node-name
            (slot-value request 'gr8s.node.v1::peer-address)
            (slot-value request 'gr8s.node.v1::peer-port)
            (slot-value request 'gr8s.node.v1::peer-id)
            :complete-p (slot-value request 'gr8s.node.v1::complete))
           (response "ok"))
          ((string= action "withdraw")
           (gr8s.image-distribution::tracker-withdraw-peer
            tracker digest node-name)
           (response "ok"))
          (t (error "Unknown image tracker action ~S" action)))))))

(defun start-node-grpc-server (store &key (host "127.0.0.1") (port 0)
                                            (heartbeat-timeout-seconds 15)
                                            pki
                                            (cluster-pod-cidr +default-cluster-pod-cidr+)
                                            (node-prefix +default-node-pod-prefix+)
                                            cluster-pod-cidrs
                                            node-prefixes
                                            (overlay-backend "vxlan")
                                            (wireguard-listen-port 51820))
  "Create and start the node control-plane gRPC server on HOST:PORT: register the
   Connect service (and the Enrollment service when PKI is given), spawn its accept
   thread and the heartbeat monitor, and block until it is listening. Errors on a
   non-positive heartbeat timeout or if the listener never comes up. Returns the
   NODE-GRPC-SERVER (with its actual bound port)."
  (unless (plusp heartbeat-timeout-seconds)
    (error "Heartbeat timeout must be positive"))
  (unless (member overlay-backend '("vxlan" "wireguard") :test #'string=)
    (error "Overlay backend must be vxlan or wireguard"))
  (unless (<= 1 wireguard-listen-port 65535)
    (error "WireGuard listen port must be between 1 and 65535"))
  (multiple-value-bind (cluster-pod-cidrs node-prefixes)
      (normalize-pod-pool-geometry (or cluster-pod-cidrs cluster-pod-cidr)
                                   (or node-prefixes node-prefix))
   (let* ((grpc-server (apply #'ag-grpc:make-grpc-server port :host host
                             (node-server-tls-options pki)))
         (server (%make-node-grpc-server
                  :store store
                  :grpc-server grpc-server
                  :port port
                  :heartbeat-timeout-seconds heartbeat-timeout-seconds
                  :pki pki
                  :cluster-pod-cidr (first cluster-pod-cidrs)
                  :node-prefix (first node-prefixes)
                  :cluster-pod-cidrs cluster-pod-cidrs
                  :node-prefixes node-prefixes
                  :overlay-backend overlay-backend
                  :wireguard-listen-port wireguard-listen-port)))
    (gr8s.node.v1::register-node-service-service
     grpc-server
     :connect-handler (lambda (context stream)
                        (handle-node-connect server context stream))
     :track-image-handler (lambda (request context)
                            (handle-image-tracker-request server request context)))
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
    server)))

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
