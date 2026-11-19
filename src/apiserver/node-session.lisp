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

(defun node-network-domain (node)
  "Return NODE's standard region and zone, with stable explicit fallbacks."
  (let ((labels (node-record-labels node)))
    (values (or (and labels (gethash "topology.kubernetes.io/region" labels))
                "unknown-region")
            (or (and labels (gethash "topology.kubernetes.io/zone" labels))
                "unknown-zone"))))

(defun node-record->overlay-node (node)
  "Project NODE's Kubernetes identity into the overlay-node the cl-wireguard-overlay
planner groups by: its name and its region/zone."
  (multiple-value-bind (region zone) (node-network-domain node)
    (make-overlay-node :name (node-record-name node) :region region :zone zone)))

(defun node-network-link-cost (left right)
  "Return the planner's bounded locality cost between LEFT and RIGHT."
  (multiple-value-bind (left-region left-zone) (node-network-domain left)
    (multiple-value-bind (right-region right-zone) (node-network-domain right)
      (cond ((and (string= left-region right-region)
                  (string= left-zone right-zone)) 1)
            ((string= left-region right-region) 10)
            (t 100)))))

(defstruct (node-grpc-server
             (:constructor %make-node-grpc-server
                 (&key store grpc-server thread port heartbeat-timeout-seconds
                       pki cluster-pod-cidr node-prefix cluster-pod-cidrs node-prefixes
                       overlay-backend mtu
                       wireguard-listen-port wireguard-relay-server
                       wireguard-relay-address image-tracker clock
                       gateway-stability-seconds session-admission-fn
                       session-endpoints-fn)))
  store
  ;; HA admits persistent agent streams only on the publishing leader.
  ;; Enrollment and peer-operation relay are deliberately independent.
  session-admission-fn
  ;; Where a refused agent should go instead: the members that serve nodes as
  ;; (HOST PORT), leader first.
  session-endpoints-fn
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
  ;; Pod interface MTU handed to every node; NIL picks the backend default
  ;; (1450 vxlan, 1420 wireguard). Set explicitly when the underlay is itself
  ;; a tunnel, or the overlay's full-size frames overflow it (podster-cm3).
  mtu
  (wireguard-listen-port 51820)
  wireguard-relay-server
  wireguard-relay-address
  (clock #'get-universal-time)
  ;; NIL is used only by direct unit fixtures constructed with the private
  ;; constructor. START-NODE-GRPC-SERVER always installs a validated interval.
  gateway-stability-seconds
  (image-tracker (gr8s.image-distribution::make-image-tracker))
  (revisions (make-hash-table :test #'equal))
  (snapshots (make-hash-table :test #'equal))
  (publication-locks (make-hash-table :test #'equal))
  (statuses (make-hash-table :test #'equal))
  ;; Complete Gateway observations, bound to the reporting session and receipt time.
  (gateway-reports (make-hash-table :test #'equal))
  (acknowledged-revisions (make-hash-table :test #'equal))
  ;; Latest validated complete local receiver report:
  ;; (session revision proofs owner-projection).
  (service-receiver-reports (make-hash-table :test #'equal))
  ;; A grant is tied to discovery, trusted owner inventory, and the exact
  ;; authenticated sessions that acknowledged the risk-only phase.
  service-risk-grant-digest
  service-risk-grant-owner-projection
  service-risk-grant-receiver-projection
  service-risk-grant-identities
  service-risk-grant-sessions
  (operations (make-hash-table :test #'equal))
  (operation-queues (make-hash-table :test #'equal))
  (sessions (make-hash-table :test #'equal))
  ;; Last accepted reflexive-endpoint change per target node. This bounds an
  ;; authenticated but faulty reporter's ability to churn peer trials.
  (nat-observation-times (make-hash-table :test #'equal))
  ;; Nodes currently admitted as sparse transit gateways, plus a bounded
  ;; human-readable history of admission and removal decisions.
  (transit-eligible (make-hash-table :test #'equal))
  (topology-decisions nil)
  ;; (VARIANT TARGET-MEMBER NODE-NAME PAYLOAD) -> accepting member id or NIL.
  ;; HA installs this peer relay; single-node servers leave it NIL.
  operation-router
  ;; Handles @control-plane/ID operation frames addressed to this process.
  member-operation-handler
  (lock (bt:make-lock "gr8s node sessions"))
  monitor-thread
  (stopping-p nil))

(defun clear-service-risk-grant-locked (server)
  "Forget a grant while holding the node-session lock."
  (setf (node-grpc-server-service-risk-grant-digest server) nil
        (node-grpc-server-service-risk-grant-owner-projection server) nil
        (node-grpc-server-service-risk-grant-receiver-projection server) nil
        (node-grpc-server-service-risk-grant-identities server) nil
        (node-grpc-server-service-risk-grant-sessions server) nil))

(defstruct (node-agent-session
             (:constructor make-node-agent-session (stream)))
  stream
  node-id
  (lock (bt:make-lock "gr8s node agent session"))
  (last-envelope-time (get-universal-time))
  (evicted-p nil)
  ;; The agent opened the pinned v2 risk map before this authenticated hello.
  ;; Its snapshot ACK is withheld until local risk and owner readback succeed.
  (service-risk-v2-p nil)
  ;; Whether the agent applies desired-state deltas, and the last snapshot this
  ;; session delivered, which the next delta changes (podster-uqb.139).
  deltas-p
  delivered
  gateway-deltas-p
  (gateway-revision 0)
  (gateway-acknowledged-revision 0)
  gateway-resources
  gateway-pending-since
  gateway-repair-required-p
  gateway-discovery-key-cache         ; validated octets -> key, bounded to the last full projection
  gateway-repair-key-cache            ; immutable byte identities -> key, bounded to the last repair
  gateway-dependency-epoch)

(defparameter +desired-state-delta-capability+ "desired-state-delta"
  "The NodeHello capability of an agent that rebuilds snapshots from deltas.")

(defparameter +default-node-max-connections-per-ip+ 32
  "Default cap on concurrent connections the node control-plane listener accepts
   from a single source address, passed through to the gRPC server. It bounds the
   pre-handshake window: a node authenticates only after connecting, so without a
   per-source cap one unauthenticated peer could open connections up to the global
   pool limit and starve every other node. 32 is a quarter of ag-grpc's default
   128-connection pool -- generous enough for a modest fleet behind one NAT while
   denying any single source most of the pool. Tune via START-NODE-GRPC-SERVER's
   :MAX-CONNECTIONS-PER-IP (NIL disables the per-source cap).")

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
     :gateway-dependency-revision (slot-value snapshot 'gr8s.node.v1::gateway-dependency-revision)
     :network (slot-value snapshot 'gr8s.node.v1::network)
     :routes (slot-value snapshot 'gr8s.node.v1::routes)
     :pods (remove-if (lambda (pod)
                        (let ((old (gethash (slot-value pod 'gr8s.node.v1::uid) base-pods)))
                          (and old (same-pod-assignment-p old pod))))
                      (slot-value snapshot 'gr8s.node.v1::pods))
     :removed-pod-uids (loop for uid being the hash-keys of base-pods
                             unless (gethash uid current) collect uid)
     :service-risk-grant-digest
     (slot-value snapshot 'gr8s.node.v1::service-risk-grant-digest)
     :service-receivers (slot-value snapshot 'gr8s.node.v1::service-receivers)
     :service-discovery-changed service-discovery-changed
     :service-discovery-objects-json
     (when service-discovery-changed
       (slot-value snapshot 'gr8s.node.v1::service-discovery-objects-json)))))

(defvar *node-publications* nil)

(defun call-with-node-publication (server node-name function)
  "Order capture and delivery for this node, permitting nested publication helpers."
  (let ((key (cons server node-name)))
    (if (member key *node-publications* :test #'equal)
        (funcall function)
        (let ((lock (bt:with-lock-held ((node-grpc-server-lock server))
                      (or (gethash node-name (node-grpc-server-publication-locks server))
                          (setf (gethash node-name (node-grpc-server-publication-locks server))
                                (bt:make-lock (format nil "gr8s configuration publication ~A" node-name)))))))
          (bt:with-lock-held (lock)
            (let ((*node-publications* (cons key *node-publications*)))
              (funcall function)))))))

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
        (setf (node-agent-session-delivered session) snapshot)
        (install-node-gateway-baseline session snapshot)))))

(defun install-node-gateway-baseline
    (session snapshot &optional (dependency-epoch (slot-value snapshot 'gr8s.node.v1::gateway-dependency-revision)))
  "Reset the derived view after full node delivery, with SESSION's send lock held."
  (when (node-agent-session-gateway-deltas-p session)
    (let ((resources (make-hash-table :test #'equal))
          (previous-cache (node-agent-session-gateway-discovery-key-cache session))
          (next-cache (make-hash-table :test #'equalp
                                      #+sbcl :hash-function #+sbcl #'gr8s.kubelet::discovery-octet-hash)))
      (dolist (bytes (slot-value snapshot 'gr8s.node.v1::service-discovery-objects-json))
        (let ((key (or (and previous-cache (gethash bytes previous-cache))
                       (car (gr8s.kubelet::decode-service-discovery-entry bytes)))))
          (setf (gethash bytes next-cache) key)
          (when (member (first key) gr8s.protocol::+gateway-config-resources+ :test #'equal)
            (setf (gethash key resources) bytes))))
      (setf (node-agent-session-gateway-resources session) resources
            (node-agent-session-gateway-discovery-key-cache session) next-cache
            (node-agent-session-gateway-repair-key-cache session) nil
            (node-agent-session-gateway-pending-since session) nil
            (node-agent-session-gateway-repair-required-p session) nil
            (node-agent-session-gateway-revision session) 0
            (node-agent-session-gateway-acknowledged-revision session) 0
            (node-agent-session-gateway-dependency-epoch session) dependency-epoch))))

(defun deliver-node-gateway-config
    (session changes &key (dependency-epoch (node-agent-session-gateway-dependency-epoch session)))
  "Send only changed rows, committing the session base after a successful send."
  (bt:with-lock-held ((node-agent-session-lock session))
    (deliver-node-gateway-config-locked session changes dependency-epoch)))

(defun deliver-node-gateway-config-locked (session changes dependency-epoch)
  "Send an ordered batch with SESSION's lock already held."
  (let ((snapshot (node-agent-session-delivered session))
        (resources (node-agent-session-gateway-resources session)))
    (unless (node-agent-session-gateway-deltas-p session)
      (return-from deliver-node-gateway-config-locked (values nil :unsupported)))
    (unless (and snapshot resources
                 (eql dependency-epoch (node-agent-session-gateway-dependency-epoch session)))
      (return-from deliver-node-gateway-config-locked (values nil :baseline-required)))
    (let* ((changed
             (remove-if
              (lambda (change)
                (let* ((key (gr8s.protocol::gateway-resource-change-key change))
                       (old (gethash key resources)))
                  (if (slot-value change 'gr8s.node.v1::deleted)
                      (null old)
                      (equalp old (slot-value change 'gr8s.node.v1::object-json))))) changes))
           (base (node-agent-session-gateway-revision session)))
      (unless changed (return-from deliver-node-gateway-config-locked (values nil :unchanged)))
      (let ((update (make-instance 'gr8s.node.v1::gateway-config-update
                                   :base-node-revision (slot-value snapshot 'gr8s.node.v1::revision)
                                   :base-revision base :revision (1+ base) :changes changed)))
        (gr8s.protocol::validate-gateway-config-update
         update (slot-value snapshot 'gr8s.node.v1::revision) base)
        (ag-grpc:stream-send (node-agent-session-stream session)
                             (make-server-envelope :gateway-config update))
        (dolist (change changed)
          (let ((key (gr8s.protocol::gateway-resource-change-key change)))
            (if (slot-value change 'gr8s.node.v1::deleted)
                (remhash key resources)
                (setf (gethash key resources) (slot-value change 'gr8s.node.v1::object-json)))))
        (when (= base (node-agent-session-gateway-acknowledged-revision session))
          (setf (node-agent-session-gateway-pending-since session) (get-internal-real-time)))
        (setf (node-agent-session-gateway-revision session) (1+ base))
        (values update :sent)))))

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
                    ;; Frames carry live session/store structs; unbounded
                    ;; printing turned each one into multi-KB journal lines
                    ;; (podster-ao6). Depth/length limits keep the stacks
                    ;; readable and the journal sane.
                    (let ((*standard-output* output)
                          (*print-level* 3)
                          (*print-length* 8)
                          (*print-lines* 1))
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

(defun queue-member-operation (server member-id request)
  "Register REQUEST and route it to one exact control-plane MEMBER-ID over member mTLS."
  (let* ((node-name (format nil "@control-plane/~A" member-id))
         (operation (make-pending-node-operation node-name request))
         (operation-id (operation-request-id request))
         (router (node-grpc-server-operation-router server)))
    (unless router (error "control-plane member routing is unavailable"))
    (bt:with-lock-held ((node-grpc-server-lock server))
      (when (gethash operation-id (node-grpc-server-operations server))
        (error "Member operation ~A already exists" operation-id))
      (setf (gethash operation-id (node-grpc-server-operations server)) operation))
    (let ((owner (funcall router :operation-request member-id node-name request)))
      (unless owner
        (release-node-operation server operation)
        (error "control-plane member ~A did not accept the debug operation" member-id))
      (setf (pending-node-operation-remote-member operation) owner))
    operation))

(defun accept-routed-node-operation (server origin-member node-name variant payload)
  "Accept a peer's routed operation frame when this member owns NODE-NAME's live
agent session. REQUEST creates a shadow operation bound to ORIGIN-MEMBER; INPUT
and CANCEL follow that operation's local agent session. Returns true only when
the frame was accepted here."
  (when (uiop:string-prefix-p "@control-plane/" node-name)
    (let ((handler (node-grpc-server-member-operation-handler server)))
      (return-from accept-routed-node-operation
        (and handler (funcall handler origin-member variant payload)))))
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

(defun note-node-operation-stream (server node-name message)
  "Append MESSAGE locally, or return it to the peer that originated a routed
operation. No-op when no operation matches MESSAGE's id, or when NODE-NAME is not
the node the operation was addressed to."
  (let ((operation
          (find-node-operation
           server (slot-value message 'gr8s.node.v1::operation-id))))
    (cond
      ((null operation))
      ((not (equal node-name (pending-node-operation-node-name operation)))
       ;; A node may only speak for operations addressed to itself; reject a
       ;; stream forged against another node's in-flight operation id.
       (format *error-output*
               "gr8s: node ~A sent an operation stream for ~A owned by ~A; ignoring~%"
               node-name (slot-value message 'gr8s.node.v1::operation-id)
               (pending-node-operation-node-name operation)))
      (t
       (let ((origin (pending-node-operation-origin-member operation)))
         (if origin
             (let ((router (node-grpc-server-operation-router server)))
               (unless (and router
                            (funcall router :operation-stream origin
                                     (pending-node-operation-node-name operation) message))
                 (finish-node-operation operation :error "Operation origin is unavailable")))
             (record-node-operation-stream operation message)))))))

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

(defun note-node-operation-response (server node-name response)
  "Finish the matching operation when RESPONSE is terminal (complete or failed),
   carrying the response and, on failure, its error message. No-op for a
   non-terminal status, an unknown operation id, or a RESPONSE from a node other
   than the one the operation was addressed to."
  (let ((operation
          (find-node-operation
           server (slot-value response 'gr8s.node.v1::operation-id))))
    (when (and operation
               (or (equal node-name (pending-node-operation-node-name operation))
                   (progn
                     (format *error-output*
                             "gr8s: node ~A sent an operation response for ~A owned by ~A; ignoring~%"
                             node-name (slot-value response 'gr8s.node.v1::operation-id)
                             (pending-node-operation-node-name operation))
                     nil)))
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

(define-condition node-session-refused (error)
  ((expected :initarg :expected :reader node-session-refused-expected)
   (message :initarg :message :reader node-session-refused-message)
   (endpoints :initarg :endpoints :initform nil :reader node-session-refused-endpoints))
  (:report (lambda (condition stream)
             (format stream "Expected node-session payload ~S; the peer reported: ~A"
                     (node-session-refused-expected condition)
                     (node-session-refused-message condition))))
  (:documentation "The peer answered with a protocol-error. ENDPOINTS, HOST:PORT
strings, are the members it says can admit the session instead."))

(defun node-envelope-payload (envelope variant)
  "The payload ENVELOPE carries for VARIANT. Errors unless ENVELOPE's active
   payload case is exactly VARIANT; a protocol-error in VARIANT's place reports
   the peer's own explanation rather than just the payload case, so a refused
   handshake is diagnosable from the refused side's log (podster-ddc)."
  (let ((actual (slot-value envelope 'gr8s.node.v1::payload-case)))
    (unless (eq variant actual)
      (if (eq actual :protocol-error)
          (let ((reported (slot-value envelope 'gr8s.node.v1::protocol-error)))
            (error 'node-session-refused
                   :expected variant
                   :message (slot-value reported 'gr8s.node.v1::message)
                   :endpoints (slot-value reported 'gr8s.node.v1::session-endpoints)))
          (error "Expected node-session payload ~S, received ~S" variant actual)))
    (slot-value envelope (find-symbol (symbol-name variant) :gr8s.node.v1))))

(defun assigned-node-network (server node-name)
  "The NodeNetworkConfig for NODE-NAME: the cluster and this node's Pod CIDRs, the
   cluster DNS address, the node's underlay address, the fixed overlay VNI 42, and
   the configured Pod MTU (default 1450, or 1420 for the wireguard backend).
   Errors if NODE-NAME is unknown."
  (let ((node (get-node (node-grpc-server-store server) node-name)))
    (make-instance 'gr8s.node.v1::node-network-config
                   :cluster-pod-cidr (node-grpc-server-cluster-pod-cidr server)
                   :node-pod-cidr (node-record-pod-cidr node)
                   :cluster-pod-cidrs (copy-list (node-grpc-server-cluster-pod-cidrs server))
                   :node-pod-cidrs (coerce (node-record-all-pod-cidrs node) 'list)
                   :service-translations
                   (gr8s.network::service-translation-identity-messages (node-grpc-server-store server))
                   :dns-address +dns-pod-server-address+
                   :underlay-address (node-record-underlay-address node)
                   :overlay-backend (node-grpc-server-overlay-backend server)
                   :wireguard-listen-port
                   (if (string= "wireguard" (node-grpc-server-overlay-backend server))
                       (node-grpc-server-wireguard-listen-port server)
                       0)
                   :vni 42
                   :mtu (or (node-grpc-server-mtu server)
                            (if (string= "wireguard"
                                         (node-grpc-server-overlay-backend server))
                                1420 1450)))))

(defun wireguard-projected-endpoints (server source-name peer)
  "Return PEER's authenticated candidates plus SOURCE-NAME's pair-specific relay."
  (append
   (mapcar (lambda (endpoint)
             (make-instance 'gr8s.node.v1::wireguard-endpoint
                            :name (first endpoint) :address (second endpoint)
                            :port (third endpoint)))
           (node-record-wireguard-endpoints peer))
   (let ((relay (node-grpc-server-wireguard-relay-server server))
         (address (node-grpc-server-wireguard-relay-address server)))
     (when (and relay address)
       (handler-case
           (let* ((now (get-universal-time))
                  (now-unix (- now 2208988800))
                  (source (get-node (node-grpc-server-store server) source-name))
                  (reflexive (find "nat-reflexive"
                                   (node-record-wireguard-endpoints source)
                                   :key #'first :test #'string=))
                  (observed-at (node-record-wireguard-reflexive-observed-at source)))
             (when (and reflexive observed-at (<= 0 (- now-unix observed-at) 180))
               ;; A fresh reflexive observation only signals that SOURCE-NAME is
               ;; behind NAT and may need the relay; it never authorizes a relay
               ;; source. The relay is the authority on SOURCE-NAME's source and
               ;; learns it first-hand from SOURCE-NAME's own traffic, so a peer's
               ;; self-asserted observation can no longer redirect it (N1).
               (let ((channel
                       (gr8s.network::ensure-wireguard-relay-server-channel
                        relay source-name (node-record-name peer) now)))
                 (list (make-instance
                        'gr8s.node.v1::wireguard-endpoint
                        :name "relay" :address address
                        :port (gr8s.network::wireguard-relay-channel-port-for
                               channel source-name))))))
         (error (condition)
           (format *error-output* "gr8s relay allocation failed for ~A/~A: ~A~%"
                   source-name (node-record-name peer) condition)
           nil))))))

(defun wireguard-next-hop-message (server source-name node)
  (make-instance 'gr8s.node.v1::wireguard-next-hop
                 :node-id (node-record-id node)
                 :node-name (node-record-name node)
                 :underlay-address (node-record-underlay-address node)
                 :wireguard-public-key (node-record-wireguard-public-key node)
                 :wireguard-listen-port (node-grpc-server-wireguard-listen-port server)
                 :wireguard-endpoints
                 (wireguard-projected-endpoints server source-name node)))

(defun assigned-node-routes (server node-name)
  "Project every destination Pod CIDR and its authenticated direct or sparse next hop."
  (let* ((store (node-grpc-server-store server))
         (wireguard-p (string= "wireguard" (node-grpc-server-overlay-backend server)))
         (source (get-node store node-name))
         (now (funcall (node-grpc-server-clock server))))
    (when (string= "" (node-record-underlay-address source))
      (return-from assigned-node-routes nil))
    (let* ((eligible
             (remove-if
              (lambda (node)
                ;; VXLAN peers are direct Pod routes, independent of the
                ;; agent lease. Existing Pods and sockets survive a restart.
                ;; WireGuard transit selection retains its readiness fencing.
                (or (and wireguard-p
                         (node-grpc-server-gateway-stability-seconds server)
                         (not (node-record-ready-p node)))
                    (string= "" (node-record-underlay-address node))
                    (string= "" (node-record-pod-cidr node))
                    (and wireguard-p
                         (/= 32 (length (node-record-wireguard-public-key node))))))
              (copy-list (list-nodes store))))
           (stable-transit
             (if (null (node-grpc-server-gateway-stability-seconds server))
                 (mapcar #'node-record-name eligible)
                 (loop for node in eligible
                       for ready-since = (node-record-ready-since node)
                       when (and ready-since
                                 (>= (- now ready-since)
                                     (node-grpc-server-gateway-stability-seconds server)))
                         collect (node-record-name node))))
           (plan (and wireguard-p
                      (plan-wireguard-topology
                       (mapcar #'node-record->overlay-node eligible)
                       :transit-node-names stable-transit)))
           (ordered (sort eligible #'string< :key #'node-record-name)))
      (loop for node in ordered
            unless (string= node-name (node-record-name node))
              collect
              (let* ((destination-name (node-record-name node))
                     (hop-name (and plan
                                    (wireguard-topology-next-hop
                                     plan node-name destination-name)))
                     (hop-node (and hop-name (get-node store hop-name))))
                (multiple-value-bind (region zone) (node-network-domain node)
                  (make-instance
                   'gr8s.node.v1::node-route
                   :node-id (node-record-id node)
                   :node-name destination-name
                   :pod-cidr (node-record-pod-cidr node)
                   :pod-cidrs (coerce (node-record-all-pod-cidrs node) 'list)
                   :underlay-address (node-record-underlay-address node)
                   :region region :zone zone
                   :capacity-score
                   (node-steering-capacity-score (node-record-capacity node))
                   :link-cost (node-network-link-cost source node)
                   :wireguard-public-key
                   (if wireguard-p (node-record-wireguard-public-key node) #())
                   :wireguard-endpoints
                   (when wireguard-p
                     (wireguard-projected-endpoints server node-name node))
                   :wireguard-listen-port
                   (if wireguard-p (node-grpc-server-wireguard-listen-port server) 0)
                   :next-hop
                   (and hop-node
                        (not (string= hop-name destination-name))
                        (wireguard-next-hop-message server node-name hop-node)))))))))

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
        (call-with-node-publication
         server name
         (lambda ()
          (let ((snapshot (attach-node-topology
                         server name
                         (node-desired-state-snapshot (node-grpc-server-store server) name))))
          (unless (same-node-snapshot-topology-p
                   (current-node-snapshot server name) snapshot)
            (publish-node-desired-state server name snapshot)))))))))

(defun merge-wireguard-reflexive-endpoint (endpoints address port)
  "Replace the kernel-observed NAT candidate without disturbing manual candidates."
  (append (remove "nat-reflexive" endpoints :key #'first :test #'string=)
          (list (list "nat-reflexive" address port))))

(defun merge-wireguard-advertised-endpoints (advertised durable)
  "Keep NAT evidence server-owned while replacing a node's manual candidates."
  (when (find-if (lambda (endpoint)
                   (member (first endpoint) '("nat-reflexive" "relay")
                           :test #'string=))
                 advertised)
    (error "WireGuard endpoint names nat-reflexive and relay are reserved"))
  (append advertised
          (remove-if-not (lambda (endpoint)
                           (string= "nat-reflexive" (first endpoint)))
                         durable)))

(defun accept-wireguard-nat-observation-p (server target now &optional (minimum-seconds 30))
  (bt:with-lock-held ((node-grpc-server-lock server))
    (let ((previous (gethash target (node-grpc-server-nat-observation-times server))))
      (when (or (null previous) (>= (- now previous) minimum-seconds))
        (setf (gethash target (node-grpc-server-nat-observation-times server)) now)
        t))))

(defun record-authenticated-wireguard-observations
    (server reporter observations
     &key (now (- (get-universal-time) 2208988800)) (fresh-seconds 180))
  "Publish fresh WireGuard endpoints observed by authenticated REPORTER.
The reported peer key must already belong to a registered node. These remain
candidates; agents still require their transactional handshake/probe gates."
  (dolist (observation observations)
    (handler-case
        (let* ((key (slot-value observation 'gr8s.node.v1::peer-public-key))
               (handshake
                 (slot-value observation 'gr8s.node.v1::latest-handshake-unix-seconds))
               (received (slot-value observation 'gr8s.node.v1::received-bytes))
               (target
                 (and (= 32 (length key))
                      (find key (list-nodes (node-grpc-server-store server))
                            :key #'node-record-wireguard-public-key :test #'equalp))))
          (when (and target
                     (not (string= reporter (node-record-name target)))
                     (plusp received)
                     (<= 0 (- now handshake) fresh-seconds))
            (let* ((target-name (node-record-name target))
                   (address (canonical-node-underlay-address
                             (slot-value observation 'gr8s.node.v1::address)))
                   (port (slot-value observation 'gr8s.node.v1::port))
                   (candidate (list "nat-reflexive" address port))
                   (current (find "nat-reflexive"
                                  (node-record-wireguard-endpoints target)
                                  :key #'first :test #'string=)))
              (when (accept-wireguard-nat-observation-p server target-name now)
                (let ((changed (not (equal current candidate))))
                  ;; The observation only updates TARGET's reflexive endpoint
                  ;; CANDIDATE, which the data path still re-gates through each
                  ;; agent's own WireGuard handshake probe. It deliberately no
                  ;; longer touches any relay source authorization: a peer must
                  ;; not be able to redirect another node's relay source by self-
                  ;; asserted observation (N1). The relay learns that source
                  ;; first-hand from the target's own traffic instead.
                  (update-node-wireguard-endpoints
                   (node-grpc-server-store server) target-name
                   (merge-wireguard-reflexive-endpoint
                    (node-record-wireguard-endpoints target)
                    address port)
                   :reflexive-observed-at now)
                  (when changed
                    (refresh-node-peer-topology server target-name)))))))
      (error (condition)
        (format *error-output* "gr8s ignored WireGuard NAT observation from ~A: ~A~%"
                reporter condition)))))

(defun prepare-node-connect-snapshot (server node-name last-applied)
  "The desired-state snapshot a (re)connecting agent whose last applied revision is
   LAST-APPLIED should receive, reusing the published one when its content is
   unchanged and its revision is at least LAST-APPLIED, else assigning a revision
   strictly above both LAST-APPLIED and the in-memory counter and recording it.
   Guarantees a restarted control plane never hands back a revision an agent has
   already moved past."
  ;; Rebuild from durable desired state after a control-plane restart. Revision
  ;; counters in memory must never strand an agent ahead of its new server.
  (call-with-node-publication server node-name
   (lambda ()
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
                  (gethash node-name (node-grpc-server-snapshots server)) snapshot)))))))))

(defun current-node-snapshot (server node-name)
  "The snapshot currently published to NODE-NAME, or a fresh empty
   DesiredStateSnapshot when none has been published yet."
  (bt:with-lock-held ((node-grpc-server-lock server))
    (or (gethash node-name (node-grpc-server-snapshots server))
        (make-instance 'gr8s.node.v1::desired-state-snapshot))))

(defun note-node-snapshot-ack (server node-name ack &optional session)
  "Record NODE-NAME's acknowledged revision from ACK when it advances convergence:
   only when ACK is applied, SESSION still owns the node, its revision exceeds
   the last ack, and it does not run ahead of the published revision."
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
          (when (and (or (null session)
                         (eq session (gethash node-name
                                              (node-grpc-server-sessions server))))
                     (> revision acknowledged) (<= revision published))
            (setf (gethash node-name
                           (node-grpc-server-acknowledged-revisions server))
                  revision)))))))

(defun note-node-gateway-config-ack (server node-name ack session)
  "Record only this session's Gateway progress, never node/Service convergence."
  (bt:with-lock-held ((node-agent-session-lock session))
    (bt:with-lock-held ((node-grpc-server-lock server))
      (let ((snapshot (node-agent-session-delivered session))
            (revision (slot-value ack 'gr8s.node.v1::revision)))
        (when (and (eq session (gethash node-name (node-grpc-server-sessions server)))
                   snapshot
                   (= (slot-value ack 'gr8s.node.v1::base-node-revision)
                      (slot-value snapshot 'gr8s.node.v1::revision))
                   (< (node-agent-session-gateway-acknowledged-revision session) revision)
                   (<= revision (node-agent-session-gateway-revision session)))
          (if (slot-value ack 'gr8s.node.v1::applied)
              (setf (node-agent-session-gateway-acknowledged-revision session) revision
                    (node-agent-session-gateway-pending-since session)
                    (unless (= revision (node-agent-session-gateway-revision session))
                      (get-internal-real-time)))
              (setf (node-agent-session-gateway-repair-required-p session) t)))))))

(defun canonical-node-service-receiver-proofs (server node-name status &optional session)
  "Accept only complete receiver reports for the current ACKed assignment.
Each proof must name an exact owner incarnation belonging to the authenticated
node; stale, duplicate, or foreign proofs clear the entire report."
  (let ((revision (slot-value status 'gr8s.node.v1::service-receiver-revision))
        (proofs (slot-value status 'gr8s.node.v1::service-receivers)))
    (bt:with-lock-held ((node-grpc-server-lock server))
      (let* ((current (gethash node-name (node-grpc-server-sessions server)))
             (snapshot (gethash node-name (node-grpc-server-snapshots server)))
             (network (and snapshot (slot-value snapshot 'gr8s.node.v1::network)))
             (records (and network (slot-value network 'gr8s.node.v1::service-translations)))
             (expected (make-hash-table :test #'equal))
             (seen (make-hash-table :test #'equal)))
        (unless (and (integerp revision) (plusp revision) current
                     (or (null session) (eq session current))
                     (not (node-agent-session-evicted-p current))
                     snapshot (= revision (slot-value snapshot 'gr8s.node.v1::revision))
                     (= revision (gethash node-name
                                          (node-grpc-server-acknowledged-revisions server) 0)))
          (return-from canonical-node-service-receiver-proofs nil))
        (dolist (record records)
          (when (and (string= node-name (slot-value record 'gr8s.node.v1::node-name))
                     (string= (node-agent-session-node-id current)
                              (slot-value record 'gr8s.node.v1::node-id)))
            (setf (gethash (slot-value record 'gr8s.node.v1::pod-uid) expected)
                  (gr8s.network::service-translation-incarnation-token
                   (slot-value record 'gr8s.node.v1::node-id)
                   (slot-value record 'gr8s.node.v1::sandbox-id)
                   (slot-value record 'gr8s.node.v1::interface-name)
                   (slot-value record 'gr8s.node.v1::pod-ip)
                   (slot-value record 'gr8s.node.v1::translation-ip)
                   (slot-value record 'gr8s.node.v1::incarnation-generation)))))
        (let ((canonical nil))
          (dolist (proof proofs)
            (unless (typep proof 'gr8s.node.v1::service-receiver-proof)
              (return-from canonical-node-service-receiver-proofs nil))
            (let* ((uid (slot-value proof 'gr8s.node.v1::pod-uid))
                   (epoch (slot-value proof 'gr8s.node.v1::incarnation))
                   (wanted (gethash uid expected)))
              (unless (and wanted (not (gethash uid seen))
                           (= 16 (length epoch)) (equalp epoch wanted))
                (return-from canonical-node-service-receiver-proofs nil))
              (setf (gethash uid seen) t)
              (push (make-instance 'gr8s.node.v1::service-receiver-proof
                                   :pod-uid uid :incarnation (copy-seq epoch)) canonical)))
          (values (sort canonical #'string<
                        :key (lambda (proof) (slot-value proof 'gr8s.node.v1::pod-uid)))
                  t))))))

(defun note-node-service-receiver-status (server node-name status &optional session)
  "Store an explicit complete receiver report for this current session and
ACKed revision. Sparse Pod status messages leave the last report alone.
An explicit unready or malformed current report withdraws its prior proof."
  (let ((revision (slot-value status 'gr8s.node.v1::service-receiver-revision)))
    (when (slot-value status 'gr8s.node.v1::service-receiver-report-present)
      (unless (and (integerp revision) (plusp revision))
        (bt:with-lock-held ((node-grpc-server-lock server))
          (when (or (null session)
                    (eq session (gethash node-name (node-grpc-server-sessions server))))
            (remhash node-name (node-grpc-server-service-receiver-reports server))))
        (return-from note-node-service-receiver-status (values nil nil)))
      (multiple-value-bind (proofs valid-p)
          (canonical-node-service-receiver-proofs server node-name status session)
        (bt:with-lock-held ((node-grpc-server-lock server))
          (let ((current (gethash node-name (node-grpc-server-sessions server)))
                (snapshot (gethash node-name (node-grpc-server-snapshots server))))
            (when (and current snapshot
                       (or (null session) (eq session current))
                       (= revision (slot-value snapshot 'gr8s.node.v1::revision)))
              (if valid-p
                  (setf (gethash node-name
                                 (node-grpc-server-service-receiver-reports server))
                        (list current revision proofs
                              (service-risk-snapshot-owner-projection snapshot)))
                  ;; Status and ACK use the same stream but separate sending
                  ;; threads. A new revision's status may reach us before its
                  ;; ACK; keep the old projection-bound report until the next
                  ;; complete status after ACK. An invalid ACKed report revokes.
                  (when (<= revision
                            (gethash node-name
                                     (node-grpc-server-acknowledged-revisions server) 0))
                    (remhash node-name
                             (node-grpc-server-service-receiver-reports server)))))))
        (values proofs valid-p)))))

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

(defun merge-node-pod-address-status (object pod-status)
  "Merge authenticated wire status into OBJECT without discarding additional IPs."
  (setf (gethash "phase" object) (slot-value pod-status 'gr8s.node.v1::phase))
  (let ((primary (slot-value pod-status 'gr8s.node.v1::pod-ip)))
    (unless (string= "" primary)
      (setf (gethash "podIP" object) primary)
      (let ((addresses (gethash "podIPs" object)))
        (unless (and (vectorp addresses) (plusp (length addresses))
                     (every (lambda (item)
                              (and (hash-table-p item)
                                   (stringp (gethash "ip" item))))
                            addresses)
                     (string= primary (gethash "ip" (aref addresses 0))))
          (setf (gethash "podIPs" object)
                (vector (json-object "ip" primary)))))))
  object)

(defun handle-node-agent-envelope (server node-name envelope &optional session)
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
     (let* ((now (funcall (node-grpc-server-clock server)))
            (previously-ready-p
              (node-record-ready-p
               (get-node (node-grpc-server-store server) node-name))))
       (when (node-grpc-server-wireguard-relay-server server)
         (gr8s.network::refresh-wireguard-relay-node
          (node-grpc-server-wireguard-relay-server server) node-name now))
       (mark-node-ready (node-grpc-server-store server)
                        node-name now
                        :lease-duration (node-grpc-server-heartbeat-timeout-seconds server))
       (note-node-runtime-health
        (node-grpc-server-store server) node-name
        (slot-value (slot-value envelope 'gr8s.node.v1::heartbeat)
                    'gr8s.node.v1::runtime-down-message))
       (let ((heartbeat (slot-value envelope 'gr8s.node.v1::heartbeat)))
         (note-node-pressure
          (node-grpc-server-store server) node-name
          (slot-value heartbeat 'gr8s.node.v1::memory-pressure)
          (slot-value heartbeat 'gr8s.node.v1::disk-pressure)
          (slot-value heartbeat 'gr8s.node.v1::pid-pressure)))
       (note-node-heartbeat-lease (node-grpc-server-store server) node-name now)
       (unless previously-ready-p
         (note-topology-decision
          server now node-name :recovered-as-destination
          "heartbeat restored; reachable as a destination while transit cooldown runs")
         (refresh-node-peer-topology server node-name))))
    (:snapshot-ack
     (note-node-snapshot-ack
      server node-name
      (slot-value envelope 'gr8s.node.v1::snapshot-ack) session))
    (:gateway-config-ack
     (note-node-gateway-config-ack
      server node-name (slot-value envelope 'gr8s.node.v1::gateway-config-ack) session))
    (:status
     (let ((status (slot-value envelope 'gr8s.node.v1::status)))
       (note-node-gateway-status server node-name status session)
       (multiple-value-bind (receivers valid-p)
           (note-node-service-receiver-status server node-name status session)
         (setf (slot-value status 'gr8s.node.v1::service-receivers) receivers
               (slot-value status 'gr8s.node.v1::service-receiver-revision)
               (if valid-p
                   (slot-value status 'gr8s.node.v1::service-receiver-revision)
                   0)))
       (when (slot-value status 'gr8s.node.v1::resource-capacity)
         (update-node-capacity
          (node-grpc-server-store server) node-name
          (node-capacity-from-entries (slot-value status 'gr8s.node.v1::resource-capacity))
          :allocatable (node-capacity-from-entries (slot-value status 'gr8s.node.v1::resource-allocatable))))
       (setf (slot-value status 'gr8s.node.v1::wireguard-peer-observations)
             (canonical-node-wireguard-observations
              server node-name
              (slot-value status 'gr8s.node.v1::wireguard-peer-observations)))
       (bt:with-lock-held ((node-grpc-server-lock server))
         (setf (gethash node-name (node-grpc-server-statuses server)) status))
       (handler-case
           (update-node-csi-registrations (node-grpc-server-store server) node-name
                                          (slot-value status 'gr8s.node.v1::csi-drivers))
         (kubernetes-error (condition)
           (format *error-output* "gr8s CSINode ~A update failed: ~A~%" node-name condition)))
       (let ((entries (slot-value status 'gr8s.node.v1::device-plugin-resources)))
         (when entries
           (let ((resources (core-object)))
             (dolist (entry entries)
               (unless (and (extended-resource-name-p (car entry))
                            (plusp (length (cdr entry))) (every #'digit-char-p (cdr entry)))
                 (error "Invalid device plugin capacity from node ~A" node-name))
               (setf (gethash (car entry) resources) (cdr entry)))
             (update-node-extended-resources (node-grpc-server-store server) node-name resources :merge t))))
       (record-authenticated-wireguard-observations
        server node-name
        (slot-value status 'gr8s.node.v1::wireguard-peer-observations))
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
                                           (com.inuoe.jzon:parse bytes))
                                       (error () nil))))
                        (unless (hash-table-p object) (setf object (make-hash-table :test #'equal)))
                        (merge-node-pod-address-status object pod-status)
                        (let ((events (gethash "gr8sRuntimeEvents" object)))
                          (remhash "gr8sRuntimeEvents" object)
                          (save-pod-observation
                           (node-grpc-server-store server) pod object
                           :validator
                           (lambda (copy)
                             (let ((translation (gr8s.network::normalize-node-service-translation
                                                 (node-grpc-server-store server) node-name pod copy)))
                               (if translation
                                   (setf (gethash "gr8sServiceTranslation" copy) translation)
                                   (remhash "gr8sServiceTranslation" copy)))
                             (setf object copy)))
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
      server node-name (slot-value envelope 'gr8s.node.v1::operation-response)))
    (:operation-stream
     (note-node-operation-stream
      server node-name (slot-value envelope 'gr8s.node.v1::operation-stream)))
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
       :message (princ-to-string condition)
       :session-endpoints
       (when (typep condition 'node-session-not-admitted)
         (node-session-not-admitted-endpoints condition)))
      :sequence 1))))

(defun node-sessions-admitted-p (server)
  (let ((predicate (node-grpc-server-session-admission-fn server)))
    (or (null predicate) (funcall predicate))))

(define-condition node-session-not-admitted (error)
  ((endpoints :initarg :endpoints :initform nil :reader node-session-not-admitted-endpoints))
  (:report "Node sessions require an active control-plane leader; reconnect to another endpoint")
  (:documentation "This member is not the leader that serves node sessions.
ENDPOINTS, HOST:PORT strings, are the members that may be, leader first."))

(defun node-session-endpoint-strings (server)
  "The members that serve node sessions, as HOST:PORT strings, leader first."
  (let ((endpoints-fn (node-grpc-server-session-endpoints-fn server)))
    (when endpoints-fn
      (mapcar (lambda (endpoint) (format nil "~A:~D" (first endpoint) (second endpoint)))
              (ignore-errors (funcall endpoints-fn))))))

(defun ensure-node-session-admitted (server)
  (unless (node-sessions-admitted-p server)
    (error 'node-session-not-admitted :endpoints (node-session-endpoint-strings server))))

(defun call-once-store-is-available (function &key (patience 35) (pause 0.05))
  "Call FUNCTION, and again after PAUSE seconds for as long as it signals a 503.
A checkpoint closes the store to writes for a moment, up to its drain limit; an
agent's report that arrives then is handled once the store reopens rather than
ending the session, which costs the node its readiness (podster-htq). After
PATIENCE seconds the 503 is signalled as it stands."
  (loop with deadline = (+ (get-internal-real-time) (* patience internal-time-units-per-second))
        do (handler-case (return (funcall function))
             (kubernetes-error (condition)
               (unless (and (eql 503 (kubernetes-error-status-code condition))
                            (< (get-internal-real-time) deadline))
                 (error condition))
               (sleep pause)))))

(defun handle-node-connect-internal (server context stream)
  "Serve one agent Connect stream end to end: read and authenticate the NodeHello,
   update the node's underlay address/capacity/kubelet port, build its connect
   snapshot, then -- holding the session send lock so nothing races the handshake --
   register the session, send ServerHello and the initial complete snapshot, and
   flush any queued operations. Then loop handling inbound envelopes until the stream
   ends. On exit deregisters the session and fails its pending operations. Refreshes
   peer topology when this node's underlay address changed."
  (ensure-node-session-admitted server)
  (let ((first (ag-grpc:stream-recv stream)))
    (unless first (error "Node session ended before its hello"))
    (ensure-node-protocol-version (slot-value first 'gr8s.node.v1::protocol-version))
    (let* ((hello (node-envelope-payload first :hello))
           (node-name (slot-value hello 'gr8s.node.v1::node-name))
           (authenticated (authenticate-node-peer (node-grpc-server-pki server) context node-name))
           (certificate-request (slot-value hello 'gr8s.node.v1::certificate-request))
           (renewed-node-certificate
             (if (and authenticated
                      (node-certificate-needs-active-ca-renewal-p
                       (node-grpc-server-pki server) authenticated))
                 (progn
                   (unless (plusp (length certificate-request))
                     (error "Node ~A must provide a certificate request to renew its retired-CA credential"
                            node-name))
                   (babel:string-to-octets
                    (renew-authenticated-node-csr
                     (node-grpc-server-pki server) node-name authenticated certificate-request)
                    :encoding :utf-8))
                 #()))
           (wireguard-public-key
             (slot-value hello 'gr8s.node.v1::wireguard-public-key))
           (wireguard-endpoints
             (mapcar
              (lambda (endpoint)
                (list (slot-value endpoint 'gr8s.node.v1::name)
                      (slot-value endpoint 'gr8s.node.v1::address)
                      (slot-value endpoint 'gr8s.node.v1::port)))
              (slot-value hello 'gr8s.node.v1::wireguard-endpoints)))
           (node (get-node (node-grpc-server-store server) node-name))
           (previously-ready-p (node-record-ready-p node))
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
                        wireguard-public-key))
                     (endpoints-changed
                       (update-node-wireguard-endpoints
                        (node-grpc-server-store server) node-name
                        (merge-wireguard-advertised-endpoints
                         wireguard-endpoints
                         (node-record-wireguard-endpoints node)))))
                 (or address-changed key-changed endpoints-changed))))
           (ready-node
             (mark-node-ready
              (node-grpc-server-store server) node-name
              (funcall (node-grpc-server-clock server))
              :lease-duration (node-grpc-server-heartbeat-timeout-seconds server)))
           (snapshot
             (let ((predecessor
                     ;; Remove the predecessor before building the reconnect snapshot.
                     ;; Otherwise a concurrent publisher could select its old grant.
                     (bt:with-lock-held ((node-grpc-server-lock server))
                       (prog1 (gethash node-name (node-grpc-server-sessions server))
                         (remhash node-name (node-grpc-server-sessions server))
                         (remhash node-name (node-grpc-server-acknowledged-revisions server))
                         (clear-service-risk-grant-locked server)))))
               ;; Close the superseded session's connection so its handler thread
               ;; and socket are released; otherwise a node that reconnects
               ;; repeatedly leaks connections against the listener's slot cap.
               (when predecessor (close-node-agent-session predecessor))
               (prepare-node-connect-snapshot
                server node-name
                (slot-value hello 'gr8s.node.v1::last-applied-revision))))
           (session (progn
                      (update-node-capacity (node-grpc-server-store server) node-name
                                            (node-capacity-from-entries (slot-value hello 'gr8s.node.v1::capacity)))
                      (update-node-kubelet-port (node-grpc-server-store server) node-name
                                                (or (slot-value hello 'gr8s.node.v1::kubelet-port) 0))
                      (let ((session (make-node-agent-session stream)))
                        (setf (node-agent-session-node-id session) (node-record-id node)
                              (node-agent-session-deltas-p session)
                              (member +desired-state-delta-capability+
                                      (slot-value hello 'gr8s.node.v1::capabilities)
                                      :test #'equal)
                              (node-agent-session-gateway-deltas-p session)
                              (member gr8s.protocol::+gateway-config-delta-capability+
                                      (slot-value hello 'gr8s.node.v1::capabilities) :test #'equal)
                              (node-agent-session-service-risk-v2-p session)
                              (member "service-risk-v2"
                                      (slot-value hello 'gr8s.node.v1::capabilities)
                                      :test #'equal))
                        session)))
           (heartbeat-interval
             (max 1 (floor (node-grpc-server-heartbeat-timeout-seconds server) 2))))
      (declare (ignore ready-node))
      (when authenticated
        (record-node-certificate-issuer
         (node-grpc-server-store server) node-name
         (node-certificate-issuer-fingerprint
          (node-grpc-server-pki server) authenticated)))
      (unwind-protect
           (progn
             (ensure-node-session-admitted server)
             ;; Register and drain queued work atomically; hold the send lock
             ;; through the handshake so a concurrent publication or operation
             ;; cannot arrive before ServerHello and the initial snapshot.
             (bt:with-lock-held ((node-agent-session-lock session))
               (let ((operations nil))
                 (bt:with-lock-held ((node-grpc-server-lock server))
                   (setf (gethash node-name (node-grpc-server-sessions server)) session
                         snapshot (gethash node-name (node-grpc-server-snapshots server) snapshot)
                         operations (gethash node-name (node-grpc-server-operation-queues server)))
                   ;; Bind drained work before any handshake step can fail.
                   (dolist (operation operations)
                     (setf (pending-node-operation-session operation) session))
                   (clear-service-risk-grant-locked server)
                   ;; A previous session's ACK cannot prove this incarnation
                   ;; has rebuilt its local v2 risk map after a restart.
                   (remhash node-name (node-grpc-server-acknowledged-revisions server))
                   (remhash node-name (node-grpc-server-operation-queues server)))
                 ;; Recheck outside the server lock: leadership may have changed
                 ;; during the handshake, after the monitor last swept sessions.
                 (ensure-node-session-admitted server)
                 (ag-grpc:stream-send
                  stream (make-server-envelope
                          :hello (make-instance 'gr8s.node.v1::server-hello
                                                :node-id (node-record-id node)
                                                :heartbeat-interval-seconds heartbeat-interval
                                               :assigned-pod-cidr (node-record-pod-cidr node)
                                               :assigned-pod-cidrs
                                               (coerce (node-record-all-pod-cidrs node) 'list)
                                               :cluster-ca-bundle
                                               (if (node-grpc-server-pki server)
                                                   (babel:string-to-octets
                                                    (uiop:read-file-string
                                                     (cluster-pki-ca-certificate-path
                                                      (node-grpc-server-pki server)))
                                                    :encoding :utf-8)
                                                   #())
                                               :renewed-node-certificate
                                               renewed-node-certificate
                                               :session-endpoints
                                               (node-session-endpoint-strings server))
                          :sequence 1))
                 ;; Every session starts from a complete snapshot.
                 (ag-grpc:stream-send
                  stream (make-server-envelope :desired-state snapshot :sequence 2))
                 (setf (node-agent-session-delivered session) snapshot)
                 (install-node-gateway-baseline session snapshot)
                 (loop for operation in operations for sequence from 3
                       do (ag-grpc:stream-send
                           stream (make-server-envelope
                                   :operation-request (pending-node-operation-request operation)
                                   :sequence sequence)))))
             (when (or topology-changed (not previously-ready-p))
               (unless previously-ready-p
                 (note-topology-decision
                  server (funcall (node-grpc-server-clock server)) node-name
                  :recovered-as-destination
                  "authenticated session restored; reachable as a destination while transit cooldown runs"))
               (refresh-node-peer-topology server node-name))
             (loop for envelope = (ag-grpc:stream-recv stream)
                   while envelope
                   do (setf (node-agent-session-last-envelope-time session) (get-universal-time))
                      (call-once-store-is-available
                       (lambda () (handle-node-agent-envelope server node-name envelope session)))
                      (setf (node-agent-session-last-envelope-time session) (get-universal-time))))
        (bt:with-lock-held ((node-grpc-server-lock server))
          (when (eq session (gethash node-name (node-grpc-server-sessions server)))
            (remhash node-name (node-grpc-server-sessions server))
            (clear-service-risk-grant-locked server)))
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

(defun close-node-agent-session (session)
  "Evict SESSION and close its underlying connection so its handler thread and
socket are released rather than leaked. Safe to call more than once."
  (setf (node-agent-session-evicted-p session) t)
  (let ((stream (node-agent-session-stream session)))
    (when (typep stream 'ag-grpc::grpc-server-call-stream)
      (ignore-errors
       (ag-http2:connection-close (ag-grpc::server-stream-connection stream))))))

(defun evict-inadmissible-node-sessions (server)
  "Release follower-owned streams so agents reconnect to the publishing leader."
  (unless (node-sessions-admitted-p server)
    (let ((sessions (bt:with-lock-held ((node-grpc-server-lock server))
                      (loop for session being the hash-values of (node-grpc-server-sessions server)
                            unless (node-agent-session-evicted-p session) collect session))))
      ;; Closing connections can run stream cleanup; never do it under the lock.
      (dolist (session sessions) (close-node-agent-session session)))))

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
          do (log-node-session-stall "no envelope handled from node ~A; closing its session" node-name)
             (close-node-agent-session session))))

(defun stable-transit-node-names (server now)
  "Return ready nodes whose uninterrupted lease has passed the gateway cooldown."
  (sort
   (loop for node in (list-nodes (node-grpc-server-store server))
         for ready-since = (node-record-ready-since node)
         when (and (node-record-ready-p node) ready-since
                   (>= (- now ready-since)
                       (node-grpc-server-gateway-stability-seconds server)))
           collect (node-record-name node))
   #'string<))

(defun note-topology-decision (server now node reason message)
  "Prepend one bounded operator-readable sparse-topology decision."
  (bt:with-lock-held ((node-grpc-server-lock server))
    (push (list :at now :node node :reason reason :message message)
          (node-grpc-server-topology-decisions server))
    (when (> (length (node-grpc-server-topology-decisions server)) 128)
      (setf (node-grpc-server-topology-decisions server)
            (subseq (node-grpc-server-topology-decisions server) 0 128)))))

(defun reconcile-node-heartbeats (server now &key (expire-leases t))
  "Expire failed leases when EXPIRE-LEASES, update stable transit admission, and
   republish topology."
  (let* ((expired
           (when expire-leases
             (expire-node-heartbeats
              (node-grpc-server-store server)
              (- now (node-grpc-server-heartbeat-timeout-seconds server)) :now now)))
         (stable (stable-transit-node-names server now))
         (added nil)
         (removed nil))
    (bt:with-lock-held ((node-grpc-server-lock server))
      (let ((previous (node-grpc-server-transit-eligible server)))
        (setf added (remove-if (lambda (name) (gethash name previous)) stable)
              removed (loop for name being the hash-keys of previous
                            unless (member name stable :test #'string=)
                              collect name))
        (clrhash previous)
        (dolist (name stable) (setf (gethash name previous) t))))
    (dolist (node expired)
      (format *error-output* "gr8s: node ~A lease expired~@[ ~Ds after its last heartbeat~]; marked not ready~%"
              (node-record-name node)
              (and (gr8s.model::node-record-last-heartbeat node)
                   (- now (gr8s.model::node-record-last-heartbeat node))))
      (note-topology-decision
       server now (node-record-name node) :lease-expired
       "lease expired; removed from destinations and transit immediately"))
    (dolist (name added)
      (note-topology-decision
       server now name :stability-window-satisfied
       "uninterrupted ready interval satisfied; admitted as a sparse transit gateway"))
    (dolist (name removed)
      (unless (find name expired :key #'node-record-name :test #'string=)
        (note-topology-decision
         server now name :transit-ineligible
         "node is no longer eligible to carry third-party sparse traffic")))
    (when (and (string= "wireguard" (node-grpc-server-overlay-backend server))
               (or expired added removed))
      (refresh-node-peer-topology server ""))
    expired))

(defun node-heartbeats-recordable-since (server recordable-since now)
  "When this member last became able to record heartbeats without a break, given
   that it was RECORDABLE-SINCE at the previous look: NOW if it has just become
   able, NIL while it cannot. Only the member that admits node sessions sees
   heartbeats, and not while its store is closed."
  (let ((store (node-grpc-server-store server)))
    (if (and (node-sessions-admitted-p server)
             (not (and store (gr8s.store::store-access-blocked-p store))))
        (or recordable-since now)
        nil)))

(defun node-leases-judgeable-p (recordable-since now timeout)
  "Whether a lease found expired at NOW can be held against its node: only once
   this member has been able to record heartbeats for a whole lease TIMEOUT. A
   follower never sees them, and a leader whose store was closed for a long
   checkpoint, or that was elected a moment ago, has not been listening long
   enough to know a node is gone (podster-htq)."
  (and recordable-since (>= (- now recordable-since) timeout)))

(defun monitor-node-heartbeats (server)
  "Until SERVER is stopping, every 50ms expire node leases past the heartbeat
   timeout and evict sessions that have gone silent."
  (loop with recordable-since = nil
        until (node-grpc-server-stopping-p server)
        do (evict-inadmissible-node-sessions server)
           (let ((now (funcall (node-grpc-server-clock server))))
             (setf recordable-since (node-heartbeats-recordable-since server recordable-since now))
             (handler-case
                 (reconcile-node-heartbeats
                  server now
                  :expire-leases (node-leases-judgeable-p
                                  recordable-since now
                                  (or (node-grpc-server-heartbeat-timeout-seconds server) 0)))
               (kubernetes-error (condition)
                 ;; A renewed lease may win consensus while this member's
                 ;; expiry is in flight. Retry from committed state next tick;
                 ;; temporary loss of a leader must not kill monitoring either.
                 (unless (member (kubernetes-error-status-code condition) '(409 503))
                   (error condition))))
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

(defun node-status-wireguard-observation (status public-key &key now)
  (and status
       (find public-key
             (subseq (slot-value status 'gr8s.node.v1::wireguard-peer-observations)
                     0 (min 64 (length (slot-value status
                                                   'gr8s.node.v1::wireguard-peer-observations))))
             :test #'equalp
             :key (lambda (observation)
                    (and (or (null now)
                             (<= 0 (- now (slot-value observation
                                                      'gr8s.node.v1::latest-handshake-unix-seconds))
                                 180))
                         (slot-value observation 'gr8s.node.v1::peer-public-key))))))

(defun unix-seconds-for-server (server)
  (let ((value (funcall (node-grpc-server-clock server))))
    (if (> value 2208988800) (- value 2208988800) value)))

(defun effective-route-peer-key (route)
  (let ((hop (slot-value route 'gr8s.node.v1::next-hop)))
    (slot-value (or hop route) 'gr8s.node.v1::wireguard-public-key)))

(defun canonical-node-wireguard-observations (server node-name observations)
  "Bound, deduplicate, validate and clamp authenticated node path evidence."
  (let ((allowed (handler-case
                     (mapcar #'effective-route-peer-key
                             (assigned-node-routes server node-name))
                   (kubernetes-error () nil)))
        (seen nil)
        (now (unix-seconds-for-server server)))
    (loop for observation in observations
          for index from 0 below 256
          for key = (slot-value observation 'gr8s.node.v1::peer-public-key)
          for handshake = (slot-value observation
                                      'gr8s.node.v1::latest-handshake-unix-seconds)
          when (and (< (length seen) 64)
                    (= 32 (length key))
                    (stringp (slot-value observation 'gr8s.node.v1::address))
                    (plusp (length (slot-value observation 'gr8s.node.v1::address)))
                    (<= 1 (slot-value observation 'gr8s.node.v1::port) 65535)
                    (find key allowed :test #'equalp)
                    (not (find key seen :test #'equalp))
                    (<= 0 (- now handshake) 180))
            collect
            (progn
              (push key seen)
              (make-instance
               'gr8s.node.v1::wireguard-peer-observation
               :peer-public-key key
               :address (slot-value observation 'gr8s.node.v1::address)
               :port (slot-value observation 'gr8s.node.v1::port)
               :latest-handshake-unix-seconds handshake
               :received-bytes (slot-value observation 'gr8s.node.v1::received-bytes)
               :path-score (steering-bounded-integer
                            (slot-value observation 'gr8s.node.v1::path-score) 10000 10000)
               :healthy (slot-value observation 'gr8s.node.v1::healthy)
               :active-flows (steering-bounded-integer
                              (slot-value observation 'gr8s.node.v1::active-flows) 1000))))))

(defun rank-image-tracker-peers (server requesting-node peers)
  "Rank authenticated swarm peers using locality and the requester's kernel evidence."
  (let* ((store (node-grpc-server-store server))
         (source (get-node store requesting-node))
         (routes (assigned-node-routes server requesting-node))
         (now (unix-seconds-for-server server))
         (status (bt:with-lock-held ((node-grpc-server-lock server))
                   (gethash requesting-node (node-grpc-server-statuses server)))))
    (multiple-value-bind (source-region source-zone) (node-network-domain source)
      (mapcar
       (lambda (candidate) (getf candidate :value))
       (rank-network-steering-candidates
        (loop for peer in peers
              for node = (handler-case
                             (get-node store
                                       (gr8s.image-distribution::tracker-peer-node-name peer))
                           (kubernetes-error () nil))
              when node
                collect
                (multiple-value-bind (region zone) (node-network-domain node)
                  (let* ((route (find (node-record-name node) routes :test #'string=
                                      :key (lambda (candidate)
                                             (slot-value candidate
                                                         'gr8s.node.v1::node-name))))
                         (observation
                          (node-status-wireguard-observation
                           status
                           (if route (effective-route-peer-key route)
                               (node-record-wireguard-public-key node))
                           :now now)))
                    (list
                     :value peer
                     :node-name (node-record-name node)
                     :same-node (string= requesting-node (node-record-name node))
                     :same-zone (and (string= source-region region)
                                     (string= source-zone zone))
                     :same-region (string= source-region region)
                     :failure-domain (list region zone)
                     :capacity (node-steering-capacity-score (node-record-capacity node))
                     :link-cost (node-network-link-cost source node)
                     :healthy (if observation
                                  (slot-value observation 'gr8s.node.v1::healthy)
                                  t)
                     :path-score (if observation
                                     (slot-value observation 'gr8s.node.v1::path-score)
                                     10000)
                     :active-flows (if observation
                                       (slot-value observation 'gr8s.node.v1::active-flows)
                                       0))))))))))

(defun commit-image-tracker-request (server request action)
  "Commit one deterministic tracker mutation, locally or through HA Raft."
  (let* ((tracker (node-grpc-server-image-tracker server))
         (command
           (gr8s.image-distribution::make-tracker-command
            :action action
            :digest (slot-value request 'gr8s.node.v1::digest)
            :node-name (slot-value request 'gr8s.node.v1::node-name)
            :now (funcall (gr8s.image-distribution::image-tracker-clock tracker))
            :token (if (eq action :acquire)
                       (gr8s.image-distribution::new-origin-token)
                       (slot-value request 'gr8s.node.v1::lease-token))
            :metainfo (slot-value request 'gr8s.node.v1::metainfo)
            :address (slot-value request 'gr8s.node.v1::peer-address)
            :port (slot-value request 'gr8s.node.v1::peer-port)
            :peer-id (slot-value request 'gr8s.node.v1::peer-id)
            :complete-p (slot-value request 'gr8s.node.v1::complete)))
         (commit (pod-store-consensus-commit-fn (node-grpc-server-store server)))
         (result (if commit
                     (funcall commit :image-tracker command)
                     (gr8s.image-distribution::tracker-apply-command tracker command))))
    (when (eq :error (getf result :status))
      (error "~A" (getf result :message)))
    result))

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
            (gr8s.image-distribution::tracker-lookup
             tracker digest node-name
             :peer-ranker (lambda (peers)
                            (rank-image-tracker-peers server node-name peers)))))
          ((string= action "acquire")
           (let ((result (commit-image-tracker-request server request :acquire)))
             (response (string-downcase (symbol-name (getf result :status)))
                       :token (gr8s.image-distribution::tracker-result-octets
                               result :token)
                       :expires-at (getf result :expires-at))))
          ((string= action "renew")
           (let ((result (commit-image-tracker-request server request :renew)))
             (response "ok" :expires-at (getf result :expires-at))))
          ((string= action "publish")
           (let ((result (commit-image-tracker-request server request :publish)))
             (response "ok"
                       :infohash
                       (gr8s.image-distribution::tracker-result-octets
                        result :infohash))))
          ((string= action "announce")
           (commit-image-tracker-request server request :announce)
           (response "ok"))
          ((string= action "withdraw")
           (commit-image-tracker-request server request :withdraw)
           (response "ok"))
          (t (error "Unknown image tracker action ~S" action)))))))

(defun start-node-grpc-server (store &key (host "127.0.0.1") (port 0)
                                            (heartbeat-timeout-seconds 15)
                                            pki
                                            session-admission-fn session-endpoints-fn
                                            (cluster-pod-cidr +default-cluster-pod-cidr+)
                                            (node-prefix +default-node-pod-prefix+)
                                            cluster-pod-cidrs
                                            node-prefixes
                                            (overlay-backend "vxlan")
                                            mtu
                                            (wireguard-listen-port 51820)
                                            wireguard-relay-address
                                            (wireguard-relay-listen "0.0.0.0")
                                            (wireguard-relay-port-start 42000)
                                            (wireguard-relay-max-channels 1024)
                                            (clock #'get-universal-time)
                                            (gateway-stability-seconds 30)
                                            (max-connections-per-ip
                                             +default-node-max-connections-per-ip+))
  "Create and start the node control-plane gRPC server on HOST:PORT: register the
   Connect service (and the Enrollment service when PKI is given), spawn its accept
   thread and the heartbeat monitor, and block until it is listening. Errors on a
   non-positive heartbeat timeout or if the listener never comes up. Returns the
   NODE-GRPC-SERVER (with its actual bound port)."
  (unless (plusp heartbeat-timeout-seconds)
    (error "Heartbeat timeout must be positive"))
  (unless (and (integerp gateway-stability-seconds)
               (not (minusp gateway-stability-seconds)))
    (error "Gateway stability interval must be a non-negative integer"))
  (unless (member overlay-backend '("vxlan" "wireguard") :test #'string=)
    (error "Overlay backend must be vxlan or wireguard"))
  (unless (or (null mtu) (and (integerp mtu) (<= 1280 mtu 9000)))
    (error "Pod MTU must be between 1280 and 9000"))
  (unless (<= 1 wireguard-listen-port 65535)
    (error "WireGuard listen port must be between 1 and 65535"))
  (multiple-value-bind (cluster-pod-cidrs node-prefixes)
      (normalize-pod-pool-geometry (or cluster-pod-cidrs cluster-pod-cidr)
                                   (or node-prefixes node-prefix))
    (when (and wireguard-relay-address (not (string= overlay-backend "wireguard")))
      (error "WireGuard relay requires the wireguard overlay backend"))
    (let* ((grpc-server (apply #'ag-grpc:make-grpc-server port :host host
                             :max-connections-per-ip max-connections-per-ip
                             (node-server-tls-options pki)))
         (relay-server
           (when wireguard-relay-address
             (gr8s.network::start-wireguard-relay-server
              :address wireguard-relay-listen
              :port-start wireguard-relay-port-start
              :max-channels wireguard-relay-max-channels)))
         (server (%make-node-grpc-server
                  :store store
                  :session-admission-fn session-admission-fn
                  :session-endpoints-fn session-endpoints-fn
                  :grpc-server grpc-server
                  :port port
                  :heartbeat-timeout-seconds heartbeat-timeout-seconds
                  :pki pki
                  :cluster-pod-cidr (first cluster-pod-cidrs)
                  :node-prefix (first node-prefixes)
                  :cluster-pod-cidrs cluster-pod-cidrs
                  :node-prefixes node-prefixes
                  :overlay-backend overlay-backend
                  :mtu mtu
                  :wireguard-listen-port wireguard-listen-port
                  :wireguard-relay-server relay-server
                  :wireguard-relay-address wireguard-relay-address
                  :image-tracker (pod-store-image-tracker store)
                  :clock clock
                  :gateway-stability-seconds gateway-stability-seconds))
         (started-p nil))
    (unwind-protect
      (progn
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
        (setf started-p t)
        server)
      (unless started-p
        (ignore-errors (ag-grpc:server-stop grpc-server))
        (when relay-server
          (gr8s.network::stop-wireguard-relay-server relay-server)))))))

(defun refresh-node-grpc-server-pki (server pki)
  "Use PKI for new node TLS connections and authenticated session handling."
  (ensure-node-server-credentials pki)
  (let ((trust (pure-tls::make-trust-store
                :certificates (cluster-pki-trust-certificates pki))))
    (bt:with-lock-held ((node-grpc-server-lock server))
      (setf (node-grpc-server-pki server) pki
            (ag-grpc::server-tls-ca-certificate
             (node-grpc-server-grpc-server server)) trust)))
  server)

(defun stop-node-grpc-server (server)
  "Stop SERVER: signal its loops to stop, stop the gRPC server, and join its monitor
   and accept threads with a bounded wait, destroying a thread still wedged in
   accept(2) as the last resort. Returns SERVER."
  (setf (node-grpc-server-stopping-p server) t)
  (when (node-grpc-server-wireguard-relay-server server)
    (gr8s.network::stop-wireguard-relay-server
     (node-grpc-server-wireguard-relay-server server)))
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
  (and (same-node-non-discovery-content-p left right)
       (equalp (slot-value left 'gr8s.node.v1::service-discovery-objects-json)
               (slot-value right 'gr8s.node.v1::service-discovery-objects-json))))

(defun same-node-non-discovery-content-p (left right)
  "Compare every desired-state field other than discovery rows and envelope revision."
  (and left right (same-node-snapshot-topology-p left right)
       (= (slot-value left 'gr8s.node.v1::gateway-dependency-revision)
          (slot-value right 'gr8s.node.v1::gateway-dependency-revision))
       (equalp (slot-value left 'gr8s.node.v1::service-risk-grant-digest)
               (slot-value right 'gr8s.node.v1::service-risk-grant-digest))
       (equalp (service-risk-snapshot-receiver-projection left)
               (service-risk-snapshot-receiver-projection right))
       (= (length (slot-value left 'gr8s.node.v1::pods)) (length (slot-value right 'gr8s.node.v1::pods)))
       (every #'same-pod-assignment-p (slot-value left 'gr8s.node.v1::pods) (slot-value right 'gr8s.node.v1::pods))))

(defun node-gateway-progress-current-p (session)
  "Pending sends may trail ACKs, but must not conceal a failed or stalled apply."
  (and (not (node-agent-session-gateway-repair-required-p session))
       (or (= (node-agent-session-gateway-revision session)
              (node-agent-session-gateway-acknowledged-revision session))
           (let ((since (node-agent-session-gateway-pending-since session)))
             (and since (< (- (get-internal-real-time) since)
                           (* *node-session-stall-seconds* internal-time-units-per-second)))))))

(defun node-session-gateway-repair-current-p (server node-name session baseline snapshot)
  "Check the live full baseline and progress fences with SESSION and SERVER locked."
  (and session baseline
       (eq session (gethash node-name (node-grpc-server-sessions server)))
       (not (node-agent-session-evicted-p session))
       (node-agent-session-gateway-deltas-p session)
       (eq baseline (node-agent-session-delivered session))
       (node-agent-session-gateway-resources session)
       (= (slot-value baseline 'gr8s.node.v1::revision)
          (gethash node-name (node-grpc-server-acknowledged-revisions server) 0))
       (node-gateway-progress-current-p session)
       (eql (node-agent-session-gateway-dependency-epoch session)
            (slot-value snapshot 'gr8s.node.v1::gateway-dependency-revision))
       (same-node-non-discovery-content-p baseline snapshot)))


(defun node-session-gateway-repair (server node-name session baseline snapshot)
  "Return eligibility and Gateway changes for authoritative repair.
Caller holds SESSION then SERVER locks inside node publication. Non-Gateway
state must match exactly; Gateway differences include missed events and deletes."
  (unless (node-session-gateway-repair-current-p server node-name session baseline snapshot)
    (return-from node-session-gateway-repair nil))
  (let ((gateway (node-agent-session-gateway-resources session))
        (other (make-hash-table :test #'equal))
        (seen (make-hash-table :test #'equal))
        (changes nil)
        (baseline-cache (node-agent-session-gateway-discovery-key-cache session))
        (repair-cache (node-agent-session-gateway-repair-key-cache session))
        (next-cache (make-hash-table :test #'eq)))
    (labels ((key-for (bytes)
               ;; Captured projections reuse immutable encoded rows. Consult their
               ;; validated identities before hashing or parsing their contents.
               (or (and repair-cache (gethash bytes repair-cache))
                   (and baseline-cache (gethash bytes baseline-cache))
                   (car (gr8s.kubelet::decode-service-discovery-entry bytes))))
             (gateway-key-p (key)
               (member (first key) gr8s.protocol::+gateway-config-resources+ :test #'equal))
             (change (key bytes)
               (make-instance 'gr8s.node.v1::gateway-resource-change
                              :resource (first key) :namespace (or (second key) "")
                              :name (third key) :deleted (null bytes)
                              :object-json (or bytes (make-array 0 :element-type '(unsigned-byte 8))))))
      (dolist (bytes (slot-value baseline 'gr8s.node.v1::service-discovery-objects-json))
        (let ((key (key-for bytes)))
          (unless (gateway-key-p key) (setf (gethash key other) bytes))))
      (dolist (bytes (slot-value snapshot 'gr8s.node.v1::service-discovery-objects-json))
        (let ((key (key-for bytes)))
          (when (gethash key seen) (return-from node-session-gateway-repair nil))
          (if (gateway-key-p key)
              (unless (equalp bytes (gethash key gateway)) (push (change key bytes) changes))
              (unless (equalp bytes (gethash key other))
                (return-from node-session-gateway-repair nil)))
          (setf (gethash key seen) t (gethash bytes next-cache) key)))
      (maphash (lambda (key bytes)
                 (declare (ignore bytes))
                 (unless (gethash key seen) (return-from node-session-gateway-repair nil))) other)
      (maphash (lambda (key bytes)
                 (declare (ignore bytes))
                 (unless (gethash key seen) (push (change key nil) changes))) gateway))
    (setf (node-agent-session-gateway-repair-key-cache session) next-cache)
    (values t (nreverse changes))))

(defun service-risk-node-identities (store)
  (mapcar (lambda (node) (cons (node-record-name node) (node-record-id node)))
          (gr8s.controllers::list-nodes store)))

(defun service-risk-owner-projection (store)
  (mapcar #'ag-proto:serialize-to-bytes
          (gr8s.network::service-translation-identity-messages store)))

(defun service-risk-snapshot-owner-projection (snapshot)
  (let ((network (slot-value snapshot 'gr8s.node.v1::network)))
    (when network
      (mapcar #'ag-proto:serialize-to-bytes
              (slot-value network 'gr8s.node.v1::service-translations)))))

(defun service-risk-snapshot-receiver-projection (snapshot)
  (mapcar #'ag-proto:serialize-to-bytes
          (slot-value snapshot 'gr8s.node.v1::service-receivers)))

(defun cluster-service-ready-receivers-locked
    (server owner-projection identities)
  "Return the complete receiver set only after authenticated node reports
cover this owner projection. The caller holds the server lock."
  (when (service-risk-receivers-published-locked-p
         server owner-projection identities)
    (mapcar (lambda (bytes)
              (let ((owner (ag-proto:deserialize-from-bytes
                            'gr8s.node.v1::service-translation-identity bytes)))
                (make-instance 'gr8s.node.v1::service-receiver-proof
                               :pod-uid (slot-value owner 'gr8s.node.v1::pod-uid)
                               :incarnation
                               (gr8s.network::service-translation-incarnation-token
                                (slot-value owner 'gr8s.node.v1::node-id)
                                (slot-value owner 'gr8s.node.v1::sandbox-id)
                                (slot-value owner 'gr8s.node.v1::interface-name)
                                (slot-value owner 'gr8s.node.v1::pod-ip)
                                (slot-value owner 'gr8s.node.v1::translation-ip)
                                (slot-value owner 'gr8s.node.v1::incarnation-generation)))))
            owner-projection)))

(defun service-risk-receivers-published-locked-p
    (server owner-projection identities)
  "Require every trusted owner in this projection to have a current, complete
local receiver report from its authenticated node session. The caller holds
the server lock. A grant-only revision may retain the prior report while the
owner projection stays byte-identical."
  (let ((nodes (make-hash-table :test #'equal))
        (expected (make-hash-table :test #'equal)))
    (dolist (identity identities)
      (setf (gethash (car identity) nodes) (cdr identity)
            (gethash (car identity) expected) (make-hash-table :test #'equal)))
    (dolist (bytes owner-projection)
      (let* ((owner (ag-proto:deserialize-from-bytes
                     'gr8s.node.v1::service-translation-identity bytes))
             (name (slot-value owner 'gr8s.node.v1::node-name))
             (uid (slot-value owner 'gr8s.node.v1::pod-uid))
             (table (gethash name expected)))
        (unless (and table (equal (gethash name nodes)
                                  (slot-value owner 'gr8s.node.v1::node-id))
                     (not (gethash uid table)))
          (return-from service-risk-receivers-published-locked-p nil))
        (setf (gethash uid table)
              (gr8s.network::service-translation-incarnation-token
               (slot-value owner 'gr8s.node.v1::node-id)
               (slot-value owner 'gr8s.node.v1::sandbox-id)
               (slot-value owner 'gr8s.node.v1::interface-name)
               (slot-value owner 'gr8s.node.v1::pod-ip)
               (slot-value owner 'gr8s.node.v1::translation-ip)
               (slot-value owner 'gr8s.node.v1::incarnation-generation)))))
    (every
     (lambda (identity)
       (let* ((name (car identity))
              (session (gethash name (node-grpc-server-sessions server)))
              (report (gethash name (node-grpc-server-service-receiver-reports server)))
              (proofs (third report))
              (table (gethash name expected))
              (seen (make-hash-table :test #'equal)))
         (and report session
              (eq session (first report))
              (not (node-agent-session-evicted-p session))
              (<= (second report)
                  (gethash name (node-grpc-server-acknowledged-revisions server) 0))
              (equalp (fourth report) owner-projection)
              (= (length proofs) (hash-table-count table))
              (every (lambda (proof)
                       (let* ((uid (slot-value proof 'gr8s.node.v1::pod-uid))
                              (epoch (gethash uid table)))
                         (and epoch (not (gethash uid seen))
                              (setf (gethash uid seen) t)
                              (equalp epoch
                                      (slot-value proof 'gr8s.node.v1::incarnation)))))
                     proofs))))
     identities)))

(defun service-risk-retained-grant-locked-p
    (server current-owners identities)
  "Keep a previous grant only while every old receiver remains live.
The new owner projection may add Pods, but it cannot remove or replace an old
incarnation. Reports may cover either the old or new projection while nodes
converge; every old receiver must still be proven by its original session."
  (let ((old-owners (node-grpc-server-service-risk-grant-owner-projection server))
        (sessions (node-grpc-server-service-risk-grant-sessions server)))
    (and (node-grpc-server-service-risk-grant-digest server)
         old-owners sessions
         (equal identities (node-grpc-server-service-risk-grant-identities server))
         (every (lambda (old) (= 1 (count old current-owners :test #'equalp))) old-owners)
         (every
          (lambda (identity previous-session)
            (let* ((name (car identity))
                   (session (gethash name (node-grpc-server-sessions server)))
                   (report (gethash name (node-grpc-server-service-receiver-reports server)))
                   (reported-owners (fourth report))
                   (proofs (third report)))
              (and session (eq session previous-session)
                   (equal (node-agent-session-node-id session) (cdr identity))
                   (not (node-agent-session-evicted-p session))
                   (node-agent-session-service-risk-v2-p session)
                   report (<= (second report)
                              (gethash name
                                       (node-grpc-server-acknowledged-revisions server) 0))
                   (every (lambda (reported)
                            (member reported current-owners :test #'equalp))
                          reported-owners)
                   (every
                    (lambda (bytes)
                      (let* ((owner (ag-proto:deserialize-from-bytes
                                     'gr8s.node.v1::service-translation-identity bytes))
                             (uid (slot-value owner 'gr8s.node.v1::pod-uid))
                             (epoch
                               (gr8s.network::service-translation-incarnation-token
                                (slot-value owner 'gr8s.node.v1::node-id)
                                (slot-value owner 'gr8s.node.v1::sandbox-id)
                                (slot-value owner 'gr8s.node.v1::interface-name)
                                (slot-value owner 'gr8s.node.v1::pod-ip)
                                (slot-value owner 'gr8s.node.v1::translation-ip)
                                (slot-value owner 'gr8s.node.v1::incarnation-generation))))
                        (or (not (equal name (slot-value owner 'gr8s.node.v1::node-name)))
                            (and (member bytes reported-owners :test #'equalp)
                                 (= 1 (count uid proofs :test #'equal
                                             :key (lambda (proof)
                                                    (slot-value proof
                                                                'gr8s.node.v1::pod-uid))))
                                 (some (lambda (proof)
                                         (and (equal uid
                                                     (slot-value proof
                                                                 'gr8s.node.v1::pod-uid))
                                              (equalp epoch
                                                      (slot-value proof
                                                                  'gr8s.node.v1::incarnation))))
                                       proofs)))))
                    old-owners))))
          identities sessions))))

(defun service-risk-grant-for-snapshot-locked (server node-name snapshot)
  "Return this session's current or safely retained previous grant.
The caller holds the server lock; a newly joined or replaced session gets none.
The agent must match a retained digest to its previously approved selection and
check that selection against the current Service plan before preserving it."
  (let* ((digest (node-grpc-server-service-risk-grant-digest server))
         (identities (node-grpc-server-service-risk-grant-identities server))
         (position (position node-name identities :test #'equal :key #'car))
         (session (gethash node-name (node-grpc-server-sessions server)))
         (owners (service-risk-snapshot-owner-projection snapshot)))
    (when (and digest position session
               (equal identities
                      (service-risk-node-identities (node-grpc-server-store server)))
               (not (node-agent-session-evicted-p session))
               (eq session (nth position
                                (node-grpc-server-service-risk-grant-sessions server)))
               (slot-value snapshot 'gr8s.node.v1::network)
               (equalp owners
                       (service-risk-owner-projection (node-grpc-server-store server)))
               (or (and (equalp owners
                                (node-grpc-server-service-risk-grant-owner-projection server))
                        (equalp (node-grpc-server-service-risk-grant-receiver-projection server)
                                (service-risk-snapshot-receiver-projection snapshot))
                        (service-risk-receivers-published-locked-p
                         server owners identities)
                        (equalp digest
                                (gr8s.protocol::service-risk-projection-digest
                                 (slot-value snapshot
                                             'gr8s.node.v1::service-discovery-objects-json))))
                   (and (service-risk-retained-grant-locked-p server owners identities)
                        (every (lambda (old)
                                 (member old
                                         (service-risk-snapshot-receiver-projection snapshot)
                                         :test #'equalp))
                               (node-grpc-server-service-risk-grant-receiver-projection
                                server)))))
      (copy-seq digest))))

(defun publish-node-desired-state (server node-name snapshot &key deduplicate)
  "Publish caller-supplied desired state in the node's ordered delivery domain."
  (call-with-node-publication
   server node-name
   (lambda () (publish-node-desired-state-locked server node-name snapshot :deduplicate deduplicate))))

(defun publish-node-desired-state-locked (server node-name snapshot &key deduplicate)
  "Publish SNAPSHOT as NODE-NAME's new desired state: attach topology, assign the
   next revision, store it, and deliver it to the live session if any (fail-soft).
   With DEDUPLICATE, retains the existing revision for identical content or a
   Gateway-only repair delivered on the current baseline. Errors if NODE-NAME is unknown or SNAPSHOT is not a
   DesiredStateSnapshot. Returns the resulting revision."
  (get-node (node-grpc-server-store server) node-name)
  (unless (typep snapshot 'gr8s.node.v1::desired-state-snapshot)
    (error "Desired state must be a DesiredStateSnapshot"))
  (attach-node-topology server node-name snapshot)
  (let ((revision nil)
        (session nil)
        (repair-p nil)
        (repair-changes nil)
        (locked-session (bt:with-lock-held ((node-grpc-server-lock server))
                          (gethash node-name (node-grpc-server-sessions server)))))
    ;; ACK handlers take session then server; preserve that order here too.
    (flet ((record-snapshot ()
            (bt:with-lock-held ((node-grpc-server-lock server))
              (let* ((owners (service-risk-snapshot-owner-projection snapshot))
                     (identities (service-risk-node-identities (node-grpc-server-store server)))
                     (current (cluster-service-ready-receivers-locked
                               server owners identities)))
                (setf (slot-value snapshot 'gr8s.node.v1::service-receivers)
                      (or current
                          (when (and (equalp owners (service-risk-owner-projection
                                                    (node-grpc-server-store server)))
                                     (service-risk-retained-grant-locked-p
                                      server owners identities))
                            (mapcar (lambda (bytes)
                                      (ag-proto:deserialize-from-bytes
                                       'gr8s.node.v1::service-receiver-proof bytes))
                                    (node-grpc-server-service-risk-grant-receiver-projection
                                     server))))))
              (setf (slot-value snapshot 'gr8s.node.v1::service-risk-grant-digest)
                    (or (service-risk-grant-for-snapshot-locked server node-name snapshot)
                        (make-array 0 :element-type '(unsigned-byte 8))))
              (let ((existing (gethash node-name (node-grpc-server-snapshots server))))
                (when deduplicate
                  (when (and (not (and locked-session
                                       (plusp (node-agent-session-gateway-revision locked-session))))
                             (same-node-desired-content-p existing snapshot))
                    (return-from publish-node-desired-state-locked (slot-value existing 'gr8s.node.v1::revision)))
                  (multiple-value-bind (eligible changes)
                      (node-session-gateway-repair server node-name locked-session existing snapshot)
                    (when eligible
                      (setf repair-p t repair-changes changes
                            revision (slot-value existing 'gr8s.node.v1::revision))
                      (return-from record-snapshot)))))
              (setf revision
                    (1+ (gethash node-name (node-grpc-server-revisions server) 0)))
              (setf (slot-value snapshot 'gr8s.node.v1::revision) revision
                    (gethash node-name (node-grpc-server-revisions server)) revision
                    (gethash node-name (node-grpc-server-snapshots server)) snapshot
                    session (gethash node-name (node-grpc-server-sessions server))))))
      (if locked-session
          (bt:with-lock-held ((node-agent-session-lock locked-session))
            (record-snapshot)
            (when (and repair-p
                       (not (bt:with-lock-held ((node-grpc-server-lock server))
                              (node-session-gateway-repair-current-p
                               server node-name locked-session
                               (gethash node-name (node-grpc-server-snapshots server)) snapshot))))
              (setf repair-p nil deduplicate nil)
              (record-snapshot))
            ;; Keep the session lock from proof through send: ACKs cannot invalidate
            ;; its baseline/progress. Publication excludes competing configuration.
            ;; Never hold SERVER's lock across network I/O.
            (when repair-p
              (handler-case
                  (deliver-node-gateway-config-locked
                   locked-session repair-changes
                   (slot-value snapshot 'gr8s.node.v1::gateway-dependency-revision))
                (error (condition)
                  (format *error-output* "gr8s Gateway repair delivery for ~A failed: ~A~%" node-name condition)
                  (close-node-agent-session locked-session)))))
          (record-snapshot)))
    (when session
      (handler-case (deliver-node-snapshot session snapshot)
        (error (condition)
          (format *error-output* "gr8s full configuration delivery for ~A failed: ~A~%" node-name condition)
          ;; The canonical snapshot already advanced. Reconnect must resend it
          ;; in full even if the next repair finds no further desired changes.
          (close-node-agent-session session))))
    revision))

(defun node-session-acknowledged-revision (server node-name)
  "The latest authenticated session's highest applied revision, or 0 while
that session has not acknowledged its current projection."
  (bt:with-lock-held ((node-grpc-server-lock server))
    (gethash node-name (node-grpc-server-acknowledged-revisions server) 0)))

(defun service-risk-projection-published-locked-p
    (server projection owner-projection identities)
  "Check exact risk and owner-inventory ACK state under SERVER's lock."
  (and identities
       (every
        (lambda (identity)
          (let* ((name (car identity))
                 (session (gethash name (node-grpc-server-sessions server)))
                 (snapshot (gethash name (node-grpc-server-snapshots server)))
                 (revision (and snapshot
                                (slot-value snapshot 'gr8s.node.v1::revision))))
            (and session
                 (equal (node-agent-session-node-id session) (cdr identity))
                 (not (node-agent-session-evicted-p session))
                 (node-agent-session-service-risk-v2-p session)
                 snapshot (integerp revision) (plusp revision)
                 (equalp projection
                         (slot-value snapshot
                                     'gr8s.node.v1::service-discovery-objects-json))
                 (slot-value snapshot 'gr8s.node.v1::network)
                 (equalp owner-projection
                         (service-risk-snapshot-owner-projection snapshot))
                 (= revision
                    (gethash name
                             (node-grpc-server-acknowledged-revisions server) 0)))))
        identities)))

(defun service-risk-receiver-projection-published-locked-p
    (server receiver-projection identities)
  "Require every current, ACKed node snapshot to carry this receiver set."
  (every (lambda (identity)
           (let ((snapshot (gethash (car identity)
                                    (node-grpc-server-snapshots server))))
             (and snapshot
                  (equalp receiver-projection
                          (service-risk-snapshot-receiver-projection snapshot)))))
         identities))

(defun cluster-service-risk-published-p (server)
  "True when every registered v2 node ACKed current discovery and owners."
  (let* ((store (node-grpc-server-store server))
         (revision-before (pod-store-resource-revision store))
         (projection (gr8s.kubelet::service-discovery-projection store))
         (owner-projection (service-risk-owner-projection store))
         (identities (service-risk-node-identities store))
         (published (bt:with-lock-held ((node-grpc-server-lock server))
                      (service-risk-projection-published-locked-p
                       server projection owner-projection identities))))
    (and published
         (= revision-before (pod-store-resource-revision store))
         (equalp owner-projection (service-risk-owner-projection store))
         (equal identities (service-risk-node-identities store)))))

(defun refresh-cluster-service-risk-grant (server)
  "Mint after a complete risk-only ACK; retain only for the same node sessions
and discovery/owner projections. The next snapshot carries or revokes it."
  (let* ((store (node-grpc-server-store server))
         (revision-before (pod-store-resource-revision store))
         (projection (gr8s.kubelet::service-discovery-projection store))
         (owner-projection (service-risk-owner-projection store))
         (identities (service-risk-node-identities store))
         (digest (gr8s.protocol::service-risk-projection-digest projection)))
    (bt:with-lock-held ((node-grpc-server-lock server))
      (let* ((sessions (mapcar (lambda (identity)
                                 (gethash (car identity)
                                          (node-grpc-server-sessions server)))
                               identities))
             (ready (cluster-service-ready-receivers-locked
                     server owner-projection identities))
             (receiver-projection (mapcar #'ag-proto:serialize-to-bytes ready))
             (current-grant
               (and (node-grpc-server-service-risk-grant-digest server)
                    (equalp digest (node-grpc-server-service-risk-grant-digest server))
                    (equalp owner-projection
                            (node-grpc-server-service-risk-grant-owner-projection server))
                    (equalp receiver-projection
                            (node-grpc-server-service-risk-grant-receiver-projection server))
                    (equal identities (node-grpc-server-service-risk-grant-identities server))
                    (equal sessions (node-grpc-server-service-risk-grant-sessions server))
                    (service-risk-receivers-published-locked-p
                     server owner-projection identities)
                    (every (lambda (session)
                             (and session (not (node-agent-session-evicted-p session))
                                  (node-agent-session-service-risk-v2-p session)))
                           sessions)))
             (next-ready
               (and (service-risk-projection-published-locked-p
                     server projection owner-projection identities)
                    (service-risk-receivers-published-locked-p
                     server owner-projection identities)
                    (service-risk-receiver-projection-published-locked-p
                     server receiver-projection identities))))
        (cond (current-grant nil)
              (next-ready
               (setf (node-grpc-server-service-risk-grant-digest server) digest
                     (node-grpc-server-service-risk-grant-owner-projection server)
                     owner-projection
                     (node-grpc-server-service-risk-grant-receiver-projection server)
                     receiver-projection
                     (node-grpc-server-service-risk-grant-identities server) identities
                     (node-grpc-server-service-risk-grant-sessions server) sessions))
              ((service-risk-retained-grant-locked-p server owner-projection identities)
               nil)
              (t (clear-service-risk-grant-locked server)))))
    ;; The store is independent of the session lock. If it changed while the
    ;; decision was made, discard this candidate and retry on the next tick.
    (unless (and (= revision-before (pod-store-resource-revision store))
                 (equalp owner-projection (service-risk-owner-projection store))
                 (equal identities (service-risk-node-identities store)))
      (bt:with-lock-held ((node-grpc-server-lock server))
        (when (equalp digest (node-grpc-server-service-risk-grant-digest server))
          (clear-service-risk-grant-locked server))))
    (bt:with-lock-held ((node-grpc-server-lock server))
      (node-grpc-server-service-risk-grant-digest server))))
