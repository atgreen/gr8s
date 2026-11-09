;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Agent half of the persistent control-plane session.

(in-package #:gr8s.agent)

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
  (credential-token-requests (make-hash-table :test #'equal))
  (credential-token-lock (bt:make-lock "gr8s credential token requests"))
  ;; The last complete snapshot received, which the server's next delta changes.
  received)

(defstruct pending-credential-token
  response
  (changed (bt:make-condition-variable :name "gr8s credential token response")))

(defun request-agent-credential-token (session pod audience required optional)
  "Request a Pod-bound credential-provider token through SESSION and wait for its response."
  (let* ((id (generate-uid))
         (pending (make-pending-credential-token))
         (spec (gethash "spec" (pod-to-object pod)))
         (service-account (gethash "serviceAccountName" spec "")))
    (bt:with-lock-held ((agent-node-session-credential-token-lock session))
      (setf (gethash id (agent-node-session-credential-token-requests session)) pending))
    (unwind-protect
         (progn
           (send-agent-session-envelope
            session :credential-token-request
            (make-instance
             'gr8s.node.v1::credential-token-request
             :request-id id :namespace (pod-namespace pod) :pod-name (pod-name pod)
             :pod-uid (pod-uid pod) :service-account-name service-account
             :audience audience :required-annotation-keys required
             :optional-annotation-keys optional))
           (let ((response
                   (bt:with-lock-held ((agent-node-session-credential-token-lock session))
                     (loop until (pending-credential-token-response pending)
                           do (unless (bt:condition-wait
                                       (pending-credential-token-changed pending)
                                       (agent-node-session-credential-token-lock session) :timeout 60)
                                (error "Credential token request timed out")))
                     (pending-credential-token-response pending))))
             (when (plusp (length (slot-value response 'gr8s.node.v1::error-message)))
               (error "Credential token request failed: ~A"
                      (slot-value response 'gr8s.node.v1::error-message)))
             (values
              (slot-value response 'gr8s.node.v1::token)
              (slot-value response 'gr8s.node.v1::service-account-annotations)
              (list :namespace (pod-namespace pod) :name service-account
                    :uid (slot-value response 'gr8s.node.v1::service-account-uid)))))
      (bt:with-lock-held ((agent-node-session-credential-token-lock session))
        (remhash id (agent-node-session-credential-token-requests session))))))

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
  (let* ((node-id (slot-value hello 'gr8s.node.v1::node-id))
        (cidr (slot-value hello 'gr8s.node.v1::assigned-pod-cidr))
        (announced (slot-value hello 'gr8s.node.v1::assigned-pod-cidrs))
        (cidrs (if announced (coerce announced 'vector) (vector cidr)))
        (persisted-node-id (gethash "nodeId" identity ""))
        (persisted-cidr (gethash "assignedPodCIDR" identity ""))
        (persisted-cidrs (gethash "assignedPodCIDRs" identity)))
    (when (and (plusp (length persisted-node-id))
               (not (string= persisted-node-id node-id)))
      (error "Server node identity changed from ~S to ~S" persisted-node-id node-id))
    (when (zerop (length node-id)) (error "Server assigned an empty node identity"))
    (unless (and (plusp (length cidrs)) (string= cidr (aref cidrs 0)))
      (error "Server primary Pod CIDR does not match its ordered allocation"))
    (loop for assigned across cidrs do (parse-pod-cidr assigned))
    (when (and (plusp (length persisted-cidr)) (not (string= persisted-cidr cidr)))
      (error "Server Pod CIDR changed from ~S to ~S" persisted-cidr cidr))
    (when (and persisted-cidrs (not (equalp persisted-cidrs cidrs)))
      (error "Server Pod CIDRs changed from ~S to ~S" persisted-cidrs cidrs))
    ;; Persist the allocation even when this reconnect has no newer snapshot.
    (setf (gethash "nodeId" identity) node-id
          (gethash "assignedPodCIDR" identity) cidr
          (gethash "assignedPodCIDRs" identity) cidrs)
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
  (let* ((network (slot-value snapshot 'gr8s.node.v1::network))
         (assigned (gethash "assignedPodCIDR" identity))
         (assigned-all (or (gethash "assignedPodCIDRs" identity)
                           (and assigned (vector assigned))))
         (announced-all (and network (slot-value network 'gr8s.node.v1::node-pod-cidrs)))
         (network-all (and network
                           (if announced-all (coerce announced-all 'vector)
                               (vector (slot-value network 'gr8s.node.v1::node-pod-cidr))))))
    (when (and network assigned
               (or (not (string= assigned (slot-value network 'gr8s.node.v1::node-pod-cidr)))
                   (not (equalp assigned-all network-all))))
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
    (:credential-token-response
     (let* ((response (slot-value envelope 'gr8s.node.v1::credential-token-response))
            (id (slot-value response 'gr8s.node.v1::request-id)))
       (bt:with-lock-held ((agent-node-session-credential-token-lock session))
         (let ((pending (gethash id (agent-node-session-credential-token-requests session))))
           (when pending
             (setf (pending-credential-token-response pending) response)
             (bt:condition-notify (pending-credential-token-changed pending)))))))
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
                                                                     runtime-health credential-token-function-setter
                                                                     wireguard-public-key wireguard-endpoints)
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
             (when credential-token-function-setter
               (funcall credential-token-function-setter
                        (lambda (pod audience required optional)
                          (request-agent-credential-token session pod audience required optional))))
             (send-agent-session-envelope
              session :hello
               (make-instance 'gr8s.node.v1::node-hello
                              :node-name node-name
                              :patch-inventory-json (if gr8s.patch:*manager*
                                                       (gr8s.patch::octets (com.inuoe.jzon:stringify (gr8s.patch:inventory gr8s.patch:*manager*))) #())
                              :boot-id (generate-uid)
                              :agent-version "gr8s"
                              :underlay-address
                              (or underlay-address (node-channel-underlay-address channel))
                              :capabilities (list +desired-state-delta-capability+)
                              :capacity (node-reported-capacity-entries)
                              :kubelet-port kubelet-port
                              :wireguard-public-key (or wireguard-public-key #())
                              :wireguard-endpoints
                              (mapcar (lambda (endpoint)
                                        (make-instance
                                         'gr8s.node.v1::wireguard-endpoint
                                         :name (first endpoint)
                                         :address (second endpoint)
                                         :port (third endpoint)))
                                      wireguard-endpoints)
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
      (when credential-token-function-setter
        (funcall credential-token-function-setter nil))
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
                           credential-token-function-setter
                           wireguard-public-key
                           wireguard-endpoints
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
                                                 snapshot-observer kubelet-port runtime-health
                                                 credential-token-function-setter
                                                 wireguard-public-key wireguard-endpoints))
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

(defun image-tracker-response-plist (response)
  "Convert the protobuf tracker response into the image coordinator's small
plist interface without leaking generated protocol classes into that layer."
  (list :status (slot-value response 'gr8s.node.v1::status)
        :token (slot-value response 'gr8s.node.v1::lease-token)
        :expires-at (slot-value response 'gr8s.node.v1::expires-at)
        :metainfo (slot-value response 'gr8s.node.v1::metainfo)
        :infohash (slot-value response 'gr8s.node.v1::infohash)
        :peers
        (mapcar (lambda (peer)
                  (list :node-name (slot-value peer 'gr8s.node.v1::node-name)
                        :address (slot-value peer 'gr8s.node.v1::address)
                        :port (slot-value peer 'gr8s.node.v1::port)
                        :peer-id (slot-value peer 'gr8s.node.v1::peer-id)
                        :complete (slot-value peer 'gr8s.node.v1::complete)))
                (slot-value response 'gr8s.node.v1::peers))))

(defun make-image-tracker-rpc-client
    (host port node-name ca-certificate-path certificate-path private-key-path
     &key (timeout 10))
  "Return (values CALL CLOSE). CALL implements the callback contract consumed
by ENSURE-STRICT-P2P-BLOB; the channel uses the enrolled node's mTLS identity."
  (let* ((channel (make-node-tls-channel
                   host port :timeout timeout
                   :ca-certificate-path ca-certificate-path
                   :certificate-path certificate-path
                   :private-key-path private-key-path))
         (stub (gr8s.node.v1::make-node-service-stub channel)))
    (values
     (lambda (action digest &rest arguments)
       (flet ((argument (name default)
                (getf arguments name default)))
         (multiple-value-bind (response status)
             (gr8s.node.v1::node-service-track-image
              stub
              (make-instance
               'gr8s.node.v1::image-tracker-request
               :node-name node-name
               :action (string-downcase (symbol-name action))
               :digest digest
               :lease-token (argument :token #())
               :metainfo (argument :metainfo #())
               :peer-address (argument :address "")
               :peer-port (argument :port 0)
               :peer-id (argument :peer-id #())
               :complete (argument :complete nil))
              :timeout timeout)
           (declare (ignore status))
           (image-tracker-response-plist response))))
     (lambda () (ag-grpc:channel-close channel)))))
