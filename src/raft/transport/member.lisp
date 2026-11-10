;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; The ag-gRPC transport + runtime driver for the Raft core (podster-c2d.3).
;;;; Each HA member runs a RaftTransport gRPC server and dials its peers; the
;;;; core's fire-and-forget SEND-FN enqueues onto a *per-peer* outbox so a slow
;;;; or dead peer never blocks delivery to the others or re-enters the state
;;;; machine. A per-member lock serializes all state-machine access (delivered
;;;; messages, the tick clock, client proposals); a tick thread drives the
;;;; election/heartbeat timers. Lost/failed deliveries are dropped -- Raft
;;;; recovers them via retries and heartbeats.
;;;;
;;;; Timers default to etcd-like values (heartbeat ~100ms, election ~1-2s) so
;;;; the cluster stays stable despite per-call gRPC latency on the order of tens
;;;; of milliseconds.
;;;;
;;;; Wire format: one Raft message per Deliver call. Artifact chunks use bounded
;;;; binary frames; ordinary messages use readable Lisp forms with entries flattened
;;;; to (index term command) triples and *read-eval* disabled on decode. Members
;;;; authenticate each message through mutual TLS before decoding it.

(in-package #:gr8s.raft.transport)

;;; ---------------------------------------------------------------------------
;;; Wire encoding.

(defun raft-lisp-message->octets (msg)
  "Encode the Raft message plist MSG to UTF-8 octets for one Deliver call: entries
   are flattened to (index term command) triples and the form is printed with
   *PRINT-READABLY*/*PRINT-CIRCLE*/*PRINT-PRETTY* bound off. MSG is not mutated."
  (let ((wire (copy-list msg)))
    (when (getf wire :entries)
      (setf (getf wire :entries)
            (mapcar (lambda (e) (list (raft-entry-index e) (raft-entry-term e) (raft-entry-command e)))
                    (getf wire :entries))))
    (with-standard-io-syntax
      (let ((*print-readably* nil) (*print-circle* nil) (*print-pretty* nil))
        (babel:string-to-octets (prin1-to-string wire) :encoding :utf-8)))))

(defun octets->raft-lisp-message (octets)
  "Decode OCTETS back into a Raft message plist, reading the form with *READ-EVAL*
   bound off and rebuilding RAFT-ENTRY structs from their triples. The inverse of
   RAFT-MESSAGE->OCTETS."
  (let* ((string (babel:octets-to-string (coerce octets '(vector (unsigned-byte 8)))
                                          :encoding :utf-8))
         (wire (with-standard-io-syntax (let ((*read-eval* nil)) (read-from-string string)))))
    (when (getf wire :entries)
      (setf (getf wire :entries)
            (mapcar (lambda (triple)
                      (make-raft-entry :index (first triple) :term (second triple)
                                       :command (third triple)))
                    (getf wire :entries))))
    wire))

(defparameter +raft-artifact-wire-magic+ #(71 82 56 83 67 75 48 49)) ; GR8SCK01
(defconstant +raft-artifact-wire-part-limit+ 65536)

(defun raft-wire-put-u32 (bytes offset value)
  (dotimes (i 4) (setf (aref bytes (+ offset i)) (ldb (byte 8 (* 8 (- 3 i))) value))))

(defun raft-wire-get-u32 (bytes offset)
  (loop for i below 4 for value = (aref bytes offset) then (+ (ash value 8) (aref bytes (+ offset i)))
        finally (return value)))

(defun raft-message->octets (message)
  "Use a bounded binary frame for artifact chunks; other messages keep their Lisp codec."
  (unless (and (eq :snapshot-chunk (getf message :type)) (eq :artifact-v1 (getf message :format)))
    (return-from raft-message->octets (raft-lisp-message->octets message)))
  (let* ((metadata (copy-list message)) (data (getf message :data))
         (envelope (or (getf message :artifact-envelope) #())))
    (remf metadata :data)
    (remf metadata :artifact-envelope)
    (let* ((header (raft-lisp-message->octets metadata))
           (h (length header)) (e (length envelope)) (d (length data)))
      (unless (and (<= 1 h +raft-artifact-wire-part-limit+)
                   (<= 0 e +raft-artifact-wire-part-limit+) (<= 1 d +raft-artifact-wire-part-limit+))
        (error "Artifact chunk exceeds binary frame limits"))
      (let ((bytes (make-array (+ 20 h e d) :element-type '(unsigned-byte 8))))
        (replace bytes +raft-artifact-wire-magic+)
        (raft-wire-put-u32 bytes 8 h)
        (raft-wire-put-u32 bytes 12 e)
        (raft-wire-put-u32 bytes 16 d)
        (replace bytes header :start1 20)
        (replace bytes envelope :start1 (+ 20 h))
        (replace bytes data :start1 (+ 20 h e))
        bytes))))

(defun octets->raft-message (octets)
  (let ((bytes (coerce octets '(vector (unsigned-byte 8)))))
    (unless (and (>= (length bytes) 8) (equalp +raft-artifact-wire-magic+ (subseq bytes 0 8)))
      (return-from octets->raft-message (octets->raft-lisp-message bytes)))
    (unless (>= (length bytes) 20) (error "Truncated artifact chunk frame"))
    (let ((h (raft-wire-get-u32 bytes 8)) (e (raft-wire-get-u32 bytes 12)) (d (raft-wire-get-u32 bytes 16)))
      (unless (and (<= 1 h +raft-artifact-wire-part-limit+) (<= 0 e +raft-artifact-wire-part-limit+)
                   (<= 1 d +raft-artifact-wire-part-limit+) (= (length bytes) (+ 20 h e d)))
        (error "Invalid artifact chunk frame lengths"))
      (let ((message (octets->raft-lisp-message (subseq bytes 20 (+ 20 h)))))
        (unless (and (eq :snapshot-chunk (getf message :type)) (eq :artifact-v1 (getf message :format))
                     (null (getf message :data)) (null (getf message :artifact-envelope)))
          (error "Invalid artifact chunk frame metadata"))
        (setf (getf message :data) (subseq bytes (+ 20 h e)))
        (when (plusp e) (setf (getf message :artifact-envelope) (subseq bytes (+ 20 h) (+ 20 h e))))
        message))))

;;; ---------------------------------------------------------------------------
;;; Per-peer delivery link: its own queue, thread, channel and stub.

(defstruct raft-peer-link
  id (host "") (port 0) (role :voter)
  (lock (bt:make-lock "gr8s raft link"))
  (changed (bt:make-condition-variable :name "gr8s raft link changed"))
  (items '())
  ;; Published under LOCK before dequeue: registry GC must see sender-owned
  ;; snapshots even while their source callback has not opened the artifact.
  (active-items '())
  channel stub thread
  ;; Operation relay is synchronous and ordered per peer, independently of the
  ;; Raft replication outbox. A distinct HTTP/2 connection prevents a long exec
  ;; frame from delaying consensus heartbeats.
  (relay-lock (bt:make-lock "gr8s operation relay link"))
  relay-channel relay-stub)

(defstruct raft-member
  node
  (lock (bt:make-lock "gr8s raft node"))
  grpc-server (host "127.0.0.1") (port 0)
  (links (make-hash-table :test 'equal))      ; peer-id -> raft-peer-link
  (running nil) server-thread tick-thread renewal-thread
  ;; Optional leader-side Join handler (podster-c2d.10), a function of the
  ;; decoded JoinRequest returning a JoinResponse. Set by the cluster layer; when
  ;; unset the member rejects joins (accepted=false, no leader hint).
  (join-handler nil)
  ;; Installed after the node gRPC server starts. RelayOperation dispatches
  ;; incoming frames here; NIL on witnesses and transport-only tests.
  operation-server
  ;; Filesystem-only callbacks; retention runs under the member lock before WAL adoption.
  artifact-source-fn artifact-retain-fn snapshot-barrier-fn startup-check-fn (snapshot-barrier-pending nil)
  ;; Scoped, unpublished application-artifact roots. Protected by LOCK; each
  ;; owner has a distinct cell so identical concurrent references stay pinned.
  artifact-pins
  snapshot-directory snapshot-root snapshot-owner-fd snapshot-receiver
  (snapshot-max-bytes (* 16 1024 1024 1024))
  ;; This member's RAFT-CREDENTIALS. Only in-process tests run without any.
  credentials
  ;; Only a WAL opened through STORAGE-PATH belongs to this member.
  owned-storage)

(defun raft-member-close-owned-storage (member)
  (let ((storage (raft-member-owned-storage member)))
    (when storage
      (gr8s.raft:close-file-raft-storage storage)
      (setf (raft-member-owned-storage member) nil))))

(defun raft-link-enqueue (link message)
  "Append MESSAGE to LINK's outbox under its lock for its sender thread to
   encode and deliver. A new AppendEntries supersedes every older unsent one:
   each retry already contains the latest bounded batch from NEXT-INDEX, so
   retaining stale retries only duplicates large log payloads while a peer is
   unreachable. Other Raft messages retain their order. Fire-and-forget: never
   blocks on the peer."
  (bt:with-lock-held ((raft-peer-link-lock link))
    (when (member (getf message :type) '(:append-entries :install-snapshot))
      (setf (raft-peer-link-items link)
            (delete-if (lambda (item) (member (getf item :type) '(:append-entries :install-snapshot)))
                       (raft-peer-link-items link))))
    (setf (raft-peer-link-items link)
          (nconc (raft-peer-link-items link) (list message)))
    (bt:condition-notify (raft-peer-link-changed link))))

(defun raft-link-wait-batch (member link)
  "Block until LINK has outbound work or MEMBER stops, then drain its queued batch."
  (bt:with-lock-held ((raft-peer-link-lock link))
    (loop while (and (raft-member-running member)
                     (null (raft-peer-link-items link)))
          do (bt:condition-wait (raft-peer-link-changed link)
                                (raft-peer-link-lock link)))
    (when (raft-peer-link-active-items link)
      (error "Snapshot sender still owns its previous batch"))
    (setf (raft-peer-link-active-items link) (raft-peer-link-items link)
          (raft-peer-link-items link) nil)
    (raft-peer-link-active-items link)))

(defun raft-member-snapshot-messages-unlocked (member)
  "List queued and sender-owned snapshot roots while the caller owns MEMBER.
Lock order is member then link. Senders publish ownership before dequeue and
release it only after source lookup and delivery finish, including failures."
  (unless (sb-thread:holding-mutex-p (raft-member-lock member))
    (error "Snapshot root enumeration requires the member lock"))
  (let ((messages nil))
    (maphash (lambda (id link)
               (declare (ignore id))
               (bt:with-lock-held ((raft-peer-link-lock link))
                 (dolist (message (append (raft-peer-link-active-items link)
                                          (raft-peer-link-items link)))
                   (when (eq :install-snapshot (getf message :type))
                     (push message messages)))))
             (raft-member-links member))
    messages))

(defun raft-link-drop (link)
  "Tear down LINK's cached channel and stub (closing the channel, errors ignored) so
   the next send reopens them. Queued items are left in place."
  (ignore-errors (when (raft-peer-link-channel link) (ag-grpc:channel-close (raft-peer-link-channel link))))
  (setf (raft-peer-link-channel link) nil (raft-peer-link-stub link) nil))

(defun raft-link-drop-relay (link)
  "Close LINK's cached operation-relay connection so its next frame reconnects."
  (ignore-errors
    (when (raft-peer-link-relay-channel link)
      (ag-grpc:channel-close (raft-peer-link-relay-channel link))))
  (setf (raft-peer-link-relay-channel link) nil
        (raft-peer-link-relay-stub link) nil))

(defun raft-link-stub (member link)
  "Lazily open and cache a channel+stub to this peer, or NIL if unreachable."
  (or (raft-peer-link-stub link)
      (handler-case
          (let ((channel (gr8s::make-raft-channel
                          (raft-member-credentials member)
                          (raft-peer-link-host link) (raft-peer-link-port link) 2)))
            (setf (raft-peer-link-channel link) channel
                  (raft-peer-link-stub link) (gr8s.node.v1::make-raft-transport-stub channel)))
        ;; A stalled TLS handshake is a timeout, and it must not end this link's thread.
        ((or error sb-ext:timeout) () nil))))

(defun raft-link-sender-loop (member link)
  "LINK's sender thread: while MEMBER runs, drain its outbox and Deliver each message
   to the peer, dropping the link (to be reopened) on any send error. A missing stub
   or failed delivery is simply dropped -- Raft retries recover it."
  (loop while (raft-member-running member) do
    (let ((batch (raft-link-wait-batch member link)))
      (unwind-protect
           (dolist (message batch)
             (let ((stub (raft-link-stub member link)))
               (when stub
                 (handler-case
                     (if (eq :install-snapshot (getf message :type))
                         (raft-link-send-snapshot member stub message :recipient-role (raft-peer-link-role link))
                         (raft-link-deliver-message stub message))
                   (error () (raft-link-drop link))))))
        (bt:with-lock-held ((raft-peer-link-lock link))
          (setf (raft-peer-link-active-items link) nil))))))

(defun raft-member-tick-loop (member tick-seconds)
  "MEMBER's clock thread: every TICK-SECONDS, drive RAFT-TICK under the member lock to
   advance the election and heartbeat timers, until the member stops."
  (loop while (raft-member-running member) do
    (sleep tick-seconds)
    (when (raft-member-running member)
      (bt:with-lock-held ((raft-member-lock member))
        (raft-tick (raft-member-node member))
        (ignore-errors (raft-member-promote-learners member))
        (raft-member-expire-snapshot-receiver member))
      ;; Store startup checks may acquire outer application barriers. They must
      ;; run after releasing the member mutex, and never kill the tick clock.
      (let ((check (raft-member-startup-check-fn member)))
        (when check (ignore-errors (funcall check member)))))))

(defun raft-member-dispatch-message-unlocked (member message)
  (case (getf message :type)
    (:snapshot-chunk (raft-member-receive-snapshot-chunk member message))
    (:install-snapshot (error "Snapshots must use bounded chunk transport"))
    (t (raft-handle-message (raft-member-node member) message))))

(defun raft-member-dispatch-message (member message)
  "Acquire optional outer snapshot barriers BEFORE the member mutex.
Normal replication continues while the barrier drains outstanding application writers."
  (let ((barrier nil))
    (bt:with-lock-held ((raft-member-lock member))
      (if (and (raft-member-snapshot-barrier-fn member)
               (or (raft-node-snapshot-pending (raft-member-node member))
                   (raft-member-snapshot-barrier-pending member)
                   (and (eq :snapshot-chunk (getf message :type)) (getf message :done)
                        (typep (getf message :last-index) '(integer 1 *))
                        (> (getf message :last-index) (raft-node-commit-index (raft-member-node member))))))
          (setf barrier (raft-member-snapshot-barrier-fn member))
          (return-from raft-member-dispatch-message (raft-member-dispatch-message-unlocked member message))))
    (let ((owner (bt:current-thread)) (started nil) (completed nil) (invalid nil))
      (funcall barrier member message
               (lambda ()
                 (unless (and (eq owner (bt:current-thread)) (not started))
                   (setf invalid t)
                   (error "Snapshot barrier must invoke dispatch synchronously exactly once"))
                 (setf started t)
                 (bt:with-lock-held ((raft-member-lock member))
                   (multiple-value-prog1 (raft-member-dispatch-message-unlocked member message)
                     (setf completed t)))))
      (unless (and completed (not invalid)) (error "Snapshot barrier did not complete dispatch")))))

;;; ---------------------------------------------------------------------------
;;; Lifecycle.

(defun start-raft-member (id &key (host "127.0.0.1") (port 0) apply-fn storage storage-path initial-role
                                  snapshot-fn restore-fn snapshot-directory prepare-fn validate-recovery-fn after-recovery-fn
                                  ;; election timeout ~1-2s at a 50ms tick; well above gRPC call latency
                                  (timeout-fn (lambda () (+ 20 (random 20))))
                                  (heartbeat-ticks 2)
                                  credentials)
  "Create a member: a raft-node whose SEND-FN enqueues to per-peer outboxes, a
   RaftTransport gRPC server, and the delivery machinery. Peers are set with
   RAFT-MEMBER-SET-PEERS (so a fresh member cannot self-elect before it knows
   them); ticking starts with RAFT-MEMBER-START. STORAGE-PATH recovers a file WAL
   before opening the RPC listener and makes the member own/close that storage.
   PREPARE-FN installs callbacks on the new member before recovery; VALIDATE-RECOVERY-FN
   must approve its recovered WAL before node mutation. AFTER-RECOVERY-FN runs
   under the member mutex with the recovered owned WAL, before listening.
   INITIAL-ROLE keeps an unconfigured witness/learner from campaigning before join."
  (when (and storage storage-path) (error "Supply either storage or storage-path"))
  (dolist (callback (list prepare-fn validate-recovery-fn after-recovery-fn))
    (when (and callback (not (functionp callback))) (error "Invalid member startup callback")))
  (when (and after-recovery-fn (null storage-path))
    (error "After-recovery callback requires an owned WAL path"))
  (unless (member initial-role '(nil :voter :witness :learner)) (error "Invalid initial Raft role"))
  (let* ((member (make-raft-member :host host :port port :credentials credentials
                                  :snapshot-directory snapshot-directory))
         (node (make-raft-node
                :id id :peers nil
                :heartbeat-timeout heartbeat-ticks :timeout-fn timeout-fn
                :apply-fn apply-fn :storage storage
                :snapshot-fn snapshot-fn :restore-fn restore-fn
                :send-fn (lambda (to msg)
                           (let ((link (gethash to (raft-member-links member))))
                             (when link (raft-link-enqueue link msg))))))
         (server (progn
                   (setf (raft-member-node member) node)
                   (when initial-role (setf (raft-node-self-role node) initial-role))
                   (when prepare-fn (funcall prepare-fn member))
                   (bt:with-lock-held ((raft-member-lock member))
                     (when storage-path
                       (recover-raft-node node storage-path
                         :validate-fn (when validate-recovery-fn
                                        (lambda (recovered) (funcall validate-recovery-fn member recovered))))
                       (setf (raft-member-owned-storage member) (gr8s.raft:raft-node-storage node))))
                   (handler-case
                       (progn
                         (when after-recovery-fn
                           (bt:with-lock-held ((raft-member-lock member))
                             (funcall after-recovery-fn member)))
                         (raft-member-reap-snapshot-orphans member)
                         (apply #'ag-grpc:make-grpc-server port :host host
                                (gr8s::raft-server-tls-options credentials)))
                     (error (condition)
                       (raft-member-close-owned-storage member)
                       (error condition))))))
    (setf (raft-member-node member) node
          (raft-member-grpc-server member) server
          (raft-member-running member) t)
    (gr8s.node.v1::register-raft-transport-service
     server
     :patch-management-handler
     (lambda (request context)
       (unless credentials (error "Patch management requires mutual TLS"))
       (let ((peer (gr8s::authenticate-raft-peer credentials context)))
         (gr8s.patch::handle-member-command member peer request)))
     :deliver-handler (lambda (request context)
                        (let ((msg (gr8s::authenticated-raft-message
                                    credentials request context)))
                          (raft-member-dispatch-message member msg))
                        (make-instance 'gr8s.node.v1::raft-ack))
     :propose-handler
     (lambda (request context)
       (when credentials (gr8s::authenticate-raft-peer credentials context))
       (let* ((wire (gr8s.node.v1::command request))
              (message (octets->raft-message wire))
              (command (getf message :command)))
         (multiple-value-bind (result committed index)
             (raft-member-propose-sync member command :timeout 10)
           (make-instance 'gr8s.node.v1::raft-proposal-result
                          :committed (eq committed t)
                          :reason (if (eq committed t) "" (string-downcase (symbol-name committed)))
                          :index (or index 0)
                          :application-result
                          (if (and (consp command)
                                   (member (first command)
                                           '(:core-delta :pod-delta :node-delta :image-tracker)))
                              (raft-message->octets (list :result result))
                              (make-array 0 :element-type '(unsigned-byte 8)))))))
     :join-handler (lambda (request context)
                     (let ((handler (raft-member-join-handler member)))
                       (if handler
                           (funcall handler request context)
                           (make-instance 'gr8s.node.v1::join-response :accepted nil))))
     :enroll-member-handler (lambda (request context)
                              (declare (ignore context))
                              (gr8s::raft-member-handle-enroll member request))
     :renew-member-handler (lambda (request context)
                             (gr8s::raft-member-handle-renew member request context))
     :relay-operation-handler
     (lambda (request context)
       (let* ((peer (and credentials
                         (gr8s::authenticate-raft-peer credentials context)))
              (source (slot-value request 'gr8s.node.v1::source-member))
              (variant (slot-value request 'gr8s.node.v1::payload-case))
              (payload (and variant
                            (slot-value request
                                        (find-symbol (symbol-name variant) :gr8s.node.v1))))
              (node-name (slot-value request 'gr8s.node.v1::node-name))
              (node-server (raft-member-operation-server member))
              (accepted nil)
              (failure ""))
         (when (and peer (not (equal peer source)))
           (gr8s::pki-fail "member-identity-mismatch"
                           "Raft member ~A relayed an operation as ~A" peer source))
         (handler-case
             (setf accepted
                   (and node-server payload
                        (case variant
                          ((:operation-request :operation-input :operation-cancel)
                           (gr8s::accept-routed-node-operation
                            node-server source node-name variant payload))
                          ((:operation-stream :operation-response)
                           (gr8s::deliver-routed-node-operation
                            node-server variant payload))
                          (otherwise nil))))
           (error (condition) (setf failure (princ-to-string condition))))
         (make-instance 'gr8s.node.v1::routed-operation-result
                        :accepted (not (null accepted)) :error-message failure))))
    (setf (raft-member-server-thread member)
          (bt:make-thread (lambda () (ag-grpc:server-start server))
                          :name (format nil "gr8s raft server ~A" id)))
    (loop repeat 500
          until (and (eql :running (ag-grpc:server-state server)) (ag-grpc::server-socket server))
          do (sleep 0.01))
    (unless (ag-grpc::server-socket server)
      (stop-raft-member member)
      (error "raft member ~A gRPC server failed to start" id))
    (setf (raft-member-port member) (usocket:get-local-port (ag-grpc::server-socket server)))
    member))

(defun make-routed-operation (member variant node-name payload)
  "Build the peer RPC envelope for one node-operation frame."
  (let ((request
          (make-instance 'gr8s.node.v1::routed-operation
                         :source-member (raft-node-id (raft-member-node member))
                         :node-name node-name)))
    (setf (slot-value request 'gr8s.node.v1::payload-case) variant
          (slot-value request (find-symbol (symbol-name variant) :gr8s.node.v1)) payload)
    request))

(defun raft-link-relay-operation (member link variant node-name payload)
  "Send one operation frame to LINK. Return true when that peer accepted it."
  (bt:with-lock-held ((raft-peer-link-relay-lock link))
    (handler-case
        (let ((stub
                (or (raft-peer-link-relay-stub link)
                    (let ((channel
                            (gr8s::make-raft-channel
                             (raft-member-credentials member)
                             (raft-peer-link-host link) (raft-peer-link-port link) 2)))
                      (setf (raft-peer-link-relay-channel link) channel
                            (raft-peer-link-relay-stub link)
                            (gr8s.node.v1::make-raft-transport-stub channel))))))
          (slot-value
           (gr8s.node.v1::raft-transport-relay-operation
            stub (make-routed-operation member variant node-name payload) :timeout 3)
           'gr8s.node.v1::accepted))
      ((or error sb-ext:timeout) ()
        (raft-link-drop-relay link)
        nil))))

(defun raft-member-route-node-operation (member variant target-member node-name payload)
  "Route a node-operation frame through MEMBER's authenticated peer links.
With TARGET-MEMBER, send only there. Without it, offer a request to peers until
the member owning NODE-NAME's live agent session accepts it. Returns that peer's
id, or NIL."
  (if target-member
      (let ((link (gethash target-member (raft-member-links member))))
        (and link
             (raft-link-relay-operation member link variant node-name payload)
             target-member))
      (let ((links nil))
        (maphash (lambda (id link) (declare (ignore id)) (push link links))
                 (raft-member-links member))
        (dolist (link links)
          (when (raft-link-relay-operation member link variant node-name payload)
            (return (raft-peer-link-id link)))))))

(defun configure-raft-node-operation-routing (member node-server)
  "Connect NODE-SERVER's operation router to MEMBER's peer transport."
  (setf (raft-member-operation-server member) node-server
        (gr8s::node-grpc-server-operation-router node-server)
        (lambda (variant target-member node-name payload)
          (raft-member-route-node-operation
           member variant target-member node-name payload)))
  node-server)

(defun raft-member-set-peers (member peers)
  "PEERS is a list of (id host port) for the OTHER members. Creates a per-peer
   delivery link + sender thread for each."
  (bt:with-lock-held ((raft-member-lock member))
    (setf (raft-node-peers (raft-member-node member)) (mapcar #'first peers)))
  (dolist (peer peers)
    (let ((link (make-raft-peer-link :id (first peer) :host (second peer) :port (third peer))))
      (setf (gethash (first peer) (raft-member-links member)) link
            (raft-peer-link-thread link)
            (bt:make-thread (lambda () (raft-link-sender-loop member link))
                            :name (format nil "gr8s raft link ~A->~A"
                                          (raft-node-id (raft-member-node member)) (first peer)))))))

(defun raft-member-start (member &key (tick-seconds 0.05))
  "Begin driving the election/heartbeat clock (call after peers are set)."
  (when (raft-member-credentials member)
    (setf (raft-member-renewal-thread member)
          (bt:make-thread (lambda () (gr8s::raft-renewal-loop member))
                          :name (format nil "gr8s raft renewal ~A" (raft-node-id (raft-member-node member))))))
  (setf (raft-member-tick-thread member)
        (bt:make-thread (lambda () (raft-member-tick-loop member tick-seconds))
                        :name (format nil "gr8s raft tick ~A" (raft-node-id (raft-member-node member))))))

(defun raft-member-propose (member command &optional callback)
  "Propose COMMAND if this member is the leader; else (values nil nil)."
  (bt:with-lock-held ((raft-member-lock member))
    (raft-propose (raft-member-node member) command callback)))

(defun raft-member-wait-applied (member index deadline)
  "Wait until MEMBER has applied committed log INDEX, but no later than DEADLINE."
  (loop
    (when (bt:with-lock-held ((raft-member-lock member))
            (>= (raft-node-last-applied (raft-member-node member)) index))
      (return t))
    (when (>= (get-internal-real-time) deadline)
      (return nil))
    (sleep 0.005)))

(defun raft-member-forward-propose-sync (member command &key (timeout 10))
  "Forward COMMAND from follower MEMBER to its known leader and wait for commit.
   A remote commit does not complete until MEMBER has applied the returned log
   index, preserving read-after-write consistency for the serving API member.
   Returns (values application-result T) on commit, or (values NIL reason-keyword) when no
   leader is known or the leader refuses/times out.  The Raft transport's mutual
   TLS authenticates production members; plain transport remains available to
   tests."
  (let ((deadline (+ (get-internal-real-time)
                     (* timeout internal-time-units-per-second)))
        (last-reason :not-leader))
    (loop
      ;; Leadership can move while the store releases its lock and reaches this
      ;; hook. If it moved here, propose locally rather than forwarding to the
      ;; member that just stepped down.
      (when (raft-member-leader-p member)
        (multiple-value-bind (result committed index)
            (raft-member-propose-sync member command :timeout 2)
          (declare (ignore index))
          (when (eq committed t) (return (values result t)))
          (when (member committed '(:capacity :proposal-too-large))
            (return (values nil committed)))
          (setf last-reason committed)))
      (multiple-value-bind (leader address)
          (bt:with-lock-held ((raft-member-lock member))
            (let* ((node (raft-member-node member))
                   (leader (raft-node-leader-id node)))
              (values leader
                      (and leader (gethash leader (raft-node-peer-addresses node))))))
        (when (and leader address)
          (handler-case
              (let ((channel (gr8s::make-raft-channel
                              (raft-member-credentials member)
                              (first address) (second address) 2)))
                (unwind-protect
                     (let* ((stub (gr8s.node.v1::make-raft-transport-stub channel))
                            (request
                              (make-instance
                               'gr8s.node.v1::raft-proposal
                               :command (raft-message->octets (list :command command))))
                            (response
                              (gr8s.node.v1::raft-transport-propose
                               stub request :timeout 2)))
                       (if (gr8s.node.v1::committed response)
                           (let ((index (gr8s.node.v1::index response)))
                             (if (and (plusp index)
                                      (raft-member-wait-applied member index deadline))
                                 (let ((bytes (gr8s.node.v1::application-result response)))
                                   (return (values (when (plusp (length bytes))
                                                     (getf (octets->raft-message bytes) :result)) t)))
                                 (setf last-reason :timeout)))
                           (setf last-reason
                                 (or (find-symbol
                                      (string-upcase (gr8s.node.v1::reason response)) :keyword)
                                     :not-leader))))
                  (ignore-errors (ag-grpc:channel-close channel))))
            (error () (setf last-reason :timeout)))))
      (when (member last-reason '(:capacity :proposal-too-large))
        (return (values nil last-reason)))
      (when (>= (get-internal-real-time) deadline)
        (return (values nil last-reason)))
      ;; Elections and the membership transition are expected transient states;
      ;; retry inside the caller's commit budget instead of leaking not-leader.
      (sleep 0.05))))

(defun raft-member-leader-p (member)
  "Whether MEMBER is currently the Raft leader (read under the member lock)."
  (bt:with-lock-held ((raft-member-lock member)) (raft-leader-p (raft-member-node member))))

(defun stop-raft-member (member)
  "Stop MEMBER: clear its running flag and join its tick, renewal and per-peer sender
   threads, drop every link, and stop its gRPC server. Errors from any one teardown
   are ignored so shutdown always completes."
  (setf (raft-member-running member) nil)
  (maphash (lambda (id link)
             (declare (ignore id))
             (bt:with-lock-held ((raft-peer-link-lock link))
               (bt:condition-notify (raft-peer-link-changed link))))
           (raft-member-links member))
  (when (and (raft-member-tick-thread member) (bt:thread-alive-p (raft-member-tick-thread member)))
    (ignore-errors (bt:join-thread (raft-member-tick-thread member))))
  (when (and (raft-member-renewal-thread member) (bt:thread-alive-p (raft-member-renewal-thread member)))
    (ignore-errors (bt:join-thread (raft-member-renewal-thread member))))
  (maphash (lambda (id link) (declare (ignore id))
             (when (and (raft-peer-link-thread link) (bt:thread-alive-p (raft-peer-link-thread link)))
               (ignore-errors (bt:join-thread (raft-peer-link-thread link))))
             (raft-link-drop link)
             (raft-link-drop-relay link))
           (raft-member-links member))
  (ignore-errors (ag-grpc:server-stop (raft-member-grpc-server member)))
  (when (and (raft-member-server-thread member) (bt:thread-alive-p (raft-member-server-thread member)))
    (ignore-errors (bt:join-thread (raft-member-server-thread member))))
  (bt:with-lock-held ((raft-member-lock member))
    (unwind-protect
         (unwind-protect (raft-member-clear-snapshot-receiver member)
           (raft-member-close-snapshot-root member))
      (raft-member-close-owned-storage member))))
