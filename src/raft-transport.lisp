;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
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
;;;; Wire format: one Raft message per Deliver call, the message plist encoded as
;;;; a readable Lisp form (entries flattened to (index term command) triples) and
;;;; read back with *read-eval* bound off. Members are mutually authenticated
;;;; peers (cluster TLS in production), so the trust boundary is the cluster; a
;;;; binary codec is a later hardening.

(in-package #:gr8s)

;;; ---------------------------------------------------------------------------
;;; Wire encoding.

(defun raft-message->octets (msg)
  (let ((wire (copy-list msg)))
    (when (getf wire :entries)
      (setf (getf wire :entries)
            (mapcar (lambda (e) (list (raft-entry-index e) (raft-entry-term e) (raft-entry-command e)))
                    (getf wire :entries))))
    (let ((*print-readably* nil) (*print-circle* nil) (*print-pretty* nil))
      (babel:string-to-octets (prin1-to-string wire) :encoding :utf-8))))

(defun octets->raft-message (octets)
  (let* ((string (babel:octets-to-string (coerce octets '(vector (unsigned-byte 8)))
                                          :encoding :utf-8))
         (wire (let ((*read-eval* nil)) (read-from-string string))))
    (when (getf wire :entries)
      (setf (getf wire :entries)
            (mapcar (lambda (triple)
                      (make-raft-entry :index (first triple) :term (second triple)
                                       :command (third triple)))
                    (getf wire :entries))))
    wire))

;;; ---------------------------------------------------------------------------
;;; Per-peer delivery link: its own queue, thread, channel and stub.

(defstruct raft-peer-link
  id (host "") (port 0)
  (lock (bt:make-lock "gr8s raft link"))
  (items '())
  channel stub thread)

(defstruct raft-member
  node
  (lock (bt:make-lock "gr8s raft node"))
  grpc-server (host "127.0.0.1") (port 0)
  (links (make-hash-table :test 'equal))      ; peer-id -> raft-peer-link
  (running nil) server-thread tick-thread
  ;; Optional leader-side Join handler (podster-c2d.10), a function of the
  ;; decoded JoinRequest returning a JoinResponse. Set by the cluster layer; when
  ;; unset the member rejects joins (accepted=false, no leader hint).
  (join-handler nil)
  (tls nil) tls-certificate tls-key)

(defun raft-link-enqueue (link octets)
  (bt:with-lock-held ((raft-peer-link-lock link))
    (setf (raft-peer-link-items link) (nconc (raft-peer-link-items link) (list octets)))))

(defun raft-link-drop (link)
  (ignore-errors (when (raft-peer-link-channel link) (ag-grpc:channel-close (raft-peer-link-channel link))))
  (setf (raft-peer-link-channel link) nil (raft-peer-link-stub link) nil))

(defun raft-link-stub (member link)
  "Lazily open and cache a channel+stub to this peer, or NIL if unreachable."
  (or (raft-peer-link-stub link)
      (handler-case
          (let ((channel (ag-grpc:make-channel (raft-peer-link-host link) (raft-peer-link-port link)
                                               :timeout 2 :tls (raft-member-tls member) :tls-verify nil
                                               :tls-client-certificate (raft-member-tls-certificate member)
                                               :tls-client-key (raft-member-tls-key member))))
            (setf (raft-peer-link-channel link) channel
                  (raft-peer-link-stub link) (gr8s.node.v1::make-raft-transport-stub channel)))
        (error () nil))))

(defun raft-link-sender-loop (member link)
  (loop while (raft-member-running member) do
    (let ((batch (bt:with-lock-held ((raft-peer-link-lock link))
                   (prog1 (raft-peer-link-items link) (setf (raft-peer-link-items link) '())))))
      (if (null batch)
          (sleep 0.002)
          (dolist (octets batch)
            (let ((stub (raft-link-stub member link)))
              (when stub
                (handler-case
                    (gr8s.node.v1::raft-transport-deliver
                     stub (make-instance 'gr8s.node.v1::raft-envelope
                                         :protocol-version 1 :payload octets)
                     :timeout 2)
                  (error () (raft-link-drop link))))))))))

(defun raft-member-tick-loop (member tick-seconds)
  (loop while (raft-member-running member) do
    (sleep tick-seconds)
    (when (raft-member-running member)
      (bt:with-lock-held ((raft-member-lock member))
        (raft-tick (raft-member-node member))))))

;;; ---------------------------------------------------------------------------
;;; Lifecycle.

(defun start-raft-member (id &key (host "127.0.0.1") (port 0) apply-fn storage
                                  snapshot-fn restore-fn
                                  ;; election timeout ~1-2s at a 50ms tick; well above gRPC call latency
                                  (timeout-fn (lambda () (+ 20 (random 20))))
                                  (heartbeat-ticks 2)
                                  tls tls-certificate tls-key (tls-server-options nil))
  "Create a member: a raft-node whose SEND-FN enqueues to per-peer outboxes, a
   RaftTransport gRPC server, and the delivery machinery. Peers are set with
   RAFT-MEMBER-SET-PEERS (so a fresh member cannot self-elect before it knows
   them); ticking starts with RAFT-MEMBER-START."
  (let* ((member (make-raft-member :host host :port port :tls tls
                                   :tls-certificate tls-certificate :tls-key tls-key))
         (node (make-raft-node
                :id id :peers nil
                :heartbeat-timeout heartbeat-ticks :timeout-fn timeout-fn
                :apply-fn apply-fn :storage storage
                :snapshot-fn snapshot-fn :restore-fn restore-fn
                :send-fn (lambda (to msg)
                           (let ((link (gethash to (raft-member-links member))))
                             (when link (raft-link-enqueue link (raft-message->octets msg)))))))
         (server (apply #'ag-grpc:make-grpc-server port :host host tls-server-options)))
    (setf (raft-member-node member) node
          (raft-member-grpc-server member) server
          (raft-member-running member) t)
    (gr8s.node.v1::register-raft-transport-service
     server
     :deliver-handler (lambda (request context)
                        (declare (ignore context))
                        (let ((msg (octets->raft-message (gr8s.node.v1::payload request))))
                          (bt:with-lock-held ((raft-member-lock member))
                            (raft-handle-message (raft-member-node member) msg)))
                        (make-instance 'gr8s.node.v1::raft-ack))
     :join-handler (lambda (request context)
                     (declare (ignore context))
                     (let ((handler (raft-member-join-handler member)))
                       (if handler
                           (funcall handler request)
                           (make-instance 'gr8s.node.v1::join-response :accepted nil)))))
    (setf (raft-member-server-thread member)
          (bt:make-thread (lambda () (ag-grpc:server-start server))
                          :name (format nil "gr8s raft server ~A" id)))
    (loop repeat 500
          until (and (eql :running (ag-grpc:server-state server)) (ag-grpc::server-socket server))
          do (sleep 0.01))
    (unless (ag-grpc::server-socket server)
      (error "raft member ~A gRPC server failed to start" id))
    (setf (raft-member-port member) (usocket:get-local-port (ag-grpc::server-socket server)))
    member))

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
  (setf (raft-member-tick-thread member)
        (bt:make-thread (lambda () (raft-member-tick-loop member tick-seconds))
                        :name (format nil "gr8s raft tick ~A" (raft-node-id (raft-member-node member))))))

(defun raft-member-propose (member command &optional callback)
  "Propose COMMAND if this member is the leader; else (values nil nil)."
  (bt:with-lock-held ((raft-member-lock member))
    (raft-propose (raft-member-node member) command callback)))

(defun raft-member-leader-p (member)
  (bt:with-lock-held ((raft-member-lock member)) (raft-leader-p (raft-member-node member))))

(defun stop-raft-member (member)
  (setf (raft-member-running member) nil)
  (when (and (raft-member-tick-thread member) (bt:thread-alive-p (raft-member-tick-thread member)))
    (ignore-errors (bt:join-thread (raft-member-tick-thread member))))
  (maphash (lambda (id link) (declare (ignore id))
             (when (and (raft-peer-link-thread link) (bt:thread-alive-p (raft-peer-link-thread link)))
               (ignore-errors (bt:join-thread (raft-peer-link-thread link))))
             (raft-link-drop link))
           (raft-member-links member))
  (ignore-errors (ag-grpc:server-stop (raft-member-grpc-server member)))
  (when (and (raft-member-server-thread member) (bt:thread-alive-p (raft-member-server-thread member)))
    (ignore-errors (bt:join-thread (raft-member-server-thread member)))))
