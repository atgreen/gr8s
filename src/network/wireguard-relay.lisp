;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Bounded opaque-UDP relay coordination for end-to-end WireGuard sessions.

(in-package #:gr8s.network)

(defstruct (wireguard-relay-channel
            (:constructor %make-wireguard-relay-channel))
  nodes
  ports
  (sources (make-hash-table :test #'equal))
  (source-last-seen (make-hash-table :test #'equal))
  (rate-window-start 0)
  (rate-window-packets 0)
  (rate-window-bytes 0)
  (last-active 0))

(defstruct wireguard-relay-coordinator
  (port-start 42000)
  (max-channels 1024)
  (source-change-seconds 30)
  (max-packets-per-second 10000)
  (max-bytes-per-second (* 64 1024 1024))
  (idle-seconds 300)
  (channels (make-hash-table :test #'equal))
  (lock (bt:make-lock "gr8s WireGuard relay coordinator")))

(defstruct wireguard-relay-listener
  socket channel node thread (stopping-p nil))

(defstruct (wireguard-relay-server
            (:constructor %make-wireguard-relay-server))
  coordinator
  (address "0.0.0.0")
  (listeners (make-hash-table))
  (lock (bt:make-lock "gr8s WireGuard relay listeners"))
  reaper-thread
  (stopping-p nil))

(defun wireguard-relay-pair (left right)
  (when (string= left right) (error "WireGuard relay peers must differ"))
  (if (string< left right) (list left right) (list right left)))

(defun wireguard-relay-channel-port-for (channel node)
  (let ((position (position node (wireguard-relay-channel-nodes channel)
                            :test #'string=)))
    (unless position (error "Node ~A does not belong to relay channel" node))
    (nth position (wireguard-relay-channel-ports channel))))

(defun ensure-wireguard-relay-channel (coordinator left right now)
  "Return the stable bounded relay channel for LEFT and RIGHT."
  (let ((pair (wireguard-relay-pair left right)))
    (bt:with-lock-held ((wireguard-relay-coordinator-lock coordinator))
      (or (gethash pair (wireguard-relay-coordinator-channels coordinator))
          (let* ((channels (wireguard-relay-coordinator-channels coordinator))
                 (used-ports
                   (loop for channel being the hash-values of channels
                         collect (first (wireguard-relay-channel-ports channel))))
                 (index
                   (loop for candidate below
                           (wireguard-relay-coordinator-max-channels coordinator)
                         for port = (+ (wireguard-relay-coordinator-port-start coordinator)
                                       (* 2 candidate))
                         unless (member port used-ports) return candidate)))
            (unless index
              (error "WireGuard relay channel capacity exhausted"))
            (let* ((first (+ (wireguard-relay-coordinator-port-start coordinator)
                             (* 2 index)))
                   (channel (%make-wireguard-relay-channel
                             :nodes pair :ports (list first (1+ first))
                             :last-active now)))
              (when (> (1+ first) 65535)
                (error "WireGuard relay UDP port range exhausted"))
              (setf (gethash pair channels) channel)))))))

(defun note-wireguard-relay-source-unlocked
    (coordinator channel node address port now)
  "Learn NODE's relay source from the relay's own first-hand observation.

The relay is the authority on a node's relay source: it forwards whatever source
it actually sees, never a source asserted by a peer (that cross-node assertion is
the N1 poisoning the control plane no longer performs). A node's first observed
source is accepted; an established source is then STICKY -- a different source is
adopted only once the current one falls silent for SOURCE-CHANGE-SECONDS, so a
genuine node holding its session open with keepalives cannot be displaced by a
transient spoofed datagram. Forwarded traffic is still end-to-end WireGuard, so a
spoofed source that does win the bootstrap race yields no working session at the
far peer -- a bounded, self-healing disruption rather than an interception."
  (unless (and (stringp address) (typep port '(integer 1 65535)))
    (error "Invalid WireGuard relay source"))
  (wireguard-relay-channel-port-for channel node)
  (let* ((sources (wireguard-relay-channel-sources channel))
         (previous (gethash node sources))
         (last-seen (gethash node
                             (wireguard-relay-channel-source-last-seen channel)))
         (candidate (cons address port)))
    (cond
      ((equal candidate previous)
       (setf (gethash node (wireguard-relay-channel-source-last-seen channel)) now
             (wireguard-relay-channel-last-active channel) now)
       t)
      ;; An established source still seen within the damping window is sticky:
      ;; reject a challenger so one spoofed datagram cannot steal a live session.
      ((and previous last-seen
            (< (- now last-seen)
               (wireguard-relay-coordinator-source-change-seconds coordinator)))
       nil)
      (t
       (setf (gethash node sources) candidate
             (gethash node (wireguard-relay-channel-source-last-seen channel)) now
             (wireguard-relay-channel-last-active channel) now)
       t))))

(defun wireguard-relay-rate-allowed-p-unlocked (coordinator channel length now)
  (when (/= now (wireguard-relay-channel-rate-window-start channel))
    (setf (wireguard-relay-channel-rate-window-start channel) now
          (wireguard-relay-channel-rate-window-packets channel) 0
          (wireguard-relay-channel-rate-window-bytes channel) 0))
  (when (and (< (wireguard-relay-channel-rate-window-packets channel)
                (wireguard-relay-coordinator-max-packets-per-second coordinator))
             (<= (+ (wireguard-relay-channel-rate-window-bytes channel) length)
                 (wireguard-relay-coordinator-max-bytes-per-second coordinator)))
    (incf (wireguard-relay-channel-rate-window-packets channel))
    (incf (wireguard-relay-channel-rate-window-bytes channel) length)
    t))

(defun note-wireguard-relay-source
    (coordinator channel node address port now)
  "Learn NODE's NAT source, limiting changes while refreshing stable sources."
  (bt:with-lock-held ((wireguard-relay-coordinator-lock coordinator))
    (note-wireguard-relay-source-unlocked
     coordinator channel node address port now)))

(defun wireguard-relay-forward-target (channel source-node)
  "Return destination address/port and the opposite-side source port."
  (let* ((nodes (wireguard-relay-channel-nodes channel))
         (destination-node
           (cond ((string= source-node (first nodes)) (second nodes))
                 ((string= source-node (second nodes)) (first nodes))
                 (t (error "Node ~A does not belong to relay channel" source-node))))
         (destination
           (gethash destination-node (wireguard-relay-channel-sources channel))))
    (when destination
      (values (car destination) (cdr destination)
              (wireguard-relay-channel-port-for channel destination-node)))))

(defun relay-wireguard-datagram
    (coordinator channel source-node data length address port now send)
  "Learn one source and forward its exact opaque datagram at most once."
  (multiple-value-bind (target-address target-port source-port)
      (bt:with-lock-held ((wireguard-relay-coordinator-lock coordinator))
        (when (note-wireguard-relay-source-unlocked
               coordinator channel source-node address port now)
          (unless (wireguard-relay-rate-allowed-p-unlocked
                   coordinator channel length now)
            (return-from relay-wireguard-datagram nil))
          (wireguard-relay-forward-target channel source-node)))
    (when target-address
      (funcall send source-port data length target-address target-port)
      t)))

(defun expire-wireguard-relay-channels (coordinator now)
  "Remove idle channels; return their count and objects. Socket owners close them."
  (bt:with-lock-held ((wireguard-relay-coordinator-lock coordinator))
    (let ((expired nil))
      (maphash
       (lambda (pair channel)
         (when (>= (- now (wireguard-relay-channel-last-active channel))
                   (wireguard-relay-coordinator-idle-seconds coordinator))
           (push (cons pair channel) expired)))
       (wireguard-relay-coordinator-channels coordinator))
      (dolist (entry expired)
        (remhash (car entry) (wireguard-relay-coordinator-channels coordinator)))
      (values (length expired) (mapcar #'cdr expired)))))

(defun refresh-wireguard-relay-node (server node now)
  "Keep relay allocations for an authenticated live NODE from expiring."
  (let ((coordinator (wireguard-relay-server-coordinator server)))
    (bt:with-lock-held ((wireguard-relay-coordinator-lock coordinator))
      (loop for channel being the hash-values of
              (wireguard-relay-coordinator-channels coordinator)
            when (member node (wireguard-relay-channel-nodes channel)
                         :test #'string=)
              do (setf (wireguard-relay-channel-last-active channel) now)))))

(defun bind-wireguard-relay-socket (address port)
  (let ((socket (make-instance 'sb-bsd-sockets:inet-socket
                               :type :datagram :protocol :udp)))
    (handler-case
        (progn
          (setf (sb-bsd-sockets:sockopt-reuse-address socket) t
                (sb-bsd-sockets:non-blocking-mode socket) t)
          (sb-bsd-sockets:socket-bind
           socket (sb-bsd-sockets:make-inet-address address) port)
          socket)
      (error (condition)
        (ignore-errors (sb-bsd-sockets:socket-close socket))
        (error condition)))))

(defun wireguard-relay-send
    (server source-port data length address port)
  (let ((listener
          (bt:with-lock-held ((wireguard-relay-server-lock server))
            (gethash source-port (wireguard-relay-server-listeners server)))))
    (when listener
      (sb-bsd-sockets:socket-send
       (wireguard-relay-listener-socket listener) data length
       :address (list (sb-bsd-sockets:make-inet-address address) port)))))

(defun wireguard-relay-listener-loop (server listener)
  (let* ((socket (wireguard-relay-listener-socket listener))
         (descriptor (sb-bsd-sockets:socket-file-descriptor socket))
         (buffer (make-array 65535 :element-type '(unsigned-byte 8))))
    (loop until (or (wireguard-relay-server-stopping-p server)
                    (wireguard-relay-listener-stopping-p listener))
          do (when (sb-sys:wait-until-fd-usable descriptor :input 0.25)
               (handler-case
                   (multiple-value-bind (ignored length source port)
                       (sb-bsd-sockets:socket-receive socket buffer (length buffer))
                     (declare (ignore ignored))
                     (when (and length source)
                       (relay-wireguard-datagram
                        (wireguard-relay-server-coordinator server)
                        (wireguard-relay-listener-channel listener)
                        (wireguard-relay-listener-node listener)
                        buffer length
                        (format nil "~{~D~^.~}" (coerce source 'list)) port
                        (get-universal-time)
                        (lambda (source-port data size address target-port)
                          (wireguard-relay-send
                           server source-port data size address target-port)))))
                 (error (condition)
                   (unless (wireguard-relay-server-stopping-p server)
                     (format *error-output* "gr8s WireGuard relay UDP error: ~A~%"
                             condition))))))))

(defun start-wireguard-relay-server
    (&key (address "0.0.0.0") (port-start 42000) (max-channels 1024)
      (source-change-seconds 30)
      (max-packets-per-second 10000)
      (max-bytes-per-second (* 64 1024 1024)) (idle-seconds 300))
  "Create a relay service. Pair listeners are bound lazily when authenticated
topology allocates a channel."
  (let ((server
          (%make-wireguard-relay-server
           :address address
           :coordinator
           (make-wireguard-relay-coordinator
            :port-start port-start :max-channels max-channels
            :source-change-seconds source-change-seconds
            :max-packets-per-second max-packets-per-second
            :max-bytes-per-second max-bytes-per-second
            :idle-seconds idle-seconds))))
    (setf (wireguard-relay-server-reaper-thread server)
          (bt:make-thread
           (lambda ()
             (loop until (wireguard-relay-server-stopping-p server)
                   do (sleep 0.25)
                      (unless (wireguard-relay-server-stopping-p server)
                        (reap-wireguard-relay-server server (get-universal-time)))))
           :name "gr8s WireGuard relay idle reaper"))
    server))

(defun ensure-wireguard-relay-server-channel (server left right now)
  "Allocate a pair and start both UDP listeners, unwinding partial binds."
  (let ((created nil))
    (bt:with-lock-held ((wireguard-relay-server-lock server))
      (handler-case
          (let* ((coordinator (wireguard-relay-server-coordinator server))
                 (channel (ensure-wireguard-relay-channel
                           coordinator left right now)))
            (loop for node in (wireguard-relay-channel-nodes channel)
                  for port in (wireguard-relay-channel-ports channel)
                  unless (gethash port (wireguard-relay-server-listeners server))
                    do (let* ((socket (bind-wireguard-relay-socket
                                       (wireguard-relay-server-address server) port))
                              (listener (make-wireguard-relay-listener
                                         :socket socket :channel channel :node node)))
                         (setf (gethash port (wireguard-relay-server-listeners server))
                               listener)
                         (push (cons port listener) created)))
            (dolist (entry created)
              (let ((owned (cdr entry)))
                (setf (wireguard-relay-listener-thread owned)
                      (bt:make-thread
                       (lambda () (wireguard-relay-listener-loop server owned))
                       :name "gr8s WireGuard opaque UDP relay"))))
            channel)
        (error (condition)
          (dolist (entry created)
            (let* ((port (car entry))
                   (listener (cdr entry))
                   (thread (wireguard-relay-listener-thread listener)))
              (setf (wireguard-relay-listener-stopping-p listener) t)
              (ignore-errors
                (sb-bsd-sockets:socket-close
                 (wireguard-relay-listener-socket listener)))
              (when thread (ignore-errors (bt:join-thread thread)))
              (remhash port (wireguard-relay-server-listeners server))))
          (error condition))))))

(defun reap-wireguard-relay-server (server now)
  "Expire idle relay channels, stop their listener pairs, and release the ports."
  (let ((listeners nil) (count 0))
    (bt:with-lock-held ((wireguard-relay-server-lock server))
      (multiple-value-bind (expired-count channels)
          (expire-wireguard-relay-channels
           (wireguard-relay-server-coordinator server) now)
        (setf count expired-count)
        (when channels
          (maphash
           (lambda (port listener)
             (when (member (wireguard-relay-listener-channel listener) channels)
               (setf (wireguard-relay-listener-stopping-p listener) t)
               (push (cons port listener) listeners)))
           (wireguard-relay-server-listeners server))
          (dolist (entry listeners)
            (remhash (car entry) (wireguard-relay-server-listeners server))))))
    (dolist (entry listeners)
      (let ((listener (cdr entry)))
        (ignore-errors
          (bt:join-thread (wireguard-relay-listener-thread listener)))
        (ignore-errors
          (sb-bsd-sockets:socket-close
           (wireguard-relay-listener-socket listener)))))
    count))

(defun stop-wireguard-relay-server (server)
  "Stop all listener threads and close every relay socket. Idempotent."
  (setf (wireguard-relay-server-stopping-p server) t)
  (when (wireguard-relay-server-reaper-thread server)
    (ignore-errors
      (bt:join-thread (wireguard-relay-server-reaper-thread server))))
  (let ((listeners
          (loop for listener being the hash-values of
                  (wireguard-relay-server-listeners server)
                collect listener)))
    (dolist (listener listeners)
      (let ((thread (wireguard-relay-listener-thread listener)))
        (when thread (ignore-errors (bt:join-thread thread)))))
    (dolist (listener listeners)
      (ignore-errors
        (sb-bsd-sockets:socket-close (wireguard-relay-listener-socket listener))))
    (clrhash (wireguard-relay-server-listeners server)))
  nil)
