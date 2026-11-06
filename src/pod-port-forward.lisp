;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Serve kubectl port-forward. A client opens an error and a data stream per
;;;; forwarded connection, sharing a request ID, and each pair becomes one operation
;;;; on the Pod's node. Reading from a client stops while a connection's Pod isn't
;;;; keeping up, which is what a kubelet's server does too, so that holds up the same
;;;; client's other connections but no other client's.

(in-package #:gr8s)

(defconstant +spdy-status-protocol-error+ 1)

(defparameter +port-forward-tunnel-protocol+ "SPDY/3.1+portforward.k8s.io")

(defstruct port-forward-pair
  "One forwarded connection: its two streams and, once both exist, its runtime session and output thread."
  port error-stream data-stream session thread)

(defstruct (port-forward-connection (:constructor make-port-forward-connection (runtime uid server)))
  "One client's connection, holding the pairs by request ID and each stream's pair by stream ID."
  runtime uid server
  (requests (make-hash-table :test #'equal))
  (streams (make-hash-table))
  (lock (bt:make-lock "gr8s port-forward connection")))

(defun parse-port-forward-port (text)
  "Return TEXT as a port number, or NIL."
  (let ((port (and text (ignore-errors (parse-integer text)))))
    (and port (<= 1 port 65535) port)))

(defun finish-port-forward-pair (connection pair &optional message)
  "End PAIR's streams toward the client, reporting MESSAGE on its error stream."
  (let ((server (port-forward-connection-server connection)))
    (when message
      (ignore-errors
       (spdy-server-write-data server (port-forward-pair-error-stream pair)
                               (trivial-utf-8:string-to-utf-8-bytes message))))
    (dolist (stream (list (port-forward-pair-data-stream pair) (port-forward-pair-error-stream pair)))
      (ignore-errors
       (spdy-server-write-data server stream (make-array 0 :element-type '(unsigned-byte 8)) :fin t)))))

(defun run-port-forward-output (connection pair)
  "Send what the Pod says to the client until the connection ends, then end the pair's streams."
  (let ((runtime (port-forward-connection-runtime connection))
        (server (port-forward-connection-server connection))
        (session (port-forward-pair-session pair)))
    (unwind-protect
         (let ((failure
                 (handler-case
                     (loop
                       (multiple-value-bind (data done failure) (runtime-port-forward-next runtime session)
                         (when done (return failure))
                         (spdy-server-write-data server (port-forward-pair-data-stream pair) data)))
                   ((or error sb-ext:timeout) (condition)
                     (ignore-errors (runtime-cancel-port-forward runtime session "client connection failed"))
                     (princ-to-string condition)))))
           (finish-port-forward-pair connection pair failure))
      (ignore-errors (runtime-release-port-forward runtime session))
      (bt:with-lock-held ((port-forward-connection-lock connection))
        (remhash (port-forward-pair-data-stream pair) (port-forward-connection-streams connection))
        (remhash (port-forward-pair-error-stream pair) (port-forward-connection-streams connection))))))

(defun start-port-forward-pair (connection pair)
  "Start forwarding PAIR, whose streams now both exist. A failure goes to the client on its error stream."
  (handler-case
      (let ((port (or (port-forward-pair-port pair)
                      (error 'runtime-error :message "Port forwarding requires a valid port"))))
        (setf (port-forward-pair-session pair)
              (runtime-start-port-forward (port-forward-connection-runtime connection)
                                          (port-forward-connection-uid connection) port)
              (port-forward-pair-thread pair)
              (bt:make-thread (lambda () (run-port-forward-output connection pair))
                              :name "gr8s port-forward output")))
    ((or error sb-ext:timeout) (condition)
      (finish-port-forward-pair connection pair
                                (if (typep condition 'runtime-error)
                                    (runtime-error-message condition)
                                    (princ-to-string condition))))))

(defun note-port-forward-stream (connection id headers)
  "Record new stream ID, starting its pair when this was the second stream of it."
  (let* ((server (port-forward-connection-server connection))
         (lookup (lambda (name) (cdr (assoc name headers :test #'equal))))
         (type (funcall lookup "streamtype"))
         (request (funcall lookup "requestid")))
    (unless (and request (member type '("error" "data") :test #'equal))
      (spdy-server-reset server id +spdy-status-protocol-error+)
      (return-from note-port-forward-stream))
    (spdy-server-reply server id)
    (let* ((requests (port-forward-connection-requests connection))
           (pair (or (gethash request requests)
                     (setf (gethash request requests)
                           (make-port-forward-pair
                            :port (parse-port-forward-port (funcall lookup "port")))))))
      (bt:with-lock-held ((port-forward-connection-lock connection))
        (setf (gethash id (port-forward-connection-streams connection)) pair))
      (if (equal type "error")
          (setf (port-forward-pair-error-stream pair) id)
          (setf (port-forward-pair-data-stream pair) id))
      (when (and (port-forward-pair-error-stream pair) (port-forward-pair-data-stream pair))
        (remhash request requests)
        (start-port-forward-pair connection pair)))))

(defun note-port-forward-data (connection id fin data)
  "Pass data from the client to the Pod. Only the data stream carries any."
  (let ((pair (bt:with-lock-held ((port-forward-connection-lock connection))
                (gethash id (port-forward-connection-streams connection)))))
    (when (and pair (port-forward-pair-session pair) (eql id (port-forward-pair-data-stream pair)))
      ;; The Pod's side may already have ended, which the output thread reports.
      (handler-case
          (runtime-port-forward-send (port-forward-connection-runtime connection)
                                     (port-forward-pair-session pair) data :eof fin)
        (error () nil)))))

(defun note-port-forward-reset (connection id)
  "Cancel the forwarded connection whose client reset one of its streams."
  (let ((pair (bt:with-lock-held ((port-forward-connection-lock connection))
                (gethash id (port-forward-connection-streams connection)))))
    (when (and pair (port-forward-pair-session pair))
      (ignore-errors
       (runtime-cancel-port-forward (port-forward-connection-runtime connection)
                                    (port-forward-pair-session pair) "client reset the stream")))))

(defun serve-port-forward-connection (runtime uid transport)
  "Serve one client's streams until its connection ends, and then cancel whatever is still forwarding."
  (let* ((server (make-spdy-server transport))
         (connection (make-port-forward-connection runtime uid server)))
    (unwind-protect
         (handler-case
             (loop for frame = (spdy-server-read-frame server)
                   while frame
                   do (ecase (first frame)
                        (:syn (destructuring-bind (id headers fin) (rest frame)
                                (note-port-forward-stream connection id headers)
                                (when fin
                                  (note-port-forward-data connection id t
                                                          (make-array 0 :element-type '(unsigned-byte 8))))))
                        (:data (destructuring-bind (id fin data) (rest frame)
                                 (note-port-forward-data connection id fin data)))
                        (:reset (note-port-forward-reset connection (second frame)))))
           ;; The client going away part way through a frame is how many of these end.
           ((or error sb-ext:timeout) () nil))
      (let ((pairs (bt:with-lock-held ((port-forward-connection-lock connection))
                     (remove-duplicates
                      (loop for pair being the hash-values of (port-forward-connection-streams connection)
                            collect pair)))))
        (dolist (pair pairs)
          (when (port-forward-pair-session pair)
            (ignore-errors
             (runtime-cancel-port-forward runtime (port-forward-pair-session pair) "client disconnected"))))
        (dolist (pair pairs)
          (when (port-forward-pair-thread pair)
            (ignore-errors (bt:join-thread (port-forward-pair-thread pair)))))))))

(defun begin-port-forward-transport ()
  "Finish the upgrade kubectl asked for and return the transport for what follows.
It tries a WebSocket tunnel first, and falls back to SPDY if that upgrade is refused."
  (let ((upgrade (hunchentoot:header-in* :upgrade)))
    (flet ((offered-p (header protocol)
             (find protocol (uiop:split-string (or (hunchentoot:header-in* header) "")
                                               :separator '(#\, #\Space #\Tab))
                   :test #'string-equal))
           (begin ()
             (setf (hunchentoot:return-code*) 101
                   (hunchentoot:content-type*) nil
                   (hunchentoot:header-out :connection) "Upgrade")
             nil))
      (cond
        ((string-equal upgrade "websocket")
         (let ((key (hunchentoot:header-in* :sec-websocket-key)))
           (unless (and key (plusp (length key)) (offered-p :sec-websocket-protocol +port-forward-tunnel-protocol+))
             (bad-exec-request "Port forwarding requires the SPDY tunnel WebSocket protocol"))
           (begin)
           (setf (hunchentoot:header-out :upgrade) "websocket"
                 (hunchentoot:header-out :sec-websocket-accept) (websocket-accept-value key)
                 (hunchentoot:header-out :sec-websocket-protocol) +port-forward-tunnel-protocol+)
           (let ((client (hunchentoot::start-output 101 nil)))
             (finish-output client)
             (make-websocket-spdy-transport client))))
        ((string-equal upgrade "SPDY/3.1")
         (unless (offered-p :x-stream-protocol-version +port-forward-protocol+)
           (bad-exec-request "Port forwarding requires the portforward.k8s.io protocol"))
         (begin)
         (setf (hunchentoot:header-out :upgrade) "SPDY/3.1"
               (hunchentoot:header-out :x-stream-protocol-version) +port-forward-protocol+)
         (let ((client (hunchentoot::start-output 101 nil)))
           (finish-output client)
           (make-upgraded-spdy-transport client)))
        (t (bad-exec-request "Port forwarding requires a WebSocket or SPDY upgrade"))))))

(defun pod-port-forward-response (store reconciler name &optional (namespace "default"))
  "Offer a Pod port-forward to the webhooks, then serve its connections until the client goes."
  (let ((pod (get-pod store namespace name)))
    (admit-pod-port-forward store namespace name)
    (unless (upgrade-request-p)
      (bad-exec-request "Port forwarding requires an upgraded connection"))
    (serve-port-forward-connection (reconciler-runtime reconciler) (pod-uid pod)
                                   (begin-port-forward-transport))))
