;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Serve Pod exec and attach to SPDY/3.1 clients, as a kubelet's streaming server
;;;; does: kubectl falls back to SPDY when a WebSocket upgrade fails, and older
;;;; client-go users speak only SPDY. The client negotiates a remotecommand protocol
;;;; in X-Stream-Protocol-Version and then opens one stream per channel, named in its
;;;; streamType header; the status of the command goes on the error stream at the end.

(in-package #:gr8s)

(defparameter +remotecommand-spdy-protocols+
  '("v4.channel.k8s.io" "v3.channel.k8s.io" "v2.channel.k8s.io" "channel.k8s.io")
  "The remotecommand protocols a kubelet serves over SPDY, newest first. v5 is WebSocket only.")

(defparameter +remotecommand-stream-timeout+ 30
  "Seconds a client has to open its streams, a kubelet's streamCreationTimeout.")

(defun spdy-remotecommand-requested-p ()
  "Return whether the request asks to upgrade to SPDY rather than to a WebSocket."
  (string-equal (hunchentoot:header-in* :upgrade) "SPDY/3.1"))

(defun negotiate-spdy-remotecommand-protocol ()
  "Choose the newest protocol both sides speak, as httpstream.Handshake does. A client that names
none gets the original protocol; one that names only others is refused."
  (let ((offered (remove "" (mapcar (lambda (text) (string-trim '(#\Space #\Tab) text))
                                    (uiop:split-string (or (hunchentoot:header-in* :x-stream-protocol-version) "")
                                                       :separator '(#\,)))
                         :test #'equal)))
    (cond ((null offered) (values "channel.k8s.io" nil))
          ((find-if (lambda (protocol) (member protocol offered :test #'string-equal))
                    +remotecommand-spdy-protocols+)
           (values (find-if (lambda (protocol) (member protocol offered :test #'string-equal))
                            +remotecommand-spdy-protocols+)
                   t))
          (t (error 'kubernetes-error
                    :status-code 403 :reason "Forbidden"
                    :message (format nil "unable to upgrade: unable to negotiate protocol: client supports ~A, server supports ~A"
                                     offered +remotecommand-spdy-protocols+))))))

(defun begin-spdy-remotecommand (protocol named)
  "Finish the SPDY upgrade with PROTOCOL, naming it when the client NAMED any, and return the transport."
  (setf (hunchentoot:return-code*) 101
        (hunchentoot:content-type*) nil
        (hunchentoot:header-out :connection) "Upgrade"
        (hunchentoot:header-out :upgrade) "SPDY/3.1")
  (when named (setf (hunchentoot:header-out :x-stream-protocol-version) protocol))
  (let ((client (hunchentoot::start-output 101 nil)))
    (finish-output client)
    (make-upgraded-spdy-transport client)))

(defun remotecommand-expected-streams (options protocol)
  "Name the streams a client opens for OPTIONS: error always, then one per requested channel, and
resize for a terminal from v3 on. A terminal has no stderr (remotecommand.NewOptions drops it)."
  (append '("error")
          (when (exec-options-stdin options) '("stdin"))
          (when (exec-options-stdout options) '("stdout"))
          (when (and (exec-options-stderr options) (not (exec-options-tty options))) '("stderr"))
          (when (and (exec-options-tty options)
                     (member protocol '("v3.channel.k8s.io" "v4.channel.k8s.io") :test #'equal))
            '("resize"))))

(defun accept-remotecommand-streams (server expected)
  "Accept the client's streams until every one in EXPECTED exists, returning an alist of stream type
to ID and, as a second value, the data frames that arrived meanwhile, in order."
  (let ((streams nil) (early nil))
    (sb-sys:with-deadline (:seconds +remotecommand-stream-timeout+)
      (loop until (every (lambda (type) (assoc type streams :test #'equal)) expected)
            do (let ((frame (spdy-server-read-frame server)))
                 (unless frame
                   (error 'runtime-error :message "client closed the connection before opening its streams"))
                 (ecase (first frame)
                   (:syn (destructuring-bind (id headers fin) (rest frame)
                           (declare (ignore fin))
                           (let ((type (string-downcase (or (cdr (assoc "streamtype" headers :test #'equal)) ""))))
                             (if (and (member type expected :test #'equal) (not (assoc type streams :test #'equal)))
                                 (progn (spdy-server-reply server id) (push (cons type id) streams))
                                 (spdy-server-reset server id +spdy-status-protocol-error+)))))
                   (:data (push (rest frame) early))
                   (:reset nil)))))
    (values streams (nreverse early))))

(defun spdy-remotecommand-status-bytes (protocol exit-code)
  "Return what the error stream carries for EXIT-CODE: v4 sends a Status either way, and the older
protocols only a failure's message (v1WriteStatusFunc), or NIL for nothing."
  (cond ((equal protocol "v4.channel.k8s.io") (exec-exit-status-bytes exit-code))
        ((zerop exit-code) nil)
        (t (trivial-utf-8:string-to-utf-8-bytes
            (format nil "command terminated with exit code ~D" exit-code)))))

(defun spdy-remotecommand-failure-bytes (protocol message)
  "Return what the error stream carries for a stream that could not be served, with MESSAGE."
  (format *error-output* "gr8s Pod stream failed: ~A~%" message)
  (trivial-utf-8:string-to-utf-8-bytes
   (if (equal protocol "v4.channel.k8s.io")
       (com.inuoe.jzon:stringify
        (json-object "apiVersion" "v1" "kind" "Status" "status" "Failure" "message" message
                     "reason" "InternalError" "code" 500))
       message)))

(defun remotecommand-terminal-sizes (pending data)
  "Append DATA to PENDING, the octets of a resize stream not yet read, and return the complete
TerminalSize objects in them as (rows . columns), with what remains. Go's decoder, which a kubelet
uses, matches the Width and Height fields whatever their case."
  (let* ((octets (concatenate '(vector (unsigned-byte 8)) pending data))
         (end (position 10 octets :from-end t))
         (sizes nil))
    (when end
      (dolist (line (uiop:split-string (trivial-utf-8:utf-8-bytes-to-string (subseq octets 0 end))
                                       :separator '(#\Newline)))
        (let ((size (ignore-errors (com.inuoe.jzon:parse line))))
          (when (hash-table-p size)
            (flet ((field (name)
                     (loop for key being the hash-keys of size using (hash-value value)
                           when (and (string-equal key name) (integerp value)) return value)))
              (push (cons (or (field "height") 0) (or (field "width") 0)) sizes))))))
    (values (nreverse sizes) (if end (subseq octets (1+ end)) octets))))

(defun forward-spdy-exec-input (reconciler session server streams early finished-p)
  "Pass the client's stdin and terminal sizes to SESSION until the connection ends."
  (let ((stdin (cdr (assoc "stdin" streams :test #'equal)))
        (resize (cdr (assoc "resize" streams :test #'equal)))
        (pending (make-array 0 :element-type '(unsigned-byte 8))))
    (flet ((take (id fin data)
             (cond
               ((eql id stdin)
                (when (or fin (plusp (length data)))
                  (reconciler-send-exec-session-input
                   reconciler session gr8s.node.v1::+streamchannel-stream_channel_stdin+
                   (coerce data '(simple-array (unsigned-byte 8) (*))) :eof fin)))
               ((eql id resize)
                (multiple-value-bind (sizes rest) (remotecommand-terminal-sizes pending data)
                  (setf pending rest)
                  (loop for (rows . columns) in sizes
                        do (reconciler-send-exec-session-input
                            reconciler session gr8s.node.v1::+streamchannel-stream_channel_terminal_resize+
                            (make-array 0 :element-type '(unsigned-byte 8))
                            :rows rows :columns columns)))))))
      (handler-case
          (with-exec-input-reader-stop
            (dolist (frame early) (apply #'take frame))
            (loop until (funcall finished-p)
                  do (let ((frame (spdy-server-read-frame server)))
                       (case (first frame)
                         ((nil)
                          (unless (funcall finished-p)
                            (reconciler-cancel-exec-session reconciler session "SPDY client closed"))
                          (return))
                         (:data (apply #'take (rest frame)))
                         ;; Streams are all open by now; a client's further ones carry nothing here.
                         (:syn (spdy-server-reset server (second frame) +spdy-status-protocol-error+))
                         (:reset (when (eql (second frame) stdin)
                                   (reconciler-send-exec-session-input
                                    reconciler session gr8s.node.v1::+streamchannel-stream_channel_stdin+
                                    (make-array 0 :element-type '(unsigned-byte 8)) :eof t)))))))
        (error (condition)
          (unless (funcall finished-p)
            (ignore-errors
             (reconciler-cancel-exec-session reconciler session (princ-to-string condition)))))))))

(defun serve-spdy-exec-session (reconciler uid container options &key attach)
  "Bridge a SPDY client to a node exec, or with ATTACH to the container's own process, as a kubelet's
streaming server does. Output waits for the client, which holds the node back while it is slow.
The client opens the streams its request names, which can differ from OPTIONS: an attach takes the
container's own terminal setting whatever the client asked for."
  (multiple-value-bind (protocol named) (negotiate-spdy-remotecommand-protocol)
    ;; remotecommand.NewOptions: a terminal merges stderr into stdout.
    (when (exec-options-tty options) (setf (exec-options-stderr options) nil))
    (let* ((session
             (if attach
                 (reconciler-start-attach-session
                  reconciler uid container
                  :stdin (exec-options-stdin options) :stdout (exec-options-stdout options)
                  :stderr (exec-options-stderr options) :tty (exec-options-tty options))
                 (reconciler-start-exec-session
                  reconciler uid container (exec-options-command options)
                  :stdin (exec-options-stdin options) :stdout (exec-options-stdout options)
                  :stderr (exec-options-stderr options) :tty (exec-options-tty options))))
           (finished-lock (bt:make-lock "gr8s SPDY exec finished"))
           (finished nil) (completed nil) (input-thread nil) (server nil))
      (flet ((finished-p () (bt:with-lock-held (finished-lock) finished))
             (mark-finished () (bt:with-lock-held (finished-lock) (setf finished t))))
        (unwind-protect
             (progn
               (setf server (make-spdy-server (begin-spdy-remotecommand protocol named)))
               (extend-api-connection-idle-timeout)
               (multiple-value-bind (streams early)
                   (handler-case (accept-remotecommand-streams
                                  server (remotecommand-expected-streams
                                          (exec-options-from-parameters (hunchentoot:get-parameters*)) protocol))
                     ;; A client that never opens its streams gets nothing more, as from a kubelet.
                     ((or error sb-sys:deadline-timeout) (condition)
                       (format *error-output* "gr8s SPDY exec streams: ~A~%" condition)
                       (return-from serve-spdy-exec-session nil)))
                 (flet ((stream-id (type) (cdr (assoc type streams :test #'equal))))
                   (setf input-thread
                         (bt:make-thread
                          (lambda () (forward-spdy-exec-input reconciler session server streams early #'finished-p))
                          :name "gr8s SPDY exec input"))
                   ;; A client that goes away ends the exec: the cleanup below cancels it.
                   (handler-case
                       (progn
                         (loop with cursor = 0
                               do (multiple-value-bind (message next done)
                                      (reconciler-next-exec-session-output reconciler session cursor)
                                    (setf cursor next)
                                    (when message
                                      (let ((id (case (operation-stream-wire-channel message)
                                                  (1 (stream-id "stdout"))
                                                  (2 (or (stream-id "stderr") (stream-id "stdout"))))))
                                        (when id
                                          (spdy-server-write-data server id (slot-value message 'gr8s.node.v1::data)))))
                                    (when done (setf completed t) (loop-finish))))
                         ;; A failure on the node reaches the client as its message, not as a dropped connection.
                         (let ((status (handler-case
                                           (spdy-remotecommand-status-bytes
                                            protocol (reconciler-exec-session-exit-code reconciler session))
                                         (runtime-error (condition)
                                           (spdy-remotecommand-failure-bytes protocol (runtime-error-message condition))))))
                           (when status (spdy-server-write-data server (stream-id "error") status)))
                         (mark-finished)
                         (dolist (type '("stdout" "stderr" "error"))
                           (when (stream-id type)
                             (spdy-server-write-data server (stream-id type)
                                                     (make-array 0 :element-type '(unsigned-byte 8)) :fin t))))
                     ((or stream-error usocket:socket-error) (condition)
                       (format *error-output* "gr8s SPDY exec client went away: ~A~%" condition))))))
          (mark-finished)
          (unless completed
            (ignore-errors (reconciler-cancel-exec-session reconciler session "API exec stream ended")))
          (reconciler-release-exec-session reconciler session)
          (when input-thread
            (stop-exec-input-reader input-thread)
            (ignore-errors (bt:join-thread input-thread))))))))
