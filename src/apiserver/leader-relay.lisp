;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; A member that does not lead carries a write to the leader (podster-l8i).
;;;;
;;;; Only the leader writes: it takes writes one at a time, and rules such as "no
;;;; two Services hold one node port" rest on that. A follower used to answer a
;;;; write with a 307 to the leader's URL. The client then had to reach the leader
;;;; itself, and if the leader had just stopped it waited there until its own
;;;; timeout, though the member it first asked was healthy and would soon know
;;;; the next leader.
;;;;
;;;; The follower now makes that request itself, as the client: it has already
;;;; authenticated the client, and it asks the leader with this member's
;;;; administrative certificate to act for that identity (impersonation, as
;;;; `kubectl --as` does). The leader authorizes, validates and writes as it
;;;; would have done for the client.
;;;;
;;;; Each relayed write opens its own connection. While that connection is not
;;;; established the leader has seen nothing of the write, so the follower may
;;;; wait and offer it to whoever leads next, or serve it itself if that is this
;;;; member. Once the write has been sent, only the leader's answer ends it: it
;;;; is never sent twice.
;;;;
;;;; A request that upgrades its connection (exec, attach, port-forward, proxy)
;;;; is a conversation the client must hold with the member that carries it, and
;;;; is still redirected. So is a client whose identity cannot be put in headers
;;;; without changing it.

(in-package #:gr8s.apiserver)

(defparameter +leader-relay-connect-seconds+ 2
  "How long a connection to the leader may take to be established.")

(defparameter +leader-relay-answer-seconds+ 75
  "How long the leader may take to answer a write it was sent.")

(defparameter *leader-relay-patience-seconds* 30
  "How long a follower holds a write that no leader can yet be offered.")

(defparameter +leader-relay-server-name+ "kubernetes.default.svc"
  "A name every member's API certificate carries, whatever address it is reached at.")

(defun leader-relay-target (leader-url)
  "The scheme, host and port LEADER-URL names, or NIL."
  (when (stringp leader-url)
    (multiple-value-bind (match groups)
        (cl-ppcre:scan-to-strings "^(https?)://(\\[[^\\]]+\\]|[^:/\\[\\]]+):(\\d{1,5})/?$" leader-url)
      (when match
        (values (aref groups 0) (string-trim "[]" (aref groups 1)) (parse-integer (aref groups 2)))))))

(defun leader-relayed-request-p (request)
  "True for a write a follower carries to the leader: one request with one answer."
  (let ((path (hunchentoot:script-name request)))
    (and (raft-mutating-method-p (hunchentoot:request-method request))
         (not (ha-non-redirecting-write-path-p path))
         (not (hunchentoot:header-in :upgrade request))
         (not (cl-ppcre:scan "/(pods|services|nodes)/[^/]+/(exec|attach|portforward|proxy)(/|$)" path)))))

(defun leader-relay-header-text-p (text &key list-item)
  "True when TEXT arrives at the leader as it left: printable ASCII with no space
at either end. One of several values of a header (LIST-ITEM) may hold no comma,
which is where the receiver divides them."
  (and (stringp text) (plusp (length text))
       (every (lambda (character) (char<= #\Space character #\~)) text)
       (char/= #\Space (char text 0)) (char/= #\Space (char text (1- (length text))))
       (not (and list-item (find #\, text)))))

(defun leader-relay-identity-expressible-p (identity)
  "True when the leader will read IDENTITY from LEADER-RELAY-IDENTITY-HEADERS
exactly as this member holds it. A certificate may name a group \"a,b\"; sent as a
header it would arrive as the groups a and b, and the client would be given
rights it does not have. Such a client is sent to the leader to speak for itself."
  (let* ((actor (api-identity-actor identity))
         (uid (gethash "uid" actor))
         (extra (gethash "extra" actor)))
    (and (leader-relay-header-text-p (gethash "username" actor))
         (every (lambda (group) (leader-relay-header-text-p group :list-item t)) (gethash "groups" actor))
         (or (null uid) (leader-relay-header-text-p uid))
         (or (not (hash-table-p extra))
             (loop for key being the hash-keys of extra using (hash-value values)
                   always (and (leader-relay-header-text-p key)
                               ;; A header's name is read without regard to case.
                               (string= key (string-downcase key))
                               (every (lambda (value) (leader-relay-header-text-p value :list-item t))
                                      values)))))))

(defun leader-relay-identity-headers (identity)
  "Ask the leader to act for IDENTITY, which this member authenticated."
  (let ((actor (api-identity-actor identity)))
    (append (list (cons "Impersonate-User" (gethash "username" actor)))
            (map 'list (lambda (group) (cons "Impersonate-Group" group)) (gethash "groups" actor))
            (let ((uid (gethash "uid" actor)))
              (when uid (list (cons "Impersonate-Uid" uid))))
            (let ((extra (gethash "extra" actor)))
              (when (hash-table-p extra)
                (loop for key being the hash-keys of extra using (hash-value values)
                      append (map 'list
                                  (lambda (value)
                                    (cons (concatenate 'string "Impersonate-Extra-"
                                                       (hunchentoot:url-encode key :utf-8))
                                          value))
                                  values)))))))

(defun leader-relay-connect (pki scheme host port)
  "Open a connection to the leader's API, returning its socket and stream, or NIL
if none could be established in time. Nothing has been sent on a connection this
returns, and the leader has seen no request on one it does not."
  (let ((socket nil) (connected nil)
        (pure-tls:*session-ticket-cache* (make-hash-table :test 'equal)))
    (handler-case
        (unwind-protect
             (sb-sys:with-deadline (:seconds +leader-relay-connect-seconds+)
               (setf socket (usocket:socket-connect host port :element-type '(unsigned-byte 8)
                                                              :timeout +leader-relay-connect-seconds+ :nodelay t))
               (let ((stream
                       (if (equal scheme "http")
                           (usocket:socket-stream socket)
                           (multiple-value-bind (certificate key) (ensure-admin-client-credentials pki)
                             (let ((context (pure-tls:make-tls-context :verify-mode pure-tls:+verify-required+
                                                                       :auto-load-system-ca nil)))
                               (setf (pure-tls::tls-context-trust-store context)
                                     (pure-tls::make-trust-store
                                      :certificates (cluster-pki-trust-certificates pki)))
                               (pure-tls:make-tls-client-stream
                                (usocket:socket-stream socket)
                                :hostname +leader-relay-server-name+ :context context
                                :verify pure-tls:+verify-required+
                                :client-certificate (namestring certificate)
                                :client-key (namestring key)))))))
                 (setf connected t)
                 (values socket stream)))
          (when (and socket (not connected)) (ignore-errors (usocket:socket-close socket))))
      ((or error sb-sys:deadline-timeout) () nil))))

(defun leader-relay-unanswered-response ()
  "The leader was sent the write and its answer did not arrive. Whether it wrote is
not known, so the client is told that and not asked to send the write again."
  (status-response "Failure" "Timeout"
                   "The Raft leader was sent this request and did not answer; it may or may not have been carried out"
                   504))

(defun leader-relay-exchange (socket stream request body host identity)
  "Send REQUEST to the leader on STREAM and pass its answer to the client."
  (let ((method (hunchentoot:request-method request))
        (content-type (hunchentoot:header-in :content-type request))
        (started nil))
    (unwind-protect
         (handler-case
             (sb-sys:with-deadline (:seconds +leader-relay-answer-seconds+)
               (aggregator-write-request
                stream method (hunchentoot:request-uri request) host
                (append (leader-relay-identity-headers identity)
                        (when content-type (list (cons "content-type" content-type)))
                        (list (cons "x-forwarded-for" (hunchentoot:remote-addr request)))
                        (remove "x-forwarded-for" (aggregator-forwarded-headers)
                                :key #'car :test #'string-equal))
                body)
               (multiple-value-bind (code headers) (aggregator-read-response-head stream)
                 (let ((client (aggregator-send-response-head code headers)))
                   (setf started t)
                   (unless (or (eq method :head) (member code '(204 304)))
                     (aggregator-copy-body stream client headers))))
               ;; The answer is on its way; this only tells the dispatcher it was given.
               "")
           ((or error sb-sys:deadline-timeout) (condition)
             (if (or started hunchentoot::*headers-sent*)
                 (error condition)
                 (leader-relay-unanswered-response))))
      (ignore-errors (usocket:socket-close socket)))))

(defun leader-relay-no-leader-response ()
  (setf (hunchentoot:header-out :retry-after) "1")
  (status-response "Failure" "ServiceUnavailable"
                   "No Raft leader could take this request; try again" 503))

(defun ha-follower-write-response (acceptor request)
  "On a member that does not lead, carry a write to the leader and return its
answer; NIL when REQUEST is to be handled here, which includes this member
having come to lead while it held the write."
  (let ((status-fn (acceptor-leader-status-fn acceptor))
        (pki (acceptor-relay-pki acceptor)))
    (when (and status-fn (leader-relayed-request-p request)
               (not (funcall status-fn))
               (leader-relay-identity-expressible-p (request-api-identity)))
      (let ((deadline (+ (get-internal-real-time)
                         (* *leader-relay-patience-seconds* internal-time-units-per-second)))
            (body nil))
        (loop
          (multiple-value-bind (self-leader-p leader-url) (funcall status-fn)
            (when self-leader-p (return nil))
            (multiple-value-bind (scheme host port) (leader-relay-target leader-url)
              (when (and scheme (or pki (equal scheme "http")))
                (multiple-value-bind (socket stream) (leader-relay-connect pki scheme host port)
                  (when socket
                    (unless body
                      (handler-case (read-request-body request)
                        (kubernetes-error (condition)
                          (ignore-errors (usocket:socket-close socket))
                          (return (kubernetes-error-response condition))))
                      (setf body (let ((octets (hunchentoot:raw-post-data :request request :force-binary t)))
                                   (if (typep octets '(vector (unsigned-byte 8))) octets #()))))
                    (return (leader-relay-exchange socket stream request body
                                                   (format nil "~A:~D" host port)
                                                   (request-api-identity))))))
              ;; A member with no credential to ask with can only point the way.
              (when (and scheme (not pki) (not (equal scheme "http")))
                (return nil))))
          (when (>= (get-internal-real-time) deadline)
            (return (leader-relay-no-leader-response)))
          (sleep 0.2))))))
