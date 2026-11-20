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

(defparameter *leader-relay-answer-seconds* 75
  "How long the leader may take to answer a write it was sent.")

(defparameter *leader-relay-patience-seconds* 30
  "How long a follower holds a write that no leader can yet be offered.")

(defparameter *leader-relay-waiting-places* 64
  "How many writes a member holds at once while no leader can be offered them. A
write that finds no place is refused at once, as every such write used to be: a
thread is held for each, and an election must not be able to take them all.")

(defvar *leader-relay-waiting* 0)
(defvar *leader-relay-waiting-lock* (bt:make-lock "gr8s leader relay waiting places"))

(defun leader-relay-take-waiting-place ()
  (bt:with-lock-held (*leader-relay-waiting-lock*)
    (when (< *leader-relay-waiting* *leader-relay-waiting-places*)
      (incf *leader-relay-waiting*))))

(defun leader-relay-leave-waiting-place ()
  (bt:with-lock-held (*leader-relay-waiting-lock*)
    (decf *leader-relay-waiting*)))

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

;;; The client's identity, in headers

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
exactly as this member holds it, no group more and none fewer. Such a client is
carried; any other is sent to the leader to speak for itself.

A certificate may name a group \"a,b\"; sent as a header it would arrive as the
groups a and b, and the client would be given rights it does not have. The leader
also gives whoever is named like a ServiceAccount that account's groups, and
everyone but the anonymous user the group of the authenticated, so an identity
that does not already hold those would gain them."
  (let* ((actor (api-identity-actor identity))
         (username (gethash "username" actor))
         (groups (gethash "groups" actor))
         (uid (gethash "uid" actor))
         (extra (gethash "extra" actor)))
    (and (leader-relay-header-text-p username)
         (every (lambda (group) (leader-relay-header-text-p group :list-item t)) groups)
         (or (gr8s.resources::api-service-account-identity-p identity)
             (not (gr8s.resources::service-account-username-parts username)))
         (or (equal username "system:anonymous")
             (find "system:authenticated" groups :test #'equal))
         (or (null uid) (leader-relay-header-text-p uid))
         (or (not (hash-table-p extra))
             (loop for key being the hash-keys of extra using (hash-value values)
                   always (and (leader-relay-header-text-p key)
                               ;; A header's name is read without regard to case.
                               (string= key (string-downcase key))
                               (plusp (length values))
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
                ;; One header for each key: the receiver keeps only the first of
                ;; several headers whose name it has not met before.
                (loop for key being the hash-keys of extra using (hash-value values)
                      collect (cons (concatenate 'string "Impersonate-Extra-"
                                                 (hunchentoot:url-encode key :utf-8))
                                    (format nil "~{~A~^, ~}" (coerce values 'list)))))))))

;;; One member asking another

(defparameter +leader-relay-marker+ "X-Gr8s-Relayed"
  "Sent with a write one member carries to another.")

(defparameter +leader-relay-not-leader+ "x-gr8s-not-leader"
  "Answers a carried write that reached a member which does not lead, and did nothing.")

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
                               ;; The certificate must be the one issued for the address
                               ;; the membership gives for the leader.
                               (pure-tls:make-tls-client-stream
                                (usocket:socket-stream socket)
                                :hostname host :context context
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

(defun leader-relay-no-leader-response ()
  (setf (hunchentoot:header-out :retry-after) "1")
  (status-response "Failure" "ServiceUnavailable"
                   "No Raft leader could take this request; try again" 503))

(defun leader-relay-read-answer-head (stream)
  "Read the head of the leader's answer, passing over any interim response."
  (loop
    (multiple-value-bind (code headers) (aggregator-read-response-head stream)
      (unless (<= 100 code 199)
        (return (values code headers))))))

(defun leader-relay-forwarded-headers ()
  "The client's end-to-end headers, without those this member answers for itself."
  (remove-if (lambda (header)
               (member (car header) (list "expect" "x-forwarded-for" (string-downcase +leader-relay-marker+))
                       :test #'string-equal))
             (aggregator-forwarded-headers)))

(defun leader-relay-exchange (stream request body host identity)
  "Send REQUEST to the leader on STREAM and pass its answer to the client. Returns
:NOT-LEADER, with nothing passed on, when the member asked does not lead and so
did nothing with the write."
  (let ((method (hunchentoot:request-method request))
        (content-type (hunchentoot:header-in :content-type request))
        (started nil))
    (flet ((fail (condition)
             (cond ((not (or started hunchentoot::*headers-sent*))
                    (leader-relay-unanswered-response))
                   ;; Part of the answer has gone to the client and the rest will
                   ;; not come. Nothing more can be said on this connection, so it
                   ;; is closed: the client sees that the answer was cut short. The
                   ;; condition is dealt with here because a timeout is no ERROR,
                   ;; and signalled further it would stop this thread in the
                   ;; debugger with both connections held.
                   (t (format *error-output* "gr8s: the Raft leader's answer to ~A ~A was cut short: ~A~%"
                              method (hunchentoot:script-name request) condition)
                      (setf hunchentoot::*finish-processing-socket* t)
                      ""))))
      (handler-case
          (sb-sys:with-deadline (:seconds *leader-relay-answer-seconds*)
            (aggregator-write-request
             stream method (hunchentoot:request-uri request) host
             (append (leader-relay-identity-headers identity)
                     (list (cons +leader-relay-marker+ "1"))
                     (when content-type (list (cons "content-type" content-type)))
                     (list (cons "x-forwarded-for" (hunchentoot:remote-addr request)))
                     (leader-relay-forwarded-headers))
             body)
            (multiple-value-bind (code headers) (leader-relay-read-answer-head stream)
              (if (and (= code 503) (assoc +leader-relay-not-leader+ headers :test #'string=))
                  :not-leader
                  (let ((client (aggregator-send-response-head code headers)))
                    (setf started t)
                    (unless (or (eq method :head) (member code '(204 304)))
                      (aggregator-copy-body stream client headers))
                    ;; The answer has been given; this only tells the dispatcher so.
                    ""))))
        (sb-sys:deadline-timeout (condition) (fail condition))
        (error (condition) (fail condition))))))

(defun leader-relay-request-body (request)
  (read-request-body request)
  (let ((octets (hunchentoot:raw-post-data :request request :force-binary t)))
    (if (typep octets '(vector (unsigned-byte 8))) octets #())))

(defun leader-relay-refuse-carried-write ()
  "Answer a write another member carried here in the belief that this one leads."
  (setf (hunchentoot:header-out +leader-relay-not-leader+) "1")
  (leader-relay-no-leader-response))

(defun ha-follower-write-response (acceptor request)
  "On a member that does not lead, carry a write to the leader and return its
answer; NIL when REQUEST is to be handled here, which includes this member
having come to lead while it held the write."
  (let ((status-fn (acceptor-leader-status-fn acceptor))
        (pki (acceptor-relay-pki acceptor)))
    (when (and status-fn (leader-relayed-request-p request)
               (not (funcall status-fn)))
      ;; Two members that each took the other for the leader would hand a write
      ;; back and forth. The one a carried write reaches says that it does not
      ;; lead, and the one that carried it looks for the leader again.
      (when (hunchentoot:header-in :x-gr8s-relayed request)
        (return-from ha-follower-write-response (leader-relay-refuse-carried-write)))
      (unless (leader-relay-identity-expressible-p (request-api-identity))
        (return-from ha-follower-write-response nil))
      (let ((deadline (+ (get-internal-real-time)
                         (* *leader-relay-patience-seconds* internal-time-units-per-second)))
            (waiting nil) (body nil))
        (unwind-protect
             (loop
               (multiple-value-bind (self-leader-p leader-url) (funcall status-fn)
                 (when self-leader-p (return nil))
                 (multiple-value-bind (scheme host port) (leader-relay-target leader-url)
                   ;; A member with no credential to ask with can only point the way.
                   (when (and scheme (not pki) (not (equal scheme "http")))
                     (return nil))
                   (when scheme
                     (multiple-value-bind (socket stream) (leader-relay-connect pki scheme host port)
                       (when socket
                         (let ((answer
                                 (unwind-protect
                                      (handler-case
                                          (leader-relay-exchange
                                           stream request
                                           ;; Read once: a second member may be asked.
                                           (or body (setf body (leader-relay-request-body request)))
                                           (format nil "~A:~D" host port) (request-api-identity))
                                        (kubernetes-error (condition)
                                          (kubernetes-error-response condition)))
                                   (ignore-errors (usocket:socket-close socket)))))
                           (unless (eq answer :not-leader)
                             (return answer))))))))
               (when (>= (get-internal-real-time) deadline)
                 (return (leader-relay-no-leader-response)))
               (unless waiting
                 (unless (leader-relay-take-waiting-place)
                   (return (leader-relay-no-leader-response)))
                 (setf waiting t))
               (sleep 0.2))
          (when waiting (leader-relay-leave-waiting-place)))))))
