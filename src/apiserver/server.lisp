;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; The HTTP front end: the Hunchentoot acceptor that serves the Kubernetes API.
;;;;
;;;; This is the listener and request dispatch, not the handlers (see http.lisp).
;;;; It answers the health endpoints (/healthz, /livez, /readyz) the way upstream's
;;;; healthz package does, and -- when configured for HA -- redirects mutating
;;;; requests to the Raft leader so writes land where consensus happens. Three
;;;; choices here exist for compatibility rather than cleanliness: the connection
;;;; limit is raised well above Hunchentoot's default because every open watch
;;;; holds a connection; several HTTP reason phrases are overridden to match Go's
;;;; net/http, which conformance clients match on; and upgraded exec/attach streams
;;;; get a long idle timeout since a command may sit silent for hours. v1 binds
;;;; loopback only. The STOP override force-wakes the listener to work around an
;;;; intermittent shutdown hang (podster-uqb.82).

(in-package #:gr8s.apiserver)

(defparameter +api-connection-limit+ 1024
  "Connections served at once. Each open watch keeps one, and Hunchentoot's default of
100 stops accepting at that point, leaving even short requests in a handshake timeout.")

;; Clients read the status line, and some match its text: a kubectl request with a bad token
;; logs it, and upstream's in-cluster config conformance spec expects "401 Unauthorized". These
;; are the phrases Go's net/http (http.StatusText) sends where Hunchentoot's differ.
(loop for (code phrase) in '((302 "Found") (401 "Unauthorized") (408 "Request Timeout")
                             (414 "Request URI Too Long") (416 "Requested Range Not Satisfiable")
                             (504 "Gateway Timeout") (505 "HTTP Version Not Supported"))
      do (setf (gethash code hunchentoot::*http-reason-phrase-map*) phrase))

(defclass gr8s-acceptor (hunchentoot:easy-acceptor)
  ((store :initarg :store :reader acceptor-store)
   (runtime :initarg :runtime :reader acceptor-runtime)
   (reconciler :initarg :reconciler :reader acceptor-reconciler)
   (debug-state-directory :initarg :debug-state-directory :initform nil
                          :reader acceptor-debug-state-directory)
   ;; Called with a member id; returns (values local-p api-url exists-p).
   (debug-member-resolver :initarg :debug-member-resolver :initform nil
                          :reader acceptor-debug-member-resolver)
   (control-plane-metrics-fn :initarg :control-plane-metrics-fn :initform nil
                             :reader acceptor-control-plane-metrics-fn)
   ;; HA membership surface (podster-9x6): NIL (single-node) or a function of
   ;; (:list) -> the gr8s.ha:ha-control-plane-membership plist, and
   ;; (:remove id) -> (values proposed-p reason).
   (control-plane-membership-fn :initarg :control-plane-membership-fn :initform nil
                                :reader acceptor-control-plane-membership-fn)
   ;; HA (podster-c2d.7.3): NIL (single-node) or a function returning
   ;; (values self-leader-p leader-api-url). A follower redirects mutating
   ;; requests to the leader so writes always land where consensus happens.
   (leader-status-fn :initarg :leader-status-fn :initform nil :reader acceptor-leader-status-fn)
   ;; HA (podster-gxi): NIL (single-node) or a function of no arguments that
   ;; returns T once this member's store holds every write committed before the
   ;; call, or (values NIL reason) when no leader that a quorum follows can be
   ;; reached. See HA-STALE-READ-RESPONSE.
   (linearizable-read-fn :initarg :linearizable-read-fn :initform nil
                         :reader acceptor-linearizable-read-fn)
   ;; NIL, or a function returning true unless this member has lost the leader.
   (follows-a-leader-fn :initarg :follows-a-leader-fn :initform nil
                        :reader acceptor-follows-a-leader-fn))
  (:default-initargs
   :listen-backlog 512
   :taskmaster (make-instance 'hunchentoot:one-thread-per-connection-taskmaster
                              :max-thread-count +api-connection-limit+
                              :max-accept-count (+ +api-connection-limit+ 128))))

(defvar *api-connection-socket* nil
  "The socket of the API connection this thread serves, for a stream that outlives its request.")

(defun client-connection-closed-p (fd)
  "Report whether the peer of socket FD has closed it, without consuming anything it sent."
  (sb-alien:with-alien ((octet (sb-alien:array (sb-alien:unsigned 8) 1)))
    (let ((got (sb-alien:alien-funcall
                (sb-alien:extern-alien "recv" (function sb-alien:long sb-alien:int (* t) sb-alien:unsigned-long sb-alien:int))
                fd (sb-alien:alien-sap octet) 1 (logior 2 #x40)))) ; MSG_PEEK | MSG_DONTWAIT
      (zerop got))))

(defun api-watch-client-departed-p ()
  "Report whether the client connection serving the current native API watch has closed."
  (let ((socket *api-connection-socket*))
    (and socket
         (client-connection-closed-p
          (sb-sys:fd-stream-fd (usocket:socket-stream socket))))))

(defmethod hunchentoot:process-connection :around ((acceptor gr8s-acceptor) socket)
  (let ((*api-connection-socket* socket)
        ;; STOP wakes an acceptor with a connection that closes without an HTTP
        ;; request (and, for the in-cluster API, without a TLS handshake).  That
        ;; is expected shutdown traffic, not an application error.
        (hunchentoot::*log-lisp-errors-p*
          (not (hunchentoot::acceptor-shutdown-p acceptor))))
    (call-next-method)))

(defparameter +stream-idle-timeout-seconds+ (* 4 60 60)
  "How long an upgraded exec or attach stream may wait for its client: kubelet's default
StreamIdleTimeout. The connection's ordinary read timeout is Hunchentoot's 20 seconds.")

(defun extend-api-connection-idle-timeout (&optional (seconds +stream-idle-timeout-seconds+))
  "Let the current connection's client stay quiet for SECONDS. A command can run for minutes
without input, and a client without WebSocket pings (any before v5.channel.k8s.io) sends none."
  (let ((socket *api-connection-socket*))
    (when socket
      (ignore-errors (setf (sb-impl::fd-stream-timeout (usocket:socket-stream socket))
                           (coerce seconds 'single-float))))))

(defun ha-non-redirecting-write-path-p (script-name)
  "True for POST endpoints that are not real writes and must be served locally on
   any member, never redirected to the leader. Patch commands authenticate
   locally and relay over member mTLS. Authorization and token reviews are
   read-only evaluations -- they persist nothing, every member can answer them,
   and redirecting them breaks clients that probe permissions against a follower
   (the dashboard's login check POSTs a SelfSubjectRulesReview; a redirect to the
   leader's API URL fails and surfaces as \"Error Authenticating\")."
  (or (equal script-name "/apis/gr8s.io/v1/patchrollouts")
      (and (uiop:string-prefix-p "/apis/authorization.k8s.io/v1/" script-name)
           (loop for review in '("selfsubjectrulesreviews" "selfsubjectaccessreviews"
                                 "localsubjectaccessreviews")
                 thereis (uiop:string-suffix-p script-name (concatenate 'string "/" review))))
      (equal script-name "/apis/authentication.k8s.io/v1/tokenreviews")))

(defun ha-redirect-response (acceptor request)
  "When this member is not the Raft leader and REQUEST mutates, return a redirect
   to the leader (or a 503 if the leader is unknown); else NIL to serve locally."
  (when (ha-non-redirecting-write-path-p (hunchentoot:script-name request))
    (return-from ha-redirect-response nil))
  (let ((status-fn (acceptor-leader-status-fn acceptor)))
    (when status-fn
      (multiple-value-bind (self-leader-p leader-url) (funcall status-fn)
        (when (and (not self-leader-p)
                   (raft-mutating-method-p (hunchentoot:request-method request)))
          (let* ((uri (hunchentoot:request-uri request))
                 (target (raft-leader-redirect-url (hunchentoot:request-method request)
                                                   uri self-leader-p leader-url)))
            (cond
              (target
               (setf (hunchentoot:return-code*) hunchentoot:+http-temporary-redirect+
                     (hunchentoot:header-out :location) target
                     (hunchentoot:content-type*) "text/plain; charset=utf-8")
               (format nil "The Raft leader serves writes; retry at ~A~%" target))
              (t
               (setf (hunchentoot:return-code*) hunchentoot:+http-service-unavailable+
                     (hunchentoot:content-type*) "text/plain; charset=utf-8")
               (format nil "No Raft leader is currently available~%")))))))))

(defun linearizable-read-request-p (method path resource-version)
  "True for a read that Kubernetes answers from a quorum: a GET, LIST or WATCH of
resources that names no resourceVersion (\"Most Recent\" in the API concepts). A
read at resourceVersion=0 asks for any version, however old, and one at a given
version asks for that one; discovery and health describe this server; and the
gr8s.io endpoints are what an operator uses to look at a member that is cut off."
  (and (eq method :get)
       (member resource-version '(nil "") :test #'equal)
       (cl-ppcre:scan "^/(api/v1|apis/[^/]+/[^/]+)/[^/]" path)
       (not (uiop:string-prefix-p "/apis/gr8s.io/" path))
       t))

(defun ha-stale-read-response (acceptor request)
  "Before a read that must be current, bring this member up to date with the
leader; return NIL to serve it. A member that cannot reach a leader that a quorum
follows answers 503, as it already does for a write: its own state may be
arbitrarily old, and it cannot tell (podster-gxi)."
  (let ((await (acceptor-linearizable-read-fn acceptor)))
    (when (and await
               (linearizable-read-request-p (hunchentoot:request-method request)
                                            (hunchentoot:script-name request)
                                            (hunchentoot:get-parameter "resourceVersion" request)))
      (multiple-value-bind (current reason) (funcall await)
        (unless current
          (setf (hunchentoot:return-code*) hunchentoot:+http-service-unavailable+
                (hunchentoot:content-type*) "application/json"
                (hunchentoot:header-out "Retry-After") "1")
          (com.inuoe.jzon:stringify
           (json-object
            "kind" "Status" "apiVersion" "v1" "metadata" (json-object)
            "status" "Failure" "reason" "ServiceUnavailable" "code" 503
            "message" (format nil "This control-plane member cannot reach a Raft leader that a quorum follows (~(~A~)), so it cannot tell how old its state is. Retry, use another member, or pass resourceVersion=0 to read this member's own state."
                              (or reason :timeout)))))))))

;;; Health endpoints, answered as upstream's healthz package does: each check is
;;; listed by name with ?verbose, can be read alone at /<endpoint>/<check>, and can be
;;; left out with ?exclude=. Every check names a part of upstream's server that has
;;; a counterpart here which is running whenever this listener answers.

(defparameter +health-common-checks+
  '("ping" "log" "etcd"
    "poststarthook/start-apiserver-admission-initializer"
    "poststarthook/generic-apiserver-start-informers"
    "poststarthook/start-apiextensions-informers"
    "poststarthook/start-apiextensions-controllers"
    "poststarthook/crd-informer-synced"
    "poststarthook/storage-readiness"
    "poststarthook/bootstrap-controller"
    "poststarthook/start-system-namespaces-controller"
    "poststarthook/start-service-ip-repair-controllers"
    "poststarthook/scheduling/bootstrap-system-priority-classes"
    "poststarthook/start-cluster-authentication-info-controller"
    "poststarthook/start-kube-aggregator-informers"
    "poststarthook/apiservice-registration-controller"
    "poststarthook/apiservice-status-local-available-controller"
    "poststarthook/apiservice-status-remote-available-controller"
    "poststarthook/kube-apiserver-autoregistration"
    "autoregister-completion"
    "poststarthook/apiservice-openapi-controller")
  "Checks /healthz and /livez report.")

(defun health-endpoint-checks (endpoint)
  "Return the checks ENDPOINT (healthz, livez or readyz) reports, in order."
  (if (equal endpoint "readyz")
      (append (subseq +health-common-checks+ 0 3) '("informer-sync") (subseq +health-common-checks+ 3))
      +health-common-checks+))

(defun health-response (path &optional store follows-a-leader-fn)
  "Answer a health PATH such as /readyz or /livez/etcd, or return NIL for any other path."
  (let* ((parts (cl-ppcre:split "/" path :limit 3))
         (endpoint (second parts))
         (check (third parts)))
    (when (member endpoint '("healthz" "livez" "readyz") :test #'equal)
      (let ((checks (health-endpoint-checks endpoint)))
        (setf (hunchentoot:content-type*) "text/plain; charset=utf-8"
              (hunchentoot:header-out "X-Content-Type-Options") "nosniff")
        (cond
          ((and (equal endpoint "readyz") store (gr8s.store::store-access-blocked-p store))
           (setf (hunchentoot:return-code*) 503)
           "application restore in progress")
          ;; Upstream's etcd check fails when its etcd cannot serve a quorum
          ;; read, which takes the server out of a load balancer. A member that
          ;; has lost the leader is in that state; it is still alive.
          ((and (equal endpoint "readyz") (member check '(nil "" "etcd") :test #'equal)
                (not (member "etcd" (loop for (name . value) in (hunchentoot:get-parameters*)
                                          when (equal name "exclude") collect value)
                             :test #'equal))
                follows-a-leader-fn (not (funcall follows-a-leader-fn)))
           (setf (hunchentoot:return-code*) 503)
           (if (hunchentoot:get-parameter "verbose")
               (with-output-to-string (out)
                 (dolist (name checks)
                   (format out (if (equal name "etcd") "[-]etcd failed: reason withheld~%" "[+]~A ok~%") name))
                 (format out "readyz check failed~%"))
               (format nil "[-]etcd failed: this member has lost the Raft leader~%")))
          ((and check (plusp (length check)))
           (if (member check checks :test #'equal)
               "ok"
               (progn (setf (hunchentoot:return-code*) hunchentoot:+http-not-found+)
                      (format nil "404 page not found~%"))))
          ((hunchentoot:get-parameter "verbose")
           (let ((excluded (loop for (name . value) in (hunchentoot:get-parameters*)
                                 when (equal name "exclude") collect value)))
             (with-output-to-string (out)
               (dolist (name checks)
                 (if (member name excluded :test #'equal)
                     (format out "[+]~A excluded: ok~%" name)
                     (format out "[+]~A ok~%" name)))
               (format out "~A check passed~%" endpoint))))
          (t "ok"))))))

(defmethod hunchentoot:acceptor-dispatch-request
    ((acceptor gr8s-acceptor) request)
  (cond
    ((health-response (hunchentoot:script-name request) (acceptor-store acceptor)
                      (acceptor-follows-a-leader-fn acceptor)))
    ((ha-redirect-response acceptor request))
    ((ha-stale-read-response acceptor request))
    (t
     (handle-http-request (acceptor-store acceptor)
                          (acceptor-runtime acceptor)
                          (acceptor-reconciler acceptor)
                          request))))

(defun start-server (&key (address "127.0.0.1") (port 8080)
                          store runtime reconciler leader-status-fn
                          linearizable-read-fn follows-a-leader-fn
                          debug-state-directory debug-member-resolver control-plane-metrics-fn
                          control-plane-membership-fn)
  "Start the gr8s API server on ADDRESS:PORT and return the running acceptor.
   Signals an error unless ADDRESS is 127.0.0.1 (v1 listens only on loopback).
   STORE, RUNTIME, and RECONCILER default from one another: a RECONCILER supplies
   its store and runtime, a missing runtime becomes a fake one, and a missing
   reconciler is built from the store. LEADER-STATUS-FN, when given, drives HA
   redirection of mutating requests to the Raft leader."
  (unless (string= address "127.0.0.1")
    (error "gr8s v1 only listens on 127.0.0.1"))
  (let* ((actual-store (or store
                           (and reconciler (reconciler-store reconciler))))
         (actual-runtime (or runtime
                             (and reconciler
                                  (reconciler-runtime reconciler))
                             (make-fake-runtime)))
         (actual-reconciler
           (or reconciler
               (and actual-store
                    (make-reconciler actual-store actual-runtime)))))
    (hunchentoot:start
     (make-instance 'gr8s-acceptor
                    :address address
                    :port port
                    :store actual-store
                    :runtime actual-runtime
                    :reconciler actual-reconciler
                    :debug-state-directory debug-state-directory
                    :debug-member-resolver debug-member-resolver
                    :control-plane-metrics-fn control-plane-metrics-fn
                    :control-plane-membership-fn control-plane-membership-fn
                    :leader-status-fn leader-status-fn
                    :linearizable-read-fn linearizable-read-fn
                    :follows-a-leader-fn follows-a-leader-fn))))

(defparameter +api-listener-shutdown-timeout+ 2.0
  "Seconds to wait for a Hunchentoot listener after repeated shutdown wakes.")

(defmethod hunchentoot:stop :around ((acceptor gr8s-acceptor) &key soft)
  "Bound Hunchentoot's otherwise unbounded listener join during STOP."
  ;; Hunchentoot joins its listener without a timeout.  A wake is normally
  ;; enough, but a listener has intermittently remained in accept(2), leaving
  ;; `gr8s serve' stuck forever.  Keep waking only while the listener lives,
  ;; then terminate that one acceptor thread at the deadline so outer component
  ;; teardown can continue.
  (declare (ignorable soft))
  (let* ((stopped nil)
         (forced nil)
         (taskmaster (hunchentoot::acceptor-taskmaster acceptor))
         (listener (hunchentoot::acceptor-process taskmaster))
         (deadline (+ (get-internal-real-time)
                      (* +api-listener-shutdown-timeout+
                         internal-time-units-per-second)))
         (waker
           (bt:make-thread
            (lambda ()
              ;; Let CALL-NEXT-METHOD set the shutdown flag before the first
              ;; wake connection can be accepted as ordinary client traffic.
              (loop until (or stopped
                              (hunchentoot::acceptor-shutdown-p acceptor))
                    do (sleep 0.001))
              (loop until (or stopped (not (bt:thread-alive-p listener)))
                    do (when (>= (get-internal-real-time) deadline)
                         (format *error-output*
                                 "gr8s API listener did not stop in time; terminating it.~%")
                         (setf forced t)
                         (ignore-errors (bt:destroy-thread listener))
                         (return))
                       (ignore-errors
                         (hunchentoot::wake-acceptor-for-shutdown acceptor))
                       (sleep 0.1)))
            :name "gr8s server stop waker")))
    (unwind-protect
         (handler-case (call-next-method)
           (sb-thread:join-thread-error (condition)
             ;; A listener terminated by the deadline is reported as an
             ;; abnormal join by Hunchentoot before it can close this socket.
             ;; Complete those final two STOP steps here; propagate any join
             ;; failure that did not come from our terminated listener.
             (if (or (not forced) (bt:thread-alive-p listener))
                 (error condition)
                 (progn
                   (ignore-errors
                     (usocket:socket-close
                      (hunchentoot::acceptor-listen-socket acceptor)))
                   (setf (hunchentoot::acceptor-listen-socket acceptor) nil)
                   acceptor))))
      (setf stopped t)
      (ignore-errors (bt:join-thread waker)))))

(defun stop-server (server)
  "Stop the API server SERVER (a running acceptor), blocking until its listener
   exits."
  (hunchentoot:stop server))
