;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; The in-agent Lisp L7 proxy for the Gateway API data plane (podster-43k.4).
;;;; A Gateway listener is a Hunchentoot acceptor that terminates HTTP, dispatches
;;;; each request through the hostname-indexed router (gateway-router.lisp) to pick a
;;;; backend, resolves that backend to an address, and proxies the exchange to it
;;;; -- no Envoy, no sidecar. The compiled router is swappable so a route change
;;;; recompiles and hot-swaps without dropping the listener. Request/response
;;;; header hygiene and framed body copying are shared with the Pod proxy.

(in-package #:gr8s.controllers)

(defstruct gateway-tls-binding certificate key router entry routing-table secret-identity reference)
(defstruct gateway-tls-snapshot index bootstrap (parents (fset:empty-ch-map nil)) (secrets (fset:empty-ch-map nil)))
(defvar *gateway-connection-tls-snapshot* nil)
(defvar *gateway-connection-tls-binding* nil)

(defun gateway-connection-router (acceptor host)
  "Keep requests on the logical listener selected during this TLS handshake."
  (if *gateway-connection-tls-snapshot*
      (when (and *gateway-connection-tls-binding*
                 (eq *gateway-connection-tls-binding*
                     (gateway-certificate-for-host
                      (gateway-tls-snapshot-index *gateway-connection-tls-snapshot*) host)))
        (gateway-tls-binding-router *gateway-connection-tls-binding*))
      (gateway-acceptor-router acceptor)))

(defun gateway-tls-certificate-provider (hostname alpn)
  "Select material even when SNI is absent; never fall back to bootstrap material."
  (declare (ignore alpn))
  (setf *gateway-connection-tls-binding*
        (gateway-certificate-for-host
         (gateway-tls-snapshot-index *gateway-connection-tls-snapshot*) hostname))
  (unless *gateway-connection-tls-binding*
    (error 'pure-tls:tls-error :message "No admitted TLS listener for this hostname"))
  (values (gateway-tls-binding-certificate *gateway-connection-tls-binding*)
          (gateway-tls-binding-key *gateway-connection-tls-binding*)))

(defclass gateway-acceptor (hunchentoot:acceptor)
  ((router :initarg :router :accessor gateway-acceptor-router :initform nil
           :documentation "The compiled dispatch fn (host path method headers) -> GW-BACKEND|NIL; hot-swappable.")
   (resolver :initarg :resolver :accessor gateway-acceptor-resolver :initform nil
             :documentation "(lambda (GW-BACKEND) -> (values host port)|NIL) resolving a backend to an address.")
   (gateway-name :initarg :gateway-name :accessor gateway-acceptor-name :initform "gateway"))
  (:documentation "A Hunchentoot acceptor that serves one Gateway listener port."))

(defun gateway-request-host (request)
  "The request's Host header with any :port stripped (Gateway hostname matching
   is on the authority host only)."
  (let ((host (hunchentoot:header-in* :host request)))
    (when host
      (let ((colon (position #\: host :from-end t))
            (bracket (position #\] host)))
        ;; Keep IPv6 literals intact ([::1]); otherwise trim at the port colon.
        (if (and colon (or (null bracket) (> colon bracket)))
            (subseq host 0 colon)
            host)))))

(defun gateway-request-headers (request)
  "The inbound headers as an alist of (lowercase-name . value) for route matching."
  (mapcar (lambda (header) (cons (string-downcase (string (car header))) (cdr header)))
          (hunchentoot:headers-in* request)))

(defun gateway-dispatch-for-request (acceptor request)
  "Run the listener's compiled router against REQUEST. Returns a GW-DISPATCH
   (backend + matched rule's filters + matched GW-MATCH) or NIL."
  (let ((router (gateway-connection-router acceptor (gateway-request-host request))))
    (when router
      (funcall router
               (or (gateway-request-host request) "")
               (hunchentoot:script-name request)
               (string (hunchentoot:request-method request))
               (gateway-request-headers request)))))

(defun gateway-resolve-backend (acceptor backend)
  "Resolve BACKEND to (values host port) via the listener's resolver, or NIL."
  (resolve-gateway-backend backend (gateway-acceptor-resolver acceptor)))

(defun gateway-error-response (code fmt &rest args)
  "Emit a minimal text error unless the response has already been committed."
  (setf (hunchentoot:return-code*) code
        (hunchentoot:content-type*) "text/plain; charset=utf-8")
  (apply #'format nil fmt args))

;;; ---------------------------------------------------------------------------
;;; Per-route observability + token-bucket rate limiting (podster-43k.8).
;;; Counters and buckets are process-global (routes are unique by namespace/name);
;;; the eBPF token-bucket fast path is a later refinement.

(defvar *gateway-metrics-lock* (bt:make-lock "gr8s gateway metrics"))
(defvar *gateway-request-counts* (make-hash-table :test 'equal)
  "Prometheus label string -> request count.")

(defun gateway-count-request (gateway route code)
  "Increment the Prometheus request counter for GATEWAY, ROUTE and HTTP status
   CODE (labels sanitized), under the metrics lock."
  (let ((key (format nil "gateway=\"~A\",route=\"~A\",code=\"~A\""
                     (prometheus-label (or gateway "")) (prometheus-label (or route "")) code)))
    (bt:with-lock-held (*gateway-metrics-lock*)
      (incf (gethash key *gateway-request-counts* 0)))))

(defvar *gateway-span* nil
  "The OTel span of the request being answered (podster-krg.1), or NIL when tracing is off.")

(defvar *gateway-flow-sink* nil
  "A function given one flow object, as the agent's flow events are, for each request a
Gateway listener answers (podster-e9a.8), or NIL. The agent sets it while it collects.")

(defun gateway-request-flow (acceptor request dispatch backend-host backend-port started)
  "The flow event for REQUEST, answered by ACCEPTOR through DISPATCH, if it matched, to
BACKEND-HOST:BACKEND-PORT, if one was reached, having started at internal time STARTED.
The backend Pod is the flow's Pod and the client its peer. The path keeps no query. The
backend's namespace and Service are recorded too: a host-network backend's address
names its node, not a Pod."
  (let ((flow (core-object "verdict" "FORWARDED" "direction" "ingress" "protocol" "TCP"
                           "peerAddress" (hunchentoot:remote-addr request)
                           "peerPort" (hunchentoot:remote-port request)
                           "l7" (core-object
                                 "type" "http"
                                 "method" (symbol-name (hunchentoot:request-method request))
                                 "host" (or (gateway-request-host request) "")
                                 "path" (hunchentoot:script-name request)
                                 "code" (hunchentoot:return-code*)
                                 "latencyNs" (round (* (- (get-internal-real-time) started) 1000000000)
                                                    internal-time-units-per-second)
                                 ;; Gateways on one port share its listener, so the port
                                 ;; names it; the route names the HTTPRoute.
                                 "listenerPort" (hunchentoot:acceptor-port acceptor)))))
    (when (and dispatch (gw-dispatch-route-key dispatch))
      (setf (gethash "route" (gethash "l7" flow)) (gw-dispatch-route-key dispatch)))
    (when (and *gateway-span* (gr8s.otel:span-sampled-p *gateway-span*))
      (setf (gethash "traceId" (gethash "l7" flow)) (gr8s.otel:span-trace-id *gateway-span*)))
    (let ((backend (and dispatch (gw-dispatch-backend dispatch)))
          (route-key (and dispatch (gw-dispatch-route-key dispatch))))
      (when backend
        (setf (gethash "namespace" flow)
              (or (gw-backend-namespace backend)
                  (and route-key (subseq route-key 0 (position #\/ route-key))))
              (gethash "service" flow) (gw-backend-name backend))))
    (when backend-host
      (setf (gethash "podAddress" flow) backend-host)
      (when (integerp backend-port) (setf (gethash "podPort" flow) backend-port)))
    flow))

(defun gateway-metrics-text ()
  "Render the gateway request counters in Prometheus text format."
  (with-output-to-string (stream)
    (bt:with-lock-held (*gateway-metrics-lock*)
      (when (plusp (hash-table-count *gateway-request-counts*))
        (format stream "# HELP gr8s_gateway_requests_total Gateway HTTP requests by route and code.~%")
        (format stream "# TYPE gr8s_gateway_requests_total counter~%")
        (loop for key being the hash-keys of *gateway-request-counts* using (hash-value count)
              do (format stream "gr8s_gateway_requests_total{~A} ~D~%" key count))))
    (when (gr8s.otel:tracing-enabled-p)
      (write-string (gr8s.otel:otel-metrics-text) stream))))

(defstruct gw-token-bucket (tokens 0d0 :type double-float) (last 0d0 :type double-float))
(defvar *gateway-rate-lock* (bt:make-lock "gr8s gateway rate"))
(defvar *gateway-rate-buckets* (make-hash-table :test 'equal)
  "Route key -> GW-TOKEN-BUCKET.")

(defun gateway-rate-allow-p (key rps)
  "Token-bucket admission for route KEY at RPS/sec (capacity = one second's
   burst). Returns T when a token is available, NIL when the route is throttled."
  (let ((now (/ (get-internal-real-time) (float internal-time-units-per-second 1d0)))
        (capacity (float rps 1d0)))
    (bt:with-lock-held (*gateway-rate-lock*)
      (let* ((bucket (or (gethash key *gateway-rate-buckets*)
                         (setf (gethash key *gateway-rate-buckets*)
                               (make-gw-token-bucket :tokens capacity :last now))))
             (refilled (min capacity
                            (+ (gw-token-bucket-tokens bucket)
                               (* (- now (gw-token-bucket-last bucket)) (float rps 1d0))))))
        (setf (gw-token-bucket-last bucket) now)
        (if (>= refilled 1d0)
            (progn (setf (gw-token-bucket-tokens bucket) (- refilled 1d0)) t)
            (progn (setf (gw-token-bucket-tokens bucket) refilled) nil))))))

;;; ---------------------------------------------------------------------------
;;; HTTP filters (podster-43k.7): header modifiers, redirect, URL rewrite.

(defun gateway-find-filter (filters type)
  "The parsed data plist of the first FILTER of TYPE, or NIL."
  (let ((filter (find type filters :key #'gw-filter-type)))
    (and filter (gw-filter-data filter))))

(defun gateway-apply-header-ops (headers ops)
  "Apply a {:set :add :remove} header modifier to an alist of (name . value).
   remove drops by case-insensitive name; set replaces; add appends."
  (if (null ops)
      headers
      (let ((result headers))
        (dolist (name (getf ops :remove))
          (setf result (remove name result :key #'car :test #'string-equal)))
        (dolist (pair (getf ops :set))
          (setf result (remove (car pair) result :key #'car :test #'string-equal))
          (setf result (append result (list (cons (string-downcase (car pair)) (cdr pair))))))
        (dolist (pair (getf ops :add))
          (setf result (append result (list (cons (string-downcase (car pair)) (cdr pair))))))
        result)))

(defun gateway-join-prefix-rewrite (replacement rest)
  "Join a ReplacePrefixMatch REPLACEMENT with the REST of the path after the
   matched prefix (REST is \"\" or starts with \"/\")."
  (let ((replacement (if (string= replacement "") "/" replacement)))
    (cond ((string= rest "") replacement)
          ((char= #\/ (char replacement (1- (length replacement))))
           (concatenate 'string replacement (subseq rest 1)))
          (t (concatenate 'string replacement rest)))))

(defun gateway-apply-path-modifier (path match path-mod)
  "Rewrite PATH per a filter path modifier. For ReplacePrefixMatch, the matched
   GW-MATCH's path is the prefix that is replaced."
  (cond ((null path-mod) path)
        ((eq (getf path-mod :type) :full) (or (getf path-mod :value) "/"))
        ((eq (getf path-mod :type) :prefix)
         (let* ((prefix (and match (gw-match-path match)))
                (plen (and prefix (length prefix))))
           (if (and prefix (>= (length path) plen) (string= path prefix :end1 plen))
               (gateway-join-prefix-rewrite (or (getf path-mod :value) "/") (subseq path plen))
               path)))
        (t path)))

(defun gateway-apply-redirect (dispatch request)
  "Short-circuit a RequestRedirect filter: emit a 3xx with a computed Location."
  (let* ((data (gateway-find-filter (gw-dispatch-filters dispatch) :redirect))
         (scheme (or (getf data :scheme)
                     (if (hunchentoot:acceptor-ssl-p hunchentoot:*acceptor*) "https" "http")))
         (host (or (getf data :hostname) (gateway-request-host request)))
         (port (getf data :port))
         (authority (if port (format nil "~A:~A" host port) host))
         (path (gateway-apply-path-modifier (hunchentoot:script-name request)
                                            (gw-dispatch-match dispatch) (getf data :path)))
         (query (hunchentoot:query-string request))
         (location (format nil "~A://~A~A~@[?~A~]" scheme authority path
                           (and query (plusp (length query)) query))))
    (setf (hunchentoot:header-out :location) location)
    (gateway-error-response (or (getf data :status-code) 302) "")))

(defun gateway-backend-request-target (dispatch request)
  "The path and query REQUEST is forwarded with, after the matched rule's URL rewrite."
  (let* ((rewrite (gateway-find-filter (gw-dispatch-filters dispatch) :rewrite))
         (path (if rewrite
                   (gateway-apply-path-modifier (hunchentoot:script-name request)
                                                (gw-dispatch-match dispatch) (getf rewrite :path))
                   (hunchentoot:script-name request)))
         (query (hunchentoot:query-string request)))
    (format nil "~A~@[?~A~]" path (and query (plusp (length query)) query))))

(defun gateway-backend-request-headers (dispatch request)
  "REQUEST's end-to-end headers after the rule's request header modifier, led by
   the (possibly rewritten) Host and the X-Forwarded-* the backend sees."
  (let* ((rewrite (gateway-find-filter (gw-dispatch-filters dispatch) :rewrite))
         (orig-host (hunchentoot:header-in* :host))
         (scheme (if (hunchentoot:acceptor-ssl-p hunchentoot:*acceptor*) "https" "http")))
    (append (list (cons "Host" (or (and rewrite (getf rewrite :hostname)) orig-host))
                  ;; The client, after any proxies before this one that said so.
                  (cons "X-Forwarded-For"
                        (format nil "~@[~A, ~]~A" (hunchentoot:header-in* :x-forwarded-for request)
                                (hunchentoot:remote-addr request)))
                  (cons "X-Forwarded-Host" orig-host)
                  (cons "X-Forwarded-Proto" scheme)
                  (cons "X-Forwarded-Uri" (hunchentoot:script-name request)))
            ;; The Gateway is a pass-through proxy: the client's Authorization is meant
            ;; for the backend app (e.g. an S3 server's SigV4 check), so keep it.
            (gateway-trace-headers
             (gateway-apply-header-ops
              (pod-proxy-end-to-end-headers (gateway-request-headers request)
                                            :request t :consume-credential nil)
              (gateway-find-filter (gw-dispatch-filters dispatch) :request-headers))))))

(defun gateway-trace-headers (headers)
  "HEADERS with the trace context the backend continues: the Gateway's span as the
parent, when the request is traced; else HEADERS as they came, a client's traceparent
passing through."
  (if *gateway-span*
      (append (remove-if (lambda (header) (member (car header) '("traceparent" "tracestate") :test #'string-equal))
                         headers)
              (list (cons "traceparent" (gr8s.otel:span-traceparent *gateway-span*)))
              (let ((state (gr8s.otel:span-tracestate *gateway-span*)))
                (and state (list (cons "tracestate" state)))))
      headers))

(defun gateway-start-span (acceptor request dispatch)
  "The SERVER span for REQUEST, joining the client's trace; NIL when tracing is off.
Named, as OTel's HTTP conventions ask, by the method and the route that matched."
  (let ((method (symbol-name (hunchentoot:request-method request)))
        (route (and dispatch (gw-dispatch-route-key dispatch))))
    (gr8s.otel:start-server-span
     (if route (format nil "~A ~A" method route) method)
     :traceparent (hunchentoot:header-in* :traceparent request)
     :tracestate (hunchentoot:header-in* :tracestate request)
     :attributes `(("http.request.method" . ,method)
                   ("url.path" . ,(hunchentoot:script-name request))
                   ("url.scheme" . ,(if (hunchentoot:acceptor-ssl-p acceptor) "https" "http"))
                   ("server.address" . ,(or (gateway-request-host request) ""))
                   ("server.port" . ,(hunchentoot:acceptor-port acceptor))
                   ("client.address" . ,(hunchentoot:remote-addr request))
                   ("user_agent.original" . ,(or (hunchentoot:header-in* :user-agent request) ""))
                   ("gr8s.gateway.listener" . ,(gateway-acceptor-name acceptor))
                   ,@(when route `(("http.route" . ,route) ("gr8s.gateway.route" . ,route)))))))

(defun gateway-end-span (span dispatch backend-host backend-port)
  "Finish SPAN with the reply's status and the backend reached; a 5xx is an error."
  (when span
    (let ((code (hunchentoot:return-code*))
          (backend (and dispatch (gw-dispatch-backend dispatch))))
      (gr8s.otel:span-set-attribute span "http.response.status_code" code)
      (gr8s.otel:span-set-attribute span "network.peer.address" backend-host)
      (gr8s.otel:span-set-attribute span "network.peer.port" (and (integerp backend-port) backend-port))
      (when backend
        (gr8s.otel:span-set-attribute span "k8s.namespace.name" (gw-backend-namespace backend))
        (gr8s.otel:span-set-attribute span "gr8s.backend.service" (gw-backend-name backend)))
      (gr8s.otel:end-span span :error (>= code 500) :message (and (>= code 500) (format nil "HTTP ~D" code))))))

(defun gateway-set-response-head (dispatch code response-headers &key (filter #'pod-proxy-end-to-end-headers))
  "Make the reply carry the backend's CODE and RESPONSE-HEADERS (keyword alist):
   FILTER drops what is not forwarded, then the rule's response header modifier."
  (setf (hunchentoot:return-code*) code (hunchentoot:content-type*) nil)
  (dolist (header (gateway-apply-header-ops
                   (funcall filter (mapcar (lambda (h) (cons (string-downcase (string (car h))) (cdr h)))
                                           response-headers))
                   (gateway-find-filter (gw-dispatch-filters dispatch) :response-headers)))
    (let ((name (intern (string-upcase (car header)) :keyword)))
      (case name
        (:content-length (setf (hunchentoot:header-out name) (parse-integer (cdr header))))
        (:content-type (setf (hunchentoot:header-out name) (cdr header)))
        ;; A browser takes one cookie from each Set-Cookie line, and drakma joined them.
        (:set-cookie (dolist (cookie (pod-proxy-split-set-cookie (cdr header)))
                       (push (cons name cookie)
                             (slot-value hunchentoot:*reply* 'hunchentoot::headers-out))))
        (t (push (cons name (cdr header))
                 (slot-value hunchentoot:*reply* 'hunchentoot::headers-out)))))))

(defun gateway-proxy-exchange (dispatch request target method)
  "Proxy REQUEST to TARGET (\"http://host:port\"), applying the matched rule's
   URL rewrite and request/response header modifiers, and streaming the real
   upstream status, headers and framed body back. Shares header hygiene and body
   copying with the Pod proxy."
  (let ((url (concatenate 'string target (gateway-backend-request-target dispatch request)))
        (headers (gateway-backend-request-headers dispatch request))
        (body (hunchentoot:raw-post-data :force-binary t)))
    (handler-case
        (multiple-value-bind (upstream code response-headers)
            (drakma:http-request url :method method :content body
                                     :content-type (hunchentoot:header-in* :content-type)
                                     :additional-headers headers :proxy nil :redirect nil
                                     :keep-alive nil :close t :user-agent nil :accept nil
                                     :force-binary t :want-stream t :decode-content nil
                                     :preserve-uri t :connection-timeout 10 :verify nil)
          (unwind-protect
               (progn
                 (gateway-set-response-head dispatch code response-headers)
                 (let ((client (hunchentoot:send-headers)))
                   (unless (or (eq method :head) (member code '(204 304)))
                     (pod-proxy-copy-body upstream client response-headers))))
            (when (streamp upstream) (ignore-errors (close upstream)))))
      (error (condition)
        (if hunchentoot::*headers-sent*
            (error condition)
            (gateway-error-response 502 "the gateway backend connection failed: ~A" condition))))))

;;; ---------------------------------------------------------------------------
;;; WebSocket upgrades (podster-1fk). Connection and Upgrade are hop-by-hop, so
;;; the ordinary exchange strips them and a backend sees a plain GET. A WebSocket
;;; handshake instead gets its own backend connection: the handshake is replayed
;;; with its Upgrade intact, and once the backend answers 101 the two connections
;;; are spliced byte for byte, as the Pod proxy relays an upgraded exec stream.

(defvar *gateway-connection-socket* nil
  "The client socket of the connection the current Gateway request arrived on.")

(defparameter +gateway-upgrade-idle-timeout-seconds+ (* 60 60)
  "How long either end of an upgraded connection may stay quiet. A live view that only
   receives sends nothing upstream, Hunchentoot's own read timeout is 20s, and the
   backend's socket would otherwise keep its 10s connect timeout for reads.")

(defmethod hunchentoot:process-connection :around ((acceptor gateway-acceptor) socket)
  (let ((*gateway-connection-socket* socket))
    (call-next-method)))

(defun gateway-websocket-request-p ()
  "True when the current request is a WebSocket handshake. Other upgrade protocols
   (h2c) are not proxied as upgrades, as in Envoy's default."
  (and (upgrade-request-p)
       (find "websocket"
             (uiop:split-string (hunchentoot:header-in* :upgrade) :separator '(#\, #\Space #\Tab))
             :test #'string-equal)))

(defun gateway-upgrade-response-headers (headers)
  "A 101's headers minus body framing; Connection, Upgrade and Sec-WebSocket-* are
   the point of the response, so unlike other hop-by-hop fields they are kept."
  (remove-if (lambda (header) (member (car header) '("content-length" "transfer-encoding")
                                      :test #'string-equal))
             headers))

(defun gateway-upgrade-exchange (dispatch request target method)
  "Replay REQUEST's WebSocket handshake to TARGET (\"http://host:port\") with the
   rule's rewrite and header modifiers. On 101, answer the client with the
   backend's handshake response and relay both directions until either side
   closes; any other answer is returned as an ordinary response."
  (let ((headers (gateway-backend-request-headers dispatch request))
        (socket nil))
    (handler-case
        (multiple-value-bind (connected stream) (proxy-upgrade-backend target)
          (setf socket connected)
          (proxy-write-upgrade-request
           stream method (gateway-backend-request-target dispatch request)
           (cdr (assoc "Host" headers :test #'string-equal))
           (append (rest headers)
                   (list (cons "Connection" "Upgrade")
                         (cons "Upgrade" (hunchentoot:header-in* :upgrade))))
           (or (hunchentoot:raw-post-data :force-binary t) #()))
          (multiple-value-bind (code response-headers)
              (parse-http-response-head (read-http-response-head stream))
            (cond
              ((= code 101)
               (gateway-set-response-head dispatch code response-headers
                                          :filter #'gateway-upgrade-response-headers)
               (let ((client (hunchentoot::start-output 101 nil)))
                 (finish-output client)
                 ;; Both ends may stay quiet as long: the backend's socket was opened with
                 ;; a connect timeout that SBCL also applies to its reads.
                 (dolist (end (list *gateway-connection-socket* socket))
                   (when (typep end 'usocket:stream-usocket)
                     (ignore-errors
                      (setf (sb-impl::fd-stream-timeout (usocket:socket-stream end))
                            (coerce +gateway-upgrade-idle-timeout-seconds+ 'single-float)))))
                 (relay-runtime-stream client stream socket)))
              (t
               (unwind-protect
                    (progn
                      (gateway-set-response-head dispatch code response-headers)
                      (let ((client (hunchentoot:send-headers)))
                        (unless (or (eq method :head) (member code '(204 304)))
                          (pod-proxy-copy-body stream client response-headers))))
                 (ignore-errors (usocket:socket-close socket)))))))
      (error (condition)
        (when socket (ignore-errors (usocket:socket-close socket)))
        (if hunchentoot::*headers-sent*
            (error condition)
            (gateway-error-response 502 "the gateway backend connection failed: ~A" condition))))))

;;; ---------------------------------------------------------------------------
;;; ACME HTTP-01 answers. The cert-manager ACME issuer writes a Challenge; the
;;; node's Gateway view carries it here. A listener answers its token before
;;; route matching only where an HTTPRoute from the Challenge's namespace, with
;;; the solver's parentRefs, could attach and would be the one serving its
;;; dnsName -- the access an upstream http01 gatewayHTTPRoute solver route would
;;; have. No solver Pod or HTTPRoute is needed.

(defparameter +gateway-acme-challenge-prefix+ "/.well-known/acme-challenge/"
  "The RFC 8555 section 8.3 path an ACME server fetches a key authorization from.")

(defvar *gateway-acme-challenges* (make-hash-table)
  "Listener port -> token -> (dnsName . key authorization) for this node's
   pending HTTP-01 Challenges. Replaced whole, never mutated, so listener
   threads read it unlocked.")

(defun gateway-acme-solver-parent-refs (challenge)
  "The parentRefs of the solver CHALLENGE was presented for, as a list."
  (let* ((solver (gethash "solver" (gethash "spec" challenge)))
         (http01 (and (hash-table-p solver) (gethash "http01" solver)))
         (route (and (hash-table-p http01) (gethash "gatewayHTTPRoute" http01)))
         (refs (and (hash-table-p route) (gethash "parentRefs" route))))
    (if (vectorp refs) (coerce refs 'list) '())))

(defun gateway-acme-listener-serves-p (store entry challenge)
  "True when a solver HTTPRoute for CHALLENGE could attach to ENTRY's listener:
   the listener admits routes from the Challenge's namespace and is one of the
   solver's parentRefs. With no parentRefs the route attaches nowhere, and so
   does the answer. Whether ENTRY is the listener that serves the host is the
   caller's question."
  (let* ((listener (gateway-listener-entry-listener entry))
         (owner (gateway-listener-entry-owner entry))
         (owner-metadata (gethash "metadata" owner))
         (namespace (gethash "namespace" (gethash "metadata" challenge))))
    (and (gateway-listener-allows-route-p
          store (core-object "kind" "HTTPRoute" "metadata" (core-object "namespace" namespace))
          (gethash "namespace" owner-metadata) listener)
         (some (lambda (ref)
                 (gateway-parent-matches-p ref namespace
                                           (gethash "namespace" owner-metadata) (gethash "name" owner-metadata)
                                           (gethash "name" listener) (gethash "port" listener)
                                           (or (gethash "kind" owner) "Gateway")
                                           (gateway-listener-owner-group owner)))
               (gateway-acme-solver-parent-refs challenge)))))

(defun gateway-acme-port-indexes (store)
  "Port -> hostname index of the HTTP listener entries on it, in the order the
   listener planner admits them, as the router's HTTP snapshot indexes them, so
   a host selects the listener real requests for it would reach. HTTP-01 is
   plain HTTP, so HTTPS listeners never answer."
  (let ((entries-by-port (make-hash-table))
        (listener-sets (ignore-errors (list-core-resources store "listenersets"))))
    (dolist (gateway (list-core-resources store "gateways"))
      (when (gateway-controlled-p store gateway)
        (dolist (entry (gateway-listener-entries store gateway listener-sets))
          (let ((listener (gateway-listener-entry-listener entry)))
            (when (and (null (gateway-listener-entry-error entry))
                       (equal "HTTP" (gethash "protocol" listener)))
              (push (list (gethash "hostname" listener) entry)
                    (gethash (gethash "port" listener) entries-by-port)))))))
    (let ((indexes (make-hash-table)))
      (maphash (lambda (port entries)
                 (setf (gethash port indexes) (make-gateway-certificate-index (nreverse entries))))
               entries-by-port)
      indexes)))

(defun gateway-acme-challenge-table (store)
  "Index the HTTP-01 Challenges in the Gateway view STORE by the listener
   ports allowed to answer them, then by token. On each port, only the
   listener that wins the Challenge's dnsName, as the router picks it, may
   answer, and only if a solver route could attach to it."
  (let ((table (make-hash-table))
        (challenges (remove-if-not
                     (lambda (challenge)
                       (let ((spec (gethash "spec" challenge)))
                         (and (hash-table-p spec) (equal "HTTP-01" (gethash "type" spec))
                              (every (lambda (field) (stringp (gethash field spec))) '("dnsName" "token" "key")))))
                     (ignore-errors (list-core-resources store "challenges")))))
    (when challenges
      (maphash (lambda (port index)
                 (dolist (challenge challenges)
                   (let* ((spec (gethash "spec" challenge))
                          (winner (gateway-certificate-for-host index (gethash "dnsName" spec))))
                     (when (and winner (gateway-acme-listener-serves-p store winner challenge))
                       (setf (gethash (gethash "token" spec)
                                      (or (gethash port table)
                                          (setf (gethash port table) (make-hash-table :test 'equal))))
                             (cons (gethash "dnsName" spec) (gethash "key" spec)))))))
               (gateway-acme-port-indexes store)))
    table))

(defun gateway-acme-challenge-answer (acceptor request)
  "The key authorization REQUEST asks ACCEPTOR's port for, or NIL when it is
   not a GET for a token this port may answer for the request's host."
  (let ((path (hunchentoot:script-name request))
        (tokens (gethash (hunchentoot:acceptor-port acceptor) *gateway-acme-challenges*)))
    (when (and tokens
               (member (hunchentoot:request-method request) '(:get :head))
               (uiop:string-prefix-p +gateway-acme-challenge-prefix+ path))
      (let ((entry (gethash (subseq path (length +gateway-acme-challenge-prefix+)) tokens))
            (host (gateway-request-host request)))
        (when (and entry host (string-equal host (car entry)))
          (cdr entry))))))

(defmethod hunchentoot:acceptor-dispatch-request :around ((acceptor gateway-acceptor) request)
  (let ((answer (and (plusp (hash-table-count *gateway-acme-challenges*))
                     (gateway-acme-challenge-answer acceptor request))))
    (if answer
        (progn (setf (hunchentoot:return-code*) 200
                     (hunchentoot:content-type*) "text/plain")
               answer)
        (call-next-method))))

(defmethod hunchentoot:acceptor-dispatch-request ((acceptor gateway-acceptor) request)
  (let* ((dispatch (gateway-dispatch-for-request acceptor request))
         (started (get-internal-real-time))
         ;; Tracing is an observation too: a span that can't be made leaves none.
         (*gateway-span* (ignore-errors (gateway-start-span acceptor request dispatch)))
         (backend-host nil) (backend-port nil))
    (prog1
        (cond
          ((null dispatch)
           (gateway-error-response 404 "No route matched for ~A ~A"
                                   (hunchentoot:host request) (hunchentoot:script-name request)))
          ;; Per-route token-bucket rate limit (gr8s.io/rate-limit-rps annotation).
          ((and (gw-dispatch-rate-limit dispatch)
                (not (gateway-rate-allow-p (gw-dispatch-route-key dispatch)
                                           (gw-dispatch-rate-limit dispatch))))
           (gateway-error-response 429 "Too Many Requests for route ~A"
                                   (or (gw-dispatch-route-name dispatch) "")))
          ;; A RequestRedirect filter short-circuits before any backend connect.
          ((gateway-find-filter (gw-dispatch-filters dispatch) :redirect)
           (gateway-apply-redirect dispatch request))
          (t
           (let ((backend (gw-dispatch-backend dispatch)))
             (if (null backend)
                 (gateway-error-response 500 "Matched rule has no backend")
                 (multiple-value-bind (host port invalid-reason) (gateway-resolve-backend acceptor backend)
                   (setf backend-host host backend-port port)
                   (if host
                       (funcall (if (gateway-websocket-request-p) #'gateway-upgrade-exchange #'gateway-proxy-exchange)
                                dispatch request
                                (format nil "http://~A:~A" (if (find #\: host) (format nil "[~A]" host) host) port)
                                (hunchentoot:request-method request))
                       (gateway-error-response (if invalid-reason 500 503) "No reachable backend for ~A"
                                               (gw-backend-name backend))))))))
      (gateway-count-request (gateway-acceptor-name acceptor)
                             (and dispatch (gw-dispatch-route-key dispatch))
                             (hunchentoot:return-code*))
      (let ((sink *gateway-flow-sink*))
        (when sink
          ;; A flow is an observation: failing to make one never fails the request.
          (ignore-errors
           (funcall sink (gateway-request-flow acceptor request dispatch backend-host backend-port started)))))
      (ignore-errors (gateway-end-span *gateway-span* dispatch backend-host backend-port)))))

;;; ---------------------------------------------------------------------------
;;; Backend resolution + listener lifecycle.

(defstruct (gateway-certificate-index (:constructor %make-gateway-certificate-index))
  (exact (fset:empty-ch-map nil))
  (wildcard (fset:empty-ch-map nil))
  default)

(defun gateway-certificate-binding-tables (bindings)
  "Normalize desired bindings in precedence order; the first equal hostname wins."
  (let ((default nil)
        (exact (make-hash-table :test 'equal))
        (wildcards (make-hash-table :test 'equal)))
    (dolist (binding bindings)
      (destructuring-bind (host material) binding
        (if (null host)
            (unless default (setf default material))
            (let* ((wildcard (and (> (length host) 2)
                                  (string= "*." host :end2 2)))
                   (table (if wildcard wildcards exact))
                   (key (string-downcase (if wildcard (subseq host 1) host))))
              (unless (nth-value 1 (gethash key table))
                (setf (gethash key table) material))))))
    (values exact wildcards default)))

(defun make-gateway-certificate-index (bindings)
  "Build a read-only-after-publication index from (HOST MATERIAL) bindings."
  (multiple-value-bind (exact wildcards default) (gateway-certificate-binding-tables bindings)
    (%make-gateway-certificate-index
     :exact (fset:convert 'fset:ch-map exact :default nil)
     :wildcard (fset:convert 'fset:ch-map wildcards :default nil)
     :default default)))

(defun gateway-update-certificate-index (index bindings)
  "Change only differing hostname buckets; retain old reader snapshots."
  (labels ((update-map (old desired)
             (let ((next old))
               (fset:do-map (key binding old)
                 (declare (ignore binding))
                 (unless (nth-value 1 (gethash key desired))
                   (setf next (fset:less next key))))
               (maphash (lambda (key binding)
                          (unless (eq binding (fset:lookup old key))
                            (setf next (fset:with next key binding)))) desired)
               next)))
    (multiple-value-bind (exact wildcards default) (gateway-certificate-binding-tables bindings)
      (let ((next-exact (update-map (gateway-certificate-index-exact index) exact))
            (next-wildcard (update-map (gateway-certificate-index-wildcard index) wildcards)))
        (if (and (eq next-exact (gateway-certificate-index-exact index))
                 (eq next-wildcard (gateway-certificate-index-wildcard index))
                 (eq default (gateway-certificate-index-default index)))
            index
            (%make-gateway-certificate-index
             :exact next-exact :wildcard next-wildcard :default default))))))

(defun gateway-replace-certificate-binding (index hostname binding)
  "Return a new index sharing untouched branches with the published INDEX."
  (let ((next (copy-gateway-certificate-index index)))
    (cond ((null hostname) (setf (gateway-certificate-index-default next) binding))
          ((= 1 (gw-host-tier hostname))
           (setf (gateway-certificate-index-wildcard next)
                 (fset:with (gateway-certificate-index-wildcard index)
                            (string-downcase (subseq hostname 1)) binding)))
          (t (setf (gateway-certificate-index-exact next)
                   (fset:with (gateway-certificate-index-exact index)
                              (string-downcase hostname) binding))))
    next))

(defun gateway-certificate-for-host (index hostname)
  "Select exact, then longest wildcard suffix, then an explicit default.
   No matching listener returns NIL, including absent SNI without a default."
  (or (and hostname
           (let ((host (string-downcase hostname)))
             (or (fset:lookup (gateway-certificate-index-exact index) host)
                 (loop for dot = (position #\. host :start 1)
                         then (position #\. host :start (1+ dot))
                       while dot
                       thereis (fset:lookup (gateway-certificate-index-wildcard index)
                                            (subseq host dot))))))
      (gateway-certificate-index-default index)))

(defclass gateway-tls-acceptor (gateway-acceptor)
  ((certificate :initarg :certificate :initform nil :reader gateway-acceptor-certificate)
   (private-key :initarg :private-key :initform nil :reader gateway-acceptor-private-key)
   (tls-snapshot :initarg :tls-snapshot :initform nil :accessor gateway-acceptor-tls-snapshot))
  (:documentation "A Gateway HTTPS listener that terminates TLS with pure-tls,
   then dispatches the plaintext request exactly like the HTTP acceptor."))

(defmethod hunchentoot:process-connection :around ((acceptor gateway-tls-acceptor) socket)
  ;; One immutable snapshot is retained for the handshake and keep-alive requests.
  (let ((*gateway-connection-tls-snapshot* (gateway-acceptor-tls-snapshot acceptor))
        (*gateway-connection-tls-binding* nil))
    (call-next-method)))

(defmethod hunchentoot:acceptor-ssl-p ((acceptor gateway-tls-acceptor))
  "HTTPS: sets the scheme for X-Forwarded-Proto and redirect defaults."
  t)

(defmethod hunchentoot:initialize-connection-stream ((acceptor gateway-tls-acceptor) stream)
  "Wrap the accepted connection in a server-side TLS stream before Hunchentoot
   reads the request (the same mechanism as the in-cluster API acceptor)."
  (with-tls-handshake-deadline (*tls-handshake-seconds*)
    (let* ((pure-tls:*server-ticket-key* (ironclad:random-data 32))
           (snapshot *gateway-connection-tls-snapshot*)
           (bootstrap (and snapshot (gateway-tls-snapshot-bootstrap snapshot))))
      (pure-tls:make-tls-server-stream stream
                                       :certificate (if bootstrap (gateway-tls-binding-certificate bootstrap)
                                                        (gateway-acceptor-certificate acceptor))
                                       :key (if bootstrap (gateway-tls-binding-key bootstrap)
                                                (gateway-acceptor-private-key acceptor))
                                       :certificate-provider (and snapshot #'gateway-tls-certificate-provider)
                                       :verify pure-tls:+verify-none+))))

(defun gateway-service-port (service reference)
  "Return SERVICE's port named or numbered by REFERENCE."
  (find-if (lambda (port)
             (if (integerp reference)
                 (eql reference (gethash "port" port))
                 (equal reference (gethash "name" port))))
           (gethash "ports" (gethash "spec" service) #())))

(defun gateway-reference-permitted-p (store source-namespace source-kind target-namespace target-kind target-name
                                     &optional (source-group "gateway.networking.k8s.io"))
  "A cross-namespace reference needs matching from/to entries in one target grant."
  (or (equal source-namespace target-namespace)
      (and store
           (some
            (lambda (grant)
              (let ((spec (gethash "spec" grant)))
                (and (some (lambda (entry)
                             (and (equal (gethash "group" entry) source-group)
                                  (equal (gethash "kind" entry) source-kind)
                                  (equal (gethash "namespace" entry) source-namespace)))
                           (gethash "from" spec #()))
                     (some (lambda (entry)
                             (and (equal (gethash "group" entry) "")
                                  (equal (gethash "kind" entry) target-kind)
                                  (or (null (gethash "name" entry))
                                      (equal (gethash "name" entry) target-name))))
                           (gethash "to" spec #())))))
            (list-core-resources store "referencegrants" target-namespace)))))

(defun gateway-backend-reference-error (store backend)
  "Return invalid-reference reason, Service and Service port, without resolving endpoints."
  (when (gw-backend-invalid-reason backend)
    (return-from gateway-backend-reference-error (gw-backend-invalid-reason backend)))
  (when (and (gw-backend-source-namespace backend)
             (not (gateway-reference-permitted-p
                   store (gw-backend-source-namespace backend) (gw-backend-source-kind backend)
                   (gw-backend-namespace backend) "Service" (gw-backend-name backend))))
    (return-from gateway-backend-reference-error "RefNotPermitted"))
  (when store
    (let* ((namespace (or (gw-backend-namespace backend) "default"))
           (service (ignore-errors (get-core-resource store "services" namespace (gw-backend-name backend))))
           (port (and service (gateway-service-port service (gw-backend-port backend)))))
      (values (unless (and service port) "BackendNotFound") service port))))

(defun service-proxy-protocol (service)
  "The PROXY protocol version SERVICE asks its TCPRoute/TLSRoute/GRPCRoute traffic
   to carry, from its gr8s.io/proxy-protocol annotation: 2 for \"v2\", else NIL.
   The backend opts in because one not expecting the header would break."
  (let* ((metadata (and (hash-table-p service) (gethash "metadata" service)))
         (annotations (and (hash-table-p metadata) (gethash "annotations" metadata))))
    (when (and (hash-table-p annotations)
               (equal (gethash "gr8s.io/proxy-protocol" annotations) "v2"))
      2)))

(defun make-service-backend-resolver (store)
  "Resolve a valid Service reference to (values host port), and NIL and the PROXY
   protocol version after them for a Service that asks for one (podster-0gz);
   invalid references carry an HTTP500 reason as the third value."
  (lambda (backend)
    (multiple-value-bind (reason service service-port) (gateway-backend-reference-error store backend)
      (if reason
          (values nil nil reason)
          (let ((endpoints (ignore-errors (service-pod-endpoints store service service-port)))
                (proxy-protocol (service-proxy-protocol service)))
            (if endpoints
                (let ((endpoint (nth (random (length endpoints)) endpoints)))
                  (if proxy-protocol
                      (values (first endpoint) (second endpoint) nil proxy-protocol)
                      (values (first endpoint) (second endpoint))))
                (let ((cluster-ip (gethash "clusterIP" (gethash "spec" service))))
                  (when (and (stringp cluster-ip) (plusp (length cluster-ip))
                             (not (equal cluster-ip "None")))
                    (if proxy-protocol
                        (values cluster-ip (gethash "port" service-port) nil proxy-protocol)
                        (values cluster-ip (gethash "port" service-port)))))))))))

(defun start-gateway-listener (&key (address "127.0.0.1") port router resolver (name "gateway") tls)
  "Start a Gateway listener acceptor on PORT. ROUTER is a compiled dispatch fn
   and RESOLVER maps a chosen GW-BACKEND to (values host port). When TLS is a
   plist (:certificate PATH :key PATH), the listener terminates HTTPS."
  (hunchentoot:start
   (if tls
       (make-instance 'gateway-tls-acceptor
                      :address address :port port
                      :router router :resolver resolver :gateway-name name
                      :tls-snapshot (getf tls :snapshot)
                      :certificate (getf tls :certificate) :private-key (getf tls :key))
       (make-instance 'gateway-acceptor
                      :address address :port port
                      :router router :resolver resolver :gateway-name name))))

(defun stop-gateway-listener (acceptor)
  "Stop the gateway's Hunchentoot ACCEPTOR, ending its listener."
  (hunchentoot:stop acceptor))
