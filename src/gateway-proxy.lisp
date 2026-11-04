;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; The in-agent Lisp L7 proxy for the Gateway API data plane (podster-43k.4).
;;;; A Gateway listener is a Hunchentoot acceptor that terminates HTTP, dispatches
;;;; each request through the JIT-compiled router (gateway-router.lisp) to pick a
;;;; backend, resolves that backend to an address, and proxies the exchange to it
;;;; -- no Envoy, no sidecar. The compiled router is swappable so a route change
;;;; recompiles and hot-swaps without dropping the listener. Request/response
;;;; header hygiene and framed body copying are shared with the Pod proxy.

(in-package #:gr8s)

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
  (let ((router (gateway-acceptor-router acceptor)))
    (when router
      (funcall router
               (or (gateway-request-host request) "")
               (hunchentoot:script-name request)
               (string (hunchentoot:request-method request))
               (gateway-request-headers request)))))

(defun gateway-resolve-backend (acceptor backend)
  "Resolve BACKEND to (values host port) via the listener's resolver, or NIL."
  (let ((resolver (gateway-acceptor-resolver acceptor)))
    (when resolver (funcall resolver backend))))

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
  (let ((key (format nil "gateway=\"~A\",route=\"~A\",code=\"~A\""
                     (prometheus-label (or gateway "")) (prometheus-label (or route "")) code)))
    (bt:with-lock-held (*gateway-metrics-lock*)
      (incf (gethash key *gateway-request-counts* 0)))))

(defun gateway-metrics-text ()
  "Render the gateway request counters in Prometheus text format."
  (with-output-to-string (stream)
    (bt:with-lock-held (*gateway-metrics-lock*)
      (when (plusp (hash-table-count *gateway-request-counts*))
        (format stream "# HELP gr8s_gateway_requests_total Gateway HTTP requests by route and code.~%")
        (format stream "# TYPE gr8s_gateway_requests_total counter~%")
        (loop for key being the hash-keys of *gateway-request-counts* using (hash-value count)
              do (format stream "gr8s_gateway_requests_total{~A} ~D~%" key count))))))

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

(defun gateway-proxy-exchange (dispatch request target method)
  "Proxy REQUEST to TARGET (\"http://host:port\"), applying the matched rule's
   URL rewrite and request/response header modifiers, and streaming the real
   upstream status, headers and framed body back. Shares header hygiene and body
   copying with the Pod proxy."
  (let* ((rewrite (gateway-find-filter (gw-dispatch-filters dispatch) :rewrite))
         (req-ops (gateway-find-filter (gw-dispatch-filters dispatch) :request-headers))
         (resp-ops (gateway-find-filter (gw-dispatch-filters dispatch) :response-headers))
         (path (if rewrite
                   (gateway-apply-path-modifier (hunchentoot:script-name request)
                                                (gw-dispatch-match dispatch) (getf rewrite :path))
                   (hunchentoot:script-name request)))
         (query (hunchentoot:query-string request))
         (url (format nil "~A~A~@[?~A~]" target path (and query (plusp (length query)) query)))
         (orig-host (hunchentoot:header-in* :host))
         (host (or (and rewrite (getf rewrite :hostname)) orig-host))
         (scheme (if (hunchentoot:acceptor-ssl-p hunchentoot:*acceptor*) "https" "http"))
         (headers (gateway-apply-header-ops
                   (pod-proxy-end-to-end-headers (gateway-request-headers request) :request t)
                   req-ops))
         (body (hunchentoot:raw-post-data :force-binary t)))
    (setf headers (append (list (cons "Host" host) (cons "X-Forwarded-Host" orig-host)
                                (cons "X-Forwarded-Proto" scheme)
                                (cons "X-Forwarded-Uri" (hunchentoot:script-name request)))
                          headers))
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
                 (setf (hunchentoot:return-code*) code (hunchentoot:content-type*) nil)
                 (dolist (header (gateway-apply-header-ops
                                  (pod-proxy-end-to-end-headers
                                   (mapcar (lambda (h) (cons (string-downcase (string (car h))) (cdr h)))
                                           response-headers))
                                  resp-ops))
                   (let ((name (intern (string-upcase (car header)) :keyword)))
                     (case name
                       (:content-length (setf (hunchentoot:header-out name) (parse-integer (cdr header))))
                       (:content-type (setf (hunchentoot:header-out name) (cdr header)))
                       (t (push (cons name (cdr header))
                                (slot-value hunchentoot:*reply* 'hunchentoot::headers-out))))))
                 (let ((client (hunchentoot:send-headers)))
                   (unless (or (eq method :head) (member code '(204 304)))
                     (pod-proxy-copy-body upstream client response-headers))))
            (when (streamp upstream) (ignore-errors (close upstream)))))
      (error (condition)
        (if hunchentoot::*headers-sent*
            (error condition)
            (gateway-error-response 502 "the gateway backend connection failed: ~A" condition))))))

(defmethod hunchentoot:acceptor-dispatch-request ((acceptor gateway-acceptor) request)
  (let ((dispatch (gateway-dispatch-for-request acceptor request)))
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
                 (multiple-value-bind (host port) (gateway-resolve-backend acceptor backend)
                   (if host
                       (gateway-proxy-exchange
                        dispatch request
                        (format nil "http://~A:~A" (if (find #\: host) (format nil "[~A]" host) host) port)
                        (hunchentoot:request-method request))
                       (gateway-error-response 503 "No reachable backend for ~A"
                                               (gw-backend-name backend))))))))
      (gateway-count-request (gateway-acceptor-name acceptor)
                             (and dispatch (gw-dispatch-route-key dispatch))
                             (hunchentoot:return-code*)))))

;;; ---------------------------------------------------------------------------
;;; Backend resolution + listener lifecycle.

(defun make-service-backend-resolver (store)
  "A resolver mapping a GW-BACKEND (a Service reference) to an address. It
   prefers a randomly chosen ready Pod endpoint (direct dial, independent of the
   service-LB cgroup interception), and falls back to the Service ClusterIP (which
   the socket/eBPF service LB then spreads) when no endpoint is resolvable."
  (lambda (backend)
    (let* ((namespace (or (gw-backend-namespace backend) "default"))
           (service (ignore-errors (get-core-resource store "services" namespace
                                                       (gw-backend-name backend)))))
      (when service
        (let ((endpoints (ignore-errors
                          (service-pod-endpoints store service (gw-backend-port backend)))))
          (if endpoints
              (let ((endpoint (nth (random (length endpoints)) endpoints)))
                (values (first endpoint) (second endpoint)))
              (let ((cluster-ip (gethash "clusterIP" (gethash "spec" service))))
                (when (and (stringp cluster-ip) (plusp (length cluster-ip))
                           (not (equal cluster-ip "None")))
                  (values cluster-ip (gw-backend-port backend))))))))))

(defun start-gateway-listener (&key (address "127.0.0.1") port router resolver (name "gateway"))
  "Start a Gateway listener acceptor on PORT. ROUTER is a compiled dispatch fn
   and RESOLVER maps a chosen GW-BACKEND to (values host port)."
  (hunchentoot:start
   (make-instance 'gateway-acceptor
                  :address address :port port
                  :router router :resolver resolver :gateway-name name)))

(defun stop-gateway-listener (acceptor)
  (hunchentoot:stop acceptor))
