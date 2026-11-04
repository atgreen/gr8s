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

(defun gateway-select-backend (acceptor request)
  "Run the listener's compiled router against REQUEST. Returns a GW-BACKEND or NIL."
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

(defun gateway-proxy-exchange (target method)
  "Proxy the current Hunchentoot request to TARGET (a \"http://host:port\" URL),
   streaming the real upstream status, headers and framed body back to the
   client. Shares header hygiene and body copying with the Pod proxy."
  (let* ((raw (hunchentoot:request-uri*))
         (url (concatenate 'string target raw))
         (host (hunchentoot:header-in* :host))
         (scheme (if (hunchentoot:acceptor-ssl-p hunchentoot:*acceptor*) "https" "http"))
         (headers (pod-proxy-end-to-end-headers (gateway-request-headers hunchentoot:*request*)
                                                :request t))
         (body (hunchentoot:raw-post-data :force-binary t)))
    (setf headers (append (list (cons "Host" host) (cons "X-Forwarded-Host" host)
                                (cons "X-Forwarded-Proto" scheme)
                                (cons "X-Forwarded-Uri" (hunchentoot:script-name*)))
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
                 (dolist (header (pod-proxy-end-to-end-headers
                                  (mapcar (lambda (h) (cons (string-downcase (string (car h))) (cdr h)))
                                          response-headers)))
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

(defun gateway-error-response (code fmt &rest args)
  "Emit a minimal text error unless the response has already been committed."
  (setf (hunchentoot:return-code*) code
        (hunchentoot:content-type*) "text/plain; charset=utf-8")
  (apply #'format nil fmt args))

(defmethod hunchentoot:acceptor-dispatch-request ((acceptor gateway-acceptor) request)
  (let ((backend (gateway-select-backend acceptor request)))
    (cond
      ((null backend)
       (gateway-error-response 404 "No route matched for ~A ~A"
                               (hunchentoot:host request) (hunchentoot:script-name request)))
      (t
       (multiple-value-bind (host port) (gateway-resolve-backend acceptor backend)
         (if host
             (gateway-proxy-exchange
              (format nil "http://~A:~A"
                      (if (find #\: host) (format nil "[~A]" host) host) port)
              (hunchentoot:request-method request))
             (gateway-error-response 503 "No reachable backend for ~A"
                                     (gw-backend-name backend))))))))

;;; ---------------------------------------------------------------------------
;;; Backend resolution + listener lifecycle.

(defun make-service-backend-resolver (store)
  "A resolver that maps a GW-BACKEND (a Service reference) to its ClusterIP and
   the backendRef port. The eBPF/socket service LB then spreads the ClusterIP
   across ready Pod endpoints (podster-43k.7 refines this to direct endpoints)."
  (lambda (backend)
    (let* ((namespace (or (gw-backend-namespace backend) "default"))
           (service (ignore-errors (get-core-resource store "services" namespace
                                                       (gw-backend-name backend)))))
      (when service
        (let ((cluster-ip (gethash "clusterIP" (gethash "spec" service))))
          (when (and (stringp cluster-ip) (plusp (length cluster-ip))
                     (not (equal cluster-ip "None")))
            (values cluster-ip (gw-backend-port backend))))))))

(defun start-gateway-listener (&key (address "127.0.0.1") port router resolver (name "gateway"))
  "Start a Gateway listener acceptor on PORT. ROUTER is a compiled dispatch fn
   and RESOLVER maps a chosen GW-BACKEND to (values host port)."
  (hunchentoot:start
   (make-instance 'gateway-acceptor
                  :address address :port port
                  :router router :resolver resolver :gateway-name name)))

(defun stop-gateway-listener (acceptor)
  (hunchentoot:stop acceptor))
