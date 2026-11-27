;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Route authenticated Pod and Service proxy requests to an exact observed address,
;;;; and answer the Node proxy's kubelet reads from the Pods bound to that Node or
;;;; forward them to its kubelet endpoint.
;;;; Forward ordinary HTTP methods, request bytes and real upstream status/body,
;;;; and relay upgraded streams in both directions, without following backend
;;;; redirects or inheriting environment HTTP proxies.

(in-package #:gr8s.apiserver)

(defparameter *pod-proxy-methods* '(:get :post :put :patch :delete :head :options))

(defun pod-proxy-address-p (address)
  "Match Go IP.IsGlobalUnicast for numeric addresses, including IPv4-mapped IPv6."
  (and (stringp address)
       (handler-case
           (let ((bytes (if (find #\: address) (sb-bsd-sockets:make-inet6-address address)
                            (sb-bsd-sockets:make-inet-address address))))
             (when (and (= 16 (length bytes)) (every #'zerop (subseq bytes 0 10))
                        (= 255 (aref bytes 10)) (= 255 (aref bytes 11)))
               (setf bytes (subseq bytes 12)))
             (and (not (every #'zerop bytes))
                  (if (= 4 (length bytes))
                      (and (not (every (lambda (byte) (= byte 255)) bytes))
                           (/= 127 (aref bytes 0)) (not (<= 224 (aref bytes 0) 239))
                           (not (and (= 169 (aref bytes 0)) (= 254 (aref bytes 1)))))
                      (and (not (and (every #'zerop (subseq bytes 0 15)) (= 1 (aref bytes 15))))
                           (/= 255 (aref bytes 0))
                           (not (and (= #xfe (aref bytes 0)) (= #x80 (logand #xc0 (aref bytes 1)))))))))
         (error () nil))))

(defun pod-http-proxy-route (path)
  "Recognize proxy suffixes, preserving empty segments and trailing slashes."
  (multiple-value-bind (match registers)
      (cl-ppcre:scan-to-strings "^/api/v1/namespaces/([^/]+)/pods/([^/]+)/proxy(?=/|$)" path)
    (when (and match (dns-label-p (aref registers 0)))
      (values (aref registers 0) (aref registers 1) t))))

(defun pod-proxy-target (store namespace id)
  "Resolve Kubernetes scheme:name:port syntax from actual UID-keyed Pod observations."
  (let* ((parts (uiop:split-string id :separator ":"))
         (scheme (if (= 3 (length parts)) (first parts) "http"))
         (name (if (= 3 (length parts)) (second parts) (first parts)))
         (port (case (length parts) (2 (second parts)) (3 (third parts)))))
    (unless (and (member (length parts) '(1 2 3)) (dns-subdomain-p name)
                 (member scheme '("http" "https") :test #'equal)
                 (or (null port) (equal port "")
                     (and (every #'digit-char-p port) (<= 1 (parse-integer port) 65535))))
      (core-resource-error 400 "BadRequest" "Invalid Pod proxy target"))
    (with-store-lock (store)
      (let* ((pod (get-pod-unlocked store namespace name))
             (status (gethash (pod-uid pod) (pod-store-pod-observed-statuses store)))
             (address (and status (gethash "podIP" status))))
        (unless (pod-proxy-address-p address)
          (core-resource-error 400 "BadRequest" "Pod proxy address is not allowed"))
        (when (or (null port) (equal port ""))
          (setf port (or (loop for container across (gethash "containers" (gethash "spec" (pod-to-object pod)))
                              for ports = (gethash "ports" container #())
                              when (plusp (length ports)) return (gethash "containerPort" (aref ports 0)))
                         (if (equal scheme "https") 443 80))))
        (values (format nil "~A://~A:~A" scheme
                        (if (find #\: address) (format nil "[~A]" address) address) port)
                (pod-uid pod)
                (pod-node-name pod))))))

(defun pod-proxy-end-to-end-headers (headers &key request (consume-credential t))
  "Strip connection-scoped fields from forwarded HEADERS, and on a REQUEST also the
   hop-managed fields the proxy re-derives (host, content framing, x-forwarded-*).
   CONSUME-CREDENTIAL, true for a proxy that authenticated the client itself (the
   pod proxy, API aggregation — the client's Authorization is the consumed apiserver
   credential and must not leak downstream), also strips Authorization. A pass-through
   proxy like the Gateway passes NIL so the end user's Authorization reaches the
   backend application (e.g. an S3 server validating a SigV4 signature)."
  (let* ((connection (cdr (assoc "connection" headers :test #'string-equal)))
         (hop (append '("connection" "keep-alive" "proxy-authenticate" "proxy-authorization"
                        "te" "trailer" "transfer-encoding" "upgrade")
                      (when connection (mapcar (lambda (item) (string-trim '(#\Space #\Tab) item))
                                               (uiop:split-string connection :separator ",")))
                      (when (assoc "transfer-encoding" headers :test #'string-equal) '("content-length"))
                      (when request '("host" "content-length" "content-type"
                                      "x-forwarded-for" "x-forwarded-host" "x-forwarded-uri" "x-forwarded-proto"))
                      (when (and request consume-credential) '("authorization")))))
    (remove-if (lambda (header) (member (car header) hop :test #'string-equal)) headers)))

(defun pod-proxy-split-set-cookie (value)
  "The cookies in VALUE, a Set-Cookie that drakma joined with commas from several. A
comma begins another cookie only where NAME= follows; Expires dates hold commas too."
  (cl-ppcre:split ",\\s*(?=[^;,=\\s]+=)" value))

(defun pod-proxy-rewrite-location (location target prefix frontend)
  "Keep same-server absolute redirects within the proxy URL; preserve external and relative redirects."
  (let* ((uri (puri:parse-uri location)) (path (or (puri:uri-path uri) "")))
    (labels ((authority-matches-p (other)
               (and (equalp (puri:uri-host uri) (puri:uri-host other))
                    (= (or (puri:uri-port uri) (if (eq (puri:uri-scheme uri) :https) 443 80))
                       (or (puri:uri-port other) (if (eq (puri:uri-scheme other) :https) 443 80))))))
      (if (and (plusp (length path)) (char= #\/ (char path 0))
               (or (null (puri:uri-host uri)) (authority-matches-p (puri:parse-uri target))
                   (authority-matches-p (puri:parse-uri frontend))))
          (format nil "~A~A~@[?~A~]~@[#~A~]" prefix path (puri:uri-query uri) (puri:uri-fragment uri))
          location))))

(defun pod-proxy-copy-body (upstream client headers)
  "Forward real framed bytes, detecting truncated Content-Length responses."
  (let* ((length-text (unless (assoc :transfer-encoding headers) (cdr (assoc :content-length headers))))
         (remaining (and length-text (parse-integer length-text)))
         (wrapped (and (typep upstream 'flexi-streams:flexi-stream) (flexi-streams:flexi-stream-stream upstream)))
         (buffer (make-array 16384 :element-type '(unsigned-byte 8))))
    (when (typep wrapped 'chunga:chunked-input-stream)
      (setf (chunga:chunked-input-stream-eof-after-last-chunk wrapped) t))
    (loop while (or (null remaining) (plusp remaining))
          for count = (read-sequence buffer upstream :end (if remaining (min remaining (length buffer)) (length buffer)))
          do (when (zerop count)
               (when (and remaining (plusp remaining)) (error "Truncated Pod HTTP response"))
               (return))
             (write-sequence buffer client :end count)
             (finish-output client)
             (when remaining (decf remaining count)))))

(defparameter *proxy-html-url-attributes*
  '(("a" "href") ("applet" "codebase") ("area" "href") ("audio" "src") ("base" "href") ("blockquote" "cite")
    ("body" "background") ("button" "formaction") ("command" "icon") ("del" "cite") ("embed" "src")
    ("form" "action") ("frame" "longdesc" "src") ("head" "profile") ("html" "manifest")
    ("iframe" "longdesc" "src") ("img" "longdesc" "src" "usemap") ("input" "src" "usemap" "formaction")
    ("ins" "cite") ("link" "href") ("object" "classid" "codebase" "data" "usemap") ("q" "cite")
    ("script" "src") ("source" "src") ("track" "src") ("video" "poster" "src"))
  "The HTML attributes holding URLs, which a proxied page must keep pointing through the proxy.")

(defun proxy-rewrite-html-url (url target prefix frontend)
  "Point a same-server URL in a proxied page through PREFIX, unless it already goes there."
  (handler-case
      (let ((path (or (puri:uri-path (puri:parse-uri url)) "")))
        (if (uiop:string-prefix-p prefix path)
            url
            (pod-proxy-rewrite-location url target prefix frontend)))
    (error () url)))

(defun proxy-rewrite-html (html target prefix frontend)
  "Rewrite the URL attributes of HTML's tags so a proxied page's links stay inside the proxy."
  (cl-ppcre:regex-replace-all
   "(?i)<([a-z][a-z0-9]*)(\\s[^<>]*)>" html
   (lambda (whole tag attributes)
     (declare (ignore whole))
     (let ((names (cdr (assoc tag *proxy-html-url-attributes* :test #'string-equal))))
       (format nil "<~A~A>" tag
               (if names
                   (cl-ppcre:regex-replace-all
                    "(?i)(\\s)([a-z-]+)(\\s*=\\s*)(\"[^\"]*\"|'[^']*'|[^\\s\"'>]+)" attributes
                    (lambda (whole space name equals value)
                      (declare (ignore whole))
                      (if (member name names :test #'string-equal)
                          (let* ((quoted (find (char value 0) "\"'"))
                                 (bare (if quoted (subseq value 1 (1- (length value))) value))
                                 (rewritten (proxy-rewrite-html-url bare target prefix frontend)))
                            (format nil "~A~A~A~@[~C~]~A~@[~C~]" space name equals quoted rewritten quoted))
                          (format nil "~A~A~A~A" space name equals value)))
                    :simple-calls t)
                   attributes))))
   :simple-calls t))

(defun proxy-backend-connect (target dial)
  "Open TARGET's connection through DIAL, returning the transport and a byte stream
that carries TLS for an https TARGET. A proxied backend's certificate isn't checked,
as Kubernetes doesn't check it."
  (let* ((uri (puri:parse-uri target))
         (https (eq (puri:uri-scheme uri) :https))
         (host (puri:uri-host uri))
         (port (or (puri:uri-port uri) (if https 443 80)))
         (transport (funcall dial host port 10)))
    (handler-case
        (values transport
                (if https
                    (pure-tls:make-tls-client-stream
                     (gr8s.http-client:transport-stream transport) :hostname host
                     :context (pure-tls:make-tls-context :verify-mode pure-tls:+verify-none+
                                                         :auto-load-system-ca nil)
                     :verify pure-tls:+verify-none+)
                    (gr8s.http-client:transport-stream transport))
                (format nil "~A:~D" (if (find #\: host) (format nil "[~A]" host) host) port))
      (error (condition)
        (ignore-errors (gr8s.http-client:close-transport transport))
        (error condition)))))

(defun proxy-http-exchange (target prefix-pattern method &optional dial)
  "Forward the current request to TARGET, through DIAL when given; PREFIX-PATTERN delimits
the API prefix of its URL."
  (let* ((raw (hunchentoot:request-uri*))
         (question (position #\? raw))
         (raw-path (subseq raw 0 question))
         (end (nth-value 1 (cl-ppcre:scan prefix-pattern raw-path)))
         (prefix (subseq raw-path 0 end))
         (suffix (subseq raw-path end))
         (scheme (if (hunchentoot:acceptor-ssl-p hunchentoot:*acceptor*) "https" "http"))
         (host (hunchentoot:header-in* :host))
         (frontend (format nil "~A://~A" scheme host))
         (url (concatenate 'string target (if (equal suffix "") "/" suffix) (if question (subseq raw question) "")))
         (headers (pod-proxy-end-to-end-headers
                   (mapcar (lambda (header) (cons (string-downcase (string (car header))) (cdr header)))
                           (hunchentoot:headers-in*)) :request t))
         (body (hunchentoot:raw-post-data :force-binary t))
         (dialled nil))
    ;; A page's relative links need the trailing slash, so a read is sent back for it.
    (when (and (equal suffix "") (member method '(:get :head)))
      (setf (hunchentoot:header-out :location)
            (concatenate 'string raw-path "/" (if question (subseq raw question) ""))
            (hunchentoot:return-code*) 301)
      (return-from proxy-http-exchange ""))
    (setf headers (append (list (cons "Host" host) (cons "X-Forwarded-Host" host)
                               (cons "X-Forwarded-Proto" scheme) (cons "X-Forwarded-Uri" raw-path)) headers))
    (handler-case
        (multiple-value-bind (upstream code response-headers)
            (drakma:http-request url :method method :content body :content-type (hunchentoot:header-in* :content-type)
                                    :additional-headers headers :proxy nil :redirect nil :keep-alive nil :close t
                                    :user-agent nil :accept nil :force-binary t :want-stream t :decode-content nil
                                    :preserve-uri t :connection-timeout 10 :verify nil
                                    ;; Drakma takes a given stream as connected, framed as it frames its own.
                                    :stream (when dial
                                              (setf dialled (nth-value 1 (proxy-backend-connect target dial)))
                                              (flexi-streams:make-flexi-stream
                                               (chunga:make-chunked-stream dialled) :external-format :latin-1)))
          (unwind-protect
               (let* ((end-to-end (pod-proxy-end-to-end-headers
                                   (mapcar (lambda (header) (cons (string-downcase (string (car header))) (cdr header))) response-headers)))
                      (html (and (not (assoc "content-encoding" end-to-end :test #'string-equal))
                                 (uiop:string-prefix-p "text/html" (string-downcase (or (cdr (assoc "content-type" end-to-end :test #'string-equal)) "")))
                                 (not (eq method :head)) (not (member code '(204 304)))))
                      (page (when html
                              (let ((collected (flexi-streams:with-output-to-sequence (out)
                                                 (pod-proxy-copy-body upstream out response-headers))))
                                ;; Latin-1 keeps every byte intact whatever charset the page is in.
                                (flexi-streams:string-to-octets
                                 (proxy-rewrite-html (flexi-streams:octets-to-string collected :external-format :latin-1)
                                                     target prefix frontend)
                                 :external-format :latin-1)))))
                 (setf (hunchentoot:return-code*) code (hunchentoot:content-type*) nil)
                 (dolist (header end-to-end)
                   (let ((name (intern (string-upcase (car header)) :keyword)))
                     (case name
                       (:content-length (setf (hunchentoot:header-out name) (if page (length page) (parse-integer (cdr header)))))
                       (:content-type (setf (hunchentoot:header-out name) (cdr header)))
                       (:location (setf (hunchentoot:header-out name)
                                        (pod-proxy-rewrite-location (cdr header) target prefix frontend)))
                       ;; A browser takes one cookie from each Set-Cookie line.
                       (:set-cookie (dolist (cookie (pod-proxy-split-set-cookie (cdr header)))
                                      (push (cons name cookie)
                                            (slot-value hunchentoot:*reply* 'hunchentoot::headers-out))))
                       (t (push (cons name (cdr header))
                                (slot-value hunchentoot:*reply* 'hunchentoot::headers-out))))))
                 (when (and page (not (hunchentoot:header-out :content-length)))
                   (setf (hunchentoot:header-out :content-length) (length page)))
                 (let ((client (hunchentoot:send-headers)))
                   (if page
                       (write-sequence page client)
                       (unless (or (eq method :head) (member code '(204 304)))
                         (pod-proxy-copy-body upstream client response-headers)))))
            (when (streamp upstream) (ignore-errors (close upstream)))
            (when dialled (ignore-errors (close dialled)))))
      (error (condition)
        (when dialled (ignore-errors (close dialled)))
        (if hunchentoot::*headers-sent*
            (error condition)
            (core-resource-error 503 "ServiceUnavailable" "Proxied HTTP connection failed: ~A" condition))))))

(defun proxy-upgrade-request-headers (host raw-path)
  "Return the client headers for an upgraded backend request without leaking API credentials."
  (let ((headers
          (remove-if
           (lambda (header)
             (member (car header)
                     '("host" "authorization" "proxy-authorization" "content-length"
                       "x-forwarded-host" "x-forwarded-uri" "x-forwarded-proto")
                     :test #'string-equal))
           (mapcar (lambda (header)
                     (cons (string-downcase (string (car header))) (cdr header)))
                   (hunchentoot:headers-in*)))))
    (append (list (cons "Host" host)
                  (cons "X-Forwarded-Host" host)
                  (cons "X-Forwarded-Uri" raw-path)
                  (cons "X-Forwarded-Proto"
                        (if (hunchentoot:acceptor-ssl-p hunchentoot:*acceptor*) "https" "http")))
            headers)))

(defun proxy-write-upgrade-request (stream method target host headers body)
  "Write the current upgrade request to a resolved backend STREAM."
  (write-sequence
   (trivial-utf-8:string-to-utf-8-bytes
    (with-output-to-string (output)
      (format output "~A ~A HTTP/1.1~C~CHost: ~A~C~C"
              (string-upcase method) target #\Return #\Linefeed host #\Return #\Linefeed)
      (dolist (header headers)
        (unless (string-equal "host" (car header))
          (format output "~A: ~A~C~C" (car header) (cdr header) #\Return #\Linefeed)))
      (when (plusp (length body))
        (format output "Content-Length: ~D~C~C" (length body) #\Return #\Linefeed))
      (format output "~C~C" #\Return #\Linefeed)))
   stream)
  (when (plusp (length body)) (write-sequence body stream))
  (finish-output stream))

(defun proxy-upgrade-backend (target &optional dial)
  "Connect to TARGET, through DIAL when given, and return its transport and HTTP or HTTPS byte stream."
  (when dial
    (return-from proxy-upgrade-backend (proxy-backend-connect target dial)))
  (let* ((uri (puri:parse-uri target))
         (scheme (puri:uri-scheme uri))
         (host (puri:uri-host uri))
         (port (or (puri:uri-port uri) (if (eq scheme :https) 443 80)))
         (socket (usocket:socket-connect host port :element-type '(unsigned-byte 8)
                                                   :timeout 10 :nodelay t)))
    (values socket
            (if (eq scheme :https)
                (pure-tls:make-tls-client-stream
                 (usocket:socket-stream socket) :hostname host
                 :context (pure-tls:make-tls-context :verify-mode pure-tls:+verify-none+
                                                     :auto-load-system-ca nil)
                 :verify pure-tls:+verify-none+)
                (usocket:socket-stream socket))
            (format nil "~A:~D" (if (find #\: host) (format nil "[~A]" host) host) port))))

(defun proxy-upgrade-exchange (target prefix-pattern method &optional dial)
  "Forward an HTTP Upgrade handshake to TARGET, through DIAL when given, and relay its byte
stream in both directions."
  (let* ((raw (hunchentoot:request-uri*))
         (question (position #\? raw))
         (raw-path (subseq raw 0 question))
         (end (nth-value 1 (cl-ppcre:scan prefix-pattern raw-path)))
         (suffix (subseq raw-path end))
         (backend-path (concatenate 'string (if (equal suffix "") "/" suffix)
                                    (if question (subseq raw question) "")))
         (body (or (hunchentoot:raw-post-data :force-binary t) #()))
         (socket nil))
    (handler-case
        (multiple-value-bind (connected stream authority) (proxy-upgrade-backend target dial)
          (setf socket connected)
          (proxy-write-upgrade-request
           stream method backend-path authority
           (proxy-upgrade-request-headers (hunchentoot:header-in* :host) raw-path) body)
          (multiple-value-bind (status headers)
              (parse-http-response-head (read-http-response-head stream))
            (unless (= status 101)
              (error "backend refused the connection upgrade with HTTP ~D" status))
            (setf (hunchentoot:return-code*) 101 (hunchentoot:content-type*) nil)
            (dolist (header headers)
              (unless (member (car header) '(:content-length :transfer-encoding))
                (push header (slot-value hunchentoot:*reply* 'hunchentoot::headers-out))))
            (let ((client (hunchentoot::start-output 101 nil)))
              (finish-output client)
              (extend-api-connection-idle-timeout)
              (relay-runtime-stream client stream socket))))
      (error (condition)
        (when socket (ignore-errors (gr8s.http-client:close-transport socket)))
        (if hunchentoot::*headers-sent*
            (error condition)
            (core-resource-error 503 "ServiceUnavailable"
                                 "Proxied connection upgrade failed: ~A" condition))))))

(defun pod-http-proxy-response (store namespace id method)
  "Proxy an ordinary HTTP exchange to the real workload rather than synthesizing result data."
  (unless (member method *pod-proxy-methods*)
    (core-resource-error 405 "MethodNotAllowed" "Unsupported Pod proxy method"))
  (admit-pod-proxy store namespace id)
  (multiple-value-bind (target uid node) (pod-proxy-target store namespace id)
    (declare (ignore uid))
    (let ((prefix "^/api/v1/namespaces/[^/]+/pods/[^/]+/proxy(?=/|$)")
          (dial (pod-network-dial node)))
      ;; The exchange takes as long as the workload behind it; the store's part is done.
      (gr8s.store::release-store-request)
      (if (upgrade-request-p)
          (proxy-upgrade-exchange target prefix method dial)
          (proxy-http-exchange target prefix method dial)))))

;;; Service proxy

(defun service-http-proxy-route (path)
  "Recognize a Service proxy URL, returning its namespace and [scheme:]name[:port] identity."
  (multiple-value-bind (match registers)
      (cl-ppcre:scan-to-strings "^/api/v1/namespaces/([^/]+)/services/([^/]+)/proxy(?=/|$)" path)
    (when (and match (dns-label-p (aref registers 0)))
      (values (aref registers 0) (aref registers 1) t))))

(defun service-proxy-target (store namespace id)
  "Resolve [scheme:]name[:port] to a URL prefix on one ready endpoint of that Service's port."
  (let* ((parts (uiop:split-string id :separator ":"))
         (scheme (if (= 3 (length parts)) (first parts) "http"))
         (name (if (= 3 (length parts)) (second parts) (first parts)))
         (port-text (case (length parts) (2 (second parts)) (3 (third parts)) (t ""))))
    (unless (and (member (length parts) '(1 2 3)) (dns-label-p name)
                 (member scheme '("http" "https") :test #'equal))
      (core-resource-error 400 "BadRequest" "Invalid Service proxy target"))
    (let* ((service (get-core-resource store "services" namespace name))
           (ports (gethash "ports" (gethash "spec" service) #()))
           (number (and (plusp (length port-text)) (every #'digit-char-p port-text) (parse-integer port-text)))
           (port (find-if (lambda (candidate)
                            (if number
                                (eql number (gethash "port" candidate))
                                (equal port-text (gethash "name" candidate ""))))
                          ports)))
      (when (service-external-name-p service)
        (core-resource-error 503 "ServiceUnavailable" "ExternalName Service ~S has no endpoints to proxy to" name))
      (unless port
        (core-resource-error 503 "ServiceUnavailable" "no service port ~S found for service ~S" port-text name))
      (let ((endpoints (service-pod-endpoints store service port)))
        (unless endpoints
          (core-resource-error 503 "ServiceUnavailable" "no endpoints available for service ~S" name))
        (destructuring-bind (address target) (nth (random (length endpoints)) endpoints)
          (values (format nil "~A://~A:~A" scheme address target)
                  address))))))

(defun service-http-proxy-response (store namespace id method)
  "Proxy an ordinary HTTP exchange to one ready backend of a Service port."
  (unless (member method *pod-proxy-methods*)
    (core-resource-error 405 "MethodNotAllowed" "Unsupported Service proxy method"))
  (multiple-value-bind (target address) (service-proxy-target store namespace id)
    (let ((prefix "^/api/v1/namespaces/[^/]+/services/[^/]+/proxy(?=/|$)")
          (dial (pod-network-dial nil store address)))
      (gr8s.store::release-store-request)
      (if (upgrade-request-p)
          (proxy-upgrade-exchange target prefix method dial)
          (proxy-http-exchange target prefix method dial)))))

;;; Node proxy

(defun node-http-proxy-route (path)
  "Recognize a Node proxy URL, returning the Node's name, its optional port, and the path beneath it."
  (multiple-value-bind (match registers)
      (cl-ppcre:scan-to-strings "^/api/v1/nodes/([^/:]+)(?::([0-9a-z-]*))?/proxy(/.*)?$" path)
    (when (and match (dns-subdomain-p (aref registers 0)))
      (values (aref registers 0) (aref registers 1) (or (aref registers 2) "/") t))))

(defun node-http-proxy-response (store reconciler name suffix method &optional port)
  "Answer the kubelet reads clients make through the Node proxy. The Pod list and health come from
the control plane's own view; anything else goes to the node's kubelet endpoint, on PORT if given."
  (unless (with-store-lock (store) (gethash name (pod-store-nodes store)))
    (core-resource-error 404 "NotFound" "Node ~A was not found" name))
  (unless (member method '(:get :head))
    (core-resource-error 405 "MethodNotAllowed" "The Node proxy serves only kubelet reads"))
  (cond
    ((equal suffix "/pods")
     (json-response
      (json-object "apiVersion" "v1" "kind" "PodList" "metadata" (json-object)
                   "items" (coerce (loop for pod in (list-pods store nil)
                                         for object = (and (equal name (pod-node-name pod))
                                                           (pod-list-observed-object store reconciler pod))
                                         when object collect object)
                                   'vector))))
    ((member suffix '("/healthz" "/healthz/ping") :test #'equal)
     (setf (hunchentoot:content-type*) "text/plain")
     "ok")
    ((node-kubelet-endpoint store name)
     (kubelet-proxy-response store name port suffix method))
    (t (core-resource-error 404 "NotFound" "The Node proxy does not serve ~A" suffix))))
