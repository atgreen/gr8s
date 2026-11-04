;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Route authenticated Pod proxy requests to the exact Pod's observed address.
;;;; Forward ordinary HTTP methods, request bytes and real upstream status/body,
;;;; without following backend redirects or inheriting environment HTTP proxies.

(in-package #:gr8s)

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
                (pod-uid pod))))))

(defun pod-proxy-end-to-end-headers (headers &key request)
  "Strip connection-scoped fields and consumed API credentials from forwarded headers."
  (let* ((connection (cdr (assoc "connection" headers :test #'string-equal)))
         (hop (append '("connection" "keep-alive" "proxy-authenticate" "proxy-authorization"
                        "te" "trailer" "transfer-encoding" "upgrade")
                      (when connection (mapcar (lambda (item) (string-trim '(#\Space #\Tab) item))
                                               (uiop:split-string connection :separator ",")))
                      (when (assoc "transfer-encoding" headers :test #'string-equal) '("content-length"))
                      (when request '("host" "authorization" "content-length" "content-type"
                                      "x-forwarded-host" "x-forwarded-uri" "x-forwarded-proto")))))
    (remove-if (lambda (header) (member (car header) hop :test #'string-equal)) headers)))

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

(defun pod-http-proxy-response (store namespace id method)
  "Proxy an ordinary HTTP exchange to the real workload rather than synthesizing result data."
  (unless (member method *pod-proxy-methods*)
    (core-resource-error 405 "MethodNotAllowed" "Unsupported Pod proxy method"))
  (when (hunchentoot:header-in* :upgrade)
    (core-resource-error 501 "NotImplemented" "Pod proxy connection upgrades are not implemented"))
  (admit-pod-proxy store namespace id)
  (let* ((target (pod-proxy-target store namespace id))
         (raw (hunchentoot:request-uri*))
         (question (position #\? raw))
         (raw-path (subseq raw 0 question))
         (end (nth-value 1 (cl-ppcre:scan "^/api/v1/namespaces/[^/]+/pods/[^/]+/proxy(?=/|$)" raw-path)))
         (prefix (subseq raw-path 0 end))
         (suffix (subseq raw-path end))
         (scheme (if (hunchentoot:acceptor-ssl-p hunchentoot:*acceptor*) "https" "http"))
         (host (hunchentoot:header-in* :host))
         (frontend (format nil "~A://~A" scheme host))
         (url (concatenate 'string target (if (equal suffix "") "/" suffix) (if question (subseq raw question) "")))
         (headers (pod-proxy-end-to-end-headers
                   (mapcar (lambda (header) (cons (string-downcase (string (car header))) (cdr header)))
                           (hunchentoot:headers-in*)) :request t))
         (body (hunchentoot:raw-post-data :force-binary t)))
    (setf headers (append (list (cons "Host" host) (cons "X-Forwarded-Host" host)
                               (cons "X-Forwarded-Proto" scheme) (cons "X-Forwarded-Uri" raw-path)) headers))
    (handler-case
        (multiple-value-bind (upstream code response-headers)
            (drakma:http-request url :method method :content body :content-type (hunchentoot:header-in* :content-type)
                                    :additional-headers headers :proxy nil :redirect nil :keep-alive nil :close t
                                    :user-agent nil :accept nil :force-binary t :want-stream t :decode-content nil
                                    :preserve-uri t :connection-timeout 10 :verify nil)
          (unwind-protect
               (progn
                 (setf (hunchentoot:return-code*) code (hunchentoot:content-type*) nil)
                 (dolist (header (pod-proxy-end-to-end-headers
                                  (mapcar (lambda (header) (cons (string-downcase (string (car header))) (cdr header))) response-headers)))
                   (let ((name (intern (string-upcase (car header)) :keyword)))
                     (case name
                       (:content-length (setf (hunchentoot:header-out name) (parse-integer (cdr header))))
                       (:content-type (setf (hunchentoot:header-out name) (cdr header)))
                       (:location (setf (hunchentoot:header-out name)
                                        (pod-proxy-rewrite-location (cdr header) target prefix frontend)))
                       (t (push (cons name (cdr header))
                                (slot-value hunchentoot:*reply* 'hunchentoot::headers-out))))))
                 (let ((client (hunchentoot:send-headers)))
                   (unless (or (eq method :head) (member code '(204 304)))
                     (pod-proxy-copy-body upstream client response-headers))))
            (when (streamp upstream) (ignore-errors (close upstream)))))
      (error (condition)
        (if hunchentoot::*headers-sent*
            (error condition)
            (core-resource-error 503 "ServiceUnavailable" "Pod HTTP connection failed: ~A" condition))))))
