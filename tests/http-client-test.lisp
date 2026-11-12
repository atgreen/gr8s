;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Tests for the shared outbound HTTP client, focused on the connection pool:
;;;; the pool key never crosses a trust or endpoint boundary (the security
;;;; invariant), the checkout/checkin/eviction mechanics, and real keep-alive
;;;; reuse over a local TLS server.

(in-package #:gr8s/tests)

(in-suite gr8s)

;;; ---------------------------------------------------------------------------
;;; Pool key: identical inputs pool together; any trust/endpoint/identity
;;; difference must produce a distinct key.

(defun http-client-test-cert (der-octets)
  "A stand-in x509 certificate carrying only the DER the trust fingerprint hashes."
  (pure-tls::make-x509-certificate
   :raw-der (make-array (length der-octets) :element-type '(unsigned-byte 8)
                        :initial-contents der-octets)))

(test http-client-pool-key-never-crosses-a-trust-or-endpoint-boundary
  (flet ((key (&key (host "h") (port 443) (name "s") insecure (certs (list (http-client-test-cert '(1 2 3))))
                    auto-system cert key-path)
           (gr8s.http-client::connection-key host port name insecure certs auto-system cert key-path)))
    (let ((base (key)))
      ;; Identical inputs share a key, so the connection can be reused.
      (is (equal base (key)))
      ;; Every trust-relevant difference partitions the pool.
      (is (not (equal base (key :certs (list (http-client-test-cert '(9 9 9)))))))
      (is (not (equal base (key :host "other"))))
      (is (not (equal base (key :port 8443))))
      (is (not (equal base (key :name "other"))))
      (is (not (equal base (key :insecure t))))
      (is (not (equal base (key :cert #p"/tmp/client.crt" :key-path #p"/tmp/client.key"))))
      ;; Insecure and system-root trust are distinct buckets from pinned certs and
      ;; from each other.
      (is (not (equal (key :insecure t :certs nil)
                      (key :certs nil :auto-system t)))))))

;;; ---------------------------------------------------------------------------
;;; Pool mechanics with fake connections (no sockets): checkin/checkout, key
;;; isolation, idle-timeout eviction, and the per-key idle cap.

(defun http-client-test-connection (key)
  (gr8s.http-client::%make-pooled-connection :socket :fake :stream :fake :key key))

(test http-client-pool-checkin-checkout-isolation-and-eviction
  (let ((gr8s.http-client::*connection-pool* (make-hash-table :test 'equal))
        (gr8s.http-client::*idle-timeout-seconds* 90)
        (gr8s.http-client::*max-idle-per-key* 8)
        (key '("h" 443 "s" nil nil nil :system))
        (other '("h" 443 "other" nil nil nil :system)))
    (let ((conn (http-client-test-connection key)))
      ;; Checked-in connection comes back out; the pool is then empty.
      (gr8s.http-client::pool-checkin conn)
      (is (eq conn (gr8s.http-client::pool-checkout key)))
      (is (null (gr8s.http-client::pool-checkout key)))
      ;; A different key never yields it.
      (gr8s.http-client::pool-checkin conn)
      (is (null (gr8s.http-client::pool-checkout other)))
      (is (eq conn (gr8s.http-client::pool-checkout key))))
    ;; An idle connection past the timeout is discarded, not handed back.
    (let ((gr8s.http-client::*idle-timeout-seconds* 0))
      (gr8s.http-client::pool-checkin (http-client-test-connection key))
      (is (null (gr8s.http-client::pool-checkout key))))
    ;; The pool keeps at most *max-idle-per-key* per key.
    (let ((gr8s.http-client::*max-idle-per-key* 2))
      (dotimes (i 3) (gr8s.http-client::pool-checkin (http-client-test-connection key)))
      (is (gr8s.http-client::pool-checkout key))
      (is (gr8s.http-client::pool-checkout key))
      (is (null (gr8s.http-client::pool-checkout key))))))

;;; ---------------------------------------------------------------------------
;;; End-to-end reuse over a local keep-alive TLS server.  The client runs
;;; INSECURE (verification is exercised by the key tests above and the webhook
;;; suite), so the server needs only a self-signed certificate.

(defun http-client-test-self-signed (directory)
  "Write a self-signed EC certificate and key into DIRECTORY; return their paths."
  (multiple-value-bind (private public) (ironclad:generate-key-pair :secp256r1)
    (let ((cert (merge-pathnames "server.crt" directory))
          (key (merge-pathnames "server.key" directory)))
      (gr8s.security::write-private-text-exclusively key (pure-tls/acme::encode-ec-private-key-pem private))
      (gr8s.security::write-public-text-exclusively
       cert
       (pure-tls/acme::wrap-pem
        "CERTIFICATE"
        (gr8s.security::certificate-der
         (pure-tls/acme::encode-subject "localhost")
         (pure-tls/acme::encode-subject "localhost")
         (pure-tls/acme::encode-ec-public-key public)
         nil
         private)))
      (values (namestring cert) (namestring key)))))

(defun http-client-test-read-request-head (stream)
  "Read a request line + headers from STREAM (bytes), returning the lowercase-keyed
header alist and swallowing any Content-Length body."
  (let ((lines (loop for line = (gr8s.apiserver::admission-read-line stream)
                     until (zerop (length line)) collect line)))
    (let ((headers (loop for line in (rest lines)
                         for colon = (position #\: line)
                         when colon
                           collect (cons (string-downcase (subseq line 0 colon))
                                         (string-trim '(#\Space) (subseq line (1+ colon)))))))
      (let ((length (cdr (assoc "content-length" headers :test #'string=))))
        (when (and length (plusp (parse-integer length)))
          (gr8s.apiserver::admission-read-exactly stream (parse-integer length))))
      headers)))

(defun http-client-test-keepalive-backend (directory)
  "A TLS server that answers each request with a small JSON body and keeps the
connection alive.  Returns (values port connection-count-fn stop-fn), where the
count is how many TCP connections it has accepted."
  (multiple-value-bind (cert key) (http-client-test-self-signed directory)
    (let* ((listener (usocket:socket-listen "127.0.0.1" 0 :reuse-address t :element-type '(unsigned-byte 8)))
           (connections 0)
           (lock (bt:make-lock "http-client test backend"))
           (stopping nil)
           (body (trivial-utf-8:string-to-utf-8-bytes "{\"ok\":true}")))
      (flet ((serve (raw)
               (bt:with-lock-held (lock) (incf connections))
               (ignore-errors
                (let ((tls (pure-tls:make-tls-server-stream (usocket:socket-stream raw)
                                                            :certificate cert :key key)))
                  ;; Keep serving on this connection until the peer stops.
                  (loop
                    (let ((headers (http-client-test-read-request-head tls)))
                      (write-sequence
                       (trivial-utf-8:string-to-utf-8-bytes
                        (format nil "HTTP/1.1 200 OK~C~CContent-Type: application/json~C~CContent-Length: ~D~C~CConnection: keep-alive~C~C~C~C"
                                #\Return #\Linefeed #\Return #\Linefeed (length body)
                                #\Return #\Linefeed #\Return #\Linefeed #\Return #\Linefeed))
                       tls)
                      (write-sequence body tls)
                      (force-output tls)
                      (when (search "close" (string-downcase (or (cdr (assoc "connection" headers :test #'string=)) "")))
                        (return))))))
               (ignore-errors (usocket:socket-close raw))))
        (let ((thread (bt:make-thread
                       (lambda ()
                         ;; Poll so the loop notices STOPPING promptly; a blocked
                         ;; socket-accept would not unblock on the listener closing.
                         (loop until stopping
                               do (when (usocket:wait-for-input listener :timeout 0.2 :ready-only t)
                                    (handler-case
                                        (let ((raw (usocket:socket-accept listener)))
                                          (bt:make-thread (lambda () (serve raw)) :name "http-client test conn"))
                                      (error () nil)))))
                       :name "http-client test accept")))
          (values (usocket:get-local-port listener)
                  (lambda () (bt:with-lock-held (lock) connections))
                  (lambda ()
                    (setf stopping t)
                    (ignore-errors (bt:join-thread thread))
                    (ignore-errors (usocket:socket-close listener)))))))))

(test http-client-reuses-a-pooled-keepalive-connection
  (let ((gr8s.http-client::*connection-pool* (make-hash-table :test 'equal)))
    (with-temporary-store (store dir)
      (declare (ignore store))
      (multiple-value-bind (port count-fn stop-fn) (http-client-test-keepalive-backend dir)
        (unwind-protect
             (flet ((get1 (&key reuse)
                      (multiple-value-bind (code headers body)
                          (gr8s.http-client:https-request
                           :host "127.0.0.1" :port port :server-name "localhost"
                           :method :get :target "/" :insecure t :reuse reuse :timeout 10)
                        (declare (ignore headers))
                        (is (= 200 code))
                        (is (gethash "ok" (com.inuoe.jzon:parse body))))))
               ;; Two pooled requests share one TCP connection.
               (get1 :reuse t)
               (get1 :reuse t)
               (is (= 1 (funcall count-fn)))
               ;; Two plain requests each open (and close) their own.
               (get1 :reuse nil)
               (get1 :reuse nil)
               (is (= 3 (funcall count-fn))))
          (funcall stop-fn))))))
