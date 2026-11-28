;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Prove the node egress proxy (podster-wv1w.2): it names a captured connection's
;;;; destination from the TLS SNI or the HTTP Host, asks the policy verdict with the
;;;; address it resolved, and splices an admitted connection -- replaying what it read
;;;; -- or closes a refused one, reporting each decision.

(in-package #:gr8s/tests)
(def-suite egress-proxy :in gr8s)
(in-suite egress-proxy)

(defmacro with-egress-proxy ((proxy-port decisions &key (allow '("api.anthropic.com"))) &body body)
  "Run BODY with an egress proxy on a kernel port admitting the hosts in ALLOW, whose
upstream is a tag backend answering \"UP\". DECISIONS collects each report as
(host address allowed)."
  (let ((stop (gensym)) (backend-port (gensym)) (proxy (gensym)))
    `(multiple-value-bind (,stop ,backend-port) (l4-start-tag-backend "UP")
       (let* ((,decisions '())
              (,proxy (gr8s.controllers::start-egress-proxy
                       :decide (lambda (peer host address port)
                                 (declare (ignore peer address port))
                                 (values (and host (member host ',allow :test #'equal) t) "rule"))
                       :resolve (lambda (host) (declare (ignore host)) "127.0.0.1")
                       :connect (lambda (address port)
                                  (declare (ignore port))
                                  (gr8s.controllers::egress-default-connect address ,backend-port))
                       :report (lambda (peer host address port allowed rule &optional program audit)
                                 (declare (ignore peer port rule program audit))
                                 (push (list host address allowed) ,decisions))))
              (,proxy-port (gr8s.controllers::egress-proxy-port ,proxy)))
         (unwind-protect (progn ,@body)
           (gr8s.controllers::stop-egress-proxy ,proxy)
           (funcall ,stop))))))

(test egress-proxy-names-the-destination-from-sni-or-host
  (is (equal "example.com"
             (gr8s.controllers::egress-http-host
              (babel:string-to-octets (format nil "GET / HTTP/1.1~C~CHost: Example.com:8080~C~C~C~C"
                                              #\Return #\Newline #\Return #\Newline #\Return #\Newline)))))
  (is (null (gr8s.controllers::egress-http-host
             (babel:string-to-octets (format nil "GET / HTTP/1.0~C~C~C~C" #\Return #\Newline #\Return #\Newline))))))

(test egress-proxy-splices-an-admitted-tls-connection
  (with-egress-proxy (port decisions)
    (is (equal "UP" (l4-client-read-tag port :send (gwsni-client-hello :server-name "api.anthropic.com"))))
    (sleep 0.1)
    (is (equal '(("api.anthropic.com" "127.0.0.1" t)) decisions))))

(test egress-proxy-closes-a-refused-or-nameless-connection
  (with-egress-proxy (port decisions)
    (is (equal "" (l4-client-read-tag port :send (gwsni-client-hello :server-name "evil.example.com"))))
    (is (equal "" (l4-client-read-tag port :send (gwsni-client-hello))))
    (sleep 0.1)
    (is (equal '((nil nil nil) ("evil.example.com" "127.0.0.1" nil)) decisions))))

(test egress-proxy-admits-cleartext-by-host
  (with-egress-proxy (port decisions :allow ("example.org"))
    (is (equal "UP" (l4-client-read-tag
                     port :send (babel:string-to-octets
                                 (format nil "GET / HTTP/1.1~C~CHost: example.org~C~C~C~C"
                                         #\Return #\Newline #\Return #\Newline #\Return #\Newline)))))
    (sleep 0.1)
    (is (equal '(("example.org" "127.0.0.1" t)) decisions))))

(defun egress-dns-query (name &optional (qtype 1))
  "A DNS query packet for NAME's records of QTYPE, A by default."
  (0conf:encode-message
   (0conf:make-dns-message :id 7 :flags #x0100
                           :questions (list (0conf:make-question :name name :qtype qtype :qclass 1)))))

(test egress-dns-gate-answers-only-allowed-names
  (is-true (gr8s.controllers::egress-dns-name-allowed-p "web.prod.svc.cluster.local." '()))
  (is-true (gr8s.controllers::egress-dns-name-allowed-p "api.anthropic.com" '("api.anthropic.com")))
  (is-false (gr8s.controllers::egress-dns-name-allowed-p "exfil.attacker.example" '("api.anthropic.com")))
  (is-false (gr8s.controllers::egress-dns-name-allowed-p "evilcluster.local" '()))
  (is-true (gr8s.controllers::egress-dns-name-allowed-p "anything.example" :all))
  (let ((forwarded '()))
    (flet ((answer (name patterns)
             (gr8s.controllers::egress-dns-gate-answer
              (egress-dns-query name) patterns
              (lambda (packet) (push name forwarded) packet))))
      ;; Allowed: relayed as it came.
      (is (equalp (egress-dns-query "api.anthropic.com") (answer "api.anthropic.com" '("api.anthropic.com"))))
      ;; Not allowed: REFUSED, and never forwarded.
      (let ((refused (answer "secret-data.attacker.example" '("api.anthropic.com"))))
        (is (= 5 (cl-dns-proxy:dns-response-code refused))))
      (is (equal '("api.anthropic.com") forwarded)))))

(test egress-every-verdict-joins-the-flow-stream
  ;; podster-5hv.11: the agent's own report replaced the flow sink's, so no verdict
  ;; reached the stream. Both must see each one.
  (let ((reported '()) (flows '()))
    (let ((gr8s.controllers::*gateway-flow-sink* (lambda (flow) (push flow flows))))
      (funcall (gr8s.controllers::egress-verdict-reporter
                (lambda (peer host address port allowed rule)
                  (declare (ignore address port rule))
                  (push (list peer host allowed) reported)))
               "10.80.32.7" "evil.example.com" "203.0.113.5" 443 nil
               (gr8s.network::make-cnp-rule :action :deny :name "gr8-sandbox")))
    (is (equal '(("10.80.32.7" "evil.example.com" nil)) reported))
    (is (= 1 (length flows)))
    (let ((flow (first flows)))
      (is (equal "DROPPED" (gethash "verdict" flow)))
      (is (equal "evil.example.com" (gethash "peerName" flow)))
      (is (equal "gr8-sandbox" (gethash "rule" (gethash "l7" flow)))))))

(test egress-dns-gate-reports-each-decided-name
  ;; A name outside the cluster zone is a decision: reported allowed or refused. The
  ;; cluster's own names aren't, being always relayed.
  (let ((query (0conf:encode-message
                (0conf:make-dns-message :id 1 :flags #x0100
                                        :questions (list (0conf:make-question :name "Example.COM." :qtype 0conf:+type-a+))))))
    (is (equal '(("example.com" . t)) (gr8s.controllers::egress-dns-decisions query '("example.com"))))
    (is (equal '(("example.com")) (gr8s.controllers::egress-dns-decisions query '("api.anthropic.com")))))
  (is (null (gr8s.controllers::egress-dns-decisions (egress-dns-query "web.prod.svc.cluster.local") '())))
  (let ((flow (gr8s.controllers::egress-dns-flow-object "10.80.32.7" "exfil.example" nil)))
    (is (equal "DROPPED" (gethash "verdict" flow)))
    (is (equal "POLICY" (gethash "reason" flow)))
    (is (equal "dns" (gethash "type" (gethash "l7" flow))))
    (is (equal "exfil.example" (gethash "query" (gethash "l7" flow))))))

(test egress-dns-gate-reports-one-event-per-decision
  ;; A resolver asks for A and AAAA and retries: one lookup, one event.
  (let* ((now 1000) (events '())
         (report (gr8s.controllers::make-egress-dns-reporter
                  (lambda (client name allowed) (push (list client name allowed) events))
                  :clock (lambda () now))))
    (dotimes (i 4) (funcall report "10.80.32.7" "example.com" nil))
    (is (equal '(("10.80.32.7" "example.com" nil)) events))
    ;; Another Pod, another name, or the other verdict is another decision.
    (funcall report "10.80.32.8" "example.com" nil)
    (funcall report "10.80.32.7" "example.org" nil)
    (funcall report "10.80.32.7" "example.com" t)
    (is (= 4 (length events)))
    ;; Asked again after the window: a new decision.
    (incf now 6)
    (funcall report "10.80.32.7" "example.com" nil)
    (is (= 5 (length events)))))

(defun egress-test-name-table (answers &key (clock (let ((now 1000)) (lambda () now))))
  "A name table whose resolver answers from ANSWERS, an alist of name -> (addresses ttl
rcode), counting calls per name in the returned hash table."
  (let ((calls (make-hash-table :test 'equal)))
    (values (gr8s.network::make-egress-name-table
             :resolve (lambda (name)
                        (incf (gethash name calls 0))
                        (values-list (or (cdr (assoc name (funcall answers) :test #'equal)) '(nil 0 2))))
             :clock clock)
            calls)))

(test egress-dns-gate-answers-synthetic-mode-pods-with-synthetic-addresses
  (let ((forwarded '())
        (table (egress-test-name-table (lambda () '(("api.anthropic.com" ("160.79.104.10") 300 0)))))
        (patterns '("api.anthropic.com" "*.down.example")))
    (flet ((answer (name &optional (qtype 1))
             (gr8s.controllers::egress-dns-gate-answer
              (egress-dns-query name qtype) patterns
              (lambda (packet) (push name forwarded) packet)
              :synthesize (lambda (name) (gr8s.network::egress-name-answer table name)))))
      ;; An allowed A query: one synthetic address, for the name asked, with a short TTL.
      (let* ((packet (answer "api.anthropic.com"))
             (response (0conf:decode-message packet))
             (records (0conf:dns-message-answers response)))
        (is (= 0 (cl-dns-proxy:dns-response-code packet)))
        (is (= 7 (0conf:dns-message-id response)))
        (is (= 1 (length records)))
        (is (equal "api.anthropic.com" (string-right-trim "." (0conf:rr-name (first records)))))
        (is-true (gr8s.network::egress-synthetic-address-p
                  (format nil "~{~D~^.~}" (coerce (0conf:a-address (first records)) 'list))))
        (is (= gr8s.network::+egress-synthetic-ttl+ (0conf:rr-ttl (first records)))))
      ;; AAAA and HTTPS (which can carry address hints): no data, so the client uses A.
      (dolist (qtype '(28 65))
        (let ((packet (answer "api.anthropic.com" qtype)))
          (is (= 0 (cl-dns-proxy:dns-response-code packet)))
          (is (null (0conf:dns-message-answers (0conf:decode-message packet))))))
      ;; Not allowed: REFUSED. Allowed but unresolvable: SERVFAIL.
      (is (= 5 (cl-dns-proxy:dns-response-code (answer "exfil.attacker.example"))))
      (is (= 2 (cl-dns-proxy:dns-response-code (answer "api.down.example"))))
      ;; The cluster's own names are relayed as before.
      (is (equalp (egress-dns-query "web.prod.svc.cluster.local") (answer "web.prod.svc.cluster.local")))
      (is (equal '("web.prod.svc.cluster.local") forwarded)))))

;;; Synthetic addresses (podster-wv1w.8): the address a connection was dialled to names
;;; its destination, so a protocol that names nothing is admitted by name.

(defun egress-start-echo-backend ()
  "Accept connections on a kernel port and echo what each sends, speaking only when
spoken to, as a TLS server does. Returns (values stop port)."
  (let* ((socket (make-instance 'sb-bsd-sockets:inet-socket :type :stream :protocol :tcp))
         (stop (list nil)) (port nil))
    (setf (sb-bsd-sockets:sockopt-reuse-address socket) t)
    (sb-bsd-sockets:socket-bind socket #(127 0 0 1) 0)
    (setf port (nth-value 1 (sb-bsd-sockets:socket-name socket)))
    (sb-bsd-sockets:socket-listen socket 8)
    (let ((thread
            (bt:make-thread
             (lambda ()
               (loop until (car stop)
                     do (ignore-errors
                         (let ((client (sb-bsd-sockets:socket-accept socket))
                               (buffer (make-array 4096 :element-type '(unsigned-byte 8))))
                           (bt:make-thread
                            (lambda ()
                              (unwind-protect
                                   (loop (multiple-value-bind (b n) (sb-bsd-sockets:socket-receive client buffer nil)
                                           (declare (ignore b))
                                           (when (or (null n) (zerop n)) (return))
                                           (sb-bsd-sockets:socket-send client buffer n)))
                                (ignore-errors (sb-bsd-sockets:socket-close client))))
                            :name "egress echo backend conn")))))
             :name "egress echo backend")))
      (values (lambda ()
                (setf (car stop) t)
                (ignore-errors
                 (let ((waker (make-instance 'sb-bsd-sockets:inet-socket :type :stream :protocol :tcp)))
                   (unwind-protect (sb-bsd-sockets:socket-connect waker #(127 0 0 1) port)
                     (ignore-errors (sb-bsd-sockets:socket-close waker)))))
                (ignore-errors (bt:join-thread thread))
                (ignore-errors (sb-bsd-sockets:socket-close socket)))
              port))))

(defun call-with-synthetic-proxy (backend-port function &key (allow '("db.example.com" "api.example.com")))
  "Call FUNCTION with (proxy-port table dial decisions connects): an egress proxy whose
name table resolves every name to 203.0.113.5 and whose upstream is BACKEND-PORT,
admitting ALLOW. (FUNCTION dial address) sets the address the next connection is taken
to have been dialled to; DECISIONS and CONNECTS return what was reported and dialled."
  (let* ((decisions '()) (connects '()) (dialed (list nil))
         (table (gr8s.network::make-egress-name-table
                 :resolve (lambda (name) (declare (ignore name)) (values '("203.0.113.5") 30 0))))
         (proxy (gr8s.controllers::start-egress-proxy
                 :decide (lambda (peer host address port)
                           (declare (ignore peer address port))
                           (values (and host (member host allow :test #'equal) t) "rule"))
                 :resolve (lambda (host) (declare (ignore host)) (error "a synthetic connection re-resolved"))
                 :connect (lambda (address port)
                            (declare (ignore port))
                            (push address connects)
                            (gr8s.controllers::egress-default-connect "127.0.0.1" backend-port))
                 :report (lambda (peer host address port allowed rule &optional program audit)
                           (declare (ignore peer port rule program audit))
                           (push (list host address allowed) decisions))
                 :names table
                 :dialed (lambda (socket) (declare (ignore socket)) (values (car dialed) 6379)))))
    (unwind-protect
         (funcall function (gr8s.controllers::egress-proxy-port proxy) table
                  (lambda (address) (setf (car dialed) address))
                  (lambda () (sleep 0.1) decisions)
                  (lambda () connects))
      (gr8s.controllers::stop-egress-proxy proxy))))

(test egress-proxy-admits-a-synthetic-address-by-the-name-it-stands-for
  ;; A server that speaks first (Redis's peers, SSH, SMTP): the client names nothing.
  (multiple-value-bind (stop backend) (l4-start-tag-backend "UP")
    (unwind-protect
         (call-with-synthetic-proxy
          backend
          (lambda (port table dial decisions connects)
            (funcall dial (gr8s.network::egress-name-answer table "db.example.com"))
            (is (equal "UP" (l4-client-read-tag port)))
            (is (equal '(("db.example.com" "203.0.113.5" t)) (funcall decisions)))
            ;; It dialled the pinned address, without resolving the name again.
            (is (equal '("203.0.113.5") (funcall connects)))))
      (funcall stop))))

(test egress-proxy-refuses-a-synthetic-address-the-policy-or-table-doesnt-admit
  (multiple-value-bind (stop backend) (l4-start-tag-backend "UP")
    (unwind-protect
         (call-with-synthetic-proxy
          backend
          (lambda (port table dial decisions connects)
            ;; A name the policy refuses.
            (funcall dial (gr8s.network::egress-name-answer table "evil.example.com"))
            (is (equal "" (l4-client-read-tag port)))
            ;; An address the table never gave out.
            (funcall dial "198.18.200.9")
            (is (equal "" (l4-client-read-tag port)))
            (is (equal '((nil nil nil) ("evil.example.com" "203.0.113.5" nil)) (funcall decisions)))
            (is (null (funcall connects)))))
      (funcall stop))))

(test egress-proxy-refuses-tls-whose-sni-isnt-the-synthetic-addresss-name
  (multiple-value-bind (stop backend) (egress-start-echo-backend)
    (unwind-protect
         (call-with-synthetic-proxy
          backend
          (lambda (port table dial decisions connects)
            (declare (ignore connects))
            (funcall dial (gr8s.network::egress-name-answer table "api.example.com"))
            ;; Fronting: an allowed server's address, another site's name.
            (is (equal "" (l4-client-read-tag port :send (gwsni-client-hello :server-name "evil.example.com"))))
            ;; The name it stands for: spliced, ClientHello and all.
            (is (plusp (length (l4-client-read-tag port :send (gwsni-client-hello :server-name "api.example.com")))))
            (is (equal '(("api.example.com" "203.0.113.5" t) ("api.example.com" "203.0.113.5" nil))
                       (funcall decisions)))))
      (funcall stop))))

;;; Credential injection (podster-wv1w.3).

(defun egress-echo-upstream (&key tls-chain tls-key)
  "An HTTP/1.1 upstream on a kernel port that answers each request with its own head as
the body, over TLS when TLS-CHAIN is given. Returns (values stop port)."
  (let* ((socket (make-instance 'sb-bsd-sockets:inet-socket :type :stream :protocol :tcp))
         (stop (list nil)) (port nil))
    (setf (sb-bsd-sockets:sockopt-reuse-address socket) t)
    (sb-bsd-sockets:socket-bind socket #(127 0 0 1) 0)
    (setf port (nth-value 1 (sb-bsd-sockets:socket-name socket)))
    (sb-bsd-sockets:socket-listen socket 8)
    (let ((thread
            (bt:make-thread
             (lambda ()
               (loop until (car stop)
                     do (ignore-errors
                         (let* ((client (sb-bsd-sockets:socket-accept socket))
                                (raw (gr8s.controllers::egress-socket-stream client))
                                (stream (if tls-chain
                                            (pure-tls:make-tls-server-stream raw :certificate tls-chain :key tls-key)
                                            raw)))
                           (unwind-protect
                                (loop for head = (gr8s.controllers::egress-read-http-head stream)
                                      while head
                                      do (write-sequence (gr8s.controllers::egress-http-head-octets
                                                          "HTTP/1.1 200 OK"
                                                          `(("Content-Length" . ,(princ-to-string (length head)))))
                                                         stream)
                                         (write-sequence head stream)
                                         (force-output stream))
                             (ignore-errors (close stream))
                             (ignore-errors (sb-bsd-sockets:socket-close client)))))))
             :name "egress echo upstream")))
      (values (lambda ()
                (setf (car stop) t)
                (ignore-errors
                 (let ((waker (make-instance 'sb-bsd-sockets:inet-socket :type :stream :protocol :tcp)))
                   (unwind-protect (sb-bsd-sockets:socket-connect waker #(127 0 0 1) port)
                     (ignore-errors (sb-bsd-sockets:socket-close waker)))))
                (ignore-errors (bt:join-thread thread))
                (ignore-errors (sb-bsd-sockets:socket-close socket)))
              port))))

(defun egress-test-matcher (value)
  "Inject VALUE into x-api-key on /v1/ requests."
  (lambda (method path)
    (declare (ignore method))
    (when (and (>= (length path) 4) (string= "/v1/" path :end2 4))
      (values "anthropic" '("x-api-key") value))))

(defun egress-test-request (stream host path &key (stand-in t))
  "Send one request through STREAM, with a stand-in x-api-key unless STAND-IN is NIL, and
read the response. Returns (values status body)."
  (write-sequence (gr8s.controllers::egress-http-head-octets
                   (format nil "GET ~A HTTP/1.1" path)
                   `(("Host" . ,host) ,@(and stand-in '(("x-api-key" . "gr8s-injected"))) ("Accept" . "*/*")))
                  stream)
  (force-output stream)
  (multiple-value-bind (status-line headers)
      (gr8s.controllers::egress-parse-http-head (gr8s.controllers::egress-read-http-head stream))
    (let* ((length (parse-integer (or (gr8s.controllers::egress-header headers "Content-Length") "0")))
           (body (make-array length :element-type '(unsigned-byte 8))))
      (read-sequence body stream)
      (values (parse-integer (second (cl-ppcre:split " " status-line)))
              (babel:octets-to-string body :encoding :latin-1)))))

(defmacro with-injecting-proxy ((port &key matcher mint (upstream-port '(error "upstream")) names dialed
                                         inspect request-report)
                                &body body)
  "NAMES and DIALED, when given, are the proxy's name table and the address every
connection is taken to have been dialled to (podster-wv1w.8). INSPECT and REQUEST-REPORT
are the proxy's (podster-wv1w.11)."
  (let ((proxy (gensym)))
    `(let* ((,proxy (gr8s.controllers::start-egress-proxy
                     :decide (lambda (peer host address port) (declare (ignore peer host address port)) (values t nil))
                     :resolve (lambda (host) (declare (ignore host)) "127.0.0.1")
                     :connect (lambda (address port)
                                (declare (ignore address port))
                                (gr8s.controllers::egress-default-connect "127.0.0.1" ,upstream-port))
                     :inject (lambda (peer host scheme) (declare (ignore peer scheme))
                               (and (equal host "api.example.test") ,matcher))
                     :mint ,mint
                     :inspect ,inspect
                     :request-report ,request-report
                     :upstream-verify pure-tls:+verify-none+
                     :names ,names
                     :dialed ,(and dialed `(lambda (socket) (declare (ignore socket)) (values ,dialed 80)))))
            (,port (gr8s.controllers::egress-proxy-port ,proxy)))
       (unwind-protect (progn ,@body)
         (gr8s.controllers::stop-egress-proxy ,proxy)))))

(defun egress-test-client (port)
  (let ((socket (make-instance 'sb-bsd-sockets:inet-socket :type :stream :protocol :tcp)))
    (sb-bsd-sockets:socket-connect socket #(127 0 0 1) port)
    (values (gr8s.controllers::egress-socket-stream socket) socket)))

(test egress-proxy-injects-the-credential-into-cleartext-requests
  (multiple-value-bind (stop upstream) (egress-echo-upstream)
    (unwind-protect
         (with-injecting-proxy (port :matcher (egress-test-matcher "sk-real") :upstream-port upstream)
           (multiple-value-bind (stream socket) (egress-test-client port)
             (unwind-protect
                  (progn
                    ;; Matching path: the upstream sees the real key, not the placeholder.
                    (multiple-value-bind (status body) (egress-test-request stream "api.example.test" "/v1/messages")
                      (is (= 200 status))
                      (is (search "x-api-key: sk-real" body))
                      (is (not (search "gr8s-injected" body))))
                    ;; A Host other than the one the connection named: refused.
                    (is (= 421 (egress-test-request stream "evil.example.test" "/v1/messages"))))
               (ignore-errors (sb-bsd-sockets:socket-close socket)))
             ;; Another path: nothing injects there, so the stand-in would reach the
             ;; server: refused, saying why (podster-wv1w.12).
             (multiple-value-bind (stream socket) (egress-test-client port)
               (unwind-protect
                    (multiple-value-bind (status body) (egress-test-request stream "api.example.test" "/health")
                      (is (= 403 status))
                      (is (search "x-api-key carries a gr8 stand-in credential, which no rule injects for GET api.example.test/health" body)))
                 (ignore-errors (sb-bsd-sockets:socket-close socket))))))
      (funcall stop))))

(test egress-proxy-refuses-a-request-whose-credential-is-missing
  (multiple-value-bind (stop upstream) (egress-echo-upstream)
    (unwind-protect
         (with-injecting-proxy (port :matcher (egress-test-matcher nil) :upstream-port upstream)
           (multiple-value-bind (stream socket) (egress-test-client port)
             (unwind-protect
                  (is (= 403 (egress-test-request stream "api.example.test" "/v1/messages")))
               (ignore-errors (sb-bsd-sockets:socket-close socket)))))
      (funcall stop))))

;; A synthetic address stands for the injected host: the request is relayed and the
;; credential added, and a Host other than the address's name is refused.
(test egress-proxy-injects-for-the-host-a-synthetic-address-stands-for
  (multiple-value-bind (stop upstream) (egress-echo-upstream)
    (let* ((table (gr8s.network::make-egress-name-table
                   :resolve (lambda (name) (declare (ignore name)) (values '("203.0.113.5") 30 0))))
           (address (gr8s.network::egress-name-answer table "api.example.test")))
      (unwind-protect
           (with-injecting-proxy (port :matcher (egress-test-matcher "sk-real") :upstream-port upstream
                                       :names table :dialed address)
             (multiple-value-bind (stream socket) (egress-test-client port)
               (unwind-protect
                    (progn
                      (multiple-value-bind (status body) (egress-test-request stream "api.example.test" "/v1/messages")
                        (is (= 200 status))
                        (is (search "x-api-key: sk-real" body)))
                      (is (= 421 (egress-test-request stream "evil.example.test" "/v1/messages"))))
                 (ignore-errors (sb-bsd-sockets:socket-close socket)))))
        (funcall stop)))))

(defun egress-test-pem-material (certificate-pem key-pem)
  (values (list (pure-tls:parse-certificate (pure-tls::pem-decode (babel:string-to-octets certificate-pem) "CERTIFICATE")))
          (pure-tls::parse-ec-private-key (pure-tls::pem-decode (babel:string-to-octets key-pem) "EC PRIVATE KEY"))))

(test egress-proxy-terminates-tls-with-a-leaf-from-the-egress-ca
  (multiple-value-bind (ca-key ca-public) (ironclad:generate-key-pair :secp256r1)
    (let* ((ca-certificate (pure-tls:parse-certificate
                            (gr8s.security::ca-certificate-der ca-key ca-public :common-name "gr8s egress")))
           (mint (gr8s.controllers::make-egress-leaf-minter ca-key ca-certificate)))
      (multiple-value-bind (upstream-chain upstream-key)
          (multiple-value-bind (certificate-pem key-pem)
              (gr8s.controllers::cm-issue-leaf :dns-names '("api.example.test"))
            (egress-test-pem-material certificate-pem key-pem))
        (multiple-value-bind (stop upstream) (egress-echo-upstream :tls-chain upstream-chain :tls-key upstream-key)
          (unwind-protect
               (with-injecting-proxy (port :matcher (egress-test-matcher "sk-real") :mint mint :upstream-port upstream)
                 (multiple-value-bind (raw socket) (egress-test-client port)
                   (unwind-protect
                        (let ((tls (pure-tls:make-tls-client-stream raw :hostname "api.example.test"
                                                                        :verify pure-tls:+verify-none+)))
                          ;; The proxy presented a leaf for the host, signed by the egress CA.
                          (let ((leaf (first (pure-tls:tls-peer-certificate-chain tls))))
                            (is (member "api.example.test" (pure-tls::certificate-dns-names leaf) :test (function equal))))
                          (multiple-value-bind (status body) (egress-test-request tls "api.example.test" "/v1/messages")
                            (is (= 200 status))
                            (is (search "x-api-key: sk-real" body))))
                     (ignore-errors (sb-bsd-sockets:socket-close socket)))))
            (funcall stop)))))))

;;; A gr8 sandbox's egress is inspected (podster-wv1w.11): TLS terminated, every request
;;; reported, and a rule a request breaks refused under Enforce, reported under Audit.

(defun egress-test-ca-minter ()
  (multiple-value-bind (ca-key ca-public) (ironclad:generate-key-pair :secp256r1)
    (gr8s.controllers::make-egress-leaf-minter
     ca-key (pure-tls:parse-certificate (gr8s.security::ca-certificate-der ca-key ca-public :common-name "gr8s egress")))))

(defun egress-test-tls-upstream (host)
  "An echo upstream presenting its own leaf for HOST. Returns (values stop port)."
  (multiple-value-bind (chain key)
      (multiple-value-bind (certificate-pem key-pem) (gr8s.controllers::cm-issue-leaf :dns-names (list host))
        (egress-test-pem-material certificate-pem key-pem))
    (egress-echo-upstream :tls-chain chain :tls-key key)))

(defun egress-test-synthetic-address (host)
  (let ((table (gr8s.network::make-egress-name-table
                :resolve (lambda (name) (declare (ignore name)) (values '("203.0.113.5") 30 0)))))
    (values table (gr8s.network::egress-name-answer table host))))

(test egress-proxy-terminates-an-inspected-sandboxs-tls-and-reports-each-request
  ;; No credential for this host: termination is for seeing the requests.
  (multiple-value-bind (stop upstream) (egress-test-tls-upstream "web.example.test")
    (multiple-value-bind (table address) (egress-test-synthetic-address "web.example.test")
      (let ((requests '()))
        (unwind-protect
             (with-injecting-proxy (port :mint (egress-test-ca-minter) :upstream-port upstream
                                         :names table :dialed address
                                         :inspect (lambda (peer host) (declare (ignore peer host))
                                                    (list :enforcement :enforce))
                                         :request-report (lambda (peer host address port method path code rule &optional audit)
                                                           (declare (ignore peer address port))
                                                           (push (list host method path code rule audit) requests)))
               (multiple-value-bind (raw socket) (egress-test-client port)
                 (unwind-protect
                      (let ((tls (pure-tls:make-tls-client-stream raw :hostname "web.example.test"
                                                                      :verify pure-tls:+verify-none+)))
                        ;; The leaf is the egress CA's, not the server's own.
                        (let ((leaf (first (pure-tls:tls-peer-certificate-chain tls))))
                          (is (member "gr8s egress" (pure-tls::certificate-issuer-common-names leaf) :test #'equal)))
                        (multiple-value-bind (status body)
                            (egress-test-request tls "web.example.test" "/index.html" :stand-in nil)
                          (is (= 200 status))
                          (is (search "GET /index.html" body)))
                        ;; Fronting is refused under Enforce.
                        (is (= 421 (egress-test-request tls "evil.example.test" "/"))))
                   (ignore-errors (sb-bsd-sockets:socket-close socket)))
                 ;; Nothing injects for this host: a stand-in is refused, and why.
                 (multiple-value-bind (raw socket) (egress-test-client port)
                   (unwind-protect
                        (let ((tls (pure-tls:make-tls-client-stream raw :hostname "web.example.test"
                                                                        :verify pure-tls:+verify-none+)))
                          (multiple-value-bind (status body) (egress-test-request tls "web.example.test" "/v1/x")
                            (is (= 403 status))
                            (is (search "no rule injects for GET web.example.test/v1/x" body))))
                     (ignore-errors (sb-bsd-sockets:socket-close socket))))))
          (funcall stop))
        (is (equal '(("web.example.test" "GET" "/v1/x" 403 nil
                      "x-api-key carries a gr8 stand-in credential, which no rule injects for GET web.example.test/v1/x")
                     ("web.example.test" "GET" "/" 421 nil nil)
                     ("web.example.test" "GET" "/index.html" 200 nil nil))
                   requests))))))

(test egress-proxy-under-audit-reports-a-broken-rule-and-forwards
  (multiple-value-bind (stop upstream) (egress-echo-upstream)
    (multiple-value-bind (table address) (egress-test-synthetic-address "web.example.test")
      (let ((requests '()))
        (unwind-protect
             (with-injecting-proxy (port :upstream-port upstream :names table :dialed address
                                         :inspect (lambda (peer host) (declare (ignore peer host))
                                                    (list :enforcement :audit))
                                         :request-report (lambda (peer host address port method path code rule &optional audit)
                                                           (declare (ignore peer host address port method rule))
                                                           (push (list path code audit) requests)))
               (multiple-value-bind (stream socket) (egress-test-client port)
                 (unwind-protect
                      (multiple-value-bind (status body)
                          (egress-test-request stream "evil.example.test" "/x" :stand-in nil)
                        (is (= 200 status))
                        (is (search "Host: evil.example.test" body)))
                      ;; A stand-in nothing injects is reported too, and goes as it came:
                      ;; it is worthless anywhere it isn't swapped.
                      (multiple-value-bind (status body) (egress-test-request stream "web.example.test" "/y")
                        (is (= 200 status))
                        (is (search "x-api-key: gr8s-injected" body)))
                   (ignore-errors (sb-bsd-sockets:socket-close socket)))))
          (funcall stop))
        (is (equal '(("/y" 200 "x-api-key carries a gr8 stand-in credential, which no rule injects for GET web.example.test/y")
                     ("/x" 200 "Host evil.example.test is not web.example.test"))
                   requests))))))

(test egress-proxy-relays-an-inspected-sandbox-undecrypted-without-a-ca
  ;; No egress CA on the node: nothing to present, so the TLS goes through as it came
  ;; (terminating would have failed the connection), and the client completes its
  ;; handshake with the server itself.
  (multiple-value-bind (stop upstream) (egress-test-tls-upstream "web.example.test")
    (multiple-value-bind (table address) (egress-test-synthetic-address "web.example.test")
      (let ((asked '()))
        (unwind-protect
             (with-injecting-proxy (port :mint (lambda (host) (push host asked) nil) :upstream-port upstream
                                         :names table :dialed address
                                         :inspect (lambda (peer host) (declare (ignore peer host))
                                                    (list :enforcement :enforce)))
               (multiple-value-bind (raw socket) (egress-test-client port)
                 (unwind-protect
                      (let ((tls (pure-tls:make-tls-client-stream raw :hostname "web.example.test"
                                                                      :verify pure-tls:+verify-none+)))
                        (is (= 200 (egress-test-request tls "web.example.test" "/"))))
                   (ignore-errors (sb-bsd-sockets:socket-close socket)))))
          (funcall stop))
        (is (equal '("web.example.test") asked))))))

(test egress-proxy-says-where-a-refused-stand-ins-credentials-are-bound
  (multiple-value-bind (stop upstream) (egress-echo-upstream)
    (multiple-value-bind (table address) (egress-test-synthetic-address "web.example.test")
      (unwind-protect
           (let ((proxy (gr8s.controllers::start-egress-proxy
                         :decide (lambda (peer host address port) (declare (ignore peer host address port)) (values t nil))
                         :connect (lambda (address port) (declare (ignore address port))
                                    (gr8s.controllers::egress-default-connect "127.0.0.1" upstream))
                         :inspect (lambda (peer host) (declare (ignore peer host)) (list :enforcement :enforce))
                         :bindings (lambda (peer) (declare (ignore peer)) '("api.anthropic.com" "*.github.com"))
                         :names table
                         :dialed (lambda (socket) (declare (ignore socket)) (values address 80)))))
             (unwind-protect
                  (multiple-value-bind (stream socket) (egress-test-client (gr8s.controllers::egress-proxy-port proxy))
                    (unwind-protect
                         (multiple-value-bind (status body) (egress-test-request stream "web.example.test" "/")
                           (is (= 403 status))
                           (is (search "this Pod's credentials are bound to api.anthropic.com, *.github.com" body)))
                      (ignore-errors (sb-bsd-sockets:socket-close socket))))
               (gr8s.controllers::stop-egress-proxy proxy)))
        (funcall stop)))))

(defun egress-token-endpoint ()
  "A cleartext OAuth token endpoint that answers a refresh with new tokens, and the
request bodies it got. Returns (values stop port bodies)."
  (let* ((socket (make-instance 'sb-bsd-sockets:inet-socket :type :stream :protocol :tcp))
         (stop (list nil)) (bodies (list nil)) (port nil))
    (setf (sb-bsd-sockets:sockopt-reuse-address socket) t)
    (sb-bsd-sockets:socket-bind socket #(127 0 0 1) 0)
    (setf port (nth-value 1 (sb-bsd-sockets:socket-name socket)))
    (sb-bsd-sockets:socket-listen socket 8)
    (let ((thread
            (bt:make-thread
             (lambda ()
               (loop until (car stop)
                     do (ignore-errors
                         (let* ((client (sb-bsd-sockets:socket-accept socket))
                                (stream (gr8s.controllers::egress-socket-stream client)))
                           (unwind-protect
                                (multiple-value-bind (start headers)
                                    (gr8s.controllers::egress-parse-http-head (gr8s.controllers::egress-read-http-head stream))
                                  (declare (ignore start))
                                  (push (trivial-utf-8:utf-8-bytes-to-string
                                         (gr8s.controllers::egress-read-body
                                          stream (gr8s.controllers::egress-body-framing headers :request t)))
                                        (car bodies))
                                  (let ((body (trivial-utf-8:string-to-utf-8-bytes
                                               "{\"access_token\":\"sk-ant-oat-new\",\"refresh_token\":\"sk-ant-ort-new\",\"expires_in\":3600}")))
                                    (write-sequence (gr8s.controllers::egress-http-head-octets
                                                     "HTTP/1.1 200 OK"
                                                     `(("Content-Type" . "application/json")
                                                       ("Content-Length" . ,(princ-to-string (length body)))))
                                                    stream)
                                    (write-sequence body stream)
                                    (force-output stream)))
                             (ignore-errors (close stream))
                             (ignore-errors (sb-bsd-sockets:socket-close client)))))))
             :name "egress token endpoint")))
      (values (lambda ()
                (setf (car stop) t)
                (ignore-errors
                 (let ((waker (make-instance 'sb-bsd-sockets:inet-socket :type :stream :protocol :tcp)))
                   (unwind-protect (sb-bsd-sockets:socket-connect waker #(127 0 0 1) port)
                     (ignore-errors (sb-bsd-sockets:socket-close waker)))))
                (ignore-errors (bt:join-thread thread))
                (ignore-errors (sb-bsd-sockets:socket-close socket)))
              port bodies))))

(test egress-proxy-exchanges-a-refresh-and-hands-the-client-stand-ins
  ;; podster-kn03: the sandbox sends its stand-in refresh token; the endpoint gets the
  ;; real one; the client gets stand-ins; the node keeps the real new tokens.
  (multiple-value-bind (stop upstream bodies) (egress-token-endpoint)
    (let ((rotated nil))
      (unwind-protect
           (with-injecting-proxy (port :upstream-port upstream
                                       :matcher (lambda (method path)
                                                  (declare (ignore method path))
                                                  (values "gr8/claude-oauth/refresh" nil "sk-ant-ort-real"
                                                          (list :rotate (lambda (tokens) (setf rotated tokens))
                                                                :access-token-key "accessToken"
                                                                :refresh-token-key "refreshToken"))))
             (multiple-value-bind (stream socket) (egress-test-client port)
               (unwind-protect
                    (let ((body (trivial-utf-8:string-to-utf-8-bytes
                                 "{\"grant_type\":\"refresh_token\",\"refresh_token\":\"gr8s-injected\"}")))
                      (write-sequence (gr8s.controllers::egress-http-head-octets
                                       "POST /v1/oauth/token HTTP/1.1"
                                       `(("Host" . "api.example.test") ("Content-Type" . "application/json")
                                         ("Accept-Encoding" . "gzip") ("Content-Length" . ,(princ-to-string (length body)))))
                                      stream)
                      (write-sequence body stream)
                      (force-output stream)
                      (multiple-value-bind (status-line headers)
                          (gr8s.controllers::egress-parse-http-head (gr8s.controllers::egress-read-http-head stream))
                        (is (search "200" status-line))
                        (let ((answer (com.inuoe.jzon:parse
                                       (trivial-utf-8:utf-8-bytes-to-string
                                        (gr8s.controllers::egress-read-body
                                         stream (gr8s.controllers::egress-body-framing headers :status 200 :method "POST"))))))
                          (is (equal "gr8s-injected" (gethash "access_token" answer)))
                          (is (equal "gr8s-injected" (gethash "refresh_token" answer))))))
                 (ignore-errors (sb-bsd-sockets:socket-close socket)))))
        (funcall stop))
      (is (search "\"refresh_token\":\"sk-ant-ort-real\"" (first (car bodies))))
      (is (equal "sk-ant-oat-new" (cdr (assoc "accessToken" rotated :test #'equal))))
      (is (equal "sk-ant-ort-new" (cdr (assoc "refreshToken" rotated :test #'equal))))
      (is (assoc "expiresAt" rotated :test #'equal)))))

;;; podster-wv1w.27: per-credential stand-ins, swapped in by value.

(defun egress-test-request-with (stream host path headers)
  "Send one GET for PATH with HEADERS through STREAM; (values status body)."
  (write-sequence (gr8s.controllers::egress-http-head-octets
                   (format nil "GET ~A HTTP/1.1" path) `(("Host" . ,host) ,@headers ("Accept" . "*/*")))
                  stream)
  (force-output stream)
  (multiple-value-bind (status-line headers)
      (gr8s.controllers::egress-parse-http-head (gr8s.controllers::egress-read-http-head stream))
    (let* ((length (parse-integer (or (gr8s.controllers::egress-header headers "Content-Length") "0")))
           (body (make-array length :element-type '(unsigned-byte 8))))
      (read-sequence body stream)
      (values (parse-integer (second (cl-ppcre:split " " status-line)))
              (babel:octets-to-string body :encoding :latin-1)))))

(defparameter +test-stand-in-a+ "gho_gr8s-injected-0123456789abcdef01234567")
(defparameter +test-stand-in-b+ "gr8s-injected-fedcba9876543210fedcba98")

(defun egress-test-basic (user password)
  (concatenate 'string "Basic " (cl-base64:usb8-array-to-base64-string
                                 (trivial-utf-8:string-to-utf-8-bytes (format nil "~A:~A" user password)))))

(test egress-proxy-swaps-each-stand-in-for-its-own-credential
  (multiple-value-bind (stop upstream) (egress-echo-upstream)
    (unwind-protect
         (with-injecting-proxy (port :upstream-port upstream
                                     :matcher (lambda (method path) (declare (ignore method path))
                                                (values nil nil nil nil
                                                        (list (list +test-stand-in-a+ "real-a" "p/a")
                                                              (list +test-stand-in-b+ "real-b" "p/b")))))
           (flet ((ask (headers)
                    (multiple-value-bind (stream socket) (egress-test-client port)
                      (unwind-protect (egress-test-request-with stream "api.example.test" "/x" headers)
                        (ignore-errors (sb-bsd-sockets:socket-close socket))))))
             ;; In place, as the client wrote the header; two credentials for one host.
             (multiple-value-bind (status body) (ask `(("Authorization" . ,(format nil "token ~A" +test-stand-in-a+))
                                                       ("X-Other" . ,+test-stand-in-b+)))
               (is (= 200 status))
               (is (search "token real-a" body))
               (is (search "real-b" body))
               (is (not (search "gr8s-injected" body))))
             ;; Inside Basic auth, as git sends it.
             (multiple-value-bind (status body) (ask `(("Authorization" . ,(egress-test-basic "x-access-token" +test-stand-in-b+))))
               (is (= 200 status))
               (is (search (egress-test-basic "x-access-token" "real-b") body)))
             ;; No stand-in, no credential: nothing is injected by host alone.
             (multiple-value-bind (status body) (ask '(("Authorization" . "token mine")))
               (is (= 200 status))
               (is (search "token mine" body))
               (is (not (search "real-" body))))
             ;; A stand-in no credential here owns is refused, saying why.
             (multiple-value-bind (status body) (ask '(("Authorization" . "Bearer gr8s-injected-99999999999999999999")))
               (is (= 403 status))
               (is (search "carries a gr8 stand-in credential" body)))))
      (funcall stop))))

(test egress-proxy-refuses-a-stand-in-whose-credential-is-missing
  (multiple-value-bind (stop upstream) (egress-echo-upstream)
    (unwind-protect
         (with-injecting-proxy (port :upstream-port upstream
                                     :matcher (lambda (method path) (declare (ignore method path))
                                                (values nil nil nil nil (list (list +test-stand-in-a+ nil "p/a")))))
           (multiple-value-bind (stream socket) (egress-test-client port)
             (unwind-protect
                  (is (= 403 (egress-test-request-with stream "api.example.test" "/x"
                                                       `(("Authorization" . ,(format nil "Bearer ~A" +test-stand-in-a+))))))
               (ignore-errors (sb-bsd-sockets:socket-close socket)))))
      (funcall stop))))

;;; Asking the user (podster-3zu0): a name an asked run's policy refuses is answered
;;; with a reserved address, never looked up, and its connection is held while the user
;;; decides.

(test an-asked-runs-refused-name-gets-an-address-and-is-not-looked-up
  (let* ((resolved '())
         (table (gr8s.network::make-egress-name-table
                 :resolve (lambda (name) (push name resolved) (values '("160.79.104.10") 300 0))))
         (patterns '("api.anthropic.com")))
    (flet ((answer (name &optional (qtype 1))
             (gr8s.controllers::egress-dns-gate-answer
              (egress-dns-query name qtype) patterns (lambda (packet) packet)
              :synthesize (lambda (name) (gr8s.network::egress-name-answer table name))
              :reserve (lambda (name) (gr8s.network::egress-name-reserve table name)))))
      (let* ((packet (answer "pypi.org"))
             (records (0conf:dns-message-answers (0conf:decode-message packet)))
             (address (and records (format nil "~{~D~^.~}" (coerce (0conf:a-address (first records)) 'list)))))
        (is (= 0 (cl-dns-proxy:dns-response-code packet)))
        (is-true (and address (gr8s.network::egress-synthetic-address-p address)))
        (is (= gr8s.network::+egress-ask-ttl+ (0conf:rr-ttl (first records))))
        ;; The address stands for the name, which no one has looked up yet.
        (is (equal "pypi.org" (gr8s.network::egress-name-at table address)))
        (is (null resolved)))
      ;; Its other record types get no data, as an allowed name's do.
      (is (null (0conf:dns-message-answers (0conf:decode-message (answer "pypi.org" 28)))))
      ;; An allowed name is answered and looked up as before.
      (is (= 0 (cl-dns-proxy:dns-response-code (answer "api.anthropic.com"))))
      (is (equal '("api.anthropic.com") resolved)))))

(defun egress-asking-proxy (decide &key (seconds 2) refused)
  "A proxy whose DECIDE is given, asking its user for up to SECONDS, recording pending reports."
  (let ((pending '()))
    (values (gr8s.controllers::make-egress-proxy
             :decide decide :ask-seconds seconds :refused refused
             :pending (lambda (peer host port) (push (list peer host port) pending)))
            (lambda () pending))))

(test a-held-connection-waits-for-the-users-answer
  ;; Allowed as soon as a rule of the run's policy names the host. Until then the
  ;; decision by name falls through to the default, allowed with no rule, which counts
  ;; for nothing: a sandbox's deny-all rule matches addresses, not names.
  (let ((calls 0))
    (multiple-value-bind (proxy pending)
        (egress-asking-proxy (lambda (peer host address port)
                               (declare (ignore peer address port))
                               (if (and (equal host "pypi.org") (> (incf calls) 3))
                                   (values t "gr8-allow")
                                   (values t nil))))
      (is-true (gr8s.controllers::egress-await-approval proxy "10.80.0.5" "pypi.org" 443 :interval 0.05))
      (is (equal '(("10.80.0.5" "pypi.org" 443)) (funcall pending)))))
  ;; A host a rule allows already isn't held, nor reported.
  (multiple-value-bind (proxy pending) (egress-asking-proxy (lambda (&rest arguments) (declare (ignore arguments))
                                                              (values t "gr8-allow")))
    (is-true (gr8s.controllers::egress-await-approval proxy "10.80.0.5" "api.anthropic.com" 443 :interval 0.05))
    (is (null (funcall pending))))
  ;; The user's no, a label on the run's Pod, refuses it at once.
  (let ((calls 0) (start (get-internal-real-time)))
    (multiple-value-bind (proxy pending)
        (egress-asking-proxy (lambda (&rest arguments) (declare (ignore arguments)) (values nil "gr8-sandbox"))
                             :seconds 30
                             :refused (lambda (peer host) (declare (ignore peer))
                                        (and (equal host "pypi.org") (> (incf calls) 2))))
      (is-false (gr8s.controllers::egress-await-approval proxy "10.80.0.5" "pypi.org" 443 :interval 0.05))
      (is (< (- (get-internal-real-time) start) (* 5 internal-time-units-per-second)))
      (is (= 1 (length (funcall pending))))))
  ;; No answer: refused when the user has had their time.
  (multiple-value-bind (proxy) (egress-asking-proxy (lambda (&rest arguments) (declare (ignore arguments)) nil)
                                                    :seconds 1)
    (is-false (gr8s.controllers::egress-await-approval proxy "10.80.0.5" "pypi.org" 443 :interval 0.05))))

(test the-users-no-is-a-label-any-host-name-fits-in
  (let ((label (gr8s.agent::gr8-refuse-label "PyPI.org")))
    (is (equal label (gr8s.agent::gr8-refuse-label "pypi.org")))
    (is (equal "gr8s.io/refuse-" (subseq label 0 15)))
    (is (= 16 (- (length label) 15)))
    (is (string/= label (gr8s.agent::gr8-refuse-label "files.pythonhosted.org")))
    ;; gr8 computes the same label (gr8/internal/client RefuseLabel).
    (is (equal "gr8s.io/refuse-a379a6f6eeafb9a5" (gr8s.agent::gr8-refuse-label "example.com")))))
