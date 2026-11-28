;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; The node egress proxy (podster-wv1w.2, docs/design-agent-egress.md). A Pod whose
;;;; egress ClusterNetworkPolicy names domains has its outbound TCP redirected here
;;;; by the socket load balancer's connect hook, which keeps the original port, and
;;;; an sk_lookup program hands every port on the proxy address to this one listener.
;;;;
;;;; The proxy learns where the connection was going from what the client says, not
;;;; from the address it dialled: the TLS ClientHello's SNI, or for cleartext the
;;;; HTTP Host header. Hosts behind shared CDN addresses can't be told apart by IP,
;;;; so a name is the only sound thing to admit. It resolves the name itself, asks
;;;; the Pod's tiers about the name, the address it will connect to and the port
;;;; (EGRESS-CONNECTION-VERDICT), and then splices bytes or closes. A connection that
;;;; names nothing can't be admitted by name.
;;;;
;;;; A gr8 sandbox's connections are inspected (podster-wv1w.11): its TLS is terminated
;;;; with a leaf the egress CA signs and its HTTP relayed request by request, each one
;;;; reported, unless its SandboxProfile asks for passthrough. Rules a request breaks
;;;; refuse it under Enforce, and are only reported under Audit.
;;;;
;;;; Not defended here: a client that sends an allowed SNI and then a different Host
;;;; inside TLS (domain fronting) reaches whatever the allowed server routes that
;;;; Host to. Hosts that carry an injected credential are terminated instead
;;;; (podster-wv1w.3), which checks the Host too.
;;;;
;;;; A Pod with a hostname allowlist dials synthetic addresses instead (podster-wv1w.8,
;;;; egress-names.lisp), and for those the address names the destination: the proxy
;;;; admits the connection by the name it stands for, whatever protocol follows, dials
;;;; only the addresses pinned when the name was answered, and checks a TLS client's
;;;; SNI against the name rather than trusting it.

(in-package #:gr8s.controllers)

(defparameter +egress-ask-seconds+ 60
  "How long a connection to a name the user is asked about waits for their answer.")

(defstruct egress-proxy
  socket thread (stop nil) address port
  decide    ; (peer-address host address port) -> (values allowed-p rule-name)
  resolve   ; (host) -> an address string, or NIL
  connect   ; (address port) -> a connected socket, or NIL
  report    ; (peer-address host address port allowed-p rule &optional program audit), or NIL
  inject    ; (peer-address host scheme) -> NIL, or a request matcher for EGRESS-RELAY-HTTP
  inspect   ; (peer-address host) -> NIL, or (:enforcement :enforce|:audit) to terminate and relay
  bindings  ; (peer-address) -> the hosts the Pod's credentials are bound to, for explaining a refusal
  binaries  ; (peer-address peer-port host) -> (values allowed-p reason executables enforcement), or NIL
  mint      ; (host) -> (values certificate-chain key) for the egress CA's leaf, or NIL
  request-report  ; (peer-address host address port method path code rule-name &optional audit), or NIL
  (upstream-verify pure-tls:+verify-required+) ; how an injected connection checks its upstream
  names     ; the egress-name-table synthetic addresses are looked up in, or NIL
  dialed    ; (client-socket) -> (values address port) the client dialled
  ask       ; (peer-address) -> true when the Pod's user is asked about a refused name, or NIL
  refused   ; (peer-address host) -> true once that user has said no to HOST, or NIL
  pending   ; (peer-address host port) -> reports a connection held for the user to decide, or NIL
  (ask-seconds +egress-ask-seconds+)) ; how long a held connection waits for that

(defparameter +egress-proxy-head-limit+ 16384
  "The most of a cleartext request head the proxy reads looking for its Host.")

(defun egress-http-host (head)
  "The host an HTTP/1.x request HEAD (octets) names in its Host header, lowercased and
without a port, or NIL when it has none."
  (let* ((text (ignore-errors (trivial-utf-8:utf-8-bytes-to-string head)))
         (lines (and text (cl-ppcre:split "\\r?\\n" text))))
    (loop for line in (rest lines)
          for colon = (position #\: line)
          when (and colon (string-equal "host" (string-trim " " (subseq line 0 colon))))
            do (let ((value (string-trim " " (subseq line (1+ colon)))))
                 (return (string-downcase
                          (if (and (plusp (length value)) (char= (char value 0) #\[))
                              (subseq value 0 (1+ (or (position #\] value) (1- (length value)))))
                              (subseq value 0 (or (position #\: value) (length value))))))))))

(defun %egress-read-http-head (socket first)
  "Read from SOCKET, after the already-read octet FIRST, through the end of the request
head (a blank line) or the limit. Returns the octets read."
  (let ((head (make-array 1 :element-type '(unsigned-byte 8) :adjustable t :fill-pointer 1
                            :initial-element first))
        (buffer (make-array 1024 :element-type '(unsigned-byte 8))))
    (loop
      (when (or (>= (length head) +egress-proxy-head-limit+)
                (search #(13 10 13 10) head) (search #(10 10) head))
        (return))
      (multiple-value-bind (b n) (sb-bsd-sockets:socket-receive socket buffer nil)
        (declare (ignore b))
        (when (or (null n) (zerop n)) (return))
        (loop for i below n do (vector-push-extend (aref buffer i) head))))
    (coerce head '(simple-array (unsigned-byte 8) (*)))))

(defun egress-client-destination (socket)
  "Read enough of SOCKET's first bytes to name its destination. Returns (values host
prefix): HOST from the TLS SNI or HTTP Host, or NIL; PREFIX the octets read, to replay
upstream."
  (let ((first (make-array 1 :element-type '(unsigned-byte 8))))
    (multiple-value-bind (b n) (sb-bsd-sockets:socket-receive socket first 1 :waitall t)
      (declare (ignore b))
      (cond ((not (eql n 1)) (values nil nil))
            ((= (aref first 0) 22)
             ;; A TLS record: read the rest of the ClientHello record.
             (let ((header (make-array 4 :element-type '(unsigned-byte 8))))
               (multiple-value-bind (b2 n2) (sb-bsd-sockets:socket-receive socket header 4 :waitall t)
                 (declare (ignore b2))
                 (if (not (eql n2 4))
                     (values nil first)
                     (let* ((length (logior (ash (aref header 2) 8) (aref header 3)))
                            (body (make-array length :element-type '(unsigned-byte 8))))
                       (multiple-value-bind (b3 n3) (sb-bsd-sockets:socket-receive socket body length :waitall t)
                         (declare (ignore b3))
                         (let ((record (concatenate '(simple-array (unsigned-byte 8) (*))
                                                    first header (subseq body 0 (or n3 0)))))
                           (values (let ((sni (ignore-errors (parse-tls-client-hello-sni record))))
                                     (and sni (string-downcase sni)))
                                   record))))))))
            (t (let ((head (%egress-read-http-head socket (aref first 0))))
                 (values (egress-http-host head) head)))))))

(defun egress-default-resolve (host)
  "Resolve HOST to its first IPv4 address with the node's resolver, or NIL."
  (ignore-errors
   (let ((address (sb-bsd-sockets:host-ent-address (sb-bsd-sockets:get-host-by-name host))))
     (format nil "~{~D~^.~}" (coerce address 'list)))))

(defun egress-default-connect (address port)
  "Open a TCP connection to ADDRESS:PORT, or NIL."
  (ignore-errors
   (let ((socket (make-instance 'sb-bsd-sockets:inet-socket :type :stream :protocol :tcp)))
     (handler-case (progn (sb-bsd-sockets:socket-connect socket (sb-bsd-sockets:make-inet-address address) port)
                          socket)
       (error () (ignore-errors (sb-bsd-sockets:socket-close socket)) nil)))))

(defun egress-default-dialed (client)
  "The address and port CLIENT dialled: its accepted socket's own, which the steering
leaves as the client asked."
  (multiple-value-bind (octets port) (sb-bsd-sockets:socket-name client)
    (values (format nil "~{~D~^.~}" (coerce octets 'list)) port)))

(defun egress-proxy-handle (proxy client)
  "Decide and serve one captured connection CLIENT."
  (let ((upstream nil))
    (unwind-protect
         (multiple-value-bind (peer-octets) (sb-bsd-sockets:socket-peername client)
           (multiple-value-bind (dialed port) (funcall (egress-proxy-dialed proxy) client)
             (let ((peer (format nil "~{~D~^.~}" (coerce peer-octets 'list))))
               (when (and (egress-proxy-names proxy) (gr8s.network::egress-synthetic-address-p dialed))
                 (egress-proxy-handle-synthetic proxy client peer dialed port)
                 (return-from egress-proxy-handle))
               (multiple-value-bind (host prefix) (egress-client-destination client)
                 ;; A name the client looked up elsewhere, and dialled by its address, is
                 ;; asked about too (podster-3zu0): held, before it is looked up here,
                 ;; unless policy allows it by name or by the address dialled.
                 (when (and host (egress-proxy-ask proxy) (funcall (egress-proxy-ask proxy) peer)
                            (not (funcall (egress-proxy-decide proxy) peer host dialed port)))
                   (multiple-value-bind (approved rule) (egress-await-approval proxy peer host port)
                     (unless approved
                       (when (egress-proxy-report proxy)
                         (ignore-errors (funcall (egress-proxy-report proxy) peer host dialed port nil rule)))
                       (return-from egress-proxy-handle))))
                 (let ((address (and host (funcall (egress-proxy-resolve proxy) host))))
                   (multiple-value-bind (allowed rule) (funcall (egress-proxy-decide proxy) peer host address port)
                     (setf allowed (and allowed address t))
                     (multiple-value-bind (permitted reason program audit)
                         (if allowed (egress-binary-check proxy client peer host) t)
                       (unless permitted (setf allowed nil rule reason))
                       (when (egress-proxy-report proxy)
                         (ignore-errors (funcall (egress-proxy-report proxy) peer host address port allowed rule
                                                 program audit))))
                     (when allowed
                       (let* ((tls (and prefix (plusp (length prefix)) (= (aref prefix 0) 22)))
                              (matcher (and (egress-proxy-inject proxy)
                                            (funcall (egress-proxy-inject proxy) peer host (if tls "https" "http")))))
                         (when matcher
                           (egress-proxy-relay proxy client peer host address port prefix tls matcher)
                           (return-from egress-proxy-handle))
                         (setf upstream (funcall (egress-proxy-connect proxy) address port))
                         (when upstream
                           (egress-splice client upstream prefix))))))))))
      (ignore-errors (sb-bsd-sockets:socket-close client))
      (when upstream (ignore-errors (sb-bsd-sockets:socket-close upstream))))))

(defun egress-splice (client upstream prefix)
  "Splice CLIENT and UPSTREAM until either ends, sending PREFIX, read from CLIENT, first."
  (let ((closed nil))
    (flet ((close-both ()
             (unless closed
               (setf closed t)
               (ignore-errors (sb-bsd-sockets:socket-close client))
               (ignore-errors (sb-bsd-sockets:socket-close upstream)))))
      (l4-splice client upstream #'close-both prefix (length prefix)))))

(sb-alien:define-alien-routine ("poll" %egress-poll) sb-alien:int
  (fds (* (sb-alien:unsigned 32))) (count sb-alien:unsigned-long) (timeout sb-alien:int))

(defun egress-first-readable (first second)
  "Wait until socket FIRST or SECOND has input or has closed. Returns :first or :second,
or NIL when the wait fails."
  ;; Two struct pollfd {int fd; short events; short revents}, events POLLIN.
  (sb-alien:with-alien ((fds (array (sb-alien:unsigned 32) 4)))
    (setf (sb-alien:deref fds 0) (sb-bsd-sockets:socket-file-descriptor first) (sb-alien:deref fds 1) 1
          (sb-alien:deref fds 2) (sb-bsd-sockets:socket-file-descriptor second) (sb-alien:deref fds 3) 1)
    (loop
      (let ((ready (%egress-poll (sb-alien:addr (sb-alien:deref fds 0)) 2 -1)))
        (cond ((plusp ready) (return (if (plusp (ash (sb-alien:deref fds 1) -16)) :first :second)))
              ((/= (sb-alien:get-errno) sb-unix:eintr) (return nil)))))))

(defun egress-synthetic-verdict (proxy peer host addresses port)
  "Decide the Pod at PEER's connection to HOST on PORT against each of HOST's pinned
ADDRESSES in turn. Returns (values address rule allowed-p): the first address the policy
admits, or the first address and its refusing rule."
  (let ((first-rule nil))
    (dolist (address addresses (values (first addresses) first-rule nil))
      (multiple-value-bind (allowed rule) (funcall (egress-proxy-decide proxy) peer host address port)
        (when allowed (return (values address rule t)))
        (unless first-rule (setf first-rule rule))))))

(defun egress-binary-check (proxy client peer host)
  "Ask PROXY's binaries hook (podster-wv1w.13) whether the program behind CLIENT, from
PEER, may reach HOST, which policy allows. Returns (values permitted reason program
audit): PROGRAM the one that opened it, and under Audit a refusal is AUDIT instead."
  (let ((hook (egress-proxy-binaries proxy)))
    (if (null hook)
        t
        (multiple-value-bind (allowed reason executables enforcement)
            (funcall hook peer (nth-value 1 (ignore-errors (sb-bsd-sockets:socket-peername client))) host)
          (cond (allowed (values t nil (first executables)))
                ((eq enforcement :audit) (values t nil (first executables) reason))
                (t (values nil reason (first executables))))))))

(defun egress-await-approval (proxy peer host port &key (interval 0.5))
  "Whether the Pod at PEER, whose user PROXY asks, may reach HOST on PORT (podster-3zu0):
at once when a rule allows it by name; otherwise report the connection held, and wait,
deciding it again by name, until a rule allows it, the user says no (PROXY's refused),
or they have had PROXY's ask-seconds. Returns (values allowed-p rule). Decided without
an address, a sandbox's deny-all rule, which matches addresses, doesn't apply, so only
an Accept rule naming HOST counts, never the default."
  (multiple-value-bind (allowed rule) (funcall (egress-proxy-decide proxy) peer host nil port)
    (when (and allowed rule) (return-from egress-await-approval (values t rule)))
    (when (egress-proxy-pending proxy)
      (ignore-errors (funcall (egress-proxy-pending proxy) peer host port)))
    (loop with deadline = (+ (get-internal-real-time)
                             (* (egress-proxy-ask-seconds proxy) internal-time-units-per-second))
          until (or (egress-proxy-stop proxy) (> (get-internal-real-time) deadline)
                    (and (egress-proxy-refused proxy) (funcall (egress-proxy-refused proxy) peer host)))
          do (sleep interval)
             (multiple-value-setq (allowed rule) (funcall (egress-proxy-decide proxy) peer host nil port))
             (when (and allowed rule) (return-from egress-await-approval (values t rule))))
    (values nil rule)))

(defun egress-proxy-handle-synthetic (proxy client peer dialed port)
  "Serve CLIENT, which dialled the synthetic address DIALED on PORT: decide it by the name
DIALED stands for, and dial one of that name's pinned addresses, never resolving the name
again. A client that speaks first and names another host in its TLS SNI is refused. For
a Pod whose user is asked, a name policy refuses is held until they decide (podster-3zu0)
and only then looked up."
  (let ((asked (and (egress-proxy-ask proxy) (egress-proxy-names proxy)
                    (gr8s.network::egress-name-at (egress-proxy-names proxy) dialed))))
    (when (and asked (funcall (egress-proxy-ask proxy) peer))
      (multiple-value-bind (allowed rule) (egress-await-approval proxy peer asked port)
        (unless allowed
          (when (egress-proxy-report proxy)
            (ignore-errors (funcall (egress-proxy-report proxy) peer asked nil port nil rule)))
          (return-from egress-proxy-handle-synthetic nil)))))
  (multiple-value-bind (host addresses)
      (gr8s.network::egress-name-for-connect (egress-proxy-names proxy) dialed)
    (multiple-value-bind (address rule allowed) (and host (egress-synthetic-verdict proxy peer host addresses port))
      (let ((program nil) (audit nil))
       (flet ((report (allowed)
               (when (egress-proxy-report proxy)
                 (ignore-errors (funcall (egress-proxy-report proxy) peer host address port allowed rule program audit)))
               allowed))
        (unless allowed (return-from egress-proxy-handle-synthetic (report nil)))
        ;; Policy allows the name; the program that dialled it may still not be one
        ;; that may (podster-wv1w.13).
        (multiple-value-bind (permitted reason exe audited) (egress-binary-check proxy client peer host)
          (setf program exe audit audited)
          (unless permitted
            (setf rule reason)
            (return-from egress-proxy-handle-synthetic (report nil))))
        (let ((inject (egress-proxy-inject proxy))
              (inspection (and (egress-proxy-inspect proxy) (funcall (egress-proxy-inspect proxy) peer host)))
              (upstream nil))
          (flet ((relay (prefix tls matcher)
                   (report t)
                   (egress-proxy-relay proxy client peer host address port prefix tls matcher
                                       :upstream-socket (shiftf upstream nil)
                                       :enforcement (getf inspection :enforcement :enforce))))
            (unwind-protect
                 (if (and inject (or (funcall inject peer host "https") (funcall inject peer host "http")))
                     ;; A host that may carry a credential speaks HTTP, so its client speaks first.
                     (multiple-value-bind (named prefix) (egress-client-destination client)
                       (let* ((tls (egress-tls-prefix-p prefix))
                              (matcher (funcall inject peer host (if tls "https" "http"))))
                         (cond ((and tls named (string/= named host)) (report nil))
                               ((or matcher (and inspection (or tls (egress-http-request-p prefix))))
                                (relay prefix tls matcher))
                               ((setf upstream (funcall (egress-proxy-connect proxy) address port))
                                (report t)
                                (egress-splice client upstream prefix))
                               (t (report nil)))))
                     (progn
                       (setf upstream (funcall (egress-proxy-connect proxy) address port))
                       (cond ((null upstream) (report nil))
                             ;; Whoever speaks first: a server's greeting is relayed as it
                             ;; comes; a client's first bytes are read, for their SNI.
                             ((eq (egress-first-readable client upstream) :first)
                              (multiple-value-bind (named prefix) (egress-client-destination client)
                                (let ((tls (egress-tls-prefix-p prefix)))
                                  (cond ((and tls named (string/= named host)) (report nil))
                                        ((and inspection (or tls (egress-http-request-p prefix)))
                                         (relay prefix tls nil))
                                        (t (report t) (egress-splice client upstream (or prefix #())))))))
                             (t (report t) (egress-splice client upstream #())))))
              (when upstream (ignore-errors (sb-bsd-sockets:socket-close upstream)))))))))))

(defun egress-tls-prefix-p (prefix)
  "True when PREFIX, a client's first bytes, begins a TLS record."
  (and prefix (plusp (length prefix)) (= (aref prefix 0) 22)))

(defun egress-http-request-p (prefix)
  "True when PREFIX, a client's first bytes, begins an HTTP/1.x request line."
  (and prefix (plusp (length prefix))
       (let ((space (position 32 prefix :end (min (length prefix) 16))))
         (and space (plusp space)
              (every (lambda (byte) (<= 65 byte 90)) (subseq prefix 0 space))))))

(defun start-egress-proxy (&key (address "127.0.0.1") (port 0) decide
                                (resolve #'egress-default-resolve) (connect #'egress-default-connect) report
                                inject inspect bindings binaries mint request-report (upstream-verify pure-tls:+verify-required+)
                                names dialed ask refused pending (ask-seconds +egress-ask-seconds+))
  "Listen on ADDRESS:PORT and serve captured connections, one thread each. DECIDE, RESOLVE,
CONNECT, REPORT, INSPECT, NAMES, DIALED, ASK, REFUSED and PENDING are as EGRESS-PROXY documents. Returns the EGRESS-PROXY;
its PORT is the bound port (the kernel's choice when PORT is 0)."
  (let ((socket (make-instance 'sb-bsd-sockets:inet-socket :type :stream :protocol :tcp)))
    (setf (sb-bsd-sockets:sockopt-reuse-address socket) t)
    (sb-bsd-sockets:socket-bind socket (sb-bsd-sockets:make-inet-address address) port)
    (sb-bsd-sockets:socket-listen socket 128)
    (let ((proxy (make-egress-proxy :socket socket :address address
                                    :port (nth-value 1 (sb-bsd-sockets:socket-name socket))
                                    :decide decide :resolve resolve :connect connect :report report
                                    :inject inject :inspect inspect :bindings bindings :binaries binaries :mint mint
                                    :request-report request-report
                                    :upstream-verify upstream-verify
                                    :names names :dialed (or dialed #'egress-default-dialed)
                                    :ask ask :refused refused :pending pending :ask-seconds ask-seconds)))
      (setf (egress-proxy-thread proxy)
            (bt:make-thread
             (lambda ()
               (loop
                 (when (egress-proxy-stop proxy) (return))
                 (handler-case
                     (let ((client (sb-bsd-sockets:socket-accept socket)))
                       (if (egress-proxy-stop proxy)
                           (ignore-errors (sb-bsd-sockets:socket-close client))
                           (when client
                             ;; One connection's failure, an unreachable upstream say,
                             ;; ends that connection, not the agent.
                             (bt:make-thread (lambda ()
                                               (handler-case (egress-proxy-handle proxy client)
                                                 (error (condition)
                                                   (format *error-output* "gr8s egress proxy connection failed: ~A~%"
                                                           condition)
                                                   (ignore-errors (sb-bsd-sockets:socket-close client)))))
                                             :name "gr8s egress proxy conn"))))
                   (error () (when (egress-proxy-stop proxy) (return))))))
             :name "gr8s egress proxy accept"))
      proxy)))

(defun stop-egress-proxy (proxy)
  "Stop PROXY's accept loop and close its listening socket. Best-effort; NIL is a no-op."
  (when proxy
    (setf (egress-proxy-stop proxy) t)
    (ignore-errors
     (let ((waker (make-instance 'sb-bsd-sockets:inet-socket :type :stream :protocol :tcp)))
       (unwind-protect
            (sb-bsd-sockets:socket-connect waker (sb-bsd-sockets:make-inet-address (egress-proxy-address proxy))
                                           (egress-proxy-port proxy))
         (ignore-errors (sb-bsd-sockets:socket-close waker)))))
    (ignore-errors
     (when (and (egress-proxy-thread proxy) (bt:thread-alive-p (egress-proxy-thread proxy)))
       (bt:join-thread (egress-proxy-thread proxy))))
    (ignore-errors (sb-bsd-sockets:socket-close (egress-proxy-socket proxy)))))

;;; ---------------------------------------------------------------------------
;;; Steering: every TCP connection to the proxy address, whatever its port, goes to
;;; the one listener, which then knows the port the client asked for. So does every
;;; connection to a synthetic address (podster-wv1w.8), which the node delivers locally:
;;; the listener's accepted socket then also says which address was dialled.

(defparameter *egress-steering-map-forms*
  '((whistler:defmap egress-listener-sock
      :type :sockhash :key-size 4 :value-size 4 :max-entries 1)))

(defparameter *egress-steering-prog-forms*
  '((whistler:defprog egress-sk-lookup
        (:type :sk-lookup :section "sk_lookup" :license "GPL")
      ;; 169.254.1.2 in network order, whose port 53 is the egress DNS gate's own; and
      ;; 198.18.0.0/15, the synthetic range, on every port.
      (when (and (= (ctx protocol) 6)
                 (or (and (= (ctx local-ip4) #x0201fea9) (/= (ctx local-port) 53))
                     (= (logand (ctx local-ip4) #xfeff) #x12c6)))
        (let ((sk (map-lookup egress-listener-sock 0)))
          (when (/= sk 0)
            (sk-assign (ctx-ptr) sk 0)
            (sk-release sk))))
      SK_PASS)))

(defstruct egress-steering sockmap prog-fd attachment)

(defun start-egress-steering (listener-fd &key (netns-path "/proc/self/ns/net"))
  "Load and attach the sk_lookup program handing every port on the proxy address to
LISTENER-FD. Signals on failure."
  (multiple-value-bind (map-specs prog-specs)
      (whistler/loader::compile-bpf-forms *egress-steering-map-forms* *egress-steering-prog-forms*)
    (let* ((maps (whistler/loader::session-create-maps map-specs))
           (progs (whistler/loader::session-load-progs prog-specs maps))
           (sockmap (cdr (first maps)))
           (prog-fd (whistler/loader:prog-info-fd (cdr (first progs)))))
      (whistler/loader:map-update-int sockmap 0 listener-fd)
      (make-egress-steering :sockmap sockmap :prog-fd prog-fd
                            :attachment (whistler/loader:attach-sk-lookup prog-fd :netns-path netns-path)))))

(defun stop-egress-steering (steering)
  "Detach and close STEERING. Best-effort; NIL is a no-op."
  (when steering
    (ignore-errors (whistler/loader:detach (egress-steering-attachment steering)))
    (ignore-errors (sb-posix:close (egress-steering-prog-fd steering)))
    (ignore-errors (sb-posix:close (whistler/loader:map-info-fd (egress-steering-sockmap steering))))))

(defun egress-flow-object (peer host address port allowed rule &optional program audit)
  "The flow event for one proxied connection from the Pod at PEER to HOST (ADDRESS) on
PORT: forwarded, or dropped by policy with the deciding RULE's name (or why, for a
program a binaries rule refused), naming the PROGRAM that opened it and, under Audit,
the rule it broke."
  (let ((flow (core-object "verdict" (if allowed "FORWARDED" "DROPPED")
                           "direction" "egress" "protocol" "TCP"
                           "podAddress" peer
                           "peerAddress" (or address "")
                           "peerPort" port
                           "l7" (core-object "type" "egress" "host" (or host "")))))
    ;; The Network view draws a site by the name the Pod asked for.
    (when host (setf (gethash "peerName" flow) host))
    (unless allowed (setf (gethash "reason" flow) "POLICY"))
    (when rule (setf (gethash "rule" (gethash "l7" flow)) rule))
    (when program (setf (gethash "process" (gethash "l7" flow)) program))
    (when audit (setf (gethash "audit" (gethash "l7" flow)) audit))
    flow))

(defun egress-pending-flow-object (peer host port)
  "The flow event for the Pod at PEER's connection to HOST on PORT, which policy refuses
and the proxy holds while its user decides (podster-3zu0)."
  (core-object "verdict" "PENDING" "reason" "POLICY" "direction" "egress" "protocol" "TCP"
               "podAddress" peer "peerAddress" "" "peerPort" port "peerName" host
               "l7" (core-object "type" "egress" "host" host)))

(defun egress-request-flow-object (peer host address port method path code rule &optional audit)
  "The flow event for one request the proxy relayed from the Pod at PEER to HOST, naming
the SecurityProfile rule that injected a credential into it -- never the credential --
and, AUDIT, the rule it broke that Audit enforcement let through."
  (let ((flow (core-object "verdict" (if (and (integerp code) (< code 400)) "FORWARDED" "DROPPED")
                           "direction" "egress" "protocol" "TCP"
                           "podAddress" peer "peerAddress" (or address "") "peerPort" port
                           "l7" (core-object "type" "http" "method" (or method "") "host" host
                                             "path" (let ((path (or path "")))
                                                      (subseq path 0 (or (position #\? path) (length path))))
                                             "code" (or code 0))
                           "peerName" host)))
    (when rule (setf (gethash "injected" (gethash "l7" flow)) rule))
    (when audit (setf (gethash "audit" (gethash "l7" flow)) audit))
    flow))

(defun egress-verdict-reporter (report)
  "The proxy's REPORT: each connection verdict joins the flow stream (podster-5hv.11),
and REPORT, when given, sees it too."
  (lambda (peer host resolved port allowed rule &optional program audit)
    (when report
      (ignore-errors (funcall report peer host resolved port allowed rule)))
    (let ((sink *gateway-flow-sink*))
      (when sink
        (funcall sink (egress-flow-object peer host resolved port allowed
                                          (if (stringp rule) rule (and rule (gr8s.network::cnp-rule-name rule)))
                                          program audit))))))

(defun start-node-egress-proxy (decide patterns-for &key (address gr8s.network::+egress-proxy-address+) (port 15443)
                                                       inject inspect bindings binaries mint report ask refused
                                                       (upstreams (list (cons gr8s.network::+node-gateway-address+ 53))))
  "Start the node egress proxy on ADDRESS (put on the node gateway interface), steer every
port there and on the synthetic range to it, and serve the egress DNS gate on its port 53.
DECIDE is as EGRESS-PROXY documents; PATTERNS-FOR as START-EGRESS-DNS-GATE does. The gate
and the proxy share one table of synthetic addresses, whose names are looked up at the
node DNS server, UPSTREAMS. Returns (values proxy steering gate)."
  (gr8s.network::ensure-node-gateway (list gr8s.network::+node-gateway-address+ address))
  (handler-case (gr8s.network::ensure-egress-synthetic-route)
    (error (condition)
      (format *error-output* "gr8s: synthetic egress addresses won't reach the proxy: ~A~%" condition)))
  (let* ((names (gr8s.network::make-egress-name-table
                 :resolve (lambda (name)
                            (egress-upstream-a-records
                             name (lambda (packet) (cl-dns-proxy:forward-dns-udp packet upstreams 2.0))))))
         (proxy (start-egress-proxy
                :address address :port port :decide decide :inject inject :inspect inspect :bindings bindings
                :binaries binaries
                :mint mint :names names
                :ask ask :refused refused
                :pending (lambda (peer host port)
                           (let ((sink *gateway-flow-sink*))
                             (when sink (funcall sink (egress-pending-flow-object peer host port)))))
                :request-report (lambda (peer host resolved port method path code rule &optional audit)
                                  (let ((sink *gateway-flow-sink*))
                                    (when sink
                                      (funcall sink (egress-request-flow-object peer host resolved port method
                                                                                path code rule audit)))))
                :report (egress-verdict-reporter report))))
    (let ((steering nil))
      (handler-case
          (progn
            (setf steering (start-egress-steering
                            (sb-bsd-sockets:socket-file-descriptor (egress-proxy-socket proxy))))
            (values proxy steering
                    (start-egress-dns-gate :address address :port 53 :patterns-for patterns-for
                                           :names names :upstreams upstreams
                                           :report (lambda (client name allowed)
                                                     (let ((sink *gateway-flow-sink*))
                                                       (when sink
                                                         (funcall sink (egress-dns-flow-object client name allowed))))))))
        (error (condition)
          (stop-egress-steering steering)
          (stop-egress-proxy proxy)
          (error condition))))))

;;; ---------------------------------------------------------------------------
;;; The egress DNS gate. A captured Pod's DNS to the node gateway is redirected
;;; here (port 53 on the proxy address), where the querying Pod is known: the gate
;;; answers REFUSED for any name outside the cluster's own zone that the Pod's policy
;;; doesn't name, and relays the rest to the node DNS server. A query name is data
;;; leaving the node, so forwarding every name would leave a channel open.
;;;
;;; A Pod with a hostname allowlist is answered with synthetic addresses instead
;;; (podster-wv1w.8): an allowed name's A query gets the address that stands for it,
;;; any other type of query for it gets no data (an AAAA or HTTPS record would hand
;;; the client real addresses), and only the cluster's own names are relayed.

(defun egress-dns-cluster-name-p (name)
  "True when the DNS query NAME is in the cluster zone."
  (let ((name (string-downcase (string-right-trim "." name)))
        (zone gr8s.foundation::+dns-cluster-zone+))
    (or (string= name zone)
        (and (> (length name) (1+ (length zone)))
             (string= (concatenate 'string "." zone) name :start2 (- (length name) (1+ (length zone))))))))

(defun egress-dns-name-allowed-p (name patterns)
  "True when the DNS query NAME is in the cluster zone or matches one of PATTERNS
(domainNames patterns), or PATTERNS is :all."
  (or (eq patterns :all)
      (egress-dns-cluster-name-p name)
      (let ((name (string-downcase (string-right-trim "." name))))
        (some (lambda (pattern) (gr8s.network::egress-domain-matches-p pattern name)) patterns))))

(defun egress-dns-gate-answer (packet patterns forward &key synthesize reserve)
  "Answer DNS PACKET for a client allowed PATTERNS: relay it with FORWARD (packet ->
response) when every question is allowed, else REFUSED. With SYNTHESIZE, a function from
a name to (values address ttl) or (values NIL rcode), names outside the cluster zone are
answered with synthetic addresses rather than relayed. With RESERVE, the same for a name
PATTERNS don't allow but whose connection the proxy holds for the user to decide
(podster-3zu0): the address stands for the name, which isn't looked up."
  (let* ((query (ignore-errors (0conf:decode-message packet)))
         (questions (and query (0conf:dns-message-questions query))))
    (cond ((null query) nil)
          ((and reserve questions (null (rest questions))
                (not (egress-dns-name-allowed-p (0conf:question-name (first questions)) patterns)))
           (let ((question (first questions)))
             (if (/= (0conf:question-qtype question) 0conf:+type-a+)
                 (cl-dns-proxy::dns-authoritative-response query)
                 (multiple-value-bind (address ttl) (funcall reserve (0conf:question-name question))
                   (if address
                       (cl-dns-proxy::dns-authoritative-response
                        query :answers (list (make-instance '0conf:a-record
                                                            :name (0conf:question-name question)
                                                            :address (gr8s.network::ipv4-network-octets address)
                                                            :ttl ttl)))
                       (cl-dns-proxy::dns-authoritative-response query :rcode 5))))))
          ((not (and questions (every (lambda (question)
                                        (egress-dns-name-allowed-p (0conf:question-name question) patterns))
                                      questions)))
           (cl-dns-proxy::dns-authoritative-response query :rcode 5))
          ((or (null synthesize)
               (every (lambda (question) (egress-dns-cluster-name-p (0conf:question-name question))) questions))
           (funcall forward packet))
          ((rest questions) (cl-dns-proxy::dns-authoritative-response query :rcode 5))
          ((/= (0conf:question-qtype (first questions)) 0conf:+type-a+)
           (cl-dns-proxy::dns-authoritative-response query))
          (t
           (let ((question (first questions)))
             (multiple-value-bind (address ttl-or-rcode) (funcall synthesize (0conf:question-name question))
               (if address
                   (cl-dns-proxy::dns-authoritative-response
                    query :answers (list (make-instance '0conf:a-record
                                                        :name (0conf:question-name question)
                                                        :address (gr8s.network::ipv4-network-octets address)
                                                        :ttl ttl-or-rcode)))
                   (cl-dns-proxy::dns-authoritative-response query :rcode ttl-or-rcode))))))))

(defun egress-upstream-a-records (name forward)
  "Ask FORWARD (packet -> response) for NAME's A records. Returns (values addresses ttl
rcode), TTL the least the answers carry."
  (let* ((query (0conf:encode-message
                 (0conf:make-dns-message :id (random #x10000) :flags #x0100
                                         :questions (list (0conf:make-question :name name :qtype 0conf:+type-a+)))))
         (message (ignore-errors (0conf:decode-message (funcall forward query)))))
    (if (null message)
        (values nil 0 2)
        (let ((records (remove-if-not (lambda (record) (typep record '0conf:a-record))
                                      (0conf:dns-message-answers message))))
          (values (mapcar (lambda (record) (format nil "~{~D~^.~}" (coerce (0conf:a-address record) 'list))) records)
                  (if records (reduce #'min records :key #'0conf:rr-ttl) 0)
                  (logand #xf (0conf:dns-message-flags message)))))))

(defstruct egress-dns-gate udp tcp threads (stop nil))

(defun egress-dns-decisions (packet patterns)
  "Each question of DNS PACKET outside the cluster zone as (name . allowed-p) for a client
allowed PATTERNS, to report."
  (let ((query (ignore-errors (0conf:decode-message packet))))
    (loop for question in (and query (0conf:dns-message-questions query))
          for name = (string-downcase (string-right-trim "." (0conf:question-name question)))
          unless (egress-dns-cluster-name-p name)
            collect (cons name (egress-dns-name-allowed-p name patterns)))))

(defparameter +egress-dns-report-window+ 5
  "Seconds within which the DNS gate reports a Pod's lookup of a name, with the same
verdict, once: a resolver asks for A and AAAA and retries, which is one decision.")

(defun make-egress-dns-reporter (report &key (clock #'get-universal-time) (window +egress-dns-report-window+))
  "REPORT, (client name allowed-p), called once per decision: a repeat of the same
client, name and verdict within WINDOW seconds of the last report is folded into it."
  (let ((seen (make-hash-table :test #'equal)) (lock (bt:make-lock "gr8s egress DNS reports")))
    (lambda (client name allowed)
      (let ((now (funcall clock)) (key (list client name allowed)))
        (when (bt:with-lock-held (lock)
                (let ((last (gethash key seen)))
                  (when (> (hash-table-count seen) 4096)
                    ;; Forget what is past the window, so the table stays small.
                    (maphash (lambda (k time) (when (> (- now time) window) (remhash k seen))) seen))
                  (when (or (null last) (> (- now last) window))
                    (setf (gethash key seen) now))))
          (funcall report client name allowed))))))

(defun egress-dns-flow-object (peer name allowed)
  "The flow event for the Pod at PEER's DNS query for NAME, answered or refused by policy."
  (let ((flow (core-object "verdict" (if allowed "FORWARDED" "DROPPED")
                           "direction" "egress" "protocol" "UDP"
                           "podAddress" peer "peerAddress" gr8s.network::+egress-proxy-address+ "peerPort" 53
                           "l7" (core-object "type" "dns" "query" name)
                           "peerName" name)))
    (unless allowed (setf (gethash "reason" flow) "POLICY"))
    flow))

(defun start-egress-dns-gate (&key (address "127.0.0.1") (port 53) patterns-for names report
                                   (upstreams (list (cons gr8s.network::+node-gateway-address+ 53)))
                                   (timeout 2.0))
  "Serve DNS on ADDRESS:PORT over UDP and TCP. PATTERNS-FOR maps a client address to
(values patterns synthetic-p ask-p): the domain patterns it may resolve, or :all, whether
it is answered with synthetic addresses from the egress-name-table NAMES, and whether a
name it may not resolve is answered with a reserved one, for its user to decide. REPORT, when
given, is called with (client name allowed-p) for each question outside the cluster zone
of a client whose names policy decides, once per decision (MAKE-EGRESS-DNS-REPORTER).
Returns the EGRESS-DNS-GATE."
  (let* ((udp (make-instance 'sb-bsd-sockets:inet-socket :type :datagram :protocol :udp))
         (tcp (make-instance 'sb-bsd-sockets:inet-socket :type :stream :protocol :tcp))
         (gate (make-egress-dns-gate :udp udp :tcp tcp))
         (report (and report (make-egress-dns-reporter report))))
    (flet ((address-string (octets) (format nil "~{~D~^.~}" (coerce octets 'list)))
           (forward (packet) (cl-dns-proxy:forward-dns-udp packet upstreams timeout)))
      (labels ((answer (packet client forward)
                 (multiple-value-bind (patterns synthetic ask) (funcall patterns-for client)
                   (when (and report (not (eq patterns :all)))
                     (loop for (name . allowed) in (egress-dns-decisions packet patterns)
                           ;; An asked client's refused name isn't refused yet: its
                           ;; connection is held for its user to decide (podster-3zu0).
                           unless (and ask (not allowed) names)
                             do (ignore-errors (funcall report client name allowed))))
                   (egress-dns-gate-answer
                    packet patterns forward
                    :synthesize (and synthetic names
                                     (lambda (name) (gr8s.network::egress-name-answer names name)))
                    :reserve (and ask names
                                  (lambda (name) (gr8s.network::egress-name-reserve names name)))))))
      (setf (sb-bsd-sockets:sockopt-reuse-address udp) t
            (sb-bsd-sockets:sockopt-reuse-address tcp) t)
      (sb-bsd-sockets:socket-bind udp (sb-bsd-sockets:make-inet-address address) port)
      (sb-bsd-sockets:socket-bind tcp (sb-bsd-sockets:make-inet-address address)
                                  (nth-value 1 (sb-bsd-sockets:socket-name udp)))
      (sb-bsd-sockets:socket-listen tcp 32)
      (setf (egress-dns-gate-threads gate)
            (list
             (bt:make-thread
              (lambda ()
                (let ((buffer (make-array #xffff :element-type '(unsigned-byte 8))))
                  (loop until (egress-dns-gate-stop gate)
                        do (handler-case
                               (when (sb-sys:wait-until-fd-usable (sb-bsd-sockets:socket-file-descriptor udp) :input 0.2)
                                 (multiple-value-bind (b size host client-port) (sb-bsd-sockets:socket-receive udp buffer nil)
                                   (declare (ignore b))
                                   (let ((response (answer (subseq buffer 0 size) (address-string host) #'forward)))
                                     (when response
                                       (sb-bsd-sockets:socket-send udp response (length response)
                                                                   :address (list host client-port))))))
                             (error () nil)))))
              :name "gr8s egress DNS gate udp")
             (bt:make-thread
              (lambda ()
                (loop until (egress-dns-gate-stop gate)
                      do (handler-case
                             (let ((client (sb-bsd-sockets:socket-accept tcp)))
                               (when client
                                 (bt:make-thread
                                  (lambda ()
                                    (let ((stream (sb-bsd-sockets:socket-make-stream
                                                   client :input t :output t :element-type '(unsigned-byte 8)
                                                          :buffering :none)))
                                      (unwind-protect
                                           (let ((packet (cl-dns-proxy::read-dns-frame stream)))
                                             (when packet
                                               (let ((response (answer
                                                                packet
                                                                (address-string (sb-bsd-sockets:socket-peername client))
                                                                (lambda (packet)
                                                                  (cl-dns-proxy:forward-dns-tcp packet upstreams timeout)))))
                                                 (when response (cl-dns-proxy::write-dns-frame stream response)))))
                                        (ignore-errors (close stream))
                                        (ignore-errors (sb-bsd-sockets:socket-close client)))))
                                  :name "gr8s egress DNS gate tcp conn")))
                           (error () nil))))
              :name "gr8s egress DNS gate tcp"))))
      gate)))

(defun egress-dns-gate-port (gate)
  (nth-value 1 (sb-bsd-sockets:socket-name (egress-dns-gate-udp gate))))

(defun stop-egress-dns-gate (gate)
  "Stop GATE's threads and close its sockets. Best-effort; NIL is a no-op."
  (when gate
    (setf (egress-dns-gate-stop gate) t)
    (ignore-errors
     (let ((waker (make-instance 'sb-bsd-sockets:inet-socket :type :stream :protocol :tcp)))
       (unwind-protect
            (sb-bsd-sockets:socket-connect waker (sb-bsd-sockets:socket-name (egress-dns-gate-tcp gate))
                                           (egress-dns-gate-port gate))
         (ignore-errors (sb-bsd-sockets:socket-close waker)))))
    (dolist (thread (egress-dns-gate-threads gate))
      (ignore-errors (bt:join-thread thread)))
    (ignore-errors (sb-bsd-sockets:socket-close (egress-dns-gate-udp gate)))
    (ignore-errors (sb-bsd-sockets:socket-close (egress-dns-gate-tcp gate)))))

;;; ---------------------------------------------------------------------------
;;; Credential injection (podster-wv1w.3). For a host a SecurityProfile selecting
;;; the Pod names, the proxy terminates the Pod's TLS with a leaf the egress CA
;;; signs, relays HTTP/1.1 request by request, and on each request a rule matches
;;; overwrites the rule's headers with the credential. Upstream it is an ordinary
;;; verifying TLS client. A request whose Host isn't the host its TLS named is
;;; refused (421), so an allowed name can't front for another site; a request whose
;;; credential can't be found is refused (403) rather than sent without it.

(defparameter +egress-http-head-limit+ (* 64 1024))

(defun egress-read-http-head (stream)
  "Read one HTTP/1.x message head from STREAM through its blank line. Returns the octets,
or NIL at end of stream. Signals past the head limit."
  (let ((head (make-array 256 :element-type '(unsigned-byte 8) :adjustable t :fill-pointer 0)))
    (loop for byte = (read-byte stream nil nil)
          do (cond ((null byte) (return (when (plusp (length head)) (coerce head '(simple-array (unsigned-byte 8) (*))))))
                   (t (vector-push-extend byte head)
                      (when (> (length head) +egress-http-head-limit+) (error "HTTP head too large"))
                      (let ((n (length head)))
                        (when (and (>= n 4) (= (aref head (- n 1)) 10) (= (aref head (- n 2)) 13)
                                   (= (aref head (- n 3)) 10) (= (aref head (- n 4)) 13))
                          (return (coerce head '(simple-array (unsigned-byte 8) (*)))))))))))

(defun egress-parse-http-head (octets)
  "(values start-line headers), HEADERS a list of (name . value) in order."
  (let* ((lines (cl-ppcre:split "\\r\\n" (babel:octets-to-string octets :encoding :latin-1))))
    (values (first lines)
            (loop for line in (rest lines)
                  for colon = (position #\: line)
                  when (and colon (plusp colon))
                    collect (cons (subseq line 0 colon) (string-trim " " (subseq line (1+ colon))))))))

(defun egress-http-head-octets (start-line headers)
  (babel:string-to-octets
   (with-output-to-string (out)
     (format out "~A~C~C" start-line #\Return #\Newline)
     (loop for (name . value) in headers do (format out "~A: ~A~C~C" name value #\Return #\Newline))
     (format out "~C~C" #\Return #\Newline))
   :encoding :latin-1))

(defun egress-header (headers name)
  (cdr (assoc name headers :test #'string-equal)))

(defun egress-body-framing (headers &key request status method)
  "How the body after HEADERS ends: :none, (:length n), :chunked or :close."
  (let ((encoding (egress-header headers "Transfer-Encoding"))
        (length (egress-header headers "Content-Length")))
    (cond ((and (not request) (or (string-equal method "HEAD") (<= 100 status 199) (member status '(204 304)))) :none)
          ((and encoding (search "chunked" (string-downcase encoding))) :chunked)
          (length (list :length (parse-integer length)))
          (request :none)
          (t :close))))

(defun egress-copy-bytes (in out count)
  (let ((buffer (make-array 16384 :element-type '(unsigned-byte 8))))
    (loop while (plusp count)
          do (let ((n (read-sequence buffer in :end (min count (length buffer)))))
               (when (zerop n) (error "body ended early"))
               (write-sequence buffer out :end n)
               (decf count n)))
    (force-output out)))

(defun egress-copy-line (in out)
  "Copy one CRLF-terminated line; returns it without the CRLF."
  (let ((line (make-array 0 :element-type '(unsigned-byte 8) :adjustable t :fill-pointer 0)))
    (loop for byte = (read-byte in)
          do (write-byte byte out) (vector-push-extend byte line)
          until (and (= byte 10) (>= (length line) 2) (= (aref line (- (length line) 2)) 13)))
    (babel:octets-to-string (subseq line 0 (- (length line) 2)) :encoding :latin-1)))

(defun egress-copy-body (in out framing)
  "Copy one message body from IN to OUT as FRAMING says it ends, flushing as it goes so a
stream of events (SSE) arrives as it is sent."
  (cond ((eq framing :none))
        ((eq framing :close)
         ;; Until the upstream closes: flush whenever nothing more is waiting.
         (loop for byte = (handler-case (read-byte in nil nil) (error () nil))
               while byte
               do (write-byte byte out)
                  (unless (ignore-errors (listen in)) (force-output out))
               finally (force-output out)))
        ((eq framing :chunked)
         (loop
           (let* ((line (egress-copy-line in out))
                  (size (parse-integer line :radix 16 :junk-allowed t)))
             (force-output out)
             (if (and size (plusp size))
                 (progn (egress-copy-bytes in out size) (egress-copy-line in out) (force-output out))
                 ;; The last chunk, then trailers through a blank line.
                 (loop for trailer = (egress-copy-line in out)
                       until (zerop (length trailer))
                       finally (force-output out) (return-from egress-copy-body))))))
        (t (egress-copy-bytes in out (second framing)))))

(defun egress-write-response (stream code reason &optional detail)
  "Answer on STREAM with CODE and REASON, the body DETAIL (else REASON), and close."
  (let ((body (babel:string-to-octets (format nil "gr8s egress: ~A~%" (or detail reason)))))
    (write-sequence (egress-http-head-octets (format nil "HTTP/1.1 ~D ~A" code reason)
                                             `(("Content-Type" . "text/plain") ("Content-Length" . ,(princ-to-string (length body)))
                                               ("Connection" . "close")))
                    stream)
    (write-sequence body stream)
    (force-output stream)))

(defun egress-stream-splice (client upstream)
  "Copy CLIENT and UPSTREAM, two octet streams, to each other until either ends: what
an upgraded connection (a WebSocket) carries after its 101."
  (let ((other (bt:make-thread (lambda () (ignore-errors (egress-copy-body upstream client :close)))
                               :name "gr8s egress upgraded")))
    (ignore-errors (egress-copy-body client upstream :close))
    (ignore-errors (close upstream))
    (ignore-errors (bt:join-thread other))))

(defparameter +egress-stand-in+ "gr8s-injected"
  "What every stand-in credential a gr8 sandbox holds contains: gr8's placeholder files'
tokens and a SandboxProfile's placeholder values.")

(defun egress-read-body (in framing)
  "Read one message body from IN as FRAMING says it ends, whole. Returns the octets."
  (let ((out (flexi-streams:make-in-memory-output-stream)))
    (egress-copy-body in out framing)
    (flexi-streams:get-output-stream-sequence out)))

(defun egress-refresh-request-body (body content-type refresh-token)
  "BODY, an OAuth token request, with its stand-in refresh token replaced by
REFRESH-TOKEN, as (values octets content-type); NIL when it is no refresh_token grant
carrying a stand-in, to relay as it came. JSON and form bodies are understood."
  (let ((text (ignore-errors (trivial-utf-8:utf-8-bytes-to-string body))))
    (when text
      (if (search "json" (string-downcase (or content-type "")))
          (let ((object (ignore-errors (com.inuoe.jzon:parse text))))
            (when (and (hash-table-p object)
                       (equal "refresh_token" (gethash "grant_type" object))
                       (stringp (gethash "refresh_token" object))
                       (search +egress-stand-in+ (gethash "refresh_token" object)))
              (setf (gethash "refresh_token" object) refresh-token)
              (values (gr8s.resources:stringify-to-utf-8-bytes object) content-type)))
          (let ((fields (mapcar (lambda (pair)
                                  (let ((equals (position #\= pair)))
                                    (cons (hunchentoot:url-decode (subseq pair 0 (or equals (length pair))))
                                          (if equals (hunchentoot:url-decode (subseq pair (1+ equals))) ""))))
                                (cl-ppcre:split "&" text))))
            (when (and (equal "refresh_token" (cdr (assoc "grant_type" fields :test #'equal)))
                       (search +egress-stand-in+ (or (cdr (assoc "refresh_token" fields :test #'equal)) "")))
              (setf (cdr (assoc "refresh_token" fields :test #'equal)) refresh-token)
              (values (trivial-utf-8:string-to-utf-8-bytes
                       (format nil "~{~A~^&~}"
                               (mapcar (lambda (field) (format nil "~A=~A" (hunchentoot:url-encode (car field))
                                                               (hunchentoot:url-encode (cdr field))))
                                       fields)))
                      content-type)))))))

(defun egress-refresh-response-body (body access-key refresh-key &key (now-ms (* 1000 (- (get-universal-time) 2208988800))))
  "The tokens BODY, an OAuth token response, carries as (values stand-in-body tokens):
the body with its access and refresh tokens replaced by stand-ins, and an alist of
ACCESS-KEY, REFRESH-KEY and expiresAt (milliseconds) to their real values. NIL when it
carries no token."
  (let ((object (ignore-errors (com.inuoe.jzon:parse body))))
    (when (and (hash-table-p object) (stringp (gethash "access_token" object)))
      (let ((tokens (list (cons access-key (gethash "access_token" object)))))
        (setf (gethash "access_token" object) +egress-stand-in+)
        (when (stringp (gethash "refresh_token" object))
          (push (cons refresh-key (gethash "refresh_token" object)) tokens)
          (setf (gethash "refresh_token" object) +egress-stand-in+))
        (when (realp (gethash "expires_in" object))
          (push (cons "expiresAt" (princ-to-string (+ now-ms (round (* 1000 (gethash "expires_in" object))))))
                tokens))
        (values (gr8s.resources:stringify-to-utf-8-bytes object) (nreverse tokens))))))

(defun egress-relay-refresh (client upstream start-line headers method refresh-token refresh)
  "Relay one OAuth token request from CLIENT to UPSTREAM (podster-kn03): its stand-in
refresh token becomes REFRESH-TOKEN, and the real tokens the response carries go to
REFRESH's :rotate and are replaced by stand-ins. A response the proxy can't read (one
still encoded) is refused with 502 rather than handed to the client. Returns the status
the client got."
  (let* ((body (egress-read-body client (egress-body-framing headers :request t)))
         (content-type (egress-header headers "Content-Type")))
    (multiple-value-bind (swapped) (egress-refresh-request-body body content-type refresh-token)
      (let ((body (or swapped body))
            (headers (remove-if (lambda (header)
                                  (member (car header) '("Content-Length" "Transfer-Encoding" "Accept-Encoding")
                                          :test #'string-equal))
                                headers)))
        (write-sequence (egress-http-head-octets
                         start-line (append headers `(("Content-Length" . ,(princ-to-string (length body))))))
                        upstream)
        (write-sequence body upstream)
        (force-output upstream)
        (let (status response-headers)
          (loop
            (multiple-value-bind (status-line parsed)
                (egress-parse-http-head (or (egress-read-http-head upstream) (error "upstream closed")))
              (setf status (parse-integer (second (cl-ppcre:split " " status-line)) :junk-allowed t)
                    response-headers parsed)
              (unless (<= 100 status 199)
                (let* ((response (egress-read-body upstream (egress-body-framing parsed :status status :method method)))
                       (encoding (egress-header parsed "Content-Encoding")))
                  (when (and encoding (not (string-equal encoding "identity")))
                    (egress-write-response client 502 "Bad Gateway"
                                           "the token endpoint answered encoded, so its tokens can't be kept from the client")
                    (return-from egress-relay-refresh 502))
                  (multiple-value-bind (stand-in tokens)
                      (and swapped (<= 200 status 299)
                           (egress-refresh-response-body response (getf refresh :access-token-key)
                                                         (getf refresh :refresh-token-key)))
                    (when tokens (funcall (getf refresh :rotate) tokens))
                    (let ((out (or stand-in response)))
                      (write-sequence (egress-http-head-octets
                                       status-line
                                       (append (remove-if (lambda (header)
                                                            (member (car header) '("Content-Length" "Transfer-Encoding")
                                                                    :test #'string-equal))
                                                          response-headers)
                                               `(("Content-Length" . ,(princ-to-string (length out))))))
                                      client)
                      (write-sequence out client)
                      (force-output client)
                      (return-from egress-relay-refresh status))))))))))))

(defun egress-stand-in-header (headers)
  "The first of HEADERS whose value still carries a stand-in credential, or NIL."
  (find-if (lambda (header) (search +egress-stand-in+ (cdr header))) headers))

(defun egress-relay-http (client host open-upstream inject report &key (enforcement :enforce) bound-hosts)
  "Relay HTTP/1.1 requests from the CLIENT stream for HOST to the stream
OPEN-UPSTREAM opens on first use. INJECT maps (method path) to NIL or (values rule-name
headers value refresh swaps), VALUE NIL when the credential can't be found, SWAPS the
stand-ins to replace wherever the request carries them (swap-stand-ins). REPORT is called with
(method path code rule-name &optional audit) for each request, AUDIT naming the rule a
request broke that ENFORCEMENT :audit let through. A request still carrying a stand-in
credential once its rule (if any) has injected is refused with why, naming the
BOUND-HOSTS its credentials are for (podster-wv1w.12): the stand-in would otherwise
reach the server and fail there unexplained. An upgraded connection (101) is spliced
from then on."
  (let ((upstream nil))
    (unwind-protect
         (loop
           (let ((head (egress-read-http-head client)) (audit nil))
             (unless head (return))
             (multiple-value-bind (start-line headers) (egress-parse-http-head head)
               (destructuring-bind (&optional method target &rest rest) (cl-ppcre:split " " start-line)
                 (declare (ignore rest))
                 (let* ((host-header (string-downcase (or (egress-header headers "Host") "")))
                        (header-host (subseq host-header 0 (or (position #\: host-header) (length host-header))))
                        (fronted (not (string= header-host host))))
                   (unless (and method target)
                     (egress-write-response client 400 "Bad Request")
                     (funcall report method target 400 nil)
                     (return))
                   ;; A Host other than the name the connection was admitted by (domain
                   ;; fronting) is refused, or under Audit reported and never injected.
                   (when fronted
                     (if (eq enforcement :audit)
                         (setf audit (format nil "Host ~A is not ~A" header-host host))
                         (progn
                           (egress-write-response client 421 "Misdirected Request")
                           (funcall report method target 421 nil)
                           (return))))
                   (multiple-value-bind (rule-name names value refresh swaps) (and (not fronted) (funcall inject method target))
                     (when (and rule-name (null value))
                       (egress-write-response client 403 "Forbidden: the credential for this request is unavailable")
                       (funcall report method target 403 rule-name)
                       (return))
                     ;; An OAuth refresh (podster-kn03): its body, not its headers, carries
                     ;; the credential, and its response the tokens the client mustn't see.
                     (when refresh
                       (unless upstream (setf upstream (funcall open-upstream)))
                       (funcall report method target
                                (egress-relay-refresh client upstream start-line headers method value refresh)
                                rule-name audit)
                       (return))
                     (when rule-name
                       (setf headers (append (remove-if (lambda (header) (member (car header) names :test #'string-equal))
                                                        headers)
                                             (mapcar (lambda (name) (cons name value)) names))))
                     ;; Each credential whose stand-in the request carries, in its place
                     ;; (podster-wv1w.27); one it carries without a credential is refused.
                     (when swaps
                       (multiple-value-bind (swapped applied missing) (gr8s.network::swap-stand-ins headers swaps)
                         (when missing
                           (egress-write-response client 403 "Forbidden: the credential for this request is unavailable")
                           (funcall report method target 403 (first missing))
                           (return))
                         (setf headers swapped)
                         (unless rule-name (setf rule-name (first applied)))))
                     (let ((stand-in (egress-stand-in-header headers)))
                       (when stand-in
                         (let ((reason (format nil "~A carries a gr8 stand-in credential, which no rule injects for ~A ~A~A~:[~;; this Pod's credentials are bound to ~:*~{~A~^, ~}~]"
                                               (car stand-in) method host
                                               (subseq target 0 (or (position #\? target) (length target)))
                                               bound-hosts)))
                           (if (eq enforcement :audit)
                               (setf audit (if audit (format nil "~A; ~A" audit reason) reason))
                               (progn
                                 (egress-write-response client 403 "Forbidden" reason)
                                 (funcall report method target 403 rule-name reason)
                                 (return))))))
                     ;; A client waiting for 100 Continue would wait on us: it sends anyway after a pause.
                     (setf headers (remove "Expect" headers :key #'car :test #'string-equal))
                     (unless upstream (setf upstream (funcall open-upstream)))
                     (write-sequence (egress-http-head-octets start-line headers) upstream)
                     (egress-copy-body client upstream (egress-body-framing headers :request t))
                     (force-output upstream)
                     (let (status response-headers framing)
                       (loop
                         (let ((response (or (egress-read-http-head upstream) (error "upstream closed"))))
                           (multiple-value-bind (status-line parsed) (egress-parse-http-head response)
                             (setf status (parse-integer (second (cl-ppcre:split " " status-line)) :junk-allowed t)
                                   response-headers parsed)
                             (write-sequence response client)
                             (force-output client)
                             (unless (and (<= 100 status 199) (/= status 101)) (return)))))
                       (when (= status 101)
                         (funcall report method target status rule-name audit)
                         (egress-stream-splice client upstream)
                         (return))
                       (setf framing (egress-body-framing response-headers :status status :method method))
                       (egress-copy-body upstream client framing)
                       (funcall report method target status rule-name audit)
                       (when (or (eq framing :close)
                                 (string-equal (or (egress-header headers "Connection") "") "close")
                                 (string-equal (or (egress-header response-headers "Connection") "") "close"))
                         (return)))))))))
      (when upstream (ignore-errors (close upstream))))))

(defun egress-socket-stream (socket)
  (sb-bsd-sockets:socket-make-stream socket :input t :output t :element-type '(unsigned-byte 8)
                                            :buffering :full))

(defun egress-prefixed-stream (prefix socket)
  "A bidirectional octet stream over SOCKET whose input begins with PREFIX, the bytes
already read from it."
  (let ((stream (egress-socket-stream socket)))
    (values (make-two-way-stream
             (make-concatenated-stream (flexi-streams:make-in-memory-input-stream prefix) stream)
             stream)
            stream)))

(defun egress-proxy-relay (proxy client peer host address port prefix tls matcher
                           &key upstream-socket (enforcement :enforce))
  "Serve an admitted connection to HOST request by request, injecting what MATCHER (or
NIL) says: terminate the client's TLS (when TLS) with a leaf for HOST, and relay to
UPSTREAM-SOCKET, or ADDRESS:PORT, over verified TLS when TLS. Without a leaf to present,
a connection nothing is injected into is relayed undecrypted instead."
  (let ((client-stream nil) (raw nil))
    (unwind-protect
         (multiple-value-bind (chain key) (and tls (egress-proxy-mint proxy) (funcall (egress-proxy-mint proxy) host))
           (when (and tls (null chain))
             (unless (or matcher (null upstream-socket))
               (egress-splice client (shiftf upstream-socket nil) prefix)
               (return-from egress-proxy-relay))
             (error "no egress CA on this node to terminate ~A" host))
           (multiple-value-bind (two-way socket-stream) (egress-prefixed-stream prefix client)
             (setf raw socket-stream)
             (setf client-stream
                   (if tls
                       (pure-tls:make-tls-server-stream two-way :certificate chain :key key
                                                                :alpn-protocols '("http/1.1"))
                       two-way))
             (egress-relay-http
              client-stream host
              (lambda ()
                (let ((socket (or (shiftf upstream-socket nil)
                                  (funcall (egress-proxy-connect proxy) address port)
                                  (error "could not connect to ~A:~D" address port))))
                  (if tls
                      (pure-tls:make-tls-client-stream (egress-socket-stream socket)
                                                       :hostname host :verify (egress-proxy-upstream-verify proxy)
                                                       :alpn-protocols '("http/1.1"))
                      (egress-socket-stream socket))))
              (or matcher (lambda (method path) (declare (ignore method path)) nil))
              (lambda (method path code rule &optional audit)
                (when (egress-proxy-request-report proxy)
                  (ignore-errors (funcall (egress-proxy-request-report proxy)
                                          peer host address port method path code rule audit))))
              :enforcement enforcement
              :bound-hosts (and (egress-proxy-bindings proxy)
                                (ignore-errors (funcall (egress-proxy-bindings proxy) peer))))))
      (when upstream-socket (ignore-errors (sb-bsd-sockets:socket-close upstream-socket)))
      (when client-stream (ignore-errors (close client-stream)))
      (when raw (ignore-errors (close raw))))))
