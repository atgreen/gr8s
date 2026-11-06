;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; The L4 data plane for TCPRoute / TLSRoute / GRPCRoute (podster-43k.9). A TCP
;;;; listener splices a connection straight to a backend; a TLS listener peeks the
;;;; ClientHello SNI (gateway-sni, without terminating) and steers the connection
;;;; to the backend whose TLSRoute/GRPCRoute hostname matches -- SNI passthrough,
;;;; the agent as the L4 gateway. Backends and weighting reuse the HTTP router's
;;;; GW-BACKEND; byte copying is a pair of threads per connection.

(in-package #:gr8s)

;;; ---------------------------------------------------------------------------
;;; Normalized L4 routes (parsed from stored TCPRoute/TLSRoute/GRPCRoute).

(defstruct l4-tcp-route
  (namespace nil)
  (backends '() :type list))            ; GW-BACKEND list (weighted)

(defstruct l4-sni-route
  (namespace nil)
  (hostnames '() :type list)            ; SNI host match: "h" or "*.suffix"
  (backends '() :type list))

(defun l4-route-backends (object namespace)
  "Flatten all rules' backendRefs of an L4 route object into GW-BACKENDs."
  (let ((spec (gethash "spec" object)) (backends '()))
    (when spec
      (let ((rules (gethash "rules" spec)))
        (when rules
          (loop for rule across rules
                for refs = (gethash "backendRefs" rule)
                when refs do (loop for ref across refs
                                   do (push (gw-parse-backend ref namespace) backends))))))
    (nreverse backends)))

(defun parse-tcproute (object)
  (let ((namespace (gethash "namespace" (gethash "metadata" object))))
    (make-l4-tcp-route :namespace namespace :backends (l4-route-backends object namespace))))

(defun parse-sni-route (object)
  "Parse a TLSRoute or GRPCRoute (both routed by SNI hostname) into an L4-SNI-ROUTE."
  (let* ((metadata (gethash "metadata" object))
         (namespace (gethash "namespace" metadata))
         (spec (gethash "spec" object)))
    (make-l4-sni-route :namespace namespace
                       :hostnames (gw-string-list (and spec (gethash "hostnames" spec)))
                       :backends (l4-route-backends object namespace))))

;;; ---------------------------------------------------------------------------
;;; SNI host matching + dispatch.

(defun l4-host-match-p (pattern sni)
  "Exact or \"*.suffix\" wildcard match of an SNI host against a route PATTERN."
  (cond ((null pattern) nil)
        ((and (> (length pattern) 2) (string= pattern "*." :end1 2))
         (let ((suffix (subseq pattern 1)))     ; "*.example.com" -> ".example.com"
           (and (> (length sni) (length suffix))
                (string= sni suffix :start1 (- (length sni) (length suffix))))))
        (t (string-equal pattern sni))))

(defun l4-sni-dispatch (sni-routes sni)
  "Return a GW-BACKEND for the SNI host (exact beats wildcard), or NIL."
  (when sni
    (let ((best nil) (best-rank -1))
      (dolist (route sni-routes)
        (dolist (pattern (l4-sni-route-hostnames route))
          (when (l4-host-match-p pattern sni)
            (let ((rank (if (and (> (length pattern) 2) (string= pattern "*." :end1 2)) 1 2)))
              (when (> rank best-rank)
                (setf best-rank rank best (gw-pick-weighted (l4-sni-route-backends route))))))))
      best)))

(defun l4-tcp-dispatch (tcp-routes)
  "Return a GW-BACKEND for a TCP listener (host-agnostic), or NIL."
  (when tcp-routes (gw-pick-weighted (l4-tcp-route-backends (first tcp-routes)))))

;;; ---------------------------------------------------------------------------
;;; Byte plumbing.

(defun l4-copy (from-socket to-socket)
  "Copy FROM-SOCKET to TO-SOCKET until EOF or error, using raw socket I/O (not
   fd-streams, which are unsafe under the concurrent read/write of a splice)."
  (let ((buffer (make-array 16384 :element-type '(unsigned-byte 8))))
    (handler-case
        (loop
          (multiple-value-bind (buf n) (sb-bsd-sockets:socket-receive from-socket buffer nil)
            (declare (ignore buf))
            (when (or (null n) (zerop n)) (return))
            (let ((sent 0))
              (loop while (< sent n)
                    do (incf sent (sb-bsd-sockets:socket-send
                                   to-socket (subseq buffer sent n) (- n sent)))))))
      (error () nil))))

(defun l4-splice (client-socket backend-socket close-both &optional prefix prefix-end)
  "Splice CLIENT-SOCKET and BACKEND-SOCKET bidirectionally until EOF. PREFIX, if
   given, is bytes already read from the client (the peeked ClientHello) sent to
   the backend first. When either direction ends, CLOSE-BOTH (idempotent) shuts
   both sockets so the other copy thread's blocked receive errors out."
  ;; Best effort: a backend that closes without reading the replayed ClientHello
  ;; must not abort the splice before its reply is copied back.
  (when (and prefix (plusp (or prefix-end 0)))
    (handler-case
        (let ((sent 0))
          (loop while (< sent prefix-end)
                do (incf sent (sb-bsd-sockets:socket-send
                               backend-socket (subseq prefix sent prefix-end) (- prefix-end sent)))))
      (error () nil)))
  (let ((up (bt:make-thread (lambda ()
                              (l4-copy client-socket backend-socket)
                              (funcall close-both))
                            :name "gr8s l4 c->b")))
    (l4-copy backend-socket client-socket)            ; backend -> client on this thread
    (funcall close-both)
    (ignore-errors (bt:join-thread up))))

;;; ---------------------------------------------------------------------------
;;; Listener.

(defstruct l4-listener socket thread (stop nil) address port
  mode dispatcher resolver)             ; dispatcher is hot-swappable

(defun l4-connect-backend (resolver backend)
  "Resolve BACKEND and open a socket to it, or NIL."
  (when backend
    (multiple-value-bind (host port) (funcall resolver backend)
      (when host
        (handler-case
            (let ((socket (make-instance 'sb-bsd-sockets:inet-socket :type :stream :protocol :tcp)))
              (sb-bsd-sockets:socket-connect socket (sb-bsd-sockets:make-inet-address host) port)
              socket)
          (error () nil))))))

(defun l4-peek-client-hello (client-socket)
  "Read exactly one TLS ClientHello record from CLIENT-SOCKET. Returns
   (values bytes sni), where BYTES are the record to replay to the backend."
  (let ((header (make-array 5 :element-type '(unsigned-byte 8))))
    (multiple-value-bind (buf hn) (sb-bsd-sockets:socket-receive client-socket header 5 :waitall t)
      (declare (ignore buf))
      (if (and hn (= hn 5) (= (aref header 0) 22))
          (let* ((record-length (logior (ash (aref header 3) 8) (aref header 4)))
                 (body (make-array record-length :element-type '(unsigned-byte 8))))
            (multiple-value-bind (b2 bn) (sb-bsd-sockets:socket-receive client-socket body record-length
                                                                        :waitall t)
              (declare (ignore b2))
              (let ((full (concatenate '(simple-array (unsigned-byte 8) (*))
                                       header (subseq body 0 (or bn 0)))))
                (values full (ignore-errors (parse-tls-client-hello-sni full))))))
          (values (subseq header 0 (max (or hn 0) 0)) nil)))))

(defun l4-handle-connection (client-socket listener)
  "Route one accepted connection: pick a backend (by SNI for :tls, directly for
   :tcp) via the listener's current dispatcher, connect, and splice raw bytes."
  (let ((mode (l4-listener-mode listener))
        (dispatcher (l4-listener-dispatcher listener))
        (resolver (l4-listener-resolver listener)))
   (unwind-protect
       (let (backend prefix prefix-end)
         (ecase mode
           (:tcp (setf backend (funcall dispatcher nil)))
           (:tls (multiple-value-bind (bytes sni) (l4-peek-client-hello client-socket)
                   (setf prefix bytes prefix-end (length bytes)
                         backend (funcall dispatcher sni)))))
         (let ((backend-socket (l4-connect-backend resolver backend)))
           (when backend-socket
             (let ((closed nil))
               (flet ((close-both ()
                        (unless closed
                          (setf closed t)
                          (ignore-errors (sb-bsd-sockets:socket-close client-socket))
                          (ignore-errors (sb-bsd-sockets:socket-close backend-socket)))))
                 (unwind-protect
                      (l4-splice client-socket backend-socket #'close-both prefix prefix-end)
                   (close-both)))))))
    (ignore-errors (sb-bsd-sockets:socket-close client-socket)))))

(defun start-l4-listener (&key (address "127.0.0.1") port mode dispatcher resolver (name "l4"))
  "Start an L4 listener on PORT. MODE is :tcp or :tls. DISPATCHER maps an SNI
   host (or NIL) to a GW-BACKEND; RESOLVER maps a GW-BACKEND to (values host port)."
  (let ((socket (make-instance 'sb-bsd-sockets:inet-socket :type :stream :protocol :tcp)))
    (setf (sb-bsd-sockets:sockopt-reuse-address socket) t)
    (sb-bsd-sockets:socket-bind socket (sb-bsd-sockets:make-inet-address address) port)
    (sb-bsd-sockets:socket-listen socket 32)
    ;; Record the bound port, which the kernel chose when PORT is 0: STOP-L4-LISTENER connects to it.
    (let ((listener (make-l4-listener :socket socket :address address
                                      :port (nth-value 1 (sb-bsd-sockets:socket-name socket))
                                      :mode mode :dispatcher dispatcher :resolver resolver)))
      (setf (l4-listener-thread listener)
            (bt:make-thread
             (lambda ()
               (loop
                 (when (l4-listener-stop listener) (return))
                 (handler-case
                     (let ((client (sb-bsd-sockets:socket-accept socket)))
                       (if (l4-listener-stop listener)
                           (ignore-errors (sb-bsd-sockets:socket-close client))
                           (when client
                             (bt:make-thread
                              (lambda () (l4-handle-connection client listener))
                              :name (format nil "gr8s l4 conn ~A" name)))))
                   (error () (when (l4-listener-stop listener) (return))))))
             :name (format nil "gr8s l4 accept ~A" name)))
      listener)))

(defun l4-listener-swap-dispatcher (listener dispatcher)
  "Hot-swap the listener's dispatcher; new connections use it immediately."
  (setf (l4-listener-dispatcher listener) dispatcher))

(defun stop-l4-listener (listener)
  (when listener
    (setf (l4-listener-stop listener) t)
    ;; Wake the blocked accept with a throwaway self-connection, then join.
    (ignore-errors
     (let ((waker (make-instance 'sb-bsd-sockets:inet-socket :type :stream :protocol :tcp)))
       (unwind-protect
            (sb-bsd-sockets:socket-connect
             waker (sb-bsd-sockets:make-inet-address (l4-listener-address listener))
             (l4-listener-port listener))
         (ignore-errors (sb-bsd-sockets:socket-close waker)))))
    (ignore-errors
     (when (and (l4-listener-thread listener) (bt:thread-alive-p (l4-listener-thread listener)))
       (bt:join-thread (l4-listener-thread listener))))
    (ignore-errors (sb-bsd-sockets:socket-close (l4-listener-socket listener)))))
