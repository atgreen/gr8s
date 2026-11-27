;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; A STUN responder for browser nodes (podster-zra1, docs/design-browser-nodes.md).
;;;;
;;;; Two tabs behind different NATs connect directly only when each learns the public
;;;; address its NAT gives it, and offers that to the other; then both send at once and
;;;; their NATs let the replies in. A STUN binding request (RFC 8489) is how a browser
;;;; asks: it sends one datagram, and the answer names the address and port it came
;;;; from. Serving that here keeps visitors' addresses away from third parties. Nothing
;;;; else of STUN is needed: no authentication, no relaying (a tab that can't reach a peer
;;;; directly still reaches it through its session), so the answer is one small datagram
;;;; per request, barely larger than the request.

(in-package #:gr8s.server)

(defconstant +stun-magic-cookie+ #x2112A442)

(defun stun-binding-response (request address port)
  "The binding success response to REQUEST, a STUN binding request (octets) received from
ADDRESS (an IPv4 address as four octets) and PORT, naming that address and port in an
XOR-MAPPED-ADDRESS; NIL when REQUEST is not a well-formed binding request."
  (when (and (>= (length request) 20)
             (zerop (logand (aref request 0) #xC0))
             (= #x0001 (logior (ash (aref request 0) 8) (aref request 1)))
             (= (+ 20 (logior (ash (aref request 2) 8) (aref request 3))) (length request))
             (= +stun-magic-cookie+ (logior (ash (aref request 4) 24) (ash (aref request 5) 16)
                                            (ash (aref request 6) 8) (aref request 7))))
    (let ((response (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))
          (x-port (logxor port (ash +stun-magic-cookie+ -16))))
      ;; Header: Binding Success Response, 12 octets of attributes, the cookie, and the
      ;; request's transaction id.
      (replace response #(#x01 #x01 #x00 #x0C #x21 #x12 #xA4 #x42))
      (replace response request :start1 8 :start2 8 :end2 20)
      ;; XOR-MAPPED-ADDRESS: IPv4, the port and address masked with the cookie.
      (replace response (vector #x00 #x20 #x00 #x08 #x00 #x01 (ldb (byte 8 8) x-port) (ldb (byte 8 0) x-port))
               :start1 20)
      (loop for index from 0 below 4
            do (setf (aref response (+ 28 index))
                     (logxor (aref address index) (ldb (byte 8 (- 24 (* 8 index))) +stun-magic-cookie+))))
      response)))

(defstruct (browser-stun (:constructor %make-browser-stun (socket port)))
  "A STUN responder: its UDP socket, the port it answers on, and its thread."
  socket port (thread nil) (stopping nil))

(defun start-browser-stun (address port)
  "Answer STUN binding requests on UDP ADDRESS:PORT until stopped. Returns the responder."
  (let ((socket (make-instance 'sb-bsd-sockets:inet-socket :type :datagram :protocol :udp)))
    (setf (sb-bsd-sockets:sockopt-reuse-address socket) t)
    (sb-bsd-sockets:socket-bind socket (sb-bsd-sockets:make-inet-address address) port)
    (let ((stun (%make-browser-stun socket (nth-value 1 (sb-bsd-sockets:socket-name socket))))
          (buffer (make-array 1500 :element-type '(unsigned-byte 8))))
      (setf (browser-stun-thread stun)
            (bt:make-thread
             (lambda ()
               (loop until (browser-stun-stopping stun)
                     do (handler-case
                            (multiple-value-bind (received length from from-port)
                                (sb-bsd-sockets:socket-receive socket buffer nil)
                              (declare (ignore received))
                              (let ((response (and (= 4 (length from))
                                                   (stun-binding-response (subseq buffer 0 length) from from-port))))
                                (when response
                                  (sb-bsd-sockets:socket-send socket response nil :address (list from from-port)))))
                          (error (condition)
                            (unless (browser-stun-stopping stun)
                              (format *error-output* "gr8s browser STUN: ~A~%" condition))))))
             :name "gr8s browser STUN"))
      stun)))

(defun stop-browser-stun (stun)
  "Stop STUN answering."
  (setf (browser-stun-stopping stun) t)
  ;; A datagram of its own wakes the thread from its receive.
  (ignore-errors
   (let ((waker (make-instance 'sb-bsd-sockets:inet-socket :type :datagram :protocol :udp)))
     (unwind-protect
          (sb-bsd-sockets:socket-send waker (make-array 1 :element-type '(unsigned-byte 8) :initial-element 0) nil
                                      :address (list #(127 0 0 1) (browser-stun-port stun)))
       (sb-bsd-sockets:socket-close waker))))
  (when (browser-stun-thread stun)
    (ignore-errors (bt:join-thread (browser-stun-thread stun))))
  (ignore-errors (sb-bsd-sockets:socket-close (browser-stun-socket stun))))
