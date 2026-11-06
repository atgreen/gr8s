;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Speak the client side of SPDY/3.1 to containerd's CRI streaming server. Its
;;;; WebSocket protocols stop at v4, which cannot end stdin alone, so a Pod stream
;;;; that needs stdin EOF has to use SPDY as a kubelet's API server would. Only what
;;;; remotecommand needs is here: a stream per channel, data, half-close and pings.
;;;; Header blocks go out as stored zlib blocks, which need the SPDY dictionary's
;;;; identity in the stream header but none of its contents, and those coming back
;;;; say nothing this client uses, so they are skipped undecoded.

(in-package #:gr8s)

(defparameter +spdy-zlib-header+ #(#x78 #xF9 #xE3 #xC6 #xA7 #xC2)
  "A zlib stream header announcing the SPDY/3 dictionary, by its Adler-32.")

(defconstant +spdy-syn-stream+ 1)
(defconstant +spdy-rst-stream+ 3)
(defconstant +spdy-ping+ 6)
(defconstant +spdy-goaway+ 7)
(defconstant +spdy-flag-fin+ 1)

(defstruct (spdy-session (:constructor make-spdy-session (stream)))
  stream
  (next-stream-id 1)
  (headers-started nil)
  (write-lock (bt:make-lock "gr8s SPDY writer")))

(defun spdy-put-u32 (value output)
  "Append VALUE to the octet vector OUTPUT, most significant byte first."
  (loop for shift from 24 downto 0 by 8 do (vector-push-extend (ldb (byte 8 shift) value) output)))

(defun spdy-octet-buffer ()
  "Return an empty growing octet vector."
  (make-array 64 :element-type '(unsigned-byte 8) :adjustable t :fill-pointer 0))

(defun spdy-header-block (session pairs)
  "Encode the name and value PAIRS as the next piece of SESSION's one header compression stream."
  (let ((raw (spdy-octet-buffer)) (block (spdy-octet-buffer)))
    (spdy-put-u32 (length pairs) raw)
    (loop for (name . value) in pairs
          do (dolist (text (list name value))
               (let ((octets (trivial-utf-8:string-to-utf-8-bytes text)))
                 (spdy-put-u32 (length octets) raw)
                 (loop for octet across octets do (vector-push-extend octet raw)))))
    (unless (spdy-session-headers-started session)
      (loop for octet across +spdy-zlib-header+ do (vector-push-extend octet block))
      (setf (spdy-session-headers-started session) t))
    (vector-push-extend 0 block)
    (let ((size (length raw)))
      (dolist (octet (list (ldb (byte 8 0) size) (ldb (byte 8 8) size)
                           (logxor 255 (ldb (byte 8 0) size)) (logxor 255 (ldb (byte 8 8) size))))
        (vector-push-extend octet block)))
    (loop for octet across raw do (vector-push-extend octet block))
    ;; A sync flush's empty block makes the server's inflater hand over what it has at the frame's end.
    (loop for octet across #(0 0 0 #xFF #xFF) do (vector-push-extend octet block))
    block))

(defun spdy-write-control-frame (session type flags payload)
  "Send a control frame of TYPE with PAYLOAD. Call holding SESSION's write lock."
  (let ((stream (spdy-session-stream session)) (head (spdy-octet-buffer)))
    (dolist (octet (list #x80 3 (ldb (byte 8 8) type) (ldb (byte 8 0) type)))
      (vector-push-extend octet head))
    (spdy-put-u32 (logior (ash flags 24) (length payload)) head)
    (write-sequence head stream)
    (write-sequence payload stream)
    (finish-output stream)))

(defun spdy-open-stream (session stream-type &optional headers)
  "Open a stream the server will take for the channel STREAM-TYPE, returning its ID.
HEADERS are further (name . value) pairs for it."
  (bt:with-lock-held ((spdy-session-write-lock session))
    (let ((id (spdy-session-next-stream-id session)) (payload (spdy-octet-buffer)))
      (incf (spdy-session-next-stream-id session) 2)
      (spdy-put-u32 id payload)
      (spdy-put-u32 0 payload)
      (vector-push-extend 0 payload)
      (vector-push-extend 0 payload)
      (loop for octet across (spdy-header-block session (append headers (list (cons "streamtype" stream-type))))
            do (vector-push-extend octet payload))
      (spdy-write-control-frame session +spdy-syn-stream+ 0 payload)
      id)))

(defun spdy-write-data (session id data &key fin)
  "Send DATA on stream ID, with FIN ending this side of it."
  (bt:with-lock-held ((spdy-session-write-lock session))
    (let ((stream (spdy-session-stream session)) (head (spdy-octet-buffer)))
      (spdy-put-u32 id head)
      (spdy-put-u32 (logior (ash (if fin +spdy-flag-fin+ 0) 24) (length data)) head)
      (write-sequence head stream)
      (write-sequence data stream)
      (finish-output stream))))

(defun spdy-read-octets (stream count)
  "Read exactly COUNT octets, or return NIL at the end of STREAM."
  (let* ((buffer (make-array count :element-type '(unsigned-byte 8)))
         (got (read-sequence buffer stream)))
    (and (= got count) buffer)))

(defun spdy-read-u32 (octets start)
  "Read a big-endian 32-bit integer from OCTETS at START."
  (loop with value = 0
        for index from start below (+ start 4)
        do (setf value (+ (* value 256) (aref octets index)))
        finally (return value)))

(defun spdy-read-frame (session)
  "Return the next frame of interest as (:data id fin octets) or (:reset id), or NIL at the end.
Pings are answered here. A GOAWAY ends the session, and other control frames carry nothing needed."
  (let ((stream (spdy-session-stream session)))
    (loop
      (let ((head (spdy-read-octets stream 8)))
        (unless head (return nil))
        (let* ((flags (aref head 4))
               (size (logand (spdy-read-u32 head 4) #xFFFFFF))
               (payload (if (plusp size) (or (spdy-read-octets stream size) (return nil))
                            (make-array 0 :element-type '(unsigned-byte 8)))))
          (if (logbitp 7 (aref head 0))
              (let ((type (+ (* 256 (aref head 2)) (aref head 3))))
                (cond ((= type +spdy-ping+)
                       (bt:with-lock-held ((spdy-session-write-lock session))
                         (spdy-write-control-frame session +spdy-ping+ 0 payload)))
                      ((= type +spdy-goaway+) (return nil))
                      ((= type +spdy-rst-stream+)
                       (return (list :reset (logand (spdy-read-u32 payload 0) #x7FFFFFFF))))))
              (return (list :data (logand (spdy-read-u32 head 0) #x7FFFFFFF)
                            (logbitp 0 flags) payload))))))))

(defun runtime-spdy-request (target host port protocol)
  "Return the HTTP request upgrading to SPDY for the stream PROTOCOL."
  (format nil
          "POST ~A HTTP/1.1~C~CHost: ~A:~D~C~CConnection: Upgrade~C~CUpgrade: SPDY/3.1~C~CX-Stream-Protocol-Version: ~A~C~CContent-Length: 0~C~C~C~C"
          target #\Return #\Linefeed host port #\Return #\Linefeed
          #\Return #\Linefeed #\Return #\Linefeed protocol #\Return #\Linefeed
          #\Return #\Linefeed #\Return #\Linefeed))

(defun connect-runtime-stream (url &key (protocol "v4.channel.k8s.io"))
  "Upgrade a one-time streaming URL to SPDY, returning the socket and a session."
  (multiple-value-bind (host port target) (parse-runtime-stream-url url)
    (let* ((socket (usocket:socket-connect host port :element-type '(unsigned-byte 8)))
           (stream (usocket:socket-stream socket)))
      (handler-case
          (progn
            (write-sequence (ascii-octets (runtime-spdy-request target host port protocol)) stream)
            (finish-output stream)
            (multiple-value-bind (status headers) (parse-http-response-head (read-http-response-head stream))
              (declare (ignore headers))
              (unless (= 101 status)
                (error 'runtime-error
                       :message (format nil "containerd rejected the stream with HTTP ~D" status))))
            (values socket (make-spdy-session stream)))
        (error (condition)
          (ignore-errors (usocket:socket-close socket))
          (if (typep condition 'runtime-error)
              (error condition)
              (error 'runtime-error :message (princ-to-string condition))))))))
