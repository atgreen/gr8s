;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Speak the server side of SPDY/3.1 to kubectl, for Pod port forwarding. Clients
;;;; open streams and name them in compressed header blocks, so unlike the runtime
;;;; client this has to read those, which takes a small inflate seeded with SPDY's
;;;; dictionary. The same frames travel over an upgraded connection or tunnelled in
;;;; WebSocket messages, so they go through a transport.

(in-package #:gr8s)

(defparameter +port-forward-protocol+ "portforward.k8s.io"
  "The stream protocol of port forwarding, between kubectl and here and between the agent and the runtime.")

;;; Inflate (RFC 1951), one header block at a time. A SPDY sender ends each block
;;; with a sync flush, so a block never stops part way through a deflate block, but
;;; all of a connection's blocks are one stream and refer back to earlier output.

(defconstant +spdy-inflate-window+ 32768)

(defconstant +spdy-max-header-block+ (* 1024 1024)
  "The most a header block may expand to, so a small frame can't demand unbounded memory.")

(defstruct (spdy-inflater (:constructor %make-spdy-inflater))
  (history (make-array (+ (length +spdy-header-dictionary+) 4096)
                       :element-type '(unsigned-byte 8) :adjustable t :fill-pointer 0))
  (started nil))

(defun make-spdy-inflater ()
  "Return an inflater with SPDY's dictionary as the output its first block refers back to."
  (let ((inflater (%make-spdy-inflater)))
    (loop for octet across +spdy-header-dictionary+
          do (vector-push-extend octet (spdy-inflater-history inflater)))
    inflater))

(defun inflate-huffman-table (lengths)
  "Return the canonical code's symbol count per length and its symbols, in code order."
  (let ((counts (make-array 16 :initial-element 0))
        (offsets (make-array 16 :initial-element 0))
        (symbols (make-array (length lengths) :initial-element 0)))
    (loop for length across lengths do (incf (aref counts length)))
    (setf (aref counts 0) 0)
    (loop for bits from 1 below 15
          do (setf (aref offsets (1+ bits)) (+ (aref offsets bits) (aref counts bits))))
    (loop for symbol from 0 for length across lengths
          when (plusp length)
            do (setf (aref symbols (aref offsets length)) symbol)
               (incf (aref offsets length)))
    (cons counts symbols)))

(defparameter +inflate-length-base+
  #(3 4 5 6 7 8 9 10 11 13 15 17 19 23 27 31 35 43 51 59 67 83 99 115 131 163 195 227 258))
(defparameter +inflate-length-extra+
  #(0 0 0 0 0 0 0 0 1 1 1 1 2 2 2 2 3 3 3 3 4 4 4 4 5 5 5 5 0))
(defparameter +inflate-distance-base+
  #(1 2 3 4 5 7 9 13 17 25 33 49 65 97 129 193 257 385 513 769 1025 1537 2049 3073 4097 6145
    8193 12289 16385 24577))
(defparameter +inflate-distance-extra+
  #(0 0 0 0 1 1 2 2 3 3 4 4 5 5 6 6 7 7 8 8 9 9 10 10 11 11 12 12 13 13))
(defparameter +inflate-code-length-order+ #(16 17 18 0 8 7 9 6 10 5 11 4 12 3 13 2 14 1 15))

(defparameter +inflate-fixed-tables+
  (cons (inflate-huffman-table
         (let ((lengths (make-array 288)))
           (dotimes (symbol 288 lengths)
             (setf (aref lengths symbol)
                   (cond ((< symbol 144) 8) ((< symbol 256) 9) ((< symbol 280) 7) (t 8))))))
        (inflate-huffman-table (make-array 30 :initial-element 5))))

(defun inflate-octets (history input start)
  "Inflate INPUT from START until it runs out, appending the output to the vector HISTORY."
  (let ((bit-position (* 8 start)) (end (* 8 (length input))) (limit (+ (length history) +spdy-max-header-block+)))
    (labels ((take-bits (count)
               (when (> (+ bit-position count) end) (error "Header block ended inside a deflate code"))
               (let ((value 0))
                 (dotimes (index count value)
                   (when (logbitp (mod bit-position 8) (aref input (floor bit-position 8)))
                     (setf value (logior value (ash 1 index))))
                   (incf bit-position))))
             (emit (octet)
               (when (>= (length history) limit) (error "Header block expands too far"))
               (vector-push-extend octet history))
             (take-symbol (table)
               (let ((code 0) (first 0) (index 0))
                 (loop for bits from 1 to 15
                       do (setf code (logior code (take-bits 1)))
                          (let ((count (aref (car table) bits)))
                            (when (< (- code count) first)
                              (return-from take-symbol
                                (aref (cdr table) (+ index (- code first)))))
                            (incf index count)
                            (incf first count)
                            (setf first (ash first 1)
                                  code (ash code 1))))
                 (error "Invalid deflate code")))
             (copy-match (length distance)
               (when (> distance (length history)) (error "Deflate distance is too far back"))
               (dotimes (index length)
                 (emit (aref history (- (length history) distance)))))
             (take-codes (literals distances)
               (loop for symbol = (take-symbol literals)
                     until (= symbol 256)
                     do (if (< symbol 256)
                            (emit symbol)
                            (let* ((slot (- symbol 257))
                                   (length (progn
                                             (unless (< slot 29) (error "Invalid deflate length"))
                                             (+ (aref +inflate-length-base+ slot)
                                                (take-bits (aref +inflate-length-extra+ slot)))))
                                   (distance-slot (take-symbol distances)))
                              (unless (< distance-slot 30) (error "Invalid deflate distance"))
                              (copy-match length (+ (aref +inflate-distance-base+ distance-slot)
                                                    (take-bits (aref +inflate-distance-extra+ distance-slot))))))))
             (take-dynamic-tables ()
               (let* ((literal-count (+ 257 (take-bits 5)))
                      (distance-count (+ 1 (take-bits 5)))
                      (code-count (+ 4 (take-bits 4)))
                      (code-lengths (make-array 19 :initial-element 0))
                      (lengths (make-array (+ literal-count distance-count) :initial-element 0))
                      (index 0))
                 (dotimes (slot code-count)
                   (setf (aref code-lengths (aref +inflate-code-length-order+ slot)) (take-bits 3)))
                 (let ((table (inflate-huffman-table code-lengths)))
                   (loop while (< index (length lengths))
                         do (let ((symbol (take-symbol table)))
                              (if (< symbol 16)
                                  (progn (setf (aref lengths index) symbol) (incf index))
                                  (multiple-value-bind (value repeat)
                                      (case symbol
                                        (16 (when (zerop index) (error "Deflate repeat has nothing before it"))
                                         (values (aref lengths (1- index)) (+ 3 (take-bits 2))))
                                        (17 (values 0 (+ 3 (take-bits 3))))
                                        (t (values 0 (+ 11 (take-bits 7)))))
                                    (when (> (+ index repeat) (length lengths))
                                      (error "Deflate repeat overruns its table"))
                                    (dotimes (ignored repeat)
                                      (setf (aref lengths index) value)
                                      (incf index)))))))
                 (values (inflate-huffman-table (subseq lengths 0 literal-count))
                         (inflate-huffman-table (subseq lengths literal-count)))))
             (take-stored ()
               (setf bit-position (* 8 (ceiling bit-position 8)))
               (let ((size (take-bits 16)) (check (take-bits 16)))
                 (unless (= size (logxor check #xFFFF)) (error "Deflate stored block is corrupt"))
                 (dotimes (ignored size) (emit (take-bits 8))))))
      (loop while (<= (+ bit-position 8) end)
            do (take-bits 1)
               (ecase (take-bits 2)
                 (0 (take-stored))
                 (1 (take-codes (car +inflate-fixed-tables+) (cdr +inflate-fixed-tables+)))
                 (2 (multiple-value-bind (literals distances) (take-dynamic-tables)
                      (take-codes literals distances)))
                 (3 (error "Invalid deflate block type")))))))

(defun spdy-inflate-header-block (inflater block)
  "Return the name and value pairs in BLOCK, the next piece of INFLATER's compression stream."
  (let ((history (spdy-inflater-history inflater)) (start 0))
    (unless (spdy-inflater-started inflater)
      ;; Two octets of zlib header, then the dictionary's identifier, as the client side sends too.
      (unless (and (>= (length block) 6)
                   (not (mismatch +spdy-zlib-header+ block :start1 2 :end1 6 :start2 2 :end2 6)))
        (error "SPDY header block doesn't use the SPDY dictionary"))
      (setf start 6 (spdy-inflater-started inflater) t))
    (when (> (length history) (* 2 +spdy-inflate-window+))
      (replace history history :start2 (- (length history) +spdy-inflate-window+))
      (setf (fill-pointer history) +spdy-inflate-window+))
    (let ((before (length history)))
      (inflate-octets history block start)
      (let* ((position before)
             (count (spdy-read-u32 history position)))
        (incf position 4)
        (loop repeat count
              collect (flet ((take-text ()
                               (let ((size (spdy-read-u32 history position)))
                                 (incf position 4)
                                 (prog1 (trivial-utf-8:utf-8-bytes-to-string
                                         (coerce (subseq history position (+ position size))
                                                 '(simple-array (unsigned-byte 8) (*))))
                                   (incf position size)))))
                        (let* ((name (string-downcase (take-text))) (value (take-text)))
                          (cons name value))))))))

;;; Transports

(defstruct spdy-transport
  "READ-OCTETS takes a count and returns that many octets, or NIL at the end. WRITE-OCTETS sends one frame."
  read-octets write-octets)

(defun make-upgraded-spdy-transport (stream)
  "Return a transport for SPDY frames sent directly over the upgraded connection STREAM."
  (make-spdy-transport
   :read-octets
   (lambda (count)
     (let ((buffer (make-array count :element-type '(unsigned-byte 8))) (got 0))
       ;; One read of a TLS stream returns only what its current record holds.
       (loop while (< got count)
             do (let ((next (read-sequence buffer stream :start got)))
                  (when (= next got) (return-from nil nil))
                  (setf got next))
             finally (return buffer))))
   :write-octets
   (lambda (octets)
     (write-sequence octets stream)
     (finish-output stream))))

(defun make-websocket-spdy-transport (stream)
  "Return a transport for SPDY frames tunnelled through WebSocket messages on STREAM."
  (let ((lock (bt:make-lock "gr8s SPDY tunnel writer"))
        (pending (make-array 0 :element-type '(unsigned-byte 8)))
        (position 0))
    (flet ((next-message ()
             (loop
               (multiple-value-bind (opcode payload fin-p masked-p) (read-websocket-frame stream)
                 (declare (ignore fin-p))
                 (case opcode
                   ((0 2)
                    (unless masked-p
                      (error 'runtime-error :message "WebSocket client frames must be masked"))
                    (return payload))
                   (8 (return nil))
                   (9 (bt:with-lock-held (lock) (write-websocket-frame stream 10 payload)))
                   (10)
                   (otherwise (error 'runtime-error :message "Unsupported WebSocket tunnel frame")))))))
      (make-spdy-transport
       :read-octets
       (lambda (count)
         (let ((buffer (make-array count :element-type '(unsigned-byte 8))) (got 0))
           (loop while (< got count)
                 do (when (>= position (length pending))
                      (let ((message (next-message)))
                        (unless message (return-from nil nil))
                        (setf pending message position 0)))
                    (let ((taken (min (- count got) (- (length pending) position))))
                      (replace buffer pending :start1 got :start2 position :end2 (+ position taken))
                      (incf got taken)
                      (incf position taken))
                 finally (return buffer))))
       :write-octets
       (lambda (octets)
         (bt:with-lock-held (lock) (write-websocket-frame stream 2 octets)))))))

;;; Frames

(defconstant +spdy-syn-reply+ 2)

(defstruct (spdy-server (:constructor make-spdy-server (transport)))
  transport
  (inflater (make-spdy-inflater))
  ;; This holds the state of the header compression stream this side sends.
  (encoder (make-spdy-session nil))
  (write-lock (bt:make-lock "gr8s SPDY server writer")))

(defun spdy-server-write-frame (server head payload)
  "Send the octets of HEAD and PAYLOAD as one frame. Call holding SERVER's write lock."
  (funcall (spdy-transport-write-octets (spdy-server-transport server))
           (concatenate '(simple-array (unsigned-byte 8) (*)) head payload)))

(defun spdy-server-control-frame (server type payload)
  "Send a control frame of TYPE with PAYLOAD. Call holding SERVER's write lock."
  (let ((head (spdy-octet-buffer)))
    (dolist (octet (list #x80 3 (ldb (byte 8 8) type) (ldb (byte 8 0) type)))
      (vector-push-extend octet head))
    (spdy-put-u32 (length payload) head)
    (spdy-server-write-frame server head payload)))

(defun spdy-server-reply (server id)
  "Accept stream ID, which a client's CreateStream waits for."
  (bt:with-lock-held ((spdy-server-write-lock server))
    (let ((payload (spdy-octet-buffer)))
      (spdy-put-u32 id payload)
      (loop for octet across (spdy-header-block (spdy-server-encoder server) nil)
            do (vector-push-extend octet payload))
      (spdy-server-control-frame server +spdy-syn-reply+ payload))))

(defun spdy-server-reset (server id status)
  "Refuse stream ID with the RST_STREAM STATUS code."
  (bt:with-lock-held ((spdy-server-write-lock server))
    (let ((payload (spdy-octet-buffer)))
      (spdy-put-u32 id payload)
      (spdy-put-u32 status payload)
      (spdy-server-control-frame server +spdy-rst-stream+ payload))))

(defun spdy-server-write-data (server id data &key fin)
  "Send DATA on stream ID, with FIN ending this side of it."
  (bt:with-lock-held ((spdy-server-write-lock server))
    (let ((head (spdy-octet-buffer)))
      (spdy-put-u32 id head)
      (spdy-put-u32 (logior (ash (if fin +spdy-flag-fin+ 0) 24) (length data)) head)
      (spdy-server-write-frame server head data))))

(defun spdy-server-read-frame (server)
  "Return the next frame of interest as (:syn id headers fin), (:data id fin octets) or (:reset id),
or NIL at the end. Pings are answered here, and a GOAWAY ends the session."
  (let ((read (spdy-transport-read-octets (spdy-server-transport server))))
    (loop
      (let ((head (funcall read 8)))
        (unless head (return nil))
        (let* ((flags (aref head 4))
               (size (logand (spdy-read-u32 head 4) #xFFFFFF))
               (payload (if (plusp size)
                            (or (funcall read size) (return nil))
                            (make-array 0 :element-type '(unsigned-byte 8)))))
          (if (logbitp 7 (aref head 0))
              (let ((type (+ (* 256 (aref head 2)) (aref head 3))))
                (cond ((= type +spdy-syn-stream+)
                       (return (list :syn (logand (spdy-read-u32 payload 0) #x7FFFFFFF)
                                     (spdy-inflate-header-block (spdy-server-inflater server) (subseq payload 10))
                                     (logbitp 0 flags))))
                      ((= type +spdy-ping+)
                       (bt:with-lock-held ((spdy-server-write-lock server))
                         (spdy-server-control-frame server +spdy-ping+ payload)))
                      ((= type +spdy-goaway+) (return nil))
                      ((= type +spdy-rst-stream+)
                       (return (list :reset (logand (spdy-read-u32 payload 0) #x7FFFFFFF))))))
              (return (list :data (logand (spdy-read-u32 head 0) #x7FFFFFFF)
                            (logbitp 0 flags) payload))))))))
