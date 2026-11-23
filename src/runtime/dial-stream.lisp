;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; A TCP connection that a node opens on the control plane's behalf, as a binary
;;;; Lisp stream. TLS and HTTP run over it as over a socket, so a control plane with
;;;; no route to Pod IPs can still call a webhook in a Pod. It rides a port-forward
;;;; session, whose credit windows already pace each direction.

(in-package #:gr8s.runtime)

(defgeneric runtime-start-dial (runtime node-name address port)
  (:documentation "Ask NODE-NAME to connect to ADDRESS:PORT, returning a port-forward session."))
(defmethod runtime-start-dial ((runtime t) node-name address port)
  (declare (ignore node-name address port))
  (error 'runtime-error :message "This runtime cannot dial through a node"))

(defclass dial-stream (trivial-gray-streams:fundamental-binary-input-stream
                       trivial-gray-streams:fundamental-binary-output-stream)
  ((runtime :initarg :runtime)
   (session :initarg :session)
   ;; What the node sent last, and how much of it has been read.
   (input :initform (make-array 0 :element-type '(unsigned-byte 8)))
   (position :initform 0)
   (output :initform (make-array 64 :element-type '(unsigned-byte 8) :adjustable t :fill-pointer 0))
   (done :initform nil)
   (closed :initform nil)
   (lock :initform (bt:make-lock "gr8s dial stream"))))

(defun open-dial-stream (runtime node-name address port)
  "Return a stream connected to ADDRESS:PORT by NODE-NAME."
  (make-instance 'dial-stream :runtime runtime
                              :session (runtime-start-dial runtime node-name address port)))

(defmethod stream-element-type ((stream dial-stream)) '(unsigned-byte 8))

(defun dial-stream-fill (stream)
  "Wait for more input. Return NIL at its end, signalling the failure that ended it, if any."
  (with-slots (runtime session input position done closed) stream
    (loop
      (when (or done closed) (return nil))
      (multiple-value-bind (data finished failure) (runtime-port-forward-next runtime session)
        (cond (finished
               (setf done t)
               (when (and failure (not closed))
                 (error 'runtime-error :message failure))
               (return nil))
              ((plusp (length data))
               (setf input data position 0)
               (return t)))))))

(defmethod trivial-gray-streams:stream-read-byte ((stream dial-stream))
  (with-slots (input position) stream
    (if (or (< position (length input)) (dial-stream-fill stream))
        (prog1 (aref input position) (incf position))
        :eof)))

(defmethod trivial-gray-streams:stream-read-sequence ((stream dial-stream) sequence start end &key)
  (with-slots (input position) stream
    (let ((index start) (end (or end (length sequence))))
      (loop while (and (< index end)
                       (or (< position (length input)) (dial-stream-fill stream)))
            do (let ((count (min (- end index) (- (length input) position))))
                 (replace sequence input :start1 index :end1 (+ index count) :start2 position)
                 (incf index count)
                 (incf position count)))
      index)))

(defun dial-stream-send (stream data)
  "Send DATA, a simple octet vector, to the node."
  (with-slots (runtime session closed) stream
    (when closed (error 'stream-error :stream stream))
    (runtime-port-forward-send runtime session data)))

(defun dial-stream-flush (stream)
  "Send what WRITE-BYTE has gathered."
  (with-slots (output) stream
    (when (plusp (length output))
      (let ((data (coerce output '(simple-array (unsigned-byte 8) (*)))))
        (setf (fill-pointer output) 0)
        (dial-stream-send stream data)))))

(defmethod trivial-gray-streams:stream-write-byte ((stream dial-stream) byte)
  (vector-push-extend byte (slot-value stream 'output))
  byte)

(defparameter +dial-stream-buffer-bytes+ (* 64 1024)
  "How much a dial stream gathers before it sends without being asked. A client writes a
request in many small pieces; each piece sent is a frame, which reaching a node through
another control-plane member costs a round trip (podster-tjp).")

(defmethod trivial-gray-streams:stream-write-sequence ((stream dial-stream) sequence start end &key)
  (let ((output (slot-value stream 'output))
        (end (or end (length sequence))))
    (loop for index from start below end
          do (vector-push-extend (elt sequence index) output))
    (when (>= (length output) +dial-stream-buffer-bytes+)
      (dial-stream-flush stream)))
  sequence)

(defmethod trivial-gray-streams:stream-force-output ((stream dial-stream))
  (dial-stream-flush stream))

(defmethod trivial-gray-streams:stream-finish-output ((stream dial-stream))
  (dial-stream-flush stream))

(defmethod close ((stream dial-stream) &key abort)
  (declare (ignore abort))
  ;; Another thread may close the stream to end a read that is waiting on the node.
  (with-slots (runtime session closed lock) stream
    (when (bt:with-lock-held (lock) (and (not closed) (setf closed t)))
      (ignore-errors (runtime-cancel-port-forward runtime session "connection closed"))
      (ignore-errors (runtime-release-port-forward runtime session))))
  (call-next-method))
