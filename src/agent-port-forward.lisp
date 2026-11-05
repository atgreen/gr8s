;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Carry one forwarded connection between the control plane and the runtime, which
;;;; reaches the port inside the Pod's network namespace, so a server listening only
;;;; on the Pod's localhost works. Port forwarding can move far more than a terminal,
;;;; so each direction has a credit window: a slow client or Pod holds up only this
;;;; connection. Writes get their own thread, because a Pod that stops reading must
;;;; not block the node session the operation arrived on.

(in-package #:gr8s)

(defstruct (node-port-forward-operation
             (:include node-exec-operation)
             (:constructor make-node-port-forward-operation
                 (node-runtime request socket session emit data-stream error-stream)))
  data-stream
  error-stream
  ;; (DATA . EOF) entries for the Pod, in order. The control plane's window bounds them.
  (input nil)
  (unacknowledged-output 0)
  writer
  (changed (bt:make-condition-variable :name "gr8s port-forward operation")))

(defun emit-port-forward-stream (operation &key data acknowledged)
  "Send the control plane DATA from the Pod, or tell it ACKNOWLEDGED bytes went to the Pod."
  (funcall (node-exec-operation-emit operation) :operation-stream
           (make-instance 'gr8s.node.v1::operation-stream
                          :operation-id (slot-value (node-exec-operation-request operation)
                                                    'gr8s.node.v1::operation-id)
                          :channel (if data
                                       gr8s.node.v1::+streamchannel-stream_channel_stdout+
                                       gr8s.node.v1::+streamchannel-stream_channel_unspecified+)
                          :data (or data (make-array 0 :element-type '(unsigned-byte 8)))
                          :acknowledged-bytes (or acknowledged 0))))

(defun wait-for-port-forward-output-window (operation size)
  "Return once SIZE more bytes may go to the control plane, or NIL if the operation has finished."
  (bt:with-lock-held ((node-exec-operation-lock operation))
    (loop
      (when (node-exec-operation-finished-p operation) (return nil))
      (when (< (node-port-forward-operation-unacknowledged-output operation) +port-forward-window-bytes+)
        (incf (node-port-forward-operation-unacknowledged-output operation) size)
        (return t))
      ;; FINISH-NODE-EXEC-OPERATION doesn't know this variable, so look again regularly.
      (bt:condition-wait (node-port-forward-operation-changed operation)
                         (node-exec-operation-lock operation) :timeout 0.2))))

(defun run-node-port-forward-reader (operation)
  "Forward what the Pod sends until the runtime has ended both streams, then report the outcome."
  (let ((open (list (node-port-forward-operation-data-stream operation)
                    (node-port-forward-operation-error-stream operation)))
        (message (spdy-octet-buffer)))
    (handler-case
        (loop while open
              do (let ((frame (spdy-read-frame (node-exec-operation-session operation))))
                   (ecase (first frame)
                     ((nil) (return))
                     (:reset (setf open (remove (second frame) open)))
                     (:data
                      (destructuring-bind (id fin data) (rest frame)
                        (cond
                          ((eql id (node-port-forward-operation-error-stream operation))
                           (loop for octet across data do (vector-push-extend octet message)))
                          ((plusp (length data))
                           (when (wait-for-port-forward-output-window operation (length data))
                             (emit-port-forward-stream operation :data data))))
                        (when fin (setf open (remove id open))))))))
      (error (condition)
        (finish-node-exec-operation operation :error (princ-to-string condition))
        (return-from run-node-port-forward-reader nil)))
    (if (plusp (length message))
        (finish-node-exec-operation
         operation :error (sb-ext:octets-to-string (coerce message '(simple-array (unsigned-byte 8) (*)))
                                                   :external-format '(:utf-8 :replacement #\?)))
        (finish-node-exec-operation operation))))

(defun run-node-port-forward-writer (operation)
  "Write queued data to the Pod, acknowledging each piece, until the client ends or the operation does."
  (handler-case
      (loop
        (let ((entry (bt:with-lock-held ((node-exec-operation-lock operation))
                       (loop until (or (node-port-forward-operation-input operation)
                                       (node-exec-operation-finished-p operation))
                             do (bt:condition-wait (node-port-forward-operation-changed operation)
                                                   (node-exec-operation-lock operation) :timeout 0.2))
                       (pop (node-port-forward-operation-input operation)))))
          (unless entry (return))
          (destructuring-bind (data . eof) entry
            (when (or eof (plusp (length data)))
              (spdy-write-data (node-exec-operation-session operation)
                               (node-port-forward-operation-data-stream operation) data :fin eof))
            (when (plusp (length data))
              (emit-port-forward-stream operation :acknowledged (length data)))
            (when eof (return)))))
    (error (condition)
      (finish-node-exec-operation operation :error (princ-to-string condition)))))

(defun write-node-port-forward-input (operation input)
  "Queue data for the Pod, or note how much the client has now taken. This never blocks."
  (let ((acknowledged (slot-value input 'gr8s.node.v1::acknowledged-bytes))
        (data (slot-value input 'gr8s.node.v1::data))
        (eof (slot-value input 'gr8s.node.v1::eof)))
    (bt:with-lock-held ((node-exec-operation-lock operation))
      (when (plusp acknowledged)
        (decf (node-port-forward-operation-unacknowledged-output operation) acknowledged))
      (when (or eof (plusp (length data)))
        (setf (node-port-forward-operation-input operation)
              (nconc (node-port-forward-operation-input operation) (list (cons data eof)))))
      (bt:condition-notify (node-port-forward-operation-changed operation)))))

(defun start-node-port-forward-operation (node-runtime request emit)
  "Connect to the runtime's forwarding stream for REQUEST's port, and start moving data."
  (assigned-operation-pod node-runtime request)
  (let ((port (slot-value request 'gr8s.node.v1::port))
        (uid (slot-value request 'gr8s.node.v1::pod-uid)))
    (unless (<= 1 port 65535)
      (error 'runtime-error :message "Port forwarding requires a valid port"))
    (multiple-value-bind (socket session)
        (connect-runtime-stream (runtime-port-forward-url (node-runtime-runtime node-runtime) uid port)
                                :protocol +port-forward-protocol+)
      (handler-case
          (let* ((headers (list (cons "port" (write-to-string port)) (cons "requestid" "0")))
                 (error-stream (spdy-open-stream session "error" headers))
                 (data-stream (spdy-open-stream session "data" headers))
                 (operation (make-node-port-forward-operation
                             node-runtime request socket session emit data-stream error-stream)))
            ;; This side never writes to the error stream, as kubectl doesn't.
            (spdy-write-data session error-stream (make-array 0 :element-type '(unsigned-byte 8)) :fin t)
            (remember-node-exec-operation node-runtime operation)
            (emit-node-exec-response operation gr8s.node.v1::+operationstatus-operation_status_accepted+)
            (setf (node-exec-operation-thread operation)
                  (bt:make-thread (lambda () (run-node-port-forward-reader operation))
                                  :name "gr8s port-forward reader")
                  (node-port-forward-operation-writer operation)
                  (bt:make-thread (lambda () (run-node-port-forward-writer operation))
                                  :name "gr8s port-forward writer"))
            operation)
        (error (condition)
          (ignore-errors (usocket:socket-close socket))
          (error 'runtime-error :message (princ-to-string condition)))))))
