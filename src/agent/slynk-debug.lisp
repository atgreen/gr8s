;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Run a lifetime-bound Slynk server inside one selected node agent and carry
;;;; its already-authenticated protocol bytes over the node operation stream.

(in-package #:gr8s.agent)

(defstruct (node-slynk-operation
             (:include node-exec-operation)
             (:constructor make-node-slynk-operation
                 (node-runtime request socket session emit debug-session)))
  debug-session
  (input nil)
  writer
  (changed (bt:make-condition-variable :name "gr8s node Slynk operation")))

(defmethod cleanup-node-operation ((operation node-slynk-operation))
  (stop-on-demand-debug-session (node-slynk-operation-debug-session operation)))

(defun run-node-slynk-reader (operation)
  "Relay Slynk output until it closes or the operation is cancelled."
  (let ((buffer (make-array 65536 :element-type '(unsigned-byte 8)))
        (fd (sb-bsd-sockets:socket-file-descriptor
             (usocket::socket (node-exec-operation-socket operation)))))
    (handler-case
        (loop
          for count = (sb-sys:with-pinned-objects (buffer)
                        (multiple-value-bind (read errno)
                            (sb-unix:unix-read fd (sb-sys:vector-sap buffer) (length buffer))
                          (unless read
                            (error "Slynk tunnel read failed (errno ~D)" errno))
                          read))
          while (plusp count)
          do (when (wait-for-node-exec-output-window operation count)
               (emit-node-exec-stream
                operation gr8s.node.v1::+streamchannel-stream_channel_stdout+
                (subseq buffer 0 count))))
      (error (condition)
        (unless (node-exec-operation-finished-p operation)
          (finish-node-exec-operation operation :error (princ-to-string condition)))
        (return-from run-node-slynk-reader nil)))
    (finish-node-exec-operation operation)))

(defun run-node-slynk-writer (operation)
  "Write queued tunnel input without blocking the authenticated node session."
  (handler-case
      (loop
        (let ((entry
                (bt:with-lock-held ((node-exec-operation-lock operation))
                  (loop until (or (node-slynk-operation-input operation)
                                  (node-exec-operation-finished-p operation))
                        do (bt:condition-wait (node-slynk-operation-changed operation)
                                              (node-exec-operation-lock operation) :timeout 0.2))
                  (pop (node-slynk-operation-input operation)))))
          (unless entry (return))
          (destructuring-bind (data . eof) entry
            (when (plusp (length data))
              (write-sequence data (node-exec-operation-session operation))
              (finish-output (node-exec-operation-session operation)))
            (when eof
              (ignore-errors (usocket:socket-shutdown (node-exec-operation-socket operation) :output))
              (return)))))
    (error (condition)
      (finish-node-exec-operation operation :error (princ-to-string condition)))))

(defun write-node-slynk-input (operation input)
  "Queue debugger bytes and apply output acknowledgements without blocking."
  (let ((acknowledged (slot-value input 'gr8s.node.v1::acknowledged-bytes))
        (data (slot-value input 'gr8s.node.v1::data))
        (eof (slot-value input 'gr8s.node.v1::eof)))
    (bt:with-lock-held ((node-exec-operation-lock operation))
      (when (plusp acknowledged)
        (setf (node-exec-operation-unacknowledged-output operation)
              (max 0 (- (node-exec-operation-unacknowledged-output operation) acknowledged)))
        (bt:condition-notify (node-exec-operation-output-window operation)))
      (when (or eof (plusp (length data)))
        (setf (node-slynk-operation-input operation)
              (nconc (node-slynk-operation-input operation) (list (cons data eof)))))
      (bt:condition-notify (node-slynk-operation-changed operation)))))

(defun start-node-slynk-operation (node-runtime request emit)
  "Start one temporary debugger in NODE-RUNTIME and register its byte stream."
  (let ((debug-session
          (start-on-demand-debug-session
           (node-runtime-state-directory node-runtime)
           :store (node-runtime-store node-runtime)
           :reconciler (node-runtime-reconciler node-runtime))))
    (handler-case
        (multiple-value-bind (stream socket) (open-on-demand-debug-stream debug-session)
          (let ((operation (make-node-slynk-operation
                            node-runtime request socket stream emit debug-session)))
            (remember-node-exec-operation node-runtime operation)
            (emit-node-exec-response
             operation gr8s.node.v1::+operationstatus-operation_status_accepted+)
            (setf (node-exec-operation-thread operation)
                  (bt:make-thread (lambda () (run-node-slynk-reader operation))
                                  :name "gr8s Slynk tunnel reader")
                  (node-slynk-operation-writer operation)
                  (bt:make-thread (lambda () (run-node-slynk-writer operation))
                                  :name "gr8s Slynk tunnel writer"))
            operation))
      (error (condition)
        (stop-on-demand-debug-session debug-session)
        (error condition)))))
