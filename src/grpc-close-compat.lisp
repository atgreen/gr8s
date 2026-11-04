;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Make the pinned ag-http2 connection finalizer safe when shutdown and the
;;;; connection reader close the same object concurrently or repeatedly. On
;;;; SBCL, closing a usocket stream leaves its socket object's numeric FD intact;
;;;; a second shutdown can therefore terminate an unrelated, newly opened socket.

(in-package #:gr8s)

(defvar *upstream-http2-connection-close* (symbol-function 'ag-http2:connection-close)
  "Capture the true pinned dependency finalizer once, including across ASDF reloads.")

(defvar *http2-close-ownership-lock* (bt:make-lock "gr8s HTTP/2 close ownership"))
(defvar *http2-close-owners*
  #+sbcl (make-hash-table :test #'eq :weakness :key)
  #-sbcl (make-hash-table :test #'eq)
  "Claims last for the connection's lifetime, even if upstream cleanup signals.
Weak keys on SBCL, gr8s's supported native runtime, do not retain dead connections.")

(defun claim-http2-connection-close (connection)
  "Give exactly one caller ownership of the dependency's socket finalization."
  (bt:with-lock-held (*http2-close-ownership-lock*)
    (unless (or (gethash connection *http2-close-owners*)
                (eq :closed (ag-http2:connection-state connection)))
      (setf (gethash connection *http2-close-owners*) t))))

(defun finish-open-http2-socket (connection)
  "Cover cancellation before upstream entered, without touching a closed/reused FD."
  (let ((socket (ag-http2::connection-socket connection)))
    (when (and socket (open-stream-p (usocket:socket-stream socket)))
      (setf (ag-http2:connection-state connection) :closed)
      (bt2:condition-broadcast (ag-http2::connection-flow-control-cv connection))
      (ignore-errors (usocket:socket-shutdown socket :io))
      (ignore-errors (usocket:socket-close socket)))))

(defun ag-http2:connection-close (connection &key (error-code ag-http2::+error-no-error+) debug-data)
  "Run the pinned upstream finalizer once; never retry a potentially reused FD.
Keep upstream cleanup callbacks, best-effort GOAWAY, bounded write-lock wait,
flow-control wakeup, and unwind-protected socket release unchanged. Establish
our own unwind protection before admitting cancellation after the claim."
  (let ((owned nil))
    #+sbcl
    (sb-sys:without-interrupts
      (unwind-protect
           (when (setf owned (claim-http2-connection-close connection))
             (sb-sys:with-local-interrupts
               (funcall *upstream-http2-connection-close* connection
                        :error-code error-code :debug-data debug-data)))
        (when owned (finish-open-http2-socket connection))))
    #-sbcl
    (unwind-protect
         (when (setf owned (claim-http2-connection-close connection))
           (funcall *upstream-http2-connection-close* connection
                    :error-code error-code :debug-data debug-data))
      (when owned (finish-open-http2-socket connection)))))
