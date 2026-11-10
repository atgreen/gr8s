;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Make the pinned ag-http2 connection finalizer safe when shutdown and the
;;;; connection reader close the same object concurrently or repeatedly. On
;;;; SBCL, closing a usocket stream leaves its socket object's numeric FD intact;
;;;; a second shutdown can therefore terminate an unrelated, newly opened socket.
;;;; Buffer reset and stream disposal also require the frame writer lock: socket
;;;; shutdown wakes blocked writes before a deferred finalizer recycles buffers.

(in-package #:gr8s.protocol)

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
  "Finish pending stream cleanup after a cancelled handoff; never reuse a closed FD.
Socket and flow-control wakeups cannot wake a server STREAM-RECV waiter: its
message buffer is closed only by the stream callback. Upstream atomically
claims each callback, so this sweep cannot repeat an already invoked callback."
  (unwind-protect
       (let* ((mux (ag-http2:connection-multiplexer connection))
              (streams (when mux
                         (bt2:with-lock-held ((ag-http2::multiplexer-lock mux))
                           (loop for stream being the hash-values of
                                 (ag-http2::multiplexer-streams mux) collect stream)))))
         (dolist (stream streams)
           ;; Preserve the original error while attempting every pending callback.
           (handler-case (ag-http2::stream-run-cleanup stream)
             (serious-condition () nil))))
    (setf (ag-http2:connection-state connection) :closed)
    (bt2:with-lock-held ((ag-http2::connection-flow-control-lock connection))
      (bt2:condition-broadcast (ag-http2::connection-flow-control-cv connection)))
    (let ((socket (ag-http2::connection-socket connection)))
      (when (and socket (open-stream-p (usocket:socket-stream socket)))
        (ignore-errors (usocket:socket-shutdown socket :io))
        (release-http2-socket-after-writer connection)))))

(defun discard-unsent-http2-output (connection)
  "With CONNECTION's write lock held, drop bytes left by an unwound writer.
Every ag-http2 frame write is followed by FORCE-OUTPUT, so nothing legitimate is
pending at close. But SBCL's FLUSH-OUTPUT-BUFFER resets the buffer only after
write(2) returns: an interrupt that unwinds a writer there (a superseded Pod
creation is cancelled that way) leaves frames the peer already received, and
the GOAWAY flush would send them again. A repeated DATA frame with END_STREAM
crashed containerd's grpc-go server (podster-uqb.138). CLEAR-OUTPUT is a no-op
on SBCL fd-streams, so reset the buffer itself."
  #+sbcl
  (let ((stream (ag-http2::connection-stream connection)))
    (when (typep stream 'sb-sys:fd-stream)
      (let ((buffer (sb-impl::fd-stream-obuf stream)))
        (when buffer
          (setf (sb-impl::buffer-head buffer) 0
                (sb-impl::buffer-tail buffer) 0)))
      (setf (sb-impl::fd-stream-output-queue stream) nil)))
  #-sbcl
  (ignore-errors (clear-output (ag-http2::connection-stream connection))))

(defun release-http2-socket-after-writer (connection)
  "Recycle stream buffers only after the last active frame writer releases them.
The owner has already shut down the socket, which wakes blocked kernel writes.
A delayed writer must not make the closing caller wait indefinitely. Retain the
socket in a private finalizer until its write lock becomes available instead."
  (let ((lock (ag-http2::connection-write-lock connection)))
    (flet ((release-socket ()
             (ignore-errors (discard-unsent-http2-output connection))
             (ignore-errors
               (usocket:socket-close (ag-http2::connection-socket connection)))))
      (if (ignore-errors (bt2:acquire-lock lock :wait nil))
          (unwind-protect (release-socket) (bt2:release-lock lock))
          (bt:make-thread
           (lambda ()
             (bt2:with-lock-held (lock) (release-socket)))
           :name "gr8s HTTP/2 deferred socket close")))))

(defun close-http2-connection-body (connection &key error-code debug-data)
  "Pinned upstream cleanup/GOAWAY semantics with exclusive output-buffer access."
  (let* ((mux (ag-http2:connection-multiplexer connection))
         (streams (when mux
                    (bt2:with-lock-held ((ag-http2::multiplexer-lock mux))
                      (loop for stream being the hash-values of
                            (ag-http2::multiplexer-streams mux) collect stream)))))
    (dolist (stream streams)
      (setf (ag-http2:stream-state stream) :closed)
      (ag-http2::stream-run-cleanup stream)))
  (when (eq :open (ag-http2:connection-state connection))
    (setf (ag-http2:connection-state connection) :closing)
    (bt2:with-lock-held ((ag-http2::connection-flow-control-lock connection))
      (bt2:condition-broadcast (ag-http2::connection-flow-control-cv connection)))
    (ignore-errors
      (bt2:with-lock-held ((ag-http2::connection-write-lock connection)
                           :timeout ag-http2::+goaway-lock-timeout+)
        (discard-unsent-http2-output connection)
        (ag-http2:write-frame
         (ag-http2::make-goaway-frame (ag-http2::connection-last-stream-id connection)
                                      error-code debug-data)
         (ag-http2::connection-stream connection))
        (force-output (ag-http2::connection-stream connection))))))

(defvar *http2-connection-close-body* nil
  "Close body hook, also used to exercise cancellation at ownership handoff.")

(defun ag-http2:connection-close (connection &key (error-code ag-http2::+error-no-error+) debug-data)
  "Finalize once, keeping active writers' buffers alive until they release them.
Shutdown wakes socket and flow-control waiters immediately. Stream disposal may
finish asynchronously when a writer still owns the connection write lock."
  (let ((owned nil))
    #+sbcl
    (sb-sys:without-interrupts
      (unwind-protect
           (when (setf owned (claim-http2-connection-close connection))
             (sb-sys:with-local-interrupts
               (funcall (or *http2-connection-close-body* #'close-http2-connection-body) connection
                        :error-code error-code :debug-data debug-data)))
        (when owned (finish-open-http2-socket connection))))
    #-sbcl
    (unwind-protect
         (when (setf owned (claim-http2-connection-close connection))
           (funcall (or *http2-connection-close-body* #'close-http2-connection-body) connection
                    :error-code error-code :debug-data debug-data))
      (when owned (finish-open-http2-socket connection)))))
