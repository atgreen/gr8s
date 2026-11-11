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

(defvar *upstream-http2-connection-read-frame* (symbol-function 'ag-http2:connection-read-frame))
(defvar *upstream-http2-connection-handshake* (symbol-function 'ag-http2::connection-handshake))
(defvar *upstream-http2-server-handshake* (symbol-function 'ag-http2:server-connection-handshake))
(defvar *http2-owned-socket-disposal* nil)
(defvar *http2-socket-connections*
  #+sbcl (make-hash-table :test #'eq :weakness :key)
  #-sbcl (make-hash-table :test #'eq))
(defvar *http2-input-lifetimes*
  #+sbcl (make-hash-table :test #'eq :weakness :key)
  #-sbcl (make-hash-table :test #'eq))
(defstruct http2-input-lifetime (active 0) (drained (bt:make-semaphore)))

(defun http2-socket-connection-unlocked (socket)
  (let ((value (gethash socket *http2-socket-connections*)))
    #+sbcl (when value (sb-ext:weak-pointer-value value))
    #-sbcl value))

(defun register-http2-socket-unlocked (connection)
  (when (slot-boundp connection 'ag-http2::socket)
    (let ((socket (ag-http2::connection-socket connection)))
      (when (and (typep socket 'usocket:stream-usocket)
                 (not (eq connection (http2-socket-connection-unlocked socket))))
        ;; A weak value avoids a socket -> connection -> socket retention cycle.
        (setf (gethash socket *http2-socket-connections*)
              #+sbcl (sb-ext:make-weak-pointer connection)
              #-sbcl connection)))))

(defmethod initialize-instance :around ((connection ag-http2:http2-connection) &rest arguments &key &allow-other-keys)
  (declare (ignore arguments))
  (multiple-value-prog1 (call-next-method)
    (bt:with-lock-held (*http2-close-ownership-lock*)
      (register-http2-socket-unlocked connection))))

(defmethod usocket:socket-close :around ((socket usocket:stream-usocket))
  ;; The server's accepted-worker unwind also closes its raw usocket. It must
  ;; join connection finalization instead of bypassing deferred buffer disposal.
  (let ((connection (unless (eq socket *http2-owned-socket-disposal*)
                      (bt:with-lock-held (*http2-close-ownership-lock*)
                        (http2-socket-connection-unlocked socket)))))
    (if connection (ag-http2:connection-close connection) (call-next-method))))

(defun claim-http2-input (connection)
  (bt:with-lock-held (*http2-close-ownership-lock*)
    (unless (or (gethash connection *http2-close-owners*)
                (eq :closed (ag-http2:connection-state connection)))
      (register-http2-socket-unlocked connection)
      (let ((state (or (gethash connection *http2-input-lifetimes*)
                       (setf (gethash connection *http2-input-lifetimes*) (make-http2-input-lifetime)))))
        (incf (http2-input-lifetime-active state))
        state))))

(defun release-http2-input (connection state)
  (let ((notify nil))
    (bt:with-lock-held (*http2-close-ownership-lock*)
      (when (gethash connection *http2-close-owners*)
        ;; A handshake finishing concurrently with close must not reopen it.
        (setf (ag-http2:connection-state connection) :closed))
      (decf (http2-input-lifetime-active state))
      (setf notify (and (zerop (http2-input-lifetime-active state))
                        (gethash connection *http2-close-owners*))))
    (when notify (bt:signal-semaphore (http2-input-lifetime-drained state)))))

(defun call-with-http2-input (connection function)
  (let ((state nil))
    #+sbcl
    (sb-sys:without-interrupts
      (unwind-protect
           (progn
             (setf state (claim-http2-input connection))
             (unless state (error 'end-of-file :stream (ag-http2::connection-stream connection)))
             (sb-sys:with-local-interrupts (funcall function)))
        (when state (release-http2-input connection state))))
    #-sbcl
    (unwind-protect
         (progn
           (setf state (claim-http2-input connection))
           (unless state (error 'end-of-file :stream (ag-http2::connection-stream connection)))
           (funcall function))
      (when state (release-http2-input connection state)))))

(defun http2-active-input (connection)
  (bt:with-lock-held (*http2-close-ownership-lock*)
    (let ((state (gethash connection *http2-input-lifetimes*)))
      (when (and state (plusp (http2-input-lifetime-active state))) state))))

(defun await-http2-input (connection)
  (let ((state (http2-active-input connection)))
    (when state (bt:wait-on-semaphore (http2-input-lifetime-drained state)))))

(defun ag-http2:connection-read-frame (connection)
  (call-with-http2-input connection
    (lambda () (funcall *upstream-http2-connection-read-frame* connection))))

(defun ag-http2::connection-handshake (connection)
  (call-with-http2-input connection
    (lambda ()
      (bt2:with-lock-held ((ag-http2::connection-write-lock connection))
        (funcall *upstream-http2-connection-handshake* connection)))))

(defun ag-http2:server-connection-handshake (connection)
  (call-with-http2-input connection
    (lambda ()
      (bt2:with-lock-held ((ag-http2::connection-write-lock connection))
        (funcall *upstream-http2-server-handshake* connection)))))

(defun claim-http2-connection-close (connection)
  "Give exactly one caller ownership of the dependency's socket finalization."
  (bt:with-lock-held (*http2-close-ownership-lock*)
    (register-http2-socket-unlocked connection)
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
  "Dispose buffers only after input owners and frame writers have left.
Shutdown already wakes blocked socket operations. Never wait for input while
holding the writer lock: processing an incoming frame may need that lock."
  (let ((lock (ag-http2::connection-write-lock connection)))
    (flet ((release-socket ()
             (ignore-errors (discard-unsent-http2-output connection))
             (let* ((socket (ag-http2::connection-socket connection))
                    (*http2-owned-socket-disposal* socket))
               (ignore-errors (usocket:socket-close socket)))))
      (if (and (not (http2-active-input connection))
               (ignore-errors (bt2:acquire-lock lock :wait nil)))
          (unwind-protect (release-socket) (bt2:release-lock lock))
          (bt:make-thread
           (lambda ()
             (await-http2-input connection)
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
  "Finalize once, retaining buffers until active input and output owners exit.
Shutdown wakes socket and flow-control waiters immediately. Stream disposal may
finish asynchronously while an input owner or frame writer is still active."
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
