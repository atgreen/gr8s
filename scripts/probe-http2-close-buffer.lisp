;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Standalone regression probe for podster-ucm.11.9's HTTP/2 buffer race.
;;;; No root or containers required. Run from the repository:
;;;; sbcl --noinform --non-interactive --load scripts/probe-http2-close-buffer.lisp
;;;; Close must return while the writer lock is held, leave its buffer intact,
;;;; and release the socket after the writer unlocks. The original snapshot
;;;; corruption remains a separate, unproven causal link.

(require :asdf)
(asdf:load-system "gr8s")
(let* ((listener (usocket:socket-listen "127.0.0.1" 0 :element-type '(unsigned-byte 8)))
       (socket (usocket:socket-connect "127.0.0.1" (usocket:get-local-port listener) :element-type '(unsigned-byte 8)))
       (peer (usocket:socket-accept listener))
       (stream (usocket:socket-stream socket))
       (connection (make-instance 'ag-http2:http2-connection :socket socket :stream stream :client-p t))
       (returned (bt:make-semaphore))
       (closer nil) (close-error nil) (before nil) (after nil))
  (setf (ag-http2:connection-multiplexer connection) (ag-http2::make-stream-multiplexer :client-p t))
  (unwind-protect
       (progn
         (setf (ag-http2:connection-state connection) :open)
         (bt2:with-lock-held ((ag-http2::connection-write-lock connection))
           (write-byte 42 stream)
           (setf before (sb-impl::buffer-tail (sb-impl::fd-stream-obuf stream)))
           (setf closer
                 (bt:make-thread
                  (lambda ()
                    (unwind-protect
                         (handler-case (ag-http2:connection-close connection)
                           (error (condition) (setf close-error condition)))
                      (bt:signal-semaphore returned)))
                  :name "HTTP2 close buffer probe"))
           (unless (bt:wait-on-semaphore returned :timeout 3)
             (error "Close did not return within its bounded lock wait"))
           (setf after (sb-impl::buffer-tail (sb-impl::fd-stream-obuf stream)))
           (unless (open-stream-p stream)
             (error "Stream recycled while writer still owns its buffer")))
         (bt:join-thread closer)
         (when close-error (error close-error))
         (format t "~&HTTP2_CLOSE_BUFFER_PROBE before=~D after=~D mutated-while-writer-owned-lock=~A~%"
                 before after (and (plusp before) (/= before after)))
         (unless (and (plusp before) (= before after))
           (error "Active writer buffer changed during close"))
         (loop repeat 300 while (open-stream-p stream) do (sleep 0.01))
         (when (open-stream-p stream) (error "Deferred close did not release socket")))
    (when closer (bt:join-thread closer))
    (ignore-errors (ag-http2:connection-close connection))
    (ignore-errors (usocket:socket-close peer))
    (ignore-errors (usocket:socket-close listener))))
