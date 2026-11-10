;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Deterministic diagnostic for podster-ucm.11.9. This reproduces an HTTP/2
;;;; output-buffer ownership violation; it does NOT establish the cause of the
;;;; original invalid-UTF8 snapshot spool. No root or containers are required.
;;;; Run from the repository: sbcl --noinform --non-interactive --load
;;;; scripts/probe-http2-close-buffer.lisp
;;;; A successful reproduction prints mutated-while-writer-owned-lock=T.
;;;; Upstream finalization is paused by a thread-local function binding, so the
;;;; buffer is inspected before socket closure and without timing-based sleeps.

(require :asdf)
(asdf:load-system "gr8s")
(let* ((listener (usocket:socket-listen "127.0.0.1" 0 :element-type '(unsigned-byte 8)))
       (socket (usocket:socket-connect "127.0.0.1" (usocket:get-local-port listener) :element-type '(unsigned-byte 8)))
       (peer (usocket:socket-accept listener))
       (stream (usocket:socket-stream socket))
       (connection (make-instance 'ag-http2:http2-connection :socket socket :stream stream :client-p t))
       (entered (bt:make-semaphore)) (release (bt:make-semaphore))
       (closer nil) (close-error nil) (before nil) (after nil))
  (setf (ag-http2:connection-multiplexer connection) (ag-http2::make-stream-multiplexer :client-p t))
  (unwind-protect
       (progn
         ;; Hold the same lock that all frame writers own. Pause close before
         ;; upstream finalization so the observation cannot depend on FD reuse.
         (bt2:with-lock-held ((ag-http2::connection-write-lock connection))
           (write-byte 42 stream)
           (setf before (sb-impl::buffer-tail (sb-impl::fd-stream-obuf stream)))
           (setf closer
                 (bt:make-thread
                  (lambda ()
                    (let ((gr8s.protocol::*upstream-http2-connection-close*
                            (lambda (&rest args)
                              (declare (ignore args))
                              (bt:signal-semaphore entered)
                              (unless (bt:wait-on-semaphore release :timeout 10)
                                (error "Probe release timed out")))))
                      (handler-case (ag-http2:connection-close connection)
                        (error (condition) (setf close-error condition)))))
                  :name "HTTP2 close buffer probe"))
           (unless (bt:wait-on-semaphore entered :timeout 10)
             (error "Close did not enter upstream handoff"))
           (setf after (sb-impl::buffer-tail (sb-impl::fd-stream-obuf stream))))
         (bt:signal-semaphore release)
         (bt:join-thread closer)
         (when close-error (error close-error))
         (format t "~&HTTP2_CLOSE_BUFFER_PROBE before=~D after=~D mutated-while-writer-owned-lock=~A~%"
                 before after (and (plusp before) (/= before after)))
         (unless (and (plusp before) (zerop after))
           (error "Expected current unsafe behavior was not reproduced")))
    (bt:signal-semaphore release)
    (when closer (bt:join-thread closer))
    (ignore-errors (ag-http2:connection-close connection))
    (ignore-errors (usocket:socket-close peer))
    (ignore-errors (usocket:socket-close listener))))
