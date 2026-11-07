;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Exercise real HTTP/2 finalization against loopback sockets, including FD
;;;; reuse, overlapping shutdown, cleanup errors and compatibility-module reload.

(in-package #:gr8s/tests)
(def-suite grpc-close :in gr8s)
(in-suite grpc-close)

(defmacro with-http2-close-connection ((connection socket peer listener) &body body)
  "Own a real loopback connection and release its sockets after each close regression."
  `(let* ((,listener (usocket:socket-listen "127.0.0.1" 0 :element-type '(unsigned-byte 8)))
          (,socket (usocket:socket-connect "127.0.0.1" (usocket:get-local-port ,listener)
                                           :element-type '(unsigned-byte 8)))
          (,peer (usocket:socket-accept ,listener))
          (,connection (make-instance 'ag-http2:http2-connection :socket ,socket
                                       :stream (usocket:socket-stream ,socket) :client-p t)))
     (setf (ag-http2:connection-multiplexer ,connection) (ag-http2::make-stream-multiplexer :client-p t))
     (unwind-protect (progn ,@body)
       (ignore-errors (ag-http2:connection-close ,connection))
       (ignore-errors (usocket:socket-close ,peer))
       (ignore-errors (usocket:socket-close ,listener)))))

(defun check-fresh-connection-after-repeated-close (connection listener old-socket)
  "Exercise an actual reused descriptor, not a mocked shutdown counter."
  (let* ((fresh (usocket:socket-connect "127.0.0.1" (usocket:get-local-port listener)
                                       :element-type '(unsigned-byte 8)))
         (peer (usocket:socket-accept listener)))
    (unwind-protect
         (progn
           #+sbcl
           (is (= (sb-bsd-sockets:socket-file-descriptor (usocket:socket old-socket))
                  (sb-bsd-sockets:socket-file-descriptor (usocket:socket fresh))))
           (ag-http2:connection-close connection)
           (write-byte 42 (usocket:socket-stream peer))
           (force-output (usocket:socket-stream peer))
           (sb-sys:with-deadline (:seconds 2)
             (is (eql 42 (read-byte (usocket:socket-stream fresh) nil :eof)))))
      (ignore-errors (usocket:socket-close fresh))
      (ignore-errors (usocket:socket-close peer)))))

(test repeated-connection-close-cannot-shutdown-a-reused-file-descriptor
  (with-http2-close-connection (connection socket peer listener)
    (ag-http2:connection-close connection)
    (check-fresh-connection-after-repeated-close connection listener socket)))

(test overlapping-close-does-not-release-the-first-callers-socket
  (with-http2-close-connection (connection socket peer listener)
    (let* ((entered (bt:make-semaphore :name "HTTP/2 close entered"))
           (release (bt:make-semaphore :name "HTTP/2 close release"))
           (stream (ag-http2::connection-new-stream connection))
           (thread nil))
      (setf (ag-http2::stream-cleanup-callback stream)
            (lambda (stream) (declare (ignore stream))
              (bt:signal-semaphore entered) (bt:wait-on-semaphore release)))
      (unwind-protect
           (progn
             (setf thread (bt:make-thread (lambda () (ag-http2:connection-close connection))
                                         :name "HTTP/2 initial close"))
             (is (bt:wait-on-semaphore entered :timeout 2))
             (ag-http2:connection-close connection)
             (is (open-stream-p (usocket:socket-stream socket)))
             (bt:signal-semaphore release)
             (bt:join-thread thread)
             (is (eq :closed (ag-http2:connection-state connection)))
             (check-fresh-connection-after-repeated-close connection listener socket))
        (bt:signal-semaphore release)
        (when thread (bt:join-thread thread))))))

(test cleanup-error-does-not-allow-retrying-a-stale-descriptor
  (with-http2-close-connection (connection socket peer listener)
    (setf (ag-http2::stream-cleanup-callback (ag-http2::connection-new-stream connection))
          (lambda (stream) (declare (ignore stream)) (error "deliberate cleanup error")))
    (signals error (ag-http2:connection-close connection))
    (is (eq :closed (ag-http2:connection-state connection)))
    (is (not (open-stream-p (usocket:socket-stream socket))))
    (check-fresh-connection-after-repeated-close connection listener socket)))

(test reloading-close-compatibility-preserves-the-true-upstream-function
  (let ((original gr8s::*upstream-http2-connection-close*))
    (load (asdf:system-relative-pathname :gr8s "src/protocol/grpc-close-compat.lisp"))
    (is (eq original gr8s::*upstream-http2-connection-close*)))
  (with-http2-close-connection (connection socket peer listener)
    (ag-http2:connection-close connection)
    (check-fresh-connection-after-repeated-close connection listener socket)))

(define-condition http2-close-cancelled (serious-condition) ())

(test interrupted-ownership-handoff-cleans-stream-and-flow-control-waiters
  (with-http2-close-connection (connection socket peer listener)
    (let* ((entered (bt:make-semaphore :name "HTTP/2 upstream handoff"))
           (release (bt:make-semaphore :name "HTTP/2 upstream paused"))
           (reader-entered (bt:make-semaphore :name "HTTP/2 message reader entered"))
           (flow-entered (bt:make-semaphore :name "HTTP/2 flow waiter entered"))
           (buffer (ag-grpc::make-stream-message-buffer))
           (cleanup-count 0) (reader-result :pending) (flow-result :pending)
           (cancelled nil) (thread nil) (reader nil) (flow-waiter nil))
      (setf (ag-http2::stream-cleanup-callback (ag-http2::connection-new-stream connection))
            (lambda (stream) (declare (ignore stream))
              (incf cleanup-count) (ag-grpc::buffer-close buffer)))
      (unwind-protect
           (progn
             (setf reader (bt:make-thread
                           (lambda ()
                             (bt:signal-semaphore reader-entered)
                             (setf reader-result (multiple-value-list (ag-grpc::buffer-pop-message buffer))))
                           :name "HTTP/2 pending message reader")
                   flow-waiter (bt:make-thread
                                (lambda ()
                                  (bt2:with-lock-held ((ag-http2::connection-flow-control-lock connection))
                                    (bt:signal-semaphore flow-entered)
                                    (loop until (eq :closed (ag-http2:connection-state connection))
                                          do (bt2:condition-wait (ag-http2::connection-flow-control-cv connection)
                                                                  (ag-http2::connection-flow-control-lock connection)))
                                    (setf flow-result :closed)))
                                :name "HTTP/2 flow-control waiter"))
             (is (bt:wait-on-semaphore reader-entered :timeout 2))
             (is (bt:wait-on-semaphore flow-entered :timeout 2))
             (setf thread
                   (bt:make-thread
                    (lambda ()
                      ;; Pause exactly after the ownership claim and before
                      ;; entering the upstream finalizer's unwind protection.
                      (let ((gr8s::*upstream-http2-connection-close*
                              (lambda (&rest args)
                                (declare (ignore args))
                                (bt:signal-semaphore entered)
                                (bt:wait-on-semaphore release))))
                        (handler-case (ag-http2:connection-close connection)
                          (http2-close-cancelled () (setf cancelled t)))))
                    :name "HTTP/2 interrupted close"))
             (is (bt:wait-on-semaphore entered :timeout 2))
             (bt:interrupt-thread thread (lambda () (error 'http2-close-cancelled)))
             (bt:join-thread thread)
             (is-true cancelled)
             (is (eq :closed (ag-http2:connection-state connection)))
             (is (not (open-stream-p (usocket:socket-stream socket))))
             (is (wait-until (lambda () (not (eq :pending reader-result))) :timeout 2))
             (is (equal '(nil nil) reader-result))
             (is (wait-until (lambda () (eq :closed flow-result)) :timeout 2))
             (is (= 1 cleanup-count))
             (ag-http2:connection-close connection)
             (is (= 1 cleanup-count))
             (check-fresh-connection-after-repeated-close connection listener socket))
        (bt:signal-semaphore release)
        (ag-grpc::buffer-close buffer)
        (setf (ag-http2:connection-state connection) :closed)
        (bt2:with-lock-held ((ag-http2::connection-flow-control-lock connection))
          (bt2:condition-broadcast (ag-http2::connection-flow-control-cv connection)))
        (dolist (worker (list thread reader flow-waiter))
          (when worker (bt:join-thread worker)))))))

(test close-does-not-resend-frames-an-unwound-writer-left-buffered
  ;; podster-uqb.138: SBCL resets an fd-stream's buffer only after write(2)
  ;; returns, so a writer unwound there leaves a frame the peer already has.
  ;; The farewell GOAWAY must not flush it a second time.
  (with-http2-close-connection (connection socket peer listener)
    (let ((stale (ag-http2::make-data-frame 1 (make-array 5 :element-type '(unsigned-byte 8) :initial-element 0)
                                           :end-stream t)))
      (setf (ag-http2:connection-state connection) :open)
      (ag-http2:write-frame stale (usocket:socket-stream socket))
      (ag-http2:connection-close connection)
      (let ((received (make-array 0 :element-type '(unsigned-byte 8) :adjustable t :fill-pointer 0)))
        (sb-sys:with-deadline (:seconds 2)
          (loop for byte = (read-byte (usocket:socket-stream peer) nil nil)
                while byte do (vector-push-extend byte received)))
        ;; Only the GOAWAY (type 7) arrived; no DATA frame (type 0).
        (is (>= (length received) 9))
        (is (= 7 (aref received 3)))
        (is (= (length received) (+ 9 (+ (ash (aref received 0) 16) (ash (aref received 1) 8) (aref received 2)))))))))
