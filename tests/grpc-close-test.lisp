;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Exercise real HTTP/2 finalization against loopback sockets, including FD
;;;; reuse, overlapping shutdown, cleanup errors and compatibility-module reload.

(in-package #:gr8s/tests)
(def-suite grpc-close :in gr8s)
(in-suite grpc-close)

(defmacro with-http2-close-connection ((connection socket peer listener) &body body)
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
    (load (asdf:system-relative-pathname :gr8s "src/grpc-close-compat.lisp"))
    (is (eq original gr8s::*upstream-http2-connection-close*)))
  (with-http2-close-connection (connection socket peer listener)
    (ag-http2:connection-close connection)
    (check-fresh-connection-after-repeated-close connection listener socket)))
