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
  (let ((original gr8s.protocol::*upstream-http2-connection-close*))
    (load (asdf:system-relative-pathname :gr8s "src/protocol/grpc-close-compat.lisp"))
    (is (eq original gr8s.protocol::*upstream-http2-connection-close*)))
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
                      (let ((gr8s.protocol::*http2-connection-close-body*
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

(test late-frames-do-not-recreate-retired-streams
  (with-http2-close-connection (connection socket peer listener)
    (let* ((mux (ag-http2:connection-multiplexer connection))
           (stream (ag-http2::multiplexer-new-stream mux))
           (id (ag-http2:stream-id stream))
           (cleanups 0))
      (setf (ag-http2::stream-cleanup-callback stream)
            (lambda (ignored) (declare (ignore ignored)) (incf cleanups)))
      (ag-http2::multiplexer-close-stream mux id)
      (ag-http2::multiplexer-forget-stream mux id)
      (dolist (frame (list (ag-http2::make-data-frame id #(1 2 3) :end-stream t)
                           (ag-http2::make-window-update-frame id 3)
                           (ag-http2::make-rst-stream-frame id ag-http2::+error-cancel+)
                           (ag-http2::make-headers-frame
                            id (ag-http2::hpack-encode (ag-http2::make-hpack-encoder)
                                                      '((:status . "200")))
                            :end-headers t :end-stream t)))
        (ag-http2::process-frame connection frame)
        (is (zerop (hash-table-count (ag-http2::multiplexer-streams mux)))))
      (is (= 1 cleanups))
      (is (eq :closed (ag-http2:stream-state (ag-http2::multiplexer-get-stream mux id))))
      (is (zerop (length (ag-http2::stream-data-buffer stream)))))))

(test connection-close-marks-stream-closed-before-retirement-callback
  (with-http2-close-connection (connection socket peer listener)
    (let* ((mux (ag-http2:connection-multiplexer connection))
           (stream (ag-http2::multiplexer-new-stream mux)))
      (setf (ag-http2::stream-cleanup-callback stream)
            (lambda (closed)
              (ag-http2::multiplexer-forget-stream mux (ag-http2:stream-id closed))))
      (ag-http2:connection-close connection)
      (is (eq :closed (ag-http2:stream-state stream)))
      (is (zerop (hash-table-count (ag-http2::multiplexer-streams mux)))))))

(test consumed-http2-data-releases-capacity-without-altering-returned-payload
  (let ((stream (ag-http2::make-http2-stream 1))
        (payload (make-array 65536 :element-type '(unsigned-byte 8) :initial-element 42)))
    (ag-http2::stream-append-data stream payload)
    (let ((consumed (ag-http2::stream-consume-data stream)))
      (is (equalp payload consumed))
      (is (zerop (array-total-size (ag-http2::stream-data-buffer stream))))
      ;; Reuse does not alter the caller's already-consumed data.
      (ag-http2::stream-append-data stream #(1 2 3))
      (is (equalp #(1 2 3) (ag-http2::stream-consume-data stream)))
      (is (equalp payload consumed))
      (is (zerop (array-total-size (ag-http2::stream-data-buffer stream)))))))

(test unary-dispatch-does-not-retain-request-body-in-http2-stream
  (with-http2-close-connection (connection socket peer listener)
    (let* ((stream (ag-http2::connection-new-stream connection))
           (id (ag-http2::stream-id stream))
           (payload (make-array 65536 :element-type '(unsigned-byte 8) :initial-element 7))
           (original (symbol-function 'ag-grpc::server-dispatch-handler))
           (dispatched nil))
      (ag-grpc::connection-set-stream-context connection stream :test-context)
      (ag-grpc::connection-set-stream-handler connection stream :test-handler)
      (ag-http2::stream-append-data stream payload)
      (unwind-protect
           (progn
             (setf (symbol-function 'ag-grpc::server-dispatch-handler)
                   (lambda (server conn ctx handler body)
                     (declare (ignore server conn ctx handler))
                     (setf dispatched t)
                     (is (equalp payload body))
                     (is (zerop (array-total-size (ag-http2::stream-data-buffer stream))))))
             (ag-grpc::server-handle-data nil connection (ag-http2::make-data-frame id #() :end-stream t))
             (is-true dispatched))
        (setf (symbol-function 'ag-grpc::server-dispatch-handler) original)))))

(test retired-http2-stream-ids-stay-closed-with-bounded-metadata
  (let ((mux (ag-http2::make-stream-multiplexer :client-p t)) (cleanups 0))
    (dotimes (i 10000)
      (let* ((stream (ag-http2::multiplexer-new-stream mux)) (id (ag-http2::stream-id stream)))
        (setf (ag-http2::stream-cleanup-callback stream) (lambda (ignored) (declare (ignore ignored)) (incf cleanups)))
        (ag-http2::multiplexer-close-stream mux id)
        (ag-http2::multiplexer-forget-stream mux id)))
    (is (= 10000 cleanups))
    (is (zerop (hash-table-count (ag-http2::multiplexer-streams mux))))
    (is (< (hash-table-size (ag-http2::multiplexer-streams mux)) 64))
    (dolist (id '(1 9999 19999))
      (let ((old (ag-http2::multiplexer-get-stream mux id)))
        (is (eq :closed (ag-http2::stream-state old)))
        (ag-http2::multiplexer-close-stream mux id)))
    (is (= 10000 cleanups))
    (is (zerop (hash-table-count (ag-http2::multiplexer-streams mux))))
    ;; The peer's parity has an independent high-water mark; skipped IDs close implicitly.
    (ag-http2::multiplexer-get-stream mux 8)
    (is (eq :closed (ag-http2::stream-state (ag-http2::multiplexer-get-stream mux 4))))
    (is (eq :idle (ag-http2::stream-state (ag-http2::multiplexer-get-stream mux 10))))))

(test retirement-preserves-active-and-unread-stream-state
  (let* ((mux (ag-http2::make-stream-multiplexer))
         (first (ag-http2::multiplexer-new-stream mux))
         (second (ag-http2::multiplexer-new-stream mux)))
    (signals error (ag-http2::multiplexer-forget-stream mux (ag-http2::stream-id first)))
    (ag-http2::stream-append-data first #(1 2 3))
    (ag-http2::multiplexer-close-stream mux (ag-http2::stream-id first))
    (is (eq first (ag-http2::multiplexer-get-stream mux (ag-http2::stream-id first))))
    (is (equalp #(1 2 3) (ag-http2::stream-consume-data first)))
    (ag-http2::multiplexer-forget-stream mux (ag-http2::stream-id first))
    (is (eq second (ag-http2::multiplexer-get-stream mux (ag-http2::stream-id second))))
    (is (= 1 (hash-table-count (ag-http2::multiplexer-streams mux))))))

(test completed-unary-rpcs-retire-both-sides-of-one-live-connection
  (let* ((server (ag-grpc:make-grpc-server 0 :host "127.0.0.1"))
         (thread nil) (channel nil) (server-mux nil) (peak 0) (calls 0))
    (ag-grpc::server-register-handler server "/retirement.Test/Echo"
      (lambda (request ctx)
        (declare (ignore request))
        (let* ((mux (ag-http2:connection-multiplexer (ag-grpc::context-connection ctx)))
               (count (hash-table-count (ag-http2::multiplexer-streams mux))))
          (when server-mux (unless (eq mux server-mux) (error "RPC unexpectedly reconnected")))
          (setf server-mux mux peak (max peak count))
          (incf calls))
        (make-instance 'gr8s.node.v1::raft-ack))
      :request-type 'gr8s.node.v1::raft-ack :response-type 'gr8s.node.v1::raft-ack)
    (unwind-protect
         (progn
           (setf thread (bt:make-thread (lambda () (ag-grpc:server-start server))))
           (unless (poll-until (lambda () (ag-grpc::server-socket server))) (error "Test server did not listen"))
           (setf channel (gr8s.security::make-raft-channel nil "127.0.0.1" (usocket:get-local-port (ag-grpc::server-socket server)) 5))
           (dotimes (i 512)
             (ag-grpc:call-unary channel "/retirement.Test/Echo" (make-instance 'gr8s.node.v1::raft-ack)
                                 :response-type 'gr8s.node.v1::raft-ack :timeout 5))
           (is (= 512 calls))
           (is (= 1 peak))
           (is (zerop (hash-table-count (ag-http2::multiplexer-streams
                                        (ag-http2:connection-multiplexer (ag-grpc::channel-connection channel))))))
           (is (poll-until (lambda () (zerop (hash-table-count (ag-http2::multiplexer-streams server-mux)))))))
      (when channel (ignore-errors (ag-grpc:channel-close channel)))
      (ag-grpc:server-stop server)
      (when thread (bt:join-thread thread)))))

(test failed-stream-setup-and-early-server-stream-exit-release-transport
  (with-http2-close-connection (connection socket peer listener)
    (setf (ag-http2:connection-state connection) :open)
    (let* ((channel (make-instance 'ag-grpc::grpc-channel :host "127.0.0.1" :port 1
                                                        :connection connection :default-timeout nil))
           (mux (ag-http2:connection-multiplexer connection)))
      ;; Malformed metadata fails after allocation, before a stream is returned.
      (dolist (setup (list (lambda () (ag-grpc:call-server-stream channel "/bad" #() :metadata '(42)))
                          (lambda () (ag-grpc:call-client-streaming channel "/bad" :metadata '(42)))
                          (lambda () (ag-grpc:call-bidirectional-streaming channel "/bad" :metadata '(42)))
                          ;; Serialization fails after request headers have gone out.
                          (lambda () (ag-grpc:call-server-stream channel "/bad" 42))))
        (signals error (funcall setup))
        (is (zerop (hash-table-count (ag-http2::multiplexer-streams mux)))))
      (is (eq :early
              (catch 'exit-stream
                (ag-grpc:with-server-stream (stream channel "/early" #())
                  (throw 'exit-stream :early)))))
      (is (zerop (hash-table-count (ag-http2::multiplexer-streams mux)))))))

(test rejected-unary-call-retires-without-registered-handler-state
  (with-http2-close-connection (connection socket peer listener)
    (let* ((server (ag-grpc:make-grpc-server 0 :host "127.0.0.1"))
           (stream (ag-http2::connection-new-stream connection))
           (id (ag-http2:stream-id stream)))
      (setf (ag-http2:stream-state stream) :half-closed-remote
            (ag-http2:stream-headers stream) '((:path . "/missing")))
      (ag-grpc::server-handle-headers server connection
                                     (ag-http2::make-headers-frame id #() :end-headers t) "test")
      (is (eq :closed (ag-http2:stream-state stream)))
      (is (zerop (hash-table-count (ag-http2::multiplexer-streams
                                    (ag-http2:connection-multiplexer connection)))))
      (is (zerop (ag-http2:connection-active-streams connection))))))

(test streaming-decoder-releases-consumed-capacity-and-preserves-partial-message
  (with-http2-close-connection (connection socket peer listener)
    (let* ((stream (ag-http2::connection-new-stream connection))
           (id (ag-http2:stream-id stream))
           (ctx (make-instance 'ag-grpc::grpc-call-context :connection connection :stream-id id))
           (handler (make-instance 'ag-grpc::grpc-handler :request-type 'gr8s.node.v1::raft-ack))
           (buffer (ag-grpc::make-stream-message-buffer))
           (frame (ag-grpc::encode-grpc-message #())))
      (ag-grpc::connection-set-stream-context connection stream ctx)
      (ag-grpc::connection-set-stream-handler connection stream handler)
      (setf (gethash id (ag-http2:connection-stream-buffers connection)) buffer
            (ag-http2:stream-data-buffer stream)
            (make-array 65536 :element-type '(unsigned-byte 8) :adjustable t :fill-pointer 0))
      (ag-http2::stream-append-data stream (concatenate '(vector (unsigned-byte 8)) frame frame (subseq frame 0 3)))
      (ag-grpc::server-handle-data nil connection (ag-http2::make-data-frame id #()))
      (is (= 2 (length (ag-grpc::stream-message-buffer-messages buffer))))
      (is (equalp (subseq frame 0 3) (ag-http2:stream-data-buffer stream)))
      (is (= 3 (array-total-size (ag-http2:stream-data-buffer stream))))
      (ag-http2::stream-append-data stream (subseq frame 3))
      (ag-grpc::server-handle-data nil connection (ag-http2::make-data-frame id #() :end-stream t))
      (is (= 3 (length (ag-grpc::stream-message-buffer-messages buffer))))
      (is (zerop (array-total-size (ag-http2:stream-data-buffer stream))))
      (is-true (ag-grpc::stream-message-buffer-closed-p buffer)))))

(test deadline-heap-removes-arbitrary-entries-and-clears-backing-slots
  (let* ((heap (cl-cancel::make-heap))
         (entries (loop for deadline in '(9 2 7 1 8 3 6 4 5 0)
                        collect (cl-cancel::make-deadline-entry :deadline deadline))))
    (dolist (entry entries) (cl-cancel::heap-insert heap entry))
    ;; Remove both interior and leaf entries; replacement may bubble either way.
    (dolist (entry (subseq entries 0 5))
      (is (eq entry (cl-cancel::heap-remove-entry heap entry)))
      (is (null (cl-cancel::heap-remove-entry heap entry))))
    (is (equal '(0 3 4 5 6)
               (loop until (cl-cancel::heap-empty-p heap)
                     collect (cl-cancel::deadline-entry-deadline (cl-cancel::heap-pop heap)))))
    (let ((data (cl-cancel::heap-data heap)))
      (is (loop for i below (length entries) always (null (row-major-aref data i)))))
    (is (every (lambda (entry) (null (cl-cancel::deadline-entry-heap-index entry))) entries))))

(test cancelled-deadlines-release-timer-registration-including-parent-cancel
  (multiple-value-bind (parent cancel-parent) (cl-cancel:with-cancel (cl-cancel:background))
    (unwind-protect
         (progn
           (multiple-value-bind (child cancel-child) (cl-cancel:with-timeout parent 60)
             (is-true (cl-cancel::cancellable-timer-entry child))
             (funcall cancel-child)
             (funcall cancel-child)
             (is (null (cl-cancel::cancellable-timer-entry child))))
           (multiple-value-bind (child cancel-child) (cl-cancel:with-timeout parent 60)
             (declare (ignore cancel-child))
             (funcall cancel-parent)
             (is (null (cl-cancel::cancellable-timer-entry child)))))
      (funcall cancel-parent))))

(test concurrent-deadline-setup-and-cancel-leaves-no-registrations
  (let ((threads
          (loop repeat 4 collect
            (bt:make-thread
             (lambda ()
               (loop repeat 200 always
                 (multiple-value-bind (ctx cancel) (cl-cancel:with-timeout (cl-cancel:background) 60)
                   (funcall cancel)
                   (null (cl-cancel::cancellable-timer-entry ctx)))))))))
    (is (every #'identity (mapcar #'bt:join-thread threads)))))

(test deadline-timer-still-fires-after-arbitrary-cancellation
  (multiple-value-bind (later cancel-later) (cl-cancel:with-timeout (cl-cancel:background) 60)
    (unwind-protect
         (multiple-value-bind (soon cancel-soon) (cl-cancel:with-timeout (cl-cancel:background) 1/5)
           (unwind-protect
                (progn
                  (funcall cancel-later)
                  (is (not (cl-cancel:cancelled-p soon)))
                  (is (poll-until (lambda () (cl-cancel:cancelled-p soon))))
                  (is (typep (cl-cancel:err soon) 'cl-cancel:deadline-exceeded)))
             (funcall cancel-soon)))
      (funcall cancel-later))))

(test parent-cancel-racing-with-deadline-registration-leaves-no-timers
  (dotimes (round 20)
    (declare (ignore round))
    (multiple-value-bind (parent cancel-parent) (cl-cancel:with-cancel (cl-cancel:background))
    (let* ((started (bt:make-semaphore :name "deadline registration started"))
           (creator (bt:make-thread
                     (lambda ()
                       (bt:signal-semaphore started)
                       (loop repeat 1000 collect
                         (nth-value 0 (cl-cancel:with-timeout parent 60)))))))
      (unwind-protect
           (progn
             (bt:wait-on-semaphore started)
             (funcall cancel-parent)
             (let ((children (bt:join-thread creator)))
               (is (every #'cl-cancel:cancelled-p children))
               (is (every (lambda (child) (null (cl-cancel::cancellable-timer-entry child))) children))))
        (funcall cancel-parent))))))

(test grpc-fractional-wire-timeouts-retain-epoch-deadline-precision
  (with-http2-close-connection (connection socket peer listener)
    (let ((server (ag-grpc:make-grpc-server 0 :host "127.0.0.1")))
      (ag-grpc:server-register-handler server "/precision.Test/Echo"
                                     (lambda (request context) (declare (ignore request context)))
                                     :request-type 'gr8s.node.v1::raft-ack
                                     :response-type 'gr8s.node.v1::raft-ack)
      (dolist (case '(("100m" 1/10) ("100000u" 1/10) ("99999999n" 99999999/1000000000)))
        (destructuring-bind (wire duration) case
          (let* ((stream (ag-http2::connection-new-stream connection))
                 (id (ag-http2:stream-id stream))
                 (before (cl-cancel:get-current-time)))
            (is (= duration (ag-grpc::parse-grpc-timeout wire)))
            (is (rationalp (ag-grpc::parse-grpc-timeout wire)))
            (setf (ag-http2:stream-state stream) :open
                  (ag-http2:stream-headers stream)
                  (list (cons :path "/precision.Test/Echo") (cons "grpc-timeout" wire)))
            (ag-grpc::server-handle-headers server connection
                                           (ag-http2::make-headers-frame id #() :end-headers t) "test")
            (let* ((after (cl-cancel:get-current-time))
                   (context (ag-grpc::connection-get-stream-context connection stream))
                   (deadline (cl-cancel:deadline (ag-grpc::context-cancel-context context))))
              (is (rationalp deadline))
              (is (<= (+ before duration) deadline (+ after duration))))))))))

(test direct-channel-cancel-releases-stream-and-runs-cleanup-once
  (with-http2-close-connection (connection socket peer listener)
    (let* ((channel (make-instance 'ag-grpc::grpc-channel :connection connection))
           (mux (ag-http2:connection-multiplexer connection))
           (stream (ag-http2::connection-new-stream connection))
           (id (ag-http2:stream-id stream)) (cleanups 0))
      (setf (ag-http2:stream-state stream) :open
            (ag-http2:stream-cleanup-callback stream)
            (lambda (ignored) (declare (ignore ignored)) (incf cleanups)))
      (ag-http2::stream-append-data stream #(1 2 3))
      (ag-grpc:channel-cancel-stream channel id)
      (ag-grpc:channel-cancel-stream channel id)
      (is (= 1 cleanups))
      (is (eq :closed (ag-http2:stream-state stream)))
      (is (zerop (hash-table-count (ag-http2::multiplexer-streams mux))))
      (sb-sys:with-deadline (:seconds 2)
        (is (typep (ag-http2::read-frame (usocket:socket-stream peer)) 'ag-http2::rst-stream-frame)))
      (is (null (usocket:wait-for-input (list peer) :timeout 0.05 :ready-only t))))))

(test direct-channel-cancel-cleans-up-after-real-write-failure
  (with-http2-close-connection (connection socket peer listener)
    (let* ((channel (make-instance 'ag-grpc::grpc-channel :connection connection))
           (mux (ag-http2:connection-multiplexer connection))
           (stream (ag-http2::connection-new-stream connection)) (cleanups 0))
      (setf (ag-http2:stream-state stream) :open
            (ag-http2:stream-cleanup-callback stream)
            (lambda (ignored) (declare (ignore ignored)) (incf cleanups)))
      (close (ag-http2::connection-stream connection))
      (signals error (ag-grpc:channel-cancel-stream channel (ag-http2:stream-id stream)))
      (is (= 1 cleanups))
      (is (eq :closed (ag-http2:stream-state stream)))
      (is (zerop (hash-table-count (ag-http2::multiplexer-streams mux)))))))

(test bidi-scope-preserves-normal-half-close-and-cancels-abnormal-exits
  (with-http2-close-connection (connection socket peer listener)
    (setf (ag-http2:connection-state connection) :open)
    (let* ((channel (make-instance 'ag-grpc::grpc-channel :host "127.0.0.1" :port 1
                                                        :connection connection :default-timeout nil))
           (mux (ag-http2:connection-multiplexer connection)))
      (multiple-value-bind (stream marker)
          (ag-grpc:with-bidi-stream (stream channel "/scope") (values stream :normal))
        (is (eq :normal marker))
        (is (eq :half-closed-local
                (ag-http2:stream-state (ag-http2::multiplexer-get-stream mux (ag-grpc::bidi-stream-id stream)))))
        (is (= 1 (hash-table-count (ag-http2::multiplexer-streams mux))))
        (ag-grpc:channel-cancel-stream channel (ag-grpc::bidi-stream-id stream)))
      (is (eq :early (catch 'bidi-exit
                       (ag-grpc:with-bidi-stream (stream channel "/scope")
                         (throw 'bidi-exit :early)))))
      (is (zerop (hash-table-count (ag-http2::multiplexer-streams mux))))
      (let ((original (make-condition 'simple-error :format-control "bidi body failed")))
        (is (eq original (handler-case
                             (ag-grpc:with-bidi-stream (stream channel "/scope") (error original))
                           (error (condition) condition)))))
      (is (zerop (hash-table-count (ag-http2::multiplexer-streams mux))))
      ;; Normal BODY return followed by a failed half-close must also retire.
      (signals error
        (ag-grpc:with-bidi-stream (stream channel "/scope")
          (close (ag-http2::connection-stream connection))))
      (is (zerop (hash-table-count (ag-http2::multiplexer-streams mux)))))))

(test close-preserves-active-writer-buffer-until-write-lock-is-released
  (with-http2-close-connection (connection socket peer listener)
    (let ((closed (bt:make-semaphore)) (closer nil) (failure nil))
      (setf (ag-http2:connection-state connection) :open)
      (unwind-protect
           (progn
             (bt2:with-lock-held ((ag-http2::connection-write-lock connection))
               (write-byte 42 (usocket:socket-stream socket))
               (let ((tail (sb-impl::buffer-tail
                            (sb-impl::fd-stream-obuf (usocket:socket-stream socket)))))
                 (is (plusp tail))
                 (setf closer
                       (bt:make-thread
                        (lambda ()
                          (unwind-protect
                               (handler-case (ag-http2:connection-close connection)
                                 (error (condition) (setf failure condition)))
                            (bt:signal-semaphore closed)))
                        :name "HTTP/2 close with active writer"))
                 ;; The upstream GOAWAY lock timeout is one second. Close must
                 ;; return without recycling a buffer still owned by this writer.
                 (is (bt:wait-on-semaphore closed :timeout 3))
                 (is (null failure))
                 (is (eq :closed (ag-http2:connection-state connection)))
                 (is (open-stream-p (usocket:socket-stream socket)))
                 (is (= tail (sb-impl::buffer-tail
                              (sb-impl::fd-stream-obuf (usocket:socket-stream socket)))))
                 (ag-http2:connection-close connection)
                 (is (open-stream-p (usocket:socket-stream socket)))))
             (when closer (bt:join-thread closer))
             (is (wait-until (lambda () (not (open-stream-p (usocket:socket-stream socket))))
                             :timeout 3))
             (check-fresh-connection-after-repeated-close connection listener socket))
        (when closer (bt:join-thread closer))))))

(test interrupted-close-defers-buffer-release-while-writer-holds-lock
  (with-http2-close-connection (connection socket peer listener)
    (bt2:with-lock-held ((ag-http2::connection-write-lock connection))
      (write-byte 42 (usocket:socket-stream socket))
      (let ((gr8s.protocol::*http2-connection-close-body*
              (lambda (&rest args) (declare (ignore args))
                (error 'http2-close-cancelled))))
        (signals http2-close-cancelled (ag-http2:connection-close connection)))
      (is (open-stream-p (usocket:socket-stream socket)))
      (is (= 1 (sb-impl::buffer-tail
                (sb-impl::fd-stream-obuf (usocket:socket-stream socket))))))
    (is (wait-until (lambda () (not (open-stream-p (usocket:socket-stream socket))))
                    :timeout 3))
    (check-fresh-connection-after-repeated-close connection listener socket)))

(test socket-shutdown-wakes-a-backpressured-writer-before-buffer-disposal
  (with-http2-close-connection (connection socket peer listener)
    (let ((writer nil) (finished nil) (write-failed nil)
          (payload (make-array (* 4 1024 1024) :element-type '(unsigned-byte 8)
                                                   :initial-element 42)))
      (setf (ag-http2:connection-state connection) :open)
      (unwind-protect
           (progn
             (setf writer
                   (bt:make-thread
                    (lambda ()
                      (unwind-protect
                           (handler-case
                               (sb-sys:with-deadline (:seconds 10)
                                 (bt2:with-lock-held ((ag-http2::connection-write-lock connection))
                                   (write-sequence payload (usocket:socket-stream socket))
                                   (force-output (usocket:socket-stream socket))))
                             (error () (setf write-failed t)))
                        (setf finished t)))
                    :name "HTTP/2 backpressured frame writer"))
             ;; Leave the peer unread so output fills the socket. Seeing input
             ;; proves the writer started; FINISHED must still be false.
             (is (wait-until (lambda () (listen (usocket:socket-stream peer))) :timeout 3))
             (is (not finished))
             (ag-http2:connection-close connection)
             (is (wait-until (lambda () finished) :timeout 3))
             (is-true write-failed)
             (is (wait-until (lambda () (not (open-stream-p (usocket:socket-stream socket))))
                             :timeout 3)))
        (when (open-stream-p (usocket:socket-stream socket))
          (ignore-errors (usocket:socket-shutdown socket :io)))
        (when writer (bt:join-thread writer))))))

(test accepted-worker-raw-close-cannot-bypass-a-deferred-writer-close
  (with-http2-close-connection (connection socket peer listener)
    (let ((returned (bt:make-semaphore)) (closer nil) (failure nil))
      (setf (ag-http2:connection-state connection) :open)
      (unwind-protect
           (progn
             (bt2:with-lock-held ((ag-http2::connection-write-lock connection))
               (write-byte 42 (usocket:socket-stream socket))
               (setf closer
                     (bt:make-thread
                      (lambda ()
                        (unwind-protect
                             (handler-case (ag-http2:connection-close connection)
                               (error (condition) (setf failure condition)))
                          (bt:signal-semaphore returned)))))
               (is (bt:wait-on-semaphore returned :timeout 3))
               (is (null failure))
               (is (open-stream-p (usocket:socket-stream socket)))
               ;; This is the accepted worker's outer unwind cleanup after
               ;; SERVER-HANDLE-CONNECTION returned from its bounded close.
               (usocket:socket-close socket)
               (is (open-stream-p (usocket:socket-stream socket))))
             (when closer (bt:join-thread closer))
             (is (wait-until (lambda () (not (open-stream-p (usocket:socket-stream socket)))) :timeout 3)))
        (when closer (bt:join-thread closer))))))

(test close-preserves-an-active-frame-readers-input-buffer
  (with-http2-close-connection (connection socket peer listener)
    (let ((entered (bt:make-semaphore)) (release (bt:make-semaphore))
          (reader nil) (failure nil) (held-input nil)
          (read-frame (symbol-function 'ag-http2:read-frame)))
      (setf (ag-http2:connection-state connection) :open)
      (write-byte 42 (usocket:socket-stream peer))
      (force-output (usocket:socket-stream peer))
      (unwind-protect
           (progn
             (setf (symbol-function 'ag-http2:read-frame)
                   (lambda (stream &optional limit)
                     (declare (ignore limit))
                     ;; Own a real fd-stream input buffer across a suspension,
                     ;; as a partial frame read can do while waiting for bytes.
                     (read-byte stream)
                     (setf held-input (sb-impl::fd-stream-ibuf stream))
                     (bt:signal-semaphore entered)
                     (unless (bt:wait-on-semaphore release :timeout 10)
                       (error "Frame reader was not released"))
                     nil)
                   reader (bt:make-thread
                           (lambda ()
                             (handler-case (ag-http2:connection-read-frame connection)
                               (error (condition) (setf failure condition))))))
             (is (bt:wait-on-semaphore entered :timeout 3))
             (is (not (null held-input)))
             (is (null failure))
             (ag-http2:connection-close connection)
             (is (open-stream-p (usocket:socket-stream socket)))
             (is (eq held-input (sb-impl::fd-stream-ibuf (usocket:socket-stream socket))))
             (bt:signal-semaphore release)
             (bt:join-thread reader)
             (setf reader nil)
             (is (null failure))
             (is (wait-until (lambda () (not (open-stream-p (usocket:socket-stream socket)))) :timeout 3)))
        (bt:signal-semaphore release)
        (when reader (bt:join-thread reader))
        (setf (symbol-function 'ag-http2:read-frame) read-frame)))))

(test close-ownership-rejects-late-readers-before-public-state-closes
  (with-http2-close-connection (connection socket peer listener)
    (let ((claimed (bt:make-semaphore)) (release (bt:make-semaphore))
          (closer nil) (failure nil) (called nil)
          (read-frame (symbol-function 'ag-http2:read-frame)))
      (setf (ag-http2:connection-state connection) :open)
      (unwind-protect
           (progn
             (setf (symbol-function 'ag-http2:read-frame)
                   (lambda (&rest args) (declare (ignore args)) (setf called t) nil)
                   closer
                   (bt:make-thread
                    (lambda ()
                      (let ((gr8s.protocol::*http2-connection-close-body*
                              (lambda (&rest args)
                                (declare (ignore args))
                                (bt:signal-semaphore claimed)
                                (bt:wait-on-semaphore release :timeout 10))))
                        (handler-case (ag-http2:connection-close connection)
                          (error (condition) (setf failure condition)))))))
             (is (bt:wait-on-semaphore claimed :timeout 3))
             (is (eq :open (ag-http2:connection-state connection)))
             (signals end-of-file (ag-http2:connection-read-frame connection))
             (is-false called)
             (bt:signal-semaphore release)
             (bt:join-thread closer)
             (setf closer nil)
             (is (null failure))
             (is (eq :closed (ag-http2:connection-state connection))))
        (bt:signal-semaphore release)
        (when closer (bt:join-thread closer))
        (setf (symbol-function 'ag-http2:read-frame) read-frame)))))

(test interrupted-frame-reader-releases-input-ownership
  (with-http2-close-connection (connection socket peer listener)
    (let ((entered (bt:make-semaphore)) (release (bt:make-semaphore))
          (reader nil) (cancelled nil) (failure nil)
          (read-frame (symbol-function 'ag-http2:read-frame)))
      (setf (ag-http2:connection-state connection) :open)
      (unwind-protect
           (progn
             (setf (symbol-function 'ag-http2:read-frame)
                   (lambda (&rest args)
                     (declare (ignore args))
                     (bt:signal-semaphore entered)
                     (bt:wait-on-semaphore release :timeout 10)
                     nil)
                   reader
                   (bt:make-thread
                    (lambda ()
                      (handler-case (ag-http2:connection-read-frame connection)
                        (http2-close-cancelled () (setf cancelled t))
                        (error (condition) (setf failure condition))))))
             (is (bt:wait-on-semaphore entered :timeout 3))
             (sb-thread:interrupt-thread reader (lambda () (error 'http2-close-cancelled)))
             (bt:join-thread reader)
             (setf reader nil)
             (is-true cancelled)
             (is (null failure))
             (ag-http2:connection-close connection)
             (is-false (open-stream-p (usocket:socket-stream socket))))
        (bt:signal-semaphore release)
        (when reader (bt:join-thread reader))
        (setf (symbol-function 'ag-http2:read-frame) read-frame)))))

(test handshake-rundown-preserves-buffers-and-cannot-reopen-a-closed-connection
  (dolist (server-p '(nil t))
    (with-http2-close-connection (connection socket peer listener)
      (let ((entered (bt:make-semaphore)) (release (bt:make-semaphore))
            (closed (bt:make-semaphore)) (handshake nil) (closer nil)
            (read-failure nil) (close-failure nil))
        (setf (ag-http2:connection-state connection) :new)
        (unwind-protect
             (progn
               (setf handshake
                     (bt:make-thread
                      (lambda ()
                        (let* ((body (lambda (incoming)
                                       (write-byte 42 (ag-http2::connection-stream incoming))
                                       (bt:signal-semaphore entered)
                                       (bt:wait-on-semaphore release :timeout 10)
                                       ;; Both upstream handshakes mark OPEN last.
                                       (setf (ag-http2:connection-state incoming) :open)))
                               (gr8s.protocol::*upstream-http2-connection-handshake* body)
                               (gr8s.protocol::*upstream-http2-server-handshake* body))
                          (handler-case
                              (if server-p (ag-http2:server-connection-handshake connection)
                                  (ag-http2::connection-handshake connection))
                            (error (condition) (setf read-failure condition)))))))
               (is (bt:wait-on-semaphore entered :timeout 3))
               (setf closer
                     (bt:make-thread
                      (lambda ()
                        (unwind-protect
                             (handler-case (ag-http2:connection-close connection)
                               (error (condition) (setf close-failure condition)))
                          (bt:signal-semaphore closed)))))
               (is (bt:wait-on-semaphore closed :timeout 3))
               (is (null close-failure))
               (is (open-stream-p (usocket:socket-stream socket)))
               (usocket:socket-close socket)
               (is (open-stream-p (usocket:socket-stream socket)))
               (bt:signal-semaphore release)
               (bt:join-thread handshake)
               (setf handshake nil)
               (is (null read-failure))
               (is (eq :closed (ag-http2:connection-state connection)))
               (is (wait-until (lambda () (not (open-stream-p (usocket:socket-stream socket)))) :timeout 3)))
          (bt:signal-semaphore release)
          (when handshake (bt:join-thread handshake))
          (when closer (bt:join-thread closer)))))))

(test http2-lifetime-hooks-preserve-unrelated-sockets-and-partial-initialization
  (let ((partial (make-instance 'ag-http2:http2-connection :client-p t)))
    (is (typep partial 'ag-http2:http2-connection))
    (is-false (slot-boundp partial 'ag-http2::socket)))
  (with-http2-close-connection (connection socket peer listener)
    ;; PEER has no HTTP/2 connection wrapper, so raw close stays immediate.
    (usocket:socket-close peer)
    (is-false (open-stream-p (usocket:socket-stream peer)))
    (is (open-stream-p (usocket:socket-stream socket)))))
