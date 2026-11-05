(in-package #:gr8s)

(defparameter +api-connection-limit+ 1024
  "Connections served at once. Each open watch keeps one, and Hunchentoot's default of
100 stops accepting at that point, leaving even short requests in a handshake timeout.")

(defclass gr8s-acceptor (hunchentoot:easy-acceptor)
  ((store :initarg :store :reader acceptor-store)
   (runtime :initarg :runtime :reader acceptor-runtime)
   (reconciler :initarg :reconciler :reader acceptor-reconciler))
  (:default-initargs
   :listen-backlog 512
   :taskmaster (make-instance 'hunchentoot:one-thread-per-connection-taskmaster
                              :max-thread-count +api-connection-limit+
                              :max-accept-count (+ +api-connection-limit+ 128))))

(defmethod hunchentoot:acceptor-dispatch-request
    ((acceptor gr8s-acceptor) request)
  (if (member (hunchentoot:script-name request)
              '("/livez" "/readyz")
              :test #'string=)
      (progn
        (setf (hunchentoot:content-type*) "text/plain; charset=utf-8")
        "ok")
      (handle-http-request (acceptor-store acceptor)
                           (acceptor-runtime acceptor)
                           (acceptor-reconciler acceptor)
                           request)))

(defun start-server (&key (address "127.0.0.1") (port 8080)
                          store runtime reconciler)
  (unless (string= address "127.0.0.1")
    (error "gr8s v1 only listens on 127.0.0.1"))
  (let* ((actual-store (or store
                           (and reconciler (reconciler-store reconciler))))
         (actual-runtime (or runtime
                             (and reconciler
                                  (reconciler-runtime reconciler))
                             (make-fake-runtime)))
         (actual-reconciler
           (or reconciler
               (and actual-store
                    (make-reconciler actual-store actual-runtime)))))
    (hunchentoot:start
     (make-instance 'gr8s-acceptor
                    :address address
                    :port port
                    :store actual-store
                    :runtime actual-runtime
                    :reconciler actual-reconciler))))

(defmethod hunchentoot:stop :around ((acceptor gr8s-acceptor) &key soft)
  "Keep waking the listener: STOP has one wake attempt and then an unbounded join."
  ;; The single dummy connection swallows its own errors, and the host suite
  ;; intermittently hung here with the listener never exiting (podster-uqb.82).
  (declare (ignorable soft))
  (let ((stopped nil))
    (bt:make-thread
     (lambda ()
       (loop until stopped
             do (sleep 0.5)
                (unless stopped
                  (ignore-errors (hunchentoot::wake-acceptor-for-shutdown acceptor)))))
     :name "gr8s server stop waker")
    ;; The waker notices within half a second; STOP need not wait for it.
    (unwind-protect (call-next-method)
      (setf stopped t))))

(defun stop-server (server)
  (hunchentoot:stop server))
