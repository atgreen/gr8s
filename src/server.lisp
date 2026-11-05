(in-package #:gr8s)

(defparameter +api-connection-limit+ 1024
  "Connections served at once. Each open watch keeps one, and Hunchentoot's default of
100 stops accepting at that point, leaving even short requests in a handshake timeout.")

(defclass gr8s-acceptor (hunchentoot:easy-acceptor)
  ((store :initarg :store :reader acceptor-store)
   (runtime :initarg :runtime :reader acceptor-runtime)
   (reconciler :initarg :reconciler :reader acceptor-reconciler)
   ;; HA (podster-c2d.7.3): NIL (single-node) or a function returning
   ;; (values self-leader-p leader-api-url). A follower redirects mutating
   ;; requests to the leader so writes always land where consensus happens.
   (leader-status-fn :initarg :leader-status-fn :initform nil :reader acceptor-leader-status-fn))
  (:default-initargs
   :listen-backlog 512
   :taskmaster (make-instance 'hunchentoot:one-thread-per-connection-taskmaster
                              :max-thread-count +api-connection-limit+
                              :max-accept-count (+ +api-connection-limit+ 128))))

(defun ha-redirect-response (acceptor request)
  "When this member is not the Raft leader and REQUEST mutates, return a redirect
   to the leader (or a 503 if the leader is unknown); else NIL to serve locally."
  (let ((status-fn (acceptor-leader-status-fn acceptor)))
    (when status-fn
      (multiple-value-bind (self-leader-p leader-url) (funcall status-fn)
        (when (and (not self-leader-p)
                   (raft-mutating-method-p (hunchentoot:request-method request)))
          (let* ((uri (hunchentoot:request-uri request))
                 (target (raft-leader-redirect-url (hunchentoot:request-method request)
                                                   uri self-leader-p leader-url)))
            (cond
              (target
               (setf (hunchentoot:return-code*) hunchentoot:+http-temporary-redirect+
                     (hunchentoot:header-out :location) target
                     (hunchentoot:content-type*) "text/plain; charset=utf-8")
               (format nil "The Raft leader serves writes; retry at ~A~%" target))
              (t
               (setf (hunchentoot:return-code*) hunchentoot:+http-service-unavailable+
                     (hunchentoot:content-type*) "text/plain; charset=utf-8")
               (format nil "No Raft leader is currently available~%")))))))))

(defmethod hunchentoot:acceptor-dispatch-request
    ((acceptor gr8s-acceptor) request)
  (cond
    ((member (hunchentoot:script-name request)
             '("/livez" "/readyz")
             :test #'string=)
     (setf (hunchentoot:content-type*) "text/plain; charset=utf-8")
     "ok")
    ((ha-redirect-response acceptor request))
    (t
     (handle-http-request (acceptor-store acceptor)
                          (acceptor-runtime acceptor)
                          (acceptor-reconciler acceptor)
                          request))))

(defun start-server (&key (address "127.0.0.1") (port 8080)
                          store runtime reconciler leader-status-fn)
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
                    :reconciler actual-reconciler
                    :leader-status-fn leader-status-fn))))

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
