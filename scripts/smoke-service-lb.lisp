;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; End-to-end privileged smoke for the ClusterIP socket load balancer
;;;; (podster-7q2.4).  Requires real root (CAP_BPF, cgroup2, bpffs).
;;;;
;;;; It attaches the connect4 LB to a throwaway cgroup, runs two real backend
;;;; TCP servers, programs a Service VIP -> {backend A, backend B}, moves this
;;;; process into the cgroup, and connects to the VIP.  The VIP (10.96.0.77) has
;;;; no route, so a *successful* connection is itself proof the destination was
;;;; rewritten in-kernel before routing.  Repeated connects must reach both
;;;; backends, proving load spreading.  No containerd or Pods are required.
;;;;
;;;; Run:  make smoke-service-lb        (invokes this under sudo)

(require :asdf)
(let ((project (truename (merge-pathnames "../" (uiop:pathname-directory-pathname *load-truename*)))))
  (asdf:initialize-source-registry
   `(:source-registry
     (:directory ,project)
     (:tree ,(merge-pathnames "ocicl/" project))
     :inherit-configuration)))
(asdf:load-system :gr8s)
(in-package #:gr8s.network)

(defvar *vip* "10.96.0.77")
(defvar *vip-port* 80)
(defvar *backend-a-port* 19001)
(defvar *backend-b-port* 19002)
(defvar *connect-attempts* 40)
(defvar *failures* 0)

(defun check (ok format &rest arguments)
  (format t "~&[~A] ~A~%" (if ok " ok " "FAIL") (apply #'format nil format arguments))
  (unless ok (incf *failures*)))

(defun start-backend-server (port label)
  "Listen on 127.0.0.1:PORT and answer each connection with LABEL's character."
  (let ((socket (make-instance 'sb-bsd-sockets:inet-socket :type :stream :protocol :tcp)))
    (setf (sb-bsd-sockets:sockopt-reuse-address socket) t)
    (sb-bsd-sockets:socket-bind socket (sb-bsd-sockets:make-inet-address "127.0.0.1") port)
    (sb-bsd-sockets:socket-listen socket 16)
    (values
     socket
     (bt:make-thread
      (lambda ()
        (loop
          (handler-case
              (let ((client (sb-bsd-sockets:socket-accept socket)))
                (ignore-errors (sb-bsd-sockets:socket-send client (string label) 1))
                (ignore-errors (sb-bsd-sockets:socket-close client)))
            (error () (return)))))
      :name (format nil "gr8s backend ~A" label)))))

(defun connect-to-vip ()
  "Connect to the VIP and return the backend label character, or NIL on failure."
  (let ((socket (make-instance 'sb-bsd-sockets:inet-socket :type :stream :protocol :tcp)))
    (unwind-protect
         (handler-case
             (sb-ext:with-timeout 5
               (sb-bsd-sockets:socket-connect socket (sb-bsd-sockets:make-inet-address *vip*) *vip-port*)
               (let ((buffer (make-array 1 :element-type '(unsigned-byte 8))))
                 (multiple-value-bind (buf length) (sb-bsd-sockets:socket-receive socket buffer 1)
                   (declare (ignore buf))
                   (and (plusp length) (code-char (aref buffer 0))))))
           (error () nil))
      (ignore-errors (sb-bsd-sockets:socket-close socket)))))

(defun join-cgroup (cgroup-path)
  (with-open-file (stream (concatenate 'string cgroup-path "/cgroup.procs")
                          :direction :output :if-exists :append :if-does-not-exist :error)
    (format stream "~D~%" (sb-posix:getpid))))

(defun leave-cgroup ()
  (ignore-errors
   (with-open-file (stream "/sys/fs/cgroup/cgroup.procs" :direction :output :if-exists :append)
     (format stream "~D~%" (sb-posix:getpid)))))

(defun run-service-lb-e2e ()
  (unless (zerop (sb-posix:geteuid))
    (error "this smoke requires real root (CAP_BPF, cgroup2, bpffs)"))
  (let* ((pin-directory (format nil "/sys/fs/bpf/gr8s-slb-e2e-~D/" (sb-posix:getpid)))
         (cgroup-path (format nil "/sys/fs/cgroup/gr8s-slb-e2e-~D" (sb-posix:getpid)))
         (dataplane nil) (server-a nil) (thread-a nil) (server-b nil) (thread-b nil))
    (ensure-directories-exist (concatenate 'string cgroup-path "/"))
    (unwind-protect
         (progn
           (multiple-value-setq (server-a thread-a) (start-backend-server *backend-a-port* #\A))
           (multiple-value-setq (server-b thread-b) (start-backend-server *backend-b-port* #\B))
           (setf dataplane (start-service-lb-dataplane cgroup-path pin-directory))
           (check (not (null (service-lb-dataplane-attachment dataplane)))
                  "connect4 LB attached to ~A" cgroup-path)
           ;; VIP 10.96.0.77:80 -> {127.0.0.1:19001 (A), 127.0.0.1:19002 (B)}.
           (service-lb-write-service dataplane *vip* *vip-port* 0
                                     (list (cons "127.0.0.1" *backend-a-port*)
                                           (cons "127.0.0.1" *backend-b-port*)))
           (join-cgroup cgroup-path)
           (let ((hits (make-hash-table :test #'eql)) (ok 0))
             (dotimes (i *connect-attempts*)
               (let ((label (connect-to-vip)))
                 (when label (incf ok) (incf (gethash label hits 0)))))
             (leave-cgroup)
             (check (= ok *connect-attempts*)
                    "~D/~D connects to the unrouted VIP succeeded (redirected in-kernel)"
                    ok *connect-attempts*)
             (check (plusp (gethash #\A hits 0)) "backend A served ~D connection(s)" (gethash #\A hits 0))
             (check (plusp (gethash #\B hits 0)) "backend B served ~D connection(s)" (gethash #\B hits 0))))
      (leave-cgroup)
      (when dataplane (ignore-errors (stop-service-lb-dataplane dataplane)))
      (when server-a (ignore-errors (sb-bsd-sockets:socket-close server-a)))
      (when server-b (ignore-errors (sb-bsd-sockets:socket-close server-b)))
      (when thread-a (ignore-errors (bt:destroy-thread thread-a)))
      (when thread-b (ignore-errors (bt:destroy-thread thread-b)))
      (ignore-errors (sb-posix:rmdir cgroup-path))
      (ignore-errors (uiop:delete-empty-directory pin-directory)))
    (if (zerop *failures*)
        (format t "~&service-lb end-to-end smoke: PASS~%")
        (format t "~&service-lb end-to-end smoke: ~D FAILURE(S)~%" *failures*))
    (sb-ext:exit :code (if (zerop *failures*) 0 1))))

(run-service-lb-e2e)
