;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
(in-package #:gr8s.kubelet)

(defstruct (local-resource-server (:constructor %make-local-resource-server))
  path listener server thread running (clients nil) (workers nil)
  (lock (bt:make-lock "local resource server")))
(defvar *local-resource-worker* nil)

(defun kubelet-endpoint-status (path)
  "Classify PATH as :ABSENT, :ACTIVE, :STALE, or :NON-SOCKET.
ACTIVE means a Unix stream listener accepted a connection. STALE is a socket
inode with no listener and is safe for a kubelet to replace."
  (let* ((path (pathname path))
         (stat (ignore-errors (sb-posix:lstat path))))
    (cond
      ((null stat) :absent)
      ((/= sb-posix:s-ifsock
           (logand sb-posix:s-ifmt (sb-posix:stat-mode stat)))
       :non-socket)
      (t
       (let ((probe (make-instance 'sb-bsd-sockets:local-socket
                                   :type :stream :protocol 0)))
         (unwind-protect
              (if (ignore-errors
                    (sb-bsd-sockets:socket-connect probe (namestring path))
                    t)
                  :active
                  :stale)
           (sb-bsd-sockets:socket-close probe)))))))

(defun local-resource-accept-loop (server)
  "Bound local RPC workers and track every transport for deterministic shutdown."
  (let ((slots (bt:make-semaphore :count 32)))
    (loop while (local-resource-server-running server)
          do (handler-case
                 (let* ((native (sb-bsd-sockets:socket-accept (local-resource-server-listener server)))
                        (client (make-instance 'device-plugin-client :socket native
                                              :stream (sb-bsd-sockets:socket-make-stream native :input t :output t
                                                                                        :element-type '(unsigned-byte 8) :buffering :full))))
                   (if (and (local-resource-server-running server) (bt:wait-on-semaphore slots :timeout 0.001))
                       (bt:with-lock-held ((local-resource-server-lock server))
                         (push client (local-resource-server-clients server))
                         (push (bt:make-thread
                                (lambda ()
                                  (unwind-protect
                                       (catch server
                                         (let ((*local-resource-worker* server))
                                           (handler-case (ag-grpc::server-handle-connection (local-resource-server-server server) client)
                                             (error (condition)
                                               (when (local-resource-server-running server)
                                                 (format *error-output* "gr8s local resource RPC: ~A~%" condition))))))
                                    (ignore-errors (usocket:socket-close client))
                                    (bt:with-lock-held ((local-resource-server-lock server))
                                      (setf (local-resource-server-clients server) (delete client (local-resource-server-clients server))
                                            (local-resource-server-workers server) (delete (bt:current-thread) (local-resource-server-workers server))))
                                    (bt:signal-semaphore slots))) :name "podresources RPC")
                               (local-resource-server-workers server)))
                       (usocket:socket-close client)))
               (error (condition)
                 (when (local-resource-server-running server)
                   (format *error-output* "gr8s local resource listener: ~A~%" condition) (sleep 0.1)))))))

(defun start-local-resource-server (path configure)
  "Bind a root-only Unix endpoint, refusing active sockets or regular files."
  (let* ((path (pathname path)) (server (%make-local-resource-server :path path :server (ag-grpc:make-grpc-server 0 :connection-idle-timeout 30)))
         (native nil))
    (ensure-directories-exist path)
    (when (ignore-errors (sb-posix:lstat path))
      (unless (= sb-posix:s-ifsock (logand sb-posix:s-ifmt (sb-posix:stat-mode (sb-posix:lstat path))))
        (error "PodResources endpoint is not a socket: ~A" path))
      (let ((probe (make-instance 'sb-bsd-sockets:local-socket :type :stream :protocol 0)))
        (unwind-protect
             (when (ignore-errors (sb-bsd-sockets:socket-connect probe (namestring path)) t)
               (error "Another kubelet owns ~A" path))
          (sb-bsd-sockets:socket-close probe)))
      (delete-file path))
    (setf native (make-instance 'sb-bsd-sockets:local-socket :type :stream :protocol 0))
    (handler-case
        (progn
          (funcall configure (local-resource-server-server server))
          (sb-bsd-sockets:socket-bind native (namestring path))
          (sb-posix:chmod path #o600)
          (sb-bsd-sockets:socket-listen native 32)
          (setf (local-resource-server-listener server) native (local-resource-server-running server) t
                (ag-grpc::server-state (local-resource-server-server server)) :running
                (local-resource-server-thread server) (bt:make-thread (lambda () (local-resource-accept-loop server)) :name "podresources listener"))
          server)
      (error (condition) (sb-bsd-sockets:socket-close native) (error condition)))))

(defun stop-local-resource-server (server)
  "Wake accept and interrupt blocked HTTP/2 polls, retaining no owned workers."
  (when (and server (local-resource-server-running server))
    (setf (local-resource-server-running server) nil)
    (let ((wake (make-instance 'sb-bsd-sockets:local-socket :type :stream :protocol 0)))
      (unwind-protect (ignore-errors (sb-bsd-sockets:socket-connect wake (namestring (local-resource-server-path server))))
        (sb-bsd-sockets:socket-close wake)))
    (bt:join-thread (local-resource-server-thread server))
    (sb-bsd-sockets:socket-close (local-resource-server-listener server))
    (let ((clients nil) (workers nil))
      (bt:with-lock-held ((local-resource-server-lock server))
        (setf clients (copy-list (local-resource-server-clients server)) workers (copy-list (local-resource-server-workers server))))
      (dolist (client clients) (ignore-errors (usocket:socket-close client)))
      (dolist (worker workers)
        (when (bt:thread-alive-p worker)
          (ignore-errors (bt:interrupt-thread worker (lambda () (when (eq server *local-resource-worker*) (throw server :stopped)))))))
      (dolist (worker workers) (ignore-errors (bt:join-thread worker))))
    (ignore-errors (delete-file (local-resource-server-path server))))
  nil)
