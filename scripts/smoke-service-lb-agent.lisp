;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; End-to-end validation of the AGENT Service-LB path (podster-7q2.7), without
;;;; any Pod networking.  It drives the exact convergence the agent uses:
;;;; Service + EndpointSlice objects in a store -> converge-service-lb-controller
;;;; -> the attached connect4 program's maps.  Backends are loopback TCP servers
;;;; (127.0.0.1 / 127.0.0.2, same port), so the only thing under test is the LB:
;;;; a connect(2) to the unrouted ClusterIP must be redirected in-kernel to a
;;;; backend, and repeated connects must spread across both.
;;;;
;;;; Requires real root (CAP_BPF, cgroup2, bpffs).
;;;; Run:  sudo sbcl --noinform --script scripts/smoke-service-lb-agent.lisp

(require :asdf)
(let ((project (truename (merge-pathnames "../" (uiop:pathname-directory-pathname *load-truename*)))))
  (asdf:initialize-source-registry
   `(:source-registry (:directory ,project) (:tree ,(merge-pathnames "ocicl/" project))
     :inherit-configuration)))
(asdf:load-system :gr8s)
(in-package #:gr8s)

(defvar *vip* "10.96.0.77")
(defvar *vip-port* 80)
(defvar *backend-port* 19001)
(defvar *backends* '(("127.0.0.1" . #\A) ("127.0.0.2" . #\B)))
(defvar *attempts* 40)
(defvar *failures* 0)

(defun check (ok fmt &rest args)
  (format t "~&[~A] ~A~%" (if ok " ok " "FAIL") (apply #'format nil fmt args))
  (unless ok (incf *failures*)))

(defun start-backend (address label)
  (let ((socket (make-instance 'sb-bsd-sockets:inet-socket :type :stream :protocol :tcp)))
    (setf (sb-bsd-sockets:sockopt-reuse-address socket) t)
    (sb-bsd-sockets:socket-bind socket (sb-bsd-sockets:make-inet-address address) *backend-port*)
    (sb-bsd-sockets:socket-listen socket 16)
    (values socket
            (bt:make-thread
             (lambda ()
               (loop (handler-case
                         (let ((c (sb-bsd-sockets:socket-accept socket)))
                           (ignore-errors (sb-bsd-sockets:socket-send c (string label) 1))
                           (ignore-errors (sb-bsd-sockets:socket-close c)))
                       (error () (return)))))
             :name (format nil "backend ~A" label)))))

(defun connect-vip ()
  (let ((socket (make-instance 'sb-bsd-sockets:inet-socket :type :stream :protocol :tcp)))
    (unwind-protect
         (handler-case
             (sb-ext:with-timeout 5
               (sb-bsd-sockets:socket-connect socket (sb-bsd-sockets:make-inet-address *vip*) *vip-port*)
               (let ((buf (make-array 1 :element-type '(unsigned-byte 8))))
                 (multiple-value-bind (b n) (sb-bsd-sockets:socket-receive socket buf 1)
                   (declare (ignore b))
                   (and (plusp n) (code-char (aref buf 0))))))
           (error () nil))
      (ignore-errors (sb-bsd-sockets:socket-close socket)))))

(defun seed-store (store)
  "Install a ClusterIP Service and a ready EndpointSlice, as the agent receives
them in its service-discovery snapshot."
  (setf (gethash (core-resource-key "services" "default" "web") (pod-store-resources store))
        (core-object "apiVersion" "v1" "kind" "Service"
                     "metadata" (core-object "name" "web" "namespace" "default" "uid" "web-uid")
                     "spec" (core-object "type" "ClusterIP" "clusterIP" *vip*
                                         "ports" (vector (core-object "name" "" "port" *vip-port*)))))
  (setf (gethash (core-resource-key "endpointslices" "default" "web-slice") (pod-store-resources store))
        (core-object "apiVersion" "discovery.k8s.io/v1" "kind" "EndpointSlice"
                     "metadata" (core-object "name" "web-slice" "namespace" "default"
                                             "labels" (core-object "kubernetes.io/service-name" "web"))
                     "addressType" "IPv4"
                     "ports" (vector (core-object "name" "" "protocol" "TCP" "port" *backend-port*))
                     "endpoints" (vector (core-object "conditions" (core-object "ready" t)
                                                      "addresses" (vector "127.0.0.1"))
                                         (core-object "conditions" (core-object "ready" t)
                                                      "addresses" (vector "127.0.0.2"))))))

(defun join-cgroup (path) (with-open-file (s (concatenate 'string path "/cgroup.procs")
                                             :direction :output :if-exists :append :if-does-not-exist :error)
                            (format s "~D~%" (sb-posix:getpid))))
(defun leave-cgroup () (ignore-errors (with-open-file (s "/sys/fs/cgroup/cgroup.procs"
                                                         :direction :output :if-exists :append)
                                        (format s "~D~%" (sb-posix:getpid)))))

(defun run ()
  (unless (zerop (sb-posix:geteuid)) (error "needs root (CAP_BPF, cgroup2, bpffs)"))
  (let* ((pin (format nil "/sys/fs/bpf/gr8s-slb-agent-~D/" (sb-posix:getpid)))
         (cgroup (format nil "/sys/fs/cgroup/gr8s-slb-agent-~D" (sb-posix:getpid)))
         (state (format nil "/tmp/gr8s-slb-agent-~D/" (sb-posix:getpid)))
         (dataplane nil) (servers nil))
    (ensure-directories-exist (concatenate 'string cgroup "/"))
    (ensure-directories-exist state)
    (unwind-protect
         (let* ((store (open-store state)))
           (dolist (b *backends*) (multiple-value-bind (s th) (start-backend (car b) (cdr b))
                                    (push (cons s th) servers)))
           (seed-store store)
           (setf dataplane (start-service-lb-dataplane cgroup pin))
           (check (not (null (service-lb-dataplane-attachment dataplane)))
                  "connect4 LB attached to ~A" cgroup)
           ;; The exact agent convergence: read Service + EndpointSlice from the
           ;; store and write the LB maps.
           (let ((controller (make-service-lb-controller store dataplane)))
             (converge-service-lb-controller controller))
           (check (equalp (service-lb-service-value 2 0)
                          (whistler/loader:map-lookup (service-lb-service-table dataplane)
                                                      (service-lb-vip-key *vip* *vip-port*)))
                  "convergence wrote VIP ~A:~D with 2 backends" *vip* *vip-port*)
           (join-cgroup cgroup)
           (let ((hits (make-hash-table :test #'eql)) (ok 0))
             (dotimes (i *attempts*)
               (let ((label (connect-vip))) (when label (incf ok) (incf (gethash label hits 0)))))
             (leave-cgroup)
             (check (= ok *attempts*) "~D/~D connects to the unrouted ClusterIP succeeded" ok *attempts*)
             (check (plusp (gethash #\A hits 0)) "backend A (127.0.0.1) served ~D" (gethash #\A hits 0))
             (check (plusp (gethash #\B hits 0)) "backend B (127.0.0.2) served ~D" (gethash #\B hits 0))))
      (leave-cgroup)
      (when dataplane (ignore-errors (stop-service-lb-dataplane dataplane)))
      (dolist (s servers)
        (ignore-errors (sb-bsd-sockets:socket-close (car s)))
        (ignore-errors (bt:destroy-thread (cdr s))))
      (ignore-errors (sb-posix:rmdir cgroup))
      (ignore-errors (uiop:delete-empty-directory pin))
      (ignore-errors (uiop:delete-directory-tree (pathname state) :validate t :if-does-not-exist :ignore)))
    (if (zerop *failures*)
        (format t "~&agent Service-LB smoke: PASS~%")
        (format t "~&agent Service-LB smoke: ~D FAILURE(S)~%" *failures*))
    (sb-ext:exit :code (if (zerop *failures*) 0 1))))

(run)
