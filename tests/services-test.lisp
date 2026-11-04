;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Verify durable Service IP allocation and immutable identities, namespace-
;;;; scoped endpoint selection, and real TCP forwarding including client half-close.

(in-package #:gr8s/tests)
(def-suite services :in gr8s)
(in-suite services)

(defun service-test-object (name &optional (target 80))
  "Create a simple selector-based TCP ClusterIP Service request."
  (gr8s::core-object "apiVersion" "v1" "kind" "Service"
                     "metadata" (gr8s::core-object "name" name)
                     "spec" (gr8s::core-object "selector" (gr8s::core-object "app" "web")
                                               "ports" (vector (gr8s::core-object "port" 8080 "targetPort" target)))))

(test services-allocate-durably-without-consuming-dry-run-addresses
  (with-temporary-store (store directory)
    (let* ((one (gr8s::create-core-resource store "services" (service-test-object "one") "alpha"))
           (two (gr8s::create-core-resource store "services" (service-test-object "two") "beta")))
      (is (equal "10.96.0.10" (gethash "clusterIP" (gethash "spec" one))))
      (is (equal "10.96.0.11" (gethash "clusterIP" (gethash "spec" two))))
      (let ((reopened (open-store directory)))
        (let* ((preview (gr8s::create-core-resource reopened "services" (service-test-object "preview") "alpha" :dry-run t))
               (three (gr8s::create-core-resource reopened "services" (service-test-object "three") "alpha")))
          (is (equal "10.96.0.12" (gethash "clusterIP" (gethash "spec" preview))))
          (is (equal "10.96.0.12" (gethash "clusterIP" (gethash "spec" three))))
          (is (= 3 (length (gr8s::list-core-resources reopened "services"))))))
      (let ((duplicate (service-test-object "duplicate")))
        (setf (gethash "clusterIP" (gethash "spec" duplicate)) "10.96.0.10")
        (signals kubernetes-error (gr8s::create-core-resource store "services" duplicate "alpha")))
      (signals kubernetes-error
        (gr8s::update-core-resource store "services" "alpha" "one"
          (lambda (object) (setf (gethash "clusterIP" (gethash "spec" object)) "10.96.0.20") object)))
      (is (equal "10.96.0.10" (gethash "clusterIP" (gethash "spec" (gr8s::get-core-resource store "services" "alpha" "one"))))))))

(test services-resolve-only-live-matching-pods-in-their-namespace
  (with-temporary-store (store directory)
    (values directory)
    (gr8s:register-node store (gr8s:make-node-record :id "worker-id" :name "worker-a" :pod-cidr "10.88.0.0/24"))
    (gr8s:mark-node-ready store "worker-a" (get-universal-time))
    (let ((service (gr8s::create-core-resource store "services" (service-test-object "web" "http") "alpha")))
      (dolist (namespace '("alpha" "beta"))
        (let* ((object (com.inuoe.jzon:parse *valid-pod-json*))
               (metadata (gethash "metadata" object))
               (container (aref (gethash "containers" (gethash "spec" object)) 0)))
          (setf (gethash "namespace" metadata) namespace
                (gethash "labels" metadata) (gr8s::core-object "app" "web")
                (gethash "ports" container) (vector (gr8s::core-object "name" "http" "containerPort" 7777)))
          (let ((pod (create-pod store (parse-pod object))))
            (gr8s::persist-pod-assignment store pod "worker-a")
            (gr8s::update-pod-observed-status store pod
             (gr8s::core-object "phase" "Running" "podIP" "192.0.2.5"
                                "conditions" (vector (gr8s::core-object "type" "Ready" "status" "True")))))))
      (let ((port (aref (gethash "ports" (gethash "spec" service)) 0)))
        (is (equal '(("192.0.2.5" 7777)) (gr8s::service-pod-endpoints store service port)))
        (let* ((pod (get-pod store "alpha" "hello"))
               (status (gr8s::copy-core-object (gr8s::pod-observed-status store pod))))
          (setf (gethash "status" (aref (gethash "conditions" status) 0)) "False")
          (gr8s::update-pod-observed-status store pod status)
          (is (null (gr8s::service-pod-endpoints store service port)))
          (setf (gethash "status" (aref (gethash "conditions" status) 0)) "True")
          (gr8s::update-pod-observed-status store pod status))
        (gr8s::mark-pod-deleting store "alpha" "hello")
        (is (null (gr8s::service-pod-endpoints store service port)))))))

(test tcp-service-proxy-forwards-real-data-after-a-client-half-close
  (let* ((backend (usocket:socket-listen "127.0.0.1" 0 :reuse-address t :element-type '(unsigned-byte 8)))
         (backend-thread nil) (proxy nil) (client nil) (received nil))
    (unwind-protect
         (progn
           (setf backend-thread
                 (bt:make-thread
                  (lambda ()
                    (let ((peer (usocket:socket-accept backend :element-type '(unsigned-byte 8))))
                      (unwind-protect
                           (let ((input (make-array 5 :element-type '(unsigned-byte 8)))
                                 (stream (usocket:socket-stream peer)))
                             (read-sequence input stream)
                             (setf received (trivial-utf-8:utf-8-bytes-to-string input))
                             (write-sequence (trivial-utf-8:string-to-utf-8-bytes "world") stream)
                             (finish-output stream))
                        (ignore-errors (usocket:socket-close peer)))))
                  :name "gr8s Service test backend"))
           (setf proxy (gr8s::start-tcp-service-proxy "127.0.0.1" 0
                         (lambda () (list "127.0.0.1" (usocket:get-local-port backend)))))
           (setf client (usocket:socket-connect "127.0.0.1" (usocket:get-local-port (gr8s::tcp-service-proxy-socket proxy))
                                               :element-type '(unsigned-byte 8)))
           (sb-sys:with-deadline (:seconds 5)
             (write-sequence (trivial-utf-8:string-to-utf-8-bytes "hello") (usocket:socket-stream client))
             (finish-output (usocket:socket-stream client))
             (usocket:socket-shutdown client :output)
             (let ((reply (make-array 5 :element-type '(unsigned-byte 8))))
               (is (= 5 (read-sequence reply (usocket:socket-stream client))))
               (is (equal "world" (trivial-utf-8:utf-8-bytes-to-string reply)))))
           (bt:join-thread backend-thread)
           (is (equal "hello" received))
           (gr8s::stop-tcp-service-proxy proxy)
           (is (not (bt:thread-alive-p (gr8s::tcp-service-proxy-thread proxy)))))
      (when client (ignore-errors (usocket:socket-close client)))
      (when proxy (gr8s::stop-tcp-service-proxy proxy))
      (ignore-errors (usocket:socket-close backend))
      (when (and backend-thread (bt:thread-alive-p backend-thread)) (ignore-errors (bt:destroy-thread backend-thread))))))

(test service-proxy-retired-request-cleanup-cannot-shutdown-a-reused-descriptor
  #+sbcl
  (let* ((listener (usocket:socket-listen "127.0.0.1" 0 :reuse-address t :element-type '(unsigned-byte 8)))
         (port (usocket:get-local-port listener))
         (old-upstream (usocket:socket-connect "127.0.0.1" port :element-type '(unsigned-byte 8)))
         (old-client (usocket:socket-accept listener :element-type '(unsigned-byte 8)))
         (old-fd (sb-bsd-sockets:socket-file-descriptor (usocket::socket old-upstream)))
         (proxy (gr8s::make-tcp-service-proxy)) (fresh nil) (peer nil))
    (unwind-protect
         (progn
           (setf (gethash old-client (gr8s::tcp-service-proxy-connections proxy)) (list old-client old-upstream))
           (gr8s::service-proxy-close-connection proxy old-client)
           (setf fresh (usocket:socket-connect "127.0.0.1" port :element-type '(unsigned-byte 8))
                 peer (usocket:socket-accept listener :element-type '(unsigned-byte 8)))
           (is (= old-fd (sb-bsd-sockets:socket-file-descriptor (usocket::socket fresh))))
           ;; SBCL's usocket stream close leaves the old socket wrapper's fd slot
           ;; intact. An unguarded shutdown on it half-closes FRESH, not OLD.
           (gr8s::service-proxy-shutdown-upstream-output proxy old-client old-upstream)
           (write-byte 77 (usocket:socket-stream fresh))
           (finish-output (usocket:socket-stream fresh))
           (sb-sys:with-deadline (:seconds 2)
             (is (= 77 (read-byte (usocket:socket-stream peer) nil -1))))
           (setf (gethash fresh (gr8s::tcp-service-proxy-connections proxy)) (list fresh fresh))
           (gr8s::service-proxy-shutdown-upstream-output proxy fresh fresh)
           (sb-sys:with-deadline (:seconds 2)
             (is (eq :eof (read-byte (usocket:socket-stream peer) nil :eof)))))
      (when fresh (ignore-errors (usocket:socket-close fresh)))
      (when peer (ignore-errors (usocket:socket-close peer)))
      (ignore-errors (usocket:socket-close old-client))
      (ignore-errors (usocket:socket-close old-upstream))
      (ignore-errors (usocket:socket-close listener)))))
