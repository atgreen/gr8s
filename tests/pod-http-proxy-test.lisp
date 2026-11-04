;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Exercise Pod proxy resolution and actual HTTP forwarding through two owned
;;;; servers, including binary requests, status codes, headers and URI suffixes.

(in-package #:gr8s/tests)
(def-suite pod-http-proxy :in gr8s)
(in-suite pod-http-proxy)

(defclass pod-proxy-test-upstream (hunchentoot:acceptor)
  ((observations :initform nil :accessor proxy-test-observations)))

(defmethod hunchentoot:acceptor-dispatch-request ((acceptor pod-proxy-test-upstream) request)
  "Return the actual workload's response and retain what crossed its HTTP boundary."
  (let ((body (hunchentoot:raw-post-data :force-binary t)))
    (push (list :method (hunchentoot:request-method request) :uri (hunchentoot:request-uri request)
                :authorization (hunchentoot:header-in :authorization request)
                :app (hunchentoot:header-in :x-app request) :body body)
          (proxy-test-observations acceptor))
    (setf (hunchentoot:content-type*) "application/octet-stream")
    (cond ((equal "/echo" (hunchentoot:script-name request))
           (setf (hunchentoot:return-code*) 201) body)
          ((equal "/missing" (hunchentoot:script-name request))
           (setf (hunchentoot:return-code*) 404) "actual missing file")
          ((equal "/redirect" (hunchentoot:script-name request))
           (setf (hunchentoot:return-code*) 302 (hunchentoot:header-out :location) "/target") "actual redirect")
          (t #(0 255 1 2 127)))))

(defun pod-proxy-test-address ()
  "Find this host's real routed address without sending a datagram to the network."
  (let ((socket (usocket:socket-connect "192.0.2.1" 9 :protocol :datagram)))
    (unwind-protect
         (format nil "~{~D~^.~}" (coerce (usocket:get-local-address socket) 'list))
      (usocket:socket-close socket))))

(defun proxy-api-request (suffix &rest options)
  "Call the real control-plane HTTP listener with environment proxying disabled."
  (apply #'drakma:http-request
         (concatenate 'string "http://127.0.0.1:18080/api/v1/namespaces/default/pods/hello/proxy" suffix)
         :proxy nil :redirect nil :force-binary t :preserve-uri t options))

(test pod-proxy-target-uses-observed-uid-address-and-kubernetes-port-defaults
  (with-temporary-store (store path)
    (let ((pod (create-pod store (parse-pod *valid-pod-json*))))
      (signals kubernetes-error (gr8s::pod-proxy-target store "default" "hello"))
      (gr8s::save-pod-observation store pod (gr8s::core-object "phase" "Running" "podIP" "10.88.0.20"))
      (multiple-value-bind (url uid) (gr8s::pod-proxy-target store "default" "hello")
        (is (equal "http://10.88.0.20:8080" url)) (is (equal (pod-uid pod) uid)))
      (is (equal "https://10.88.0.20:8443" (gr8s::pod-proxy-target store "default" "https:hello:8443")))
      (dolist (id '("hello:not-a-port" "hello:0" "hello:65536" "ftp:hello:80" "a:b:c:d"))
        (signals kubernetes-error (gr8s::pod-proxy-target store "default" id)))
      (dolist (ip '("127.0.0.1" "169.254.1.1" "0.0.0.0" "224.0.0.1" "::1" "fe80::1"))
        (gr8s::save-pod-observation store pod (gr8s::core-object "phase" "Running" "podIP" ip))
        (signals kubernetes-error (gr8s::pod-proxy-target store "default" "hello")))
      (gr8s::save-pod-observation store pod (gr8s::core-object "phase" "Running" "podIP" "fd00::20"))
      (is (equal "http://[fd00::20]:8080" (gr8s::pod-proxy-target store "default" "hello"))))))

(test pod-proxy-forwards-real-http-methods-binary-data-status-and-query
  (with-temporary-store (store path)
    (let* ((address (pod-proxy-test-address))
           (object (com.inuoe.jzon:parse *valid-pod-json*))
           (upstream (make-instance 'pod-proxy-test-upstream :address address :port 18182 :access-log-destination nil))
           (frontend nil))
      (setf (gethash "containerPort" (aref (gethash "ports" (aref (gethash "containers" (gethash "spec" object)) 0)) 0)) 18182)
      (hunchentoot:start upstream)
      (unwind-protect
           (progn
             (setf frontend (start-server :address "127.0.0.1" :port 18080 :store store :runtime (make-fake-runtime)))
             (let ((pod (create-pod store (parse-pod object))))
               (gr8s::save-pod-observation store pod (gr8s::core-object "phase" "Running" "podIP" address)))
             (multiple-value-bind (bytes code)
                 (proxy-api-request "/results/dns@pod_name?file=a%2Fb&x=1"
                                    :additional-headers '(("X-App" . "application-value") ("Authorization" . "Bearer api-secret")))
               (is (= 200 code)) (is (equalp #(0 255 1 2 127) bytes)))
             (let ((actual (first (proxy-test-observations upstream))))
               (is (equal "/results/dns@pod_name?file=a%2Fb&x=1" (getf actual :uri)))
               (is (equal "application-value" (getf actual :app))) (is (null (getf actual :authorization))))
             (dolist (method '(:post :put :patch :delete))
               (multiple-value-bind (bytes code)
                   (proxy-api-request "/echo" :method method
                                      :content (make-array 4 :element-type '(unsigned-byte 8) :initial-contents '(0 255 128 42))
                                      :content-type "application/octet-stream")
                 (is (= 201 code)) (is (equalp #(0 255 128 42) bytes))))
             (multiple-value-bind (body code) (proxy-api-request "/missing")
               (is (= 404 code)) (is (equalp (trivial-utf-8:string-to-utf-8-bytes "actual missing file") body)))
             (multiple-value-bind (body code headers) (proxy-api-request "/redirect")
               (declare (ignore body)) (is (= 302 code))
               (is (equal "/api/v1/namespaces/default/pods/hello/proxy/target" (cdr (assoc :location headers)))))
             (multiple-value-bind (body code) (proxy-api-request "/" :method :head)
               (is (= 200 code)) (is (zerop (length body))))
             (multiple-value-bind (body code) (proxy-api-request "/" :method :options)
               (is (= 200 code)) (is (equalp #(0 255 1 2 127) body)))
             (multiple-value-bind (body code) (proxy-api-request "/" :additional-headers '(("Upgrade" . "websocket")))
               (declare (ignore body)) (is (= 501 code))))
        (when frontend (stop-server frontend))
        (hunchentoot:stop upstream)))))

(test pod-proxy-routes-and-authorization-retain-the-proxy-subresource
  (dolist (path '("/api/v1/namespaces/default/pods/hello/proxy"
                  "/api/v1/namespaces/default/pods/hello/proxy/"
                  "/api/v1/namespaces/default/pods/hello/proxy/results/a@b"))
    (is (not (null (nth-value 2 (gr8s::pod-http-proxy-route path)))))
    (multiple-value-bind (verb group resource name namespace)
        (gr8s::kubernetes-authorization-target path :get)
      (is (equal '("get" "" "pods/proxy" "hello" "default") (list verb group resource name namespace)))))
  (is (not (nth-value 2 (gr8s::pod-http-proxy-route "/api/v1/namespaces/default/pods/hello/proxy-other")))))
