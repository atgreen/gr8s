;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
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
                :app (hunchentoot:header-in :x-app request) :body body
                :hop (hunchentoot:header-in :x-hop request)
                :forwarded-uri (hunchentoot:header-in :x-forwarded-uri request)
                :forwarded-host (hunchentoot:header-in :x-forwarded-host request))
          (proxy-test-observations acceptor))
    (setf (hunchentoot:content-type*) "application/octet-stream")
    (cond ((equal "/echo" (hunchentoot:script-name request))
           (setf (hunchentoot:return-code*) 201) body)
          ((equal "/missing" (hunchentoot:script-name request))
           (setf (hunchentoot:return-code*) 404) "actual missing file")
          ((equal "/redirect" (hunchentoot:script-name request))
           (setf (hunchentoot:return-code*) 302 (hunchentoot:header-out :location) "/target") "actual redirect")
          ((equal "/chunks" (hunchentoot:script-name request))
           (let ((stream (hunchentoot:send-headers)))
             (write-sequence #(0 255) stream) (finish-output stream)
             (write-sequence #(1 2 127) stream) (finish-output stream))
           nil)
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
         (format nil "http://127.0.0.1:~D/api/v1/namespaces/default/pods/hello/proxy~A" *http-test-port* suffix)
         :proxy nil :redirect nil :force-binary t :preserve-uri t options))

(test pod-proxy-relays-an-upgraded-connection-in-both-directions
  (with-temporary-store (store path)
    (let* ((address (pod-proxy-test-address))
           (object (com.inuoe.jzon:parse *valid-pod-json*))
           (listener (usocket:socket-listen address 0 :reuse-address t
                                                    :element-type '(unsigned-byte 8)))
           (upstream-request nil)
           (upstream-payload nil)
           (upstream-thread
             (bt:make-thread
              (lambda ()
                (let* ((socket (usocket:socket-accept listener :element-type '(unsigned-byte 8)))
                       (stream (usocket:socket-stream socket)))
                  (unwind-protect
                       (progn
                         (setf upstream-request
                               (gr8s.protocol::octets-as-ascii (gr8s.protocol::read-http-response-head stream)))
                         (write-sequence
                          (gr8s.protocol::ascii-octets
                           (format nil "HTTP/1.1 101 Switching Protocols~C~CConnection: Upgrade~C~CUpgrade: gr8s-test~C~CX-Upstream: kept~C~C~C~C"
                                   #\Return #\Linefeed #\Return #\Linefeed
                                   #\Return #\Linefeed #\Return #\Linefeed
                                   #\Return #\Linefeed))
                          stream)
                         (finish-output stream)
                         (setf upstream-payload (read-exact-octets stream 4))
                         (write-sequence (gr8s.protocol::ascii-octets "pong") stream)
                         (finish-output stream))
                    (ignore-errors (usocket:socket-close socket)))))
              :name "gr8s Pod proxy upgrade upstream"))
           (frontend nil)
           (client nil))
      (setf (gethash "containerPort" (aref (gethash "ports" (aref (gethash "containers" (gethash "spec" object)) 0)) 0))
            (usocket:get-local-port listener))
      (unwind-protect
           (progn
             (setf frontend (start-http-test-server :store store :runtime (make-fake-runtime)))
             (let ((pod (create-pod store (parse-pod object))))
               (gr8s.kubelet::save-pod-observation store pod (gr8s.resources::core-object "phase" "Running" "podIP" address)))
             (setf client (usocket:socket-connect "127.0.0.1" *http-test-port*
                                                  :element-type '(unsigned-byte 8)))
             (let ((stream (usocket:socket-stream client)))
               (setf (sb-impl::fd-stream-timeout stream) 10.0)
               (write-sequence
                (gr8s.protocol::ascii-octets
                 (format nil "GET /api/v1/namespaces/default/pods/hello/proxy/tunnel?x=1 HTTP/1.1~C~CHost: api.example~C~CAuthorization: Bearer secret~C~CConnection: Upgrade~C~CUpgrade: gr8s-test~C~CContent-Length: 0~C~C~C~C"
                         #\Return #\Linefeed #\Return #\Linefeed #\Return #\Linefeed
                         #\Return #\Linefeed #\Return #\Linefeed #\Return #\Linefeed
                         #\Return #\Linefeed))
                stream)
               (finish-output stream)
               (multiple-value-bind (status headers)
                   (gr8s.protocol::parse-http-response-head (gr8s.protocol::read-http-response-head stream))
                 (is (= 101 status))
                 (when (= 101 status)
                   (is (equal "gr8s-test" (cdr (assoc :upgrade headers))))
                   (is (equal "kept" (cdr (assoc :x-upstream headers))))
                   (write-sequence (gr8s.protocol::ascii-octets "ping") stream)
                   (finish-output stream)
                   (is (equalp (gr8s.protocol::ascii-octets "pong") (read-exact-octets stream 4))))))
             (when upstream-request
               (bt:join-thread upstream-thread)
               (is (search "GET /tunnel?x=1 HTTP/1.1" upstream-request))
               (is (search "Upgrade: gr8s-test" upstream-request :test #'char-equal))
               (is (null (search "Authorization:" upstream-request :test #'char-equal)))
               (is (equalp (gr8s.protocol::ascii-octets "ping") upstream-payload))))
        (when client (ignore-errors (usocket:socket-close client)))
        (when frontend (stop-server frontend))
        (ignore-errors (usocket:socket-close listener))
        (when (bt:thread-alive-p upstream-thread)
          (ignore-errors (bt:destroy-thread upstream-thread)))))))

(test service-proxy-relays-an-upgraded-connection-to-a-ready-endpoint
  (with-temporary-store (store path)
    (let* ((address (pod-proxy-test-address))
           (listener (usocket:socket-listen address 0 :reuse-address t
                                                    :element-type '(unsigned-byte 8)))
           (upstream-request nil)
           (upstream-thread
             (bt:make-thread
              (lambda ()
                (let* ((socket (usocket:socket-accept listener :element-type '(unsigned-byte 8)))
                       (stream (usocket:socket-stream socket)))
                  (unwind-protect
                       (progn
                         (setf upstream-request
                               (gr8s.protocol::octets-as-ascii (gr8s.protocol::read-http-response-head stream)))
                         (write-sequence
                          (gr8s.protocol::ascii-octets
                           (format nil "HTTP/1.1 101 Switching Protocols~C~CConnection: Upgrade~C~CUpgrade: service-test~C~C~C~C"
                                   #\Return #\Linefeed #\Return #\Linefeed
                                   #\Return #\Linefeed #\Return #\Linefeed))
                          stream)
                         (finish-output stream)
                         (let ((byte (read-byte stream)))
                           (write-byte (1+ byte) stream)
                           (finish-output stream)))
                    (ignore-errors (usocket:socket-close socket)))))
              :name "gr8s Service proxy upgrade upstream"))
           (frontend nil)
           (client nil))
      (gr8s.resources::create-core-resource
       store "services"
       (gr8s.resources::core-object
        "metadata" (gr8s.resources::core-object "name" "web")
        "spec" (gr8s.resources::core-object
                "ports" (vector (gr8s.resources::core-object "name" "http" "port" 80))))
       "default")
      (gr8s.resources::create-core-resource
       store "endpointslices"
       (gr8s.resources::core-object
        "metadata" (gr8s.resources::core-object
                    "name" "web-ready"
                    "labels" (gr8s.resources::core-object "kubernetes.io/service-name" "web"))
        "addressType" "IPv4"
        "endpoints" (vector (gr8s.resources::core-object
                             "addresses" (vector address)
                             "conditions" (gr8s.resources::core-object "ready" t)))
        "ports" (vector (gr8s.resources::core-object
                         "name" "http" "port" (usocket:get-local-port listener)
                         "protocol" "TCP")))
       "default")
      (unwind-protect
           (progn
             (setf frontend (start-http-test-server :store store :runtime (make-fake-runtime))
                   client (usocket:socket-connect "127.0.0.1" *http-test-port*
                                                  :element-type '(unsigned-byte 8)))
             (let ((stream (usocket:socket-stream client)))
               (setf (sb-impl::fd-stream-timeout stream) 10.0)
               (write-sequence
                (gr8s.protocol::ascii-octets
                 (format nil "GET /api/v1/namespaces/default/services/web:http/proxy/tunnel HTTP/1.1~C~CHost: api.example~C~CConnection: Upgrade~C~CUpgrade: service-test~C~C~C~C"
                         #\Return #\Linefeed #\Return #\Linefeed #\Return #\Linefeed
                         #\Return #\Linefeed #\Return #\Linefeed))
                stream)
               (finish-output stream)
               (multiple-value-bind (status headers)
                   (gr8s.protocol::parse-http-response-head (gr8s.protocol::read-http-response-head stream))
                 (is (= 101 status))
                 (is (equal "service-test" (cdr (assoc :upgrade headers)))))
               (write-byte 41 stream)
               (finish-output stream)
               (is (= 42 (read-byte stream))))
             (bt:join-thread upstream-thread)
             (is (search "GET /tunnel HTTP/1.1" upstream-request)))
        (when client (ignore-errors (usocket:socket-close client)))
        (when frontend (stop-server frontend))
        (ignore-errors (usocket:socket-close listener))
        (when (bt:thread-alive-p upstream-thread)
          (ignore-errors (bt:destroy-thread upstream-thread)))))))

(test pod-proxy-target-uses-observed-uid-address-and-kubernetes-port-defaults
  (with-temporary-store (store path)
    (let ((pod (create-pod store (parse-pod *valid-pod-json*))))
      (signals kubernetes-error (gr8s.apiserver::pod-proxy-target store "default" "hello"))
      (gr8s.kubelet::save-pod-observation store pod (gr8s.resources::core-object "phase" "Running" "podIP" "10.88.0.20"))
      (multiple-value-bind (url uid) (gr8s.apiserver::pod-proxy-target store "default" "hello")
        (is (equal "http://10.88.0.20:8080" url)) (is (equal (pod-uid pod) uid)))
      (is (equal "https://10.88.0.20:8443" (gr8s.apiserver::pod-proxy-target store "default" "https:hello:8443")))
      (dolist (id '("hello:not-a-port" "hello:0" "hello:65536" "ftp:hello:80" "a:b:c:d"))
        (signals kubernetes-error (gr8s.apiserver::pod-proxy-target store "default" id)))
      (dolist (ip '("127.0.0.1" "169.254.1.1" "0.0.0.0" "224.0.0.1" "::1" "fe80::1"))
        (gr8s.kubelet::save-pod-observation store pod (gr8s.resources::core-object "phase" "Running" "podIP" ip))
        (signals kubernetes-error (gr8s.apiserver::pod-proxy-target store "default" "hello")))
      (gr8s.kubelet::save-pod-observation store pod (gr8s.resources::core-object "phase" "Running" "podIP" "fd00::20"))
      (is (equal "http://[fd00::20]:8080" (gr8s.apiserver::pod-proxy-target store "default" "hello")))
      (dolist (ip '("0.1.2.3" "240.1.2.3" "::ffff:192.0.2.1"))
        (gr8s.kubelet::save-pod-observation store pod (gr8s.resources::core-object "phase" "Running" "podIP" ip))
        (is (stringp (gr8s.apiserver::pod-proxy-target store "default" "hello")))))))

(test pod-proxy-numeric-address-policy-matches-global-unicast-classification
  (dolist (ip '("10.88.0.2" "192.0.2.1" "0.1.2.3" "240.0.0.1" "2001:db8::2" "fd00::2" "::ffff:10.88.0.2"))
    (is (not (null (gr8s.apiserver::pod-proxy-address-p ip)))))
  (dolist (ip '("0.0.0.0" "255.255.255.255" "127.1.2.3" "169.254.1.2" "224.1.2.3" "::" "::1" "fe80::2"
               "ff02::1" "::ffff:127.0.0.1" "::ffff:169.254.1.2" "not-an-address" "1:2:3:4:5:6:7:10000"))
    (is (not (gr8s.apiserver::pod-proxy-address-p ip)))))

(test pod-proxy-forwards-real-http-methods-binary-data-status-and-query
  (with-temporary-store (store path)
    (let* ((address (pod-proxy-test-address))
           (object (com.inuoe.jzon:parse *valid-pod-json*))
           (upstream (make-instance 'pod-proxy-test-upstream :address address :port 0 :access-log-destination nil))
           (frontend nil))
      (hunchentoot:start upstream)
      (setf (gethash "containerPort" (aref (gethash "ports" (aref (gethash "containers" (gethash "spec" object)) 0)) 0))
            (hunchentoot:acceptor-port upstream))
      (unwind-protect
           (progn
             (setf frontend (start-http-test-server :store store :runtime (make-fake-runtime)))
             (let ((pod (create-pod store (parse-pod object))))
               (gr8s.kubelet::save-pod-observation store pod (gr8s.resources::core-object "phase" "Running" "podIP" address)))
             (multiple-value-bind (bytes code)
                 (proxy-api-request "/results/dns@pod_name?file=a%2Fb&x=1"
                                    :additional-headers '(("X-App" . "application-value") ("Authorization" . "Bearer api-secret")))
               (is (= 200 code)) (is (equalp #(0 255 1 2 127) bytes)))
             (let ((actual (first (proxy-test-observations upstream))))
               (is (equal "/results/dns@pod_name?file=a%2Fb&x=1" (getf actual :uri)))
               (is (equal "application-value" (getf actual :app))) (is (null (getf actual :authorization)))
               (is (equal "/api/v1/namespaces/default/pods/hello/proxy/results/dns@pod_name" (getf actual :forwarded-uri)))
               (is (equal (format nil "127.0.0.1:~D" *http-test-port*) (getf actual :forwarded-host))))
             (multiple-value-bind (bytes code)
                 (sb-sys:with-deadline (:seconds 5)
                   (proxy-api-request "/chunks" :additional-headers '(("Connection" . "X-Hop, close") ("X-Hop" . "remove-me"))))
               (is (= 200 code)) (is (equalp #(0 255 1 2 127) bytes))
               (is (null (getf (first (proxy-test-observations upstream)) :hop))))
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
               (is (= 200 code)) (is (equalp #(0 255 1 2 127) body))))
        (when frontend (stop-server frontend))
        (hunchentoot:stop upstream)))))

(test pod-proxy-routes-and-authorization-retain-the-proxy-subresource
  (dolist (path '("/api/v1/namespaces/default/pods/hello/proxy"
                  "/api/v1/namespaces/default/pods/hello/proxy/"
                  "/api/v1/namespaces/default/pods/hello/proxy/results/a@b"))
    (is (not (null (nth-value 2 (gr8s.apiserver::pod-http-proxy-route path)))))
    (multiple-value-bind (verb group resource name namespace)
        (gr8s.apiserver::kubernetes-authorization-target path :get)
      (is (equal '("get" "" "pods/proxy" "hello" "default") (list verb group resource name namespace)))))
  (is (not (nth-value 2 (gr8s.apiserver::pod-http-proxy-route "/api/v1/namespaces/default/pods/hello/proxy-other")))))

(test pod-proxy-redirects-preserve-relative-external-query-and-fragment-semantics
  (let ((target "http://10.88.0.2:8080") (prefix "/api/v1/namespaces/n/pods/p/proxy")
        (frontend "https://api.example:443"))
    (dolist (location '("../relative?x=1" "https://outside.example/path" "http://10.88.0.2:8081/other-port"))
      (is (equal location (gr8s.apiserver::pod-proxy-rewrite-location location target prefix frontend))))
    (dolist (location '("/target?x=a%2Fb#fragment" "http://10.88.0.2:8080/target?x=a%2Fb#fragment"
                        "https://api.example/target?x=a%2Fb#fragment"))
      (is (equal (concatenate 'string prefix "/target?x=a%2Fb#fragment")
                 (gr8s.apiserver::pod-proxy-rewrite-location location target prefix frontend))))))

(test pod-proxy-rbac-requires-a-separate-scoped-proxy-grant
  (with-temporary-store (store directory)
    (service-account-test-store store "proxy-reader" "default")
    (let* ((secret (gr8s.resources::ensure-service-account-credential store "default" "proxy-reader"))
           (identity (gr8s.resources::authenticate-service-account-token store (service-account-test-token secret))))
      (labels ((grant (name resource)
                 (gr8s.resources::create-core-resource store "roles"
                   (gr8s.resources::core-object "metadata" (gr8s.resources::core-object "name" name)
                                     "rules" (vector (gr8s.resources::core-object "apiGroups" #("") "resources" (vector resource)
                                                                       "verbs" #("get") "resourceNames" #("hello")))) "default")
                 (gr8s.resources::create-core-resource store "rolebindings"
                   (gr8s.resources::core-object "metadata" (gr8s.resources::core-object "name" name)
                                     "roleRef" (gr8s.resources::core-object "apiGroup" "rbac.authorization.k8s.io" "kind" "Role" "name" name)
                                     "subjects" (vector (gr8s.resources::core-object "kind" "ServiceAccount" "name" "proxy-reader" "namespace" "default"))) "default"))
               (allowed (name namespace method)
                 (multiple-value-bind (verb group resource parsed-name parsed-namespace)
                     (gr8s.apiserver::kubernetes-authorization-target
                      (format nil "/api/v1/namespaces/~A/pods/~A/proxy/results/file" namespace name) method)
                   (gr8s.resources::service-account-authorized-p store identity verb group resource parsed-name parsed-namespace))))
        (grant "pod-reader" "pods")
        (is (not (allowed "hello" "default" :get)))
        (grant "pod-proxy-reader" "pods/proxy")
        (is (not (null (allowed "hello" "default" :get))))
        (is (not (allowed "other" "default" :get)))
        (is (not (allowed "hello" "other" :get)))
        (is (not (allowed "hello" "default" :post)))
        (gr8s.resources::delete-core-resource store "rolebindings" "default" "pod-proxy-reader")
        (is (not (allowed "hello" "default" :get)))))))
