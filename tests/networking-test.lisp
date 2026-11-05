;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Verify Service node port allocation, session affinity and status writes, the
;;;; Endpoints controller and mirroring, the networking.k8s.io API objects, the
;;;; Service and Node proxy routes, and real TCP and UDP node port relaying.

(in-package #:gr8s/tests)
(def-suite networking :in gr8s)
(in-suite networking)

(defun network-service (name &rest spec-pairs)
  "Build a selector Service request with a TCP port 80 and extra SPEC-PAIRS."
  (let ((spec (gr8s::core-object "selector" (gr8s::core-object "app" "web")
                                 "ports" (vector (gr8s::core-object "name" "http" "port" 80 "targetPort" 8080)))))
    (loop for (key value) on spec-pairs by #'cddr do (setf (gethash key spec) value))
    (gr8s::core-object "metadata" (gr8s::core-object "name" name) "spec" spec)))

(defun service-node-port (service &optional (index 0))
  (gethash "nodePort" (aref (gethash "ports" (gethash "spec" service)) index)))

(test node-ports-allocate-in-range-and-survive-updates
  (with-temporary-store (store directory)
    (values directory)
    (let* ((one (gr8s::create-core-resource store "services" (network-service "one" "type" "NodePort") "alpha"))
           (port (service-node-port one)))
      (is (<= 30000 port 32767))
      (let ((updated (gr8s::update-core-resource
                      store "services" "alpha" "one"
                      (lambda (object)
                        (remhash "nodePort" (aref (gethash "ports" (gethash "spec" object)) 0))
                        object))))
        (is (= port (service-node-port updated))))
      (let ((two (gr8s::create-core-resource store "services" (network-service "two" "type" "NodePort") "alpha")))
        (is (/= port (service-node-port two))))
      ;; Another Service may not take it, a port outside the range is refused, and
      ;; a ClusterIP Service may not ask for one.
      (let ((taken (network-service "taken" "type" "NodePort")))
        (setf (gethash "nodePort" (aref (gethash "ports" (gethash "spec" taken)) 0)) port)
        (signals kubernetes-error (gr8s::create-core-resource store "services" taken "alpha")))
      (let ((outside (network-service "outside" "type" "NodePort")))
        (setf (gethash "nodePort" (aref (gethash "ports" (gethash "spec" outside)) 0)) 80)
        (signals kubernetes-error (gr8s::create-core-resource store "services" outside "alpha")))
      (let ((plain (network-service "plain")))
        (setf (gethash "nodePort" (aref (gethash "ports" (gethash "spec" plain)) 0)) 30555)
        (signals kubernetes-error (gr8s::create-core-resource store "services" plain "alpha")))
      ;; Leaving the type gives the port back.
      (let ((cluster-ip (gr8s::update-core-resource
                         store "services" "alpha" "one"
                         (lambda (object) (setf (gethash "type" (gethash "spec" object)) "ClusterIP") object))))
        (is (null (service-node-port cluster-ip)))))))

(test load-balancer-services-allocate-node-ports-unless-told-not-to
  (with-temporary-store (store directory)
    (values directory)
    (let ((default (gr8s::create-core-resource
                    store "services" (network-service "lb" "type" "LoadBalancer" "loadBalancerClass" "example.com/lb") "alpha"))
          (none (gr8s::create-core-resource
                 store "services" (network-service "bare" "type" "LoadBalancer" "allocateLoadBalancerNodePorts" nil) "alpha")))
      (is (integerp (service-node-port default)))
      (is (equal "example.com/lb" (gethash "loadBalancerClass" (gethash "spec" default))))
      (is (equal "Cluster" (gethash "externalTrafficPolicy" (gethash "spec" default))))
      (is (null (service-node-port none))))))

(test external-name-converts-to-node-port-and-back
  (with-temporary-store (store directory)
    (values directory)
    (gr8s::create-core-resource
     store "services" (gr8s::core-object "metadata" (gr8s::core-object "name" "alias")
                                         "spec" (gr8s::core-object "type" "ExternalName" "externalName" "db.example.com"))
     "alpha")
    (let ((node-port (gr8s::update-core-resource
                      store "services" "alpha" "alias"
                      (lambda (object)
                        (let ((spec (gethash "spec" object)))
                          (setf (gethash "type" spec) "NodePort" (gethash "externalName" spec) ""
                                (gethash "ports" spec) (vector (gr8s::core-object "name" "http" "port" 80 "targetPort" 9376))))
                        object))))
      (is (gr8s::service-ip-index (gethash "clusterIP" (gethash "spec" node-port))))
      (is (null (gethash "externalName" (gethash "spec" node-port))))
      (is (integerp (service-node-port node-port))))
    (let ((alias (gr8s::update-core-resource
                  store "services" "alpha" "alias"
                  (lambda (object)
                    (let ((spec (gethash "spec" object)))
                      (setf (gethash "type" spec) "ExternalName" (gethash "externalName" spec) "db.example.com")
                      (remhash "clusterIP" spec) (remhash "clusterIPs" spec))
                    object))))
      (is (null (gethash "clusterIP" (gethash "spec" alias))))
      (is (null (service-node-port alias))))))

(test services-accept-one-port-number-over-two-protocols
  (with-temporary-store (store directory)
    (values directory)
    (let* ((input (network-service "both"))
           (spec (gethash "spec" input)))
      (setf (gethash "ports" spec)
            (vector (gr8s::core-object "name" "tcp" "port" 80 "protocol" "TCP")
                    (gr8s::core-object "name" "udp" "port" 80 "protocol" "UDP")))
      (let ((created (gr8s::create-core-resource store "services" input "alpha")))
        (is (equal "UDP" (gethash "protocol" (aref (gethash "ports" (gethash "spec" created)) 1))))))
    (let* ((input (network-service "same"))
           (spec (gethash "spec" input)))
      (setf (gethash "ports" spec)
            (vector (gr8s::core-object "name" "a" "port" 80 "protocol" "TCP")
                    (gr8s::core-object "name" "b" "port" 80 "protocol" "TCP")))
      (signals kubernetes-error (gr8s::create-core-resource store "services" input "alpha")))))

(test session-affinity-defaults-its-timeout-and-drops-it-when-off
  (with-temporary-store (store directory)
    (values directory)
    (let* ((on (gr8s::create-core-resource store "services" (network-service "sticky" "sessionAffinity" "ClientIP") "alpha"))
           (timeout (gethash "timeoutSeconds" (gethash "clientIP" (gethash "sessionAffinityConfig" (gethash "spec" on))))))
      (is (= 10800 timeout))
      (is (= 10800 (gr8s::service-affinity-timeout on)))
      (let ((off (gr8s::update-core-resource
                  store "services" "alpha" "sticky"
                  (lambda (object)
                    (let ((spec (gethash "spec" object)))
                      (setf (gethash "sessionAffinity" spec) "None")
                      (remhash "sessionAffinityConfig" spec))
                    object))))
        (is (null (gethash "sessionAffinityConfig" (gethash "spec" off))))
        (is (null (gr8s::service-affinity-timeout off)))))))

(test session-affinity-can-be-switched-off-with-the-timeout-still-set
  ;; A client that reads a ClientIP Service back and changes only the affinity still sends its timeout.
  (with-temporary-store (store directory)
    (values directory)
    (gr8s::create-core-resource store "services" (network-service "sticky" "sessionAffinity" "ClientIP") "alpha")
    (let ((off (gr8s::update-core-resource
                store "services" "alpha" "sticky"
                (lambda (object) (setf (gethash "sessionAffinity" (gethash "spec" object)) "None") object))))
      (is (null (gethash "sessionAffinityConfig" (gethash "spec" off)))))
    (signals kubernetes-error
      (gr8s::create-core-resource
       store "services"
       (network-service "bad" "sessionAffinityConfig" (gr8s::core-object "clientIP" (gr8s::core-object "timeoutSeconds" 5)))
       "alpha"))))

(test host-network-pods-claim-their-container-ports-on-the-host
  (flet ((pod (host-port)
           (let ((port (gr8s::core-object "containerPort" 8080)))
             (when host-port (setf (gethash "hostPort" port) host-port))
             (parse-pod (gr8s::core-object "apiVersion" "v1" "kind" "Pod"
                                           "metadata" (gr8s::core-object "name" "web" "namespace" "default")
                                           "spec" (gr8s::core-object "hostNetwork" t "containers"
                                                                     (vector (gr8s::core-object "name" "c" "image" "busybox"
                                                                                                "ports" (vector port)))))))))
    (is (gr8s::pod-host-network-p (pod nil)))
    (is (equal '(("TCP" "" . 8080)) (gr8s::pod-host-ports (pod nil))))
    (is (equal '(("TCP" "" . 8080)) (gr8s::pod-host-ports (pod 8080))))
    (signals kubernetes-error (pod 9090))))

(test service-status-subresource-owns-status-and-collection-delete-matches-labels
  (with-core-api (store path)
    (values path)
    (check-core-status 201 "/api/v1/namespaces/alpha/services" :method :post
                       :object (network-service "lb" "type" "LoadBalancer"))
    ;; Status is ignored on the main resource and accepted on the subresource.
    (let ((plain (check-core-status 200 "/api/v1/namespaces/alpha/services/lb" :method :patch
                                    :content-type "application/merge-patch+json"
                                    :object (gr8s::core-object "status" (gr8s::core-object "loadBalancer" (gr8s::core-object "ingress" (vector (gr8s::core-object "ip" "203.0.113.1"))))))))
      (is (null (gethash "ingress" (gethash "loadBalancer" (gethash "status" plain))))))
    (let ((patched (check-core-status 200 "/api/v1/namespaces/alpha/services/lb/status" :method :patch
                                      :content-type "application/merge-patch+json"
                                      :object (gr8s::core-object
                                               "metadata" (gr8s::core-object "annotations" (gr8s::core-object "patchedstatus" "true"))
                                               "status" (gr8s::core-object "loadBalancer" (gr8s::core-object "ingress" (vector (gr8s::core-object "ip" "203.0.113.1"))))))))
      (is (equal "true" (gethash "patchedstatus" (gethash "annotations" (gethash "metadata" patched)))))
      (is (= 1 (length (gethash "ingress" (gethash "loadBalancer" (gethash "status" patched)))))))
    ;; The stored status survives a later spec write.
    (let ((relabelled (check-core-status 200 "/api/v1/namespaces/alpha/services/lb" :method :patch
                                         :content-type "application/strategic-merge-patch+json"
                                         :object (gr8s::core-object "metadata" (gr8s::core-object "labels" (gr8s::core-object "test-service" "patched"))))))
      (is (= 1 (length (gethash "ingress" (gethash "loadBalancer" (gethash "status" relabelled)))))))
    (check-core-status 200 "/api/v1/namespaces/alpha/services/lb/status")
    (dolist (spec '(("a" "delete") ("b" "delete") ("c" "keep")))
      (let ((input (network-service (first spec))))
        (setf (gethash "labels" (gethash "metadata" input)) (gr8s::core-object "e2e" (second spec)))
        (check-core-status 201 "/api/v1/namespaces/beta/services" :method :post :object input)))
    (check-core-status 200 "/api/v1/namespaces/beta/services" :method :delete :parameters '(("labelSelector" . "e2e=delete")))
    (is (equal '("c") (mapcar (lambda (object) (gethash "name" (gethash "metadata" object)))
                              (gr8s::list-core-resources store "services" "beta"))))))

(test endpoints-follow-selector-services-and-end-with-them
  (with-temporary-store (store directory)
    (values directory)
    (gr8s:register-node store (gr8s:make-node-record :id "worker-id" :name "worker-a" :pod-cidr "10.88.0.0/24"))
    (gr8s:mark-node-ready store "worker-a" (get-universal-time))
    (let ((input (network-service "web")))
      (setf (gethash "labels" (gethash "metadata" input)) (gr8s::core-object "tier" "front"))
      (gr8s::create-core-resource store "services" input "alpha"))
    (gr8s::reconcile-endpoints store)
    (let ((empty (gr8s::get-core-resource store "endpoints" "alpha" "web")))
      (is (equal "front" (gethash "tier" (gethash "labels" (gethash "metadata" empty)))))
      (is (zerop (length (gethash "subsets" empty)))))
    (create-endpointslice-test-pod store "one" "alpha" "192.0.2.1" :target 8080)
    (create-endpointslice-test-pod store "two" "alpha" "192.0.2.2" :target 8080 :ready nil)
    (gr8s::reconcile-endpoints store)
    (let* ((revision (gr8s::pod-store-resource-revision store))
           (endpoints (gr8s::get-core-resource store "endpoints" "alpha" "web")))
      (is (= 1 (length (gethash "subsets" endpoints))))
      (let ((subset (aref (gethash "subsets" endpoints) 0)))
        (is (equal "192.0.2.1" (gethash "ip" (aref (gethash "addresses" subset) 0))))
        (is (equal "192.0.2.2" (gethash "ip" (aref (gethash "notReadyAddresses" subset) 0))))
        (is (= 8080 (gethash "port" (aref (gethash "ports" subset) 0)))))
      (gr8s::reconcile-endpoints store)
      (is (= revision (gr8s::pod-store-resource-revision store))))
    (gr8s::delete-core-resource store "services" "alpha" "web")
    (signals kubernetes-error (gr8s::get-core-resource store "endpoints" "alpha" "web"))))

(test manual-endpoints-survive-and-mirror-only-behind-selectorless-services
  (with-temporary-store (store directory)
    (values directory)
    (flet ((endpoints (ip)
             (gr8s::core-object "metadata" (gr8s::core-object "name" "custom")
                                "subsets" (vector (gr8s::core-object "addresses" (vector (gr8s::core-object "ip" ip))
                                                                     "ports" (vector (gr8s::core-object "port" 80))))))
           (slices ()
             (gr8s::list-core-resources store "endpointslices" "alpha")))
      ;; No Service yet: the object stays and nothing mirrors it.
      (gr8s::create-core-resource store "endpoints" (endpoints "10.1.2.3") "alpha")
      (gr8s::reconcile-endpoints store)
      (is (null (slices)))
      (is (equal "TCP" (gethash "protocol" (aref (gethash "ports" (aref (gethash "subsets" (gr8s::get-core-resource store "endpoints" "alpha" "custom")) 0)) 0))))
      (gr8s::create-core-resource
       store "services" (gr8s::core-object "metadata" (gr8s::core-object "name" "custom")
                                           "spec" (gr8s::core-object "ports" (vector (gr8s::core-object "name" "example" "port" 80))))
       "alpha")
      (gr8s::reconcile-endpoints store)
      (is (= 1 (length (slices))))
      (let* ((slice (first (slices))) (metadata (gethash "metadata" slice)))
        (is (equal "custom" (gethash "kubernetes.io/service-name" (gethash "labels" metadata))))
        (is (equal "endpointslicemirroring-controller.k8s.io"
                   (gethash "endpointslice.kubernetes.io/managed-by" (gethash "labels" metadata))))
        (is (equal "10.1.2.3" (aref (gethash "addresses" (aref (gethash "endpoints" slice) 0)) 0)))
        (is (= 80 (gethash "port" (aref (gethash "ports" slice) 0)))))
      ;; An update changes the same slice in place.
      (let ((uid (gethash "uid" (gethash "metadata" (first (slices))))))
        (gr8s::update-core-resource store "endpoints" "alpha" "custom"
                                    (lambda (old) (declare (ignore old)) (endpoints "10.2.3.4")))
        (gr8s::reconcile-endpoints store)
        (is (= 1 (length (slices))))
        (is (equal uid (gethash "uid" (gethash "metadata" (first (slices))))))
        (is (equal "10.2.3.4" (aref (gethash "addresses" (aref (gethash "endpoints" (first (slices))) 0)) 0))))
      ;; Deleting the Service keeps a manual Endpoints object but ends the mirror.
      (gr8s::delete-core-resource store "services" "alpha" "custom")
      (is (gr8s::get-core-resource store "endpoints" "alpha" "custom"))
      (gr8s::reconcile-endpoints store)
      (is (null (slices))))))

(test api-service-publishes-endpoints-and-a-matching-slice
  (with-temporary-store (store directory)
    (values directory)
    (gr8s::ensure-native-api-service store)
    (gr8s::ensure-native-api-service store)
    (let ((endpoints (gr8s::get-core-resource store "endpoints" "default" "kubernetes"))
          (slice (gr8s::get-core-resource store "endpointslices" "default" "kubernetes"))
          (cidr (gr8s::get-core-resource store "servicecidrs" nil "kubernetes")))
      (is (equal "10.96.0.1" (gethash "ip" (aref (gethash "addresses" (aref (gethash "subsets" endpoints) 0)) 0))))
      (is (equal "10.96.0.1" (aref (gethash "addresses" (aref (gethash "endpoints" slice) 0)) 0)))
      (is (equal "True" (gethash "status" (aref (gethash "conditions" (gethash "status" cidr)) 0))))
      ;; The server writes that slice itself, so the mirror leaves it alone.
      (gr8s::reconcile-endpoints store)
      (is (= 1 (length (gr8s::list-core-resources store "endpointslices" "default")))))))

(test networking-api-serves-ingress-classes-cidrs-and-addresses
  (with-core-api (store path)
    (values store path)
    (let ((group (check-core-status 200 "/apis/networking.k8s.io/v1")))
      (dolist (name '("ingresses" "ingressclasses" "servicecidrs" "ipaddresses" "ingresses/status" "servicecidrs/status"))
        (is (find name (gethash "resources" group) :test #'equal :key (lambda (o) (gethash "name" o))))))
    (check-core-status 200 "/apis/networking.k8s.io")
    (let* ((ingress (check-core-status 201 "/apis/networking.k8s.io/v1/namespaces/alpha/ingresses" :method :post
                                       :object (gr8s::core-object
                                                "metadata" (gr8s::core-object "name" "web")
                                                "spec" (gr8s::core-object "defaultBackend" (gr8s::core-object "service" (gr8s::core-object "name" "default-backend" "port" (gr8s::core-object "number" 8080)))))))
           (status (check-core-status 200 "/apis/networking.k8s.io/v1/namespaces/alpha/ingresses/web/status" :method :patch
                                      :content-type "application/merge-patch+json"
                                      :object (gr8s::core-object "status" (gr8s::core-object "loadBalancer" (gr8s::core-object "ingress" (vector (gr8s::core-object "ip" "169.1.1.1"))))))))
      (is (= 1 (gethash "generation" (gethash "metadata" ingress))))
      (is (= 1 (length (gethash "ingress" (gethash "loadBalancer" (gethash "status" status)))))))
    (check-core-status 422 "/apis/networking.k8s.io/v1/namespaces/alpha/ingresses" :method :post
                       :object (gr8s::core-object "metadata" (gr8s::core-object "name" "empty") "spec" (gr8s::core-object)))
    (check-core-status 201 "/apis/networking.k8s.io/v1/ingressclasses" :method :post
                       :object (gr8s::core-object "metadata" (gr8s::core-object "name" "generic")
                                                  "spec" (gr8s::core-object "controller" "example.com/controller")))
    (check-core-status 422 "/apis/networking.k8s.io/v1/ingressclasses" :method :post
                       :object (gr8s::core-object "metadata" (gr8s::core-object "name" "bad") "spec" (gr8s::core-object)))
    (let ((cidr (check-core-status 201 "/apis/networking.k8s.io/v1/servicecidrs" :method :post
                                   :object (gr8s::core-object "metadata" (gr8s::core-object "name" "extra")
                                                              "spec" (gr8s::core-object "cidrs" (vector "203.0.113.0/24"))))))
      ;; Nothing allocates from another range, so the object says so rather than claiming Ready.
      (is (equal "False" (gethash "status" (aref (gethash "conditions" (gethash "status" cidr)) 0)))))
    (check-core-status 422 "/apis/networking.k8s.io/v1/servicecidrs" :method :post
                       :object (gr8s::core-object "metadata" (gr8s::core-object "name" "hostbits")
                                                  "spec" (gr8s::core-object "cidrs" (vector "203.0.113.1/24"))))
    (let ((parent (gr8s::core-object "group" "mygroup" "resource" "myresources" "namespace" "foo" "name" "bar")))
      (dolist (name '("255.255.255.255" "fe80::42:1dff:fe84:f9e2"))
        (check-core-status 201 "/apis/networking.k8s.io/v1/ipaddresses" :method :post
                           :object (gr8s::core-object "metadata" (gr8s::core-object "name" name)
                                                      "spec" (gr8s::core-object "parentRef" parent))))
      (check-core-status 200 "/apis/networking.k8s.io/v1/ipaddresses/fe80::42:1dff:fe84:f9e2")
      (check-core-status 422 "/apis/networking.k8s.io/v1/ipaddresses" :method :post
                         :object (gr8s::core-object "metadata" (gr8s::core-object "name" "not-an-ip")
                                                    "spec" (gr8s::core-object "parentRef" parent))))))

(test proxy-urls-resolve-to-their-parts
  (is (equal '("alpha" "web" t)
             (multiple-value-list (gr8s::service-http-proxy-route "/api/v1/namespaces/alpha/services/web/proxy"))))
  (is (equal "http:web:portname" (nth-value 1 (gr8s::service-http-proxy-route "/api/v1/namespaces/alpha/services/http:web:portname/proxy/a/b"))))
  (is (null (gr8s::service-http-proxy-route "/api/v1/namespaces/alpha/services/web/proxying")))
  (is (equal '("gr8s-local" "10250" "/pods" t)
             (multiple-value-list (gr8s::node-http-proxy-route "/api/v1/nodes/gr8s-local:10250/proxy/pods"))))
  (is (equal '("gr8s-local" nil "/" t)
             (multiple-value-list (gr8s::node-http-proxy-route "/api/v1/nodes/gr8s-local/proxy"))))
  (is (null (gr8s::node-http-proxy-route "/api/v1/nodes/gr8s-local"))))

(test service-proxy-target-picks-a-ready-endpoint-of-the-named-port
  (with-temporary-store (store directory)
    (values directory)
    (gr8s::create-core-resource
     store "services" (gr8s::core-object "metadata" (gr8s::core-object "name" "web")
                                         "spec" (gr8s::core-object "ports" (vector (gr8s::core-object "name" "a" "port" 80)
                                                                                   (gr8s::core-object "name" "tls" "port" 443))))
     "alpha")
    (gr8s::create-core-resource
     store "endpointslices"
     (gr8s::core-object "metadata" (gr8s::core-object "name" "web-1" "labels" (gr8s::core-object "kubernetes.io/service-name" "web"))
                        "addressType" "IPv4"
                        "endpoints" (vector (gr8s::core-object "addresses" (vector "192.0.2.9")))
                        "ports" (vector (gr8s::core-object "name" "a" "port" 8080 "protocol" "TCP")
                                        (gr8s::core-object "name" "tls" "port" 8443 "protocol" "TCP")))
     "alpha")
    (is (equal "http://192.0.2.9:8080" (gr8s::service-proxy-target store "alpha" "web:a")))
    (is (equal "http://192.0.2.9:8080" (gr8s::service-proxy-target store "alpha" "web:80")))
    (is (equal "https://192.0.2.9:8443" (gr8s::service-proxy-target store "alpha" "https:web:tls")))
    (signals kubernetes-error (gr8s::service-proxy-target store "alpha" "web:missing"))
    (signals kubernetes-error (gr8s::service-proxy-target store "alpha" "ftp:web:a"))))

(test proxied-html-keeps-rooted-links-inside-the-proxy
  (let ((prefix "/api/v1/namespaces/n/pods/p/proxy") (target "http://10.88.0.5:80") (frontend "https://api:6443"))
    (flet ((rewrite (html) (gr8s::proxy-rewrite-html html target prefix frontend)))
      (is (equal "<a href=\"/api/v1/namespaces/n/pods/p/proxy/rewriteme\">test</a>" (rewrite "<a href=\"/rewriteme\">test</a>")))
      ;; Relative and foreign links stay, as do links already inside and other attributes.
      (is (equal "<a href=\"rewriteme\">x</a>" (rewrite "<a href=\"rewriteme\">x</a>")))
      (is (equal "<a href=\"http://example.com/x\">x</a>" (rewrite "<a href=\"http://example.com/x\">x</a>")))
      (is (equal "<a href=\"/api/v1/namespaces/n/pods/p/proxy/x\">x</a>" (rewrite "<a href=\"/api/v1/namespaces/n/pods/p/proxy/x\">x</a>")))
      (is (equal "<div title=\"/x\">/x</div>" (rewrite "<div title=\"/x\">/x</div>")))
      (is (equal "<img class='i' src='/api/v1/namespaces/n/pods/p/proxy/i.png'>" (rewrite "<img class='i' src='/i.png'>"))))))

(test node-port-chooser-holds-a-client-only-with-affinity
  (let* ((backends '(("10.0.0.1" . 80) ("10.0.0.2" . 80) ("10.0.0.3" . 80)))
         (held (gr8s::make-node-port-target backends 60))
         (free (gr8s::make-node-port-target backends nil))
         (client #(10 88 0 9))
         (first-choice (funcall held client)))
    (is (member first-choice backends :test #'equal))
    (is (every (lambda (choice) (equal choice first-choice))
               (loop repeat 40 collect (funcall held client))))
    (is (< 1 (length (remove-duplicates (loop repeat 200 collect (funcall free client)) :test #'equal))))))

(defun loopback-udp-echo (replies)
  "Start a one-datagram-at-a-time UDP server on loopback; return its socket and thread."
  (let ((socket (make-instance 'sb-bsd-sockets:inet-socket :type :datagram :protocol :udp)))
    (sb-bsd-sockets:socket-bind socket #(127 0 0 1) 0)
    (values socket
            (bt:make-thread
             (lambda ()
               (let ((buffer (make-array 2048 :element-type '(unsigned-byte 8))))
                 (loop repeat replies
                       do (multiple-value-bind (data length address port) (sb-bsd-sockets:socket-receive socket buffer nil)
                            (declare (ignore data))
                            (sb-bsd-sockets:socket-send socket buffer length :address (list address port))))))))))

(test udp-port-forwarder-relays-datagrams-both-ways
  (multiple-value-bind (server thread) (loopback-udp-echo 1)
    (let* ((backend (nth-value 1 (sb-bsd-sockets:socket-name server)))
           (port (+ 40000 (random 10000)))
           (forwarder (gr8s::start-host-port-forwarder "127.0.0.1" port (cons "127.0.0.1" backend) "UDP"))
           (client (make-instance 'sb-bsd-sockets:inet-socket :type :datagram :protocol :udp))
           (buffer (make-array 16 :element-type '(unsigned-byte 8))))
      (unwind-protect
           (progn
             (sb-bsd-sockets:socket-connect client #(127 0 0 1) port)
             (sb-bsd-sockets:socket-send client (coerce #(1 2 3) '(vector (unsigned-byte 8))) 3)
             (is (sb-sys:wait-until-fd-usable (sb-bsd-sockets:socket-file-descriptor client) :input 5))
             (multiple-value-bind (data length) (sb-bsd-sockets:socket-receive client buffer nil)
               (declare (ignore data))
               (is (= 3 length))
               (is (equalp #(1 2 3) (subseq buffer 0 3)))))
        (ignore-errors (sb-bsd-sockets:socket-close client))
        (gr8s::stop-host-port-forwarder forwarder)
        (ignore-errors (bt:join-thread thread :timeout 1))
        (ignore-errors (sb-bsd-sockets:socket-close server))))))

(test host-port-targets-distinguish-protocol-and-address
  (with-temporary-store (store directory)
    (values directory)
    (let ((forwarders (make-hash-table :test #'equal))
          (targets (make-hash-table :test #'equal))
          (port (+ 40000 (random 10000))))
      (setf (gethash (list* "TCP" "127.0.0.1" port) targets) (cons "127.0.0.1" 1)
            (gethash (list* "UDP" "127.0.0.1" port) targets) (cons "127.0.0.1" 1))
      (unwind-protect
           (progn
             (gr8s::converge-port-forwarders forwarders targets)
             (is (= 2 (hash-table-count forwarders)))
             (is (equal "UDP" (gr8s::host-port-forwarder-protocol (gethash (list* "UDP" "127.0.0.1" port) forwarders))))
             (remhash (list* "TCP" "127.0.0.1" port) targets)
             (gr8s::converge-port-forwarders forwarders targets)
             (is (= 1 (hash-table-count forwarders))))
        (gr8s::stop-host-port-forwarders forwarders)))))

(test service-lb-program-compiles-with-affinity
  (multiple-value-bind (maps programs) (gr8s::compile-service-lb)
    (is (= 3 (length maps)))
    (is (= 1 (length programs)))))
