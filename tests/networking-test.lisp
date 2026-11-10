;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
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
    (gr8s::ensure-native-api-service store "192.0.2.10" 6443)
    (gr8s::ensure-native-api-service store "192.0.2.10" 6443)
    (let ((endpoints (gr8s::get-core-resource store "endpoints" "default" "kubernetes"))
          (slice (gr8s::get-core-resource store "endpointslices" "default" "kubernetes"))
          (cidr (gr8s::get-core-resource store "servicecidrs" nil "kubernetes")))
      (is (equal "192.0.2.10" (gethash "ip" (aref (gethash "addresses" (aref (gethash "subsets" endpoints) 0)) 0))))
      (is (equal "192.0.2.10" (aref (gethash "addresses" (aref (gethash "endpoints" slice) 0)) 0)))
      (is (= 6443 (gethash "port" (aref (gethash "ports" (aref (gethash "subsets" endpoints) 0)) 0))))
      (is (= 6443 (gethash "port" (aref (gethash "ports" slice) 0))))
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
      ;; ClusterIPs are allocated from every IPv4 range, so another one is Ready too.
      (is (equal "True" (gethash "status" (aref (gethash "conditions" (gethash "status" cidr)) 0)))))
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

(test pod-stays-pending-until-every-container-has-started
  (flet ((status (state &optional last-state)
           (let ((status (gr8s::core-object "state" state)))
             (when last-state (setf (gethash "lastState" status) last-state))
             status)))
    (let ((running (status (gr8s::core-object "running" (gr8s::core-object))))
          (creating (status (gr8s::core-object "waiting" (gr8s::core-object "reason" "ContainerCreating"))))
          (restarting (status (gr8s::core-object "waiting" (gr8s::core-object "reason" "CrashLoopBackOff"))
                              (gr8s::core-object "terminated" (gr8s::core-object "exitCode" 1)))))
      (is (equal "Pending" (gr8s::container-lifecycle-phase (list running creating) t)))
      (is (equal "Running" (gr8s::container-lifecycle-phase (list running running) t)))
      ;; A container that has run before and is waiting to restart does not take the Pod back to Pending.
      (is (equal "Running" (gr8s::container-lifecycle-phase (list running restarting) t))))))

(test pod-with-an-unreported-container-is-pending
  ;; The runtime reports only the containers it has created so far.
  (let* ((object (com.inuoe.jzon:parse *valid-pod-json*))
         (spec (gethash "spec" object))
         (first-container (aref (gethash "containers" spec) 0))
         (second-container (gr8s::copy-core-object first-container)))
    (setf (gethash "name" second-container) "later"
          (gethash "ports" second-container) #()
          (gethash "containers" spec) (vector first-container second-container)
          (gethash "nodeName" spec) "worker-a")
    (let* ((pod (parse-pod object))
           (status (gr8s::core-object "phase" "Running"
                                      "containerStatuses"
                                      (vector (gr8s::core-object "name" (gethash "name" first-container)
                                                                 "state" (gr8s::core-object "running" (gr8s::core-object))))))
           (result (gr8s::add-declared-container-statuses pod status)))
      (is (equal "Pending" (gethash "phase" result)))
      (is (= 2 (length (gethash "containerStatuses" result))))
      (is (gr8s::container-status-never-started-p (aref (gethash "containerStatuses" result) 1))))))

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

(defun kernel-assigned-port (&rest protocols)
  "Return a loopback port the kernel assigned that is free for each of PROTOCOLS (:tcp, :udp).
A fixed or random port in the ephemeral range can already be taken on a shared host
(podster-uqb.199), so each test that needs one port for both protocols asks for it here."
  (loop repeat 100
        do (let ((sockets nil))
             (unwind-protect
                  (handler-case
                      (let ((port 0))
                        (dolist (protocol protocols (return-from kernel-assigned-port port))
                          (let ((socket (make-instance 'sb-bsd-sockets:inet-socket
                                                       :type (if (eq protocol :udp) :datagram :stream)
                                                       :protocol protocol)))
                            (push socket sockets)
                            (sb-bsd-sockets:socket-bind socket #(127 0 0 1) port)
                            (setf port (nth-value 1 (sb-bsd-sockets:socket-name socket))))))
                    (sb-bsd-sockets:socket-error () nil))
               (mapc (lambda (socket) (ignore-errors (sb-bsd-sockets:socket-close socket))) sockets)))
        finally (error "no loopback port was free for ~{~A~^ and ~}" protocols)))

(test udp-port-forwarder-relays-datagrams-both-ways
  (multiple-value-bind (server thread) (loopback-udp-echo 1)
    (let* ((backend (nth-value 1 (sb-bsd-sockets:socket-name server)))
           (port (kernel-assigned-port :udp))
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
          (port (kernel-assigned-port :tcp :udp)))
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
  ;; Service, backend, membership/affinity index, affinity and UDP reverse maps
  ;; and connect/sendmsg/recvmsg hooks for both address families.
  (multiple-value-bind (maps programs) (gr8s::compile-service-lb)
    (is (= 10 (length maps)))
    (is (= 6 (length programs)))))

;;; Traffic policies, external IPs and health check node ports

(defun update-service-spec (store name function)
  "Read Service NAME back from STORE and send it again after FUNCTION changes its spec, as a client does."
  (gr8s::update-core-resource store "services" "alpha" name
                              (lambda (object) (funcall function (gethash "spec" object)) object)))

(test local-traffic-policies-are-accepted-and-default-to-cluster
  (with-temporary-store (store directory)
    (values directory)
    (let ((plain (gr8s::create-core-resource store "services" (network-service "plain") "alpha"))
          (local (gr8s::create-core-resource store "services"
                                             (network-service "local" "internalTrafficPolicy" "Local") "alpha"))
          (node-port (gr8s::create-core-resource store "services"
                                                 (network-service "edge" "type" "NodePort" "externalTrafficPolicy" "Local")
                                                 "alpha")))
      (is (equal "Cluster" (gethash "internalTrafficPolicy" (gethash "spec" plain))))
      (is (null (gethash "externalTrafficPolicy" (gethash "spec" plain))))
      (is (equal "Local" (gethash "internalTrafficPolicy" (gethash "spec" local))))
      (is (equal "Local" (gethash "externalTrafficPolicy" (gethash "spec" node-port))))
      ;; A NodePort Service needs no health check.
      (is (null (gethash "healthCheckNodePort" (gethash "spec" node-port)))))
    (signals kubernetes-error
      (gr8s::create-core-resource store "services" (network-service "odd" "internalTrafficPolicy" "Nearby") "alpha"))
    (signals kubernetes-error
      (gr8s::create-core-resource store "services"
                                  (network-service "odd" "type" "NodePort" "externalTrafficPolicy" "Nearby") "alpha"))
    ;; Only an externally accessible Service takes an external policy.
    (signals kubernetes-error
      (gr8s::create-core-resource store "services" (network-service "odd" "externalTrafficPolicy" "Local") "alpha"))
    ;; Going back to ClusterIP with the policy unchanged drops it, as upstream does.
    (let ((back (update-service-spec store "edge" (lambda (spec) (setf (gethash "type" spec) "ClusterIP")))))
      (is (null (gethash "externalTrafficPolicy" (gethash "spec" back))))
      (is (null (service-node-port back))))))

(test local-load-balancers-hold-a-health-check-node-port-only-while-local
  (with-temporary-store (store directory)
    (values directory)
    (let* ((created (gr8s::create-core-resource
                     store "services" (network-service "lb" "type" "LoadBalancer" "externalTrafficPolicy" "Local") "alpha"))
           (health (gethash "healthCheckNodePort" (gethash "spec" created))))
      (is (<= gr8s::+node-port-minimum+ health gr8s::+node-port-maximum+))
      (is (/= health (service-node-port created)))
      ;; No other Service may take it as a node port.
      (let ((thief (network-service "thief" "type" "NodePort")))
        (setf (gethash "nodePort" (aref (gethash "ports" (gethash "spec" thief)) 0)) health)
        (signals kubernetes-error (gr8s::create-core-resource store "services" thief "alpha")))
      ;; An update that omits it keeps it; changing it is refused.
      (is (= health (gethash "healthCheckNodePort"
                             (gethash "spec" (update-service-spec store "lb" (lambda (spec) (remhash "healthCheckNodePort" spec)))))))
      (signals kubernetes-error
        (update-service-spec store "lb" (lambda (spec) (setf (gethash "healthCheckNodePort" spec) (1+ health)))))
      ;; Cluster releases it, and Local may then ask for the same one back.
      (let ((cluster (update-service-spec store "lb" (lambda (spec) (setf (gethash "externalTrafficPolicy" spec) "Cluster")))))
        (is (null (gethash "healthCheckNodePort" (gethash "spec" cluster)))))
      (let ((again (update-service-spec store "lb" (lambda (spec)
                                                     (setf (gethash "externalTrafficPolicy" spec) "Local"
                                                           (gethash "healthCheckNodePort" spec) health)))))
        (is (= health (gethash "healthCheckNodePort" (gethash "spec" again))))))
    ;; Asking for one outside the range, or on a Service that can't use it, is refused.
    (signals kubernetes-error
      (gr8s::create-core-resource
       store "services" (network-service "low" "type" "LoadBalancer" "externalTrafficPolicy" "Local" "healthCheckNodePort" 80)
       "alpha"))
    (signals kubernetes-error
      (gr8s::create-core-resource
       store "services" (network-service "np" "type" "NodePort" "healthCheckNodePort" 31999) "alpha"))))

(test external-ips-source-ranges-and-traffic-distribution-are-validated
  (with-temporary-store (store directory)
    (values directory)
    (let ((external (gr8s::create-core-resource
                     store "services" (network-service "ext" "externalIPs" #("203.0.113.250") "trafficDistribution" "PreferClose")
                     "alpha")))
      (is (equalp #("203.0.113.250") (gethash "externalIPs" (gethash "spec" external))))
      ;; External IPs make a ClusterIP Service externally accessible.
      (is (equal "Cluster" (gethash "externalTrafficPolicy" (gethash "spec" external))))
      (is (equal "PreferClose" (gethash "trafficDistribution" (gethash "spec" external)))))
    (dolist (address '("127.0.0.1" "0.0.0.0" "169.254.1.1" "224.0.0.5" "010.1.1.1" "not-an-ip"))
      (signals kubernetes-error
        (gr8s::create-core-resource store "services" (network-service "bad" "externalIPs" (vector address)) "alpha")))
    (let ((balancer (gr8s::create-core-resource
                     store "services" (network-service "lb" "type" "LoadBalancer"
                                                       "loadBalancerSourceRanges" #("192.0.2.0/24" " 198.51.100.7/32")
                                                       "loadBalancerIP" "192.0.2.10")
                     "alpha")))
      (is (= 2 (length (gethash "loadBalancerSourceRanges" (gethash "spec" balancer)))))
      (is (equal "192.0.2.10" (gethash "loadBalancerIP" (gethash "spec" balancer)))))
    (signals kubernetes-error
      (gr8s::create-core-resource store "services" (network-service "ranged" "loadBalancerSourceRanges" #("192.0.2.0/24")) "alpha"))
    (signals kubernetes-error
      (gr8s::create-core-resource store "services" (network-service "lb2" "type" "LoadBalancer"
                                                                    "loadBalancerSourceRanges" #("192.0.2.0/33"))
                                  "alpha"))
    (signals kubernetes-error
      (gr8s::create-core-resource store "services" (network-service "far" "trafficDistribution" "PreferFar") "alpha"))))

(test node-port-chooser-sends-node-local-clients-to-every-endpoint
  ;; externalTrafficPolicy Local spreads outside clients over this node's endpoints only, but a
  ;; client on the node itself still reaches every endpoint, as kube-proxy short-circuits it.
  (let* ((local '(("10.0.0.1" . 80)))
         (all '(("10.0.0.1" . 80) ("10.0.1.1" . 80)))
         (chooser (gr8s::make-node-port-target local nil :local-origin all :local-addresses '("10.0.0.7"))))
    (is (every (lambda (choice) (equal choice '("10.0.0.1" . 80)))
               (loop repeat 50 collect (funcall chooser #(198 51 100 4)))))
    (is (= 2 (length (remove-duplicates (loop repeat 200 collect (funcall chooser #(10 0 0 7))) :test #'equal))))
    (is (= 2 (length (remove-duplicates (loop repeat 200 collect (funcall chooser #(127 0 0 1))) :test #'equal)))))
  ;; Only a Local policy keeps the client's address, and only for a client elsewhere.
  (let ((keeping (gr8s::make-node-port-target '(("10.0.0.1" . 80)) nil :local-origin '(("10.0.0.1" . 80))
                                              :keep-source t))
        (cluster (gr8s::make-node-port-target '(("10.0.0.1" . 80)) nil :local-origin '(("10.0.0.1" . 80)))))
    (is (eq t (nth-value 1 (funcall keeping #(198 51 100 4)))))
    (is (null (nth-value 1 (funcall keeping #(127 0 0 1)))))
    (is (null (nth-value 1 (funcall cluster #(198 51 100 4))))))
  ;; With no local endpoint an outside client is not relayed at all.
  (let ((chooser (gr8s::make-node-port-target nil nil :local-origin '(("10.0.1.1" . 80)))))
    (is (null (funcall chooser #(198 51 100 4))))
    (is (equal '("10.0.1.1" . 80) (funcall chooser #(127 0 0 1))))))

(defun http-get-status-line (port)
  "Send a GET to 127.0.0.1:PORT and return the response's first line and its body."
  (let ((socket (make-instance 'sb-bsd-sockets:inet-socket :type :stream :protocol :tcp)))
    (unwind-protect
         (progn
           (sb-bsd-sockets:socket-connect socket #(127 0 0 1) port)
           (let ((request (trivial-utf-8:string-to-utf-8-bytes
                           (format nil "GET /healthz HTTP/1.1~C~CHost: x~C~C~C~C" #\Return #\Newline #\Return #\Newline #\Return #\Newline))))
             (sb-bsd-sockets:socket-send socket request (length request)))
           (let ((buffer (make-array 4096 :element-type '(unsigned-byte 8))) (seen 0))
             (loop (multiple-value-bind (data length) (sb-bsd-sockets:socket-receive socket buffer (- 4096 seen))
                     (declare (ignore data))
                     (if (and length (plusp length)) (incf seen length) (return))))
             (let* ((text (trivial-utf-8:utf-8-bytes-to-string (subseq buffer 0 seen)))
                    (break (search (format nil "~C~C~C~C" #\Return #\Newline #\Return #\Newline) text)))
               (values (subseq text 0 (position #\Return text)) (subseq text (+ break 4))))))
      (ignore-errors (sb-bsd-sockets:socket-close socket)))))

(test health-check-node-port-reports-local-ready-endpoints
  (let ((server (gr8s::start-health-check-server 0)))
    (unwind-protect
         (let ((port (nth-value 1 (sb-bsd-sockets:socket-name (gr8s::health-check-server-listener server)))))
           (setf (gr8s::health-check-server-namespace server) "alpha"
                 (gr8s::health-check-server-name server) "lb")
           (multiple-value-bind (status body) (http-get-status-line port)
             (is (equal "HTTP/1.1 503 Service Unavailable" status))
             (let ((json (com.inuoe.jzon:parse body)))
               (is (= 0 (gethash "localEndpoints" json)))
               (is (equal "lb" (gethash "name" (gethash "service" json))))))
           (setf (gr8s::health-check-server-count server) 2)
           (multiple-value-bind (status body) (http-get-status-line port)
             (is (equal "HTTP/1.1 200 OK" status))
             (is (= 2 (gethash "localEndpoints" (com.inuoe.jzon:parse body))))))
      (gr8s::stop-health-check-server server))))

;;; ClusterIPs from every ServiceCIDR, each claimed by an IPAddress

(defun service-ip-claim (store address)
  (gr8s::get-core-resource store "ipaddresses" nil address))

(test cluster-ips-come-from-every-service-cidr-and-are-claimed
  (with-temporary-store (store directory)
    (values directory)
    (gr8s::ensure-default-service-cidr store)
    (gr8s::create-core-resource store "servicecidrs"
                                (gr8s::core-object "metadata" (gr8s::core-object "name" "extra")
                                                   "spec" (gr8s::core-object "cidrs" (vector "203.0.113.0/24")))
                                nil)
    ;; A dynamic address comes from the default range, and its IPAddress names the Service.
    (let* ((plain (gr8s::create-core-resource store "services" (network-service "plain") "alpha"))
           (address (gethash "clusterIP" (gethash "spec" plain)))
           (claim (service-ip-claim store address)))
      (is (gr8s::service-ip-index address))
      (is (equal "ipallocator.k8s.io"
                 (gethash "ipaddress.kubernetes.io/managed-by" (gethash "labels" (gethash "metadata" claim)))))
      (is (equal '("alpha" "plain") (gr8s::ip-address-parent-service claim))))
    ;; An address in the other range is accepted and claimed; one in no range is refused.
    (let ((extra (gr8s::create-core-resource store "services" (network-service "extra" "clusterIP" "203.0.113.10") "alpha")))
      (is (equal "203.0.113.10" (gethash "clusterIP" (gethash "spec" extra))))
      (is (service-ip-claim store "203.0.113.10")))
    (signals kubernetes-error
      (gr8s::create-core-resource store "services" (network-service "outside" "clusterIP" "198.51.100.10") "alpha"))
    ;; Nor are a range's network and broadcast addresses, or an address another IPAddress holds.
    (signals kubernetes-error
      (gr8s::create-core-resource store "services" (network-service "edge" "clusterIP" "203.0.113.255") "alpha"))
    (gr8s::create-core-resource store "ipaddresses"
                                (gr8s::core-object "metadata" (gr8s::core-object "name" "203.0.113.11")
                                                   "spec" (gr8s::core-object "parentRef"
                                                                             (gr8s::core-object "group" "example.com" "resource" "things"
                                                                                                "name" "held")))
                                nil)
    (signals kubernetes-error
      (gr8s::create-core-resource store "services" (network-service "taken" "clusterIP" "203.0.113.11") "alpha"))
    ;; A Service that goes away leaves a stale claim: an allocation may take the address over,
    ;; and the repair pass removes it.
    (gr8s::delete-core-resource store "services" "alpha" "extra")
    (is (service-ip-claim store "203.0.113.10"))
    (gr8s::create-core-resource store "services" (network-service "again" "clusterIP" "203.0.113.10") "beta")
    (is (equal '("beta" "again") (gr8s::ip-address-parent-service (service-ip-claim store "203.0.113.10"))))
    (gr8s::delete-core-resource store "services" "beta" "again")
    (gr8s::reconcile-service-ip-addresses store)
    (signals kubernetes-error (service-ip-claim store "203.0.113.10"))
    ;; The user's own IPAddress is never touched.
    (is (service-ip-claim store "203.0.113.11"))))

(test service-ip-repair-claims-addresses-of-older-services
  (with-temporary-store (store directory)
    (values directory)
    (let ((address (gethash "clusterIP" (gethash "spec" (gr8s::create-core-resource
                                                          store "services" (network-service "old") "alpha")))))
      ;; As if the Service predated IPAddress objects.
      (gr8s::delete-core-resource store "ipaddresses" nil address)
      (gr8s::reconcile-service-ip-addresses store)
      (is (equal '("alpha" "old") (gr8s::ip-address-parent-service (service-ip-claim store address)))))))

(defun sctp-available-p ()
  "True when this kernel can open an SCTP socket."
  (handler-case
      (progn (sb-bsd-sockets:socket-close (make-instance 'sb-bsd-sockets:inet-socket :type :stream :protocol :sctp)) t)
    (error () nil)))

(test sctp-port-forwarder-relays-an-association
  ;; SCTP host ports and node ports are relayed like TCP ones, as one-to-one associations.
  (if (not (sctp-available-p))
      (skip "this kernel has no SCTP")
      (let ((server (make-instance 'sb-bsd-sockets:inet-socket :type :stream :protocol :sctp)))
        (sb-bsd-sockets:socket-bind server #(127 0 0 1) 0)
        (sb-bsd-sockets:socket-listen server 4)
        (let* ((backend (nth-value 1 (sb-bsd-sockets:socket-name server)))
               (echo (bt:make-thread
                      (lambda ()
                        (let ((peer (sb-bsd-sockets:socket-accept server))
                              (buffer (make-array 64 :element-type '(unsigned-byte 8))))
                          (unwind-protect
                               (multiple-value-bind (data length) (sb-bsd-sockets:socket-receive peer buffer nil)
                                 (declare (ignore data))
                                 (sb-bsd-sockets:socket-send peer buffer length))
                            (sb-bsd-sockets:socket-close peer))))))
               (forwarder (gr8s::start-host-port-forwarder "127.0.0.1" 0 (cons "127.0.0.1" backend) "SCTP"))
               (port (nth-value 1 (sb-bsd-sockets:socket-name (gr8s::host-port-forwarder-listener forwarder))))
               (client (make-instance 'sb-bsd-sockets:inet-socket :type :stream :protocol :sctp))
               (buffer (make-array 16 :element-type '(unsigned-byte 8))))
          (unwind-protect
               (progn
                 (sb-bsd-sockets:socket-connect client #(127 0 0 1) port)
                 (sb-bsd-sockets:socket-send client (coerce #(4 5 6) '(vector (unsigned-byte 8))) 3)
                 (is (sb-sys:wait-until-fd-usable (sb-bsd-sockets:socket-file-descriptor client) :input 5))
                 (multiple-value-bind (data length) (sb-bsd-sockets:socket-receive client buffer nil)
                   (declare (ignore data))
                   (is (eql 3 length))
                   (is (equalp #(4 5 6) (subseq buffer 0 3)))))
            (ignore-errors (sb-bsd-sockets:socket-close client))
            (gr8s::stop-host-port-forwarder forwarder)
            (ignore-errors (bt:join-thread echo :timeout 2))
            (ignore-errors (sb-bsd-sockets:socket-close server)))))))

(test sctp-node-ports-and-host-ports-are-planned
  (with-temporary-store (store directory)
    (values directory)
    (let ((service (network-service "sctp" "type" "NodePort")))
      (setf (gethash "protocol" (aref (gethash "ports" (gethash "spec" service)) 0)) "SCTP")
      (let* ((created (gr8s::create-core-resource store "services" service "alpha"))
             (node-port (service-node-port created)))
        (gr8s::create-core-resource
         store "endpointslices"
         (gr8s::core-object "metadata" (gr8s::core-object "name" "sctp-manual"
                                                          "labels" (gr8s::core-object "kubernetes.io/service-name" "sctp"))
                            "addressType" "IPv4"
                            "ports" (vector (gr8s::core-object "name" "http" "port" 8080 "protocol" "SCTP"))
                            "endpoints" (vector (gr8s::core-object "addresses" (vector "192.0.2.5")
                                                                   "conditions" (gr8s::core-object "ready" t))))
         "alpha")
        (let ((plan (gethash (list* "SCTP" "" node-port) (gr8s::desired-node-port-targets store))))
          (is (equal '(("192.0.2.5" . 8080)) (first plan))))))))

(test load-balancer-service-ports-are-planned-on-the-node-address
  (with-temporary-store (store directory)
    (declare (ignore directory))
    (let* ((service (gr8s::create-core-resource
                     store "services" (network-service "lb" "type" "LoadBalancer") "alpha"))
           (port (aref (gethash "ports" (gethash "spec" service)) 0))
           (node-port (gethash "nodePort" port)))
      (gr8s::create-core-resource
       store "endpointslices"
       (gr8s::core-object "metadata" (gr8s::core-object "name" "lb-manual"
                                                       "labels" (gr8s::core-object "kubernetes.io/service-name" "lb"))
                          "addressType" "IPv4"
                          "ports" (vector (gr8s::core-object "name" "http" "port" 8080 "protocol" "TCP"))
                          "endpoints" (vector (gr8s::core-object "addresses" (vector "192.0.2.5")
                                                                 "conditions" (gr8s::core-object "ready" t))))
       "alpha")
      (let* ((plans (gr8s::desired-node-port-targets store :node-address "192.0.2.10"))
             (node-port-plan (gethash (list* "TCP" "" node-port) plans))
             (load-balancer-plan (gethash (list* "TCP" "192.0.2.10" 80) plans)))
        (is (equal node-port-plan load-balancer-plan))
        (is (equal '(("192.0.2.5" . 8080)) (first load-balancer-plan)))))))

(test colliding-load-balancers-route-the-service-port-to-the-deterministic-owner
  (with-temporary-store (store directory)
    (declare (ignore directory))
    ;; Create in reverse order to prove ownership does not depend on hash or
    ;; insertion order. Both NodePorts remain independently usable.
    (dolist (name '("beta" "alpha"))
      (gr8s::create-core-resource
       store "services" (network-service name "type" "LoadBalancer") "alpha")
      (gr8s::create-core-resource
       store "endpointslices"
       (gr8s::core-object
        "metadata" (gr8s::core-object "name" (format nil "~A-manual" name)
                                      "labels" (gr8s::core-object "kubernetes.io/service-name" name))
        "addressType" "IPv4"
        "ports" (vector (gr8s::core-object "name" "http" "port" 8080 "protocol" "TCP"))
        "endpoints" (vector (gr8s::core-object
                             "addresses" (vector (if (equal name "alpha") "192.0.2.5" "192.0.2.6"))
                             "conditions" (gr8s::core-object "ready" t))))
       "alpha"))
    (let* ((plans (gr8s::desired-node-port-targets store :node-address "192.0.2.10"))
           (load-balancer-plan (gethash (list* "TCP" "192.0.2.10" 80) plans)))
      (is (equal '(("192.0.2.5" . 8080)) (first load-balancer-plan)))
      (dolist (name '("alpha" "beta"))
        (let* ((service (gr8s::get-core-resource store "services" "alpha" name))
               (node-port (gethash "nodePort" (aref (gethash "ports" (gethash "spec" service)) 0))))
          (is (gethash (list* "TCP" "" node-port) plans)))))))

(test transparent-reply-rules-match-exactly-one-relayed-flow
  ;; fib_rule_hdr for AF_INET /32 to /32 in the reply table, then the client as destination, the
  ;; Pod as source, and the Pod's and relay's ports as one-port ranges.
  (let ((message (gr8s::transparent-reply-rule-message "10.88.0.5" 8080 "192.0.2.7" 40001 "TCP")))
    (is (equalp (vector 2 32 32 0 gr8s::+transparent-reply-table+ 0 0 1) (subseq message 0 8)))
    (is (search #(8 0 1 0 192 0 2 7) message))
    (is (search #(8 0 2 0 10 88 0 5) message))
    (is (search (gr8s::netlink-octets #(8 0 23 0) (gr8s::netlink-integer 8080 2) (gr8s::netlink-integer 8080 2)) message))
    (is (search (gr8s::netlink-octets #(8 0 24 0) (gr8s::netlink-integer 40001 2) (gr8s::netlink-integer 40001 2)) message))
    (is (search #(5 0 22 0 6) message)))
  (is (search #(5 0 22 0 17) (gr8s::transparent-reply-rule-message "10.88.0.5" 53 "192.0.2.7" 40001 "UDP"))))

(test proxy-ignores-endpoint-slices-labelled-headless
  ;; kube-proxy's slice informer skips service.kubernetes.io/headless; DNS still reads the slice.
  (with-temporary-store (store directory)
    (values directory)
    (let ((service (gr8s::create-core-resource
                    store "services"
                    (gr8s::core-object "metadata" (gr8s::core-object "name" "custom")
                                       "spec" (gr8s::core-object "ports" (vector (gr8s::core-object "name" "port80" "port" 80))))
                    "alpha")))
      (gr8s::create-core-resource
       store "endpointslices"
       (gr8s::core-object "metadata" (gr8s::core-object "name" "custom-slice"
                                                        "labels" (gr8s::core-object "kubernetes.io/service-name" "custom"
                                                                                    "service.kubernetes.io/headless" ""))
                          "addressType" "IPv4"
                          "ports" (vector (gr8s::core-object "name" "port80" "port" 8090 "protocol" "TCP"))
                          "endpoints" (vector (gr8s::core-object "addresses" (vector "192.0.2.5")
                                                                 "conditions" (gr8s::core-object "ready" t))))
       "alpha")
      (let ((port (aref (gethash "ports" (gethash "spec" service)) 0)))
        (is (= 1 (length (gr8s::service-slice-endpoint-records store service port))))
        (is (null (gr8s::service-slice-endpoint-records store service port :proxy t)))
        (is (null (gr8s::service-port-backends store service port)))))))

(test node-port-errors-use-upstream-wording
  ;; e2e matches "<port>.*port is already allocated" and "<port>.*port is not in the valid range".
  (with-temporary-store (store directory)
    (values directory)
    (let* ((first (gr8s::create-core-resource store "services" (network-service "first" "type" "NodePort") "alpha"))
           (port (service-node-port first)))
      (flet ((message (node-port)
               (let ((input (network-service "second" "type" "NodePort")))
                 (setf (gethash "nodePort" (aref (gethash "ports" (gethash "spec" input)) 0)) node-port)
                 (handler-case (progn (gr8s::create-core-resource store "services" input "alpha") nil)
                   (kubernetes-error (condition) (gr8s::kubernetes-error-message condition))))))
        (is (cl-ppcre:scan (format nil "~D.*port is already allocated" port) (message port)))
        (is (cl-ppcre:scan "40000.*port is not in the valid range" (message 40000)))))))

(test udp-ports-are-bound-on-each-host-address
  ;; A wildcard UDP listener would answer from the route's address, not the one the client used.
  (let ((targets (make-hash-table :test #'equal)))
    (setf (gethash (list* "UDP" "" 30001) targets) :udp
          (gethash (list* "TCP" "" 30000) targets) :tcp
          (gethash (list* "UDP" "192.0.2.1" 5353) targets) :pinned)
    (gr8s::bind-udp-ports-per-address targets '("127.0.0.1" "10.0.2.15"))
    (is (eq :udp (gethash (list* "UDP" "127.0.0.1" 30001) targets)))
    (is (eq :udp (gethash (list* "UDP" "10.0.2.15" 30001) targets)))
    (is (null (gethash (list* "UDP" "" 30001) targets)))
    (is (eq :tcp (gethash (list* "TCP" "" 30000) targets)))
    (is (eq :pinned (gethash (list* "UDP" "192.0.2.1" 5353) targets))))
  ;; This host's own addresses come from rtnetlink, loopback among them.
  (is (member "127.0.0.1" (gr8s::host-ipv4-addresses) :test #'equal)))

;;; Ingress classes and NetworkPolicy over the API

(test ingress-gets-the-newest-default-class-on-create
  (with-temporary-store (store directory)
    (values directory)
    (flet ((ingress-class (name default)
             (gr8s::create-core-resource
              store "ingressclasses"
              (gr8s::core-object "metadata" (if default
                                                (gr8s::core-object "name" name "annotations"
                                                                   (gr8s::core-object "ingressclass.kubernetes.io/is-default-class" "true"))
                                                (gr8s::core-object "name" name))
                                 "spec" (gr8s::core-object "controller" "example.com/controller"))
              nil))
           (ingress (name &optional class)
             (let ((spec (gr8s::core-object "defaultBackend" (gr8s::core-object "service" (gr8s::core-object "name" "web" "port" (gr8s::core-object "number" 80))))))
               (when class (setf (gethash "ingressClassName" spec) class))
               (gethash "ingressClassName"
                        (gethash "spec" (gr8s::create-core-resource
                                         store "ingresses" (gr8s::core-object "metadata" (gr8s::core-object "name" name) "spec" spec)
                                         "alpha"))))))
      (ingress-class "plain" nil)
      (is (null (ingress "none")))
      ;; Two default classes created together: the lower name wins the tie.
      (ingress-class "zeta" t)
      (ingress-class "alpha" t)
      (is (equal "alpha" (ingress "defaulted")))
      ;; A class the Ingress names itself is kept.
      (is (equal "plain" (ingress "chosen" "plain"))))))

(test ingress-class-parameters-decode-their-api-group
  (let* ((parameters (core-test-protobuf '((1 "example.com") (2 "fookind") (3 "fooname") (4 "Namespace") (5 "foo-ns"))))
         (spec (core-test-protobuf (list (list 1 "example.com/controller") (list 2 parameters))))
         (object (gr8s::decode-core-resource-protobuf
                  (core-test-protobuf-envelope "IngressClass" (list (list 1 (core-test-protobuf '((1 "ingressclass1"))))
                                                                    (list 2 spec))
                                               "networking.k8s.io/v1")
                  "IngressClass")))
    (is (equal "example.com" (gethash "apiGroup" (gethash "parameters" (gethash "spec" object)))))))

(test network-policies-decode-from-protobuf-and-validate-end-ports
  (let* ((port (core-test-protobuf (list (list 2 (core-test-protobuf '((1 0) (2 20000)))) (list 3 20000))))
         (rule (core-test-protobuf (list (list 1 port))))
         (spec (core-test-protobuf (list (list 3 rule) (list 4 "Egress"))))
         (object (gr8s::decode-core-resource-protobuf
                  (core-test-protobuf-envelope "NetworkPolicy" (list (list 1 (core-test-protobuf '((1 "endport"))))
                                                                     (list 2 spec))
                                               "networking.k8s.io/v1")
                  "NetworkPolicy"))
         (decoded (aref (gethash "ports" (aref (gethash "egress" (gethash "spec" object)) 0)) 0)))
    (is (eql 20000 (gethash "port" decoded)))
    (is (eql 20000 (gethash "endPort" decoded))))
  (with-temporary-store (store directory)
    (values directory)
    (flet ((policy (name port)
             (gr8s::create-core-resource
              store "networkpolicies"
              (gr8s::core-object "metadata" (gr8s::core-object "name" name)
                                 "spec" (gr8s::core-object "podSelector" (gr8s::core-object)
                                                           "policyTypes" #("Egress")
                                                           "egress" (vector (gr8s::core-object "ports" (vector port)))))
              "alpha")))
      (is (policy "equal" (gr8s::core-object "port" 20000 "endPort" 20000)))
      (is (policy "range" (gr8s::core-object "port" 10000 "endPort" 20000)))
      (signals kubernetes-error (policy "no-port" (gr8s::core-object "endPort" 20000)))
      (signals kubernetes-error (policy "named" (gr8s::core-object "port" "serve-80" "endPort" 20000)))
      (signals kubernetes-error (policy "below" (gr8s::core-object "port" 30000 "endPort" 20000)))
      (signals kubernetes-error
        (gr8s::create-core-resource
         store "networkpolicies"
         (gr8s::core-object "metadata" (gr8s::core-object "name" "outside")
                            "spec" (gr8s::core-object "podSelector" (gr8s::core-object)
                                                      "egress" (vector (gr8s::core-object
                                                                        "to" (vector (gr8s::core-object
                                                                                      "ipBlock" (gr8s::core-object "cidr" "10.0.0.0/16"
                                                                                                                   "except" #("10.1.0.0/24"))))))))
         "alpha")))))
