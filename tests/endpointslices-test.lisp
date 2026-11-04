;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Verify EndpointSlice API interoperability and actual selector-Service
;;;; observations, including named-port partitions, terminating readiness, manual
;;;; backends, durable identities, exact owner UID deletion and live watches.

(in-package #:gr8s/tests)
(def-suite endpointslices :in gr8s)
(in-suite endpointslices)

(defun endpointslice-test-object (name &optional (address "192.0.2.9") (target 8080))
  "Build an independently managed, selectorless IPv4 backend."
  (gr8s::core-object "apiVersion" "discovery.k8s.io/v1" "kind" "EndpointSlice"
                    "metadata" (gr8s::core-object "name" name "labels" (gr8s::core-object "kubernetes.io/service-name" "web"))
                    "addressType" "IPv4" "endpoints" (vector (gr8s::core-object "addresses" (vector address)))
                    "ports" (vector (gr8s::core-object "port" target))))

(defun create-endpointslice-test-pod (store name namespace address &key (target 7777) (ready t) (label "web"))
  "Persist an actual assigned Pod and a real-shaped agent observation for controller tests."
  (let* ((object (com.inuoe.jzon:parse *valid-pod-json*))
         (metadata (gethash "metadata" object))
         (container (aref (gethash "containers" (gethash "spec" object)) 0)))
    (setf (gethash "name" metadata) name (gethash "namespace" metadata) namespace
          (gethash "labels" metadata) (gr8s::core-object "app" label)
          (gethash "ports" container) (vector (gr8s::core-object "name" "http" "containerPort" target)))
    (let ((pod (create-pod store (parse-pod object))))
      (gr8s::persist-pod-assignment store pod "worker-a")
      (gr8s::update-pod-observed-status store pod
        (gr8s::core-object "phase" "Running" "podIP" address
                          "conditions" (vector (gr8s::core-object "type" "Ready" "status" (if ready "True" "False")))))
      (get-pod store namespace name))))

(test endpointslices-partition-real-observations-and-recover-without-journal-churn
  (with-temporary-store (store directory)
    (gr8s:register-node store (gr8s:make-node-record :id "worker-id" :name "worker-a" :pod-cidr "10.88.0.0/24"))
    (gr8s:mark-node-ready store "worker-a" (get-universal-time))
    (gr8s::create-core-resource store "services" (service-test-object "web" "http") "alpha")
    (create-endpointslice-test-pod store "one" "alpha" "192.0.2.1")
    (create-endpointslice-test-pod store "two" "alpha" "192.0.2.2" :target 8888 :ready nil)
    (create-endpointslice-test-pod store "foreign" "beta" "192.0.2.3")
    (create-endpointslice-test-pod store "unmatched" "alpha" "192.0.2.4" :label "other")
    (gr8s::reconcile-endpointslices store)
    (let* ((slices (gr8s::list-core-resources store "endpointslices" "alpha"))
           (uids (sort (mapcar (lambda (o) (gethash "uid" (gethash "metadata" o))) slices) #'string<))
           (revision (gr8s::pod-store-resource-revision store)))
      (is (= 2 (length slices)))
      (is (= 2 (reduce #'+ slices :key (lambda (o) (length (gethash "endpoints" o))))))
      (is (equal '(7777 8888) (sort (mapcar (lambda (o) (gethash "port" (aref (gethash "ports" o) 0))) slices) #'<)))
      (let ((ready-slice (find 7777 slices :key (lambda (o) (gethash "port" (aref (gethash "ports" o) 0))))))
        (is (eq t (gethash "ready" (gethash "conditions" (aref (gethash "endpoints" ready-slice) 0))))))
      (gr8s::reconcile-endpointslices store)
      (is (= revision (gr8s::pod-store-resource-revision store)))
      (let ((reopened (open-store directory)))
        (gr8s::reconcile-endpointslices reopened)
        (is (= revision (gr8s::pod-store-resource-revision reopened)))
        (is (equal uids (sort (mapcar (lambda (o) (gethash "uid" (gethash "metadata" o)))
                                     (gr8s::list-core-resources reopened "endpointslices" "alpha")) #'string<))))
      (gr8s::mark-pod-deleting store "alpha" "one")
      (gr8s::reconcile-endpointslices store)
      (let* ((slice (find 7777 (gr8s::list-core-resources store "endpointslices" "alpha")
                          :key (lambda (o) (gethash "port" (aref (gethash "ports" o) 0)))))
             (conditions (gethash "conditions" (aref (gethash "endpoints" slice) 0))))
        (is (null (gethash "ready" conditions)))
        (is (eq t (gethash "serving" conditions)))
        (is (eq t (gethash "terminating" conditions)))))))

(test endpointslices-preserve-manual-backends-and-service-uid-boundaries
  (with-temporary-store (store directory)
    (let* ((input (service-test-object "web"))
           (manual (gr8s::create-core-resource store "endpointslices" (endpointslice-test-object "manual") "alpha")))
      (remhash "selector" (gethash "spec" input))
      (let* ((service (gr8s::create-core-resource store "services" input "alpha"))
             (port (aref (gethash "ports" (gethash "spec" service)) 0)))
        (gr8s::reconcile-endpointslices store)
        (is (equal '(("192.0.2.9" 8080)) (gr8s::service-pod-endpoints store service port)))
        (is (equal (gethash "uid" (gethash "metadata" manual))
                   (gethash "uid" (gethash "metadata" (first (gr8s::list-core-resources store "endpointslices" "alpha"))))))
        (gr8s::delete-core-resource store "services" "alpha" "web")
        (gr8s::collect-orphaned-api-objects (make-reconciler store (make-fake-runtime)))
        (is (= 1 (length (gr8s::list-core-resources store "endpointslices" "alpha"))))
        (setf (gethash "selector" (gethash "spec" input)) (gr8s::core-object "app" "web"))
        (let ((replacement (gr8s::create-core-resource store "services" input "alpha")))
          (gr8s::reconcile-endpointslices store)
          (is (= 2 (length (gr8s::list-core-resources store "endpointslices" "alpha"))))
          (gr8s::delete-core-resource store "services" "alpha" "web" :uid (gethash "uid" (gethash "metadata" replacement)))
          (gr8s::collect-orphaned-api-objects (make-reconciler store (make-fake-runtime)))
          (is (= 1 (length (gr8s::list-core-resources store "endpointslices" "alpha")))))))))

(test endpointslice-http-wire-discovery-validation-and-collection-deletion
  (with-core-api (store path)
    (let* ((collection "/apis/discovery.k8s.io/v1/namespaces/alpha/endpointslices")
           (created (check-core-status 201 collection :method :post :object (endpointslice-test-object "manual"))))
      (is (equal "discovery.k8s.io/v1" (gethash "groupVersion" (check-core-status 200 "/apis/discovery.k8s.io/v1"))))
      (is (gethash "io.k8s.api.discovery.v1.EndpointSlice" (gethash "schemas" (gethash "components"
          (check-core-status 200 "/openapi/v3/apis/discovery.k8s.io/v1")))))
      (setf (gethash "addressType" created) "IPv6")
      (check-core-status 422 (concatenate 'string collection "/manual") :method :put :object created)
      (check-core-status 422 collection :method :post :object (endpointslice-test-object "bad" "127.0.0.1"))
      (let* ((metadata (core-test-protobuf '((1 "typed"))))
             (conditions (core-test-protobuf '((1 0))))
             (endpoint (core-test-protobuf (list (list 1 "192.0.2.10") (list 2 conditions))))
             (port (core-test-protobuf '((1 "") (2 "TCP") (3 8080))))
             (request (core-test-protobuf-envelope "EndpointSlice"
                         (list (list 1 metadata) (list 2 endpoint) (list 3 port) (list 4 "IPv4")) "discovery.k8s.io/v1"))
             (response (check-core-status 201 collection :method :post :content-type "application/vnd.kubernetes.protobuf" :octets request)))
        (is (null (gethash "ready" (gethash "conditions" (aref (gethash "endpoints" response) 0))))))
      (check-core-status 200 collection :method :delete)
      (is (null (gr8s::list-core-resources store "endpointslices" "alpha"))))))

(test endpointslices-bound-chunks-and-honor-publish-not-ready
  (with-temporary-store (store directory)
    (gr8s:register-node store (gr8s:make-node-record :id "worker-id" :name "worker-a" :pod-cidr "10.88.0.0/24"))
    (gr8s:mark-node-ready store "worker-a" (get-universal-time))
    (let ((input (service-test-object "web" "http")))
      (setf (gethash "publishNotReadyAddresses" (gethash "spec" input)) t
            (gethash "clusterIP" (gethash "spec" input)) "None")
      (gr8s::create-core-resource store "services" input "alpha"))
    (dotimes (index 101)
      (create-endpointslice-test-pod store (format nil "pod-~D" index) "alpha" (format nil "192.0.2.~D" (1+ index)) :ready nil))
    (gr8s::reconcile-endpointslices store)
    (let ((slices (gr8s::list-core-resources store "endpointslices" "alpha")))
      (is (equal '(1 100) (sort (mapcar (lambda (o) (length (gethash "endpoints" o))) slices) #'<)))
      (dolist (slice slices)
        (loop for endpoint across (gethash "endpoints" slice)
              do (is (eq t (gethash "ready" (gethash "conditions" endpoint))))
                 (is (null (gethash "serving" (gethash "conditions" endpoint)))))))
    (let ((revision (gr8s::pod-store-resource-revision store)))
      (gr8s::reconcile-endpointslices store)
      (is (= revision (gr8s::pod-store-resource-revision store))))))

(test endpointslices-reject-false-arrays-and-allocate-typed-generated-names
  (with-temporary-store (store directory)
    (let ((input (endpointslice-test-object "manual")))
      (setf (gethash "endpoints" input) nil)
      (signals kubernetes-error (gr8s::create-core-resource store "endpointslices" input "alpha")))
    (let* ((input (endpointslice-test-object "")) (metadata (gethash "metadata" input)))
      (setf (gethash "generateName" metadata) (make-string 100 :initial-element #\a))
      (let ((created (gr8s::create-core-resource store "endpointslices" input "alpha")))
        (is (= 63 (length (gethash "name" (gethash "metadata" created)))))))))
