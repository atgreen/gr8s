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
      (let* ((metadata (core-test-protobuf '((1 "typed") (6 ""))))
             (conditions (core-test-protobuf '((1 0))))
             (endpoint (core-test-protobuf (list (list 1 "192.0.2.10") (list 2 conditions))))
             (port (core-test-protobuf '((1 "") (2 "TCP") (3 8080))))
             (request (core-test-protobuf-envelope "EndpointSlice"
                         (list (list 1 metadata) (list 2 endpoint) (list 3 port) (list 4 "IPv4")) "discovery.k8s.io/v1"))
             (response (check-core-status 201 collection :method :post :content-type "application/vnd.kubernetes.protobuf" :octets request)))
        (is (null (gethash "ready" (gethash "conditions" (aref (gethash "endpoints" response) 0)))))
        (is (plusp (length (gethash "resourceVersion" (gethash "metadata" response))))))
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
        (is (equal "" (gethash "service.kubernetes.io/headless" (gethash "labels" (gethash "metadata" slice)))))
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

(test endpointslices-ignore-unlabeled-manual-slices
  (with-temporary-store (store directory)
    (let ((manual (endpointslice-test-object "unlabeled")))
      (remhash "labels" (gethash "metadata" manual))
      (gr8s::create-core-resource store "endpointslices" manual "alpha"))
    (let ((service (gr8s::create-core-resource store "services" (service-test-object "web") "alpha")))
      (gr8s::reconcile-endpointslices store)
      (is (= 2 (length (gr8s::list-core-resources store "endpointslices" "alpha"))))
      (is (null (gr8s::service-pod-endpoints store service (aref (gethash "ports" (gethash "spec" service)) 0)))))
    (is (gr8s::get-core-resource store "endpointslices" "alpha" "unlabeled"))))

(test endpointslice-generations-distinguish-label-data-and-annotation-updates
  (with-temporary-store (store directory)
    (let* ((input (endpointslice-test-object "manual")) (metadata (gethash "metadata" input)))
      (setf (gethash "generation" metadata) 999)
      (is (= 1 (gethash "generation" (gethash "metadata" (gr8s::create-core-resource store "endpointslices" input "alpha"))))))
    (let ((annotated (gr8s::update-core-resource store "endpointslices" "alpha" "manual"
                       (lambda (object) (setf (gethash "annotations" (gethash "metadata" object)) (gr8s::core-object "example.com/note" "new")) object))))
      (is (= 1 (gethash "generation" (gethash "metadata" annotated)))))
    (let ((relabeled (gr8s::update-core-resource store "endpointslices" "alpha" "manual"
                       (lambda (object) (setf (gethash "app" (gethash "labels" (gethash "metadata" object))) "changed") object))))
      (is (= 2 (gethash "generation" (gethash "metadata" relabeled)))))
    (let ((changed (gr8s::update-core-resource store "endpointslices" "alpha" "manual"
                       (lambda (object) (setf (gethash "port" (aref (gethash "ports" object) 0)) 9090
                                              (gethash "resourceVersion" (gethash "metadata" object)) "") object))))
      (is (= 3 (gethash "generation" (gethash "metadata" changed)))))))

(test endpointslice-create-treats-empty-and-null-resource-versions-as-unset
  (with-temporary-store (store directory)
    (dolist (value (list "" 'gr8s::null))
      (let* ((input (endpointslice-test-object (if (stringp value) "empty" "null")))
             (metadata (gethash "metadata" input)))
        (setf (gethash "resourceVersion" metadata) value)
        (is (plusp (length (gethash "resourceVersion" (gethash "metadata"
           (gr8s::create-core-resource store "endpointslices" input "alpha"))))))))
    (let ((input (endpointslice-test-object "nonempty")))
      (setf (gethash "resourceVersion" (gethash "metadata" input)) "1")
      (signals kubernetes-error (gr8s::create-core-resource store "endpointslices" input "alpha")))))

(test generated-endpointslices-pass-admission-as-the-controller
  ;; While admission is configured, each generated slice is admitted as upstream's
  ;; endpointslice controller writes it: mutations land and refusals hold the write back.
  (with-temporary-store (store directory)
    (values directory)
    (gr8s:register-node store (gr8s:make-node-record :id "worker-id" :name "worker-a" :pod-cidr "10.88.0.0/24"))
    (gr8s:mark-node-ready store "worker-a" (get-universal-time))
    (flet ((policy (name operations expression)
             (gr8s::create-core-resource store "validatingadmissionpolicies"
               (gr8s::core-object
                "apiVersion" "admissionregistration.k8s.io/v1" "kind" "ValidatingAdmissionPolicy"
                "metadata" (gr8s::core-object "name" name)
                "spec" (gr8s::core-object
                        "matchConstraints" (gr8s::core-object
                                            "resourceRules" (vector (gr8s::core-object
                                                                     "apiGroups" #("discovery.k8s.io") "apiVersions" #("v1")
                                                                     "operations" operations "resources" #("endpointslices"))))
                        "validations" (vector (gr8s::core-object "expression" expression "message" name))))
               nil)
             (gr8s::create-core-resource store "validatingadmissionpolicybindings"
               (gr8s::core-object
                "apiVersion" "admissionregistration.k8s.io/v1" "kind" "ValidatingAdmissionPolicyBinding"
                "metadata" (gr8s::core-object "name" name)
                "spec" (gr8s::core-object "policyName" name "validationActions" #("Deny")))
               nil)))
      (policy "controller-only" #("CREATE" "UPDATE")
              "request.userInfo.username == 'system:serviceaccount:kube-system:endpointslice-controller'")
      (policy "no-second-endpoint" #("UPDATE") "size(object.endpoints) < 2")
      (gr8s::create-core-resource store "services" (service-test-object "web" "http") "alpha")
      (create-endpointslice-test-pod store "one" "alpha" "192.0.2.1")
      (gr8s::reconcile-endpointslices store)
      ;; Created, as the controller.
      (let ((slices (gr8s::list-core-resources store "endpointslices" "alpha")))
        (is (= 1 (length slices)))
        (is (= 1 (length (gethash "endpoints" (first slices))))))
      ;; Adding a second endpoint is an update the policy refuses, so the slice stays as it was.
      (create-endpointslice-test-pod store "two" "alpha" "192.0.2.2")
      (gr8s::reconcile-endpointslices store)
      (is (= 1 (length (gethash "endpoints" (first (gr8s::list-core-resources store "endpointslices" "alpha"))))))
      ;; Once allowed, the next pass writes it.
      (gr8s::delete-core-resource store "validatingadmissionpolicybindings" nil "no-second-endpoint")
      (gr8s::reconcile-endpointslices store)
      (is (= 2 (length (gethash "endpoints" (first (gr8s::list-core-resources store "endpointslices" "alpha")))))))))
