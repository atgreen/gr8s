;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Verify Table and PartialObjectMetadata negotiation, printed columns, chunked
;;;; lists, custom printer columns and the 406 for what has no such form.

(in-package #:gr8s/tests)
(def-suite table-printing :in gr8s)
(in-suite table-printing)

(defparameter +table-accept+ "application/json;as=Table;v=v1;g=meta.k8s.io")

(defun table-test-get (path &key (accept +table-accept+) parameters)
  "GET PATH with an Accept header, returning the parsed body and status."
  (multiple-value-bind (body status)
      (drakma:http-request (core-api-url path)
                           :method :get :accept accept :parameters parameters)
    (values (com.inuoe.jzon:parse body :max-string-length (* 2 1024 1024)) status)))

(defun table-test-namespace ()
  "Create namespace alpha."
  (check-core-status 201 "/api/v1/namespaces" :method :post
    :object (gr8s::core-object "apiVersion" "v1" "kind" "Namespace" "metadata" (gr8s::core-object "name" "alpha"))))

(test table-prints-configmaps-with-columns-and-row-objects
  (with-core-api (store path)
    (values store path)
    (table-test-namespace)
    (check-core-status 201 "/api/v1/namespaces/alpha/configmaps" :method :post
      :object (core-fixture "ConfigMap" "one" "data" (gr8s::core-object "a" "1" "b" "2")))
    (multiple-value-bind (table status) (table-test-get "/api/v1/namespaces/alpha/configmaps/one")
      (is (= 200 status))
      (is (equal "Table" (gethash "kind" table)))
      (is (equal "meta.k8s.io/v1" (gethash "apiVersion" table)))
      (is (equal '("Name" "Data" "Age") (map 'list (lambda (column) (gethash "name" column)) (gethash "columnDefinitions" table))))
      (let ((row (aref (gethash "rows" table) 0)))
        (is (equal "one" (aref (gethash "cells" row) 0)))
        (is (= 2 (aref (gethash "cells" row) 1)))
        (is (equal "PartialObjectMetadata" (gethash "kind" (gethash "object" row))))
        (is (equal "one" (gethash "name" (gethash "metadata" (gethash "object" row)))))))
    (let ((table (table-test-get "/api/v1/namespaces/alpha/configmaps/one"
                                 :parameters '(("includeObject" . "None")))))
      (is (not (nth-value 1 (gethash "object" (aref (gethash "rows" table) 0))))))
    (let ((table (table-test-get "/api/v1/namespaces/alpha/configmaps/one"
                                 :parameters '(("includeObject" . "Object")))))
      (is (equal "ConfigMap" (gethash "kind" (gethash "object" (aref (gethash "rows" table) 0))))))
    (let ((table (table-test-get "/api/v1/namespaces/alpha/configmaps/one"
                                 :accept "application/json;as=Table;v=v1beta1;g=meta.k8s.io")))
      (is (equal "meta.k8s.io/v1beta1" (gethash "apiVersion" table))))))

(test table-lists-keep-chunking-and-order
  (with-core-api (store path)
    (values store path)
    (table-test-namespace)
    (dotimes (index 5)
      (check-core-status 201 "/api/v1/namespaces/alpha/configmaps" :method :post
        :object (core-fixture "ConfigMap" (format nil "item-~D" index))))
    (let* ((page (table-test-get "/api/v1/namespaces/alpha/configmaps" :parameters '(("limit" . "2"))))
           (metadata (gethash "metadata" page)))
      (is (= 2 (length (gethash "rows" page))))
      (is (plusp (length (gethash "resourceVersion" metadata))))
      (is (plusp (length (gethash "continue" metadata))))
      (is (equal "item-0" (aref (gethash "cells" (aref (gethash "rows" page) 0)) 0)))
      (let ((next (table-test-get "/api/v1/namespaces/alpha/configmaps"
                                  :parameters (list (cons "continue" (gethash "continue" metadata))))))
        (is (equal "item-2" (aref (gethash "cells" (aref (gethash "rows" next) 0)) 0)))))))

(test table-negotiation-follows-accept-order-and-refuses-the-unrepresentable
  (with-core-api (store path)
    (values store path)
    (table-test-namespace)
    (check-core-status 201 "/api/v1/namespaces/alpha/configmaps" :method :post :object (core-fixture "ConfigMap" "one"))
    ;; Plain JSON first keeps the plain object; the kubectl order prefers the Table.
    (is (equal "ConfigMap"
               (gethash "kind" (table-test-get "/api/v1/namespaces/alpha/configmaps/one"
                                               :accept (format nil "application/json,~A" +table-accept+)))))
    (is (equal "Table"
               (gethash "kind" (table-test-get "/api/v1/namespaces/alpha/configmaps/one"
                                               :accept (format nil "~A,application/json" +table-accept+)))))
    (is (equal "ConfigMap" (gethash "kind" (table-test-get "/api/v1/namespaces/alpha/configmaps/one" :accept "*/*"))))
    ;; Nothing a Table can describe.
    (multiple-value-bind (body status) (table-test-get "/api/v1")
      (declare (ignore body))
      (is (= 406 status)))
    ;; An error stays a Status.
    (multiple-value-bind (body status) (table-test-get "/api/v1/namespaces/alpha/configmaps/missing")
      (is (= 404 status))
      (is (equal "Status" (gethash "kind" body))))
    ;; Metadata only.
    (let ((partial (table-test-get "/api/v1/namespaces/alpha/configmaps/one"
                                   :accept "application/json;as=PartialObjectMetadata;v=v1;g=meta.k8s.io")))
      (is (equal "PartialObjectMetadata" (gethash "kind" partial)))
      (is (equal "one" (gethash "name" (gethash "metadata" partial)))))
    (let ((partial (table-test-get "/api/v1/namespaces/alpha/configmaps"
                                   :accept "application/json;as=PartialObjectMetadataList;v=v1;g=meta.k8s.io")))
      (is (equal "PartialObjectMetadataList" (gethash "kind" partial)))
      (is (= 1 (length (gethash "items" partial)))))))

(test table-prints-custom-resource-printer-columns
  (with-core-api (store path)
    (values store path)
    (table-test-namespace)
    (let* ((definition (crd-fixture))
           (version (aref (gethash "versions" (gethash "spec" definition)) 0)))
      (setf (gethash "additionalPrinterColumns" version)
            (vector (gr8s::core-object "name" "Count" "type" "integer" "jsonPath" ".spec.count")
                    (gr8s::core-object "name" "Missing" "type" "string" "jsonPath" ".spec.nothing")
                    (gr8s::core-object "name" "Age" "type" "date" "jsonPath" ".metadata.creationTimestamp")))
      (check-core-status 201 "/apis/apiextensions.k8s.io/v1/customresourcedefinitions" :method :post :object definition))
    (check-core-status 201 "/apis/widgets.example.test/v1/namespaces/alpha/widgets" :method :post
      :object (let ((instance (crd-instance)))
                (setf (gethash "count" (gethash "spec" instance)) 3)
                instance))
    (let* ((table (table-test-get "/apis/widgets.example.test/v1/namespaces/alpha/widgets"))
           (cells (gethash "cells" (aref (gethash "rows" table) 0))))
      (is (equal '("Name" "Count" "Missing" "Age")
                 (map 'list (lambda (column) (gethash "name" column)) (gethash "columnDefinitions" table))))
      (is (equal "one" (aref cells 0)))
      (is (= 3 (aref cells 1)))
      (is (eq 'null (aref cells 2)))
      (is (stringp (aref cells 3))))
    ;; An unsupported column is refused when the definition is admitted.
    (let ((bad (crd-fixture :plural "others" :kind "Other")))
      (setf (gethash "additionalPrinterColumns" (aref (gethash "versions" (gethash "spec" bad)) 0))
            (vector (gr8s::core-object "name" "X" "type" "nope" "jsonPath" ".spec.count")))
      (check-core-status 422 "/apis/apiextensions.k8s.io/v1/customresourcedefinitions" :method :post :object bad))))

(test table-pod-status-follows-kubectl
  (flet ((row (json)
           (multiple-value-list (gr8s::table-pod-row (com.inuoe.jzon:parse json)))))
    (destructuring-bind (ready status restarts)
        (row "{\"metadata\":{},\"spec\":{\"containers\":[{},{}]},\"status\":{\"phase\":\"Running\",\"containerStatuses\":[{\"ready\":true,\"restartCount\":2,\"state\":{\"running\":{}}},{\"ready\":false,\"restartCount\":1,\"state\":{\"waiting\":{\"reason\":\"CrashLoopBackOff\"}}}]}}")
      (is (equal "1/2" ready))
      (is (equal "CrashLoopBackOff" status))
      (is (equal "3" restarts)))
    (destructuring-bind (ready status restarts)
        (row "{\"metadata\":{\"deletionTimestamp\":\"2024-01-01T00:00:00Z\"},\"spec\":{\"containers\":[{}]},\"status\":{\"phase\":\"Running\"}}")
      (declare (ignore ready restarts))
      (is (equal "Terminating" status)))
    (destructuring-bind (ready status restarts)
        (row "{\"metadata\":{},\"spec\":{\"containers\":[{}],\"initContainers\":[{\"name\":\"i\"}]},\"status\":{\"phase\":\"Pending\",\"initContainerStatuses\":[{\"name\":\"i\",\"state\":{\"waiting\":{\"reason\":\"ImagePullBackOff\"}}}]}}")
      (declare (ignore ready restarts))
      (is (equal "Init:ImagePullBackOff" status)))))

(test custom-scale-subresource-reads-and-writes-replicas
  (with-core-api (store path)
    (values store path)
    (table-test-namespace)
    (let* ((definition (crd-fixture))
           (version (aref (gethash "versions" (gethash "spec" definition)) 0))
           (schema (gethash "openAPIV3Schema" (gethash "schema" version)))
           (properties (gethash "properties" schema)))
      (setf (gethash "replicas" (gethash "properties" (gethash "spec" properties))) (gr8s::core-object "type" "integer")
            (gethash "replicas" (gethash "properties" (gethash "status" properties))) (gr8s::core-object "type" "integer")
            (gethash "selector" (gethash "properties" (gethash "status" properties))) (gr8s::core-object "type" "string"))
      (setf (gethash "scale" (gethash "subresources" version))
            (gr8s::core-object "specReplicasPath" ".spec.replicas" "statusReplicasPath" ".status.replicas"
                               "labelSelectorPath" ".status.selector"))
      (check-core-status 201 "/apis/apiextensions.k8s.io/v1/customresourcedefinitions" :method :post :object definition))
    (let ((discovery (check-core-status 200 "/apis/widgets.example.test/v1")))
      (is (find "widgets/scale" (gethash "resources" discovery) :test #'equal :key (lambda (entry) (gethash "name" entry)))))
    (check-core-status 201 "/apis/widgets.example.test/v1/namespaces/alpha/widgets" :method :post
      :object (let ((instance (crd-instance)))
                (setf (gethash "replicas" (gethash "spec" instance)) 2)
                instance))
    (let* ((scale-path "/apis/widgets.example.test/v1/namespaces/alpha/widgets/one/scale")
           (scale (check-core-status 200 scale-path)))
      (is (equal "Scale" (gethash "kind" scale)))
      (is (= 2 (gethash "replicas" (gethash "spec" scale))))
      (setf (gethash "replicas" (gethash "spec" scale)) 5)
      (let ((updated (check-core-status 200 scale-path :method :put :object scale)))
        (is (= 5 (gethash "replicas" (gethash "spec" updated)))))
      (is (= 5 (gethash "replicas" (gethash "spec" (check-core-status 200 "/apis/widgets.example.test/v1/namespaces/alpha/widgets/one")))))
      ;; The stale revision of the old read now conflicts.
      (check-core-status 409 scale-path :method :put :object scale)
      (let ((patched (check-core-status 200 scale-path :method :patch
                       :octets "{\"spec\":{\"replicas\":7}}" :content-type "application/merge-patch+json")))
        (is (= 7 (gethash "replicas" (gethash "spec" patched))))))
    ;; Bad paths are refused at admission.
    (let* ((bad (crd-fixture :plural "others" :kind "Other"))
           (version (aref (gethash "versions" (gethash "spec" bad)) 0)))
      (setf (gethash "scale" (gethash "subresources" version))
            (gr8s::core-object "specReplicasPath" ".status.x" "statusReplicasPath" ".status.y"))
      (check-core-status 422 "/apis/apiextensions.k8s.io/v1/customresourcedefinitions" :method :post :object bad))))

(test openapi-publishes-typed-groups-and-a-protobuf-v2-document
  (with-core-api (store path)
    (values store path)
    (let* ((document (check-core-status 200 "/openapi/v3/apis/flowcontrol.apiserver.k8s.io/v1"))
           (schemas (gethash "schemas" (gethash "components" document)))
           (flow (gethash "io.k8s.api.flowcontrol.v1.FlowSchema" schemas)))
      (is (hash-table-p flow))
      (is (equal "flowcontrol.apiserver.k8s.io"
                 (gethash "group" (aref (gethash "x-kubernetes-group-version-kind" flow) 0))))
      (is (equal "FlowSchema" (gethash "kind" (aref (gethash "x-kubernetes-group-version-kind" flow) 0)))))
    (dolist (entry '(("resource.k8s.io/v1" . "io.k8s.api.resource.v1.ResourceClaim")
                     ("coordination.k8s.io/v1" . "io.k8s.api.coordination.v1.Lease")
                     ("authorization.k8s.io/v1" . "io.k8s.api.authorization.v1.SubjectAccessReview")
                     ("authentication.k8s.io/v1" . "io.k8s.api.authentication.v1.TokenReview")
                     ("admissionregistration.k8s.io/v1" . "io.k8s.api.admissionregistration.v1.ValidatingAdmissionPolicy")))
      (let* ((document (check-core-status 200 (format nil "/openapi/v3/apis/~A" (car entry))))
             (schema (gethash (cdr entry) (gethash "schemas" (gethash "components" document)))))
        (is (hash-table-p schema) "~A misses ~A" (car entry) (cdr entry))))
    ;; Protobuf is what client-go asks for; anything else keeps JSON.
    (multiple-value-bind (body status headers)
        (drakma:http-request (core-api-url "/openapi/v2") :force-binary t
                             :accept "application/com.github.proto-openapi.spec.v2@v1.0+protobuf")
      (is (= 200 status))
      (is (search "protobuf" (cdr (assoc :content-type headers))))
      (is (typep body '(vector (unsigned-byte 8))))
      ;; Document.swagger is field 1, a string.
      (is (= 10 (aref body 0)))
      (is (= 3 (aref body 1)))
      (is (equal "2.0" (trivial-utf-8:utf-8-bytes-to-string (subseq body 2 5))))
      (let ((text (map 'string #'code-char body)))
        (is (search "io.k8s.api.flowcontrol.v1.FlowSchema" text))
        (is (search "x-kubernetes-group-version-kind" text))))
    (is (equal "2.0" (gethash "swagger" (check-core-status 200 "/openapi/v2"))))))
