;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Verify the Pod status subresource keeps client fields that survive
;;;; reconciliation, never changes the spec, and that Pod collection deletion and
;;;; host addresses behave as Kubernetes clients expect.

(in-package #:gr8s/tests)
(def-suite pod-status-http :in gr8s)
(in-suite pod-status-http)

(defun status-test-pod (store name &optional (labels "{}"))
  "Create and return a Pod in the default namespace with the LABELS JSON object."
  (create-pod store (parse-pod (format nil "{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"name\":~S,\"namespace\":\"default\",\"labels\":~A},\"spec\":{\"containers\":[{\"name\":\"c\",\"image\":\"busybox:latest\"}]}}" name labels))))

(defun pod-api (path &key (method :get) content (content-type "application/json"))
  "Request PATH beneath the default namespace's Pods, returning parsed JSON and the code."
  (core-api-request (format nil "/api/v1/namespaces/default/pods~A" path)
                    :method method :content-type content-type
                    :octets (and content (trivial-utf-8:string-to-utf-8-bytes content))))

(defun pod-condition-status (object type)
  "Return the status of OBJECT's condition named TYPE."
  (let ((condition (find type (gethash "conditions" (gethash "status" object) #()) :test #'equal
                         :key (lambda (item) (gethash "type" item)))))
    (and condition (gethash "status" condition))))

(test status-patch-persists-message-reason-and-annotations
  (with-core-api (store path)
    (values path)
    (status-test-pod store "web")
    (multiple-value-bind (object code)
        (pod-api "/web/status" :method :patch :content-type "application/merge-patch+json"
                 :content "{\"metadata\":{\"annotations\":{\"patchedstatus\":\"true\"}},\"status\":{\"message\":\"Patched by e2e test\",\"reason\":\"E2E\"}}")
      (is (= 200 code))
      (is (equal "Patched by e2e test" (gethash "message" (gethash "status" object))))
      (is (equal "E2E" (gethash "reason" (gethash "status" object))))
      (is (equal "true" (gethash "patchedstatus" (gethash "annotations" (gethash "metadata" object))))))
    ;; A later read still has the fields, after another reconciliation.
    (multiple-value-bind (object code) (pod-api "/web/status")
      (is (= 200 code))
      (is (equal "E2E" (gethash "reason" (gethash "status" object)))))))

(test status-writes-cannot-change-the-spec
  (with-core-api (store path)
    (values path)
    (status-test-pod store "web")
    (pod-api "/web/status" :method :patch :content-type "application/merge-patch+json"
             :content "{\"spec\":{\"containers\":[{\"name\":\"c\",\"image\":\"evil:latest\"}]},\"status\":{\"message\":\"m\"}}")
    (is (equal "busybox:latest" (gethash "image" (aref (gethash "containers" (gethash "spec" (pod-api "/web"))) 0))))))

(test written-system-conditions-show-once-and-custom-ones-stay
  (with-core-api (store path)
    (values path)
    (status-test-pod store "web")
    (let ((object (pod-api "/web/status" :method :patch :content-type "application/merge-patch+json"
                           :content "{\"status\":{\"conditions\":[{\"type\":\"Ready\",\"status\":\"False\"},{\"type\":\"example.com/gate\",\"status\":\"True\"}]}}")))
      (is (equal "False" (pod-condition-status object "Ready")))
      (is (equal "True" (pod-condition-status object "example.com/gate"))))
    (let ((later (pod-api "/web")))
      (is (equal "True" (pod-condition-status later "example.com/gate")))
      (is (= 1 (count "example.com/gate" (gethash "conditions" (gethash "status" later)) :test #'equal
                      :key (lambda (item) (gethash "type" item))))))))

(test status-writes-honor-preconditions-and-dry-run
  (with-core-api (store path)
    (values path)
    (let* ((pod (status-test-pod store "web"))
           (old (pod-resource-version pod)))
      (pod-api "/web" :method :patch :content-type "application/merge-patch+json"
               :content "{\"metadata\":{\"labels\":{\"a\":\"b\"}}}")
      (multiple-value-bind (object code)
          (pod-api "/web/status" :method :put :content-type "application/json"
                   :content (format nil "{\"metadata\":{\"name\":\"web\",\"resourceVersion\":~S},\"status\":{\"message\":\"m\"}}" old))
        (declare (ignore object))
        (is (= 409 code)))
      (multiple-value-bind (object code)
          (pod-api "/web/status?dryRun=All" :method :patch :content-type "application/merge-patch+json"
                   :content "{\"status\":{\"message\":\"preview\"}}")
        (is (= 200 code))
        (is (equal "preview" (gethash "message" (gethash "status" object)))))
      (is (null (gethash "message" (gethash "status" (pod-api "/web"))))))))

(test client-status-survives-a-store-reopen
  (with-temporary-store (store path)
    (let ((pod (status-test-pod store "web")))
      (gr8s.apiserver::save-pod-client-status store pod (gr8s.resources::core-object "reason" "E2E"))
      (let ((reopened (open-store path)))
        (is (equal "E2E" (gethash "reason" (gethash (pod-uid pod) (gr8s.store::pod-store-pod-client-statuses reopened)))))))))

(test typed-status-writes-decode-only-writable-fields
  (flet ((field (number text)
           (let ((bytes (trivial-utf-8:string-to-utf-8-bytes text)))
             (concatenate '(vector (unsigned-byte 8)) (vector (logior (ash number 3) 2) (length bytes)) bytes))))
    (let* ((condition (concatenate '(vector (unsigned-byte 8)) (field 1 "Ready") (field 2 "False")))
           (status (concatenate '(vector (unsigned-byte 8))
                                (field 3 "hello") (field 4 "E2E") (field 5 "9.9.9.9")
                                (vector (logior (ash 2 3) 2) (length condition)) condition))
           (decoded (gr8s.apiserver::decode-pod-status-protobuf status)))
      (is (equal "hello" (gethash "message" decoded)))
      (is (equal "E2E" (gethash "reason" decoded)))
      (is (null (gethash "hostIP" decoded)))
      (is (equal "False" (gethash "status" (aref (gethash "conditions" decoded) 0)))))))

(test collection-delete-removes-only-selected-pods
  (with-core-api (store path)
    (values path)
    (status-test-pod store "selected" "{\"type\":\"Testing\"}")
    (status-test-pod store "other" "{\"type\":\"Keep\"}")
    (multiple-value-bind (object code)
        (pod-api "?labelSelector=type=Testing" :method :delete)
      (declare (ignore object))
      (is (= 200 code)))
    ;; An unassigned Pod has nothing to stop, so it goes at once; the other stays.
    (is (= 404 (nth-value 1 (pod-api "/selected"))))
    (is (= 200 (nth-value 1 (pod-api "/other"))))))

(test assigned-pods-publish-the-nodes-address
  (with-temporary-store (store path)
    (declare (ignorable path))
    (let ((node (gr8s.model::make-node-record :id "n" :name "n1" :pod-cidr "10.80.0.0/20" :underlay-address "192.0.2.7")))
      (setf (gethash "n1" (gr8s.store::pod-store-nodes store)) node)
      (let* ((pod (create-pod store (parse-pod "{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"name\":\"a\"},\"spec\":{\"nodeName\":\"n1\",\"containers\":[{\"name\":\"c\",\"image\":\"busybox:latest\"}]}}")))
             (status (gr8s.kubelet::add-pod-status-conditions store pod (gr8s.kubelet::pod-status "Running"))))
        (is (equal "192.0.2.7" (gethash "hostIP" status)))
        (is (equal "192.0.2.7" (gethash "ip" (aref (gethash "hostIPs" status) 0))))))
    ;; An unassigned Pod has no host to report.
    (let* ((pod (create-pod store (parse-pod *valid-pod-json*)))
           (status (gr8s.kubelet::add-pod-status-conditions store pod (gr8s.kubelet::pod-status "Pending"))))
      (is (null (gethash "hostIP" status))))))

(test a-node-without-an-underlay-reports-this-host
  (let ((gr8s.apiserver::*local-primary-ipv4* "198.51.100.4"))
    (is (equal "198.51.100.4" (gr8s.apiserver::node-reported-address (gr8s.model::make-node-record :id "n" :name "n" :underlay-address ""))))
    (is (equal "192.0.2.7" (gr8s.apiserver::node-reported-address (gr8s.model::make-node-record :id "n" :name "n" :underlay-address "192.0.2.7"))))))
