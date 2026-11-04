;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Exercise the Gateway API group (gateway.networking.k8s.io/v1): durable CRUD
;;;; for cluster-scoped GatewayClass and namespaced Gateway/HTTPRoute, aggregated
;;;; and per-group discovery, and fail-closed schema validation of required spec
;;;; fields.

(in-package #:gr8s/tests)
(def-suite gateway-api :in gr8s)
(in-suite gateway-api)

(defparameter *gateway-class-json*
  "{\"apiVersion\":\"gateway.networking.k8s.io/v1\",\"kind\":\"GatewayClass\",
    \"metadata\":{\"name\":\"gr8s\"},
    \"spec\":{\"controllerName\":\"gr8s.io/gateway-controller\"}}")

(defparameter *gateway-json*
  "{\"apiVersion\":\"gateway.networking.k8s.io/v1\",\"kind\":\"Gateway\",
    \"metadata\":{\"name\":\"web\"},
    \"spec\":{\"gatewayClassName\":\"gr8s\",
             \"listeners\":[{\"name\":\"http\",\"port\":80,\"protocol\":\"HTTP\"}]}}")

(defparameter *httproute-json*
  "{\"apiVersion\":\"gateway.networking.k8s.io/v1\",\"kind\":\"HTTPRoute\",
    \"metadata\":{\"name\":\"app\"},
    \"spec\":{\"parentRefs\":[{\"name\":\"web\"}],
             \"hostnames\":[\"app.example.com\"],
             \"rules\":[{\"backendRefs\":[{\"name\":\"app-svc\",\"port\":8080}]}]}}")

(defun gw-parse (json) (com.inuoe.jzon:parse json))

(test gateway-objects-persist-and-discover
  (with-core-api (store directory)
    ;; A namespace to host the namespaced objects.
    (check-core-status 201 "/api/v1/namespaces" :method :post
                       :object (gw-parse "{\"apiVersion\":\"v1\",\"kind\":\"Namespace\",\"metadata\":{\"name\":\"gw\"}}"))
    (let ((cases
            (list
             (list "/apis/gateway.networking.k8s.io/v1/gatewayclasses"
                   "gatewayclasses" nil "gr8s" (gw-parse *gateway-class-json*))
             (list "/apis/gateway.networking.k8s.io/v1/namespaces/gw/gateways"
                   "gateways" "gw" "web" (gw-parse *gateway-json*))
             (list "/apis/gateway.networking.k8s.io/v1/namespaces/gw/httproutes"
                   "httproutes" "gw" "app" (gw-parse *httproute-json*)))))
      (dolist (c cases)
        (destructuring-bind (collection resource namespace name object) c
          (let* ((created (check-core-status 201 collection :method :post :object object))
                 (metadata (gethash "metadata" created))
                 (url (concatenate 'string collection "/" name)))
            (is (stringp (gethash "uid" metadata)))
            (is (equal namespace (gethash "namespace" metadata)))
            (is (equal "gateway.networking.k8s.io/v1" (gethash "apiVersion" created)))
            ;; Duplicate create conflicts; GET and the store round-trip match.
            (check-core-status 409 collection :method :post :object object)
            (is (equalp created (check-core-status 200 url)))
            (is (equalp created (gr8s::get-core-resource (open-store directory) resource namespace name)))
            (let ((list (check-core-status 200 collection)))
              (is (= 1 (length (gethash "items" list)))))))))
    ;; Cluster-scoped GatewayClass must not be reachable under a namespace.
    (check-core-status 404 "/apis/gateway.networking.k8s.io/v1/namespaces/gw/gatewayclasses/gr8s")
    ;; Aggregated discovery advertises the group.
    (let* ((groups (gethash "groups" (check-core-status 200 "/apis")))
           (names (map 'list (lambda (g) (gethash "name" g)) groups)))
      (is (member "gateway.networking.k8s.io" names :test #'equal)))
    ;; The group object and per-version discovery list all three resources.
    (let ((group (check-core-status 200 "/apis/gateway.networking.k8s.io")))
      (is (equal "APIGroup" (gethash "kind" group)))
      (is (equal "gateway.networking.k8s.io" (gethash "name" group))))
    (let* ((discovery (check-core-status 200 "/apis/gateway.networking.k8s.io/v1"))
           (resources (gethash "resources" discovery))
           (names (map 'list (lambda (r) (gethash "name" r)) resources)))
      (is (= 3 (length resources)))
      (dolist (n '("gatewayclasses" "gateways" "httproutes"))
        (is (member n names :test #'equal))))))

(test gateway-validation-fails-closed-on-missing-required-fields
  (with-core-api (store directory)
    (values store directory)
    (check-core-status 201 "/api/v1/namespaces" :method :post
                       :object (gw-parse "{\"apiVersion\":\"v1\",\"kind\":\"Namespace\",\"metadata\":{\"name\":\"gw\"}}"))
    ;; GatewayClass without controllerName.
    (check-core-status 422 "/apis/gateway.networking.k8s.io/v1/gatewayclasses" :method :post
                       :object (gw-parse "{\"apiVersion\":\"gateway.networking.k8s.io/v1\",\"kind\":\"GatewayClass\",\"metadata\":{\"name\":\"bad\"},\"spec\":{}}"))
    ;; Gateway without gatewayClassName.
    (check-core-status 422 "/apis/gateway.networking.k8s.io/v1/namespaces/gw/gateways" :method :post
                       :object (gw-parse "{\"apiVersion\":\"gateway.networking.k8s.io/v1\",\"kind\":\"Gateway\",\"metadata\":{\"name\":\"bad\"},\"spec\":{\"listeners\":[{\"name\":\"http\",\"port\":80,\"protocol\":\"HTTP\"}]}}"))
    ;; Gateway with an empty listeners array.
    (check-core-status 422 "/apis/gateway.networking.k8s.io/v1/namespaces/gw/gateways" :method :post
                       :object (gw-parse "{\"apiVersion\":\"gateway.networking.k8s.io/v1\",\"kind\":\"Gateway\",\"metadata\":{\"name\":\"bad\"},\"spec\":{\"gatewayClassName\":\"gr8s\",\"listeners\":[]}}"))
    ;; Gateway listener with an out-of-range port.
    (check-core-status 422 "/apis/gateway.networking.k8s.io/v1/namespaces/gw/gateways" :method :post
                       :object (gw-parse "{\"apiVersion\":\"gateway.networking.k8s.io/v1\",\"kind\":\"Gateway\",\"metadata\":{\"name\":\"bad\"},\"spec\":{\"gatewayClassName\":\"gr8s\",\"listeners\":[{\"name\":\"http\",\"port\":0,\"protocol\":\"HTTP\"}]}}"))
    ;; HTTPRoute with a non-array rules field.
    (check-core-status 422 "/apis/gateway.networking.k8s.io/v1/namespaces/gw/httproutes" :method :post
                       :object (gw-parse "{\"apiVersion\":\"gateway.networking.k8s.io/v1\",\"kind\":\"HTTPRoute\",\"metadata\":{\"name\":\"bad\"},\"spec\":{\"rules\":\"nope\"}}"))))
