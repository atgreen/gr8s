;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Publish API discovery for the Gateway API group (gateway.networking.k8s.io
;;;; /v1: GatewayClass, Gateway, HTTPRoute). The objects themselves are ordinary
;;;; durable stored resources -- persistence, CRUD routing and validation are the
;;;; shared transactional registry (see *stored-resource-types* and
;;;; normalize-bootstrap-resource). This file only advertises the group so
;;;; clients such as kubectl can discover and operate on the resources.

(in-package #:gr8s)

(defun gateway-api-group ()
  "Describe the implemented Gateway API group for aggregated discovery."
  (core-object "apiVersion" "v1" "kind" "APIGroup" "name" "gateway.networking.k8s.io"
               "versions" (vector (core-object "groupVersion" "gateway.networking.k8s.io/v1"
                                                "version" "v1"))
               "preferredVersion" (core-object "groupVersion" "gateway.networking.k8s.io/v1"
                                                "version" "v1")))

(defun gateway-discovery-response ()
  "Advertise the actual Gateway API operations from the durable registry."
  (json-response (core-object "apiVersion" "v1" "kind" "APIResourceList"
                              "groupVersion" "gateway.networking.k8s.io/v1"
                              "resources" (stored-resource-discovery "gateway.networking.k8s.io/v1"))))
