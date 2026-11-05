;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Publish API discovery for the cert-manager group (cert-manager.io/v1:
;;;; Issuer, ClusterIssuer, Certificate, CertificateRequest). The objects
;;;; themselves are ordinary durable stored resources -- persistence, CRUD
;;;; routing and validation are the shared transactional registry (see
;;;; *stored-resource-types* and normalize-bootstrap-resource). This file only
;;;; advertises the group so clients such as kubectl can discover it.

(in-package #:gr8s)

(defun cert-manager-api-group ()
  "Describe the implemented cert-manager API group for aggregated discovery."
  (core-object "apiVersion" "v1" "kind" "APIGroup" "name" "cert-manager.io"
               "versions" (vector (core-object "groupVersion" "cert-manager.io/v1" "version" "v1"))
               "preferredVersion" (core-object "groupVersion" "cert-manager.io/v1" "version" "v1")))

(defun cert-manager-discovery-response ()
  "Advertise the actual cert-manager operations from the durable registry."
  (json-response (core-object "apiVersion" "v1" "kind" "APIResourceList"
                              "groupVersion" "cert-manager.io/v1"
                              "resources" (stored-resource-discovery "cert-manager.io/v1"))))
