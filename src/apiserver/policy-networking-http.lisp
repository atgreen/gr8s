;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Publish API discovery for network-policy-api's group
;;;; (policy.networking.k8s.io/v1alpha2: ClusterNetworkPolicy, podster-wv1w.1). As
;;;; for cert-manager, the objects are ordinary durable stored resources; this file
;;;; only advertises the group, so installing the upstream CRDs as well is a
;;;; double registration.

(in-package #:gr8s.apiserver)

(defun policy-networking-api-group ()
  "Describe the implemented policy.networking.k8s.io API group."
  (core-object "apiVersion" "v1" "kind" "APIGroup" "name" "policy.networking.k8s.io"
               "versions" (vector (core-object "groupVersion" "policy.networking.k8s.io/v1alpha2"
                                               "version" "v1alpha2"))
               "preferredVersion" (core-object "groupVersion" "policy.networking.k8s.io/v1alpha2"
                                               "version" "v1alpha2")))

(defun kruise-agents-api-group ()
  "Describe the agents.kruise.io API group gr8s serves a subset of (SecurityProfile,
podster-wv1w.3). Installing OpenKruise Agents' CRDs as well registers it twice."
  (core-object "apiVersion" "v1" "kind" "APIGroup" "name" "agents.kruise.io"
               "versions" (vector (core-object "groupVersion" "agents.kruise.io/v1alpha1" "version" "v1alpha1"))
               "preferredVersion" (core-object "groupVersion" "agents.kruise.io/v1alpha1" "version" "v1alpha1")))

(defun kruise-agents-discovery-response ()
  "Advertise SecurityProfile from the durable registry."
  (json-response (core-object "apiVersion" "v1" "kind" "APIResourceList"
                              "groupVersion" "agents.kruise.io/v1alpha1"
                              "resources" (stored-resource-discovery "agents.kruise.io/v1alpha1"))))

(defun gr8ify-api-group ()
  "Describe the gr8ify.gr8s.io API group (SandboxProfile, podster-wv1w.5)."
  (core-object "apiVersion" "v1" "kind" "APIGroup" "name" "gr8ify.gr8s.io"
               "versions" (vector (core-object "groupVersion" "gr8ify.gr8s.io/v1alpha1" "version" "v1alpha1"))
               "preferredVersion" (core-object "groupVersion" "gr8ify.gr8s.io/v1alpha1" "version" "v1alpha1")))

(defun gr8ify-discovery-response ()
  "Advertise SandboxProfile from the durable registry."
  (json-response (core-object "apiVersion" "v1" "kind" "APIResourceList"
                              "groupVersion" "gr8ify.gr8s.io/v1alpha1"
                              "resources" (stored-resource-discovery "gr8ify.gr8s.io/v1alpha1"))))

(defun policy-networking-discovery-response ()
  "Advertise ClusterNetworkPolicy from the durable registry."
  (json-response (core-object "apiVersion" "v1" "kind" "APIResourceList"
                              "groupVersion" "policy.networking.k8s.io/v1alpha2"
                              "resources" (stored-resource-discovery "policy.networking.k8s.io/v1alpha2"))))
