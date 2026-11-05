;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; ClusterTrustBundle (KEP-3257/4317) is a cluster-scoped certificates.k8s.io
;;;; /v1beta1 resource carrying a signer's CA trust anchors. Exercise its CRUD
;;;; and that discovery advertises it cluster-scoped under v1beta1.

(in-package #:gr8s/tests)

(in-suite gr8s)

(test clustertrustbundle-is-a-cluster-scoped-certificates-v1beta1-resource
  (with-temporary-store (store directory)
    (let ((object (gr8s::core-object
                   "apiVersion" "certificates.k8s.io/v1beta1" "kind" "ClusterTrustBundle"
                   "metadata" (gr8s::core-object "name" "ate-roots")
                   "spec" (gr8s::core-object
                           "signerName" "servicedns.podcert.ate.dev/identity"
                           "trustBundle" "-----BEGIN CERTIFICATE-----
MIIBtest
-----END CERTIFICATE-----
"))))
      ;; Cluster-scoped: created with a NIL namespace, and durable CRUD works.
      (gr8s::create-core-resource store "clustertrustbundles" object nil)
      (let ((got (gr8s::get-core-resource store "clustertrustbundles" nil "ate-roots")))
        (is (string= "ClusterTrustBundle" (gethash "kind" got)))
        (is (string= "certificates.k8s.io/v1beta1" (gethash "apiVersion" got)))
        (is (string= "servicedns.podcert.ate.dev/identity"
                     (gethash "signerName" (gethash "spec" got)))))
      (is (= 1 (length (gr8s::list-core-resources store "clustertrustbundles"))))
      (gr8s::delete-core-resource store "clustertrustbundles" nil "ate-roots")
      (is (= 0 (length (gr8s::list-core-resources store "clustertrustbundles"))))
      ;; A non-object spec is rejected.
      (signals gr8s:kubernetes-error
        (gr8s::create-core-resource
         store "clustertrustbundles"
         (gr8s::core-object "apiVersion" "certificates.k8s.io/v1beta1" "kind" "ClusterTrustBundle"
                            "metadata" (gr8s::core-object "name" "bad") "spec" "not-an-object")
         nil)))
    ;; Discovery advertises it, cluster-scoped, under certificates.k8s.io/v1beta1.
    (let ((entry (find "clustertrustbundles"
                       (gr8s::stored-resource-discovery "certificates.k8s.io/v1beta1")
                       :key (lambda (r) (gethash "name" r)) :test #'equal)))
      (is (not (null entry)))
      (is (null (gethash "namespaced" entry)))
      (is (string= "ClusterTrustBundle" (gethash "kind" entry))))))
