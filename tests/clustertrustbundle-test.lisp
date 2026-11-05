;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; ClusterTrustBundle (KEP-3257/4317) is a cluster-scoped certificates.k8s.io
;;;; /v1 resource carrying a signer's CA trust anchors. Exercise its CRUD
;;;; and that discovery advertises it cluster-scoped under v1.

(in-package #:gr8s/tests)

(in-suite gr8s)

(test clustertrustbundle-is-a-cluster-scoped-certificates-v1-resource
  (with-temporary-store (store directory)
    (let ((object (gr8s::core-object
                   "apiVersion" "certificates.k8s.io/v1" "kind" "ClusterTrustBundle"
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
        (is (string= "certificates.k8s.io/v1" (gethash "apiVersion" got)))
        (is (string= "servicedns.podcert.ate.dev/identity"
                     (gethash "signerName" (gethash "spec" got)))))
      (is (= 1 (length (gr8s::list-core-resources store "clustertrustbundles"))))
      (gr8s::delete-core-resource store "clustertrustbundles" nil "ate-roots")
      (is (= 0 (length (gr8s::list-core-resources store "clustertrustbundles"))))
      ;; A non-object spec is rejected.
      (signals gr8s:kubernetes-error
        (gr8s::create-core-resource
         store "clustertrustbundles"
         (gr8s::core-object "apiVersion" "certificates.k8s.io/v1" "kind" "ClusterTrustBundle"
                            "metadata" (gr8s::core-object "name" "bad") "spec" "not-an-object")
         nil)))
    ;; Discovery advertises it, cluster-scoped, under certificates.k8s.io/v1.
    (let ((entry (find "clustertrustbundles"
                       (gr8s::stored-resource-discovery "certificates.k8s.io/v1")
                       :key (lambda (r) (gethash "name" r)) :test #'equal)))
      (is (not (null entry)))
      (is (null (gethash "namespaced" entry)))
      (is (string= "ClusterTrustBundle" (gethash "kind" entry))))))

(defun ctb-object (name signer &optional live)
  (let ((metadata (gr8s::core-object "name" name)))
    (when live (setf (gethash "labels" metadata) (gr8s::core-object "canarying" "live")))
    (gr8s::core-object "apiVersion" "certificates.k8s.io/v1" "kind" "ClusterTrustBundle"
                       "metadata" metadata
                       "spec" (gr8s::core-object "signerName" signer "trustBundle" (format nil "PEM-~A~%" name)))))

(defun ctb-source-pem (store source)
  (trivial-utf-8:utf-8-bytes-to-string
   (second (first (gr8s::cluster-trust-bundle-volume-files store source #o644)))))

(test clustertrustbundle-projected-source-validates-and-resolves
  ;; Validation: a clusterTrustBundle projected source needs a path and exactly
  ;; one of name / signerName.
  (finishes
    (gr8s::validate-projected-source
     (gr8s::core-object "sources"
                        (vector (gr8s::core-object "clusterTrustBundle"
                                                   (gr8s::core-object "path" "roots.pem" "signerName" "s"))))))
  (signals gr8s:kubernetes-error
    (gr8s::validate-projected-source
     (gr8s::core-object "sources"
                        (vector (gr8s::core-object "clusterTrustBundle"
                                                   (gr8s::core-object "signerName" "s")))))) ; no path
  (signals gr8s:kubernetes-error
    (gr8s::validate-projected-source
     (gr8s::core-object "sources"
                        (vector (gr8s::core-object "clusterTrustBundle"
                                                   (gr8s::core-object "path" "r.pem" "name" "a" "signerName" "s")))))) ; both
  ;; Resolution against the store: name, signerName (concatenated), label-narrowed.
  (with-temporary-store (store directory)
    (gr8s::create-core-resource store "clustertrustbundles" (ctb-object "roots-a" "sds/identity" t) nil)
    (gr8s::create-core-resource store "clustertrustbundles" (ctb-object "roots-b" "sds/identity" nil) nil)
    (is (string= (format nil "PEM-roots-a~%")
                 (ctb-source-pem store (gr8s::core-object "path" "b.pem" "name" "roots-a"))))
    (is (string= (format nil "PEM-roots-a~%PEM-roots-b~%")
                 (ctb-source-pem store (gr8s::core-object "path" "b.pem" "signerName" "sds/identity"))))
    (is (string= (format nil "PEM-roots-a~%")
                 (ctb-source-pem store (gr8s::core-object "path" "b.pem" "signerName" "sds/identity"
                                                          "labelSelector" (gr8s::core-object
                                                                           "matchLabels" (gr8s::core-object "canarying" "live"))))))
    ;; A missing named bundle fails unless optional.
    (signals gr8s:kubernetes-error
      (gr8s::cluster-trust-bundle-volume-files store (gr8s::core-object "path" "b.pem" "name" "absent") #o644))
    (is (string= "" (ctb-source-pem store (gr8s::core-object "path" "b.pem" "name" "absent" "optional" t))))
    ;; Projected to the node via the service-discovery snapshot.
    (let ((resources (make-hash-table :test #'equal)))
      (gr8s::install-service-discovery-projection
       resources (slot-value (gr8s::node-desired-state-snapshot store "n1")
                             'gr8s.node.v1::service-discovery-objects-json))
      (is (not (null (gethash (gr8s::core-resource-key "clustertrustbundles" nil "roots-a") resources)))))))
