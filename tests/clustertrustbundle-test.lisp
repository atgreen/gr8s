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

(test clustertrustbundle-accepts-kep3257-signer-linked-colon-name
  ;; A signer-linked ClusterTrustBundle is named <signerName, final / as :>:<suffix>
  ;; (KEP-3257), so its name carries colons and is not a DNS subdomain. gr8s must
  ;; accept it -- Agent Substrate's podcertcontroller creates exactly these.
  (with-temporary-store (store directory)
    (let ((name "podidentity.podcert.ate.dev:identity:primary-bundle"))
      (gr8s::create-core-resource
       store "clustertrustbundles"
       (gr8s::core-object "apiVersion" "certificates.k8s.io/v1" "kind" "ClusterTrustBundle"
                          "metadata" (gr8s::core-object "name" name)
                          "spec" (gr8s::core-object "signerName" "podidentity.podcert.ate.dev/identity"
                                                    "trustBundle" (format nil "-----BEGIN CERTIFICATE-----~%X~%-----END CERTIFICATE-----~%")))
       nil)
      (is (string= name (gethash "name" (gethash "metadata"
                          (gr8s::get-core-resource store "clustertrustbundles" nil name))))))))

(test clustertrustbundle-decodes-from-client-go-protobuf
  ;; client-go encodes built-in API objects as protobuf; gr8s must decode a
  ;; ClusterTrustBundle create body (Agent Substrate's podcertcontroller does).
  (let* ((meta (core-test-protobuf (list (list 1 "roots"))))
         (spec (core-test-protobuf (list (list 1 "servicedns.podcert.ate.dev/identity")
                                         (list 2 (format nil "-----BEGIN CERTIFICATE-----~%X~%-----END CERTIFICATE-----~%")))))
         (bytes (core-test-protobuf-envelope "ClusterTrustBundle"
                                             (list (list 1 meta) (list 2 spec)) "certificates.k8s.io/v1"))
         (object (gr8s::decode-core-resource-protobuf bytes "ClusterTrustBundle")))
    (is (string= "ClusterTrustBundle" (gethash "kind" object)))
    (is (string= "roots" (gethash "name" (gethash "metadata" object))))
    (is (string= "servicedns.podcert.ate.dev/identity" (gethash "signerName" (gethash "spec" object))))
    (is (search "BEGIN CERTIFICATE" (gethash "trustBundle" (gethash "spec" object))))))

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
    ;; As in the kubelet (and the 1.37 conformance specs), an empty labelSelector
    ;; selects every bundle of the signer, while an absent one selects none.
    (is (string= (format nil "PEM-roots-a~%PEM-roots-b~%")
                 (ctb-source-pem store (gr8s::core-object "path" "b.pem" "signerName" "sds/identity"
                                                          "labelSelector" (gr8s::core-object)))))
    (signals gr8s:runtime-error
      (gr8s::cluster-trust-bundle-volume-files store (gr8s::core-object "path" "b.pem" "signerName" "sds/identity") #o644))
    (is (string= "" (ctb-source-pem store (gr8s::core-object "path" "b.pem" "signerName" "sds/identity" "optional" t))))
    (is (string= (format nil "PEM-roots-b~%")
                 (ctb-source-pem store (gr8s::core-object "path" "b.pem" "signerName" "sds/identity"
                                                          "labelSelector" (gr8s::core-object
                                                                           "matchExpressions"
                                                                           (vector (gr8s::core-object "key" "canarying" "operator" "DoesNotExist")))))))
    (is (string= (format nil "PEM-roots-a~%")
                 (ctb-source-pem store (gr8s::core-object "path" "b.pem" "signerName" "sds/identity"
                                                          "labelSelector" (gr8s::core-object
                                                                           "matchLabels" (gr8s::core-object "canarying" "live"))))))
    ;; A missing named bundle fails unless optional, as a mount the kubelet retries
    ;; while the Pod waits, not as an invalid Pod.
    (signals gr8s:runtime-error
      (gr8s::cluster-trust-bundle-volume-files store (gr8s::core-object "path" "b.pem" "name" "absent") #o644))
    (is (string= "" (ctb-source-pem store (gr8s::core-object "path" "b.pem" "name" "absent" "optional" t))))
    ;; Projected to the node via the service-discovery snapshot.
    (let ((resources (make-hash-table :test #'equal)))
      (gr8s::install-service-discovery-projection
       resources (slot-value (gr8s::node-desired-state-snapshot store "n1")
                             'gr8s.node.v1::service-discovery-objects-json))
      (let ((projected (gethash (gr8s::core-resource-key "clustertrustbundles" nil "roots-a") resources)))
        (is (not (null projected)))
        ;; Labels must survive projection so a signerName+labelSelector volume
        ;; can match (ate's postgres-ca mounts by podcert.ate.dev/canarying=live).
        (is (string= "live" (gethash "canarying" (gethash "labels" (gethash "metadata" projected)))))))))
