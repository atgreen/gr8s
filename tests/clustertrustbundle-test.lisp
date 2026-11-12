;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; ClusterTrustBundle (KEP-3257/4317) is a cluster-scoped certificates.k8s.io
;;;; /v1 resource carrying a signer's CA trust anchors. Exercise its CRUD
;;;; and that discovery advertises it cluster-scoped under v1.

(in-package #:gr8s/tests)

(in-suite gr8s)

;;; Real self-signed CA certificates: ClusterTrustBundles accept nothing else (v1.37 validation).

(defvar *ctb-test-cas* (make-hash-table :test #'equal))

(defun ctb-test-ca-pem (tag)
  "A distinct CA certificate PEM per TAG, ending in a newline, made with the cluster PKI code."
  (or (gethash tag *ctb-test-cas*)
      (setf (gethash tag *ctb-test-cas*)
            (let ((directory (uiop:ensure-directory-pathname
                              (merge-pathnames (format nil "gr8s-ctb-test-~A-~D" tag (random 1000000000))
                                               (uiop:temporary-directory)))))
              (unwind-protect
                   (let ((pem (gr8s.controllers::pod-certificate-ca-pem (gr8s.security::ensure-cluster-pki directory))))
                     (if (uiop:string-suffix-p pem (string #\Newline)) pem (format nil "~A~%" pem)))
                (uiop:delete-directory-tree directory :validate t :if-does-not-exist :ignore))))))


(test clustertrustbundle-is-a-cluster-scoped-certificates-v1-resource
  (with-temporary-store (store directory)
    (let ((object (gr8s.resources::core-object
                   "apiVersion" "certificates.k8s.io/v1" "kind" "ClusterTrustBundle"
                   "metadata" (gr8s.resources::core-object "name" "servicedns.podcert.ate.dev:identity:ate-roots")
                   "spec" (gr8s.resources::core-object
                           "signerName" "servicedns.podcert.ate.dev/identity"
                           "trustBundle" (ctb-test-ca-pem "ate-roots")))))
      ;; Cluster-scoped: created with a NIL namespace, and durable CRUD works.
      (gr8s.resources::create-core-resource store "clustertrustbundles" object nil)
      (let ((got (gr8s.resources::get-core-resource store "clustertrustbundles" nil "servicedns.podcert.ate.dev:identity:ate-roots")))
        (is (string= "ClusterTrustBundle" (gethash "kind" got)))
        (is (string= "certificates.k8s.io/v1" (gethash "apiVersion" got)))
        (is (string= "servicedns.podcert.ate.dev/identity"
                     (gethash "signerName" (gethash "spec" got)))))
      (is (= 1 (length (gr8s.resources::list-core-resources store "clustertrustbundles"))))
      (gr8s.resources::delete-core-resource store "clustertrustbundles" nil "servicedns.podcert.ate.dev:identity:ate-roots")
      (is (= 0 (length (gr8s.resources::list-core-resources store "clustertrustbundles"))))
      ;; A non-object spec is rejected.
      (signals gr8s.model::kubernetes-error
        (gr8s.resources::create-core-resource
         store "clustertrustbundles"
         (gr8s.resources::core-object "apiVersion" "certificates.k8s.io/v1" "kind" "ClusterTrustBundle"
                            "metadata" (gr8s.resources::core-object "name" "bad") "spec" "not-an-object")
         nil)))
    ;; Discovery advertises it, cluster-scoped, under certificates.k8s.io/v1.
    (let ((entry (find "clustertrustbundles"
                       (gr8s.resources::stored-resource-discovery "certificates.k8s.io/v1")
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
      (gr8s.resources::create-core-resource
       store "clustertrustbundles"
       (gr8s.resources::core-object "apiVersion" "certificates.k8s.io/v1" "kind" "ClusterTrustBundle"
                          "metadata" (gr8s.resources::core-object "name" name)
                          "spec" (gr8s.resources::core-object "signerName" "podidentity.podcert.ate.dev/identity"
                                                    "trustBundle" (ctb-test-ca-pem "primary")))
       nil)
      (is (string= name (gethash "name" (gethash "metadata"
                          (gr8s.resources::get-core-resource store "clustertrustbundles" nil name))))))))

(test clustertrustbundle-decodes-from-client-go-protobuf
  ;; client-go encodes built-in API objects as protobuf; gr8s must decode a
  ;; ClusterTrustBundle create body (Agent Substrate's podcertcontroller does).
  (let* ((meta (core-test-protobuf (list (list 1 "roots"))))
         (spec (core-test-protobuf (list (list 1 "servicedns.podcert.ate.dev/identity")
                                         (list 2 (format nil "-----BEGIN CERTIFICATE-----~%X~%-----END CERTIFICATE-----~%")))))
         (bytes (core-test-protobuf-envelope "ClusterTrustBundle"
                                             (list (list 1 meta) (list 2 spec)) "certificates.k8s.io/v1"))
         (object (gr8s.resources::decode-core-resource-protobuf bytes "ClusterTrustBundle")))
    (is (string= "ClusterTrustBundle" (gethash "kind" object)))
    (is (string= "roots" (gethash "name" (gethash "metadata" object))))
    (is (string= "servicedns.podcert.ate.dev/identity" (gethash "signerName" (gethash "spec" object))))
    (is (search "BEGIN CERTIFICATE" (gethash "trustBundle" (gethash "spec" object))))))

(defun ctb-object (name signer &optional live)
  (let ((metadata (gr8s.resources::core-object "name" (format nil "~A:~A" (substitute #\: #\/ signer) name))))
    (when live (setf (gethash "labels" metadata) (gr8s.resources::core-object "canarying" "live")))
    (gr8s.resources::core-object "apiVersion" "certificates.k8s.io/v1" "kind" "ClusterTrustBundle"
                       "metadata" metadata
                       "spec" (gr8s.resources::core-object "signerName" signer "trustBundle" (ctb-test-ca-pem name)))))

(defun ctb-source-pem (store source)
  (trivial-utf-8:utf-8-bytes-to-string
   (second (first (gr8s.kubelet::cluster-trust-bundle-volume-files store source #o644)))))

(test clustertrustbundle-projected-source-validates-and-resolves
  ;; Validation: a clusterTrustBundle projected source needs a path and exactly
  ;; one of name / signerName.
  (finishes
    (gr8s.kubelet::validate-projected-source
     (gr8s.resources::core-object "sources"
                        (vector (gr8s.resources::core-object "clusterTrustBundle"
                                                   (gr8s.resources::core-object "path" "roots.pem" "signerName" "s"))))))
  (signals gr8s.model::kubernetes-error
    (gr8s.kubelet::validate-projected-source
     (gr8s.resources::core-object "sources"
                        (vector (gr8s.resources::core-object "clusterTrustBundle"
                                                   (gr8s.resources::core-object "signerName" "s")))))) ; no path
  (signals gr8s.model::kubernetes-error
    (gr8s.kubelet::validate-projected-source
     (gr8s.resources::core-object "sources"
                        (vector (gr8s.resources::core-object "clusterTrustBundle"
                                                   (gr8s.resources::core-object "path" "r.pem" "name" "a" "signerName" "s")))))) ; both
  ;; Resolution against the store: name, signerName (concatenated), label-narrowed.
  (with-temporary-store (store directory)
    (gr8s.resources::create-core-resource store "clustertrustbundles" (ctb-object "roots-a" "sds.example.com/identity" t) nil)
    (gr8s.resources::create-core-resource store "clustertrustbundles" (ctb-object "roots-b" "sds.example.com/identity" nil) nil)
    (is (string= (ctb-test-ca-pem "roots-a")
                 (ctb-source-pem store (gr8s.resources::core-object "path" "b.pem" "name" "sds.example.com:identity:roots-a"))))
    ;; As in the kubelet (and the 1.37 conformance specs), an empty labelSelector
    ;; selects every bundle of the signer, while an absent one selects none.
    (is (string= (concatenate 'string (ctb-test-ca-pem "roots-a") (ctb-test-ca-pem "roots-b"))
                 (ctb-source-pem store (gr8s.resources::core-object "path" "b.pem" "signerName" "sds.example.com/identity"
                                                          "labelSelector" (gr8s.resources::core-object)))))
    (signals gr8s.runtime::runtime-error
      (gr8s.kubelet::cluster-trust-bundle-volume-files store (gr8s.resources::core-object "path" "b.pem" "signerName" "sds.example.com/identity") #o644))
    (is (string= "" (ctb-source-pem store (gr8s.resources::core-object "path" "b.pem" "signerName" "sds.example.com/identity" "optional" t))))
    (is (string= (ctb-test-ca-pem "roots-b")
                 (ctb-source-pem store (gr8s.resources::core-object "path" "b.pem" "signerName" "sds.example.com/identity"
                                                          "labelSelector" (gr8s.resources::core-object
                                                                           "matchExpressions"
                                                                           (vector (gr8s.resources::core-object "key" "canarying" "operator" "DoesNotExist")))))))
    (is (string= (ctb-test-ca-pem "roots-a")
                 (ctb-source-pem store (gr8s.resources::core-object "path" "b.pem" "signerName" "sds.example.com/identity"
                                                          "labelSelector" (gr8s.resources::core-object
                                                                           "matchLabels" (gr8s.resources::core-object "canarying" "live"))))))
    ;; A missing named bundle fails unless optional, as a mount the kubelet retries
    ;; while the Pod waits, not as an invalid Pod.
    (signals gr8s.runtime::runtime-error
      (gr8s.kubelet::cluster-trust-bundle-volume-files store (gr8s.resources::core-object "path" "b.pem" "name" "absent") #o644))
    (is (string= "" (ctb-source-pem store (gr8s.resources::core-object "path" "b.pem" "name" "absent" "optional" t))))
    ;; Projected to the node via the service-discovery snapshot.
    (let ((resources (make-hash-table :test #'equal)))
      (gr8s.kubelet::install-service-discovery-projection
       resources (slot-value (gr8s.controllers::node-desired-state-snapshot store "n1")
                             'gr8s.node.v1::service-discovery-objects-json))
      (let ((projected (gethash (gr8s.resources::core-resource-key "clustertrustbundles" nil "sds.example.com:identity:roots-a") resources)))
        (is (not (null projected)))
        ;; Labels must survive projection so a signerName+labelSelector volume
        ;; can match (ate's postgres-ca mounts by podcert.ate.dev/canarying=live).
        (is (string= "live" (gethash "canarying" (gethash "labels" (gethash "metadata" projected)))))))))

(test clustertrustbundles-are-validated-as-upstream
  ;; pkg/apis/certificates/validation at v1.37: signer-linked names carry the
  ;; signer as a prefix, unlinked ones have no colon, the bundle holds only CA
  ;; certificates, and the signer cannot change.
  (with-temporary-store (store directory)
    (flet ((bundle (name signer pem)
             (gr8s.resources::core-object "apiVersion" "certificates.k8s.io/v1" "kind" "ClusterTrustBundle"
                                "metadata" (gr8s.resources::core-object "name" name)
                                "spec" (if signer
                                           (gr8s.resources::core-object "signerName" signer "trustBundle" pem)
                                           (gr8s.resources::core-object "trustBundle" pem))))
           (rejected (object)
             (handler-case (progn (gr8s.resources::create-core-resource store "clustertrustbundles" object nil) nil)
               (gr8s.model::kubernetes-error (condition) (gr8s.model::kubernetes-error-message condition)))))
      (let ((ca (ctb-test-ca-pem "valid")))
        (finishes (gr8s.resources::create-core-resource store "clustertrustbundles" (bundle "plain" nil ca) nil))
        (finishes (gr8s.resources::create-core-resource store "clustertrustbundles"
                                              (bundle "example.com:signer:one" "example.com/signer" ca) nil))
        (is (search "must be named with prefix example.com:signer:"
                    (rejected (bundle "other-name" "example.com/signer" ca))))
        (is (search "must not have \":\" in its name" (rejected (bundle "has:colon" nil ca))))
        (is (search "fully qualified domain" (rejected (bundle "nodot:one" "nodot" ca))))
        (is (search "at least one trust anchor" (rejected (bundle "empty" nil ""))))
        (is (search "does not parse as X.509"
                    (rejected (bundle "junk" nil (format nil "-----BEGIN CERTIFICATE-----~%MIIBtest~%-----END CERTIFICATE-----~%")))))
        (is (search "bad block type"
                    (rejected (bundle "key" nil (format nil "-----BEGIN PRIVATE KEY-----~%MIIBtest~%-----END PRIVATE KEY-----~%")))))
        (is (search "duplicate trust anchor" (rejected (bundle "twice" nil (concatenate 'string ca ca)))))
        ;; The signer is immutable; the bundle may be replaced with other CAs.
        (signals gr8s.model::kubernetes-error
          (gr8s.resources::update-core-resource store "clustertrustbundles" nil "example.com:signer:one"
            (lambda (current) (setf (gethash "signerName" (gethash "spec" current)) "example.com/other") current)))
        (finishes
          (gr8s.resources::update-core-resource store "clustertrustbundles" nil "example.com:signer:one"
            (lambda (current) (setf (gethash "trustBundle" (gethash "spec" current)) (ctb-test-ca-pem "rotated")) current)))))))

(test truncated-der-is-refused-before-it-is-parsed
  ;; pure-tls's DER parser loops without end on a truncated constructed element,
  ;; so gr8s checks untrusted DER first. A SEQUENCE claiming 437 bytes in 6:
  (let ((truncated (coerce #(48 130 1 181 235 45) '(vector (unsigned-byte 8)))))
    (is (not (gr8s.security::der-well-formed-p truncated)))
    (is (not (gr8s.security::der-well-formed-p (coerce #(48 3 2 1) '(vector (unsigned-byte 8))))))
    (is (gr8s.security::der-well-formed-p (coerce #(48 3 2 1 5) '(vector (unsigned-byte 8)))))
    (signals gr8s.model::kubernetes-error
      (gr8s.security::parse-and-verify-certificate-request
       (trivial-utf-8:string-to-utf-8-bytes (pure-tls/acme::wrap-pem "CERTIFICATE REQUEST" truncated))))))
