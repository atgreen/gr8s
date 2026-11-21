;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Cluster registry trust (podster-b0c): a ClusterTrustBundle annotated
;;;; gr8s.io/registries makes its CAs trusted for exactly those registries on
;;;; every node, joined with each node's --registry-ca, with no restart.

(in-package #:gr8s/tests)

(in-suite gr8s)

(defmacro with-registry-trust-directory ((directory &key flag-files) &body body)
  "Run BODY with this node's registry trust isolated in a fresh DIRECTORY."
  `(let* ((,directory (merge-pathnames (format nil "gr8s-registry-trust-~36R/" (random (expt 36 10)))
                                       (uiop:temporary-directory)))
          (gr8s.image-distribution::*registry-trust-directory* nil)
          (gr8s.image-distribution::*registry-ca-flag-files* nil)
          (gr8s.image-distribution::*registry-ca-files* nil)
          (gr8s.image-distribution::*cluster-registry-trust* nil))
     (unwind-protect
          (progn (gr8s.image-distribution::start-registry-trust ,directory ,flag-files)
                 ,@body)
       (uiop:delete-directory-tree ,directory :validate t :if-does-not-exist :ignore))))

(defun registry-trust-bundle (name registries pem)
  (gr8s.resources::core-object
   "apiVersion" "certificates.k8s.io/v1" "kind" "ClusterTrustBundle"
   "metadata" (if registries
                  (gr8s.resources::core-object
                   "name" name "annotations"
                   (gr8s.resources::core-object "gr8s.io/registries" registries))
                  (gr8s.resources::core-object "name" name))
   "spec" (gr8s.resources::core-object "trustBundle" pem)))

(defun registry-trust-ca-file (host)
  (getf (gr8s.image-distribution::registry-tls-arguments host) :ca-file))

(test registry-trust-annotation-names-registries-strictly
  (is (equal '("registry.lab:30500" "ghcr.example")
             (gr8s.image-distribution::registry-trust-annotation-hosts " registry.lab:30500,  ghcr.example ")))
  (is (equal '("a.example" "b.example")
             (gr8s.image-distribution::registry-trust-annotation-hosts "a.example b.example")))
  (signals error (gr8s.image-distribution::registry-trust-annotation-hosts " , "))
  (signals error (gr8s.image-distribution::registry-trust-annotation-hosts "bad/host"))
  ;; HOST:443 and HOST are one registry.
  (signals error (gr8s.image-distribution::registry-trust-annotation-hosts "r.example, R.example:443")))

(test cluster-registry-trust-joins-the-bundles-naming-each-registry
  (is (equal '(("ghcr.example" "B") ("registry.lab:30500" "A" "B"))
             (gr8s.image-distribution::cluster-registry-trust
              (list (registry-trust-bundle "b" "registry.lab:30500, ghcr.example" "B")
                    (registry-trust-bundle "a" "Registry.Lab:30500" "A")
                    ;; Not a registry bundle, and a malformed one: neither trusted.
                    (registry-trust-bundle "plain" nil "C")
                    (registry-trust-bundle "bad" "ok.example, bad/host" "D"))))))

(test cluster-registry-trust-adds-to-the-node-flag-and-survives-restart
  (let ((flag (merge-pathnames (format nil "gr8s-registry-flag-~36R.pem" (random (expt 36 10)))
                               (uiop:temporary-directory))))
    (alexandria:write-string-into-file "FLAG" flag :if-exists :supersede)
    (unwind-protect
         (with-registry-trust-directory (directory :flag-files (list (cons "registry.lab:30500" flag)
                                                                     (cons "flag-only.example" flag)))
           (is (equal (namestring flag) (namestring (registry-trust-ca-file "registry.lab:30500"))))
           (gr8s.image-distribution::install-cluster-registry-trust
            '(("cluster-only.example" "CLUSTER") ("registry.lab:30500" "CLUSTER")))
           ;; A host both name trusts both; the flag alone still covers its own.
           (is (equal (format nil "FLAG~%CLUSTER")
                      (alexandria:read-file-into-string (registry-trust-ca-file "registry.lab:30500"))))
           (is (equal "CLUSTER" (alexandria:read-file-into-string (registry-trust-ca-file "cluster-only.example"))))
           (is (equal (namestring flag) (namestring (registry-trust-ca-file "flag-only.example"))))
           (is (null (registry-trust-ca-file "other.example")))
           ;; A restarted node verifies as before, ahead of its first snapshot.
           (let ((gr8s.image-distribution::*registry-ca-files* nil)
                 (gr8s.image-distribution::*cluster-registry-trust* nil))
             (gr8s.image-distribution::start-registry-trust
              directory (list (cons "registry.lab:30500" flag) (cons "flag-only.example" flag)))
             (is (equal "CLUSTER" (alexandria:read-file-into-string (registry-trust-ca-file "cluster-only.example")))))
           ;; Removing the cluster's CA takes effect now, and leaves no file behind.
           (gr8s.image-distribution::install-cluster-registry-trust nil)
           (is (null (registry-trust-ca-file "cluster-only.example")))
           (is (equal (namestring flag) (namestring (registry-trust-ca-file "registry.lab:30500"))))
           (is (null (directory (merge-pathnames "*.pem" directory)))))
      (ignore-errors (delete-file flag)))))

(test snapshot-cluster-trust-bundles-verify-a-private-registry
  (with-registry-tls-test-pkis (directory pki)
    (multiple-value-bind (certificate key)
        (registry-tls-test-leaf pki directory "ip" :ip-addresses '("127.0.0.1"))
      (multiple-value-bind (port stop)
          (registry-tls-test-backend certificate key (lambda (path) (declare (ignore path)) (values 200 nil "{}")))
        (unwind-protect
             (with-registry-trust-directory (trust-directory)
               (let ((host (format nil "127.0.0.1:~D" port))
                     (resources (make-hash-table :test 'equal)))
                 (flet ((proxy () (with-full-tls-handshakes
                                   (gr8s.image-distribution::proxy-oci-registry-request :get host "/v2/" nil)))
                        (snapshot (&rest bundles)
                          (clrhash resources)
                          (dolist (bundle bundles)
                            (setf (gethash (list "clustertrustbundles" nil (gethash "name" (gethash "metadata" bundle)))
                                           resources)
                                  bundle))
                          (gr8s.agent::install-snapshot-registry-trust resources)))
                   (signals error (proxy))
                   (let ((ca (alexandria:read-file-into-string (registry-tls-test-ca pki))))
                     ;; Trusted for another registry only: still refused.
                     (snapshot (registry-trust-bundle "elsewhere" "other.example:5000" ca))
                     (signals error (proxy))
                     (snapshot (registry-trust-bundle "lab" host ca))
                     (is (= 200 (nth-value 1 (proxy))))
                     ;; The bundle deleted: refused again, without a restart.
                     (snapshot)
                     (signals error (proxy))))))
          (funcall stop))))))

(test clustertrustbundle-registries-annotation-is-validated
  (with-temporary-store (store directory)
    (let ((pem (ctb-test-ca-pem "registry-trust")))
      (signals gr8s.model::kubernetes-error
        (gr8s.resources::create-core-resource
         store "clustertrustbundles" (registry-trust-bundle "bad" "registry.lab:30500, bad/host" pem) nil))
      (gr8s.resources::create-core-resource
       store "clustertrustbundles" (registry-trust-bundle "lab" "registry.lab:30500" pem) nil)
      ;; An annotation added by a metadata-only update is held to the same rules.
      (signals gr8s.model::kubernetes-error
        (gr8s.resources::update-core-resource
         store "clustertrustbundles" nil "lab"
         (lambda (object)
           (setf (gethash "gr8s.io/registries" (gethash "annotations" (gethash "metadata" object)))
                 "a.example a.example")
           object))))))

(test node-projection-carries-only-the-registries-annotation
  (let* ((bundle (registry-trust-bundle "lab" "registry.lab:30500" "PEM"))
         (public nil))
    (setf (gethash "other" (gethash "annotations" (gethash "metadata" bundle))) "private")
    (setf public (gr8s.kubelet::service-discovery-public-object bundle))
    (is (equal '("gr8s.io/registries")
               (alexandria:hash-table-keys (gethash "annotations" (gethash "metadata" public)))))
    (is (null (gethash "annotations" (gethash "metadata" (gr8s.kubelet::service-discovery-public-object
                                                           (registry-trust-bundle "plain" nil "PEM"))))))))
