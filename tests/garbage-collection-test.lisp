;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Validate actual background deletion of Pod and Secret dependents, immutable
;;;; owner identity across name reuse, and the Kubernetes protobuf owner fields.

(in-package #:gr8s/tests)
(def-suite garbage-collection :in gr8s)
(in-suite garbage-collection)

(defun test-owner-reference (pod)
  "Build an owner reference using the Pod's actual server-assigned UID."
  (gr8s::core-object "apiVersion" "v1" "kind" "Pod" "name" (pod-name pod) "uid" (pod-uid pod)))

(test owner-references-retain-live-dependents-and-collect-real-orphans
  (with-temporary-store (store directory)
    (values directory)
    (let* ((runtime (make-fake-runtime)) (reconciler (make-reconciler store runtime))
           (parent (create-pod store (parse-pod *valid-pod-json*)))
           (child-object (com.inuoe.jzon:parse *valid-pod-json*)))
      (setf (gethash "name" (gethash "metadata" child-object)) "child"
            (gethash "ownerReferences" (gethash "metadata" child-object)) (vector (test-owner-reference parent)))
      (let ((child (create-pod store (parse-pod child-object))))
        (gr8s::create-core-resource store "secrets"
          (gr8s::core-object "metadata" (gr8s::core-object "name" "plugin-tls" "ownerReferences" (vector (test-owner-reference parent)))
                             "data" (gr8s::core-object "tls" "Ynl0ZXM=")) "default")
        (gr8s::reconcile-all reconciler)
        (gr8s::collect-orphaned-api-objects reconciler)
        (is (= 2 (length (list-pods store))))
        (is (= 1 (length (gr8s::list-core-resources store "secrets"))))
        (gr8s::delete-reconciled-pod reconciler "default" "hello")
        ;; A new owner with the same name cannot adopt the old owner's children.
        (create-pod store (parse-pod *valid-pod-json*))
        (gr8s::collect-orphaned-api-objects reconciler)
        (signals kubernetes-error (get-pod store "default" "child"))
        (is (null (runtime-observe runtime (pod-uid child))))
        (is (null (gr8s::list-core-resources store "secrets")))))))

(test garbage-collector-keeps-unknown-owner-kinds
  (with-temporary-store (store directory)
    (values directory)
    (let ((object (com.inuoe.jzon:parse *valid-pod-json*)))
      (setf (gethash "ownerReferences" (gethash "metadata" object))
            (vector (gr8s::core-object "apiVersion" "example.org/v1" "kind" "FutureOwner" "name" "future" "uid" "future-uid")))
      (create-pod store (parse-pod object))
      (gr8s::collect-orphaned-api-objects (make-reconciler store (make-fake-runtime)))
      (is (= 1 (length (list-pods store)))))))

(test protobuf-owner-references-preserve-upstream-field-identities
  (let* ((owner (core-test-protobuf (list (list 5 "v1") (list 1 "Pod") (list 3 "sonobuoy") (list 4 "owner-uid"))))
         (metadata (core-test-protobuf (list (list 1 "tls-secret") (list 3 "sonobuoy") (list 13 owner))))
         (bytes (core-test-protobuf-envelope "Secret" (list (list 1 metadata))))
         (decoded (gr8s::decode-core-resource-protobuf bytes "Secret"))
         (reference (aref (gethash "ownerReferences" (gethash "metadata" decoded)) 0)))
    (is (equal "v1" (gethash "apiVersion" reference)))
    (is (equal "Pod" (gethash "kind" reference)))
    (is (equal "sonobuoy" (gethash "name" reference)))
    (is (equal "owner-uid" (gethash "uid" reference)))))

(test stale-deletion-preconditions-cannot-remove-a-reused-pod-name
  (with-temporary-store (store directory)
    (values directory)
    (let* ((reconciler (make-reconciler store (make-fake-runtime)))
           (old (create-pod store (parse-pod *valid-pod-json*))))
      (gr8s::delete-reconciled-pod reconciler "default" "hello")
      (let ((new (create-pod store (parse-pod *valid-pod-json*))))
        (signals kubernetes-error
          (gr8s::delete-reconciled-pod reconciler "default" "hello" :uid (pod-uid old)))
        (is (equal (pod-uid new) (pod-uid (get-pod store "default" "hello"))))
        (is (not (gr8s::deletion-requested-p new)))))))

(defun gc-test-configmap (store name &rest owners)
  "Create a ConfigMap in alpha owned by the objects OWNERS, each a stored object or a kind and name list."
  (gr8s::create-core-resource
   store "configmaps"
   (gr8s::core-object
    "apiVersion" "v1" "kind" "ConfigMap"
    "metadata" (gr8s::core-object
                "name" name
                "ownerReferences"
                (map 'vector (lambda (owner)
                               (if (hash-table-p owner)
                                   (gr8s::core-object "apiVersion" "v1" "kind" "ConfigMap"
                                                      "name" (gethash "name" (gethash "metadata" owner))
                                                      "uid" (gethash "uid" (gethash "metadata" owner))
                                                      "blockOwnerDeletion" t)
                                   (gr8s::core-object "apiVersion" "v1" "kind" "ConfigMap"
                                                      "name" (first owner) "uid" (second owner))))
                     owners)))
   "alpha"))

(test collector-drops-an-absent-owner-while-another-keeps-the-dependent
  (with-temporary-store (store path)
    (values path)
    (let* ((reconciler (make-reconciler store (make-fake-runtime)))
           (live (gc-test-configmap store "live"))
           (dependent (gc-test-configmap store "dependent" live '("gone" "gone-uid"))))
      (values dependent)
      (gr8s::collect-orphaned-api-objects reconciler)
      (let ((owners (gethash "ownerReferences"
                             (gethash "metadata" (gr8s::get-core-resource store "configmaps" "alpha" "dependent")))))
        (is (= 1 (length owners)))
        (is (equal "live" (gethash "name" (aref owners 0)))))
      ;; An unrelated dependent whose only owner is absent is still collected.
      (gc-test-configmap store "orphan" '("gone" "gone-uid"))
      (gr8s::collect-orphaned-api-objects reconciler)
      (signals kubernetes-error (gr8s::get-core-resource store "configmaps" "alpha" "orphan")))))

(test collector-drops-an-absent-owner-from-a-pod-with-a-live-owner
  (with-temporary-store (store path)
    (values path)
    (let* ((reconciler (make-reconciler store (make-fake-runtime)))
           (live (gc-test-configmap store "live"))
           (object (gr8s::copy-core-object (pod-to-object (parse-pod *valid-pod-json*)))))
      (setf (gethash "namespace" (gethash "metadata" object)) "alpha"
            (gethash "ownerReferences" (gethash "metadata" object))
            (vector (gr8s::core-object "apiVersion" "v1" "kind" "ConfigMap" "name" "live"
                                       "uid" (gethash "uid" (gethash "metadata" live)))
                    (gr8s::core-object "apiVersion" "v1" "kind" "ConfigMap" "name" "gone" "uid" "gone-uid")))
      (let ((pod (create-pod store (parse-pod object))))
        (gr8s::collect-orphaned-api-objects reconciler)
        (let ((current (get-pod store "alpha" (pod-name pod))))
          (is (not (gr8s::deletion-requested-p current)))
          (is (= 1 (length (gethash "ownerReferences" (gethash "metadata" (pod-to-object current)))))))))))

(test foreground-deletion-holds-any-core-kind-for-its-blocking-dependents
  (with-temporary-store (store path)
    (values path)
    (let* ((reconciler (make-reconciler store (make-fake-runtime)))
           (owner (gc-test-configmap store "owner"))
           (dependent (gc-test-configmap store "dependent" owner)))
      (values dependent)
      (is-true (gr8s::core-deletion-held-p store "configmaps" "alpha" "owner" "Foreground"))
      (is-false (gr8s::core-deletion-held-p store "configmaps" "alpha" "owner" "Background"))
      (is-false (gr8s::core-deletion-held-p store "configmaps" "alpha" "dependent" "Foreground"))
      (gr8s::delete-workload-resource store "configmaps" "alpha" "owner" :policy "Foreground")
      (let ((held (gethash "metadata" (gr8s::get-core-resource store "configmaps" "alpha" "owner"))))
        (is-true (gethash "deletionTimestamp" held))
        (is (equalp #("foregroundDeletion") (gethash "finalizers" held))))
      (gr8s::process-workload-deletions reconciler)
      (signals kubernetes-error (gr8s::get-core-resource store "configmaps" "alpha" "dependent"))
      (gr8s::process-workload-deletions reconciler)
      (signals kubernetes-error (gr8s::get-core-resource store "configmaps" "alpha" "owner"))
      (is (zerop (hash-table-count (gr8s::pod-store-workload-deletions store)))))))

(test orphan-deletion-of-a-core-kind-detaches-its-dependents
  (with-temporary-store (store path)
    (values path)
    (let* ((reconciler (make-reconciler store (make-fake-runtime)))
           (owner (gc-test-configmap store "owner"))
           (dependent (gc-test-configmap store "dependent" owner)))
      (values dependent)
      (is-true (gr8s::core-deletion-held-p store "configmaps" "alpha" "owner" "Orphan"))
      (gr8s::delete-workload-resource store "configmaps" "alpha" "owner" :policy "Orphan")
      (is (equalp #("orphan") (gethash "finalizers" (gethash "metadata" (gr8s::get-core-resource store "configmaps" "alpha" "owner")))))
      (gr8s::process-workload-deletions reconciler)
      (signals kubernetes-error (gr8s::get-core-resource store "configmaps" "alpha" "owner"))
      (let ((metadata (gethash "metadata" (gr8s::get-core-resource store "configmaps" "alpha" "dependent"))))
        (is (zerop (length (gethash "ownerReferences" metadata))))))))
