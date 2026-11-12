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
  (gr8s.resources::core-object "apiVersion" "v1" "kind" "Pod" "name" (pod-name pod) "uid" (pod-uid pod)))

(test owner-references-retain-live-dependents-and-collect-real-orphans
  (with-temporary-store (store directory)
    (values directory)
    (let* ((runtime (make-fake-runtime)) (reconciler (make-reconciler store runtime))
           (parent (create-pod store (parse-pod *valid-pod-json*)))
           (child-object (com.inuoe.jzon:parse *valid-pod-json*)))
      (setf (gethash "name" (gethash "metadata" child-object)) "child"
            (gethash "ownerReferences" (gethash "metadata" child-object)) (vector (test-owner-reference parent)))
      (let ((child (create-pod store (parse-pod child-object))))
        (gr8s.resources::create-core-resource store "secrets"
          (gr8s.resources::core-object "metadata" (gr8s.resources::core-object "name" "plugin-tls" "ownerReferences" (vector (test-owner-reference parent)))
                             "data" (gr8s.resources::core-object "tls" "Ynl0ZXM=")) "default")
        (gr8s.kubelet::reconcile-all reconciler)
        (gr8s.controllers::collect-orphaned-api-objects reconciler)
        (is (= 2 (length (list-pods store))))
        (is (= 1 (length (gr8s.resources::list-core-resources store "secrets"))))
        (gr8s.kubelet::delete-reconciled-pod reconciler "default" "hello")
        ;; A new owner with the same name cannot adopt the old owner's children.
        (create-pod store (parse-pod *valid-pod-json*))
        (gr8s.controllers::collect-orphaned-api-objects reconciler)
        (signals kubernetes-error (get-pod store "default" "child"))
        (is (null (runtime-observe runtime (pod-uid child))))
        (is (null (gr8s.resources::list-core-resources store "secrets")))))))

(test garbage-collector-keeps-unknown-owner-kinds
  (with-temporary-store (store directory)
    (values directory)
    (let ((object (com.inuoe.jzon:parse *valid-pod-json*)))
      (setf (gethash "ownerReferences" (gethash "metadata" object))
            (vector (gr8s.resources::core-object "apiVersion" "example.org/v1" "kind" "FutureOwner" "name" "future" "uid" "future-uid")))
      (create-pod store (parse-pod object))
      (gr8s.controllers::collect-orphaned-api-objects (make-reconciler store (make-fake-runtime)))
      (is (= 1 (length (list-pods store)))))))

(test protobuf-owner-references-preserve-upstream-field-identities
  (let* ((owner (core-test-protobuf (list (list 5 "v1") (list 1 "Pod") (list 3 "sonobuoy") (list 4 "owner-uid"))))
         (metadata (core-test-protobuf (list (list 1 "tls-secret") (list 3 "sonobuoy") (list 13 owner))))
         (bytes (core-test-protobuf-envelope "Secret" (list (list 1 metadata))))
         (decoded (gr8s.resources::decode-core-resource-protobuf bytes "Secret"))
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
      (gr8s.kubelet::delete-reconciled-pod reconciler "default" "hello")
      (let ((new (create-pod store (parse-pod *valid-pod-json*))))
        (signals kubernetes-error
          (gr8s.kubelet::delete-reconciled-pod reconciler "default" "hello" :uid (pod-uid old)))
        (is (equal (pod-uid new) (pod-uid (get-pod store "default" "hello"))))
        (is (not (gr8s.kubelet::deletion-requested-p new)))))))

(defun gc-test-configmap (store name &rest owners)
  "Create a ConfigMap in alpha owned by the objects OWNERS, each a stored object or a kind and name list."
  (gr8s.resources::create-core-resource
   store "configmaps"
   (gr8s.resources::core-object
    "apiVersion" "v1" "kind" "ConfigMap"
    "metadata" (gr8s.resources::core-object
                "name" name
                "ownerReferences"
                (map 'vector (lambda (owner)
                               (if (hash-table-p owner)
                                   (gr8s.resources::core-object "apiVersion" "v1" "kind" "ConfigMap"
                                                      "name" (gethash "name" (gethash "metadata" owner))
                                                      "uid" (gethash "uid" (gethash "metadata" owner))
                                                      "blockOwnerDeletion" t)
                                   (gr8s.resources::core-object "apiVersion" "v1" "kind" "ConfigMap"
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
      (gr8s.controllers::collect-orphaned-api-objects reconciler)
      (let ((owners (gethash "ownerReferences"
                             (gethash "metadata" (gr8s.resources::get-core-resource store "configmaps" "alpha" "dependent")))))
        (is (= 1 (length owners)))
        (is (equal "live" (gethash "name" (aref owners 0)))))
      ;; An unrelated dependent whose only owner is absent is still collected.
      (gc-test-configmap store "orphan" '("gone" "gone-uid"))
      (gr8s.controllers::collect-orphaned-api-objects reconciler)
      (signals kubernetes-error (gr8s.resources::get-core-resource store "configmaps" "alpha" "orphan")))))

(test collector-drops-an-absent-owner-from-a-pod-with-a-live-owner
  (with-temporary-store (store path)
    (values path)
    (let* ((reconciler (make-reconciler store (make-fake-runtime)))
           (live (gc-test-configmap store "live"))
           (object (gr8s.resources::copy-core-object (pod-to-object (parse-pod *valid-pod-json*)))))
      (setf (gethash "namespace" (gethash "metadata" object)) "alpha"
            (gethash "ownerReferences" (gethash "metadata" object))
            (vector (gr8s.resources::core-object "apiVersion" "v1" "kind" "ConfigMap" "name" "live"
                                       "uid" (gethash "uid" (gethash "metadata" live)))
                    (gr8s.resources::core-object "apiVersion" "v1" "kind" "ConfigMap" "name" "gone" "uid" "gone-uid")))
      (let ((pod (create-pod store (parse-pod object))))
        (gr8s.controllers::collect-orphaned-api-objects reconciler)
        (let ((current (get-pod store "alpha" (pod-name pod))))
          (is (not (gr8s.kubelet::deletion-requested-p current)))
          (is (= 1 (length (gethash "ownerReferences" (gethash "metadata" (pod-to-object current)))))))))))

(test foreground-deletion-holds-any-core-kind-for-its-blocking-dependents
  (with-temporary-store (store path)
    (values path)
    (let* ((reconciler (make-reconciler store (make-fake-runtime)))
           (owner (gc-test-configmap store "owner"))
           (dependent (gc-test-configmap store "dependent" owner)))
      (values dependent)
      (is-true (gr8s.controllers::core-deletion-held-p store "configmaps" "alpha" "owner" "Foreground"))
      (is-false (gr8s.controllers::core-deletion-held-p store "configmaps" "alpha" "owner" "Background"))
      (is-false (gr8s.controllers::core-deletion-held-p store "configmaps" "alpha" "dependent" "Foreground"))
      (gr8s.controllers::delete-workload-resource store "configmaps" "alpha" "owner" :policy "Foreground")
      (let ((held (gethash "metadata" (gr8s.resources::get-core-resource store "configmaps" "alpha" "owner"))))
        (is-true (gethash "deletionTimestamp" held))
        (is (equalp #("foregroundDeletion") (gethash "finalizers" held))))
      (gr8s.controllers::process-workload-deletions reconciler)
      (signals kubernetes-error (gr8s.resources::get-core-resource store "configmaps" "alpha" "dependent"))
      (gr8s.controllers::process-workload-deletions reconciler)
      (signals kubernetes-error (gr8s.resources::get-core-resource store "configmaps" "alpha" "owner"))
      (is (zerop (hash-table-count (gr8s.store::pod-store-workload-deletions store)))))))

(test orphan-deletion-of-a-core-kind-detaches-its-dependents
  (with-temporary-store (store path)
    (values path)
    (let* ((reconciler (make-reconciler store (make-fake-runtime)))
           (owner (gc-test-configmap store "owner"))
           (dependent (gc-test-configmap store "dependent" owner)))
      (values dependent)
      (is-true (gr8s.controllers::core-deletion-held-p store "configmaps" "alpha" "owner" "Orphan"))
      (gr8s.controllers::delete-workload-resource store "configmaps" "alpha" "owner" :policy "Orphan")
      (is (equalp #("orphan") (gethash "finalizers" (gethash "metadata" (gr8s.resources::get-core-resource store "configmaps" "alpha" "owner")))))
      (gr8s.controllers::process-workload-deletions reconciler)
      (signals kubernetes-error (gr8s.resources::get-core-resource store "configmaps" "alpha" "owner"))
      (let ((metadata (gethash "metadata" (gr8s.resources::get-core-resource store "configmaps" "alpha" "dependent"))))
        (is (zerop (length (gethash "ownerReferences" metadata))))))))

(test a-finalizer-holds-a-deleted-object-until-a-client-removes-it
  ;; As the API server does for any kind: deletion sets deletionTimestamp, no finalizer
  ;; may be added after that, and removing the last one completes the deletion.
  (with-temporary-store (store directory)
    (declare (ignorable directory))
    (flet ((finalizers (resource name list)
             (gr8s.resources::update-core-resource store resource "alpha" name
               (lambda (object) (setf (gethash "finalizers" (gethash "metadata" object)) (coerce list 'vector)) object)))
           (gone-p (resource name)
             (handler-case (progn (gr8s.resources::get-core-resource store resource "alpha" name) nil)
               (kubernetes-error () t))))
      (gr8s.resources::create-core-resource store "configmaps"
        (gr8s.resources::core-object "metadata" (gr8s.resources::core-object "name" "held" "finalizers" #("example.com/hold"))) "alpha")
      (gr8s.resources::create-core-resource store "services"
        (gr8s.resources::core-object "metadata" (gr8s.resources::core-object "name" "web")
                           "spec" (gr8s.resources::core-object "selector" (gr8s.resources::core-object "app" "web")
                                                     "ports" (vector (gr8s.resources::core-object "port" 80)))) "alpha")
      (finalizers "services" "web" '("example.com/lb"))
      (dolist (target '(("configmaps" "held") ("services" "web")))
        (destructuring-bind (resource name) target
          (gr8s.resources::delete-core-resource store resource "alpha" name)
          (let ((metadata (gethash "metadata" (gr8s.resources::get-core-resource store resource "alpha" name))))
            (is-true (gethash "deletionTimestamp" metadata))
            (is (= 1 (length (gethash "finalizers" metadata)))))
          ;; Deleting again changes nothing, and no finalizer can be added now.
          (gr8s.resources::delete-core-resource store resource "alpha" name)
          (signals kubernetes-error (finalizers resource name '("example.com/hold" "example.com/lb" "example.com/more")))
          (finalizers resource name '())
          (is-true (gone-p resource name)))))))

(test a-finalizer-holds-a-deleted-deployment
  (with-temporary-store (store directory)
    (declare (ignorable directory))
    (let ((deployment (workload-fixture "Deployment" "web" 1)))
      (setf (gethash "finalizers" (gethash "metadata" deployment)) #("example.com/hold"))
      (gr8s.resources::create-core-resource store "deployments" deployment "alpha"))
    (gr8s.controllers::delete-workload-resource store "deployments" "alpha" "web")
    (is-true (gethash "deletionTimestamp" (gethash "metadata" (gr8s.resources::get-core-resource store "deployments" "alpha" "web"))))
    (gr8s.resources::update-core-resource store "deployments" "alpha" "web"
      (lambda (object) (setf (gethash "finalizers" (gethash "metadata" object)) #()) object))
    (signals kubernetes-error (gr8s.resources::get-core-resource store "deployments" "alpha" "web"))))
