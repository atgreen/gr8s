;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
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
