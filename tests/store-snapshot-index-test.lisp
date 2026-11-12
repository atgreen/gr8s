;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
(in-package #:gr8s/tests)
(def-suite store-snapshot-index :in gr8s)
(in-suite store-snapshot-index)

(defun snapshot-index-records-path (directory records)
  (let ((path (merge-pathnames "index-validation.jsonl" directory)))
    (setf (gethash "records" (car (last records))) (1- (length records)))
    (write-snapshot-test-records path records)
    path))

(defun snapshot-index-row (records kind)
  (find kind records :test #'equal :key (lambda (row) (gethash "kind" row))))

(defun snapshot-index-copy (object)
  (com.inuoe.jzon:parse (com.inuoe.jzon:stringify object)))

(test snapshot-index-rejects-duplicate-identities-before-completion
  (with-temporary-store (store directory)
    (let ((source (merge-pathnames "source.jsonl" directory)))
      (capture-valid-store-snapshot store source)
      (dolist (kind '("resource" "pod" "node"))
        (let* ((records (read-store-snapshot-records source))
               (row (snapshot-index-copy (snapshot-index-row records kind)))
               (end-seen nil))
          (setf records (append (butlast records) (list row (car (last records)))))
          (signals error
            (gr8s.resources::validate-store-snapshot
             (snapshot-index-records-path directory records)
             :function (lambda (record) (when (equal "end" (gethash "kind" record)) (setf end-seen t)))))
          (is (not end-seen))))
      ;; UID and logical name are independently unique.
      (dolist (which '(:uid :name))
        (let* ((records (read-store-snapshot-records source))
               (row (snapshot-index-copy (snapshot-index-row records "pod")))
               (metadata (gethash "metadata" (gethash "object" row))))
          (ecase which
            (:uid (setf (gethash "name" metadata) "other-name"))
            (:name (setf (gethash "uid" metadata) "other-uid"
                         (gethash "uid" (gethash "publication" row)) "other-uid")))
          (signals error (gr8s.resources::validate-store-snapshot
                          (snapshot-index-records-path directory
                            (append (butlast records) (list row (car (last records)))))))))
      (is (gr8s.resources::validate-store-snapshot source :expected-index 42 :expected-term 7))
      (is (= 1 (hash-table-count (gr8s.store::pod-store-pods store)))))))

(test snapshot-index-node-claims-are-canonical-and-check-overlap-both-directions
  (with-temporary-store (store directory)
    (let ((source (merge-pathnames "source.jsonl" directory)))
      (capture-valid-store-snapshot store source)
      (dolist (cidrs '(("10.88.0.0/20" "10.88.1.0/24")
                       ("10.88.1.0/24" "10.88.0.0/20")
                       ("fd00::/64" "fd00:0:0:0::1/96")
                       ("fd00::1/96" "fd00::/64")))
        (let* ((records (read-store-snapshot-records source))
               (first (gethash "object" (snapshot-index-row records "node")))
               (row (snapshot-index-copy (snapshot-index-row records "node")))
               (second (gethash "object" row)))
          (setf (gethash "podCIDR" first) (first cidrs) (gethash "podCIDRs" first) (vector (first cidrs))
                (gethash "name" second) "other-node" (gethash "id" second) "other-id"
                (gethash "podCIDR" second) (second cidrs) (gethash "podCIDRs" second) (vector (second cidrs)))
          (signals error (gr8s.resources::validate-store-snapshot
                          (snapshot-index-records-path directory
                            (append (butlast records) (list row (car (last records)))))))))
      (dolist (field '("id" "name" "underlayAddress" "wireguardPublicKey"))
        (let* ((records (read-store-snapshot-records source))
               (first (gethash "object" (snapshot-index-row records "node")))
               (row (snapshot-index-copy (snapshot-index-row records "node")))
               (second (gethash "object" row)))
          (setf (gethash "name" second) "other-node" (gethash "id" second) "other-id"
                (gethash "podCIDR" second) "10.89.0.0/20" (gethash "podCIDRs" second) #("10.89.0.0/20"))
          (cond ((equal field "underlayAddress")
                 (setf (gethash field first) "fd00::1" (gethash field second) "fd00:0:0:0:0:0:0:1"))
                ((equal field "wireguardPublicKey")
                 (setf (gethash field first) (ag-grpc:base64-encode (make-array 32 :element-type '(unsigned-byte 8) :initial-element 7))
                       (gethash field second) (gethash field first)))
                (t (setf (gethash field second) (gethash field first))))
          (signals error (gr8s.resources::validate-store-snapshot
                          (snapshot-index-records-path directory
                            (append (butlast records) (list row (car (last records))))))))))))

(defun snapshot-test-resource-record (resource object namespace)
  (setf (gethash "resourceVersion" (gethash "metadata" object)) "0")
  (when namespace (setf (gethash "namespace" (gethash "metadata" object)) namespace))
  (gr8s.resources::core-object "kind" "resource" "resource" resource "namespace" (or namespace 'gr8s.resources::null)
                    "name" (gethash "name" (gethash "metadata" object)) "object" object))

(test snapshot-index-resolves-custom-definitions-after-instances-and-checks-shapes
  (with-temporary-store (store directory)
    (let ((source (merge-pathnames "source.jsonl" directory)))
      (capture-valid-store-snapshot store source)
      (let* ((records (read-store-snapshot-records source))
             (definition (snapshot-test-resource-record "customresourcedefinitions" (crd-fixture) nil))
             (instance (snapshot-test-resource-record "custom:widgets.example.test/widgets" (crd-instance) "default"))
             (prefix (append (butlast records) (list instance))) (end (car (last records))))
        (is (gr8s.resources::validate-store-snapshot
             (snapshot-index-records-path directory (append prefix (list definition end)))))
        (dolist (change '(:absent :kind :version :scope :duplicate-collection :storage))
          (let ((def (snapshot-index-copy definition)))
            (case change
              (:kind (setf (gethash "kind" (gethash "names" (gethash "spec" (gethash "object" def)))) "Other"))
              (:version (setf (gethash "name" (aref (gethash "versions" (gethash "spec" (gethash "object" def))) 0)) "v2"))
              (:scope (setf (gethash "scope" (gethash "spec" (gethash "object" def))) "Cluster"))
              (:storage (setf (gethash "storage" (aref (gethash "versions" (gethash "spec" (gethash "object" def))) 0)) nil)))
            (signals error
              (gr8s.resources::validate-store-snapshot
               (snapshot-index-records-path directory
                 (append prefix (unless (eq change :absent) (list def))
                         (when (eq change :duplicate-collection) (list (snapshot-index-copy def))) (list end)))))))))))

(test snapshot-index-controller-keys-are-unique-within-each-map
  (with-temporary-store (store directory)
    (let ((source (merge-pathnames "source.jsonl" directory)))
      (capture-valid-store-snapshot store source)
      (let* ((records (read-store-snapshot-records source))
             (one (gr8s.resources::core-object "kind" "workloadDeletion" "key" "same" "value" (gr8s.resources::core-object)))
             (two (gr8s.resources::core-object "kind" "jobControllerState" "key" "same" "value" (gr8s.resources::core-object)))
             (prefix (butlast records)) (end (car (last records))))
        (is (gr8s.resources::validate-store-snapshot
             (snapshot-index-records-path directory (append prefix (list one two end)))))
        (signals error (gr8s.resources::validate-store-snapshot
                        (snapshot-index-records-path directory (append prefix (list one one end)))))))))

(test snapshot-index-accepts-distinct-dual-stack-nodes
  (with-temporary-store (store directory)
    (let ((source (merge-pathnames "source.jsonl" directory)))
      (capture-valid-store-snapshot store source)
      (let* ((records (read-store-snapshot-records source))
             (first (gethash "object" (snapshot-index-row records "node")))
             (row (snapshot-index-copy (snapshot-index-row records "node")))
             (second (gethash "object" row)))
        (setf (gethash "podCIDRs" first) #("10.88.0.0/20" "fd00::/64")
              (gethash "underlayAddress" first) "fd01::1"
              (gethash "id" second) "other-id" (gethash "name" second) "other-node"
              (gethash "podCIDR" second) "10.89.0.0/20"
              (gethash "podCIDRs" second) #("10.89.0.0/20" "fd00:0:0:1::/64")
              (gethash "underlayAddress" second) "fd01::2")
        (is (gr8s.resources::validate-store-snapshot
             (snapshot-index-records-path directory (append (butlast records) (list row (car (last records)))))))))))
