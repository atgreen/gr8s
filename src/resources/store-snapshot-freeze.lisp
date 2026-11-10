;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
(in-package #:gr8s.resources)

(defun freeze-snapshot-containers (value &optional (depth 0))
  "Copy mutable JSON containers, sharing immutable scalar/string payloads.
Store APIs replace published strings; they never destructively edit them."
  (when (> depth 128) (error "Snapshot value exceeds maximum nesting depth"))
  (cond
    ((hash-table-p value)
     (let ((copy (make-hash-table :test (hash-table-test value))))
       (maphash (lambda (key item)
                  (setf (gethash key copy) (freeze-snapshot-containers item (1+ depth))))
                value)
       copy))
    ((stringp value) value)
    ((vectorp value)
     (map 'vector (lambda (item) (freeze-snapshot-containers item (1+ depth))) value))
    ((consp value)
     (mapcar (lambda (item) (freeze-snapshot-containers item (1+ depth))) value))
    (t value)))

(defun freeze-store-snapshot (store index term)
  "Freeze an application boundary under verified outer barriers and the raw lock.
The HA caller must also own the member lock and pair INDEX/TERM with a prepared
Raft boundary. The returned private view retains no live store or lock."
  (unless (and (typep index '(integer 0 *)) (typep term '(integer 0 *)))
    (error "Invalid frozen store snapshot boundary"))
  (unless (gr8s.store::store-application-barriers-owned-p store)
    (error "Freezing a snapshot requires the outer application barriers"))
  (when (gr8s.store::pod-stage-active-p store)
    (error "Cannot freeze a speculative store transaction"))
  (bt:with-lock-held ((pod-store-lock store))
    (gr8s.store::require-store-reload-quiescence store)
    (let* ((shadow (gr8s.store::make-pod-store (pod-store-path store)))
           (keys (make-snapshot-secret-keys :store shadow))
           (pods nil) (nodes nil))
      ;; Published core objects and history entries are immutable. Only their
      ;; indexes/list spine are copied; duplicating payloads would exhaust heap.
      (setf (pod-store-resources shadow) (alexandria:copy-hash-table (pod-store-resources store))
            (pod-store-template-history shadow) (copy-list (pod-store-template-history store))
            (pod-store-resource-revision shadow) (pod-store-resource-revision store)
            (pod-store-pod-revision shadow) (pod-store-pod-revision store)
            (gr8s.store::pod-store-pod-revision-epoch-floor shadow)
            (gr8s.store::pod-store-pod-revision-epoch-floor store)
            (pod-store-resource-history-start shadow) (pod-store-resource-history-start store)
            (pod-store-template-history-floor shadow) (pod-store-template-history-floor store)
            (pod-store-template-token-key shadow)
            (when (pod-store-template-token-key store) (copy-seq (pod-store-template-token-key store)))
            (pod-store-secret-encryption-config shadow)
            (freeze-snapshot-containers (pod-store-secret-encryption-config store))
            (pod-store-workload-deletions shadow)
            (freeze-snapshot-containers (pod-store-workload-deletions store))
            (pod-store-job-controller-states shadow)
            (freeze-snapshot-containers (pod-store-job-controller-states store))
            (pod-store-image-tracker shadow)
            (gr8s.image-distribution::freeze-image-tracker (pod-store-image-tracker store)))
      ;; Read credentials before releasing the credential barrier, not once per
      ;; Secret later during disk I/O. Exact frozen records identify the keys.
      (when (secret-encryption-enabled-p shadow)
        (loop for record across (gethash "keys" (pod-store-secret-encryption-config shadow))
              do (setf (gethash record (snapshot-secret-keys-records keys))
                       (derive-secret-encryption-key store record))))
      (maphash
       (lambda (key pod)
         (declare (ignore key))
         (push (freeze-snapshot-containers
                (core-object "kind" "pod" "object" (pod-to-object pod)
                             "checkpoint" (gr8s.store::pod-checkpoint-object store pod)
                             "publication" (gr8s.store::pod-publication-object store pod)))
               pods))
       (pod-store-pods store))
      (maphash
       (lambda (name node)
         (declare (ignore name))
         (push (freeze-snapshot-containers
                (core-object "kind" "node" "object" (gr8s.store::node-replicated-object node)))
               nodes))
       (pod-store-nodes store))
      (%make-frozen-store-snapshot :store shadow :index index :term term
                                   :pod-records (nreverse pods) :node-records (nreverse nodes)
                                   :secret-keys keys))))

(defun capture-frozen-store-snapshot (view path)
  "Serialize VIEW without acquiring any live application or member mutex."
  (check-type view frozen-store-snapshot)
  (let ((*snapshot-secret-keys* (frozen-store-snapshot-secret-keys view)))
    (publish-store-snapshot
     path (lambda (stream)
            (write-store-snapshot-records
             (frozen-store-snapshot-store view) stream
             (frozen-store-snapshot-index view) (frozen-store-snapshot-term view)
             :frozen-view view)))))
