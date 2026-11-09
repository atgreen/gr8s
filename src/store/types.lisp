;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; In-memory indexes and synchronization state owned by the durable store.

(in-package #:gr8s.store)

(defstruct (pod-store (:constructor make-pod-store (path)))
  "Hold durable paths, in-memory indexes, observed status, and the store lock."
  path
  data-root
  (pods (make-hash-table :test #'equal))
  (nodes (make-hash-table :test #'equal))
  (resources (make-hash-table :test #'equal))
  (resource-revision 0)
  template-history
  (template-history-recent nil)
  (template-history-maintained-at 0)
  (template-history-floor 0)
  (resource-history-start 0)
  template-token-key
  (event-expirations (make-hash-table :test #'equal))
  (core-journal-bytes 0)
  (core-checkpoint-bytes 0)
  (core-checkpoint-needed t)
  in-cluster-config
  (credential-lock (bt:make-lock "gr8s ServiceAccount credentials"))
  service-account-signing-key
  (verified-tokens (make-hash-table :test #'equal))
  (projected-tokens (make-hash-table :test #'equal))
  (pod-certificates (make-hash-table :test #'equal))
  (workload-lock (bt:make-lock "gr8s workload controllers"))
  (workload-deletions (make-hash-table :test #'equal))
  (job-controller-states (make-hash-table :test #'equal))
  (pod-finalization-states (make-hash-table :test #'equal))
  (pod-observed-phases (make-hash-table :test #'equal))
  (pod-observed-statuses (make-hash-table :test #'equal))
  (pod-observed-resource-versions (make-hash-table :test #'equal))
  (pod-condition-histories (make-hash-table :test #'equal))
  consensus-pod-revision
  (pod-revision 0)
  (pod-revision-ceiling 0)
  (watch-journal-p t)
  (pod-watch-floor 0)
  pod-watch-journal
  (pod-watch-journal-length 0)
  (pod-watch-journal-bytes 0)
  (pod-watch-views (make-hash-table :test #'equal))
  (node-watch-floor 0)
  node-watch-journal
  (node-watch-journal-length 0)
  (node-watch-journal-bytes 0)
  (pod-published-statuses (make-hash-table :test #'equal))
  (pod-client-statuses (make-hash-table :test #'equal))
  (nominated-nodes (make-hash-table :test #'equal))
  (scheduling-notes (make-hash-table :test #'equal))
  (lock (bt:make-lock "gr8s store"))
  consensus-commit-fn
  (consensus-write-lock (bt:make-lock "gr8s consensus write")))
