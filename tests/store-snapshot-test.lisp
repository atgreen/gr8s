;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
(in-package #:gr8s/tests)
(def-suite store-snapshot :in gr8s)
(in-suite store-snapshot)

(defun freeze-test-store-snapshot (store index term)
  (gr8s.store::quiesce-store-access store :timeout 0)
  (unwind-protect
       (gr8s.store::call-with-store-application-barriers
        store (lambda () (gr8s.resources::freeze-store-snapshot store index term)))
    (gr8s.store::resume-store-access store)))

(test frozen-application-snapshot-is-independent-of-live-containers
  (with-temporary-store (store root)
    (let* ((pod (ha-make-pod store "frozen-pod"))
           (node (gr8s.model::make-node-record :id "frozen-node" :name "frozen-node"
                                       :pod-cidr "10.88.0.0/20"))
           (bulk (make-string 65536 :initial-element #\x))
           (object (gr8s.resources::core-object "payload" bulk))
           (history (gr8s.resources::core-object "resource" "configmaps" "old" object))
           (controller (gr8s.resources::core-object "nested" (vector (gr8s.resources::core-object "count" 1))))
           (ordinary (merge-pathnames "before.jsonl" root))
           (target (merge-pathnames "frozen.jsonl" root)))
      (gr8s.controllers::register-node store node)
      (setf (gr8s.model::node-record-labels node) (gr8s.resources::core-object "pool" "original")
            (gethash (gr8s.model::pod-uid pod) (gr8s.store::pod-store-pod-condition-histories store))
            (vector (gr8s.resources::core-object "type" "Ready" "status" "False"))
            (gethash (gr8s.model::pod-uid pod) (gr8s.store::pod-store-pod-published-statuses store))
            (gr8s.resources::core-object "phase" "Pending"))
      (setf (gethash '("configmaps" "default" "bulk") (gr8s.store::pod-store-resources store)) object
            (gr8s.store::pod-store-template-history store) (list history)
            (gethash "job" (gr8s.store::pod-store-job-controller-states store)) controller
            (gethash "deletion" (gr8s.store::pod-store-workload-deletions store))
            (gr8s.resources::core-object "nested" (vector 1 2)))
      (populate-snapshot-tracker store)
      (gr8s.resources::capture-store-snapshot store ordinary 42 7)
      (let* ((view (freeze-test-store-snapshot store 42 7))
             (shadow (gr8s.resources::frozen-store-snapshot-store view))
             (original (symbol-function 'com.inuoe.jzon:stringify))
             (writes 0))
        (is (not (eq store shadow)))
        (is (eq object (gethash '("configmaps" "default" "bulk") (gr8s.store::pod-store-resources shadow))))
        (is (not (eq (gr8s.store::pod-store-template-history store) (gr8s.store::pod-store-template-history shadow))))
        (is (eq history (first (gr8s.store::pod-store-template-history shadow))))
        (is (eq bulk (gethash "payload" (gethash '("configmaps" "default" "bulk")
                                                 (gr8s.store::pod-store-resources shadow)))))
        ;; Core publication replaces objects; mutable model/controller containers
        ;; can change in place and must already have private snapshot copies.
        (clrhash (gr8s.store::pod-store-resources store))
        (setf (gr8s.store::pod-store-template-history store) nil
              (gethash "count" (aref (gethash "nested" controller) 0)) 2
              (aref (gethash "nested" (gethash "deletion" (gr8s.store::pod-store-workload-deletions store))) 0) 9
              (gethash "changed" (gethash "metadata" (gr8s.model::pod-to-object pod))) t
              (gethash "pool" (gr8s.model::node-record-labels node)) "changed"
              (gethash "status" (aref (gethash (gr8s.model::pod-uid pod)
                                               (gr8s.store::pod-store-pod-condition-histories store)) 0)) "True"
              (gethash "phase" (gethash (gr8s.model::pod-uid pod)
                                        (gr8s.store::pod-store-pod-published-statuses store))) "Running")
        (clrhash (gr8s.store::pod-store-pods store))
        (clrhash (gr8s.store::pod-store-nodes store))
        (gr8s.image-distribution::clear-image-tracker-state (gr8s.store::pod-store-image-tracker store))
        (unwind-protect
             (progn
               (setf (symbol-function 'com.inuoe.jzon:stringify)
                     (lambda (value &rest arguments)
                       (dolist (lock (list (gr8s.store::pod-store-lock store)
                                           (gr8s.store::pod-store-workload-lock store)
                                           (gr8s.store::pod-store-credential-lock store)
                                           (gr8s.store::pod-store-consensus-write-lock store)))
                         (is (not (sb-thread:holding-mutex-p lock))))
                       (incf writes)
                       (apply original value arguments)))
               (gr8s.resources::capture-frozen-store-snapshot view target))
          (setf (symbol-function 'com.inuoe.jzon:stringify) original))
        (let ((expected (read-store-snapshot-records ordinary))
              (actual (read-store-snapshot-records target)))
          (is (= writes (length actual)))
          (is (= (length expected) (length actual)))
          (is (every (lambda (record) (member record actual :test #'equalp)) expected)))
        (signals error (gr8s.resources::capture-frozen-store-snapshot view target))
        (is (= #o600 (logand #o777 (sb-posix:stat-mode (sb-posix:stat (namestring target))))))))))

(test frozen-application-snapshot-requires-drained-outer-barriers
  (with-temporary-store (store root)
    (declare (ignore root))
    (signals error (gr8s.resources::freeze-store-snapshot store 1 1))
    (gr8s.store::call-with-store-application-barriers
     store (lambda () (signals error (gr8s.resources::freeze-store-snapshot store 1 1))))))

(test frozen-secret-snapshot-pins-keys-before-credential-changes
  (with-temporary-store (store root)
    (gr8s.resources::enable-secret-encryption store)
    (gr8s.resources::create-core-resource
     store "secrets"
     (gr8s.resources::core-object "apiVersion" "v1" "kind" "Secret"
                        "metadata" (gr8s.resources::core-object "name" "frozen-secret")
                        "data" (gr8s.resources::core-object "password" "cGlubmVk")) "default")
    (let* ((view (freeze-test-store-snapshot store 42 7))
           (shadow (gr8s.resources::frozen-store-snapshot-store view))
           (target (merge-pathnames "frozen-secret.jsonl" root))
           (config (gr8s.store::pod-store-secret-encryption-config store)))
      (delete-file (merge-pathnames "pki/cluster-ca.key" root))
      (setf (gr8s.store::pod-store-secret-encryption-config store) nil)
      (gr8s.resources::capture-frozen-store-snapshot view target)
      (is (null (search "cGlubmVk" (uiop:read-file-string target))))
      (let* ((records (read-store-snapshot-records target))
             (row (find "resource" records :test #'equal :key (lambda (row) (gethash "kind" row))))
             (gr8s.resources::*snapshot-secret-keys*
               (gr8s.resources::frozen-store-snapshot-secret-keys view)))
        (is (equal "cGlubmVk"
                   (gethash "password"
                            (gethash "data" (gr8s.resources::decrypt-secret-object shadow "secrets" (gethash "object" row))))))
        ;; A different store must never inherit the snapshot's credentials, and
        ;; a record not pinned in this view must not fall back to today's key.
        (signals error (gr8s.resources::derive-secret-encryption-key store (aref (gethash "keys" config) 0)))
        (signals error (gr8s.resources::derive-secret-encryption-key shadow (gr8s.resources::core-object "salt" "invalid")))))))

(defun read-store-snapshot-records (path)
  (with-open-file (stream path)
    (loop for line = (read-line stream nil) while line collect (com.inuoe.jzon:parse line))))

(test store-snapshot-streams-committed-records-and-excludes-local-data
  (with-temporary-store (store directory)
    (let* ((target (merge-pathnames "snapshot.jsonl" directory))
           (pod (ha-make-pod store "captured-pod"))
           (original (symbol-function 'com.inuoe.jzon:stringify))
           (writes 0))
      (gr8s.controllers::register-node store (gr8s.model::make-node-record :id "captured-node" :name "captured-node" :pod-cidr "10.88.0.0/20"))
      (setf (gethash '("secrets" "default" "shared") (gr8s.store::pod-store-resources store))
            (gr8s.resources::core-object "data" (gr8s.resources::core-object "shared" "replicated-secret"))
            (gethash '("events" "default" "local") (gr8s.store::pod-store-resources store))
            (gr8s.resources::core-object "message" "local-event-sentinel"))
      (setf (gethash "controller" (gr8s.store::pod-store-job-controller-states store))
            (gr8s.resources::core-object "finished" 2)
            (gethash "deleting" (gr8s.store::pod-store-workload-deletions store))
            (gr8s.resources::core-object "policy" "Foreground")
            (gr8s.store::pod-store-template-history store)
            (list (gr8s.resources::core-object "resource" "configmaps" "revision" 9)
                  (gr8s.resources::core-object "resource" "events" "message" "local-history-sentinel")))
      (gr8s.security::write-private-text-exclusively
       (merge-pathnames "pki/member-private.key" directory) "member-private-sentinel")
      (unwind-protect
           (progn
             (setf (symbol-function 'com.inuoe.jzon:stringify)
                   (lambda (object &rest arguments &key stream &allow-other-keys)
                     (unless stream (error "Snapshot constructed an intermediate JSON string"))
                     (incf writes)
                     (apply original object arguments)))
             (multiple-value-bind (path count)
                 (gr8s.resources::capture-store-snapshot store target 42 7)
               (is (equal path target))
               (is (= count writes))))
        (setf (symbol-function 'com.inuoe.jzon:stringify) original))
      (let* ((records (read-store-snapshot-records target))
             (header (first records))
             (pod-record (find "pod" records :test #'equal :key (lambda (r) (gethash "kind" r))))
             (text (uiop:read-file-string target)))
        (is (= 42 (gethash "index" header)))
        (is (= 7 (gethash "term" header)))
        (is (= (1- (length records)) (gethash "records" (car (last records)))))
        (is (equal (gr8s.model::pod-uid pod) (gethash "uid" (gethash "metadata" (gethash "object" pod-record)))))
        (is (hash-table-p (gethash "checkpoint" pod-record)))
        (is (hash-table-p (gethash "publication" pod-record)))
        (is (search "replicated-secret" text))
        (is (not (search "local-event-sentinel" text)))
        (is (not (search "local-history-sentinel" text)))
        (is (find "history" records :test #'equal :key (lambda (r) (gethash "kind" r))))
        (is (find "jobControllerState" records :test #'equal :key (lambda (r) (gethash "kind" r))))
        (is (find "workloadDeletion" records :test #'equal :key (lambda (r) (gethash "kind" r))))
        (is (not (search "member-private-sentinel" text)))
        (is (= #o600 (logand #o777 (sb-posix:stat-mode (sb-posix:stat (namestring target))))))))))

(test encrypted-store-snapshot-does-not-expose-secret-data
  (with-temporary-store (store directory)
    (gr8s.resources::enable-secret-encryption store)
    (gr8s.resources::create-core-resource
     store "secrets"
     (gr8s.resources::core-object
      "apiVersion" "v1" "kind" "Secret"
      "metadata" (gr8s.resources::core-object "name" "snapshot-secret")
      "data" (gr8s.resources::core-object "password" "c25hcHNob3Qtc2VudGluZWw="))
     "default")
    (let ((target (merge-pathnames "encrypted-snapshot.jsonl" directory)))
      (gr8s.resources::capture-store-snapshot store target 42 7)
      (let ((text (uiop:read-file-string target)))
        (is (null (search "c25hcHNob3Qtc2VudGluZWw=" text)))
        (is (search "encryptedData" text))))))

(test store-snapshot-failure-does-not-publish-a-partial-artifact
  (with-temporary-store (store directory)
    (let ((target (merge-pathnames "failed.jsonl" directory))
          (original (symbol-function 'com.inuoe.jzon:stringify)) (writes 0))
      (unwind-protect
           (progn
             (setf (symbol-function 'com.inuoe.jzon:stringify)
                   (lambda (object &rest arguments)
                     (when (= 2 (incf writes)) (error "Injected serialization failure"))
                     (apply original object arguments)))
             (signals error (gr8s.resources::capture-store-snapshot store target 1 1)))
        (setf (symbol-function 'com.inuoe.jzon:stringify) original))
      (is (null (probe-file target)))
      (is (null (directory (merge-pathnames "*.tmp" directory))))
      (gr8s.resources::capture-store-snapshot store target 1 1)
      (let ((before (uiop:read-file-string target)))
        (signals error (gr8s.resources::capture-store-snapshot store target 2 1))
        (is (equal before (uiop:read-file-string target)))))))

(test store-snapshot-during-proposal-sees-committed-node-state
  (with-temporary-store (store directory)
    (let ((target (merge-pathnames "committed.jsonl" directory)))
      (gr8s.controllers::register-node store (gr8s.model::make-node-record :id "worker" :name "worker" :pod-cidr "10.88.0.0/20"))
      (let ((revision (gr8s.model::node-record-resource-version (gr8s.controllers::get-node store "worker"))))
        (setf (gr8s.store::pod-store-consensus-commit-fn store)
              (lambda (&rest arguments)
                (declare (ignore arguments))
                (gr8s.resources::capture-store-snapshot store target 42 7)
                (error "Proposal did not commit")))
        (signals error (gr8s.controllers::mark-node-ready store "worker" (get-universal-time)))
        (let* ((row (find "node" (read-store-snapshot-records target)
                          :test #'equal :key (lambda (r) (gethash "kind" r))))
               (object (gethash "object" row)))
          (is (not (eq t (gethash "ready" object))))
          (is (equal revision (gethash "resourceVersion" object))))))))

(defun capture-valid-store-snapshot (store target)
  (gr8s.resources::create-core-resource store "configmaps"
                              (core-fixture "ConfigMap" "snapshot-config"
                                            "data" (gr8s.resources::core-object "key" "value")) "default")
  (ha-make-pod store "snapshot-pod")
  (gr8s.controllers::register-node store (gr8s.model::make-node-record :id "snapshot-worker" :name "snapshot-worker" :pod-cidr "10.88.0.0/20"))
  (gr8s.resources::capture-store-snapshot store target 42 7))

(defun write-snapshot-test-records (path records)
  (with-open-file (stream path :direction :output :if-exists :supersede)
    (dolist (record records) (com.inuoe.jzon:stringify record :stream stream) (terpri stream))))

(test snapshot-reader-validates-streamed-records-and-boundary
  (with-temporary-store (store directory)
    (let ((target (merge-pathnames "valid.jsonl" directory)) (count 0))
      (capture-valid-store-snapshot store target)
      (multiple-value-bind (header clocks records)
          (gr8s.resources::map-store-snapshot-records
           target (lambda (record) (is (hash-table-p record)) (incf count)) :expected-index 42 :expected-term 7)
        (is (= 42 (gethash "index" header)))
        (is (= (gr8s.store::pod-store-pod-revision store) (gethash "podRevision" clocks)))
        (is (= records count)))
      (signals error (gr8s.resources::map-store-snapshot-records target nil :expected-index 41))
      (signals error (gr8s.resources::map-store-snapshot-records target nil :expected-term 8)))))

(test snapshot-reader-rejects-invalid-framing-and-records
  (with-temporary-store (store directory)
    (let ((target (merge-pathnames "valid.jsonl" directory))
          (mutated (merge-pathnames "mutated.jsonl" directory)))
      (capture-valid-store-snapshot store target)
      (dolist (mutator
                (list (lambda (r) (rest r))
                      (lambda (r) (remove (second r) r))
                      (lambda (r) (butlast r))
                      (lambda (r) (setf (gethash "version" (first r)) 2) r)
                      (lambda (r) (setf (gethash "records" (car (last r))) 0) r)
                      (lambda (r) (append (butlast r) (list (first r) (car (last r)))))
                      (lambda (r) (setf (gethash "resourceHistoryStart" (second r)) 999999) r)
                      (lambda (r) (setf (gethash "templateTokenKey" (second r)) "AA==") r)
                      (lambda (r)
                        (let ((row (find "resource" r :test #'equal :key (lambda (x) (gethash "kind" x)))))
                          (setf (gethash "name" row) "different")) r)
                      (lambda (r)
                        (let ((row (find "resource" r :test #'equal :key (lambda (x) (gethash "kind" x)))))
                          (setf (gethash "resource" row) "events")) r)
                      (lambda (r)
                        (let ((row (find "pod" r :test #'equal :key (lambda (x) (gethash "kind" x)))))
                          (setf (gethash "uid" (gethash "publication" row)) "different")) r)
                      (lambda (r)
                        (let ((row (find "node" r :test #'equal :key (lambda (x) (gethash "kind" x)))))
                          (setf (gethash "id" (gethash "object" row)) nil)) r)
                      (lambda (r)
                        (let ((row (find "pod" r :test #'equal :key (lambda (x) (gethash "kind" x)))))
                          (setf (gethash "uid" (gethash "metadata" (gethash "object" row))) "../outside"
                                (gethash "uid" (gethash "publication" row)) "../outside")) r)
                      (lambda (r)
                        (let ((row (find "node" r :test #'equal :key (lambda (x) (gethash "kind" x)))))
                          (setf (gethash "id" (gethash "object" row)) "../outside")) r)
                      (lambda (r)
                        (let ((row (find "pod" r :test #'equal :key (lambda (x) (gethash "kind" x)))))
                          (setf (gethash "conditions" (gethash "checkpoint" row)) "invalid")) r)
                      (lambda (r)
                        (let ((row (find "history" r :test #'equal :key (lambda (x) (gethash "kind" x)))))
                          (setf (gethash "time" (gethash "entry" row)) "invalid")) r)
                      (lambda (r) (setf (gethash "kind" (third r)) "file") r)))
        (write-snapshot-test-records mutated (funcall mutator (read-store-snapshot-records target)))
        (signals error (gr8s.resources::map-store-snapshot-records mutated nil)))
      (signals error (gr8s.resources::map-store-snapshot-records target nil :max-record-bytes 32))
      (write-snapshot-test-records mutated (read-store-snapshot-records target))
      (sb-posix:truncate (namestring mutated) (1- (sb-posix:stat-size (sb-posix:stat (namestring mutated)))))
      (signals error (gr8s.resources::map-store-snapshot-records mutated nil))
      (write-snapshot-test-records mutated (read-store-snapshot-records target))
      (with-open-file (stream mutated :direction :output :if-exists :append) (terpri stream))
      (signals error (gr8s.resources::map-store-snapshot-records mutated nil)))))

(test snapshot-writer-rejects-oversized-record-before-publication
  (with-temporary-store (store directory)
    (let ((target (merge-pathnames "oversized.jsonl" directory))
          (gr8s.resources::*store-snapshot-max-record-bytes* 16))
      (signals error (gr8s.resources::capture-store-snapshot store target 1 1))
      (is (null (probe-file target)))
      (is (null (directory (merge-pathnames "*.tmp" directory)))))))
