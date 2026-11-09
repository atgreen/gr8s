;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;; sbcl --dynamic-space-size 384 --noinform --non-interactive --load scripts/test-store-snapshot-memory.lisp
;;;; Set GR8S_SNAPSHOT_LEGACY=1 to exercise whole-state JSON materialization.
(require :asdf)
(asdf:load-asd (truename "gr8s.asd"))
(asdf:load-system "gr8s")
(let* ((directory (merge-pathnames (format nil "gr8s-artifact-memory-~A/" (gr8s::generate-uid))
                                  (uiop:temporary-directory)))
       (count (parse-integer (or (uiop:getenv "GR8S_SNAPSHOT_RECORDS") "1024")))
       (bytes 65536)
       (validated-count nil)
       (materialized-count nil)
       (reload-descriptor nil)
       (reloaded nil)
       (retained nil)
       (retain (equal "1" (uiop:getenv "GR8S_SNAPSHOT_RETAIN")))
       (reload (equal "1" (uiop:getenv "GR8S_SNAPSHOT_RELOAD")))
       (materialize (equal "1" (uiop:getenv "GR8S_SNAPSHOT_MATERIALIZE")))
       (legacy (equal "1" (uiop:getenv "GR8S_SNAPSHOT_LEGACY"))))
  (sb-posix:mkdir (namestring directory) #o700)
  (unwind-protect
       (let* ((store (gr8s:open-store directory))
              (target (merge-pathnames "artifact.jsonl" directory)))
         (dotimes (i count)
           (let ((name (format nil "config-~D" i)))
             (setf (gethash (list "configmaps" "default" name) (gr8s::pod-store-resources store))
                   (gr8s::core-object
                    "apiVersion" "v1" "kind" "ConfigMap"
                    "metadata" (gr8s::core-object "name" name "namespace" "default" "resourceVersion" "1")
                    "data" (gr8s::core-object "payload" (make-string bytes :element-type 'base-char :initial-element #\x))))))
         (setf (gr8s::pod-store-resource-revision store) 1)
         (sb-ext:gc :full t)
         (if legacy
             (let ((json (gr8s.resources::core-state-json
                          store (gr8s::pod-store-resources store) 1
                          (gr8s::pod-store-workload-deletions store)
                          (gr8s::pod-store-job-controller-states store))))
               (gr8s.security::write-private-text-exclusively target json))
             (progn
               (gr8s.resources::capture-store-snapshot store target 1 1)
               (setf validated-count
                     (nth-value 2 (gr8s.resources::validate-store-snapshot
                                   target :expected-index 1 :expected-term 1)))))
         (when (and retain (not legacy))
           (multiple-value-bind (path reference)
               (gr8s.resources::retain-store-snapshot-artifact
                directory target 1 1 (gr8s.raft.transport::raft-snapshot-file-digest target))
             (delete-file target)
             (setf target (gr8s.resources::checked-store-snapshot-artifact-path directory reference)
                   retained (equal path target))))
         (when (and (or materialize reload) (not legacy))
           (multiple-value-bind (path descriptor records)
               (gr8s.resources::materialize-store-snapshot
                directory target (gr8s.raft.transport::raft-snapshot-file-digest target)
                :expected-index 1 :expected-term 1
                :minimum-resource-revision (when reload (1+ (gr8s::pod-store-resource-revision store)))
                :minimum-pod-revision (when reload (1+ (gr8s::pod-store-pod-revision-ceiling store))))
             (declare (ignore path))
             (setf materialized-count records reload-descriptor descriptor)))
         (when (and reload (not legacy))
           (gr8s.store::quiesce-store-access store :timeout 0)
           (setf reloaded (eq store (gr8s.store::reload-store-application
                                     store (gethash "generation" reload-descriptor))))
           (gr8s.store::resume-store-access store)
           (assert (= count (hash-table-count (gr8s::pod-store-resources store))))
           (let ((object (gr8s::get-core-resource store "configmaps" "default" (format nil "config-~D" (1- count)))))
             (assert (= bytes (length (gethash "payload" (gethash "data" object)))))))
         (let ((result (gr8s::core-object
                        "passed" t "legacy" legacy "records" count
                        "validatedRecords" validated-count "materializedRecords" materialized-count
                        "residentResourcesAfterOperation" (hash-table-count (gr8s::pod-store-resources store))
                        "reloadedSameStore" reloaded "retainedArtifactAfterTransferCleanup" retained "payloadBytes" (* count bytes)
                        "artifactBytes" (sb-posix:stat-size (sb-posix:stat (namestring target))))))
           (unless reloaded
             (setf (gethash "residentSourceResources" result) (hash-table-count (gr8s::pod-store-resources store))))
           (format t "~&~A~%" (com.inuoe.jzon:stringify result))))
    (uiop:delete-directory-tree directory :validate t :if-does-not-exist :ignore)))
