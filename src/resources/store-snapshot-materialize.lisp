;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
(in-package #:gr8s.resources)

(defun open-snapshot-generation-output (path &key binary)
  (let ((fd (sb-posix:open (namestring path)
                           (logior sb-posix:o-wronly sb-posix:o-creat sb-posix:o-excl) #o600)))
    (handler-case
        (if binary (sb-sys:make-fd-stream fd :output t :element-type '(unsigned-byte 8) :auto-close t)
            (sb-sys:make-fd-stream fd :output t :element-type 'character :external-format :utf-8 :auto-close t))
      (error (condition) (sb-posix:close fd) (error condition)))))

(defun write-snapshot-generation-file (path writer)
  (with-open-stream (stream (open-snapshot-generation-output path))
    (funcall writer stream)
    (finish-output stream)
    (sb-posix:fsync (sb-sys:fd-stream-fd stream))))

(defun write-snapshot-generation-json (path object)
  (write-snapshot-generation-file path (lambda (stream) (com.inuoe.jzon:stringify object :stream stream))))

(defun copy-snapshot-generation-source (source target expected-digest)
  "Hash exactly the private bytes later parsed; never reopen the caller's source."
  (let ((fd (sb-posix:open (namestring source) (logior sb-posix:o-rdonly sb-posix:o-nofollow sb-posix:o-nonblock) 0))
        (input nil) (hash (ironclad:make-digest :sha256))
        (buffer (make-array 65536 :element-type '(unsigned-byte 8))) (copied 0))
    (unwind-protect
         (let ((stat (sb-posix:fstat fd)))
           (unless (and (sb-posix:s-isreg (sb-posix:stat-mode stat)) (plusp (sb-posix:stat-size stat)))
             (error "Snapshot source must be a nonempty regular file"))
           (setf input (sb-sys:make-fd-stream fd :input t :element-type '(unsigned-byte 8) :auto-close t))
           (with-open-stream (output (open-snapshot-generation-output target :binary t))
             (loop for count = (read-sequence buffer input) while (plusp count) do
               (incf copied count)
               (when (> copied (sb-posix:stat-size stat)) (error "Snapshot source grew during copy"))
               (ironclad:update-digest hash buffer :end count)
               (write-sequence buffer output :end count))
             (unless (and (= copied (sb-posix:stat-size stat))
                          (equal expected-digest (ironclad:byte-array-to-hex-string (ironclad:produce-digest hash))))
               (error "Snapshot artifact size or digest mismatch"))
             (finish-output output)
             (sb-posix:fsync (sb-sys:fd-stream-fd output))))
      (if input (close input) (sb-posix:close fd)))))

(defun snapshot-observation-record (record)
  "Omit absent fields instead of encoding Lisp/JSON null for legacy checkpoint readers."
  (let* ((object (gethash "object" record)) (metadata (gethash "metadata" object))
         (checkpoint (gethash "checkpoint" record))
         (result (core-object "formatVersion" 1 "uid" (gethash "uid" metadata)
                              "name" (gethash "name" metadata) "namespace" (gethash "namespace" metadata)
                              "conditions" (gethash "conditions" checkpoint))))
    (dolist (field '("clientStatus" "status" "finalization"))
      (when (hash-table-p (gethash field checkpoint)) (setf (gethash field result) (gethash field checkpoint))))
    (when (gethash "status" result)
      (setf (gethash "observedResourceVersion" result) (gethash "observedResourceVersion" checkpoint)))
    result))

(defun rebase-snapshot-resource-object (object offset minimum maximum)
  "Translate a freshly decoded object into the new local revision epoch.
Versions older than the retained interval clamp to the minimum, so current and
historical views agree without reusing pre-restore public versions. Secret AAD
uses resource/namespace/name/key identity, not this public resourceVersion."
  (when (hash-table-p object)
    (let* ((metadata (gethash "metadata" object))
           (version (and (hash-table-p metadata) (gethash "resourceVersion" metadata)))
           (revision (and (stringp version) (parse-integer version :junk-allowed nil))))
      (unless (and revision (<= 0 revision maximum))
        (error "Invalid snapshot object revision during epoch rebase"))
      (setf (gethash "resourceVersion" metadata)
            (write-to-string (max minimum (+ revision offset))))))
  object)

(defun materialize-store-snapshot (root source expected-digest &key expected-index expected-term
                                                                minimum-resource-revision minimum-pod-revision
                                                                (generation-id (generate-uid)))
  "Build and complete a fresh application generation; NEVER select it or mutate a live store.
An expected SHA256 binds the artifact to its descriptor. Pre-completion failures
retain an incomplete private generation. A completion sync error may leave its
validated marker visible. This function never writes the live selector."
  (unless (and (stringp expected-digest) (= 64 (length expected-digest))
               (every (lambda (c) (find c "0123456789abcdef")) expected-digest))
    (error "Invalid expected snapshot digest"))
  (dolist (minimum (list minimum-resource-revision minimum-pod-revision))
    (unless (or (null minimum) (typep minimum '(unsigned-byte 64)))
      (error "Invalid snapshot materialization revision minimum")))
  (let* ((path (gr8s.store::create-store-generation root generation-id))
         (artifact (merge-pathnames "staging-artifact.part" path))
         (staged (gr8s.store::make-pod-store (uiop:ensure-directory-pathname root)))
         (fields '("items" "customResourceItems" "workloadDeletions" "jobControllerStates" "templateHistory"))
         (spools nil) (tracker-output nil) (tracker-count 0) (counts (make-hash-table :test #'equal))
         (header nil) (clocks nil) (target-clocks nil) (record-count nil)
         (resource-offset 0) (source-resource-revision 0) (pod-rebased nil))
    (setf (gr8s.store::pod-store-data-root staged) path)
    (dolist (directory '("objects/" "nodes/" "observations/" "publications/" "metadata/" "image-tracker/"))
      (gr8s.store::ensure-store-generation-directory (merge-pathnames directory path) path))
    (unwind-protect
         (progn
           (copy-snapshot-generation-source (pathname source) artifact expected-digest)
           (setf tracker-output (open-snapshot-generation-output (merge-pathnames "image-tracker/state.jsonl" path)))
           (dolist (field fields)
             (push (cons field (open-snapshot-generation-output
                               (merge-pathnames (format nil "staging-~A.part" field) path))) spools))
           (labels ((emit (field object &optional key)
                      (let ((stream (cdr (assoc field spools :test #'equal))))
                        (when (plusp (gethash field counts 0)) (write-char #\, stream))
                        (incf (gethash field counts 0))
                        (when key (com.inuoe.jzon:stringify key :stream stream) (write-char #\: stream))
                        (com.inuoe.jzon:stringify object :stream stream))))
             (multiple-value-setq (header clocks record-count)
               (validate-store-snapshot
                artifact :expected-index expected-index :expected-term expected-term
                :function
                (lambda (record)
                  (let ((kind (gethash "kind" record)) (object (gethash "object" record)))
                    (cond
                      ((equal kind "clocks")
                       ;; Keep the validator's source clocks untouched.
                       (setf target-clocks (alexandria:copy-hash-table record))
                       (setf source-resource-revision (gethash "resourceRevision" record))
                       (when minimum-resource-revision
                         ;; Move the retained interval into a fresh epoch, not
                         ;; merely its final clock. Keeping the interval width
                         ;; avoids exponential revision growth on repeated restore.
                         (setf resource-offset
                               (max 0 (- minimum-resource-revision (gethash "templateHistoryFloor" record))))
                         (let ((revision (+ source-resource-revision resource-offset)))
                           (unless (< revision (1- (expt 2 64)))
                             (error "No resource revision space remains after restore"))
                           (setf (gethash "resourceRevision" target-clocks) revision
                                 (gethash "templateHistoryFloor" target-clocks)
                                 (+ (gethash "templateHistoryFloor" record) resource-offset)
                                 (gethash "resourceHistoryStart" target-clocks)
                                 (max minimum-resource-revision
                                      (+ (gethash "resourceHistoryStart" record) resource-offset)))))
                       (when minimum-pod-revision
                         (setf pod-rebased (> minimum-pod-revision (gethash "podRevision" record))
                               (gethash "podRevision" target-clocks)
                               (max minimum-pod-revision (gethash "podRevision" record)))
                         (unless (< (+ (gethash "podRevision" target-clocks) gr8s.store::*pod-revision-reservation*)
                                    (1- (expt 2 64)))
                           (error "No Pod revision reservation space remains after restore"))))
                      ((gr8s.image-distribution::image-tracker-record-p record)
                       (com.inuoe.jzon:stringify record :stream tracker-output)
                       (terpri tracker-output)
                       (incf tracker-count))
                      ((equal kind "resource")
                       (when minimum-resource-revision
                         (rebase-snapshot-resource-object object resource-offset
                                                          minimum-resource-revision source-resource-revision))
                       (let ((resource (gethash "resource" record)))
                         (if (custom-resource-key-p resource)
                             (emit "customResourceItems" (core-object "resource" resource "object" object))
                             (emit "items" object))))
                      ((equal kind "workloadDeletion") (emit "workloadDeletions" (gethash "value" record) (gethash "key" record)))
                      ((equal kind "jobControllerState") (emit "jobControllerStates" (gethash "value" record) (gethash "key" record)))
                      ((equal kind "history")
                       (let ((entry (gethash "entry" record)))
                         (when minimum-resource-revision
                           (incf (gethash "revision" entry) resource-offset)
                           (dolist (field '("old" "new"))
                             (rebase-snapshot-resource-object
                              (gethash field entry) resource-offset minimum-resource-revision source-resource-revision))
                           ;; Metadata strings changed; do not reuse stale heap estimates.
                           (remhash "bytes" entry)
                           (remhash "bytesVersion" entry))
                         (emit "templateHistory" entry)))
                      ((equal kind "node")
                       (when pod-rebased
                         (setf (gethash "resourceVersion" object) (write-to-string (gethash "podRevision" target-clocks))))
                       (write-snapshot-generation-json
                        (merge-pathnames (format nil "nodes/~A.json" (gethash "id" object)) path) object))
                      ((equal kind "pod")
                       (when pod-rebased
                         ;; Desired/observation revisions are shared Raft CAS
                         ;; identities. Rebase only the member's API publication.
                         (setf (gethash "resourceVersion" (gethash "publication" record))
                               (write-to-string (gethash "podRevision" target-clocks))))
                       (let* ((pod (gr8s.store::store-parse-pod object)) (uid (pod-uid pod))
                              (publication (gethash "publication" record)))
                         (write-snapshot-generation-json (merge-pathnames (format nil "~A.json" uid) path) object)
                         (write-snapshot-generation-json (gr8s.store::pod-status-state-path staged uid)
                                                         (snapshot-observation-record record))
                         (gr8s.store::persist-pod-publication
                          staged pod :status (gethash "status" publication)
                          :revision (parse-integer (gethash "resourceVersion" publication)))))))))))
           (setf clocks target-clocks)
           (finish-output tracker-output)
           (sb-posix:fsync (sb-sys:fd-stream-fd tracker-output))
           (close tracker-output)
           (when (zerop tracker-count) (delete-file (merge-pathnames "image-tracker/state.jsonl" path)))
           (dolist (spool spools) (close (cdr spool)))
           (write-snapshot-generation-file
            (core-resource-state-path staged)
            (lambda (stream)
              (write-char #\{ stream)
              (let ((metadata (core-object "version" 2 "revision" (gethash "resourceRevision" clocks)
                                           "templateHistoryFloor" (gethash "templateHistoryFloor" clocks)
                                           "secretsEncryption" (gethash "secretsEncryption" clocks 'null)
                                           "resourceHistoryStart" (gethash "resourceHistoryStart" clocks)
                                           "eventExpirations" (core-object)))
                    (buffer (make-string 65536)))
                (let ((key (gethash "templateTokenKey" clocks)))
                  (when (stringp key) (setf (gethash "templateTokenKey" metadata) key)))
                (maphash (lambda (key value)
                           (com.inuoe.jzon:stringify key :stream stream) (write-char #\: stream)
                           (com.inuoe.jzon:stringify value :stream stream) (write-char #\, stream)) metadata)
                (loop for field in fields for first = t then nil do
                  (unless first (write-char #\, stream))
                  (com.inuoe.jzon:stringify field :stream stream) (write-char #\: stream)
                  (let ((map-p (member field '("workloadDeletions" "jobControllerStates") :test #'equal)))
                    (write-char (if map-p #\{ #\[) stream)
                    (with-open-file (input (merge-pathnames (format nil "staging-~A.part" field) path)
                                           :external-format :utf-8)
                      (loop for count = (read-sequence buffer input) while (plusp count)
                            do (write-sequence buffer stream :end count)))
                    (write-char (if map-p #\} #\]) stream))))
              (write-char #\} stream)))
           (dolist (name '("metadata/consensus-pod-revision.txt" "pod-revision.ceiling"))
             (write-snapshot-generation-file
              (merge-pathnames name path)
              (lambda (stream) (write-string (write-to-string (gethash "podRevision" clocks)) stream))))
           (write-snapshot-generation-json
            (merge-pathnames "metadata/snapshot-boundary.json" path)
            (core-object "version" 1 "index" (gethash "index" header) "term" (gethash "term" header)
                         "resourceRevision" (gethash "resourceRevision" clocks) "podRevision" (gethash "podRevision" clocks)
                         "resourceEpochFloor" (gethash "resourceHistoryStart" clocks)
                         "podEpochFloor" (if minimum-pod-revision (gethash "podRevision" clocks)
                                             (gethash "podEpochFloor" clocks 0))))
           (dolist (field fields) (delete-file (merge-pathnames (format nil "staging-~A.part" field) path)))
           (delete-file artifact)
           (dolist (directory '("objects/" "nodes/" "observations/" "publications/" "metadata/" "image-tracker/" ""))
             (gr8s.store::sync-store-generation-directory (merge-pathnames directory path)))
           (let ((descriptor (gr8s.store::complete-store-generation
                              root generation-id (gethash "index" header) (gethash "term" header) expected-digest)))
             (values path descriptor record-count)))
      (when (and tracker-output (open-stream-p tracker-output)) (close tracker-output))
      (dolist (spool spools) (when (open-stream-p (cdr spool)) (close (cdr spool)))))))
