;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;; Internal HCP worker/transport probe; offline TLS, not production serve.
(in-package #:cl-user)

(defun compaction-native-try-sample (member-lock store-lock function)
  "Return only fresh progress, or an explicit busy observation without progress."
  (or (sb-thread:with-mutex (member-lock :wait-p nil)
        (or (sb-thread:with-mutex (store-lock :wait-p nil) (funcall function))
            (gr8s::core-object "busy" t "busyLock" "store" "blocked" t)))
      (gr8s::core-object "busy" t "busyLock" "member" "blocked" t)))

(defun compaction-cluster-native-main ()
  (when (equal "--prepare-tls" (first (uiop:command-line-arguments)))
    (learner-native-prepare-tls (second (uiop:command-line-arguments))
                               (cddr (uiop:command-line-arguments)))
    (return-from compaction-cluster-native-main))
  (gr8s.server::install-memory-hooks)
  (handler-case
      (destructuring-bind (root-text id mode port-text rounds-text delay-text &optional tls-flag)
          (uiop:command-line-arguments)
        (declare (ignore delay-text))
        (setf gr8s.store::*podtemplate-clock* (constantly 4000000000))
        (let* ((root (uiop:ensure-directory-pathname root-text))
               (control (merge-pathnames "harness/" root))
               (request-path (merge-pathnames "request.json" control))
               (response-path (merge-pathnames "response.json" control))
               (store (gr8s:open-store root)) (member nil) (ha nil) (producer nil)
               (original (symbol-function 'gr8s.resources::capture-frozen-store-snapshot))
               (original-capacity (symbol-function 'gr8s.raft::raft-replication-capacity-index))
               (original-catchup (symbol-function 'gr8s.raft::raft-storage-read-catchup))
               (original-cache-prefix (symbol-function 'gr8s.raft::raft-storage-cache-prefix))
               (original-replace-wal (symbol-function 'gr8s.raft::raft-storage-replace-snapshot))
               (storage-stages (make-hash-table :test #'equal))
               (lock (bt:make-lock "compaction probe state"))
               (armed nil) (held nil) (held-index nil) (stopping nil)
               (completed 0) (finished nil) (failure nil) (refusals 0) (conflict-retries 0) (cache-batches 0)
               (loaded-history (reduce #'+ (gr8s::pod-store-template-history store)
                                       :key #'gr8s.resources::template-history-entry-bytes)))
          (labels
              ((timed-storage-stage (name function)
                 (let ((started (get-internal-real-time)))
                   (unwind-protect (funcall function)
                     (let ((elapsed (/ (- (get-internal-real-time) started)
                                       (float internal-time-units-per-second 1d0))))
                       (bt:with-lock-held (lock)
                         (let ((row (or (gethash name storage-stages)
                                        (setf (gethash name storage-stages) (vector 0 0d0 0d0 0d0)))))
                           (incf (aref row 0)) (incf (aref row 1) elapsed)
                           (setf (aref row 2) (max (aref row 2) elapsed) (aref row 3) elapsed)))))))
               (retry-write (function)
                 (let ((deadline (+ (get-internal-real-time) (* 120 internal-time-units-per-second))))
                   (loop
                     (when (bt:with-lock-held (lock) stopping) (error "Probe stopping"))
                     (handler-case (progn (funcall function) (return t))
                       (gr8s:kubernetes-error (condition)
                         (cond
                           ((= 503 (gr8s::kubernetes-error-status-code condition)))
                           ;; CORE-CONFLICT is a committed no-op: rebuilding the
                           ;; transaction against the now-current state is safe.
                           ;; Do not retry AlreadyExists or arbitrary conflicts.
                           ((and (= 409 (gr8s::kubernetes-error-status-code condition))
                                 (equal "Resource changed before its consensus transaction committed"
                                        (gr8s::kubernetes-error-message condition)))
                            (bt:with-lock-held (lock) (incf conflict-retries)))
                           (t (error condition)))))
                     (when (> (get-internal-real-time) deadline) (error "Probe write timed out"))
                     (sleep 0.02))))
               (find-owned (name value &optional uid)
                 (handler-case
                     (let* ((object (gr8s::get-core-resource store "configmaps" "default" name))
                            (actual (gethash "uid" (gethash "metadata" object))))
                       (unless (and (stringp actual) (plusp (length actual))
                                    (or (null uid) (equal uid actual))
                                    (equal value (gethash "value" (gethash "data" object))))
                         (error "Probe object identity/content changed: ~A" name))
                       actual)
                   (gr8s:kubernetes-error (condition)
                     (if (= 404 (gr8s::kubernetes-error-status-code condition)) nil
                         (error condition)))))
               (create-owned (name value)
                 ;; A lost reply can follow a committed create. Only this
                 ;; operation's private key and exact payload prove success.
                 (let ((uid nil))
                   (retry-write
                    (lambda ()
                      (handler-case
                          (gr8s::create-core-resource store "configmaps" (input name value) "default")
                        (gr8s:kubernetes-error (condition)
                          (unless (and (= 409 (gr8s::kubernetes-error-status-code condition))
                                       (equal "AlreadyExists" (gr8s::kubernetes-error-reason condition)))
                            (error condition))))
                      (setf uid (find-owned name value))
                      (unless uid (error "Created probe object disappeared: ~A" name))))
                   uid))
               (delete-owned (name value uid)
                 (retry-write (lambda ()
                                (unless (find-owned name value uid)
                                  (error "Probe object absent before its first delete: ~A" name))))
                 (retry-write
                  (lambda ()
                    ;; Absence is success only after our own delete attempt,
                    ;; following a confirmed create of this unique round key.
                    (handler-case
                        (gr8s::delete-core-resource store "configmaps" "default" name :uid uid)
                      (gr8s:kubernetes-error (condition)
                        (unless (= 404 (gr8s::kubernetes-error-status-code condition))
                          (error condition))))
                    (when (find-owned name value uid)
                      (error "Deleted probe object remains: ~A" name)))))
               (input (name value)
                 (gr8s::core-object "apiVersion" "v1" "kind" "ConfigMap"
                   "metadata" (gr8s::core-object "name" name)
                   "data" (gr8s::core-object "value" value)))
               (peer-progress ()
                 ;; STATUS already holds the member mutex. Never encode command
                 ;; payloads, only bounded queue descriptors and scalar progress.
                 (let ((node (gr8s::raft-member-node member)))
                   (coerce
                    (loop for id being the hash-keys of (gr8s.raft.transport::raft-member-links member)
                            using (hash-value link)
                          collect
                          (bt:with-lock-held ((gr8s.raft.transport::raft-peer-link-lock link))
                            (gr8s::core-object
                             "peer" id
                             "nextIndex" (gethash id (gr8s.raft:raft-node-next-index node) 0)
                             "matchIndex" (gethash id (gr8s.raft:raft-node-match-index node) 0)
                             "snapshotRequired" (if (gethash id (gr8s.raft::raft-node-peer-snapshot-required node)) t nil)
                             "senderAlive" (if (and (gr8s.raft.transport::raft-peer-link-thread link)
                                                    (bt:thread-alive-p (gr8s.raft.transport::raft-peer-link-thread link))) t nil)
                             "queuedCount" (length (gr8s.raft.transport::raft-peer-link-items link))
                             "queuedTypes" (coerce
                                            (loop for message in (gr8s.raft.transport::raft-peer-link-items link)
                                                  for i below 4 collect (string-downcase (symbol-name (getf message :type)))) 'vector)
                             "activeSnapshots" (coerce
                                                (loop for message in (gr8s.raft.transport::raft-peer-link-active-items link)
                                                      for i below 4 when (eq :install-snapshot (getf message :type))
                                                        collect (getf message :last-index)) 'vector))))
                    'vector)))
               (status ()
                 (let* ((artifact-keep nil)
                        (object
                         (compaction-native-try-sample
                          (gr8s::raft-member-lock member) (gr8s::pod-store-lock store)
                          (lambda ()
                             (let ((node (gr8s::raft-member-node member)))
                               (setf artifact-keep (gr8s.resources::store-snapshot-artifact-keep-digests-unlocked member root))
                               (gr8s::core-object
                                "busy" nil
                                "blocked" (if (gr8s.store::pod-store-access-blocked store) t nil)
                                "role" (string-downcase (symbol-name (gr8s::raft-node-role node)))
                                "selfRole" (string-downcase (symbol-name (gr8s::raft-node-self-role node)))
                                "term" (gr8s::raft-node-current-term node)
                                "gcCpuSeconds" (/ sb-ext:*gc-run-time* (float internal-time-units-per-second 1d0))
                                "gcWallSeconds" (/ sb-ext:*gc-real-time* (float internal-time-units-per-second 1d0))
                                "peerProgress" (peer-progress)
                                "commit" (gr8s::raft-node-commit-index node)
                                "applied" (gr8s::raft-node-last-applied node)
                                "snapshot" (gr8s::raft-node-snapshot-index node)
                                "quorumMembers" (gr8s::raft-cluster-size node)
                                "compactionEntryThreshold" (gr8s.ha::ha-control-plane-compaction-entries ha)
                                "configMaps"
                                (coerce
                                 (sort
                                  (loop for key being the hash-keys of (gr8s::pod-store-resources store)
                                        using (hash-value object)
                                        when (and (equal "configmaps" (first key))
                                                  (equal "default" (second key)))
                                          collect (vector (third key)
                                                          (gethash "uid" (gethash "metadata" object))
                                                          (gethash "value" (gethash "data" object))))
                                  #'string< :key (lambda (row) (aref row 0)))
                                 'vector)
                                "catchupCacheBytes" (gr8s.raft::raft-storage-catchup-usage (gr8s.raft:raft-node-storage node))
                                "catchupCacheSegments" (nth-value 1 (gr8s.raft::raft-storage-catchup-usage (gr8s.raft:raft-node-storage node)))
                                "retainedBudgetBytes" (or (gr8s.raft::raft-node-retained-byte-limit node) 0)
                                "retainedEstimatedBytes"
                                (loop for entry across (gr8s.raft:raft-node-log node)
                                      sum (+ 128 (gr8s.ha::store-raft-command-retention-weight
                                                  (gr8s.raft:raft-entry-command entry))))
                                "historyEstimatedBytes" (reduce #'+ (gr8s::pod-store-template-history store)
                                                         :key #'gr8s.resources::template-history-entry-bytes)
                                "loadedHistoryEstimatedBytes" loaded-history
                                "heapAfterGcBytes" gr8s.server::*heap-after-gc*
                                "heapLimitMiB" (/ (sb-ext:dynamic-space-size) (* 1024 1024))
                                "mutualTls" (if (gr8s.raft.transport::raft-member-credentials member) t nil)))))))
                   (when (gethash "busy" object) (return-from status object))
                   (let ((base (gr8s.store::store-generation-base root))
                         (retired (merge-pathnames "metadata/retired-generations/" root))
                         (generations 0) (trash 0) (records 0))
                     (when (gr8s.store::store-generation-stat base)
                       (gr8s.store::map-generation-directory-entries
                        base (lambda (name)
                               (cond ((gr8s.store::store-generation-id-p name) (incf generations))
                                     ((uiop:string-prefix-p ".retired-" name) (incf trash))) t)))
                     (when (gr8s.store::store-generation-stat retired)
                       (gr8s.store::map-generation-directory-entries
                        retired (lambda (name) (when (equal (pathname-type name) "json") (incf records)) t)))
                     (setf (gethash "applicationGenerationCount" object) generations
                           (gethash "retiredGenerationCount" object) records
                           (gethash "generationTrashCount" object) trash))
                   (let ((registry (merge-pathnames "snapshot-artifacts/" root))
                         (canonical 0) (trash 0) (reclaimable 0))
                     (when (gr8s.store::store-generation-stat registry)
                       (gr8s.store::check-store-generation-directory registry)
                       (gr8s.raft.transport::raft-snapshot-map-directory
                        registry (lambda (name)
                                   (cond ((gr8s.resources::store-snapshot-artifact-trash-name-p name) (incf trash))
                                         ((gr8s.resources::store-snapshot-artifact-filename-p name)
                                          (incf canonical)
                                          (unless (gethash (subseq name 0 64) artifact-keep)
                                            (let ((stat (gr8s.store::store-generation-stat (merge-pathnames name registry))))
                                              (when (and stat (gr8s.raft.transport::raft-snapshot-private-stat-p stat nil))
                                                (incf reclaimable)))))))))
                     (setf (gethash "artifactCanonicalCount" object) canonical
                           (gethash "artifactProtectedCount" object) (hash-table-count artifact-keep)
                           (gethash "artifactReclaimableCount" object) reclaimable
                           (gethash "artifactTrashCount" object) trash))
                   (bt:with-lock-held ((gr8s.ha::ha-control-plane-maintenance-lock ha))
                     (setf (gethash "artifactFilesReaped" object) (gr8s.ha::ha-control-plane-artifacts-reaped ha)
                           (gethash "artifactMaintenanceError" object) (gr8s.ha::ha-control-plane-artifact-maintenance-error ha)
                           (gethash "generationFilesReaped" object) (gr8s.ha::ha-control-plane-generation-reaped-files ha)
                           (gethash "maintenanceError" object) (gr8s.ha::ha-control-plane-maintenance-error ha)
                           (gethash "maintenanceWorkerUp" object)
                           (if (and (gr8s.ha::ha-control-plane-maintenance-thread ha)
                                    (bt:thread-alive-p (gr8s.ha::ha-control-plane-maintenance-thread ha))) t nil)))
                   (bt:with-lock-held ((gr8s.ha::ha-control-plane-compaction-lock ha))
                     (setf (gethash "checkpoints" object) (gr8s.ha::ha-control-plane-compaction-count ha)
                           (gethash "compactionError" object) (gr8s.ha::ha-control-plane-compaction-error ha)
                           (gethash "compactionPhases" object)
                           (coerce
                            (loop for name in '("freeze" "capture" "retain" "publish")
                                  for row across (gr8s.ha::ha-control-plane-compaction-phase-times ha)
                                  collect (gr8s::core-object
                                           "phase" name "attempts" (if row (aref row 0) 0)
                                           "totalSeconds" (/ (if row (aref row 1) 0) (float internal-time-units-per-second 1d0))
                                           "maxSeconds" (/ (if row (aref row 2) 0) (float internal-time-units-per-second 1d0))
                                           "lastSeconds" (/ (if row (aref row 3) 0) (float internal-time-units-per-second 1d0))
                                           "gcTotalSeconds" (/ (if row (aref row 4) 0) (float internal-time-units-per-second 1d0))
                                           "gcMaxSeconds" (/ (if row (aref row 5) 0) (float internal-time-units-per-second 1d0))
                                           "gcLastSeconds" (/ (if row (aref row 6) 0) (float internal-time-units-per-second 1d0))))
                            'vector)
                           (gethash "compactionMemberLocks" object)
                           (coerce
                            (loop for name in '("check" "freeze" "publish" "resume")
                                  for row across (gr8s.ha::ha-control-plane-compaction-member-lock-times ha)
                                  collect (gr8s::core-object
                                           "section" name "attempts" (if row (aref row 0) 0)
                                           "totalSeconds" (/ (if row (aref row 1) 0) (float internal-time-units-per-second 1d0))
                                           "maxSeconds" (/ (if row (aref row 2) 0) (float internal-time-units-per-second 1d0))
                                           "lastSeconds" (/ (if row (aref row 3) 0) (float internal-time-units-per-second 1d0))
                                           "gcTotalSeconds" (/ (if row (aref row 4) 0) (float internal-time-units-per-second 1d0))
                                           "gcMaxSeconds" (/ (if row (aref row 5) 0) (float internal-time-units-per-second 1d0))
                                           "gcLastSeconds" (/ (if row (aref row 6) 0) (float internal-time-units-per-second 1d0))))
                            'vector)))
                   (bt:with-lock-held (lock)
                     (setf (gethash "captureHeld" object) (if held t nil)
                           (gethash "heldIndex" object) held-index
                           (gethash "completedRounds" object) completed
                           (gethash "churnFinished" object) (if finished t nil)
                           (gethash "replicationCapacityRefusals" object) refusals
                           (gethash "committedConflictRetries" object) conflict-retries
                           (gethash "catchupCacheBatches" object) cache-batches
                           (gethash "storageStages" object)
                           (coerce (loop for name in '("cache-prefix" "replace-wal")
                                         for row = (gethash name storage-stages)
                                         when row collect
                                           (gr8s::core-object "stage" name "attempts" (aref row 0)
                                             "totalSeconds" (aref row 1) "maxSeconds" (aref row 2)
                                             "lastSeconds" (aref row 3))) 'vector)
                           (gethash "churnError" object) failure))
                   object))
               (churn ()
                 (handler-case
                     (progn
                       (dotimes (i (parse-integer rounds-text))
                         ;; Deliberately pause the producer between transactions
                         ;; while held captures leave room for a marker write.
                         (loop while (bt:with-lock-held (lock) (and held (not stopping))) do (sleep 0.02))
                         (let* ((name (format nil "churn-~D" i))
                                (value (make-string 65536 :initial-element #\x))
                                (uid (create-owned name value)))
                           (delete-owned name value uid))
                         (bt:with-lock-held (lock) (setf completed (1+ i))))
                       (bt:with-lock-held (lock) (setf finished t)))
                   (error (condition) (bt:with-lock-held (lock) (setf failure (princ-to-string condition)))))))
            (unwind-protect
                 (progn
                   (setf member (gr8s.resources::start-store-member-from-wal
                                 store id (merge-pathnames "raft/control-plane.log" root)
                                 :bootstrap-role (cond ((equal mode "founder") :founder) ((equal mode "learner") :learner))
                                 :credentials (when (equal tls-flag "--tls")
                                                (gr8s.security::load-raft-credentials (merge-pathnames "tls/" root)))
                                 :port (parse-integer port-text)))
                   (bt:with-lock-held ((gr8s::raft-member-lock member))
                     (setf (gr8s.raft::raft-node-uncommitted-byte-limit (gr8s::raft-member-node member)) (* 16 1024 1024)
                           (gr8s.raft::raft-node-uncommitted-weight-fn (gr8s::raft-member-node member))
                           #'gr8s.ha::store-raft-command-retention-weight))
                   (gr8s::raft-member-start member)
                   (setf ha (gr8s.ha::make-ha-control-plane :member member :store store
                             :compaction-bytes (* 16 1024 1024) :compaction-entries 100000 :compaction-interval 0.01)
                         (symbol-function 'gr8s.resources::capture-frozen-store-snapshot)
                         (lambda (view path)
                           (bt:with-lock-held ((gr8s::raft-member-lock member))
                             (bt:with-lock-held (lock)
                               (when armed
                                 (setf armed nil held t held-index (gr8s.resources::frozen-store-snapshot-index view)
                                       (gr8s.ha::ha-control-plane-compaction-entries ha) 100000))))
                           (loop while (bt:with-lock-held (lock) (and held (not stopping))) do (sleep 0.02))
                           (funcall original view path)))
                   (setf (symbol-function 'gr8s.raft::raft-replication-capacity-index)
                         (lambda (node previous entries)
                           (let ((denied (funcall original-capacity node previous entries)))
                             (when denied (bt:with-lock-held (lock) (incf refusals)))
                             denied)))
                   (setf (symbol-function 'gr8s.raft::raft-storage-read-catchup)
                         (lambda (storage node next)
                           (let ((result (funcall original-catchup storage node next)))
                             (when result (bt:with-lock-held (lock) (incf cache-batches)))
                             result)))
                   (setf (symbol-function 'gr8s.raft::raft-storage-cache-prefix)
                         (lambda (&rest arguments)
                           (timed-storage-stage "cache-prefix" (lambda () (apply original-cache-prefix arguments))))
                         (symbol-function 'gr8s.raft::raft-storage-replace-snapshot)
                         (lambda (&rest arguments)
                           (timed-storage-stage "replace-wal" (lambda () (apply original-replace-wal arguments)))))
                   (gr8s.ha::start-ha-maintenance-worker ha)
                   (gr8s.ha::start-ha-compaction-worker ha)
                   (learner-native-write-json (merge-pathnames "ready.json" control) (gr8s::core-object "ready" t))
                   (loop
                     (when (probe-file request-path)
                       (let* ((request (with-open-file (stream request-path) (com.inuoe.jzon:parse stream)))
                              (command (gethash "command" request))
                              (response
                                (handler-case
                                    (cond
                                      ((equal command "status") (status))
                                      ((equal command "join")
                                       (gr8s::core-object "accepted" (if (gr8s::raft-cluster-join member "127.0.0.1" (gethash "port" request)) t nil)))
                                      ((equal command "namespace")
                                       (retry-write (lambda () (gr8s::create-core-resource store "namespaces"
                                                                (gr8s::core-object "apiVersion" "v1" "kind" "Namespace"
                                                                  "metadata" (gr8s::core-object "name" "default")) nil)))
                                       (gr8s::core-object "committed" t))
                                      ((equal command "write")
                                       (retry-write (lambda () (gr8s::create-core-resource store "configmaps"
                                                                (input (gethash "name" request) (gethash "value" request)) "default")))
                                       (gr8s::core-object "committed" t))
                                      ((equal command "read")
                                       (let ((object nil))
                                         (retry-write (lambda ()
                                                        (setf object (gr8s::get-core-resource
                                                                      store "configmaps" "default" (gethash "name" request)))))
                                         (gr8s::core-object "value" (gethash "value" (gethash "data" object)))))
                                      ((equal command "hold-capture")
                                       ;; A prior replay phase leaves different WAL
                                       ;; tails. Force only the next capture's entry
                                       ;; trigger, restoring normal policy in its hook.
                                       (bt:with-lock-held ((gr8s::raft-member-lock member))
                                         (bt:with-lock-held (lock)
                                           (setf armed t (gr8s.ha::ha-control-plane-compaction-entries ha) 1)))
                                       (gr8s::core-object "armed" t))
                                      ((equal command "release-capture") (bt:with-lock-held (lock) (setf held nil)) (gr8s::core-object "released" t))
                                      ((equal command "prefix-churn")
                                       (let ((count (gethash "rounds" request)))
                                         (unless (typep count '(integer 1 36)) (error "Invalid prefix fixture rounds"))
                                         (dotimes (i count)
                                           (let* ((name (format nil "archived-prefix-~D" i))
                                                  (value (make-string 65536 :initial-element #\p))
                                                  (uid (create-owned name value)))
                                             (delete-owned name value uid)))
                                         (gr8s::core-object "rounds" count "payloadBytes" (* count 65536))))
                                      ((equal command "start-churn")
                                       (when producer (error "Producer already started"))
                                       (setf producer (bt:make-thread #'churn :name "compaction probe producer"))
                                       (gr8s::core-object "started" t))
                                      ((equal command "stop") (gr8s::core-object "stopped" t))
                                      (t (error "Unknown probe command")))
                                  (error (condition) (gr8s::core-object "error" (princ-to-string condition))))))
                         (delete-file request-path)
                         (setf (gethash "nonce" response) (gethash "nonce" request))
                         (learner-native-write-json response-path response)
                         (when (equal command "stop") (return))))
                     (sleep 0.02)))
              (bt:with-lock-held (lock) (setf stopping t held nil))
              (when producer (bt:join-thread producer))
              (when ha (gr8s::stop-ha-control-plane ha))
              (when (and member (null ha)) (gr8s::stop-raft-member member))
              (setf (symbol-function 'gr8s.resources::capture-frozen-store-snapshot) original
                    (symbol-function 'gr8s.raft::raft-replication-capacity-index) original-capacity
                    (symbol-function 'gr8s.raft::raft-storage-read-catchup) original-catchup
                    (symbol-function 'gr8s.raft::raft-storage-cache-prefix) original-cache-prefix
                    (symbol-function 'gr8s.raft::raft-storage-replace-snapshot) original-replace-wal)))))
    (error (condition) (format *error-output* "Compaction cluster probe failed: ~A~%" condition) (uiop:quit 1))))
