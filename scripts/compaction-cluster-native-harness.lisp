;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;; Internal HCP worker/transport probe; offline TLS, not production serve.
(in-package #:cl-user)

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
               (lock (bt:make-lock "compaction probe state"))
               (armed nil) (held nil) (held-index nil) (stopping nil)
               (completed 0) (finished nil) (failure nil) (refusals 0) (conflict-retries 0)
               (loaded-history (reduce #'+ (gr8s::pod-store-template-history store)
                                       :key #'gr8s.resources::template-history-entry-bytes)))
          (labels
              ((retry-write (function)
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
               (input (name value)
                 (gr8s::core-object "apiVersion" "v1" "kind" "ConfigMap"
                   "metadata" (gr8s::core-object "name" name)
                   "data" (gr8s::core-object "value" value)))
               (status ()
                 (let ((object
                         (bt:with-lock-held ((gr8s::raft-member-lock member))
                           (bt:with-lock-held ((gr8s::pod-store-lock store))
                             (let ((node (gr8s::raft-member-node member)))
                               (gr8s::core-object
                                "role" (string-downcase (symbol-name (gr8s::raft-node-role node)))
                                "selfRole" (string-downcase (symbol-name (gr8s::raft-node-self-role node)))
                                "term" (gr8s::raft-node-current-term node)
                                "commit" (gr8s::raft-node-commit-index node)
                                "applied" (gr8s::raft-node-last-applied node)
                                "snapshot" (gr8s::raft-node-snapshot-index node)
                                "quorumMembers" (gr8s::raft-cluster-size node)
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
                   (setf (gethash "blocked" object) (if (gr8s.store::store-access-blocked-p store) t nil))
                   (bt:with-lock-held ((gr8s.ha::ha-control-plane-compaction-lock ha))
                     (setf (gethash "checkpoints" object) (gr8s.ha::ha-control-plane-compaction-count ha)
                           (gethash "compactionError" object) (gr8s.ha::ha-control-plane-compaction-error ha)))
                   (bt:with-lock-held (lock)
                     (setf (gethash "captureHeld" object) (if held t nil)
                           (gethash "heldIndex" object) held-index
                           (gethash "completedRounds" object) completed
                           (gethash "churnFinished" object) (if finished t nil)
                           (gethash "replicationCapacityRefusals" object) refusals
                           (gethash "committedConflictRetries" object) conflict-retries
                           (gethash "churnError" object) failure))
                   object))
               (churn ()
                 (handler-case
                     (progn
                       (dotimes (i (parse-integer rounds-text))
                         ;; Deliberately pause the producer between transactions
                         ;; while held captures leave room for a marker write.
                         (loop while (bt:with-lock-held (lock) (and held (not stopping))) do (sleep 0.02))
                         (retry-write (lambda () (gr8s::create-core-resource store "configmaps"
                                                   (input "churn" (make-string 65536 :initial-element #\x)) "default")))
                         (retry-write (lambda () (gr8s::delete-core-resource store "configmaps" "default" "churn")))
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
                           (bt:with-lock-held (lock)
                             (when armed (setf armed nil held t held-index (gr8s.resources::frozen-store-snapshot-index view))))
                           (loop while (bt:with-lock-held (lock) (and held (not stopping))) do (sleep 0.02))
                           (funcall original view path)))
                   (setf (symbol-function 'gr8s.raft::raft-replication-capacity-index)
                         (lambda (node previous entries)
                           (let ((denied (funcall original-capacity node previous entries)))
                             (when denied (bt:with-lock-held (lock) (incf refusals)))
                             denied)))
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
                                      ((equal command "hold-capture") (bt:with-lock-held (lock) (setf armed t)) (gr8s::core-object "armed" t))
                                      ((equal command "release-capture") (bt:with-lock-held (lock) (setf held nil)) (gr8s::core-object "released" t))
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
                    (symbol-function 'gr8s.raft::raft-replication-capacity-index) original-capacity)))))
    (error (condition) (format *error-output* "Compaction cluster probe failed: ~A~%" condition) (uiop:quit 1))))
