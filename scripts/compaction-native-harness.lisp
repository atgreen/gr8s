;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;; Native internal HA compaction acceptance; no containers, BPF, or serve.
(in-package #:cl-user)

(defun compaction-native-await (function)
  (let ((deadline (+ (get-internal-real-time) (* 30 internal-time-units-per-second))))
    (loop for result = (funcall function)
          when result return result
          when (> (get-internal-real-time) deadline) do (error "Compaction acceptance timed out")
          do (sleep 0.01))))

(defun compaction-native-write (function)
  (compaction-native-await
   (lambda () (handler-case (progn (funcall function) t)
                (gr8s:kubernetes-error (condition)
                  (unless (= 503 (gr8s::kubernetes-error-status-code condition)) (error condition))
                  nil)))))

(defun compaction-native-root-bytes (root)
  "Diagnostic estimate with identity deduplication, without copying payloads."
  (let ((seen (make-hash-table :test 'eq)))
    (labels ((walk (value)
               (cond ((or (null value) (numberp value) (symbolp value) (characterp value)) 0)
                     ((gethash value seen) 0)
                     (t (setf (gethash value seen) t)
                        (typecase value
                          (string (+ 16 (* (if (typep value 'base-string) 1 4) (length value))))
                          (hash-table (let ((bytes (+ 480 (* 40 (hash-table-count value)))))
                                        (maphash (lambda (key item) (incf bytes (+ (walk key) (walk item)))) value)
                                        bytes))
                          (cons (+ 16 (walk (car value)) (walk (cdr value))))
                          (vector (+ 16 (* 8 (length value)) (loop for item across value sum (walk item))))
                          (t 16))))))
      (walk root))))

(defun compaction-native-cold-recovery (root-text port-text clock-text)
  (let* ((root (uiop:ensure-directory-pathname root-text)) (store nil) (ha nil)
         (result (gr8s::core-object "passed" nil "phase" "cold-recovery"
                   "heapLimitMiB" (/ (sb-ext:dynamic-space-size) (* 1024 1024)))))
    (setf gr8s.store::*podtemplate-clock* (constantly (parse-integer clock-text)))
    (unwind-protect
         (handler-case
             (progn
               (assert (= 384 (gethash "heapLimitMiB" result)))
               (setf (sb-ext:gc-logfile) (namestring (merge-pathnames "cold-gc.log" root))
                     store (gr8s:open-store root :defer-restore-completion t))
               ;; Check the full checkpoint before HA deliberately establishes
               ;; a new watch epoch during application snapshot recovery.
               (let ((history-bytes (reduce #'+ (gr8s::pod-store-template-history store)
                                           :key #'gr8s.resources::template-history-entry-bytes)))
                 (setf (gethash "loadedHistoryEstimatedBytes" result) history-bytes)
                 (assert (>= history-bytes (- gr8s.resources::*resource-watch-history-bytes* (* 2 65536)))))
               (setf ha (gr8s::start-ha-control-plane store :id "compact-native" :init t
                          :port (parse-integer port-text)))
               (compaction-native-await (lambda () (gr8s::ha-control-plane-leader-p ha)))
               (assert (equal "preserved" (gethash "value" (gethash "data"
                         (gr8s::get-core-resource store "configmaps" "default" "sentinel")))))
               (let ((history-bytes (reduce #'+ (gr8s::pod-store-template-history store)
                                           :key #'gr8s.resources::template-history-entry-bytes)))
                 (setf (gethash "historyEstimatedBytes" result) history-bytes))
               (setf (gethash "passed" result) t (gethash "coldRecovery" result) t
                     (gethash "sentinelRecovered" result) t))
           (error (condition) (setf (gethash "error" result) (princ-to-string condition))))
      (when ha (gr8s::stop-ha-control-plane ha)))
    (write-line (com.inuoe.jzon:stringify result))
    (uiop:quit (if (gethash "passed" result) 0 1))))

(defun compaction-native-main ()
  (gr8s.server::install-memory-hooks)
  ;; Host speed must not make this retention probe easier by aging history out.
  ;; Set the process-wide default so the Raft application thread sees it too.
  (setf gr8s.store::*podtemplate-clock* (constantly (get-universal-time)))
  (destructuring-bind (root-text rounds-text &optional recovery-port recovery-clock) (uiop:command-line-arguments)
    (when (equal rounds-text "--recover-only")
      (return-from compaction-native-main
        (compaction-native-cold-recovery root-text recovery-port recovery-clock)))
    (let* ((root (uiop:ensure-directory-pathname root-text)) (rounds (parse-integer rounds-text))
           (store (gr8s:open-store root)) (ha nil) (port nil)
           (max-wal 0) (max-artifacts 0) (max-registry-files 0) (max-history 0) (checkpoints 0) (samples 0)
           (result (gr8s::core-object "passed" nil "nativeHarness" t "productionServe" nil
                     "vmAcceptance" nil "automaticWorker" t "productionDefaultEnabled" nil
                     "rounds" rounds "payloadBytesWritten" (* rounds 65536)
                     "walTriggerBytes" (* 16 1024 1024)
                     "historyClockFrozen" t
                     "historyClock" (funcall gr8s.store::*podtemplate-clock*)
                     "historyByteBudget" gr8s.resources::*resource-watch-history-bytes*
                     "heapLimitMiB" (/ (sb-ext:dynamic-space-size) (* 1024 1024)))))
      ;; Observe the collector's normal decisions, including fragmentation and
      ;; old-generation retention, without forcing collections or tuning policy.
      (setf (sb-ext:gc-logfile) (namestring (merge-pathnames "gc.log" root)))
      (labels ((ready () (gr8s::ha-control-plane-leader-p ha))
               (sample ()
                 (let ((member (gr8s::ha-control-plane-member ha)))
                   (bt:with-lock-held ((gr8s::raft-member-lock member))
                     (let* ((files (uiop:directory-files (merge-pathnames "snapshot-artifacts/" root)))
                            (artifacts (count "jsonl" files :test #'equal :key #'pathname-type))
                            (pins (length (gr8s.raft.transport::raft-member-artifact-pins member))))
                       ;; Bootstrap + current + one pinned candidate; LINK can
                       ;; briefly expose both candidate and its private .part.
                       (assert (<= artifacts (+ 2 pins)))
                       (assert (<= (length files) (+ 2 (* 2 pins))))
                       (setf max-wal (max max-wal (sb-posix:stat-size
                                                  (sb-posix:stat (merge-pathnames "raft/control-plane.log" root))))
                             max-artifacts (max max-artifacts artifacts)
                             max-registry-files (max max-registry-files (length files)))))
                   (bt:with-lock-held ((gr8s::raft-member-lock member))
                     (bt:with-lock-held ((gr8s::pod-store-lock store))
                       (let* ((node (gr8s::raft-member-node member))
                              (history (gr8s::pod-store-template-history store))
                              (metrics (gr8s::core-object
                                        "resourceRevision" (gr8s::pod-store-resource-revision store)
                                        "heapAfterGcBytes" gr8s.server::*heap-after-gc*
                                        "historyEstimatedBytes" (reduce #'+ history :key #'gr8s.resources::template-history-entry-bytes)
                                        "historyUniqueBytes" (compaction-native-root-bytes history)
                                        "logRetainedEntries" (length (gr8s.raft:raft-node-log node))
                                        "logCommandHeapBytes" (loop for entry across (gr8s.raft:raft-node-log node)
                                                                   sum (compaction-native-root-bytes (gr8s.raft:raft-entry-command entry))))))
                         (setf max-history (max max-history (gethash "historyEstimatedBytes" metrics)))
                         (format *error-output* "~&compaction progress: ~A~%" (com.inuoe.jzon:stringify metrics))
                         (finish-output *error-output*))))
                   (incf samples))))
        (unwind-protect
             (handler-case
                 (progn
                   (assert (= 384 (gethash "heapLimitMiB" result)))
                   (assert (>= rounds 2048))
                   (setf ha (gr8s::start-ha-control-plane store :id "compact-native" :init t
                             :compaction-bytes (* 16 1024 1024) :compaction-entries 100000 :compaction-interval 0.01)
                         port (gr8s::raft-member-port (gr8s::ha-control-plane-member ha)))
                   (compaction-native-await #'ready)
                   (compaction-native-write
                    (lambda () (gr8s::create-core-resource store "namespaces"
                                  (gr8s::core-object "apiVersion" "v1" "kind" "Namespace"
                                    "metadata" (gr8s::core-object "name" "default")) nil)))
                   (compaction-native-write
                    (lambda () (gr8s::create-core-resource store "configmaps"
                                  (gr8s::core-object "apiVersion" "v1" "kind" "ConfigMap"
                                    "metadata" (gr8s::core-object "name" "sentinel")
                                    "data" (gr8s::core-object "value" "preserved")) "default")))
                   (dotimes (i rounds)
                     (compaction-native-write
                      (lambda () (gr8s::create-core-resource store "configmaps"
                                    (gr8s::core-object "apiVersion" "v1" "kind" "ConfigMap"
                                      "metadata" (gr8s::core-object "name" "churn")
                                      "data" (gr8s::core-object "value" (make-string 65536 :initial-element #\x))) "default")))
                     (compaction-native-write (lambda () (gr8s::delete-core-resource store "configmaps" "default" "churn")))
                     (when (zerop (mod i 32)) (sample)))
                   (compaction-native-await #'ready)
                   (sample)
                   (bt:with-lock-held ((gr8s.ha::ha-control-plane-compaction-lock ha))
                     (setf checkpoints (gr8s.ha::ha-control-plane-compaction-count ha))
                     (assert (null (gr8s.ha::ha-control-plane-compaction-error ha))))
                   (assert (>= checkpoints 2))
                   (assert (< max-wal (* 32 1024 1024)))
                   (assert (<= max-artifacts 3))
                   (assert (>= max-history (- gr8s.resources::*resource-watch-history-bytes* (* 2 65536))))
                   (gr8s::stop-ha-control-plane ha)
                   (assert (null (gr8s.ha::ha-control-plane-compaction-thread ha)))
                   (let ((count (length (uiop:directory-files (merge-pathnames "snapshot-artifacts/" root)))))
                     (setf (gethash "quiescentArtifactCount" result) count)
                     (assert (<= count 2)))
                   ;; Preserve the full retained checkpoint and journal before
                   ;; in-place HA recovery advances the watch epoch. The runner
                   ;; cold-loads this independent disk copy in a fresh process.
                   (uiop:run-program
                    (list "cp" "-a" "--reflink=auto" (namestring root)
                          (namestring (merge-pathnames "cold-state/"
                                        (uiop:pathname-parent-directory-pathname root)))))
                   ;; Recover the existing quiesced store through production's
                   ;; in-place restore barriers. Cold OPEN-STORE is checked by
                   ;; the runner in a fresh process, with the same frozen clock.
                   ;; This fixture owns shutdown's gate and has no external
                   ;; ingress. Release it through the checked lifecycle API so
                   ;; startup can acquire its own gate; the stopped consensus
                   ;; hook remains attached throughout this handoff.
                   (gr8s.store::resume-store-access store)
                   (setf ha (gr8s::start-ha-control-plane store :id "compact-native" :init t :port port))
                   (compaction-native-await #'ready)
                   (assert (equal "preserved" (gethash "value" (gethash "data"
                             (gr8s::get-core-resource store "configmaps" "default" "sentinel")))))
                   (setf (gethash "passed" result) t
                         (gethash "checkpoints" result) checkpoints
                         (gethash "sampledMaxWalBytes" result) max-wal
                         (gethash "sampledMaxArtifactCount" result) max-artifacts
                         (gethash "sampledMaxRegistryFileCount" result) max-registry-files
                         (gethash "sampledMaxHistoryEstimatedBytes" result) max-history
                         (gethash "samples" result) samples
                         (gethash "memberPort" result) port
                         (gethash "inPlaceMemberRecovery" result) t
                         (gethash "sentinelRecovered" result) t))
               (error (condition) (setf (gethash "error" result) (princ-to-string condition))))
          (when ha (gr8s::stop-ha-control-plane ha)))
        (write-line (com.inuoe.jzon:stringify result))
        (uiop:quit (if (gethash "passed" result) 0 1))))))
