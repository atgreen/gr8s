;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;; sbcl --dynamic-space-size 384 --noinform --non-interactive --load scripts/test-store-snapshot-memory.lisp
;;;; Set GR8S_SNAPSHOT_LEGACY=1 to exercise whole-state JSON materialization.
(require :asdf)
(asdf:load-asd (truename "gr8s.asd"))
(asdf:load-system "gr8s")
(defun transfer-memory-test-artifact (root reference)
  (let ((sink-root (merge-pathnames "transfer-sink/" root))
        (sender nil) (receiver nil) (channel nil) (restored nil))
    (sb-posix:mkdir (namestring sink-root) #o700)
    (unwind-protect
         (progn
           (setf sender (gr8s::start-raft-member "source")
                 receiver (gr8s::start-raft-member "sink" :storage-path (merge-pathnames "raft/wal" sink-root)
                            :restore-fn (lambda (ref) (setf restored ref))))
           (gr8s.resources::configure-store-artifact-transport sender root)
           (gr8s.resources::configure-store-artifact-transport receiver sink-root)
           (setf channel (gr8s::make-raft-channel nil "127.0.0.1" (gr8s::raft-member-port receiver) 2))
           (gr8s.raft.transport::raft-link-send-snapshot
            sender (gr8s.node.v1::make-raft-transport-stub channel)
            (list :type :install-snapshot :term 1 :from "source" :last-index 1 :last-term 1
                  :state (list :gr8s-raft-snapshot 1 :application reference :application-present t
                               :members '(("source" . :voter) ("sink" . :learner)) :addresses nil :api-urls nil)))
           (assert (equal reference restored))
           (assert (= 1 (gr8s::raft-node-last-applied (gr8s::raft-member-node receiver))))
           (gr8s.resources::checked-store-snapshot-artifact-path sink-root reference))
      (when channel (ag-grpc:channel-close channel))
      (when receiver (gr8s::stop-raft-member receiver))
      (when sender (gr8s::stop-raft-member sender)))))

(defun transfer-live-memory-test-artifact (root reference count)
  (let* ((sink-root (merge-pathnames "live-transfer-sink/" root))
         (ready (merge-pathnames "receiver-ready.txt" root))
         (report (merge-pathnames "receiver-report.json" root))
         (stop (merge-pathnames "receiver-stop.txt" root))
         (log (merge-pathnames "receiver.log" root))
         (process nil) (sender nil) (channel nil) (completed nil))
    (sb-posix:mkdir (namestring sink-root) #o700)
    (labels ((await-file (path timeout)
               (loop with deadline = (+ (get-internal-real-time) (* timeout internal-time-units-per-second))
                     until (or (probe-file path) (not (sb-ext:process-alive-p process))
                               (>= (get-internal-real-time) deadline)) do (sleep 0.05))
               (unless (probe-file path)
                 (error "Live restore receiver did not produce ~A:~%~A" path (uiop:read-file-string log)))))
      (unwind-protect
           (progn
             (setf process
                   (sb-ext:run-program "sbcl"
                    (list "--dynamic-space-size" "384" "--noinform" "--non-interactive" "--load"
                          (namestring (truename "scripts/store-restore-memory-receiver.lisp")) "--"
                          (namestring sink-root) (write-to-string count) (namestring ready) (namestring report) (namestring stop))
                    :search t :wait nil :input nil :output log :error :output))
             (await-file ready 120)
             (setf sender (gr8s::start-raft-member "source"))
             (gr8s.resources::configure-store-artifact-transport sender root)
             (setf channel (gr8s::make-raft-channel nil "127.0.0.1" (parse-integer (uiop:read-file-string ready)) 2))
             (gr8s.raft.transport::raft-link-send-snapshot
              sender (gr8s.node.v1::make-raft-transport-stub channel)
              (list :type :install-snapshot :term 1 :from "source" :last-index 1 :last-term 1
                    :state (list :gr8s-raft-snapshot 1 :application reference :application-present t
                                 :members '(("source" . :voter) ("sink" . :learner)) :addresses nil :api-urls nil)))
             (await-file report 60)
             (let ((result (com.inuoe.jzon:parse (uiop:read-file-string report))))
               (assert (eq t (gethash "passed" result)))
               (assert (= count (gethash "records" result)))
               (setf completed t)
               (values (gr8s.resources::checked-store-snapshot-artifact-path sink-root reference) result)))
        (when channel (ag-grpc:channel-close channel))
        (when sender (gr8s::stop-raft-member sender))
        (when process
          (ignore-errors (gr8s::write-private-text-atomically stop "stop"))
          (loop repeat 200 while (sb-ext:process-alive-p process) do (sleep 0.05))
          (when (sb-ext:process-alive-p process) (sb-ext:process-kill process 9))
          (sb-ext:process-wait process)
          (let ((exit-code (sb-ext:process-exit-code process)))
            (sb-ext:process-close process)
            (when (and completed (not (eql 0 exit-code)))
              (error "Live restore receiver failed during shutdown:~%~A" (uiop:read-file-string log)))))))))

(let* ((directory (merge-pathnames (format nil "gr8s-artifact-memory-~A/" (gr8s::generate-uid))
                                  (uiop:temporary-directory)))
       (count (parse-integer (or (uiop:getenv "GR8S_SNAPSHOT_RECORDS") "1024")))
       (bytes 65536)
       (validated-count nil)
       (materialized-count nil)
       (reload-descriptor nil)
       (reloaded nil)
       (retained nil) (retained-reference nil) (transferred nil) (receiver-report nil)
       (live-transfer (equal "1" (uiop:getenv "GR8S_SNAPSHOT_LIVE_TRANSFER")))
       (transfer (or live-transfer (equal "1" (uiop:getenv "GR8S_SNAPSHOT_TRANSFER"))))
       (retain (or transfer (equal "1" (uiop:getenv "GR8S_SNAPSHOT_RETAIN"))))
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
                   retained (equal path target) retained-reference reference)))
         (when (and transfer (not legacy))
           (if live-transfer
               (multiple-value-setq (target receiver-report)
                 (transfer-live-memory-test-artifact directory retained-reference count))
               (setf target (transfer-memory-test-artifact directory retained-reference)))
           (setf transferred t))
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
                        "reloadedSameStore" reloaded "retainedArtifactAfterTransferCleanup" retained "transferredArtifact" transferred "liveReceiver" receiver-report "payloadBytes" (* count bytes)
                        "artifactBytes" (sb-posix:stat-size (sb-posix:stat (namestring target))))))
           (unless reloaded
             (setf (gethash "residentSourceResources" result) (hash-table-count (gr8s::pod-store-resources store))))
           (format t "~&~A~%" (com.inuoe.jzon:stringify result))))
    (uiop:delete-directory-tree directory :validate t :if-does-not-exist :ignore)))
