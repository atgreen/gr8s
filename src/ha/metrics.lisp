;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
(in-package #:gr8s.ha)

(defun ha-metrics-text (hcp)
  "Copy local Raft/worker measurements without encoding commands or changing state."
  (let ((member (ha-control-plane-member hcp)) (samples nil) (peers nil) (phases nil) (sections nil) (receives nil))
    (bt:with-lock-held ((raft-member-lock member))
      (let* ((node (raft-member-node member))
             (last (gr8s.raft::raft-last-log-index node))
             (commit (raft-node-commit-index node))
             (log (gr8s.raft:raft-node-log node)))
        (setf samples
              (list (list "gr8s_raft_term" "Current local Raft term." (gr8s.raft:raft-node-current-term node))
                    (list "gr8s_raft_is_leader" "Whether this member currently believes it is leader; not a quorum probe."
                          (if (eq :leader (gr8s.raft:raft-node-role node)) 1 0))
                    (list "gr8s_raft_commit_index" "Local committed log index." commit)
                    (list "gr8s_raft_applied_index" "Local applied log index." (raft-node-last-applied node))
                    (list "gr8s_raft_snapshot_index" "Local durable snapshot index." (raft-node-snapshot-index node))
                    (list "gr8s_raft_apply_lag_entries" "Committed entries not yet applied locally."
                          (max 0 (- commit (raft-node-last-applied node))))
                    (list "gr8s_raft_retained_entries" "Entries retained in the local Raft log." (length log))
                    (list "gr8s_raft_uncommitted_entries" "Local entries beyond the commit index." (max 0 (- last commit)))
                    (list "gr8s_raft_retained_bytes" "Estimated retained command bytes using the admission estimator."
                          (loop for entry across log
                                sum (+ 128 (funcall (gr8s.raft::raft-node-uncommitted-weight-fn node)
                                                    (gr8s.raft:raft-entry-command entry)))))))
        (when (gr8s.raft::raft-node-retained-byte-limit node)
          (push (list "gr8s_raft_retained_limit_bytes" "Configured retained-log admission budget."
                      (gr8s.raft::raft-node-retained-byte-limit node)) samples))
        (multiple-value-bind (bytes count) (gr8s.raft::raft-storage-catchup-usage (gr8s.raft:raft-node-storage node))
          (push (list "gr8s_raft_catchup_cache_bytes" "Physical bytes retained in anonymous catch-up segments." bytes) samples)
          (push (list "gr8s_raft_catchup_cache_segments" "Anonymous catch-up segment descriptors retained locally." count) samples))
        (when (gr8s.raft::raft-node-catchup-byte-limit node)
          (push (list "gr8s_raft_catchup_cache_limit_bytes" "Configured disk catch-up cache budget."
                      (gr8s.raft::raft-node-catchup-byte-limit node)) samples))
        (push (list "gr8s_raft_catchup_cache_error" "Whether the disk cache encountered an error since its last successful segment."
                    (if (and (typep (gr8s.raft:raft-node-storage node) 'gr8s.raft::file-raft-storage)
                             (gr8s.raft::file-raft-storage-catchup-error (gr8s.raft:raft-node-storage node))) 1 0)) samples)
        (maphash
         (lambda (id link)
           (bt:with-lock-held ((gr8s.raft.transport::raft-peer-link-lock link))
             (when (gr8s.raft.transport::raft-member-configured-peer-p member id)
               (push (list id (gr8s.raft.transport::raft-peer-link-received-messages link)
                           (when (eql (gr8s.raft:raft-node-current-term node)
                                      (gr8s.raft.transport::raft-peer-link-last-receive-term link))
                             (gr8s.raft.transport::raft-peer-link-last-receive-ticks link))) receives))
             (push (list id
                         (when (eq :leader (gr8s.raft:raft-node-role node))
                           (max 0 (- last (gethash id (gr8s.raft:raft-node-match-index node) 0))))
                         (+ (length (gr8s.raft.transport::raft-peer-link-items link))
                            (length (gr8s.raft.transport::raft-peer-link-active-items link)))) peers)))
         (gr8s.raft.transport::raft-member-links member))))
    (bt:with-lock-held ((ha-control-plane-compaction-lock hcp))
      (setf phases (loop for name in '("freeze" "capture" "retain" "publish")
                         for row across (ha-control-plane-compaction-phase-times hcp)
                         collect (cons name (if row (coerce row 'list) '(0 0 0 0 0 0 0)))))
      (setf sections
            (loop for name in '("check" "freeze" "publish" "resume")
                  for row across (ha-control-plane-compaction-member-lock-times hcp)
                  collect (cons name (if row (coerce row 'list) '(0 0 0 0 0 0 0)))))
      (setf samples
            (append samples
                    (list (list "gr8s_compaction_completed_total" "Successful local automatic/manual worker checkpoints."
                                (ha-control-plane-compaction-count hcp) "counter")
                          (list "gr8s_compaction_in_flight" "Whether a local worker capture/publication is in progress."
                                (if (ha-control-plane-compaction-in-flight hcp) 1 0))
                          (list "gr8s_compaction_error" "Whether the worker retains an error since its last successful checkpoint."
                                (if (ha-control-plane-compaction-error hcp) 1 0))))))
    (bt:with-lock-held ((ha-control-plane-maintenance-lock hcp))
      (push (list "gr8s_generation_reaped_files_total" "Retired application data files reclaimed locally."
                  (ha-control-plane-generation-reaped-files hcp) "counter") samples)
      (push (list "gr8s_generation_reclamation_error" "Whether the last maintenance attempt failed."
                  (if (ha-control-plane-maintenance-error hcp) 1 0)) samples)
      (push (list "gr8s_generation_reclamation_worker_up" "Whether the local generation maintenance thread is alive."
                  (if (and (ha-control-plane-maintenance-thread hcp)
                           (bt:thread-alive-p (ha-control-plane-maintenance-thread hcp))) 1 0)) samples))
    (with-output-to-string (out)
      (dolist (sample (sort samples #'string< :key #'first))
        (destructuring-bind (name help value &optional (type "gauge")) sample
          (gr8s.kubelet::write-prometheus-family out name help type (list (list nil value)))))
      (loop for (prefix label rows) in
              (list (list "gr8s_compaction_phase_" "phase" phases)
                    (list "gr8s_compaction_member_lock_" "section" sections))
            do (loop for (suffix help type column) in
                     '(("observations_total" "Executed attempts, including abnormal exits." "counter" 0)
                       ("duration_seconds_total" "Total monotonic execution time; excludes lock acquisition wait." "counter" 1)
                       ("duration_seconds_max" "Longest observed execution since control-plane startup." "gauge" 2)
                       ("duration_seconds_last" "Latest observed execution time." "gauge" 3)
                       ("gc_seconds_total" "Sum of process GC-time deltas during executions; not exclusive attribution." "counter" 4)
                       ("gc_seconds_max" "Largest process GC-time delta during an execution." "gauge" 5)
                       ("gc_seconds_last" "Process GC-time delta during the latest execution." "gauge" 6))
                     do (gr8s.kubelet::write-prometheus-family
                         out (concatenate 'string prefix suffix) help type
                         (loop for (name . row) in rows
                               collect (list (list (cons label name))
                                             (if (zerop column) (nth column row)
                                                 (/ (float (nth column row) 1d0)
                                                    internal-time-units-per-second)))))))
      (gr8s.kubelet::write-prometheus-family
       out "gr8s_raft_peer_received_messages_total"
       "Recognized current-term messages from configured peers dispatched normally; link lifetime, not quorum health." "counter"
       (loop for (id count ticks) in receives collect (list (list (cons "peer" id)) count)))
      (gr8s.kubelet::write-prometheus-family
       out "gr8s_raft_peer_receive_observed"
       "Whether a configured peer has a normal recognized message receipt in the current local term." "gauge"
       (loop for (id count ticks) in receives collect (list (list (cons "peer" id)) (if ticks 1 0))))
      (gr8s.kubelet::write-prometheus-family
       out "gr8s_raft_peer_last_receive_age_seconds"
       "Monotonic age of last recognized current-term receipt; omitted before observation or after term change." "gauge"
       (loop with now = (get-internal-real-time)
             for (id count ticks) in receives when ticks
               collect (list (list (cons "peer" id))
                             (/ (float (max 0 (- now ticks)) 1d0) internal-time-units-per-second))))
      (gr8s.kubelet::write-prometheus-family
       out "gr8s_raft_peer_replication_lag_entries" "Leader's last log index minus peer acknowledged match index; leader only." "gauge"
       (loop for (id lag queued) in peers when lag collect (list (list (cons "peer" id)) lag)))
      (gr8s.kubelet::write-prometheus-family
       out "gr8s_raft_peer_outbox_messages" "Queued plus sender-owned messages on each configured peer link." "gauge"
       (loop for (id lag queued) in peers collect (list (list (cons "peer" id)) queued))))))
