;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
(in-package #:gr8s.ha)

(defun ha-metrics-text (hcp)
  "Copy local Raft/worker measurements without encoding commands or changing state."
  (let ((member (ha-control-plane-member hcp)) (samples nil) (peers nil))
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
        (maphash
         (lambda (id link)
           (bt:with-lock-held ((gr8s.raft.transport::raft-peer-link-lock link))
             (push (list id
                         (when (eq :leader (gr8s.raft:raft-node-role node))
                           (max 0 (- last (gethash id (gr8s.raft:raft-node-match-index node) 0))))
                         (+ (length (gr8s.raft.transport::raft-peer-link-items link))
                            (length (gr8s.raft.transport::raft-peer-link-active-items link)))) peers)))
         (gr8s.raft.transport::raft-member-links member))))
    (bt:with-lock-held ((ha-control-plane-compaction-lock hcp))
      (setf samples
            (append samples
                    (list (list "gr8s_compaction_completed_total" "Successful local automatic/manual worker checkpoints."
                                (ha-control-plane-compaction-count hcp) "counter")
                          (list "gr8s_compaction_in_flight" "Whether a local worker capture/publication is in progress."
                                (if (ha-control-plane-compaction-in-flight hcp) 1 0))
                          (list "gr8s_compaction_error" "Whether the worker retains an error since its last successful checkpoint."
                                (if (ha-control-plane-compaction-error hcp) 1 0))))))
    (with-output-to-string (out)
      (dolist (sample (sort samples #'string< :key #'first))
        (destructuring-bind (name help value &optional (type "gauge")) sample
          (gr8s.kubelet::write-prometheus-family out name help type (list (list nil value)))))
      (gr8s.kubelet::write-prometheus-family
       out "gr8s_raft_peer_replication_lag_entries" "Leader's last log index minus peer acknowledged match index; leader only." "gauge"
       (loop for (id lag queued) in peers when lag collect (list (list (cons "peer" id)) lag)))
      (gr8s.kubelet::write-prometheus-family
       out "gr8s_raft_peer_outbox_messages" "Queued plus sender-owned messages on each configured peer link." "gauge"
       (loop for (id lag queued) in peers collect (list (list (cons "peer" id)) queued))))))
