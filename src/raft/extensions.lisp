;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; gr8s-specific extensions layered over the cl-raft engine.
;;;;
;;;; The library's RAFT-APPEND-MESSAGE computes a bounded cached catch-up prefix
;;;; inline.  The snapshot transport needs that prefix on its own, independent of
;;;; a peer's snapshot preference, so gr8s factors it out here over the library's
;;;; node and storage accessors.

(in-package #:gr8s.raft)

(defun raft-cached-append-message (node peer)
  "Return a bounded real cached prefix, independent of snapshot preference."
  (let* ((next (gethash peer (raft-node-next-index node) (1+ (raft-last-log-index node))))
         (cached (when (and (raft-node-catchup-byte-limit node)
                            (<= next (raft-node-snapshot-index node)))
                   (raft-storage-read-catchup (raft-node-storage node) node next))))
    (when cached
      (list :type :append-entries :term (raft-node-current-term node) :from (raft-node-id node)
            :prev-log-index (1- next) :prev-log-term (car cached) :entries (cdr cached)
            :leader-commit (raft-node-commit-index node)))))
