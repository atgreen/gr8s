;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Package boundary for the transport-independent Raft consensus engine and
;;;; its durable write-ahead log.
;;;;
;;;; The engine and WAL now live in the standalone cl-raft library (installed via
;;;; ocicl).  gr8s.raft is a thin facade: it inherits the library's public API,
;;;; re-exports it so gr8s.raft.transport and gr8s.ha keep using gr8s.raft as
;;;; before, imports the handful of library internals those packages reach into,
;;;; and adds raft-cached-append-message (see extensions.lisp), a gr8s-specific
;;;; accessor the snapshot transport needs that the library keeps inlined.

(defpackage #:gr8s.raft
  (:use #:cl #:cl-raft)
  ;; Library internals that gr8s.ha / gr8s.raft.transport reach into directly,
  ;; and that raft-cached-append-message is built from.
  (:import-from #:cl-raft
   #:file-raft-storage-catchup-error
   #:file-raft-storage-ownership-fd
   #:raft-command-memory-weight
   #:raft-command-wire-weight
   #:raft-commit-prepared-compaction
   #:raft-node-catchup-byte-limit
   #:raft-node-peer-snapshot-required
   #:raft-node-retained-byte-limit
   #:raft-node-uncommitted-byte-limit
   #:raft-node-uncommitted-weight-fn
   #:raft-prepare-compaction
   #:raft-prepared-compaction-index
   #:raft-prepared-compaction-term
   #:raft-resume-snapshot-install
   #:raft-snapshot-envelope-p
   #:raft-storage-catchup-usage
   #:raft-storage-clear-catchup
   #:raft-storage-read-catchup
   #:raft-validate-snapshot-envelope)
  (:export #:raft-cached-append-message))

;;; Re-export the whole cl-raft public surface through gr8s.raft so packages that
;;; (:use #:gr8s.raft) inherit it exactly as they did the in-tree engine.
(eval-when (:compile-toplevel :load-toplevel :execute)
  (do-external-symbols (symbol '#:cl-raft)
    (export symbol '#:gr8s.raft)))
