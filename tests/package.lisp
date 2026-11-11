(defpackage #:gr8s/tests
  (:use #:cl #:fiveam)
  (:import-from #:gr8s
                #:create-pod
                #:container-spec-args
                #:container-spec-command
                #:container-spec-env
                #:container-spec-image
                #:container-spec-name
                #:container-spec-ports
                #:kubernetes-error
                #:kubernetes-error-reason
                #:delete-pod
                #:fake-runtime-ensure-count
                #:get-pod
                #:list-pods
                #:make-fake-runtime
                #:make-reconciler
                #:mark-pod-deleting
                #:open-store
                #:parse-pod
                #:pod-containers
                #:pod-name
                #:pod-namespace
                #:pod-restart-policy
                #:parse-cli-options
                #:pod-resource-version
                #:pod-to-object
                #:pod-uid
                #:reconcile-all
                #:reconcile-pod
                #:reconciler-logs
                #:runtime-observe
                #:runtime-delete
                #:runtime-ensure
                #:runtime-error
                #:runtime-error-message
                #:runtime-logs
                #:runtime-pod-resource-version
                #:runtime-pod-phase
                #:runtime-pod-uid
                #:set-fake-runtime-failure
                #:start-server
                #:start-reconciliation-worker
                #:stop-reconciliation-worker
                #:stop-server
                #:update-pod))

(in-package #:gr8s/tests)

(def-suite gr8s)
(in-suite gr8s)

(eval-when (:compile-toplevel :load-toplevel :execute)
  ;; Several gr8s tests exercise engine internals that now live in the extracted
  ;; ocicl libraries.  Expose those symbols on the gr8s facades for the test run
  ;; only -- keeping the production packages' surface minimal -- so the existing
  ;; integration tests keep reaching them through the gr8s.* names they always
  ;; used.
  (flet ((rehome (lib pkg names)
           (let ((lp (find-package lib)) (pp (find-package pkg)))
             (dolist (name names)
               (let ((sym (find-symbol name lp)))
                 (if sym
                     (shadowing-import sym pp)
                     (warn "test re-home: ~A has no ~A" lib name)))))))
    (rehome '#:cl-raft '#:gr8s.raft
            (list
                   "FILE-RAFT-CHECKPOINT-SYNC"
                   "FILE-RAFT-STORAGE-CATCHUP-ERROR"
                   "FILE-RAFT-STORAGE-CATCHUP-SEGMENTS"
                   "FILE-RAFT-STORAGE-ENTRY-FRAMES"
                   "FILE-RAFT-STORAGE-STREAM"
                   "FILE-RAFT-TAIL-SYNC"
                   "FILE-RAFT-WRITE"
                   "LOAD-RAFT-LOG"
                   "MAKE-RAFT-ENTRY"
                   "MAKE-RAFT-NODE"
                   "RAFT-APPEND-MESSAGE"
                   "RAFT-APPLY-COMMITTED"
                   "RAFT-BECOME-LEADER"
                   "RAFT-CAPTURE-SNAPSHOT"
                   "RAFT-CATCHUP-EVICT"
                   "RAFT-CATCHUP-FRAMED-PREFIX-SIZE"
                   "RAFT-CATCHUP-SEGMENT-FD"
                   "RAFT-COMMIT-PREPARED-COMPACTION"
                   "RAFT-CONFIGURE"
                   "RAFT-HANDLE-APPEND-ENTRIES"
                   "RAFT-HANDLE-APPEND-ENTRIES-REPLY"
                   "RAFT-HANDLE-INSTALL-SNAPSHOT-REPLY"
                   "RAFT-LOG-TERM"
                   "RAFT-NODE-APPEND-BYTE-BUDGET"
                   "RAFT-NODE-APPEND-ENTRY-LIMIT"
                   "RAFT-NODE-CATCHUP-BYTE-LIMIT"
                   "RAFT-NODE-PEER-APPLIED"
                   "RAFT-NODE-PEER-SNAPSHOT-REQUIRED"
                   "RAFT-NODE-PENDING"
                   "RAFT-NODE-RETAINED-BYTE-LIMIT"
                   "RAFT-NODE-UNCOMMITTED-BYTE-LIMIT"
                   "RAFT-PERSIST-HARD-STATE"
                   "RAFT-PREPARE-COMPACTION"
                   "RAFT-RECOVERED-COMMIT-INDEX"
                   "RAFT-RECOVERED-ENTRIES"
                   "RAFT-RESTORE-SNAPSHOT-CONTENTS"
                   "RAFT-SET-COMMIT-INDEX"
                   "RAFT-SET-HARD-STATE"
                   "RAFT-STORAGE-APPEND-ENTRY"
                   "RAFT-STORAGE-CATCHUP-USAGE"
                   "RAFT-STORAGE-CLEAR-CATCHUP"
                   "RAFT-STORAGE-READ-CATCHUP"
                   "RAFT-STORAGE-REPLACE-SNAPSHOT"
                   "RAFT-STORAGE-SAVE-HARD-STATE"
                   "RAFT-WAL-FORM-METRICS"
                   "RAFT-WAL-WRITE-FRAME"
                   "RECOVER-RAFT-NODE"))
    (rehome '#:cl-raft '#:gr8s.raft (list "+RAFT-WAL-HEADER-LENGTH+"))
    (rehome '#:cl-torrent '#:gr8s.image-distribution (list "BENCODE-MAP-ENTRIES"))
    (rehome '#:cl-work-queue '#:gr8s (list "WORK-QUEUE-LANES"))
    (rehome '#:cl-cronexpr '#:gr8s (list "*CRON-ZONES*" "*CRON-ZONES-LOCK*"))))
