(defpackage #:gr8s/tests
  (:use #:cl #:fiveam)
  (:import-from #:gr8s.apiserver
                #:start-server
                #:stop-server)
  (:import-from #:gr8s.kubelet
                #:make-reconciler
                #:parse-pod
                #:reconcile-all
                #:reconcile-pod
                #:reconciler-logs)
  (:import-from #:gr8s.model
                #:container-spec-args
                #:container-spec-command
                #:container-spec-env
                #:container-spec-image
                #:container-spec-name
                #:container-spec-ports
                #:kubernetes-error
                #:kubernetes-error-reason
                #:pod-containers
                #:pod-name
                #:pod-namespace
                #:pod-resource-version
                #:pod-restart-policy
                #:pod-to-object
                #:pod-uid)
  (:import-from #:gr8s.runtime
                #:fake-runtime-ensure-count
                #:make-fake-runtime
                #:runtime-delete
                #:runtime-ensure
                #:runtime-error
                #:runtime-error-message
                #:runtime-logs
                #:runtime-observe
                #:runtime-pod-phase
                #:runtime-pod-resource-version
                #:runtime-pod-uid
                #:set-fake-runtime-failure)
  (:import-from #:gr8s.server
                #:parse-cli-options
                #:start-reconciliation-worker
                #:stop-reconciliation-worker)
  (:import-from #:gr8s.store
                #:create-pod
                #:delete-pod
                #:get-pod
                #:list-pods
                #:mark-pod-deleting
                #:open-store
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
    (rehome '#:cl-torrent '#:gr8s.image-distribution (list "BENCODE-MAP-ENTRIES"))))
