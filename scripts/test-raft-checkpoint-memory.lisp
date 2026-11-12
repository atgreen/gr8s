;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;; Repeated Raft checkpoint reclamation within a 384 MiB dynamic heap.
(require :asdf)
(asdf:load-asd (truename "gr8s.asd"))
(asdf:load-system "gr8s")
(when (uiop:getenv "GR8S_RAFT_LEGACY_CORE") (load (uiop:getenv "GR8S_RAFT_LEGACY_CORE")))
(let* ((root (uiop:ensure-directory-pathname (sb-posix:mkdtemp "/tmp/gr8s-raft-memory-XXXXXX")))
       (path (merge-pathnames "wal" root))
       (storage (gr8s.raft:open-file-raft-storage path))
       (value nil) (node nil) (recovered nil)
       (rounds 16) (batch 128) (payload-bytes (* 64 1024))
       (max-checkpoint-bytes 0) (started (get-internal-real-time)))
  (unwind-protect
       (progn
         (setf node (gr8s.raft:make-raft-node
                     :id "memory" :storage storage
                     :send-fn (lambda (&rest ignored) (declare (ignore ignored)))
                     :apply-fn (lambda (command) (setf value (second command)))
                     :snapshot-fn (lambda () value)))
         (setf (gr8s.raft:raft-node-current-term node) 1
               (gr8s.raft:raft-node-voted-for node) "memory")
         (gr8s.raft:raft-persist-hard-state node)
         (dotimes (round rounds)
           (dotimes (i batch)
             (let ((index (+ 1 i (* round batch))))
               (gr8s.raft:raft-log-append node
                 (gr8s.raft:make-raft-entry
                   :term 1 :command (list :set (list index (make-string payload-bytes :initial-element #\x)))))))
           (let ((boundary (- (gr8s.raft:raft-last-log-index node) 2)))
             (setf (gr8s.raft:raft-node-commit-index node) boundary)
             (gr8s.raft:raft-apply-committed node)
             (assert (= boundary (first value)))
             (gr8s.raft:raft-compact node boundary)
             (assert (= 2 (fill-pointer (gr8s.raft:raft-node-log node))))
             (with-open-file (stream path :element-type '(unsigned-byte 8))
               (setf max-checkpoint-bytes (max max-checkpoint-bytes (file-length stream)))
               (assert (< (file-length stream) (* 256 1024)))))
           (sb-ext:gc :full t))
         (gr8s.raft:close-file-raft-storage storage)
         (setf recovered
               (gr8s.raft:make-raft-node
                 :id "memory" :send-fn (lambda (&rest ignored) (declare (ignore ignored)))
                 :restore-fn (lambda (state) (setf value state))
                 :apply-fn (lambda (command) (setf value (second command)))))
         (gr8s.raft:recover-raft-node recovered path)
         (assert (= (- (* rounds batch) 2) (first value)))
         (setf (gr8s.raft:raft-node-commit-index recovered) (* rounds batch))
         (gr8s.raft:raft-apply-committed recovered)
         (assert (= (* rounds batch) (first value)))
         (format t "~&~A~%"
           (com.inuoe.jzon:stringify
             (gr8s.resources::core-object "passed" t "rounds" rounds "entries" (* rounds batch)
               "payloadBytes" payload-bytes "cumulativePayloadMiB" (/ (* rounds batch payload-bytes) (* 1024 1024))
               "maxCheckpointBytes" max-checkpoint-bytes "retainedTailEntries" 2 "restartRecovered" t
               "heapLimitMiB" (/ (sb-ext:dynamic-space-size) (* 1024 1024))
               "seconds" (/ (- (get-internal-real-time) started) (float internal-time-units-per-second))))))
    (gr8s.raft:close-file-raft-storage storage)
    (when recovered (gr8s.raft:close-file-raft-storage (gr8s.raft:raft-node-storage recovered)))
    (uiop:delete-directory-tree root :validate t :if-does-not-exist :ignore)))
