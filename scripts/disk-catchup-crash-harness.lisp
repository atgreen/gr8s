;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;; Internal Raft storage crash probe, not production serve acceptance.
(require :asdf)
(asdf:load-asd (truename "gr8s.asd"))
(asdf:load-system "gr8s")
(in-package #:gr8s.raft)
(destructuring-bind (mode root-text) (uiop:command-line-arguments)
  (let* ((root (uiop:ensure-directory-pathname root-text))
         (path (merge-pathnames "control-plane.log" root)))
    (cond
      ((equal mode "hold")
       (let* ((storage (open-file-raft-storage path))
              (node (make-raft-node :id "crash-probe" :role :leader :current-term 2
                                   :storage storage :catchup-byte-limit (* 8 1024 1024)
                                   :commit-index 3 :last-applied 3
                                   :log (make-array 3 :adjustable t :fill-pointer 3
                                          :initial-contents
                                          (loop for i from 1 to 3 collect
                                            (make-raft-entry :index i :term 2 :command (list :payload i)))))))
         (raft-persist-hard-state node)
         (map nil (lambda (entry) (raft-storage-append-entry storage entry)) (raft-node-log node))
         (raft-storage-save-commit-index storage 3)
         (raft-compact node 3)
         (assert (= 1 (nth-value 1 (raft-storage-catchup-usage storage))))
         (let* ((segment (first (file-raft-storage-catchup-segments storage)))
                (fd (raft-catchup-segment-fd segment)))
           (assert (zerop (sb-posix:stat-nlink (sb-posix:fstat fd))))
           (with-open-file (out (merge-pathnames "ready.json" root) :direction :output :if-exists :error)
             (format out "{\"pid\":~D,\"fd\":~D,\"bytes\":~D}" (sb-posix:getpid) fd
                     (raft-storage-catchup-usage storage))))
         ;; Intentionally no orderly cleanup: the parent kills this process.
         (loop (sleep 1))))
      ((equal mode "recover")
       (let ((node (make-raft-node :id "crash-probe")))
         (recover-raft-node node path)
         (unwind-protect
              (progn
                (assert (= 3 (raft-node-snapshot-index node)))
                (assert (= 3 (raft-node-commit-index node)))
                (assert (= 2 (raft-node-current-term node)))
                (assert (zerop (length (raft-node-log node))))
                (assert (zerop (raft-storage-catchup-usage (raft-node-storage node))))
                (assert (zerop (nth-value 1 (raft-storage-catchup-usage (raft-node-storage node)))))
                (with-open-file (out (merge-pathnames "recovered.json" root) :direction :output :if-exists :error)
                  (write-string "{\"recovered\":true,\"snapshot\":3,\"commit\":3,\"cacheBytes\":0}" out)))
           (close-file-raft-storage (raft-node-storage node)))))
      (t (error "Unknown crash probe mode")))))
