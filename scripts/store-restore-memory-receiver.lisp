;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;; Child process for GR8S_SNAPSHOT_LIVE_TRANSFER memory acceptance.
(require :asdf)
(asdf:load-asd (truename "gr8s.asd"))
(asdf:load-system "gr8s")
(destructuring-bind (root-string count-string ready-string report-string stop-string)
    (let ((args (uiop:command-line-arguments)))
      (if (equal "--" (first args)) (rest args) args))
  (let* ((root (uiop:ensure-directory-pathname root-string))
         (count (parse-integer count-string))
         (store (gr8s:open-store root))
         (member (gr8s::start-raft-member "sink" :storage-path (merge-pathnames "raft/wal" root)))
         (reported nil))
    (unwind-protect
         (progn
           (gr8s.resources::configure-member-store-restore member store)
           (gr8s::write-private-text-atomically ready-string (write-to-string (gr8s::raft-member-port member)))
           (loop until (probe-file stop-string) do
             (when (and (not reported)
                        (bt:with-lock-held ((gr8s::raft-member-lock member))
                          (= 1 (gr8s::raft-node-last-applied (gr8s::raft-member-node member))))
                        (not (gr8s.store::store-access-blocked-p store)))
               (let ((object (gr8s::get-core-resource store "configmaps" "default" (format nil "config-~D" (1- count)))))
                 (assert (= count (hash-table-count (gr8s::pod-store-resources store))))
                 (assert (= 65536 (length (gethash "payload" (gethash "data" object)))))
                 (assert (null (gr8s.store::read-store-restore-intent root)))
                 (gr8s::write-private-text-atomically
                  report-string
                  (com.inuoe.jzon:stringify
                   (gr8s::core-object "passed" t "liveApplicationRestore" t "records" count
                                     "payloadBytes" (* count 65536) "appliedIndex" 1
                                     "resourceRevision" (gr8s::pod-store-resource-revision store))))
                 (setf reported t)))
             (sleep 0.05)))
      (gr8s::stop-raft-member member))))
