;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;; Source-process fixture for repeated application-WAL crash recovery tests.
(require :asdf)
(asdf:load-asd (truename "gr8s.asd"))
(asdf:load-system "gr8s")
(destructuring-bind (root-string wal-string ready-string report-string stop-string &optional (mode "normal"))
    (let ((args (uiop:command-line-arguments))) (if (equal "--" (first args)) (rest args) args))
  (let* ((root (uiop:ensure-directory-pathname root-string))
         (store (gr8s.store::open-store root))
         (member
           (progn
             (when (equal mode "hold-load")
               (let ((original (symbol-function 'gr8s.store::load-store-application-files)))
                 (setf (symbol-function 'gr8s.store::load-store-application-files)
                       (lambda (incoming)
                         (if (eq incoming store)
                             (progn
                               (gr8s.security::write-private-text-atomically ready-string "{\"phase\":\"loading\"}")
                               (loop (sleep 1)))
                             (funcall original incoming))))))
             (gr8s.resources::start-store-member-from-wal store "sink" wal-string)))
         (server nil) (reported nil))
    (unwind-protect
         (progn
           (setf server (gr8s.apiserver::start-server :address "127.0.0.1" :port 0 :store store :runtime (gr8s.runtime::make-fake-runtime)))
           (let* ((object (gethash '("configmaps" "default" "recover") (gr8s.store::pod-store-resources store)))
                  (node (gr8s.raft.transport::raft-member-node member)))
             (gr8s.security::write-private-text-atomically
              ready-string
              (com.inuoe.jzon:stringify
               (gr8s.resources::core-object "raftPort" (gr8s.raft.transport::raft-member-port member)
                                 "apiPort" (hunchentoot:acceptor-port server)
                                 "baseline" (gethash "k" (gethash "data" object))
                                 "resourceRevision" (gr8s.store::pod-store-resource-revision store)
                                 "term" (cl-raft::raft-node-current-term node)
                                 "vote" (cl-raft::raft-node-voted-for node)
                                 "appliedIndex" (cl-raft::raft-node-last-applied node)))))
           (loop until (probe-file stop-string) do
             (when (and (not reported) (not (gr8s.store::store-access-blocked-p store)))
               (let* ((object (gr8s.resources::get-core-resource store "configmaps" "default" "recover"))
                      (node (gr8s.raft.transport::raft-member-node member)))
                 (gr8s.security::write-private-text-atomically
                  report-string
                  (com.inuoe.jzon:stringify
                   (gr8s.resources::core-object "value" (gethash "k" (gethash "data" object))
                                     "resourceVersion" (gethash "resourceVersion" (gethash "metadata" object))
                                     "appliedIndex" (cl-raft::raft-node-last-applied node)
                                     "lastLogIndex" (cl-raft::raft-last-log-index node))))
                 (setf reported t)))
             (sleep 0.05)))
      (when server (gr8s.apiserver::stop-server server))
      (gr8s.raft.transport::stop-raft-member member))))
