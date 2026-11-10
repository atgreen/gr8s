;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;; Source-process fixture for repeated application-WAL crash recovery tests.
(require :asdf)
(asdf:load-asd (truename "gr8s.asd"))
(asdf:load-system "gr8s")
(destructuring-bind (root-string wal-string ready-string report-string stop-string &optional (mode "normal"))
    (let ((args (uiop:command-line-arguments))) (if (equal "--" (first args)) (rest args) args))
  (let* ((root (uiop:ensure-directory-pathname root-string))
         (store (gr8s:open-store root))
         (member
           (progn
             (when (equal mode "hold-load")
               (let ((original (symbol-function 'gr8s.store::load-store-application-files)))
                 (setf (symbol-function 'gr8s.store::load-store-application-files)
                       (lambda (incoming)
                         (if (eq incoming store)
                             (progn
                               (gr8s::write-private-text-atomically ready-string "{\"phase\":\"loading\"}")
                               (loop (sleep 1)))
                             (funcall original incoming))))))
             (gr8s.resources::start-store-member-from-wal store "sink" wal-string)))
         (server nil) (reported nil))
    (unwind-protect
         (progn
           (setf server (gr8s::start-server :address "127.0.0.1" :port 0 :store store :runtime (gr8s::make-fake-runtime)))
           (let* ((object (gethash '("configmaps" "default" "recover") (gr8s::pod-store-resources store)))
                  (node (gr8s::raft-member-node member)))
             (gr8s::write-private-text-atomically
              ready-string
              (com.inuoe.jzon:stringify
               (gr8s::core-object "raftPort" (gr8s::raft-member-port member)
                                 "apiPort" (hunchentoot:acceptor-port server)
                                 "baseline" (gethash "k" (gethash "data" object))
                                 "resourceRevision" (gr8s::pod-store-resource-revision store)
                                 "term" (gr8s::raft-node-current-term node)
                                 "vote" (gr8s::raft-node-voted-for node)
                                 "appliedIndex" (gr8s::raft-node-last-applied node)))))
           (loop until (probe-file stop-string) do
             (when (and (not reported) (not (gr8s.store::store-access-blocked-p store)))
               (let* ((object (gr8s::get-core-resource store "configmaps" "default" "recover"))
                      (node (gr8s::raft-member-node member)))
                 (gr8s::write-private-text-atomically
                  report-string
                  (com.inuoe.jzon:stringify
                   (gr8s::core-object "value" (gethash "k" (gethash "data" object))
                                     "resourceVersion" (gethash "resourceVersion" (gethash "metadata" object))
                                     "appliedIndex" (gr8s::raft-node-last-applied node)
                                     "lastLogIndex" (gr8s::raft-last-log-index node))))
                 (setf reported t)))
             (sleep 0.05)))
      (when server (gr8s::stop-server server))
      (gr8s::stop-raft-member member))))
