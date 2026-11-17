;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; `serve --cluster-reset` (podster-0d9): when a committed voter's host is
;;;; gone forever, the survivors have no quorum and no way to commit the
;;;; membership change that would remove it. The reset rewrites the durable WAL
;;;; offline so the local member is the sole voter: the snapshot envelope names
;;;; only it, committed membership changes are neutralized so replay cannot
;;;; resurrect the lost configuration, the uncommitted tail is dropped, and the
;;;; hard-state term is bumped past everything the lost members ever saw.
;;;; The waiting founder's journal must also say WHY it waits.

(in-package #:gr8s/tests)
(def-suite cluster-reset :in gr8s)
(in-suite cluster-reset)

(defmacro with-reset-scratch-directory ((root) &body body)
  `(let ((,root (uiop:ensure-directory-pathname
                 (sb-posix:mkdtemp
                  (namestring (merge-pathnames "gr8s-reset-XXXXXX" (uiop:temporary-directory)))))))
     (unwind-protect (progn ,@body)
       (uiop:delete-directory-tree ,root :validate t :if-does-not-exist :ignore))))

(defun write-two-voter-wal (root)
  "The durable shape of the incident: a snapshot envelope naming voters a and b,
   a committed config change that also admitted c, and an uncommitted config
   change still in flight."
  (ensure-directories-exist (merge-pathnames "raft/" root))
  (let* ((wal (merge-pathnames "raft/control-plane.log" root))
         (storage (gr8s.raft:open-file-raft-storage wal)))
    (unwind-protect
         (progn
           (gr8s.raft::raft-storage-replace-snapshot
            storage 5 1
            '(:cl-raft-snapshot 1
              :application (:gr8s-store-artifact 1 :index 5 :term 1 :sha256 "0123")
              :application-present t
              :members (("a" . :voter) ("b" . :voter))
              :addresses (("a" "10.0.0.1" 7000) ("b" "10.0.0.2" 7000))
              :api-urls (("a" . "https://10.0.0.1:6443") ("b" . "https://10.0.0.2:6443"))
              :promotions nil)
            2 nil #())
           (gr8s.raft:raft-storage-append-entry
            storage (gr8s.raft:make-raft-entry :index 6 :term 2 :command '(:node-delta "{}")))
           (gr8s.raft:raft-storage-append-entry
            storage (gr8s.raft:make-raft-entry
                     :index 7 :term 2
                     :command '(:raft-config :members (("a" . :voter) ("b" . :voter) ("c" . :voter))
                                :addresses (("a" "10.0.0.1" 7000) ("b" "10.0.0.2" 7000) ("c" "10.0.0.3" 7000)))))
           (gr8s.raft:raft-storage-save-commit-index storage 7)
           (gr8s.raft:raft-storage-append-entry
            storage (gr8s.raft:make-raft-entry
                     :index 8 :term 2
                     :command '(:raft-config :members (("a" . :voter) ("d" . :voter))))))
      (gr8s.raft:close-file-raft-storage storage))
    wal))

(test cluster-reset-rewrites-membership-to-the-sole-local-voter
  (with-reset-scratch-directory (root)
    (let ((wal (write-two-voter-wal root)))
      (let ((removed (gr8s.ha:reset-control-plane-membership root "a")))
        (is (equal '("b" "c") (sort removed #'string<))
            "every durably admitted member except the survivor is reported removed"))
      (let* ((recovered (gr8s.raft:load-raft-log wal))
             (state (gr8s.raft:raft-recovered-snapshot-state recovered))
             (plist (cddr state)))
        (is (equal '(("a" . :voter)) (getf plist :members)))
        (is (equal '(("a" "10.0.0.1" 7000)) (getf plist :addresses))
            "the lost members' addresses go with them")
        (is (equal '(("a" . "https://10.0.0.1:6443")) (getf plist :api-urls)))
        (is (null (getf plist :promotions)))
        (is (equal '(:gr8s-store-artifact 1 :index 5 :term 1 :sha256 "0123")
                   (getf plist :application))
            "the application baseline reference is untouched")
        (is (= 3 (gr8s.raft:raft-recovered-term recovered))
            "the hard-state term is bumped past everything the lost members saw")
        (is (= 7 (gr8s.raft:raft-recovered-commit-index recovered)))
        (let ((entries (gr8s.raft:raft-recovered-entries recovered)))
          (is (= 2 (length entries)) "the uncommitted tail is dropped")
          (is (equal '(:node-delta "{}")
                     (gr8s.raft:raft-entry-command (first entries)))
              "committed application entries survive untouched")
          (is (equal '(:store-recovery-barrier)
                     (gr8s.raft:raft-entry-command (second entries)))
              "a committed membership change is neutralized to a no-op"))))))

(test cluster-reset-recovery-elects-the-sole-voter-configuration
  (with-reset-scratch-directory (root)
    (write-two-voter-wal root)
    (gr8s.ha:reset-control-plane-membership root "a")
    (let ((node (cl-raft::make-raft-node :id "a" :send-fn (lambda (&rest args) (declare (ignore args))))))
      (gr8s.raft::recover-raft-node node (merge-pathnames "raft/control-plane.log" root))
      (unwind-protect
           (progn
             (is (null (gr8s.raft:raft-node-peers node))
                 "replaying the reset WAL leaves no peers to wait for")
             (is (eq :voter (gr8s.raft::raft-member-role node "a")))
             (is (= 7 (gr8s.raft:raft-node-commit-index node)))
             (is (= 7 (gr8s.raft:raft-node-last-applied node))
                 "every committed entry applies without a quorum"))
        (gr8s.raft:close-file-raft-storage (gr8s.raft:raft-node-storage node))))))

(test cluster-reset-is-idempotent-and-validates-its-member
  (with-reset-scratch-directory (root)
    (write-two-voter-wal root)
    (is (not (null (gr8s.ha:reset-control-plane-membership root "a"))))
    (is (null (gr8s.ha:reset-control-plane-membership root "a"))
        "a second reset finds the member already alone")
    (signals error (gr8s.ha:reset-control-plane-membership root "nobody"))))

(test cluster-reset-requires-an-existing-wal
  (with-reset-scratch-directory (root)
    (signals error (gr8s.ha:reset-control-plane-membership root "a"))))

(test recovery-wait-report-names-quorum-and-silent-members
  (let* ((node (cl-raft::make-raft-node :id "a" :peers '("b")
                                        :send-fn (lambda (&rest args) (declare (ignore args)))))
         (member (gr8s.raft.transport::make-raft-member :node node))
         (hcp (gr8s.ha::make-ha-control-plane :member member :store nil)))
    (setf (gethash "b" (gr8s.raft:raft-node-peer-addresses node)) '("10.0.0.2" 7000))
    (let ((report (gr8s.ha:ha-recovery-wait-report hcp)))
      (is (search "2 of 2 voting members" report))
      (is (search "a (this member)" report))
      (is (search "b (10.0.0.2:7000), not heard from since startup" report))
      (is (search "--cluster-reset" report)))
    (let ((link (gr8s.raft.transport::make-raft-peer-link :id "b")))
      (setf (gr8s.raft.transport::raft-peer-link-received-messages link) 3
            (gethash "b" (gr8s.raft.transport::raft-member-links member)) link)
      (is (search "b (10.0.0.2:7000), in contact"
                  (gr8s.ha:ha-recovery-wait-report hcp))
          "a peer that has delivered messages reports as in contact"))))

(test serve-parses-cluster-reset
  (let ((options (gr8s.server::parse-serve-options
                  (list "--state-directory" "/tmp/x" "--cluster-reset" "--node-name" "a"))))
    (is (eq t (getf options :cluster-reset)))
    (is (eq t (getf options :raft-init)) "--cluster-reset implies founding alone"))
  (signals error
    (gr8s.server::parse-serve-options
     (list "--state-directory" "/tmp/x" "--cluster-reset" "--join" "h:7000" "--node-name" "a"))))
