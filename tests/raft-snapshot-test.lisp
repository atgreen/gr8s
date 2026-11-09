;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
(in-package #:gr8s/tests)
(def-suite raft-snapshot :in gr8s)
(in-suite raft-snapshot)

(defun snapshot-test-source ()
  (multiple-value-bind (node kv) (make-standalone-node :snapshot/restore t)
    (gr8s::raft-configure node '(("n1" . :voter) ("b" . :voter) ("w" . :witness) ("l" . :learner)))
    (setf (gethash "n1" (gr8s::raft-node-peer-addresses node)) '("127.0.0.1" 19001)
          (gethash "b" (gr8s::raft-node-peer-addresses node)) '("127.0.0.1" 19002)
          (gethash "n1" (gr8s::raft-node-api-urls node)) "https://127.0.0.1:6443"
          (gr8s::raft-node-current-term node) 2)
    (dotimes (i 5)
      (gr8s::raft-log-append node (gr8s::make-raft-entry :term 2 :command (list :set "x" i))))
    (setf (gr8s::raft-node-commit-index node) 3)
    (gr8s::raft-apply-committed node)
    (gr8s::raft-compact node 3)
    (values node kv)))

(defun snapshot-test-message (source)
  (setf (gethash "b" (gr8s::raft-node-next-index source)) 1)
  (gr8s::raft-append-message source "b"))

(test snapshot-install-retains-matching-tail-and-recovers-membership
  (with-raft-temp-dir (path)
    (let* ((source (snapshot-test-source))
           (storage (gr8s::open-file-raft-storage path))
           (node (make-standalone-node :storage storage :snapshot/restore t)))
      (setf (gr8s::raft-node-id node) "b")
      (unwind-protect
           (progn
             (dotimes (i 5)
               (gr8s::raft-log-append node (gr8s::make-raft-entry :term 2 :command (list :set "x" i))))
             (gr8s::raft-handle-message node (snapshot-test-message source))
             (is (= 3 (gr8s::raft-node-snapshot-index node)))
             (is (= 5 (gr8s::raft-last-log-index node)))
             (is (eq :learner (gethash "l" (gr8s::raft-node-roles node))))
             (is (member "l" (gr8s::raft-replicate-ids node) :test #'equal))
             (is (eq :witness (gethash "w" (gr8s::raft-node-roles node))))
             (gr8s::close-file-raft-storage storage)
             (multiple-value-bind (restored kv) (make-standalone-node :snapshot/restore t)
               (setf (gr8s::raft-node-id restored) "b")
               (unwind-protect
                    (progn
                      (gr8s::recover-raft-node restored path)
                      (is (= 2 (gethash "x" kv)))
                      (is (eq :voter (gr8s::raft-node-self-role restored)))
                      (is (equal '("127.0.0.1" 19001) (gethash "n1" (gr8s::raft-node-peer-addresses restored))))
                      (is (equal "https://127.0.0.1:6443" (gethash "n1" (gr8s::raft-node-api-urls restored))))
                      (is (eq :learner (gethash "l" (gr8s::raft-node-roles restored))))
                      (setf (gr8s::raft-node-commit-index restored) 5)
                      (gr8s::raft-apply-committed restored)
                      (is (= 4 (gethash "x" kv))))
                 (gr8s::close-file-raft-storage (gr8s::raft-node-storage restored)))))
        (gr8s::close-file-raft-storage storage)))))

(test snapshot-conflicting-tail-is-discarded-and-stale-image-cannot-roll-back
  (let* ((source (snapshot-test-source))
         (node (make-standalone-node :snapshot/restore t)) (message (snapshot-test-message source)))
    (setf (gr8s::raft-node-id node) "b")
    (dotimes (i 5)
      (gr8s::raft-log-append node (gr8s::make-raft-entry :term 1 :command (list :set "wrong" i))))
    (gr8s::raft-handle-message node message)
    (is (= 3 (gr8s::raft-last-log-index node)))
    (let ((state (gr8s::raft-node-snapshot-state node)))
      (gr8s::raft-handle-message node message)
      (is (eq state (gr8s::raft-node-snapshot-state node)))
      (is (= 3 (gr8s::raft-node-last-applied node))))))

(test snapshot-storage-failure-does-not-restore-or-acknowledge
  (let* ((source (snapshot-test-source))
         (storage (make-instance 'failing-raft-storage :operation :snapshot))
         (node (make-standalone-node :storage storage)) (restores 0) (replies nil))
    (setf (gr8s::raft-node-current-term node) 2
          (gr8s::raft-node-restore-fn node) (lambda (state) (declare (ignore state)) (incf restores))
          (gr8s::raft-node-send-fn node) (lambda (to message) (declare (ignore to)) (push message replies)))
    (signals error (gr8s::raft-handle-message node (snapshot-test-message source)))
    (is (= 0 restores))
    (is (= 0 (gr8s::raft-node-snapshot-index node)))
    (is (null replies))
    (is (null (gr8s::raft-node-snapshot-pending node)))))

(test snapshot-restore-failure-blocks-clock-until-durable-install-is-retried
  (with-raft-temp-dir (path)
    (let* ((source (snapshot-test-source)) (storage (gr8s::open-file-raft-storage path))
           (node (make-standalone-node :storage storage :snapshot/restore t))
           (original (gr8s::raft-node-restore-fn node)) (attempts 0) (replies nil))
      (unwind-protect
           (progn
             (setf (gr8s::raft-node-restore-fn node)
                   (lambda (state)
                     (when (= 1 (incf attempts)) (error "Transient restore failure"))
                     (funcall original state))
                   (gr8s::raft-node-send-fn node)
                   (lambda (to message) (declare (ignore to)) (push message replies)))
             (signals error (gr8s::raft-handle-message node (snapshot-test-message source)))
             (is (not (null (gr8s::raft-node-snapshot-pending node))))
             (is (null replies))
             (is (= 3 (gr8s::raft-recovered-snapshot-index (gr8s::load-raft-log path))))
             (let ((elapsed (gr8s::raft-node-election-elapsed node)))
               (gr8s::raft-tick node)
               (is (= elapsed (gr8s::raft-node-election-elapsed node))))
             (gr8s::raft-handle-message node (snapshot-test-message source))
             (is (= 2 attempts))
             (is (null (gr8s::raft-node-snapshot-pending node)))
             (is (= 3 (gr8s::raft-node-last-applied node)))
             (is (getf (first replies) :success)))
        (gr8s::close-file-raft-storage storage)))))

(test compacted-follower-rejects-older-append-with-a-forward-hint
  (let ((node (snapshot-test-source)) (reply nil))
    (setf (gr8s::raft-node-send-fn node) (lambda (to msg) (declare (ignore to)) (setf reply msg)))
    (gr8s::raft-handle-message node
      '(:type :append-entries :term 2 :from "b" :prev-log-index 0 :prev-log-term 0 :entries nil :leader-commit 0))
    (is (not (getf reply :success)))
    (is (= 4 (getf reply :next-index)))
    (is (= 5 (gr8s::raft-last-log-index node)))))

(test partitioned-voter-witness-and-learner-catch-up-through-a-snapshot
  (dolist (role '(:voter :witness :learner))
    (let ((sim (three-node-sim)))
      (configure-cluster sim (list '("a" . :voter) '("b" . :voter) (cons "c" role)))
      (dolist (entry (rsim-nodes sim))
        (let ((kv (rsim-kv sim (car entry))))
          (setf (gr8s::raft-node-snapshot-fn (cdr entry))
                (lambda () (loop for k being the hash-keys of kv using (hash-value v) collect (cons k v)))
                (gr8s::raft-node-restore-fn (cdr entry))
                (lambda (state) (clrhash kv) (dolist (pair state) (setf (gethash (car pair) kv) (cdr pair)))))))
      (rsim-run sim 8)
      (setf (rsim-groups sim) '(("a" "b") ("c")))
      (dotimes (i 20)
        (gr8s::raft-propose (rsim-node sim "a") (list :set "counter" i))
        (rsim-run sim 1))
      (gr8s::raft-compact (rsim-node sim "a") 20)
      (dotimes (i 5)
        (gr8s::raft-propose (rsim-node sim "a") (list :set "counter" (+ 20 i)))
        (rsim-run sim 1))
      (setf (rsim-groups sim) nil)
      (rsim-run sim 20)
      (is (= 24 (gethash "counter" (rsim-kv sim "c"))) "~A catches up" role)
      (is (= 20 (gr8s::raft-node-snapshot-index (rsim-node sim "c"))))
      (is (= 25 (gr8s::raft-node-last-applied (rsim-node sim "c"))))
      (is (eq role (gr8s::raft-node-self-role (rsim-node sim "c")))))))

(defun snapshot-test-bytes (message)
  (babel:string-to-octets
    (with-standard-io-syntax (let ((*print-pretty* nil) (*read-eval* nil)) (prin1-to-string message)))
    :encoding :utf-8))

(defun snapshot-test-chunk (message bytes offset count &key (token "test") digest)
  (list :type :snapshot-chunk :from (getf message :from) :term (getf message :term)
        :last-index (getf message :last-index) :last-term (getf message :last-term)
        :offset offset :total (length bytes) :token token
        :digest (or digest (ironclad:byte-array-to-hex-string (ironclad:digest-sequence :sha256 bytes)))
        :data (subseq bytes offset (+ offset count)) :done (= (+ offset count) (length bytes))))

(defun snapshot-test-cleanup-member (member)
  (gr8s.raft.transport::raft-member-clear-snapshot-receiver member)
  (gr8s.raft.transport::raft-member-close-snapshot-root member))

(test snapshot-chunks-are-private-ordered-retryable-and-applied-only-when-complete
  (let* ((source (snapshot-test-source)) (message (snapshot-test-message source)) (bytes (snapshot-test-bytes message))
         (node (make-standalone-node :snapshot/restore t)) (member (gr8s::make-raft-member :node node :running t)))
    (unwind-protect
         (progn
           (gr8s.raft.transport::raft-member-receive-snapshot-chunk member (snapshot-test-chunk message bytes 0 16))
           (is (= 0 (gr8s::raft-node-snapshot-index node)))
           (let* ((receiver (gr8s.raft.transport::raft-member-snapshot-receiver member))
                  (path (gr8s.raft.transport::raft-snapshot-receiver-path receiver)))
             (is (= #o600 (logand #o777 (sb-posix:stat-mode (sb-posix:stat path)))))
             (signals error
               (gr8s.raft.transport::raft-member-receive-snapshot-chunk member (snapshot-test-chunk message bytes 17 16)))
             (gr8s.raft.transport::raft-member-receive-snapshot-chunk member (snapshot-test-chunk message bytes 0 16 :token "retry"))
             (is (not (probe-file path))))
           (gr8s.raft.transport::raft-member-receive-snapshot-chunk
            member (snapshot-test-chunk message bytes 16 (- (length bytes) 16) :token "retry"))
           (is (= 3 (gr8s::raft-node-snapshot-index node)))
           (is (null (gr8s.raft.transport::raft-member-snapshot-receiver member))))
      (snapshot-test-cleanup-member member))))

(test snapshot-corruption-and-oversize-chunks-never-apply
  (let* ((message (snapshot-test-message (snapshot-test-source))) (bytes (snapshot-test-bytes message))
         (node (make-standalone-node :snapshot/restore t)) (member (gr8s::make-raft-member :node node :running t)))
    (unwind-protect
         (progn
           (signals error
             (gr8s.raft.transport::raft-member-receive-snapshot-chunk
              member (snapshot-test-chunk message bytes 0 (length bytes) :digest (make-string 64 :initial-element #\0))))
           (is (= 0 (gr8s::raft-node-snapshot-index node)))
           (is (null (gr8s.raft.transport::raft-member-snapshot-receiver member)))
           (let ((chunk (snapshot-test-chunk message bytes 0 (length bytes))))
             (setf (getf chunk :data) (make-array 65537 :element-type '(unsigned-byte 8) :initial-element 0)
                   (getf chunk :total) 65537)
             (signals error (gr8s.raft.transport::raft-member-receive-snapshot-chunk member chunk)))
           (is (null (gr8s.raft.transport::raft-member-snapshot-receiver member))))
      (snapshot-test-cleanup-member member))))

(test snapshot-retries-coalesce-with-append-entries
  (let ((link (gr8s::make-raft-peer-link :id "b")) (message (snapshot-test-message (snapshot-test-source))))
    (dotimes (i 1000) (gr8s::raft-link-enqueue link message))
    (is (= 1 (length (gr8s::raft-peer-link-items link))))
    (gr8s::raft-link-enqueue link '(:type :append-entries :term 2 :from "n1"))
    (is (= 1 (length (gr8s::raft-peer-link-items link))))
    (is (eq :append-entries (getf (first (gr8s::raft-peer-link-items link)) :type)))))

(test abandoned-snapshot-partials-expire-without-changing-application-state
  (let* ((message (snapshot-test-message (snapshot-test-source))) (bytes (snapshot-test-bytes message))
         (node (make-standalone-node :snapshot/restore t)) (member (gr8s::make-raft-member :node node :running t)))
    (unwind-protect
         (progn
           (gr8s.raft.transport::raft-member-receive-snapshot-chunk member (snapshot-test-chunk message bytes 0 16))
           (let* ((receiver (gr8s.raft.transport::raft-member-snapshot-receiver member))
                  (path (gr8s.raft.transport::raft-snapshot-receiver-path receiver)))
             (setf (gr8s.raft.transport::raft-snapshot-receiver-activity receiver)
                   (- (get-internal-real-time) (* 61 internal-time-units-per-second)))
             (gr8s.raft.transport::raft-member-expire-snapshot-receiver member)
             (is (null (gr8s.raft.transport::raft-member-snapshot-receiver member)))
             (is (not (probe-file path)))
             (is (= 0 (gr8s::raft-node-snapshot-index node)))))
      (snapshot-test-cleanup-member member))))

(defun snapshot-test-member-credentials (root id founder)
  (let* ((directory (merge-pathnames (format nil "~A/" id) root))
         (key (merge-pathnames "member.key" directory))
         (certificate (merge-pathnames "member.crt" directory)))
    (ensure-directories-exist directory)
    (gr8s::write-private-text-atomically
     certificate (gr8s::issue-raft-member-certificate
                  (gr8s::raft-credentials-pki founder) id (gr8s::generate-node-key-and-csr id key)))
    (gr8s.security::make-raft-credentials
     :ca-path (gr8s::raft-credentials-ca-path founder) :ca (gr8s::raft-credentials-ca founder)
     :certificate-path certificate :key-path key)))

(test mutual-tls-snapshot-retries-catches-up-and-survives-leadership-handoff
  (with-temporary-store (unused root)
    (declare (ignore unused))
    (let* ((credentials (gr8s::ensure-raft-founder-credentials (merge-pathnames "founder/" root) "a"))
           (a-kv (make-hash-table :test 'equal)) (b-kv (make-hash-table :test 'equal))
           (a nil) (b nil) (w nil) (learner nil) (learner-kv (make-hash-table :test 'equal)) (b-storage nil)
           (original (symbol-function 'gr8s.raft.transport::raft-link-deliver-message))
           (injected nil) (chunks nil) (observation-lock (bt:make-lock "snapshot test observations")))
      (labels ((capture (kv) (loop for k being the hash-keys of kv using (hash-value v) collect (cons k v)))
               (restore (kv state) (clrhash kv) (dolist (pair state) (setf (gethash (car pair) kv) (cdr pair)))))
        (unwind-protect
             (progn
               (setf a (gr8s::start-raft-member "a" :credentials credentials
                         :apply-fn (lambda (command) (raft-kv-apply a-kv command))
                         :snapshot-fn (lambda () (capture a-kv))
                         :restore-fn (lambda (state) (restore a-kv state))))
               (gr8s::raft-cluster-init a)
               (gr8s::raft-member-start a)
               (is (poll-until (lambda () (gr8s::raft-member-leader-p a))))
               (setf w (gr8s::start-raft-member "w" :credentials (snapshot-test-member-credentials root "w" credentials)))
               (is (gr8s::raft-cluster-join w "127.0.0.1" (gr8s::raft-member-port a) :role :witness))
               (gr8s::raft-member-start w)
               (multiple-value-bind (value committed)
                   (gr8s::raft-member-propose-sync a (list :set "blob" (make-string (* 256 1024) :initial-element #\x)))
                 (declare (ignore value)) (is (eq t committed)))
               (dotimes (i 5)
                 (multiple-value-bind (value committed) (gr8s::raft-member-propose-sync a (list :set "counter" i))
                   (declare (ignore value)) (is (eq t committed))))
               (let ((boundary nil))
                 (bt:with-lock-held ((gr8s::raft-member-lock a))
                   (setf boundary (gr8s::raft-node-last-applied (gr8s::raft-member-node a)))
                   (gr8s::raft-compact (gr8s::raft-member-node a) boundary))
                 (setf (symbol-function 'gr8s.raft.transport::raft-link-deliver-message)
                       (lambda (stub message)
                         (when (eq :snapshot-chunk (getf message :type))
                           (bt:with-lock-held (observation-lock)
                             (push (length (getf message :data)) chunks)
                             (when (and (not injected) (plusp (getf message :offset)))
                               (setf injected t)
                               (error "Injected snapshot connection interruption"))))
                         (funcall original stub message)))
                 (setf b-storage (gr8s::open-file-raft-storage (merge-pathnames "b-wal" root))
                       b (gr8s::start-raft-member "b" :storage b-storage
                           :credentials (snapshot-test-member-credentials root "b" credentials)
                           :apply-fn (lambda (command) (raft-kv-apply b-kv command))
                           :snapshot-fn (lambda () (capture b-kv))
                           :restore-fn (lambda (state) (restore b-kv state))))
                 (is (gr8s::raft-cluster-join b "127.0.0.1" (gr8s::raft-member-port a)))
                 (gr8s::raft-member-start b)
                 (is (poll-until (lambda () (and (eql 4 (gethash "counter" b-kv))
                                                (>= (gr8s::raft-node-last-applied (gr8s::raft-member-node b)) (1+ boundary))))
                                 :timeout 30))
                 (is (= (* 256 1024) (length (gethash "blob" b-kv))))
                 (is (= boundary (gr8s::raft-node-snapshot-index (gr8s::raft-member-node b))))
                 (is (eq :voter (gr8s::raft-node-self-role (gr8s::raft-member-node b))))
                 (bt:with-lock-held (observation-lock)
                   (is-true injected)
                   (is (> (length chunks) 4))
                   (is (every (lambda (size) (<= 1 size 65536)) chunks)))
                 (is (null (gr8s.raft.transport::raft-member-snapshot-receiver b)))
                 (setf learner (gr8s::start-raft-member "l"
                                 :credentials (snapshot-test-member-credentials root "l" credentials)
                                 :apply-fn (lambda (command) (raft-kv-apply learner-kv command))
                                 :snapshot-fn (lambda () (capture learner-kv))
                                 :restore-fn (lambda (state) (restore learner-kv state))))
                 (is (gr8s::raft-cluster-join learner "127.0.0.1" (gr8s::raft-member-port a) :role :learner))
                 (gr8s::raft-member-start learner)
                 (is (poll-until
                       (lambda () (and (eql 4 (gethash "counter" learner-kv))
                                       (eq :learner (gethash "l" (gr8s::raft-node-roles (gr8s::raft-member-node learner))))
                                       (not (gr8s::raft-node-removed (gr8s::raft-member-node learner))))) :timeout 30))
                 (is (= boundary (gr8s::raft-node-snapshot-index (gr8s::raft-member-node learner))))
                 (gr8s::stop-raft-member a)
                 (setf a nil)
                 (is (poll-until (lambda () (gr8s::raft-member-leader-p b)) :timeout 20))
                 (multiple-value-bind (value committed) (gr8s::raft-member-propose-sync b '(:set "after" "handoff"))
                   (is (eq t committed))
                   (is (equal "handoff" value)))
                 (is (equal "handoff" (gethash "after" b-kv)))
                 (is (poll-until (lambda () (equal "handoff" (gethash "after" learner-kv)))))
                 (is (eq :learner (gr8s::raft-node-self-role (gr8s::raft-member-node learner))))))
          (dolist (member (list a b w learner)) (when member (ignore-errors (gr8s::stop-raft-member member))))
          (setf (symbol-function 'gr8s.raft.transport::raft-link-deliver-message) original)
          (when b-storage (gr8s::close-file-raft-storage b-storage)))))))

(test snapshot-wire-is-independent-of-debug-printer-and-reader-settings
  (let* ((bytes (make-array 64 :element-type '(unsigned-byte 8) :initial-element 255))
         (*print-length* 3) (*print-level* 1) (*print-base* 16) (*read-base* 16)
         (message (list :type :snapshot-chunk :term 31 :data bytes))
         (decoded (gr8s::octets->raft-message (gr8s::raft-message->octets message))))
    (is (= 31 (getf decoded :term)))
    (is (equalp bytes (getf decoded :data)))))

(test application-log-compaction-without-a-snapshot-callback-cannot-transfer
  (let ((node (make-standalone-node)))
    (gr8s::raft-log-append node (gr8s::make-raft-entry :term 1 :command '(:set "x" 1)))
    (setf (gr8s::raft-node-commit-index node) 1)
    (gr8s::raft-apply-committed node)
    (gr8s::raft-compact node 1)
    (setf (gethash "b" (gr8s::raft-node-next-index node)) 1)
    (signals error (gr8s::raft-append-message node "b"))))

(test stateless-checkpoints-also-require-an-exact-configuration-boundary
  (let ((node (gr8s::make-raft-node :id "n1")))
    (gr8s::raft-log-append node (gr8s::make-raft-entry :term 1 :command '(:noop)))
    (gr8s::raft-log-append node (gr8s::make-raft-entry :term 1 :command '(:noop)))
    (setf (gr8s::raft-node-commit-index node) 2 (gr8s::raft-node-last-applied node) 2)
    (gr8s::raft-compact node 1)
    (setf (gethash "b" (gr8s::raft-node-next-index node)) 1)
    (signals error (gr8s::raft-append-message node "b"))
    (signals error (gr8s.raft::raft-restore-snapshot-contents node (gr8s::raft-node-snapshot-state node)))))

(test durable-application-log-cannot-be-discarded-without-a-recoverable-snapshot
  (with-raft-temp-dir (path)
    (let* ((storage (gr8s::open-file-raft-storage path)) (node (make-standalone-node :storage storage)))
      (unwind-protect
           (progn
             (gr8s::raft-log-append node (gr8s::make-raft-entry :term 1 :command '(:set "x" 1)))
             (setf (gr8s::raft-node-commit-index node) 1)
             (gr8s::raft-apply-committed node)
             (let ((before (uiop:read-file-string path)))
               (signals error (gr8s::raft-compact node 1))
               (is (equal before (uiop:read-file-string path))))
             (is (= 0 (gr8s::raft-node-snapshot-index node)))
             (is (= 1 (gr8s::raft-last-log-index node))))
        (gr8s::close-file-raft-storage storage)))))

(defun snapshot-owner-test-member (base)
  (gr8s::make-raft-member :node (gr8s::make-raft-node :id "owner-test")
                          :snapshot-directory base :running t))

(defun snapshot-owner-test-payload (root &optional (name "out-test.snapshot"))
  (let ((path (merge-pathnames name root)))
    (gr8s.raft.transport::raft-snapshot-create-file path)
    (with-open-file (stream path :direction :output :if-exists :overwrite)
      (write-string "snapshot payload must survive while its owner lives" stream))
    path))

(defun snapshot-owner-test-abandon (member)
  (let ((root (gr8s.raft.transport::raft-member-snapshot-root member)))
    (sb-posix:close (gr8s.raft.transport::raft-member-snapshot-owner-fd member))
    (setf (gr8s.raft.transport::raft-member-snapshot-owner-fd member) nil
          (gr8s.raft.transport::raft-member-snapshot-root member) nil)
    root))

(test snapshot-root-locks-protect-live-members-in-the-same-process
  (with-temporary-store (unused base)
    (declare (ignore unused))
    (let* ((left (snapshot-owner-test-member base)) (right (snapshot-owner-test-member base))
           (root (gr8s.raft.transport::raft-member-snapshot-root-unlocked left))
           (payload (snapshot-owner-test-payload root)))
      (unwind-protect
           (progn
             (gr8s.raft.transport::raft-member-snapshot-root-unlocked right)
             (is (not (null (probe-file payload))))
             (is (= #o700 (logand #o777 (sb-posix:stat-mode (sb-posix:stat root)))))
             (is (= #o700 (logand #o777 (sb-posix:stat-mode
                                       (sb-posix:stat (uiop:pathname-parent-directory-pathname root))))))
             (is (plusp (logand 1 (cffi:foreign-funcall "fcntl" :int
                                   (gr8s.raft.transport::raft-member-snapshot-owner-fd left) :int 1 :int)))) ; F_GETFD
             (gr8s.raft.transport::raft-member-close-snapshot-root left)
             (is (not (probe-file root)))
             (is (not (null (probe-file (gr8s.raft.transport::raft-member-snapshot-root right))))))
        (snapshot-test-cleanup-member left)
        (snapshot-test-cleanup-member right)))))

(test snapshot-root-reaping-reclaims-unlocked-payload-and-incomplete-creation
  (with-temporary-store (unused base)
    (declare (ignore unused))
    (let* ((old (snapshot-owner-test-member base)) (fresh (snapshot-owner-test-member base))
           (root (gr8s.raft.transport::raft-member-snapshot-root-unlocked old))
           (payload (snapshot-owner-test-payload root))
           (empty (uiop:ensure-directory-pathname
                   (sb-posix:mkdtemp (namestring (merge-pathnames ".raft-transfer-v2-XXXXXX" (uiop:pathname-parent-directory-pathname root))))))
           (legacy (uiop:ensure-directory-pathname
                    (sb-posix:mkdtemp (namestring (merge-pathnames ".raft-transfer-XXXXXX" (uiop:pathname-parent-directory-pathname root)))))))
      (unwind-protect
           (progn
             (snapshot-owner-test-payload legacy)
             (snapshot-owner-test-abandon old)
             (gr8s.raft.transport::raft-member-snapshot-root-unlocked fresh)
             (is (not (probe-file payload)))
             (is (not (probe-file root)))
             (is (not (probe-file empty)))
             (is (not (null (probe-file (merge-pathnames "out-test.snapshot" legacy))))))
        (snapshot-test-cleanup-member fresh)))))

(test snapshot-root-reaping-preserves-symlinks-hardlinks-and-unknown-content
  (with-temporary-store (unused base)
    (declare (ignore unused))
    (dolist (variant '(:payload-link :owner-link :root-link :hard-link :unknown-file :unknown-directory :public-mode))
      (let* ((old (snapshot-owner-test-member base)) (fresh (snapshot-owner-test-member base))
             (root (gr8s.raft.transport::raft-member-snapshot-root-unlocked old))
             (payload (snapshot-owner-test-payload root))
             (outside (merge-pathnames (format nil "outside-~A" variant) base))
             (actual-root root))
        (unwind-protect
             (progn
               (gr8s.raft.transport::raft-snapshot-create-file outside)
               (with-open-file (stream outside :direction :output :if-exists :overwrite) (write-string "do not touch" stream))
               (snapshot-owner-test-abandon old)
               (ecase variant
                 (:payload-link (sb-posix:unlink (namestring payload)) (sb-posix:symlink (namestring outside) (namestring payload)))
                 (:owner-link (sb-posix:unlink (namestring (merge-pathnames ".owner" root)))
                              (sb-posix:symlink (namestring outside) (namestring (merge-pathnames ".owner" root))))
                 (:root-link
                  (setf actual-root (merge-pathnames "outside-root/" base))
                  (sb-posix:rename (namestring root) (namestring actual-root))
                  (sb-posix:symlink (namestring actual-root) (string-right-trim "/" (namestring root))))
                 (:hard-link (sb-posix:unlink (namestring payload)) (sb-posix:link (namestring outside) (namestring payload)))
                 (:unknown-file (snapshot-owner-test-payload root "user-notes"))
                 (:unknown-directory (ensure-directories-exist (merge-pathnames "user-directory/" root)))
                 (:public-mode (sb-posix:chmod (namestring root) #o755)))
               (gr8s.raft.transport::raft-member-snapshot-root-unlocked fresh)
               (is (equal "do not touch" (uiop:read-file-string outside)) "~A preserves outside data" variant)
               (is (not (null (probe-file actual-root))) "~A preserves unrecognized root" variant)
               (is (not (null (probe-file (merge-pathnames "out-test.snapshot" actual-root))))))
          (snapshot-test-cleanup-member fresh))))))

(test snapshot-ownership-reaping-recovers-after-a-real-process-is-killed
  (with-temporary-store (unused base)
    (declare (ignore unused))
    (let* ((script (merge-pathnames "snapshot-owner-child.lisp" base))
           (ready (merge-pathnames "snapshot-owner-ready.txt" base))
           (log (merge-pathnames "snapshot-owner-child.log" base))
           (process nil) (restarted nil) (live (snapshot-owner-test-member base)) (fresh (snapshot-owner-test-member base))
           (live-root (gr8s.raft.transport::raft-member-snapshot-root-unlocked live))
           (live-payload (snapshot-owner-test-payload live-root)))
      (with-open-file (stream script :direction :output :if-does-not-exist :create)
        (format stream "(require :asdf)~%(asdf:load-asd ~S)~%(asdf:load-system :gr8s)~%"
                (namestring (merge-pathnames "gr8s.asd" (asdf:system-source-directory :gr8s))))
        (format stream "(let* ((member (gr8s.raft.transport:make-raft-member :node (gr8s.raft:make-raft-node :id ~S) :snapshot-directory ~S)) (root (gr8s.raft.transport::raft-member-snapshot-root-unlocked member)) (file (merge-pathnames ~S root)))~%" "child" (namestring base) "in-crash.snapshot")
        (write-line "(gr8s.raft.transport::raft-snapshot-create-file file)" stream)
        (write-line "(with-open-file (out file :direction :output :if-exists :overwrite) (write-string (make-string 65536 :initial-element (code-char 120)) out))" stream)
        (format stream "(gr8s::write-private-text-atomically ~S (namestring root))~%" (namestring ready))
        (write-line "(loop (sleep 1)))" stream))
      (unwind-protect
           (progn
             (setf process (sb-ext:run-program "sbcl" (list "--noinform" "--non-interactive" "--load" (namestring script))
                                               :search t :wait nil :input nil :output log :error :output))
             (poll-until (lambda () (or (probe-file ready) (not (sb-ext:process-alive-p process)))) :timeout 60)
             (unless (probe-file ready)
               (error "Snapshot child did not become ready (~A):~%~A"
                      (sb-ext:process-status process) (uiop:read-file-string log)))
             (is (not (null (probe-file ready))))
             (let* ((child-root (uiop:ensure-directory-pathname (string-trim '(#\Newline #\Return) (uiop:read-file-string ready))))
                    (payload (merge-pathnames "in-crash.snapshot" child-root)))
               (gr8s.raft.transport::raft-member-snapshot-root-unlocked fresh)
               (is (not (null (probe-file payload))) "a live foreign process owns its payload")
               (is (= 65536 (with-open-file (stream payload :element-type '(unsigned-byte 8)) (file-length stream))))
               (gr8s.raft.transport::raft-member-close-snapshot-root fresh)
               (sb-ext:process-kill process 9)
               (sb-ext:process-wait process)
               (is (eq :signaled (sb-ext:process-status process)))
               (setf restarted (gr8s::start-raft-member "restarted" :snapshot-directory base))
               (is (not (probe-file child-root)))
               (is (not (probe-file payload)))
               (is (not (null (probe-file live-payload))) "the other live member remains intact")))
        (when process
          (when (sb-ext:process-alive-p process) (sb-ext:process-kill process 9) (sb-ext:process-wait process))
          (sb-ext:process-close process))
        (when restarted (gr8s::stop-raft-member restarted))
        (snapshot-test-cleanup-member fresh)
        (snapshot-test-cleanup-member live)))))

(test snapshot-root-rejects-public-or-symlinked-ownership-namespaces
  (with-temporary-store (unused base)
    (declare (ignore unused))
    (let* ((member (snapshot-owner-test-member base))
           (namespace (merge-pathnames (format nil ".gr8s-raft-transfers-v2-~D/" (sb-posix:geteuid)) base))
           (outside (merge-pathnames "operator-data/" base)))
      (sb-posix:mkdir (namestring namespace) #o755)
      (sb-posix:chmod (namestring namespace) #o755)
      (unwind-protect
           (progn
             (signals error (gr8s.raft.transport::raft-member-snapshot-root-unlocked member))
             (is (null (gr8s.raft.transport::raft-member-snapshot-root member)))
             (sb-posix:rmdir (namestring namespace))
             (sb-posix:mkdir (namestring outside) #o700)
             (let ((payload (snapshot-owner-test-payload outside)))
               (sb-posix:symlink (namestring outside) (string-right-trim "/" (namestring namespace)))
               (signals error (gr8s.raft.transport::raft-member-snapshot-root-unlocked member))
               (is (not (null (probe-file payload))))
               (sb-posix:unlink (string-right-trim "/" (namestring namespace))))
             (is (not (null (gr8s.raft.transport::raft-member-snapshot-root-unlocked member))))
             (is (not (null (probe-file (merge-pathnames "out-test.snapshot" outside))))))
        (snapshot-test-cleanup-member member)))))

(test ha-serve-reclaims-scratch-before-opening-the-store
  (with-temporary-store (unused base)
    (declare (ignore unused))
    (let* ((old (snapshot-owner-test-member (merge-pathnames "raft/transfers/" base)))
           (root (gr8s.raft.transport::raft-member-snapshot-root-unlocked old))
           (original (symbol-function 'gr8s:open-store)) (opened nil))
      (snapshot-owner-test-payload root)
      (snapshot-owner-test-abandon old)
      (unwind-protect
           (progn
             (setf (symbol-function 'gr8s:open-store)
                   (lambda (directory)
                     (declare (ignore directory))
                     (setf opened t)
                     (is (not (probe-file root)))
                     (throw 'snapshot-store-opened :opened)))
             (is (eq :opened
                     (catch 'snapshot-store-opened
                       (gr8s.server::serve (list :state-directory base :listen "127.0.0.1" :port 0 :raft-init t)))))
             (is-true opened))
        (setf (symbol-function 'gr8s:open-store) original)))))

(in-suite gr8s)
