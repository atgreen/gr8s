;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
(in-package #:gr8s/tests)
(def-suite store-member-restore :in gr8s)
(in-suite store-member-restore)

(defun seed-member-restore-artifact (store root)
  (gr8s::create-core-resource store "configmaps" (configmap-input "incoming" "k" "snapshot") "default")
  (let ((path (merge-pathnames "incoming.jsonl" root)))
    (gr8s.resources::capture-store-snapshot store path 42 7)
    (nth-value 1 (gr8s.resources::retain-store-snapshot-artifact root path 42 7 (snapshot-test-digest path)))))

(defun send-member-restore-message (sender receiver message)
  (let ((channel (gr8s::make-raft-channel (gr8s::raft-member-credentials sender)
                                        "127.0.0.1" (gr8s::raft-member-port receiver) 2)))
    (unwind-protect
         (gr8s.raft.transport::raft-link-deliver-message (gr8s.node.v1::make-raft-transport-stub channel) message)
      (ag-grpc:channel-close channel))))

(defun member-restore-heartbeat ()
  (list :type :append-entries :term 10 :from "source" :prev-log-index 0 :prev-log-term 0 :entries nil :leader-commit 0))

(test artifact-dispatch-restores-the-same-store-and-reopens-only-after-raft-publication
  (with-temporary-store (source source-root)
    (with-temporary-store (sink sink-root)
      (let* ((reference (seed-member-restore-artifact source source-root))
             (credentials (gr8s::ensure-raft-founder-credentials (merge-pathnames "tls/" source-root) "source"))
             (sink-credentials (snapshot-test-member-credentials (merge-pathnames "tls/" sink-root) "sink" credentials))
             (sender nil) (receiver nil))
        (gr8s::create-core-resource sink "configmaps" (configmap-input "old" "k" "old") "default")
        (setf (gr8s::pod-store-resource-revision sink) 10000)
        (unwind-protect
             (progn
               (setf sender (gr8s::start-raft-member "source" :credentials credentials)
                     receiver (gr8s::start-raft-member "sink" :storage-path (merge-pathnames "raft/wal" sink-root)
                                 :credentials sink-credentials))
               (gr8s.resources::configure-store-artifact-transport sender source-root)
               (gr8s.resources::configure-member-store-restore receiver sink)
               (send-artifact-wire-test-snapshot sender receiver (artifact-wire-test-message reference))
               (is (equal "snapshot" (configmap-value sink "incoming" "k")))
               (is (null (configmap-value sink "old" "k")))
               (is (> (gr8s::pod-store-resource-revision sink) 10000))
               (is (= 42 (gr8s::raft-node-last-applied (gr8s::raft-member-node receiver))))
               (is (null (gr8s.raft:raft-node-snapshot-pending (gr8s::raft-member-node receiver))))
               (is-false (gr8s.store::store-access-blocked-p sink))
               (is (null (gr8s.store::read-store-restore-intent sink-root)))
               (is (equal "snapshot" (configmap-value (gr8s:open-store sink-root) "incoming" "k"))))
          (when receiver (gr8s::stop-raft-member receiver))
          (when sender (gr8s::stop-raft-member sender)))))))

(test ordinary-rpc-retries-failed-application-restore-under-the-outer-barriers
  (with-temporary-store (source source-root)
    (with-temporary-store (sink sink-root)
      (let ((reference (seed-member-restore-artifact source source-root))
            (sender nil) (receiver nil)
            (original (symbol-function 'gr8s.store::load-store-application-files)))
        (unwind-protect
             (progn
               (setf sender (gr8s::start-raft-member "source")
                     receiver (gr8s::start-raft-member "sink" :storage-path (merge-pathnames "raft/wal" sink-root)))
               (gr8s.resources::configure-store-artifact-transport sender source-root)
               (gr8s.resources::configure-member-store-restore receiver sink)
               (unwind-protect
                    (progn
                      (setf (symbol-function 'gr8s.store::load-store-application-files)
                            (lambda (store)
                              (if (eq store sink) (error "Injected application load failure") (funcall original store))))
                      (signals error (send-artifact-wire-test-snapshot sender receiver (artifact-wire-test-message reference))))
                 (setf (symbol-function 'gr8s.store::load-store-application-files) original))
               (is-true (gr8s.store::store-access-blocked-p sink))
               (is (gr8s.store::read-store-restore-intent sink-root))
               (is-true (gr8s.raft:raft-node-snapshot-pending (gr8s::raft-member-node receiver)))
               (send-member-restore-message sender receiver (member-restore-heartbeat))
               (is (equal "snapshot" (configmap-value sink "incoming" "k")))
               (is-false (gr8s.store::store-access-blocked-p sink))
               (is (null (gr8s.store::read-store-restore-intent sink-root)))
               (is (null (gr8s.raft:raft-node-snapshot-pending (gr8s::raft-member-node receiver))))
               (is (= 42 (gr8s::raft-node-last-applied (gr8s::raft-member-node receiver)))))
          (setf (symbol-function 'gr8s.store::load-store-application-files) original)
          (when receiver (gr8s::stop-raft-member receiver))
          (when sender (gr8s::stop-raft-member sender)))))))

(test snapshot-dispatch-does-not-open-a-gate-owned-by-another-operation
  (with-temporary-store (source source-root)
    (with-temporary-store (sink sink-root)
      (let ((reference (seed-member-restore-artifact source source-root)) (sender nil) (receiver nil))
        (unwind-protect
             (progn
               (setf sender (gr8s::start-raft-member "source")
                     receiver (gr8s::start-raft-member "sink" :storage-path (merge-pathnames "raft/wal" sink-root)))
               (gr8s.resources::configure-store-artifact-transport sender source-root)
               (gr8s.resources::configure-member-store-restore receiver sink)
               (gr8s.store::quiesce-store-access sink)
               (signals error (send-artifact-wire-test-snapshot sender receiver (artifact-wire-test-message reference)))
               (is-true (gr8s.store::store-access-blocked-p sink))
               (is (= 0 (gr8s::raft-node-last-applied (gr8s::raft-member-node receiver))))
               (is (null (gr8s.store::read-store-restore-intent sink-root)))
               (gr8s.store::resume-store-access sink)
               (is-false (gr8s.store::store-access-blocked-p sink)))
          (when receiver (gr8s::stop-raft-member receiver))
          (when sender (gr8s::stop-raft-member sender)))))))

(test outstanding-writer-can-commit-while-snapshot-dispatch-waits-for-its-barrier
  (with-temporary-store (source source-root)
    (with-temporary-store (sink sink-root)
      (let ((reference (seed-member-restore-artifact source source-root))
            (sender nil) (receiver nil) (writer nil) (transfer nil) (command nil)
            (writer-result nil) (transfer-result nil)
            (prepared (sb-thread:make-semaphore :count 0)) (committed (sb-thread:make-semaphore :count 0)))
        (unwind-protect
             (progn
               (setf sender (gr8s::start-raft-member "source")
                     receiver (gr8s::start-raft-member "sink" :storage-path (merge-pathnames "raft/wal" sink-root)
                                 :apply-fn (lambda (entry)
                                             (prog1 (apply-ha-core-command sink entry)
                                               (sb-thread:signal-semaphore committed)))))
               (gr8s.resources::configure-store-artifact-transport sender source-root)
               (gr8s.resources::configure-member-store-restore receiver sink)
               ;; The author has released its raw store lock but retains the
               ;; consensus writer lock while waiting for the committed apply.
               (setf (gr8s::pod-store-consensus-commit-fn sink)
                     (lambda (tag payload)
                       (setf command (list tag payload))
                       (sb-thread:signal-semaphore prepared)
                       (unless (sb-thread:wait-on-semaphore committed :timeout 15) (error "Writer never committed"))
                       '(:core-ok)))
               (setf writer (sb-thread:make-thread
                             (lambda () (setf writer-result
                               (handler-case
                                   (progn (gr8s::create-core-resource sink "configmaps" (configmap-input "in-flight" "k" "committed") "default") t)
                                 (error (condition) (princ-to-string condition)))))))
               (is-true (sb-thread:wait-on-semaphore prepared :timeout 10))
               (setf transfer (sb-thread:make-thread
                               (lambda () (setf transfer-result
                                 (handler-case
                                     (progn (send-artifact-wire-test-snapshot sender receiver (artifact-wire-test-message reference)) t)
                                   (error (condition) (princ-to-string condition)))))))
               (is (poll-until (lambda () (gr8s.store::store-access-blocked-p sink))))
               (send-member-restore-message
                sender receiver
                (list :type :append-entries :term 9 :from "source" :prev-log-index 0 :prev-log-term 0
                      :entries (list (gr8s::make-raft-entry :index 1 :term 4 :command command)) :leader-commit 1))
               (sb-thread:join-thread writer :timeout 20 :default nil)
               (sb-thread:join-thread transfer :timeout 20 :default nil)
               (is (eq t writer-result))
               (is (eq t transfer-result))
               (is (equal "snapshot" (configmap-value sink "incoming" "k")))
               (is-false (gr8s.store::store-access-blocked-p sink)))
          (sb-thread:signal-semaphore committed)
          (when writer (sb-thread:join-thread writer :timeout 20 :default nil))
          (when transfer (sb-thread:join-thread transfer :timeout 20 :default nil))
          (when receiver (gr8s::stop-raft-member receiver))
          (when sender (gr8s::stop-raft-member sender)))))))

(test ordinary-rpc-can-retry-gate-resume-after-raft-publication
  (with-temporary-store (source source-root)
    (with-temporary-store (sink sink-root)
      (let ((reference (seed-member-restore-artifact source source-root))
            (sender nil) (receiver nil) (original (symbol-function 'gr8s.store::resume-store-access)))
        (unwind-protect
             (progn
               (setf sender (gr8s::start-raft-member "source")
                     receiver (gr8s::start-raft-member "sink" :storage-path (merge-pathnames "raft/wal" sink-root)))
               (gr8s.resources::configure-store-artifact-transport sender source-root)
               (gr8s.resources::configure-member-store-restore receiver sink)
               (unwind-protect
                    (progn
                      (setf (symbol-function 'gr8s.store::resume-store-access)
                            (lambda (store) (if (eq store sink) (error "Injected gate resume failure") (funcall original store))))
                      (signals error (send-artifact-wire-test-snapshot sender receiver (artifact-wire-test-message reference))))
                 (setf (symbol-function 'gr8s.store::resume-store-access) original))
               (is (= 42 (gr8s::raft-node-last-applied (gr8s::raft-member-node receiver))))
               (is (null (gr8s.raft:raft-node-snapshot-pending (gr8s::raft-member-node receiver))))
               (is-true (gr8s.store::store-access-blocked-p sink))
               (is-true (gr8s.raft.transport::raft-member-snapshot-barrier-pending receiver))
               (send-member-restore-message sender receiver (member-restore-heartbeat))
               (is-false (gr8s.store::store-access-blocked-p sink))
               (is-false (gr8s.raft.transport::raft-member-snapshot-barrier-pending receiver))
               (is (equal "snapshot" (configmap-value sink "incoming" "k"))))
          (setf (symbol-function 'gr8s.store::resume-store-access) original)
          (when receiver (gr8s::stop-raft-member receiver))
          (when sender (gr8s::stop-raft-member sender)))))))

(test retention-failure-before-wal-reopens-the-unchanged-application
  (with-temporary-store (source source-root)
    (with-temporary-store (sink sink-root)
      (let ((reference (seed-member-restore-artifact source source-root)) (sender nil) (receiver nil))
        (gr8s::create-core-resource sink "configmaps" (configmap-input "old" "k" "unchanged") "default")
        (unwind-protect
             (progn
               (setf sender (gr8s::start-raft-member "source")
                     receiver (gr8s::start-raft-member "sink" :storage-path (merge-pathnames "raft/wal" sink-root)))
               (gr8s.resources::configure-store-artifact-transport sender source-root)
               (gr8s.resources::configure-member-store-restore receiver sink)
               (setf (gr8s.raft.transport::raft-member-artifact-retain-fn receiver)
                     (lambda (&rest args) (declare (ignore args)) nil))
               (signals error (send-artifact-wire-test-snapshot sender receiver (artifact-wire-test-message reference)))
               (is-false (gr8s.store::store-access-blocked-p sink))
               (is-false (gr8s.raft.transport::raft-member-snapshot-barrier-pending receiver))
               (is (= 0 (gr8s::raft-node-last-applied (gr8s::raft-member-node receiver))))
               (is (equal "unchanged" (configmap-value sink "old" "k"))))
          (when receiver (gr8s::stop-raft-member receiver))
          (when sender (gr8s::stop-raft-member sender)))))))

(test incoming-snapshot-cannot-observe-partially-installed-restore-callbacks
  (with-temporary-store (source source-root)
    (with-temporary-store (sink sink-root)
      (let ((reference (seed-member-restore-artifact source source-root))
            (sender nil) (receiver nil) (configure-thread nil) (transfer-thread nil)
            (configured nil) (transferred nil)
            (prepared (sb-thread:make-semaphore :count 0))
            (release (sb-thread:make-semaphore :count 0))
            (entered (sb-thread:make-semaphore :count 0))
            (install (symbol-function 'gr8s.resources::install-store-artifact-transport-unlocked))
            (dispatch (symbol-function 'gr8s.raft.transport::raft-member-dispatch-message)))
        (unwind-protect
             (progn
               (setf sender (gr8s::start-raft-member "source")
                     receiver (gr8s::start-raft-member "sink" :storage-path (merge-pathnames "raft/wal" sink-root)))
               (gr8s.resources::configure-store-artifact-transport sender source-root)
               (setf (symbol-function 'gr8s.resources::install-store-artifact-transport-unlocked)
                     (lambda (member root)
                       (prog1 (funcall install member root)
                         (when (eq member receiver)
                           (sb-thread:signal-semaphore prepared)
                           (unless (sb-thread:wait-on-semaphore release :timeout 15)
                             (error "Configuration barrier never released"))))))
               (setf (symbol-function 'gr8s.raft.transport::raft-member-dispatch-message)
                     (lambda (member message)
                       (when (eq member receiver) (sb-thread:signal-semaphore entered))
                       (funcall dispatch member message)))
               (setf configure-thread
                     (sb-thread:make-thread
                      (lambda () (setf configured
                        (handler-case (progn (gr8s.resources::configure-member-store-restore receiver sink) t)
                          (error (condition) (princ-to-string condition)))))))
               (is-true (sb-thread:wait-on-semaphore prepared :timeout 10))
               (setf transfer-thread
                     (sb-thread:make-thread
                      (lambda () (setf transferred
                        (handler-case (progn (send-artifact-wire-test-snapshot sender receiver (artifact-wire-test-message reference)) t)
                          (error (condition) (princ-to-string condition)))))))
               (is-true (sb-thread:wait-on-semaphore entered :timeout 10))
               (is (null transferred))
               (sb-thread:signal-semaphore release)
               (sb-thread:join-thread configure-thread :timeout 20 :default nil)
               (sb-thread:join-thread transfer-thread :timeout 20 :default nil)
               (is (eq t configured))
               (is (eq t transferred))
               (is (equal "snapshot" (configmap-value sink "incoming" "k"))))
          (sb-thread:signal-semaphore release)
          (when configure-thread (sb-thread:join-thread configure-thread :timeout 20 :default nil))
          (when transfer-thread (sb-thread:join-thread transfer-thread :timeout 20 :default nil))
          (setf (symbol-function 'gr8s.resources::install-store-artifact-transport-unlocked) install
                (symbol-function 'gr8s.raft.transport::raft-member-dispatch-message) dispatch)
          (when receiver (gr8s::stop-raft-member receiver))
          (when sender (gr8s::stop-raft-member sender)))))))
