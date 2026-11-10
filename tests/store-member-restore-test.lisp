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

(defun startup-store-raw-value (store)
  (let ((object (gethash '("configmaps" "default" "recover") (gr8s::pod-store-resources store))))
    (and object (gethash "k" (gethash "data" object)))))

(defun make-startup-store-wal (store root &key single-voter)
  "Files contain B; durable snapshot contains A; WAL tail contains B then uncommitted C."
  (gr8s::create-core-resource store "configmaps" (configmap-input "recover" "k" "A") "default")
  (let ((artifact (merge-pathnames "baseline.jsonl" root))
        (wal (merge-pathnames "raft/recovery.log" root)))
    (gr8s.resources::capture-store-snapshot store artifact 42 7)
    (multiple-value-bind (retained reference)
        (gr8s.resources::retain-store-snapshot-artifact root artifact 42 7 (snapshot-test-digest artifact))
      (let* ((state (getf (artifact-wire-test-message reference) :state))
             (b (capture-ha-core-write store
                  (lambda () (gr8s::update-core-resource store "configmaps" "default" "recover"
                    (lambda (object) (setf (gethash "k" (gethash "data" object)) "B") object))))))
        (apply-ha-core-command store b)
        (let ((c (capture-ha-core-write store
                   (lambda () (gr8s::update-core-resource store "configmaps" "default" "recover"
                     (lambda (object) (setf (gethash "k" (gethash "data" object)) "C") object)))))
              (storage (gr8s::open-file-raft-storage wal)))
          (when single-voter (setf (getf (cddr state) :members) '(("sink" . :voter))))
          (unwind-protect
               (gr8s.raft::raft-storage-replace-snapshot
                storage 42 7 state 9 (if single-voter "sink" "source")
                (coerce (append (list (gr8s::make-raft-entry :index 43 :term 9 :command b))
                                (unless single-voter (list (gr8s::make-raft-entry :index 44 :term 9 :command c)))) 'vector))
            (close (gr8s.raft::file-raft-storage-stream storage))))
        (values wal reference retained)))))

(test startup-restores-baseline-before-listening-and-applies-only-confirmed-suffix
  (with-temporary-store (store root)
    (gr8s::ensure-cluster-pki root)
    (let* ((key (merge-pathnames "pki/cluster-ca.key" root))
           (identity (uiop:read-file-string key))
           (wal (make-startup-store-wal store root))
           (member nil) (observed nil)
           (original (symbol-function 'ag-grpc:make-grpc-server))
           (sender (gr8s::make-raft-member)))
      (is (equal "B" (startup-store-raw-value store)))
      (unwind-protect
           (progn
             (unwind-protect
                  (progn
                    (setf (symbol-function 'ag-grpc:make-grpc-server)
                          (lambda (&rest args)
                            (setf observed (list (startup-store-raw-value store)
                                                 (gr8s.store::store-access-blocked-p store)
                                                 (gr8s.store::store-application-barriers-owned-p store)))
                            (apply original args)))
                    (setf member (gr8s.resources::start-store-member-from-wal store "sink" wal)))
               (setf (symbol-function 'ag-grpc:make-grpc-server) original))
             (is (equal '("A" t t) observed))
             (is (= 42 (gr8s::raft-node-last-applied (gr8s::raft-member-node member))))
             (is (= 44 (gr8s::raft-last-log-index (gr8s::raft-member-node member))))
             (is (= 503 (core-resource-status (lambda () (gr8s::get-core-resource store "configmaps" "default" "recover")))))
             (send-member-restore-message sender member
              (list :type :request-vote :term 9 :from "other" :last-log-index 44 :last-log-term 9))
             (is-true (gr8s.store::store-access-blocked-p store))
             (is (equal "source" (gr8s::raft-node-voted-for (gr8s::raft-member-node member))))
             (send-member-restore-message sender member
              (list :type :append-entries :term 8 :from "source" :prev-log-index 44 :prev-log-term 9 :entries nil :leader-commit 44))
             (is-true (gr8s.store::store-access-blocked-p store))
             (send-member-restore-message sender member
              (list :type :append-entries :term 9 :from "source" :prev-log-index 44 :prev-log-term 9 :entries nil :leader-commit 43))
             (is (equal "B" (configmap-value store "recover" "k")))
             (is (= 43 (gr8s::raft-node-last-applied (gr8s::raft-member-node member))))
             (is (= 44 (gr8s::raft-last-log-index (gr8s::raft-member-node member))))
             (is-false (gr8s.store::store-access-blocked-p store))
             (is (null (gr8s.raft.transport::raft-member-startup-check-fn member)))
             (is (equal identity (uiop:read-file-string key)))
             (let ((d (capture-ha-core-write store
                        (lambda () (gr8s::update-core-resource store "configmaps" "default" "recover"
                          (lambda (object) (setf (gethash "k" (gethash "data" object)) "D") object))))))
               (send-member-restore-message sender member
                (list :type :append-entries :term 10 :from "source" :prev-log-index 43 :prev-log-term 9
                      :entries (list (gr8s::make-raft-entry :index 44 :term 10 :command d)) :leader-commit 44)))
             (is (equal "D" (configmap-value store "recover" "k")))
             (is (= 44 (gr8s::raft-node-last-applied (gr8s::raft-member-node member))))
             (is (= 10 (gr8s::raft-entry-term (car (last (gr8s::raft-recovered-entries (gr8s::load-raft-log wal))))))))
        (setf (symbol-function 'ag-grpc:make-grpc-server) original)
        (when member (gr8s::stop-raft-member member))))))

(test recovered-single-voter-opens-api-only-after-its-current-term-commit
  (with-temporary-store (store root)
    (let ((wal (make-startup-store-wal store root :single-voter t)) (member nil))
      (unwind-protect
           (progn
             (setf member (gr8s.resources::start-store-member-from-wal store "sink" wal :timeout-fn (lambda () 3)))
             (is-true (gr8s.store::store-access-blocked-p store))
             (is (equal "A" (startup-store-raw-value store)))
             (gr8s::raft-member-start member :tick-seconds 0.01)
             (is (poll-until (lambda () (not (gr8s.store::store-access-blocked-p store))) :timeout 10))
             (is (gr8s::raft-member-leader-p member))
             (is (equal "B" (configmap-value store "recover" "k")))
             (is (> (gr8s::raft-node-current-term (gr8s::raft-member-node member)) 9))
             (gr8s::create-core-resource store "configmaps" (configmap-input "after-restart" "k" "replicated") "default")
             (is (equal "replicated" (configmap-value store "after-restart" "k")))
             (is (>= (gr8s::raft-node-last-applied (gr8s::raft-member-node member)) 45)))
        (when member (gr8s::stop-raft-member member))))))

(test missing-or-corrupt-startup-artifact-never-opens-a-peer-listener
  (dolist (mode '(:missing :corrupt))
    (with-temporary-store (store root)
      (multiple-value-bind (wal reference path) (make-startup-store-wal store root)
        (declare (ignore reference))
        (if (eq mode :missing) (delete-file path)
            (with-open-file (out path :direction :output :if-exists :append) (write-line "corrupt" out)))
        (let ((created 0) (original (symbol-function 'ag-grpc:make-grpc-server)))
          (unwind-protect
               (progn
                 (setf (symbol-function 'ag-grpc:make-grpc-server)
                       (lambda (&rest args) (incf created) (apply original args)))
                 (signals error (gr8s.resources::start-store-member-from-wal store "sink" wal))
                 (is (= 0 created))
                 (is (equal "B" (startup-store-raw-value store)))
                 (is-true (gr8s.store::store-access-blocked-p store))
                 (is (null (gr8s.store::read-store-restore-intent root))))
            (setf (symbol-function 'ag-grpc:make-grpc-server) original)))))))

(test application-wal-baseline-and-committed-suffix-survive-repeated-process-kills
  (with-temporary-store (store root)
    (let* ((wal (make-startup-store-wal store root))
           (script (namestring (merge-pathnames "scripts/store-wal-recovery-test-child.lisp" (asdf:system-source-directory :gr8s))))
           (ready (merge-pathnames "recovery-ready.json" root))
           (report (merge-pathnames "recovery-report.json" root))
           (stop (merge-pathnames "recovery-stop.txt" root))
           (log (merge-pathnames "recovery-child.log" root))
           (process nil) (previous-version 2))
      (labels ((await-file (path)
                 (poll-until (lambda () (or (probe-file path) (not (sb-ext:process-alive-p process)))) :timeout 60)
                 (unless (probe-file path)
                   (error "Application recovery child failed:~%~A" (uiop:read-file-string log))))
               (api (port path)
                 (drakma:http-request (format nil "http://127.0.0.1:~D~A" port path) :proxy nil :redirect nil)))
        (unwind-protect
             (dotimes (cycle 3)
               (dolist (path (list ready report stop)) (when (probe-file path) (delete-file path)))
               (setf process
                     (sb-ext:run-program "sbcl"
                      (list "--dynamic-space-size" "384" "--noinform" "--non-interactive" "--load" script "--"
                            (namestring root) (namestring wal) (namestring ready) (namestring report) (namestring stop))
                      :search t :wait nil :input nil :output log :if-output-exists :supersede :error :output))
               (await-file ready)
               (let* ((startup (response-object (uiop:read-file-string ready)))
                      (api-port (gethash "apiPort" startup))
                      (remote (gr8s::make-raft-member :port (gethash "raftPort" startup)))
                      (sender (gr8s::make-raft-member)))
                 (is (equal "A" (gethash "baseline" startup)))
                 (is (> (gethash "resourceRevision" startup) previous-version))
                 (is (= 9 (gethash "term" startup)))
                 (is (equal "source" (gethash "vote" startup)))
                 (is (= 42 (gethash "appliedIndex" startup)))
                 (is (= 503 (nth-value 1 (api api-port "/readyz"))))
                 (is (= 503 (nth-value 1 (api api-port "/api/v1/namespaces/default/configmaps/recover"))))
                 (send-member-restore-message sender remote
                  (list :type :request-vote :term 9 :from "other" :last-log-index 44 :last-log-term 9))
                 (is (= 503 (nth-value 1 (api api-port "/readyz"))))
                 (send-member-restore-message sender remote
                  (list :type :append-entries :term 9 :from "source" :prev-log-index 44 :prev-log-term 9
                        :entries nil :leader-commit 43))
                 (await-file report)
                 (let ((result (response-object (uiop:read-file-string report))))
                   (is (equal "B" (gethash "value" result)))
                   (is (= 43 (gethash "appliedIndex" result)))
                   (is (= 44 (gethash "lastLogIndex" result)))
                   (is (> (parse-integer (gethash "resourceVersion" result)) previous-version))
                   (setf previous-version (parse-integer (gethash "resourceVersion" result))))
                 (is (= 200 (nth-value 1 (api api-port "/readyz"))))
                 (multiple-value-bind (body status) (api api-port "/api/v1/namespaces/default/configmaps/recover")
                   (is (= 200 status))
                   (is (equal "B" (gethash "k" (gethash "data" (response-object body)))))))
               (sb-ext:process-kill process 9)
               (sb-ext:process-wait process)
               (is (eq :signaled (sb-ext:process-status process)))
               (sb-ext:process-close process)
               (setf process nil))
          (when process
            (when (sb-ext:process-alive-p process)
              (sb-ext:process-kill process 9)
              (sb-ext:process-wait process))
            (sb-ext:process-close process)))))))

(test startup-apply-failure-retries-without-accumulating-recovery-barriers
  (with-temporary-store (store root)
    (let ((wal (make-startup-store-wal store root :single-voter t))
          (member nil) (original (symbol-function 'gr8s::install-core-state-delta))
          (attempted (sb-thread:make-semaphore :count 0)))
      (unwind-protect
           (progn
             (setf member (gr8s.resources::start-store-member-from-wal store "sink" wal :timeout-fn (lambda () 3)))
             (setf (symbol-function 'gr8s::install-core-state-delta)
                   (lambda (incoming payload)
                     (if (eq incoming store)
                         (progn (sb-thread:signal-semaphore attempted) (error "Injected suffix apply failure"))
                         (funcall original incoming payload))))
             (gr8s::raft-member-start member :tick-seconds 0.01)
             (dotimes (i 3) (is-true (sb-thread:wait-on-semaphore attempted :timeout 5)))
             (bt:with-lock-held ((gr8s::raft-member-lock member))
               (is (= 44 (gr8s::raft-last-log-index (gr8s::raft-member-node member))))
               (is (= 42 (gr8s::raft-node-last-applied (gr8s::raft-member-node member)))))
             (is-true (gr8s.store::store-access-blocked-p store))
             (setf (symbol-function 'gr8s::install-core-state-delta) original)
             (is (poll-until (lambda () (not (gr8s.store::store-access-blocked-p store))) :timeout 10))
             (is (equal "B" (configmap-value store "recover" "k")))
             (bt:with-lock-held ((gr8s::raft-member-lock member))
               (is (= 44 (gr8s::raft-last-log-index (gr8s::raft-member-node member))))))
        (setf (symbol-function 'gr8s::install-core-state-delta) original)
        (when member (gr8s::stop-raft-member member))))))

(test application-startup-never-replays-a-wal-without-an-artifact-baseline
  (dolist (mode '(:absent :opaque))
    (with-temporary-store (store root)
      (gr8s::create-core-resource store "configmaps" (configmap-input "recover" "k" "B") "default")
      (let* ((wal (merge-pathnames "raft/no-baseline.log" root))
             (storage (gr8s::open-file-raft-storage wal))
             (created 0) (original (symbol-function 'ag-grpc:make-grpc-server)))
        (unwind-protect
             (if (eq mode :absent)
                 (gr8s.raft::raft-storage-save-hard-state storage 9 "sink")
                 (gr8s.raft::raft-storage-replace-snapshot
                  storage 42 7 (list :gr8s-raft-snapshot 1 :application '(:opaque-state)
                                     :application-present t :members '(("sink" . :voter)) :addresses nil :api-urls nil)
                  9 "sink" #()))
          (gr8s::close-file-raft-storage storage))
        (let ((digest (snapshot-test-digest wal)))
          (unwind-protect
               (progn
                 (setf (symbol-function 'ag-grpc:make-grpc-server)
                       (lambda (&rest args) (incf created) (apply original args)))
                 (signals error (gr8s.resources::start-store-member-from-wal store "sink" wal))
                 (is (= 0 created))
                 (is (equal digest (snapshot-test-digest wal)))
                 (is (equal "B" (startup-store-raw-value store)))
                 (is-true (gr8s.store::store-access-blocked-p store))
                 (is (null (gr8s.store::read-store-restore-intent root))))
            (setf (symbol-function 'ag-grpc:make-grpc-server) original)))))))

(test rejected-recovered-wal-validation-prevents-listener-construction
  (with-temporary-store (store root)
    (let* ((wal (make-startup-store-wal store root))
           (digest (snapshot-test-digest wal))
           (original (symbol-function 'ag-grpc:make-grpc-server))
           (prepared 0) (listeners 0))
      (unwind-protect
           (progn
             (setf (symbol-function 'ag-grpc:make-grpc-server)
                   (lambda (&rest args) (incf listeners) (apply original args)))
             (signals error
               (gr8s::start-raft-member "sink" :storage-path wal
                :prepare-fn (lambda (member) (declare (ignore member)) (incf prepared))
                :validate-recovery-fn (lambda (member recovered) (declare (ignore member recovered)) nil)))
             (is (= 1 prepared))
             (is (= 0 listeners))
             (is (equal digest (snapshot-test-digest wal))))
        (setf (symbol-function 'ag-grpc:make-grpc-server) original)))))

(test process-killed-after-startup-selection-recovers-the-durable-intent
  (with-temporary-store (store root)
    (gr8s::ensure-cluster-pki root)
    (multiple-value-bind (wal reference artifact) (make-startup-store-wal store root)
      (declare (ignore artifact))
      (let* ((script (namestring (merge-pathnames "scripts/store-wal-recovery-test-child.lisp" (asdf:system-source-directory :gr8s))))
             (ready (merge-pathnames "interrupted-ready.json" root))
             (report (merge-pathnames "interrupted-report.json" root))
             (stop (merge-pathnames "interrupted-stop.txt" root))
             (log (merge-pathnames "interrupted-child.log" root))
             (key (merge-pathnames "pki/cluster-ca.key" root))
             (identity (snapshot-test-digest key)) (process nil))
        (labels ((launch (mode)
                   (setf process
                         (sb-ext:run-program "sbcl"
                          (list "--dynamic-space-size" "384" "--noinform" "--non-interactive" "--load" script "--"
                                (namestring root) (namestring wal) (namestring ready) (namestring report) (namestring stop) mode)
                          :search t :wait nil :input nil :output log :if-output-exists :supersede :error :output)))
                 (await-file (path)
                   (poll-until (lambda () (or (probe-file path) (not (sb-ext:process-alive-p process)))) :timeout 60)
                   (unless (probe-file path) (error "Interrupted recovery child failed:~%~A" (uiop:read-file-string log)))))
          (unwind-protect
               (progn
                 (launch "hold-load")
                 (await-file ready)
                 (is (equal "loading" (gethash "phase" (response-object (uiop:read-file-string ready)))))
                 (sb-ext:process-kill process 9)
                 (sb-ext:process-wait process)
                 (is (eq :signaled (sb-ext:process-status process)))
                 (sb-ext:process-close process)
                 (setf process nil)
                 (let ((intent (gr8s.store::read-store-restore-intent root)))
                   (is-true intent)
                   (is (= 42 (gethash "index" intent)))
                   (is (equal (eighth reference) (gethash "artifactSha256" intent))))
                 (is (equal identity (snapshot-test-digest key)))
                 (delete-file ready)
                 (launch "normal")
                 (await-file ready)
                 (let* ((startup (response-object (uiop:read-file-string ready)))
                        (remote (gr8s::make-raft-member :port (gethash "raftPort" startup))))
                   (is (equal "A" (gethash "baseline" startup)))
                   (is (= 42 (gethash "appliedIndex" startup)))
                   (send-member-restore-message (gr8s::make-raft-member) remote
                    (list :type :append-entries :term 9 :from "source" :prev-log-index 44 :prev-log-term 9
                          :entries nil :leader-commit 43)))
                 (await-file report)
                 (let ((result (response-object (uiop:read-file-string report))))
                   (is (equal "B" (gethash "value" result)))
                   (is (= 43 (gethash "appliedIndex" result))))
                 (is (null (gr8s.store::read-store-restore-intent root)))
                 (is (equal identity (snapshot-test-digest key))))
            (when process
              (when (sb-ext:process-alive-p process)
                (sb-ext:process-kill process 9)
                (sb-ext:process-wait process))
              (sb-ext:process-close process))))))))
