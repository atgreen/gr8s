;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Exercise real HTTP/gRPC log delivery while another Pod's runtime creation
;;;; is blocked, preserving snapshot acknowledgement and session cancellation.

(in-package #:gr8s/tests)
(in-suite gr8s)

(defstruct (blocked-log-runtime (:include gr8s::fake-runtime)
                                (:constructor make-blocked-log-runtime ()))
  (entered nil)
  (released nil)
  (lock (bt:make-lock "blocked log runtime"))
  (changed (bt:make-condition-variable :name "blocked log runtime changed")))

(defmethod gr8s:runtime-ensure ((runtime blocked-log-runtime) pod)
  "Model a blocked image pull for one Pod without blocking direct reads of another Pod's logs."
  (when (equal "slow" (pod-name pod))
    (bt:with-lock-held ((blocked-log-runtime-lock runtime))
      (setf (blocked-log-runtime-entered runtime) t)
      (bt:condition-notify (blocked-log-runtime-changed runtime))
      (loop until (blocked-log-runtime-released runtime)
            do (bt:condition-wait (blocked-log-runtime-changed runtime)
                                 (blocked-log-runtime-lock runtime)))))
  (call-next-method))

(defun release-blocked-log-runtime (runtime)
  "Let the simulated slow image pull finish during test teardown."
  (bt:with-lock-held ((blocked-log-runtime-lock runtime))
    (setf (blocked-log-runtime-released runtime) t)
    (bt:condition-notify (blocked-log-runtime-changed runtime))))

(defun node-log-test-pod (name)
  "Build a Never-restarting Pod explicitly assigned to the test node."
  (let ((input (com.inuoe.jzon:parse *valid-pod-json*)))
    (setf (gethash "name" (gethash "metadata" input)) name
          (gethash "nodeName" (gethash "spec" input)) "log-worker"
          (gethash "restartPolicy" (gethash "spec" input)) "Never")
    (parse-pod input)))

(test logs-remain-available-while-another-pod-snapshot-is-blocked
  (with-temporary-store (store path)
    (gr8s:register-node store (gr8s:make-node-record :id "log-worker-id" :name "log-worker"
                                                   :pod-cidr "10.88.21.0/24"))
    (let* ((completed (create-pod store (node-log-test-pod "completed")))
           (runtime (make-blocked-log-runtime))
           (node (gr8s::make-node-runtime (merge-pathnames "log-agent/" path) runtime nil))
           (server (gr8s:start-node-grpc-server store :host "127.0.0.1" :port 0
                                               :heartbeat-timeout-seconds 6))
           (proxy (gr8s::make-control-plane-runtime store server))
           (api (start-server :address "127.0.0.1" :port 18091 :store store :runtime proxy))
           (identity (merge-pathnames "session/identity.json" path))
           (control (gr8s::make-node-session-control))
           (applied nil)
           (applied-lock (bt:make-lock "applied log-test snapshots"))
           (agent nil))
      (unwind-protect
           (progn
             (gr8s::start-node-runtime node)
             (setf agent
                   (bt:make-thread
                    (lambda ()
                      (gr8s:run-node-session
                       "127.0.0.1" (gr8s:node-grpc-server-port server) "log-worker" identity
                       (lambda (snapshot)
                         (let ((statuses (gr8s::reconcile-node-snapshot node snapshot)))
                           (bt:with-lock-held (applied-lock)
                             (push (slot-value snapshot 'gr8s.node.v1::revision) applied))
                           statuses))
                       :underlay-address "" :control control :reconnect-delay .01
                       :status-provider (lambda () (gr8s::node-runtime-status node))
                       :operation-handler
                       (lambda (variant payload emit)
                         (gr8s::dispatch-node-operation node variant payload emit))))))
             (is-true (wait-until (lambda () (= 1 (gr8s:node-session-acknowledged-revision server "log-worker")))
                                 :timeout 5))
             ;; The target really completed and retained its output. The new
             ;; snapshot below blocks a different runtime creation operation.
             (let ((actual (runtime-observe runtime (pod-uid completed))))
               (setf (runtime-pod-phase actual) "Succeeded"
                     (gethash "web" (gr8s::runtime-pod-logs actual)) (format nil "projected-secret=value-1~%")))
             (is-true
              (wait-until (lambda () (equal "Succeeded" (gethash "phase" (or (gr8s::pod-observed-status store completed)
                                                                                          (gr8s::core-object)))))
                          :timeout 8))
             (create-pod store (node-log-test-pod "slow"))
             (let ((revision (gr8s::publish-node-snapshot proxy "log-worker")))
               (is-true (wait-until (lambda () (blocked-log-runtime-entered runtime)) :timeout 5))
               ;; A later revision must queue behind the blocked application,
               ;; without blocking receipt of the independent log request.
               (setf revision
                     (gr8s:publish-node-desired-state
                      server "log-worker" (gr8s::node-desired-state-snapshot store "log-worker")))
               (multiple-value-bind (octets status)
                   (drakma:http-request "http://127.0.0.1:18091/api/v1/namespaces/default/pods/completed/log?container=web"
                                        :force-binary t :connection-timeout 15)
                 (let ((body (trivial-utf-8:utf-8-bytes-to-string octets)))
                   (is (= 200 status) "log HTTP response ~A: ~A" status body)
                   (is (equal (format nil "projected-secret=value-1~%") body))))
               (is-false (blocked-log-runtime-released runtime))
               (is (= 1 (gr8s:node-session-acknowledged-revision server "log-worker")))
               (is (= 1 (gethash "lastAppliedRevision" (com.inuoe.jzon:parse identity))))
               (is-true (gr8s:node-record-ready-p (gr8s:get-node store "log-worker")))
               (release-blocked-log-runtime runtime)
               (is-true (wait-until (lambda () (= revision (gr8s:node-session-acknowledged-revision server "log-worker")))
                                   :timeout 5))
               (is (equal '(1 2 3) (bt:with-lock-held (applied-lock) (reverse applied))))))
        (release-blocked-log-runtime runtime)
        (gr8s::cancel-node-session control)
        (when agent (ignore-errors (bt:join-thread agent)))
        (stop-server api)
        (gr8s::stop-node-runtime node)
        (gr8s:stop-node-grpc-server server)))))

(test cancelling-a-session-unwinds-blocked-snapshot-without-acknowledging-it
  (with-temporary-store (store path)
    (gr8s:register-node store (gr8s:make-node-record :id "cancel-snapshot-id" :name "cancel-snapshot"
                                                   :pod-cidr "10.88.22.0/24"))
    (let* ((server (gr8s:start-node-grpc-server store :host "127.0.0.1" :port 0))
           (identity (merge-pathnames "cancel-session/identity.json" path))
           (control (gr8s::make-node-session-control))
           (barrier (make-blocked-log-runtime))
           (unwound nil) (converted-to-error nil) (applied nil) (agent nil))
      (unwind-protect
           (progn
             (setf agent
                   (bt:make-thread
                    (lambda ()
                      (gr8s:run-node-session
                       "127.0.0.1" (gr8s:node-grpc-server-port server) "cancel-snapshot" identity
                       (lambda (snapshot)
                         (declare (ignore snapshot))
                         (unwind-protect
                              (progn
                                ;; Match runtime wrappers which convert ERROR
                                ;; to Pending. Cancellation must bypass them.
                                (handler-case
                                    (bt:with-lock-held ((blocked-log-runtime-lock barrier))
                                      (setf (blocked-log-runtime-entered barrier) t)
                                      (loop until (blocked-log-runtime-released barrier)
                                            do (bt:condition-wait (blocked-log-runtime-changed barrier)
                                                                 (blocked-log-runtime-lock barrier))))
                                  (error () (setf converted-to-error t)))
                                (setf applied t)
                                nil)
                           (setf unwound t)))
                       :underlay-address "" :control control :reconnect-delay .01))))
             (is-true (wait-until (lambda () (blocked-log-runtime-entered barrier)) :timeout 5))
             (gr8s::cancel-node-session control)
             (is-true (wait-until (lambda () (not (bt:thread-alive-p agent))) :timeout 3))
             (is-true unwound)
             (is-false converted-to-error)
             (is-false applied)
             (is (= 0 (gr8s:node-session-acknowledged-revision server "cancel-snapshot")))
             (is (= 0 (gethash "lastAppliedRevision" (com.inuoe.jzon:parse identity) 0))))
        (release-blocked-log-runtime barrier)
        (gr8s::cancel-node-session control)
        (when agent (ignore-errors (bt:join-thread agent)))
        (gr8s:stop-node-grpc-server server)))))

(test failing-snapshot-work-closes-its-session-and-drops-queued-revisions
  (let* ((closed nil)
         (barrier (make-blocked-log-runtime))
         (applied nil)
         (worker (gr8s::start-agent-snapshot-worker
                  (lambda (snapshot replay)
                    (declare (ignore replay))
                    (push (slot-value snapshot 'gr8s.node.v1::revision) applied)
                    (bt:with-lock-held ((blocked-log-runtime-lock barrier))
                      (setf (blocked-log-runtime-entered barrier) t)
                      (loop until (blocked-log-runtime-released barrier)
                            do (bt:condition-wait (blocked-log-runtime-changed barrier)
                                                 (blocked-log-runtime-lock barrier))))
                    (error "Failed snapshot persistence"))
                  (lambda () (setf closed t)))))
    (unwind-protect
         (progn
           (gr8s::queue-agent-snapshot-work worker (make-instance 'gr8s.node.v1::desired-state-snapshot :revision 1) :replay t)
           (is-true (wait-until (lambda () (blocked-log-runtime-entered barrier))))
           (gr8s::queue-agent-snapshot-work worker (make-instance 'gr8s.node.v1::desired-state-snapshot :revision 2))
           (release-blocked-log-runtime barrier)
           (is-true (wait-until (lambda () closed)))
           (is (equal '(1) applied))
           (is (typep (gr8s::agent-snapshot-worker-failure worker) 'error))
           (is (null (gr8s::agent-snapshot-worker-pending worker))))
      (release-blocked-log-runtime barrier)
      (gr8s::stop-agent-snapshot-worker worker))))

(test stopping-snapshot-work-during-its-failure-handler-is-contained
  (let* ((barrier (make-blocked-log-runtime))
         (worker
           (gr8s::start-agent-snapshot-worker
            (lambda (snapshot replay) (declare (ignore snapshot replay)) (error "Failed application"))
            (lambda ()
              (bt:with-lock-held ((blocked-log-runtime-lock barrier))
                (setf (blocked-log-runtime-entered barrier) t)
                (loop until (blocked-log-runtime-released barrier)
                      do (bt:condition-wait (blocked-log-runtime-changed barrier)
                                           (blocked-log-runtime-lock barrier))))))))
    (unwind-protect
         (progn
           (gr8s::queue-agent-snapshot-work worker (make-instance 'gr8s.node.v1::desired-state-snapshot :revision 1))
           (is-true (wait-until (lambda () (blocked-log-runtime-entered barrier))))
           (gr8s::stop-agent-snapshot-worker worker)
           (is-false (bt:thread-alive-p (gr8s::agent-snapshot-worker-thread worker))))
      (release-blocked-log-runtime barrier)
      (ignore-errors (gr8s::stop-agent-snapshot-worker worker)))))

(test queued-full-snapshots-are-bounded-and-cannot-regress
  (let* ((barrier (make-blocked-log-runtime))
         (applied nil)
         (worker
           (gr8s::start-agent-snapshot-worker
            (lambda (snapshot replay)
              (declare (ignore replay))
              (let ((revision (slot-value snapshot 'gr8s.node.v1::revision)))
                (when (= revision 1)
                  (bt:with-lock-held ((blocked-log-runtime-lock barrier))
                    (setf (blocked-log-runtime-entered barrier) t)
                    (loop until (blocked-log-runtime-released barrier)
                          do (bt:condition-wait (blocked-log-runtime-changed barrier)
                                               (blocked-log-runtime-lock barrier)))))
                (push revision applied)))
            (lambda () (error "Unexpected session failure")))))
    (unwind-protect
         (progn
           (gr8s::queue-agent-snapshot-work
            worker (make-instance 'gr8s.node.v1::desired-state-snapshot :revision 1) :replay t)
           (is-true (wait-until (lambda () (blocked-log-runtime-entered barrier))))
           (loop for revision from 2 to 100
                 do (gr8s::queue-agent-snapshot-work
                     worker (make-instance 'gr8s.node.v1::desired-state-snapshot :revision revision)))
           ;; Concurrent publishers can deliver an older envelope late.
           (gr8s::queue-agent-snapshot-work
            worker (make-instance 'gr8s.node.v1::desired-state-snapshot :revision 40))
           (bt:with-lock-held ((gr8s::agent-snapshot-worker-lock worker))
             (is (= 1 (length (gr8s::agent-snapshot-worker-pending worker)))))
           (release-blocked-log-runtime barrier)
           (is-true (wait-until (lambda () (= 2 (length applied)))))
           (is (equal '(100 1) applied)))
      (release-blocked-log-runtime barrier)
      (gr8s::stop-agent-snapshot-worker worker))))

(test urgent-withdrawal-cleans-an-unrelated-pod-before-a-retained-pull-finishes
  (with-temporary-store (control-store path)
    (let* ((slow (create-pod control-store (node-log-test-pod "slow")))
           (finished (create-pod control-store (node-log-test-pod "finished")))
           (runtime (make-blocked-log-runtime))
           (node (gr8s::make-node-runtime (merge-pathnames "urgent-agent/" path) runtime nil))
           (first (desired-snapshot-for-test slow finished))
           (latest (desired-snapshot-for-test slow))
           (applied nil)
           (closed nil)
           (worker nil))
      (setf (slot-value latest 'gr8s.node.v1::revision) 2
            (gr8s::node-runtime-state node) :running)
      (dolist (pod (list slow finished)) (gr8s::put-assigned-pod (gr8s::node-runtime-store node) pod))
      (gr8s:runtime-ensure runtime finished)
      (unwind-protect
           (progn
             (setf worker
                   (gr8s::start-agent-snapshot-worker
                    (lambda (snapshot replay)
                      (declare (ignore replay))
                      (gr8s::reconcile-node-snapshot node snapshot)
                      (push (slot-value snapshot 'gr8s.node.v1::revision) applied))
                    (lambda () (setf closed t))
                    :receive-snapshot (lambda (snapshot) (gr8s::receive-node-snapshot-intent node snapshot))))
             (gr8s::queue-agent-snapshot-work worker first :replay t)
             (is-true (wait-until (lambda () (blocked-log-runtime-entered runtime))))
             ;; The latest full snapshot withdraws finished but retains slow.
             ;; Its cleanup must not wait for the unchanged pull to complete.
             (gr8s::queue-agent-snapshot-work worker latest)
             (is-true (wait-until (lambda () (null (gr8s:runtime-observe runtime (pod-uid finished))))))
             (is-false (blocked-log-runtime-released runtime))
             (is (null applied))
             (is-false closed)
             (release-blocked-log-runtime runtime)
             (is-true (wait-until (lambda () (equal '(2) applied))))
             (is (= 2 (gr8s::fake-runtime-ensure-count runtime)))
             (is (null (gr8s::agent-snapshot-worker-failure worker))))
        (release-blocked-log-runtime runtime)
        (gr8s::stop-agent-snapshot-worker worker)))))

(test failed-urgent-persistence-does-not-publish-or-cancel-running-convergence
  (with-temporary-store (control-store path)
    (let* ((slow (create-pod control-store (node-log-test-pod "slow")))
           (runtime (make-blocked-log-runtime))
           (node (gr8s::make-node-runtime (merge-pathnames "persist-agent/" path) runtime nil))
           (reconciler (gr8s::node-runtime-reconciler node))
           (persist (symbol-function 'gr8s::persist-pod))
           (cancelled nil)
           (owner nil))
      (gr8s::put-assigned-pod (gr8s::node-runtime-store node) slow)
      (unwind-protect
           (progn
             (setf owner (bt:make-thread
                          (lambda ()
                            (handler-case
                                (gr8s::reconcile-pod reconciler (pod-namespace slow) (pod-name slow))
                              (gr8s::pod-reconciliation-superseded () (setf cancelled t))))))
             (is-true (wait-until (lambda () (blocked-log-runtime-entered runtime))))
             (setf (symbol-function 'gr8s::persist-pod)
                   (lambda (&rest arguments) (declare (ignore arguments)) (error "Simulated durable write failure")))
             (signals error (gr8s::receive-node-snapshot-intent node (desired-snapshot-for-test)))
             (is (= -1 (gr8s::node-runtime-received-revision node)))
             (is-false cancelled)
             (is-false (gr8s::deletion-requested-p
                        (gr8s:get-pod (gr8s::node-runtime-store node) (pod-namespace slow) (pod-name slow))))
             (is-true (bt:thread-alive-p owner)))
        (setf (symbol-function 'gr8s::persist-pod) persist)
        (release-blocked-log-runtime runtime)
        (when owner (bt:join-thread owner))))))

(test withdrawn-slow-pod-is-never-recreated-or-acknowledged-from-an-old-snapshot
  (with-temporary-store (control-store path)
    (let* ((slow (create-pod control-store (node-log-test-pod "slow")))
           (runtime (make-blocked-log-runtime))
           (node (gr8s::make-node-runtime (merge-pathnames "withdraw-agent/" path) runtime nil))
           (first (desired-snapshot-for-test slow))
           (latest (desired-snapshot-for-test))
           (applied nil) (closed nil) (worker nil))
      (setf (slot-value latest 'gr8s.node.v1::revision) 2
            (gr8s::node-runtime-state node) :running)
      (unwind-protect
           (progn
             (setf worker
                   (gr8s::start-agent-snapshot-worker
                    (lambda (snapshot replay)
                      (declare (ignore replay))
                      (gr8s::reconcile-node-snapshot node snapshot)
                      (push (slot-value snapshot 'gr8s.node.v1::revision) applied))
                    (lambda () (setf closed t))
                    :receive-snapshot (lambda (snapshot) (gr8s::receive-node-snapshot-intent node snapshot))))
             (gr8s::queue-agent-snapshot-work worker first :replay t)
             (is-true (wait-until (lambda () (blocked-log-runtime-entered runtime))))
             (gr8s::queue-agent-snapshot-work worker latest)
             (is-true (wait-until (lambda () (equal '(2) applied))))
             (is-false closed)
             (is (= 0 (gr8s::fake-runtime-ensure-count runtime)))
             (is (null (gr8s:list-pods (gr8s::node-runtime-store node))))
             (signals gr8s::pod-reconciliation-superseded (gr8s::reconcile-node-snapshot node first))
             (is (= 0 (gr8s::fake-runtime-ensure-count runtime)))
             ;; A private forced withdrawal never edits the public object.
             (is-false (gr8s::deletion-requested-p (gr8s:get-pod control-store (pod-namespace slow) (pod-name slow)))))
        (release-blocked-log-runtime runtime)
        (gr8s::stop-agent-snapshot-worker worker)))))

(test urgent-assigned-deletion-preserves-authoritative-rv-and-grace
  (with-temporary-store (control-store path)
    (let* ((pod (create-pod control-store (node-log-test-pod "assigned")))
           (node (gr8s::make-node-runtime (merge-pathnames "grace-agent/" path) (make-fake-runtime) nil)))
      (gr8s::put-assigned-pod (gr8s::node-runtime-store node) pod)
      (let* ((deleting (gr8s::mark-pod-deleting control-store (pod-namespace pod) (pod-name pod) :grace-period 7))
             (snapshot (desired-snapshot-for-test deleting)))
        (is-true (gr8s::receive-node-snapshot-intent node snapshot))
        (let ((private (gr8s:get-pod (gr8s::node-runtime-store node) (pod-namespace pod) (pod-name pod))))
          (is (equal (pod-resource-version deleting) (pod-resource-version private)))
          (is (= (gr8s::pod-deletion-deadline deleting) (gr8s::pod-deletion-deadline private)))
          (is (= 7 (gethash "deletionGracePeriodSeconds" (gethash "metadata" (pod-to-object private))))))))))

(test real-session-acks-only-the-durable-replacement-and-replays-it-on-reconnect
  (with-temporary-store (store path)
    (gr8s:register-node store (gr8s:make-node-record :id "urgent-worker-id" :name "log-worker"
                                                   :pod-cidr "10.88.23.0/24"))
    (let* ((slow (create-pod store (node-log-test-pod "slow")))
           (runtime (make-blocked-log-runtime))
           (node (gr8s::make-node-runtime (merge-pathnames "wire-agent/" path) runtime nil))
           (server (gr8s:start-node-grpc-server store :host "127.0.0.1" :port 0))
           (identity (merge-pathnames "wire-session/identity.json" path))
           (control (gr8s::make-node-session-control))
           (applied nil) (agent nil))
      (setf (gr8s::node-runtime-state node) :running)
      (labels ((apply-snapshot (snapshot)
                 (prog1 (gr8s::reconcile-node-snapshot node snapshot)
                   (push (slot-value snapshot 'gr8s.node.v1::revision) applied)))
               (receive-snapshot (snapshot) (gr8s::receive-node-snapshot-intent node snapshot)))
        (unwind-protect
             (progn
               (is (= 1 (gr8s:publish-node-desired-state server "log-worker" (gr8s::node-desired-state-snapshot store "log-worker"))))
               (setf agent
                     (bt:make-thread
                      (lambda ()
                        (gr8s:run-node-session
                         "127.0.0.1" (gr8s:node-grpc-server-port server) "log-worker" identity
                         #'apply-snapshot :snapshot-observer #'receive-snapshot
                         :underlay-address "" :control control :reconnect-delay .01))))
               (is-true (wait-until (lambda () (blocked-log-runtime-entered runtime)) :timeout 5))
               (is (= 0 (gr8s:node-session-acknowledged-revision server "log-worker")))
               (is (= 0 (gethash "lastAppliedRevision" (com.inuoe.jzon:parse identity) 0)))
               (gr8s::remove-pod store (pod-namespace slow) (pod-name slow))
               (is (= 2 (gr8s:publish-node-desired-state server "log-worker"
                                                       (gr8s::node-desired-state-snapshot store "log-worker"))))
               (is-true (wait-until (lambda () (= 2 (gr8s:node-session-acknowledged-revision server "log-worker"))) :timeout 5))
               (is (equal '(2) applied))
               (is (= 2 (gethash "lastAppliedRevision" (com.inuoe.jzon:parse identity))))
               (is (= 0 (gr8s::fake-runtime-ensure-count runtime)))
               (gr8s::cancel-node-session control)
               (bt:join-thread agent)
               (setf agent nil)
               (gr8s:run-node-session
                "127.0.0.1" (gr8s:node-grpc-server-port server) "log-worker" identity
                #'apply-snapshot :snapshot-observer #'receive-snapshot :underlay-address "" :max-sessions 1)
               (is (equal '(2 2) applied)))
          (release-blocked-log-runtime runtime)
          (gr8s::cancel-node-session control)
          (when agent (ignore-errors (bt:join-thread agent)))
          (gr8s:stop-node-grpc-server server))))))

(test a-duplicate-revision-cannot-drop-required-initial-replay
  (let* ((barrier (make-blocked-log-runtime))
         (calls nil)
         (worker (gr8s::start-agent-snapshot-worker
                  (lambda (snapshot replay)
                    (declare (ignore snapshot))
                    (push replay calls)
                    (when (= 1 (length calls))
                      (bt:with-lock-held ((blocked-log-runtime-lock barrier))
                        (setf (blocked-log-runtime-entered barrier) t)
                        (loop until (blocked-log-runtime-released barrier)
                              do (bt:condition-wait (blocked-log-runtime-changed barrier)
                                                   (blocked-log-runtime-lock barrier))))
                      (error 'gr8s::pod-reconciliation-superseded)))
                  (lambda () (error "Unexpected replay failure")))))
    (unwind-protect
         (progn
           (gr8s::queue-agent-snapshot-work worker (desired-snapshot-for-test) :replay t)
           (is-true (wait-until (lambda () (blocked-log-runtime-entered barrier))))
           (gr8s::queue-agent-snapshot-work worker (desired-snapshot-for-test))
           (release-blocked-log-runtime barrier)
           (is-true (wait-until (lambda () (= 2 (length calls)))))
           (is (equal '(t t) calls)))
      (release-blocked-log-runtime barrier)
      (gr8s::stop-agent-snapshot-worker worker))))

(test stale-uid-withdrawal-does-not-cancel-a-replacement-owning-the-same-name
  (with-temporary-store (control-store path)
    (let* ((old (create-pod control-store (node-log-test-pod "slow")))
           (runtime (make-blocked-log-runtime))
           (node (gr8s::make-node-runtime (merge-pathnames "replacement-agent/" path) runtime nil))
           (store (gr8s::node-runtime-store node))
           (mark (symbol-function 'gr8s::mark-pod-deleting))
           (replacement nil) (owner nil) (cancelled nil))
      (gr8s::put-assigned-pod store old)
      (unwind-protect
           (progn
             (setf (symbol-function 'gr8s::mark-pod-deleting)
                   (lambda (&rest arguments)
                     ;; Complete the old UID and reuse its name between the
                     ;; arrival observer's list and exact-UID deletion write.
                     (gr8s::remove-pod store (pod-namespace old) (pod-name old))
                     (setf replacement (create-pod store (node-log-test-pod "slow"))
                           owner (bt:make-thread
                                  (lambda ()
                                    (handler-case
                                        (gr8s::reconcile-pod (gr8s::node-runtime-reconciler node)
                                                             (pod-namespace replacement) (pod-name replacement))
                                      (gr8s::pod-reconciliation-superseded () (setf cancelled t))))))
                     (unless (wait-until (lambda () (blocked-log-runtime-entered runtime)))
                       (error "Replacement did not enter convergence"))
                     (apply mark arguments)))
             (is-false (gr8s::receive-node-snapshot-intent node (desired-snapshot-for-test)))
             (is-false (equal (pod-uid old) (pod-uid replacement)))
             (is-false cancelled)
             (is-false (gr8s::deletion-requested-p (gr8s:get-pod store (pod-namespace replacement) (pod-name replacement))))
             (is-true (bt:thread-alive-p owner)))
        (setf (symbol-function 'gr8s::mark-pod-deleting) mark)
        (release-blocked-log-runtime runtime)
        (when owner (bt:join-thread owner))))))
