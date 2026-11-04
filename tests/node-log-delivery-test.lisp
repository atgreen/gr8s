;;;; SPDX-FileCopyrightText: 2026 gr8s contributors
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
                    (push snapshot applied)
                    (bt:with-lock-held ((blocked-log-runtime-lock barrier))
                      (setf (blocked-log-runtime-entered barrier) t)
                      (loop until (blocked-log-runtime-released barrier)
                            do (bt:condition-wait (blocked-log-runtime-changed barrier)
                                                 (blocked-log-runtime-lock barrier))))
                    (error "Failed snapshot persistence"))
                  (lambda () (setf closed t)))))
    (unwind-protect
         (progn
           (gr8s::queue-agent-snapshot-work worker 1 :replay t)
           (is-true (wait-until (lambda () (blocked-log-runtime-entered barrier))))
           (gr8s::queue-agent-snapshot-work worker 2)
           (release-blocked-log-runtime barrier)
           (is-true (wait-until (lambda () closed)))
           (is (equal '(1) applied))
           (is (typep (gr8s::agent-snapshot-worker-failure worker) 'error))
           (is (null (gr8s::agent-snapshot-worker-pending worker))))
      (release-blocked-log-runtime barrier)
      (gr8s::stop-agent-snapshot-worker worker))))
