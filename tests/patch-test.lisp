;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
(in-package #:gr8s/tests)
(in-suite gr8s)
(def-suite patch :in gr8s)
(in-suite patch)
(declaim (notinline patch-fixture-value))
(defun patch-fixture-value () 0)
(defvar *patch-migration-count* 0)
(defun call-with-patch-fixture (function &key (levels 1) (healthy t) (domains #("fixture"))
                                               (replaces #("GR8S/TESTS::PATCH-FIXTURE-VALUE"))
                                               (extra-source ""))
  (let* ((directory (merge-pathnames (format nil "gr8s-patch-test-~A/" (gr8s.patch::identifier)) #P"/tmp/"))
         (gr8s.patch::*domains* (make-hash-table :test 'equal))
         (gr8s.patch::*patch-definitions* (make-hash-table :test 'equal))
         (key (ironclad:make-private-key :ed25519 :x (ironclad:random-data 32)))
         (public (getf (ironclad:destructure-private-key key) :y))
         (manager nil)
         (image (merge-pathnames "image/" directory)))
    (unwind-protect
         (progn
           (gr8s.patch:register-domain "fixture" '("GR8S/TESTS::PATCH-FIXTURE-VALUE"))
           (setf manager (gr8s.patch:open-manager directory "worker-a" '("worker")))
           (gr8s.patch::durable-json (gr8s.patch::path manager "trusted-keys.json")
                                     (gr8s.patch::object "fixture" (ironclad:byte-array-to-hex-string public)))
           (let ((recipe (gr8s.patch::object "publisher" "fixture" "levels"
                                            (make-array levels))))
             (loop for number from 1 to levels do
               (let* ((name (format nil "gr8s-patch-~A-~D" (gr8s.patch::identifier) number))
                      (source (merge-pathnames (format nil "source/~D/" number) directory))
                      (system-file (concatenate 'string name ".asd")))
                 (gr8s.patch::durable-bytes
                  (merge-pathnames system-file source)
                  (gr8s.patch::octets (format nil "(asdf:defsystem ~S :depends-on (\"gr8s\") :serial t :components ((:file \"code\")))" name)))
                 (gr8s.patch::durable-bytes
                  (merge-pathnames "code.lisp" source)
                  (gr8s.patch::octets
                   (format nil "(in-package #:gr8s/tests)~%(defun patch-fixture-value () ~D)~%(gr8s.patch:register-patch :migrate (lambda (context) (declare (ignore context)) (gr8s.patch:checkpoint \"once\" (lambda () (incf *patch-migration-count*)))) :verify (lambda (context) (declare (ignore context)) ~S))~%"
                           number healthy)))
                 (setf (aref (gethash "levels" recipe) (1- number))
                       (gr8s.patch::object "summary" (format nil "Fixture fix ~D" number)
                                           "mode" "reload" "roles" #("worker")
                                           "domains" domains "replaces" replaces
                                           "system" name "systemFile" system-file
                                           "sourceDirectory" (namestring source) "files" (vector system-file "code.lisp")))))
             (loop for level across (gethash "levels" recipe) do
               (unless domains (remhash "domains" level))
               (unless replaces (remhash "replaces" level))
               (let ((file (merge-pathnames "code.lisp" (gethash "sourceDirectory" level))))
                 (with-open-file (stream file :direction :output :if-exists :append)
                   (write-string extra-source stream))))
             (gr8s.patch::build-artifact recipe key image))
           (funcall function manager image directory))
      (when manager (gr8s.patch:close-manager manager))
      (setf (symbol-function 'patch-fixture-value) (lambda () 0))
      (uiop:delete-directory-tree directory :validate t :if-does-not-exist :ignore))))
(test patch-cli-contract
  (is (eq :patch (getf (parse-cli-options '("patch" "apply" "patch-1" "--watch")) :command)))
  (is (getf (parse-cli-options '("patch" "apply" "patch-1" "--watch")) :watch))
  (is (= 7 (getf (parse-cli-options '("patch" "plan" "registry/train:latest" "--level" "7")) :level)))
  (dolist (arguments '(("patch" "apply") ("patch" "plan" "x" "--level" "-1")
                       ("patch" "history") ("patch" "status" "--wat") ("patch" "unknown")))
    (signals error (parse-cli-options arguments))))
(test patch-signed-layout-is-inspected-without-evaluation
  (call-with-patch-fixture
   (lambda (manager image directory)
     (declare (ignore directory))
     (let ((artifact (gr8s.patch:inspect-artifact manager image)))
       (is (= 1 (length (gethash "levels" (gethash "index" artifact)))))
       (is (= 0 (patch-fixture-value)))
       (is (= 0 (gethash "installedLevel" (gr8s.patch:inventory manager))))))))
(test patch-untrusted-publisher-is-rejected-before-load
  (call-with-patch-fixture
   (lambda (manager image directory)
     (declare (ignore directory))
     (gr8s.patch::durable-json (gr8s.patch::path manager "trusted-keys.json") (gr8s.patch::object))
     (signals error (gr8s.patch:inspect-artifact manager image))
     (is (= 0 (patch-fixture-value))))))
(test patch-corrupt-content-is-rejected
  (call-with-patch-fixture
   (lambda (manager image directory)
     (declare (ignore directory))
     (let* ((artifact (gr8s.patch:inspect-artifact manager image))
            (level (aref (gethash "levels" (gethash "index" artifact)) 0))
            (file (aref (gethash "files" level) 0)))
       (gr8s.patch::durable-bytes (gr8s.patch::blob-path manager (gethash "digest" file)) #(1 2 3))
       (signals error (gr8s.patch::cached-artifact manager (gethash "digest" artifact)))))))
(test patch-loads-in-process-and-reconstructs-after-restart
  (let ((*patch-migration-count* 0))
    (call-with-patch-fixture
     (lambda (manager image directory)
       (let* ((artifact (gr8s.patch:inspect-artifact manager image))
              (hash (gethash "digest" artifact))
              (boot (gethash "bootID" (gr8s.patch:inventory manager)))
              (pid (sb-posix:getpid)))
         (gr8s.patch::apply-level manager hash 1 "grant-1" boot)
         (is (= 1 (patch-fixture-value)))
         (is (= pid (sb-posix:getpid)))
         (is (= 1 *patch-migration-count*))
         (gr8s.patch::apply-level manager hash 1 "grant-1" boot)
         (is (= 1 *patch-migration-count*))
         (signals error (gr8s.patch::apply-level manager hash 1 "new-grant" "stale-boot"))
         (gr8s.patch:close-manager manager)
         (setf (symbol-function 'patch-fixture-value) (lambda () 0))
         (let ((restarted (gr8s.patch:open-manager directory "worker-a" '("worker"))))
           (unwind-protect
                (progn
                  (is (= 0 (gr8s.patch::manager-loaded-level restarted)))
                  (gr8s.patch:recover-manager restarted)
                  (is (= 1 (patch-fixture-value)))
                  (is (= 1 *patch-migration-count*))
                  (is (not (equal boot (gethash "bootID" (gr8s.patch:inventory restarted))))))
             (gr8s.patch:close-manager restarted))))))))
(test patch-levels-are-ordered-and-cannot-downgrade
  (call-with-patch-fixture
   (lambda (manager image directory)
     (declare (ignore directory))
     (let* ((artifact (gr8s.patch:inspect-artifact manager image))
            (hash (gethash "digest" artifact)) (boot (gr8s.patch::manager-boot-id manager)))
       (signals error (gr8s.patch::apply-level manager hash 2 "skip" boot))
       (gr8s.patch::apply-level manager hash 1 "one" boot)
       (gr8s.patch::apply-level manager hash 2 "two" boot)
       (is (= 2 (patch-fixture-value)))
       (signals error (gr8s.patch::validate-prefix manager artifact 1)))) :levels 2))
(test patch-health-failure-taints-process-and-retains-recovery-intent
  (call-with-patch-fixture
   (lambda (manager image directory)
     (declare (ignore directory))
     (let ((artifact (gr8s.patch:inspect-artifact manager image)))
       (signals error (gr8s.patch::apply-level manager (gethash "digest" artifact) 1 "failed" (gr8s.patch::manager-boot-id manager)))
       (is (equal "tainted" (gethash "state" (gr8s.patch:inventory manager))))
       (is (gethash "pending" (gr8s.patch::manager-state manager)))
       (is (= 0 (gethash "level" (gr8s.patch::manager-state manager)))))) :healthy nil))
(test patch-coordinator-canary-pause-resume-and-durable-completion
  (call-with-patch-fixture
   (lambda (manager image directory)
     (declare (ignore directory))
     (let* ((state (gr8s.patch::new-cluster-state))
            (peer (gr8s.patch::object "id" "worker-a" "local" t "role" "worker"))
            (coordinator (gr8s.patch:make-coordinator
                          :manager manager :read-state (lambda () (gr8s.patch::copy-json state))
                          :update-state (lambda (fn) (setf state (funcall fn (gr8s.patch::copy-json state))))
                          :participants (lambda () (list peer)) :leader-p (constantly t)
                          :call (lambda (participant command) (declare (ignore participant)) (gr8s.patch:handle-command manager command))))
            (plan (gr8s.patch::patch-plan coordinator image 1 0))
            (id (gethash "id" plan)))
       (gr8s.patch::control-plan coordinator id "apply")
       (gr8s.patch::control-plan coordinator id "pause")
       (dotimes (n 3) (gr8s.patch:coordinator-tick coordinator))
       (is (= 0 (patch-fixture-value)))
       (gr8s.patch::control-plan coordinator id "resume")
       (dotimes (n 15) (gr8s.patch:coordinator-tick coordinator))
       (let ((final (gr8s.patch::plan-state coordinator id)))
         (is (equal "complete" (gethash "state" final)))
         (is (= 1 (gethash "policyLevel" state)))
         (is (= 1 (patch-fixture-value)))
         (is (not (hash-table-p (gethash "grant" final)))))))))
(in-suite gr8s)
(in-suite patch)
(test patch-state-directory-excludes-another-manager-in-the-same-process
  (call-with-patch-fixture
   (lambda (manager image directory)
     (declare (ignore manager image))
     (signals error (gr8s.patch:open-manager directory "duplicate" '("worker"))))))
(test patch-history-refuses-rewritten-prefix
  (call-with-patch-fixture
   (lambda (manager image directory)
     (declare (ignore directory))
     (let* ((artifact (gr8s.patch:inspect-artifact manager image))
            (boot (gr8s.patch::manager-boot-id manager)))
       (gr8s.patch::apply-level manager (gethash "digest" artifact) 1 "one" boot)
       (let ((other (gr8s.patch::copy-json artifact)))
         (setf (gethash "chain" (aref (gethash "levels" (gethash "index" other)) 0)) "sha256:rewritten")
         (signals error (gr8s.patch::validate-prefix manager other 2))))) :levels 2))
(test patch-domain-drains-active-operations-and-blocks-admission
  (let ((entered nil) (release nil) (closed nil) (second-entered nil))
    (gr8s.patch:register-domain "drain" nil)
    (let* ((domain (gethash "drain" gr8s.patch::*domains*))
           (operation (bt:make-thread (lambda () (gr8s.patch:call-in-domain
                                                  "drain" (lambda () (setf entered t) (loop until release do (sleep 0.01))))))))
      (unwind-protect
           (progn
             (loop repeat 100 until entered do (sleep 0.01))
             (is-true entered)
             (let ((closer (bt:make-thread (lambda () (gr8s.patch::close-domain domain 2) (setf closed t)))))
               (sleep 0.05) (is-false closed)
               (setf release t) (bt:join-thread operation) (bt:join-thread closer)
               (is-true closed)
               (let ((waiting (bt:make-thread (lambda () (gr8s.patch:call-in-domain "drain" (lambda () (setf second-entered t)))))))
                 (sleep 0.05) (is-false second-entered)
                 (gr8s.patch::reopen-domain domain) (bt:join-thread waiting)
                 (is-true second-entered))))
        (setf release t) (gr8s.patch::reopen-domain domain)
        (ignore-errors (bt:join-thread operation))))))
(test patch-coordinator-abort-does-not-rewind-applied-levels
  (call-with-patch-fixture
   (lambda (manager image directory)
     (declare (ignore directory))
     (let* ((state (gr8s.patch::new-cluster-state))
            (peer (gr8s.patch::object "id" "worker-a" "local" t))
            (coordinator (gr8s.patch:make-coordinator :manager manager
                          :read-state (lambda () (gr8s.patch::copy-json state))
                          :update-state (lambda (fn) (setf state (funcall fn (gr8s.patch::copy-json state))))
                          :participants (lambda () (list peer)) :leader-p (constantly t)
                          :call (lambda (p c) (declare (ignore p)) (gr8s.patch:handle-command manager c))))
            (plan (gr8s.patch::patch-plan coordinator image 2 0)) (id (gethash "id" plan)))
       (gr8s.patch::control-plan coordinator id "apply")
       (loop repeat 12 until (= 1 (gr8s.patch::manager-loaded-level manager)) do (gr8s.patch:coordinator-tick coordinator))
       (is (= 1 (gr8s.patch::manager-loaded-level manager)))
       (gr8s.patch::control-plan coordinator id "abort")
       (dotimes (i 4) (gr8s.patch:coordinator-tick coordinator))
       (is (= 1 (gr8s.patch::manager-loaded-level manager)))
       (is (equal "aborted" (gethash "state" (gr8s.patch::plan-state coordinator id)))))) :levels 2))
(in-suite gr8s)
(in-suite patch)
(test patch-api-requires-upgrade-authority-and-persists-plans
  (call-with-patch-fixture
   (lambda (manager image directory)
     (let* ((store (open-store (merge-pathnames "cluster/" directory)))
            (state (gr8s.patch::new-cluster-state))
            (peer (gr8s.patch::object "id" "worker-a" "local" t))
            (domains gr8s.patch::*domains*)
            (coordinator (gr8s.patch:make-coordinator
                          :manager manager :leader-p (constantly t)
                          :read-state (lambda () (gr8s.server::patch-store-state store))
                          :update-state (lambda (fn) (gr8s.server::update-patch-store-state store fn))
                          :participants (lambda () (list peer))
                          :call (lambda (p c) (declare (ignore p))
                                  (let ((gr8s.patch::*domains* domains)) (gr8s.patch:handle-command manager c)))))
            (old-coordinator gr8s.server::*patch-coordinator*)
            (old-token gr8s.server::*patch-admin-token*)
            (server nil))
       (declare (ignore state))
       (unwind-protect
            (progn
              (setf gr8s.server::*patch-coordinator* coordinator gr8s.server::*patch-admin-token* "fixture-token"
                    server (start-server :store store :port 0))
              (let ((url (format nil "http://127.0.0.1:~D/apis/gr8s.io/v1/patchrollouts" (hunchentoot:acceptor-port server)))
                    (body (com.inuoe.jzon:stringify (gr8s.patch::object "action" "plan" "image" (namestring image) "soakSeconds" 0))))
                (multiple-value-bind (reply status) (drakma:http-request url :method :post :content-type "application/json" :content body)
                  (declare (ignore reply)) (is (= 401 status)))
                (multiple-value-bind (reply status)
                    (drakma:http-request url :method :post :content-type "application/json" :content body
                                            :additional-headers '(("Authorization" . "Bearer fixture-token")))
                  (is (= 200 status) "~A" reply)
                  (let* ((plan (com.inuoe.jzon:parse reply)) (id (gethash "id" plan)))
                    (is (stringp id))
                    (is (equal "planned" (gethash "state" (gr8s.patch::plan-state coordinator id))))
                    (let ((options (list :server (format nil "http://127.0.0.1:~D" (hunchentoot:acceptor-port server))
                                         :token "fixture-token")))
                      (is (equal id (gethash "id" (gr8s.patch::cli-request options (gr8s.patch::object "action" "status" "id" id))))))
                    (let ((reopened (open-store (merge-pathnames "cluster/" directory))))
                      (is (gethash id (gethash "plans" (gr8s.server::patch-store-state reopened)))))))))
         (when server (stop-server server))
         (setf gr8s.server::*patch-coordinator* old-coordinator gr8s.server::*patch-admin-token* old-token))))))
(in-suite gr8s)
(in-suite patch)
(test patch-replay-preserves-a-newer-pending-recovery-target
  (call-with-patch-fixture
   (lambda (manager image directory)
     (declare (ignore directory))
     (let* ((artifact (gr8s.patch:inspect-artifact manager image))
            (hash (gethash "digest" artifact)) (state (gr8s.patch::manager-state manager))
            (original (symbol-function 'gr8s.patch::load-level)))
       (gr8s.patch::apply-level manager hash 1 "accepted-one" (gr8s.patch::manager-boot-id manager))
       (setf (gethash "pending" state) (gr8s.patch::object "artifact" hash "level" 2 "attempt" "pending-two"))
       (gr8s.patch::save-state manager)
       (unwind-protect
            (progn
              (setf (symbol-function 'gr8s.patch::load-level)
                    (lambda (&rest arguments)
                      (apply original arguments)
                      (error "Injected interruption while replaying an older accepted definition")))
              (signals error (gr8s.patch:recover-manager manager))
              (let ((journal (gr8s.patch::read-json (gr8s.patch::path manager "journal.json"))))
                (is (= 2 (gethash "level" (gethash "pending" journal))))
                (is (equal "pending-two" (gethash "attempt" (gethash "pending" journal))))))
         (setf (symbol-function 'gr8s.patch::load-level) original)))) :levels 2))
(test patch-attempt-id-cannot-be-reused-for-a-different-level
  (call-with-patch-fixture
   (lambda (manager image directory)
     (declare (ignore directory))
     (let* ((artifact (gr8s.patch:inspect-artifact manager image)) (hash (gethash "digest" artifact))
            (boot (gr8s.patch::manager-boot-id manager)))
       (gr8s.patch::apply-level manager hash 1 "same-id" boot)
       (signals error (gr8s.patch::apply-level manager hash 2 "same-id" boot)))) :levels 2))
(test patch-build-mismatch-is-rejected
  (call-with-patch-fixture
   (lambda (manager image directory)
     (declare (ignore directory))
     (let ((gr8s.patch:*build-id* "sha256:other-build"))
       (signals error (gr8s.patch:inspect-artifact manager image)))
     (is (= 0 (patch-fixture-value))))))
(in-suite gr8s)
(in-suite patch)
(test patch-worker-management-operation-uses-structured-protocol
  (call-with-patch-fixture
   (lambda (manager image directory)
     (declare (ignore image directory))
     (let* ((bt:*default-special-bindings*
              (acons 'gr8s.patch:*manager* (list 'quote manager) bt:*default-special-bindings*))
            (replies nil)
            (request (make-instance 'gr8s.node.v1::operation-request
                                    :operation-id "inventory"
                                    :kind gr8s.node.v1::+operationkind-operation_kind_patch+
                                    :patch-command-json (gr8s.patch::octets "{\"action\":\"inventory\"}")))
            (thread (gr8s.patch::start-node-patch-operation
                     request (lambda (kind message) (push (cons kind message) replies)))))
       (bt:join-thread thread)
       (let ((response (cdr (assoc :operation-response replies)))
             (stream (cdr (assoc :operation-stream replies))))
         (is (= 0 (gr8s.node.v1::exit-code response)))
         (is (= gr8s.node.v1::+operationstatus-operation_status_complete+ (gr8s.node.v1::status response)))
         (is (equal "worker-a" (gethash "name" (com.inuoe.jzon:parse
                                                    (gr8s.patch::text (gr8s.node.v1::data stream)))))))))))
(test patch-coordinator-recovers-a-lost-ack-without-repeating-migration
  (let ((*patch-migration-count* 0))
    (call-with-patch-fixture
     (lambda (manager image directory)
       (declare (ignore directory))
       (let* ((state (gr8s.patch::new-cluster-state)) (calls 0)
              (peer (gr8s.patch::object "id" "worker-a"))
              (coordinator (gr8s.patch:make-coordinator
                            :manager manager :leader-p (constantly t) :participants (lambda () (list peer))
                            :read-state (lambda () (gr8s.patch::copy-json state))
                            :update-state (lambda (fn) (setf state (funcall fn (gr8s.patch::copy-json state))))
                            :call (lambda (p c)
                                    (declare (ignore p))
                                    (let ((result (gr8s.patch:handle-command manager c)))
                                      (when (equal "apply" (gethash "action" c))
                                        (when (= 1 (incf calls)) (error "Injected lost response after durable apply"))) result))))
              (plan (gr8s.patch::patch-plan coordinator image 1 0)) (id (gethash "id" plan)))
         (gr8s.patch::control-plan coordinator id "apply")
         (loop repeat 10 until (equal "paused" (gethash "state" (gr8s.patch::plan-state coordinator id)))
               do (gr8s.patch:coordinator-tick coordinator))
         (is (equal "paused" (gethash "state" (gr8s.patch::plan-state coordinator id))))
         (is (= 1 *patch-migration-count*))
         (is (hash-table-p (gethash "grant" (gr8s.patch::plan-state coordinator id))))
         (gr8s.patch::control-plan coordinator id "resume")
         (dotimes (i 12) (gr8s.patch:coordinator-tick coordinator))
         (is (equal "complete" (gethash "state" (gr8s.patch::plan-state coordinator id))))
         (is (= 1 *patch-migration-count*)))))))
(in-suite gr8s)
(in-suite patch)
(test patch-offline-target-reconstructs-the-ordered-prefix-on-bootstrap
  (let ((*patch-migration-count* 0))
    (call-with-patch-fixture
     (lambda (manager image directory)
       (declare (ignore directory))
       (let ((artifact (gr8s.patch:inspect-artifact manager image)))
         (setf (gethash "bootstrapTarget" (gr8s.patch::manager-state manager))
               (gr8s.patch::object "digest" (gethash "digest" artifact) "level" 2))
         (gr8s.patch::save-state manager)
         (is (= 0 (patch-fixture-value)))
         (gr8s.patch:recover-manager manager)
         (is (= 2 (patch-fixture-value)))
         (is (= 2 *patch-migration-count*))
         (is (= 2 (gr8s.patch::manager-loaded-level manager)))
         (is-false (gethash "bootstrapTarget" (gr8s.patch::manager-state manager)))) ) :levels 2)))
(test patch-admission-checks-the-committed-prefix
  (call-with-patch-fixture
   (lambda (manager image directory)
     (let* ((artifact (gr8s.patch:inspect-artifact manager image))
            (level (aref (gethash "levels" (gethash "index" artifact)) 0))
            (store (open-store (merge-pathnames "admission/" directory))))
       (gr8s.server::update-patch-store-state
        store (lambda (state) (setf (gethash "policyLevel" state) 1
                                   (gethash "policyChain" state) (gethash "chain" level)) state))
       (flet ((report () (gr8s.patch::octets (com.inuoe.jzon:stringify (gr8s.patch:inventory manager)))))
         (signals error (gr8s.server::validate-patch-admission store (report)))
         (gr8s.patch::apply-level manager (gethash "digest" artifact) 1 "admitted" (gr8s.patch::manager-boot-id manager))
         (is-true (gr8s.server::validate-patch-admission store (report))))))))
(test patch-watch-retries-a-transient-coordinator-connection-failure
  (let ((original (symbol-function 'gr8s.patch::cli-request)) (calls 0))
    (unwind-protect
         (progn
           (setf (symbol-function 'gr8s.patch::cli-request)
                 (lambda (options command)
                   (declare (ignore options command))
                   (when (= 1 (incf calls)) (error "Injected leadership handoff"))
                   (gr8s.patch::object "state" "running")))
           (is (equal "running" (gethash "state" (gr8s.patch::poll-status nil "test"))))
           (is (= 2 calls)))
      (setf (symbol-function 'gr8s.patch::cli-request) original))))
(in-suite gr8s)
(in-suite patch)
(test patch-rollout-records-are-private-consensus-state
  (is-false (assoc "patchrollouts" gr8s::*stored-resource-types* :test #'equal))
  (is-true (assoc "patchrollouts" gr8s.resources::*internal-stored-resource-types* :test #'equal))
  (is-true (gr8s.ha:raft-consensus-resource-p "patchrollouts")))
(in-suite gr8s)
(in-suite patch)
(test patch-free-state-does-not-obstruct-normal-binary-upgrades
  (call-with-patch-fixture
   (lambda (manager image directory)
     (declare (ignore image))
     (gr8s.patch::save-state manager)
     (gr8s.patch:close-manager manager)
     (let* ((gr8s.patch:*build-id* (gr8s.patch::digest (gr8s.patch::octets "new-unpatched-base")))
            (next (gr8s.patch:open-manager directory "worker-a" '("worker"))))
       (unwind-protect
            (progn
              (is (= 0 (gethash "level" (gr8s.patch::manager-state next))))
              (is (equal gr8s.patch:*build-id* (gethash "buildID" (gr8s.patch::manager-state next)))))
         (gr8s.patch:close-manager next))))))
(test patch-applied-state-refuses-an-unproven-base-build
  (call-with-patch-fixture
   (lambda (manager image directory)
     (let ((artifact (gr8s.patch:inspect-artifact manager image)))
       (gr8s.patch::apply-level manager (gethash "digest" artifact) 1 "base-test" (gr8s.patch::manager-boot-id manager)))
     (gr8s.patch:close-manager manager)
     (let ((gr8s.patch:*build-id* (gr8s.patch::digest (gr8s.patch::octets "unproven-new-base"))))
       (signals error (gr8s.patch:open-manager directory "worker-a" '("worker")))))))
(in-suite patch)

(test patch-unrestricted-redefinition-and-replay-without-domains
  (let ((*patch-migration-count* 0))
    (call-with-patch-fixture
     (lambda (manager image directory)
       ;; No registered boundary or replacement allowlist is needed.
       (clrhash gr8s.patch::*domains*)
       (let* ((artifact (gr8s.patch:inspect-artifact manager image))
              (level (aref (gethash "levels" (gethash "index" artifact)) 0))
              (pid (sb-posix:getpid)))
         (is (null (gr8s.patch::level-domains manager level)))
         (gr8s.patch::apply-level manager (gethash "digest" artifact) 1 "free" (gr8s.patch::manager-boot-id manager))
         (is (= 1 (patch-fixture-value)))
         (is (= pid (sb-posix:getpid)))
         (is (= 1 *patch-migration-count*))
         (gr8s.patch:close-manager manager)
         (setf (symbol-function 'patch-fixture-value) (lambda () 0))
         (let ((restarted (gr8s.patch:open-manager directory "worker-a" '("worker"))))
           (unwind-protect
                (progn (gr8s.patch:recover-manager restarted)
                       (is (= 1 (patch-fixture-value)))
                       (is (= 1 *patch-migration-count*)))
             (gr8s.patch:close-manager restarted)))))
     :domains #() :replaces #("DESCRIPTIVE::UNREGISTERED-SYMBOL")) ))
(test patch-optional-domain-does-not-restrict-redefinitions
  (call-with-patch-fixture
   (lambda (manager image directory)
     (declare (ignore directory))
     (let* ((artifact (gr8s.patch:inspect-artifact manager image))
            (level (aref (gethash "levels" (gethash "index" artifact)) 0)))
       (is (= 1 (length (gr8s.patch::level-domains manager level))))
       (gr8s.patch::apply-level manager (gethash "digest" artifact) 1 "metadata" (gr8s.patch::manager-boot-id manager))
       (is (= 1 (patch-fixture-value)))) )
   :replaces #("DESCRIPTIVE::UNREGISTERED-SYMBOL")))
(test patch-explicit-unknown-domain-is-rejected
  (call-with-patch-fixture
   (lambda (manager image directory)
     (declare (ignore directory))
     (let ((artifact (gr8s.patch:inspect-artifact manager image)))
       (signals error (gr8s.patch::validate-prefix manager artifact 1))
       (is (= 0 (patch-fixture-value)))))
   :domains #("unknown")))

(defclass patch-arbitrary-object () ((value :initform 0 :accessor patch-arbitrary-value)))
(defgeneric patch-arbitrary-method (object))
(defmethod patch-arbitrary-method ((object patch-arbitrary-object))
  (patch-arbitrary-value object))
(defvar *patch-arbitrary-object* (make-instance 'patch-arbitrary-object))
(test patch-method-class-and-live-data-with-omitted-metadata
  (unwind-protect
       (call-with-patch-fixture
        (lambda (manager image directory)
          (declare (ignore directory))
          (clrhash gr8s.patch::*domains*)
          (let* ((artifact (gr8s.patch:inspect-artifact manager image))
                 (level (aref (gethash "levels" (gethash "index" artifact)) 0)))
            (is (not (nth-value 1 (gethash "domains" level))))
            (is (not (nth-value 1 (gethash "replaces" level))))
            (gr8s.patch::apply-level manager (gethash "digest" artifact) 1 "objects" (gr8s.patch::manager-boot-id manager))
            (is (= 42 (patch-arbitrary-method *patch-arbitrary-object*)))
            (is (= 7 (slot-value *patch-arbitrary-object* 'extra)))))
        :domains nil :replaces nil
        :extra-source "
(defclass patch-arbitrary-object ()
 ((value :initform 0 :accessor patch-arbitrary-value) (extra :initform 7)))
(setf (patch-arbitrary-value *patch-arbitrary-object*) 41)
(defmethod patch-arbitrary-method ((object patch-arbitrary-object))
 (1+ (patch-arbitrary-value object)))
")
    (setf (patch-arbitrary-value *patch-arbitrary-object*) 0)
    (defmethod patch-arbitrary-method ((object patch-arbitrary-object))
      (patch-arbitrary-value object))
    (eval '(defclass patch-arbitrary-object ()
             ((value :initform 0 :accessor patch-arbitrary-value))))))

(in-suite gr8s)
