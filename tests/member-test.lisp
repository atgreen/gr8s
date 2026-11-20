;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; `gr8s member` and its API surface (podster-9x6): the membership summary a
;;;; control plane serves at /apis/gr8s.io/v1/controlplanemembers, the
;;;; ControlPlaneMember JSON objects, and the CLI that renders them -- a voter
;;;; never heard from is a ghost, and the list must say so.

(in-package #:gr8s/tests)
(def-suite control-plane-members :in gr8s)
(in-suite control-plane-members)

(defun make-membership-test-hcp ()
  "A member view of a three-voter cluster: self (a, leader), b in contact,
   c never heard from -- a ghost."
  (let* ((node (cl-raft::make-raft-node :id "a" :send-fn (lambda (&rest args) (declare (ignore args)))))
         (member (gr8s.raft.transport::make-raft-member :node node)))
    (gr8s.raft::raft-configure node '(("a" . :voter) ("b" . :voter) ("c" . :voter)))
    (setf (gr8s.raft:raft-node-leader-id node) "a"
          (gethash "a" (gr8s.raft:raft-node-peer-addresses node)) '("10.0.0.1" 7000)
          (gethash "b" (gr8s.raft:raft-node-peer-addresses node)) '("10.0.0.2" 7000)
          (gethash "c" (gr8s.raft:raft-node-peer-addresses node)) '("10.0.0.3" 7000)
          (gethash "a" (gr8s.raft:raft-node-api-urls node)) "https://10.0.0.1:6443")
    (let ((link (gr8s.raft.transport::make-raft-peer-link :id "b")))
      (setf (gr8s.raft.transport::raft-peer-link-received-messages link) 5
            (gethash "b" (gr8s.raft.transport::raft-member-links member)) link))
    (gr8s.ha::make-ha-control-plane :member member :store nil)))

(test ha-membership-reports-roles-addresses-and-contact
  (let* ((membership (gr8s.ha:ha-control-plane-membership (make-membership-test-hcp)))
         (members (getf membership :members)))
    (is (equal "a" (getf membership :self)))
    (is (equal "a" (getf membership :leader)))
    (is (equal '("a" "b" "c") (mapcar (lambda (m) (getf m :id)) members))
        "members are sorted by id")
    (let ((a (first members)) (b (second members)) (c (third members)))
      (is (eq :self (getf a :contact)))
      (is (eq t (getf a :leader)))
      (is (equal "https://10.0.0.1:6443" (getf a :api-url)))
      (is (eq :in-contact (getf b :contact)))
      (is (null (getf b :leader)))
      (is (eq :never-heard (getf c :contact))
          "a configured voter with no delivered messages is a ghost")
      (is (equal '("10.0.0.3" 7000) (getf c :address))))))

(test control-plane-member-object-shape
  (let* ((object (gr8s.apiserver::control-plane-member-object
                  '(:id "b" :role :voter :address ("10.0.0.2" 7000)
                    :api-url "https://10.0.0.2:6443" :leader t :contact :in-contact)))
         (spec (gethash "spec" object))
         (status (gethash "status" object)))
    (is (equal "ControlPlaneMember" (gethash "kind" object)))
    (is (equal "b" (gethash "name" (gethash "metadata" object))))
    (is (equal "voter" (gethash "role" spec)))
    (is (equal "10.0.0.2:7000" (gethash "address" spec)))
    (is (equal "https://10.0.0.2:6443" (gethash "apiURL" spec)))
    (is (eq t (gethash "leader" status)))
    (is (equal "in-contact" (gethash "contact" status))))
  (let* ((object (gr8s.apiserver::control-plane-member-object
                  '(:id "c" :role :voter :address nil :api-url nil :leader nil :contact :never-heard)))
         (spec (gethash "spec" object))
         (status (gethash "status" object)))
    (is (null (gethash "address" spec)) "an unknown address is simply absent")
    (is (null (gethash "leader" status)))
    (is (equal "never-heard" (gethash "contact" status)))))

(test ha-remove-member-reports-propose-outcome
  (let ((hcp (make-membership-test-hcp)))
    ;; The constructed node is configured but never elected: not the leader.
    (multiple-value-bind (proposed reason) (gr8s.ha:ha-control-plane-remove-member hcp "c")
      (is (null proposed))
      (is (eq :not-leader reason)))))

(test member-cli-parses-list-and-remove
  (let ((options (gr8s.server::parse-member-options nil)))
    (is (eq :member-list (getf options :command))))
  (let ((options (gr8s.server::parse-member-options '("list" "--output" "json"))))
    (is (eq :member-list (getf options :command)))
    (is (equal "json" (getf options :output))))
  (let ((options (gr8s.server::parse-member-options '("remove" "gr8s2"))))
    (is (eq :member-remove (getf options :command)))
    (is (equal "gr8s2" (getf options :name))))
  (let ((options (gr8s.server::parse-member-options '("transfer-leadership" "gr8s2" "--output" "json"))))
    (is (eq :member-transfer-leadership (getf options :command)))
    (is (equal "gr8s2" (getf options :name)))
    (is (equal "json" (getf options :output))))
  (signals error (gr8s.server::parse-member-options '("transfer-leadership")))
  (signals error (gr8s.server::parse-member-options '("remove")))
  (signals error (gr8s.server::parse-member-options '("remove" "--output" "json")))
  (signals error (gr8s.server::parse-member-options '("destroy" "x")))
  (signals error (gr8s.server::parse-member-options '("list" "--output" "yaml"))))

(test member-list-renders-ghosts-and-exit-code
  (let ((request-original (symbol-function 'gr8s.server::debug-api-request-json))
        (kubeconfig-original (symbol-function 'gr8s.server::read-debug-kubeconfig)))
    (unwind-protect
         (progn
           (setf (symbol-function 'gr8s.server::read-debug-kubeconfig)
                 (lambda (path) (declare (ignore path)) (list :server "https://127.0.0.1:6443"))
                 (symbol-function 'gr8s.server::debug-api-request-json)
                 (lambda (config method target)
                   (declare (ignore config))
                   (is (equal "GET" method))
                   (is (equal "/apis/gr8s.io/v1/controlplanemembers" target))
                   (values (com.inuoe.jzon:parse
                            "{\"kind\":\"ControlPlaneMemberList\",\"leader\":\"a\",\"items\":[
                              {\"metadata\":{\"name\":\"a\"},\"spec\":{\"role\":\"voter\",\"address\":\"10.0.0.1:7000\"},
                               \"status\":{\"contact\":\"self\",\"leader\":true}},
                              {\"metadata\":{\"name\":\"c\"},\"spec\":{\"role\":\"voter\",\"address\":\"10.0.0.3:7000\"},
                               \"status\":{\"contact\":\"never-heard\"}}]}")
                           200)))
           (let* ((output (make-string-output-stream))
                  (code (gr8s.server::run-member-list-command
                         (list :command :member-list :kubeconfig "ignored" :output "text")
                         output))
                  (text (get-output-stream-string output)))
             (is (= 1 code) "a ghost makes the listing exit 1")
             (is (search "never-heard" text))
             (is (search "yes" text) "the leader row is marked")
             (is (search "--cluster-reset" text)
                 "the ghost warning points at the escape hatches")))
      (setf (symbol-function 'gr8s.server::debug-api-request-json) request-original
            (symbol-function 'gr8s.server::read-debug-kubeconfig) kubeconfig-original))))

;;; podster-7jb: gr8s kubeconfig emits inline certificate-authority-data /
;;; client-certificate-data, but the debug TLS client only takes file paths --
;;; so gr8s status/member failed UNKNOWN-CA against gr8s's own kubeconfigs.
;;; The shared wrapper materializes inline data into private temporary files
;;; for the duration of the call and removes them afterwards.

(test debug-kubeconfig-materializes-inline-certificate-data
  (let* ((root (uiop:ensure-directory-pathname
                (sb-posix:mkdtemp
                 (namestring (merge-pathnames "gr8s-kubeconfig-XXXXXX" (uiop:temporary-directory))))))
         (path (merge-pathnames "config" root))
         (encode (lambda (text) (ag-grpc:base64-encode (babel:string-to-octets text :encoding :utf-8)))))
    (unwind-protect
         (progn
           (with-open-file (out path :direction :output)
             (format out "apiVersion: v1~%current-context: gr8s~%clusters:~%- name: gr8s~%  cluster:~%    server: https://127.0.0.1:6443~%    certificate-authority-data: ~A~%contexts:~%- name: gr8s~%  context:~%    cluster: gr8s~%    user: admin~%users:~%- name: admin~%  user:~%    client-certificate-data: ~A~%    client-key-data: ~A~%"
                     (funcall encode "CA-PEM") (funcall encode "CERT-PEM") (funcall encode "KEY-PEM")))
           (let ((files nil))
             (gr8s.server::call-with-debug-kubeconfig
              path
              (lambda (config)
                (setf files (list (getf config :ca-file)
                                  (getf config :client-certificate)
                                  (getf config :client-key)))
                (is (every (lambda (file) (and file (probe-file file))) files)
                    "inline data is materialized into files for the TLS client")
                (is (equal "CA-PEM" (uiop:read-file-string (getf config :ca-file))))
                (is (equal "KEY-PEM" (uiop:read-file-string (getf config :client-key))))
                (is (equal "https://127.0.0.1:6443" (getf config :server)))))
             (is (notany (lambda (file) (and file (probe-file file))) files)
                 "the temporary credential files are removed on the way out")))
      (uiop:delete-directory-tree root :validate t :if-does-not-exist :ignore))))

(test debug-kubeconfig-passes-file-credentials-through
  (let* ((root (uiop:ensure-directory-pathname
                (sb-posix:mkdtemp
                 (namestring (merge-pathnames "gr8s-kubeconfig-XXXXXX" (uiop:temporary-directory))))))
         (path (merge-pathnames "config" root)))
    (unwind-protect
         (progn
           (with-open-file (out path :direction :output)
             (format out "apiVersion: v1~%current-context: gr8s~%clusters:~%- name: gr8s~%  cluster:~%    server: https://127.0.0.1:6443~%    certificate-authority: ca.crt~%contexts:~%- name: gr8s~%  context:~%    cluster: gr8s~%    user: admin~%users:~%- name: admin~%  user:~%    token: abc~%"))
           (gr8s.server::call-with-debug-kubeconfig
            path
            (lambda (config)
              (is (uiop:string-suffix-p (getf config :ca-file) "ca.crt")
                  "file paths resolve relative to the kubeconfig and pass through")
              (is (equal "abc" (getf config :token))))))
      (uiop:delete-directory-tree root :validate t :if-does-not-exist :ignore))))
;;; podster-84o: followers rarely message each other, so a follower's view
;;; presented every healthy peer as "never-heard" -- a false ghost. Contact is
;;; now :unknown unless this member is the leader, and the CLI says where to
;;; look instead of crying ghost.

(test follower-view-reports-contact-as-unknown
  (let* ((node (cl-raft::make-raft-node :id "b" :send-fn (lambda (&rest args) (declare (ignore args)))))
         (member (gr8s.raft.transport::make-raft-member :node node))
         (hcp (gr8s.ha::make-ha-control-plane :member member :store nil)))
    (gr8s.raft::raft-configure node '(("a" . :voter) ("b" . :voter) ("c" . :voter)))
    (setf (gr8s.raft:raft-node-leader-id node) "a")
    (let* ((membership (gr8s.ha:ha-control-plane-membership hcp))
           (members (getf membership :members)))
      (is (equal '(:unknown :self :unknown)
                 (mapcar (lambda (m) (getf m :contact)) members))
          "a follower reports peers as unknown, never as ghosts"))
    (is (equal "unknown"
               (gethash "contact"
                        (gethash "status"
                                 (gr8s.apiserver::control-plane-member-object
                                  '(:id "c" :role :voter :address nil :api-url nil
                                    :leader nil :contact :unknown))))))))

(test member-list-does-not-cry-ghost-from-a-follower
  (let ((request-original (symbol-function 'gr8s.server::debug-api-request-json))
        (kubeconfig-original (symbol-function 'gr8s.server::read-debug-kubeconfig)))
    (unwind-protect
         (progn
           (setf (symbol-function 'gr8s.server::read-debug-kubeconfig)
                 (lambda (path) (declare (ignore path)) (list :server "https://127.0.0.1:6443"))
                 (symbol-function 'gr8s.server::debug-api-request-json)
                 (lambda (config method target)
                   (declare (ignore config method target))
                   (values (com.inuoe.jzon:parse
                            "{\"kind\":\"ControlPlaneMemberList\",\"leader\":\"a\",\"items\":[
                              {\"metadata\":{\"name\":\"a\"},\"spec\":{\"role\":\"voter\"},\"status\":{\"contact\":\"unknown\",\"leader\":true}},
                              {\"metadata\":{\"name\":\"b\"},\"spec\":{\"role\":\"voter\"},\"status\":{\"contact\":\"self\"}}]}")
                           200)))
           (let* ((output (make-string-output-stream))
                  (code (gr8s.server::run-member-list-command
                         (list :command :member-list :kubeconfig "ignored" :output "text")
                         output))
                  (text (get-output-stream-string output)))
             (is (zerop code) "unknown contact is not a ghost")
             (is (search "visible only from the leader (a)" text))
             (is (not (search "never heard from" text)))))
      (setf (symbol-function 'gr8s.server::debug-api-request-json) request-original
            (symbol-function 'gr8s.server::read-debug-kubeconfig) kubeconfig-original))))

;;; podster-f9u: `gr8s member transfer-leadership NAME` has the leader hand its
;;; leadership to a voter, so that the leader can be restarted without the
;;; cluster waiting out an election.

(defun call-with-three-control-planes (function)
  "Call FUNCTION with three members of one control plane, the first of them leading."
  (with-temporary-store (s1 p1)
    (with-temporary-store (s2 p2)
      (with-temporary-store (s3 p3)
        (declare (ignore p1 p2 p3))
        (let ((h1 nil) (h2 nil) (h3 nil))
          (unwind-protect
               (progn
                 (setf h1 (gr8s.ha::start-ha-control-plane s1 :id "cp1" :init t))
                 (is (poll-until (lambda () (gr8s.ha::ha-control-plane-leader-p h1))))
                 (let ((port (gr8s.raft.transport::raft-member-port (gr8s.ha::ha-control-plane-member h1))))
                   (setf h2 (gr8s.ha::start-ha-control-plane s2 :id "cp2" :join-host "127.0.0.1" :join-port port))
                   (setf h3 (gr8s.ha::start-ha-control-plane s3 :id "cp3" :join-host "127.0.0.1" :join-port port)))
                 (is (poll-until
                      (lambda ()
                        (equal '(:voter :voter :voter)
                               (mapcar (lambda (entry) (getf entry :role))
                                       (getf (gr8s.ha:ha-control-plane-membership h1) :members))))
                      :timeout 20)
                     "both joiners become voters")
                 (funcall function h1 h2 h3))
            (dolist (h (list h1 h2 h3)) (when h (ignore-errors (gr8s.ha::stop-ha-control-plane h))))))))))

(defun transfer-leadership-outcome (hcp id &rest arguments)
  (multiple-value-list (apply #'gr8s.ha:ha-control-plane-transfer-leadership hcp id arguments)))

(test the-leader-hands-its-leadership-to-the-voter-it-is-asked-to
  (call-with-three-control-planes
   (lambda (h1 h2 h3)
     (is (equal '(nil :not-leader) (transfer-leadership-outcome h2 "cp3"))
         "only the leader can hand the leadership over")
     (is (equal '(nil :self) (transfer-leadership-outcome h1 "cp1")))
     (is (equal '(nil :not-voter) (transfer-leadership-outcome h1 "nobody")))
     (is (gr8s.ha::ha-control-plane-leader-p h1) "a refusal changes nothing")
     (is (equal '(t nil) (transfer-leadership-outcome h1 "cp2")))
     (is (poll-until (lambda () (gr8s.ha::ha-control-plane-leader-p h2)) :timeout 5)
         "the member named leads, well inside an election timeout's wait")
     (is (poll-until (lambda ()
                       (every (lambda (h) (equal "cp2" (getf (gr8s.ha:ha-control-plane-membership h) :leader)))
                              (list h1 h2 h3)))
                     :timeout 5)
         "and every member knows it")
     (is-false (gr8s.ha::ha-control-plane-leader-p h1))
     ;; The cluster takes writes under its new leader, from any member.
     (gr8s.resources::create-core-resource (gr8s.ha:ha-control-plane-store h1) "configmaps"
                                           (configmap-input "after-handover" "k" "v") "default")
     (is (poll-until (lambda ()
                       (every (lambda (h) (equal "v" (configmap-value (gr8s.ha:ha-control-plane-store h)
                                                                      "after-handover" "k")))
                              (list h1 h2 h3)))
                     :timeout 10)))))

(test the-leader-keeps-its-leadership-from-a-voter-it-cannot-hear
  (call-with-three-control-planes
   (lambda (h1 h2 h3)
     (declare (ignore h2))
     (gr8s.ha::stop-ha-control-plane h3)
     (sleep 1.5)
     (is (equal '(nil :out-of-contact) (transfer-leadership-outcome h1 "cp3" :silence-seconds 1))
         "a stopped voter could not take over, and waiting for it would hold writes up")
     (is (gr8s.ha::ha-control-plane-leader-p h1))
     (gr8s.resources::create-core-resource (gr8s.ha:ha-control-plane-store h1) "configmaps"
                                           (configmap-input "still-writable" "k" "v") "default")
     (is (equal "v" (configmap-value (gr8s.ha:ha-control-plane-store h1) "still-writable" "k"))))))

(defun call-with-stubbed-member-api (answer function)
  "Call FUNCTION while the member commands' API requests are answered by ANSWER,
a function of the method and the target that returns a body, a status and headers."
  (let ((request-original (symbol-function 'gr8s.server::debug-api-request-json))
        (kubeconfig-original (symbol-function 'gr8s.server::read-debug-kubeconfig)))
    (unwind-protect
         (progn
           (setf (symbol-function 'gr8s.server::read-debug-kubeconfig)
                 (lambda (path) (declare (ignore path)) (list :server "https://127.0.0.1:6443"))
                 (symbol-function 'gr8s.server::debug-api-request-json)
                 (lambda (config method target) (funcall answer config method target)))
           (funcall function))
      (setf (symbol-function 'gr8s.server::debug-api-request-json) request-original
            (symbol-function 'gr8s.server::read-debug-kubeconfig) kubeconfig-original))))

(defun run-transfer-leadership-command (name)
  "Run `gr8s member transfer-leadership NAME`; return its exit code and what it printed."
  (let* ((output (make-string-output-stream))
         (code (gr8s.server::run-member-transfer-leadership-command
                (list :command :member-transfer-leadership :kubeconfig "ignored" :output "text" :name name)
                output)))
    (values code (get-output-stream-string output))))

(defun member-test-status (message)
  (com.inuoe.jzon:parse (com.inuoe.jzon:stringify (gr8s.resources::core-object "kind" "Status" "message" message))))

(test transfer-leadership-waits-until-the-member-leads
  (let ((leaders (list "a" "a" "b")) (requests nil))
    (call-with-stubbed-member-api
     (lambda (config method target)
       (declare (ignore config))
       (push (list method target) requests)
       (if (equal method "POST")
           (values (member-test-status "handing over") 202)
           (values (com.inuoe.jzon:parse (format nil "{\"leader\":\"~A\",\"items\":[]}" (pop leaders))) 200)))
     (lambda ()
       (multiple-value-bind (code text) (run-transfer-leadership-command "b")
         (is (= 0 code))
         (is (search "b now leads" text)))))
    (is (equal '("POST" "/apis/gr8s.io/v1/controlplanemembers/b/leadership") (first (last requests))))
    (is (= 4 (length requests)) "it asked who leads until the answer was b")))

(test transfer-leadership-fails-when-the-member-does-not-come-to-lead
  (let ((gr8s.server::*member-leadership-wait-seconds* 0.5))
    (call-with-stubbed-member-api
     (lambda (config method target)
       (declare (ignore config target))
       (if (equal method "POST")
           (values (member-test-status "handing over") 202)
           (values (com.inuoe.jzon:parse "{\"leader\":\"a\",\"items\":[]}") 200)))
     (lambda ()
       (handler-case (progn (run-transfer-leadership-command "b") (fail "the command reported success"))
         (error (condition)
           (is (search "did not take the leadership" (princ-to-string condition)))
           (is (search "a leads" (princ-to-string condition)))))))))

(test transfer-leadership-to-the-leader-is-already-done
  (let ((requests 0))
    (call-with-stubbed-member-api
     (lambda (config method target)
       (declare (ignore config method target))
       (incf requests)
       (values (member-test-status "a already leads") 200))
     (lambda ()
       (multiple-value-bind (code text) (run-transfer-leadership-command "a")
         (is (= 0 code))
         (is (search "a already leads" text)))))
    (is (= 1 requests) "there is nothing to wait for")))

(test transfer-leadership-reports-why-it-was-refused
  (call-with-stubbed-member-api
   (lambda (config method target)
     (declare (ignore config method target))
     (values (member-test-status "control-plane member w is a witness; only a voter can lead") 409))
   (lambda ()
     (handler-case (progn (run-transfer-leadership-command "w") (fail "the command reported success"))
       (error (condition)
         (is (search "only a voter can lead" (princ-to-string condition))))))))

(test a-member-command-follows-one-redirect-to-the-leader
  (let ((servers nil))
    (call-with-stubbed-member-api
     (lambda (config method target)
       (push (list (getf config :server) method target) servers)
       (cond ((equal method "GET")
              (values (com.inuoe.jzon:parse "{\"leader\":\"b\",\"items\":[]}") 200))
             ((equal (getf config :server) "https://127.0.0.1:6443")
              (values nil 307 '((:location . "https://10.0.0.9:6443/apis/gr8s.io/v1/controlplanemembers/b/leadership"))))
             (t (values (member-test-status "handing over") 202))))
     (lambda ()
       (is (= 0 (run-transfer-leadership-command "b")))))
    (is (find '("https://10.0.0.9:6443/apis/gr8s.io/v1/controlplanemembers/b/leadership" "POST" "")
              servers :test #'equal)
        "the request is sent again to where the follower pointed")))
