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
