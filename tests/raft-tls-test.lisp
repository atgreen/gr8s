;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Verify Raft members really replicate over mutual TLS, and that everything
;;;; else is turned away: plain connections, no certificate, a worker's certificate
;;;; or token, a reused token, a wrong CA pin and a member posing as another.

(in-package #:gr8s/tests)
(def-suite raft-tls :in gr8s)
(in-suite raft-tls)

(defun raft-tls-test-pki (path)
  (gr8s.security::ensure-cluster-pki (merge-pathnames "pki/" (uiop:ensure-directory-pathname path))))

(defun member-raft-pki (control-plane)
  (gr8s.security::raft-credentials-pki (gr8s.raft.transport::raft-member-credentials (gr8s.ha::ha-control-plane-member control-plane))))

(defun control-plane-port (control-plane)
  (gr8s.raft.transport::raft-member-port (gr8s.ha::ha-control-plane-member control-plane)))

(defun control-plane-term (control-plane)
  (cl-raft::raft-node-current-term (gr8s.raft.transport::raft-member-node (gr8s.ha::ha-control-plane-member control-plane))))

(defmacro with-founded-cluster ((founder &optional (pki (gensym "PKI"))) &body body)
  "Run BODY with FOUNDER leading a one-member mutual TLS cluster, and PKI its node PKI."
  (let ((store (gensym "STORE")) (path (gensym "PATH")))
    `(with-temporary-store (,store ,path)
       (let* ((,pki (raft-tls-test-pki ,path))
              (,founder (gr8s.ha::start-ha-control-plane ,store :id "cp1" :init t :pki ,pki)))
         (declare (ignorable ,pki))
         (unwind-protect
              (progn (is (poll-until (lambda () (gr8s.ha::ha-control-plane-leader-p ,founder))))
                     ,@body)
           (gr8s.ha::stop-ha-control-plane ,founder))))))

(defun join-control-plane (founder store path id &key (node-name id)
                                                   (token (gr8s.security::create-join-token
                                                           (member-raft-pki founder) node-name :role :voter))
                                                   (ca-pin (gr8s.security::cluster-pki-ca-fingerprint (member-raft-pki founder))))
  (let ((pki (gr8s.security::ensure-joining-control-plane-pki
              (merge-pathnames "pki/" (uiop:ensure-directory-pathname path)) id
              "127.0.0.1" (control-plane-port founder) :node-name node-name :token token :ca-pin ca-pin)))
    (gr8s.ha::start-ha-control-plane store :id id :join-host "127.0.0.1" :join-port (control-plane-port founder)
                                        :node-name node-name :pki pki)))

(defun rejected-p (function)
  "Return true if calling FUNCTION signals, including by timing out."
  (handler-case (progn (funcall function) nil)
    ((or error sb-ext:timeout) () t)))

(defun attack-message (&optional (from "attacker") (term 999))
  "Return a Deliver request that would visibly advance the receiver's term if accepted."
  (make-instance 'gr8s.node.v1::raft-envelope
                 :protocol-version 1
                 :payload (gr8s.raft.transport::raft-message->octets
                           (list :type :append-entries :term term :from from :prev-index 0 :prev-term 0
                                 :entries nil :leader-commit 0))))

(defun deliver-through (channel message)
  (unwind-protect
       (gr8s.node.v1::raft-transport-deliver (gr8s.node.v1::make-raft-transport-stub channel) message :timeout 5)
    (ignore-errors (ag-grpc:channel-close channel))))

(test members-replicate-over-mutual-tls
  (with-founded-cluster (founder)
    (with-temporary-store (store path)
      (let ((joiner (join-control-plane founder store path "cp2")))
        (unwind-protect
             (let ((root (gr8s.security::raft-tls-root (raft-tls-test-pki path)))
                   (leader (gr8s.ha::ha-control-plane-member founder))
                   (follower (gr8s.ha::ha-control-plane-member joiner)))
               (is (poll-until (lambda () (member "cp2" (cl-raft::raft-node-peers (gr8s.raft.transport::raft-member-node leader))
                                                  :test #'equal))
                               :timeout 20))
               ;; A real commit needs the joiner's acknowledgement over its own TLS link.
               (is (poll-until
                    (lambda ()
                      (= 2 (count :voter (gr8s.raft.transport::raft-cluster-members leader) :key #'cdr)))
                    :timeout 20))
               (multiple-value-bind (result committed) (gr8s.raft.transport::raft-member-propose-sync leader '(:noop) :timeout 15)
                 (declare (ignore result))
                 (is (eq t committed)))
               (is (poll-until
                    (lambda ()
                      (= (cl-raft::raft-node-commit-index (gr8s.raft.transport::raft-member-node leader))
                         (cl-raft::raft-node-commit-index (gr8s.raft.transport::raft-member-node follower))))
                    :timeout 15))
               (is (poll-until
                    (lambda () (search "gr8s_raft_peer_receive_observed{peer=\"cp2\"} 1"
                                       (gr8s.ha::ha-metrics-text founder))) :timeout 10))
               (is (poll-until
                    (lambda () (search "gr8s_raft_peer_receive_observed{peer=\"cp1\"} 1"
                                       (gr8s.ha::ha-metrics-text joiner))) :timeout 10))
               (is (= #o600 (logand #o777 (sb-posix:stat-mode
                                           (sb-posix:stat (namestring (gr8s.security::raft-ca-key-path root)))))))
               (is (equal (gr8s.security::cluster-pki-ca-fingerprint (member-raft-pki founder))
                          (gr8s.security::cluster-pki-ca-fingerprint (member-raft-pki joiner)))
                   "a voter holds the CA, so it can admit members after a failover")
               (finishes (gr8s.security::ensure-raft-joiner-credentials root "cp2" "127.0.0.1" 1))
               (is (gr8s.security::raft-credentials-pki (gr8s.security::ensure-raft-joiner-credentials root "cp2" "127.0.0.1" 1))
                   "a restarted member reuses its credentials without a new token"))
          (gr8s.ha::stop-ha-control-plane joiner))))))

(test voters-share-the-service-account-signing-key
  (with-founded-cluster (founder)
    (let* ((founder-store (gr8s.ha::ha-control-plane-store founder))
           (founder-key (gr8s.resources::load-service-account-signing-key founder-store)))
      (gr8s.resources::create-core-resource
       founder-store "serviceaccounts"
       (gr8s.resources::core-object "metadata" (gr8s.resources::core-object "name" "runner"))
       "conformance")
      (with-temporary-store (store path)
        (let ((joiner (join-control-plane founder store path "cp2")))
          (unwind-protect
               (progn
                 (is (poll-until
                      (lambda ()
                        (ignore-errors
                          (gr8s.resources::get-core-resource store "serviceaccounts" "conformance" "runner")))
                      :timeout 20))
                 (let* ((account (gr8s.resources::get-core-resource founder-store "serviceaccounts"
                                                          "conformance" "runner"))
                        (token (gr8s.resources::mint-service-account-token founder-store account))
                        (joiner-key (gr8s.resources::load-service-account-signing-key store)))
                   (is (equal (gr8s.resources::service-account-key-id founder-key)
                              (gr8s.resources::service-account-key-id joiner-key))
                       "every voter publishes and verifies tokens with one cluster key")
                   (is (gr8s.resources::authenticate-service-account-token store token)
                       "a token minted by one control plane authenticates on another")))
            (gr8s.ha::stop-ha-control-plane joiner)))))))

(test follower-writes-forward-to-the-leader-over-mutual-tls
  (with-founded-cluster (founder)
    (with-temporary-store (store path)
      (let ((joiner (join-control-plane founder store path "cp2")))
        (unwind-protect
             (progn
               (is (poll-until
                    (lambda ()
                      (= 2 (count :voter
                                  (gr8s.raft.transport::raft-cluster-members
                                   (gr8s.ha::ha-control-plane-member founder))
                                  :key #'cdr)))
                    :timeout 20))
               (gr8s.resources::create-core-resource
                store "configmaps" (configmap-input "forwarded" "k" "tls") "default")
               (is (poll-until
                    (lambda ()
                      (and (equal "tls" (configmap-value store "forwarded" "k"))
                           (equal "tls"
                                  (configmap-value
                                   (gr8s.ha::ha-control-plane-store founder) "forwarded" "k"))))
                    :timeout 15))
               (gr8s.controllers::register-node
                store (gr8s.model::make-node-record :id "node-2" :name "worker-2"
                                              :pod-cidr "10.88.16.0/20"))
               (is (poll-until
                    (lambda ()
                      (and (ignore-errors (gr8s.controllers::get-node store "worker-2"))
                           (ignore-errors
                             (gr8s.controllers::get-node (gr8s.ha::ha-control-plane-store founder)
                                            "worker-2"))))
                    :timeout 15))
               (let* ((node-pki (raft-tls-test-pki path))
                      (server (gr8s.apiserver::start-node-grpc-server store :pki node-pki :port 0))
                      (directory (merge-pathnames "enrolled/" path)))
                 (unwind-protect
                      (progn
                        (gr8s.agent::enroll-node-over-grpc
                         "127.0.0.1" (gr8s.apiserver::node-grpc-server-port server)
                         "worker-enrolled" (gr8s.security::create-join-token node-pki "worker-enrolled")
                         (gr8s.security::cluster-pki-ca-fingerprint node-pki)
                         (merge-pathnames "node.key" directory)
                         (merge-pathnames "node.crt" directory)
                         (merge-pathnames "ca.crt" directory))
                        (is (probe-file (merge-pathnames "node.crt" directory))))
                   (gr8s.apiserver::stop-node-grpc-server server))))
          (gr8s.ha::stop-ha-control-plane joiner))))))

(test raft-requires-a-member-certificate
  (with-founded-cluster (founder node-pki)
    (let* ((port (control-plane-port founder))
           (raft-pki (member-raft-pki founder))
           (pin (gr8s.security::cluster-pki-ca-fingerprint raft-pki))
           (term (control-plane-term founder)))
      (is (rejected-p (lambda ()
                        (deliver-through (ag-grpc:make-channel "127.0.0.1" port :timeout 3) (attack-message))))
          "plain gRPC")
      (is (rejected-p (lambda ()
                        (deliver-through (gr8s.security::make-node-tls-channel "127.0.0.1" port :timeout 5 :ca-pin pin)
                                         (attack-message))))
          "TLS without a client certificate")
      (is (rejected-p
           (lambda ()
             (let ((channel (gr8s.security::make-node-tls-channel "127.0.0.1" port :timeout 5 :ca-pin pin)))
               (unwind-protect
                    (gr8s.node.v1::raft-transport-join
                     (gr8s.node.v1::make-raft-transport-stub channel)
                     (make-instance 'gr8s.node.v1::join-request :member-id "attacker" :host "127.0.0.1" :port 1)
                     :timeout 5)
                 (ignore-errors (ag-grpc:channel-close channel))))))
          "Join without a client certificate")
      ;; A real worker's identity, from the cluster's node CA, is worth nothing here.
      (let* ((directory (gr8s.security::cluster-pki-root node-pki))
             (key (merge-pathnames "worker.key" directory))
             (certificate (merge-pathnames "worker.crt" directory)))
        (gr8s.security::write-private-text-exclusively
         certificate
         (gr8s.security::enroll-node-csr node-pki "worker" (gr8s.security::create-join-token node-pki "worker")
                                (gr8s.security::cluster-pki-ca-fingerprint node-pki)
                                (gr8s.security::generate-node-key-and-csr "worker" key)))
        (is (rejected-p (lambda ()
                          (deliver-through
                           (gr8s.security::make-node-tls-channel "127.0.0.1" port :timeout 5 :ca-pin pin
                                                                         :certificate-path certificate
                                                                         :private-key-path key)
                           (attack-message "worker"))))
            "a worker node's certificate"))
      (is (= term (control-plane-term founder)) "no attack reached the Raft core")
      (is (member "cp1" (gr8s.raft.transport::raft-cluster-members (gr8s.ha::ha-control-plane-member founder))
                  :key #'car :test #'equal))
      (is (= 1 (length (gr8s.raft.transport::raft-cluster-members (gr8s.ha::ha-control-plane-member founder))))
          "no attack added a member"))))

(test members-can-not-pose-as-each-other
  (with-founded-cluster (founder)
    (with-temporary-store (store path)
      (let ((joiner (join-control-plane founder store path "cp2")))
        (unwind-protect
             (let ((credentials (gr8s.raft.transport::raft-member-credentials (gr8s.ha::ha-control-plane-member joiner)))
                   (term (control-plane-term founder)))
               ;; This stale message changes nothing, and shows the same call succeeds honestly.
               (is (not (rejected-p (lambda ()
                                      (deliver-through (gr8s.security::make-raft-channel credentials "127.0.0.1"
                                                                                (control-plane-port founder) 5)
                                                       (attack-message "cp2" 0))))))
               (is (rejected-p (lambda ()
                                 (deliver-through (gr8s.security::make-raft-channel credentials "127.0.0.1"
                                                                           (control-plane-port founder) 5)
                                                  (attack-message "cp1")))))
               (is (= term (control-plane-term founder)))
               (is (rejected-p
                    (lambda ()
                      (let ((channel (gr8s.security::make-raft-channel credentials "127.0.0.1" (control-plane-port founder) 5)))
                        (unwind-protect
                             (gr8s.node.v1::raft-transport-join
                              (gr8s.node.v1::make-raft-transport-stub channel)
                              (make-instance 'gr8s.node.v1::join-request :member-id "cp3" :host "127.0.0.1" :port 1)
                              :timeout 5)
                          (ignore-errors (ag-grpc:channel-close channel))))))
                   "a certificate for one member can't join another"))
          (gr8s.ha::stop-ha-control-plane joiner))))))

(defun enrollment-refused-p (founder path &key (id "cp2") (node-name id) token ca-pin (role :voter))
  "Attempt enrollment with these details and return whether it was refused and left no certificate."
  (let ((root (gr8s.security::raft-tls-root (raft-tls-test-pki path))))
    (and (rejected-p (lambda ()
                       (gr8s.security::enroll-raft-member root id "127.0.0.1" (control-plane-port founder)
                                                 :node-name node-name :token token :ca-pin ca-pin
                                                 :role role)))
         (null (probe-file (gr8s.security::raft-member-certificate-path root))))))

(test a-witness-token-can-not-escalate-to-voter
  (with-founded-cluster (founder)
    (with-temporary-store (store path)
      (declare (ignorable store))
      (let* ((raft-pki (member-raft-pki founder))
             (pin (gr8s.security::cluster-pki-ca-fingerprint raft-pki))
             (token (gr8s.security::create-join-token raft-pki "w1" :role :witness)))
        (is (enrollment-refused-p founder path :id "w1" :token token :ca-pin pin :role :voter)
            "a witness-scoped token must not release the cluster CA")
        (is (not (enrollment-refused-p founder path :id "w1" :token token :ca-pin pin :role :witness))
            "a role mismatch does not consume the token needed for the intended witness")))))

(test enrollment-needs-the-right-pin-and-an-unused-raft-token
  (with-founded-cluster (founder node-pki)
    (with-temporary-store (store path)
      (declare (ignorable store))
      (let* ((raft-pki (member-raft-pki founder))
             (pin (gr8s.security::cluster-pki-ca-fingerprint raft-pki)))
        (is (enrollment-refused-p founder path :token (gr8s.security::create-join-token node-pki "cp2") :ca-pin pin)
            "a token for a worker node")
        (is (enrollment-refused-p founder path :token "0123456789abcdef01234567.0000" :ca-pin pin)
            "a malformed token")
        (is (enrollment-refused-p founder path :id "cp1" :node-name "cp1"
                                               :token (gr8s.security::create-join-token raft-pki "cp1" :role :voter) :ca-pin pin)
            "an existing member's identity")
        (is (enrollment-refused-p founder path :token nil :ca-pin pin))
        (let ((token (gr8s.security::create-join-token raft-pki "cp2" :role :voter)))
          (is (enrollment-refused-p founder path :token token :ca-pin (gr8s.security::cluster-pki-ca-fingerprint node-pki))
              "the wrong CA pin")
          (finishes (gr8s.security::validate-token raft-pki token "cp2"))
          (is (not (enrollment-refused-p founder path :token token :ca-pin pin))))
        ;; The first enrollment succeeded and spent its token.
        (let ((token (gr8s.security::create-join-token raft-pki "cp3" :role :voter)))
          (with-temporary-store (other other-path)
            (declare (ignorable other))
            (is (not (enrollment-refused-p founder other-path :id "cp3" :token token :ca-pin pin))))
          (with-temporary-store (other other-path)
            (declare (ignorable other))
            (is (enrollment-refused-p founder other-path :id "cp3" :token token :ca-pin pin)
                "a used token")))))))

(test raft-logs-are-private-even-if-they-already-exist
  (with-raft-temp-dir (path)
    (ensure-directories-exist path)
    (close (open path :direction :output :if-does-not-exist :create))
    (sb-posix:chmod (namestring path) #o644)
    (cl-raft::close-file-raft-storage (cl-raft::open-file-raft-storage path))
    (is (= #o600 (logand #o777 (sb-posix:stat-mode (sb-posix:stat (namestring path))))))))

(test join-tokens-come-from-the-store-for-their-role
  (with-temporary-store (store path)
    (declare (ignorable store))
    (let* ((state (uiop:ensure-directory-pathname path))
           (node-pki (raft-tls-test-pki state))
           (raft-root (gr8s.security::raft-tls-root node-pki)))
      (flet ((token-output (role)
               (com.inuoe.jzon:parse
                (with-output-to-string (output)
                  (gr8s.server::print-node-join-token (list :state-directory (namestring state) :node-name "cp2" :role role)
                                               output)))))
        (signals error (token-output "control-plane"))
        (is (null (probe-file (gr8s.security::raft-ca-certificate-path raft-root)))
            "asking for a token never creates a CA")
        (is (equal (gr8s.security::cluster-pki-ca-fingerprint node-pki) (gethash "caPin" (token-output "node"))))
        (let* ((credentials (gr8s.security::ensure-raft-founder-credentials raft-root "cp1"))
               (raft-pki (gr8s.security::raft-credentials-pki credentials))
               (output (token-output "control-plane")))
          (is (equal (gr8s.security::cluster-pki-ca-fingerprint raft-pki) (gethash "caPin" output)))
          (is (not (equal (gr8s.security::cluster-pki-ca-fingerprint raft-pki) (gr8s.security::cluster-pki-ca-fingerprint node-pki))))
          (finishes (gr8s.security::validate-token raft-pki (gethash "token" output) "cp2"))
          (signals gr8s.security::pki-error (gr8s.security::validate-token node-pki (gethash "token" output) "cp2")))))))
