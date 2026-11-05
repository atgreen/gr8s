;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Verify Raft members really replicate over mutual TLS, and that everything
;;;; else is turned away: plain connections, no certificate, a worker's certificate
;;;; or token, a reused token, a wrong CA pin and a member posing as another.

(in-package #:gr8s/tests)
(def-suite raft-tls :in gr8s)
(in-suite raft-tls)

(defun raft-tls-test-pki (path)
  (gr8s:ensure-cluster-pki (merge-pathnames "pki/" (uiop:ensure-directory-pathname path))))

(defun member-raft-pki (control-plane)
  (gr8s::raft-credentials-pki (gr8s::raft-member-credentials (gr8s::ha-control-plane-member control-plane))))

(defun control-plane-port (control-plane)
  (gr8s::raft-member-port (gr8s::ha-control-plane-member control-plane)))

(defun control-plane-term (control-plane)
  (gr8s::raft-node-current-term (gr8s::raft-member-node (gr8s::ha-control-plane-member control-plane))))

(defmacro with-founded-cluster ((founder &optional (pki (gensym "PKI"))) &body body)
  "Run BODY with FOUNDER leading a one-member mutual TLS cluster, and PKI its node PKI."
  (let ((store (gensym "STORE")) (path (gensym "PATH")))
    `(with-temporary-store (,store ,path)
       (let* ((,pki (raft-tls-test-pki ,path))
              (,founder (gr8s::start-ha-control-plane ,store :id "cp1" :init t :pki ,pki)))
         (declare (ignorable ,pki))
         (unwind-protect
              (progn (is (poll-until (lambda () (gr8s::ha-control-plane-leader-p ,founder))))
                     ,@body)
           (gr8s::stop-ha-control-plane ,founder))))))

(defun join-control-plane (founder store path id &key (node-name id)
                                                   (token (gr8s:create-join-token (member-raft-pki founder) node-name))
                                                   (ca-pin (gr8s::cluster-pki-ca-fingerprint (member-raft-pki founder))))
  (let ((pki (gr8s::ensure-joining-control-plane-pki
              (merge-pathnames "pki/" (uiop:ensure-directory-pathname path)) id
              "127.0.0.1" (control-plane-port founder) :node-name node-name :token token :ca-pin ca-pin)))
    (gr8s::start-ha-control-plane store :id id :join-host "127.0.0.1" :join-port (control-plane-port founder)
                                        :node-name node-name :pki pki)))

(defun rejected-p (function)
  "Return true if calling FUNCTION signals, including by timing out."
  (handler-case (progn (funcall function) nil)
    ((or error sb-ext:timeout) () t)))

(defun attack-message (&optional (from "attacker") (term 999))
  "Return a Deliver request that would visibly advance the receiver's term if accepted."
  (make-instance 'gr8s.node.v1::raft-envelope
                 :protocol-version 1
                 :payload (gr8s::raft-message->octets
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
             (let ((root (gr8s::raft-tls-root (raft-tls-test-pki path)))
                   (leader (gr8s::ha-control-plane-member founder))
                   (follower (gr8s::ha-control-plane-member joiner)))
               (is (poll-until (lambda () (member "cp2" (gr8s::raft-node-peers (gr8s::raft-member-node leader))
                                                  :test #'equal))
                               :timeout 20))
               ;; A real commit needs the joiner's acknowledgement over its own TLS link.
               (is (poll-until
                    (lambda ()
                      (= 2 (count :voter (gr8s::raft-cluster-members leader) :key #'cdr)))
                    :timeout 20))
               (multiple-value-bind (result committed) (gr8s::raft-member-propose-sync leader '(:noop) :timeout 15)
                 (declare (ignore result))
                 (is (eq t committed)))
               (is (poll-until
                    (lambda ()
                      (= (gr8s::raft-node-commit-index (gr8s::raft-member-node leader))
                         (gr8s::raft-node-commit-index (gr8s::raft-member-node follower))))
                    :timeout 15))
               (is (= #o600 (logand #o777 (sb-posix:stat-mode
                                           (sb-posix:stat (namestring (gr8s::raft-ca-key-path root)))))))
               (is (equal (gr8s::cluster-pki-ca-fingerprint (member-raft-pki founder))
                          (gr8s::cluster-pki-ca-fingerprint (member-raft-pki joiner)))
                   "a voter holds the CA, so it can admit members after a failover")
               (finishes (gr8s::ensure-raft-joiner-credentials root "cp2" "127.0.0.1" 1))
               (is (gr8s::raft-credentials-pki (gr8s::ensure-raft-joiner-credentials root "cp2" "127.0.0.1" 1))
                   "a restarted member reuses its credentials without a new token"))
          (gr8s::stop-ha-control-plane joiner))))))

(test raft-requires-a-member-certificate
  (with-founded-cluster (founder node-pki)
    (let* ((port (control-plane-port founder))
           (raft-pki (member-raft-pki founder))
           (pin (gr8s::cluster-pki-ca-fingerprint raft-pki))
           (term (control-plane-term founder)))
      (is (rejected-p (lambda ()
                        (deliver-through (ag-grpc:make-channel "127.0.0.1" port :timeout 3) (attack-message))))
          "plain gRPC")
      (is (rejected-p (lambda ()
                        (deliver-through (gr8s::make-node-tls-channel "127.0.0.1" port :timeout 5 :ca-pin pin)
                                         (attack-message))))
          "TLS without a client certificate")
      (is (rejected-p
           (lambda ()
             (let ((channel (gr8s::make-node-tls-channel "127.0.0.1" port :timeout 5 :ca-pin pin)))
               (unwind-protect
                    (gr8s.node.v1::raft-transport-join
                     (gr8s.node.v1::make-raft-transport-stub channel)
                     (make-instance 'gr8s.node.v1::join-request :member-id "attacker" :host "127.0.0.1" :port 1)
                     :timeout 5)
                 (ignore-errors (ag-grpc:channel-close channel))))))
          "Join without a client certificate")
      ;; A real worker's identity, from the cluster's node CA, is worth nothing here.
      (let* ((directory (gr8s::cluster-pki-root node-pki))
             (key (merge-pathnames "worker.key" directory))
             (certificate (merge-pathnames "worker.crt" directory)))
        (gr8s::write-private-text-exclusively
         certificate
         (gr8s::enroll-node-csr node-pki "worker" (gr8s:create-join-token node-pki "worker")
                                (gr8s::cluster-pki-ca-fingerprint node-pki)
                                (gr8s::generate-node-key-and-csr "worker" key)))
        (is (rejected-p (lambda ()
                          (deliver-through
                           (gr8s::make-node-tls-channel "127.0.0.1" port :timeout 5 :ca-pin pin
                                                                         :certificate-path certificate
                                                                         :private-key-path key)
                           (attack-message "worker"))))
            "a worker node's certificate"))
      (is (= term (control-plane-term founder)) "no attack reached the Raft core")
      (is (member "cp1" (gr8s::raft-cluster-members (gr8s::ha-control-plane-member founder))
                  :key #'car :test #'equal))
      (is (= 1 (length (gr8s::raft-cluster-members (gr8s::ha-control-plane-member founder))))
          "no attack added a member"))))

(test members-can-not-pose-as-each-other
  (with-founded-cluster (founder)
    (with-temporary-store (store path)
      (let ((joiner (join-control-plane founder store path "cp2")))
        (unwind-protect
             (let ((credentials (gr8s::raft-member-credentials (gr8s::ha-control-plane-member joiner)))
                   (term (control-plane-term founder)))
               ;; This stale message changes nothing, and shows the same call succeeds honestly.
               (is (not (rejected-p (lambda ()
                                      (deliver-through (gr8s::make-raft-channel credentials "127.0.0.1"
                                                                                (control-plane-port founder) 5)
                                                       (attack-message "cp2" 0))))))
               (is (rejected-p (lambda ()
                                 (deliver-through (gr8s::make-raft-channel credentials "127.0.0.1"
                                                                           (control-plane-port founder) 5)
                                                  (attack-message "cp1")))))
               (is (= term (control-plane-term founder)))
               (is (rejected-p
                    (lambda ()
                      (let ((channel (gr8s::make-raft-channel credentials "127.0.0.1" (control-plane-port founder) 5)))
                        (unwind-protect
                             (gr8s.node.v1::raft-transport-join
                              (gr8s.node.v1::make-raft-transport-stub channel)
                              (make-instance 'gr8s.node.v1::join-request :member-id "cp3" :host "127.0.0.1" :port 1)
                              :timeout 5)
                          (ignore-errors (ag-grpc:channel-close channel))))))
                   "a certificate for one member can't join another"))
          (gr8s::stop-ha-control-plane joiner))))))

(defun enrollment-refused-p (founder path &key (id "cp2") (node-name id) token ca-pin)
  "Attempt enrollment with these details and return whether it was refused and left no certificate."
  (let ((root (gr8s::raft-tls-root (raft-tls-test-pki path))))
    (and (rejected-p (lambda ()
                       (gr8s::enroll-raft-member root id "127.0.0.1" (control-plane-port founder)
                                                 :node-name node-name :token token :ca-pin ca-pin)))
         (null (probe-file (gr8s::raft-member-certificate-path root))))))

(test enrollment-needs-the-right-pin-and-an-unused-raft-token
  (with-founded-cluster (founder node-pki)
    (with-temporary-store (store path)
      (declare (ignorable store))
      (let* ((raft-pki (member-raft-pki founder))
             (pin (gr8s::cluster-pki-ca-fingerprint raft-pki)))
        (is (enrollment-refused-p founder path :token (gr8s:create-join-token node-pki "cp2") :ca-pin pin)
            "a token for a worker node")
        (is (enrollment-refused-p founder path :token "0123456789abcdef01234567.0000" :ca-pin pin)
            "a malformed token")
        (is (enrollment-refused-p founder path :id "cp1" :node-name "cp1"
                                               :token (gr8s:create-join-token raft-pki "cp1") :ca-pin pin)
            "an existing member's identity")
        (is (enrollment-refused-p founder path :token nil :ca-pin pin))
        (let ((token (gr8s:create-join-token raft-pki "cp2")))
          (is (enrollment-refused-p founder path :token token :ca-pin (gr8s::cluster-pki-ca-fingerprint node-pki))
              "the wrong CA pin")
          (finishes (gr8s::validate-token raft-pki token "cp2"))
          (is (not (enrollment-refused-p founder path :token token :ca-pin pin))))
        ;; The first enrollment succeeded and spent its token.
        (let ((token (gr8s:create-join-token raft-pki "cp3")))
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
    (gr8s::close-file-raft-storage (gr8s::open-file-raft-storage path))
    (is (= #o600 (logand #o777 (sb-posix:stat-mode (sb-posix:stat (namestring path))))))))

(test join-tokens-come-from-the-store-for-their-role
  (with-temporary-store (store path)
    (declare (ignorable store))
    (let* ((state (uiop:ensure-directory-pathname path))
           (node-pki (raft-tls-test-pki state))
           (raft-root (gr8s::raft-tls-root node-pki)))
      (flet ((token-output (role)
               (com.inuoe.jzon:parse
                (with-output-to-string (output)
                  (gr8s::print-node-join-token (list :state-directory (namestring state) :node-name "cp2" :role role)
                                               output)))))
        (signals error (token-output "control-plane"))
        (is (null (probe-file (gr8s::raft-ca-certificate-path raft-root)))
            "asking for a token never creates a CA")
        (is (equal (gr8s::cluster-pki-ca-fingerprint node-pki) (gethash "caPin" (token-output "node"))))
        (let* ((credentials (gr8s::ensure-raft-founder-credentials raft-root "cp1"))
               (raft-pki (gr8s::raft-credentials-pki credentials))
               (output (token-output "control-plane")))
          (is (equal (gr8s::cluster-pki-ca-fingerprint raft-pki) (gethash "caPin" output)))
          (is (not (equal (gr8s::cluster-pki-ca-fingerprint raft-pki) (gr8s::cluster-pki-ca-fingerprint node-pki))))
          (finishes (gr8s::validate-token raft-pki (gethash "token" output) "cp2"))
          (signals gr8s:pki-error (gr8s::validate-token node-pki (gethash "token" output) "cp2")))))))
