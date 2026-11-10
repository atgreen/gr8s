;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Verify the certificates a long-lived HA cluster depends on: agents enrolled
;;;; with one control plane work with another after a failover, and member
;;;; certificates renew before they expire, over real TLS on localhost.

(in-package #:gr8s/tests)
(in-suite raft-tls)

(defun enroll-test-worker (pki directory)
  "Return the certificate and key paths of worker node \"worker\" enrolled with PKI."
  (let* ((directory (uiop:ensure-directory-pathname directory))
         (key (merge-pathnames "worker.key" directory))
         (certificate (merge-pathnames "worker.crt" directory)))
    (gr8s::write-private-text-exclusively
     certificate
     (gr8s::enroll-node-csr pki "worker" (gr8s:create-join-token pki "worker")
                            (gr8s::cluster-pki-ca-fingerprint pki)
                            (gr8s::generate-node-key-and-csr "worker" key)))
    (values certificate key)))

(defun member-certificate-fingerprint (credentials)
  (pure-tls:certificate-fingerprint
   (first (pure-tls:load-certificate-chain (gr8s::raft-credentials-certificate-path credentials)))))

(defun presented-certificate-fingerprint (credentials port)
  "Return the fingerprint of the certificate the member at PORT presents to a new connection."
  (let ((channel (gr8s::make-raft-channel credentials "127.0.0.1" port 5)))
    (unwind-protect
         (pure-tls:certificate-fingerprint
          (pure-tls:tls-peer-certificate (ag-http2:connection-stream (ag-grpc:channel-connection channel))))
      (ignore-errors (ag-grpc:channel-close channel)))))

(defun control-plane-credentials (control-plane)
  (gr8s::raft-member-credentials (gr8s::ha-control-plane-member control-plane)))

(defun far-future () (+ (get-universal-time) (* 340 24 60 60)))

(defmacro with-joined-witness ((witness founder state) &body body)
  "Run BODY with WITNESS a member of FOUNDER's cluster, its credentials under the directory STATE."
  `(let* ((raft-pki (member-raft-pki ,founder))
          (,witness (gr8s::start-raft-member
                     "w1" :credentials (gr8s::ensure-raft-joiner-credentials
                                        (merge-pathnames "raft/" (uiop:ensure-directory-pathname ,state))
                                        "w1" "127.0.0.1" (control-plane-port ,founder)
                                        :role :witness :node-name "w1"
                                        :token (gr8s:create-join-token raft-pki "w1" :role :witness)
                                        :ca-pin (gr8s::cluster-pki-ca-fingerprint raft-pki)))))
     (unwind-protect
          (progn
            (gr8s::raft-member-start ,witness)
            (is (gr8s::raft-cluster-join ,witness "127.0.0.1" (control-plane-port ,founder)
                                         :role :witness :node-name "w1"))
            (is (poll-until (lambda ()
                              (assoc "w1" (gr8s::raft-cluster-members (gr8s::ha-control-plane-member ,founder))
                                     :test #'equal))
                            :timeout 20))
            ,@body)
       (gr8s::stop-raft-member ,witness))))

(defun request-renewal (credentials port member-id key)
  "Ask the member at PORT, using CREDENTIALS, to renew MEMBER-ID's certificate using its KEY."
  (let ((channel (gr8s::make-raft-channel credentials "127.0.0.1" port 10)))
    (unwind-protect
         (gr8s.node.v1::raft-transport-renew-member
          (gr8s.node.v1::make-raft-transport-stub channel)
          (make-instance 'gr8s.node.v1::renew-member-request
                         :certificate-request (gr8s::generate-node-key-and-csr member-id key))
          :timeout 10)
      (ignore-errors (ag-grpc:channel-close channel)))))

(test agents-keep-working-after-failing-over-to-another-control-plane
  (with-founded-cluster (founder node-pki)
    (with-temporary-store (store path)
      (let ((joiner (join-control-plane founder store path "cp2")))
        (unwind-protect
             (let ((joined-pki (raft-tls-test-pki path)))
               (is (equal (gr8s::cluster-pki-ca-fingerprint node-pki)
                          (gr8s::cluster-pki-ca-fingerprint joined-pki)))
               (multiple-value-bind (certificate key) (enroll-test-worker node-pki path)
                 (is (gr8s::verify-node-certificate joined-pki (uiop:read-file-string certificate) "worker")
                     "the other control plane accepts the worker")
                 ;; The worker connects as it would after a failover, holding only the
                 ;; CA from its first enrollment, and each side checks the other.
                 (let* ((server (gr8s:start-node-grpc-server store :pki joined-pki :port 0))
                        (ca (gr8s::cluster-pki-ca-certificate-path node-pki)))
                   (unwind-protect
                        (let ((channel (gr8s::make-node-tls-channel
                                        "127.0.0.1" (gr8s:node-grpc-server-port server)
                                        :timeout 10 :ca-certificate-path ca
                                        :certificate-path certificate :private-key-path key)))
                          (is (not (null channel)))
                          (ignore-errors (ag-grpc:channel-close channel)))
                     (gr8s:stop-node-grpc-server server)))))
          (gr8s::stop-ha-control-plane joiner))))))

(test a-state-directory-with-another-ca-refuses-to-join
  (with-founded-cluster (founder)
    (with-temporary-store (store path)
      (declare (ignorable store))
      (let* ((existing (raft-tls-test-pki path))
             (fingerprint (gr8s::cluster-pki-ca-fingerprint existing))
             (root (merge-pathnames "pki/" (uiop:ensure-directory-pathname path)))
             (raft-pki (member-raft-pki founder))
             (reason (handler-case
                         (gr8s::ensure-joining-control-plane-pki
                          root "cp2" "127.0.0.1" (control-plane-port founder)
                          :node-name "cp2" :token (gr8s:create-join-token raft-pki "cp2" :role :voter)
                          :ca-pin (gr8s::cluster-pki-ca-fingerprint raft-pki))
                       (gr8s:pki-error (condition) (gr8s:pki-error-reason condition)))))
        (is (equal "node-ca-conflict" reason))
        (is (equal fingerprint (gr8s::cluster-pki-ca-fingerprint (raft-tls-test-pki path))))
        (is (null (probe-file (gr8s::raft-member-certificate-path (merge-pathnames "raft/" root))))
            "a refused member isn't left half enrolled")))))

(test the-same-node-ca-can-be-installed-again
  (with-temporary-store (store path)
    (declare (ignorable store))
    (let* ((pki (raft-tls-test-pki path))
           (certificate (uiop:read-file-string (gr8s::cluster-pki-ca-certificate-path pki)))
           (key (uiop:read-file-string (gr8s::cluster-pki-ca-private-key-path pki))))
      (finishes (gr8s::install-shared-node-ca (gr8s::cluster-pki-root pki) certificate key))
      (is (equal key (uiop:read-file-string (gr8s::cluster-pki-ca-private-key-path pki)))))))

(test witnesses-do-not-receive-the-node-ca
  (with-founded-cluster (founder)
    (with-temporary-store (store path)
      (declare (ignorable store))
      (let* ((state (uiop:ensure-directory-pathname path))
             (raft-pki (member-raft-pki founder))
             (node-root (merge-pathnames "pki/" state)))
        (gr8s::enroll-raft-member (merge-pathnames "raft/" state) "w1" "127.0.0.1" (control-plane-port founder)
                                  :role :witness :node-name "w1" :node-root node-root
                                  :token (gr8s:create-join-token raft-pki "w1" :role :witness)
                                  :ca-pin (gr8s::cluster-pki-ca-fingerprint raft-pki))
        (is (probe-file (gr8s::raft-member-certificate-path (merge-pathnames "raft/" state))))
        (is (null (probe-file (gr8s::raft-ca-certificate-path node-root))))
        (is (null (probe-file (gr8s::raft-ca-key-path (merge-pathnames "raft/" state)))))))))

(test voters-renew-their-own-certificates-in-their-last-30-days
  (with-founded-cluster (founder)
    (with-temporary-store (store path)
      (let ((joiner (join-control-plane founder store path "cp2")))
        (unwind-protect
             (let* ((member (gr8s::ha-control-plane-member founder))
                    (credentials (control-plane-credentials founder))
                    (before (member-certificate-fingerprint credentials))
                    (key (uiop:read-file-string (gr8s::raft-credentials-key-path credentials)))
                    (remaining (- (gr8s::raft-certificate-not-after credentials) (get-universal-time))))
               (is (< (* 360 24 60 60) remaining (* 366 24 60 60)) "the certificate lasts about a year")
               (is (bt:thread-alive-p (gr8s::raft-member-renewal-thread member)))
               (is (not (gr8s::raft-certificate-expiring-p credentials (get-universal-time))))
               (is (gr8s::raft-certificate-expiring-p credentials (far-future)))
               (gr8s::raft-member-renew-if-needed member)
               (is (equalp before (member-certificate-fingerprint credentials)) "it isn't due yet")
               (gr8s::raft-member-renew-if-needed member (far-future))
               (let ((after (member-certificate-fingerprint credentials)))
                 (is (not (equalp before after)))
                 (is (equal key (uiop:read-file-string (gr8s::raft-credentials-key-path credentials))))
                 (is (equalp after (presented-certificate-fingerprint (control-plane-credentials joiner)
                                                                      (control-plane-port founder)))
                     "new connections get the renewed certificate without a restart"))
               ;; The cluster still commits, and the renewed certificate authenticates.
               (multiple-value-bind (result committed) (gr8s::raft-member-propose-sync member '(:noop) :timeout 15)
                 (declare (ignore result))
                 (is (eq t committed)))
               (is (equalp (member-certificate-fingerprint (control-plane-credentials joiner))
                           (presented-certificate-fingerprint credentials (control-plane-port joiner)))))
          (gr8s::stop-ha-control-plane joiner))))))

(test witnesses-renew-through-a-voter
  (with-founded-cluster (founder)
    (with-temporary-store (store path)
      (declare (ignorable store))
      (with-joined-witness (witness founder path)
        (let* ((credentials (gr8s::raft-member-credentials witness))
               (before (member-certificate-fingerprint credentials)))
          (is (null (gr8s::raft-credentials-pki credentials)) "a witness can't sign for itself")
          (gr8s::raft-member-renew-if-needed witness (far-future))
          (is (not (equalp before (member-certificate-fingerprint credentials))))
          (is (equalp (member-certificate-fingerprint credentials)
                      (presented-certificate-fingerprint (control-plane-credentials founder)
                                                         (gr8s::raft-member-port witness)))))))))

(test a-failed-renewal-is-reported-and-keeps-the-certificate
  (with-founded-cluster (founder)
    (with-temporary-store (store path)
      (declare (ignorable store))
      (let* ((raft-pki (member-raft-pki founder))
             (credentials (gr8s::ensure-raft-joiner-credentials
                           (merge-pathnames "raft/" (uiop:ensure-directory-pathname path))
                           "w1" "127.0.0.1" (control-plane-port founder)
                           :role :witness :node-name "w1"
                           :token (gr8s:create-join-token raft-pki "w1" :role :witness)
                           :ca-pin (gr8s::cluster-pki-ca-fingerprint raft-pki)))
             ;; This member never joined, so it has no peer to ask.
             (lonely (gr8s::start-raft-member "w1" :apply-fn (lambda (c) (declare (ignore c)) nil)
                                                   :credentials credentials))
             (before (member-certificate-fingerprint credentials)))
        (unwind-protect
             (let ((report (with-output-to-string (*error-output*)
                             (finishes (gr8s::raft-member-renew-if-needed lonely (far-future))))))
               (is (search "couldn't be renewed" report))
               (is (equalp before (member-certificate-fingerprint credentials))))
          (gr8s::stop-raft-member lonely))))))

(test renewal-needs-a-current-member-and-its-own-name
  (with-founded-cluster (founder)
    (with-temporary-store (store path)
      (declare (ignorable store))
      (with-joined-witness (witness founder path)
        (let* ((credentials (gr8s::raft-member-credentials witness))
               (key (gr8s::raft-credentials-key-path credentials))
               (other-key (merge-pathnames "other.key" (uiop:ensure-directory-pathname path)))
               (port (control-plane-port founder))
               (pin (gr8s::cluster-pki-ca-fingerprint (member-raft-pki founder))))
          (is (not (rejected-p (lambda () (request-renewal credentials port "w1" key))))
              "the same request works for the member itself")
          (is (rejected-p (lambda () (request-renewal credentials port "cp1" other-key)))
              "a member can't get a certificate in another's name")
          (is (rejected-p
               (lambda ()
                 (let ((channel (gr8s::make-node-tls-channel "127.0.0.1" port :timeout 5 :ca-pin pin)))
                   (unwind-protect
                        (gr8s.node.v1::raft-transport-renew-member
                         (gr8s.node.v1::make-raft-transport-stub channel)
                         (make-instance 'gr8s.node.v1::renew-member-request
                                        :certificate-request (gr8s::generate-node-key-and-csr "w1" key))
                         :timeout 5)
                     (ignore-errors (ag-grpc:channel-close channel))))))
              "no certificate")
          (is (gr8s::raft-cluster-remove-member (gr8s::ha-control-plane-member founder) "w1"))
          (is (poll-until (lambda ()
                            (null (assoc "w1" (gr8s::raft-cluster-members (gr8s::ha-control-plane-member founder))
                                         :test #'equal)))
                          :timeout 15))
          (is (rejected-p (lambda () (request-renewal credentials port "w1" key)))
              "a removed member's certificate must be left to run out"))))))
