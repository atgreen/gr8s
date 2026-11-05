;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Mutual TLS between Raft members. The log carries every Secret and accepting a
;;;; message can rewrite cluster state, so a member must be authenticated both ways.
;;;;
;;;; Members trust a CA of their own, founded with the cluster and separate from
;;;; the node CA, so a worker's certificate or join token gets nothing on this port.
;;;; A joiner has no certificate when it starts, so it first enrolls with a one-time
;;;; token over TLS, trusting a pinned CA fingerprint, and only then starts its
;;;; server. Voters also receive the CA key, so a cluster that loses its founder can
;;;; still admit a replacement. Witnesses never lead or admit anyone, so they don't.

(in-package #:gr8s)

(defstruct raft-credentials
  "A member's TLS identity: file paths, the CA certificate and, on voters, the issuing PKI."
  ca-path certificate-path key-path ca pki)

(defun raft-tls-root (pki)
  "Return the Raft credentials directory within control-plane PKI's own."
  (merge-pathnames "raft/" (cluster-pki-root pki)))

(defun raft-ca-certificate-path (root) (merge-pathnames "pki/cluster-ca.crt" root))
(defun raft-ca-key-path (root) (merge-pathnames "pki/cluster-ca.key" root))
(defun raft-member-certificate-path (root) (merge-pathnames "member.crt" root))
(defun raft-member-key-path (root) (merge-pathnames "member.key" root))

(defun load-raft-credentials (root)
  "Load the enrolled credentials under ROOT, including the PKI when this member holds the CA key."
  (make-raft-credentials
   :ca-path (raft-ca-certificate-path root)
   :certificate-path (raft-member-certificate-path root)
   :key-path (raft-member-key-path root)
   :ca (first (pure-tls:load-certificate-chain (raft-ca-certificate-path root)))
   :pki (when (probe-file (raft-ca-key-path root)) (ensure-cluster-pki root))))

(defun raft-member-certificate-der (pki member-id subject-public-key)
  "Sign MEMBER-ID's identity, which it presents both as a server and as a client."
  (certificate-der
   (pure-tls/acme::encode-subject +pki-ca-common-name+)
   (pure-tls/acme::encode-subject member-id)
   subject-public-key
   (list
    (pure-tls/acme::encode-critical-extension
     +oid-key-usage+ (pure-tls/acme::encode-bit-string #(#xa0) 5))
    (pure-tls/acme::encode-extension
     +oid-extended-key-usage+
     (pure-tls/acme::encode-sequence
      (pure-tls/acme::encode-oid +oid-client-auth+)
      (pure-tls/acme::encode-oid '(1 3 6 1 5 5 7 3 1))))
    ;; The TLS client checks this fixed name; the common name carries the identity.
    (pure-tls/acme::encode-extension
     pure-tls/acme::*oid-subject-alt-name*
     (pure-tls/acme::encode-san-extension (list +node-server-common-name+))))
   (cluster-pki-ca-private-key pki)))

(defun issue-raft-member-certificate (pki member-id csr)
  "Return a certificate chain PEM for MEMBER-ID from its verified signing request."
  (multiple-value-bind (requested-subject subject-public-key) (parse-and-verify-node-csr csr member-id)
    (declare (ignore requested-subject))
    (concatenate 'string
                 (pure-tls/acme::wrap-pem "CERTIFICATE"
                                          (raft-member-certificate-der pki member-id subject-public-key))
                 (uiop:read-file-string (cluster-pki-ca-certificate-path pki)))))

(defun ensure-raft-founder-credentials (root member-id)
  "Create or reuse the CA and member identity of the member founding a cluster."
  (ensure-valid-node-name member-id)
  (let ((pki (ensure-cluster-pki root)))
    (unless (probe-file (raft-member-certificate-path root))
      (write-private-text-atomically
       (raft-member-certificate-path root)
       (issue-raft-member-certificate
        pki member-id (generate-node-key-and-csr member-id (raft-member-key-path root)))))
    (load-raft-credentials root)))

(defun consume-raft-join-token (pki token node-name)
  "Check TOKEN against the Raft token store and use it up. Caller holds the PKI lock."
  (multiple-value-bind (record path salt digest) (validate-token pki token node-name)
    (declare (ignore record))
    (write-private-text-atomically path (token-record-json node-name salt digest "used"))))

(defun raft-member-handle-enroll (member request)
  "Issue a certificate to a new member presenting a Raft join token and return its credentials."
  (let* ((credentials (raft-member-credentials member))
         (pki (and credentials (raft-credentials-pki credentials)))
         (id (gr8s.node.v1::member-id request))
         (voter (not (string-equal "witness" (gr8s.node.v1::role request)))))
    (unless pki (pki-fail "enrollment-disabled" "This Raft member can't enroll others"))
    (ensure-valid-node-name id)
    ;; A fresh token must not let its holder take over an existing member's identity.
    (when (assoc id (bt:with-lock-held ((raft-member-lock member))
                      (raft-current-config (raft-member-node member)))
                 :test #'equal)
      (pki-fail "member-exists" "Raft member ~A already exists" id))
    (bt:with-lock-held ((cluster-pki-lock pki))
      (let ((certificate (issue-raft-member-certificate pki id (gr8s.node.v1::certificate-request request))))
        (consume-raft-join-token pki (gr8s.node.v1::join-token request) (gr8s.node.v1::node-name request))
        (make-instance 'gr8s.node.v1::enroll-member-response
                       :certificate certificate
                       :ca-certificate (uiop:read-file-string (cluster-pki-ca-certificate-path pki))
                       :ca-private-key (if voter
                                           (uiop:read-file-string (cluster-pki-ca-private-key-path pki))
                                           ""))))))

(defun enroll-raft-member (root member-id host port &key node-name token ca-pin (role :voter))
  "Obtain MEMBER-ID's credentials from the member at HOST:PORT and store them under ROOT."
  (ensure-valid-node-name member-id)
  (unless (and token ca-pin)
    (pki-fail "missing-enrollment" "Joining a Raft cluster requires a join token and a CA pin"))
  (let* ((csr (generate-node-key-and-csr member-id (progn (ensure-directories-exist root)
                                                          (raft-member-key-path root))))
         ;; The pin is checked here, before the token or anything else is sent.
         (channel (make-node-tls-channel host port :timeout 30 :ca-pin ca-pin)))
    (unwind-protect
         (let* ((response
                  (gr8s.node.v1::raft-transport-enroll-member
                   (gr8s.node.v1::make-raft-transport-stub channel)
                   (make-instance 'gr8s.node.v1::enroll-member-request
                                  :member-id member-id :node-name (or node-name member-id)
                                  :join-token token :role (string-downcase (symbol-name role))
                                  :certificate-request csr)
                   :timeout 30))
                (ca-pem (gr8s.node.v1::ca-certificate response))
                (key-pem (gr8s.node.v1::ca-private-key response)))
           (verify-enrollment-ca-pin ca-pem ca-pin)
           (write-private-text-atomically (raft-ca-certificate-path root) ca-pem)
           (when (plusp (length key-pem))
             (write-private-text-atomically (raft-ca-key-path root) key-pem))
           ;; Written last, because its presence means enrollment is complete.
           (write-private-text-atomically (raft-member-certificate-path root)
                                          (gr8s.node.v1::certificate response)))
      (ignore-errors (ag-grpc:channel-close channel)))))

(defun ensure-raft-joiner-credentials (root member-id host port &rest enrollment &key &allow-other-keys)
  "Reuse the credentials a restarted member already holds, or enroll through HOST:PORT."
  (unless (probe-file (raft-member-certificate-path root))
    (apply #'enroll-raft-member root member-id host port enrollment))
  (load-raft-credentials root))

(defun raft-server-tls-options (credentials)
  "Return server options for CREDENTIALS. Clients without a certificate may connect only to enroll."
  (when credentials
    (list :tls t
          :tls-certificate (namestring (raft-credentials-certificate-path credentials))
          :tls-key (namestring (raft-credentials-key-path credentials))
          :tls-verify-client :optional
          :tls-ca-certificate
          (pure-tls::make-trust-store :certificates (list (raft-credentials-ca credentials))))))

(defun authenticate-raft-peer (credentials context)
  "Return the member id in the verified client certificate on CONTEXT's connection, or signal."
  (let* ((stream (ag-http2:connection-stream (ag-grpc::context-connection context)))
         (certificate (and (typep stream 'pure-tls::tls-stream)
                           (pure-tls:tls-peer-certificate stream)))
         (ca (raft-credentials-ca credentials)))
    (unless certificate
      (pki-fail "unauthenticated-member" "Raft requests require a member certificate"))
    (require-internal-certificate-profile certificate ca)
    (handler-case
        (pure-tls::verify-certificate-chain (list certificate) (list ca)
                                            :purpose :client-auth :trust-anchor-mode :replace)
      (error (condition)
        (pki-fail "untrusted-member" "Raft member certificate isn't trusted: ~A" condition)))
    (let ((names (pure-tls:certificate-subject-common-names certificate)))
      (unless (= 1 (length names))
        (pki-fail "untrusted-member" "Raft member certificate must name one member"))
      (first names))))

(defun authenticated-raft-message (credentials request context)
  "Decode a delivered message, first authenticating its sender when this member uses TLS."
  (if credentials
      (let ((peer (authenticate-raft-peer credentials context))
            (message (octets->raft-message (gr8s.node.v1::payload request))))
        (unless (equal peer (getf message :from))
          (pki-fail "member-identity-mismatch" "Raft member ~A sent a message as another member" peer))
        message)
      (octets->raft-message (gr8s.node.v1::payload request))))

(defun make-raft-channel (credentials host port timeout)
  "Open a channel to a peer, authenticating both ends when this member uses TLS."
  (if credentials
      (make-node-tls-channel host port :timeout timeout
                                       :ca-certificate-path (raft-credentials-ca-path credentials)
                                       :certificate-path (raft-credentials-certificate-path credentials)
                                       :private-key-path (raft-credentials-key-path credentials))
      (ag-grpc:make-channel host port :timeout timeout)))
