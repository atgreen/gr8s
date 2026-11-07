;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
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

(in-package #:gr8s.security)

(defstruct raft-credentials
  "A member's TLS identity: file paths, the CA certificate and, on voters, the issuing PKI.
NODE-PKI is the control plane's own, whose CA is shared with voters it enrolls."
  ca-path certificate-path key-path ca pki node-pki)

(defparameter +raft-certificate-renewal-seconds+ (* 30 24 60 60)
  "How long before a member certificate expires its member starts trying to renew it.")

(defparameter +raft-renewal-check-seconds+ 3600
  "How often a member checks its certificate, so a failed renewal is soon tried again.")

(defun raft-tls-root (pki)
  "Return the Raft credentials directory within control-plane PKI's own."
  (merge-pathnames "raft/" (cluster-pki-root pki)))

(defun raft-ca-certificate-path (root)
  "Path under ROOT of the Raft cluster CA certificate, the trust anchor every member shares."
  (merge-pathnames "pki/cluster-ca.crt" root))
(defun raft-ca-key-path (root)
  "Path under ROOT of the Raft cluster CA private key. Only a voter holds it; its presence is how the credentials carry a PKI."
  (merge-pathnames "pki/cluster-ca.key" root))
(defun raft-member-certificate-path (root)
  "Path under ROOT of this member's own certificate. Written last on enrollment, so its presence means enrollment is complete."
  (merge-pathnames "member.crt" root))
(defun raft-member-key-path (root)
  "Path under ROOT of this member's private key."
  (merge-pathnames "member.key" root))

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
         (node-pki (and credentials (raft-credentials-node-pki credentials)))
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
                                           "")
                       :node-ca-certificate
                       (if (and voter node-pki)
                           (uiop:read-file-string (cluster-pki-ca-certificate-path node-pki))
                           "")
                       :node-ca-private-key
                       (if (and voter node-pki)
                           (uiop:read-file-string (cluster-pki-ca-private-key-path node-pki))
                           "")
                       :service-account-signing-key
                       (if (and voter node-pki)
                           (uiop:read-file-string
                            (service-account-signing-key-path-under-pki-root
                             (cluster-pki-root node-pki)))
                           ""))))))

(defun install-shared-node-ca (node-root certificate-pem key-pem)
  "Store the cluster's node CA under NODE-ROOT, refusing to replace a different complete one,
because certificates it has already issued would stop working."
  (let ((certificate-path (raft-ca-certificate-path node-root))
        (key-path (raft-ca-key-path node-root))
        (incoming (pure-tls:certificate-fingerprint (certificate-from-pem certificate-pem))))
    (unless (and (probe-file certificate-path) (probe-file key-path)
                 (equalp incoming (pure-tls:certificate-fingerprint
                                   (first (pure-tls:load-certificate-chain certificate-path)))))
      (when (and (probe-file certificate-path) (probe-file key-path))
        (pki-fail "node-ca-conflict"
                  "~A already has a different cluster CA; join with a new state directory" node-root))
      (write-private-text-atomically key-path key-pem)
      (write-private-text-atomically certificate-path certificate-pem))))

(defun enroll-raft-member (root member-id host port &key node-name token ca-pin (role :voter) node-root)
  "Obtain MEMBER-ID's credentials from the member at HOST:PORT and store them under ROOT.
A voter given NODE-ROOT also stores the cluster's shared node CA there."
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
           (when (and node-root (plusp (length (gr8s.node.v1::node-ca-certificate response))))
             (install-shared-node-ca node-root (gr8s.node.v1::node-ca-certificate response)
                                     (gr8s.node.v1::node-ca-private-key response)))
           (when (and node-root
                      (plusp (length (gr8s.node.v1::service-account-signing-key response))))
             (install-shared-service-account-signing-key
              node-root (gr8s.node.v1::service-account-signing-key response)))
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

(defun ensure-joining-control-plane-pki (node-root member-id host port &key node-name token ca-pin)
  "Enroll a joining control plane if needed, then return its PKI, which uses the cluster's node CA.
This must come first, or the control plane would create a node CA of its own."
  (ensure-raft-joiner-credentials (merge-pathnames "raft/" node-root) member-id host port
                                  :node-name node-name :token token :ca-pin ca-pin :node-root node-root)
  (ensure-cluster-pki node-root))

(defun raft-certificate-not-after (credentials)
  "Return when the member certificate currently on disk expires, as a universal time."
  (pure-tls::x509-certificate-validity-not-after
   (first (pure-tls:load-certificate-chain (raft-credentials-certificate-path credentials)))))

(defun raft-certificate-expiring-p (credentials now)
  "Return whether the member certificate is within its renewal period at universal time NOW."
  (< (- (raft-certificate-not-after credentials) now) +raft-certificate-renewal-seconds+))

(defun raft-member-handle-renew (member request context)
  "Issue a new certificate to the current member authenticated on CONTEXT's connection."
  (let* ((credentials (raft-member-credentials member))
         (pki (and credentials (raft-credentials-pki credentials))))
    (unless pki (pki-fail "renewal-disabled" "This Raft member can't renew others"))
    (let ((id (authenticate-raft-peer credentials context)))
      ;; A valid certificate alone isn't enough: a removed member's must run out.
      (unless (assoc id (bt:with-lock-held ((raft-member-lock member))
                          (raft-current-config (raft-member-node member)))
                     :test #'equal)
        (pki-fail "unknown-member" "~A isn't a member of this Raft cluster" id))
      (bt:with-lock-held ((cluster-pki-lock pki))
        (make-instance 'gr8s.node.v1::renew-member-response
                       :certificate (issue-raft-member-certificate
                                     pki id (gr8s.node.v1::certificate-request request)))))))

(defun request-raft-certificate-from-peers (member csr)
  "Return a new certificate chain from the first peer able to issue one, or signal why none did."
  (let* ((credentials (raft-member-credentials member))
         (node (raft-member-node member))
         (peers (bt:with-lock-held ((raft-member-lock member))
                  (loop for id being the hash-keys of (raft-node-peer-addresses node) using (hash-value address)
                        unless (equal id (raft-node-id node)) collect address)))
         (failure "this member knows no peers"))
    (dolist (address peers (pki-fail "renewal-failed" "No Raft member could renew this certificate: ~A" failure))
      (handler-case
          (let ((channel (make-raft-channel credentials (first address) (second address) 10)))
            (unwind-protect
                 (return (gr8s.node.v1::certificate
                          (gr8s.node.v1::raft-transport-renew-member
                           (gr8s.node.v1::make-raft-transport-stub channel)
                           (make-instance 'gr8s.node.v1::renew-member-request :certificate-request csr)
                           :timeout 10)))
              (ignore-errors (ag-grpc:channel-close channel))))
        ((or error sb-ext:timeout) (condition) (setf failure (princ-to-string condition)))))))

(defun renew-raft-member-certificate (member)
  "Replace MEMBER's certificate, keeping its key. New connections present it, and an old
one fails once its certificate expires and is then opened again with the new one."
  (let* ((credentials (raft-member-credentials member))
         (pki (raft-credentials-pki credentials))
         (id (raft-node-id (raft-member-node member)))
         (csr (generate-node-key-and-csr id (raft-credentials-key-path credentials)))
         ;; A voter holds the CA, so it can renew itself even after being offline past expiry.
         (chain (if pki
                    (bt:with-lock-held ((cluster-pki-lock pki))
                      (issue-raft-member-certificate pki id csr))
                    (request-raft-certificate-from-peers member csr))))
    (verify-node-server-certificate (certificate-from-pem chain) (raft-credentials-ca credentials))
    (write-private-text-atomically (raft-credentials-certificate-path credentials) chain)))

(defun raft-member-renew-if-needed (member &optional (now (get-universal-time)))
  "Renew MEMBER's certificate if it's due. A failure is reported and retried by the next check."
  (let ((credentials (raft-member-credentials member)))
    (when (raft-certificate-expiring-p credentials now)
      (handler-case (renew-raft-member-certificate member)
        ((or error sb-ext:timeout) (condition)
          (format *error-output* "gr8s Raft member ~A certificate expires in ~D days and couldn't be renewed: ~A~%"
                  (raft-node-id (raft-member-node member))
                  (floor (- (raft-certificate-not-after credentials) now) 86400) condition))))))

(defun raft-renewal-loop (member)
  "Check MEMBER's certificate now and then periodically, until the member stops."
  (loop while (raft-member-running member) do
    (raft-member-renew-if-needed member)
    (loop repeat +raft-renewal-check-seconds+
          while (raft-member-running member)
          do (sleep 1))))

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
