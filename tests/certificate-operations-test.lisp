;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Contract tests for read-only certificate inventory and expiry reporting.

(in-package #:gr8s/tests)

(in-suite gr8s)

(test certificate-status-cli-options-are-explicit
  (let ((options (parse-cli-options
                  '("certificate" "status" "--state-directory" "/srv/gr8s"
                    "--output" "json" "--warn-within" "45d"))))
    (is (eq :certificate-status (getf options :command)))
    (is (equal "/srv/gr8s" (getf options :state-directory)))
    (is (eq :json (getf options :output-format)))
    (is (= (* 45 86400) (getf options :warn-within))))
  (signals error (parse-cli-options '("certificate" "unknown")))
  (signals error (parse-cli-options '("certificate" "status" "--warn-within" "soon")))
  (signals error (parse-cli-options '("certificate" "status" "--output" "yaml"))))

(test certificate-leaf-rotation-cli-options-match-k3s-shape
  (let ((options (parse-cli-options
                  '("certificate" "rotate" "--state-directory" "/srv/gr8s"
                    "--service" "api-server,admin"))))
    (is (eq :certificate-rotate (getf options :command)))
    (is (equal "/srv/gr8s" (getf options :state-directory)))
    (is (equal '("api-server" "admin") (getf options :services))))
  (signals error (parse-cli-options '("certificate" "rotate" "--service" "unknown"))))

(test staged-authority-rotation-selects-online-kubeconfig-mode
  (let ((ca (parse-cli-options
             '("certificate" "rotate-ca" "prepare" "--kubeconfig" "/tmp/admin.conf")))
        (sa (parse-cli-options
             '("certificate" "service-account-key" "promote"
               "--kubeconfig" "/tmp/admin.conf"))))
    (is (eq :certificate-ca-prepare (getf ca :command)))
    (is (equal "/tmp/admin.conf" (getf ca :kubeconfig)))
    (is (eq :certificate-service-account-key-promote (getf sa :command)))
    (is (equal "/tmp/admin.conf" (getf sa :kubeconfig)))))

(test certificate-leaf-rotation-is-selective-and-atomic-at-pair-boundaries
  (with-temporary-store (store directory)
    (declare (ignore store))
    (let* ((pki-directory (merge-pathnames "pki/" directory))
           (pki (gr8s:ensure-cluster-pki pki-directory))
           (api (gr8s::ensure-kubernetes-api-credentials pki :addresses '("192.0.2.10")))
           (admin (gr8s::ensure-admin-client-credentials pki))
           (api-key (merge-pathnames "kubernetes-api.key" pki-directory))
           (api-before (uiop:read-file-string api))
           (api-key-before (uiop:read-file-string api-key))
           (admin-before (uiop:read-file-string admin)))
      (is (= 0 (gr8s.server::run-certificate-rotation
                (list :state-directory (namestring directory)
                      :services '("api-server")
                      :api-addresses '("192.0.2.10")))))
      (is (not (string= api-before (uiop:read-file-string api))))
      (is (not (string= api-key-before (uiop:read-file-string api-key))))
      (is (string= admin-before (uiop:read-file-string admin)))
      (let ((leaf (first (pure-tls:load-certificate-chain api))))
        (pure-tls::verify-certificate-chain
         (list leaf) (list (gr8s::cluster-pki-ca-certificate pki))
         :purpose :server-auth :trust-anchor-mode :replace)
        (is (pure-tls::verify-hostname leaf "192.0.2.10"))))))

(test failed-leaf-certificate-replacement-keeps-the-old-key-pair-usable
  (with-temporary-store (store directory)
    (declare (ignore store))
    (let* ((pki (gr8s:ensure-cluster-pki directory))
           (certificate (gr8s::ensure-kubernetes-api-credentials pki))
           (key (merge-pathnames "kubernetes-api.key" directory))
           (certificate-before (uiop:read-file-string certificate))
           (key-before (uiop:read-file-string key))
           (original (symbol-function 'gr8s::write-private-text-atomically)))
      (unwind-protect
           (progn
             (setf (symbol-function 'gr8s::write-private-text-atomically)
                   (lambda (path text)
                     (if (equal (pathname path) certificate)
                         (error "injected leaf write failure")
                         (funcall original path text))))
             (signals error
               (gr8s::ensure-kubernetes-api-credentials
                pki :renew-within most-positive-fixnum :rotate-key t)))
        (setf (symbol-function 'gr8s::write-private-text-atomically) original))
      (is (string= certificate-before (uiop:read-file-string certificate)))
      (is (string= key-before (uiop:read-file-string key)))
      (let ((leaf (first (pure-tls:load-certificate-chain certificate))))
        (pure-tls::verify-certificate-chain
         (list leaf) (list (gr8s::cluster-pki-ca-certificate pki))
         :purpose :server-auth :trust-anchor-mode :replace)
        (is-true (pure-tls::verify-hostname leaf "127.0.0.1"))))))

(test interrupted-leaf-key-replacement-finishes-from-durable-intent
  (with-temporary-store (store directory)
    (declare (ignore store))
    (let* ((pki (gr8s:ensure-cluster-pki directory))
           (certificate (gr8s::ensure-kubernetes-api-credentials pki))
           (key (merge-pathnames "kubernetes-api.key" directory))
           (old-certificate (uiop:read-file-string certificate))
           (old-key (uiop:read-file-string key)))
      (gr8s::ensure-kubernetes-api-credentials
       pki :renew-within most-positive-fixnum :rotate-key t)
      (let* ((new-certificate (uiop:read-file-string certificate))
             (new-key (uiop:read-file-string key))
             (manifest (gr8s::leaf-rotation-manifest-path certificate)))
        (gr8s::write-private-text-atomically certificate old-certificate)
        (gr8s::write-private-text-atomically key old-key)
        (gr8s::write-private-text-atomically
         manifest
         (com.inuoe.jzon:stringify
          (gr8s.resources::core-object
           "format" "gr8s-leaf-rotation" "version" 1
           "key" new-key "certificate" new-certificate)))
        ;; Model SIGKILL after the first replacement: no condition handler ran.
        (gr8s::write-private-text-atomically key new-key)
        (gr8s::ensure-kubernetes-api-credentials pki :renew-within 0)
        (is (string= new-key (uiop:read-file-string key)))
        (is (string= new-certificate (uiop:read-file-string certificate)))
        (is-false (probe-file manifest))))))

(test expiring-api-and-admin-leaves-renew-on-ensure
  (with-temporary-store (store directory)
    (declare (ignore store))
    (let* ((pki (gr8s:ensure-cluster-pki directory))
           (api (gr8s::ensure-kubernetes-api-credentials pki))
           (admin (gr8s::ensure-admin-client-credentials pki))
           (api-before (uiop:read-file-string api))
           (admin-before (uiop:read-file-string admin))
           (api-key (merge-pathnames "kubernetes-api.key" directory))
           (admin-key (merge-pathnames "admin.key" directory))
           (api-key-before (uiop:read-file-string api-key))
           (admin-key-before (uiop:read-file-string admin-key))
           (force-within (* 2 365 86400)))
      (gr8s::ensure-kubernetes-api-credentials pki :renew-within force-within)
      (gr8s::ensure-admin-client-credentials pki :renew-within force-within)
      (is (not (string= api-before (uiop:read-file-string api))))
      (is (not (string= admin-before (uiop:read-file-string admin))))
      (is (string= api-key-before (uiop:read-file-string api-key)))
      (is (string= admin-key-before (uiop:read-file-string admin-key))))))

(test certificate-rotation-selects-internal-server-and-kubelet-client-roles
  (with-temporary-store (store directory)
    (declare (ignore store))
    (let* ((pki (gr8s:ensure-cluster-pki (merge-pathnames "pki/" directory)))
           (node-server (gr8s::ensure-node-server-credentials pki))
           (kubelet-client
             (gr8s.apiserver::ensure-apiserver-kubelet-client-credentials pki))
           (node-before (uiop:read-file-string node-server))
           (client-before (uiop:read-file-string kubelet-client)))
      (gr8s.server::run-certificate-rotation
       (list :state-directory directory :services '("node-server")))
      (is (not (string= node-before (uiop:read-file-string node-server))))
      (is (string= client-before (uiop:read-file-string kubelet-client)))
      (gr8s.server::run-certificate-rotation
       (list :state-directory directory :services '("apiserver-kubelet-client")))
      (is (not (string= client-before (uiop:read-file-string kubelet-client)))))))

(test explicit-raft-member-rotation-replaces-key-and-certificate
  (with-temporary-store (store directory)
    (declare (ignore store))
    (let ((pki-directory (merge-pathnames "pki/" directory)))
      (gr8s.security::ensure-raft-founder-credentials pki-directory "member-a")
      (let* ((certificate (gr8s.security::raft-member-certificate-path pki-directory))
           (key (gr8s.security::raft-member-key-path pki-directory))
           (certificate-before (uiop:read-file-string certificate))
           (key-before (uiop:read-file-string key)))
      (is (= 0 (gr8s.server::run-certificate-rotation
                (list :state-directory directory :services '("raft-member")))))
      (is (not (string= certificate-before (uiop:read-file-string certificate))))
      (is (not (string= key-before (uiop:read-file-string key))))
      (let ((credentials (gr8s.security::load-raft-credentials pki-directory)))
        (gr8s.security::verify-node-server-certificate
         (first (pure-tls:load-certificate-chain certificate))
         (gr8s.security::raft-credentials-ca credentials)))))))

(test staged-ca-rotation-keeps-old-trust-until-old-leaves-are-reissued
  (with-temporary-store (store directory)
    (declare (ignore store))
    (let* ((pki-root (merge-pathnames "pki/" directory))
           (pki (gr8s:ensure-cluster-pki pki-root))
           (old-fingerprint (gr8s::cluster-pki-ca-fingerprint pki))
           (api (gr8s::ensure-kubernetes-api-credentials pki))
           (admin (gr8s::ensure-admin-client-credentials pki)))
      (gr8s.server::prepare-cluster-ca-rotation pki-root)
      (is (equal "prepared"
                 (gethash "stage"
                          (gr8s.server::read-cluster-ca-transition-manifest pki-root))))
      (let ((prepared (gr8s:ensure-cluster-pki pki-root)))
        (is (equal old-fingerprint (gr8s::cluster-pki-ca-fingerprint prepared)))
        (is (= 2 (length (gr8s::cluster-pki-trust-certificates prepared)))))
      (gr8s.server::promote-cluster-ca-rotation pki-root)
      (is (equal "promoted"
                 (gethash "stage"
                          (gr8s.server::read-cluster-ca-transition-manifest pki-root))))
      (let ((promoted (gr8s:ensure-cluster-pki pki-root)))
        (is (not (equal old-fingerprint (gr8s::cluster-pki-ca-fingerprint promoted))))
        (is (= 2 (length (gr8s::cluster-pki-trust-certificates promoted))))
        (is (equal "system:admin"
                   (gr8s::api-identity-username
                    (gr8s::certificate-api-identity
                     (pure-tls:load-certificate-chain admin)
                     (gr8s::cluster-pki-trust-certificates promoted)))))
        (signals error (gr8s.server::finalize-cluster-ca-rotation pki-root :store-directory directory))
        (gr8s::ensure-kubernetes-api-credentials promoted :renew-within most-positive-fixnum)
        (gr8s::ensure-admin-client-credentials promoted :renew-within most-positive-fixnum)
        (gr8s.server::finalize-cluster-ca-rotation pki-root :store-directory directory)
        (is (equal "idle"
                   (gethash "stage"
                            (gr8s.server::read-cluster-ca-transition-manifest pki-root))))
        (let ((final (gr8s:ensure-cluster-pki pki-root)))
          (is (= 1 (length (gr8s::cluster-pki-trust-certificates final))))
          (is (not (probe-file (merge-pathnames "pki/pki/cluster-ca-retiring.crt"
                                                directory))))
          (is (probe-file api)))))))

(test interrupted-ca-promotion-recovers-from-the-versioned-manifest
  (with-temporary-store (store directory)
    (declare (ignore store))
    (let ((pki-root (merge-pathnames "pki/" directory)))
      (gr8s:ensure-cluster-pki pki-root)
    (gr8s.server::prepare-cluster-ca-rotation pki-root)
    (let* ((active-key (merge-pathnames "pki/pki/cluster-ca.key" directory))
           (original (symbol-function 'gr8s::write-private-text-atomically))
           (injected nil))
      (unwind-protect
           (progn
             (setf (symbol-function 'gr8s::write-private-text-atomically)
                   (lambda (path text)
                     (when (and (not injected) (equal (pathname path) active-key))
                       (setf injected t)
                       (error "injected promotion interruption"))
                     (funcall original path text)))
             (signals error (gr8s.server::promote-cluster-ca-rotation pki-root)))
        (setf (symbol-function 'gr8s::write-private-text-atomically) original))
      (is (equal "promoting"
                 (gethash "stage"
                          (gr8s.server::read-cluster-ca-transition-manifest pki-root))))
      (is (stringp (gr8s.server::promote-cluster-ca-rotation pki-root)))
      (is (equal "promoted"
                 (gethash "stage"
                          (gr8s.server::read-cluster-ca-transition-manifest pki-root))))
      (let ((pki (gr8s:ensure-cluster-pki pki-root)))
        (is (= 2 (length (gr8s::cluster-pki-trust-certificates pki)))))))))

(test interrupted-ca-prepare-and-finalize-resume-idempotently
  (with-temporary-store (store directory)
    (declare (ignore store))
    (gr8s:ensure-cluster-pki (merge-pathnames "pki/" directory))
    (let* ((active-certificate (merge-pathnames "pki/pki/cluster-ca.crt" directory))
           (original (symbol-function 'gr8s::write-private-text-atomically))
           (injected nil))
      (flet ((interrupt-next-active-write ()
               (setf injected nil
                     (symbol-function 'gr8s::write-private-text-atomically)
                     (lambda (path text)
                       (when (and (not injected) (equal (pathname path) active-certificate))
                         (setf injected t)
                         (error "injected CA transition interruption"))
                       (funcall original path text)))))
        (unwind-protect
             (progn
               (interrupt-next-active-write)
               (signals error (gr8s.server::prepare-cluster-ca-rotation (merge-pathnames "pki/" directory)))
               (setf (symbol-function 'gr8s::write-private-text-atomically) original)
               (is (stringp (gr8s.server::prepare-cluster-ca-rotation (merge-pathnames "pki/" directory))))
               (gr8s.server::promote-cluster-ca-rotation (merge-pathnames "pki/" directory))
               (interrupt-next-active-write)
               (signals error (gr8s.server::finalize-cluster-ca-rotation (merge-pathnames "pki/" directory) :store-directory directory)))
          (setf (symbol-function 'gr8s::write-private-text-atomically) original)))
      (is-true (gr8s.server::finalize-cluster-ca-rotation (merge-pathnames "pki/" directory) :store-directory directory))
      (is (equal "idle"
                 (gethash "stage"
                          (gr8s.server::read-cluster-ca-transition-manifest (merge-pathnames "pki/" directory))))))))

(test authenticated-node-session-rolls-dual-trust-without-stranding-old-leaves
  (with-temporary-store (store directory)
    (declare (ignore store))
    (let* ((pki-root (merge-pathnames "pki/" directory))
           (pki (gr8s:ensure-cluster-pki pki-root))
           (agent-directory (merge-pathnames "agent/" directory))
           (agent-ca (merge-pathnames "ca.crt" agent-directory))
           (agent-cert (merge-pathnames "node.crt" agent-directory))
           (agent-key (merge-pathnames "node.key" agent-directory)))
      (ensure-directories-exist agent-ca)
      (gr8s.apiserver::issue-cluster-certificate
       pki agent-cert agent-key "system:node:worker-a" "system:nodes")
      (gr8s::write-private-text-atomically
       agent-ca (uiop:read-file-string (gr8s::cluster-pki-ca-certificate-path pki)))
      (gr8s.server::prepare-cluster-ca-rotation pki-root)
      (flet ((hello (text)
               (make-instance 'gr8s.node.v1::server-hello
                              :cluster-ca-bundle
                              (babel:string-to-octets text :encoding :utf-8))))
        (gr8s.agent::install-agent-cluster-ca-bundle
         (hello (uiop:read-file-string (gr8s::cluster-pki-ca-certificate-path pki)))
         agent-ca agent-cert)
        (is (= 2 (length (pure-tls:load-certificate-chain agent-ca))))
        (gr8s.server::promote-cluster-ca-rotation pki-root)
        (let* ((promoted (gr8s:ensure-cluster-pki pki-root))
               (new-only (gr8s.server::certificate-pem
                          (gr8s::cluster-pki-ca-certificate promoted)))
               (before (uiop:read-file-string agent-ca)))
          (signals error
            (gr8s.agent::install-agent-cluster-ca-bundle
             (hello new-only) agent-ca agent-cert))
          (is (string= before (uiop:read-file-string agent-ca)))
          (gr8s.apiserver::issue-cluster-certificate
           promoted agent-cert agent-key "system:node:worker-a" "system:nodes")
          (gr8s.agent::install-agent-cluster-ca-bundle
           (hello new-only) agent-ca agent-cert)
          (is (= 1 (length (pure-tls:load-certificate-chain agent-ca)))))))))

(test authenticated-node-session-renews-an-old-ca-leaf-before-dropping-trust
  (with-temporary-store (store directory)
    (declare (ignore store))
    (let* ((pki-root (merge-pathnames "pki/" directory))
           (pki (gr8s:ensure-cluster-pki pki-root))
           (agent-directory (merge-pathnames "renewing-agent/" directory))
           (agent-ca (merge-pathnames "ca.crt" agent-directory))
           (agent-cert (merge-pathnames "node.crt" agent-directory))
           (agent-key (merge-pathnames "node.key" agent-directory)))
      (ensure-directories-exist agent-ca)
      (let ((csr (gr8s:generate-node-key-and-csr "worker-a" agent-key)))
        (multiple-value-bind (subject spki)
            (gr8s.security::parse-and-verify-node-csr csr "worker-a")
          (declare (ignore subject))
          (gr8s::write-private-text-atomically
           agent-cert
           (pure-tls/acme::wrap-pem
            "CERTIFICATE"
            (gr8s.security::node-certificate-der
             pki (pure-tls/acme::encode-subject "worker-a") spki))))
        (gr8s::write-private-text-atomically
         agent-ca (uiop:read-file-string (gr8s::cluster-pki-ca-certificate-path pki)))
        (gr8s.server::prepare-cluster-ca-rotation pki-root)
        (gr8s.server::promote-cluster-ca-rotation pki-root)
        (let* ((promoted (gr8s:ensure-cluster-pki pki-root))
               (old-leaf (gr8s.security::certificate-from-pem
                          (uiop:read-file-string agent-cert)))
               (renewed
                 (gr8s.security::renew-authenticated-node-csr
                  promoted "worker-a" old-leaf csr))
               (hello
                 (make-instance
                  'gr8s.node.v1::server-hello
                  :cluster-ca-bundle
                  (babel:string-to-octets
                   (uiop:read-file-string
                    (gr8s::cluster-pki-ca-certificate-path promoted))
                   :encoding :utf-8)
                  :renewed-node-certificate
                  (babel:string-to-octets renewed :encoding :utf-8))))
          (is-true
           (gr8s.security::node-certificate-needs-active-ca-renewal-p
            promoted old-leaf))
          (is-true
           (gr8s.agent::install-agent-session-credentials
            hello agent-ca agent-cert))
          (is-true
           (gr8s:verify-node-certificate
            promoted (uiop:read-file-string agent-cert) "worker-a"))
          (is-false
           (gr8s.security::node-certificate-needs-active-ca-renewal-p
            promoted
            (gr8s.security::certificate-from-pem
             (uiop:read-file-string agent-cert))))
          (is (= 2 (length (pure-tls:load-certificate-chain agent-ca))))
          (gr8s.server::finalize-cluster-ca-rotation pki-root :store-directory directory)
          (is-false
           (gr8s.agent::install-agent-session-credentials
            (make-instance
             'gr8s.node.v1::server-hello
             :cluster-ca-bundle
             (babel:string-to-octets
              (uiop:read-file-string
               (gr8s::cluster-pki-ca-certificate-path
                (gr8s:ensure-cluster-pki pki-root)))
              :encoding :utf-8))
            agent-ca agent-cert))
          (is (= 1 (length (pure-tls:load-certificate-chain agent-ca)))))))))

(test ha-pki-authority-is-encrypted-replicated-and-extracted
  (with-temporary-store (leader leader-root)
    (with-temporary-store (follower follower-root)
      (let ((leader-pki-root (merge-pathnames "pki/" leader-root)))
        (gr8s:ensure-cluster-pki leader-pki-root)
        (let ((raft-root (merge-pathnames "raft/" leader-pki-root)))
        (gr8s.security::ensure-raft-founder-credentials raft-root "cp1")
        (dolist (relative '("pki/cluster-ca.crt" "pki/cluster-ca.key"))
          (let ((source (merge-pathnames relative raft-root))
                (target (merge-pathnames relative (merge-pathnames "pki/raft/" follower-root))))
            (gr8s::write-private-text-atomically target (uiop:read-file-string source)))))
        (gr8s.server::prepare-cluster-ca-rotation leader-pki-root))
      (let* ((envelope (gr8s.resources::publish-pki-authority leader))
             (durable
               (multiple-value-bind (state)
                   (gr8s.resources::read-durable-core-state leader)
                 (com.inuoe.jzon:stringify state))))
        (is-false (search "PRIVATE KEY" (com.inuoe.jzon:stringify envelope)))
        (is-false (search "PRIVATE KEY" durable))
        (gr8s.resources::install-core-state-blob follower durable)
        (is-true (gr8s.resources::current-pki-authority-envelope follower)
                 "replicated resources include the authority envelope; keys: ~S"
                 (loop for key being the hash-keys of (gr8s::pod-store-resources follower)
                       collect key))
        (let ((reopened (gr8s:open-store follower-root)))
          (is-true (gr8s.resources::current-pki-authority-envelope reopened)
                   "the encrypted authority record survives a store restart")
          (gr8s.resources::reconcile-pki-authority reopened))
        (gr8s.resources::reconcile-pki-authority follower)
        (let ((notifications 0)
              (observer nil))
          (setf observer (lambda () (incf notifications)))
          (gr8s.resources::add-pki-authority-observer follower observer)
          (gr8s.resources::reconcile-pki-authority follower)
          (is (= 0 notifications)
              "reconciling an unchanged authority does not refresh TLS consumers")
        (dolist (relative '("pki/pki/cluster-ca.crt" "pki/pki/cluster-ca.key"
                            "pki/pki/cluster-ca-next.crt" "pki/pki/cluster-ca-next.key"
                            "pki/pki/cluster-ca-rotation.json"))
          (is-true (probe-file (merge-pathnames relative leader-root))
                   "leader retained ~A under ~A" relative leader-root)
          (is-true (probe-file (merge-pathnames relative follower-root))
                   "follower extracted ~A under ~A" relative follower-root)
          (is (string=
               (uiop:read-file-string (merge-pathnames relative leader-root))
               (uiop:read-file-string (merge-pathnames relative follower-root)))))
        (gr8s.server::update-replicated-pki-authority leader "ca" :promote)
        (let ((promoted
                (multiple-value-bind (state)
                    (gr8s.resources::read-durable-core-state leader)
                  (com.inuoe.jzon:stringify state))))
          (gr8s.resources::install-core-state-blob follower promoted)
          (gr8s.resources::reconcile-pki-authority follower)
          (is (= 1 notifications)
              "installing a changed authority refreshes TLS consumers exactly once")
          (is-false (probe-file (merge-pathnames "pki/pki/cluster-ca-next.key" follower-root)))
          (dolist (relative '("pki/pki/cluster-ca.crt" "pki/pki/cluster-ca.key"
                              "pki/pki/cluster-ca-retiring.crt" "pki/pki/cluster-ca-retiring.key"
                              "pki/pki/cluster-ca-rotation.json"))
            (is (string=
                 (uiop:read-file-string (merge-pathnames relative leader-root))
                 (uiop:read-file-string (merge-pathnames relative follower-root)))))
          (gr8s.resources::remove-pki-authority-observer follower observer)
          (gr8s.resources::publish-pki-authority follower)
          (is (= 1 notifications)
              "a removed observer is not called")))))))

(test ca-finalize-requires-every-registered-agent-to-reconnect-under-active-ca
  (with-temporary-store (store directory)
    (let* ((pki-root (merge-pathnames "pki/" directory))
           (pki (gr8s:ensure-cluster-pki pki-root))
           (old-fingerprint (gr8s::cluster-pki-ca-fingerprint pki)))
      (gr8s:register-node
       store (gr8s.model:make-node-record
              :id "worker-a-id" :name "worker-a" :pod-cidr "10.80.1.0/24"))
      (gr8s::record-node-certificate-issuer store "worker-a" old-fingerprint)
      (gr8s.server::prepare-cluster-ca-rotation pki-root)
      (gr8s.server::promote-cluster-ca-rotation pki-root)
      (let ((promoted (gr8s:ensure-cluster-pki pki-root)))
        (gr8s::ensure-kubernetes-api-credentials promoted :renew-within most-positive-fixnum)
        (gr8s::ensure-admin-client-credentials promoted :renew-within most-positive-fixnum)
        (signals error (gr8s.server::finalize-cluster-ca-rotation pki-root :store-directory directory))
        (gr8s::record-node-certificate-issuer
         store "worker-a" (gr8s::cluster-pki-ca-fingerprint promoted))
        (is-true (gr8s.server::finalize-cluster-ca-rotation pki-root :store-directory directory))))))

(test ca-rotation-cli-uses-explicit-stages
  (dolist (stage '("prepare" "promote" "finalize"))
    (let ((options (parse-cli-options
                    (list "certificate" "rotate-ca" stage
                          "--state-directory" "/srv/gr8s"))))
      (is (eq (intern (format nil "CERTIFICATE-CA-~A" (string-upcase stage)) :keyword)
              (getf options :command)))))
  (signals error (parse-cli-options '("certificate" "rotate-ca" "now"))))

(test certificate-mutations-refuse-a-live-serve-state-directory
  (with-temporary-store (store directory)
    (declare (ignore store))
    (gr8s.server::call-with-serve-state-ownership
     (list :state-directory directory)
     (lambda ()
       (signals error
         (gr8s.server::run-certificate-rotation
          (list :state-directory directory :services '("admin"))))
       (signals error
         (gr8s.server::run-cluster-ca-rotation
          (list :state-directory directory :command :certificate-ca-prepare)))))))

(test service-account-signing-key-rotation-cli-options-are-explicit
  (dolist (stage '(("prepare" :certificate-service-account-key-prepare)
                   ("promote" :certificate-service-account-key-promote)
                   ("finalize" :certificate-service-account-key-finalize)))
    (let ((options (parse-cli-options
                    (list "certificate" "service-account-key" (first stage)
                          "--state-directory" "/srv/gr8s"))))
      (is (eq (second stage) (getf options :command)))
      (is (equal "/srv/gr8s" (getf options :state-directory)))))
  (signals error (parse-cli-options '("certificate" "service-account-key" "replace")))
  (signals error (parse-cli-options '("certificate" "service-account-key" "prepare" "--bogus"))))

(test service-account-signing-key-rotation-dispatches-through-the-public-cli
  (with-temporary-store (store directory)
    (gr8s::load-service-account-signing-key store)
    (dolist (stage '("prepare" "promote" "finalize"))
      (let ((output
              (with-output-to-string (*standard-output*)
                (is (= 0 (gr8s::main-with-environment
                          (list "certificate" "service-account-key" stage
                                "--state-directory" (namestring directory))
                          (constantly nil) (constantly 99)))))))
        (is (plusp (length (string-trim '(#\Newline) output))))))
    (let ((record (com.inuoe.jzon:parse
                   (gr8s::service-account-signing-key-path store))))
      (is (= 1 (length (gethash "keys" record))))
      (is (null (gethash "preparedKid" record))))))

(test certificate-inventory-is-read-only-deterministic-and-classifies-expiry
  (with-temporary-store (store directory)
    (declare (ignore store))
    (let* ((pki (gr8s:ensure-cluster-pki (merge-pathnames "pki/" directory)))
           (ca-path (gr8s:cluster-pki-ca-certificate-path pki))
           (ca (first (pure-tls:load-certificate-chain ca-path)))
           (not-before (pure-tls:certificate-not-before ca))
           (not-after (pure-tls:certificate-not-after ca))
           (before (uiop:read-file-string ca-path))
           (healthy (gr8s.server::certificate-inventory directory :now (get-universal-time)
                                                   :warn-within 1))
           (warning (gr8s.server::certificate-inventory directory :now (get-universal-time)
                                                   :warn-within (* 11 365 86400)))
           (expired (gr8s.server::certificate-inventory directory :now (1+ not-after)
                                                   :warn-within 1))
           (future (gr8s.server::certificate-inventory directory :now (1- not-before)
                                                  :warn-within 1)))
      (flet ((ca-record (records)
               (find "cluster-ca" records :key (lambda (record) (getf record :name))
                                         :test #'string=)))
        (is (eq :healthy (getf (ca-record healthy) :severity)))
        (is (eq :warning (getf (ca-record warning) :severity)))
        (is (eq :expired (getf (ca-record expired) :severity)))
        (is (eq :not-yet-valid (getf (ca-record future) :severity)))
        (is (eq :missing (getf (find "kubernetes-api" healthy
                                          :key (lambda (record) (getf record :name))
                                          :test #'string=)
                                    :severity))))
      (is (string= before (uiop:read-file-string ca-path)))
      (is (equal (mapcar (lambda (record) (getf record :name)) healthy)
                 (sort (copy-list (mapcar (lambda (record) (getf record :name)) healthy))
                       #'string<)))
      (is (string= (gr8s.server::certificate-inventory-json healthy)
                   (gr8s.server::certificate-inventory-json healthy))))))

(test certificate-inventory-reports-invalid-certificates-and-signing-key
  (with-temporary-store (store directory)
    (gr8s::load-service-account-signing-key store)
    (let ((bad (merge-pathnames "pki/kubernetes-api.crt" directory)))
      (with-open-file (stream bad :direction :output :if-exists :supersede)
        (write-line "not a certificate" stream))
      (let* ((records (gr8s.server::certificate-inventory directory))
             (api (find "kubernetes-api" records :key (lambda (record) (getf record :name))
                                                   :test #'string=))
             (signer (find "service-account-signing-key" records
                           :key (lambda (record) (getf record :name)) :test #'string=)))
        (is (eq :invalid (getf api :severity)))
        (is (eq :key (getf signer :kind)))
        (is (stringp (getf signer :fingerprint)))))))

(test certificate-inventory-covers-standalone-agent-layout
  (with-temporary-store (store directory)
    (declare (ignore store))
    (let* ((pki (gr8s:ensure-cluster-pki directory))
           (ca-path (gr8s:cluster-pki-ca-certificate-path pki)))
      (uiop:copy-file ca-path (merge-pathnames "ca.crt" directory))
      (uiop:copy-file ca-path (merge-pathnames "node.crt" directory))
      (let ((records (gr8s.server::certificate-inventory directory)))
        (is (eq :healthy
                (getf (find "agent-standalone-trust-anchor" records
                            :key (lambda (record) (getf record :name)) :test #'string=)
                      :severity)))
        (is (eq :healthy
                (getf (find "node-client" records
                            :key (lambda (record) (getf record :name)) :test #'string=)
                      :severity)))))))

(test certificate-inventory-covers-combined-agent-trust-anchor
  (with-temporary-store (store directory)
    (declare (ignore store))
    (let* ((pki (gr8s:ensure-cluster-pki directory))
           (ca-path (gr8s:cluster-pki-ca-certificate-path pki))
           (agent-ca (merge-pathnames "agent/ca.crt" directory)))
      (ensure-directories-exist agent-ca)
      (uiop:copy-file ca-path agent-ca)
      (let* ((records (gr8s.server::certificate-inventory directory))
             (anchor (find "agent-trust-anchor" records
                           :key (lambda (record) (getf record :name)) :test #'string=)))
        (is (eq :healthy (getf anchor :severity)))
        (is (string= (namestring agent-ca) (getf anchor :path)))))))

(test certificate-inventory-bounds-signing-key-input
  (with-temporary-store (store directory)
    (declare (ignore store))
    (let ((path (merge-pathnames "pki/service-account-signing-key.json" directory)))
      (ensure-directories-exist path)
      (with-open-file (stream path :direction :output :if-exists :supersede)
        (write-string (make-string (1+ (* 1024 1024)) :initial-element #\x) stream))
      (let* ((records (gr8s.server::certificate-inventory directory))
             (signer (find "service-account-signing-key" records
                           :key (lambda (record) (getf record :name)) :test #'string=)))
        (is (eq :invalid (getf signer :severity)))
        (is (search "exceeds" (getf signer :error)))))))

(test certificate-status-table-and-json-have-stable-machine-fields
  (with-temporary-store (store directory)
    (declare (ignore store))
    (gr8s:ensure-cluster-pki (merge-pathnames "pki/" directory))
    (let* ((records (gr8s.server::certificate-inventory directory))
           (table (with-output-to-string (stream)
                    (gr8s.server::write-certificate-inventory-table records stream)))
           (json (gr8s.server::certificate-inventory-json records))
           (parsed (com.inuoe.jzon:parse json)))
      (is (search "NAME" table))
      (is (search "cluster-ca" table))
      (is (vectorp parsed))
      (let ((ca (find "cluster-ca" parsed :key (lambda (record) (gethash "name" record))
                                           :test #'string=)))
        (is (equal "certificate" (gethash "kind" ca)))
        (is (gethash "notAfter" ca))
        (is (gethash "severity" ca))))))

(test certificate-status-dispatches-through-the-public-cli
  (with-temporary-store (store directory)
    (declare (ignore store))
    (let* ((arguments (list "certificate" "status" "--state-directory"
                            (namestring directory) "--output" "json"))
           (before (directory (merge-pathnames "**/*" directory)))
           (output (with-output-to-string (*standard-output*)
                     (is (= 0 (gr8s::main-with-environment
                               arguments (constantly nil) (constantly 99)))))))
      (is (search "service-account-signing-key" output))
      (is (search "missing" output))
      (is (equal before (directory (merge-pathnames "**/*" directory)))))))
