;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Serve the Kubernetes API over pure-tls with cluster service DNS/IP SANs,
;;;; token/certificate authentication and live RBAC checks.  The same server is
;;;; reached directly by administrators and through the in-cluster Service.

(in-package #:gr8s.apiserver)

(defparameter +kubernetes-api-dns-names+
  '("kubernetes" "kubernetes.default" "kubernetes.default.svc"
    "kubernetes.default.svc.cluster.local" "localhost"))

(defparameter +certificate-leaf-renewal-seconds+ (* 90 86400)
  "Renew locally owned one-year leaf certificates within this startup window.")

(defun certificate-renewal-due-p (path renew-within)
  "True when PATH's leaf expires within RENEW-WITHIN seconds or cannot be read."
  (handler-case
      (let ((leaf (first (pure-tls:load-certificate-chain path))))
        (or (null leaf)
            (<= (- (pure-tls:certificate-not-after leaf) (get-universal-time))
                renew-within)))
    (error () t)))

(defun kubernetes-api-addresses
    (addresses &optional (local-addresses (ignore-errors (gr8s.network::host-ipv4-addresses))))
  "Return the unique API ADDRESSES plus every local IPv4 address and the stable
Service and loopback addresses. Covering all local addresses (as k0s does) means
the server certificate verifies against whichever local address a client is
pointed at, so a kubeconfig that advertises one interface is not broken by the
server having picked a different one (podster-1v6)."
  (remove-duplicates (append addresses local-addresses '("10.96.0.1" "127.0.0.1"))
                     :test #'equal))

(defun ensure-kubernetes-api-credentials
    (pki &key (addresses nil) (renew-within +certificate-leaf-renewal-seconds+) rotate-key)
  "Create or validate a persisted Kubernetes API server identity under the cluster CA."
  (let ((certificate-path (merge-pathnames "kubernetes-api.crt" (cluster-pki-root pki)))
        (key-path (merge-pathnames "kubernetes-api.key" (cluster-pki-root pki)))
        (names (kubernetes-api-addresses addresses)))
    (bt:with-lock-held ((cluster-pki-lock pki))
      (finish-pending-leaf-rotation certificate-path key-path)
      (unless
          (and (probe-file certificate-path) (probe-file key-path)
               (not (certificate-renewal-due-p certificate-path renew-within))
               (handler-case
                   (let ((leaf (first (pure-tls:load-certificate-chain certificate-path))))
                     (pure-tls::verify-certificate-chain
                      (list leaf) (list (cluster-pki-ca-certificate pki))
                      :purpose :server-auth :trust-anchor-mode :replace)
                     (every (lambda (name) (pure-tls::verify-hostname leaf name) t)
                            (append names +kubernetes-api-dns-names+)))
                 (error () nil)))
        ;; Atomic replacement also migrates pre-HTTPS-only installations whose
        ;; certificate did not cover the externally selected listener address.
        (issue-cluster-certificate
         pki certificate-path key-path "kubernetes.default.svc" nil
         :server t :addresses names :dns-names +kubernetes-api-dns-names+
         :rotate-key rotate-key)))
    (values certificate-path key-path)))

(defun ensure-admin-client-credentials
    (pki &key (renew-within +certificate-leaf-renewal-seconds+) rotate-key)
  "Return the persisted system:admin client identity used by generated kubeconfigs."
  (let ((certificate (merge-pathnames "admin.crt" (cluster-pki-root pki)))
        (key (merge-pathnames "admin.key" (cluster-pki-root pki))))
    (bt:with-lock-held ((cluster-pki-lock pki))
      (finish-pending-leaf-rotation certificate key)
      (unless (and (probe-file certificate) (probe-file key)
                   (not (certificate-renewal-due-p certificate renew-within))
                   (handler-case
                       (progn
                         (pure-tls::verify-certificate-chain
                          (list (first (pure-tls:load-certificate-chain certificate)))
                          (list (cluster-pki-ca-certificate pki))
                          :purpose :client-auth :trust-anchor-mode :replace)
                         t)
                     (error () nil)))
        (issue-cluster-certificate pki certificate key "system:admin" "system:masters"
                                   :rotate-key rotate-key)))
    (values certificate key)))

(defun kubeconfig-user-name-p (name)
  "True when NAME may be a certificate user: a plain name, never system:*, so a
generated credential can't claim a built-in identity."
  (and (stringp name) (<= 1 (length name) 64)
       (not (eql 0 (search "system:" name)))
       (every (lambda (character) (or (alphanumericp character) (find character "._:@-"))) name)
       (alphanumericp (char name 0))))

(defun ensure-user-client-credentials (pki name)
  "Return the persisted client identity for user NAME, in no group: what it may do is
what RBAC grants NAME (podster-q35k)."
  (unless (kubeconfig-user-name-p name)
    (error "not a user name a kubeconfig may carry: ~S" name))
  (let* ((directory (merge-pathnames "users/" (cluster-pki-root pki)))
         (certificate (merge-pathnames (make-pathname :name name :type "crt") directory))
         (key (merge-pathnames (make-pathname :name name :type "key") directory)))
    (ensure-directories-exist directory)
    (bt:with-lock-held ((cluster-pki-lock pki))
      (finish-pending-leaf-rotation certificate key)
      (unless (and (probe-file certificate) (probe-file key)
                   (not (certificate-renewal-due-p certificate +certificate-leaf-renewal-seconds+)))
        (issue-cluster-certificate pki certificate key name nil)))
    (values certificate key)))

(defclass gr8s-in-cluster-acceptor (gr8s-acceptor)
  ((certificate :initarg :certificate :reader in-cluster-certificate)
   (private-key :initarg :private-key :reader in-cluster-private-key)
   (client-ca :initarg :client-ca :reader in-cluster-client-ca))
  (:documentation "Serve authenticated Kubernetes API requests over pure-tls."))

(defmethod hunchentoot:acceptor-ssl-p ((acceptor gr8s-in-cluster-acceptor))
  "Identify this acceptor as HTTPS for request URL handling."
  t)

(defvar *api-connection-certificate-chain* nil
  "TLS peer chain with verified key possession, scoped to one connection including keepalive requests.")

(defstruct api-certificate-cache
  second chain roots material depth identity)

(defvar *api-connection-certificate-cache* nil
  "One positive authentication result for this connection; never an authorization decision.")

(defun cached-api-certificate-identity (chain ca cache &optional (now (get-universal-time)))
  "Reuse verification only at the same time, with the same connection's certificate inputs.
The native Windows/macOS verifier uses its own clock, so it is never cached here.
TLS peer certificates and acceptor trust certificates are server-owned parsed objects;
retain their identities and copies of their DER to detect replacement or material edits."
  #+(or windows darwin macos)
  (locally (declare (ignore cache)) (certificate-api-identity chain ca :now now))
  #-(or windows darwin macos)
  (if (null cache)
      (certificate-api-identity chain ca :now now)
      (let* ((roots (if (listp ca) ca (list ca)))
             (certificates (append chain roots)))
        (unless (and (api-certificate-cache-identity cache)
                     (eql now (api-certificate-cache-second cache))
                     (equal chain (api-certificate-cache-chain cache))
                     (equal roots (api-certificate-cache-roots cache))
                     (eql pure-tls::*default-verify-depth* (api-certificate-cache-depth cache))
                     (every (lambda (certificate bytes)
                              (equalp (pure-tls::x509-certificate-raw-der certificate) bytes))
                            certificates (api-certificate-cache-material cache)))
          ;; A failed revalidation must not leave a previous positive result reusable.
          (setf (api-certificate-cache-identity cache) nil)
          (let ((identity (certificate-api-identity chain ca :now now)))
            (when identity
              (setf (api-certificate-cache-second cache) now
                    (api-certificate-cache-chain cache) (copy-list chain)
                    (api-certificate-cache-roots cache) (copy-list roots)
                    (api-certificate-cache-material cache)
                    (mapcar (lambda (certificate) (copy-seq (pure-tls::x509-certificate-raw-der certificate))) certificates)
                    (api-certificate-cache-depth cache) pure-tls::*default-verify-depth*
                    (api-certificate-cache-identity cache) identity))))
        ;; Request handlers may retain or modify their identity; keep the cache private.
        (let ((identity (api-certificate-cache-identity cache)))
          (when identity
            (gr8s.resources::make-api-user-identity
             :username (copy-seq (gr8s.resources::api-user-identity-username identity))
             :uid (let ((uid (gr8s.resources::api-user-identity-uid identity))) (and uid (copy-seq uid)))
             :groups (copy-core-object (gr8s.resources::api-user-identity-groups identity))
             :extra (copy-core-object (gr8s.resources::api-user-identity-extra identity))))))))

(defmethod hunchentoot:process-connection :around ((acceptor gr8s-in-cluster-acceptor) socket)
  "Isolate TLS peer identity across worker reuse and retain it across keepalive requests."
  (let ((*api-connection-certificate-chain* nil)
        (*api-connection-certificate-cache* (make-api-certificate-cache)))
    (call-next-method)))

(defmethod hunchentoot:initialize-connection-stream ((acceptor gr8s-in-cluster-acceptor) stream)
  "Request optional client proof-of-possession; HTTP authenticators verify trust and token alternatives."
  (with-tls-handshake-deadline (*tls-handshake-seconds*)
    ;; This TLS implementation's resumption tickets do not retain peer chains.
    ;; Fresh ticket keys require a full certificate handshake on every connection.
    (let* ((pure-tls:*server-ticket-key* (ironclad:random-data 32))
           (tls (pure-tls:make-tls-server-stream stream :certificate (in-cluster-certificate acceptor)
                    :key (in-cluster-private-key acceptor) :verify pure-tls:+verify-peer+
                    ;; Preserve TLS CertificateVerify proof, but defer CA/expiry/purpose
                    ;; checks to HTTP so another authenticator may accept a valid token.
                    :trust-store nil)))
      (setf *api-connection-certificate-chain* (pure-tls:tls-peer-certificate-chain tls))
      tls)))

(defun field-selector-exact-name (selector)
  "Return the object name SELECTOR requires, which authorization treats as the request's name."
  (when selector
    (loop for term in (uiop:split-string selector :separator ",")
          for trimmed = (string-trim " " term)
          do (cond ((uiop:string-prefix-p "metadata.name==" trimmed)
                    (return (subseq trimmed (length "metadata.name=="))))
                   ((uiop:string-prefix-p "metadata.name=" trimmed)
                    (return (subseq trimmed (length "metadata.name="))))))))

(defun kubernetes-authorization-target (path method &key watch field-selector)
  "Return verb, group, resource, name and namespace for Kubernetes request PATH.
As upstream does, a collection request selecting one name by FIELD-SELECTOR is about that name,
so that a rule limited by resourceNames can allow reading and watching just that object."
  (let* ((parts (remove "" (uiop:split-string path :separator '(#\/)) :test #'equal))
         (group (cond ((and (equal "api" (first parts)) (equal "v1" (second parts))) "")
                      ((and (equal "apis" (first parts)) (>= (length parts) 3)) (second parts))))
         (tail (when group (nthcdr (if (equal group "") 2 3) parts)))
         (namespaced (and (>= (length tail) 3) (equal "namespaces" (first tail))))
         (namespace (when namespaced (second tail)))
         ;; A Namespace's own subresources share the shape of a namespaced collection.
         (namespace-subresource (and namespaced (= 3 (length tail))
                                     (member (third tail) '("status" "finalize") :test #'equal)))
         (namespaced (and namespaced (not namespace-subresource)))
         (resource-parts (if namespaced (cddr tail) tail))
         (resource (first resource-parts)) (name (second resource-parts))
         (verb (case method (:get (cond (watch "watch") (name "get") (resource "list") (t "get")))
                            (:post "create") (:put "update") (:patch "patch")
                            (:delete (if name "delete" "deletecollection"))
                            (:head "get") (t "")))
         ;; A WebSocket upgrade is a GET, but it opens a way into the Pod rather than reading
         ;; anything, so as upstream has since v1.35, read access isn't enough for one.
         (verb (if (and (equal group "") (equal resource "pods") (eq method :get)
                        (member (third resource-parts) '("exec" "attach" "portforward") :test #'equal))
                   "create"
                   verb))
         ;; Like Pod exec, traces are opened with a WebSocket GET but create an
         ;; ephemeral privileged operation; list permission must never authorize one.
         (verb (if (and (equal group "gr8s.io") (equal resource "traces")
                        namespaced (eq method :get))
                   "create"
                   verb)))
    (when (and (equal group "gr8s.io") (eq method :get)
               (equal (third resource-parts) "slynk")
               (member resource '("nodes" "controlplanemembers") :test #'equal))
      (setf verb "create"))
    (values verb group
            (when resource (if (third resource-parts) (format nil "~A/~A" resource (third resource-parts)) resource))
            (or name
                (and (member verb '("list" "watch" "deletecollection") :test #'equal)
                     (let ((selected (field-selector-exact-name field-selector)))
                       (and selected (path-segment-name-p selected) selected))))
            namespace)))

(defun authenticated-discovery-request-p (path method)
  "Recognize read-only discovery URLs granted to all authenticated accounts."
  (and (member method '(:get :head))
       (or (member path '("/version" "/api" "/apis" "/api/v1" "/openapi/v2" "/openapi/v3") :test #'equal)
           ;; As upstream's system:discovery role grants: kubectl validates with these.
           (uiop:string-prefix-p "/openapi/v3/" path)
           (let ((parts (remove "" (uiop:split-string path :separator '(#\/)) :test #'equal)))
             (and (member (length parts) '(2 3)) (equal "apis" (first parts)))))))

(defun authenticated-health-request-p (path method)
  "Recognize the health reads upstream's system:public-info-viewer role grants everyone."
  (and (member method '(:get :head))
       (cl-ppcre:scan "^/(healthz|livez|readyz)(/.*)?$" path)
       t))

(defun authenticated-self-review-request-p (path method)
  "Recognize the self reviews upstream's system:basic-user role grants all authenticated users.
RBAC rules name no version, so the grant covers every version, served or not; an unserved
one then answers 404 rather than 403, as upstream's does."
  (and (eq method :post)
       (cl-ppcre:scan "^/apis/(authorization\\.k8s\\.io/[^/]+/selfsubject(access|rules)reviews|authentication\\.k8s\\.io/[^/]+/selfsubjectreviews)$"
                      path)
       t))

(defun authorize-in-cluster-request (store request)
  "Authenticate a verified certificate or live bearer token, then enforce current RBAC."
  (let* ((header (hunchentoot:header-in :authorization request))
         (token (authorization-bearer-token header))
         (authenticated (or (handler-case
                                (cached-api-certificate-identity *api-connection-certificate-chain*
                                  (in-cluster-client-ca (hunchentoot:request-acceptor request))
                                  *api-connection-certificate-cache*)
                              (kubernetes-error () nil))
                            (and token (authenticate-service-account-token store token))))
         (identity (and authenticated (impersonated-api-identity store authenticated request)))
         (path (request-route-path (hunchentoot:script-name request))) (method (hunchentoot:request-method request)))
    (when identity (setf *flowcontrol-request-level* (flowcontrol-note-request store identity path method)))
    (unless identity (core-resource-error 401 "Unauthorized" "A valid client certificate or ServiceAccount bearer token is required"))
    (unless (or (authenticated-discovery-request-p path method)
                (authenticated-self-review-request-p path method)
                (authenticated-health-request-p path method))
      (multiple-value-bind (verb group resource name namespace)
          (kubernetes-authorization-target path method :watch (true-parameter-p (hunchentoot:parameter "watch"))
                                                       :field-selector (hunchentoot:parameter "fieldSelector"))
        (unless (service-account-authorized-p store identity verb group resource name namespace path)
          (core-resource-error 403 "Forbidden" "User ~A is not allowed to ~A ~A"
                               (api-identity-username identity) verb (or resource path)))
        ;; Upstream authorizes the GET itself as get, then the connection as create
        ;; (AuthorizePodWebsocketUpgradeCreatePermission): a stream into a Pod needs both.
        (when (and (eq method :get) (equal group "")
                   (member resource '("pods/exec" "pods/attach" "pods/portforward") :test #'equal)
                   (not (service-account-authorized-p store identity "get" group resource name namespace path)))
          (core-resource-error 403 "Forbidden" "User ~A is not allowed to get ~A"
                               (api-identity-username identity) resource))))
    identity))

(defvar *api-audit-sink* nil
  "A function of one audit-event core-object that records an API audit event, or
NIL to disable API audit logging. Bound by serve from --audit-log-path.")

(defun api-audit-log-sink (stream)
  "Return an audit sink that appends each event to STREAM as one JSON line."
  (lambda (event)
    (ignore-errors
      (com.inuoe.jzon:stringify event :stream stream)
      (terpri stream)
      (finish-output stream))))

(defun build-api-audit-event (identity verb group resource name namespace
                              source-ip user-agent request-uri status)
  "Build a Metadata-level API audit event (who did what, when, from where, result)."
  (core-object
   "kind" "Event"
   "apiVersion" "audit.k8s.io/v1"
   "level" "Metadata"
   "timestamp" (current-timestamp)
   "verb" (or verb :null)
   "user" (core-object
           "username" (if identity (api-identity-username identity) "system:anonymous")
           "groups" (coerce (and identity (api-identity-groups identity)) 'vector))
   "sourceIPs" (vector (or source-ip :null))
   "userAgent" (or user-agent :null)
   "objectRef" (core-object "resource" (or resource :null) "apiGroup" (or group :null)
                            "namespace" (or namespace :null) "name" (or name :null))
   "requestURI" (or request-uri :null)
   "responseStatus" (core-object "code" status)))

(defun emit-api-audit-event (identity request status)
  "Record one API audit event for REQUEST when auditing is enabled."
  (when *api-audit-sink*
    (ignore-errors
      (let ((path (request-route-path (hunchentoot:script-name request)))
            (method (hunchentoot:request-method request)))
        (multiple-value-bind (verb group resource name namespace)
            (handler-case (kubernetes-authorization-target path method)
              (error () (values (string-downcase (princ-to-string method)) nil nil nil nil)))
          (funcall *api-audit-sink*
                   (build-api-audit-event
                    identity verb group resource name namespace
                    (or (hunchentoot:header-in :x-forwarded-for request)
                        (hunchentoot:remote-addr request))
                    (hunchentoot:header-in :user-agent request)
                    (hunchentoot:request-uri request)
                    status)))))))

(defmethod hunchentoot:acceptor-dispatch-request ((acceptor gr8s-in-cluster-acceptor) request)
  "Enforce authentication and authorization on the dedicated TLS API listener."
  (let ((identity nil))
    (unwind-protect
         (handler-case
             (let* ((*flowcontrol-request-level* nil)
                    (store (acceptor-store acceptor))
                    ;; Authentication, flow control and RBAC all read the store,
                    ;; before the request is routed and takes its lease. Token
                    ;; verification swallows a refused read, so while a checkpoint
                    ;; had the store a valid token was answered 401, which tells a
                    ;; client its credentials are bad rather than to try again
                    ;; (podster-t5g). Under a lease the reads wait the checkpoint
                    ;; out, and a store closed for a restore answers 503.
                    (*authenticated-api-identity*
                      (if store
                          (call-with-brief-store-access
                           store (request-route-path (hunchentoot:script-name request))
                           (lambda () (authorize-in-cluster-request store request)))
                          (authorize-in-cluster-request store request))))
               (setf identity *authenticated-api-identity*)
               (call-next-method))
           (kubernetes-error (condition) (kubernetes-error-response condition)))
      (emit-api-audit-event identity request (hunchentoot:return-code*)))))

(defun start-in-cluster-api (store runtime reconciler pki &key (address "0.0.0.0") (port 6443)
                                                               (certificate-addresses nil)
                                                               leader-status-fn
                                                               linearizable-read-fn
                                                               follows-a-leader-fn
                                                               debug-state-directory
                                                               debug-member-resolver
                                                               control-plane-metrics-fn
                                                               control-plane-membership-fn)
  "Start the authenticated TLS Kubernetes API listener."
  (multiple-value-bind (certificate key)
      (ensure-kubernetes-api-credentials pki :addresses (cons address certificate-addresses))
    (hunchentoot:start
     (make-instance 'gr8s-in-cluster-acceptor :address address :port port :store store
                    :runtime runtime :reconciler reconciler
                    :leader-status-fn leader-status-fn
                    :relay-pki pki
                    :linearizable-read-fn linearizable-read-fn
                    :follows-a-leader-fn follows-a-leader-fn
                    :debug-state-directory debug-state-directory
                    :debug-member-resolver debug-member-resolver
                    :control-plane-metrics-fn control-plane-metrics-fn
                    :control-plane-membership-fn control-plane-membership-fn
                    :certificate (namestring certificate) :private-key (namestring key)
                    :client-ca (cluster-pki-trust-certificates pki)))))

(defparameter +service-network-interface+ "gr8s-services")

(defun service-network-owner (ca-fingerprint)
  "The identity stamped on the service interface of the cluster whose CA has CA-FINGERPRINT."
  (format nil "gr8s-services/~A" ca-fingerprint))

(defun in-cluster-network-owner (pki)
  "Bind the native service interface identity to its owning cluster CA."
  (service-network-owner (cluster-pki-ca-fingerprint pki)))

(defun service-network-owned-by-p (owner)
  "Recognize only OWNER's dummy interface and deterministic MAC identity."
  (let ((attributes (network-link-attributes +service-network-interface+)))
    (and (network-link-kind-p attributes "dummy")
         (equalp (gethash 1 attributes) (network-identity-mac owner))
         (or (equalp (gethash 20 attributes) (netlink-string owner))
             (network-link-untagged-p attributes)))))

(defun in-cluster-network-owned-p (pki)
  "Recognize only this cluster's service interface."
  (service-network-owned-by-p (in-cluster-network-owner pki)))

(defun ensure-in-cluster-network (pki)
  "Ensure the owned native service interface has the Kubernetes API virtual IP."
  (let* ((name +service-network-interface+) (owner (in-cluster-network-owner pki))
         (created (zerop (native-interface-index name))))
    (when created
      (call-rtnetlink 16 #x600
        (netlink-octets (netlink-interface-message)
                       (netlink-attribute 3 (netlink-string name))
                       (netlink-attribute 1 (network-identity-mac owner))
                       (netlink-attribute 18 (netlink-attribute 1 (netlink-string "dummy"))))))
    (unless (in-cluster-network-owned-p pki)
      (invalid-cni "service interface belongs to another cluster"))
    (set-network-link-owner name owner)
    (add-network-address name "10.96.0.1" 32)
    (set-network-link-up name)
    created))

(defun remove-in-cluster-network (pki)
  "Remove the native service interface only if its cluster ownership still matches."
  (unless (zerop (native-interface-index +service-network-interface+))
    (unless (in-cluster-network-owned-p pki) (invalid-cni "refusing to remove a foreign service interface"))
    (delete-network-link +service-network-interface+)))
