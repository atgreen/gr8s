;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Serve the in-cluster Kubernetes API over pure-tls with a distinct server
;;;; certificate, cluster service DNS/IP SANs, token/certificate authentication and
;;;; live RBAC checks. The existing local administrative HTTP endpoint remains
;;;; separate from this authenticated listener.

(in-package #:gr8s)

(defun kubernetes-api-san-extension ()
  "Encode the service DNS identities and IPv4 addresses of the API listener."
  (apply #'pure-tls/acme::encode-sequence
         (append
          (loop for name in '("kubernetes" "kubernetes.default" "kubernetes.default.svc"
                             "kubernetes.default.svc.cluster.local" "localhost")
                collect (pure-tls/acme::encode-der #x82 (pki-ascii-octets name)))
          (list (pure-tls/acme::encode-der #x87 #(10 96 0 1))
                (pure-tls/acme::encode-der #x87 #(127 0 0 1))))))

(defun ensure-kubernetes-api-credentials (pki)
  "Create or validate a persisted Kubernetes API server identity under the cluster CA."
  (let ((certificate-path (merge-pathnames "kubernetes-api.crt" (cluster-pki-root pki)))
        (key-path (merge-pathnames "kubernetes-api.key" (cluster-pki-root pki))))
    (bt:with-lock-held ((cluster-pki-lock pki))
      (cond
        ((and (probe-file certificate-path) (probe-file key-path))
         (let ((leaf (first (pure-tls:load-certificate-chain certificate-path))))
           (pure-tls::verify-certificate-chain (list leaf) (list (cluster-pki-ca-certificate pki))
                                             :purpose :server-auth :trust-anchor-mode :replace)
           (pure-tls::verify-hostname leaf "kubernetes.default.svc")))
        ((or (probe-file certificate-path) (probe-file key-path))
         (pki-fail "incomplete-api-identity" "Kubernetes API certificate/key pair is incomplete"))
        (t
         (multiple-value-bind (private public) (ironclad:generate-key-pair :secp256r1)
           (let* ((der (certificate-der
                        (pure-tls/acme::encode-subject +pki-ca-common-name+)
                        (pure-tls/acme::encode-subject "kubernetes.default.svc")
                        (pure-tls/acme::encode-ec-public-key public)
                        (list (pure-tls/acme::encode-critical-extension +oid-key-usage+
                                (pure-tls/acme::encode-bit-string #(#x80) 7))
                              (pure-tls/acme::encode-extension +oid-extended-key-usage+
                                (pure-tls/acme::encode-sequence (pure-tls/acme::encode-oid '(1 3 6 1 5 5 7 3 1))))
                              (pure-tls/acme::encode-extension pure-tls/acme::*oid-subject-alt-name*
                                (kubernetes-api-san-extension)))
                        (cluster-pki-ca-private-key pki)))
                  (chain (concatenate 'string (pure-tls/acme::wrap-pem "CERTIFICATE" der)
                                      (uiop:read-file-string (cluster-pki-ca-certificate-path pki)))))
             (write-private-text-exclusively key-path (pure-tls/acme::encode-ec-private-key-pem private))
             (handler-case (write-private-text-exclusively certificate-path chain)
               (error (condition) (ignore-errors (delete-file key-path)) (error condition))))))))
    (values certificate-path key-path)))

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

(defmethod hunchentoot:process-connection :around ((acceptor gr8s-in-cluster-acceptor) socket)
  "Isolate TLS peer identity across worker reuse and retain it across keepalive requests."
  (let ((*api-connection-certificate-chain* nil)) (call-next-method)))

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
                   verb)))
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
         (token (when (and header (uiop:string-prefix-p "Bearer " header)) (subseq header 7)))
         (authenticated (or (handler-case
                                (certificate-api-identity *api-connection-certificate-chain*
                                  (in-cluster-client-ca (hunchentoot:request-acceptor request)))
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
                               (api-identity-username identity) verb (or resource path)))))
    identity))

(defmethod hunchentoot:acceptor-dispatch-request ((acceptor gr8s-in-cluster-acceptor) request)
  "Enforce authentication and authorization on the dedicated TLS API listener."
  (handler-case
      (let* ((*flowcontrol-request-level* nil)
             (*authenticated-api-identity* (authorize-in-cluster-request (acceptor-store acceptor) request)))
        (call-next-method))
    (kubernetes-error (condition) (kubernetes-error-response condition))))

(defun start-in-cluster-api (store runtime reconciler pki &key (address "10.96.0.1") (port 443))
  "Start a TLS API listener; the caller owns its service address and shutdown."
  (multiple-value-bind (certificate key) (ensure-kubernetes-api-credentials pki)
    (hunchentoot:start
     (make-instance 'gr8s-in-cluster-acceptor :address address :port port :store store
                    :runtime runtime :reconciler reconciler
                    :certificate (namestring certificate) :private-key (namestring key)
                    :client-ca (cluster-pki-ca-certificate pki)))))

(defparameter +service-network-interface+ "gr8s-services")

(defun in-cluster-network-owner (pki)
  "Bind the native service interface identity to its owning cluster CA."
  (format nil "gr8s-services/~A" (cluster-pki-ca-fingerprint pki)))

(defun in-cluster-network-owned-p (pki)
  "Recognize only this cluster's dummy interface and deterministic MAC identity."
  (let* ((attributes (network-link-attributes +service-network-interface+))
         (owner (in-cluster-network-owner pki)))
    (and (network-link-kind-p attributes "dummy")
         (equalp (gethash 1 attributes) (network-identity-mac owner))
         (or (equalp (gethash 20 attributes) (netlink-string owner))
             (network-link-untagged-p attributes)))))

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
