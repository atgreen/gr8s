;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Project public Service discovery data over authenticated node snapshots and
;;;; resolve Service names from durable local ClusterIP and ready EndpointSlice data.

(in-package #:gr8s.kubelet)

(defun service-discovery-public-object (object)
  "Copy only public DNS fields; exclude arbitrary annotations and unrelated resources."
  (let* ((kind (gethash "kind" object)) (source (gethash "metadata" object))
         (metadata (core-object)) (result (core-object)))
    (unless (member kind '("Namespace" "Service" "EndpointSlice" "NetworkPolicy" "Ingress" "IngressClass"
                           "GatewayClass" "Gateway" "HTTPRoute" "TCPRoute" "TLSRoute" "GRPCRoute" "ReferenceGrant"
                           "Secret" "ClusterTrustBundle" "PodCertificateRequest") :test #'equal)
      (invalid-pod "unsupported public Service discovery kind"))
    (dolist (key '("name" "namespace" "uid" "resourceVersion"))
      (when (gethash key source) (setf (gethash key metadata) (gethash key source))))
    (when (equal kind "EndpointSlice")
      (setf (gethash "labels" metadata)
            (core-object "kubernetes.io/service-name"
                         (gethash "kubernetes.io/service-name" (gethash "labels" source (core-object)))))
      ;; kube-proxy ignores a slice labelled headless, so the node's proxy must see the label.
      (multiple-value-bind (value present) (gethash "service.kubernetes.io/headless" (gethash "labels" source (core-object)))
        (when present (setf (gethash "service.kubernetes.io/headless" (gethash "labels" metadata)) value))))
    (setf (gethash "kind" result) kind
          (gethash "apiVersion" result) (cond ((member kind '("Namespace" "Service") :test #'equal) "v1")
                                              ((equal kind "Secret") "v1")
                                              ((equal kind "ClusterTrustBundle") "certificates.k8s.io/v1")
                                              ((equal kind "PodCertificateRequest") "certificates.k8s.io/v1")
                                              ((member kind '("NetworkPolicy" "Ingress" "IngressClass") :test #'equal)
                                               "networking.k8s.io/v1")
                                              ((member kind '("GatewayClass" "Gateway" "HTTPRoute" "TCPRoute" "TLSRoute" "GRPCRoute" "ReferenceGrant") :test #'equal)
                                               "gateway.networking.k8s.io/v1")
                                              (t "discovery.k8s.io/v1"))
          (gethash "metadata" result) metadata)
    (cond
      ((equal kind "Namespace")
       (when (gethash "labels" source)
         (setf (gethash "labels" metadata) (copy-core-object (gethash "labels" source)))))
      ((equal kind "Service")
       (let ((spec (core-object)))
         ;; What the node's Service proxy needs, as kube-proxy reads it.
         (dolist (key '("clusterIP" "clusterIPs" "ipFamilies" "ports" "type" "externalName"
                        "sessionAffinity" "sessionAffinityConfig" "internalTrafficPolicy"
                        "externalTrafficPolicy" "externalIPs" "healthCheckNodePort" "trafficDistribution"))
           (when (gethash key (gethash "spec" object))
             (setf (gethash key spec) (copy-core-object (gethash key (gethash "spec" object))))))
         (setf (gethash "spec" result) spec)
         ;; kube-proxy ignores a Service either label is on, and serves load balancer addresses.
         (let ((labels (gethash "labels" source)) (kept (core-object)))
           (dolist (key '("service.kubernetes.io/service-proxy-name" "service.kubernetes.io/headless"))
             (multiple-value-bind (value present) (and (hash-table-p labels) (gethash key labels))
               (when present (setf (gethash key kept) value))))
           (when (plusp (hash-table-count kept)) (setf (gethash "labels" metadata) kept)))
         (let* ((status (gethash "status" object))
                (balancer (and (hash-table-p status) (gethash "loadBalancer" status)))
                (ingress (and (hash-table-p balancer) (gethash "ingress" balancer))))
           (when (and (vectorp ingress) (plusp (length ingress)))
             (setf (gethash "status" result)
                   (core-object "loadBalancer"
                                (core-object "ingress"
                                             (map 'vector (lambda (entry)
                                                            (let ((kept (core-object)))
                                                              (when (hash-table-p entry)
                                                                (dolist (key '("ip" "ipMode"))
                                                                  (when (stringp (gethash key entry))
                                                                    (setf (gethash key kept) (gethash key entry)))))
                                                              kept))
                                                  ingress))))))))
      ((equal kind "NetworkPolicy")
       ;; The spec as network-policy-projection resolved it: podSelector, defaulted
       ;; policyTypes, and rules whose peers are addresses. The node needs nothing else.
       (setf (gethash "spec" result) (copy-core-object (gethash "spec" object))))
      ((member kind '("Ingress" "IngressClass"
                      "GatewayClass" "Gateway" "HTTPRoute" "TCPRoute" "TLSRoute" "GRPCRoute" "ReferenceGrant") :test #'equal)
       ;; The agent's Gateway controller reconciles these into L7 proxy listeners,
       ;; so it needs the full spec (controllerName / listeners / parentRefs+rules).
       (setf (gethash "spec" result) (copy-core-object (gethash "spec" object)))
       (when (member kind '("Gateway" "GatewayClass" "HTTPRoute" "TCPRoute" "TLSRoute" "GRPCRoute") :test #'equal)
         ;; Desired spec identity is UID + generation. Status writes -- now
         ;; including route Accepted/ResolvedRefs -- must not invalidate discovery
         ;; digests or force another dataplane snapshot.
         (remhash "resourceVersion" metadata)
         (setf (gethash "generation" metadata) (gethash "generation" source 1)))
       (when (equal kind "Ingress")
         (let ((annotations (gethash "annotations" source)) (kept (core-object)))
           (when (hash-table-p annotations)
             (dolist (key '("kubernetes.io/ingress.class" "gr8s.io/rate-limit-rps"))
               (multiple-value-bind (value present) (gethash key annotations)
                 (when present (setf (gethash key kept) value)))))
           (when (plusp (hash-table-count kept))
             (setf (gethash "annotations" metadata) kept)))))
      ((equal kind "Secret")
       ;; A Gateway HTTPS listener terminates TLS on the node, so the node needs
       ;; the referenced certificate and private key (podster-045.6). Only
       ;; kubernetes.io/tls Secrets are projectable, and only their type + data
       ;; cross over, so no other Secret kind or field ever reaches the node.
       (unless (equal (gethash "type" object) "kubernetes.io/tls")
         (invalid-pod "only kubernetes.io/tls Secrets are projectable"))
       (setf (gethash "type" result) (gethash "type" object)
             (gethash "data" result) (copy-core-object (gethash "data" object))))
      ((equal kind "ClusterTrustBundle")
       ;; Trust anchors a node needs for the clusterTrustBundle projected volume
       ;; (KEP-4317). The whole spec (signerName + trustBundle PEM) is public, and
       ;; the labels must cross too: a clusterTrustBundle source selects bundles
       ;; by labelSelector (e.g. podcert.ate.dev/canarying=live), so dropping
       ;; them would leave a signerName+selector volume matching nothing.
       (when (gethash "labels" source)
         (setf (gethash "labels" metadata) (copy-core-object (gethash "labels" source))))
       (setf (gethash "spec" result) (copy-core-object (gethash "spec" object))))
      ((equal kind "PodCertificateRequest")
       ;; The node created this request's public key and now needs the signed
       ;; result back to mount it (KEP-4317). Both spec (which pins the node, pod
       ;; and key) and status (the issued certificateChain) carry only public
       ;; data; the private key never left the node.
       (setf (gethash "spec" result) (copy-core-object (gethash "spec" object)))
       (when (gethash "status" object)
         (setf (gethash "status" result) (copy-core-object (gethash "status" object)))))
      (t
       (dolist (key '("addressType" "endpoints" "ports"))
         (setf (gethash key result) (copy-core-object (gethash key object))))))
    result))

(defun gateway-referenced-tls-secrets (store)
  "kubernetes.io/tls Secrets named by an HTTPS listener's certificateRefs on any
   Gateway, so the node that terminates the listener's TLS can load the cert and
   key (podster-045.6). Deduplicated by (namespace . name); missing Secrets are
   skipped (the listener stays down until the Secret exists)."
  (let ((seen (make-hash-table :test #'equal))
        (secrets '()))
    (dolist (gateway (list-core-resources store "gateways"))
      (let* ((metadata (gethash "metadata" gateway))
             (gateway-namespace (gethash "namespace" metadata))
             (spec (gethash "spec" gateway))
             (listeners (and spec (gethash "listeners" spec))))
        (when listeners
          (loop for listener across listeners
                when (equal (gethash "protocol" listener) "HTTPS")
                  do (let* ((tls (gethash "tls" listener))
                            (refs (and tls (gethash "certificateRefs" tls))))
                       (when (and refs (plusp (length refs)))
                         (let* ((ref (aref refs 0))
                                (kind (or (gethash "kind" ref) "Secret"))
                                (name (gethash "name" ref))
                                (namespace (or (gethash "namespace" ref) gateway-namespace)))
                           (when (and (equal kind "Secret") name
                                      (equal (or (gethash "group" ref) "") "")
                                      (gr8s.controllers::gateway-reference-permitted-p
                                       store gateway-namespace "Gateway" namespace "Secret" name)
                                      (not (gethash (cons namespace name) seen)))
                             (setf (gethash (cons namespace name) seen) t)
                             (let ((secret (ignore-errors
                                            (get-core-resource store "secrets" namespace name))))
                               (when (and secret (equal "kubernetes.io/tls" (gethash "type" secret)))
                                 (push secret secrets)))))))))))
    (nreverse secrets)))

(defun ingress-referenced-tls-secrets (store)
  "Return TLS Secrets named by any Ingress, deduplicated by namespace/name."
  (let ((seen (make-hash-table :test #'equal)) (secrets nil))
    (dolist (ingress (list-core-resources store "ingresses"))
      (let* ((metadata (gethash "metadata" ingress))
             (namespace (gethash "namespace" metadata))
             (tls (gethash "tls" (gethash "spec" ingress))))
        (when tls
          (loop for entry across tls
                for name = (gethash "secretName" entry)
                for key = (and name (cons namespace name))
                when (and key (not (gethash key seen)))
                  do (setf (gethash key seen) t)
                     (let ((secret (ignore-errors
                                    (get-core-resource store "secrets" namespace name))))
                       (when (and secret (equal "kubernetes.io/tls" (gethash "type" secret)))
                         (push secret secrets)))))))
    (nreverse secrets)))

(defun build-service-discovery-projection (store &optional previous-cache)
  "Encode a captured view, reusing unchanged immutable rows; return bytes and a bounded cache."
  (labels ((objects (resource)
             (loop for key being the hash-keys of (pod-store-resources store)
                   using (hash-value object)
                   when (equal resource (first key)) collect object)))
    (let* ((next-cache (make-hash-table :test 'eq))
           (rows (append (objects "namespaces")
                          (objects "services")
                          (objects "endpointslices")
                          ;; NetworkPolicy selectors are resolved against cluster Pods and Namespaces.
                          (network-policy-projection store)
                          (objects "ingressclasses")
                          (objects "ingresses")
                          (objects "referencegrants")
                          (objects "gatewayclasses")
                          (objects "gateways")
                          (objects "httproutes")
                          (objects "tcproutes")
                          (objects "tlsroutes")
                          (objects "grpcroutes")
                          (objects "clustertrustbundles")
                          (objects "podcertificaterequests")
                          (gateway-referenced-tls-secrets store)
                          (ingress-referenced-tls-secrets store)))
           (encoded
             (mapcar (lambda (object)
                       (let ((entry
                               (or (and previous-cache (gethash object previous-cache))
                                   (let ((metadata (gethash "metadata" object)))
                                     (cons (format nil "~A/~A/~A" (gethash "kind" object)
                                                   (gethash "namespace" metadata) (gethash "name" metadata))
                                           (trivial-utf-8:string-to-utf-8-bytes
                                            (endpointslice-canonical-json
                                             (service-discovery-public-object object))))))))
                         (setf (gethash object next-cache) entry)
                         entry))
                     rows)))
      ;; Resolved policies and TLS membership are recomputed above. Only identical
      ;; source objects can reuse bytes; UID/resourceVersion alone are insufficient.
      (values (mapcar #'cdr (sort encoded #'string< :key #'car)) next-cache))))

(defvar *discovery-projection-cache* nil)

(defun call-with-discovery-projection-cache (function)
  "Share immutable projection bytes only within this consistent controller pass."
  (let ((*discovery-projection-cache* (or *discovery-projection-cache* (make-hash-table :test 'eq))))
    (funcall function)))

(defun discovery-projection-stamp-unlocked (store)
  (list (pod-store-resources store) (pod-store-resource-revision store)
        (gr8s.store::pod-store-pod-revision store)
        (gr8s.store::pod-store-gateway-dependency-revision store)))

(defun capture-service-discovery-store (store)
  "Capture immutable resource rows and the Pod indexes needed for policy resolution."
  (with-store-lock (store)
    (let ((view (gr8s.store::make-pod-store nil)))
      (setf (pod-store-resources view) (pod-store-resources store)
            (pod-store-resource-revision view) (pod-store-resource-revision store)
            (gr8s.store::pod-store-gateway-dependency-revision view)
            (gr8s.store::pod-store-gateway-dependency-revision store)
            (gr8s.store::pod-store-pods view) (alexandria:copy-hash-table (gr8s.store::pod-store-pods store))
            (gr8s.store::pod-store-nodes view) (alexandria:copy-hash-table (gr8s.store::pod-store-nodes store))
            (gr8s.store::pod-store-pod-revision view) (gr8s.store::pod-store-pod-revision store)
            (gr8s.store::pod-store-pod-observed-statuses view)
            (alexandria:copy-hash-table (gr8s.store::pod-store-pod-observed-statuses store))
            (gr8s.store::pod-store-pod-observed-phases view)
            (alexandria:copy-hash-table (gr8s.store::pod-store-pod-observed-phases store))
            (gr8s.store::pod-store-pod-observed-resource-versions view)
            (alexandria:copy-hash-table (gr8s.store::pod-store-pod-observed-resource-versions store)))
      (values view (gr8s.store::pod-store-discovery-encoding-cache store)
              (discovery-projection-stamp-unlocked store)))))

(defun discovery-projection-current-p (store cached stamp)
  "Caller holds STORE's lock. Observations can change before the Pod watch revision."
  (and cached (equal stamp (first cached))
       (let ((observed (gr8s.store::pod-store-pod-observed-statuses store))
             (captured (fourth cached)))
         (and (= (hash-table-count observed) (hash-table-count captured))
              (loop for uid being the hash-keys of observed using (hash-value status)
                    always (eq status (gethash uid captured)))))))

(defun service-discovery-projection (store)
  "Reuse a coherent projection while all resource and Pod inputs remain unchanged."
  (with-store-lock (store)
    (let* ((stamp (discovery-projection-stamp-unlocked store))
           (pass-cache (and *discovery-projection-cache*
                            (gethash store *discovery-projection-cache*)))
           (cached (gr8s.store::pod-store-discovery-projection-cache store)))
      (when (discovery-projection-current-p store pass-cache stamp)
        (return-from service-discovery-projection (values (second pass-cache) (third pass-cache))))
      (when (discovery-projection-current-p store cached stamp)
        ;; Keep the retained list private; encoded byte vectors are immutable.
        (let ((projection (copy-list (second cached))))
          (when *discovery-projection-cache*
            (setf (gethash store *discovery-projection-cache*)
                  (list stamp projection (third cached) (fourth cached))))
          (return-from service-discovery-projection (values projection (third cached)))))))
  (multiple-value-bind (view previous-cache stamp) (capture-service-discovery-store store)
    (multiple-value-bind (projection next-cache) (build-service-discovery-projection view previous-cache)
      (let* ((dependency-revision (gr8s.store::pod-store-gateway-dependency-revision view))
             (cached (list stamp projection dependency-revision
                           (gr8s.store::pod-store-pod-observed-statuses view))))
        (with-store-lock (store)
          ;; A slower capture must not replace a newer published projection.
          (when (discovery-projection-current-p store cached (discovery-projection-stamp-unlocked store))
            (setf (gr8s.store::pod-store-discovery-projection-cache store) cached))
          (when (eq previous-cache (gr8s.store::pod-store-discovery-encoding-cache store))
            (setf (gr8s.store::pod-store-discovery-encoding-cache store) next-cache)))
        (let ((result (copy-list projection)))
          (when *discovery-projection-cache*
            (setf (gethash store *discovery-projection-cache*)
                  (list stamp result dependency-revision (fourth cached))))
          (values result dependency-revision))))))

(defun decode-service-discovery-entry (bytes)
  "Validate one public discovery entry and return its resource key and object."
    (let* ((object (com.inuoe.jzon:parse bytes :max-string-length (* 2 1024 1024)))
           (public (service-discovery-public-object object))
           (metadata (gethash "metadata" public))
           (namespace (gethash "namespace" metadata)) (name (gethash "name" metadata))
           (resource (cond ((equal "Namespace" (gethash "kind" public)) "namespaces")
                           ((equal "Service" (gethash "kind" public)) "services")
                           ((equal "NetworkPolicy" (gethash "kind" public)) "networkpolicies")
                           ((equal "IngressClass" (gethash "kind" public)) "ingressclasses")
                           ((equal "Ingress" (gethash "kind" public)) "ingresses")
                           ((equal "ReferenceGrant" (gethash "kind" public)) "referencegrants")
                           ((equal "GatewayClass" (gethash "kind" public)) "gatewayclasses")
                           ((equal "Gateway" (gethash "kind" public)) "gateways")
                           ((equal "HTTPRoute" (gethash "kind" public)) "httproutes")
                           ((equal "TCPRoute" (gethash "kind" public)) "tcproutes")
                           ((equal "TLSRoute" (gethash "kind" public)) "tlsroutes")
                           ((equal "GRPCRoute" (gethash "kind" public)) "grpcroutes")
                           ((equal "Secret" (gethash "kind" public)) "secrets")
                           ((equal "ClusterTrustBundle" (gethash "kind" public)) "clustertrustbundles")
                           ((equal "PodCertificateRequest" (gethash "kind" public)) "podcertificaterequests")
                           (t "endpointslices"))))
      (unless (and (stringp name) (plusp (length name))
                   ;; GatewayClass, IngressClass and ClusterTrustBundle are cluster-scoped (no
                   ;; namespace); all others are namespaced.
                   (if (member resource '("namespaces" "gatewayclasses" "ingressclasses" "clustertrustbundles") :test #'equal)
                       (null namespace) (dns-label-p namespace)))
        (invalid-pod "public Service discovery metadata is invalid"))
      (cons (core-resource-key resource namespace name) public)))

(defun discovery-octet-hash (bytes)
  "FNV-1a content hash for discovery octets; cache equality still compares exact bytes."
  (declare (type (vector (unsigned-byte 8)) bytes)
           (optimize (speed 3) (safety 1)))
  (let ((hash 2166136261))
    (declare (type (unsigned-byte 32) hash))
    (dotimes (index (length bytes) (logand hash most-positive-fixnum))
      (setf hash (ldb (byte 32 0) (* (logxor hash (aref bytes index)) 16777619))))))

(defun decode-service-discovery-projection (projection &optional cache)
  "Return validated resources and a decoding cache bounded to this projection.
Exact octets are the keys; strings inside JSON never receive case-folded lookup."
  (let ((resources (make-hash-table :test 'equal))
        (next-cache (make-hash-table :test 'equalp
                                    #+sbcl :hash-function #+sbcl #'discovery-octet-hash)))
    (dolist (bytes projection)
      (check-type bytes (vector (unsigned-byte 8)))
      (let ((entry (or (and cache (gethash bytes cache)) (decode-service-discovery-entry bytes))))
        (setf (gethash (car entry) resources) (cdr entry)
              (gethash bytes next-cache) entry)))
    (values resources next-cache)))

(defun install-service-discovery-projection (resources projection)
  "Validate discovery entries and merge them into the atomic resource index."
  (maphash (lambda (key object) (setf (gethash key resources) object))
           (decode-service-discovery-projection projection))
  nil)

(defun service-dns-address-answer (question address)
  "Build an A or AAAA answer matching the requested family, or return NIL."
  (let ((type (0conf:question-qtype question)))
    (cond ((and (= type 0conf:+type-a+) (not (find #\: address)))
           (make-instance '0conf:a-record :name (0conf:question-name question)
                          :address (0conf:parse-ipv4 address) :ttl 5))
          ((and (= type 0conf:+type-aaaa+) (find #\: address))
           (make-instance '0conf:aaaa-record :name (0conf:question-name question)
                          :address (0conf:parse-ipv6 address) :ttl 5)))))

(defun resolve-insecure-pod-question (question)
  "Serve the IP-encoded pod.cluster.local form enabled by Kubernetes's default CoreDNS manifest."
  (let* ((name (canonical-dns-name (0conf:question-name question)))
         (labels (uiop:split-string name :separator ".")))
    (when (and (= 5 (length labels))
               (equal (last labels 3) '("pod" "cluster" "local")))
      (let ((address (substitute #\. #\- (first labels))))
        (handler-case
            (progn
              (unless (dns-label-p (second labels)) (error "invalid Pod namespace"))
              (0conf:parse-ipv4 address)
              (values (when (= (0conf:question-qtype question) 0conf:+type-a+)
                        (list (service-dns-address-answer question address)))
                      t))
          (error () (values nil nil)))))))

(defun resolve-store-service-question (store question &optional rotate-addresses)
  "Resolve a normal or headless Service and optional headless endpoint hostname."
  (when (dns-name-in-zone-p (0conf:question-name question) "pod.cluster.local")
    (return-from resolve-store-service-question (resolve-insecure-pod-question question)))
  (when (equal "dns-version.cluster.local" (canonical-dns-name (0conf:question-name question)))
    (return-from resolve-store-service-question
      (values (when (member (0conf:question-qtype question) (list 0conf:+type-txt+ 0conf:+type-any+))
                (list (make-instance '0conf:txt-record :name (0conf:question-name question) :strings '("1.1.0") :ttl 30))) t)))
  (when (= (0conf:question-qtype question) 0conf:+type-srv+)
    (return-from resolve-store-service-question (resolve-store-service-srv store question)))
  (let* ((name (canonical-dns-name (0conf:question-name question)))
         (labels (uiop:split-string name :separator "."))
         (count (length labels)))
    (unless (and (member count '(5 6))
                 (equal (last labels 3) '("svc" "cluster" "local")))
      (return-from resolve-store-service-question (values nil nil)))
    (let* ((service-name (nth (- count 5) labels)) (namespace (nth (- count 4) labels))
           (hostname (when (= count 6) (first labels))))
      (handler-case
          (let* ((service (get-core-resource store "services" namespace service-name))
                 (spec (gethash "spec" service)) (addresses nil))
            (when (and (null hostname) (service-external-name-p service))
              (return-from resolve-store-service-question
                (values (list (service-dns-cname-record question (gethash "externalName" spec))) t)))
            (if (equal "None" (gethash "clusterIP" spec))
                (dolist (slice (list-core-resources store "endpointslices" namespace))
                  (when (and (member (gethash "addressType" slice) '("IPv4" "IPv6") :test #'equal)
                             (equal service-name (gethash "kubernetes.io/service-name"
                                                    (gethash "labels" (gethash "metadata" slice) (core-object)))))
                    (loop for endpoint across (gethash "endpoints" slice #())
                          unless (service-dns-endpoint-unready-p endpoint)
                            do (loop for address across (gethash "addresses" endpoint #())
                                     when (or (null hostname)
                                              (equal hostname (service-dns-endpoint-hostname endpoint address)))
                                       do (pushnew address addresses :test #'equal)))))
                (unless hostname
                  (setf addresses (coerce (gethash "clusterIPs" spec
                                                   (vector (gethash "clusterIP" spec))) 'list))))
            (let ((ordered (sort addresses #'string<)))
              (when (and rotate-addresses (null hostname)
                         (equal "None" (gethash "clusterIP" spec))
                         (> (length ordered) 1))
                (setf ordered (funcall rotate-addresses name ordered)))
              (values (remove nil (mapcar (lambda (address) (service-dns-address-answer question address))
                                          ordered))
                    (if (equal "None" (gethash "clusterIP" spec))
                        (not (null addresses))
                        (null hostname)))))
        (kubernetes-error (condition)
          (if (= 404 (kubernetes-error-status-code condition)) (values nil nil) (error condition)))))))

(defun store-service-dns-resolver (store)
  "Capture the agent's durable store for both DNS worker threads."
  (let ((offsets (make-hash-table :test #'equal))
        (lock (bt:make-lock "gr8s headless DNS rotation")))
    (labels ((rotate (name addresses)
               (bt:with-lock-held (lock)
                 (let* ((key (list name (length addresses)))
                        (offset (mod (gethash key offsets 0) (length addresses))))
                   (setf (gethash key offsets) (1+ offset))
                   (append (nthcdr offset addresses) (subseq addresses 0 offset))))))
      (lambda (question)
        (if (and (= (0conf:question-qtype question) 0conf:+type-ptr+)
                 (service-dns-reverse-address (0conf:question-name question)))
            (resolve-store-service-ptr store question)
            (resolve-store-service-question store question #'rotate))))))

;;; ---------------------------------------------------------------------------
;;; External zone: serve Gateway/route hostnames authoritatively (podster-iga).
;;; Each node answers names in a configured external zone with its OWN gateway
;;; address, so an upstream resolver that forwards the zone to every node
;;; aggregates them and a down node simply drops out. The gr8s DNS owns both the
;;; Gateway state and the answer, so there is nothing to push -- the record is
;;; the live state (the CoreDNS k8s_external / cluster.local model).

(defun parse-dns-ipv4-octets (address)
  "Parse a dotted-quad IPv4 string into a four-octet vector, or NIL."
  (let ((parts (and (stringp address) (uiop:split-string address :separator "."))))
    (when (and parts (= 4 (length parts)))
      (let ((octets (mapcar (lambda (part) (ignore-errors (parse-integer part))) parts)))
        (when (every (lambda (octet) (typep octet '(integer 0 255))) octets)
          (coerce octets 'vector))))))

(defun dns-name-serves-hostname-p (name hostname)
  "True when query NAME is served by a Gateway/route/ingress HOSTNAME, which may be
a single-label wildcard such as \"*.example.net\" (one extra label before the
suffix). Both are compared canonically (lowercased, no trailing dot)."
  (let ((name (canonical-dns-name name)) (hostname (canonical-dns-name hostname)))
    (cond
      ((zerop (length hostname)) nil)
      ((and (> (length hostname) 1) (char= #\* (char hostname 0)))
       (let ((suffix (subseq hostname 1))) ; ".example.net"
         (and (> (length name) (length suffix))
              (string= suffix (subseq name (- (length name) (length suffix))))
              (let ((label (subseq name 0 (- (length name) (length suffix)))))
                (and (plusp (length label)) (not (find #\. label)))))))
      (t (string= name hostname)))))

(defun store-external-served-hostnames (store)
  "The external hostnames this cluster serves: Gateway listener hostnames (wildcards
kept), HTTPRoute hostnames, and Ingress rule hosts."
  (let ((hostnames nil))
    (flet ((add (host) (when (and (stringp host) (plusp (length host)))
                         (pushnew host hostnames :test #'equal))))
      (dolist (gateway (ignore-errors (list-core-resources store "gateways")))
        (loop for listener across (gethash "listeners" (gethash "spec" gateway (core-object)) #())
              do (add (gethash "hostname" listener))))
      (dolist (route (ignore-errors (list-core-resources store "httproutes")))
        (loop for host across (gethash "hostnames" (gethash "spec" route (core-object)) #())
              do (add host)))
      (dolist (ingress (ignore-errors (list-core-resources store "ingresses")))
        (loop for rule across (gethash "rules" (gethash "spec" ingress (core-object)) #())
              do (add (gethash "host" rule)))))
    hostnames))

(defun external-zone-answer (store serve-zones node-address question)
  "Authoritatively answer QUESTION when its name is in a configured external
SERVE-ZONE: an A record of NODE-ADDRESS (this node's IPv4 gateway address) when the
name matches a served Gateway/route/ingress hostname, NXDOMAIN when it is in a zone
but matches nothing, NODATA for a matched name whose type we do not serve. Returns
(values answers handled-p rcode), or (nil nil nil) when the name is in no serve-zone
so the proxy forwards it upstream as usual."
  (let ((name (0conf:question-name question)))
    (when (and serve-zones
               (some (lambda (zone) (dns-name-in-zone-p name zone)) serve-zones))
      (if (some (lambda (host) (dns-name-serves-hostname-p name host))
                (store-external-served-hostnames store))
          (let ((octets (and (= (0conf:question-qtype question) 0conf:+type-a+)
                             (parse-dns-ipv4-octets node-address))))
            (values (when octets
                      (list (make-instance '0conf:a-record :name name :address octets :ttl 30)))
                    t 0))
          (values nil t +dns-name-error+)))))

(defun make-cluster-dns-resolver (store &key serve-zones node-address)
  "Return a cl-dns-proxy resolver for STORE that answers cluster-authoritative
names -- the reserved API service, and any name in the cluster zone, as NXDOMAIN
when it does not resolve -- plus any configured external SERVE-ZONES, whose
Gateway/route/ingress hostnames resolve to this node's NODE-ADDRESS (podster-iga);
it declines everything else so the proxy forwards it upstream.  The proxy's
resolver protocol is (ANSWERS HANDLED-P RCODE); gr8s's store resolver speaks
(ANSWERS EXISTS REVERSE-AUTHORITY), which this adapts, so the cluster-DNS policy
stays in gr8s while the forwarding proxy stays general."
  (let ((service-resolver (store-service-dns-resolver store)))
    (lambda (question)
      (let ((name (0conf:question-name question)))
        (cond
          ((string= (canonical-dns-name name) +dns-kubernetes-service+)
           (values (kubernetes-service-answer question) t 0))
          (t
           (multiple-value-bind (answers handled rcode)
               (external-zone-answer store serve-zones node-address question)
             (if handled
                 (values answers handled rcode)
                 (multiple-value-bind (answers exists reverse-authority)
                     (funcall service-resolver question)
                   (if (or reverse-authority (dns-name-in-zone-p name +dns-cluster-zone+))
                       (values answers t (if exists 0 +dns-name-error+))
                       (values nil nil nil)))))))))))

(defun make-external-zone-dns-resolver (store serve-zones node-address)
  "A resolver for the node's externally reachable DNS listener (podster-iga): it
answers the configured external SERVE-ZONES authoritatively (Gateway/route/ingress
hostnames -> this node's NODE-ADDRESS, NXDOMAIN for in-zone names it does not serve)
and REFUSES everything else, so the listener is authoritative-only -- never an open
forwarder for arbitrary names."
  (lambda (question)
    (multiple-value-bind (answers handled rcode)
        (external-zone-answer store serve-zones node-address question)
      (if handled
          (values answers handled rcode)
          ;; Not in a serve zone: REFUSED (rcode 5). Never forward from this listener.
          (values nil t 5)))))

(defun service-dns-endpoint-unready-p (endpoint)
  "Exclude explicitly unready endpoints while retaining unspecified or null readiness."
  (let ((conditions (gethash "conditions" endpoint (core-object))))
    (and (nth-value 1 (gethash "ready" conditions)) (null (gethash "ready" conditions)))))

(defun service-dns-endpoint-hostname (endpoint address)
  "Use the explicit endpoint hostname or a stable unique address-derived DNS label."
  (let ((hostname (gethash "hostname" endpoint)))
    (if (and (stringp hostname) (plusp (length hostname))) hostname
        (substitute #\- #\: (substitute #\- #\. (canonical-dns-name address))))))

(defun service-dns-srv-record (question port target)
  "Return a named-port record whose target and port refer to the actual selected backend."
  (make-instance '0conf:srv-record :name (0conf:question-name question)
                 :priority 10 :weight 100 :port port :target target :ttl 5))

(defun resolve-store-service-srv (store question)
  "Resolve named Service ports or actual ready headless endpoint ports and hostnames."
  (let* ((labels (uiop:split-string (canonical-dns-name (0conf:question-name question)) :separator "."))
         (port-label (first labels)) (protocol-label (second labels)))
    (unless (and (= 7 (length labels)) (equal (last labels 3) '("svc" "cluster" "local"))
                 (> (length port-label) 1) (char= #\_ (char port-label 0))
                 (> (length protocol-label) 1) (char= #\_ (char protocol-label 0)))
      (return-from resolve-store-service-srv (values nil nil)))
    (let* ((port-name (subseq port-label 1)) (protocol (string-upcase (subseq protocol-label 1)))
           (name (third labels)) (namespace (fourth labels))
           (fqdn (format nil "~A.~A.svc.cluster.local" name namespace)))
      (handler-case
          (let* ((service (get-core-resource store "services" namespace name))
                 (spec (gethash "spec" service))
                 (port (find-if (lambda (candidate)
                                  (and (equal port-name (gethash "name" candidate))
                                       (equal protocol (gethash "protocol" candidate "TCP"))))
                                (gethash "ports" spec #()))))
            ;; A headless Service's named ports are its endpoints', as CoreDNS reads them from the
            ;; slices: a selectorless one's slices may name ports its spec does not.
            (when (or (service-external-name-p service)
                      (and (null port) (not (equal "None" (gethash "clusterIP" spec)))))
              (return-from resolve-store-service-srv (values nil nil)))
            (unless (equal "None" (gethash "clusterIP" spec))
              (return-from resolve-store-service-srv
                (values (list (service-dns-srv-record question (gethash "port" port) fqdn)) t)))
            (let ((targets nil))
              (dolist (slice (list-core-resources store "endpointslices" namespace))
                (when (and (member (gethash "addressType" slice) '("IPv4" "IPv6") :test #'equal)
                           (equal name (gethash "kubernetes.io/service-name"
                                                (gethash "labels" (gethash "metadata" slice) (core-object)))))
                  (loop for backend-port across (gethash "ports" slice #())
                        when (and (equal port-name (gethash "name" backend-port))
                                  (equal protocol (gethash "protocol" backend-port "TCP"))
                                  (integerp (gethash "port" backend-port)))
                          do (loop for endpoint across (gethash "endpoints" slice #())
                                   unless (service-dns-endpoint-unready-p endpoint)
                                     do (loop for address across (gethash "addresses" endpoint #())
                                              for target = (format nil "~A.~A" (service-dns-endpoint-hostname endpoint address) fqdn)
                                              do (pushnew (list (gethash "port" backend-port) target) targets :test #'equal))))))
              (values (mapcar (lambda (target) (service-dns-srv-record question (first target) (second target)))
                              (sort targets #'string< :key (lambda (target) (format nil "~A/~A" (second target) (first target)))))
                      (not (null targets)))))
        (kubernetes-error (condition)
          (if (= 404 (kubernetes-error-status-code condition)) (values nil nil) (error condition)))))))

(defun service-dns-cname-record (question target)
  "Encode a genuine CNAME wire record without modifying the upstream DNS codec."
  (let ((writer (0conf:make-writer)))
    ;; A separate writer deliberately emits an uncompressed DNS name. This is
    ;; valid CNAME RDATA and remains independently decodable by the generic codec.
    (0conf:write-name writer target)
    (make-instance '0conf:unknown-record :rtype 0conf:+type-cname+
                   :name (0conf:question-name question) :rdata (0conf:writer-result writer) :ttl 5)))
