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
    (unless (member kind '("Service" "EndpointSlice" "NetworkPolicy" "Ingress" "IngressClass"
                           "GatewayClass" "Gateway" "HTTPRoute" "TCPRoute" "TLSRoute" "GRPCRoute"
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
          (gethash "apiVersion" result) (cond ((equal kind "Service") "v1")
                                              ((equal kind "Secret") "v1")
                                              ((equal kind "ClusterTrustBundle") "certificates.k8s.io/v1")
                                              ((equal kind "PodCertificateRequest") "certificates.k8s.io/v1")
                                              ((member kind '("NetworkPolicy" "Ingress" "IngressClass") :test #'equal)
                                               "networking.k8s.io/v1")
                                              ((member kind '("GatewayClass" "Gateway" "HTTPRoute" "TCPRoute" "TLSRoute" "GRPCRoute") :test #'equal)
                                               "gateway.networking.k8s.io/v1")
                                              (t "discovery.k8s.io/v1"))
          (gethash "metadata" result) metadata)
    (cond
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
                      "GatewayClass" "Gateway" "HTTPRoute" "TCPRoute" "TLSRoute" "GRPCRoute") :test #'equal)
       ;; The agent's Gateway controller reconciles these into L7 proxy listeners,
       ;; so it needs the full spec (controllerName / listeners / parentRefs+rules).
       (setf (gethash "spec" result) (copy-core-object (gethash "spec" object)))
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
                                      (not (gethash (cons namespace name) seen)))
                             (setf (gethash (cons namespace name) seen) t)
                             (let ((secret (ignore-errors
                                            (get-core-resource store "secrets" namespace name))))
                               (when secret (push secret secrets)))))))))))
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
                       (when secret (push secret secrets)))))))
    (nreverse secrets)))

(defun service-discovery-projection (store)
  "Serialize each public Service and EndpointSlice once in stable key order."
  (mapcar (lambda (object)
            (trivial-utf-8:string-to-utf-8-bytes
             (endpointslice-canonical-json (service-discovery-public-object object))))
          (sort (append (list-core-resources store "services")
                        (list-core-resources store "endpointslices")
                        ;; Resolved against the cluster's Pods and Namespaces, which nodes do not see.
                        (network-policy-projection store)
                        (list-core-resources store "ingressclasses")
                        (list-core-resources store "ingresses")
                        (list-core-resources store "gatewayclasses")
                        (list-core-resources store "gateways")
                        (list-core-resources store "httproutes")
                        (list-core-resources store "tcproutes")
                        (list-core-resources store "tlsroutes")
                        (list-core-resources store "grpcroutes")
                        (list-core-resources store "clustertrustbundles")
                        (list-core-resources store "podcertificaterequests")
                        (gateway-referenced-tls-secrets store)
                        (ingress-referenced-tls-secrets store))
                #'string< :key (lambda (object)
                                 (let ((metadata (gethash "metadata" object)))
                                   (format nil "~A/~A/~A" (gethash "kind" object)
                                           (gethash "namespace" metadata) (gethash "name" metadata)))))))

(defun install-service-discovery-projection (resources projection)
  "Validate public discovery entries and add them to the same atomic resource index."
  (dolist (bytes projection)
    (let* ((object (com.inuoe.jzon:parse (trivial-utf-8:utf-8-bytes-to-string bytes)
                                       :max-string-length (* 2 1024 1024)))
           (public (service-discovery-public-object object))
           (metadata (gethash "metadata" public))
           (namespace (gethash "namespace" metadata)) (name (gethash "name" metadata))
           (resource (cond ((equal "Service" (gethash "kind" public)) "services")
                           ((equal "NetworkPolicy" (gethash "kind" public)) "networkpolicies")
                           ((equal "IngressClass" (gethash "kind" public)) "ingressclasses")
                           ((equal "Ingress" (gethash "kind" public)) "ingresses")
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
                   (if (member resource '("gatewayclasses" "ingressclasses" "clustertrustbundles") :test #'equal)
                       (null namespace) (dns-label-p namespace)))
        (invalid-pod "public Service discovery metadata is invalid"))
      (setf (gethash (core-resource-key resource namespace name) resources) public))))

(defun service-dns-address-answer (question address)
  "Build an A or AAAA answer matching the requested family, or return NIL."
  (let ((type (0conf:question-qtype question)))
    (cond ((and (= type 0conf:+type-a+) (not (find #\: address)))
           (make-instance '0conf:a-record :name (0conf:question-name question)
                          :address (0conf:parse-ipv4 address) :ttl 5))
          ((and (= type 0conf:+type-aaaa+) (find #\: address))
           (make-instance '0conf:aaaa-record :name (0conf:question-name question)
                          :address (0conf:parse-ipv6 address) :ttl 5)))))

(defun resolve-store-service-question (store question)
  "Resolve a normal or headless Service and optional headless endpoint hostname."
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
            (values (remove nil (mapcar (lambda (address) (service-dns-address-answer question address))
                                        (sort addresses #'string<)))
                    (if (equal "None" (gethash "clusterIP" spec))
                        (not (null addresses))
                        (null hostname))))
        (kubernetes-error (condition)
          (if (= 404 (kubernetes-error-status-code condition)) (values nil nil) (error condition)))))))

(defun store-service-dns-resolver (store)
  "Capture the agent's durable store for both DNS worker threads."
  (lambda (question)
    (if (and (= (0conf:question-qtype question) 0conf:+type-ptr+)
             (service-dns-reverse-address (0conf:question-name question)))
        (resolve-store-service-ptr store question)
        (resolve-store-service-question store question))))

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
