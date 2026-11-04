;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Project public Service discovery data over authenticated node snapshots and
;;;; resolve Service names from durable local ClusterIP and ready EndpointSlice data.

(in-package #:gr8s)

(defun service-discovery-public-object (object)
  "Copy only public DNS fields; exclude arbitrary annotations and unrelated resources."
  (let* ((kind (gethash "kind" object)) (source (gethash "metadata" object))
         (metadata (core-object)) (result (core-object)))
    (unless (member kind '("Service" "EndpointSlice") :test #'equal)
      (invalid-pod "unsupported public Service discovery kind"))
    (dolist (key '("name" "namespace" "uid" "resourceVersion"))
      (when (gethash key source) (setf (gethash key metadata) (gethash key source))))
    (when (equal kind "EndpointSlice")
      (setf (gethash "labels" metadata)
            (core-object "kubernetes.io/service-name"
                         (gethash "kubernetes.io/service-name" (gethash "labels" source (core-object))))))
    (setf (gethash "kind" result) kind
          (gethash "apiVersion" result) (if (equal kind "Service") "v1" "discovery.k8s.io/v1")
          (gethash "metadata" result) metadata)
    (if (equal kind "Service")
        (let ((spec (core-object)))
          (dolist (key '("clusterIP" "clusterIPs" "ipFamilies" "ports" "type"))
            (when (gethash key (gethash "spec" object))
              (setf (gethash key spec) (copy-core-object (gethash key (gethash "spec" object))))))
          (setf (gethash "spec" result) spec))
        (dolist (key '("addressType" "endpoints" "ports"))
          (setf (gethash key result) (copy-core-object (gethash key object)))))
    result))

(defun service-discovery-projection (store)
  "Serialize each public Service and EndpointSlice once in stable key order."
  (mapcar (lambda (object)
            (trivial-utf-8:string-to-utf-8-bytes
             (endpointslice-canonical-json (service-discovery-public-object object))))
          (sort (append (list-core-resources store "services")
                        (list-core-resources store "endpointslices"))
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
           (resource (if (equal "Service" (gethash "kind" public)) "services" "endpointslices")))
      (unless (and (dns-label-p namespace) (stringp name) (plusp (length name)))
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
  (lambda (question) (resolve-store-service-question store question)))

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
            (unless port (return-from resolve-store-service-srv (values nil nil)))
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
