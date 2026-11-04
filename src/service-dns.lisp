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
                          unless (or (let ((conditions (gethash "conditions" endpoint (core-object))))
                                       (and (nth-value 1 (gethash "ready" conditions))
                                            (null (gethash "ready" conditions))))
                                     (and hostname (not (equal hostname (gethash "hostname" endpoint)))))
                            do (loop for address across (gethash "addresses" endpoint #())
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
