;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
(in-package #:gr8s.controllers)

(defparameter *foreign-gateway-slice-manager* "gateway.gr8s.io")

(defun foreign-gateway-listener-snapshots (controllers)
  "Copy socket destinations while the caller owns the listener convergence lock."
  (loop for controller being the hash-values of (foreign-gateway-controllers-gateways controllers)
        append
        (loop for gateway in (list-core-resources (gateway-controller-store controller) "gateways")
              collect
              (list gateway
                    (coerce
                     (loop for service-port across
                           (foreign-gateway-service-ports gateway nil (gateway-controller-store controller))
                           for number = (gethash "port" service-port)
                           for http = (gethash number (gateway-controller-listeners controller))
                           for l4 = (gethash number (gateway-controller-l4-listeners controller))
                           for actual = (cond (http (hunchentoot:acceptor-port (car http)))
                                              (l4 (l4-listener-port (cdr l4))))
                           when actual collect
                             (gr8s.resources::core-object "name" (gethash "name" service-port)
                                                         "protocol" "TCP" "port" actual))
                     'vector)))))

(defun foreign-gateway-slice-name (service node-name family)
  (concatenate 'string "gr8s-gw-"
               (ironclad:byte-array-to-hex-string
                (ironclad:digest-sequence :sha256
                 (trivial-utf-8:string-to-utf-8-bytes
                  (format nil "~A/~A/~A" (gethash "uid" (gethash "metadata" service)) node-name family))))))

(defun foreign-gateway-endpoint-slice (service node-name family addresses ports)
  (gr8s.resources::core-object
   "apiVersion" "discovery.k8s.io/v1" "kind" "EndpointSlice"
   "metadata" (gr8s.resources::core-object
               "name" (foreign-gateway-slice-name service node-name family)
               "namespace" (gethash "namespace" (gethash "metadata" service))
               "ownerReferences" (vector (foreign-gateway-owner-reference service))
               "labels" (gr8s.resources::core-object
                         "kubernetes.io/service-name" (gethash "name" (gethash "metadata" service))
                         "endpointslice.kubernetes.io/managed-by" *foreign-gateway-slice-manager*)
               "annotations" (gr8s.resources::core-object "gr8s.io/gateway-node" node-name))
   "addressType" family "ports" ports
   "endpoints" (vector (gr8s.resources::core-object
                        "addresses" (coerce addresses 'vector) "nodeName" node-name
                        "conditions" (gr8s.resources::core-object "ready" t)))))

(defun foreign-gateway-upsert-slice (cluster service desired)
  (let* ((metadata (gethash "metadata" desired))
         (namespace (gethash "namespace" metadata))
         (path (gr8s.kube-client:resource-path "discovery.k8s.io" "v1" "endpointslices"
                                              :namespace namespace :name (gethash "name" metadata)))
         (current (foreign-gateway-get cluster path)))
    (cond
      ((null current)
       (gr8s.kube-client:kube-create
        cluster (gr8s.kube-client:resource-path "discovery.k8s.io" "v1" "endpointslices" :namespace namespace)
        desired))
      ((not (foreign-gateway-owned-by-p current service))
       (error "Refusing unrelated EndpointSlice ~A" path))
      (t
       (let ((changed nil) (old-metadata (gethash "metadata" current)))
         (dolist (field '("addressType" "ports" "endpoints"))
           (unless (equalp (gethash field desired) (gethash field current))
             (setf changed t (gethash field current) (gethash field desired))))
         (dolist (field '("labels" "annotations" "ownerReferences"))
           (unless (equalp (gethash field metadata) (gethash field old-metadata))
             (setf changed t (gethash field old-metadata) (gethash field metadata))))
         (if changed (gr8s.kube-client:kube-replace cluster path current) current))))))

(defun foreign-gateway-local-slice-p (slice node-name &optional service)
  "Labels alone do not authorize deletion; require the exact Service owner."
  (let ((metadata (gethash "metadata" slice))
        (owner (and service (gethash "metadata" service))))
    (and service
         (foreign-gateway-owned-by-p slice service)
         (equal (gethash "namespace" metadata) (gethash "namespace" owner))
         (equal (gethash "name" metadata)
                (foreign-gateway-slice-name service node-name (gethash "addressType" slice)))
         (equal (gethash "name" owner)
                (gethash "kubernetes.io/service-name" (gethash "labels" metadata (make-hash-table))))
         (some (lambda (reference)
                 (and (eq t (gethash "controller" reference))
                      (equal "gateway.networking.k8s.io/v1" (gethash "apiVersion" reference))
                      (equal "Gateway" (gethash "kind" reference))
                      (stringp (gethash "name" reference))
                      (equal (gethash "name" owner)
                             (foreign-gateway-service-name (gethash "name" reference)))))
               (foreign-gateway-vector (gethash "ownerReferences" owner)))
         (equal *foreign-gateway-slice-manager*
                (gethash "endpointslice.kubernetes.io/managed-by"
                         (gethash "labels" metadata (make-hash-table))))
         (equal node-name (gethash "gr8s.io/gateway-node"
                                  (gethash "annotations" metadata (make-hash-table)))))))

(defun foreign-gateway-delete-slice (cluster slice)
  "Delete only the exact observed UID/version, so a replacement cannot be removed."
  (let ((metadata (gethash "metadata" slice)))
    (gr8s.kube-client:kube-request
     cluster :delete
     (gr8s.kube-client:resource-path "discovery.k8s.io" "v1" "endpointslices"
                                    :namespace (gethash "namespace" metadata) :name (gethash "name" metadata))
     :body (gr8s.resources::core-object
            "apiVersion" "v1" "kind" "DeleteOptions"
            "preconditions" (gr8s.resources::core-object
                             "uid" (gethash "uid" metadata)
                             "resourceVersion" (gethash "resourceVersion" metadata))))))

(defun foreign-gateway-withdraw-local-endpoints (cluster node-name)
  "Read the API directly at shutdown; an informer may not have seen our last write."
  (let ((page (gr8s.kube-client:kube-list
               cluster (gr8s.kube-client:resource-path "discovery.k8s.io" "v1" "endpointslices")
               :label-selector (format nil "endpointslice.kubernetes.io/managed-by=~A"
                                       *foreign-gateway-slice-manager*)
               :timeout 10)))
    (loop for slice across (foreign-gateway-vector (gethash "items" page))
          for metadata = (gethash "metadata" slice)
          when (equal node-name (gethash "gr8s.io/gateway-node"
                                         (gethash "annotations" metadata (make-hash-table))))
            do (let* ((name (gethash "kubernetes.io/service-name"
                                    (gethash "labels" metadata (make-hash-table))))
                      (service (and name (foreign-gateway-get
                                          cluster (gr8s.kube-client:resource-path
                                                   nil "v1" "services"
                                                   :namespace (gethash "namespace" metadata) :name name)))))
                 (when (foreign-gateway-local-slice-p slice node-name service)
                   (handler-case (foreign-gateway-delete-slice cluster slice)
                     (gr8s.kube-client:kube-error (condition)
                       (unless (member (gr8s.kube-client:kube-error-status condition) '(404 409))
                         (error condition)))))))))

(defun foreign-gateway-publish-endpoint-snapshot (cluster node-name addresses gateway ports)
  "Publish one Gateway and return the desired EndpointSlice key, if any."
  (let* ((metadata (gethash "metadata" gateway))
         (namespace (gethash "namespace" metadata))
         (service (foreign-gateway-get
                   cluster (gr8s.kube-client:resource-path
                            nil "v1" "services" :namespace namespace
                            :name (foreign-gateway-service-name (gethash "name" metadata)))))
         ;; HTTP and L4 acceptors currently bind IPv4 only.
         (members (remove-if (lambda (address) (find #\: address)) addresses)))
    (when (and service (foreign-gateway-owned-by-p service gateway)
               (plusp (length ports)) members)
      (let ((slice (foreign-gateway-endpoint-slice service node-name "IPv4" members ports)))
        (foreign-gateway-upsert-slice cluster service slice)
        (list namespace (gethash "name" (gethash "metadata" slice)))))))

(defun foreign-gateway-publish-local-endpoints (view cluster node-name snapshots)
  "Publish independent Gateways; preserve prior endpoints on transient API failure."
  (let* ((node (get-core-resource view "nodes" nil node-name))
         (addresses (loop for entry across (foreign-gateway-vector (gethash "addresses" (gethash "status" node)))
                          when (equal "InternalIP" (gethash "type" entry)) collect (gethash "address" entry)))
         (desired (make-hash-table :test #'equal))
         (failed-services (make-hash-table :test #'equal)))
    (dolist (snapshot snapshots)
      (destructuring-bind (gateway ports) snapshot
        (let* ((metadata (gethash "metadata" gateway))
               (service-key (list (gethash "namespace" metadata)
                                  (foreign-gateway-service-name (gethash "name" metadata)))))
          (handler-case
              (let ((key (foreign-gateway-publish-endpoint-snapshot cluster node-name addresses gateway ports)))
                (when key (setf (gethash key desired) t)))
            (error (condition)
              (setf (gethash service-key failed-services) t)
              (format *error-output* "~&gr8s Gateway ~A/~A endpoint publication failed: ~A~%"
                      (gethash "namespace" metadata) (gethash "name" metadata) condition))))))
    (dolist (slice (list-core-resources view "endpointslices"))
      (let* ((metadata (gethash "metadata" slice))
             (namespace (gethash "namespace" metadata))
             (service-name (gethash "kubernetes.io/service-name"
                                    (gethash "labels" metadata (make-hash-table))))
             (service (and service-name
                           (ignore-errors (get-core-resource view "services" namespace service-name)))))
        (when (and (foreign-gateway-local-slice-p slice node-name service)
                   (not (gethash (list namespace service-name) failed-services))
                   (not (gethash (list namespace (gethash "name" metadata)) desired)))
          (handler-case (foreign-gateway-delete-slice cluster slice)
            (gr8s.kube-client:kube-error (condition)
              (unless (member (gr8s.kube-client:kube-error-status condition) '(404 409)) (error condition)))))))))
