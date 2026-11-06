;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Keep core Endpoints in step with their sources. A selector Service's Endpoints
;;;; follow actual Pod observations, as its generated EndpointSlices do; a manual
;;;; Endpoints object behind a selectorless Service is mirrored into EndpointSlices,
;;;; so the data plane and DNS, which read only slices, serve it as well.

(in-package #:gr8s)

(defparameter *endpointslice-mirror-manager* "endpointslicemirroring-controller.k8s.io")

(defun endpoints-address-for-pod (pod address service)
  "Describe one Pod as an Endpoints address."
  (let ((result (core-object "ip" address
                             "targetRef" (core-object "kind" "Pod" "namespace" (pod-namespace pod)
                                                      "name" (pod-name pod) "uid" (pod-uid pod))))
        (spec (gethash "spec" (pod-to-object pod))))
    (when (pod-node-name pod) (setf (gethash "nodeName" result) (pod-node-name pod)))
    (when (and (plusp (length (gethash "hostname" spec "")))
               (equal (gethash "name" (gethash "metadata" service)) (gethash "subdomain" spec)))
      (setf (gethash "hostname" result) (gethash "hostname" spec)))
    result))

(defun endpoints-port-from-slice-port (port)
  "Convert a resolved EndpointSlice port to its Endpoints form, which omits an empty name."
  (let ((result (copy-core-object port)))
    (when (equal "" (gethash "name" result "")) (remhash "name" result))
    result))

(defun endpoints-service-subsets (store service)
  "Group a selector Service's observed Pods by their resolved ports. Caller holds the store lock."
  (let* ((spec (gethash "spec" service)) (selector (gethash "selector" spec))
         (namespace (gethash "namespace" (gethash "metadata" service)))
         (publish-not-ready (eq t (gethash "publishNotReadyAddresses" spec)))
         (groups (make-hash-table :test #'equal)))
    (loop for pod being the hash-values of (pod-store-pods store)
          for labels = (gethash "labels" (gethash "metadata" (pod-to-object pod)))
          for status = (gethash (pod-uid pod) (pod-store-pod-observed-statuses store))
          for address = (and status (gethash "podIP" status))
          do (when (and (equal namespace (pod-namespace pod)) (stringp address) (plusp (length address))
                        (not (member (gethash "phase" status) '("Succeeded" "Failed") :test #'equal))
                        (or publish-not-ready (not (deletion-requested-p pod)))
                        (loop for key being the hash-keys of selector using (hash-value value)
                              always (and labels (equal value (gethash key labels)))))
               (let ((ports (endpointslice-pod-ports pod service)))
                 (when (plusp (length ports))
                   (let* ((key (endpointslice-canonical-json ports))
                          (group (or (gethash key groups) (setf (gethash key groups) (list ports nil nil))))
                          (entry (endpoints-address-for-pod pod address service)))
                     (if (or publish-not-ready (pod-status-ready-p status))
                         (push entry (second group))
                         (push entry (third group))))))))
    (flet ((sorted (addresses)
             (coerce (sort addresses #'string< :key (lambda (entry) (gethash "ip" entry))) 'vector)))
      (coerce
       (loop for key in (sort (loop for key being the hash-keys of groups collect key) #'string<)
             collect (destructuring-bind (ports ready not-ready) (gethash key groups)
                       (let ((subset (core-object "ports" (map 'vector #'endpoints-port-from-slice-port ports))))
                         (when ready (setf (gethash "addresses" subset) (sorted ready)))
                         (when not-ready (setf (gethash "notReadyAddresses" subset) (sorted not-ready)))
                         subset)))
       'vector))))

(defun endpoints-desired-object (service existing subsets)
  "Build a selector Service's Endpoints, carrying the Service's labels as the upstream controller does."
  (let* ((metadata (gethash "metadata" service))
         (labels (copy-core-object (gethash "labels" metadata (core-object))))
         (result-metadata (if existing (copy-core-object (gethash "metadata" existing)) (core-object))))
    (if (equal "None" (gethash "clusterIP" (gethash "spec" service)))
        (setf (gethash "service.kubernetes.io/headless" labels) "")
        (remhash "service.kubernetes.io/headless" labels))
    (setf (gethash "name" result-metadata) (gethash "name" metadata)
          (gethash "namespace" result-metadata) (gethash "namespace" metadata)
          (gethash "labels" result-metadata) labels)
    (core-object "apiVersion" "v1" "kind" "Endpoints" "metadata" result-metadata "subsets" subsets)))

(defun endpoints-mirror-groups (endpoints)
  "Group a manual Endpoints object's addresses into (family canonical-ports) slice contents."
  (let ((groups (make-hash-table :test #'equal)))
    (loop for subset across (gethash "subsets" endpoints #())
          for ports = (map 'vector (lambda (port)
                                     (let ((entry (copy-core-object port)))
                                       (setf (gethash "name" entry) (gethash "name" entry ""))
                                       entry))
                           (gethash "ports" subset #()))
          do (loop for (field ready) in '(("addresses" t) ("notReadyAddresses" nil))
                   do (loop for address across (gethash field subset #())
                            for ip = (gethash "ip" address)
                            for family = (if (find #\: ip) "IPv6" "IPv4")
                            for key = (list family (endpointslice-canonical-json ports))
                            for group = (or (gethash key groups) (setf (gethash key groups) (list ports nil)))
                            for endpoint = (core-object "addresses" (vector ip)
                                                        "conditions" (core-object "ready" (if ready t nil)))
                            do (dolist (name '("hostname" "nodeName" "targetRef"))
                                 (when (and (gethash name address) (not (equal "" (gethash name address))))
                                   (setf (gethash name endpoint) (copy-core-object (gethash name address)))))
                               (push endpoint (second group)))))
    groups))

(defun reconcile-mirrored-endpoints-unlocked (store resources revision)
  "Update RESOURCES so mirror slices match the mirrorable Endpoints; return the new revision.
A slice belongs here only while its Endpoints exists behind a selectorless Service."
  (let ((used (make-hash-table :test #'equal))
        (existing (loop for object being the hash-values of resources
                        when (and (equal "EndpointSlice" (gethash "kind" object))
                                  (equal *endpointslice-mirror-manager*
                                         (gethash "endpointslice.kubernetes.io/managed-by"
                                                  (gethash "labels" (gethash "metadata" object) (core-object)))))
                          collect object)))
    (dolist (endpoints (loop for object being the hash-values of resources
                             when (equal "Endpoints" (gethash "kind" object)) collect object))
      (let* ((metadata (gethash "metadata" endpoints)) (namespace (gethash "namespace" metadata))
             (name (gethash "name" metadata))
             (service (gethash (core-resource-key "services" namespace name) resources)))
        (when (and service (zerop (hash-table-count (gethash "selector" (gethash "spec" service) (core-object))))
                   (not (equal "true" (gethash "endpointslice.kubernetes.io/skip-mirror"
                                               (gethash "labels" metadata (core-object))))))
          (let ((groups (endpoints-mirror-groups endpoints)))
            (dolist (key (sort (loop for key being the hash-keys of groups collect key) #'string< :key #'prin1-to-string))
              (destructuring-bind (ports endpoint-list) (gethash key groups)
                (let* ((old (find-if (lambda (slice)
                                       (and (not (gethash (gethash "uid" (gethash "metadata" slice)) used))
                                            (equal namespace (gethash "namespace" (gethash "metadata" slice)))
                                            (equal name (gethash "kubernetes.io/service-name" (gethash "labels" (gethash "metadata" slice))))
                                            (equal (first key) (gethash "addressType" slice))
                                            (equal (second key) (endpointslice-canonical-json (gethash "ports" slice)))))
                                     existing))
                       (labels (copy-core-object (gethash "labels" metadata (core-object))))
                       (slice-meta (if old (copy-core-object (gethash "metadata" old)) (core-object))))
                  (setf (gethash "kubernetes.io/service-name" labels) name
                        (gethash "endpointslice.kubernetes.io/managed-by" labels) *endpointslice-mirror-manager*
                        (gethash "labels" slice-meta) labels (gethash "namespace" slice-meta) namespace
                        (gethash "ownerReferences" slice-meta)
                        (vector (core-object "apiVersion" "v1" "kind" "Endpoints" "name" name
                                             "uid" (gethash "uid" metadata) "controller" t)))
                  (unless old
                    (loop for candidate = (concatenate 'string (subseq name 0 (min 57 (length name))) "-"
                                                       (string-downcase (subseq (generate-uid) 0 5)))
                          unless (gethash (core-resource-key "endpointslices" namespace candidate) resources)
                            do (setf (gethash "name" slice-meta) candidate) (return)))
                  (let* ((object (normalize-endpointslice-resource
                                  (core-object "metadata" slice-meta "addressType" (first key)
                                               "ports" (copy-core-object ports)
                                               "endpoints" (coerce (reverse endpoint-list) 'vector))
                                  namespace (gethash "name" slice-meta)))
                         (resource-key (core-resource-key "endpointslices" namespace (gethash "name" slice-meta))))
                    (when (or (null old) (not (equal (endpointslice-canonical-json old) (endpointslice-canonical-json object))))
                      (prepare-endpointslice-write object old)
                      (prepare-core-resource-metadata object old (incf revision))
                      (setf (gethash resource-key resources) object))
                    (setf (gethash (gethash "uid" (gethash "metadata" (or old object))) used) t)))))))))
    (dolist (slice existing)
      (let ((slice-meta (gethash "metadata" slice)))
        (unless (gethash (gethash "uid" slice-meta) used)
          (remhash (core-resource-key "endpointslices" (gethash "namespace" slice-meta) (gethash "name" slice-meta)) resources)
          (incf revision))))
    revision))

(defun endpoints-planned-writes-unlocked (store resources)
  "Return (key object existing) for each selector Service whose Endpoints should change. Caller holds the store lock."
  (loop for service being the hash-values of (pod-store-resources store)
        for spec = (gethash "spec" service) for metadata = (gethash "metadata" service)
        when (and (equal "Service" (gethash "kind" service))
                  (not (service-external-name-p service))
                  (plusp (hash-table-count (gethash "selector" spec (core-object)))))
          nconc (let* ((key (core-resource-key "endpoints" (gethash "namespace" metadata) (gethash "name" metadata)))
                       (existing (gethash key resources))
                       (object (endpoints-desired-object service existing (endpoints-service-subsets store service))))
                  (when (or (null existing)
                            (not (equal (endpointslice-canonical-json (gethash "subsets" existing #()))
                                        (endpointslice-canonical-json (gethash "subsets" object))))
                            (not (equal (endpointslice-canonical-json (gethash "labels" (gethash "metadata" existing) (core-object)))
                                        (endpointslice-canonical-json (gethash "labels" (gethash "metadata" object))))))
                    (list (list key object existing))))))

(defun reconcile-endpoints (store)
  "Publish selector Services' Endpoints and mirror manual Endpoints in one store transaction.
While admission is configured, the Endpoints writes are first admitted outside the lock, as
upstream's endpoint controller writes them through the API, and committed if nothing changed
meanwhile; a refused write waits for a later pass. Mirrored slices stay a direct write."
  (let ((admitted :direct) (planned-at nil))
    (when (endpointslice-admission-configured-p store)
      (multiple-value-bind (writes revision)
          (with-store-lock (store)
            (values (endpoints-planned-writes-unlocked store (copy-core-resource-index store))
                    (pod-store-resource-revision store)))
        (setf planned-at revision
              admitted (loop for (key object existing) in writes
                             for result = (handler-case
                                              (admit-controller-write store "endpoints" object existing (second key)
                                                                      "endpoint-controller")
                                            (kubernetes-error (condition)
                                              (format *error-output* "~&gr8s endpoints controller: ~A~%"
                                                      (kubernetes-error-message condition))
                                              nil))
                             when result collect (list key result existing)))))
    (with-store-lock (store)
      (when (or (eq admitted :direct) (= planned-at (pod-store-resource-revision store)))
        (let ((resources (copy-core-resource-index store))
              (revision (pod-store-resource-revision store)))
          (loop for (key object existing) in (if (eq admitted :direct)
                                                 (endpoints-planned-writes-unlocked store resources)
                                                 admitted)
                do (prepare-core-resource-metadata object existing (incf revision))
                   (setf (gethash key resources) object))
          (setf revision (reconcile-mirrored-endpoints-unlocked store resources revision))
          (unless (= revision (pod-store-resource-revision store))
            (commit-core-resources store resources revision))))))
  store)
