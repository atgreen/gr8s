;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;; kubelet PodResources v1: reservations, not usage measurements.
(in-package #:gr8s.kubelet)

(defun podresources-topology (nodes)
  (when nodes (make-instance 'pr::topology-info :nodes (mapcar (lambda (id) (make-instance 'pr::numa-node :id id)) nodes))))

(defun podresources-memory (amounts node)
  (when node
    (loop for name being the hash-keys of amounts using (hash-value bytes)
          when (plusp bytes) collect (make-instance 'pr::container-memory :memory-type name :size (ceiling bytes)
                                                                          :topology (podresources-topology (list node))))))

(defun podresources-devices (manager uid name &key allocatable)
  "Preserve device-to-NUMA associations, including different affinities in one resource."
  (when manager
    (bt:with-lock-held ((device-plugin-manager-allocation-lock manager))
      (bt:with-lock-held ((device-plugin-manager-lock manager))
        (let ((resources (if allocatable (device-plugin-manager-plugins manager)
                             (gethash name (gethash uid (device-plugin-manager-allocations manager) (core-object)) (core-object)))))
          (loop for resource being the hash-keys of resources using (hash-value reservation)
                for plugin = (gethash resource (device-plugin-manager-plugins manager))
                append (let ((groups (make-hash-table :test #'equal)))
                         (dolist (id (if allocatable
                                         (loop for device in (device-plugin-devices plugin) when (equal "Healthy" (dp::health device)) collect (dp::id device))
                                         (coerce (gethash "ids" reservation) 'list)))
                           (let* ((device (and plugin (find id (device-plugin-devices plugin) :key #'dp::id :test #'equal)))
                                  (nodes (and device (dp::topology device) (sort (mapcar #'dp::id (dp::nodes (dp::topology device))) #'<))))
                             (push id (gethash nodes groups))))
                         (loop for nodes being the hash-keys of groups using (hash-value ids)
                               collect (make-instance 'pr::container-devices :resource-name resource :device-ids (sort ids #'string<)
                                                                               :topology (podresources-topology nodes))))))))))

(defun podresources-dynamic-resources (manager pod container)
  "Report prepared DRA claims scoped to each container's request references."
  (when manager
    (bt:with-lock-held ((dra-manager-lock manager))
      (let ((pairs (pod-resource-claim-pairs pod)))
        (loop for reference across (gethash "claims" (gethash "resources" container (core-object)) #())
              for name = (cdr (assoc (gethash "name" reference) pairs :test #'equal))
              for prepared = (and name (gethash (core-resource-key "resourceclaims" (pod-namespace pod) name) (dra-manager-claims manager)))
              when prepared collect
                (make-instance 'pr::dynamic-resource :claim-name name :claim-namespace (pod-namespace pod)
                  :claim-resources
                  (loop for driver being the hash-keys of (dra-prepared-claim-driver-devices prepared) using (hash-value devices)
                        append (loop for device in devices
                                     when (or (null (gr8s.dra.v1::request-names device))
                                              (some (lambda (request) (dra-request-matches-p (gethash "request" reference) request))
                                                    (gr8s.dra.v1::request-names device)))
                                       collect (make-instance 'pr::claim-resource :driver-name driver
                                                              :pool-name (gr8s.dra.v1::pool-name device)
                                                              :device-name (gr8s.dra.v1::device-name device)
                                                              :share-id (gr8s.dra.v1::share-id device)
                                                              :cdi-devices (mapcar (lambda (id) (make-instance 'pr::cdi-device :name id))
                                                                                  (gr8s.dra.v1::cdi-device-ids device)))))))))))

(defun podresources-reported-containers (pod)
  "Match kubelet v1: report application containers and restartable init sidecars."
  (let ((spec (resource-pod-spec pod)))
    (append (remove-if-not (lambda (container) (equal "Always" (gethash "restartPolicy" container)))
                           (coerce (gethash "initContainers" spec #()) 'list))
            (coerce (gethash "containers" spec #()) 'list))))

(defun podresources-pod (manager dra pod)
  "Called under the resource-manager lock so a response has coherent CPU reservations."
  (let* ((plan (gethash (pod-uid pod) (node-resource-manager-allocations manager)))
         (node (and plan (gethash "node" plan)))
         (pod-level (and plan (eq t (gethash "podLevel" plan)))))
    (make-instance 'pr::pod-resources :name (pod-name pod) :namespace (pod-namespace pod)
      :cpu-ids (when pod-level (coerce (gethash "cpus" plan) 'list))
      :memory (when (and plan (eq t (gethash "podLevelMemory" plan))) (podresources-memory (gethash "memory" plan) node))
      :containers
      (loop for container in (podresources-reported-containers pod)
            for name = (gethash "name" container)
            for allocation = (and plan (gethash name (gethash "containers" plan)))
            collect (make-instance 'pr::container-resources :name name
                      :cpu-ids (when (and allocation (not (eq t (gethash "shared" allocation))))
                                 (coerce (gethash "cpus" allocation) 'list))
                      :memory (when allocation (podresources-memory (gethash "memory" allocation) node))
                      :devices (podresources-devices (node-resource-manager-devices manager) (pod-uid pod) name)
                      :dynamic-resources (podresources-dynamic-resources dra pod container))))))

(defun podresources-list (manager dra)
  (bt:with-lock-held ((node-resource-manager-lock manager))
    (make-instance 'pr::list-pod-resources-response
      :pod-resources (loop for pod in (list-pods (node-resource-manager-store manager))
                           unless (terminal-pod-phase-p (gethash "phase" (or (pod-observed-status (node-resource-manager-store manager) pod) (core-object))))
                           collect (podresources-pod manager dra pod)))))

(defun podresources-get (manager dra request)
  (bt:with-lock-held ((node-resource-manager-lock manager))
    (let ((pod (find-if (lambda (pod) (and (equal (pr::pod-name request) (pod-name pod))
                                          (equal (pr::pod-namespace request) (pod-namespace pod))))
                        (list-pods (node-resource-manager-store manager)))))
      (unless pod (error 'ag-grpc:grpc-status-error :code ag-grpc:+grpc-status-not-found+ :message "Pod not found"))
      (make-instance 'pr::get-pod-resources-response :pod-resources (podresources-pod manager dra pod)))))

(defun podresources-allocatable (manager)
  "Total allocatable inventory includes assigned resources, as the standard API requires."
  (bt:with-lock-held ((node-resource-manager-lock manager))
    (let ((topology (node-resource-manager-topology manager)))
      (make-instance 'pr::allocatable-resources-response
        :devices (podresources-devices (node-resource-manager-devices manager) nil nil :allocatable t)
        :cpu-ids (when (equal "static" (node-resource-manager-policy manager))
                   (sort (set-difference (coerce (gethash "online" topology) 'list) (node-resource-manager-reserved manager)) #'<))
        :memory (when (equal "single-numa-node" (node-resource-manager-topology-policy manager))
                  (loop for node in (topology-node-ids topology)
                        append (let ((amounts (core-object "memory" (topology-node-memory topology node "memory"))))
                                 (maphash (lambda (resource bytes) (declare (ignore bytes))
                                            (setf (gethash resource amounts) (topology-node-memory topology node resource)))
                                          (gethash "hugepages" (find node (gethash "nodes" topology) :key (lambda (n) (gethash "id" n)))))
                                 (podresources-memory amounts node))))))))

(defun start-podresources-server (manager dra &key (path #P"/var/lib/kubelet/pod-resources/kubelet.sock"))
  (start-local-resource-server
   path (lambda (server)
          (dolist (method (list (list "List" 'pr::list-pod-resources-request 'pr::list-pod-resources-response
                                      (lambda (request context) (declare (ignore request context)) (podresources-list manager dra)))
                               (list "Get" 'pr::get-pod-resources-request 'pr::get-pod-resources-response
                                     (lambda (request context) (declare (ignore context)) (podresources-get manager dra request)))
                               (list "GetAllocatableResources" 'pr::allocatable-resources-request 'pr::allocatable-resources-response
                                     (lambda (request context) (declare (ignore request context)) (podresources-allocatable manager)))))
            (ag-grpc:server-register-handler server (concatenate 'string "/v1.PodResourcesLister/" (first method))
                                           (fourth method) :request-type (second method) :response-type (third method))))))
