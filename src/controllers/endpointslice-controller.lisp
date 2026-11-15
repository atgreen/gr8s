;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Publish actual selector-Service backends as durable EndpointSlices. One store
;;;; transaction snapshots Pod observations, partitions address families and named
;;;; ports, and updates only exact Service-owned slices; manual slices survive.

(in-package #:gr8s.controllers)

(defparameter *endpointslice-manager* "endpointslice-controller.k8s.io")
(defparameter *endpoints-per-slice* 100)

(defun endpointslice-canonical-json (value)
  "Compare JSON maps without depending on key insertion order or folding string case."
  (labels ((ordered (item)
             (cond ((hash-table-p item)
                    (let ((copy (core-object)))
                      (dolist (key (sort (loop for key being the hash-keys of item collect key) #'string<))
                        (setf (gethash key copy) (ordered (gethash key item)))) copy))
                   ((and (vectorp item) (not (stringp item))) (map 'vector #'ordered item))
                   (t item))))
    (com.inuoe.jzon:stringify (ordered value))))

(defun endpointslice-service-owner-p (slice service)
  "Require matching namespace, Service UID and authoritative manager before modifying a slice."
  (let ((metadata (gethash "metadata" slice)) (owner (gethash "metadata" service)))
    (and (equal (gethash "namespace" metadata) (gethash "namespace" owner))
         (equal *endpointslice-manager* (gethash "endpointslice.kubernetes.io/managed-by" (gethash "labels" metadata (core-object))))
         (find-if (lambda (ref) (and (equal "v1" (gethash "apiVersion" ref)) (equal "Service" (gethash "kind" ref))
                                    (equal (gethash "uid" owner) (gethash "uid" ref)) (eq t (gethash "controller" ref))))
                  (gethash "ownerReferences" metadata #())))))

(defun endpointslice-pod-ports (pod service)
  "Resolve every Service target port against this Pod; partition heterogeneous named targets."
  (let ((result nil))
    (loop for port across (json-array (gethash "ports" (gethash "spec" service)))
          for target = (service-port-target pod port)
          do (when target
               (let ((entry (core-object "name" (gethash "name" port "") "protocol" (gethash "protocol" port "TCP") "port" target)))
                 (when (gethash "appProtocol" port) (setf (gethash "appProtocol" entry) (gethash "appProtocol" port)))
                 (push entry result))))
    (coerce (nreverse result) 'vector)))

(defun endpointslice-pod-endpoint (store pod status service address)
  "Describe the actual Pod identity, address, readiness and termination state. Caller holds the store lock."
  (let* ((deleting (deletion-requested-p pod)) (node (and (pod-node-name pod) (gethash (pod-node-name pod) (pod-store-nodes store))))
         (serving (and (pod-status-ready-p status) (or (null node) (node-record-ready-p node))))
         (ready (or (eq t (gethash "publishNotReadyAddresses" (gethash "spec" service))) (and serving (not deleting))))
         (endpoint (core-object "addresses" (vector address)
                                "conditions" (core-object "ready" (if ready t nil) "serving" (if serving t nil)
                                                          "terminating" (if deleting t nil))
                                "targetRef" (core-object "apiVersion" "v1" "kind" "Pod" "namespace" (pod-namespace pod)
                                                         "name" (pod-name pod) "uid" (pod-uid pod)))))
    (when (pod-node-name pod) (setf (gethash "nodeName" endpoint) (pod-node-name pod)))
    (let ((zone (and node (gethash "topology.kubernetes.io/zone" (node-labels node))))
          (distribution (gethash "trafficDistribution" (gethash "spec" service))))
      (when (and (stringp zone) (plusp (length zone))) (setf (gethash "zone" endpoint) zone))
      ;; Hints for a ready endpoint, as upstream's preferClose heuristic writes them.
      (when (and ready (member distribution '("PreferClose" "PreferSameZone" "PreferSameNode") :test #'equal))
        (let ((hints (core-object)))
          (when (gethash "zone" endpoint)
            (setf (gethash "forZones" hints) (vector (core-object "name" (gethash "zone" endpoint)))))
          (when (and (equal distribution "PreferSameNode") (pod-node-name pod))
            (setf (gethash "forNodes" hints) (vector (core-object "name" (pod-node-name pod)))))
          (when (plusp (hash-table-count hints)) (setf (gethash "hints" endpoint) hints)))))
    (let* ((spec (gethash "spec" (pod-to-object pod))) (hostname (gethash "hostname" spec))
           (subdomain (gethash "subdomain" spec)) (name (gethash "name" (gethash "metadata" service))))
      (when (and hostname (plusp (length hostname)) (equal name subdomain)) (setf (gethash "hostname" endpoint) hostname)))
    endpoint))

(defun endpointslice-service-groups (store service)
  "Group observed, nonterminal selector matches by address family and resolved ports. Caller holds the store lock."
  (let* ((spec (gethash "spec" service)) (selector (gethash "selector" spec))
         (namespace (gethash "namespace" (gethash "metadata" service)))
         (families (gethash "ipFamilies" spec #("IPv4"))) (groups (make-hash-table :test #'equal)))
    (when (and (not (service-external-name-p service)) (hash-table-p selector) (plusp (hash-table-count selector)))
      (dolist (pod (sort (loop for pod being the hash-values of (pod-store-pods store)
                              when (equal namespace (pod-namespace pod)) collect pod) #'string< :key #'pod-uid))
        (let* ((labels (gethash "labels" (gethash "metadata" (pod-to-object pod))))
               (status (gethash (pod-uid pod) (pod-store-pod-observed-statuses store))))
          (when (and status (not (member (gethash "phase" status) '("Succeeded" "Failed") :test #'equal))
                     (loop for key being the hash-keys of selector using (hash-value value)
                           always (and labels (equal value (gethash key labels)))))
            (let* ((ports (endpointslice-pod-ports pod service))
                   (addresses (or (gethash "podIPs" status)
                                  (when (gethash "podIP" status) (vector (core-object "ip" (gethash "podIP" status)))) #())))
              (when (plusp (length ports))
                (loop for family across families
                      for address = (loop for item across addresses for value = (gethash "ip" item)
                                          when (endpointslice-address-p value family) return value)
                      when address
                        do (let* ((key (list family (endpointslice-canonical-json ports)))
                                  (group (or (gethash key groups) (setf (gethash key groups) (list ports nil)))))
                             (push (endpointslice-pod-endpoint store pod status service address) (second group)))))))))
      ;; Kubernetes keeps an empty slice so selector Services remain discoverable before Pods receive addresses.
      (when (zerop (hash-table-count groups))
        (loop for family across families do (setf (gethash (list family "[]") groups) (list #() nil)))))
    groups))

(defun reconcile-service-endpointslices (store service &key plan)
  "Commit one Service's generated slices atomically without changing manually managed slices. Caller holds the store lock.
With PLAN, commit nothing and return the writes, as (key object old) lists, the deletions, as
(name old) lists, and the revision they were planned at."
  (let* ((metadata (gethash "metadata" service)) (namespace (gethash "namespace" metadata))
         (name (gethash "name" metadata)) (resources (copy-core-resource-index store))
         (revision (pod-store-resource-revision store)) (groups (endpointslice-service-groups store service))
         (existing (sort (loop for object being the hash-values of resources
                              when (and (equal "EndpointSlice" (gethash "kind" object))
                                        (endpointslice-service-owner-p object service)) collect object)
                         #'string< :key (lambda (object)
                                         (let ((endpoints (gethash "endpoints" object)))
                                           (if (plusp (length endpoints))
                                               (let ((reference (gethash "targetRef" (aref endpoints 0))))
                                                 (if (hash-table-p reference) (gethash "uid" reference "") ""))
                                               (gethash "name" (gethash "metadata" object)))))))
         (used (make-hash-table :test #'equal))
         (planned-writes nil) (planned-deletes nil) (planned-at revision))
    (dolist (key (sort (loop for key being the hash-keys of groups collect key) #'string< :key #'prin1-to-string))
      (destructuring-bind (ports endpoints) (gethash key groups)
        (let ((remaining (nreverse endpoints)) (first t))
          (loop while (or first remaining)
                do (setf first nil)
                   (let* ((chunk (subseq remaining 0 (min *endpoints-per-slice* (length remaining))))
                          (old (find-if (lambda (slice)
                                          (and (not (gethash (gethash "uid" (gethash "metadata" slice)) used))
                                               (equal (first key) (gethash "addressType" slice))
                                               (equal (second key) (endpointslice-canonical-json (gethash "ports" slice))))) existing))
                          (labels (copy-core-object (gethash "labels" metadata (core-object))))
                          (slice-meta (if old (copy-core-object (gethash "metadata" old)) (core-object))))
                     (setf remaining (nthcdr (length chunk) remaining)
                           (gethash "kubernetes.io/service-name" labels) name
                           (gethash "endpointslice.kubernetes.io/managed-by" labels) *endpointslice-manager*
                           (gethash "labels" slice-meta) labels (gethash "namespace" slice-meta) namespace
                           (gethash "ownerReferences" slice-meta)
                           (vector (core-object "apiVersion" "v1" "kind" "Service" "name" name "uid" (gethash "uid" metadata) "controller" t)))
                     (if (equal "None" (gethash "clusterIP" (gethash "spec" service)))
                         (setf (gethash "service.kubernetes.io/headless" labels) "")
                         (remhash "service.kubernetes.io/headless" labels))
                     (unless old
                       (loop for candidate = (concatenate 'string (subseq name 0 (min 57 (length name))) "-"
                                                         (string-downcase (subseq (generate-uid) 0 5)))
                             unless (gethash (core-resource-key "endpointslices" namespace candidate) resources)
                               do (setf (gethash "name" slice-meta) candidate) (return)))
                     (let* ((object (normalize-endpointslice-resource
                                     (core-object "metadata" slice-meta "addressType" (first key) "ports" (copy-core-object ports)
                                                  "endpoints" (coerce chunk 'vector)) namespace (gethash "name" slice-meta)))
                            (resource-key (core-resource-key "endpointslices" namespace (gethash "name" slice-meta))))
                       (when (or (null old) (not (equal (endpointslice-canonical-json old) (endpointslice-canonical-json object))))
                         (if plan
                             (push (list resource-key object old) planned-writes)
                             (progn
                               (prepare-endpointslice-write object old)
                               (prepare-core-resource-metadata object old (incf revision))
                               (setf (gethash resource-key resources) object))))
                       (setf (gethash (gethash "uid" (gethash "metadata" (or old object))) used) t)))))))
    (dolist (slice existing)
      (let ((slice-meta (gethash "metadata" slice)))
        (unless (gethash (gethash "uid" slice-meta) used)
          (if plan
              (push (list (gethash "name" slice-meta) slice) planned-deletes)
              (progn
                (remhash (core-resource-key "endpointslices" namespace (gethash "name" slice-meta)) resources)
                (incf revision))))))
    (if plan
        (values (nreverse planned-writes) (nreverse planned-deletes) planned-at)
        (unless (= revision (pod-store-resource-revision store)) (commit-core-resources store resources revision)))))

(defun endpointslice-admission-configured-p (store)
  "Report whether any webhook or admission policy exists that could select generated slices."
  (some (lambda (resource) (list-core-resources store resource))
        '("mutatingwebhookconfigurations" "validatingwebhookconfigurations"
          "mutatingadmissionpolicies" "validatingadmissionpolicies")))

(defun reconcile-service-endpointslices-admitted (store service)
  "Plan one Service's slice writes, admit each as the endpointslice controller outside the store
lock, as upstream's controller writes through the API, and commit what was admitted if
nothing changed meanwhile. A refused write is left for a later pass."
  (let* ((metadata (gethash "metadata" service)) (namespace (gethash "namespace" metadata)))
    (multiple-value-bind (writes deletes planned-at)
        (with-store-lock (store) (reconcile-service-endpointslices store service :plan t))
      (when (or writes deletes)
        (flet ((refused (condition)
                 (format *error-output* "~&gr8s endpointslice controller: ~A~%" (kubernetes-error-message condition))
                 nil))
          (let ((admitted (loop for (key object old) in writes
                                for result = (handler-case
                                                 (admit-controller-write store "endpointslices" object old namespace
                                                                         "endpointslice-controller")
                                               (kubernetes-error (condition) (refused condition)))
                                when result collect (list key result old)))
                (removed (remove-if-not (lambda (entry)
                                          (controller-delete-allowed-p store "endpointslices" namespace (first entry)
                                                                       "endpointslice-controller"))
                                        deletes)))
            (with-store-lock (store)
              ;; Anything else written meanwhile may have changed the plan: the next pass replans.
              (when (= planned-at (pod-store-resource-revision store))
                (let ((resources (copy-core-resource-index store)) (revision planned-at))
                  (loop for (key object old) in admitted
                        do (let ((object (normalize-endpointslice-resource object namespace (third key))))
                             (prepare-endpointslice-write object old)
                             (prepare-core-resource-metadata object old (incf revision))
                             (setf (gethash key resources) object)))
                  (loop for (name) in removed
                        do (remhash (core-resource-key "endpointslices" namespace name) resources)
                           (incf revision))
                  (unless (= revision planned-at) (commit-core-resources store resources revision)))))))))))

(defun reconcile-endpointslices (store)
  "Publish selector Services from durable actual Pod observations under one store snapshot.
While admission is configured, each Service's writes are admitted first, outside the lock."
  (if (endpointslice-admission-configured-p store)
      (dolist (service (with-store-lock (store)
                         (loop for object being the hash-values of (pod-store-resources store)
                               when (equal "Service" (gethash "kind" object)) collect object)))
        (reconcile-service-endpointslices-admitted store service))
      (with-store-lock (store)
        (dolist (service (loop for object being the hash-values of (pod-store-resources store)
                              when (equal "Service" (gethash "kind" object)) collect object))
          (reconcile-service-endpointslices store service))))
  store)

(defun service-slice-endpoint-records (store service port &key proxy)
  "Read every endpoint of PORT's protocol from the Service's IPv4 slices, ready or not, as kube-proxy does.
For the PROXY, as kube-proxy's informer does, a slice labelled service.kubernetes.io/headless is ignored.
Returns (values records found). Each record is a plist with :address, :port, :ready, :serving,
:terminating, :node, :zone, :zone-hints and :node-hints; an unset condition counts as true, except
terminating, as upstream's proxy reads them."
  (let* ((metadata (gethash "metadata" service)) (name (gethash "name" metadata))
         (port-name (gethash "name" port "")) (result nil) (found nil))
    (dolist (slice (list-core-resources store "endpointslices" (gethash "namespace" metadata)))
      (when (and (member (gethash "addressType" slice) '("IPv4" "IPv6") :test #'equal)
                 (equal name (gethash "kubernetes.io/service-name" (gethash "labels" (gethash "metadata" slice) (core-object)))))
        (setf found t)
        (let ((target (find-if (lambda (candidate)
                                 (and (equal port-name (gethash "name" candidate ""))
                                      (equal (gethash "protocol" port "TCP") (gethash "protocol" candidate "TCP"))))
                               (gethash "ports" slice #()))))
          (when (and target (integerp (gethash "port" target))
                     (not (and proxy (nth-value 1 (gethash "service.kubernetes.io/headless"
                                                            (gethash "labels" (gethash "metadata" slice) (core-object)))))))
            (loop for endpoint across (json-array (gethash "endpoints" slice #()))
                  for conditions = (gethash "conditions" endpoint (core-object))
                  for hints = (gethash "hints" endpoint)
                  do (flet ((condition-true-p (key default)
                              (multiple-value-bind (value present) (gethash key conditions)
                                (if (and present (not (eq value 'null))) (eq value t) default)))
                            (hint-names (key)
                              (and (hash-table-p hints)
                                   (loop for hint across (json-array (gethash key hints #())) collect (gethash "name" hint)))))
                       (let ((record (list :port (gethash "port" target)
                                           :ready (condition-true-p "ready" t)
                                           :serving (condition-true-p "serving" t)
                                           :terminating (condition-true-p "terminating" nil)
                                           :node (gethash "nodeName" endpoint)
                                           :zone (gethash "zone" endpoint)
                                           :zone-hints (hint-names "forZones")
                                           :node-hints (hint-names "forNodes"))))
                         (loop for address across (json-array (gethash "addresses" endpoint))
                               unless (find-if (lambda (seen) (and (equal address (getf seen :address))
                                                                   (eql (getf record :port) (getf seen :port))))
                                               result)
                                 do (push (list* :address address record) result)))))))))
    (values (nreverse result) found)))

(defun service-slice-endpoints (store service port)
  "Resolve real forwarding backends for PORT's protocol from matching slices, including selectorless manual Services."
  (multiple-value-bind (records found) (service-slice-endpoint-records store service port)
    (values (loop for record in records
                  when (getf record :ready) collect (list (getf record :address) (getf record :port)))
            found)))

(defun service-topology-mode (records node-name zone)
  "Choose, as kube-proxy does, which topology hints to follow: :node when every ready endpoint has
a node hint and one names NODE-NAME, else :zone likewise for ZONE, else NIL to ignore hints."
  (let ((ready (remove-if-not (lambda (record) (getf record :ready)) records)))
    (cond ((null ready) nil)
          ((and node-name (every (lambda (record) (getf record :node-hints)) ready)
                (some (lambda (record) (member node-name (getf record :node-hints) :test #'equal)) ready))
           :node)
          ((and zone (every (lambda (record) (getf record :zone-hints)) ready)
                (some (lambda (record) (member zone (getf record :zone-hints) :test #'equal)) ready))
           :zone))))

(defun categorize-service-endpoints (records spec &key node-name zone)
  "Split endpoint RECORDS for Service SPEC as kube-proxy's CategorizeEndpoints does.
Returns (values cluster local local-ready-count any), ANY being kube-proxy's hasAnyEndpoints: the ready endpoints the topology hints allow,
or failing those every serving terminating one; this node's ready endpoints, or failing those its
serving terminating ones; and how many ready endpoints are on this node. An endpoint without a
node, as a selectorless manual one, is never local. Each list holds (address port) pairs."
  (let* ((local-p (lambda (record) (and node-name (equal node-name (getf record :node)))))
         (external (service-externally-accessible-p spec))
         (uses-cluster (or (equal "Cluster" (gethash "internalTrafficPolicy" spec "Cluster"))
                           (and external (equal "Cluster" (gethash "externalTrafficPolicy" spec "Cluster")))))
         (uses-local (or (equal "Local" (gethash "internalTrafficPolicy" spec))
                         (and external (equal "Local" (gethash "externalTrafficPolicy" spec)))))
         (fallback-p (lambda (record) (and (getf record :serving) (getf record :terminating))))
         (cluster nil) (local nil))
    (when uses-cluster
      (let ((mode (service-topology-mode records node-name zone)))
        (setf cluster (remove-if-not (lambda (record)
                                       (and (getf record :ready)
                                            (case mode
                                              (:node (member node-name (getf record :node-hints) :test #'equal))
                                              (:zone (member zone (getf record :zone-hints) :test #'equal))
                                              (t t))))
                                     records))
        (unless cluster (setf cluster (remove-if-not fallback-p records)))))
    (when uses-local
      (setf local (or (remove-if-not (lambda (record) (and (funcall local-p record) (getf record :ready))) records)
                      (remove-if-not (lambda (record) (and (funcall local-p record) (funcall fallback-p record))) records))))
    (flet ((pairs (list) (mapcar (lambda (record) (list (getf record :address) (getf record :port))) list)))
      (values (pairs cluster) (pairs local)
              (count-if (lambda (record) (and (funcall local-p record) (getf record :ready))) records)
              (and (or cluster
                       (some (lambda (record) (or (getf record :ready) (funcall fallback-p record))) records))
                   t)))))

(defun service-node-zone (store node-name)
  "This node's zone as its own endpoints report it, or NIL. The agent has no Node objects, and
without a zone kube-proxy, too, ignores zone hints."
  (when node-name
    (dolist (slice (list-core-resources store "endpointslices"))
      (loop for endpoint across (json-array (gethash "endpoints" slice #()))
            when (and (equal node-name (gethash "nodeName" endpoint)) (stringp (gethash "zone" endpoint)))
              do (return-from service-node-zone (gethash "zone" endpoint))))))

(defun service-port-backends (store service port &key node-name zone)
  "Resolve the backends SERVICE's PORT sends each kind of traffic to on node NODE-NAME.
Returns (values internal external local-origin local-ready-count any) as (address port) lists:
INTERNAL for the ClusterIP, which internalTrafficPolicy governs; EXTERNAL for node ports,
external IPs and load balancer addresses reached from elsewhere, which externalTrafficPolicy
governs; LOCAL-ORIGIN for those reached from this node itself, which kube-proxy short-circuits to
every endpoint while the Service uses any; the ready local endpoint count a health check reports;
and whether the port has any usable endpoint anywhere, without which kube-proxy rejects traffic."
  (let ((spec (gethash "spec" service)))
    (multiple-value-bind (records found) (service-slice-endpoint-records store service port :proxy t)
      (if (not found)
          ;; No slices yet: the agent's own selector-matched Pods, all on this node.
          (let ((endpoints (service-pod-endpoints store service port)))
            (values endpoints endpoints endpoints (length endpoints) (and endpoints t)))
          (multiple-value-bind (cluster local ready-local any)
              (categorize-service-endpoints records spec :node-name node-name :zone zone)
            (let ((internal (if (equal "Local" (gethash "internalTrafficPolicy" spec)) local cluster))
                  (external (if (equal "Local" (gethash "externalTrafficPolicy" spec)) local cluster)))
              (values internal external (or cluster local) ready-local any)))))))
