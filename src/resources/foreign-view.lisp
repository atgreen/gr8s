;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; A foreign cluster's watch cache behind the desired-state read seam
;;;; (docs/design-foreign-cluster-networking.md).
;;;;
;;;; The gateway and network consumers read desired state through
;;;; GET-CORE-RESOURCE, LIST-CORE-RESOURCES and LIST-PODS.  On a foreign
;;;; Kubernetes cluster those reads come from here instead of the gr8s store:
;;;; each resource collection is materialized by a gr8s.kube-client informer,
;;;; started lazily on first read and kept current by list+watch.  Objects are
;;;; the same JSON-shaped hash tables both sides speak, so the planners cannot
;;;; tell the difference.

(in-package #:gr8s.resources)

(defparameter +foreign-resource-locations+
  '(("pods"            ""                           "v1"       t)
    ("namespaces"      ""                           "v1"       nil)
    ("nodes"           ""                           "v1"       nil)
    ("services"        ""                           "v1"       t)
    ("secrets"         ""                           "v1"       t)
    ("configmaps"      ""                           "v1"       t)
    ("endpointslices"  "discovery.k8s.io"           "v1"       t)
    ("networkpolicies" "networking.k8s.io"          "v1"       t)
    ("ingresses"       "networking.k8s.io"          "v1"       t)
    ("ingressclasses"  "networking.k8s.io"          "v1"       nil)
    ("gatewayclasses"  "gateway.networking.k8s.io"  "v1"       nil)
    ("gateways"        "gateway.networking.k8s.io"  "v1"       t)
    ("httproutes"      "gateway.networking.k8s.io"  "v1"       t)
    ("grpcroutes"      "gateway.networking.k8s.io"  "v1"       t)
    ("tcproutes"       "gateway.networking.k8s.io"  "v1alpha2" t)
    ("tlsroutes"       "gateway.networking.k8s.io"  "v1alpha2" t)
    ("referencegrants" "gateway.networking.k8s.io"  "v1beta1"  t))
  "Where each collection the consumers read lives on a conformant cluster:
resource, API group (empty = core), version, and whether it is namespaced.")

(defstruct (foreign-resource-view (:constructor %make-foreign-resource-view))
  "The desired-state read seam over a foreign cluster's informers.
ON-CHANGE, when set, is called with (resource change key object) after any
cache update, so an agent can nudge its reconcilers."
  cluster on-change listenerset-group listenerset-location
  (discovery-retry-seconds 30)
  (listenerset-discovery-after 0)
  (snapshot-lock (bt:make-lock "gr8s foreign resource snapshots"))
  (snapshot-index (fset:empty-ch-map nil 'fset:compare 'fset:eql-compare))
  (route-parents (fset:empty-ch-map nil))
  (listenerset-parents (fset:empty-ch-map nil))
  (namespace-selectors (fset:empty-ch-map nil))
  (revision 0) (history-floor 0) history
  (lock (bt:make-lock "gr8s foreign resource view"))
  (informers (make-hash-table :test 'equal)))

(defun make-foreign-resource-view (cluster &key on-change listenerset-group
                                               (discovery-retry-seconds 30)
                                               (history-limit 4096))
  (check-type history-limit (integer 1 *))
  (%make-foreign-resource-view :cluster cluster :on-change on-change
                              :listenerset-group listenerset-group
                              :discovery-retry-seconds discovery-retry-seconds
                              :history (make-array history-limit :initial-element nil)))

(defstruct foreign-resource-snapshot index revision route-parents
  (listenerset-parents (fset:empty-ch-map nil))
  (namespace-selectors (fset:empty-ch-map nil)))

(defun foreign-owner-namespace-selectors (resource owner)
  "Extract the namespace selectors that can affect this listener owner."
  (when owner
    (let ((spec (gethash "spec" owner)) (selectors nil))
      (flet ((collect-policy (policy)
               (let ((namespaces (and policy (gethash "namespaces" policy))))
                 (when (and namespaces (equal "Selector" (gethash "from" namespaces))
                            (gethash "selector" namespaces))
                   (push (gethash "selector" namespaces) selectors)))))
        (when (equal resource "gateways")
          (collect-policy (gethash "allowedListeners" spec)))
        (loop for listener across (gethash "listeners" spec #())
              do (collect-policy (gethash "allowedRoutes" listener))))
      selectors)))

(defun foreign-route-parent-keys (route)
  "Keep complete owner identity, independent of current listener admission."
  (when route
    (let ((namespace (gethash "namespace" (gethash "metadata" route))))
      (remove-duplicates
       (loop for ref across (gethash "parentRefs" (gethash "spec" route) #())
             collect (list (or (gethash "group" ref) "gateway.networking.k8s.io")
                           (or (gethash "kind" ref) "Gateway")
                           (or (gethash "namespace" ref) namespace)
                           (gethash "name" ref))) :test #'equal))))

(defun foreign-listenerset-parent-keys (owner)
  (when owner
    (let* ((parent (gethash "parentRef" (gethash "spec" owner)))
           (metadata (gethash "metadata" owner)))
      (when (and parent
                 (equal (gethash "group" parent "gateway.networking.k8s.io") "gateway.networking.k8s.io")
                 (equal (gethash "kind" parent "Gateway") "Gateway"))
        (list (list (gethash "namespace" parent (gethash "namespace" metadata))
                    (gethash "name" parent)))))))

(defun foreign-update-parent-index (index key old new parent-keys)
  (let ((before (funcall parent-keys old))
        (after (funcall parent-keys new)))
    (dolist (parent before)
      (unless (member parent after :test #'equal)
        (let ((bucket (fset:lookup index parent)))
          (when bucket
            (let ((next (fset:less bucket key)))
              (setf index (if (fset:empty? next) (fset:less index parent)
                              (fset:with index parent next))))))))
    (dolist (parent after)
      (unless (member parent before :test #'equal)
        (setf index (fset:with index parent
                               (fset:with (or (fset:lookup index parent) (fset:empty-ch-map nil)) key t)))))
    index))

(defun foreign-snapshot-gateway-listenersets (snapshot gateway-key)
  "Read only this Gateway's children; reject a stale controller UID.
ParentRefs address names, so resolve the UID against this same immutable snapshot."
  (let* ((parent (subseq gateway-key 0 2))
         (gateway (foreign-snapshot-object (foreign-resource-snapshot-index snapshot)
                                           (cons "gateways" parent)))
         (bucket (and gateway
                      (equal (third gateway-key) (gethash "uid" (gethash "metadata" gateway)))
                      (fset:lookup (foreign-resource-snapshot-listenerset-parents snapshot) parent)))
         (owners nil))
    (when bucket
      (fset:do-map (key present bucket)
        (declare (ignore present))
        (push (apply #'get-core-resource snapshot "listenersets" key) owners)))
    (sort owners #'string< :key (lambda (owner)
                                 (let ((metadata (gethash "metadata" owner)))
                                   (format nil "~A/~A" (gethash "namespace" metadata)
                                           (gethash "name" metadata)))))))

(defun foreign-snapshot-parent-routes (snapshot parent)
  "Read only HTTPRoutes that reference PARENT, including currently rejected routes."
  (let ((bucket (fset:lookup (foreign-resource-snapshot-route-parents snapshot) parent))
        (routes nil))
    (when bucket
      (fset:do-map (key present bucket)
        (declare (ignore present))
        (push (apply #'get-core-resource snapshot "httproutes" key) routes)))
    (sort routes #'string< :key (lambda (route)
                                 (let ((metadata (gethash "metadata" route)))
                                   (format nil "~A/~A" (gethash "namespace" metadata) (gethash "name" metadata)))))))

(defun foreign-snapshot-object (index key)
  (let ((collection (fset:lookup index (first key))))
    (and collection (fset:lookup collection (rest key)))))

(defun foreign-view-note (view resource change key object)
  "Retain a coherent immutable view before notifying consumers of a cache change.
History retains keys only, never old Secret material. Readers own old snapshots."
  (let* ((metadata (gethash "metadata" object))
         (identity (list resource (gethash "namespace" metadata) (gethash "name" metadata)))
         (value (unless (eq change :deleted) (copy-core-object object))))
    (bt:with-lock-held ((foreign-resource-view-snapshot-lock view))
      (let* ((index (foreign-resource-view-snapshot-index view))
             (collection (or (fset:lookup index resource)
                             (fset:empty-ch-map nil 'fset:compare 'fset:eql-compare)))
             (next (if value (fset:with collection (rest identity) value)
                       (fset:less collection (rest identity))))
             (revision (incf (foreign-resource-view-revision view)))
             (history (foreign-resource-view-history view)))
        (when (equal resource "httproutes")
          (setf (foreign-resource-view-route-parents view)
                (foreign-update-parent-index (foreign-resource-view-route-parents view) (rest identity)
                                             (foreign-snapshot-object index identity) value #'foreign-route-parent-keys)))
        (when (equal resource "listenersets")
          (setf (foreign-resource-view-listenerset-parents view)
                (foreign-update-parent-index (foreign-resource-view-listenerset-parents view) (rest identity)
                                             (foreign-snapshot-object index identity) value #'foreign-listenerset-parent-keys)))
        (when (member resource '("gateways" "listenersets") :test #'equal)
          (let ((selectors (foreign-owner-namespace-selectors resource value))
                (previous (foreign-resource-view-namespace-selectors view)))
            (setf (foreign-resource-view-namespace-selectors view)
                  (if selectors (fset:with previous identity selectors)
                      (fset:less previous identity)))))
        (setf (foreign-resource-view-snapshot-index view)
              (if (fset:empty? next) (fset:less index resource) (fset:with index resource next))
              (aref history (mod revision (length history))) identity
              (foreign-resource-view-history-floor view)
              (max (foreign-resource-view-history-floor view) (- revision (length history))))))
    (let ((on-change (foreign-resource-view-on-change view)))
      (when on-change (funcall on-change resource change key object)))))

(defun foreign-view-snapshot (view &optional since)
  "Return snapshot, revision, coalesced key/object changes, and full-rebuild flag.
The caller must start/synchronize its required informers before first capture."
  (bt:with-lock-held ((foreign-resource-view-snapshot-lock view))
    (let* ((revision (foreign-resource-view-revision view))
           (index (foreign-resource-view-snapshot-index view))
           (full (or (null since) (< since (foreign-resource-view-history-floor view))
                     (> since revision)))
           (changes nil))
      (unless full
        (let ((seen (make-hash-table :test 'equal))
              (history (foreign-resource-view-history view)))
          (loop for sequence from (1+ since) to revision
                for key = (aref history (mod sequence (length history)))
                unless (gethash key seen)
                  do (setf (gethash key seen) t)
                     (push (cons (copy-list key)
                                 (let ((object (foreign-snapshot-object index key)))
                                   (when object (copy-core-object object)))) changes))))
      (values (make-foreign-resource-snapshot :index index :revision revision
                                             :listenerset-parents (foreign-resource-view-listenerset-parents view)
                                             :namespace-selectors (foreign-resource-view-namespace-selectors view)
                                             :route-parents (foreign-resource-view-route-parents view))
              revision (nreverse changes) full))))

(defmethod get-core-resource ((snapshot foreign-resource-snapshot) resource namespace name)
  (let ((object (foreign-snapshot-object (foreign-resource-snapshot-index snapshot)
                                         (list resource namespace name))))
    (unless object
      (core-resource-error 404 "NotFound" "~A ~A/~A was not found" resource namespace name))
    (copy-core-object object)))

(defmethod list-core-resources ((snapshot foreign-resource-snapshot) resource &optional namespace)
  (let ((collection (fset:lookup (foreign-resource-snapshot-index snapshot) resource))
        (objects nil))
    (when collection
      (fset:do-map (key object collection)
        (when (or (null namespace) (equal namespace (first key)))
          (push (copy-core-object object) objects))))
    (values (sort objects #'string< :key (lambda (object)
                                          (let ((metadata (gethash "metadata" object)))
                                            (format nil "~A/~A" (gethash "namespace" metadata)
                                                    (gethash "name" metadata)))))
            (write-to-string (foreign-resource-snapshot-revision snapshot)))))

(defun foreign-resource-location (resource &optional view)
  (when (and view (equal resource "listenersets"))
    (return-from foreign-resource-location (foreign-view-listenerset-location view)))
  (or (assoc resource +foreign-resource-locations+ :test #'equal)
      (core-resource-error 404 "NotFound"
                           "~A is not a resource this foreign view follows" resource)))

(defparameter +foreign-listenerset-apis+
  '(("gateway.networking.k8s.io" "v1" "listenersets" "ListenerSet")
    ("gateway.networking.k8s.io" "v1beta1" "listenersets" "ListenerSet")
    ("gateway.networking.x-k8s.io" "v1alpha1" "xlistenersets" "XListenerSet")))

(defun foreign-listenerset-location (api-resource-lists &key group)
  "Choose one supported ListenerSet API from advertised resource lists.
GROUP restricts selection to an explicitly configured API group. Stable APIs
take precedence by default; never alias objects from another group."
  (loop for (candidate-group version name kind) in +foreign-listenerset-apis+
        when (and (or (null group) (equal group candidate-group))
                  (loop for api in api-resource-lists
                        thereis
                        (and (equal (gethash "groupVersion" api)
                                    (format nil "~A/~A" candidate-group version))
                             (loop for resource across (gethash "resources" api #())
                                   thereis
                                   (and (equal name (gethash "name" resource))
                                        (equal kind (gethash "kind" resource))
                                        (eq t (gethash "namespaced" resource))
                                        (every (lambda (verb)
                                                 (find verb (gethash "verbs" resource)
                                                       :test #'equal))
                                               '("list" "watch")))))))
          return (list name candidate-group version t)))

(defun discover-foreign-listenerset-location (cluster &key group)
  "Discover a served ListenerSet API. Only a 404 means optional API absence."
  (loop for (candidate-group version) in +foreign-listenerset-apis+
        when (or (null group) (equal group candidate-group))
          do (let* ((api
                      (handler-case
                          (gr8s.kube-client:kube-get
                           cluster (format nil "/apis/~A/~A" candidate-group version))
                        (gr8s.kube-client:kube-error (condition)
                          (unless (= 404 (gr8s.kube-client:kube-error-status condition))
                            (error condition)))))
                    (location (and api (foreign-listenerset-location (list api) :group group))))
               (when location (return location)))))

(defun foreign-view-listenerset-location (view)
  "Cache the chosen API; retry optional API absence at a bounded frequency."
  (bt:with-lock-held ((foreign-resource-view-lock view))
    (or (foreign-resource-view-listenerset-location view)
        (when (>= (get-internal-real-time)
                  (foreign-resource-view-listenerset-discovery-after view))
          (let ((location
                  (discover-foreign-listenerset-location
                   (foreign-resource-view-cluster view)
                   :group (foreign-resource-view-listenerset-group view))))
            (setf (foreign-resource-view-listenerset-location view) location
                  (foreign-resource-view-listenerset-discovery-after view)
                  (+ (get-internal-real-time)
                     (* internal-time-units-per-second
                        (foreign-resource-view-discovery-retry-seconds view))))
            location)))))

(defun foreign-view-informer (view resource)
  "The started, synced informer for RESOURCE, created on first use."
  (let ((location (foreign-resource-location resource view)))
    (unless location (return-from foreign-view-informer nil))
    (destructuring-bind (name group version namespaced) location
    (declare (ignore namespaced))
    (let ((informer
            (bt:with-lock-held ((foreign-resource-view-lock view))
              (or (gethash resource (foreign-resource-view-informers view))
                  (setf (gethash resource (foreign-resource-view-informers view))
                        (gr8s.kube-client:start-informer
                         (foreign-resource-view-cluster view)
                         (gr8s.kube-client:resource-path group version name)
                         :on-change
                         (lambda (change key object)
                           (foreign-view-note view resource change key object))))))))
      ;; First readers wait for the initial list, so an early reconciliation
      ;; sees the cluster rather than an empty cache.
      (loop repeat 600
            until (gr8s.kube-client:informer-synced-p informer)
            do (let ((failure (gr8s.kube-client::informer-last-error informer)))
                 (when failure (error failure)))
               (sleep 1/10))
      (let ((failure (gr8s.kube-client::informer-last-error informer)))
        (when failure (error failure)))
      informer))))

(defun stop-foreign-resource-view (view)
  "Stop every informer the view has started."
  (let ((informers (bt:with-lock-held ((foreign-resource-view-lock view))
                     (prog1 (loop for informer being the hash-values
                                    of (foreign-resource-view-informers view)
                                  collect informer)
                       (clrhash (foreign-resource-view-informers view))
                       (setf (foreign-resource-view-listenerset-location view) nil
                             (foreign-resource-view-listenerset-discovery-after view) 0)))))
    (mapc #'gr8s.kube-client:stop-informer informers))
  (bt:with-lock-held ((foreign-resource-view-snapshot-lock view))
    (setf (foreign-resource-view-snapshot-index view)
          (fset:empty-ch-map nil 'fset:compare 'fset:eql-compare)
          (foreign-resource-view-route-parents view) (fset:empty-ch-map nil)
          (foreign-resource-view-listenerset-parents view) (fset:empty-ch-map nil)
          (foreign-resource-view-namespace-selectors view) (fset:empty-ch-map nil)
          (foreign-resource-view-history-floor view) (incf (foreign-resource-view-revision view)))
    (fill (foreign-resource-view-history view) nil))
  nil)

(defmethod get-core-resource ((view foreign-resource-view) resource namespace name)
  (let ((location (foreign-resource-location resource view)))
    (unless location
      (core-resource-error 404 "NotFound" "~A API is not installed" resource))
    (destructuring-bind (collection group version namespaced) location
    (declare (ignore group version))
    (let* ((key (if (and namespaced namespace (plusp (length namespace)))
                    (concatenate 'string namespace "/" name)
                    name))
           (object (gr8s.kube-client:informer-object
                    (foreign-view-informer view resource) key)))
      (unless object
        (core-resource-error 404 "NotFound" "~A ~A/~A was not found"
                             (core-resource-kind collection) namespace name))
      (copy-core-object object)))))

(defmethod list-core-resources ((view foreign-resource-view) resource &optional namespace)
  (let ((informer (foreign-view-informer view resource)))
    (unless informer (return-from list-core-resources (values nil "0")))
    (values
     (sort (loop for object in (gr8s.kube-client:informer-objects informer)
                 for metadata = (gethash "metadata" object)
                 when (or (null namespace)
                          (equal namespace (gethash "namespace" metadata)))
                   collect (copy-core-object object))
           #'string< :key (lambda (object)
                            (let ((metadata (gethash "metadata" object)))
                              (format nil "~A/~A" (gethash "namespace" metadata)
                                      (gethash "name" metadata)))))
     (or (gr8s.kube-client::informer-resource-version informer) "0"))))

(defmethod gr8s.store:list-pods ((view foreign-resource-view) &optional namespace)
  "The foreign cluster's Pods as model Pods carrying their watched objects.
The strict parser validates Pods as submitted for creation and rejects fields
every live cluster sets (status, projected volumes, scheduling detail), which
would silently starve policy resolution of real Pods.  The network consumers
read identity and the authoritative object only, so build exactly that."
  (loop for object in (list-core-resources view "pods" namespace)
        for metadata = (gethash "metadata" object)
        for spec = (gethash "spec" object)
        when (and metadata (gethash "name" metadata))
          collect (gr8s.model::make-pod
                   :name (gethash "name" metadata)
                   :namespace (or (gethash "namespace" metadata) "default")
                   :uid (gethash "uid" metadata)
                   :resource-version (gethash "resourceVersion" metadata)
                   :node-name (and spec (gethash "nodeName" spec))
                   :object object)))

(defmethod gr8s.store:pod-reported-status ((view foreign-resource-view) pod)
  "A foreign Pod's status travels inside the watched object itself."
  (let ((object (handler-case
                    (get-core-resource view "pods"
                                       (gr8s.model:pod-namespace pod)
                                       (gr8s.model:pod-name pod))
                  (error () nil))))
    (and object (gethash "status" object))))
