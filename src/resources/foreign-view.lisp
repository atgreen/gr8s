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
  cluster on-change
  (lock (bt:make-lock "gr8s foreign resource view"))
  (informers (make-hash-table :test 'equal)))

(defun make-foreign-resource-view (cluster &key on-change)
  (%make-foreign-resource-view :cluster cluster :on-change on-change))

(defun foreign-resource-location (resource)
  (or (assoc resource +foreign-resource-locations+ :test #'equal)
      (core-resource-error 404 "NotFound"
                           "~A is not a resource this foreign view follows" resource)))

(defun foreign-view-informer (view resource)
  "The started, synced informer for RESOURCE, created on first use."
  (destructuring-bind (name group version namespaced) (foreign-resource-location resource)
    (declare (ignore namespaced))
    (let ((informer
            (bt:with-lock-held ((foreign-resource-view-lock view))
              (or (gethash resource (foreign-resource-view-informers view))
                  (setf (gethash resource (foreign-resource-view-informers view))
                        (gr8s.kube-client:start-informer
                         (foreign-resource-view-cluster view)
                         (gr8s.kube-client:resource-path group version name)
                         :on-change
                         (let ((on-change (foreign-resource-view-on-change view)))
                           (when on-change
                             (lambda (change key object)
                               (funcall on-change resource change key object))))))))))
      ;; First readers wait for the initial list, so an early reconciliation
      ;; sees the cluster rather than an empty cache.
      (loop repeat 600
            until (gr8s.kube-client:informer-synced-p informer)
            do (sleep 1/10))
      informer)))

(defun stop-foreign-resource-view (view)
  "Stop every informer the view has started."
  (let ((informers (bt:with-lock-held ((foreign-resource-view-lock view))
                     (prog1 (loop for informer being the hash-values
                                    of (foreign-resource-view-informers view)
                                  collect informer)
                       (clrhash (foreign-resource-view-informers view))))))
    (mapc #'gr8s.kube-client:stop-informer informers))
  nil)

(defmethod get-core-resource ((view foreign-resource-view) resource namespace name)
  (destructuring-bind (collection group version namespaced) (foreign-resource-location resource)
    (declare (ignore group version))
    (let* ((key (if (and namespaced namespace (plusp (length namespace)))
                    (concatenate 'string namespace "/" name)
                    name))
           (object (gr8s.kube-client:informer-object
                    (foreign-view-informer view resource) key)))
      (unless object
        (core-resource-error 404 "NotFound" "~A ~A/~A was not found"
                             (core-resource-kind collection) namespace name))
      (copy-core-object object))))

(defmethod list-core-resources ((view foreign-resource-view) resource &optional namespace)
  (let ((informer (foreign-view-informer view resource)))
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
