;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Create the user-facing ClusterRoles every Kubernetes cluster ships. Their rules
;;;; are upstream's plugin/pkg/auth/authorizer/rbac/bootstrappolicy at release-1.36,
;;;; where admin, edit and view are built by aggregating system:aggregate-to-* roles.
;;;; Aggregation is not implemented here, so each role holds its expanded rules. A
;;;; role grants nothing until someone binds it, and none of these is bound by default.

(in-package #:gr8s)

(defparameter *default-view-rules*
  '((("")
     ("configmaps" "endpoints" "persistentvolumeclaims" "persistentvolumeclaims/status" "pods" "replicationcontrollers" "replicationcontrollers/scale" "serviceaccounts" "services" "services/status")
     ("get" "list" "watch"))
    (("")
     ("bindings" "limitranges" "namespaces/status" "pods/log" "pods/status" "replicationcontrollers/status" "resourcequotas" "resourcequotas/status")
     ("get" "list" "watch"))
    (("")
     ("namespaces")
     ("get" "list" "watch"))
    (("" "events.k8s.io")
     ("events")
     ("get" "list" "watch"))
    (("discovery.k8s.io")
     ("endpointslices")
     ("get" "list" "watch"))
    (("apps")
     ("controllerrevisions" "daemonsets" "daemonsets/status" "deployments" "deployments/scale" "deployments/status" "replicasets" "replicasets/scale" "replicasets/status" "statefulsets" "statefulsets/scale" "statefulsets/status")
     ("get" "list" "watch"))
    (("autoscaling")
     ("horizontalpodautoscalers" "horizontalpodautoscalers/status")
     ("get" "list" "watch"))
    (("batch")
     ("cronjobs" "cronjobs/status" "jobs" "jobs/status")
     ("get" "list" "watch"))
    (("extensions")
     ("daemonsets" "daemonsets/status" "deployments" "deployments/scale" "deployments/status" "ingresses" "ingresses/status" "networkpolicies" "replicasets" "replicasets/scale" "replicasets/status" "replicationcontrollers/scale")
     ("get" "list" "watch"))
    (("policy")
     ("poddisruptionbudgets" "poddisruptionbudgets/status")
     ("get" "list" "watch"))
    (("networking.k8s.io")
     ("ingresses" "ingresses/status" "networkpolicies")
     ("get" "list" "watch"))
    (("resource.k8s.io")
     ("resourceclaims" "resourceclaims/status" "resourceclaimtemplates")
     ("get" "list" "watch")))
  "Upstream's system:aggregate-to-view rules: API groups, resources, verbs.")

(defparameter *default-edit-rules*
  '((("")
     ("pods/attach" "pods/exec" "pods/portforward" "pods/proxy" "secrets" "services/proxy")
     ("get" "list" "watch"))
    (("")
     ("serviceaccounts")
     ("impersonate"))
    (("")
     ("pods" "pods/attach" "pods/exec" "pods/portforward" "pods/proxy")
     ("create" "delete" "deletecollection" "patch" "update"))
    (("")
     ("pods/eviction")
     ("create"))
    (("")
     ("configmaps" "persistentvolumeclaims" "replicationcontrollers" "replicationcontrollers/scale" "secrets" "serviceaccounts" "services" "services/proxy")
     ("create" "delete" "deletecollection" "patch" "update"))
    (("")
     ("serviceaccounts/token")
     ("create"))
    (("" "events.k8s.io")
     ("events")
     ("create" "delete" "deletecollection" "patch" "update"))
    (("apps")
     ("daemonsets" "deployments" "deployments/rollback" "deployments/scale" "replicasets" "replicasets/scale" "statefulsets" "statefulsets/scale")
     ("create" "delete" "deletecollection" "patch" "update"))
    (("autoscaling")
     ("horizontalpodautoscalers")
     ("create" "delete" "deletecollection" "patch" "update"))
    (("batch")
     ("cronjobs" "jobs")
     ("create" "delete" "deletecollection" "patch" "update"))
    (("extensions")
     ("daemonsets" "deployments" "deployments/rollback" "deployments/scale" "ingresses" "networkpolicies" "replicasets" "replicasets/scale" "replicationcontrollers/scale")
     ("create" "delete" "deletecollection" "patch" "update"))
    (("policy")
     ("poddisruptionbudgets")
     ("create" "delete" "deletecollection" "patch" "update"))
    (("networking.k8s.io")
     ("ingresses" "networkpolicies")
     ("create" "delete" "deletecollection" "patch" "update"))
    (("coordination.k8s.io")
     ("leases")
     ("create" "delete" "deletecollection" "get" "list" "patch" "update" "watch"))
    (("resource.k8s.io")
     ("resourceclaims" "resourceclaimtemplates")
     ("create" "delete" "deletecollection" "patch" "update")))
  "Upstream's system:aggregate-to-edit rules: API groups, resources, verbs.")

(defparameter *default-admin-rules*
  '((("authorization.k8s.io")
     ("localsubjectaccessreviews")
     ("create"))
    (("rbac.authorization.k8s.io")
     ("rolebindings" "roles")
     ("create" "delete" "deletecollection" "get" "list" "patch" "update" "watch")))
  "Upstream's system:aggregate-to-admin rules: API groups, resources, verbs.")

(defun default-cluster-role-rules (&rest rule-sets)
  "Turn RULE-SETS of API groups, resources and verbs into RBAC policy rules."
  (coerce (loop for rules in rule-sets
                append (loop for (groups resources verbs) in rules
                             collect (core-object "apiGroups" (coerce groups 'vector)
                                                  "resources" (coerce resources 'vector)
                                                  "verbs" (coerce verbs 'vector))))
          'vector))

(defun default-rbac-metadata (name)
  "Mark NAME as upstream marks its bootstrap policy objects."
  (core-object "name" name
               "labels" (core-object "kubernetes.io/bootstrapping" "rbac-defaults")
               "annotations" (core-object "rbac.authorization.kubernetes.io/autoupdate" "true")))

(defun ensure-default-rbac-object (store resource body)
  "Create a default RBAC object unless one by that name exists, which is left as it is."
  (handler-case (create-core-resource store resource body nil)
    (kubernetes-error (condition)
      (unless (= 409 (kubernetes-error-status-code condition)) (error condition)))))

(defun ensure-default-cluster-roles (store)
  "Create cluster-admin, admin, edit and view, and bind cluster-admin to system:masters.
The authorizer already admits system:masters outright, so that binding grants nothing new;
it records the fact for clients that read RBAC objects."
  (loop for (name . rules)
          in (list (cons "cluster-admin"
                         (vector (core-object "apiGroups" #("*") "resources" #("*") "verbs" #("*"))
                                 (core-object "nonResourceURLs" #("*") "verbs" #("*"))))
                   (cons "view" (default-cluster-role-rules *default-view-rules*))
                   (cons "edit" (default-cluster-role-rules *default-edit-rules* *default-view-rules*))
                   (cons "admin" (default-cluster-role-rules *default-admin-rules* *default-edit-rules* *default-view-rules*)))
        do (ensure-default-rbac-object
            store "clusterroles" (core-object "metadata" (default-rbac-metadata name) "rules" rules)))
  (ensure-default-rbac-object
   store "clusterrolebindings"
   (core-object "metadata" (default-rbac-metadata "cluster-admin")
                "roleRef" (core-object "apiGroup" "rbac.authorization.k8s.io" "kind" "ClusterRole" "name" "cluster-admin")
                "subjects" (vector (core-object "apiGroup" "rbac.authorization.k8s.io" "kind" "Group" "name" "system:masters")))))
