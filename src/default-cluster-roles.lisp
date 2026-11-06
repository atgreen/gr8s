;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Create the user-facing ClusterRoles every Kubernetes cluster ships, and aggregate
;;;; ClusterRoles as upstream's clusterrole-aggregation controller does. Their rules
;;;; are upstream's plugin/pkg/auth/authorizer/rbac/bootstrappolicy at release-1.36,
;;;; where admin, edit and view carry an aggregationRule selecting the labelled
;;;; system:aggregate-to-* roles, so a chart's role labelled aggregate-to-edit adds to
;;;; edit. A role grants nothing until someone binds it, and none of these is bound by
;;;; default.

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

(defun ensure-default-rbac-object (store resource body &optional namespace)
  "Create a default RBAC object unless one by that name exists, which is left as it is."
  (handler-case (create-core-resource store resource body namespace)
    (kubernetes-error (condition)
      (unless (= 409 (kubernetes-error-status-code condition)) (error condition)))))

;;; Aggregation

(defun validate-cluster-role-aggregation-rule (role)
  "Validate ROLE's aggregationRule as upstream does: at least one valid label selector."
  (multiple-value-bind (rule present) (gethash "aggregationRule" role)
    (cond
      ((or (not present) (eq rule 'null)) (remhash "aggregationRule" role))
      (t
       (require-object rule "aggregationRule")
       (reject-unsupported-fields rule '("clusterRoleSelectors") "aggregationRule")
       (let ((selectors (gethash "clusterRoleSelectors" rule)))
         (unless (and (vectorp selectors) (not (stringp selectors)) (plusp (length selectors)))
           (core-resource-error 422 "Invalid" "aggregationRule.clusterRoleSelectors: Required value: at least one clusterRoleSelector required if aggregationRule is non-nil"))
         (loop for selector across selectors
               do (validate-workload-selector selector :allow-empty t)))))))

(defun cluster-role-aggregated-rules (role roles)
  "Return the rules ROLE's aggregationRule gathers from ROLES: for each selector in turn, the
selected roles in name order, each new rule once, and never ROLE's own."
  (let ((rules nil) (name (object-name role)))
    (loop for selector across (gethash "clusterRoleSelectors" (gethash "aggregationRule" role))
          do (dolist (other (sort (remove-if-not (lambda (candidate)
                                                   (workload-selector-matches-p
                                                    selector (or (gethash "labels" (gethash "metadata" candidate)) (core-object))))
                                                 roles)
                                  #'string< :key #'object-name))
               (unless (equal name (object-name other))
                 (loop for rule across (let ((value (gethash "rules" other))) (if (vectorp value) value #()))
                       unless (find rule rules :test #'crd-json-equal-p)
                         do (setf rules (append rules (list (copy-core-object rule))))))))
    (coerce rules 'vector)))

(defun reconcile-cluster-role-aggregation (store)
  "Keep every aggregating ClusterRole's rules equal to the union its selectors gather."
  (let ((roles (list-core-resources store "clusterroles")))
    (dolist (role roles)
      (when (hash-table-p (gethash "aggregationRule" role))
        (let ((wanted (cluster-role-aggregated-rules role roles)))
          (unless (crd-json-equal-p wanted (let ((value (gethash "rules" role))) (if (vectorp value) value #())))
            (handler-case
                (let ((*apply-update-manager* nil))
                  (update-core-resource store "clusterroles" nil (object-name role)
                                        (lambda (object) (setf (gethash "rules" object) wanted) object)))
              ;; Lost a race with a writer: the next pass looks again.
              (kubernetes-error () nil))))))))

(defun ensure-default-cluster-roles (store)
  "Create cluster-admin, admin, edit and view with their aggregated sources, and bind
cluster-admin to system:masters.
The authorizer already admits system:masters outright, so that binding grants nothing new;
it records the fact for clients that read RBAC objects."
  (ensure-default-rbac-object
   store "clusterroles"
   (core-object "metadata" (default-rbac-metadata "cluster-admin")
                "rules" (vector (core-object "apiGroups" #("*") "resources" #("*") "verbs" #("*"))
                                (core-object "nonResourceURLs" #("*") "verbs" #("*")))))
  ;; The aggregated roles' sources first, labelled as upstream labels them, so the
  ;; aggregation pass below finds them.
  (loop for (name rules . targets)
          in (list (list "system:aggregate-to-admin" *default-admin-rules* "admin")
                   (list "system:aggregate-to-edit" *default-edit-rules* "admin" "edit")
                   (list "system:aggregate-to-view" *default-view-rules* "admin" "edit" "view"))
        do (let ((metadata (default-rbac-metadata name)))
             (dolist (target targets)
               (setf (gethash (format nil "rbac.authorization.k8s.io/aggregate-to-~A" target) (gethash "labels" metadata)) "true"))
             (ensure-default-rbac-object
              store "clusterroles" (core-object "metadata" metadata "rules" (default-cluster-role-rules rules)))))
  (dolist (name '("admin" "edit" "view"))
    (ensure-default-rbac-object
     store "clusterroles"
     (core-object "metadata" (default-rbac-metadata name)
                  "aggregationRule"
                  (core-object "clusterRoleSelectors"
                               (vector (core-object "matchLabels"
                                                    (core-object (format nil "rbac.authorization.k8s.io/aggregate-to-~A" name) "true"))))
                  "rules" #())))
  ;; Fill them now, so they grant what they should before the first controller pass.
  (reconcile-cluster-role-aggregation store)
  (ensure-default-rbac-object
   store "clusterrolebindings"
   (core-object "metadata" (default-rbac-metadata "cluster-admin")
                "roleRef" (core-object "apiGroup" "rbac.authorization.k8s.io" "kind" "ClusterRole" "name" "cluster-admin")
                "subjects" (vector (core-object "apiGroup" "rbac.authorization.k8s.io" "kind" "Group" "name" "system:masters")))))
