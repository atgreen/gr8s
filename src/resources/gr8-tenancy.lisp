;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Keep gr8's users apart on a shared machine (podster-tcr8). gr8 --setup gives each
;;;; user a namespace of their own and records on it who owns it: their identity, UID
;;;; and groups. Those namespaces admit the privileged Pods gr8 makes (the host's / is
;;;; mounted), so what confines a run is the UID it runs as. A Pod there must run as
;;;; the owner, within the owner's groups, and can't gain privilege: no escalation,
;;;; no capabilities, no host namespaces or ports. And the cluster-scoped objects gr8
;;;; makes for a run, ClusterNetworkPolicies and SandboxProfiles, may select only the
;;;; Pods of their creator's own namespaces, so one user can't widen another's runs.

(in-package #:gr8s.resources)

(defparameter +gr8-owner-annotation+ "gr8s.io/gr8-owner"
  "The identity a gr8 user's namespace belongs to, as gr8 --setup issued it.")

(defparameter +gr8-owner-uid-annotation+ "gr8s.io/gr8-uid"
  "The UID every Pod in a gr8 user's namespace runs as.")

(defparameter +gr8-owner-gids-annotation+ "gr8s.io/gr8-gids"
  "The groups, comma-separated, a Pod in a gr8 user's namespace may run with.")

(defparameter +gr8-user-prefix+ "gr8:"
  "Identities gr8 --setup issues; what they create cluster-wide is held to their namespaces.")

(defparameter +gr8-allowed-sysctls+ '("net.ipv4.ping_group_range")
  "The sysctls a gr8 Pod may set: unprivileged ping, which is namespaced and harmless.")

(defun %gr8-field (object &rest keys)
  (loop for key in keys
        do (setf object (and (hash-table-p object) (gethash key object)))
        finally (return object)))

(defun %gr8-integer (text)
  (and (stringp text) (plusp (length text)) (every #'digit-char-p text)
       (parse-integer text)))

(defun gr8-namespace-owner (namespace)
  "The UID and groups NAMESPACE's Pods must run with, when it is a gr8 user's; else NIL."
  (let* ((annotations (%gr8-field namespace "metadata" "annotations"))
         (uid (%gr8-integer (%gr8-field annotations +gr8-owner-uid-annotation+))))
    (when uid
      (values uid
              (remove nil (mapcar #'%gr8-integer
                                  (uiop:split-string (or (%gr8-field annotations +gr8-owner-gids-annotation+) "")
                                                     :separator ",")))))))

(defun %gr8-true-p (value) (eq value t))

(defun gr8-pod-violations (pod uid gids)
  "What in POD's spec breaks running as UID within GIDS without gaining privilege."
  (let* ((spec (%gr8-field pod "spec"))
         (security (%gr8-field spec "securityContext"))
         (violations '()))
    (flet ((violation (control &rest arguments)
             (push (apply #'format nil control arguments) violations))
           (group-p (gid) (and (integerp gid) (member gid gids))))
      (dolist (field '("hostNetwork" "hostPID" "hostIPC"))
        (when (%gr8-true-p (%gr8-field spec field)) (violation "spec.~A" field)))
      (when (%gr8-field spec "runtimeClassName") (violation "spec.runtimeClassName"))
      (unless (eql uid (%gr8-field security "runAsUser"))
        (violation "spec.securityContext.runAsUser must be ~D" uid))
      (unless (group-p (%gr8-field security "runAsGroup"))
        (violation "spec.securityContext.runAsGroup must be one of the owner's groups"))
      (let ((supplemental (%gr8-field security "supplementalGroups")))
        (unless (every #'group-p (if (vectorp supplemental) (coerce supplemental 'list) '()))
          (violation "spec.securityContext.supplementalGroups must be the owner's groups")))
      (when (%gr8-field security "fsGroup") (violation "spec.securityContext.fsGroup"))
      (when (%gr8-field security "seLinuxOptions") (violation "spec.securityContext.seLinuxOptions"))
      (let ((sysctls (%gr8-field security "sysctls")))
        (when (vectorp sysctls)
          (loop for sysctl across sysctls
                for name = (%gr8-field sysctl "name")
                unless (member name +gr8-allowed-sysctls+ :test #'equal)
                  do (violation "sysctl ~A" name))))
      (dolist (list '("initContainers" "containers" "ephemeralContainers"))
        (let ((containers (%gr8-field spec list)))
          (when (vectorp containers)
            (loop for container across containers
                  for name = (%gr8-field container "name")
                  for context = (%gr8-field container "securityContext")
                  for user = (%gr8-field context "runAsUser")
                  for group = (%gr8-field context "runAsGroup")
                  for drop = (%gr8-field context "capabilities" "drop")
                  for add = (%gr8-field context "capabilities" "add")
                  do (when (and user (not (eql user uid)))
                       (violation "container ~A runAsUser must be ~D" name uid))
                     (when (and group (not (group-p group)))
                       (violation "container ~A runAsGroup must be one of the owner's groups" name))
                     (when (%gr8-true-p (%gr8-field context "privileged"))
                       (violation "container ~A privileged" name))
                     ;; Without no_new_privs, the host's setuid programs under the mounted /
                     ;; would run as root.
                     (multiple-value-bind (escalation present)
                         (and (hash-table-p context) (gethash "allowPrivilegeEscalation" context))
                       (unless (and present (null escalation))
                         (violation "container ~A allowPrivilegeEscalation must be false" name)))
                     (unless (and (vectorp drop) (find "ALL" drop :test #'equal))
                       (violation "container ~A must drop ALL capabilities" name))
                     (when (and (vectorp add) (plusp (length add)))
                       (violation "container ~A adds capabilities" name))
                     (unless (member (%gr8-field context "procMount") '(nil "Default") :test #'equal)
                       (violation "container ~A procMount" name))
                     (when (%gr8-field context "seLinuxOptions")
                       (violation "container ~A seLinuxOptions" name))
                     (let ((ports (%gr8-field container "ports")))
                       (when (and (vectorp ports)
                                  (some (lambda (port) (let ((host (%gr8-field port "hostPort")))
                                                         (and host (not (eql host 0)))))
                                        ports))
                         (violation "container ~A hostPort" name))))))))
    (nreverse violations)))

(defun admit-gr8-namespace-pod (store namespace pod)
  "Refuse POD, a Pod object bound for NAMESPACE, when NAMESPACE is a gr8 user's and POD
could run as anyone but its owner or gain privilege there."
  (let ((object (ignore-errors (get-core-resource store "namespaces" nil namespace))))
    (multiple-value-bind (uid gids) (gr8-namespace-owner object)
      (when uid
        (let ((violations (gr8-pod-violations pod uid gids)))
          (when violations
            (core-resource-error
             403 "Forbidden"
             "pods ~S is forbidden: namespace ~A belongs to UID ~D, and a Pod there must run as it without gaining privilege (podster-tcr8): ~{~A~^, ~}"
             (or (%gr8-field pod "metadata" "name") (%gr8-field pod "metadata" "generateName") "")
             namespace uid violations)))))))

(defun gr8-user-identity-p (identity)
  "True when IDENTITY is one gr8 --setup issued."
  (let ((name (and identity (api-user-identity-username identity))))
    (and (stringp name) (eql 0 (search +gr8-user-prefix+ name)))))

(defun gr8-namespace-owned-by-p (store namespace username)
  "True when gr8 --setup made NAMESPACE for USERNAME. Called from resource validation,
which holds STORE's lock."
  (let ((object (ignore-errors (get-core-resource-unlocked store "namespaces" nil namespace))))
    (equal username (%gr8-field object "metadata" "annotations" +gr8-owner-annotation+))))

(defun %gr8-pinned-namespace (selector)
  "The one namespace SELECTOR names by kubernetes.io/metadata.name alone, else NIL."
  (let ((labels (%gr8-field selector "matchLabels"))
        (expressions (%gr8-field selector "matchExpressions")))
    (when (and (hash-table-p labels) (= 1 (hash-table-count labels))
               (or (null expressions) (and (vectorp expressions) (zerop (length expressions))))
               (hash-table-p selector)
               (null (set-difference (loop for key being the hash-keys of selector collect key)
                                     '("matchLabels" "matchExpressions") :test #'equal)))
      (let ((name (gethash "kubernetes.io/metadata.name" labels)))
        (and (stringp name) name)))))

(defun %gr8-object-namespace (resource object)
  "The namespace whose Pods OBJECT, a ClusterNetworkPolicy or SandboxProfile, is for,
when it names exactly one; else NIL."
  (let ((spec (%gr8-field object "spec")))
    (cond ((equal resource "sandboxprofiles")
           (%gr8-pinned-namespace (%gr8-field spec "namespaceSelector")))
          ((equal resource "clusternetworkpolicies")
           (let ((subject (%gr8-field spec "subject")))
             (and (hash-table-p subject) (= 1 (hash-table-count subject))
                  (cond ((%gr8-field subject "pods")
                         (%gr8-pinned-namespace (%gr8-field subject "pods" "namespaceSelector")))
                        ((%gr8-field subject "namespaces")
                         (%gr8-pinned-namespace (%gr8-field subject "namespaces"))))))))))

(defun %gr8-object-owned-p (store resource object username)
  "True when OBJECT is for the Pods of one namespace USERNAME owns. Holds STORE's lock."
  (let ((namespace (%gr8-object-namespace resource object)))
    (and namespace (gr8-namespace-owned-by-p store namespace username))))

(defun %gr8-refuse-cluster-object (resource name username)
  (core-resource-error
   403 "Forbidden"
   "~A ~S is forbidden: ~A may make, change or delete one only for the Pods of a namespace of their own, named by kubernetes.io/metadata.name (podster-tcr8)"
   resource (or name "") username))

(defun admit-gr8-user-cluster-object (store resource object identity)
  "Refuse a cluster-scoped OBJECT a gr8 user writes unless it, and any object it
replaces, is for their own namespace's Pods alone: a ClusterNetworkPolicy's subject,
a SandboxProfile's namespaceSelector. Called from resource validation, under STORE's lock."
  (when (and store (member resource '("clusternetworkpolicies" "sandboxprofiles") :test #'equal)
             (gr8-user-identity-p identity))
    (let* ((username (api-user-identity-username identity))
           (name (%gr8-field object "metadata" "name"))
           (old (and (stringp name) (ignore-errors (get-core-resource-unlocked store resource nil name)))))
      (unless (and (%gr8-object-owned-p store resource object username)
                   (or (null old) (%gr8-object-owned-p store resource old username)))
        (%gr8-refuse-cluster-object resource name username)))))

(defun admit-gr8-user-cluster-delete (store resource name identity)
  "Refuse a gr8 user's deletion of another user's ClusterNetworkPolicy or SandboxProfile."
  (when (and (member resource '("clusternetworkpolicies" "sandboxprofiles") :test #'equal)
             (gr8-user-identity-p identity))
    (let ((username (api-user-identity-username identity)))
      (with-store-lock (store)
        (let ((old (ignore-errors (get-core-resource-unlocked store resource nil name))))
          (when (and old (not (%gr8-object-owned-p store resource old username)))
            (%gr8-refuse-cluster-object resource name username)))))))
