;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Validate the Pod features needed to run in-cluster clients: volume sources
;;;; and mounts, numeric Linux identities, downward environment references and
;;;; selectors for the labels gr8s actually assigns to its worker nodes.

(in-package #:gr8s)

(defun pod-runtime-container-object (pod container)
  "Return CONTAINER's authoritative JSON specification within POD."
  (find (container-spec-name container) (gethash "containers" (gethash "spec" (pod-to-object pod)))
        :key (lambda (object) (gethash "name" object)) :test #'equal))

(defun safe-volume-relative-path-p (path)
  "Accept a nonempty relative volume file path without traversal components."
  (and (stringp path) (plusp (length path)) (not (char= #\/ (char path 0)))
       (not (find #\Null path))
       (every (lambda (part) (and (plusp (length part)) (not (member part '("." "..") :test #'equal))))
              (uiop:split-string path :separator '(#\/)))))

(defun validate-linux-security-context (context &key pod)
  "Validate the Linux identity and privilege settings implemented by the CRI adapter."
  (when context
    (reject-unsupported-fields context
                               (if pod '("runAsUser" "runAsGroup" "runAsNonRoot" "fsGroup")
                                   '("runAsUser" "runAsGroup" "runAsNonRoot" "privileged"
                                     "readOnlyRootFilesystem" "allowPrivilegeEscalation")) "securityContext")
    (dolist (field '("runAsUser" "runAsGroup" "fsGroup"))
      (when (gethash field context)
        (unless (typep (gethash field context) '(integer 0 4294967294))
          (invalid-pod "securityContext.~A must be a Linux UID/GID" field))))
    (dolist (field '("runAsNonRoot" "privileged" "readOnlyRootFilesystem" "allowPrivilegeEscalation"))
      (multiple-value-bind (value present) (gethash field context)
        (when (and present (not (member value '(t nil))))
          (invalid-pod "securityContext.~A must be boolean" field))))
    (when (and (eq t (gethash "runAsNonRoot" context))
               (eql 0 (gethash "runAsUser" context)))
      (invalid-pod "runAsNonRoot cannot be combined with runAsUser 0"))))

(defun validate-pod-field-reference (variable)
  "Validate downward fields and namespace-local Secret/ConfigMap key environment sources."
  (when (nth-value 1 (gethash "value" variable))
    (invalid-pod "env.value and env.valueFrom are mutually exclusive"))
  (let* ((from (require-object (gethash "valueFrom" variable) "env.valueFrom"))
         (sources (loop for key being the hash-keys of from collect key)))
    (reject-unsupported-fields from '("fieldRef" "secretKeyRef" "configMapKeyRef") "env.valueFrom")
    (unless (= 1 (length sources)) (invalid-pod "env.valueFrom requires exactly one source"))
    (let* ((kind (first sources)) (ref (require-object (gethash kind from) "environment source")))
      (if (equal kind "fieldRef")
          (progn
            (reject-unsupported-fields ref '("fieldPath" "apiVersion") "fieldRef")
            (unless (and (equal "v1" (gethash "apiVersion" ref "v1"))
                         (member (gethash "fieldPath" ref)
                                 '("metadata.name" "metadata.namespace" "metadata.uid" "spec.nodeName" "status.podIP") :test #'equal))
              (invalid-pod "unsupported downward API field reference")))
          (progn
            (reject-unsupported-fields ref '("name" "key" "optional") "environment key reference")
            (require-dns-subdomain (gethash "name" ref) "environment source name")
            (unless (core-data-key-p (gethash "key" ref)) (invalid-pod "invalid environment source key"))
            (multiple-value-bind (optional present) (gethash "optional" ref)
              (when (and present (not (member optional '(t nil))))
                (invalid-pod "environment key reference optional must be boolean"))))))))

(defun validate-runtime-container (container)
  "Validate mount declarations, image policy and container security settings."
  (when (gethash "imagePullPolicy" container)
    (unless (member (gethash "imagePullPolicy" container) '("Always" "IfNotPresent" "Never") :test #'equal)
      (invalid-pod "invalid imagePullPolicy")))
  (when (gethash "workingDir" container)
    (unless (and (stringp (gethash "workingDir" container))
                 (plusp (length (gethash "workingDir" container)))
                 (char= #\/ (char (gethash "workingDir" container) 0)))
      (invalid-pod "workingDir must be absolute")))
  (validate-linux-security-context (gethash "securityContext" container))
  (loop for mount across (optional-vector container "volumeMounts" "container")
        do (reject-unsupported-fields mount '("name" "mountPath" "readOnly") "volumeMount")
           (require-dns-label (gethash "name" mount) "volumeMount.name")
           (let ((path (gethash "mountPath" mount)))
             (unless (and (stringp path) (plusp (length path)) (char= #\/ (char path 0))
                          (not (find #\Null path))
                          (not (member ".." (uiop:split-string path :separator '(#\/)) :test #'equal)))
               (invalid-pod "volumeMount.mountPath must be an absolute path without traversal")))
           (multiple-value-bind (value present) (gethash "readOnly" mount)
             (when (and present (not (member value '(t nil))))
               (invalid-pod "volumeMount.readOnly must be boolean")))))

(defun validate-pod-volume (volume)
  "Validate a durable ConfigMap, Secret or disk-backed emptyDir volume."
  (reject-unsupported-fields volume '("name" "configMap" "secret" "emptyDir") "volume")
  (require-dns-label (gethash "name" volume) "volume.name")
  (let ((sources (remove-if-not (lambda (key) (nth-value 1 (gethash key volume)))
                                '("configMap" "secret" "emptyDir"))))
    (unless (= 1 (length sources)) (invalid-pod "volume requires exactly one source"))
    (let* ((kind (first sources)) (source (require-object (gethash kind volume) "volume source")))
      (if (equal kind "emptyDir")
          (reject-unsupported-fields source nil "emptyDir")
          (let ((name-field (if (equal kind "configMap") "name" "secretName")))
            (reject-unsupported-fields source (list name-field "items" "defaultMode" "optional") "volume source")
            (require-dns-subdomain (gethash name-field source) "volume source name")
            (multiple-value-bind (optional present) (gethash "optional" source)
              (when (and present (not (member optional '(t nil))))
                (invalid-pod "volume source optional must be boolean")))
            (when (gethash "defaultMode" source)
              (unless (typep (gethash "defaultMode" source) '(integer 0 511))
                (invalid-pod "volume defaultMode must be between 0 and 0777")))
            (loop for item across (optional-vector source "items" "volume source")
                  do (reject-unsupported-fields item '("key" "path" "mode") "volume item")
                     (require-nonempty-string (gethash "key" item) "volume item key")
                     (unless (safe-volume-relative-path-p (gethash "path" item))
                       (invalid-pod "volume item path must be relative without traversal"))
                     (when (gethash "mode" item)
                       (unless (typep (gethash "mode" item) '(integer 0 511))
                         (invalid-pod "volume item mode must be between 0 and 0777")))))))))

(defun validate-runtime-pod-spec (spec)
  "Validate Pod-level volume, security, service account and scheduling fields."
  (validate-linux-security-context (gethash "securityContext" spec) :pod t)
  (when (gethash "serviceAccountName" spec)
    (require-dns-subdomain (gethash "serviceAccountName" spec) "serviceAccountName"))
  (multiple-value-bind (value present) (gethash "automountServiceAccountToken" spec)
    (when (and present (not (member value '(t nil))))
      (invalid-pod "automountServiceAccountToken must be boolean")))
  (let ((names nil))
    (loop for volume across (optional-vector spec "volumes" "spec")
          do (validate-pod-volume volume)
             (when (member (gethash "name" volume) names :test #'equal) (invalid-pod "volume names must be unique"))
             (push (gethash "name" volume) names))
    (loop for container across (optional-vector spec "containers" "spec")
          do (require-object container "container")
             (loop for mount across (optional-vector container "volumeMounts" "container")
                   unless (member (gethash "name" mount) names :test #'equal)
                     do (invalid-pod "volumeMount references an unknown volume"))))
  (let ((selector (gethash "nodeSelector" spec)))
    (when selector
      (reject-unsupported-fields selector '("kubernetes.io/os" "kubernetes.io/arch" "kubernetes.io/hostname") "nodeSelector")
      (maphash (lambda (key value) (declare (ignore key)) (require-nonempty-string value "nodeSelector value")) selector)))
  (loop for toleration across (optional-vector spec "tolerations" "spec")
        do (reject-unsupported-fields toleration '("key" "operator" "value" "effect" "tolerationSeconds") "toleration")
           (unless (member (gethash "operator" toleration "Equal") '("Equal" "Exists") :test #'equal)
             (invalid-pod "invalid toleration operator"))
           (when (gethash "effect" toleration)
             (unless (member (gethash "effect" toleration) '("" "NoSchedule" "PreferNoSchedule" "NoExecute") :test #'equal)
               (invalid-pod "invalid toleration effect")))))

(defun pod-node-selector-matches-p (pod node)
  "Match POD's supported node labels against a registered worker NODE."
  (let ((selector (gethash "nodeSelector" (gethash "spec" (pod-to-object pod)))))
    (or (null selector)
        (loop for key being the hash-keys of selector using (hash-value expected)
              always (equal expected
                            (cond ((equal key "kubernetes.io/os") "linux")
                                  ((equal key "kubernetes.io/arch") (native-node-architecture))
                                  ((equal key "kubernetes.io/hostname") (node-record-name node))))))))

(defun pod-requests-privileged-container-p (pod)
  "Return whether any validated container needs a privileged sandbox."
  (loop for container across (gethash "containers" (gethash "spec" (pod-to-object pod)))
        thereis (let ((context (gethash "securityContext" container)))
                  (and context (eq t (gethash "privileged" context))))))
