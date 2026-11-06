;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Validate the Pod features needed to run in-cluster clients: volume sources
;;;; and mounts, numeric Linux identities, downward environment references and
;;;; selectors for the labels gr8s actually assigns to its worker nodes.

(in-package #:gr8s)

(defun pod-runtime-container-object (pod container)
  "Return CONTAINER's authoritative JSON specification within POD."
  (find (container-spec-name container)
        (let ((spec (gethash "spec" (pod-to-object pod))))
          (concatenate 'vector (gethash "initContainers" spec #()) (gethash "containers" spec)
                       (gethash "ephemeralContainers" spec #())))
        :key (lambda (object) (gethash "name" object)) :test #'equal))

(defun safe-volume-relative-path-p (path)
  "Accept a nonempty relative volume file path without traversal components."
  (and (stringp path) (plusp (length path)) (not (char= #\/ (char path 0)))
       (not (find #\Null path))
       (every (lambda (part) (and (plusp (length part)) (not (member part '("." "..") :test #'equal))))
              (uiop:split-string path :separator '(#\/)))))

(defun drop-null-fields (object)
  "Remove explicit JSON nulls, which Kubernetes treats the same as omitted fields."
  (dolist (key (loop for key being the hash-keys of object using (hash-value value)
                     when (eq value 'null) collect key))
    (remhash key object))
  object)

(defparameter *seccomp-profile-root* #P"/var/lib/kubelet/seccomp/"
  "Where Localhost seccomp profiles are read from: the kubelet's default, where profile installers
such as the security-profiles-operator put them.")

(defun validate-seccomp-profile (profile)
  "Accept the profile types CRI applies. A Localhost profile names a file under the profile root."
  (drop-null-fields (require-object profile "securityContext.seccompProfile"))
  (reject-unsupported-fields profile '("type" "localhostProfile") "seccompProfile")
  (let ((type (gethash "type" profile)) (localhost (gethash "localhostProfile" profile)))
    (unless (member type '("RuntimeDefault" "Unconfined" "Localhost") :test #'equal)
      (invalid-pod "seccompProfile.type ~S must be RuntimeDefault, Unconfined or Localhost" type))
    (cond ((equal type "Localhost")
           (unless (safe-volume-relative-path-p localhost)
             (invalid-pod "seccompProfile.localhostProfile must be a relative path without traversal when type is Localhost")))
          (localhost
           (invalid-pod "seccompProfile.localhostProfile requires type Localhost")))))

(defun validate-selinux-options (options)
  "Validate the SELinux label components forwarded to the container runtime."
  (drop-null-fields (require-object options "securityContext.seLinuxOptions"))
  (reject-unsupported-fields options '("user" "role" "type" "level") "seLinuxOptions")
  (maphash (lambda (key value)
             (unless (stringp value) (invalid-pod "seLinuxOptions.~A must be a string" key)))
           options))

(defun validate-container-capabilities (capabilities)
  "Validate capability names without an invented allowlist; the runtime rejects unknown ones."
  (drop-null-fields (require-object capabilities "securityContext.capabilities"))
  (reject-unsupported-fields capabilities '("add" "drop") "capabilities")
  (dolist (field '("add" "drop"))
    (loop for name across (optional-vector capabilities field "capabilities")
          do (unless (and (stringp name) (plusp (length name))
                          (every (lambda (character)
                                   (or (alphanumericp character) (char= character #\_))) name))
               (invalid-pod "capabilities.~A contains an invalid name" field)))))

(defun validate-apparmor-profile (profile)
  "Validate an appArmorProfile as the API server does; the node decides whether it can enforce it."
  (drop-null-fields (require-object profile "securityContext.appArmorProfile"))
  (reject-unsupported-fields profile '("type" "localhostProfile") "appArmorProfile")
  (let ((type (gethash "type" profile)) (localhost (gethash "localhostProfile" profile)))
    (cond ((equal type "Localhost")
           (unless (and (stringp localhost) (plusp (length (string-trim " " localhost))))
             (invalid-pod "appArmorProfile.localhostProfile must be set when AppArmor type is Localhost"))
           (unless (equal localhost (string-trim '(#\Space #\Tab #\Newline #\Return) localhost))
             (invalid-pod "appArmorProfile.localhostProfile must not be padded with whitespace"))
           (when (> (length localhost) 4095)
             (invalid-pod "appArmorProfile.localhostProfile may not be more than 4095 bytes")))
          ((member type '("RuntimeDefault" "Unconfined") :test #'equal)
           (when localhost
             (invalid-pod "appArmorProfile.localhostProfile can only be set when AppArmor type is Localhost")))
          ((member type '(nil "") :test #'equal)
           (invalid-pod "appArmorProfile.type is required when appArmorProfile is set"))
          (t (invalid-pod "appArmorProfile.type ~S must be RuntimeDefault, Unconfined or Localhost" type)))))

(defun validate-windows-options (options)
  "Accept windowsOptions, which a Linux node ignores, when they are well formed."
  (drop-null-fields (require-object options "securityContext.windowsOptions"))
  (reject-unsupported-fields options '("gmsaCredentialSpecName" "gmsaCredentialSpec" "runAsUserName" "hostProcess")
                             "windowsOptions")
  (dolist (field '("gmsaCredentialSpecName" "gmsaCredentialSpec" "runAsUserName"))
    (when (and (gethash field options) (not (stringp (gethash field options))))
      (invalid-pod "windowsOptions.~A must be a string" field)))
  (multiple-value-bind (value present) (gethash "hostProcess" options)
    (when (and present (not (member value '(t nil))))
      (invalid-pod "windowsOptions.hostProcess must be boolean"))))

(defun validate-security-context-enum (context field values)
  "Require CONTEXT's optional FIELD to be one of VALUES."
  (when (gethash field context)
    (unless (member (gethash field context) values :test #'equal)
      (invalid-pod "securityContext.~A ~S is not one of ~{~A~^, ~}" field (gethash field context) values))))

(defun validate-linux-security-context (context &key pod)
  "Validate the Linux identity, confinement and privilege settings implemented by the CRI adapter."
  (when context
    (drop-null-fields (require-object context "securityContext"))
    (reject-unsupported-fields context
                               (if pod '("runAsUser" "runAsGroup" "runAsNonRoot" "fsGroup"
                                         "supplementalGroups" "seLinuxOptions" "seccompProfile" "sysctls"
                                         "fsGroupChangePolicy" "supplementalGroupsPolicy" "seLinuxChangePolicy"
                                         "appArmorProfile" "windowsOptions")
                                   '("runAsUser" "runAsGroup" "runAsNonRoot" "privileged"
                                     "readOnlyRootFilesystem" "allowPrivilegeEscalation"
                                     "seLinuxOptions" "seccompProfile" "capabilities"
                                     "appArmorProfile" "windowsOptions" "procMount")) "securityContext")
    (when pod (validate-pod-sysctls context))
    (validate-security-context-enum context "fsGroupChangePolicy" '("OnRootMismatch" "Always"))
    (validate-security-context-enum context "supplementalGroupsPolicy" '("Merge" "Strict"))
    (validate-security-context-enum context "seLinuxChangePolicy" '("Recursive" "MountOption"))
    (validate-security-context-enum context "procMount" '("Default" "Unmasked"))
    ;; Pods share the node's user namespace (hostUsers is true), where /proc stays masked.
    (when (equal "Unmasked" (gethash "procMount" context))
      (invalid-pod "securityContext.procMount: `hostUsers` must be false to use `Unmasked`"))
    (when (gethash "appArmorProfile" context) (validate-apparmor-profile (gethash "appArmorProfile" context)))
    (when (gethash "windowsOptions" context) (validate-windows-options (gethash "windowsOptions" context)))
    (when (gethash "seccompProfile" context) (validate-seccomp-profile (gethash "seccompProfile" context)))
    (when (gethash "seLinuxOptions" context) (validate-selinux-options (gethash "seLinuxOptions" context)))
    (when (gethash "capabilities" context) (validate-container-capabilities (gethash "capabilities" context)))
    (loop for group across (optional-vector context "supplementalGroups" "securityContext")
          do (unless (typep group '(integer 0 4294967294))
               (invalid-pod "securityContext.supplementalGroups must contain Linux GIDs")))
    (dolist (field '("runAsUser" "runAsGroup" "fsGroup"))
      (when (gethash field context)
        (unless (typep (gethash field context) '(integer 0 4294967294))
          (invalid-pod "securityContext.~A must be a Linux UID/GID" field))))
    (dolist (field '("runAsNonRoot" "privileged" "readOnlyRootFilesystem" "allowPrivilegeEscalation"))
      (multiple-value-bind (value present) (gethash field context)
        (when (and present (not (member value '(t nil))))
          (invalid-pod "securityContext.~A must be boolean" field))))))

(defun pod-metadata-subscript-reference (field)
  "Recognize a valid single-key label/annotation downward environment reference."
  (when (stringp field)
    (loop for kind in '("labels" "annotations")
          for prefix = (format nil "metadata.~A['" kind)
          when (and (uiop:string-prefix-p prefix field) (uiop:string-suffix-p field "']")
                    (> (length field) (+ (length prefix) 2)))
            do (let ((key (subseq field (length prefix) (- (length field) 2))))
                 (when (core-qualified-key-p key) (return (cons kind key)))))))

(defun validate-resource-field-reference (reference)
  "Validate a resourceFieldRef's implemented resource and its divisor."
  (drop-null-fields (require-object reference "resourceFieldRef"))
  (reject-unsupported-fields reference '("containerName" "resource" "divisor") "resourceFieldRef")
  (unless (member (gethash "resource" reference)
                  '("limits.cpu" "limits.memory" "requests.cpu" "requests.memory"
                    "limits.ephemeral-storage" "requests.ephemeral-storage") :test #'equal)
    (invalid-pod "resourceFieldRef.resource ~S is not supported" (gethash "resource" reference)))
  (when (gethash "divisor" reference)
    (when (minusp (container-quantity-coefficient (parse-container-quantity (gethash "divisor" reference))))
      (invalid-pod "resourceFieldRef.divisor must not be negative"))))

(defun validate-pod-field-reference (variable)
  "Validate downward fields and namespace-local Secret/ConfigMap key environment sources."
  (when (nth-value 1 (gethash "value" variable))
    (invalid-pod "env.value and env.valueFrom are mutually exclusive"))
  (let* ((from (require-object (gethash "valueFrom" variable) "env.valueFrom"))
         (sources (loop for key being the hash-keys of from collect key)))
    (reject-unsupported-fields from '("fieldRef" "resourceFieldRef" "secretKeyRef" "configMapKeyRef") "env.valueFrom")
    (unless (= 1 (length sources)) (invalid-pod "env.valueFrom requires exactly one source"))
    (let* ((kind (first sources)) (ref (require-object (gethash kind from) "environment source")))
      (cond
        ((equal kind "fieldRef")
         (reject-unsupported-fields ref '("fieldPath" "apiVersion") "fieldRef")
         (unless (and (equal "v1" (gethash "apiVersion" ref "v1"))
                      (or (member (gethash "fieldPath" ref)
                                  '("metadata.name" "metadata.namespace" "metadata.uid" "spec.nodeName" "spec.serviceAccountName"
                                    "status.podIP" "status.podIPs" "status.hostIP" "status.hostIPs") :test #'equal)
                          (pod-metadata-subscript-reference (gethash "fieldPath" ref))))
           (invalid-pod "unsupported downward API field reference")))
        ;; Unlike in a volume, an unnamed container here means the variable's own.
        ((equal kind "resourceFieldRef") (validate-resource-field-reference ref))
        (t
         (reject-unsupported-fields ref '("name" "key" "optional") "environment key reference")
         (require-dns-subdomain (gethash "name" ref) "environment source name")
         (unless (core-data-key-p (gethash "key" ref)) (invalid-pod "invalid environment source key"))
         (multiple-value-bind (optional present) (gethash "optional" ref)
           (when (and present (not (member optional '(t nil))))
             (invalid-pod "environment key reference optional must be boolean"))))))))

(defun validate-environment-sources (container)
  "Validate envFrom entries: an optional prefix and exactly one local object reference."
  (loop for source across (optional-vector container "envFrom" "container")
        do (drop-null-fields (require-object source "envFrom"))
           (reject-unsupported-fields source '("prefix" "configMapRef" "secretRef") "envFrom")
           (let ((prefix (gethash "prefix" source ""))
                 (reference (or (gethash "configMapRef" source) (gethash "secretRef" source))))
             (unless (stringp prefix) (invalid-pod "envFrom.prefix must be a string"))
             (when (find #\= prefix) (invalid-pod "envFrom.prefix must not contain ="))
             (unless (and reference (not (and (gethash "configMapRef" source) (gethash "secretRef" source))))
               (invalid-pod "envFrom requires exactly one of configMapRef and secretRef"))
             (drop-null-fields (require-object reference "envFrom reference"))
             (reject-unsupported-fields reference '("name" "optional") "envFrom reference")
             (require-dns-subdomain (gethash "name" reference) "envFrom reference name")
             (multiple-value-bind (optional present) (gethash "optional" reference)
               (when (and present (not (member optional '(t nil))))
                 (invalid-pod "envFrom reference optional must be boolean"))))))

(defun validate-runtime-container (container)
  "Validate mount declarations, executable probes, image policy and security settings."
  (validate-environment-sources container)
  (validate-container-lifecycle container)
  (validate-container-resize-policy container)
  (dolist (field '("stdin" "stdinOnce" "tty"))
    (multiple-value-bind (value present) (gethash field container)
      (when (and present (not (member value '(t nil))))
        (invalid-pod "container.~A must be boolean" field))))
  (dolist (kind '("startupProbe" "readinessProbe" "livenessProbe"))
    (when (gethash kind container) (validate-container-probe (gethash kind container) kind)))
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
        do (reject-unsupported-fields mount '("name" "mountPath" "readOnly" "subPath" "subPathExpr" "mountPropagation") "volumeMount")
           (require-dns-label (gethash "name" mount) "volumeMount.name")
           (let ((propagation (gethash "mountPropagation" mount)))
             (when propagation
               (unless (member propagation '("None" "HostToContainer" "Bidirectional") :test #'equal)
                 (invalid-pod "volumeMount.mountPropagation ~S is not supported" propagation))
               (when (and (equal propagation "Bidirectional")
                          (not (eq t (gethash "privileged" (gethash "securityContext" container (core-object))))))
                 (invalid-pod "Bidirectional mount propagation requires a privileged container"))))
           (dolist (field '("subPath" "subPathExpr"))
             (when (nth-value 1 (gethash field mount))
               (unless (valid-container-subpath-p (gethash field mount))
                 (invalid-pod "volumeMount.~A must be relative without parent traversal" field))))
           (when (and (plusp (length (gethash "subPath" mount "")))
                      (plusp (length (gethash "subPathExpr" mount ""))))
             (invalid-pod "volumeMount.subPath and subPathExpr are mutually exclusive"))
           (let ((path (gethash "mountPath" mount)))
             (unless (and (stringp path) (plusp (length path)) (char= #\/ (char path 0))
                          (not (find #\Null path))
                          (not (member ".." (uiop:split-string path :separator '(#\/)) :test #'equal)))
               (invalid-pod "volumeMount.mountPath must be an absolute path without traversal")))
           (multiple-value-bind (value present) (gethash "readOnly" mount)
             (when (and present (not (member value '(t nil))))
               (invalid-pod "volumeMount.readOnly must be boolean")))))

(defun validate-empty-dir-source (source)
  "Accept disk-backed and tmpfs emptyDirs; the node evicts a Pod whose disk-backed one outgrows its limit."
  (drop-null-fields source)
  (reject-unsupported-fields source '("medium" "sizeLimit") "emptyDir")
  (let ((medium (gethash "medium" source "")) (limit (gethash "sizeLimit" source)))
    (unless (member medium '("" "Memory") :test #'equal)
      (invalid-pod "emptyDir.medium ~S is not supported" medium))
    (unless (member limit '(nil 0 "0") :test #'equal)
      (storage-quantity limit "emptyDir.sizeLimit"))))

(defun validate-ephemeral-source (source)
  "Validate a generic ephemeral volume's claim template; its claim is admitted when created."
  (drop-null-fields source)
  (reject-unsupported-fields source '("volumeClaimTemplate") "ephemeral")
  (let* ((template (require-object (gethash "volumeClaimTemplate" source) "ephemeral.volumeClaimTemplate"))
         (spec (require-object (gethash "spec" template) "ephemeral.volumeClaimTemplate.spec")))
    (drop-null-fields template)
    (reject-unsupported-fields template '("metadata" "spec") "ephemeral.volumeClaimTemplate")
    (when (gethash "metadata" template)
      (let ((metadata (require-object (gethash "metadata" template) "ephemeral.volumeClaimTemplate.metadata")))
        (drop-null-fields metadata)
        (when (or (gethash "name" metadata) (gethash "generateName" metadata))
          (invalid-pod "ephemeral.volumeClaimTemplate.metadata cannot set a name"))))
    (validate-storage-access-modes (gethash "accessModes" spec))
    (storage-quantity
     (gethash "storage" (require-object (gethash "requests" (require-object (gethash "resources" spec) "resources")) "requests"))
     "resources.requests.storage")))

(defun validate-volume-mode (object field)
  "Require OBJECT's optional FIELD to be a permission mode."
  (when (gethash field object)
    (unless (typep (gethash field object) '(integer 0 511))
      (invalid-pod "volume ~A must be between 0 and 0777" field))))

(defun validate-object-volume-source (source name-field)
  "Validate the object name, optional flag and key items of a ConfigMap or Secret source."
  (require-dns-subdomain (gethash name-field source) "volume source name")
  (multiple-value-bind (optional present) (gethash "optional" source)
    (when (and present (not (member optional '(t nil))))
      (invalid-pod "volume source optional must be boolean")))
  (loop for item across (optional-vector source "items" "volume source")
        do (drop-null-fields item)
           (reject-unsupported-fields item '("key" "path" "mode") "volume item")
           (require-nonempty-string (gethash "key" item) "volume item key")
           (unless (safe-volume-relative-path-p (gethash "path" item))
             (invalid-pod "volume item path must be relative without traversal"))
           (validate-volume-mode item "mode")))

(defun validate-downward-items (source)
  "Validate downward API files: one metadata field or container resource each."
  (loop for item across (optional-vector source "items" "downwardAPI")
        do (drop-null-fields item)
           (reject-unsupported-fields item '("path" "fieldRef" "resourceFieldRef" "mode") "downwardAPI item")
           (unless (safe-volume-relative-path-p (gethash "path" item))
             (invalid-pod "downwardAPI item path must be relative without traversal"))
           (validate-volume-mode item "mode")
           (let ((field (gethash "fieldRef" item)) (resource (gethash "resourceFieldRef" item)))
             (unless (and (or field resource) (not (and field resource)))
               (invalid-pod "downwardAPI item requires exactly one of fieldRef and resourceFieldRef"))
             (when field
               (drop-null-fields (require-object field "fieldRef"))
               (reject-unsupported-fields field '("fieldPath" "apiVersion") "fieldRef")
               (unless (and (equal "v1" (gethash "apiVersion" field "v1"))
                            (or (member (gethash "fieldPath" field)
                                        '("metadata.name" "metadata.namespace" "metadata.uid"
                                          "metadata.labels" "metadata.annotations") :test #'equal)
                                (pod-metadata-subscript-reference (gethash "fieldPath" field))))
                 (invalid-pod "unsupported downwardAPI volume field reference")))
             (when resource
               (validate-resource-field-reference resource)
               (require-nonempty-string (gethash "containerName" resource) "resourceFieldRef.containerName")))))

(defun validate-projected-token-source (source)
  "Validate one serviceAccountToken projection's path, audience and lifetime."
  (drop-null-fields (require-object source "serviceAccountToken"))
  (reject-unsupported-fields source '("path" "audience" "expirationSeconds") "serviceAccountToken")
  (unless (safe-volume-relative-path-p (gethash "path" source))
    (invalid-pod "serviceAccountToken.path must be a safe relative path"))
  (let ((audience (gethash "audience" source)))
    (when (and audience (not (stringp audience))) (invalid-pod "serviceAccountToken.audience must be a string")))
  (let ((seconds (gethash "expirationSeconds" source)))
    (when (and seconds (not (and (integerp seconds) (<= 600 seconds (expt 2 32)))))
      (invalid-pod "serviceAccountToken.expirationSeconds must be between 10 minutes and 2^32 seconds"))))

(defconstant +pod-certificate-max-expiration-seconds+ (* 91 24 60 60)
  "The longest lifetime a podCertificate projection may request: 91 days (7862400s).")

(defun validate-pod-certificate-source (source paths)
  "Validate one podCertificate projection (KEP-4317): its required signerName, the
   one keyType gr8s issues, its bounded lifetime and its distinct output paths.
   Returns the paths it contributes, so the caller can keep them conflict-free."
  (drop-null-fields (require-object source "podCertificate"))
  (reject-unsupported-fields source '("signerName" "keyType" "maxExpirationSeconds"
                                      "credentialBundlePath" "keyPath" "certificateChainPath"
                                      "userAnnotations" "user")
                             "podCertificate")
  (require-nonempty-string (gethash "signerName" source) "podCertificate.signerName")
  (let ((key-type (gethash "keyType" source)))
    (unless (equal key-type "ECDSAP256")
      (invalid-pod "podCertificate.keyType must be ECDSAP256 (the only type gr8s issues)")))
  ;; userAnnotations (copied verbatim into the request's unverifiedUserAnnotations
  ;; for the signer) must be a string map; user is the file owner UID gr8s honors
  ;; via fsGroup/ownership already.
  (let ((annotations (gethash "userAnnotations" source)))
    (when annotations (validate-core-string-map annotations "podCertificate.userAnnotations")))
  (let ((user (gethash "user" source)))
    (when (and user (not (typep user '(integer 0 4294967294))))
      (invalid-pod "podCertificate.user must be a Linux UID")))
  ;; Upstream's ValidatePodCertificateProjection bounds, worded as it words them:
  ;; the 1.37 conformance specs match these messages.
  (let ((seconds (gethash "maxExpirationSeconds" source)))
    (when seconds
      (unless (integerp seconds)
        (invalid-pod "podCertificate.maxExpirationSeconds must be an integer"))
      (when (< seconds 3600)
        (invalid-pod "podCertificate.maxExpirationSeconds: Invalid value: ~D: if provided, maxExpirationSeconds must be >= 3600" seconds))
      (when (> seconds +pod-certificate-max-expiration-seconds+)
        (invalid-pod "podCertificate.maxExpirationSeconds: Invalid value: ~D: if provided, maxExpirationSeconds must be <= ~D"
                     seconds +pod-certificate-max-expiration-seconds+))))
  (let ((contributed nil))
    (dolist (field '("credentialBundlePath" "keyPath" "certificateChainPath"))
      (let ((path (gethash field source)))
        (when path
          (unless (safe-volume-relative-path-p path)
            (invalid-pod "podCertificate.~A must be a safe relative path" field))
          (when (or (member path paths :test #'equal) (member path contributed :test #'equal))
            (invalid-pod "projected volume has conflicting path ~S" path))
          (push path contributed))))
    (unless contributed
      (invalid-pod "podCertificate requires at least one of credentialBundlePath, keyPath or certificateChainPath"))
    contributed))

(defun validate-projected-source (projected)
  "Validate a projected volume, refusing sources that have no real implementation here."
  (drop-null-fields projected)
  (reject-unsupported-fields projected '("sources" "defaultMode") "projected")
  (validate-volume-mode projected "defaultMode")
  (let ((paths nil))
    (loop for source across (optional-vector projected "sources" "projected")
          do (drop-null-fields source)
             (reject-unsupported-fields source '("configMap" "secret" "downwardAPI" "serviceAccountToken"
                                                 "clusterTrustBundle" "podCertificate") "projected source")
             (unless (= 1 (hash-table-count source))
               (invalid-pod "projected source requires exactly one kind"))
             (let ((part (or (gethash "configMap" source) (gethash "secret" source))))
               (when part
                 (drop-null-fields (require-object part "projected source"))
                 (reject-unsupported-fields part '("name" "items" "optional") "projected source")
                 (validate-object-volume-source part "name")))
             (let ((part (gethash "downwardAPI" source)))
               (when part
                 (drop-null-fields (require-object part "downwardAPI"))
                 (reject-unsupported-fields part '("items") "downwardAPI")
                 (validate-downward-items part)))
             (let ((part (gethash "serviceAccountToken" source)))
               (when part
                 (validate-projected-token-source part)
                 (when (member (gethash "path" part) paths :test #'equal)
                   (invalid-pod "projected volume has conflicting path ~S" (gethash "path" part)))
                 (push (gethash "path" part) paths)))
             (let ((part (gethash "clusterTrustBundle" source)))
               (when part
                 (drop-null-fields (require-object part "clusterTrustBundle"))
                 (reject-unsupported-fields part '("path" "name" "signerName" "labelSelector" "optional")
                                            "clusterTrustBundle")
                 (let ((path (gethash "path" part))
                       (name (gethash "name" part))
                       (signer (gethash "signerName" part)))
                   (unless (and (stringp path) (plusp (length path)))
                     (invalid-pod "clusterTrustBundle projection requires a path"))
                   ;; Exactly one selector: a concrete name, or a signerName
                   ;; (optionally narrowed by labelSelector).
                   (unless (if name (not signer) signer)
                     (invalid-pod "clusterTrustBundle requires exactly one of name or signerName"))
                   (when (and name (gethash "labelSelector" part))
                     (invalid-pod "clusterTrustBundle labelSelector applies only with signerName"))
                   (when (member path paths :test #'equal)
                     (invalid-pod "projected volume has conflicting path ~S" path))
                   (push path paths))))
             (let ((part (gethash "podCertificate" source)))
               (when part
                 (setf paths (append (validate-pod-certificate-source part paths) paths))))
             (let ((part (or (gethash "configMap" source) (gethash "secret" source) (gethash "downwardAPI" source))))
               (when part
                 (loop for item across (gethash "items" part #())
                       do (when (member (gethash "path" item) paths :test #'equal)
                            (invalid-pod "projected volume has conflicting path ~S" (gethash "path" item)))
                          (push (gethash "path" item) paths)))))))

(defun validate-image-volume-source (source)
  "Validate an image volume's required reference and optional pull policy."
  (drop-null-fields source)
  (reject-unsupported-fields source '("reference" "pullPolicy") "image")
  (require-nonempty-string (gethash "reference" source) "image.reference")
  (when (gethash "pullPolicy" source)
    (unless (member (gethash "pullPolicy" source) '("Always" "IfNotPresent" "Never") :test #'equal)
      (invalid-pod "invalid image.pullPolicy"))))

(defun validate-pod-volume (volume)
  "Validate a durable ConfigMap, Secret, downward API, projected, disk or tmpfs volume."
  (drop-null-fields volume)
  (reject-unsupported-fields volume '("name" "configMap" "secret" "downwardAPI" "projected" "emptyDir" "hostPath" "persistentVolumeClaim" "nfs" "ephemeral" "csi" "image") "volume")
  (require-dns-label (gethash "name" volume) "volume.name")
  (let ((sources (remove-if-not (lambda (key) (nth-value 1 (gethash key volume)))
                                '("configMap" "secret" "downwardAPI" "projected" "emptyDir" "hostPath" "persistentVolumeClaim" "nfs" "ephemeral" "csi" "image"))))
    (unless (= 1 (length sources)) (invalid-pod "volume requires exactly one source"))
    (let* ((kind (first sources)) (source (require-object (gethash kind volume) "volume source")))
      (when (equal kind "hostPath")
        (reject-unsupported-fields source '("path" "type") "hostPath")
        (validate-host-storage-source source)
        (return-from validate-pod-volume volume))
      (when (equal kind "nfs")
        (drop-null-fields source)
        (reject-unsupported-fields source '("server" "path" "readOnly") "nfs")
        (validate-nfs-source source)
        (return-from validate-pod-volume volume))
      (when (equal kind "csi")
        (drop-null-fields source)
        (reject-unsupported-fields source '("driver" "readOnly" "fsType" "volumeAttributes" "nodePublishSecretRef") "csi")
        (unless (csi-driver-name-valid-p (gethash "driver" source))
          (invalid-pod "csi.driver must be a CSI driver name"))
        (when (gethash "volumeAttributes" source)
          (validate-core-string-map (gethash "volumeAttributes" source) "csi.volumeAttributes"))
        (when (gethash "nodePublishSecretRef" source)
          (require-dns-subdomain (gethash "name" (gethash "nodePublishSecretRef" source)) "csi.nodePublishSecretRef.name"))
        (return-from validate-pod-volume volume))
      (when (equal kind "ephemeral")
        (validate-ephemeral-source source)
        (return-from validate-pod-volume volume))
      (when (equal kind "image")
        (validate-image-volume-source source)
        (return-from validate-pod-volume volume))
      (when (equal kind "persistentVolumeClaim")
        (reject-unsupported-fields source '("claimName" "readOnly") "persistentVolumeClaim")
        (require-dns-subdomain (gethash "claimName" source) "persistentVolumeClaim.claimName")
        (multiple-value-bind (value present) (gethash "readOnly" source)
          (when (and present (not (member value '(t nil)))) (invalid-pod "persistentVolumeClaim.readOnly must be boolean")))
        (return-from validate-pod-volume volume))
      (cond
        ((equal kind "emptyDir") (validate-empty-dir-source source))
        ((equal kind "downwardAPI")
         (drop-null-fields source)
         (reject-unsupported-fields source '("items" "defaultMode") "downwardAPI")
         (validate-volume-mode source "defaultMode")
         (validate-downward-items source))
        ((equal kind "projected") (validate-projected-source source))
        (t (let ((name-field (if (equal kind "configMap") "name" "secretName")))
             (drop-null-fields source)
             (reject-unsupported-fields source (list name-field "items" "defaultMode" "optional") "volume source")
             (validate-volume-mode source "defaultMode")
             (validate-object-volume-source source name-field)))))))

(defun validate-runtime-pod-spec (spec)
  "Validate Pod-level volume, security, service account and scheduling fields."
  ;; The API server defaults an absent Pod securityContext to an empty one, which clients
  ;; such as kubectl debug read without checking for nil.
  (when (member (gethash "securityContext" spec) '(nil null))
    (setf (gethash "securityContext" spec) (core-object)))
  (validate-linux-security-context (gethash "securityContext" spec) :pod t)
  ;; A Pod that declares itself Linux cannot carry Windows settings, as upstream validates.
  (when (and (equal "linux" (gethash "name" (gethash "os" spec (core-object))))
             (some (lambda (context) (and (hash-table-p context) (gethash "windowsOptions" context)))
                   (cons (gethash "securityContext" spec)
                         (map 'list (lambda (container) (and (hash-table-p container) (gethash "securityContext" container)))
                              (concatenate 'vector (optional-vector spec "initContainers" "spec")
                                           (optional-vector spec "containers" "spec")
                                           (optional-vector spec "ephemeralContainers" "spec"))))))
    (invalid-pod "securityContext.windowsOptions: Forbidden: windows options cannot be set for a linux pod"))
  ;; serviceAccount is the deprecated alias: it names the account when serviceAccountName
  ;; does not, and otherwise mirrors it, as the API server's conversion does.
  (multiple-value-bind (alias present) (gethash "serviceAccount" spec)
    (when present
      (when (member alias '(null "") :test #'equal) (setf alias nil))
      (when (and alias (not (stringp alias))) (invalid-pod "spec.serviceAccount must be a string"))
      (when (and alias (member (gethash "serviceAccountName" spec) '(nil null "") :test #'equal))
        (setf (gethash "serviceAccountName" spec) alias))
      (if (stringp (gethash "serviceAccountName" spec))
          (setf (gethash "serviceAccount" spec) (gethash "serviceAccountName" spec))
          (remhash "serviceAccount" spec))))
  (when (gethash "serviceAccountName" spec)
    (require-dns-subdomain (gethash "serviceAccountName" spec) "serviceAccountName"))
  (multiple-value-bind (value present) (gethash "automountServiceAccountToken" spec)
    (when (and present (not (member value '(t nil))))
      (invalid-pod "automountServiceAccountToken must be boolean")))
  (when (eq (gethash "imagePullSecrets" spec) 'null) (remhash "imagePullSecrets" spec))
  (loop for reference across (optional-vector spec "imagePullSecrets" "spec")
        do (drop-null-fields (require-object reference "imagePullSecrets"))
           (reject-unsupported-fields reference '("name") "imagePullSecrets")
           ;; As upstream, an empty name is accepted and then ignored.
           (unless (equal "" (gethash "name" reference ""))
             (require-dns-subdomain (gethash "name" reference) "imagePullSecrets.name")))
  (let ((names nil))
    (loop for volume across (optional-vector spec "volumes" "spec")
          do (validate-pod-volume volume)
             (when (member (gethash "name" volume) names :test #'equal) (invalid-pod "volume names must be unique"))
             (push (gethash "name" volume) names))
    (loop for container across (concatenate 'vector (optional-vector spec "initContainers" "spec")
                                           (optional-vector spec "containers" "spec")
                                           (optional-vector spec "ephemeralContainers" "spec"))
          do (require-object container "container")
             (loop for mount across (optional-vector container "volumeMounts" "container")
                   unless (member (gethash "name" mount) names :test #'equal)
                     do (invalid-pod "volumeMount references an unknown volume"))))
  (when (gethash "nodeSelector" spec) (validate-pod-node-selector (gethash "nodeSelector" spec)))
  (validate-pod-tolerations spec)
  (validate-pod-policy-fields spec)
  (validate-pod-scheduler-name spec)
  (validate-pod-scheduling-gates spec)
  (validate-pod-readiness-gates spec)
  (validate-pod-affinity spec)
  (validate-topology-spread-constraints spec))

(defparameter +default-scheduler-name+ "default-scheduler"
  "The scheduler a Pod names by default, which is the one gr8s runs.")

(defun validate-pod-scheduler-name (spec)
  "Default an omitted spec.schedulerName as the API server does, and require a DNS subdomain."
  (when (member (gethash "schedulerName" spec) '(nil null "") :test #'equal)
    (setf (gethash "schedulerName" spec) +default-scheduler-name+))
  (require-dns-subdomain (gethash "schedulerName" spec) "spec.schedulerName"))

(defun pod-scheduler-name (pod)
  "Return the name of the scheduler responsible for placing POD."
  (gethash "schedulerName" (gethash "spec" (pod-to-object pod)) +default-scheduler-name+))

(defun pod-for-this-scheduler-p (pod)
  "Return whether gr8s's scheduler places POD; any other scheduler binds it through pods/binding."
  (equal +default-scheduler-name+ (pod-scheduler-name pod)))

(defun validate-pod-scheduling-gates (spec)
  "Validate spec.schedulingGates: unique qualified names, none left once a node is named."
  (when (eq (gethash "schedulingGates" spec) 'null) (remhash "schedulingGates" spec))
  (let ((names nil))
    (loop for gate across (optional-vector spec "schedulingGates" "spec")
          do (drop-null-fields (require-object gate "schedulingGate"))
             (reject-unsupported-fields gate '("name") "schedulingGate")
             (let ((name (gethash "name" gate)))
               (unless (core-qualified-key-p name)
                 (invalid-pod "spec.schedulingGates.name ~S must be a qualified name" name))
               (when (member name names :test #'equal)
                 (invalid-pod "spec.schedulingGates: Duplicate value: ~S" name))
               (push name names)))
    (when (and names (stringp (gethash "nodeName" spec)) (plusp (length (gethash "nodeName" spec))))
      (invalid-pod "spec.nodeName: Forbidden: cannot be set until all schedulingGates have been cleared"))))

(defun pod-scheduling-gated-p (pod)
  "Return whether POD still carries scheduling gates, which keep every scheduler from placing it."
  (plusp (length (gethash "schedulingGates" (gethash "spec" (pod-to-object pod)) #()))))

(defun validate-pod-readiness-gates (spec)
  "Validate spec.readinessGates: each names a qualified condition type that Ready also waits for."
  (when (eq (gethash "readinessGates" spec) 'null) (remhash "readinessGates" spec))
  (loop for gate across (optional-vector spec "readinessGates" "spec")
        do (drop-null-fields (require-object gate "readinessGate"))
           (reject-unsupported-fields gate '("conditionType") "readinessGate")
           (unless (core-qualified-key-p (gethash "conditionType" gate))
             (invalid-pod "spec.readinessGates.conditionType ~S must be a qualified name"
                          (gethash "conditionType" gate)))))

(defun pod-readiness-gate-types (pod)
  "Return the condition types POD's readiness gates wait for."
  (loop for gate across (gethash "readinessGates" (gethash "spec" (pod-to-object pod)) #())
        collect (gethash "conditionType" gate)))

(defun pod-readiness-gates-message (pod conditions)
  "Explain, as a kubelet does, which of POD's readiness gates CONDITIONS leave unmet; NIL when all are True."
  (let ((messages
          (loop for type in (pod-readiness-gate-types pod)
                for condition = (find-pod-condition conditions type)
                unless (and condition (equal "True" (gethash "status" condition)))
                  collect (if condition
                              (format nil "the status of pod readiness gate ~S is not \"True\", but ~A"
                                      type (gethash "status" condition))
                              (format nil "corresponding condition of pod readiness gate ~S does not exist." type)))))
    (when messages (format nil "~{~A~^, ~}" messages))))

(defun validate-node-selector-term (term)
  "Validate a NodeSelectorTerm's label expressions and metadata.name field requirements."
  (drop-null-fields (require-object term "nodeSelectorTerm"))
  (reject-unsupported-fields term '("matchExpressions" "matchFields") "nodeSelectorTerm")
  (flet ((check (requirement)
           (drop-null-fields (require-object requirement "node selector requirement"))
           (reject-unsupported-fields requirement '("key" "operator" "values") "node selector requirement")
           (let ((operator (gethash "operator" requirement)) (values (gethash "values" requirement #())))
             (cond ((member operator '("In" "NotIn") :test #'equal)
                    (when (zerop (length values)) (invalid-pod "node selector operator ~A requires values" operator)))
                   ((member operator '("Exists" "DoesNotExist") :test #'equal)
                    (when (plusp (length values)) (invalid-pod "node selector operator ~A forbids values" operator)))
                   ((member operator '("Gt" "Lt") :test #'equal)
                    (unless (and (= 1 (length values))
                                 (ignore-errors (parse-integer (aref values 0))))
                      (invalid-pod "node selector operator ~A requires one integer value" operator)))
                   (t (invalid-pod "Invalid node selector operator ~S" operator))))))
    (loop for requirement across (optional-vector term "matchExpressions" "nodeSelectorTerm")
          do (check requirement)
             (unless (core-qualified-key-p (gethash "key" requirement))
               (invalid-pod "Invalid node selector key ~S" (gethash "key" requirement))))
    (loop for requirement across (optional-vector term "matchFields" "nodeSelectorTerm")
          do (check requirement)
             (unless (and (equal "metadata.name" (gethash "key" requirement))
                          (member (gethash "operator" requirement) '("In" "NotIn") :test #'equal)
                          (= 1 (length (gethash "values" requirement))))
               (invalid-pod "matchFields only supports one metadata.name value with In or NotIn")))))

(defun validate-pod-affinity (spec)
  "Validate node affinity and inter-Pod affinity, all of which the scheduler evaluates."
  (when (eq (gethash "affinity" spec) 'null) (remhash "affinity" spec))
  (let ((affinity (gethash "affinity" spec)))
    (when affinity
      (drop-null-fields (require-object affinity "spec.affinity"))
      (reject-unsupported-fields affinity '("nodeAffinity" "podAffinity" "podAntiAffinity") "spec.affinity")
      (dolist (kind '("podAffinity" "podAntiAffinity"))
        (when (gethash kind affinity)
          (validate-pod-affinity-group (gethash kind affinity) kind)))
      (let ((node-affinity (gethash "nodeAffinity" affinity)))
        (when node-affinity
          (drop-null-fields (require-object node-affinity "nodeAffinity"))
          (reject-unsupported-fields node-affinity '("requiredDuringSchedulingIgnoredDuringExecution"
                                                     "preferredDuringSchedulingIgnoredDuringExecution")
                                     "nodeAffinity")
          (let ((required (gethash "requiredDuringSchedulingIgnoredDuringExecution" node-affinity)))
            (when required
              (let ((terms (optional-vector required "nodeSelectorTerms" "nodeAffinity")))
                (when (zerop (length terms)) (invalid-pod "nodeAffinity requires at least one nodeSelectorTerm"))
                (map nil #'validate-node-selector-term terms))))
          (loop for entry across (optional-vector node-affinity "preferredDuringSchedulingIgnoredDuringExecution" "nodeAffinity")
                do (reject-unsupported-fields entry '("weight" "preference") "preferred node affinity")
                   (unless (typep (gethash "weight" entry) '(integer 1 100))
                     (invalid-pod "preferred node affinity weight must be between 1 and 100"))
                   (validate-node-selector-term (require-object (gethash "preference" entry) "preference"))))))))

(defun validate-pod-node-selector (selector)
  "Accept any qualified label; a label no node carries simply leaves the Pod unscheduled."
  (require-object selector "nodeSelector")
  (maphash (lambda (key value)
             (unless (core-qualified-key-p key) (invalid-pod "nodeSelector key ~S is invalid" key))
             (unless (core-label-name-p value :empty t) (invalid-pod "nodeSelector value for ~S is invalid" key)))
           selector))

(defun validate-pod-tolerations (spec)
  "Validate the toleration list of a Pod or RuntimeClass scheduling SPEC."
  (loop for toleration across (optional-vector spec "tolerations" "spec")
        do (reject-unsupported-fields toleration '("key" "operator" "value" "effect" "tolerationSeconds") "toleration")
           (unless (member (gethash "operator" toleration "Equal") '("Equal" "Exists") :test #'equal)
             (invalid-pod "invalid toleration operator"))
           (when (gethash "effect" toleration)
             (unless (member (gethash "effect" toleration) '("" "NoSchedule" "PreferNoSchedule" "NoExecute") :test #'equal)
               (invalid-pod "invalid toleration effect")))))

(defun validate-pod-policy-fields (spec)
  "Validate the runtime class, priority, overhead and active deadline fields admission resolves."
  (dolist (field '("runtimeClassName" "priorityClassName" "priority" "preemptionPolicy" "overhead" "activeDeadlineSeconds"))
    (when (eq (gethash field spec) 'null) (remhash field spec)))
  (when (gethash "runtimeClassName" spec)
    (require-dns-subdomain (gethash "runtimeClassName" spec) "spec.runtimeClassName"))
  (when (equal "" (gethash "priorityClassName" spec)) (remhash "priorityClassName" spec))
  (when (gethash "priorityClassName" spec)
    (require-dns-subdomain (gethash "priorityClassName" spec) "spec.priorityClassName"))
  (when (nth-value 1 (gethash "priority" spec))
    (unless (typep (gethash "priority" spec) '(signed-byte 32)) (invalid-pod "spec.priority must be an int32")))
  (when (gethash "preemptionPolicy" spec)
    (unless (member (gethash "preemptionPolicy" spec) '("PreemptLowerPriority" "Never") :test #'equal)
      (invalid-pod "spec.preemptionPolicy must be PreemptLowerPriority or Never")))
  (when (gethash "activeDeadlineSeconds" spec)
    (unless (typep (gethash "activeDeadlineSeconds" spec) '(integer 1 9223372036854775807))
      (invalid-pod "spec.activeDeadlineSeconds must be a positive int64")))
  (let ((overhead (gethash "overhead" spec)))
    (when overhead
      (require-object overhead "spec.overhead")
      (dolist (name (loop for name being the hash-keys of overhead collect name))
        (unless (member name '("cpu" "memory") :test #'equal)
          (invalid-pod "spec.overhead[~A] has no implemented accounting" name))
        (setf (gethash name overhead)
              (container-quantity-string (container-quantity-round (parse-container-quantity (gethash name overhead)) -3)))))))

(defun node-builtin-labels (node)
  "Return the labels gr8s derives from what NODE actually is."
  (core-object "kubernetes.io/os" "linux"
               "kubernetes.io/arch" (native-node-architecture)
               "kubernetes.io/hostname" (node-record-name node)))

(defun node-labels (node)
  "Return all of NODE's labels: the derived ones and those written through the API."
  (let ((labels (node-builtin-labels node)))
    (when (node-record-labels node)
      (maphash (lambda (key value) (setf (gethash key labels) value)) (node-record-labels node)))
    labels))

(defun node-selector-matches-p (selector node)
  "Match a Pod spec's nodeSelector against NODE's actual labels."
  (or (member selector '(nil null))
      (let ((labels (node-labels node)))
        (loop for key being the hash-keys of selector using (hash-value expected)
              always (equal expected (gethash key labels))))))

(defun pod-node-selector-matches-p (pod node)
  "Match POD's node selector against the labels registered worker NODE exposes."
  (let ((selector (gethash "nodeSelector" (gethash "spec" (pod-to-object pod)))))
    (or (null selector)
        (let ((labels (storage-node-labels node)))
          (loop for key being the hash-keys of selector using (hash-value expected)
                always (equal expected (gethash key labels)))))))

(defun pod-runtime-handler (pod)
  "Return the admission-resolved CRI handler of POD's RuntimeClass, or NIL for the default runtime."
  (let* ((object (pod-to-object pod))
         (annotations (gethash "annotations" (gethash "metadata" object))))
    (when (and annotations (gethash "runtimeClassName" (gethash "spec" object)))
      (gethash "node.gr8s.io/runtime-handler" annotations))))

(defun pod-requests-privileged-container-p (pod)
  "Return whether any validated container needs a privileged sandbox."
  (loop for container across (let ((spec (gethash "spec" (pod-to-object pod))))
                               (concatenate 'vector (gethash "initContainers" spec #()) (gethash "containers" spec)))
        thereis (let ((context (gethash "securityContext" container)))
                  (and context (eq t (gethash "privileged" context))))))
