(in-package #:gr8s)

;;;; API-server defaults for Pod specs, as upstream v1.37.2 applies them when it decodes a
;;;; request: SetDefaults_PodSpec, SetDefaults_Pod and the nested SetDefaults_* and +default
;;;; markers that pkg/apis/core/v1/zz_generated.defaults.go applies under a Pod. Clients that
;;;; diff or patch (kubectl apply, GitOps tools, controllers) read these fields back.
;;;;
;;;; A Pod's runtime fingerprint covers its spec, so defaults are added only to Pods being
;;;; created and to updates of Pods already stored with them: adding them to a Pod stored by
;;;; an older gr8s would restart it.

(defun default-json-field (object field value)
  "Set FIELD of OBJECT to VALUE when it is absent, null or empty, as Go's zero-value checks do."
  (when (and (hash-table-p object) (member (gethash field object) '(nil null "") :test #'equal))
    (setf (gethash field object) value)))

(defun default-json-pointer-field (object field value)
  "Set FIELD of OBJECT to VALUE only when it is absent or null: a pointer field keeps an explicit zero."
  (when (and (hash-table-p object) (member (gethash field object '|absent|) '(|absent| null)))
    (setf (gethash field object) value)))

(defun json-items (object field)
  "Return OBJECT's FIELD as a list of its object elements, ignoring anything malformed."
  (let ((value (and (hash-table-p object) (gethash field object))))
    (when (and (vectorp value) (not (stringp value)))
      (remove-if-not #'hash-table-p (coerce value 'list)))))

(defun json-child (object field)
  "Return OBJECT's FIELD when it is an object, else NIL."
  (let ((value (and (hash-table-p object) (gethash field object))))
    (and (hash-table-p value) value)))

(defun default-http-get-action (action)
  "SetDefaults_HTTPGetAction."
  (default-json-field action "path" "/")
  (default-json-field action "scheme" "HTTP"))

(defun default-container-object (container)
  "Default one container, init container or ephemeral container object."
  (when (stringp (gethash "image" container))
    (default-json-field container "imagePullPolicy" (default-image-pull-policy (gethash "image" container))))
  (default-json-field container "terminationMessagePath" "/dev/termination-log")
  (default-json-field container "terminationMessagePolicy" "File")
  (dolist (port (json-items container "ports"))
    (default-json-field port "protocol" "TCP"))
  (dolist (variable (json-items container "env"))
    (let ((source (json-child variable "valueFrom")))
      (default-json-field (json-child source "fieldRef") "apiVersion" "v1")
      (default-json-pointer-field (json-child source "fileKeyRef") "optional" nil)))
  (dolist (kind '("livenessProbe" "readinessProbe" "startupProbe"))
    (let ((probe (json-child container kind)))
      (when probe
        (default-http-get-action (json-child probe "httpGet"))
        (default-json-pointer-field (json-child probe "grpc") "service" ""))))
  (let ((lifecycle (json-child container "lifecycle")))
    (dolist (hook '("postStart" "preStop"))
      (default-http-get-action (json-child (json-child lifecycle hook) "httpGet"))))
  container)

(defparameter +default-volume-mode+ #o644
  "The defaultMode SetDefaults_*VolumeSource give secret, configMap, downwardAPI and projected volumes.")

(defun default-downward-items (source)
  "SetDefaults_ObjectFieldSelector on each fieldRef of a downwardAPI SOURCE."
  (dolist (item (json-items source "items"))
    (default-json-field (json-child item "fieldRef") "apiVersion" "v1")))

(defparameter +volume-source-fields+
  '("hostPath" "emptyDir" "gcePersistentDisk" "awsElasticBlockStore" "gitRepo" "secret" "nfs" "iscsi"
    "glusterfs" "persistentVolumeClaim" "rbd" "flexVolume" "cinder" "cephfs" "flocker" "downwardAPI" "fc"
    "azureFile" "configMap" "vsphereVolume" "quobyte" "azureDisk" "photonPersistentDisk" "projected"
    "portworxVolume" "scaleIO" "storageos" "csi" "ephemeral" "image")
  "The members of v1.VolumeSource, of which SetDefaults_Volume finds none in a sourceless volume.")

(defun default-volume-object (volume)
  "Default one Pod volume object."
  (unless (some (lambda (field) (json-child volume field)) +volume-source-fields+)
    (setf (gethash "emptyDir" volume) (core-object)))
  (default-json-pointer-field (json-child volume "hostPath") "type" "")
  (dolist (field '("secret" "configMap" "downwardAPI" "projected"))
    (default-json-pointer-field (json-child volume field) "defaultMode" +default-volume-mode+))
  (default-downward-items (json-child volume "downwardAPI"))
  (dolist (source (json-items (json-child volume "projected") "sources"))
    (default-downward-items (json-child source "downwardAPI"))
    (default-json-pointer-field (json-child source "serviceAccountToken") "expirationSeconds" 3600))
  (let ((image (json-child volume "image")))
    (when (and image (stringp (gethash "reference" image)))
      (default-json-field image "pullPolicy" (default-image-pull-policy (gethash "reference" image)))))
  (let ((claim (json-child (json-child (json-child volume "ephemeral") "volumeClaimTemplate") "spec")))
    (default-json-pointer-field claim "volumeMode" "Filesystem"))
  volume)

(defun default-pod-template-spec-object (spec)
  "Apply SetDefaults_PodSpec and the nested defaults that a Pod template's spec receives."
  (when (hash-table-p spec)
    (default-json-field spec "dnsPolicy" "ClusterFirst")
    (default-json-field spec "restartPolicy" "Always")
    (default-json-pointer-field spec "securityContext" (core-object))
    (default-json-pointer-field spec "terminationGracePeriodSeconds" 30)
    (default-json-field spec "schedulerName" +default-scheduler-name+)
    (dolist (field '("initContainers" "containers" "ephemeralContainers"))
      (mapc #'default-container-object (json-items spec field)))
    (mapc #'default-volume-object (json-items spec "volumes")))
  spec)

(defun defaulted-pod-template (template)
  "Return a copy of the Pod TEMPLATE (metadata and spec) with its spec defaulted.
Controllers compare templates through this, so that one stored by an older gr8s, which
lacks the defaults, still matches the same template stored since with them."
  (let ((copy (copy-core-object template)))
    (default-pod-template-spec-object (json-child copy "spec"))
    copy))

(defun default-pod-spec-object (spec)
  "Apply a Pod's spec defaults: a template's, and those SetDefaults_Pod adds for a Pod alone."
  (when (hash-table-p spec)
    (default-pod-template-spec-object spec)
    (default-json-pointer-field spec "enableServiceLinks" t))
  spec)

(defun pod-spec-defaulted-p (spec)
  "Return whether SPEC already carries every default, as a Pod created since they were added does."
  (let ((defaulted (copy-core-object spec)))
    (default-pod-spec-object defaulted)
    (core-json-equal-p spec defaulted)))

(defparameter +default-toleration-taints+ '("node.kubernetes.io/not-ready" "node.kubernetes.io/unreachable")
  "The NoExecute taints DefaultTolerationSeconds admission makes every Pod tolerate for a while.")

(defparameter +default-toleration-seconds+ 300
  "How long those tolerations last: upstream's --default-not-ready-toleration-seconds and
--default-unreachable-toleration-seconds default.")

(defun default-taint-tolerated-p (tolerations key)
  "Report whether TOLERATIONS already cover the NoExecute taint KEY, as the plugin decides:
a toleration with that key or none, and with effect NoExecute or none."
  (flet ((text (toleration field)
           (let ((value (gethash field toleration))) (if (stringp value) value ""))))
    (some (lambda (toleration)
            (and (member (text toleration "key") (list key "") :test #'equal)
                 (member (text toleration "effect") '("NoExecute" "") :test #'equal)))
          tolerations)))

(defun pod-default-tolerations-p (spec)
  "Report whether a Pod SPEC tolerates both taints DefaultTolerationSeconds covers."
  (let ((tolerations (json-items spec "tolerations")))
    (every (lambda (key) (default-taint-tolerated-p tolerations key)) +default-toleration-taints+)))

(defun default-pod-tolerations (spec)
  "Admit a Pod SPEC as upstream's DefaultTolerationSeconds plugin does: append a NoExecute
toleration with tolerationSeconds 300 for each of the not-ready and unreachable taints it does
not already tolerate. Upstream runs it on Pod creates and updates, before the webhooks."
  (when (hash-table-p spec)
    (let* ((tolerations (json-items spec "tolerations"))
           (added (loop for key in +default-toleration-taints+
                        unless (default-taint-tolerated-p tolerations key)
                          collect (core-object "key" key "operator" "Exists" "effect" "NoExecute"
                                               "tolerationSeconds" +default-toleration-seconds+))))
      (when added
        (setf (gethash "tolerations" spec) (concatenate 'vector (spec-tolerations spec) added)))))
  spec)

(defun default-pod-admission (spec old-spec)
  "Apply the default tolerations to a Pod SPEC being created, or written over OLD-SPEC when that
already has them. A Pod stored without them keeps its spec, which its runtime fingerprint covers."
  (when (or (null old-spec) (pod-default-tolerations-p old-spec))
    (default-pod-tolerations spec))
  spec)

(defun default-created-pod (pod)
  "Default a Pod being created, and return it."
  (default-pod-spec-object (gethash "spec" (pod-to-object pod)))
  (default-pod-admission (gethash "spec" (pod-to-object pod)) nil)
  pod)

(defun default-updated-pod (existing replacement)
  "Default REPLACEMENT when EXISTING was stored with the defaults, so that a client that omits a
default does not change the Pod. A Pod stored without them keeps the representation it has."
  (when (pod-spec-defaulted-p (gethash "spec" (pod-to-object existing)))
    (default-pod-spec-object (gethash "spec" (pod-to-object replacement))))
  (default-pod-admission (gethash "spec" (pod-to-object replacement)) (gethash "spec" (pod-to-object existing)))
  replacement)

;;;; Defaults of other kinds, from the same upstream v1.37.2 files: core/v1's
;;;; SetObjectDefaults_PersistentVolume, apps/v1's SetObjectDefaults_StatefulSet and
;;;; networking/v1's SetObjectDefaults_NetworkPolicy.

(defun default-persistent-volume-source (kind source)
  "Default the PersistentVolume SOURCE of KIND as SetObjectDefaults_PersistentVolume does:
SetDefaults_HostPathVolumeSource, and the rbd, iscsi, azureDisk and scaleIO +default markers."
  (when (hash-table-p source)
    (cond ((equal kind "hostPath") (default-json-pointer-field source "type" ""))
          ((equal kind "rbd")
           (default-json-field source "pool" "rbd")
           (default-json-field source "user" "admin")
           (default-json-field source "keyring" "/etc/ceph/keyring"))
          ((equal kind "iscsi") (default-json-field source "iscsiInterface" "default"))
          ((equal kind "azureDisk")
           (default-json-pointer-field source "cachingMode" "ReadWrite")
           (default-json-pointer-field source "fsType" "ext4")
           (default-json-pointer-field source "readOnly" nil)
           (default-json-pointer-field source "kind" "Shared"))
          ((equal kind "scaleIO")
           (default-json-field source "storageMode" "ThinProvisioned")
           (default-json-field source "fsType" "xfs"))))
  source)

(defun default-claim-template (template)
  "Default a StatefulSet's claim TEMPLATE as SetObjectDefaults_StatefulSet does, through
SetDefaults_PersistentVolumeClaim (status.phase Pending) and SetDefaults_PersistentVolumeClaimSpec
(spec.volumeMode Filesystem)."
  (when (hash-table-p template)
    (let ((spec (json-child template "spec"))
          (status (or (json-child template "status") (setf (gethash "status" template) (core-object)))))
      (default-json-pointer-field spec "volumeMode" "Filesystem")
      (default-json-field status "phase" "Pending")))
  template)

(defun default-network-policy-spec (spec)
  "Default a NetworkPolicy SPEC as SetObjectDefaults_NetworkPolicy does: policyTypes, when it
names none, is Ingress, with Egress too when there are egress rules (SetDefaults_NetworkPolicy),
and every rule's port without a protocol has TCP (SetDefaults_NetworkPolicyPort)."
  (when (hash-table-p spec)
    (let ((types (gethash "policyTypes" spec)))
      (when (or (member types '(nil null)) (and (vectorp types) (not (stringp types)) (zerop (length types))))
        (setf (gethash "policyTypes" spec)
              (if (json-items spec "egress") (vector "Ingress" "Egress") (vector "Ingress")))))
    (dolist (direction '("ingress" "egress"))
      (dolist (rule (json-items spec direction))
        (dolist (port (json-items rule "ports"))
          (default-json-pointer-field port "protocol" "TCP")))))
  spec)
