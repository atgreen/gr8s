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

(defun default-created-pod (pod)
  "Default a Pod being created, and return it."
  (default-pod-spec-object (gethash "spec" (pod-to-object pod)))
  pod)

(defun default-updated-pod (existing replacement)
  "Default REPLACEMENT when EXISTING was stored with the defaults, so that a client that omits a
default does not change the Pod. A Pod stored without them keeps the representation it has."
  (when (pod-spec-defaulted-p (gethash "spec" (pod-to-object existing)))
    (default-pod-spec-object (gethash "spec" (pod-to-object replacement))))
  replacement)
