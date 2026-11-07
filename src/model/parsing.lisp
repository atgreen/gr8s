;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Parse the supported Kubernetes Pod JSON into GR8S.MODEL domain values.

(in-package #:gr8s.model)

(defstruct (pod-parser-policy
             (:constructor make-pod-parser-policy
                 (&key (environment-reference-validator (constantly nil))
                       (container-validator (constantly nil))
                       (metadata-validator (constantly nil))
                       (spec-validator (constantly nil))
                       (resource-validator (constantly nil)))))
  "Inject validation owned by higher layers without making MODEL depend on them."
  environment-reference-validator
  container-validator
  metadata-validator
  spec-validator
  resource-validator)

(defun invalid-pod (control &rest arguments)
  "Signal an HTTP 422 Kubernetes error formatted by CONTROL and ARGUMENTS."
  (error 'kubernetes-error
         :status-code 422
         :reason "Invalid"
         :message (apply #'format nil control arguments)))

(defun object-value (object key &optional (context "object"))
  "Return KEY from OBJECT, or reject the missing field in CONTEXT."
  (multiple-value-bind (value present-p) (gethash key object)
    (if present-p
        value
        (invalid-pod "~A requires field ~S" context key))))

(defun require-object (value context)
  "Return VALUE when it is a JSON object, otherwise reject it in CONTEXT."
  (unless (hash-table-p value)
    (invalid-pod "~A must be an object" context))
  value)

(defun reject-unsupported-fields (object allowed context)
  "Validate that OBJECT contains only ALLOWED string keys in CONTEXT."
  (require-object object context)
  (maphash (lambda (key value)
             (declare (ignore value))
             (unless (member key allowed :test #'string=)
               (invalid-pod "~A field ~S is not supported" context key)))
           object)
  object)

(defun require-empty-object-if-present (object key context)
  "Require KEY, when present in OBJECT, to contain an empty JSON object."
  (multiple-value-bind (value present-p) (gethash key object)
    (when present-p
      (require-object value context)
      (unless (zerop (hash-table-count value))
        (invalid-pod "~A must be empty" context)))))

(defun require-nonempty-string (value context)
  "Return VALUE when it is a non-empty string, or reject it in CONTEXT."
  (unless (and (stringp value) (plusp (length value)))
    (invalid-pod "~A must be a non-empty string" context))
  value)

(defun dns-label-character-p (character)
  "Return true when CHARACTER is valid inside a lower-case DNS label."
  (or (and (char>= character #\a) (char<= character #\z))
      (digit-char-p character)
      (char= character #\-)))

(defun dns-label-p (value &optional (maximum-length 63))
  "Return true when VALUE is a valid DNS label within MAXIMUM-LENGTH."
  (and (stringp value)
       (plusp (length value))
       (<= (length value) maximum-length)
       (every #'dns-label-character-p value)
       (not (char= #\- (char value 0)))
       (not (char= #\- (char value (1- (length value)))))))

(defun dns-subdomain-p (value)
  "Return true when VALUE is a valid Kubernetes-style DNS subdomain."
  ;; UIOP splits "" into no labels at all, which EVERY would accept.
  (and (stringp value)
       (<= 1 (length value) 253)
       (every (lambda (label) (dns-label-p label 253))
              (uiop:split-string value :separator '(#\.)))))

(defun require-dns-label (value context)
  "Return VALUE when it is a DNS label, or reject it in CONTEXT."
  (unless (dns-label-p value)
    (invalid-pod "~A must be a lowercase DNS label" context))
  value)

(defun require-dns-subdomain (value context)
  "Return VALUE when it is a DNS subdomain, or reject it in CONTEXT."
  (unless (dns-subdomain-p value)
    (invalid-pod "~A must be a lowercase DNS subdomain" context))
  value)

(defun optional-vector (object key context)
  "Return array KEY from OBJECT, defaulting to an empty vector."
  (let ((value (gethash key object #())))
    (unless (and (vectorp value) (not (stringp value)))
      (invalid-pod "~A.~A must be an array" context key))
    value))

(defun require-string-vector (value context)
  "Return VALUE when it is an array of strings, or reject it in CONTEXT."
  (unless (and (vectorp value)
               (every #'stringp value))
    (invalid-pod "~A must be an array of strings" context))
  value)

(defun parse-environment (container policy)
  "Validate environment entries and return their literal name/value pairs."
  (loop for variable across (optional-vector container "env" "container")
        do (reject-unsupported-fields variable '("name" "value" "valueFrom") "env")
           (require-nonempty-string (gethash "name" variable) "env.name")
           (when (gethash "valueFrom" variable)
             (funcall (pod-parser-policy-environment-reference-validator policy)
                      variable))
        unless (gethash "valueFrom" variable)
          collect (cons (gethash "name" variable)
                        (let ((value (gethash "value" variable "")))
                          (unless (stringp value) (invalid-pod "env.value must be a string"))
                          value))))

(defun parse-ports (container)
  "Parse and validate the container ports and host ports in CONTAINER."
  (loop for port across (optional-vector container "ports" "container")
        collect
        (progn
          (reject-unsupported-fields
           port '("containerPort" "hostPort" "hostIP" "name" "protocol") "port")
          (let ((number (object-value port "containerPort" "port"))
                (protocol (gethash "protocol" port "TCP"))
                (host-port (gethash "hostPort" port 0))
                (host-ip (gethash "hostIP" port "")))
            (unless (and (integerp number) (<= 1 number 65535))
              (invalid-pod "containerPort must be between 1 and 65535"))
            (unless (and (integerp host-port) (<= 0 host-port 65535))
              (invalid-pod "hostPort must be between 1 and 65535"))
            (unless (and (stringp host-ip)
                         (or (zerop (length host-ip))
                             (handler-case
                                 (progn (0conf:parse-ipv4 host-ip) t)
                               (error () nil))))
              (invalid-pod "hostIP must be an IPv4 address"))
            (unless (member protocol '("TCP" "UDP" "SCTP") :test #'equal)
              (invalid-pod "container port protocol must be TCP, UDP or SCTP"))
            number))))

(defun default-container-termination-message (object)
  "Apply the Kubernetes termination message defaults and validate requested paths and policies."
  (loop for (field default) in '(("terminationMessagePath" "/dev/termination-log")
                                 ("terminationMessagePolicy" "File"))
        do (when (member (gethash field object) '(nil null "") :test #'equal)
             (setf (gethash field object) default)))
  (let ((path (gethash "terminationMessagePath" object)))
    (unless (and (stringp path) (plusp (length path)) (char= #\/ (char path 0))
                 (<= (length path) 4096) (not (find #\Null path))
                 (not (member ".." (uiop:split-string path :separator '(#\/)) :test #'equal)))
      (invalid-pod "container.terminationMessagePath must be an absolute path without traversal")))
  (unless (member (gethash "terminationMessagePolicy" object) '("File" "FallbackToLogsOnError") :test #'equal)
    (invalid-pod "container.terminationMessagePolicy must be File or FallbackToLogsOnError")))

(defun parse-container (object policy)
  "Validate a container JSON OBJECT and return a CONTAINER-SPEC."
  (reject-unsupported-fields
   object '("name" "image" "command" "args" "env" "envFrom" "ports" "resources"
            "imagePullPolicy" "volumeMounts" "securityContext" "workingDir"
            "startupProbe" "readinessProbe" "livenessProbe"
            "terminationMessagePath" "terminationMessagePolicy" "stdin" "stdinOnce" "tty" "lifecycle" "resizePolicy"
            "restartPolicy" "restartPolicyRules")
   "container")
  (default-container-termination-message object)
  (funcall (pod-parser-policy-container-validator policy) object)
  (make-container-spec
   :name (require-dns-label
          (object-value object "name" "container") "container.name")
   :image (require-nonempty-string
           (object-value object "image" "container") "container.image")
   :command (require-string-vector
             (optional-vector object "command" "container")
             "container.command")
   :args (require-string-vector
          (optional-vector object "args" "container")
          "container.args")
   :env (parse-environment object policy)
   :ports (parse-ports object)))

(defun parse-init-container (object policy)
  "Validate an init container and parse it with POLICY."
  (require-object object "init container")
  (when (eq (gethash "restartPolicy" object) 'null)
    (remhash "restartPolicy" object))
  (unless (equal "Always" (gethash "restartPolicy" object))
    (dolist (key '("startupProbe" "readinessProbe" "livenessProbe" "lifecycle"))
      (when (nth-value 1 (gethash key object))
        (invalid-pod "ordinary init containers cannot define ~A" key))))
  (parse-container object policy))

(defparameter +ephemeral-container-forbidden-fields+
  '("ports" "startupProbe" "readinessProbe" "livenessProbe" "lifecycle"
    "resizePolicy" "restartPolicy"))

(defun parse-ephemeral-container (object policy)
  "Validate an ephemeral container declaration and parse it with POLICY."
  (require-object object "ephemeral container")
  (dolist (field +ephemeral-container-forbidden-fields+)
    (when (nth-value 1 (gethash field object))
      (invalid-pod "ephemeral containers cannot define ~A" field)))
  (when (eq (gethash "targetContainerName" object) 'null)
    (remhash "targetContainerName" object))
  (let ((target (gethash "targetContainerName" object)))
    (remhash "targetContainerName" object)
    (unwind-protect (parse-container object policy)
      (when target (setf (gethash "targetContainerName" object) target)))))

(defun parse-pod-ephemeral-containers (spec policy)
  "Parse SPEC's ephemeral containers, requiring real target containers."
  (when (eq (gethash "ephemeralContainers" spec) 'null)
    (remhash "ephemeralContainers" spec))
  (let ((declared (optional-vector spec "ephemeralContainers" "spec"))
        (targets
          (map 'list (lambda (container) (gethash "name" container))
               (concatenate 'vector
                            (optional-vector spec "initContainers" "spec")
                            (optional-vector spec "containers" "spec")))))
    (loop for object across declared
          do (let ((target (and (hash-table-p object)
                                (gethash "targetContainerName" object))))
               (when (and target (not (member target targets :test #'equal)))
                 (invalid-pod
                  "ephemeral container targetContainerName ~S names no container of this Pod"
                  target))))
    (map 'vector (lambda (object) (parse-ephemeral-container object policy))
         declared)))

(defun validate-owner-references (metadata)
  "Validate owner identities. Foreground deletion honors blockOwnerDeletion on any dependent."
  (let ((owners (gethash "ownerReferences" metadata)) (controllers 0))
    (when (and owners (not (eq owners 'null)))
      (unless (and (vectorp owners) (not (stringp owners)))
        (invalid-pod "metadata.ownerReferences must be an array"))
      (loop for owner across owners
            do (reject-unsupported-fields owner '("apiVersion" "kind" "name" "uid" "controller" "blockOwnerDeletion") "ownerReference")
               (dolist (key '("apiVersion" "kind" "name" "uid"))
                 (require-nonempty-string (gethash key owner) "ownerReference identity"))
               (dolist (key '("controller" "blockOwnerDeletion"))
                 (multiple-value-bind (value present) (gethash key owner)
                   (when (and present (not (member value '(t nil)))) (invalid-pod "ownerReference flag must be boolean"))))
               (when (eq t (gethash "controller" owner)) (incf controllers)))
      (when (> controllers 1) (invalid-pod "an object can have only one controller owner")))))

(defun pod-generate-name-prefix (metadata)
  "Validate an optional Pod name prefix, allowing a trailing dash as Kubernetes does."
  (let ((prefix (gethash "generateName" metadata "")))
    (when (eq prefix 'null) (setf prefix ""))
    (unless (stringp prefix) (invalid-pod "metadata.generateName must be a string"))
    (when (plusp (length prefix))
      (require-dns-subdomain
       ;; Match apimachinery's maskTrailingDash, including its two-byte cut.
       (if (and (> (length prefix) 1) (char= #\- (char prefix (1- (length prefix)))))
           (concatenate 'string (subseq prefix 0 (- (length prefix) 2)) "a")
           prefix)
       "metadata.generateName"))
    prefix))

(defun parse-pod-with-policy (input policy &key allow-generate-name)
  "Parse JSON text or an object into the supported, validated POD model."
  (let* ((object (require-object
                  (if (hash-table-p input)
                      input
                      (com.inuoe.jzon:parse input))
                  "Pod"))
         (metadata (object-value object "metadata" "Pod"))
         (spec (object-value object "spec" "Pod")))
    (reject-unsupported-fields
     object '("apiVersion" "kind" "metadata" "spec" "status") "Pod")
    (require-empty-object-if-present object "status" "Pod.status")
    (unless (string= "v1" (require-nonempty-string
                            (object-value object "apiVersion" "Pod")
                            "apiVersion"))
      (invalid-pod "apiVersion must be v1"))
    (unless (string= "Pod" (require-nonempty-string
                             (object-value object "kind" "Pod")
                             "kind"))
      (invalid-pod "kind must be Pod"))
    (reject-unsupported-fields
     metadata '("name" "generateName" "namespace" "labels" "annotations" "uid"
                "resourceVersion" "creationTimestamp" "deletionTimestamp"
                "deletionGracePeriodSeconds" "generation" "ownerReferences" "finalizers" "managedFields")
     "metadata")
    (validate-owner-references metadata)
    (funcall (pod-parser-policy-metadata-validator policy) metadata)
    (reject-unsupported-fields
     spec '("containers" "initContainers" "restartPolicy" "dnsPolicy" "nodeName" "volumes"
            "securityContext" "serviceAccountName" "automountServiceAccountToken" "imagePullSecrets"
            "tolerations" "nodeSelector" "enableServiceLinks" "terminationGracePeriodSeconds" "hostname" "subdomain" "dnsConfig"
            "runtimeClassName" "priorityClassName" "priority" "preemptionPolicy" "overhead" "activeDeadlineSeconds"
            "affinity" "os" "hostNetwork" "hostPID" "hostIPC" "hostUsers" "shareProcessNamespace" "hostAliases" "ephemeralContainers"
            "readinessGates" "schedulerName" "hostnameOverride" "setHostnameAsFQDN" "serviceAccount"
            "topologySpreadConstraints" "schedulingGates" "resources" "schedulingGroup") "spec")
    ;; GenericWorkload is beta and off by default in v1.37, so the API server drops the field.
    (remhash "schedulingGroup" spec)
    (dolist (field '("hostname" "subdomain"))
      (when (eq (gethash field spec) 'null) (remhash field spec))
      (let ((value (gethash field spec "")))
        (unless (and (stringp value) (or (zerop (length value)) (dns-label-p value)))
          (invalid-pod "spec.~A must be a DNS label or empty" field))))
    (let ((grace (gethash "terminationGracePeriodSeconds" spec 30)))
      (when (eq grace 'null) (setf grace 30))
      ;; As the API server does, a negative grace period becomes the shortest one.
      (when (and (integerp grace) (minusp grace) (>= grace (- #x8000000000000000)))
        (setf grace 1))
      (unless (and (integerp grace) (<= 0 grace #x7fffffffffffffff))
        (invalid-pod "spec.terminationGracePeriodSeconds must be an int64"))
      (setf (gethash "terminationGracePeriodSeconds" spec) grace))
    (funcall (pod-parser-policy-spec-validator policy) spec)
    (let* ((prefix (pod-generate-name-prefix metadata))
           (specified (gethash "name" metadata))
           (name (if (and allow-generate-name (plusp (length prefix))
                          (or (null specified) (eq specified 'null) (equal specified "")))
                     nil
                     (require-dns-subdomain specified "metadata.name")))
           (namespace (gethash "namespace" metadata "default"))
           (containers (object-value spec "containers" "spec"))
           (restart-policy (gethash "restartPolicy" spec "Always"))
           (node-name (gethash "nodeName" spec)))
      (require-dns-label namespace "metadata.namespace")
      (unless (and (vectorp containers) (plusp (length containers)))
        (invalid-pod "spec.containers must be a non-empty array"))
      (unless (and (stringp restart-policy)
                   (member restart-policy '("Always" "OnFailure" "Never")
                           :test #'string=))
        (invalid-pod "restartPolicy must be Always, OnFailure, or Never"))
      (when node-name
        (require-dns-subdomain node-name "spec.nodeName"))
      (let* ((parsed-containers
               (map 'vector (lambda (object) (parse-container object policy)) containers))
             (init-containers
               (map 'vector (lambda (object) (parse-init-container object policy))
                    (optional-vector spec "initContainers" "spec")))
             (ephemeral-containers (parse-pod-ephemeral-containers spec policy))
             (all-containers (concatenate 'vector init-containers parsed-containers ephemeral-containers)))
        ;; Pod-level resources are checked against the containers' normalized ones.
        (funcall (pod-parser-policy-resource-validator policy) spec)
        (unless (= (length all-containers)
                   (length (remove-duplicates
                            (map 'list #'container-spec-name all-containers)
                            :test #'string=)))
          (invalid-pod "container names must be unique"))
        (make-pod
         :name name
         :namespace namespace
         :containers parsed-containers
         :init-containers init-containers
         :ephemeral-containers ephemeral-containers
         :restart-policy restart-policy
         :uid (gethash "uid" metadata)
         :resource-version (gethash "resourceVersion" metadata)
         :node-name node-name
         :object object)))))

(defun pod-to-object (pod)
  "Return POD's authoritative Kubernetes JSON object."
  (pod-object pod))
