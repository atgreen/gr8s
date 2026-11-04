;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Define gr8s's deliberately small Kubernetes domain model and the strict
;;;; JSON-to-model boundary used by the HTTP API.  Parsing accepts the fields
;;;; emitted by kubectl for a namespaced Pod, rejects unsupported
;;;; semantics early, and returns simple structures shared by storage,
;;;; scheduling, reconciliation, and runtime adapters.

(in-package #:gr8s)

(define-condition kubernetes-error (error)
  ((status-code
    :initarg :status-code
    :reader kubernetes-error-status-code)
   (reason
    :initarg :reason
    :reader kubernetes-error-reason)
   (message
    :initarg :message
    :reader kubernetes-error-message))
  (:report (lambda (condition stream)
             (format stream "~A: ~A"
                     (kubernetes-error-reason condition)
                     (kubernetes-error-message condition))))
  (:documentation "Describe an HTTP-facing Kubernetes API failure."))

(defstruct container-spec
  "Represent the supported, runtime-relevant portion of a Pod container."
  name
  image
  command
  args
  env
  ports)

(defstruct pod
  "Represent a validated Kubernetes Pod and its authoritative JSON object."
  name
  namespace
  containers
  (init-containers #())
  (restart-policy "Always")
  uid
  resource-version
  node-name
  object
  ;; Newer client-visible revision from status alone, never acknowledged by agents.
  status-revision)

(defun pod-all-containers (pod)
  "Return init and application containers for shared credentials, mounts and named operations."
  (concatenate 'vector (pod-init-containers pod) (pod-containers pod)))

(defstruct node-record
  "Represent a registered worker node and its control-plane lease state."
  id
  name
  pod-cidr
  (underlay-address "")
  (ready-p nil)
  last-heartbeat
  lease-deadline
  ;; Quantity strings by resource name, from the agent; NIL until it first reports.
  capacity)

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
  (and (stringp value)
       (<= (length value) 253)
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

(defun parse-environment (container)
  "Validate environment entries and return their literal name/value pairs."
  (loop for variable across (optional-vector container "env" "container")
        do (reject-unsupported-fields variable '("name" "value" "valueFrom") "env")
           (require-nonempty-string (gethash "name" variable) "env.name")
           (when (gethash "valueFrom" variable)
             (validate-pod-field-reference variable))
        unless (gethash "valueFrom" variable)
          collect (cons (gethash "name" variable)
                        (let ((value (gethash "value" variable "")))
                          (unless (stringp value) (invalid-pod "env.value must be a string"))
                          value))))

(defun parse-ports (container)
  "Parse and validate the supported TCP container ports in CONTAINER."
  (loop for port across (optional-vector container "ports" "container")
        collect
        (progn
          (reject-unsupported-fields
           port '("containerPort" "name" "protocol") "port")
          (let ((number (object-value port "containerPort" "port"))
                (protocol (gethash "protocol" port "TCP")))
            (unless (and (integerp number) (<= 1 number 65535))
              (invalid-pod "containerPort must be between 1 and 65535"))
            (unless (and (stringp protocol) (string= protocol "TCP"))
              (invalid-pod "only TCP container ports are supported"))
            number))))

(defun default-container-termination-message (object)
  "Apply the Kubernetes termination message defaults, refusing any other requested behavior."
  (loop for (field default) in '(("terminationMessagePath" "/dev/termination-log")
                                 ("terminationMessagePolicy" "File"))
        do (let ((value (gethash field object)))
             (cond ((member value '(nil null "") :test #'equal) (setf (gethash field object) default))
                   ((not (equal value default))
                    (invalid-pod "container.~A other than ~S is not implemented" field default))))))

(defun parse-container (object)
  "Validate a container JSON OBJECT and return a CONTAINER-SPEC."
  (reject-unsupported-fields
   object '("name" "image" "command" "args" "env" "envFrom" "ports" "resources"
            "imagePullPolicy" "volumeMounts" "securityContext" "workingDir"
            "startupProbe" "readinessProbe" "livenessProbe"
            "terminationMessagePath" "terminationMessagePolicy")
   "container")
  (default-container-termination-message object)
  (normalize-container-resources object)
  (validate-runtime-container object)
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
   :env (parse-environment object)
   :ports (parse-ports object)))

(defun validate-owner-references (metadata)
  "Validate owner identities and the supported nonblocking ownership relationship."
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
               (when (eq t (gethash "controller" owner)) (incf controllers))
               (when (and (eq t (gethash "blockOwnerDeletion" owner))
                          (not (and (eq t (gethash "controller" owner))
                                    (equal "Job" (gethash "kind" owner))
                                    (equal "batch/v1" (gethash "apiVersion" owner)))))
                 (invalid-pod "blocking foreground owner deletion requires a supported Job controller")))
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

(defun parse-pod (input &key allow-generate-name)
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
                "deletionGracePeriodSeconds" "generation" "ownerReferences" "finalizers")
     "metadata")
    (validate-owner-references metadata)
    (validate-pod-finalizers metadata)
    (reject-unsupported-fields
     spec '("containers" "initContainers" "restartPolicy" "dnsPolicy" "nodeName" "volumes"
            "securityContext" "serviceAccountName" "automountServiceAccountToken"
            "tolerations" "nodeSelector" "enableServiceLinks" "terminationGracePeriodSeconds" "hostname" "subdomain" "dnsConfig") "spec")
    (dolist (field '("hostname" "subdomain"))
      (when (eq (gethash field spec) 'null) (remhash field spec))
      (let ((value (gethash field spec "")))
        (unless (and (stringp value) (or (zerop (length value)) (dns-label-p value)))
          (invalid-pod "spec.~A must be a DNS label or empty" field))))
    (let ((grace (gethash "terminationGracePeriodSeconds" spec 30)))
      (when (eq grace 'null) (setf grace 30))
      (unless (and (integerp grace) (<= 0 grace #x7fffffffffffffff))
        (invalid-pod "spec.terminationGracePeriodSeconds must be a nonnegative int64"))
      (setf (gethash "terminationGracePeriodSeconds" spec) grace))
    (validate-runtime-pod-spec spec)
    (validate-pod-dns-spec spec)
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
      (let* ((parsed-containers (map 'vector #'parse-container containers))
             (init-containers (map 'vector #'parse-init-container
                                   (optional-vector spec "initContainers" "spec")))
             (all-containers (concatenate 'vector init-containers parsed-containers)))
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
         :restart-policy restart-policy
         :uid (gethash "uid" metadata)
         :resource-version (gethash "resourceVersion" metadata)
         :node-name node-name
         :object object)))))

(defun pod-to-object (pod)
  "Return POD's authoritative Kubernetes JSON object."
  (pod-object pod))
