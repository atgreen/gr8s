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
                     (kubernetes-error-message condition)))))

(defstruct container-spec
  name
  image
  command
  args
  env
  ports)

(defstruct pod
  name
  namespace
  containers
  (restart-policy "Always")
  uid
  resource-version
  node-name
  object)

(defstruct node-record
  id
  name
  pod-cidr
  (ready-p nil)
  last-heartbeat)

(defun invalid-pod (control &rest arguments)
  (error 'kubernetes-error
         :status-code 422
         :reason "Invalid"
         :message (apply #'format nil control arguments)))

(defun object-value (object key &optional (context "object"))
  (multiple-value-bind (value present-p) (gethash key object)
    (if present-p
        value
        (invalid-pod "~A requires field ~S" context key))))

(defun require-object (value context)
  (unless (hash-table-p value)
    (invalid-pod "~A must be an object" context))
  value)

(defun reject-unsupported-fields (object allowed context)
  (require-object object context)
  (maphash (lambda (key value)
             (declare (ignore value))
             (unless (member key allowed :test #'string=)
               (invalid-pod "~A field ~S is not supported" context key)))
           object)
  object)

(defun require-empty-object-if-present (object key context)
  (multiple-value-bind (value present-p) (gethash key object)
    (when present-p
      (require-object value context)
      (unless (zerop (hash-table-count value))
        (invalid-pod "~A must be empty" context)))))

(defun require-nonempty-string (value context)
  (unless (and (stringp value) (plusp (length value)))
    (invalid-pod "~A must be a non-empty string" context))
  value)

(defun dns-label-character-p (character)
  (or (and (char>= character #\a) (char<= character #\z))
      (digit-char-p character)
      (char= character #\-)))

(defun dns-label-p (value &optional (maximum-length 63))
  (and (stringp value)
       (plusp (length value))
       (<= (length value) maximum-length)
       (every #'dns-label-character-p value)
       (not (char= #\- (char value 0)))
       (not (char= #\- (char value (1- (length value)))))))

(defun dns-subdomain-p (value)
  (and (stringp value)
       (<= (length value) 253)
       (every #'dns-label-p
              (uiop:split-string value :separator '(#\.)))))

(defun require-dns-label (value context)
  (unless (dns-label-p value)
    (invalid-pod "~A must be a lowercase DNS label" context))
  value)

(defun require-dns-subdomain (value context)
  (unless (dns-subdomain-p value)
    (invalid-pod "~A must be a lowercase DNS subdomain" context))
  value)

(defun optional-vector (object key context)
  (let ((value (gethash key object #())))
    (unless (vectorp value)
      (invalid-pod "~A.~A must be an array" context key))
    value))

(defun require-string-vector (value context)
  (unless (and (vectorp value)
               (every #'stringp value))
    (invalid-pod "~A must be an array of strings" context))
  value)

(defun parse-environment (container)
  (loop for variable across (optional-vector container "env" "container")
        do (reject-unsupported-fields variable '("name" "value") "env")
        collect (cons (require-nonempty-string
                       (object-value variable "name" "env")
                       "env.name")
                      (let ((value (object-value variable "value" "env")))
                        (unless (stringp value)
                          (invalid-pod "env.value must be a string"))
                        value))))

(defun parse-ports (container)
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

(defun parse-container (object)
  (reject-unsupported-fields
   object '("name" "image" "command" "args" "env" "ports" "resources")
   "container")
  (require-empty-object-if-present object "resources" "container.resources")
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

(defun parse-pod (input)
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
     metadata '("name" "namespace" "labels" "annotations" "uid"
                "resourceVersion" "creationTimestamp" "deletionTimestamp")
     "metadata")
    (reject-unsupported-fields
     spec '("containers" "restartPolicy" "dnsPolicy" "nodeName") "spec")
    (multiple-value-bind (dns-policy present-p) (gethash "dnsPolicy" spec)
      (when (and present-p
                 (not (and (stringp dns-policy)
                           (string= dns-policy "ClusterFirst"))))
        (invalid-pod "only dnsPolicy ClusterFirst is supported")))
    (let* ((name (require-dns-subdomain
                  (object-value metadata "name" "metadata") "metadata.name"))
           (namespace (gethash "namespace" metadata "default"))
           (containers (object-value spec "containers" "spec"))
           (restart-policy (gethash "restartPolicy" spec "Always"))
           (node-name (gethash "nodeName" spec)))
      (unless (string= "default"
                       (require-nonempty-string namespace "metadata.namespace"))
        (invalid-pod "only the default namespace is supported"))
      (unless (and (vectorp containers) (plusp (length containers)))
        (invalid-pod "spec.containers must be a non-empty array"))
      (unless (and (stringp restart-policy)
                   (member restart-policy '("Always" "OnFailure" "Never")
                           :test #'string=))
        (invalid-pod "restartPolicy must be Always, OnFailure, or Never"))
      (when node-name
        (require-dns-subdomain node-name "spec.nodeName"))
      (let ((parsed-containers (map 'vector #'parse-container containers)))
        (unless (= (length parsed-containers)
                   (length (remove-duplicates
                            (map 'list #'container-spec-name parsed-containers)
                            :test #'string=)))
          (invalid-pod "container names must be unique"))
        (make-pod
         :name name
         :namespace namespace
         :containers parsed-containers
         :restart-policy restart-policy
         :uid (gethash "uid" metadata)
         :resource-version (gethash "resourceVersion" metadata)
         :node-name node-name
         :object object)))))

(defun pod-to-object (pod)
  (pod-object pod))
