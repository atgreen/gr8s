(in-package #:gr8s)

(defun json-object (&rest pairs)
  (let ((object (make-hash-table :test #'equal)))
    (loop for (key value) on pairs by #'cddr
          do (setf (gethash key object) value))
    object))

(defun json-response (object &optional (status 200))
  (setf (hunchentoot:return-code*) status
        ;; client-go v0.27 discovery compares this media type literally. JSON
        ;; is UTF-8 already; a charset parameter breaks its legacy fallback.
        (hunchentoot:content-type*) "application/json")
  (com.inuoe.jzon:stringify (event-api-view object)))

(defun status-response (status reason message code)
  (json-response
   (json-object "apiVersion" "v1"
                "kind" "Status"
                "status" status
                "reason" reason
                "message" message
                "code" code)
   code))

(defun kubernetes-error-response (error)
  (status-response "Failure"
                   (kubernetes-error-reason error)
                   (kubernetes-error-message error)
                   (kubernetes-error-status-code error)))

(defun copy-json-object (object)
  (com.inuoe.jzon:parse (com.inuoe.jzon:stringify object)))

(defun pod-response-object (pod status)
  (let ((object (copy-json-object (pod-to-object pod))))
    (setf (gethash "status" object) status)
    object))

(defun request-pod-in-namespace (object namespace &key allow-generate-name)
  "Validate the request namespace and default omitted Pod metadata.namespace."
  (let* ((metadata (require-object (gethash "metadata" object) "metadata"))
         (specified (gethash "namespace" metadata)))
    (when (and specified (not (equal specified "")) (not (equal namespace specified)))
      (core-resource-error 400 "BadRequest" "metadata.namespace does not match request namespace"))
    (setf (gethash "namespace" metadata) namespace)
    (parse-pod object :allow-generate-name allow-generate-name)))

(defun request-object (&optional (namespace "default"))
  (request-pod-in-namespace
   (core-resource-request-object "Pod")
   namespace))

(defun request-json-object ()
  (require-object
   (com.inuoe.jzon:parse (hunchentoot:raw-post-data :force-text t))
   "patch"))

(defun merge-json-object (target patch)
  (maphash
   (lambda (key patch-value)
     (cond
       ((eq patch-value 'null)
        (remhash key target))
       ((and (hash-table-p patch-value)
             (hash-table-p (gethash key target)))
        (merge-json-object (gethash key target) patch-value))
       (t
        (setf (gethash key target) patch-value))))
   patch)
  target)

(defun version-response ()
  (json-response
   (json-object "major" "1"
                "minor" "36"
                "gitVersion" "v1.36.0-gr8s.0"
                "gitCommit" "unknown"
                "gitTreeState" "clean"
                "buildDate" "1970-01-01T00:00:00Z"
                "goVersion" "common-lisp"
                "compiler" "sbcl"
                "platform" "linux/amd64")))

(defun api-versions-response ()
  (json-response
   (json-object "apiVersion" "v1"
                "kind" "APIVersions"
                "versions" #( "v1")
                "serverAddressByClientCIDRs" #())))

(defun api-groups-response ()
  (json-response
   (json-object "apiVersion" "v1"
                "kind" "APIGroupList"
                "groups"
                (vector (json-object "name" "rbac.authorization.k8s.io"
                                     "versions" (vector (json-object "groupVersion" "rbac.authorization.k8s.io/v1" "version" "v1"))
                                     "preferredVersion" (json-object "groupVersion" "rbac.authorization.k8s.io/v1" "version" "v1"))
                        (event-api-group)))))

(defun api-resources-response ()
  (json-response
   (json-object
    "apiVersion" "v1" "groupVersion" "v1" "kind" "APIResourceList"
    "resources"
    (concatenate
     'vector
     (vector
      (json-object "name" "pods" "singularName" "pod" "namespaced" t "kind" "Pod"
                   "verbs" #("create" "delete" "get" "list" "patch" "update") "shortNames" #("po"))
      (json-object "name" "pods/log" "singularName" "" "namespaced" t "kind" "Pod" "verbs" #("get"))
      (json-object "name" "pods/exec" "singularName" "" "namespaced" t "kind" "Pod" "verbs" #("create"))
      (json-object "name" "nodes" "singularName" "node" "namespaced" nil "kind" "Node" "verbs" #("get" "list")))
     (stored-resource-discovery "v1")))))

(defvar *schema-reference-prefix* "#/definitions/")

(defun reference-schema (name)
  (json-object "$ref" (format nil "~A~A" *schema-reference-prefix* name)))

(defun string-array-schema ()
  (json-object "type" "array"
               "items" (json-object "type" "string")))

(defun openapi-definitions ()
  (let ((definitions (make-hash-table :test #'equal)))
    (setf
     (gethash "io.k8s.apimachinery.pkg.apis.meta.v1.ObjectMeta" definitions)
     (json-object
      "type" "object"
      "properties"
      (json-object "name" (json-object "type" "string")
                   "namespace" (json-object "type" "string")
                   "uid" (json-object "type" "string")
                   "resourceVersion" (json-object "type" "string")
                   "generation" (json-object "type" "integer" "format" "int64")
                   "deletionTimestamp" (json-object "type" "string" "format" "date-time")
                   "deletionGracePeriodSeconds" (json-object "type" "integer" "format" "int64")
                   "labels" (json-object "type" "object"
                                         "additionalProperties"
                                         (json-object "type" "string"))
                   "annotations" (json-object "type" "object"
                                              "additionalProperties"
                                              (json-object "type" "string"))))
     (gethash "io.k8s.api.core.v1.EnvVar" definitions)
     (json-object "type" "object"
                  "required" #( "name" "value")
                  "properties"
                  (json-object "name" (json-object "type" "string")
                               "value" (json-object "type" "string")))
     (gethash "io.k8s.api.core.v1.ContainerPort" definitions)
     (json-object "type" "object"
                  "required" #( "containerPort")
                  "properties"
                  (json-object "containerPort" (json-object "type" "integer"
                                                             "format" "int32")
                               "name" (json-object "type" "string")
                               "protocol" (json-object "type" "string")))
     (gethash "io.k8s.api.core.v1.Container" definitions)
     (json-object
      "type" "object"
      "required" #( "name" "image")
      "properties"
      (json-object
       "name" (json-object "type" "string")
       "image" (json-object "type" "string")
       "command" (string-array-schema)
       "args" (string-array-schema)
       "env" (json-object "type" "array"
                          "items" (reference-schema "io.k8s.api.core.v1.EnvVar"))
       "ports" (json-object
                "type" "array"
                "items" (reference-schema "io.k8s.api.core.v1.ContainerPort"))))
     (gethash "io.k8s.api.core.v1.PodSpec" definitions)
     (json-object
      "type" "object"
      "required" #( "containers")
      "properties"
      (json-object
       "containers" (json-object
                     "type" "array"
                     "items" (reference-schema "io.k8s.api.core.v1.Container"))
       "restartPolicy" (json-object "type" "string")
       "terminationGracePeriodSeconds" (json-object "type" "integer" "format" "int64" "minimum" 0)))
     (gethash "io.k8s.api.core.v1.Pod" definitions)
     (json-object
      "type" "object"
      "required" #( "apiVersion" "kind" "metadata" "spec")
      "x-kubernetes-group-version-kind"
      (vector (json-object "group" "" "version" "v1" "kind" "Pod"))
      "properties"
      (json-object
       "apiVersion" (json-object "type" "string")
       "kind" (json-object "type" "string")
       "metadata" (reference-schema
                   "io.k8s.apimachinery.pkg.apis.meta.v1.ObjectMeta")
       "spec" (reference-schema "io.k8s.api.core.v1.PodSpec"))))
    (add-core-resource-openapi-definitions definitions)))

(defun openapi-document ()
  (json-object "swagger" "2.0"
               "info" (json-object "title" "gr8s" "version" "v1")
               "paths" (make-hash-table :test #'equal)
               "definitions" (openapi-definitions)))

(defun openapi-response ()
  (json-response (openapi-document)))

(defun openapi-v3-discovery-response ()
  (json-response
   (json-object
    "paths"
    (json-object
     "api/v1"
     (json-object "serverRelativeURL" "/openapi/v3/api/v1?hash=gr8s-v1")
     "apis/events.k8s.io/v1"
     (json-object "serverRelativeURL" "/openapi/v3/apis/events.k8s.io/v1?hash=gr8s-events-v1")))))

(defun pod-group-version-kind ()
  (json-object "group" "" "version" "v1" "kind" "Pod"))

(defun openapi-v3-pod-paths ()
  (json-object
   "/api/v1/namespaces/{namespace}/pods"
   (json-object
    "parameters"
    (vector (json-object "name" "namespace"
                         "in" "path"
                         "required" t
                         "schema" (json-object "type" "string")))
    "post"
    (json-object
     "operationId" "createCoreV1NamespacedPod"
     "x-kubernetes-action" "post"
     "x-kubernetes-group-version-kind" (pod-group-version-kind)
     "requestBody"
     (json-object
      "required" t
      "content"
      (json-object
       "application/json"
       (json-object "schema"
                    (reference-schema "io.k8s.api.core.v1.Pod"))))
     "responses"
     (json-object
      "201"
      (json-object
       "description" "Created"
       "content"
       (json-object
        "application/json"
        (json-object "schema"
                     (reference-schema "io.k8s.api.core.v1.Pod")))))))
   "/api/v1/namespaces/{namespace}/pods/{name}"
   (json-object
    "parameters"
    (vector (json-object "name" "namespace"
                         "in" "path"
                         "required" t
                         "schema" (json-object "type" "string"))
            (json-object "name" "name"
                         "in" "path"
                         "required" t
                         "schema" (json-object "type" "string")))
    "patch"
    (json-object
     "operationId" "patchCoreV1NamespacedPod"
     "x-kubernetes-action" "patch"
     "x-kubernetes-group-version-kind" (pod-group-version-kind)
     "parameters"
     (vector (json-object "name" "fieldValidation"
                          "in" "query"
                          "schema" (json-object "type" "string")))
     "requestBody"
     (json-object
      "required" t
      "content"
      (json-object
       "application/strategic-merge-patch+json"
       (json-object "schema"
                    (reference-schema "io.k8s.api.core.v1.Pod"))
       "application/apply-patch+yaml"
       (json-object "schema"
                    (reference-schema "io.k8s.api.core.v1.Pod"))))
     "responses"
     (json-object
      "200"
      (json-object
       "description" "OK"
       "content"
       (json-object
        "application/json"
        (json-object "schema"
                     (reference-schema "io.k8s.api.core.v1.Pod")))))))))

(defun openapi-v3-response (&optional (version "v1"))
  (let ((*schema-reference-prefix* "#/components/schemas/"))
    (json-response
     (json-object
      "openapi" "3.0.0"
      "info" (json-object "title" "gr8s" "version" "v1")
      "paths" (if (equal version "events.k8s.io/v1")
                  (add-event-openapi-paths (core-object) t)
                  (add-core-resource-openapi-paths (openapi-v3-pod-paths)))
      "components" (json-object "schemas" (openapi-definitions))))))

(defun create-pod-response (store reconciler &optional (namespace "default"))
  (let* ((input (request-pod-in-namespace (core-resource-request-object "Pod") namespace :allow-generate-name t))
         (pod (create-pod store (admit-in-cluster-pod store input)))
         (status (reconcile-pod reconciler (pod-namespace pod) (pod-name pod))))
    (json-response (pod-response-object pod status) 201)))

(defun list-pods-response (store reconciler &optional (namespace "default"))
  (let ((labels (core-selector-predicate (hunchentoot:parameter "labelSelector")))
        (fields (core-selector-predicate (hunchentoot:parameter "fieldSelector") :fields t
                                         :field-paths '("metadata.name" "metadata.namespace" "spec.nodeName"
                                                        "spec.serviceAccountName" "spec.restartPolicy"
                                                        "status.phase" "status.podIP"))))
    (json-response
     (json-object "apiVersion" "v1" "kind" "PodList"
                  "metadata" (json-object "resourceVersion" "0")
                  "items" (coerce
                           (loop for pod in (list-pods store namespace)
                                 when (funcall labels (pod-to-object pod))
                                   append (let ((object (pod-response-object pod (reconcile-pod reconciler (pod-namespace pod) (pod-name pod)))))
                                            (when (funcall fields object) (list object)))) 'vector)))))

(defun get-pod-response (store reconciler name &optional (namespace "default"))
  (let ((pod (get-pod store namespace name)))
    (json-response
     (pod-response-object pod (reconcile-pod reconciler namespace name)))))

(defun apply-pod-response (store reconciler name &optional (namespace "default"))
  (let* ((patch (request-json-object))
         (existing (handler-case (get-pod store namespace name)
                     (kubernetes-error (error)
                       (if (= 404 (kubernetes-error-status-code error))
                           nil
                           (error error)))))
         (replacement
           (request-pod-in-namespace
            (if existing
                (merge-json-object
                 (copy-json-object (pod-to-object existing)) patch)
                patch)
            namespace)))
    (unless (string= name (pod-name replacement))
      (invalid-pod "request name does not match metadata.name"))
    (let ((pod (if existing
                   (update-pod store replacement
                               (pod-resource-version existing))
                   (create-pod store replacement))))
      (json-response
       (pod-response-object
        pod (reconcile-pod reconciler namespace name))
       (if existing 200 201)))))

(defun replace-pod-response (store reconciler name &optional (namespace "default"))
  (let ((replacement (request-object namespace)))
    (unless (string= name (pod-name replacement))
      (invalid-pod "request name does not match metadata.name"))
    (unless (pod-resource-version replacement)
      (invalid-pod "PUT requires metadata.resourceVersion"))
    (let ((pod (update-pod store replacement
                           (pod-resource-version replacement))))
      (json-response
       (pod-response-object
        pod (reconcile-pod reconciler namespace name))))))

(defun pod-delete-request-arguments ()
  "Decode JSON/protobuf DeleteOptions and query options without mutating desired state."
  (let* ((body (hunchentoot:raw-post-data :force-binary t))
         (options (if (and body (plusp (length body)))
                      (core-resource-request-object "DeleteOptions") (json-object)))
         (preconditions (gethash "preconditions" options))
         (preview (gethash "dryRun" options))
         (query-grace (hunchentoot:parameter "gracePeriodSeconds"))
         (arguments nil))
    (when preconditions
      (require-object preconditions "preconditions")
      (dolist (key '("uid" "resourceVersion"))
        (when (gethash key preconditions)
          (require-nonempty-string (gethash key preconditions) key))))
    (when (and preview (not (eq preview 'null)))
      (unless (and (vectorp preview) (not (stringp preview))
                   (every (lambda (value) (equal value "All")) preview))
        (core-resource-error 400 "BadRequest" "DeleteOptions.dryRun must contain only All")))
    (let ((policy (or (gethash "propagationPolicy" options)
                      (hunchentoot:parameter "propagationPolicy"))))
      (when (and policy (not (eq policy 'null)) (not (equal policy "Background")))
        (invalid-pod "Pod deletion currently supports Background propagation only")))
    (when (eq t (gethash "orphanDependents" options))
      (invalid-pod "Orphan propagation is not supported"))
    (multiple-value-bind (grace supplied) (gethash "gracePeriodSeconds" options)
      (when (eq grace 'null) (setf supplied nil))
      (when (and query-grace (not supplied))
        (setf grace (handler-case (parse-integer query-grace)
                      (error () (core-resource-error 400 "BadRequest" "Invalid gracePeriodSeconds")))
              supplied t))
      (when supplied (setf arguments (list :grace-period grace))))
    (append arguments
            (list :uid (and preconditions (gethash "uid" preconditions))
                  :resource-version (and preconditions (gethash "resourceVersion" preconditions))
                  :dry-run (or (core-resource-dry-run-p)
                               (and (vectorp preview) (not (stringp preview)) (plusp (length preview))))))))

(defun delete-pod-response (store reconciler name &optional (namespace "default"))
  "Start or shorten Pod shutdown and return promptly while its agent stops containers."
  (declare (ignore store))
  (multiple-value-bind (status pod)
      (apply #'delete-reconciled-pod reconciler namespace name (pod-delete-request-arguments))
    (if (equal "Deleted" (and status (gethash "reason" status)))
        (status-response "Success" "Deleted" (format nil "Pod ~A deleted" name) 200)
        (json-response (pod-response-object pod (or status (pod-status "Running" :reason "Terminating")))))))

(defun pod-logs-response (store reconciler name &optional (namespace "default"))
  (let* ((pod (get-pod store namespace name))
         (container (or (hunchentoot:parameter "container")
                        (container-spec-name (aref (pod-containers pod) 0)))))
    (unless (find container (pod-containers pod)
                  :key #'container-spec-name :test #'string=)
      (error 'kubernetes-error
             :status-code 400
             :reason "BadRequest"
             :message (format nil "container ~A is not valid for pod ~A"
                              container name)))
    (setf (hunchentoot:content-type*) "text/plain; charset=utf-8")
    (or (reconciler-logs reconciler (pod-uid pod) container) "")))

(defstruct exec-options
  command
  container
  stdin
  stdout
  stderr
  tty)

(defun true-parameter-p (value)
  (and value (string-equal value "true")))

(defun exec-options-from-parameters (parameters)
  (make-exec-options
   :command (loop for (name . value) in parameters
                  when (string= name "command") collect value)
   :container (cdr (assoc "container" parameters :test #'string=))
   :stdin (true-parameter-p
           (cdr (assoc "stdin" parameters :test #'string=)))
   :stdout (true-parameter-p
            (cdr (assoc "stdout" parameters :test #'string=)))
   :stderr (true-parameter-p
            (cdr (assoc "stderr" parameters :test #'string=)))
   :tty (true-parameter-p
         (cdr (assoc "tty" parameters :test #'string=)))))

(defparameter *runtime-upgrade-request-headers*
  '(:connection :upgrade :sec-websocket-key :sec-websocket-version
    :sec-websocket-protocol :x-stream-protocol-version :origin :user-agent))

(defun header-name (keyword)
  (string-capitalize (symbol-name keyword)))

(defun runtime-upgrade-request (target host port headers)
  (with-output-to-string (output)
    (format output "POST ~A HTTP/1.1~C~CHost: ~A:~D~C~C"
            target #\Return #\Linefeed host port #\Return #\Linefeed)
    (dolist (header headers)
      (when (member (car header) *runtime-upgrade-request-headers*)
        (format output "~A: ~A~C~C"
                (header-name (car header)) (cdr header)
                #\Return #\Linefeed)))
    (format output "~C~C" #\Return #\Linefeed)))

(defun parse-runtime-stream-url (url)
  (let ((prefix "http://"))
    (unless (and (>= (length url) (length prefix))
                 (string-equal prefix url :end2 (length prefix)))
      (error 'runtime-error
             :message "containerd returned a non-HTTP streaming URL"))
    (let* ((authority-start (length prefix))
           (target-start (or (position #\/ url :start authority-start)
                             (length url)))
           (authority (subseq url authority-start target-start))
           (colon (position #\: authority :from-end t))
           (host (and colon (subseq authority 0 colon)))
           (port-text (and colon (subseq authority (1+ colon))))
           (target (if (< target-start (length url))
                       (subseq url target-start)
                       "/")))
      (unless (and host
                   (member host '("127.0.0.1" "localhost" "[::1]")
                           :test #'string-equal)
                   (plusp (length port-text)))
        (error 'runtime-error
               :message "containerd returned a non-loopback streaming URL"))
      (let ((port (parse-integer port-text :junk-allowed t)))
        (unless (and port (<= 1 port 65535))
          (error 'runtime-error
                 :message "containerd returned an invalid streaming port"))
        (values host port target)))))

(defparameter *runtime-upgrade-response-headers*
  '(:connection :upgrade :sec-websocket-accept :sec-websocket-protocol
    :x-stream-protocol-version))

(defun ascii-octets (string)
  (let ((octets (make-array (length string)
                            :element-type '(unsigned-byte 8))))
    (loop for character across string
          for index from 0
          do (setf (aref octets index) (char-code character)))
    octets))

(defun octets-as-ascii (octets)
  (map 'string #'code-char octets))

(defun read-http-response-head (stream)
  (let ((head (make-array 512 :element-type '(unsigned-byte 8)
                          :adjustable t :fill-pointer 0))
        (state 0))
    (loop
      (let ((octet (read-byte stream nil nil)))
        (unless octet
          (error 'runtime-error
                 :message "containerd closed the exec stream before replying"))
        (vector-push-extend octet head)
        (setf state
              (case state
                (0 (if (= octet 13) 1 0))
                (1 (cond ((= octet 10) 2) ((= octet 13) 1) (t 0)))
                (2 (if (= octet 13) 3 0))
                (3 (if (= octet 10) 4 0))))
        (when (= state 4)
          (return head))
        (when (> (length head) 65536)
          (error 'runtime-error
                 :message "containerd returned oversized exec headers"))))))

(defun trim-http-line (line)
  (string-right-trim '(#\Return #\Linefeed) line))

(defun parse-http-response-head (octets)
  (with-input-from-string (input (octets-as-ascii octets))
    (let* ((status-line (trim-http-line (or (read-line input nil) "")))
           (first-space (position #\Space status-line))
           (second-space (and first-space
                              (position #\Space status-line
                                        :start (1+ first-space))))
           (status (and first-space
                        (parse-integer status-line
                                       :start (1+ first-space)
                                       :end second-space
                                       :junk-allowed t)))
           (headers nil))
      (unless status
        (error 'runtime-error
               :message "containerd returned an invalid exec response"))
      (loop for raw = (read-line input nil nil)
            while raw
            for line = (trim-http-line raw)
            until (zerop (length line))
            do (let ((colon (position #\: line)))
                 (when colon
                   (push (cons (intern (string-upcase (subseq line 0 colon))
                                       :keyword)
                               (string-trim '(#\Space #\Tab)
                                            (subseq line (1+ colon))))
                         headers))))
      (values status (nreverse headers)))))

(defun upgrade-request-p ()
  (let ((connection (hunchentoot:header-in* :connection))
        (upgrade (hunchentoot:header-in* :upgrade)))
    (and connection upgrade
         (find "upgrade"
               (uiop:split-string connection :separator '(#\, #\Space #\Tab))
               :test #'string-equal))))

(defun copy-binary-stream (input output)
  (let ((buffer (make-array 16384 :element-type '(unsigned-byte 8))))
    (loop for first = (read-byte input nil nil)
          while first
          do (setf (aref buffer 0) first)
             (let ((count 1))
               (loop while (and (< count (length buffer)) (listen input))
                     do (setf (aref buffer count) (read-byte input))
                        (incf count))
               (write-sequence buffer output :end count)
               (finish-output output)))))

(defun relay-runtime-stream (client upstream socket)
  (let ((client-to-runtime
          (bt:make-thread
           (lambda ()
             (unwind-protect
                  (ignore-errors (copy-binary-stream client upstream))
               (ignore-errors (usocket:socket-shutdown socket :io))))
           :name "gr8s exec client-to-runtime")))
    (declare (ignore client-to-runtime))
    (unwind-protect
         (copy-binary-stream upstream client)
      (ignore-errors (usocket:socket-close socket)))))

(defun proxy-runtime-stream (url)
  (multiple-value-bind (host port target)
      (parse-runtime-stream-url url)
    (let* ((socket (usocket:socket-connect
                    host port :element-type '(unsigned-byte 8)))
           (upstream (usocket:socket-stream socket)))
      (handler-case
          (progn
            (write-sequence
             (ascii-octets
              (runtime-upgrade-request
               target host port (hunchentoot:headers-in*)))
             upstream)
            (finish-output upstream)
            (multiple-value-bind (status headers)
                (parse-http-response-head
                 (read-http-response-head upstream))
              (unless (= status 101)
                (error 'runtime-error
                       :message
                       (format nil
                               "containerd rejected the exec upgrade with HTTP ~D"
                               status)))
              (setf (hunchentoot:return-code*) 101
                    (hunchentoot:content-type*) nil)
              (dolist (header headers)
                (when (member (car header)
                              *runtime-upgrade-response-headers*)
                  (setf (hunchentoot:header-out (car header))
                        (cdr header))))
              ;; SEND-HEADERS treats an unknown-length response as a chunked
              ;; body.  An upgraded connection has no HTTP body: its following
              ;; octets belong to WebSocket/SPDY and must remain untouched.
              (let ((client (hunchentoot::start-output 101 nil)))
                (finish-output client)
                (relay-runtime-stream client upstream socket))))
        (error (condition)
          (ignore-errors (usocket:socket-close socket))
          (if (typep condition 'runtime-error)
              (error condition)
              (error 'runtime-error :message (princ-to-string condition))))))))

(defparameter *kubernetes-websocket-protocols*
  '("v5.channel.k8s.io" "v4.channel.k8s.io"))

(defun requested-kubernetes-websocket-protocol ()
  (let ((requested
          (uiop:split-string
           (or (hunchentoot:header-in* :sec-websocket-protocol) "")
           :separator '(#\, #\Space #\Tab))))
    (find-if (lambda (protocol)
               (find protocol requested :test #'string-equal))
             *kubernetes-websocket-protocols*)))

(defun websocket-accept-value (key)
  (ag-grpc:base64-encode
   (ironclad:digest-sequence
    :sha1
    (trivial-utf-8:string-to-utf-8-bytes
     (concatenate 'string key "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")))))

(defun write-kubernetes-channel-frame (stream channel data)
  (let ((payload (make-array (1+ (length data))
                             :element-type '(unsigned-byte 8))))
    (setf (aref payload 0) channel)
    (replace payload data :start1 1)
    (write-websocket-frame stream 2 payload)))

(defun exec-exit-status-bytes (exit-code)
  (when (zerop exit-code)
    (return-from exec-exit-status-bytes
      (trivial-utf-8:string-to-utf-8-bytes
       (com.inuoe.jzon:stringify
        (json-object "apiVersion" "v1" "kind" "Status" "status" "Success")))))
  (trivial-utf-8:string-to-utf-8-bytes
   (with-output-to-string (output)
     (com.inuoe.jzon:stringify
      (let ((status (make-hash-table :test #'equal))
            (details (make-hash-table :test #'equal))
            (cause (make-hash-table :test #'equal)))
        (setf (gethash "apiVersion" status) "v1"
              (gethash "kind" status) "Status"
              (gethash "status" status) "Failure"
              (gethash "message" status)
              (format nil "command terminated with exit code ~D" exit-code)
              (gethash "reason" status) "NonZeroExitCode"
              (gethash "code" status) 500
              (gethash "reason" cause) "ExitCode"
              (gethash "message" cause) (princ-to-string exit-code)
              (gethash "causes" details) (list cause)
              (gethash "details" status) details)
        status)
      :stream output))))

(defun serve-runtime-exec-sync (result stdout-p stderr-p)
  (let ((key (hunchentoot:header-in* :sec-websocket-key))
        (protocol (requested-kubernetes-websocket-protocol)))
    (unless (and key (plusp (length key)))
      (bad-exec-request "Pod exec requires Sec-WebSocket-Key"))
    (unless protocol
      (bad-exec-request "Pod exec requires a supported channel protocol"))
    (setf (hunchentoot:return-code*) 101
          (hunchentoot:content-type*) nil
          (hunchentoot:header-out :connection) "Upgrade"
          (hunchentoot:header-out :upgrade) "websocket"
          (hunchentoot:header-out :sec-websocket-accept)
          (websocket-accept-value key)
          (hunchentoot:header-out :sec-websocket-protocol) protocol)
    (let ((client (hunchentoot::start-output 101 nil)))
      (finish-output client)
      (when stdout-p
        (write-kubernetes-channel-frame
         client 1 (runtime-exec-result-stdout result)))
      (when stderr-p
        (write-kubernetes-channel-frame
         client 2 (runtime-exec-result-stderr result)))
      (write-kubernetes-channel-frame
       client 3
       (exec-exit-status-bytes (runtime-exec-result-exit-code result)))
      (write-websocket-frame
       client 8 (make-array 2 :element-type '(unsigned-byte 8)
                            :initial-contents '(3 232))))))

(define-condition exec-input-reader-stopped (error) ())

(defun begin-kubernetes-websocket ()
  (let ((key (hunchentoot:header-in* :sec-websocket-key))
        (protocol (requested-kubernetes-websocket-protocol)))
    (unless (and key (plusp (length key)))
      (bad-exec-request "Pod exec requires Sec-WebSocket-Key"))
    (unless protocol
      (bad-exec-request "Pod exec requires a supported channel protocol"))
    (setf (hunchentoot:return-code*) 101
          (hunchentoot:content-type*) nil
          (hunchentoot:header-out :connection) "Upgrade"
          (hunchentoot:header-out :upgrade) "websocket"
          (hunchentoot:header-out :sec-websocket-accept)
          (websocket-accept-value key)
          (hunchentoot:header-out :sec-websocket-protocol) protocol)
    (let ((client (hunchentoot::start-output 101 nil)))
      (finish-output client)
      client)))

(defun terminal-size-from-channel-data (data)
  (let ((size
          (com.inuoe.jzon:parse
           (trivial-utf-8:utf-8-bytes-to-string data))))
    (values (gethash "height" size 0)
            (gethash "width" size 0))))

(defun forward-kubernetes-exec-input
    (reconciler session stream write-lock finished-p)
  (handler-case
      (loop until (funcall finished-p)
            do (multiple-value-bind (opcode payload fin-p masked-p)
                   (read-websocket-frame stream)
                 (declare (ignore fin-p))
                 (case opcode
                   (2
                    (unless masked-p
                      (error 'runtime-error
                             :message "WebSocket client frames must be masked"))
                    (when (zerop (length payload))
                      (error 'runtime-error
                             :message "Empty remotecommand input frame"))
                    (case (aref payload 0)
                      (0
                       (reconciler-send-exec-session-input
                        reconciler session
                        gr8s.node.v1::+streamchannel-stream_channel_stdin+
                        (subseq payload 1)))
                      (4
                       (multiple-value-bind (rows columns)
                           (terminal-size-from-channel-data (subseq payload 1))
                         (reconciler-send-exec-session-input
                          reconciler session
                          gr8s.node.v1::+streamchannel-stream_channel_terminal_resize+
                          (make-array 0 :element-type '(unsigned-byte 8))
                          :rows rows :columns columns)))
                      (255
                       (when (and (> (length payload) 1)
                                  (= 0 (aref payload 1)))
                         (reconciler-send-exec-session-input
                          reconciler session
                          gr8s.node.v1::+streamchannel-stream_channel_stdin+
                          (make-array 0 :element-type '(unsigned-byte 8))
                          :eof t)))
                      (otherwise
                       (error 'runtime-error
                              :message "Unsupported remotecommand input channel"))))
                   (8
                    (unless (funcall finished-p)
                      (reconciler-cancel-exec-session
                       reconciler session "WebSocket client closed"))
                    (return))
                   (9
                    (bt:with-lock-held (write-lock)
                      (write-websocket-frame stream 10 payload)))
                   (10)
                   (otherwise
                    (error 'runtime-error
                           :message "Unsupported WebSocket input frame")))))
    (exec-input-reader-stopped () nil)
    (error (condition)
      (unless (funcall finished-p)
        (ignore-errors
          (reconciler-cancel-exec-session
           reconciler session (princ-to-string condition)))))))

(defun operation-stream-wire-channel (message)
  (case (slot-value message 'gr8s.node.v1::channel)
    (#.gr8s.node.v1::+streamchannel-stream_channel_stdout+ 1)
    (#.gr8s.node.v1::+streamchannel-stream_channel_stderr+ 2)))

(defun serve-agent-exec-session (reconciler uid container options)
  (let* ((session
           (reconciler-start-exec-session
            reconciler uid container (exec-options-command options)
            :stdin (exec-options-stdin options)
            :stdout (exec-options-stdout options)
            :stderr (exec-options-stderr options)
            :tty (exec-options-tty options)))
         (client (begin-kubernetes-websocket))
         (write-lock (bt:make-lock "gr8s kubectl exec websocket writer"))
         (finished-lock (bt:make-lock "gr8s kubectl exec finished"))
         (finished-p nil)
         (completed-p nil)
         (input-thread nil))
    (labels ((finished-p ()
               (bt:with-lock-held (finished-lock) finished-p))
             (mark-finished ()
               (bt:with-lock-held (finished-lock) (setf finished-p t))))
      (unwind-protect
           (progn
             (setf input-thread
                   (bt:make-thread
                    (lambda ()
                      (forward-kubernetes-exec-input
                       reconciler session client write-lock #'finished-p))
                    :name "gr8s kubectl exec input"))
             (loop with cursor = 0
                   do (multiple-value-bind (message next-cursor done-p)
                          (reconciler-next-exec-session-output
                           reconciler session cursor)
                        (setf cursor next-cursor)
                        (when message
                          (let ((channel
                                  (operation-stream-wire-channel message)))
                            (when channel
                              (bt:with-lock-held (write-lock)
                                (write-kubernetes-channel-frame
                                 client channel
                                 (slot-value message 'gr8s.node.v1::data))))))
                        (when done-p
                          (setf completed-p t)
                          (loop-finish))))
             (let ((exit-code
                     (reconciler-exec-session-exit-code reconciler session)))
               (bt:with-lock-held (write-lock)
                 (write-kubernetes-channel-frame
                  client 3 (exec-exit-status-bytes exit-code))))
             (mark-finished)
             (bt:with-lock-held (write-lock)
               (write-websocket-frame
                client 8 (make-array 2 :element-type '(unsigned-byte 8)
                                     :initial-contents '(3 232)))))
        (mark-finished)
        (unless completed-p
          (ignore-errors
            (reconciler-cancel-exec-session
             reconciler session "API exec stream ended")))
        (reconciler-release-exec-session reconciler session)
        (when (and input-thread (bt:thread-alive-p input-thread))
          (bt:interrupt-thread
           input-thread
           (lambda () (error 'exec-input-reader-stopped))))
        (when input-thread
          (ignore-errors (bt:join-thread input-thread)))))))

(defun bad-exec-request (message)
  (error 'kubernetes-error :status-code 400 :reason "BadRequest"
         :message message))

(defun pod-exec-response (store reconciler name &optional (namespace "default"))
  (unless (upgrade-request-p)
    (bad-exec-request "Pod exec requires an upgraded connection"))
  (let* ((pod (get-pod store namespace name))
         (options
           (exec-options-from-parameters (hunchentoot:get-parameters*)))
         (container
           (or (exec-options-container options)
               (container-spec-name (aref (pod-containers pod) 0)))))
    (unless (exec-options-command options)
      (bad-exec-request "Pod exec requires at least one command argument"))
    (unless (find container (pod-containers pod)
                  :key #'container-spec-name :test #'string=)
      (bad-exec-request
       (format nil "container ~A is not valid for pod ~A" container name)))
    (if (and (not (exec-options-stdin options))
             (not (exec-options-tty options)))
        (serve-runtime-exec-sync
         (reconciler-exec-sync
          reconciler (pod-uid pod) container (exec-options-command options)
          :timeout 30)
         (exec-options-stdout options)
         (exec-options-stderr options))
        (if (typep (reconciler-runtime reconciler) 'control-plane-runtime)
            (serve-agent-exec-session
             reconciler (pod-uid pod) container options)
            (proxy-runtime-stream
             (reconciler-exec-url
              reconciler (pod-uid pod) container (exec-options-command options)
              :stdin (exec-options-stdin options)
              :stdout (exec-options-stdout options)
              :stderr (exec-options-stderr options)
              :tty (exec-options-tty options)))))))

(defun pod-route-parts (path)
  "Return Pod subresource parts, namespace, and a route match indicator."
  (let ((parts (uiop:split-string path :separator '(#\/))))
    (when (and (<= 6 (length parts))
               (equal (subseq parts 0 4) '("" "api" "v1" "namespaces"))
               (dns-label-p (fifth parts)) (equal "pods" (sixth parts))
               (every (lambda (part) (plusp (length part))) (nthcdr 6 parts)))
      (values (nthcdr 6 parts) (fifth parts) t))))

(defun dispatch-pod-request (store runtime reconciler path method)
  (declare (ignore runtime))
  (multiple-value-bind (parts namespace matched) (pod-route-parts path)
    (declare (ignore matched))
    (cond
      ((and (null parts) (eq method :post))
       (create-pod-response store reconciler namespace))
      ((and (null parts) (eq method :get))
       (list-pods-response store reconciler namespace))
      ((and (= 1 (length parts)) (eq method :get))
       (get-pod-response store reconciler (first parts) namespace))
      ((and (= 1 (length parts)) (eq method :patch))
       (apply-pod-response store reconciler (first parts) namespace))
      ((and (= 1 (length parts)) (eq method :put))
       (replace-pod-response store reconciler (first parts) namespace))
      ((and (= 1 (length parts)) (eq method :delete))
       (delete-pod-response store reconciler (first parts) namespace))
      ((and (= 2 (length parts)) (string= "log" (second parts)) (eq method :get))
       (pod-logs-response store reconciler (first parts) namespace))
      ((and (= 2 (length parts)) (string= "exec" (second parts)) (member method '(:get :post)))
       (pod-exec-response store reconciler (first parts) namespace))
      (t (status-response "Failure" "NotFound"
                          (format nil "No route for ~A ~A" method path) 404)))))

(defun handle-http-request (store runtime reconciler request)
  (handler-case
      (let ((path (hunchentoot:script-name request))
            (method (hunchentoot:request-method request)))
        (cond
          ((string= path "/metrics")
           (setf (hunchentoot:content-type*) "text/plain; version=0.0.4; charset=utf-8")
           (runtime-network-metrics runtime))
          ((string= path "/version") (version-response))
          ((string= path "/api") (api-versions-response))
          ((string= path "/apis") (api-groups-response))
          ((string= path "/apis/events.k8s.io") (json-response (event-api-group)))
          ((string= path "/apis/events.k8s.io/v1") (event-discovery-response))
          ((string= path "/apis/rbac.authorization.k8s.io/v1") (rbac-resources-response))
          ((string= path "/openapi/v2") (openapi-response))
          ((string= path "/openapi/v3") (openapi-v3-discovery-response))
          ((string= path "/openapi/v3/apis/events.k8s.io/v1") (openapi-v3-response "events.k8s.io/v1"))
          ((string= path "/openapi/v3/api/v1") (openapi-v3-response))
          ((string= path "/api/v1") (api-resources-response))
          ((and (eq method :get) (string= path "/api/v1/nodes"))
           (nodes-api-response store))
          ((and (eq method :get) (uiop:string-prefix-p "/api/v1/nodes/" path)
                (dns-subdomain-p (subseq path (length "/api/v1/nodes/"))))
           (nodes-api-response store (subseq path (length "/api/v1/nodes/"))))
          ((core-resource-route path)
           (dispatch-core-resource-request store path method))
          ((and (string= path "/api/v1/pods") (eq method :get))
           (list-pods-response store reconciler nil))
          ((nth-value 2 (pod-route-parts path))
           (dispatch-pod-request store runtime reconciler path method))
          (t (status-response "Failure" "NotFound" "route not found" 404))))
    (kubernetes-error (error)
      (kubernetes-error-response error))
    (com.inuoe.jzon:json-parse-error (error)
      (status-response "Failure" "BadRequest" (princ-to-string error) 400))
    (runtime-error (error)
      (status-response "Failure" "RuntimeError"
                       (runtime-error-message error) 500))))
