;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Put admission webhooks on the API write paths. Webhooks run outside the
;;;; store lock over a snapshot, so each write previews itself, admits the result
;;;; and commits with an optimistic revision, restarting on a lost race. Requests
;;;; no webhook selects keep the direct store path unchanged.

(in-package #:gr8s.apiserver)

(defun admission-request-options (kind)
  "Describe the current request's write options as the webhook's request.options."
  (let ((options (core-object "apiVersion" "meta.k8s.io/v1" "kind" kind)))
    (unless *admission-controller*
      (when (hunchentoot:parameter "dryRun")
        (setf (gethash "dryRun" options) (vector (hunchentoot:parameter "dryRun"))))
      (dolist (field '("fieldManager" "fieldValidation"))
        (when (hunchentoot:parameter field)
          (setf (gethash field options) (hunchentoot:parameter field)))))
    options))

(defmacro with-controller-admission ((controller) &body body)
  "Run BODY's writes through the webhooks as the in-process CONTROLLER, which has no HTTP request."
  `(let ((*admission-controller* ,controller)) ,@body))

(defun controller-create-core-resource (store resource input namespace controller)
  "Create INPUT as the in-process CONTROLLER does through the API, past admission. Call
without STORE's lock, because webhooks answer over the network."
  (with-controller-admission (controller)
    (admitted-create-core-resource store resource input namespace)))

(defun controller-update-core-resource (store resource namespace name transform controller)
  "Update as the in-process CONTROLLER does through the API, past admission. Call without
STORE's lock, because webhooks answer over the network."
  (with-controller-admission (controller)
    (admitted-update-core-resource store resource namespace name transform)))

(defun admit-controller-pod (store object controller)
  "Run a Pod OBJECT that CONTROLLER is creating through the webhooks and in-cluster admission.
Call without STORE's lock, because webhooks answer over the network. Return the POD to commit."
  (with-controller-admission (controller)
    (let* ((metadata (gethash "metadata" object)) (namespace (gethash "namespace" metadata)))
      (multiple-value-bind (admitted attributes)
          (admit-pod-input store "CREATE" namespace (gethash "name" metadata) object nil)
        (admit-pod-result store attributes
                          (admit-in-cluster-pod store (request-pod-in-namespace admitted namespace :allow-generate-name t)))))))

(defun admit-controller-object (store resource input namespace controller)
  "Run an object CONTROLLER commits under its own lock through the webhooks, returning what to commit.
Call without STORE's lock. Writes that need no such lock use ADMITTED-CREATE-CORE-RESOURCE instead."
  (with-controller-admission (controller)
    (let* ((name (gethash "name" (gethash "metadata" input)))
           (attributes (admission-attributes-for store "CREATE" resource namespace name
                                                 :options (admission-request-options "CreateOptions"))))
      (if (not (admission-active-p store attributes))
          input
          (progn
            (setf (admission-object attributes) (admission-input-view store resource input namespace attributes))
            (let ((mutated (admission-mutate store attributes)))
              (setf (admission-object attributes) (admission-input-view store resource mutated namespace attributes))
              (admission-validate store attributes)
              mutated))))))

(defun admit-controller-write (store resource input old namespace controller)
  "Run CONTROLLER's create of INPUT, or its update of OLD to INPUT, through admission,
returning what to commit. Call without STORE's lock."
  (with-controller-admission (controller)
    (let* ((name (gethash "name" (gethash "metadata" input)))
           (attributes (admission-attributes-for store (if old "UPDATE" "CREATE") resource namespace name
                                                 :options (admission-request-options
                                                           (if old "UpdateOptions" "CreateOptions")))))
      (if (not (admission-active-p store attributes))
          input
          (progn
            (when old
              (setf (admission-old-object attributes)
                    (admission-stamp-object attributes (core-resource-update-view resource old))))
            (setf (admission-object attributes) (admission-input-view store resource input namespace attributes))
            (let ((mutated (admission-mutate store attributes)))
              (setf (admission-object attributes) (admission-input-view store resource mutated namespace attributes))
              (admission-validate store attributes)
              mutated))))))

(defun custom-resource-storage-view (store resource)
  "Return the definition and storage version of custom RESOURCE, which a controller has no request to name."
  (when (custom-resource-key-p resource)
    (let ((definition (with-store-lock (store)
                        (loop for key being the hash-keys of (pod-store-resources store) using (hash-value object)
                              when (and (equal "customresourcedefinitions" (first key))
                                        (equal resource (crd-custom-key object)))
                                return (copy-core-object object)))))
      (when definition
        (values definition
                (gethash "name" (find-if (lambda (version) (gethash "storage" version))
                                         (gethash "versions" (gethash "spec" definition)))))))))

(defun controller-delete-allowed-p (store resource namespace name controller)
  "Offer CONTROLLER's deletion of an object to the webhooks, returning whether it may go ahead.
A refusal is logged and the controller tries again on a later pass, as an API client would."
  (handler-case
      (with-controller-admission (controller)
        (multiple-value-bind (*crd-view-definition* *crd-request-version*) (custom-resource-storage-view store resource)
          (let ((attributes (admission-attributes-for store "DELETE" resource namespace name
                                                      :options (admission-delete-options nil))))
            (when (admission-active-p store attributes)
              (admit-delete store attributes
                            (if (equal resource "pods")
                                (copy-core-object (pod-to-object (get-pod store namespace name)))
                                (core-resource-update-view resource (get-core-resource store resource namespace name)))))))
        t)
    (kubernetes-error (condition)
      (unless (= 404 (kubernetes-error-status-code condition))
        (format *error-output* "gr8s ~A: deletion of ~A ~@[~A/~]~A refused: ~A~%"
                controller resource namespace name condition))
      nil)))

(defun delete-controller-pod (reconciler namespace name controller &key uid)
  "Delete a Pod as CONTROLLER once the webhooks allow it, returning whether it went ahead."
  (when (controller-delete-allowed-p (reconciler-store reconciler) "pods" namespace name controller)
    (delete-reconciled-pod reconciler namespace name :uid uid)
    t))

(defun admission-delete-options (options)
  "Describe DeleteOptions for a webhook, copying what the client sent."
  (let ((described (if (hash-table-p options) (copy-core-object options) (core-object))))
    (setf (gethash "apiVersion" described) "meta.k8s.io/v1" (gethash "kind" described) "DeleteOptions")
    described))

(defun admission-input-view (store resource input namespace attributes)
  "Show mutating webhooks INPUT with its defaults when it already validates.
An object a webhook still has to repair goes to it as submitted, as do objects
without a name yet and custom objects, which stay in the requested version."
  (admission-stamp-object
   attributes
   (let* ((metadata (and (hash-table-p input) (gethash "metadata" input)))
          (name (and (hash-table-p metadata) (gethash "name" metadata))))
     (or (and name (not (custom-resource-key-p resource))
              (handler-case
                  (with-store-lock (store)
                    (normalize-core-resource resource input namespace name store))
                (kubernetes-error () nil)))
         (copy-core-object input)))))

(defun admission-preview-input (input)
  "Return INPUT without the resourceVersion that only its committing create refuses."
  (let ((metadata (gethash "metadata" input)))
    (if (and (hash-table-p metadata) (nth-value 1 (gethash "resourceVersion" metadata)))
        (let ((copy (copy-core-object input)))
          (remhash "resourceVersion" (gethash "metadata" copy))
          copy)
        input)))

(defun admitted-create-core-resource (store resource input namespace &key dry-run)
  "Create through the webhooks: mutate, preview the result, validate, then commit that identity."
  (let* ((metadata (require-object (gethash "metadata" input) "metadata"))
         (attributes (admission-attributes-for store "CREATE" resource namespace (gethash "name" metadata)
                                               :options (admission-request-options "CreateOptions")
                                               :dry-run dry-run)))
    (if (not (admission-active-p store attributes))
        (create-core-resource store resource input namespace :dry-run dry-run)
        (progn
          (setf (admission-object attributes) (admission-input-view store resource input namespace attributes))
          (let* ((mutated (admission-mutate store attributes))
                 ;; Upstream's storage refuses a set resourceVersion or a name in use only after
                 ;; validating admission has run, so the preview leaves the revision out, a name
                 ;; in use previews the object as submitted, and the commit refuses either.
                 (preview (handler-case
                              (create-core-resource store resource (admission-preview-input mutated) namespace :dry-run t)
                            (kubernetes-error (condition)
                              (if (equal "AlreadyExists" (kubernetes-error-reason condition))
                                  (admission-input-view store resource (admission-preview-input mutated) namespace attributes)
                                  (error condition)))))
                 (preview-metadata (gethash "metadata" preview))
                 (final (copy-core-object mutated)))
            (setf (admission-object attributes) (admission-stamp-object attributes preview)
                  (admission-name attributes) (gethash "name" preview-metadata)
                  (gethash "name" (gethash "metadata" final)) (gethash "name" preview-metadata))
            (admission-validate store attributes)
            (let ((*core-resource-assigned-uid* (gethash "uid" preview-metadata)))
              (create-core-resource store resource final namespace :dry-run dry-run)))))))

(defparameter +admission-update-attempts+ 8
  "Times a webhook-admitted update restarts after losing a race to another writer.")

(defun admitted-update-core-resource (store resource namespace name transform &key dry-run)
  "Update through the webhooks, restarting from the latest object if it changes meanwhile.
A client's own stale resourceVersion still fails, in the preview of the next attempt."
  (let ((attributes (admission-attributes-for store "UPDATE" resource namespace name
                                              :options (admission-request-options "UpdateOptions")
                                              :dry-run dry-run)))
    (unless (admission-active-p store attributes)
      (return-from admitted-update-core-resource
        (update-core-resource store resource namespace name transform :dry-run dry-run)))
    (loop repeat +admission-update-attempts+
          do (let* ((existing (get-core-resource store resource namespace name))
                    (old (core-resource-update-view resource existing))
                    (requested (funcall transform (copy-core-object old))))
               (setf (admission-old-object attributes) (admission-stamp-object attributes (copy-core-object old))
                     (admission-object attributes) (admission-input-view store resource requested namespace attributes))
               ;; The defaulted view keeps the revision the client sent, if any.
               (let* ((mutated (admission-mutate store attributes))
                      (preview (update-core-resource store resource namespace name
                                                     (lambda (current) (declare (ignore current)) (copy-core-object mutated))
                                                     :dry-run t))
                      (final (copy-core-object mutated)))
                 (setf (admission-object attributes) (admission-stamp-object attributes preview)
                       (gethash "resourceVersion" (gethash "metadata" final))
                       (gethash "resourceVersion" (gethash "metadata" existing)))
                 (admission-validate store attributes)
                 (handler-case
                     (return-from admitted-update-core-resource
                       (update-core-resource store resource namespace name
                                             (lambda (current) (declare (ignore current)) final)
                                             :dry-run dry-run))
                   (kubernetes-error (condition)
                     (unless (= 409 (kubernetes-error-status-code condition)) (error condition)))))))
    (core-resource-error 409 "Conflict" "The resource kept changing during admission; apply your changes to the latest version")))

(defun admit-delete (store attributes old)
  "Offer a deletion of OLD to the webhooks. They can refuse it, but it has no object to change."
  (setf (admission-old-object attributes) (admission-stamp-object attributes old)
        (admission-object attributes) nil)
  (admission-mutate store attributes)
  (admission-validate store attributes))

(defun admit-core-delete (store resource namespace name options dry-run)
  "Offer the deletion of one stored object to the webhooks."
  (let ((attributes (admission-attributes-for store "DELETE" resource namespace name
                                              :options (admission-delete-options options) :dry-run dry-run)))
    (when (admission-active-p store attributes)
      (admit-delete store attributes (core-resource-update-view resource (get-core-resource store resource namespace name))))))

(defun admit-core-delete-collection (store resource namespace options dry-run)
  "Offer each selected object of a collection deletion to the webhooks before deleting any."
  (let ((attributes (admission-attributes-for store "DELETE" resource namespace nil
                                              :options (admission-delete-options options) :dry-run dry-run)))
    (when (admission-active-p store attributes)
      (let ((labels (core-selector-predicate (hunchentoot:parameter "labelSelector")))
            (fields (crd-field-selector-test resource (hunchentoot:parameter "fieldSelector"))))
        (dolist (object (list-core-resources store resource namespace))
          (when (and (funcall labels object) (funcall fields object))
            (let ((metadata (gethash "metadata" object)))
              (setf (admission-name attributes) (gethash "name" metadata)
                    (admission-namespace attributes) (gethash "namespace" metadata))
              (admit-delete store attributes (core-resource-update-view resource object)))))))))

(defun admit-subresource-write (store resource subresource namespace name input old
                                &key kind kind-api-version dry-run)
  "Run the webhooks over a subresource write and return the INPUT they settle on."
  (let ((attributes (admission-attributes-for store "UPDATE" resource namespace name
                                              :subresource subresource :kind kind :kind-api-version kind-api-version
                                              :options (admission-request-options "UpdateOptions") :dry-run dry-run)))
    (if (not (admission-active-p store attributes))
        input
        (progn
          (setf (admission-object attributes) (admission-stamp-object attributes (copy-core-object input))
                (admission-old-object attributes) (admission-stamp-object attributes (copy-core-object old)))
          (let ((mutated (admission-mutate store attributes)))
            (admission-validate store attributes)
            mutated)))))

(defun admit-connect (store subresource namespace name kind options)
  "Offer a Pod connection to the webhooks, whose object is the connection's options."
  (let ((attributes (admission-attributes-for store "CONNECT" "pods" namespace name
                                              :subresource subresource :kind kind :object options)))
    (when (admission-active-p store attributes)
      (setf (gethash "apiVersion" options) "v1" (gethash "kind" options) kind)
      (admission-mutate store attributes)
      (admission-validate store attributes))))

(defun admit-pod-exec (store namespace name options)
  "Offer a Pod exec with its PodExecOptions to the webhooks."
  (admit-connect store "exec" namespace name "PodExecOptions"
                 (core-object "stdin" (and (exec-options-stdin options) t)
                              "stdout" (and (exec-options-stdout options) t)
                              "stderr" (and (exec-options-stderr options) t)
                              "tty" (and (exec-options-tty options) t)
                              "container" (or (exec-options-container options) "")
                              "command" (coerce (exec-options-command options) 'vector))))

(defun admit-pod-attach (store namespace name options)
  "Offer a Pod attach with its PodAttachOptions to the webhooks."
  (admit-connect store "attach" namespace name "PodAttachOptions"
                 (core-object "stdin" (and (exec-options-stdin options) t)
                              "stdout" (and (exec-options-stdout options) t)
                              "stderr" (and (exec-options-stderr options) t)
                              "tty" (and (exec-options-tty options) t)
                              "container" (or (exec-options-container options) ""))))

(defun admit-pod-port-forward (store namespace name)
  "Offer a Pod port-forward with its PodPortForwardOptions to the webhooks."
  (admit-connect store "portforward" namespace name "PodPortForwardOptions" (core-object)))

(defun admit-pod-proxy (store namespace id)
  "Offer a Pod proxy connection with its PodProxyOptions to the webhooks."
  (let* ((raw (hunchentoot:script-name*))
         (end (nth-value 1 (cl-ppcre:scan "^/api/v1/namespaces/[^/]+/pods/[^/]+/proxy" raw)))
         (parts (uiop:split-string id :separator ":"))
         (name (if (= 3 (length parts)) (second parts) (first parts))))
    (admit-connect store "proxy" namespace name "PodProxyOptions"
                   (core-object "path" (if end (subseq raw end) "")))))

(defun admit-pod-input (store operation namespace name raw old)
  "Run the mutating webhooks over a Pod write and return the object to parse.
Returns the attributes as a second value for the validating step."
  ;; Upstream's built-in mutating plugins, DefaultTolerationSeconds among them, run before the webhooks.
  (when (hash-table-p raw)
    (default-pod-admission (gethash "spec" raw) (and old (gethash "spec" (pod-to-object old)))))
  (let ((attributes (admission-attributes-for store operation "pods" namespace name
                                              :options (admission-request-options
                                                        (if (equal operation "CREATE") "CreateOptions" "UpdateOptions"))
                                              :dry-run (and (not *admission-controller*) (core-resource-dry-run-p)))))
    (if (not (admission-active-p store attributes))
        (values raw attributes)
        (let ((view (handler-case
                        (let ((copy (copy-core-object raw)))
                          (copy-core-object (pod-to-object (request-pod-in-namespace copy namespace :allow-generate-name t))))
                      (kubernetes-error () (copy-core-object raw)))))
          (setf (admission-object attributes) (admission-stamp-object attributes view)
                (admission-old-object attributes) (and old (admission-stamp-object attributes (copy-core-object (pod-to-object old)))))
          (values (admission-mutate store attributes) attributes)))))

(defun admit-pod-result (store attributes pod)
  "Run the validating webhooks over the final POD, assigning a generated name first."
  (admit-pod-security store attributes (copy-core-object (pod-to-object pod)))
  (when (admission-active-p store attributes)
    (with-store-lock (store) (assign-generated-pod-name-unlocked store pod))
    (setf (admission-name attributes) (pod-name pod)
          (admission-object attributes) (admission-stamp-object attributes (copy-core-object (pod-to-object pod))))
    (admission-validate store attributes))
  pod)

(defun admit-pod-delete (store namespace name options)
  "Offer a Pod deletion to the webhooks."
  (let ((attributes (admission-attributes-for store "DELETE" "pods" namespace name
                                              :options (admission-delete-options options)
                                              :dry-run (core-resource-dry-run-p))))
    (when (admission-active-p store attributes)
      (admit-delete store attributes (copy-core-object (pod-to-object (get-pod store namespace name)))))))
