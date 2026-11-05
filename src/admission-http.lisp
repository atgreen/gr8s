;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Put admission webhooks on the API write paths. Webhooks run outside the
;;;; store lock over a snapshot, so each write previews itself, admits the result
;;;; and commits with an optimistic revision, restarting on a lost race. Requests
;;;; no webhook selects keep the direct store path unchanged.

(in-package #:gr8s)

(defun admission-request-options (kind)
  "Describe the current request's write options as the webhook's request.options."
  (let ((options (core-object "apiVersion" "meta.k8s.io/v1" "kind" kind)))
    (when (hunchentoot:parameter "dryRun")
      (setf (gethash "dryRun" options) (vector (hunchentoot:parameter "dryRun"))))
    (dolist (field '("fieldManager" "fieldValidation"))
      (when (hunchentoot:parameter field)
        (setf (gethash field options) (hunchentoot:parameter field))))
    options))

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
                 (preview (create-core-resource store resource mutated namespace :dry-run t))
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

(defun pod-attach-response (store name namespace)
  "Offer a Pod attach to the webhooks, then refuse it because the runtime cannot attach."
  (let ((options (exec-options-from-parameters (hunchentoot:get-parameters*))))
    (get-pod store namespace name)
    (admit-connect store "attach" namespace name "PodAttachOptions"
                   (core-object "stdin" (and (exec-options-stdin options) t)
                                "stdout" (and (exec-options-stdout options) t)
                                "stderr" (and (exec-options-stderr options) t)
                                "tty" (and (exec-options-tty options) t)
                                "container" (or (exec-options-container options) "")))
    (core-resource-error 501 "NotImplemented" "Pod attach is not implemented")))

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
  (let ((attributes (admission-attributes-for store operation "pods" namespace name
                                              :options (admission-request-options
                                                        (if (equal operation "CREATE") "CreateOptions" "UpdateOptions"))
                                              :dry-run (core-resource-dry-run-p))))
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
