;;;; SPDX-License-Identifier: MIT
(in-package #:gr8s-diagnose)

;;; Observations that take more than reading one field: comparisons of two
;;; counters, presence tests, and facts derived from several containers.

(defun path-value (resource path)
  "Return value and presence; JSON false (NIL) must not mean missing."
  (let ((cursor resource))
    (dolist (part (uiop:split-string path :separator "."))
      (unless (hash-table-p cursor) (return-from path-value (values nil nil)))
      (multiple-value-bind (value present) (gethash part cursor)
        (unless present (return-from path-value (values nil nil)))
        (setf cursor value)))
    (values cursor t)))

(defun json-array-p (value) (and (vectorp value) (not (stringp value))))

(defvar *fields-read* (make-hash-table :test #'equal))

(defun fields-read (kind)
  "The fields the checks of KIND read, from reads/2 in rules/catalog.pl."
  (multiple-value-bind (paths known) (gethash kind *fields-read*)
    (if known paths (setf (gethash kind *fields-read*) (known `(reads ,kind ?path) '?path)))))

(defun collect-additional-observations (resource kind emit)
  ;; Hand the rules what the API holds and let them compare it: a number as
  ;; itself, a list as its length, JSON false as false. A path that is not a
  ;; field of the object, such as condition.Ready, is observed elsewhere.
  (dolist (path (fields-read kind))
    (multiple-value-bind (value present) (path-value resource path)
      (when present
        (cond ((json-array-p value) (funcall emit "object" path (vector 'count (length value))))
              ((null value) (funcall emit "object" path :false))
              ((or (stringp value) (realp value) (eq value t)) (funcall emit "object" path value))))))
  (when (equal kind "EndpointSlice")
    (let ((endpoints (field resource "endpoints")))
      (when (and (json-array-p endpoints) (plusp (length endpoints))
                 (every (lambda (endpoint)
                          (multiple-value-bind (ready present) (path-value endpoint "conditions.ready")
                            (and present (null ready)))) endpoints))
        (funcall emit "object" "derived.all-endpoints-unready" t))))
  (when (equal kind "Pod")
    (when (and (stringp (field resource "metadata" "deletionTimestamp"))
               (let ((finalizers (field resource "metadata" "finalizers")))
                 (and (json-array-p finalizers) (plusp (length finalizers)))))
      (funcall emit "object" "derived.deleting-with-finalizers" t))
    (dolist (section '("containerStatuses" "initContainerStatuses" "ephemeralContainerStatuses"))
      (loop for container across (or (field resource "status" section) #())
            for location = (format nil "~A/~A" section (field container "name"))
            for restarts = (field container "restartCount")
            do (when (integerp restarts)
                 (funcall emit location "container.restartCount" restarts))
               (when (equal "Error" (field container "state" "terminated" "reason"))
                 (funcall emit "object" "derived.current-container-error" t))))
    (dolist (section '("containers" "initContainers" "ephemeralContainers"))
      (loop for container across (or (field resource "spec" section) #())
            for location = (format nil "~A/~A" section (field container "name"))
            do (dolist (path '("securityContext.privileged" "securityContext.runAsUser"
                              "securityContext.allowPrivilegeEscalation" "securityContext.readOnlyRootFilesystem"
                              "imagePullPolicy"))
                 (multiple-value-bind (value present) (path-value container path)
                   (when present (funcall emit location (concatenate 'string "container." path)
                                          (if (null value) :false value)))))))))
