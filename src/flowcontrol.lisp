;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Classify requests by FlowSchema and report the result in the response headers
;;;; upstream's clients read, keep the mandatory exempt and catch-all objects, report
;;;; dangling references and publish each priority level's nominal seats. Requests are
;;;; classified but not queued or rejected: no limit is enforced.

(in-package #:gr8s)

(defparameter +flowcontrol-api-version+ "flowcontrol.apiserver.k8s.io/v1")
(defparameter +flowcontrol-server-seats+ 600
  "Upstream's default server concurrency limit, which limited levels share out.")
(defparameter +flowcontrol-refresh-units+ (floor internal-time-units-per-second 4)
  "Least time between rereading the FlowSchemas, since classification runs on every request.")

(defvar *flowcontrol-snapshot* nil
  "List of store, revision, read time and classification table, replaced as a whole.")

(defun flowcontrol-table (store)
  "Return (schema . level-uid) pairs in match order, rereading them only when something changed."
  (let ((snapshot *flowcontrol-snapshot*) (revision (pod-store-resource-revision store))
        (now (get-internal-real-time)))
    (if (and snapshot (eq store (first snapshot))
             (or (eql revision (second snapshot))
                 (< (- now (third snapshot)) +flowcontrol-refresh-units+)))
        (fourth snapshot)
        (let* ((levels (list-core-resources store "prioritylevelconfigurations"))
               (schemas (stable-sort
                         (sort (list-core-resources store "flowschemas") #'string< :key #'object-name)
                         #'< :key (lambda (schema) (gethash "matchingPrecedence" (gethash "spec" schema) 1000))))
               (table (loop for schema in schemas
                            for level = (find (gethash "name" (gethash "priorityLevelConfiguration" (gethash "spec" schema)))
                                              levels :key #'object-name :test #'equal)
                            when level
                              collect (cons schema (gethash "uid" (gethash "metadata" level))))))
          (setf *flowcontrol-snapshot* (list store revision now table))
          table))))

(defun flowcontrol-listed-p (entries value wildcard)
  "Test whether a rule's list ENTRIES names VALUE or holds WILDCARD."
  (and (crd-array-p entries)
       (or (find wildcard entries :test #'equal) (find value entries :test #'equal))
       t))

(defun flowcontrol-subject-matches-p (subject username groups)
  "Test one Subject against a requester."
  (let ((kind (gethash "kind" subject)))
    (cond
      ((equal kind "User")
       (let ((name (table-get subject "user" "name"))) (or (equal name "*") (equal name username))))
      ((equal kind "Group")
       (let ((name (table-get subject "group" "name")))
         (or (equal name "*") (find name groups :test #'equal))))
      ((equal kind "ServiceAccount")
       (let ((namespace (table-get subject "serviceAccount" "namespace"))
             (name (table-get subject "serviceAccount" "name")))
         (multiple-value-bind (own-namespace own-name) (service-account-username-parts username)
           (and own-namespace (equal namespace own-namespace)
                (or (equal name "*") (equal name own-name)))))))))

(defun flowcontrol-url-matches-p (patterns path)
  "Test a request path against nonResourceURLs, where a trailing /* covers a whole subtree."
  (and (crd-array-p patterns)
       (some (lambda (pattern)
               (or (equal pattern "*") (equal pattern path)
                   (and (uiop:string-suffix-p pattern "/*")
                        (let ((prefix (subseq pattern 0 (1- (length pattern)))))
                          (or (uiop:string-prefix-p prefix path)
                              (equal path (subseq prefix 0 (1- (length prefix)))))))))
             patterns)))

(defun flowcontrol-rule-matches-p (rule username groups path verb group resource namespace)
  "Test one PolicyRulesWithSubjects against a request."
  (and (some (lambda (subject) (flowcontrol-subject-matches-p subject username groups))
             (or (gethash "subjects" rule) #()))
       (if resource
           (some (lambda (policy)
                   (and (flowcontrol-listed-p (gethash "verbs" policy) verb "*")
                        (flowcontrol-listed-p (gethash "apiGroups" policy) group "*")
                        (flowcontrol-listed-p (gethash "resources" policy) resource "*")
                        (if namespace
                            (flowcontrol-listed-p (gethash "namespaces" policy) namespace "*")
                            (eq t (gethash "clusterScope" policy)))))
                 (let ((rules (gethash "resourceRules" rule))) (if (crd-array-p rules) rules #())))
           (some (lambda (policy)
                   (and (flowcontrol-listed-p (gethash "verbs" policy) verb "*")
                        (flowcontrol-url-matches-p (gethash "nonResourceURLs" policy) path)))
                 (let ((rules (gethash "nonResourceRules" rule))) (if (crd-array-p rules) rules #()))))))

(defun flowcontrol-classify (store identity path method &optional watch)
  "Return the FlowSchema and priority level UIDs of a request, or NIL when nothing matches."
  (multiple-value-bind (verb group resource name namespace)
      (kubernetes-authorization-target path method :watch watch)
    (declare (ignore name))
    (let ((username (api-identity-username identity)) (groups (coerce (api-identity-groups identity) 'list)))
      (loop for (schema . level) in (flowcontrol-table store)
            do (when (some (lambda (rule)
                             (flowcontrol-rule-matches-p rule username groups path verb group resource namespace))
                           (or (gethash "rules" (gethash "spec" schema)) #()))
                 (return (values (gethash "uid" (gethash "metadata" schema)) level)))))))

(defun flowcontrol-note-request (store identity path method)
  "Say on the response which FlowSchema and priority level this request classified as."
  (multiple-value-bind (schema level) (flowcontrol-classify store identity path method (true-parameter-p (hunchentoot:parameter "watch")))
    (when schema
      (setf (hunchentoot:header-out "X-Kubernetes-PF-FlowSchema-UID") schema
            (hunchentoot:header-out "X-Kubernetes-PF-PriorityLevel-UID") level))))

;;; Mandatory objects and status

(defun flowcontrol-all-rule ()
  "Build the rule that matches every request of every user."
  (core-object
   "subjects" (vector (core-object "kind" "Group" "group" (core-object "name" "system:authenticated"))
                      (core-object "kind" "Group" "group" (core-object "name" "system:unauthenticated")))
   "resourceRules" (vector (core-object "verbs" #("*") "apiGroups" #("*") "resources" #("*")
                                        "clusterScope" t "namespaces" #("*")))
   "nonResourceRules" (vector (core-object "verbs" #("*") "nonResourceURLs" #("*")))))

(defun flowcontrol-mandatory-objects ()
  "List (collection . object) for the objects upstream's API server always keeps."
  (flet ((object (kind name spec)
           (core-object "apiVersion" +flowcontrol-api-version+ "kind" kind
                        "metadata" (core-object "name" name) "spec" spec)))
    (list
     (cons "prioritylevelconfigurations"
           (object "PriorityLevelConfiguration" "exempt"
                   (core-object "type" "Exempt" "exempt" (core-object "nominalConcurrencyShares" 0 "lendablePercent" 0))))
     (cons "prioritylevelconfigurations"
           (object "PriorityLevelConfiguration" "catch-all"
                   (core-object "type" "Limited"
                                "limited" (core-object "nominalConcurrencyShares" 5 "lendablePercent" 0
                                                       "limitResponse" (core-object "type" "Reject")))))
     (cons "flowschemas"
           (object "FlowSchema" "exempt"
                   (core-object "matchingPrecedence" 1
                                "priorityLevelConfiguration" (core-object "name" "exempt")
                                "rules" (vector (let ((rule (flowcontrol-all-rule)))
                                                  (setf (gethash "subjects" rule)
                                                        (vector (core-object "kind" "Group" "group" (core-object "name" "system:masters"))))
                                                  rule)))))
     (cons "flowschemas"
           (object "FlowSchema" "catch-all"
                   (core-object "matchingPrecedence" 10000
                                "priorityLevelConfiguration" (core-object "name" "catch-all")
                                "distinguisherMethod" (core-object "type" "ByUser")
                                "rules" (vector (flowcontrol-all-rule))))))))

(defun flowcontrol-dangling-condition (schema levels)
  "Return the Dangling condition SCHEMA should now report, reusing its old one when true to it."
  (let* ((name (gethash "name" (gethash "priorityLevelConfiguration" (gethash "spec" schema))))
         (dangling (not (find name levels :key #'object-name :test #'equal)))
         (status (if dangling "True" "False"))
         (old (find "Dangling" (or (table-get schema "status" "conditions") #())
                    :test #'equal :key (lambda (condition) (gethash "type" condition)))))
    (if (and old (equal status (gethash "status" old)))
        old
        (core-object "type" "Dangling" "status" status "lastTransitionTime" (current-timestamp)
                     "reason" (if dangling "NotFound" "Found")
                     "message" (if dangling
                                   (format nil "This FlowSchema references the PriorityLevelConfiguration object named ~S but there is no such object" name)
                                   (format nil "This FlowSchema references the PriorityLevelConfiguration object named ~S and it exists" name))))))

(defun reconcile-flowcontrol (store)
  "Restore the mandatory objects and keep every FlowSchema's Dangling condition true."
  (let ((*apply-update-manager* nil))
    (dolist (entry (flowcontrol-mandatory-objects))
      (destructuring-bind (collection . object) entry
        (handler-case (get-core-resource store collection nil (object-name object))
          (kubernetes-error (condition)
            (when (= 404 (kubernetes-error-status-code condition))
              (handler-case (create-core-resource store collection object nil)
                (kubernetes-error () nil)))))))
    (let ((levels (list-core-resources store "prioritylevelconfigurations")))
      (dolist (schema (list-core-resources store "flowschemas"))
        (let ((condition (flowcontrol-dangling-condition schema levels))
              (current (or (table-get schema "status" "conditions") #())))
          (unless (find condition current :test #'eq)
            (handler-case
                (let ((*typed-api-status-write* t))
                  (update-core-resource
                   store "flowschemas" nil (object-name schema)
                   (lambda (object)
                     (let ((status (or (table-get object "status") (core-object))))
                       (setf (gethash "conditions" status)
                             (concatenate 'vector
                                          (remove "Dangling" (or (gethash "conditions" status) #())
                                                  :test #'equal :key (lambda (entry) (gethash "type" entry)))
                                          (vector condition))
                             (gethash "status" object) status)
                       object))))
              ;; Lost a race with a writer: the next pass looks again.
              (kubernetes-error () nil))))))))

(defun flowcontrol-metrics-text (store)
  "Publish each limited priority level's nominal seats, as upstream's metric does."
  (let* ((levels (list-core-resources store "prioritylevelconfigurations"))
         (limited (remove-if-not (lambda (level) (hash-table-p (table-get level "spec" "limited"))) levels))
         (total (reduce #'+ (mapcar (lambda (level) (or (table-get level "spec" "limited" "nominalConcurrencyShares") 30)) limited))))
    (with-output-to-string (out)
      (format out "# HELP apiserver_flowcontrol_nominal_limit_seats Nominal number of execution seats configured for each priority level~%")
      (format out "# TYPE apiserver_flowcontrol_nominal_limit_seats gauge~%")
      (dolist (level levels)
        (format out "apiserver_flowcontrol_nominal_limit_seats{priority_level=~S} ~D~%"
                (object-name level)
                (if (member level limited)
                    (ceiling (* +flowcontrol-server-seats+ (or (table-get level "spec" "limited" "nominalConcurrencyShares") 30))
                             (max 1 total))
                    0))))))
