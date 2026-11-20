;;;; SPDX-License-Identifier: MIT
(in-package #:gr8s-diagnose)

;;; The facts behind rules/logs.pl and rules/access.pl: what a run that
;;; crashed wrote, and what those rules then ask the cluster.

(defun previous-log (getter pod ns container)
  "The last lines the container's previous run wrote, each bounded, or NIL."
  (multiple-value-bind (log state)
      (funcall getter "PreviousLog" ns (format nil "~A/~A" (field pod "metadata" "name") container))
    (let ((text (and (eq state :present) (field log "text"))))
      (when (and (stringp text) (plusp (length (string-trim '(#\Space #\Newline) text))))
        (mapcar (lambda (line) (if (> (length line) 400) (concatenate 'string (subseq line 0 400) " ...") line))
                (last (uiop:split-string (string-right-trim '(#\Newline) text) :separator '(#\Newline))
                      40))))))

(defun access-facts (getter scope)
  "The bindings and roles that can give access in SCOPE, the atom cluster or
namespace(Name), as facts of rules/access.pl."
  (let ((facts nil)
        (namespace (and (simple-vector-p scope) (svref scope 1))))
    (labels ((items (kind ns)
               (multiple-value-bind (list state) (funcall getter kind ns nil)
                 (if (complete-list-p list state)
                     (field list "items")
                     (return-from access-facts (list (list 'access_unknown))))))
             (strings (value) (remove-if-not #'stringp (coerce (or value #()) 'list)))
             (bindings (kind where ns)
               (loop for binding across (items kind ns)
                     for id = (format nil "~A/~@[~A/~]~A" kind ns (field binding "metadata" "name"))
                     do (push (list 'binding id where (or (field binding "roleRef" "kind") "")
                                    (or (field binding "roleRef" "name") ""))
                              facts)
                        (loop for subject across (or (field binding "subjects") #())
                              do (push (list 'subject id (or (field subject "kind") "")
                                             (or (field subject "namespace") "") (or (field subject "name") ""))
                                       facts))))
             (roles (kind home ns)
               (loop for role across (items kind ns)
                     do (loop for rule across (or (field role "rules") #())
                              when (field rule "resources")
                                do (push (list 'grants kind home (or (field role "metadata" "name") "")
                                               (strings (field rule "verbs"))
                                               (or (strings (field rule "apiGroups")) (list ""))
                                               (strings (field rule "resources")))
                                         facts)))))
      (bindings "ClusterRoleBinding" 'cluster nil)
      (roles "ClusterRole" "" nil)
      (when namespace
        (bindings "RoleBinding" namespace namespace)
        (roles "Role" namespace namespace)))
    facts))

(defun answer-log-question (getter)
  "Supply what the rules ask for: whether the API serves a kind, where the
kubernetes Service is, and who is allowed what."
  (lambda (question)
    (flet ((asks (name) (string= name (symbol-name (if (simple-vector-p question) (svref question 0) question)))))
      (cond ((asks "SERVES")
             ;; A kind that cannot be listed is unserved as far as the doctor can tell.
             (unless (eq :present (nth-value 1 (funcall getter (svref question 1) nil nil)))
               (list (list 'kind_unserved (svref question 1)))))
            ((asks "API_ADDRESS")
             (let ((address (field (funcall getter "Service" "default" "kubernetes") "spec" "clusterIP")))
               (when (stringp address) (list (list 'api_address address)))))
            ((asks "ACCESS") (access-facts getter (svref question 1)))))))

(defun log-findings (pod ns getter crashes)
  "Findings from what crashed runs wrote. CRASHES pairs each crash finding
with the lines of its container's previous run."
  (let* ((facts (loop for (finding . lines) in crashes
                      for container = (gethash "container" finding)
                      for application = (container-application
                                         (find container (or (field pod "spec" "containers") #())
                                               :test #'equal :key (lambda (c) (field c "name"))))
                      collect (list 'crashed_container container)
                      when application collect (list 'runs container (fourth application) (second application))
                      append (loop for line in lines collect (list 'wrote container line))))
         (known (append facts
                        (loop for question in (prove facts '((asks ?question)) '?question)
                              append (funcall (answer-log-question getter) question)))))
    (flet ((finding (code container summary step arguments)
             (let ((crash (car (find container crashes :test #'equal
                                     :key (lambda (entry) (gethash "container" (car entry)))))))
               (object "code" code "rule" code "severity" "warning" "container" container
                       "summary" (apply #'format nil summary (field pod "metadata" "name") container arguments)
                       "detailHeading" (gethash "detailHeading" crash) "detail" (gethash "detail" crash)
                       "nextStep" step "commands" (gethash "commands" crash)
                       "evidence" (gethash "evidence" crash)))))
      (append
       (loop for (code container details)
               in (prove known '((log_finding ?code ?container ?details)) '(?code ?container ?details))
             for (summary step) = (first (known `(log_explanation ,code ?summary ?step) '(?summary ?step)))
             collect (finding code container summary step details))
       (loop for (code container details)
               in (prove known '((access_finding ?code ?container ?details)) '(?code ?container ?details))
             for (summary step) = (first (known `(access_explanation ,code ?summary ?step) '(?summary ?step)))
             collect (finding code container summary step details))))))
