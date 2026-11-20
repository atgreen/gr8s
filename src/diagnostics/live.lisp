;;;; SPDX-License-Identifier: MIT
(in-package #:gr8s-diagnose)

(defparameter *target-kinds*
  '(("pdb" . "PodDisruptionBudget") ("poddisruptionbudget" . "PodDisruptionBudget") ("pod" . "Pod") ("node" . "Node") ("event" . "Event")
    ("pvc" . "PersistentVolumeClaim") ("pv" . "PersistentVolume")
    ("deployment" . "Deployment") ("job" . "Job") ("cronjob" . "CronJob") ("replicaset" . "ReplicaSet")
    ("statefulset" . "StatefulSet") ("daemonset" . "DaemonSet")
    ("namespace" . "Namespace") ("service" . "Service") ("endpointslice" . "EndpointSlice")
    ("hpa" . "HorizontalPodAutoscaler") ("csr" . "CertificateSigningRequest")))

(defun object (&rest pairs)
  (let ((result (make-hash-table :test #'equal)))
    (loop for (key value) on pairs by #'cddr do (setf (gethash key result) value))
    result))

(defun field (object &rest path)
  (reduce (lambda (value key) (and (hash-table-p value) (gethash key value)))
          path :initial-value object))

(defun timestamp ()
  (multiple-value-bind (second minute hour day month year)
      (decode-universal-time (get-universal-time) 0)
    (format nil "~4,'0D-~2,'0D-~2,'0DT~2,'0D:~2,'0D:~2,'0DZ"
            year month day hour minute second)))

(defun references (pod)
  "Return only required references, without configuration or Secret values."
  (let ((refs nil))
    (labels ((emit (kind name key location &optional (domain :data))
               (when (and (stringp name) (plusp (length name)))
                 (push (list kind name key location domain) refs)))
             (reference (kind ref name-field location &optional items)
               (when (and ref (not (eq t (field ref "optional"))))
                 (emit kind (field ref name-field) nil location)
                 (when (field ref "key")
                   (emit kind (field ref name-field) (field ref "key") location))
                 (loop for item across (or items #())
                       do (emit kind (field ref name-field) (field item "key") location :volume)))))
      (dolist (section '("containers" "initContainers" "ephemeralContainers"))
        (loop for container across (or (field pod "spec" section) #())
              for location = (format nil "~A/~A" section (field container "name"))
              do (loop for env across (or (field container "env") #())
                       do (reference "Secret" (field env "valueFrom" "secretKeyRef")
                                     "name" location)
                          (reference "ConfigMap" (field env "valueFrom" "configMapKeyRef")
                                     "name" location))
                 (loop for env across (or (field container "envFrom") #())
                       do (reference "Secret" (field env "secretRef") "name" location)
                          (reference "ConfigMap" (field env "configMapRef") "name" location))))
      (loop for volume across (or (field pod "spec" "volumes") #())
            for location = (format nil "volume/~A" (field volume "name"))
            do (reference "Secret" (field volume "secret") "secretName" location
                          (field volume "secret" "items"))
               (reference "ConfigMap" (field volume "configMap") "name" location
                          (field volume "configMap" "items"))
               (loop for source across (or (field volume "projected" "sources") #())
                     do (reference "Secret" (field source "secret") "name" location
                                   (field source "secret" "items"))
                        (reference "ConfigMap" (field source "configMap") "name" location
                                   (field source "configMap" "items")))))
    (when (> (length refs) 128) (error "More than 128 required reference checks."))
    (remove-duplicates (nreverse refs) :test #'equal)))

(defun explain (answer)
  "A finding from one answer of missing/6 in rules/references.pl."
  (destructuring-bind (what kind ns name details evidence) answer
    (let ((key (and (equal what "key") (first details)))
          (location (car (last details))))
      (object
       "code" (if key "missing-key" "missing-resource")
       "severity" "warning"
       "subject" (format nil "~A/~A/~A" kind ns name)
       "detailKey" (format nil "~:[MISSING-RESOURCE~;MISSING-KEY~]/~@[~A~]" key key)
       "summary"
       (if key
           (format nil "~A requires key ~S in ~A ~A/~A, but that key is absent." location key kind ns name)
           (format nil "~A requires ~A ~A/~A, which was not found." location kind ns name))
       "groupSummary" (if key
                          (format nil "Required key ~S is absent from ~A ~A/~A." key kind ns name)
                          (format nil "Required ~A ~A/~A was not found." kind ns name))
       "nextStep" "Provision the required configuration or correct the Pod template reference."
       "evidence" (coerce evidence 'vector)))))

(defun diagnose-pod (name namespace getter)
  "GETTER returns OBJECT and :PRESENT, :ABSENT or :UNKNOWN. Never retain values."
  (let ((facts nil) (evidence nil) (unknown nil)
        (cache (make-hash-table :test #'equal)) (findings nil) (ref-count 0))
    (labels ((observe (kind ns resource state value)
               (let ((id (format nil "e~D" (1+ (length evidence)))))
                 (push (object "id" id "kind" kind "namespace" ns "name" resource
                               "observedAt" (timestamp)
                               "result" (string-downcase (symbol-name state))
                               "uid" (field value "metadata" "uid")
                               "resourceVersion" (field value "metadata" "resourceVersion"))
                       evidence)
                 id))
             (fetch (kind ns resource)
               (or (gethash (list kind ns resource) cache)
                   (multiple-value-bind (value state) (funcall getter kind ns resource)
                     (let* ((id (observe kind ns resource state value))
                            ;; Preserve key names only; never put values into facts or reports.
                            (keys (when (eq state :present)
                                    (loop for section in '("data" "binaryData")
                                          append (let ((table (field value section)))
                                                   (when (hash-table-p table)
                                                     (loop for key being the hash-keys of table
                                                           collect (cons section key))))))))
                       (when (eq state :unknown) (push id unknown))
                       (setf (gethash (list kind ns resource) cache) (list state keys id)))))))
      (multiple-value-bind (pod state) (funcall getter "Pod" namespace name)
        (let ((pod-evidence (observe "Pod" namespace name state pod)))
          (if (not (eq state :present))
              (push pod-evidence unknown)
              (progn
                (unless (and (equal name (field pod "metadata" "name"))
                             (equal namespace (field pod "metadata" "namespace"))
                             (stringp (field pod "metadata" "uid")))
                  (error "Pod response identity does not match requested target."))
                (let ((refs (references pod)))
                  (setf ref-count (length refs))
                  (dolist (ref refs)
                    (destructuring-bind (kind resource key location domain) ref
                      ;; A reference to a whole object names no key.
                      (push (list 'required (field pod "metadata" "uid") location
                                  kind namespace resource (or key 'none) domain pod-evidence)
                            facts)
                      (destructuring-bind (lookup-state keys lookup-evidence)
                          (fetch kind namespace resource)
                        (case lookup-state
                          (:absent
                           ;; One absence fact per object, even with multiple references.
                           (when (not (member (list kind namespace resource) (gethash :absent cache)
                                              :test #'equal))
                             (push (list kind namespace resource) (gethash :absent cache))
                             (push (list 'absent kind namespace resource lookup-evidence) facts)))
                          (:present
                           (when (and key (not (some (lambda (entry)
                                          (and (equal key (cdr entry))
                                               (or (eq domain :volume)
                                                   (equal "data" (car entry))))) keys)))
                             (let ((fact (list 'key_absent kind namespace resource key domain lookup-evidence)))
                               (unless (member fact (gethash :missing-keys cache) :test #'equal)
                                 (push fact (gethash :missing-keys cache))
                                 (push fact facts)))))))))
                (setf findings
                      (append (mapcar #'explain
                                      (prove (reverse facts)
                                             '((missing ?what ?kind ?namespace ?name ?details ?proof))
                                             '(?what ?kind ?namespace ?name ?details ?proof)))
                              (readiness-findings pod namespace pod-evidence)
                              (catalog-findings pod "Pod" pod-evidence))))
                ;; Do not attach old observations to a replaced or changed Pod.
                (multiple-value-bind (after after-state) (funcall getter "Pod" namespace name)
                  (unless (and (eq after-state :present)
                               (equal (field pod "metadata" "uid") (field after "metadata" "uid"))
                               (equal (field pod "metadata" "resourceVersion")
                                      (field after "metadata" "resourceVersion")))
                    (setf findings nil)
                    (push (observe "Pod" namespace name :changed-during-collection nil) unknown)))))))
      (object "target" (format nil "Pod/~A/~A" namespace name)
              "status" (cond (unknown "incomplete") (findings "findings") (t "no-findings"))
              "scope" "Required configuration references and selected Pod status rules; no finding is not a health verdict."
              "checks" ref-count "findings" (coerce findings 'vector)
              "unknownEvidence" (coerce (nreverse unknown) 'vector)
              "evidence" (coerce (nreverse evidence) 'vector)))))

(defun safe-text (text)
  "Prevent control sequences from API strings being interpreted by a terminal."
  (with-output-to-string (out)
    (loop for character across (or text "")
          do (if (or (< (char-code character) 32) (<= 127 (char-code character) 159))
                 (format out "\\u~4,'0X" (char-code character))
                 (write-char character out)))))

(defun print-report (report &optional (stream *standard-output*))
  (format stream "~A — ~A~%" (safe-text (gethash "target" report)) (gethash "status" report))
  (loop for finding across (gethash "findings" report)
        do (format stream "~%~A~%  Next: ~A~%  Evidence: ~{~A~^, ~}~%"
                   (safe-text (gethash "summary" finding)) (gethash "nextStep" finding)
                   (coerce (gethash "evidence" finding) 'list)))
  (unless (plusp (length (gethash "findings" report)))
    (format stream "No findings were established by the selected diagnostic rules.~%"))
  (loop for id across (gethash "unknownEvidence" report)
        for observation = (find id (gethash "evidence" report) :test #'equal
                                :key (lambda (e) (gethash "id" e)))
        do (format stream "Could not complete check of ~A ~A/~A (~A; evidence ~A).~%"
                   (gethash "kind" observation) (safe-text (gethash "namespace" observation))
                   (safe-text (gethash "name" observation)) (gethash "result" observation) id))
  (format stream "~%~A~%" (gethash "scope" report)))

(defun kubectl-getter (kubeconfig context)
  "Read through kubectl. A NIL KUBECONFIG leaves kubectl its own default configuration.
Kind PreviousLog with name POD/CONTAINER reads the last lines of that
container's previous run, as an object with a text field. Kind MemberView with
name HOST:PORT reads Namespace default through that one API server."
  (lambda (kind namespace name)
    (handler-case
        (let* ((log (equal kind "PreviousLog"))
               (member (equal kind "MemberView"))
               (slash (and log (position #\/ name)))
               (process
                 (uiop:launch-program
                  (append (list "kubectl" "--request-timeout=10s")
                          (when kubeconfig (list "--kubeconfig" kubeconfig))
                          (when context (list "--context" context))
                          (cond
                            (log (list "logs" (subseq name 0 slash) "-c" (subseq name (1+ slash))
                                       "--previous" "--tail=40" "--namespace" namespace))
                            (member (list "--server" (format nil "https://~A" name)
                                          "get" "namespace" "default" "-o" "json"))
                            (t (append (list "get" (string-downcase kind))
                                      (when name (list name "--ignore-not-found"))
                                      (when (namespaced-kind-p kind)
                                        (if namespace (list "--namespace" namespace) (list "--all-namespaces")))
                                      (list "-o" "json")))))
                  :output :stream :error-output nil)))
          (unwind-protect
               (sb-ext:with-timeout 15
                 (let ((text
                         (with-output-to-string (out)
                           (loop for character = (read-char (uiop:process-info-output process) nil nil)
                                 for size from 0 while character
                                 do (when (>= size (* 8 1024 1024)) (error "Response too large."))
                                    (write-char character out)))))
                   (cond ((not (zerop (uiop:wait-process process))) (values nil :unknown))
                         ((zerop (length (string-trim '(#\Space #\Tab #\Newline #\Return) text)))
                          (values nil :absent))
                         (log (values (object "text" text) :present))
                         (t (values (com.inuoe.jzon:parse text) :present)))))
            (when (uiop:process-alive-p process) (uiop:terminate-process process :urgent t))
            (uiop:wait-process process)
            (uiop:close-streams process)))
      (sb-ext:timeout () (values nil :unknown))
      (error () (values nil :unknown)))))

(defun main (arguments)
  (handler-case
      (let ((kind "Pod") (name nil) (namespace "default") (kubeconfig nil) (context nil) (json nil))
        (labels ((value (flag)
                   (or (pop arguments) (error "Missing value for ~A" flag))))
          (loop while arguments for arg = (pop arguments)
                do (cond ((equal arg "--kubeconfig") (setf kubeconfig (value arg)))
                         ((equal arg "--context") (setf context (value arg)))
                         ((member arg '("-n" "--namespace") :test #'equal)
                          (setf namespace (value arg)))
                         ((equal arg "--json") (setf json t))
                         ((and (not name) (position #\/ arg))
                          (let* ((slash (position #\/ arg))
                                 (match (assoc (subseq arg 0 slash) *target-kinds* :test #'equal)))
                            (unless match (error "Unsupported resource kind."))
                            (setf kind (cdr match) name (subseq arg (1+ slash)))))
                         (t (error "Usage: gr8s-diagnose KIND/NAME [--kubeconfig FILE] [-n NAMESPACE] [--context NAME] [--json]")))))
        (unless (and name (plusp (length name))
                     (alphanumericp (char name 0))
                     (every (lambda (c) (or (find c "abcdefghijklmnopqrstuvwxyz0123456789-.") nil)) name)
                     (plusp (length namespace))
                     (every (lambda (c) (find c "abcdefghijklmnopqrstuvwxyz0123456789-")) namespace))
          (error "Specify a KIND/NAME target."))
        (let ((report (diagnose-resource kind name namespace (kubectl-getter kubeconfig context))))
          (if json (progn (com.inuoe.jzon:stringify report :stream *standard-output*) (terpri))
              (print-report report))
          (cond ((equal "incomplete" (gethash "status" report)) 2)
                ((plusp (length (gethash "findings" report))) 1)
                (t 0))))
    (error (condition)
      (format *error-output* "Diagnosis failed: ~A~%" condition)
      2)))
