;;;; SPDX-License-Identifier: MIT
(in-package #:gr8s-diagnose)

(defparameter *checkup-kinds*
  '("Node" "Namespace" "Pod" "Deployment" "ReplicaSet" "StatefulSet" "DaemonSet"
    "Job" "CronJob" "PersistentVolumeClaim" "PersistentVolume" "Service"
    "EndpointSlice" "HorizontalPodAutoscaler" "CertificateSigningRequest" "PodDisruptionBudget"))

(defun doctor-help (&optional (stream *standard-output*))
  (format stream "gr8s doctor — evidence-backed diagnostics~%
  diagnose [KIND/NAME] [-n NAMESPACE] [--kubeconfig FILE] [--context NAME] [--notes] [--markdown | --json]
  impact KIND/NAME [-n NAMESPACE] [--kubeconfig FILE] [--context NAME] [--json]
  host [--state-directory DIR] [--cluster-pod-cidr CIDR] [--fix]~%
Diagnose with no target surveys everything you can see, or one namespace with -n,
and reports the causes it finds with what each one explains. With KIND/NAME it
reports on that resource, what it depends on and what depends on it. It only reads.
What cannot be read is reported as incomplete. Configuration notes need --notes.
The report is wrapped and styled for a terminal and plain for a pipe; --markdown
writes it as Markdown.
Impact says what would stop working if a node, workload, Secret, ConfigMap or
claim went away. Without --kubeconfig, kubectl uses its own default configuration.
Checkup is an alias for diagnose without a target. Host retains the local host checks.~%"))

(defun resource-target (kind ns name)
  (if (namespaced-kind-p kind) (format nil "~A/~A/~A" kind ns name)
      (format nil "~A/~A" kind name)))

(defun resource-links (resource kind ns)
  "Named dependencies only; owner UID guards against replacements with the same name."
  (let ((links nil))
    (labels ((link (kind name &optional uid)
               (when (and (stringp name) (plusp (length name)))
                 (push (list kind (if (namespaced-kind-p kind) ns nil) name uid) links))))
      (loop for owner across (or (field resource "metadata" "ownerReferences") #())
            for owner-kind = (field owner "kind")
            when (member owner-kind '("ReplicaSet" "Deployment" "StatefulSet" "DaemonSet" "Job" "CronJob") :test #'equal)
              do (link owner-kind (field owner "name") (field owner "uid")))
      (when (equal kind "Pod")
        (link "Node" (field resource "spec" "nodeName"))
        (link "ServiceAccount" (field resource "spec" "serviceAccountName"))
        (link "RuntimeClass" (field resource "spec" "runtimeClassName"))
        (loop for volume across (or (field resource "spec" "volumes") #())
              do (link "PersistentVolumeClaim" (field volume "persistentVolumeClaim" "claimName"))))
      (when (equal kind "PersistentVolumeClaim")
        (link "PersistentVolume" (field resource "spec" "volumeName"))
        (link "StorageClass" (field resource "spec" "storageClassName")))
      (when (equal kind "PersistentVolume")
        (link "StorageClass" (field resource "spec" "storageClassName"))))
    (remove-duplicates (nreverse links) :test #'equal)))

(defun diagnose-tree-entry (kind name ns getter)
  "Contain evaluation failures to one resource, without copying response text into errors."
  (handler-case
      (let ((observed nil))
        (let ((report (diagnose-resource kind name ns
                        (lambda (k n resource-name)
                          (multiple-value-bind (value state) (funcall getter k n resource-name)
                            (when (and (equal k kind) (equal n ns) (equal resource-name name))
                              (setf observed value))
                            (values value state))))))
          (augment-causal-report report observed kind ns getter)
          (augment-pod-events report observed kind ns getter)
          (augment-pod-placement report observed kind getter)
          (list report observed (resource-links observed kind ns))))
    (error (condition)
      (list (object "target" (resource-target kind ns name) "status" "incomplete"
                    "scope" "Resource evaluation failed; no health conclusion is available for this resource."
                    "findings" #() "unknownEvidence" #("x1")
                    "evidence" (vector (object "id" "x1" "kind" kind "namespace" ns "name" name
                                               "observedAt" (timestamp) "result" "diagnosis-error"
                                               "errorClass" (string (type-of condition)))))
            nil nil))))

(defun diagnose-tree (kind name namespace getter &optional (cache (make-hash-table :test #'equal)))
  "Return reports and limit warnings. Shared report cache holds observations from this run."
  (let ((queue (list (list kind namespace name nil))) (seen nil) (reports nil) (warnings nil))
    (loop while queue
          for link = (pop queue)
          do (destructuring-bind (current-kind ns current-name expected-uid) link
               (let ((key (list current-kind ns current-name)))
                 (unless (member key seen :test #'equal)
                   (when (>= (length seen) 64)
                     (push "Dependency traversal stopped at 64 resources." warnings)
                     (return))
                   (push key seen)
                   (let* ((entry
                            (or (gethash key cache)
                                (setf (gethash key cache)
                                      (diagnose-tree-entry current-kind current-name ns getter))))
                          (report (first entry)) (resource (second entry)))
                     (if (and expected-uid (not (equal expected-uid (field resource "metadata" "uid"))))
                         (push (format nil "Owner identity changed or could not be verified: ~A."
                                       (resource-target current-kind ns current-name)) warnings)
                         (progn
                           (push report reports)
                           (when (and (plusp (length (gethash "evidence" report)))
                                      (equal "present" (gethash "result" (aref (gethash "evidence" report) 0)))
                                      (not (find "changed-during-collection" (gethash "evidence" report)
                                                 :test #'equal :key (lambda (e) (gethash "result" e)))))
                             (setf queue (append queue (third entry)))))))))))
    (values (nreverse reports) (nreverse warnings))))

(defun grouped-findings (origins)
  "ORIGINS contains (root-target . reports); group only identical subjects and findings."
  (let ((groups (make-hash-table :test #'equal)))
    (dolist (origin origins)
      (dolist (report (cdr origin))
        (loop for finding across (gethash "findings" report)
              for subject = (or (gethash "subject" finding) (gethash "target" report))
              for key = (list (gethash "code" finding) subject
                             (or (gethash "detailKey" finding) (gethash "summary" finding)))
              do (let ((group (or (gethash key groups)
                                 (setf (gethash key groups)
                                       (object "rule" (gethash "code" finding) "subject" subject
                                               "severity" (or (gethash "severity" finding) "warning")
                                               "summary" (or (gethash "groupSummary" finding) (gethash "summary" finding))
                                               "nextStep" (gethash "nextStep" finding)
                                               "commands" (or (gethash "commands" finding) #())
                                               "detailHeading" (gethash "detailHeading" finding)
                                               "detail" (gethash "detail" finding)
                                               "affectedTargets" nil "evidence" nil)))))
                   (pushnew (car origin) (gethash "affectedTargets" group) :test #'equal)
                   (loop for id across (gethash "evidence" finding)
                         for observation = (find id (gethash "evidence" report) :test #'equal
                                                 :key (lambda (e) (gethash "id" e)))
                         when observation do
                           (let ((proof (object "target" (gethash "target" report) "observation" observation)))
                             (pushnew proof (gethash "evidence" group) :test #'equalp)))))))
    (coerce
     (sort (loop for group being the hash-values of groups
                 do (setf (gethash "affectedTargets" group)
                          (coerce (sort (gethash "affectedTargets" group) #'string<) 'vector)
                          (gethash "evidence" group) (coerce (gethash "evidence" group) 'vector))
                 collect group)
           #'string< :key (lambda (g) (format nil "~D/~A/~A/~A" (if (equal "warning" (gethash "severity" g)) 0 1) (gethash "subject" g)
                                             (gethash "rule" g) (gethash "summary" g)))) 'vector)))

(defun reuse-list-observations (getter &key (max-entries 32) (max-items 200))
  "Reuse bounded LIST responses within one survey; named GETs always reach GETTER.
The third return value records the original collection time, including cache hits."
  (let ((cache (make-hash-table :test #'equal)))
    (lambda (kind ns name)
      (if name
          (funcall getter kind ns name)
          (let* ((key (list kind ns)) (cached (gethash key cache)))
            (if cached (values-list cached)
                (multiple-value-bind (resource state observed-at) (funcall getter kind ns nil)
                  (let ((answer (list resource state (or observed-at (timestamp))))
                        (items (field resource "items")))
                    (when (and (< (hash-table-count cache) max-entries)
                               (or (and (null resource) (not (eq state :present)))
                                   (and (json-array-p items) (<= (length items) max-items))))
                      (setf (gethash key cache) answer))
                    (values-list answer)))))))))

(defun plain-target (target)
  "Render Kind/namespace/name or Kind/name as words."
  (let ((parts (uiop:split-string (or target "") :separator "/")))
    (flet ((kind (word)
             (if (and (plusp (length word)) (lower-case-p (char word 0))) (string-capitalize word) word)))
      (case (length parts)
        (3 (format nil "~A ~A in namespace ~A" (kind (first parts)) (third parts) (second parts)))
        (2 (format nil "~A ~A" (kind (first parts)) (second parts)))
        (t (or target ""))))))

(defun bounded-getter (getter &key (max-requests 500) (seconds 120))
  "Stop starting API requests when the run budget is exhausted; remaining reads are unknown."
  (let ((requests 0) (deadline (+ (get-internal-real-time) (* seconds internal-time-units-per-second))))
    (lambda (kind ns name)
      (if (or (>= requests max-requests) (>= (get-internal-real-time) deadline))
          (values nil :unknown)
          (progn (incf requests) (funcall getter kind ns name))))))

(defun doctor-main (arguments)
  (handler-case
      (let ((command (pop arguments)) (namespace nil) (kubeconfig nil) (context nil) (json nil) (target nil)
            (notes nil) (markdown nil))
        (when (or (null command) (member command '("--help" "-h" "help") :test #'equal))
          (doctor-help) (return-from doctor-main 0))
        (unless (member command '("diagnose" "checkup" "impact") :test #'equal)
          (error "Expected diagnose or impact; use gr8s doctor host for host checks."))
        (when (member "--help" arguments :test #'equal) (doctor-help) (return-from doctor-main 0))
        (labels ((value (flag) (or (pop arguments) (error "Missing value for ~A" flag))))
          (loop while arguments for arg = (pop arguments)
                do (cond ((equal arg "--kubeconfig") (setf kubeconfig (value arg)))
                         ((equal arg "--context") (setf context (value arg)))
                         ((member arg '("-n" "--namespace") :test #'equal) (setf namespace (value arg)))
                         ((equal arg "--json") (setf json t))
                         ((equal arg "--notes") (setf notes t))
                         ((equal arg "--markdown") (setf markdown t))
                         ((and (member command '("diagnose" "impact") :test #'equal) (null target) (position #\/ arg))
                          (setf target arg))
                         (t (error "Unknown doctor argument: ~A" arg)))))
        (when (and namespace (or (zerop (length namespace))
                                 (> (length namespace) 63)
                                 (not (alphanumericp (char namespace 0)))
                                 (not (every (lambda (c) (find c "abcdefghijklmnopqrstuvwxyz0123456789-")) namespace))))
          (error "Invalid namespace."))
        (when (equal command "impact")
          (unless target (error "Specify the KIND/NAME whose loss to consider."))
          (let ((report (call-with-progress
                         (lambda ()
                           (impact-target target namespace (bounded-getter (kubectl-getter kubeconfig context)))))))
            (if json (progn (com.inuoe.jzon:stringify report :stream *standard-output*) (terpri))
                (print-impact report))
            (return-from doctor-main (if (equal "incomplete" (gethash "status" report)) 2 0))))
        (let* ((getter (bounded-getter (kubectl-getter kubeconfig context)))
               (report (call-with-progress
                        (lambda ()
                          (if target (diagnose-target target namespace getter) (checkup namespace getter))))))
          (if json (progn (com.inuoe.jzon:stringify report :stream *standard-output*) (terpri))
              (print-survey report :notes notes :markdown markdown))
          (cond ((equal "incomplete" (gethash "status" report)) 2)
                ((plusp (length (gethash "problems" report))) 1) (t 0))))
    (error (condition) (format *error-output* "Doctor failed: ~A~%" condition) 2)))

(defun impact-target (target namespace getter)
  "The impact report for KIND/NAME. A Secret or ConfigMap is named, never read."
  (let* ((slash (position #\/ target))
         (kind (cdr (assoc (subseq target 0 slash)
                           (append '(("secret" . "Secret") ("configmap" . "ConfigMap")) *target-kinds*)
                           :test #'equal)))
         (name (subseq target (1+ slash))))
    (unless (and kind (plusp (length name)) (alphanumericp (char name 0))
                 (every (lambda (c) (find c "abcdefghijklmnopqrstuvwxyz0123456789-.")) name))
      (error "Specify a supported KIND/NAME target."))
    (impact-report kind name (when (namespaced-kind-p kind) (or namespace "default")) getter)))

(defun diagnose-target (target namespace getter)
  "Report on one KIND/NAME within a survey of its namespace, or of the cluster
for a cluster-scoped kind. A target that cannot be read is reported alone."
  (let* ((slash (position #\/ target))
         (kind (cdr (assoc (subseq target 0 slash) *target-kinds* :test #'equal)))
         (name (subseq target (1+ slash))))
    (unless (and kind (plusp (length name)) (alphanumericp (char name 0))
                 (every (lambda (c) (find c "abcdefghijklmnopqrstuvwxyz0123456789-.")) name))
      (error "Specify a supported KIND/NAME target."))
    (let ((ns (when (namespaced-kind-p kind) (or namespace "default"))))
      (multiple-value-bind (resource state) (funcall getter kind ns name)
        (if (eq state :present)
            (checkup ns getter :target (list kind ns name))
            (multiple-value-bind (reports notes)
                (diagnose-tree kind name ns
                               (lambda (k n resource-name)
                                 (if (equal (list k n resource-name) (list kind ns name))
                                     (values resource state)
                                     (funcall getter k n resource-name))))
              (survey-report (resource-target kind ns name)
                             (list (cons (resource-target kind ns name) reports)) notes nil)))))))

(defun doctor-command-route (arguments)
  "Native parser hook. NIL retains the legacy host option parser."
  (cond ((or (null arguments) (member (first arguments) '("--help" "-h" "help") :test #'equal))
         (list :command :doctor-cluster :arguments nil))
        ((member (first arguments) '("diagnose" "checkup" "impact") :test #'equal)
         (list :command :doctor-cluster :arguments arguments))))
