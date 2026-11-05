;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Answer clients asking for meta.k8s.io Table or PartialObjectMetadata. Common
;;;; kinds print upstream's columns, custom resources print their declared
;;;; additionalPrinterColumns, and every other object gets Name and Created At.

(in-package #:gr8s)

(defvar *table-request* nil
  "The representation this request negotiated: :table, :partial, :refuse (only forms not offered here) or NIL.")
(defvar *table-api-version* "meta.k8s.io/v1" "The meta.k8s.io version the client asked for.")
(defvar *table-send-columns* t "Whether this Table still carries column definitions, which a watch sends once.")

(defun negotiate-table-request ()
  "Read the Accept header, honoring its order, into *TABLE-REQUEST* and *TABLE-API-VERSION* values."
  (let ((refused nil))
    (dolist (parts (accept-media-ranges) (values (and refused :refuse) "meta.k8s.io/v1"))
      (let* ((media (first parts))
             (json (member media '("application/json" "*/*" "application/*") :test #'equal))
             (form (find-if (lambda (part) (uiop:string-prefix-p "as=" part)) (rest parts)))
             (group (find-if (lambda (part) (uiop:string-prefix-p "g=" part)) (rest parts)))
             (version (find-if (lambda (part) (uiop:string-prefix-p "v=" part)) (rest parts))))
        (cond
          ((null form) (return (values nil "meta.k8s.io/v1")))
          ((and json (equal group "g=meta.k8s.io") (member version '("v=v1" "v=v1beta1") :test #'equal)
                (member form '("as=Table" "as=PartialObjectMetadata" "as=PartialObjectMetadataList") :test #'equal))
           (return (values (if (equal form "as=Table") :table :partial)
                           (format nil "meta.k8s.io/~A" (subseq version 2)))))
          ((member form '("as=Table" "as=PartialObjectMetadata" "as=PartialObjectMetadataList") :test #'equal)
           (setf refused t)))))))

;;; Cells

(defun table-human-duration (seconds)
  "Print a duration as kubectl does: 5s, 3m20s, 4h, 2d3h, 4y12d."
  (cond
    ((< seconds -1) "<invalid>")
    ((< seconds 0) "0s")
    ((< seconds 120) (format nil "~Ds" seconds))
    ((< seconds 600)
     (multiple-value-bind (minutes rest) (floor seconds 60)
       (if (zerop rest) (format nil "~Dm" minutes) (format nil "~Dm~Ds" minutes rest))))
    ((< seconds 3600) (format nil "~Dm" (floor seconds 60)))
    ((< seconds (* 8 3600))
     (multiple-value-bind (hours rest) (floor seconds 3600)
       (if (< rest 60) (format nil "~Dh" hours) (format nil "~Dh~Dm" hours (floor rest 60)))))
    ((< seconds (* 48 3600)) (format nil "~Dh" (floor seconds 3600)))
    ((< seconds (* 8 86400))
     (multiple-value-bind (days rest) (floor seconds 86400)
       (if (< rest 3600) (format nil "~Dd" days) (format nil "~Dd~Dh" days (floor rest 3600)))))
    ((< seconds (* 2 365 86400)) (format nil "~Dd" (floor seconds 86400)))
    ((< seconds (* 8 365 86400))
     (multiple-value-bind (years rest) (floor seconds (* 365 86400))
       (if (< rest 86400) (format nil "~Dy" years) (format nil "~Dy~Dd" years (floor rest 86400)))))
    (t (format nil "~Dy" (floor seconds (* 365 86400))))))

(defun table-timestamp-age (timestamp)
  "Print the time since an RFC 3339 TIMESTAMP, as translateTimestampSince does."
  (let ((nanos (and (stringp timestamp) (cel-parse-rfc3339 timestamp))))
    (if nanos
        (table-human-duration (- (- (get-universal-time) #.(encode-universal-time 0 0 0 1 1 1970 0))
                                 (floor nanos 1000000000)))
        "<unknown>")))

(defun table-get (object &rest path)
  "Walk PATH through nested objects, giving NIL for anything absent."
  (let ((value object))
    (dolist (key path value)
      (setf value (and (hash-table-p value) (let ((next (gethash key value))) (if (eq next 'null) nil next)))))))

(defun table-age (object)
  "Print OBJECT's age."
  (table-timestamp-age (table-get object "metadata" "creationTimestamp")))

(defun table-or-none (value)
  "Print an empty value as <none>."
  (if (or (null value) (equal value "")) "<none>" value))

(defun table-list (items &optional (limit 3))
  "Join strings as kubectl's listWithMoreString does, naming only the first few."
  (let* ((items (coerce (or items #()) 'list)) (count (length items)))
    (cond ((zerop count) "<none>")
          ((> count limit) (format nil "~{~A~^,~} + ~D more..." (subseq items 0 limit) (- count limit)))
          (t (format nil "~{~A~^,~}" items)))))

(defun table-join (items)
  "Join a sequence with commas."
  (format nil "~{~A~^,~}" (coerce (or items #()) 'list)))

(defun table-map-text (map)
  "Print a string map as sorted k=v pairs, as labels.FormatLabels does."
  (if (and (hash-table-p map) (plusp (hash-table-count map)))
      (format nil "~{~A~^,~}"
              (sort (loop for key being the hash-keys of map using (hash-value value)
                          collect (format nil "~A=~A" key value))
                    #'string<))
      "<none>"))

(defun table-selector-text (selector)
  "Print a LabelSelector."
  (cond
    ((not (hash-table-p selector)) "<none>")
    (t
     (let ((terms (append
                   (let ((labels (gethash "matchLabels" selector)))
                     (and (hash-table-p labels)
                          (sort (loop for key being the hash-keys of labels using (hash-value value)
                                      collect (format nil "~A=~A" key value))
                                #'string<)))
                   (loop for expression across (or (let ((value (gethash "matchExpressions" selector)))
                                                     (and (crd-array-p value) value))
                                                   #())
                         collect (let ((operator (gethash "operator" expression)) (key (gethash "key" expression))
                                       (values (gethash "values" expression #())))
                                   (cond ((equal operator "Exists") key)
                                         ((equal operator "DoesNotExist") (format nil "!~A" key))
                                         (t (format nil "~A ~(~A~) (~{~A~^,~})" key operator (coerce values 'list)))))))))
       (if terms (format nil "~{~A~^,~}" terms) "<none>")))))

(defun table-template-containers (spec)
  "Name a Pod spec's containers."
  (table-join (map 'list (lambda (container) (gethash "name" container)) (or (table-get spec "containers") #()))))

(defun table-template-images (spec)
  "Name a Pod spec's container images."
  (table-join (map 'list (lambda (container) (gethash "image" container)) (or (table-get spec "containers") #()))))

(defun table-workload-wide (object)
  "Return the wide cells a workload shares: containers, images and selector."
  (let ((spec (table-get object "spec" "template" "spec")))
    (list (table-template-containers spec) (table-template-images spec)
          (table-selector-text (table-get object "spec" "selector")))))

(defun table-count (object &rest path)
  "Read an integer field defaulting to 0."
  (or (apply #'table-get object path) 0))

(defun table-condition (object type)
  "Find the condition TYPE in OBJECT's status."
  (find type (or (table-get object "status" "conditions") #())
        :test #'equal :key (lambda (condition) (gethash "type" condition))))

;;; Pod status as kubectl shows it

(defun table-init-container-status (object position reason)
  "Apply one init container status to REASON, giving the new reason and whether it blocks."
  (let* ((container (aref (table-get object "status" "initContainerStatuses") position))
         (terminated (table-get container "state" "terminated"))
         (waiting (table-get container "state" "waiting"))
         (declared (find (gethash "name" container) (or (table-get object "spec" "initContainers") #())
                         :test #'equal :key (lambda (entry) (gethash "name" entry))))
         (restartable (and declared (equal "Always" (gethash "restartPolicy" declared)))))
    (cond
      ((and terminated (eql 0 (gethash "exitCode" terminated))) (values reason nil))
      ((and restartable (eq t (gethash "started" container))) (values reason nil))
      (terminated
       (let ((why (gethash "reason" terminated)))
         (values (cond ((and (stringp why) (plusp (length why))) (format nil "Init:~A" why))
                       ((plusp (or (gethash "signal" terminated) 0)) (format nil "Init:Signal:~D" (gethash "signal" terminated)))
                       (t (format nil "Init:ExitCode:~D" (gethash "exitCode" terminated))))
                 t)))
      ((and waiting (plusp (length (or (gethash "reason" waiting) ""))) (not (equal "PodInitializing" (gethash "reason" waiting))))
       (values (format nil "Init:~A" (gethash "reason" waiting)) t))
      (t (values (format nil "Init:~D/~D" position (length (or (table-get object "spec" "initContainers") #()))) t)))))

(defun table-pod-row (object)
  "Compute a Pod's Ready, Status and Restarts cells, as printPod does."
  (let* ((phase (table-get object "status" "phase"))
         (status-reason (table-get object "status" "reason"))
         (reason (or (and (plusp (length (or status-reason ""))) status-reason) phase ""))
         (statuses (or (table-get object "status" "containerStatuses") #()))
         (init-statuses (or (table-get object "status" "initContainerStatuses") #()))
         (init-declared (or (table-get object "spec" "initContainers") #()))
         (total (+ (length (or (table-get object "spec" "containers") #()))
                   (count "Always" init-declared :test #'equal :key (lambda (entry) (gethash "restartPolicy" entry)))))
         (ready 0) (restarts 0) (last-restart nil) (initializing nil))
    (flet ((note-restart (container)
             (let ((finished (table-get container "lastState" "terminated" "finishedAt")))
               (when (and finished (or (null last-restart) (string> finished last-restart)))
                 (setf last-restart finished)))))
      (let ((scheduled (table-condition object "PodScheduled")))
        (when (and scheduled (equal "SchedulingGated" (gethash "reason" scheduled)))
          (setf reason "SchedulingGated")))
      (loop for index from 0 below (length init-statuses)
            do (let ((container (aref init-statuses index)))
                 (incf restarts (or (gethash "restartCount" container) 0))
                 (note-restart container)
                 (multiple-value-bind (next blocking) (table-init-container-status object index reason)
                   (setf reason next)
                   (when blocking (setf initializing t) (return)))))
      (let ((initialized (table-condition object "Initialized")))
        (when (or (not initializing) (and initialized (equal "True" (gethash "status" initialized))))
          (setf restarts 0 last-restart nil)
          (loop for entry across init-statuses
                for declared = (find (gethash "name" entry) init-declared :test #'equal
                                     :key (lambda (item) (gethash "name" item)))
                do (when (and declared (equal "Always" (gethash "restartPolicy" declared)))
                     (incf restarts (or (gethash "restartCount" entry) 0))
                     (note-restart entry)
                     (when (and (eq t (gethash "started" entry)) (eq t (gethash "ready" entry))) (incf ready))))
          (let ((running nil) (failure nil))
            (loop for index from (1- (length statuses)) downto 0
                  do (let* ((container (aref statuses index))
                            (waiting (table-get container "state" "waiting"))
                            (terminated (table-get container "state" "terminated")))
                       (incf restarts (or (gethash "restartCount" container) 0))
                       (note-restart container)
                       (cond
                         ((and waiting (plusp (length (or (gethash "reason" waiting) ""))))
                          (setf reason (gethash "reason" waiting)))
                         (terminated
                          (let ((why (gethash "reason" terminated)))
                            (setf reason (cond ((and (stringp why) (plusp (length why))) why)
                                               ((plusp (or (gethash "signal" terminated) 0))
                                                (format nil "Signal:~D" (gethash "signal" terminated)))
                                               (t (format nil "ExitCode:~D" (or (gethash "exitCode" terminated) 0))))))
                          (unless (eql 0 (gethash "exitCode" terminated)) (setf failure reason)))
                         ((and (eq t (gethash "ready" container)) (table-get container "state" "running"))
                          (setf running t)
                          (incf ready)))))
            (when (equal reason "Completed")
              (let ((pod-ready (table-condition object "Ready")))
                (cond ((and running pod-ready (equal "True" (gethash "status" pod-ready))) (setf reason "Running"))
                      (failure (setf reason failure))
                      (running (setf reason "NotReady")))))))))
    (when (table-get object "metadata" "deletionTimestamp")
      (cond ((equal status-reason "NodeLost") (setf reason "Unknown"))
            ((not (member phase '("Succeeded" "Failed") :test #'equal)) (setf reason "Terminating"))))
    (values (format nil "~D/~D" ready total) reason
            (if (and (plusp restarts) last-restart)
                (format nil "~D (~A ago)" restarts (table-timestamp-age last-restart))
                (format nil "~D" restarts)))))

(defun table-pod-readiness-gates (object)
  "Print how many of a Pod's readiness gates hold."
  (let ((gates (table-get object "spec" "readinessGates")))
    (if (plusp (length gates))
        (format nil "~D/~D"
                (count-if (lambda (gate)
                            (let ((condition (table-condition object (gethash "conditionType" gate))))
                              (and condition (equal "True" (gethash "status" condition)))))
                          gates)
                (length gates))
        "<none>")))

;;; Column tables. A column is (name type &key format priority), and a row function
;;; turns an object into its cells after the name.

(defparameter +table-column-descriptions+
  '(("Name" . "Name must be unique within a namespace.")
    ("Age" . "CreationTimestamp is a timestamp representing the server time when this object was created.")
    ("Created At" . "CreationTimestamp is a timestamp representing the server time when this object was created."))
  "Descriptions of the columns every kind shares.")

(defvar *table-printers* (make-hash-table :test #'equal) "Column definitions and row functions by kind.")

(defmacro define-table-printer (kind columns (object) &body body)
  "Print KIND with COLUMNS after the Name column; BODY returns the remaining cells as a list."
  `(setf (gethash ,kind *table-printers*)
         (cons ',columns (lambda (,object) (declare (ignorable ,object)) ,@body))))

(define-table-printer "Pod"
    (("Ready" "string") ("Status" "string") ("Restarts" "string") ("Age" "string")
     ("IP" "string" :priority 1) ("Node" "string" :priority 1)
     ("Nominated Node" "string" :priority 1) ("Readiness Gates" "string" :priority 1))
    (object)
  (multiple-value-bind (ready reason restarts) (table-pod-row object)
    (list ready reason restarts (table-age object)
          (table-or-none (or (let ((ips (table-get object "status" "podIPs")))
                               (and (plusp (length ips)) (gethash "ip" (aref ips 0))))
                             (table-get object "status" "podIP")))
          (table-or-none (table-get object "spec" "nodeName"))
          (table-or-none (table-get object "status" "nominatedNodeName"))
          (table-pod-readiness-gates object))))

(define-table-printer "PodTemplate"
    (("Containers" "string") ("Images" "string") ("Pod Labels" "string"))
    (object)
  (let ((spec (table-get object "template" "spec")))
    (list (table-template-containers spec) (table-template-images spec)
          (table-map-text (table-get object "template" "metadata" "labels")))))

(define-table-printer "ReplicationController"
    (("Desired" "integer") ("Current" "integer") ("Ready" "integer") ("Age" "string")
     ("Containers" "string" :priority 1) ("Images" "string" :priority 1) ("Selector" "string" :priority 1))
    (object)
  (let ((spec (table-get object "spec" "template" "spec")))
    (list (table-count object "spec" "replicas") (table-count object "status" "replicas")
          (table-count object "status" "readyReplicas") (table-age object)
          (table-template-containers spec) (table-template-images spec)
          (table-map-text (table-get object "spec" "selector")))))

(define-table-printer "ReplicaSet"
    (("Desired" "integer") ("Current" "integer") ("Ready" "integer") ("Age" "string")
     ("Containers" "string" :priority 1) ("Images" "string" :priority 1) ("Selector" "string" :priority 1))
    (object)
  (list* (table-count object "spec" "replicas") (table-count object "status" "replicas")
         (table-count object "status" "readyReplicas") (table-age object)
         (table-workload-wide object)))

(define-table-printer "Deployment"
    (("Ready" "string") ("Up-to-date" "string") ("Available" "string") ("Age" "string")
     ("Containers" "string" :priority 1) ("Images" "string" :priority 1) ("Selector" "string" :priority 1))
    (object)
  (list* (format nil "~D/~D" (table-count object "status" "readyReplicas") (table-count object "spec" "replicas"))
         (table-count object "status" "updatedReplicas") (table-count object "status" "availableReplicas")
         (table-age object) (table-workload-wide object)))

(define-table-printer "DaemonSet"
    (("Desired" "integer") ("Current" "integer") ("Ready" "integer") ("Up-to-date" "integer")
     ("Available" "integer") ("Node Selector" "string") ("Age" "string")
     ("Containers" "string" :priority 1) ("Images" "string" :priority 1) ("Selector" "string" :priority 1))
    (object)
  (list* (table-count object "status" "desiredNumberScheduled") (table-count object "status" "currentNumberScheduled")
         (table-count object "status" "numberReady") (table-count object "status" "updatedNumberScheduled")
         (table-count object "status" "numberAvailable")
         (table-map-text (table-get object "spec" "template" "spec" "nodeSelector"))
         (table-age object) (table-workload-wide object)))

(define-table-printer "StatefulSet"
    (("Ready" "string") ("Age" "string") ("Containers" "string" :priority 1) ("Images" "string" :priority 1))
    (object)
  (let ((spec (table-get object "spec" "template" "spec")))
    (list (format nil "~D/~D" (table-count object "status" "readyReplicas") (table-count object "spec" "replicas"))
          (table-age object) (table-template-containers spec) (table-template-images spec))))

(define-table-printer "ControllerRevision"
    (("Controller" "string") ("Revision" "integer") ("Age" "string"))
    (object)
  (let ((owner (find-if (lambda (reference) (eq t (gethash "controller" reference)))
                        (or (table-get object "metadata" "ownerReferences") #()))))
    (list (if owner
              (format nil "~(~A~)/~A" (gethash "kind" owner) (gethash "name" owner))
              "<none>")
          (table-count object "revision") (table-age object))))

(defun table-job-status (object)
  "Print a Job's Status column."
  (flet ((holds (type)
           (let ((condition (table-condition object type)))
             (and condition (equal "True" (gethash "status" condition))))))
    (cond ((holds "Failed") "Failed")
          ((holds "Complete") "Complete")
          ((table-get object "metadata" "deletionTimestamp") "Terminating")
          ((holds "FailureTarget") "FailureTarget")
          ((holds "SuccessCriteriaMet") "SuccessCriteriaMet")
          ((table-get object "spec" "suspend") "Suspended")
          (t "Running"))))

(define-table-printer "Job"
    (("Status" "string") ("Completions" "string") ("Duration" "string") ("Age" "string")
     ("Containers" "string" :priority 1) ("Images" "string" :priority 1) ("Selector" "string" :priority 1))
    (object)
  (let* ((completions (table-get object "spec" "completions"))
         (parallelism (table-get object "spec" "parallelism"))
         (succeeded (table-count object "status" "succeeded"))
         (start (table-get object "status" "startTime"))
         (finish (table-get object "status" "completionTime"))
         (spec (table-get object "spec" "template" "spec")))
    (list* (table-job-status object)
           (if (equal "Indexed" (table-get object "spec" "completionMode"))
               (format nil "~D/~D" succeeded (or completions 1))
               (if completions
                   (format nil "~D/~D" succeeded completions)
                   (if (and parallelism (> parallelism 1))
                       (format nil "~D/1 of ~D" succeeded parallelism)
                       (format nil "~D/1" succeeded))))
           (cond ((null start) "")
                 (finish (table-human-duration
                          (floor (- (or (cel-parse-rfc3339 finish) 0) (or (cel-parse-rfc3339 start) 0)) 1000000000)))
                 (t (table-timestamp-age start)))
           (table-age object)
           (list (table-template-containers spec) (table-template-images spec)
                 (table-selector-text (table-get object "spec" "selector"))))))

(define-table-printer "CronJob"
    (("Schedule" "string") ("Timezone" "string") ("Suspend" "boolean") ("Active" "integer")
     ("Last Schedule" "string") ("Age" "string")
     ("Containers" "string" :priority 1) ("Images" "string" :priority 1) ("Selector" "string" :priority 1))
    (object)
  (let ((spec (table-get object "spec" "jobTemplate" "spec" "template" "spec"))
        (last (table-get object "status" "lastScheduleTime")))
    (list (table-get object "spec" "schedule") (table-or-none (table-get object "spec" "timeZone"))
          (and (table-get object "spec" "suspend") t)
          (length (or (table-get object "status" "active") #()))
          (if last (table-timestamp-age last) "<none>")
          (table-age object) (table-template-containers spec) (table-template-images spec)
          (table-selector-text (table-get object "spec" "jobTemplate" "spec" "selector")))))

(defun table-service-ports (object)
  "Print a Service's Port(s) cell."
  (let ((ports (or (table-get object "spec" "ports") #())))
    (if (zerop (length ports))
        "<none>"
        (format nil "~{~A~^,~}"
                (map 'list (lambda (port)
                             (format nil "~D~@[:~D~]/~A" (gethash "port" port)
                                     (let ((node-port (gethash "nodePort" port)))
                                       (and (integerp node-port) (plusp node-port) node-port))
                                     (gethash "protocol" port "TCP")))
                     ports)))))

(defun table-service-external (object)
  "Print a Service's External-IP cell."
  (let ((type (table-get object "spec" "type"))
        (ingress (or (table-get object "status" "loadBalancer" "ingress") #()))
        (external (or (table-get object "spec" "externalIPs") #())))
    (cond
      ((member type '("ClusterIP" "NodePort" nil) :test #'equal)
       (if (plusp (length external)) (table-join external) "<none>"))
      ((equal type "LoadBalancer")
       (let ((addresses (append (map 'list (lambda (entry) (or (gethash "ip" entry) (gethash "hostname" entry))) ingress)
                                (coerce external 'list))))
         (if addresses (table-list addresses) "<pending>")))
      ((equal type "ExternalName") (table-get object "spec" "externalName"))
      (t "<unknown>"))))

(define-table-printer "Service"
    (("Type" "string") ("Cluster-IP" "string") ("External-IP" "string") ("Port(s)" "string") ("Age" "string")
     ("Selector" "string" :priority 1))
    (object)
  (list (or (table-get object "spec" "type") "ClusterIP")
        (table-or-none (table-get object "spec" "clusterIP"))
        (table-service-external object) (table-service-ports object) (table-age object)
        (table-map-text (table-get object "spec" "selector"))))

(define-table-printer "Ingress"
    (("Class" "string") ("Hosts" "string") ("Address" "string") ("Ports" "string") ("Age" "string"))
    (object)
  (let ((hosts (loop for rule across (or (table-get object "spec" "rules") #())
                     collect (or (gethash "host" rule) "*")))
        (addresses (map 'list (lambda (entry) (or (gethash "ip" entry) (gethash "hostname" entry)))
                        (or (table-get object "status" "loadBalancer" "ingress") #()))))
    (list (table-or-none (table-get object "spec" "ingressClassName"))
          (if hosts (table-list hosts) "*")
          (if addresses (table-list addresses) "")
          (if (plusp (length (or (table-get object "spec" "tls") #()))) "80, 443" "80")
          (table-age object))))

(define-table-printer "IngressClass"
    (("Controller" "string") ("Parameters" "string") ("Age" "string"))
    (object)
  (let ((parameters (table-get object "spec" "parameters")))
    (list (table-get object "spec" "controller")
          (if parameters
              (format nil "~@[~A/~]~A/~A" (gethash "apiGroup" parameters) (gethash "kind" parameters) (gethash "name" parameters))
              "<none>")
          (table-age object))))

(define-table-printer "Endpoints"
    (("Endpoints" "string") ("Age" "string"))
    (object)
  (let ((entries (loop for subset across (or (table-get object "subsets") #())
                       nconc (loop for address across (or (gethash "addresses" subset) #())
                                   nconc (if (plusp (length (or (gethash "ports" subset) #())))
                                             (map 'list (lambda (port)
                                                          (format nil "~A:~D" (gethash "ip" address) (gethash "port" port)))
                                                  (gethash "ports" subset))
                                             (list (gethash "ip" address)))))))
    (list (if entries (table-list entries) "<none>") (table-age object))))

(define-table-printer "EndpointSlice"
    (("AddressType" "string") ("Ports" "string") ("Endpoints" "string") ("Age" "string"))
    (object)
  (let ((addresses (loop for endpoint across (or (table-get object "endpoints") #())
                         nconc (coerce (or (gethash "addresses" endpoint) #()) 'list)))
        (ports (map 'list (lambda (port) (gethash "port" port)) (or (table-get object "ports") #()))))
    (list (table-get object "addressType")
          (if ports (table-join ports) "<unset>")
          (if addresses (table-list addresses) "<unset>")
          (table-age object))))

(defun table-node-status (object)
  "Print a Node's Status cell."
  (let* ((ready (table-condition object "Ready"))
         (parts (list (cond ((null ready) "Unknown")
                            ((equal "True" (gethash "status" ready)) "Ready")
                            (t "NotReady")))))
    (when (table-get object "spec" "unschedulable")
      (setf parts (append parts (list "SchedulingDisabled"))))
    (format nil "~{~A~^,~}" parts)))

(defun table-node-roles (object)
  "Print a Node's Roles cell from its role labels."
  (let ((labels (table-get object "metadata" "labels")) (roles nil))
    (when (hash-table-p labels)
      (maphash (lambda (key value)
                 (declare (ignore value))
                 (when (uiop:string-prefix-p "node-role.kubernetes.io/" key)
                   (push (subseq key (length "node-role.kubernetes.io/")) roles)))
               labels))
    (if roles (format nil "~{~A~^,~}" (sort roles #'string<)) "<none>")))

(defun table-node-address (object type)
  "Find a Node address of TYPE."
  (let ((address (find type (or (table-get object "status" "addresses") #())
                       :test #'equal :key (lambda (entry) (gethash "type" entry)))))
    (if address (gethash "address" address) "<none>")))

(define-table-printer "Node"
    (("Status" "string") ("Roles" "string") ("Age" "string") ("Version" "string")
     ("Internal-IP" "string" :priority 1) ("External-IP" "string" :priority 1) ("OS-Image" "string" :priority 1)
     ("Kernel-Version" "string" :priority 1) ("Container-Runtime" "string" :priority 1))
    (object)
  (list (table-node-status object) (table-node-roles object) (table-age object)
        (or (table-get object "status" "nodeInfo" "kubeletVersion") "")
        (table-node-address object "InternalIP") (table-node-address object "ExternalIP")
        (table-or-none (table-get object "status" "nodeInfo" "osImage"))
        (table-or-none (table-get object "status" "nodeInfo" "kernelVersion"))
        (table-or-none (table-get object "status" "nodeInfo" "containerRuntimeVersion"))))

(define-table-printer "Namespace"
    (("Status" "string") ("Age" "string"))
    (object)
  (list (table-get object "status" "phase") (table-age object)))

(define-table-printer "Secret"
    (("Type" "string") ("Data" "string") ("Age" "string"))
    (object)
  (list (table-get object "type")
        (let ((data (table-get object "data"))) (if (hash-table-p data) (hash-table-count data) 0))
        (table-age object)))

(define-table-printer "ConfigMap"
    (("Data" "string") ("Age" "string"))
    (object)
  (list (+ (let ((data (table-get object "data"))) (if (hash-table-p data) (hash-table-count data) 0))
           (let ((data (table-get object "binaryData"))) (if (hash-table-p data) (hash-table-count data) 0)))
        (table-age object)))

(define-table-printer "ServiceAccount"
    (("Secrets" "string") ("Age" "string"))
    (object)
  (list (length (or (table-get object "secrets") #())) (table-age object)))

(defun table-event-source (object)
  "Print an Event's Source cell."
  (let ((component (or (table-get object "source" "component") (table-get object "reportingComponent") ""))
        (host (table-get object "source" "host")))
    (if (and host (plusp (length host))) (format nil "~A, ~A" component host) component)))

(define-table-printer "Event"
    (("Last Seen" "string") ("Type" "string") ("Reason" "string") ("Object" "string")
     ("Subobject" "string" :priority 1) ("Source" "string" :priority 1) ("Message" "string")
     ("First Seen" "string" :priority 1) ("Count" "string" :priority 1) ("Name" "string" :priority 1 :format "name"))
    (object)
  (let* ((involved (or (table-get object "involvedObject") (table-get object "regarding")))
         (last (or (table-get object "series" "lastObservedTime") (table-get object "lastTimestamp")
                   (table-get object "eventTime") (table-get object "metadata" "creationTimestamp")))
         (first (or (table-get object "firstTimestamp") (table-get object "eventTime")
                    (table-get object "metadata" "creationTimestamp"))))
    (list (table-timestamp-age last)
          (table-get object "type") (table-get object "reason")
          (format nil "~(~A~)/~A" (table-get involved "kind") (table-get involved "name"))
          (or (table-get involved "fieldPath") "")
          (table-event-source object)
          (table-get object "message")
          (table-timestamp-age first)
          (or (table-get object "count") (table-get object "series" "count") 1)
          (table-get object "metadata" "name"))))

(define-table-printer "PodDisruptionBudget"
    (("Min Available" "string") ("Max Unavailable" "string") ("Allowed Disruptions" "integer") ("Age" "string"))
    (object)
  (list (let ((value (table-get object "spec" "minAvailable"))) (if value (format nil "~A" value) "N/A"))
        (let ((value (table-get object "spec" "maxUnavailable"))) (if value (format nil "~A" value) "N/A"))
        (table-count object "status" "disruptionsAllowed") (table-age object)))

(define-table-printer "HorizontalPodAutoscaler"
    (("Reference" "string") ("Targets" "string") ("MinPods" "string") ("MaxPods" "string") ("Replicas" "string") ("Age" "string"))
    (object)
  (let ((reference (table-get object "spec" "scaleTargetRef")))
    (list (format nil "~A/~A" (table-get reference "kind") (table-get reference "name"))
          "<unknown>"
          (or (table-get object "spec" "minReplicas") "<unset>")
          (table-get object "spec" "maxReplicas")
          (table-count object "status" "currentReplicas") (table-age object))))

(define-table-printer "ResourceQuota"
    (("Age" "string") ("Request" "string") ("Limit" "string"))
    (object)
  (flet ((pairs (limit)
           (let ((hard (table-get object "status" "hard")) (used (table-get object "status" "used")) (terms nil))
             (when (hash-table-p hard)
               (maphash (lambda (key value)
                          (when (eq limit (and (or (uiop:string-prefix-p "limits." key)) t))
                            (push (format nil "~A: ~A/~A" key (table-get used key) value) terms)))
                        hard))
             (format nil "~{~A~^, ~}" (sort terms #'string<)))))
    (list (table-age object) (pairs nil) (pairs t))))

(define-table-printer "NetworkPolicy"
    (("Pod-Selector" "string") ("Age" "string"))
    (object)
  (list (let ((text (table-selector-text (table-get object "spec" "podSelector"))))
          (if (equal text "<none>") "<none>" text))
        (table-age object)))

(defun table-role-binding-subjects (object kind)
  "List a binding's subjects of KIND, namespaced for service accounts."
  (table-list
   (loop for subject across (or (table-get object "subjects") #())
         when (equal kind (gethash "kind" subject))
           collect (if (equal kind "ServiceAccount")
                       (format nil "~A/~A" (gethash "namespace" subject "") (gethash "name" subject))
                       (gethash "name" subject)))
   10))

(define-table-printer "Role" (("Created At" "string")) (object) (list (table-get object "metadata" "creationTimestamp")))
(define-table-printer "ClusterRole" (("Created At" "string")) (object) (list (table-get object "metadata" "creationTimestamp")))
(dolist (kind '("RoleBinding" "ClusterRoleBinding"))
  (setf (gethash kind *table-printers*)
        (cons '(("Role" "string") ("Age" "string") ("Users" "string" :priority 1)
                ("Groups" "string" :priority 1) ("ServiceAccounts" "string" :priority 1))
              (lambda (object)
                (list (format nil "~A/~A" (table-get object "roleRef" "kind") (table-get object "roleRef" "name"))
                      (table-age object)
                      (table-role-binding-subjects object "User")
                      (table-role-binding-subjects object "Group")
                      (table-role-binding-subjects object "ServiceAccount"))))))

(define-table-printer "CertificateSigningRequest"
    (("Age" "string") ("SignerName" "string") ("Requestor" "string") ("RequestedDuration" "string") ("Condition" "string"))
    (object)
  (let ((conditions (remove nil (map 'list (lambda (condition) (gethash "type" condition))
                                     (or (table-get object "status" "conditions") #()))))
        (seconds (table-get object "spec" "expirationSeconds")))
    (list (table-age object) (table-get object "spec" "signerName") (table-get object "spec" "username")
          (if seconds (table-human-duration seconds) "<none>")
          (let ((text (if conditions (format nil "~{~A~^,~}" conditions) "Pending")))
            (if (table-get object "status" "certificate") (format nil "~A,Issued" text) text)))))

(define-table-printer "APIService"
    (("Service" "string") ("Available" "string") ("Age" "string"))
    (object)
  (let ((service (table-get object "spec" "service"))
        (available (find "Available" (or (table-get object "status" "conditions") #()) :test #'equal
                         :key (lambda (condition) (gethash "type" condition)))))
    (list (if (hash-table-p service)
              (format nil "~A/~A" (gethash "namespace" service) (gethash "name" service))
              "Local")
          (cond ((null available) "Unknown")
                ((equal "True" (gethash "status" available)) "True")
                (t (format nil "False (~A)" (gethash "reason" available))))
          (table-age object))))

(define-table-printer "Lease"
    (("Holder" "string") ("Age" "string"))
    (object)
  (list (or (table-get object "spec" "holderIdentity") "") (table-age object)))

(define-table-printer "PriorityClass"
    (("Value" "integer") ("Global-Default" "boolean") ("Age" "string") ("PreemptionPolicy" "string"))
    (object)
  (list (table-get object "value") (and (table-get object "globalDefault") t)
        (table-age object) (or (table-get object "preemptionPolicy") "PreemptLowerPriority")))

(define-table-printer "RuntimeClass"
    (("Handler" "string") ("Age" "string"))
    (object)
  (list (table-get object "handler") (table-age object)))

(define-table-printer "ValidatingWebhookConfiguration"
    (("Webhooks" "integer") ("Age" "string"))
    (object)
  (list (length (or (table-get object "webhooks") #())) (table-age object)))

(define-table-printer "MutatingWebhookConfiguration"
    (("Webhooks" "integer") ("Age" "string"))
    (object)
  (list (length (or (table-get object "webhooks") #())) (table-age object)))

(define-table-printer "ValidatingAdmissionPolicy"
    (("Validations" "integer") ("ParamKind" "string") ("Age" "string"))
    (object)
  (list (length (or (table-get object "spec" "validations") #()))
        (let ((kind (table-get object "spec" "paramKind")))
          (if kind (format nil "~A/~A" (gethash "apiVersion" kind) (gethash "kind" kind)) "<unset>"))
        (table-age object)))

(define-table-printer "StorageClass"
    (("Provisioner" "string") ("ReclaimPolicy" "string") ("VolumeBindingMode" "string")
     ("AllowVolumeExpansion" "string") ("Age" "string"))
    (object)
  (list (table-get object "provisioner") (or (table-get object "reclaimPolicy") "Delete")
        (or (table-get object "volumeBindingMode") "Immediate")
        (and (table-get object "allowVolumeExpansion") t) (table-age object)))

(define-table-printer "PersistentVolume"
    (("Capacity" "string") ("Access Modes" "string") ("Reclaim Policy" "string") ("Status" "string")
     ("Claim" "string") ("StorageClass" "string") ("VolumeAttributesClass" "string") ("Reason" "string") ("Age" "string"))
    (object)
  (let ((claim (table-get object "spec" "claimRef")))
    (list (or (table-get object "spec" "capacity" "storage") "")
          (table-join (table-get object "spec" "accessModes"))
          (or (table-get object "spec" "persistentVolumeReclaimPolicy") "")
          (or (table-get object "status" "phase") "")
          (if claim (format nil "~A/~A" (gethash "namespace" claim) (gethash "name" claim)) "")
          (or (table-get object "spec" "storageClassName") "")
          (table-or-none (table-get object "spec" "volumeAttributesClassName"))
          (or (table-get object "status" "reason") "")
          (table-age object))))

(define-table-printer "PersistentVolumeClaim"
    (("Status" "string") ("Volume" "string") ("Capacity" "string") ("Access Modes" "string")
     ("StorageClass" "string") ("VolumeAttributesClass" "string") ("Age" "string"))
    (object)
  (list (or (table-get object "status" "phase") "")
        (or (table-get object "spec" "volumeName") "")
        (or (table-get object "status" "capacity" "storage") "")
        (table-join (table-get object "status" "accessModes"))
        (or (table-get object "spec" "storageClassName") "")
        (table-or-none (table-get object "spec" "volumeAttributesClassName"))
        (table-age object)))

;;; JSONPath for printer columns: .a.b, [n], [*] and [?(@.a=="b")].

(defun table-json-path-steps (path)
  "Split a printer column's JSONPath into steps, or NIL when it is outside this subset."
  (let ((position 0) (size (length path)) (steps nil))
    (when (and (plusp size) (char= #\{ (char path 0)) (char= #\} (char path (1- size))))
      (setf path (subseq path 1 (1- size)) size (length path)))
    (when (and (plusp size) (char= #\$ (char path 0))) (incf position))
    (loop while (< position size)
          do (let ((character (char path position)))
               (cond
                 ((char= character #\.)
                  (let ((end (or (position-if (lambda (next) (find next ".[")) path :start (1+ position)) size)))
                    (when (> end (1+ position))
                      (push (list :field (subseq path (1+ position) end)) steps))
                    (setf position end)))
                 ((char= character #\[)
                  (let* ((end (or (position #\] path :start position)
                                  (return-from table-json-path-steps nil)))
                         (inner (subseq path (1+ position) end)))
                    (cond
                      ((equal inner "*") (push (list :all) steps))
                      ((and (plusp (length inner)) (every #'digit-char-p inner))
                       (push (list :index (parse-integer inner)) steps))
                      ((and (> (length inner) 2) (member (char inner 0) '(#\' #\")))
                       (push (list :field (subseq inner 1 (1- (length inner)))) steps))
                      (t
                       (multiple-value-bind (match groups)
                           (cl-ppcre:scan-to-strings "^\\?\\(@\\.([A-Za-z0-9_.-]+)\\s*==\\s*[\"']([^\"']*)[\"']\\)$" inner)
                         (unless match (return-from table-json-path-steps nil))
                         (push (list :filter (aref groups 0) (aref groups 1)) steps))))
                    (setf position (1+ end))))
                 (t (return-from table-json-path-steps nil)))))
    (nreverse steps)))

(defun table-json-path-values (value steps)
  "Return the values STEPS select from VALUE."
  (if (null steps)
      (list value)
      (destructuring-bind (kind &optional first-argument second-argument) (first steps)
        (ecase kind
          (:field
           (when (hash-table-p value)
             (multiple-value-bind (next present) (gethash first-argument value)
               (and present (table-json-path-values next (rest steps))))))
          (:index
           (when (and (crd-array-p value) (< first-argument (length value)))
             (table-json-path-values (aref value first-argument) (rest steps))))
          (:all
           (when (crd-array-p value)
             (loop for item across value nconc (table-json-path-values item (rest steps)))))
          (:filter
           (when (crd-array-p value)
             (loop for item across value
                   when (and (hash-table-p item)
                             (equal (format nil "~A" (table-json-path-field item first-argument)) second-argument))
                     nconc (table-json-path-values item (rest steps)))))))))

(defun table-json-path-field (object path)
  "Read a dotted PATH from OBJECT."
  (let ((value object))
    (dolist (key (uiop:split-string path :separator '(#\.)) value)
      (setf value (and (hash-table-p value) (gethash key value))))))

(defun table-custom-cell (object column)
  "Evaluate one additionalPrinterColumn on OBJECT."
  (let* ((steps (table-json-path-steps (gethash "jsonPath" column)))
         (values (and steps (table-json-path-values object steps)))
         (type (gethash "type" column)))
    (if (null values)
        'null
        (let ((value (first values)))
          (cond
            ((equal type "date") (if (stringp value) (table-timestamp-age value) 'null))
            ((and (equal type "integer") (not (integerp value))) 'null)
            ((and (equal type "number") (not (numberp value))) 'null)
            ((and (equal type "boolean") (not (member value '(t nil)))) 'null)
            ((and (equal type "string") (hash-table-p value)) (com.inuoe.jzon:stringify value))
            ((and (equal type "string") (crd-array-p value)) (com.inuoe.jzon:stringify value))
            (t value))))))

(defun table-custom-columns (version)
  "Return a custom version's declared columns, or the default Age when it declares none."
  (let ((declared (gethash "additionalPrinterColumns" version)))
    (if (and (crd-array-p declared) (plusp (length declared)))
        (coerce declared 'list)
        (list (core-object "name" "Age" "type" "date" "jsonPath" ".metadata.creationTimestamp"
                           "description" (cdr (assoc "Age" +table-column-descriptions+ :test #'equal)))))))

;;; Tables

(defun table-column-object (name type &key format priority description)
  "Describe one column as metav1.TableColumnDefinition does."
  (core-object "name" name "type" type "format" (or format "")
               "description" (or description (cdr (assoc name +table-column-descriptions+ :test #'equal)) "")
               "priority" (or priority 0)))

(defun table-columns-for (kind)
  "Return the column objects for KIND, or NIL for a custom kind's own."
  (let ((printer (gethash kind *table-printers*)))
    (if printer
        (cons (table-column-object "Name" "string" :format "name")
              (mapcar (lambda (column) (apply #'table-column-object column)) (car printer)))
        (list (table-column-object "Name" "string" :format "name")
              (table-column-object "Created At" "date")))))

(defun table-row-cells (kind object)
  "Return OBJECT's cells for KIND's columns."
  (let ((printer (gethash kind *table-printers*)) (name (table-get object "metadata" "name")))
    (if printer
        (let ((cells (funcall (cdr printer) object)))
          (cons name (mapcar (lambda (cell) (if (null cell) nil cell)) cells)))
        (list name (table-get object "metadata" "creationTimestamp")))))

(defun table-partial-object (object)
  "Reduce OBJECT to PartialObjectMetadata."
  (core-object "kind" "PartialObjectMetadata" "apiVersion" *table-api-version*
               "metadata" (or (table-get object "metadata") (core-object))))

(defun table-row-object (object)
  "Return the object a row embeds, as includeObject asks."
  (let ((include (hunchentoot:parameter "includeObject")))
    (unless (member include '(nil "" "None" "Metadata" "Object") :test #'equal)
      (core-resource-error 400 "BadRequest" "includeObject must be None, Metadata or Object"))
    (cond ((equal include "None") nil)
          ((equal include "Object") object)
          (t (table-partial-object object)))))

(defun table-row (kind object custom-columns)
  "Build one row of KIND's Table for OBJECT."
  (let* ((cells (if custom-columns
                    (cons (table-get object "metadata" "name")
                          (mapcar (lambda (column) (table-custom-cell object column)) custom-columns))
                    (table-row-cells kind object)))
         (row (core-object "cells" (coerce cells 'vector)))
         (embedded (table-row-object object)))
    (when embedded (setf (gethash "object" row) embedded))
    (when (equal kind "Pod")
      (let ((phase (table-get object "status" "phase")))
        (cond ((equal phase "Succeeded")
               (setf (gethash "conditions" row)
                     (vector (core-object "type" "Completed" "status" "True"
                                          "reason" "Succeeded" "message" "The pod has completed successfully."))))
              ((equal phase "Failed")
               (setf (gethash "conditions" row)
                     (vector (core-object "type" "Completed" "status" "True"
                                          "reason" "Failed" "message" "The pod failed.")))))))
    row))

(defun table-object-p (object)
  "Test whether OBJECT is a resource or list a Table can describe."
  (and (hash-table-p object)
       (hash-table-p (gethash "metadata" object))
       (stringp (gethash "kind" object))
       (not (member (gethash "kind" object) '("Status" "Table" "Scale" "TokenRequest" "Binding" "Eviction" "PodLogOptions")
                    :test #'equal))
       (not (uiop:string-suffix-p (gethash "kind" object) "Review"))))

(defun table-custom-version ()
  "Return the custom version this request reads, when it reads one."
  (and *crd-view-definition* (crd-version *crd-view-definition* *crd-request-version*)))

(defun table-view (object)
  "Render a resource or list as a Table."
  (let* ((kind (gethash "kind" object))
         (items (gethash "items" object))
         (list-p (and (crd-array-p items) (uiop:string-suffix-p kind "List")))
         (item-kind (if list-p (subseq kind 0 (- (length kind) 4)) kind))
         (custom-version (table-custom-version))
         (custom-columns (and custom-version (table-custom-columns custom-version)))
         (table-metadata (core-object)))
    (let ((metadata (gethash "metadata" object)))
      (when list-p
        (dolist (field '("resourceVersion" "continue" "remainingItemCount"))
          (multiple-value-bind (value present) (gethash field metadata)
            (when (and present (not (equal value "")))
              (setf (gethash field table-metadata) value)))))
      (unless list-p
        (when (gethash "resourceVersion" metadata)
          (setf (gethash "resourceVersion" table-metadata) (gethash "resourceVersion" metadata)))))
    (let ((table (core-object
                  "kind" "Table" "apiVersion" *table-api-version* "metadata" table-metadata
                  "rows" (map 'vector
                              (lambda (item) (table-row item-kind item custom-columns))
                              (if list-p items (vector object))))))
      (when *table-send-columns*
        (setf (gethash "columnDefinitions" table)
              (coerce (if custom-columns
                          (cons (table-column-object "Name" "string" :format "name")
                                (mapcar (lambda (column)
                                          (core-object "name" (gethash "name" column) "type" (gethash "type" column)
                                                       "format" (gethash "format" column "")
                                                       "description" (gethash "description" column "")
                                                       "priority" (gethash "priority" column 0)))
                                        custom-columns))
                          (table-columns-for item-kind))
                      'vector)))
      table)))

(defun table-partial-view (object)
  "Render a resource or list as PartialObjectMetadata or PartialObjectMetadataList."
  (let* ((kind (gethash "kind" object)) (items (gethash "items" object)))
    (if (and (crd-array-p items) (uiop:string-suffix-p kind "List"))
        (core-object "kind" "PartialObjectMetadataList" "apiVersion" *table-api-version*
                     "metadata" (gethash "metadata" object)
                     "items" (map 'vector #'table-partial-object items))
        (table-partial-object object))))

(defun table-representation (object)
  "Apply the negotiated representation to OBJECT, a response on its way out."
  (cond
    ((null *table-request*) object)
    ((table-object-p object)
     (ecase *table-request*
       (:table (table-view object))
       (:partial (table-partial-view object))
       (:refuse (table-not-acceptable))))
    ((and (hash-table-p object) (equal "Status" (gethash "kind" object))) object)
    (t (table-not-acceptable))))

(defun table-not-acceptable ()
  "Refuse a client that accepts only representations this response cannot take."
  (core-resource-error 406 "NotAcceptable"
                       "only the following media types are accepted: application/json, application/vnd.kubernetes.protobuf"))
