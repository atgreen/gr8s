;;;; SPDX-License-Identifier: MIT
(in-package #:gr8s-diagnose)

;; What the cluster said in the last hour about an unhealthy Pod. The Event message is
;; the only place the API keeps a probe's output or a mount or pull error, so
;; it is shown, bounded, with the finding it explains. A crashed run's last log
;; lines are read the same way.
(defparameter *event-text-limit* 800)

(defun pod-troubled-p (pod)
  "Only a Pod that reports trouble is worth a namespace Event list."
  (or (condition-p pod "Ready" "False")
      (some #'restarting-p (concatenate 'vector (or (field pod "status" "containerStatuses") #())
                                        (or (field pod "status" "initContainerStatuses") #())))
      (member (field pod "status" "phase") '("Pending" "Failed" "Unknown") :test #'equal)))

(defun event-last-seen (event)
  (or (field event "series" "lastObservedTime") (field event "lastTimestamp") (field event "eventTime")))

(defun event-count (event)
  (let ((count (or (field event "series" "count") (field event "count"))))
    (if (and (integerp count) (plusp count)) count 1)))

(defun event-container (event)
  "The container named by a fieldPath such as spec.containers{api}, if any."
  (let* ((path (field event "involvedObject" "fieldPath"))
         (open (and (stringp path) (position #\{ path)))
         (close (and open (position #\} path :start open))))
    (when close (subseq path (1+ open) close))))

(defun event-text (event)
  (let ((message (string-right-trim '(#\Space #\Tab #\Newline #\Return) (or (field event "message") ""))))
    (if (> (length message) *event-text-limit*)
        (concatenate 'string (subseq message 0 *event-text-limit*) " ...")
        message)))

(defun recent-pod-events (pod events)
  "The latest Event of the last hour per kind of occurrence that names this exact Pod."
  (let ((latest (make-hash-table :test #'equal)))
    (loop for event across events
          for message = (field event "message")
          ;; Probe failures share a reason; the text before the colon tells them apart.
          for key = (list (field event "type") (field event "reason") (event-container event)
                          (and (stringp message) (subseq message 0 (position #\: message))))
          for old = (gethash key latest)
          when (and (stringp (field event "reason")) (stringp message)
                    (equal (field pod "metadata" "uid") (field event "involvedObject" "uid"))
                    (recent-event-p event 3600)
                    (or (null old) (string> (event-last-seen event) (event-last-seen old))))
            do (setf (gethash key latest) event))
    (sort (loop for event being the hash-values of latest collect event)
          #'string> :key #'event-last-seen)))

(defun event-heading (event)
  (format nil "Kubernetes reported this ~[~;once~:;~:*~D times~], most recently at ~A:"
          (event-count event) (event-last-seen event)))

(defun probe-finding-for-event (findings event)
  "The readiness finding that EVENT's probe output explains, if there is one."
  (when (equal "Unhealthy" (field event "reason"))
    (find-if (lambda (finding)
               (let ((prefix (cdr (assoc (gethash "code" finding)
                                         '(("readiness-probe-failing" . "Readiness probe")
                                           ("startup-probe-pending" . "Startup probe")
                                           ("restarts-liveness-kill" . "Liveness probe")) :test #'equal))))
                 (and prefix (equal (gethash "container" finding) (event-container event))
                      (uiop:string-prefix-p prefix (field event "message")))))
             findings)))

(defun event-finding (pod event evidence)
  (let* ((reason (field event "reason")) (container (event-container event))
         (known (first (catalog-findings event "Event" evidence))))
    (object "code" (if known (gethash "code" known) "pod-warning-event")
            "rule" (if known (gethash "code" known) "pod-warning-event") "severity" "warning"
            "summary" (format nil "Pod ~A~@[, container ~S~]: Kubernetes raised the warning ~A."
                              (field pod "metadata" "name") container reason)
            "detailHeading" (event-heading event) "detail" (event-text event)
            "nextStep" (if known (gethash "nextStep" known)
                           "Read the message; it comes from the component that raised the warning.")
            "evidence" (vector evidence))))

(defun augment-pod-events (report pod kind ns getter)
  "Collect what only a troubled Pod is worth asking for: its recent Events and
the log of a run that crashed. Attach each to the finding it explains."
  (when (and (equal kind "Pod") (hash-table-p pod) (pod-troubled-p pod)
             (plusp (length (gethash "evidence" report)))
             (equal "present" (field (aref (gethash "evidence" report) 0) "result"))
             (not (find "changed-during-collection" (gethash "evidence" report) :test #'equal
                        :key (lambda (e) (field e "result")))))
    (multiple-value-bind (list state observed-at) (funcall getter "Event" ns nil)
      (let* ((items (field list "items")) (evidence nil) (findings nil)
             (complete (and (eq state :present) (json-array-p items)
                            (let ((more (field list "metadata" "continue"))) (or (null more) (equal more ""))))))
        (flet ((observe (name result event)
                 (let ((id (format nil "v~D" (1+ (length evidence)))))
                   (push (object "id" id "kind" "Event" "namespace" ns "name" name "result" result
                                 "observedAt" (or observed-at (timestamp))
                                 "uid" (field event "metadata" "uid")
                                 "resourceVersion" (field event "metadata" "resourceVersion"))
                         evidence)
                   id)))
          (if (not complete)
              (setf (gethash "unknownEvidence" report)
                    (concatenate 'vector (gethash "unknownEvidence" report)
                                 (vector (observe "*" (if (eq state :present) "invalid-or-incomplete-response"
                                                          (string-downcase (symbol-name state))) nil)))
                    (gethash "status" report) "incomplete")
              (let ((events (recent-pod-events pod items)))
                ;; Some rules need what the Events say; add what they now establish.
                (let ((known (map 'list (lambda (finding) (gethash "code" finding)) (gethash "findings" report))))
                  (setf (gethash "findings" report)
                        (concatenate 'vector (gethash "findings" report)
                                     (remove-if (lambda (finding) (member (gethash "code" finding) known :test #'equal))
                                                (readiness-findings pod ns (field (aref (gethash "evidence" report) 0) "id")
                                                                    events)))))
                (dolist (event (remove "Warning" events :test-not #'equal :key (lambda (e) (field e "type"))))
                  (let ((id (observe (field event "metadata" "name") "present" event))
                        (explained (probe-finding-for-event (coerce (gethash "findings" report) 'list) event)))
                    (if explained
                        (setf (gethash "detailHeading" explained) (event-heading event)
                              (gethash "detail" explained) (event-text event)
                              (gethash "evidence" explained) (concatenate 'vector (gethash "evidence" explained) (vector id)))
                        (push (event-finding pod event id) findings))))
                ;; A crash explains itself only in what the program wrote before it died.
                (let ((crashes (loop for finding across (gethash "findings" report)
                                     for lines = (and (member (gethash "code" finding) '("restarts-crash" "restarted-earlier")
                                                              :test #'equal)
                                                      (previous-log getter pod ns (gethash "container" finding)))
                                     for step = (and lines (first (known `(quoted_step ,(gethash "code" finding) ?step) '?step)))
                                     when step do (setf (gethash "nextStep" finding) step)
                                     when lines
                                       do (setf (gethash "detailHeading" finding) "The last lines it wrote before exiting:"
                                                (gethash "detail" finding)
                                                (format nil "~{~A~^~%~}"
                                                        (mapcar (lambda (line)
                                                                  (if (> (length line) 300)
                                                                      (concatenate 'string (subseq line 0 300) " ...")
                                                                      line))
                                                                (last lines 6))))
                                       and collect (cons finding lines))))
                  (setf findings (append (reverse (log-findings pod ns getter crashes)) findings)))
                (setf findings (append (reverse (application-findings pod ns (coerce (gethash "findings" report) 'list)))
                                       findings))))
          (setf (gethash "evidence" report)
                (concatenate 'vector (gethash "evidence" report) (nreverse evidence)))
          (when findings
            (setf (gethash "findings" report)
                  (concatenate 'vector (gethash "findings" report) (nreverse findings)))
            (unless (equal "incomplete" (gethash "status" report))
              (setf (gethash "status" report) "findings")))))))
  report)
