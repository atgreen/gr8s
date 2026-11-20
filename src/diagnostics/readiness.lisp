;;;; SPDX-License-Identifier: MIT
(in-package #:gr8s-diagnose)

;;; The facts behind rules/pods.pl: why a running Pod is not ready, and why a
;;; container keeps restarting. They come from container status and the probe
;;; definitions in the Pod spec. Probe output is not in the Pod; a caller that
;;; has read the Pod's Events passes them.
(defun shell-command (words)
  "Quote an argument vector for pasting into a shell; NIL when too long to show."
  (let ((text (format nil "~{~A~^ ~}"
                      (map 'list (lambda (word)
                                   (if (and (plusp (length word))
                                            (every (lambda (c) (or (alphanumericp c) (find c "_@%+=:,./-"))) word))
                                       word
                                       (with-output-to-string (out)
                                         (write-char #\' out)
                                         (loop for c across word
                                               do (if (char= c #\') (write-string "'\\''" out) (write-char c out)))
                                         (write-char #\' out))))
                           words))))
    (when (<= (length text) 300) text)))

(defun probe-command (probe)
  (let ((command (field probe "exec" "command")))
    (when (and (json-array-p command) (plusp (length command)) (every #'stringp command))
      (shell-command command))))

(defun probe-description (probe)
  "Say what a probe does, from the Pod spec only."
  (let ((period (let ((seconds (field probe "periodSeconds"))) (if (integerp seconds) seconds 10)))
        (http (field probe "httpGet")))
    (format nil "~A every ~D second~:P"
            (cond ((field probe "exec")
                   (format nil "runs ~:[a command~;~:*`~A`~] in the container" (probe-command probe)))
                  (http (format nil "requests ~(~A~) port ~A path ~A"
                                (or (field http "scheme") "HTTP") (field http "port") (or (field http "path") "/")))
                  ((field probe "tcpSocket") (format nil "connects to TCP port ~A" (field probe "tcpSocket" "port")))
                  ((field probe "grpc") (format nil "calls the gRPC health service on port ~A" (field probe "grpc" "port")))
                  (t "is of an unrecognized type and runs"))
            period)))

(defun restarting-p (status)
  "A container that has restarted often, or is waiting to be restarted again."
  (or (and (integerp (field status "restartCount")) (>= (field status "restartCount") 5))
      (equal "CrashLoopBackOff" (field status "state" "waiting" "reason"))))

(defun readiness-facts (pod &optional events)
  "EVENTS are recent Events about POD, when the caller has read them."
  (let ((facts nil))
   (flet ((fact (&rest fact) (push fact facts)))
    (dolist (event events)
      (cond ((and (equal "Unhealthy" (field event "reason"))
                  (uiop:string-prefix-p "Liveness probe" (field event "message")))
             (fact 'liveness_failed (event-container event)))
            ((and (equal "Killing" (field event "reason")) (search "liveness" (field event "message")))
             (fact 'liveness_kill_reported (event-container event)))))
    (let ((conditions (or (field pod "status" "conditions") #())))
      (when (find-if (lambda (c) (and (equal "Ready" (field c "type")) (equal "False" (field c "status")))) conditions)
        (fact 'pod_not_ready))
      (loop for gate across (or (field pod "spec" "readinessGates") #())
            for type = (field gate "conditionType")
            when (and (stringp type)
                      (not (find-if (lambda (c) (and (equal type (field c "type")) (equal "True" (field c "status"))))
                                    conditions)))
              do (fact 'gate_unmet type)))
    (loop for (spec-section status-section) in '(("containers" "containerStatuses")
                                                 ("initContainers" "initContainerStatuses"))
          do (loop for status across (or (field pod "status" status-section) #())
                   for name = (field status "name")
                   for container = (find name (or (field pod "spec" spec-section) #())
                                         :test #'equal :key (lambda (c) (field c "name")))
                   for last = (field status "lastState" "terminated")
                   when (and (stringp name) container)
                     do (loop for (kind key) in '(("readiness" "readinessProbe") ("startup" "startupProbe")
                                                  ("liveness" "livenessProbe"))
                              for probe = (field container key)
                              when (hash-table-p probe)
                                do (fact 'probe name kind (probe-description probe)))
                        (when (restarting-p status)
                          (fact 'restarting name (or (field status "restartCount") 0))
                          (when (member (field last "exitCode") '(137 143))
                            (fact 'killed_by_signal name))
                          (cond ((equal "OOMKilled" (field last "reason"))
                                 (fact 'out_of_memory name (or (field last "finishedAt") "an unknown time")
                                       (or (field container "resources" "limits" "memory") "none")))
                                ((and (integerp (field last "exitCode")) (/= 0 (field last "exitCode")))
                                 (fact 'crashed name (field last "exitCode")
                                       (or (field last "finishedAt") "an unknown time")))))
                   when (and (stringp name) container (hash-table-p (field status "state" "running")))
                     do (fact 'container_running name)
                        (let* ((since (field status "state" "running" "startedAt")) (age (timestamp-age since)))
                          (when age (fact 'running_since name since age)))
                        ;; JSON false is NIL here; an absent flag proves nothing.
                        (multiple-value-bind (ready present) (gethash "ready" status)
                          (when (and present (null ready)) (fact 'container_unready name)))
                        (multiple-value-bind (started present) (gethash "started" status)
                          (cond ((eq started t) (fact 'container_started name))
                                ((and present (null started)) (fact 'container_not_started name))))))
    (nreverse facts))))

(defun readiness-commands (pod namespace code details)
  "Commands a person can paste to see what the API cannot show."
  (let ((name (field pod "metadata" "name")) (container (first details)))
    (cond ((equal code "readiness-gate-unmet") nil)
          ((uiop:string-prefix-p "restart" code)
           (list (format nil "kubectl -n ~A logs ~A -c ~A --previous --tail=50" namespace name container)))
          (t
           (let* ((spec (find container (concatenate 'vector (or (field pod "spec" "containers") #())
                                                     (or (field pod "spec" "initContainers") #()))
                              :test #'equal :key (lambda (c) (field c "name"))))
                  (command (probe-command (field spec (if (equal code "startup-probe-pending")
                                                          "startupProbe" "readinessProbe")))))
             (append
              (when command
                (list (format nil "kubectl -n ~A exec ~A -c ~A -- ~A" namespace name container command)))
              (list (format nil "kubectl -n ~A logs ~A -c ~A --tail=50" namespace name container))))))))

(defun readiness-findings (pod namespace evidence &optional events)
  (let ((ready (find "Ready" (or (field pod "status" "conditions") #()) :test #'equal
                     :key (lambda (c) (field c "type")))))
    (loop for (code details) in (prove (readiness-facts pod events) '((unready ?code ?details)) '(?code ?details))
          for (summary step) = (first (known `(explanation ,code ?summary ?step) '(?summary ?step)))
          for over = (known `(over ,code) t)
          collect (object "code" code "rule" code "severity" (if over "past" "warning")
                          "container" (unless (equal code "readiness-gate-unmet") (first details))
                          "since" (unless (uiop:string-prefix-p "restart" code)
                                    (field ready "lastTransitionTime"))
                          ;; What is over says last when the run it is in now began.
                          "recoveredAt" (when over (car (last details)))
                          "summary" (apply #'format nil summary (field pod "metadata" "name") details)
                          "nextStep" step
                          "commands" (coerce (readiness-commands pod namespace code details) 'vector)
                          "evidence" (vector evidence)))))
