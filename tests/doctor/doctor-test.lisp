(require :asdf)
(load (merge-pathnames "load.lisp" *load-truename*))
(in-package #:gr8s-diagnose)
(assert (fboundp 'doctor-main))
(assert (= 0 (doctor-main nil)))
(assert (= 2 (doctor-main '("checkup" "--fix"))))
(assert (= 2 (doctor-main '("diagnose" "widget/web"))))
(defun fixture-resource (kind name ns &optional spec status)
  (object "kind" kind "metadata" (object "name" name "namespace" ns "uid" name "resourceVersion" "1")
          "spec" (or spec (object)) "status" (or status (object))))
(let* ((pods (vector (fixture-resource "Pod" "p1" "test" (object "nodeName" "n1"))
                     (fixture-resource "Pod" "p2" "test" (object "nodeName" "n1"))))
       (node (fixture-resource "Node" "n1" nil nil
                 (object "conditions" (vector (object "type" "Ready" "status" "False")))))
       (node-reads 0)
       (report (checkup "test"
                  (lambda (kind ns name)
                    (declare (ignore ns))
                    (cond ((null name) (values (object "items" pods) :present))
                          ((equal kind "Node") (incf node-reads) (values node :present))
                          (t (values (find name pods :test #'equal :key (lambda (p) (field p "metadata" "name"))) :present))))
                  :kinds '("Pod"))))
  (assert (= 1 (length (gethash "groups" report))))
  (assert (= 2 (length (gethash "affectedTargets" (aref (gethash "groups" report) 0)))))
  (assert (= 2 node-reads)))
(let ((report (checkup "test" (lambda (&rest args) (declare (ignore args)) (values nil :unknown)) :kinds '("Pod"))))
  (assert (equal "incomplete" (gethash "status" report))))
(assert (= 150 (length (catalog-entries))))
(let ((resource (fixture-resource "Deployment" "web" "test" (object "replicas" 3)
                  (object "availableReplicas" 1))))
  (assert (find "deployment-available-deficit" (catalog-findings resource "Deployment" "e1")
                :test #'equal :key (lambda (f) (gethash "code" f)))))
(assert (equal '(:command :doctor-cluster :arguments nil) (doctor-command-route nil)))
(assert (equal '(:command :doctor-cluster :arguments ("checkup" "--json"))
               (doctor-command-route '("checkup" "--json"))))
(assert (null (doctor-command-route '("host" "--fix"))))
;; Unknown cluster-scoped resources must print an incomplete report, not crash on NIL namespace.
(let ((report (diagnose-resource "Node" "missing" nil
                (lambda (&rest args) (declare (ignore args)) (values nil :unknown)))))
  (assert (search "unknown" (with-output-to-string (out) (print-report report out)))))
;; Explicit false is distinct from an absent property, including readiness.
(dolist (json '("{\"spec\":{\"containers\":[{\"name\":\"api\",\"securityContext\":{}}]}}"
                "{\"spec\":{\"containers\":[{\"name\":\"api\",\"securityContext\":{\"readOnlyRootFilesystem\":true}}]}}"))
  (assert (not (find "container-readOnlyRootFilesystem" (catalog-findings (com.inuoe.jzon:parse json) "Pod" "e1")
                    :test #'equal :key (lambda (f) (gethash "code" f))))))
(assert (null (catalog-findings (com.inuoe.jzon:parse "{\"endpoints\":[{\"conditions\":{}}]}") "EndpointSlice" "e1")))
;; Missing numeric fields must not default to zero or invent a replica deficit.
(assert (null (catalog-findings (object "spec" (object "replicas" 3)) "Deployment" "e1")))
(let* ((calls 0)
       (getter (bounded-getter (lambda (&rest args) (declare (ignore args)) (incf calls) (values (object) :present))
                                :max-requests 1)))
  (assert (eq :present (nth-value 1 (funcall getter "Node" nil "one"))))
  (assert (eq :unknown (nth-value 1 (funcall getter "Node" nil "two"))))
  (assert (= 1 calls)))
;; An unreadable Secret does not prevent investigating the known assigned Node.
(let* ((pod (fixture-resource "Pod" "web" "test"
               (object "nodeName" "n1" "containers" (vector (object "name" "api" "envFrom"
                         (vector (object "secretRef" (object "name" "private"))))))))
       (node (fixture-resource "Node" "n1" nil nil
               (object "conditions" (vector (object "type" "Ready" "status" "False"))))))
  (multiple-value-bind (reports warnings)
      (diagnose-tree "Pod" "web" "test"
        (lambda (kind ns name)
          (declare (ignore ns name))
          (cond ((equal kind "Pod") (values pod :present))
                ((equal kind "Node") (values node :present))
                (t (values nil :unknown)))))
    (declare (ignore warnings))
    (assert (find "Node/n1" reports :test #'equal :key (lambda (r) (gethash "target" r))))))
;; Namespace checkup must not list unrelated cluster-wide roots.
(let ((report (checkup "test" (lambda (&rest args) (declare (ignore args)) (error "Unexpected global list"))
                      :kinds '("Node" "PersistentVolume" "Namespace"))))
  (assert (zerop (length (gethash "groups" report)))))
;; Evaluate the actual native option parser source without loading the server/runtime.
(unless (find-package :gr8s.server) (make-package :gr8s.server :use '("CL")))
(let* ((source (uiop:read-file-string (merge-pathnames "../../src/server/main.lisp" *load-truename*)))
       (*package* (find-package :gr8s.server)))
  (eval (read-from-string source nil nil :start (search "(defparameter +cli-commands+" source)))
  (dolist (name '("option-value" "parse-doctor-options" "command-help-page"))
    (let ((start (search (format nil "(defun ~A " name) source)))
      (assert start)
      (eval (read-from-string source nil nil :start start)))))
(assert (eq :doctor-cluster (getf (uiop:symbol-call :gr8s.server :parse-doctor-options nil) :command)))
(assert (eq :doctor-cluster (getf (uiop:symbol-call :gr8s.server :parse-doctor-options '("checkup" "--json")) :command)))
(assert (equal "/tmp/state" (getf (uiop:symbol-call :gr8s.server :parse-doctor-options '("host" "--state-directory" "/tmp/state")) :state-directory)))
(assert (getf (uiop:symbol-call :gr8s.server :parse-doctor-options '("--fix")) :fix))
(format t "Doctor grouping, unknown coverage, scopes, budgets and native parser checks passed.~%")

(assert (search "Read-only" (first (uiop:symbol-call :gr8s.server :command-help-page '("doctor" "diagnose" "pod/web")))))
;; One malformed response must not erase findings for other resources.
;; A survey reads each object from its list, so a named read cannot disagree with it.
(dolist (failure '("malformed-status" "invalid-list-row"))
  (let* ((good (fixture-resource "Node" "good" nil nil
                (object "conditions" (vector (object "type" "Ready" "status" "False")))))
         (bad (fixture-resource "Node" "bad" nil nil (object "conditions" 42)))
         (rows (vector bad good)))
    (when (equal failure "invalid-list-row") (setf (aref rows 0) (object "unexpected" "PRIVATE-RESPONSE")))
    (let ((report (checkup nil
                    (lambda (kind ns name)
                      (declare (ignore kind ns))
                      (cond ((null name) (values (object "items" rows) :present))
                            ((equal name "good") (values good :present))
                            (t (values bad :present)))) :kinds '("Node"))))
      (assert (equal "incomplete" (gethash "status" report)))
      (assert (find "node-Ready-False" (gethash "groups" report) :test #'equal :key (lambda (g) (field g "rule"))))
      (assert (not (search "PRIVATE-RESPONSE" (com.inuoe.jzon:stringify report)))))))
;; Evaluation errors are explicit, but their potentially sensitive payload is not printed.
(multiple-value-bind (reports warnings)
    (diagnose-tree "Node" "broken" nil
                   (lambda (&rest args) (declare (ignore args)) (error "PRIVATE-RESPONSE")))
  (assert (null warnings))
  (let ((report (first reports)))
    (assert (equal "incomplete" (gethash "status" report)))
    (assert (equal "diagnosis-error" (field (aref (gethash "evidence" report) 0) "result")))
    (assert (not (search "PRIVATE-RESPONSE" (com.inuoe.jzon:stringify report))))))
(format t "Mixed survey failures preserve valid findings and redact error payloads.~%")

;; A running container that fails its readiness check is the explanation; the
;; Ready conditions and the owner's replica deficit only restate it.
(defun unready-pod (&key (ready "false") (started "true") (probe "\"readinessProbe\":{\"exec\":{\"command\":[\"/bin/sh\",\"-ec\",\"bao status -tls-skip-verify\"]},\"periodSeconds\":5}") (gates ""))
  (com.inuoe.jzon:parse
   (format nil "{\"kind\":\"Pod\",\"metadata\":{\"name\":\"bao-0\",\"namespace\":\"test\",\"uid\":\"u1\",\"resourceVersion\":\"1\",
  \"ownerReferences\":[{\"kind\":\"StatefulSet\",\"name\":\"bao\",\"uid\":\"bao\"}]},
 \"spec\":{~A\"containers\":[{\"name\":\"bao\"~@[,~A~]}]},
 \"status\":{\"conditions\":[{\"type\":\"ContainersReady\",\"status\":\"False\"},{\"type\":\"Ready\",\"status\":\"False\"}],
  \"containerStatuses\":[{\"name\":\"bao\",\"ready\":~A~@[,\"started\":~A~],\"state\":{\"running\":{}}}]}}"
           gates probe ready started)))
(defun unready-rules (pod)
  (mapcar (lambda (f) (gethash "code" f)) (readiness-findings pod "test" "e1")))
(let ((finding (first (readiness-findings (unready-pod) "test" "e1"))))
  (assert (equal "readiness-probe-failing" (gethash "code" finding)))
  (assert (search "every 5 seconds" (gethash "summary" finding)))
  (assert (equalp #("kubectl -n test exec bao-0 -c bao -- /bin/sh -ec 'bao status -tls-skip-verify'"
                    "kubectl -n test logs bao-0 -c bao --tail=50")
                  (gethash "commands" finding))))
(assert (null (unready-rules (unready-pod :ready "true"))))
(assert (null (unready-rules (unready-pod :probe nil))))
;; An absent started flag proves neither a passed nor a pending startup check.
(assert (null (unready-rules (unready-pod :started nil))))
(assert (equal '("startup-probe-pending")
               (unready-rules (unready-pod :started "false" :probe "\"startupProbe\":{\"httpGet\":{\"path\":\"/up\",\"port\":8200}}"))))
(assert (equal '("readiness-gate-unmet")
               (unready-rules (unready-pod :ready "true" :gates "\"readinessGates\":[{\"conditionType\":\"example.com/lb\"}],"))))
(assert (equal "sh -c 'it'\\''s'" (shell-command #("sh" "-c" "it's"))))
(assert (null (shell-command (vector (make-string 400 :initial-element #\a)))))
(let* ((pod (unready-pod))
       (set (fixture-resource "StatefulSet" "bao" "test" (object "replicas" 1) (object "readyReplicas" 0)))
       (getter (lambda (kind ns name) (declare (ignore ns))
                 (let ((found (cond ((equal kind "Pod") pod) ((equal kind "StatefulSet") set))))
                   (cond (name (values found (if found :present :absent)))
                         (t (values (object "items" (if found (vector found) #())) :present))))))
       (report (checkup "test" getter :target '("Pod" "test" "bao-0") :kinds '("Pod" "StatefulSet")))
       (text (with-output-to-string (*standard-output*) (print-survey report))))
  (assert (= 4 (length (gethash "groups" report))))
  (assert (search "Pod bao-0 in namespace test: 1 problem found." text))
  (assert (< (search "1. Pod bao-0: container \"bao\" is running but not ready" text)
             (search "Because of this:" text)
             (search "- StatefulSet bao: Fewer Pods are ready" text)))
  ;; What only restates the problem on the same Pod is left to the JSON.
  (assert (not (search "- Pod bao-0: The Pod is not ready" text)))
  (assert (find "pod-Ready-False" (gethash "impact" (aref (gethash "problems" report) 0))
                :test #'equal :key (lambda (entry) (gethash "rule" entry))))
  (assert (not (search "2. " text))))
;; With nothing to explain them, the same rules stay full findings.
(let* ((node (fixture-resource "Pod" "bao-0" "test" nil
               (object "conditions" (vector (object "type" "Ready" "status" "False")))))
       (target (resource-target "Pod" "test" "bao-0"))
       (report (survey-report target (list (cons target (diagnose-tree "Pod" "bao-0" "test"
                                              (lambda (&rest args) (declare (ignore args)) (values node :present))))) nil nil))
       (text (with-output-to-string (*standard-output*) (print-survey report))))
  (assert (search "1 problem found, 1 with no known cause." text))
  (assert (search "1. Pod bao-0: The Pod is not ready" text))
  (assert (search "No cause was found for this." text))
  (assert (not (search "Because of this" text))))
(format t "Readiness explanations, paste-ready commands and plain-language report checks passed.~%")

;; Recent Warning Events about the exact Pod carry what its status cannot: the
;; probe's output joins the finding it explains, other warnings stand alone.
(defun pod-event (reason message &key (uid "u1") (type "Warning") (last (timestamp)) (container "bao") (count 7))
  (object "kind" "Event" "metadata" (object "name" (format nil "ev-~A" reason) "namespace" "test" "uid" reason "resourceVersion" "1")
          "type" type "reason" reason "message" message "count" count "lastTimestamp" last
          "involvedObject" (object "kind" "Pod" "name" "bao-0" "uid" uid
                                   "fieldPath" (format nil "spec.containers{~A}" container))))
(defun diagnose-with-events (pod events &optional (state :present))
  (let ((lists 0))
    (values (first (diagnose-tree "Pod" "bao-0" "test"
                     (lambda (kind ns name) (declare (ignore ns))
                       (cond ((and (equal kind "Pod") name) (values pod :present))
                             ((equal kind "Event") (incf lists)
                              (values (and (eq state :present) (object "items" (coerce events 'vector))) state))
                             (t (values nil :absent))))))
            lists)))
(defun finding-codes (report) (map 'list (lambda (f) (gethash "code" f)) (gethash "findings" report)))
(let* ((report (diagnose-with-events (unready-pod)
                 (list (pod-event "Unhealthy" (format nil "Readiness probe failed: Sealed true~%"))
                       (pod-event "Unhealthy" "Readiness probe failed: older" :last "2020-01-01T00:00:00Z")
                       (pod-event "FailedMount" "Unable to attach or mount volumes" :container "bao")
                       (pod-event "Rebalanced" "Custom controller warning")
                       (pod-event "BackOff" "Another Pod with the same name" :uid "replaced")
                       (pod-event "Killing" "Normal Events are not problems" :type "Normal"))))
       (probe (find "readiness-probe-failing" (gethash "findings" report) :test #'equal :key (lambda (f) (gethash "code" f)))))
  (assert (equal "Readiness probe failed: Sealed true" (gethash "detail" probe)))
  (assert (search "7 times" (gethash "detailHeading" probe)))
  (assert (= 2 (length (gethash "evidence" probe))))
  (assert (not (member "event-Unhealthy" (finding-codes report) :test #'equal)))
  (assert (member "event-FailedMount" (finding-codes report) :test #'equal))
  (assert (member "pod-warning-event" (finding-codes report) :test #'equal))
  (assert (not (member "event-BackOff" (finding-codes report) :test #'equal)))
  (assert (not (search "older" (com.inuoe.jzon:stringify report))))
  (assert (equal "findings" (gethash "status" report)))
  (let ((text (with-output-to-string (*standard-output*)
                (print-survey (survey-report "Pod/test/bao-0" (list (list "Pod/test/bao-0" report)) nil nil)))))
    (assert (search "    Readiness probe failed: Sealed true" text))))
;; An unexplained Unhealthy Event is its own finding; long text is cut.
(let ((report (diagnose-with-events (unready-pod :probe nil)
                (list (pod-event "Unhealthy" (make-string 2000 :initial-element #\x) :count 1)))))
  (let ((finding (find "event-Unhealthy" (gethash "findings" report) :test #'equal :key (lambda (f) (gethash "code" f)))))
    (assert (search "this once," (gethash "detailHeading" finding)))
    (assert (= (+ *event-text-limit* 4) (length (gethash "detail" finding))))))
;; Unreadable Events leave the other findings standing but the report incomplete.
(let ((report (diagnose-with-events (unready-pod) nil :unknown)))
  (assert (equal "incomplete" (gethash "status" report)))
  (assert (member "readiness-probe-failing" (finding-codes report) :test #'equal)))
;; A Pod that reports no trouble costs no Event list.
(assert (zerop (nth-value 1 (diagnose-with-events (fixture-resource "Pod" "bao-0" "test") nil))))
(format t "Pod Event correlation, bounds, identity, recency and unknown coverage checks passed.~%")
