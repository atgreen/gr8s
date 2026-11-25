;;;; SPDX-License-Identifier: MIT
(in-package #:gr8s-diagnose)

;;; One survey reads each kind once, links the resources it saw, and reports
;;; the deepest findings as causes with the symptoms they explain.

(defun complete-list-p (list state)
  (and (eq state :present) (json-array-p (field list "items"))
       (let ((more (field list "metadata" "continue"))) (or (null more) (equal more "")))))

(defun snapshot-getter (getter served-kinds)
  "Read each LIST once. A cluster-wide list also answers its namespaces, and a
loaded list of a SERVED-KINDS kind answers named reads of that kind."
  (let ((lists (make-hash-table :test #'equal)))
    (labels ((load-list (kind ns)
               (or (gethash (list kind ns) lists)
                   (setf (gethash (list kind ns) lists)
                         (multiple-value-bind (resource state observed-at) (funcall getter kind ns nil)
                           (let ((index (when (complete-list-p resource state) (make-hash-table :test #'equal))))
                             (when index
                               (loop for item across (field resource "items")
                                     do (setf (gethash (list (field item "metadata" "namespace")
                                                             (field item "metadata" "name")) index) item)))
                             (list resource state (or observed-at (timestamp)) index))))))
             (indexed (kind ns)
               (let ((entry (or (gethash (list kind ns) lists) (gethash (list kind nil) lists))))
                 (and entry (fourth entry) entry))))
      (lambda (kind ns name)
        (let ((entry (indexed kind ns)))
          ;; An object missing from its list may be newer than the list: ask for it.
          (cond ((and name entry (member kind served-kinds :test #'equal)
                      (gethash (list (and (namespaced-kind-p kind) ns) name) (fourth entry)))
                 (values (gethash (list (and (namespaced-kind-p kind) ns) name) (fourth entry))
                         :present (third entry)))
                (name (funcall getter kind ns name))
                ((and ns entry (null (gethash (list kind ns) lists)))
                 (values (object "items" (remove ns (field (first entry) "items") :test-not #'equal
                                                 :key (lambda (item) (field item "metadata" "namespace"))))
                         :present (third entry)))
                (t (values-list (subseq (load-list kind ns) 0 3)))))))))

(defun list-roots (getter kind namespace)
  "Return items, completeness and read time. A cluster-wide list that cannot be
read falls back to one list per visible namespace."
  (multiple-value-bind (list state observed-at) (funcall getter kind (and (namespaced-kind-p kind) namespace) nil)
    (cond ((complete-list-p list state) (values (field list "items") t observed-at))
          ((or namespace (not (namespaced-kind-p kind))) (values #() nil observed-at))
          (t (multiple-value-bind (namespaces known) (funcall getter "Namespace" nil nil)
               (let ((items nil) (complete (complete-list-p namespaces known)))
                 (when complete
                   (loop for item across (field namespaces "items")
                         for ns = (field item "metadata" "name")
                         do (multiple-value-bind (part part-state) (funcall getter kind ns nil)
                              (if (and (stringp ns) (complete-list-p part part-state))
                                  (setf items (concatenate 'list items (field part "items")))
                                  (setf complete nil)))))
                 (values (coerce items 'vector) complete observed-at)))))))

(defun dependency-edges (resources)
  "RESOURCES maps (kind namespace name) to objects. Return what each key depends
on, each key's controlling owner, and looser links that suggest a connection
without establishing one. A workload depends on the objects it owns."
  (let ((edges (make-hash-table :test #'equal)) (owners (make-hash-table :test #'equal))
        (hints (make-hash-table :test #'equal)))
    (flet ((depend (from kind ns name &optional (table edges))
             (let ((to (list kind (and (namespaced-kind-p kind) ns) name)))
               (when (and (stringp name) (gethash to resources) (not (equal from to)))
                 (pushnew to (gethash from table) :test #'equal)
                 to))))
      (loop for key being the hash-keys of resources using (hash-value resource)
            for (kind ns) = key
            do (loop for owner across (or (field resource "metadata" "ownerReferences") #())
                     for owner-key = (list (field owner "kind") (and (namespaced-kind-p (field owner "kind")) ns)
                                           (field owner "name"))
                     when (and (stringp (field owner "kind"))
                               (equal (field owner "uid") (field (gethash owner-key resources) "metadata" "uid"))
                               (depend owner-key kind ns (third key)))
                       do (setf (gethash key owners) owner-key))
               (cond ((equal kind "Pod")
                      (depend key "Node" nil (field resource "spec" "nodeName"))
                      (loop for volume across (or (field resource "spec" "volumes") #())
                            do (depend key "PersistentVolumeClaim" ns (field volume "persistentVolumeClaim" "claimName"))))
                     ((equal kind "PersistentVolumeClaim")
                      (depend key "PersistentVolume" nil (field resource "spec" "volumeName")))
                     ((equal kind "EndpointSlice")
                      (depend key "Service" ns (field resource "metadata" "labels" "kubernetes.io/service-name")))
                     ((equal kind "HorizontalPodAutoscaler")
                      (depend key (field resource "spec" "scaleTargetRef" "kind") ns
                              (field resource "spec" "scaleTargetRef" "name")))
                     ((equal kind "Service")
                      (let ((selector (field resource "spec" "selector")))
                        (when (and (hash-table-p selector) (plusp (hash-table-count selector)))
                          (loop for other being the hash-keys of resources using (hash-value pod)
                                when (and (equal "Pod" (first other)) (equal ns (second other)))
                                  do (cond ((labels-match-p (field pod "metadata" "labels") selector)
                                            (depend key "Pod" ns (third other)))
                                           ;; A Pod one label short may be what the Service waits for.
                                           ((selector-missing-labels (field pod "metadata" "labels") selector)
                                            (depend key "Pod" ns (third other) hints))))))))))
    (values edges owners hints)))

(defun reachable (start edges &optional (through (constantly t)))
  "Keys reachable from START. Search continues past a key only when THROUGH accepts it."
  (let ((seen (list start)) (queue (list start)))
    (loop while queue for key = (pop queue)
          do (when (or (equal key start) (funcall through key))
               (dolist (next (gethash key edges))
                 (unless (member next seen :test #'equal)
                   (push next seen)
                   (setf queue (append queue (list next)))))))
    (remove start seen :test #'equal)))

(defun related-keys (target resources)
  "TARGET, everything it depends on, and everything that depends on it."
  (let ((edges (dependency-edges resources)) (reverse (make-hash-table :test #'equal)))
    (maphash (lambda (from tos) (dolist (to tos) (push from (gethash to reverse)))) edges)
    (remove-duplicates (cons target (append (reachable target edges) (reachable target reverse))) :test #'equal)))

(defvar *symptom-rules* (make-hash-table :test #'equal))

(defun symptom-rule-p (rule)
  "Whether RULE only says that something beneath a resource is unhealthy.
See symptom/1 in rules/explanation.pl."
  (multiple-value-bind (symptom known) (gethash rule *symptom-rules*)
    (if known
        symptom
        (setf (gethash rule *symptom-rules*) (and (known `(symptom ,rule) t) t)))))

(defun refined-p (rule rules)
  "Whether a finding of one of RULES on the same resource says more than RULE.
See refines/2 in rules/explanation.pl."
  (let ((causes (known `(refines ?why ,rule) '?why)))
    (some (lambda (why) (member why rules :test #'equal)) causes)))

(defvar *rule-urgency* (make-hash-table :test #'equal))

(defun rule-urgency (rule)
  "Where a finding of RULE stands in the order of what to fix first.
See urgency/2 in rules/explanation.pl."
  (or (gethash rule *rule-urgency*)
      (setf (gethash rule *rule-urgency*) (first (known `(urgency ,rule ?rank) '?rank)))))

(defun problem-title (summary)
  "The first clause of SUMMARY: what is wrong, without how the doctor knows."
  (let* ((colon (search ": " summary))
         ;; "Pod web-a:" and "Container \"api\" in Pod web-a:" name the resource;
         ;; anything longer before a colon is the clause itself.
         (words (and colon (count #\Space summary :end colon)))
         (start (if (and colon (or (< words 2)
                                   (and (< words 6) (search "ontainer \"" summary :end2 colon))))
                    (+ colon 2)
                    0))
         (end (reduce #'min (loop for mark in '(": " ". " "; " ", so " ", and " ", which " ", while " ", but ")
                                  for found = (search mark summary :start2 start)
                                  when found collect found)
                      :initial-value (length summary)))
         (title (string-right-trim "." (subseq summary 0 end))))
    (if (> (length title) 110)
        (concatenate 'string (subseq title 0 (or (position #\Space title :end 108 :from-end t) 108)) " ...")
        title)))

(defun problem-detail (summary title)
  "What SUMMARY says beyond TITLE, when TITLE is how it opens; else all of it."
  (let ((rest (and (eql (length title) (mismatch title summary)) (subseq summary (length title)))))
    (loop for mark in '(": " ", so " ". ")
          when (and rest (eql (length mark) (mismatch mark rest)) (> (length rest) (length mark)))
            do (return (string-upcase (subseq rest (length mark)) :end 1))
          finally (return (if (member rest '("" ".") :test #'equal) "" summary)))))

(defun key-target (key) (resource-target (first key) (second key) (third key)))

(defun pass-through-p (key)
  "A resource that only stands between others does not end a search by being healthy."
  (member (first key) '("Service" "ReplicaSet" "Job") :test #'equal))

(defun explanation-facts (symptom-targets causes edges hints keys troubled)
  "The graph and the findings as the facts of rules/explanation.pl. Return
them and the vector that turns a resource's number back into its target."
  (let ((numbers (make-hash-table :test #'equal)) (targets (make-array 0 :adjustable t :fill-pointer t))
        (facts nil))
    (labels ((number (target)
               (or (gethash target numbers)
                   (prog1 (setf (gethash target numbers) (length targets))
                     (vector-push-extend target targets))))
             (fact (&rest fact) (push fact facts)))
      (loop for (name table) in (list (list 'depends edges) (list 'hint hints))
            do (maphash (lambda (from tos)
                          (dolist (to tos) (fact name (number (key-target from)) (number (key-target to)))))
                        table))
      (maphash (lambda (target key)
                 (when (or (gethash target troubled) (pass-through-p key)) (fact 'open (number target))))
               keys)
      (loop for cause in causes for index from 0
            do (fact 'cause_at (number (car cause)) index)
               (fact 'rule_of index (gethash "code" (cdr cause))))
      (dolist (target symptom-targets) (fact 'symptom_target (number target))))
    (values facts targets)))

(defun consequent-causes (causes edges hints keys troubled)
  "Those of CAUSES that another cause leads to, and (consequence . cause) for
each that no link joins to the cause behind it: consequence/2 in
rules/explanation.pl."
  (let ((answers (prove (explanation-facts nil causes edges hints keys troubled)
                        '((consequence ?cause ?through)) '(?cause ?through)
                        :max-steps 200000000 :max-results nil))
        (cause-vector (coerce causes 'vector)))
    (values (loop for cause in causes for index from 0
                  when (member index answers :key #'first) collect cause)
            (loop for (index through) in answers
                  when (simple-vector-p through)
                    collect (cons (aref cause-vector index) (aref cause-vector (svref through 1)))))))

(defun proved-verdicts (symptom-targets causes edges hints keys troubled)
  "For each of SYMPTOM-TARGETS, (:certain . causes), (:possible . causes) or
(:unexplained . targets beneath it), by verdict/2 in rules/explanation.pl."
  (multiple-value-bind (facts targets) (explanation-facts symptom-targets causes edges hints keys troubled)
    (let ((verdicts (make-hash-table :test #'equal)) (cause-vector (coerce causes 'vector)))
      (loop for (resource verdict)
              in (prove facts '((verdict ?resource ?verdict)) '(?resource ?verdict)
                        :max-steps 200000000 :max-results nil)
            for items = (svref verdict 1)
            do (setf (gethash (aref targets resource) verdicts)
                     (if (string= "UNEXPLAINED" (symbol-name (svref verdict 0)))
                         (cons :unexplained (mapcar (lambda (index) (aref targets index)) items))
                         (cons (if (string= "CERTAIN" (symbol-name (svref verdict 0))) :certain :possible)
                               ;; Causes in the order the findings were made.
                               (mapcar (lambda (index) (aref cause-vector index)) (sort (copy-list items) #'<))))))
      verdicts)))

(defvar *verdicts* #'proved-verdicts
  "How symptoms are matched to causes. The tests wrap it to check the rules
against the same search written in Lisp.")

(defun explain-findings (reports resources)
  "Return problems in the order to fix them, the number of advisory notes, and
what has recovered. A symptom is explained by a cause on its own resource or on
one it depends on through resources that are themselves unhealthy. A connection
that needs a looser link is recorded as possible, not certain."
  (multiple-value-bind (edges owners hints) (dependency-edges resources)
    (let ((keys (make-hash-table :test #'equal)) (causes nil) (symptoms nil) (notes 0)
          (troubled (make-hash-table :test #'equal)) (explained (make-hash-table :test #'eq))
          (bygone nil) (recovered nil)
          (problems (make-hash-table :test #'equal)) (order nil))
      (maphash (lambda (key resource) (declare (ignore resource)) (setf (gethash (key-target key) keys) key)) resources)
      (dolist (report reports)
        (loop with target = (gethash "target" report)
              with findings = (coerce (gethash "findings" report) 'list)
              with past = (lambda (finding) (equal "past" (gethash "severity" finding)))
              with rules = (mapcar (lambda (finding) (gethash "code" finding)) (remove-if past findings))
              with past-rules = (mapcar (lambda (finding) (gethash "code" finding)) (remove-if-not past findings))
              for finding in findings
              for entry = (cons target finding)
              do (cond ((equal "advisory" (gethash "severity" finding)) (incf notes))
                       ;; What has stopped, and what only restates it, is not trouble now.
                       ((or (funcall past finding)
                            (and past-rules (refined-p (gethash "code" finding) past-rules)
                                 (not (refined-p (gethash "code" finding) rules))))
                        (push entry bygone))
                       (t (setf (gethash target troubled) t)
                          (if (or (symptom-rule-p (gethash "code" finding))
                                  (refined-p (gethash "code" finding) rules))
                              (push entry symptoms)
                              (push entry causes))))))
      (setf causes (nreverse causes) symptoms (nreverse symptoms) bygone (nreverse bygone))
      ;; A cause that a deeper cause leads to is listed under it, as a symptom is.
      (multiple-value-bind (consequences across) (consequent-causes causes edges hints keys troubled)
        ;; Where no link joins the two, the rules have just established one.
        (loop for (consequence . cause) in across
              for from = (gethash (car consequence) keys) for to = (gethash (car cause) keys)
              when (and from to) do (pushnew to (gethash from edges) :test #'equal))
        (when consequences
          (setf causes (remove-if (lambda (cause) (member cause consequences :test #'eq)) causes)
                symptoms (append consequences symptoms))))
      (labels ((top-owner (key)
                 (loop for owner = (gethash key owners) while owner do (setf key owner)
                       finally (return key)))
               (impact (entry certain)
                 (object "rule" (gethash "code" (cdr entry)) "target" (car entry) "certain" certain
                         "summary" (gethash "summary" (cdr entry))
                         "recoveredAt" (gethash "recoveredAt" (cdr entry))))
               (problem (entry found)
                 ;; Replicas of one workload with the same finding are one problem,
                 ;; as are several users of one missing object.
                 (let* ((target (car entry)) (finding (cdr entry)) (key (gethash target keys))
                        (owner (and key (gethash key owners) (key-target (top-owner key))))
                        (name (and key (third key)))
                        (shape (cond ((gethash "subject" finding)
                                      (list (gethash "subject" finding) (gethash "detailKey" finding)))
                                     (owner (list owner (uiop:frob-substrings (gethash "summary" finding)
                                                                              (list name) "{}")))
                                     (t (list target (gethash "summary" finding)))))
                        (id (list found (gethash "code" finding) shape)))
                   (or (gethash id problems)
                       (progn
                         (push id order)
                         (setf (gethash id problems)
                               (object "rule" (gethash "code" finding) "causeFound" found
                                       "title" (problem-title (or (and (gethash "subject" finding)
                                                                       (gethash "groupSummary" finding))
                                                                  (gethash "summary" finding)))
                                       "summary" (or (and (gethash "subject" finding) (gethash "groupSummary" finding))
                                                     (gethash "summary" finding))
                                       "nextStep" (gethash "nextStep" finding)
                                       "commands" (or (gethash "commands" finding) #())
                                       "detailHeading" (gethash "detailHeading" finding)
                                       "detail" (gethash "detail" finding)
                                       "detailRead" (gethash "detailRead" finding)
                                       "since" (gethash "since" finding)
                                       "owner" (and (null (gethash "subject" finding)) owner)
                                       "resources" nil "impact" nil)))))))
        (dolist (cause causes)
          (pushnew (car cause) (gethash "resources" (problem cause t)) :test #'equal))
        (let ((verdicts (funcall *verdicts* (remove-duplicates (mapcar #'car symptoms) :test #'equal)
                                 causes edges hints keys troubled)))
          (dolist (symptom symptoms)
            (destructuring-bind (verdict . found) (gethash (car symptom) verdicts)
              ;; A looser link is worth a mention only when nothing explains the symptom.
              (unless (eq verdict :unexplained)
                (setf (gethash symptom explained) t)
                (dolist (cause found)
                  (push symptom (gethash (if (eq verdict :certain) "impact" "related") (problem cause t)))))))
          ;; What nothing explains stays visible. The deepest such symptom stands
          ;; for the ones above it.
          (let ((orphans (remove-if (lambda (symptom) (gethash symptom explained)) symptoms)))
            (dolist (orphan orphans)
              (let* ((below (remove (car orphan) (cdr (gethash (car orphan) verdicts)) :test #'equal))
                     (deeper (remove-if-not (lambda (other) (member (car other) below :test #'equal)) orphans))
                     (first-here (find (car orphan) orphans :test #'equal :key #'car)))
                (cond (deeper
                       (dolist (other deeper)
                         (when (eq other (find (car other) orphans :test #'equal :key #'car))
                           (push orphan (gethash "impact" (problem other nil))))))
                      ((eq orphan first-here)
                       (pushnew (car orphan) (gethash "resources" (problem orphan nil)) :test #'equal))
                      (t (push orphan (gethash "impact" (problem first-here nil)))))))))
        ;; What has stopped is listed under the cause that brought it about, if
        ;; that cause is still there, and as recovered if not.
        (loop for target in (remove-duplicates (mapcar #'car bygone) :test #'equal)
              for entries = (remove target bygone :test-not #'equal :key #'car)
              for rules = (mapcar (lambda (entry) (gethash "code" (cdr entry))) entries)
              for heads = (or (remove-if (lambda (entry)
                                           (let ((rule (gethash "code" (cdr entry))))
                                             (or (symptom-rule-p rule) (refined-p rule rules))))
                                         entries)
                              (list (first entries)))
              do (dolist (head heads)
                   (let* ((finding (cdr head))
                          (whys (known `(anywhere ?why ,(gethash "code" finding)) '?why))
                          (behind (loop for id in order for problem = (gethash id problems)
                                        when (and (gethash "causeFound" problem) (gethash "resources" problem)
                                                  (member (gethash "rule" problem) whys :test #'equal))
                                          collect problem)))
                     (if behind
                         (dolist (problem behind) (push head (gethash "impact" problem)))
                         (push (object "rule" (gethash "code" finding) "target" target
                                       "summary" (gethash "summary" finding)
                                       "recoveredAt" (gethash "recoveredAt" finding)
                                       "nextStep" (gethash "nextStep" finding)
                                       "commands" (or (gethash "commands" finding) #())
                                       "detailHeading" (gethash "detailHeading" finding)
                                       "detail" (gethash "detail" finding))
                               recovered)))))
        (let ((result
                (loop for id in (reverse order)
                      for problem = (gethash id problems)
                      for members = (reverse (gethash "resources" problem))
                      ;; Name other resources first; a Pod's own conditions add least.
                      for impact = (stable-sort (remove-duplicates (reverse (gethash "impact" problem)) :test #'equal)
                                                #'> :key (lambda (entry) (if (member (car entry) members :test #'equal) 0 1)))
                      when members
                        do (setf (gethash "resources" problem) (coerce members 'vector)
                                 (gethash "reach" problem)
                                 (length (remove-duplicates
                                          (remove-if (lambda (target) (member target members :test #'equal))
                                                     (mapcar #'car impact)) :test #'equal))
                                 (gethash "impact" problem)
                                 (concatenate 'vector
                                              (mapcar (lambda (entry) (impact entry t)) impact)
                                              (mapcar (lambda (entry) (impact entry nil))
                                                      (remove-duplicates (reverse (gethash "related" problem))
                                                                         :test #'equal))))
                           (remhash "related" problem)
                        and collect problem)))
          ;; Among causes of equal reach, the one that changed first comes first.
          (setf result (stable-sort result #'string< :key (lambda (problem) (or (gethash "since" problem) "~"))))
          (setf result (stable-sort result #'>
                                    :key (lambda (problem) (+ (if (gethash "causeFound" problem) 1000000 0)
                                                              (gethash "reach" problem)))))
          ;; What everything stands on comes before all of that.
          (values (coerce (stable-sort result #'< :key (lambda (problem) (rule-urgency (gethash "rule" problem))))
                          'vector)
                  notes
                  (coerce (nreverse recovered) 'vector)))))))

(defun focus-on (focus resources reports problems recovered)
  "Keep the problems on FOCUS or beneath it, and drop reports about resources
above it that those problems do not touch. Return reports, problems and what
of RECOVERED is on FOCUS or beneath it."
  (let* ((edges (dependency-edges resources)) (reverse (make-hash-table :test #'equal))
         (below (cons (key-target focus) (mapcar #'key-target (reachable focus edges)))))
    (maphash (lambda (from tos) (dolist (to tos) (push from (gethash to reverse)))) edges)
    (let* ((kept (remove-if-not (lambda (problem)
                                  (some (lambda (target) (member target below :test #'equal))
                                        (gethash "resources" problem)))
                                problems))
           (touched (loop for problem across kept
                          append (coerce (gethash "resources" problem) 'list)
                          append (map 'list (lambda (entry) (gethash "target" entry)) (gethash "impact" problem))))
           (above (set-difference (mapcar #'key-target (reachable focus reverse)) (append below touched)
                                  :test #'equal)))
      (values (remove-if (lambda (report) (member (gethash "target" report) above :test #'equal)) reports)
              kept
              (remove-if-not (lambda (entry) (member (gethash "target" entry) below :test #'equal)) recovered)))))

(defun survey-report (target origins warnings coverage &optional (resources (make-hash-table :test #'equal)) focus)
  "FOCUS, a resource key, narrows a survey to one diagnosed resource. Why reads failed leads the warnings."
  (setf warnings (append (read-failure-warnings) warnings))
  (let ((reports (remove-duplicates (loop for origin in origins append (cdr origin)) :test #'eq)))
    (progress "Working out what causes what")
    (multiple-value-bind (problems notes recovered) (explain-findings reports resources)
      (when focus
        (setf (values reports problems recovered) (focus-on focus resources reports problems recovered)
              origins (list (cons target reports))
              notes (loop for report in reports
                          sum (count "advisory" (gethash "findings" report) :test #'equal
                                     :key (lambda (finding) (gethash "severity" finding))))))
      (let ((groups (grouped-findings origins))
            (incomplete (or warnings (some (lambda (r) (equal "incomplete" (gethash "status" r))) reports))))
        (object "target" target
                "status" (cond (incomplete "incomplete") ((plusp (length groups)) "findings") (t "no-findings"))
                "scope" "The doctor read these resources from the Kubernetes API at slightly different moments. A cause is the deepest finding it could see, not proof of a root cause: it cannot see inside containers, and finding nothing does not prove health."
                "problems" problems "recovered" recovered "notes" notes
                "groups" groups "reports" (coerce reports 'vector)
                "warnings" (coerce warnings 'vector) "coverage" (coerce coverage 'vector))))))

(defun checkup (namespace getter &key (max-resources 2000) (kinds *checkup-kinds*) target)
  "Survey NAMESPACE, or everything visible. With TARGET, a (kind namespace name)
key, report only that resource, what it depends on and what depends on it."
  (let* ((kinds (if namespace (remove-if-not #'namespaced-kind-p kinds) kinds))
         (getter (snapshot-getter getter kinds))
         (listed (make-hash-table :test #'equal)) (roots nil) (warnings nil) (coverage nil)
         (cache (make-hash-table :test #'equal)) (origins nil))
    (dolist (kind kinds)
      (multiple-value-bind (items complete observed-at) (list-roots getter kind namespace)
        (push (object "kind" kind "result" (if complete "listed" "unknown")
                      "observedAt" (or observed-at (timestamp)) "count" (if complete (length items) 0)) coverage)
        (unless complete (push (format nil "Could not completely list ~A resources." kind) warnings))
        (loop for resource across items
              for name = (field resource "metadata" "name")
              for ns = (when (namespaced-kind-p kind) (field resource "metadata" "namespace"))
              do (if (and (stringp name) (plusp (length name))
                          (or (not (namespaced-kind-p kind))
                              (and (stringp ns) (or (null namespace) (equal namespace ns)))))
                     (let ((key (list kind ns name)))
                       (setf (gethash key listed) resource)
                       (push key roots))
                     (progn
                       (setf (gethash "result" (first coverage)) "incomplete")
                       (pushnew (format nil "Skipped an invalid or out-of-scope ~A list entry." kind)
                                warnings :test #'equal))))))
    (setf roots (nreverse roots))
    (when target
      (unless (gethash target listed)
        (multiple-value-bind (resource state) (apply getter target)
          (when (eq state :present) (setf (gethash target listed) resource))))
      (let ((related (related-keys target listed)))
        (setf roots (cons target (remove-if-not (lambda (key) (member key related :test #'equal))
                                                (remove target roots :test #'equal))))))
    (when (> (length roots) max-resources)
      (push "Resource limit reached; coverage is incomplete." warnings)
      (setf roots (subseq roots 0 max-resources)))
    (loop for key in roots for count from 1
          do (progress "Checking ~D of ~D: ~A" count (length roots) (plain-target (key-target key)))
             (destructuring-bind (kind ns name) key
               (multiple-value-bind (reports notes) (diagnose-tree kind name ns getter cache)
                 (push (cons (key-target key) reports) origins)
                 (setf warnings (append notes warnings)))))
    (setf origins (nreverse origins))
    (let ((resources (make-hash-table :test #'equal)))
      (maphash (lambda (key entry) (when (second entry) (setf (gethash key resources) (second entry)))) cache)
      (survey-report (cond (target (key-target target)) (namespace (format nil "namespace/~A" namespace)) (t "cluster"))
                     origins (reverse warnings) (nreverse coverage) resources target))))

(defun quiet-log-line (line)
  "LINE without the logfmt fields that say when and from where in the source
it was written, which tell a reader nothing about why the program stopped."
  (let ((quiet line))
    (dolist (key '("ts=" "time=" "caller="))
      (loop for start = (search key quiet)
            while (and start (or (zerop start) (char= #\Space (char quiet (1- start)))))
            do (let* ((value (+ start (length key)))
                      (end (if (and (< value (length quiet)) (char= #\" (char quiet value)))
                               (let ((close (position #\" quiet :start (1+ value)))) (and close (1+ close)))
                               (position #\Space quiet :start value))))
                 (setf quiet (concatenate 'string (subseq quiet 0 start)
                                          (string-left-trim " " (if end (subseq quiet end) "")))))))
    (if (plusp (length (string-trim " " quiet))) quiet line)))

(defvar *report-time* nil "The universal time a report is read at; NIL is now.")

(defun age-words (seconds)
  "SECONDS as a length of time, to the precision a reader acts on."
  (flet ((units (count unit) (format nil "~D ~A~P" count unit count)))
    (cond ((< seconds 60) "less than a minute")
          ((< seconds 3600) (units (floor seconds 60) "minute"))
          ((< seconds (* 48 3600)) (units (floor seconds 3600) "hour"))
          ((< seconds (* 60 86400)) (units (floor seconds 86400) "day"))
          (t (units (floor seconds (* 30 86400)) "month")))))

(defun with-ages (text)
  "TEXT with each UTC timestamp said as how long ago it was, the timestamp after it."
  (with-output-to-string (out)
    (loop with start = 0
          for mark = (position #\T text :start start)
          for from = (and mark (- mark 10))
          for stamp = (and from (>= from 0) (<= (+ from 20) (length text)) (subseq text from (+ from 20)))
          for age = (and stamp (digit-char-p (char stamp 0))
                         (or (= from 0) (not (alphanumericp (char text (1- from)))))
                         (let ((seconds (timestamp-age stamp)))
                           (and seconds (+ seconds (if *report-time* (- *report-time* (get-universal-time)) 0)))))
          while mark
          do (flet ((after (word)
                      (let ((before (- from (length word))))
                        (and (>= before start) (string= word text :start2 before :end2 from) before))))
               (cond ((and age (>= age 0))
                      ;; "at 5 minutes ago" and "since 5 minutes ago" are not said.
                      (cond ((after "since ")
                             (format out "~Afor ~A (since ~A)" (subseq text start (after "since ")) (age-words age) stamp))
                            (t (format out "~A~A ago (~A)" (subseq text start (or (after "at ") from))
                                       (age-words age) stamp)))
                      (setf start (+ from 20)))
                     (t (write-string text out :start start :end (1+ mark))
                        (setf start (1+ mark)))))
          finally (write-string text out :start start))))

(defun report-text (text)
  "TEXT from a finding as Markdown for a reader."
  (markdown-text (with-ages (or text ""))))

(defun recovery-note (entry)
  "What to add to ENTRY's summary when it does not itself say that the trouble stopped."
  (when (and (gethash "recoveredAt" entry) (not (known `(over ,(gethash "rule" entry)) t)))
    (format nil " ~A" (report-text (format nil "It has run without a restart since ~A." (gethash "recoveredAt" entry))))))

(defun problem-markdown (problem number wide)
  "WIDE surveys span namespaces, so each problem says where it is."
  (let* ((members (coerce (gethash "resources" problem) 'list)) (owner (gethash "owner" problem))
         (parts (uiop:split-string (first members) :separator "/"))
         (summary (gethash "summary" problem))
         (title (or (gethash "title" problem) (problem-title summary)))
         ;; One line for each other resource; its further findings are in the JSON.
         (impact (remove-duplicates
                  (remove-if (lambda (entry) (member (gethash "target" entry) members :test #'equal))
                             (coerce (gethash "impact" problem) 'list))
                  :test #'equal :key (lambda (entry) (gethash "target" entry)) :from-end t)))
    (with-output-to-string (out)
      (format out "## ~D. ~A~%~%*~{~A~^ · ~}*~%~%" number (report-text title)
              (remove nil (list (when (and wide (= 3 (length parts)) (plusp (rule-urgency (gethash "rule" problem))))
                                  (format nil "Namespace: ~A" (report-text (second parts))))
                                (when (gethash "since" problem)
                                  (format nil "Since: ~A" (report-text (gethash "since" problem))))
                                (format nil "Rule: ~A" (report-text (gethash "rule" problem))))))
      (let ((detail (problem-detail summary title)))
        (when (plusp (length detail)) (format out "~A~%~%" (report-text detail))))
      (cond ((and owner (rest members))
             (format out "The same on ~D of the Pods of ~A: ~{~A~^, ~}~%~%" (length members)
                     (report-text (plain-target owner))
                     (mapcar (lambda (target) (report-text (car (last (uiop:split-string target :separator "/")))))
                             members)))
            ((and (null owner) (rest members))
             (format out "Affects: ~{~A~^, ~}~%~%"
                     (mapcar (lambda (target) (report-text (plain-target target))) members))))
      (unless (gethash "causeFound" problem)
        (format out "No cause was found for this.~%~%"))
      (when (gethash "detail" problem)
        (let ((lines (uiop:split-string (gethash "detail" problem) :separator '(#\Newline)))
              (heading (gethash "detailHeading" problem)))
          (if (gethash "detailRead" problem)
              ;; The summary already says what that output means.
              (format out "~A.~%~%" (report-text (string-right-trim ":" heading)))
              (format out "~A~%~%~A~%~@[(~D more line~:P; --json has all of it)~%~%~]"
                      (report-text heading)
                      (markdown-block (mapcar #'quiet-log-line (subseq lines 0 (min 6 (length lines)))))
                      (when (> (length lines) 6) (- (length lines) 6))))))
      (format out "**What to do:** ~A~%~%" (gethash "nextStep" problem))
      (when (plusp (length (gethash "commands" problem)))
        (format out "~A~%" (markdown-block (coerce (gethash "commands" problem) 'list) "sh")))
      (loop for (heading entries) in (list (list "Because of this:" (remove nil impact :key (lambda (e) (gethash "certain" e))))
                                           (list "Possibly related:" (remove-if (lambda (e) (gethash "certain" e)) impact)))
            when entries
              do (format out "**~A**~%~%" heading)
                 (loop for entry in entries repeat 8
                       do (format out "- ~A~@[~A~]~%" (report-text (gethash "summary" entry)) (recovery-note entry)))
                 (when (> (length entries) 8) (format out "- and ~D more~%" (- (length entries) 8)))
                 (terpri out)))))

(defun survey-markdown (report &key notes)
  "Causes first, each with what it explains; then symptoms nothing explains,
and what has recovered."
  (let* ((problems (coerce (gethash "problems" report) 'list))
         (recovered (coerce (or (gethash "recovered" report) #()) 'list))
         (wide (equal "cluster" (gethash "target" report)))
         (orphans (count nil problems :key (lambda (problem) (gethash "causeFound" problem))))
         (advisories (remove "advisory" (coerce (gethash "groups" report) 'list)
                             :test-not #'equal :key (lambda (group) (gethash "severity" group)))))
    (with-output-to-string (out)
      (format out "# ~A: ~:[no problems found by the checks that ran~;~:*~D problem~:P found~]~@[, ~D with no known cause~].~@[ ~D more ~:*~[~;has~:;have~] recovered.~]~%~%"
              (report-text (string-upcase (plain-target (gethash "target" report)) :end 1))
              (when problems (length problems)) (when (plusp orphans) orphans)
              (when recovered (length recovered)))
      ;; A long report starts with its contents.
      (when (> (length problems) 3)
        (loop for problem in problems for number from 1
              do (format out "~D. ~A~%" number
                         (report-text (or (gethash "title" problem) (problem-title (gethash "summary" problem))))))
        (terpri out))
      (loop for problem in problems for number from 1
            do (write-string (problem-markdown problem number wide) out))
      (when recovered
        (format out "## Recovered~%~%These stopped without anyone's help, so there is nothing to do unless they start again.~%~%")
        (dolist (entry recovered)
          (let ((parts (uiop:split-string (gethash "target" entry) :separator "/")))
            (format out "- ~A~@[~A~]~@[ *Namespace: ~A*~]~%" (report-text (gethash "summary" entry)) (recovery-note entry)
                    (when (and wide (= 3 (length parts))) (report-text (second parts))))))
        (terpri out))
      (cond ((and notes advisories)
             (format out "## Configuration and history notes~%~%")
             (dolist (group advisories)
               (format out "- ~A (~A)~%" (report-text (gethash "summary" group)) (report-text (gethash "rule" group))))
             (terpri out))
            (advisories
             (format out "~D configuration and history note~:P not shown; add `--notes` to list ~:*~[~;it~:;them~].~%~%"
                     (length advisories))))
      (loop for warning across (gethash "warnings" report) do (format out "Incomplete: ~A~%~%" (report-text warning)))
      (loop for child across (gethash "reports" report)
            when (equal "incomplete" (gethash "status" child))
              do (format out "~A~%" (markdown-block (uiop:split-string
                                                     (string-right-trim '(#\Newline)
                                                                        (with-output-to-string (text) (print-report child text)))
                                                     :separator '(#\Newline)))))
      (when (equal "incomplete" (gethash "status" report))
        (format out "Some checks could not run, so this report is incomplete.~%~%"))
      (format out "*A cause is the deepest finding the doctor could see through the API, not proof of a root cause, and finding nothing does not prove health. `--json` has the evidence behind each finding.*~%"))))

(defun print-survey (report &key notes markdown)
  "Write REPORT for a person. MARKDOWN writes its source instead of rendering it."
  (print-markdown (survey-markdown report :notes notes) :source markdown))
