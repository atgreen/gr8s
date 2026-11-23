;;;; SPDX-License-Identifier: MIT
(require :asdf)
(load (merge-pathnames "load.lisp" *load-truename*))
(load (merge-pathnames "explanation-reference.lisp" *load-truename*))
(in-package #:gr8s-diagnose)

;; Every survey below is explained twice, by the rules and by the same search in
;; Lisp, and the two must agree.
(defvar *verdict-checks* 0)
(setf *verdicts* (lambda (&rest arguments)
                   (let ((proved (apply #'proved-verdicts arguments)))
                     (assert-verdicts-agree proved (apply #'walked-verdicts arguments))
                     (incf *verdict-checks*)
                     proved)))

(defun thing (kind name &key (ns "test") spec status owner labels)
  (object "kind" kind
          "metadata" (apply #'object "name" name "uid" name "resourceVersion" "1"
                            (append (when ns (list "namespace" ns))
                                    (when labels (list "labels" labels))
                                    (when owner (list "ownerReferences"
                                                      (vector (object "kind" (first owner) "name" (second owner)
                                                                      "uid" (second owner) "controller" t))))))
          "spec" (or spec (object)) "status" (or status (object))))
(defun crashing (name owner &optional (node "n1"))
  (thing "Pod" name :owner owner :spec (object "nodeName" node)
         :status (object "conditions" (vector (object "type" "Ready" "status" "False"))
                         "containerStatuses" (vector (object "name" "api" "state"
                                                       (object "waiting" (object "reason" "CrashLoopBackOff")))))))
(defun unready (name &optional (node "n1"))
  (thing "Pod" name :spec (object "nodeName" node)
         :status (object "conditions" (vector (object "type" "Ready" "status" "False")))))
(defun short (kind name &optional owner)
  (thing kind name :owner owner :spec (object "replicas" 3) :status (object "readyReplicas" 0)))
(defun world (&rest things)
  "A getter over THINGS that counts its reads; Events are always an empty list."
  (let ((reads nil))
    (values (lambda (kind ns name)
              (push (list kind ns name) reads)
              (let ((matches (remove-if-not (lambda (item)
                                              (and (equal kind (field item "kind"))
                                                   (or (null ns) (not (namespaced-kind-p kind))
                                                       (equal ns (field item "metadata" "namespace")))))
                                            things)))
                (if name
                    (let ((item (find name matches :test #'equal :key (lambda (i) (field i "metadata" "name")))))
                      (values item (if item :present :absent)))
                    (values (object "items" (coerce matches 'vector)) :present))))
            (lambda () reads))))
(defun problems (report) (coerce (gethash "problems" report) 'list))
(defun impact-rules (problem) (map 'list (lambda (i) (gethash "rule" i)) (gethash "impact" problem)))
;; Reports are read at 01:05 on the day the fixtures are dated.
(defun text (report)
  (let ((*report-time* (encode-universal-time 0 5 1 1 1 2026 0)))
    (with-output-to-string (*standard-output*) (print-survey report))))

;; Replicas that fail the same way are one cause, and it explains the workload above them.
(let* ((owner '("ReplicaSet" "web-1"))
       (report (checkup nil (world (short "Deployment" "web") (short "ReplicaSet" "web-1" '("Deployment" "web"))
                                   (crashing "web-1-a" owner) (crashing "web-1-b" owner) (crashing "web-1-c" owner)
                                   (thing "Node" "n1" :ns nil))))
       (problem (first (problems report))))
  (assert (= 1 (length (problems report))))
  (assert (equal "waiting-CrashLoopBackOff" (gethash "rule" problem)))
  (assert (gethash "causeFound" problem))
  (assert (= 3 (length (gethash "resources" problem))))
  (assert (equal "Deployment/test/web" (gethash "owner" problem)))
  (assert (= 2 (gethash "reach" problem)))
  (assert (subsetp '("deployment-ready-deficit" "replicaset-ready-deficit" "pod-Ready-False")
                   (impact-rules problem) :test #'equal))
  (let ((text (text report)))
    (assert (search "Cluster: 1 problem found." text))
    (assert (search "Namespace: test" text))
    (assert (search "The same on 3 of the Pods of Deployment web in namespace test: web-1-a, web-1-b, web-1-c" text))
    (assert (search "- Deployment web: Fewer Pods are ready" text))))

;; A cause that reaches more resources comes first, and a healthy Pod on a
;; troubled Node does not make that Node explain its workload.
(let* ((owner '("ReplicaSet" "web-1"))
       (pressure (thing "Node" "n2" :ns nil
                        :status (object "conditions" (vector (object "type" "DiskPressure" "status" "True")))))
       (down (thing "Node" "n1" :ns nil
                    :status (object "conditions" (vector (object "type" "Ready" "status" "False")))))
       (report (checkup nil (world (short "ReplicaSet" "web-1") (crashing "web-1-a" owner "n3")
                                   (thing "Pod" "web-1-b" :owner owner :spec (object "nodeName" "n2"))
                                   (unready "solo-1") (unready "solo-2") pressure down (thing "Node" "n3" :ns nil))))
       (problem-rules (mapcar (lambda (p) (gethash "rule" p)) (problems report))))
  (assert (equal "node-Ready-False" (first problem-rules)))
  (assert (= 2 (gethash "reach" (first (problems report)))))
  (let ((disk (find "node-DiskPressure-True" (problems report) :test #'equal :key (lambda (p) (gethash "rule" p)))))
    (assert (zerop (length (gethash "impact" disk)))))
  (assert (member "replicaset-ready-deficit"
                  (impact-rules (find "waiting-CrashLoopBackOff" (problems report) :test #'equal
                                      :key (lambda (p) (gethash "rule" p))))
                  :test #'equal)))

;; A symptom nothing explains stays visible; the deepest one stands for those above it.
(let* ((report (checkup nil (world (short "Deployment" "web") (short "ReplicaSet" "web-1" '("Deployment" "web"))
                                   (thing "Pod" "web-1-a" :owner '("ReplicaSet" "web-1")
                                          :status (object "conditions" (vector (object "type" "Ready" "status" "False")))))))
       (problem (first (problems report))))
  (assert (= 1 (length (problems report))))
  (assert (not (gethash "causeFound" problem)))
  (assert (equal "pod-Ready-False" (gethash "rule" problem)))
  (assert (subsetp '("deployment-ready-deficit" "replicaset-ready-deficit") (impact-rules problem) :test #'equal))
  (assert (search "1 problem found, 1 with no known cause." (text report))))

;; A Service's trouble is explained by the Pods it selects, and a target is
;; reported with what it depends on and what depends on it, nothing else.
(let* ((labels (object "app" "web"))
       (pod (crashing "web-a" nil)) (other (crashing "other-a" nil))
       (slice (thing "EndpointSlice" "web-x" :labels (object "kubernetes.io/service-name" "web"))))
  (setf (gethash "labels" (gethash "metadata" pod)) labels
        (gethash "endpoints" slice) (vector (object "conditions" (object "ready" nil))))
  (let* ((getter (world pod other slice (thing "Service" "web" :spec (object "selector" labels))
                        (thing "Node" "n1" :ns nil)))
         (report (checkup "test" getter :target '("Service" "test" "web")))
         (problem (first (problems report))))
    (assert (equal '("Pod/test/web-a") (coerce (gethash "resources" problem) 'list)))
    (assert (member "endpointslice-all-unready" (impact-rules problem) :test #'equal))
    (assert (not (search "other-a" (com.inuoe.jzon:stringify report))))
    (assert (search "Service web in namespace test: 1 problem found." (text report)))))

;; A Service that selects nothing because a troubled Pod lacks one label is
;; possibly related to that Pod's problem, never certainly; a different value
;; for the label is a different workload.
(flet ((survey (pod-labels healthy)
         (let ((pod (if healthy (thing "Pod" "web-a" :spec (object "nodeName" "n1")) (crashing "web-a" nil)))
               (slice (thing "EndpointSlice" "web-active-x"
                             :labels (object "kubernetes.io/service-name" "web-active"))))
           (setf (gethash "labels" (gethash "metadata" pod)) pod-labels
                 (gethash "endpoints" slice) #())
           (checkup "test" (world pod slice (thing "Node" "n1" :ns nil)
                                  (thing "Service" "web-active"
                                         :spec (object "selector" (object "app" "web" "tier" "api" "active" "true"))))))))
  (let* ((report (survey (object "app" "web" "tier" "api") nil)) (problem (first (problems report))))
    (assert (= 1 (length (problems report))))
    (assert (equal "waiting-CrashLoopBackOff" (gethash "rule" problem)))
    (let ((loose (remove-if (lambda (i) (gethash "certain" i)) (coerce (gethash "impact" problem) 'list))))
      (assert (equal '("endpointslice-empty" "service-waits-for-label")
                     (sort (mapcar (lambda (i) (gethash "rule" i)) loose) #'string<))))
    (assert (zerop (gethash "reach" problem)))
    (let ((text (text report)))
      ;; The certain consequences are all on the Pod itself, so none is listed.
      (assert (not (search "Because of this:" text)))
      (assert (< (search "Possibly related:" text)
                 (search "Service web-active selects no Pods: Pod web-a would match its selector but for the label active" text)))))
  (let ((problem (first (problems (survey (object "app" "web" "tier" "api") t)))))
    (assert (equal "service-waits-for-label" (gethash "rule" problem)))
    (assert (not (gethash "causeFound" problem))))
  (assert (find "service-selector-empty" (problems (survey (object "app" "web" "tier" "api" "active" "false") nil))
                :test #'equal :key (lambda (p) (gethash "rule" p)))))
;; A Node's report is about the Node, not about every Pod that happens to run on it.
(let ((report (checkup nil (world (crashing "web-a" nil) (thing "Node" "n1" :ns nil)) :target '("Node" nil "n1"))))
  (assert (zerop (length (problems report))))
  (assert (zerop (length (gethash "groups" report)))))
(let ((report (checkup nil (world (unready "solo-1")
                                  (thing "Node" "n1" :ns nil
                                         :status (object "conditions" (vector (object "type" "Ready" "status" "False")))))
                       :target '("Node" nil "n1"))))
  (assert (equal '("pod-Ready-False") (impact-rules (first (problems report))))))
;; Listed kinds are read once and answer named reads; a namespace is answered
;; from a cluster-wide list.
(multiple-value-bind (getter reads) (world (unready "solo-1") (unready "solo-2") (thing "Node" "n1" :ns nil))
  (checkup nil getter :kinds '("Pod" "Node"))
  (assert (= 1 (count '("Pod" nil nil) (funcall reads) :test #'equal)))
  (assert (not (find "Pod" (remove nil (funcall reads) :key #'third) :test #'equal :key #'first)))
  (assert (not (find "Node" (remove nil (funcall reads) :key #'third) :test #'equal :key #'first))))
;; When the cluster-wide list is refused, each visible namespace is listed.
(let* ((inner (world (unready "solo-1") (thing "Namespace" "test" :ns nil) (thing "Node" "n1" :ns nil)))
       (report (checkup nil (lambda (kind ns name)
                              (if (and (equal kind "Pod") (null ns) (null name))
                                  (values nil :unknown)
                                  (funcall inner kind ns name)))
                        :kinds '("Pod"))))
  (assert (= 1 (length (problems report))))
  (assert (not (equal "incomplete" (gethash "status" report)))))
;; Notes are counted, not listed, unless asked for.
(let* ((report (checkup nil (world (thing "Pod" "host" :spec (object "hostNetwork" t)))))
       (quiet (text report))
       (loud (with-output-to-string (*standard-output*) (print-survey report :notes t))))
  (assert (zerop (length (problems report))))
  (assert (search "no problems found" quiet))
  (assert (search "1 configuration and history note not shown; add `--notes` to list it." quiet))
  (assert (search "Pod host: The Pod uses the node's network directly." loud)))
;;; Rules that say why: restarts, known applications, and Services that wait for a label.
(defun restarter (name &key (code 1) (reason "Error") (restarts 6) liveness (image "example/api:1") limit started)
  (thing "Pod" name
         :spec (object "nodeName" "n1"
                       "containers" (vector (apply #'object "name" "api" "image" image
                                                   (append (when liveness (list "livenessProbe" (object "httpGet" (object "port" 80))))
                                                           (when limit (list "resources" (object "limits" (object "memory" limit))))))))
         :status (object "conditions" (vector (object "type" "Ready" "status" "True"))
                         "containerStatuses"
                         (vector (object "name" "api" "restartCount" restarts
                                         "state" (object "running" (if started (object "startedAt" started) (object)))
                                         "lastState" (object "terminated" (object "reason" reason "exitCode" code
                                                                                  "finishedAt" "2026-01-01T00:00:00Z")))))))
(defun happened (pod reason message &key (type "Warning"))
  (object "kind" "Event" "metadata" (object "name" (format nil "~A-~A" reason (length message)) "namespace" "test"
                                            "uid" (format nil "~A~A" reason (length message)) "resourceVersion" "1")
          "type" type "reason" reason "message" message "count" 3 "lastTimestamp" (timestamp)
          "involvedObject" (object "kind" "Pod" "name" pod "uid" pod "fieldPath" "spec.containers{api}")))
(defun problem-rules (report) (mapcar (lambda (p) (gethash "rule" p)) (problems report)))
(defun survey (&rest things) (checkup "test" (apply #'world (thing "Node" "n1" :ns nil) things)))

;; A crash is named with its exit code and its last log lines, and stands for the restart counter.
(let* ((report (survey (restarter "web-a")
                       (object "kind" "PreviousLog" "metadata" (object "name" "web-a/api" "namespace" "test")
                               "text" (format nil "~{line ~D~%~}fatal: cannot open database~%" '(1 2 3 4 5 6 7 8)))))
       (problem (first (problems report))))
  (assert (equal '("restarts-crash") (problem-rules report)))
  (assert (search "exited with code 1 at 2026-01-01T00:00:00Z, and it has restarted 6 times" (gethash "summary" problem)))
  (assert (equal '("container-restarts-five") (impact-rules problem)))
  (assert (equalp #("kubectl -n test logs web-a -c api --previous --tail=50") (gethash "commands" problem)))
  (assert (search "fatal: cannot open database" (gethash "detail" problem)))
  (assert (not (search "line 2" (gethash "detail" problem)))))
(assert (equal '("restarts-crash") (problem-rules (survey (restarter "web-a")))))
(let ((problem (first (problems (survey (restarter "web-a" :reason "OOMKilled" :code 137 :limit "64Mi"))))))
  (assert (equal "restarts-oom" (gethash "rule" problem)))
  (assert (search "memory limit of 64Mi" (gethash "summary" problem))))
;; A failed liveness check restarted the container only if the kubelet says so
;; or the run died by signal; a run that exited by itself merely also failed it.
(let ((failed (happened "web-a" "Unhealthy" "Liveness probe failed: timeout")))
  (assert (equal '("restarts-crash") (problem-rules (survey (restarter "web-a" :liveness t) failed))))
  (let ((problem (first (problems (survey (restarter "web-a" :liveness t :code 137) failed
                                          (happened "web-a" "Unhealthy" "Readiness probe failed: refused"))))))
    (assert (equal "restarts-liveness-kill" (gethash "rule" problem)))
    (assert (equal "Liveness probe failed: timeout" (gethash "detail" problem)))
    ;; The readiness failure is a different occurrence and is not lost.
    (assert (subsetp '("restarts-crash" "event-Unhealthy") (impact-rules problem) :test #'equal)))
  (assert (equal '("restarts-liveness-kill")
                 (problem-rules (survey (restarter "web-a" :liveness t)
                                (happened "web-a" "Killing" "Container api failed liveness probe, will be restarted"
                                          :type "Normal"))))))

;; What a crashed run wrote names the reason, and the rules ask the cluster
;; for what they need to be sure of it.
(flet ((crashed (lines &key unserved extra)
         (let ((inner (apply #'world (thing "Node" "n1" :ns nil) (restarter "web-a")
                             (object "kind" "PreviousLog" "metadata" (object "name" "web-a/api" "namespace" "test")
                                     "text" (format nil "~{~A~%~}" lines))
                             extra)))
           (checkup "test" (lambda (kind ns name)
                             (if (and unserved (equal kind unserved) (null name))
                                 (values nil :unknown)
                                 (funcall inner kind ns name)))))))
  (let* ((line "level=error msg=\"Failed to watch\" err=\"failed to list *v1alpha1.AlertmanagerConfig: route not found\"")
         (report (crashed (list line) :unserved "AlertmanagerConfig"))
         (problem (first (problems report))))
    (assert (equal '("watches-unserved-kind") (problem-rules report)))
    (assert (search "watches AlertmanagerConfig objects and the API does not serve that kind" (gethash "summary" problem)))
    (assert (member "restarts-crash" (impact-rules problem) :test #'equal))
    ;; The same line about a kind the API does serve is only a crash.
    (assert (equal '("restarts-crash") (problem-rules (crashed (list line))))))
  (assert (equal '("watches-unserved-kind")
                 (problem-rules (crashed '("msg=\"unhandled error\" err=\"failed to sync cache for AlertmanagerConfig informer\"")
                                         :unserved "AlertmanagerConfig"))))
  (let* ((refused "Get \"https://10.96.0.1:443/version\": dial tcp 10.96.0.1:443: connect: connection refused")
         (api (thing "Service" "kubernetes" :ns "default" :spec (object "clusterIP" "10.96.0.1")))
         (problem (first (problems (crashed (list refused) :extra (list api))))))
    (assert (equal "cannot-reach-api" (gethash "rule" problem)))
    (assert (search "cannot reach the Kubernetes API at 10.96.0.1:443" (gethash "summary" problem)))
    (assert (equal '("connection-refused") (problem-rules (crashed (list refused)))))
    (assert (equal '("cannot-reach-api")
                   (problem-rules (crashed '("error while trying to communicate with apiserver: connection refused"))))))
  (let ((problem (first (problems (crashed '("dial tcp: lookup db.example on 10.96.0.10:53: no such host"))))))
    (assert (equal "name-not-resolved" (gethash "rule" problem)))
    (assert (search "cannot resolve the name db.example" (gethash "summary" problem))))
  (assert (equal '("port-in-use") (problem-rules (crashed '("listen tcp :8080: bind: address already in use")))))
  ;; Each reason is reported once however often it was written.
  (assert (= 1 (length (problems (crashed (make-list 12 :initial-element "write /data/x: no space left on device")))))))

;; A cause that a deeper cause brings about is listed under it: a Pod whose
;; probe fails on a node that is down is the node's problem, not a second one.
(flet ((probing (name node)
         (thing "Pod" name
                :spec (object "nodeName" node
                              "containers" (vector (object "name" "api" "readinessProbe"
                                                           (object "httpGet" (object "port" 80)))))
                :status (object "conditions" (vector (object "type" "Ready" "status" "False"))
                                "containerStatuses" (vector (object "name" "api" "ready" nil "started" t
                                                                    "state" (object "running" (object)))))))
       (node (name ready)
         (thing "Node" name :ns nil
                :status (object "conditions" (vector (object "type" "Ready" "status" ready))))))
  (let* ((report (checkup nil (world (probing "on-down" "n1") (probing "on-up" "n2") (node "n1" "False") (node "n2" "True"))))
         (down (find "node-Ready-False" (problems report) :test #'equal :key (lambda (p) (gethash "rule" p))))
         (own (find "readiness-probe-failing" (problems report) :test #'equal :key (lambda (p) (gethash "rule" p)))))
    (assert (= 2 (length (problems report))))
    (assert (subsetp '("readiness-probe-failing" "pod-Ready-False") (impact-rules down) :test #'equal))
    (assert (equal '("Pod/test/on-up") (coerce (gethash "resources" own) 'list)))))
;; A missing Secret is why the container cannot be configured.
(let* ((pod (thing "Pod" "web-a"
                   :spec (object "nodeName" "n1"
                                 "containers" (vector (object "name" "api" "envFrom"
                                                              (vector (object "secretRef" (object "name" "db"))))))
                   :status (object "conditions" (vector (object "type" "Ready" "status" "False"))
                                   "containerStatuses"
                                   (vector (object "name" "api" "state"
                                                   (object "waiting" (object "reason" "CreateContainerConfigError")))))))
       (report (checkup "test" (world pod (thing "Node" "n1" :ns nil))))
       (problem (first (problems report))))
  (assert (equal '("missing-resource") (problem-rules report)))
  (assert (member "waiting-CreateContainerConfigError" (impact-rules problem) :test #'equal)))

;; A Pod that waits for a node: each node is tried, and the first thing that
;; rules it out is named. Nothing is concluded unless every node is ruled out.
(assert (equal '(100 2000 1500 500 268435456000 1000000) 
               (mapcar #'quantity-thousandths '("100m" "2" "1.5" ".5" "256Mi" "1k"))))
(assert (null (quantity-thousandths "lots")))
(flet ((waiting (&key tolerations selector affinity (memory "512Mi"))
         (thing "Pod" "job-a"
                :spec (apply #'object
                             "containers" (vector (object "name" "api" "resources"
                                                          (object "requests" (object "memory" memory "cpu" "100m"))))
                             (append (when tolerations (list "tolerations" tolerations))
                                     (when selector (list "nodeSelector" selector))
                                     (when affinity
                                       (list "affinity"
                                             (object "nodeAffinity"
                                                     (object "requiredDuringSchedulingIgnoredDuringExecution"
                                                             (object "nodeSelectorTerms" affinity)))))))
                :status (object "phase" "Pending"
                                "conditions" (vector (object "type" "PodScheduled" "status" "False")))))
       (worker (name &key taints cordoned labels (memory "8Gi"))
         (thing "Node" name :ns nil :labels labels
                :spec (apply #'object (append (when taints (list "taints" taints))
                                              (when cordoned (list "unschedulable" t))))
                :status (object "conditions" (vector (object "type" "Ready" "status" "True"))
                                "allocatable" (object "cpu" "4" "memory" memory "pods" "110"))))
       (resident (node memory)
         (thing "Pod" (format nil "resident-~A" node)
                :spec (object "nodeName" node
                              "containers" (vector (object "name" "db" "resources"
                                                           (object "requests" (object "memory" memory)))))
                :status (object "phase" "Running" "conditions" (vector (object "type" "Ready" "status" "True")))))
       (placed (&rest things) (checkup nil (apply #'world things))))
  (let ((control (vector (object "key" "node-role.kubernetes.io/control-plane" "effect" "NoSchedule"))))
    (let* ((report (placed (waiting) (worker "n1" :taints control) (worker "n2" :taints control)
                           (worker "n3" :cordoned t) (worker "n4" :memory "1Gi") (resident "n4" "900Mi")))
           (problem (find "pod-unschedulable" (problems report) :test #'equal :key (lambda (p) (gethash "rule" p))))
           (detail (gethash "detail" problem)))
      (assert (search "Pod job-a cannot be placed: none of the 4 nodes will take it." (gethash "summary" problem)))
      (assert (search "n1, n2 has the taint node-role.kubernetes.io/control-plane:NoSchedule, which the Pod does not tolerate" detail))
      (assert (search "n3 is cordoned" detail))
      (assert (search "n4 has 124Mi of memory free and the Pod requests 512Mi" detail))
      ;; It stands for the condition that only says the Pod is unscheduled.
      (assert (member "pod-PodScheduled-False" (impact-rules problem) :test #'equal)))
    (flet ((unplaced-p (&rest things)
             (member "pod-unschedulable" (problem-rules (apply #'placed things)) :test #'equal)))
      ;; One node that is not ruled out is enough to conclude nothing.
      (assert (not (unplaced-p (waiting) (worker "n1" :taints control) (worker "n2"))))
      (assert (not (unplaced-p (waiting :tolerations (vector (object "operator" "Exists")))
                               (worker "n1" :taints control))))
      (assert (not (unplaced-p (waiting :tolerations (vector (object "key" "node-role.kubernetes.io/control-plane"
                                                                     "operator" "Exists" "effect" "NoSchedule")))
                               (worker "n1" :taints control))))
      (assert (unplaced-p (waiting :tolerations (vector (object "key" "other" "operator" "Exists")))
                          (worker "n1" :taints control)))
      ;; A preference is not a refusal.
      (assert (not (unplaced-p (waiting) (worker "n1" :taints (vector (object "key" "k" "effect" "PreferNoSchedule"))))))
      (assert (unplaced-p (waiting :selector (object "disk" "ssd")) (worker "n1" :labels (object "disk" "spinning"))))
      (assert (not (unplaced-p (waiting :selector (object "disk" "ssd")) (worker "n1" :labels (object "disk" "ssd")))))
      (let ((zone-a (vector (object "matchExpressions"
                                    (vector (object "key" "zone" "operator" "In" "values" #("a" "b")))))))
        (assert (unplaced-p (waiting :affinity zone-a) (worker "n1" :labels (object "zone" "c"))))
        (assert (not (unplaced-p (waiting :affinity zone-a) (worker "n1" :labels (object "zone" "b"))))))
      ;; Room is judged from what is already requested on the node.
      (assert (not (unplaced-p (waiting) (worker "n1" :memory "1Gi") (resident "n1" "100Mi"))))
      (assert (unplaced-p (waiting :memory "64Gi") (worker "n1") (worker "n2"))))))

;; What a known application writes means what its authors meant, and only
;; when that application wrote it.
(flet ((wrote (image line)
         (problem-rules
          (checkup "test" (world (thing "Node" "n1" :ns nil) (restarter "web-a" :image image)
                                 (object "kind" "PreviousLog" "metadata" (object "name" "web-a/api" "namespace" "test")
                                         "text" line))))))
  (assert (equal '("coredns-loop")
                 (wrote "registry.k8s.io/coredns/coredns:v1.12.0"
                        "[FATAL] plugin/loop: Loop (127.0.0.1:55953 -> :53) detected for zone \".\"")))
  (assert (equal '("restarts-crash") (wrote "example/api:1" "[FATAL] plugin/loop: Loop (127.0.0.1:55953 -> :53) detected")))
  (assert (equal '("etcd-already-bootstrapped")
                 (wrote "quay.io/coreos/etcd:v3.6.1" "member 8e9e05c52164694d has already been bootstrapped")))
  (assert (equal '("postgres-version-mismatch")
                 (wrote "postgres:18" "FATAL:  database files are incompatible with server")))
  (assert (equal '("postgres-wrong-ownership")
                 (wrote "bitnami/postgresql:17" "FATAL:  data directory \"/var/lib/postgresql/data\" has wrong ownership")))
  (assert (equal '("redis-newer-data") (wrote "redis:7" "Can't handle RDB format version 12"))))

;; Every API server must give an object the same resourceVersion.
(flet ((control-plane (&rest versions)
         (let ((service (thing "Service" "kubernetes" :ns "default" :spec (object "clusterIP" "10.96.0.1")))
               (slice (thing "EndpointSlice" "kubernetes" :ns "default"
                             :labels (object "kubernetes.io/service-name" "kubernetes"))))
           (setf (gethash "ports" slice) (vector (object "port" 6443))
                 (gethash "endpoints" slice)
                 (coerce (loop for nil in versions for index from 1
                               collect (object "addresses" (vector (format nil "10.0.0.~D" index))))
                         'vector))
           (let ((inner (world service slice)))
             (problem-rules
              (checkup "default"
                       (lambda (kind ns name)
                         (if (equal kind "MemberView")
                             (let ((version (nth (1- (parse-integer name :start 7 :end (position #\: name))) versions)))
                               (if version
                                   (values (object "metadata" (object "name" "default" "resourceVersion" version)) :present)
                                   (values nil :unknown)))
                             (funcall inner kind ns name)))))))))
  (assert (equal '("members-disagree") (control-plane "73364" "80509")))
  (assert (null (control-plane "73364" "73364")))
  ;; A member that cannot be reached from here proves nothing, and one member has no peer.
  (assert (null (control-plane "73364" nil)))
  (assert (null (control-plane "73364"))))

;; One finding names the member furthest on and every member that differs, and
;; it comes before a problem that reaches more.
(flet ((cluster (versions &rest things)
         (let ((service (thing "Service" "kubernetes" :ns "default" :spec (object "clusterIP" "10.96.0.1")))
               (slice (thing "EndpointSlice" "kubernetes" :ns "default"
                             :labels (object "kubernetes.io/service-name" "kubernetes"))))
           (setf (gethash "ports" slice) (vector (object "port" 6443))
                 (gethash "endpoints" slice)
                 (coerce (loop for nil in versions for index from 1
                               collect (object "addresses" (vector (format nil "10.0.0.~D" index))))
                         'vector))
           (let ((inner (apply #'world service slice (thing "Node" "n1" :ns nil) things)))
             (checkup nil (lambda (kind ns name)
                            (if (equal kind "MemberView")
                                (values (object "metadata"
                                                (object "name" "default" "resourceVersion"
                                                        (nth (1- (parse-integer name :start 7 :end (position #\: name)))
                                                             versions)))
                                        :present)
                                (funcall inner kind ns name)))))))
       (wrote (pod line)
         (object "kind" "PreviousLog" "metadata" (object "name" (format nil "~A/api" pod) "namespace" "test")
                 "text" (format nil "~A~%" line))))
  (let* ((report (cluster '("9000" "80509" "73364")))
         (problem (first (problems report))))
    (assert (equal '("members-disagree") (problem-rules report)))
    ;; 9000 is behind 80509: versions are compared as numbers.
    (assert (search "10.0.0.2:6443 gives Namespace default resourceVersion 80509, and 10.0.0.1:6443 gives 9000, 10.0.0.3:6443 gives 73364."
                    (gethash "summary" problem)))
    (assert (equal "Control-plane members do not agree" (gethash "title" problem)))
    (assert (equalp #("gr8s member list") (gethash "commands" problem)))
    ;; A fault of the cluster itself is in no namespace.
    (assert (not (search "Namespace: default" (text report)))))
  (let ((stale "err=\"failed to list *v1.StatefulSet: Requested resourceVersion is newer than storage\"")
        (owner '("ReplicaSet" "web-1")))
    ;; A program that gave up on a stale answer is listed under the members that
    ;; disagree, with the workload above it, though no link joins the two.
    (let* ((report (cluster '("80509" "73364")
                            (short "Deployment" "big") (short "ReplicaSet" "big-1" '("Deployment" "big"))
                            (crashing "big-1-a" '("ReplicaSet" "big-1")) (crashing "big-1-b" '("ReplicaSet" "big-1"))
                            (short "ReplicaSet" "web-1")
                            (let ((pod (restarter "web-a")))
                              (setf (gethash "ownerReferences" (gethash "metadata" pod))
                                    (vector (object "kind" (first owner) "name" (second owner) "uid" (second owner)
                                                    "controller" t)))
                              pod)
                            (wrote "web-a" stale)))
           (problem (first (problems report))))
      (assert (equal '("members-disagree" "waiting-CrashLoopBackOff") (problem-rules report)))
      (assert (subsetp '("api-answered-behind" "restarts-crash" "replicaset-ready-deficit") (impact-rules problem)
                       :test #'equal))
      (let ((text (text report)))
        (assert (search "- Pod web-a: container \"api\" gives up because an API server answered it from a state older" text))
        ;; One line for each resource the cause reaches.
        (assert (not (search "- Pod web-a: container \"api\" keeps crashing" text)))))
    (assert (equal '("api-answered-behind") (problem-rules (cluster '("80509" "80509") (restarter "web-a") (wrote "web-a" stale)))))
    (assert (equal '("api-answered-behind")
                   (problem-rules (cluster '("80509" "80509") (restarter "web-a")
                                           (wrote "web-a" "Too large resource version: 85041, current: 77942")))))
    ;; A restart loop that has stopped is not a problem. It is listed under the
    ;; cause that is still there, or as recovered when nothing is.
    (let* ((since "2026-01-01T00:05:00Z")
           (report (cluster '("80509" "73364") (restarter "web-a" :started since) (wrote "web-a" stale)))
           (problem (first (problems report))))
      (assert (equal '("members-disagree") (problem-rules report)))
      (assert (zerop (length (gethash "recovered" report))))
      (assert (equal since (gethash "recoveredAt" (find "api-answered-behind" (coerce (gethash "impact" problem) 'list)
                                                        :test #'equal :key (lambda (entry) (gethash "rule" entry))))))
      (assert (search "from a state older than one it had already been given. It has run without a restart for 1 hour (since 2026-01-01T00:05:00Z)."
                      (text report))))
    (let* ((report (cluster '("80509" "80509") (restarter "web-a" :started "2026-01-01T00:05:00Z") (wrote "web-a" stale)))
           (recovered (coerce (gethash "recovered" report) 'list)))
      (assert (null (problems report)))
      (assert (equal '("api-answered-behind") (mapcar (lambda (entry) (gethash "rule" entry)) recovered)))
      (assert (search "no problems found by the checks that ran. 1 more has recovered." (text report)))
      (assert (search "It has run without a restart for 1 hour (since 2026-01-01T00:05:00Z). Namespace: test" (text report))))))
(let* ((report (survey (restarter "web-a" :started "2026-01-01T00:05:00Z")))
       (recovered (coerce (gethash "recovered" report) 'list)))
  (assert (null (problems report)))
  (assert (equal '("restarted-earlier") (mapcar (lambda (entry) (gethash "rule" entry)) recovered)))
  (assert (search "restarted 6 times; its last run exited with code 1 at 2026-01-01T00:00:00Z, and it has run without a restart since 2026-01-01T00:05:00Z."
                  (gethash "summary" (first recovered))))
  (assert (search "Recovered" (text report))))
(assert (search "its last run was killed for running out of memory at"
                (gethash "summary" (aref (gethash "recovered" (survey (restarter "web-a" :reason "OOMKilled" :code 137
                                                                                 :started "2026-01-01T00:05:00Z")))
                                         0))))
;; A run that began a moment ago is one more turn of the loop.
(assert (equal '("restarts-crash") (problem-rules (survey (restarter "web-a" :started (timestamp))))))

;; A program the API refuses says what it was refused. The bindings and roles
;; say which link is missing.
(flet ((refused (line &rest access)
         (checkup "test" (apply #'world (thing "Node" "n1" :ns nil) (restarter "web-a")
                                (object "kind" "PreviousLog" "metadata" (object "name" "web-a/api" "namespace" "test")
                                        "text" line)
                                access)))
       (binding (kind name role-kind role &rest subjects)
         (let ((object (thing kind name :ns (when (equal kind "RoleBinding") "test"))))
           (setf (gethash "roleRef" object) (object "kind" role-kind "name" role)
                 (gethash "subjects" object) (coerce subjects 'vector))
           object))
       (role (kind name verbs resources &optional (groups '("")))
         (let ((object (thing kind name :ns (when (equal kind "Role") "test"))))
           (setf (gethash "rules" object)
                 (vector (object "verbs" (coerce verbs 'vector) "apiGroups" (coerce groups 'vector)
                                 "resources" (coerce resources 'vector))))
           object)))
  (let ((cluster-wide "E1120 pods is forbidden: User \"system:serviceaccount:test:web\" cannot list resource \"pods\" in API group \"\" at the cluster scope")
        (account (object "kind" "ServiceAccount" "namespace" "test" "name" "web")))
    (let ((problem (first (problems (refused cluster-wide)))))
      (assert (equal "access-not-bound" (gethash "rule" problem)))
      (assert (search "ServiceAccount test/web may not list pods in any namespace, and no RoleBinding or ClusterRoleBinding gives it a role there"
                      (gethash "summary" problem)))
      (assert (member "restarts-crash" (impact-rules problem) :test #'equal)))
    (let ((problem (first (problems (refused cluster-wide
                                             (binding "ClusterRoleBinding" "web" "ClusterRole" "reader" account)
                                             (role "ClusterRole" "reader" '("get" "watch") '("pods")))))))
      (assert (equal "access-verb-missing" (gethash "rule" problem)))
      (assert (search "It is bound to ClusterRole reader, where a rule covers that resource but none gives that verb"
                      (gethash "summary" problem))))
    (assert (equal '("access-not-granted")
                   (problem-rules (refused cluster-wide
                                           (binding "ClusterRoleBinding" "web" "ClusterRole" "reader" account)
                                           (role "ClusterRole" "reader" '("list") '("services"))))))
    ;; Roles that do allow it: the refusal is not explained, so nothing is said of it.
    (assert (equal '("restarts-crash")
                   (problem-rules (refused cluster-wide
                                           (binding "ClusterRoleBinding" "web" "ClusterRole" "reader" account)
                                           (role "ClusterRole" "reader" '("*") '("pods"))))))
    ;; A RoleBinding in another namespace's scope does not reach the whole cluster.
    (assert (equal '("access-not-bound")
                   (problem-rules (refused cluster-wide
                                           (binding "RoleBinding" "web" "Role" "reader" account)
                                           (role "Role" "reader" '("list") '("pods")))))))
  ;; In a namespace, a Role bound to the namespace's ServiceAccounts as a group
  ;; allows it; quotes may arrive escaped, and the resource may be in a group.
  (let ((namespaced "level=error err=\"servicemonitors.monitoring.coreos.com is forbidden: User \\\"system:serviceaccount:test:web\\\" cannot watch resource \\\"servicemonitors\\\" in API group \\\"monitoring.coreos.com\\\" in the namespace \\\"test\\\"\""))
    (let ((problem (first (problems (refused namespaced)))))
      (assert (equal "access-not-bound" (gethash "rule" problem)))
      (assert (search "may not watch servicemonitors.monitoring.coreos.com in namespace test" (gethash "summary" problem))))
    (assert (equal '("restarts-crash")
                   (problem-rules (refused namespaced
                                           (binding "RoleBinding" "all" "Role" "monitor"
                                                    (object "kind" "Group" "name" "system:serviceaccounts:test"))
                                           (role "Role" "monitor" '("get" "list" "watch") '("servicemonitors")
                                                 '("monitoring.coreos.com"))))))))

;; A known application's own report says what is wrong, and what to run.
(flet ((bao (image initialized)
         (let ((pod (thing "Pod" "bao-0"
                           :spec (object "nodeName" "n1"
                                         "containers" (vector (object "name" "api" "image" image "readinessProbe"
                                                                      (object "exec" (object "command" #("bao" "status"))))))
                           :status (object "conditions" (vector (object "type" "Ready" "status" "False"
                                                                        "lastTransitionTime" "2026-01-02T00:00:00Z"))
                                           "containerStatuses" (vector (object "name" "api" "ready" nil "started" t
                                                                               "state" (object "running" (object))))))))
           (survey pod (happened "bao-0" "Unhealthy"
                                 (format nil "Readiness probe failed: Key          Value~%Initialized    ~A~%Sealed         true"
                                         initialized))))))
  (let* ((report (bao "quay.io/openbao/openbao:2.7.2" "false")) (problem (first (problems report))))
    (assert (equal '("openbao-uninitialized") (problem-rules report)))
    (assert (search "OpenBao in container \"api\" has never been initialised" (gethash "summary" problem)))
    (assert (equalp #("kubectl -n test exec -ti bao-0 -c api -- bao operator init"
                      "kubectl -n test exec -ti bao-0 -c api -- bao operator unseal")
                    (gethash "commands" problem)))
    (assert (equal "2026-01-02T00:00:00Z" (gethash "since" problem)))
    (assert (member "readiness-probe-failing" (impact-rules problem) :test #'equal)))
  (assert (equal '("openbao-sealed") (problem-rules (bao "hashicorp/vault:1.20" "true"))))
  (assert (equal '("readiness-probe-failing") (problem-rules (bao "example/other:1" "false")))))

;; Services that select a label the application was never configured to set are
;; one problem with its own cause, not a consequence of the Pod's other trouble.
(flet ((registered (configuration)
         (let ((pod (crashing "bao-0" nil)))
           (setf (gethash "labels" (gethash "metadata" pod)) (object "app" "bao")
                 (gethash "spec" pod)
                 (object "nodeName" "n1" "containers" (vector (object "name" "api" "image" "openbao/openbao:2"))
                         "volumes" (vector (object "name" "config" "configMap" (object "name" "bao-config")))))
           (survey pod
                   (let ((configmap (thing "ConfigMap" "bao-config")))
                     (setf (gethash "data" configmap) (object "server.hcl" configuration))
                     configmap)
                   (thing "Service" "bao-active" :spec (object "selector" (object "app" "bao" "openbao-active" "true")))
                   (thing "Service" "bao-standby" :spec (object "selector" (object "app" "bao" "openbao-active" "false")))))))
  (let* ((report (registered "storage \"raft\" {} # DO-NOT-PRINT"))
         (problem (find "service-label-never-set" (problems report) :test #'equal :key (lambda (p) (gethash "rule" p)))))
    (assert (equal '("Service/test/bao-active" "Service/test/bao-standby")
                   (sort (coerce (gethash "resources" problem) 'list) #'string<)))
    (assert (search "ConfigMap bao-config has no service_registration block" (gethash "summary" problem)))
    (assert (not (search "DO-NOT-PRINT" (com.inuoe.jzon:stringify report))))
    (assert (not (search "Possibly related" (text report))))
    ;; The Service stays empty until the Pod is healthy, so the Pod's own problem comes first.
    (assert (equal "service-label-never-set" (car (last (problem-rules report)))))
    (assert (rest (problems report))))
  (let ((report (registered "service_registration \"kubernetes\" {}")))
    (assert (not (member "service-label-never-set" (problem-rules report) :test #'equal)))
    (assert (search "Possibly related" (text report)))))

;; Among causes of equal reach the one that changed first leads, and a long
;; report starts with its contents and quotes only the start of long output.
(flet ((down (name since)
         (thing "Node" name :ns nil
                :status (object "conditions" (vector (object "type" "Ready" "status" "False"
                                                             "lastTransitionTime" since))))))
  (let* ((report (checkup nil (world (down "late" "2026-03-01T00:00:00Z") (down "early" "2026-01-01T00:00:00Z")
                                     (down "middle" "2026-02-01T00:00:00Z") (down "last" "2026-04-01T00:00:00Z"))))
         (text (text report)))
    (assert (equal '("Node/early" "Node/middle" "Node/late" "Node/last")
                   (mapcar (lambda (p) (aref (gethash "resources" p) 0)) (problems report))))
    (assert (search (format nil "~%1. Node early: The node is not ready~%2. Node middle") text))
    (assert (search "Since: 1 hour ago (2026-01-01T00:00:00Z)" text))))
(let ((text (render-markdown
             (problem-markdown (object "summary" "s" "resources" #("Pod/test/a") "impact" #() "commands" #() "rule" "r"
                                       "causeFound" t "nextStep" "n" "detailHeading" "h"
                                       "detail" (format nil "~{l~D~^~%~}" '(1 2 3 4 5 6 7 8 9)))
                               1 nil))))
  (assert (search "l6" text))
  (assert (not (search "l7" text)))
  (assert (search "(3 more lines; --json has all of it)" text)))
;; The report is Markdown. Text from the API renders as itself, a terminal
;; gets wrapped lines, and nothing a log line holds can end its block.
(assert (equal "a_b *v1 <x> `c` [y] &amp;" (string-right-trim '(#\Newline) (render-markdown (markdown-text "a_b *v1 <x> `c` [y] &amp;")))))
(assert (equal "1. not a list" (string-right-trim '(#\Newline) (render-markdown (markdown-text "1. not a list")))))
(assert (equal (format nil "    one ``` two~%    # three~%") (render-markdown (markdown-block '("one ``` two" "# three")))))
(let ((lines (uiop:split-string (render-markdown (format nil "## Title~%~%~{~A~^ ~}~%~%- ~{~A~^ ~}~%" (make-list 30 :initial-element "word")
                                                         (make-list 30 :initial-element "item"))
                                                 :width 40)
                                :separator '(#\Newline))))
  (assert (every (lambda (line) (<= (length line) 40)) lines))
  (assert (find "- item item item item item item item" lines :test #'equal))
  (assert (find "  item item item item item item item" lines :test #'equal)))
;; A command is never broken, so that it can be pasted.
(assert (search (format nil "    kubectl ~{~A~^ ~}~%" (make-list 30 :initial-element "argument"))
                (render-markdown (markdown-block (list (format nil "kubectl ~{~A~^ ~}" (make-list 30 :initial-element "argument"))) "sh")
                                 :width 40)))
(assert (equal "level=error msg=\"Unable to sync caches\" controller=alertmanager"
               (quiet-log-line "ts=2026-11-20T12:42:40.915065335Z level=error caller=/go/pkg/shared_informer.go:506 msg=\"Unable to sync caches\" controller=alertmanager")))
(assert (equal "Pod bao-0: OpenBao in container \"api\" has never been initialised"
               (problem-title "Pod bao-0: OpenBao in container \"api\" has never been initialised, so it is sealed and reports that it is not ready.")))
(assert (equal "Container \"api\" in Pod web-a: The container has restarted at least five times"
               (problem-title "Container \"api\" in Pod web-a: The container has restarted at least five times.")))
(format t "Restart, recovery, application, label, order and report rules passed.~%")
;;; Impact: the same links followed upwards.
(flet ((running (name node &key owner labels secret)
         (thing "Pod" name :owner owner :labels labels
                :spec (apply #'object "nodeName" node
                             (when secret
                               (list "containers"
                                     (vector (object "name" "api" "envFrom"
                                                     (vector (object "secretRef" (object "name" secret))))))))
                :status (object "phase" "Running" "conditions" (vector (object "type" "Ready" "status" "True")))))
       (effects (report)
         (sort (map 'list (lambda (e) (list (gethash "resource" e) (gethash "group" e) (gethash "text" e)))
                    (gethash "effects" report))
               #'string< :key #'first)))
  (let* ((web (object "app" "web"))
         (budget (thing "PodDisruptionBudget" "db" :spec (object "selector" (object "matchLabels" (object "app" "db")))
                        :status (object "disruptionsAllowed" 0)))
         (cluster (world (thing "Node" "n1" :ns nil) (thing "Node" "n2" :ns nil)
                         (thing "Deployment" "web") (thing "ReplicaSet" "web-1" :owner '("Deployment" "web"))
                         (running "web-1-a" "n1" :owner '("ReplicaSet" "web-1") :labels web :secret "token")
                         (running "web-1-b" "n2" :owner '("ReplicaSet" "web-1") :labels web :secret "token")
                         (thing "StatefulSet" "db")
                         (running "db-0" "n1" :owner '("StatefulSet" "db") :labels (object "app" "db"))
                         (running "lone" "n1")
                         (thing "Service" "web" :spec (object "selector" web))
                         (thing "Service" "db" :spec (object "selector" (object "app" "db")))
                         budget))
         (node (effects (impact-report "Node" "n1" nil cluster))))
    (assert (equal '(("Deployment/test/web" "shrinks" "1 of its 2 ready Pods goes")
                     ("Pod/test/db-0" "refused"
                      "its eviction would be refused: PodDisruptionBudget db in namespace test allows no disruption now")
                     ("Pod/test/lone" "stops" "nothing owns it, so nothing starts it again")
                     ("Service/test/db" "stops" "every Pod it sends traffic to goes")
                     ("StatefulSet/test/db" "stops" "its only ready Pod goes"))
                   node))
    ;; A Secret is named, never read: the Pods that need it keep running but could not restart.
    (assert (equal '(("Deployment/test/web" "cannot_restart"
                      "2 of its Pods keep running, but none can be started again without it"))
                   (effects (impact-report "Secret" "token" "test" cluster))))
    ;; Removing a workload takes its Pods, and so what is routed to them.
    (assert (equal '(("Service/test/db" "stops" "every Pod it sends traffic to goes"))
                   (effects (impact-report "StatefulSet" "db" "test" cluster))))
    (assert (null (effects (impact-report "Node" "n9" nil cluster))))
    (let ((text (with-output-to-string (*standard-output*) (print-impact (impact-report "Node" "n1" nil cluster)))))
      (assert (search "Losing Node n1 would affect 5 resources." text))
      (assert (< (search "Stops, until its Pods run somewhere else:" text)
                 (search "Runs on fewer Pods:" text)
                 (search "A drain would stop at:" text))))))
(format t "Impact of losing a node, a Secret and a workload passed.~%")
(assert (> *verdict-checks* 20))
(format t "Survey causes, replica collapse, reach order, unexplained symptoms, target scope, list reuse and notes checks passed.~%")

;; Steps are told to whoever watches; with nobody watching nothing is written.
(let ((steps nil))
  (let ((*progress* (lambda (step) (push step steps))))
    (checkup "test" (lambda (kind ns name) (declare (ignore kind ns name)) (values (object "items" #()) :present))))
  (assert (equal "Working out what causes what" (first steps))))
(assert (equal "" (with-output-to-string (out) (assert (eql 7 (call-with-progress (lambda () (progress "x") 7) :stream out))))))

;; A report does not open by repeating its headline.
(assert (equal "It is sealed." (problem-detail "Pod a: OpenBao was never initialised, so it is sealed." "Pod a: OpenBao was never initialised")))
(assert (equal "A gives 2." (problem-detail "Members do not agree: a gives 2." "Members do not agree")))
(assert (equal "" (problem-detail "The slice lists no endpoints." "The slice lists no endpoints")))
(assert (equal "One thing and another." (problem-detail "One thing and another." "One thing")))
;; A reader is told how long ago, with the timestamp after it.
(let ((*report-time* (encode-universal-time 0 5 1 1 1 2026 0)))
  (assert (equal "exited 50 minutes ago (2026-01-01T00:15:00Z), then 1 hour ago (2026-01-01T00:00:00Z)."
                 (with-ages "exited at 2026-01-01T00:15:00Z, then 2026-01-01T00:00:00Z.")))
  (assert (equal "2 days ago (2025-12-30T00:00:00Z)" (with-ages "2025-12-30T00:00:00Z")))
  (assert (equal "It has run for 50 minutes (since 2026-01-01T00:15:00Z)." (with-ages "It has run since 2026-01-01T00:15:00Z.")))
  ;; What is not a past timestamp is left as it is.
  (assert (equal "at 2026-01-02T00:00:00Z" (with-ages "at 2026-01-02T00:00:00Z")))
  (assert (equal "TLS To T" (with-ages "TLS To T"))))

;; A failed image pull is one problem, named by what the pull error says, with
;; the kubelet's back-off and its Failed event beneath it (podster-6id).
(flet ((puller (error &key (reason "ImagePullBackOff") (message t) (init t))
         (let ((image "quay.io/prometheus-operator/prometheus-config-reloader:v0.95.2"))
           (thing "Pod" "prom-0"
                  :spec (object "nodeName" "n1"
                                (if init "initContainers" "containers")
                                (vector (object "name" "reloader" "image" image)))
                  :status (object "conditions" (vector (object "type" "Ready" "status" "False"))
                                  (if init "initContainerStatuses" "containerStatuses")
                                  (vector (object "name" "reloader" "image" image "ready" nil "restartCount" 0
                                                  "state" (object "waiting"
                                                                  (apply #'object "reason" reason
                                                                         (when message
                                                                           (list "message"
                                                                                 (format nil "Back-off pulling image ~S: ErrImagePull: ~A"
                                                                                         image error)))))))))))
       (pull-failed (error &key (init t))
         (let ((event (happened "prom-0" "Failed"
                                (format nil "Failed to pull image \"quay.io/x:1\": ~A" error))))
           (setf (gethash "fieldPath" (gethash "involvedObject" event))
                 (if init "spec.initContainers{reloader}" "spec.containers{reloader}"))
           event)))
  (let* ((mirror (concatenate 'string "gRPC error 2 (UNKNOWN): failed to pull and unpack image: failed to copy: "
                              "httpReadSeeker: failed open: unexpected status from GET request to "
                              "http://127.0.0.1:38805/v2/prometheus-operator/prometheus-config-reloader/blobs/"
                              "sha256:fbaaf910?ns=quay.io: 503 Service Unavailable"))
         (report (survey (puller mirror) (pull-failed mirror)))
         (problem (first (problems report))))
    (assert (equal '("image-mirror-unavailable") (problem-rules report)))
    (assert (search "gr8s image mirror on its node" (gethash "summary" problem)))
    (assert (search "\"reloader\"" (gethash "summary" problem)))
    (assert (subsetp '("waiting-ImagePullBackOff" "event-Failed") (impact-rules problem) :test #'equal))
    (assert (search "503 Service Unavailable" (gethash "detail" problem))))
  ;; The waiting state alone is enough, and so is the Event alone.
  (assert (equal '("image-not-found")
                 (problem-rules (survey (puller "failed to resolve reference \"quay.io/x:1\": quay.io/x:1: not found"
                                                :init nil)))))
  (assert (equal '("image-pull-unauthorized")
                 (problem-rules (survey (puller nil :reason "ErrImagePull" :message nil :init nil)
                                        (pull-failed "pull access denied, repository does not exist or may require authorization: server message: insufficient_scope: authorization failed"
                                                     :init nil)))))
  (assert (equal '("registry-name-not-resolved")
                 (problem-rules (survey (puller "dial tcp: lookup registry.example on 10.96.0.10:53: no such host")))))
  (assert (equal '("registry-unreachable")
                 (problem-rules (survey (puller "dial tcp 192.0.2.7:443: i/o timeout")))))
  (assert (equal '("image-pull-rate-limited")
                 (problem-rules (survey (puller "429 Too Many Requests - Server message: toomanyrequests: You have reached your pull rate limit")))))
  (assert (equal '("registry-tls-untrusted")
                 (problem-rules (survey (puller "tls: failed to verify certificate: x509: certificate signed by unknown authority")))))
  ;; An error the rules don't recognise leaves the kubelet's own finding.
  (assert (equal '("waiting-ImagePullBackOff") (problem-rules (survey (puller "something unexpected"))))))
