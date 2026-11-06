(in-package #:gr8s/tests)
(def-suite template-defaults :in gr8s)
(in-suite template-defaults)

;;; Upstream v1.37.2's SetObjectDefaults_{Deployment,ReplicaSet,StatefulSet,DaemonSet,Job,CronJob,
;;; ReplicationController} apply SetDefaults_PodSpec and the nested container and volume
;;; defaults to the Pod template, but not SetDefaults_Pod's enableServiceLinks.

(defun template-spec (object &rest path)
  "Return the Pod template spec found at PATH (field names) under OBJECT's spec."
  (let ((spec (gethash "spec" object)))
    (dolist (field path) (setf spec (gethash field spec)))
    (gethash "spec" (gethash "template" spec))))

(defun check-template-defaults (pod-spec context)
  (is (equal "Always" (gethash "imagePullPolicy" (aref (gethash "containers" pod-spec) 0))) "~A" context)
  (is (equal "File" (gethash "terminationMessagePolicy" (aref (gethash "containers" pod-spec) 0))) "~A" context)
  (is (equal "ClusterFirst" (gethash "dnsPolicy" pod-spec)) "~A" context)
  (is (equal "default-scheduler" (gethash "schedulerName" pod-spec)) "~A" context)
  (is (hash-table-p (gethash "securityContext" pod-spec)) "~A" context)
  (is (null (nth-value 1 (gethash "enableServiceLinks" pod-spec))) "~A" context))

(defun minimal-pod-spec (&optional (restart "Always"))
  (gr8s::core-object "restartPolicy" restart
                     "containers" (vector (gr8s::core-object "name" "main" "image" "busybox"))))

(test workload-templates-carry-the-pod-spec-defaults
  (with-temporary-store (store path)
    (values path)
    (flet ((create (resource kind spec)
             (gr8s::create-core-resource
              store resource (gr8s::core-object "apiVersion" (if (member kind '("Job" "CronJob") :test #'equal) "batch/v1" "apps/v1")
                                                "kind" kind "metadata" (gr8s::core-object "name" "t") "spec" spec)
              "alpha")))
      (dolist (resource '(("deployments" "Deployment") ("replicasets" "ReplicaSet")
                          ("daemonsets" "DaemonSet") ("statefulsets" "StatefulSet")))
        (check-template-defaults
         (template-spec (create (first resource) (second resource)
                                (gr8s::core-object "selector" (gr8s::core-object "matchLabels" (gr8s::core-object "app" "t"))
                                                   "template" (gr8s::core-object "metadata" (gr8s::core-object "labels" (gr8s::core-object "app" "t"))
                                                                                 "spec" (minimal-pod-spec)))))
         (first resource)))
      (check-template-defaults
       (template-spec (create "jobs" "Job" (gr8s::core-object "template" (gr8s::core-object "spec" (minimal-pod-spec "Never")))))
       "jobs")
      (check-template-defaults
       (template-spec (create "cronjobs" "CronJob"
                              (gr8s::core-object "schedule" "*/5 * * * *"
                                                 "jobTemplate" (gr8s::core-object "spec" (gr8s::core-object "template" (gr8s::core-object "spec" (minimal-pod-spec "Never"))))))
                      "jobTemplate" "spec")
       "cronjobs"))))

(defun strip-template-defaults (pod-spec)
  "Remove what an older gr8s did not store in a template, as if it had stored POD-SPEC."
  (dolist (field '("schedulerName" "securityContext")) (remhash field pod-spec))
  (loop for container across (gethash "containers" pod-spec)
        do (dolist (field '("imagePullPolicy" "terminationMessagePath" "terminationMessagePolicy"))
             (remhash field container))))

(test a-deployment-gaining-template-defaults-keeps-its-replica-set
  (with-temporary-store (store path)
    (values path)
    (let* ((runtime (make-fake-runtime)) (reconciler (make-reconciler store runtime)))
      (gr8s::create-core-resource store "deployments" (workload-fixture "Deployment" "web" 2) "alpha")
      (run-workload-passes reconciler)
      (mark-workload-pods-ready store runtime)
      (run-workload-passes reconciler)
      (let ((pods (mapcar #'pod-uid (list-pods store "alpha")))
            (set (gethash "name" (gethash "metadata" (first (gr8s::list-core-resources store "replicasets" "alpha"))))))
        (is (= 2 (length pods)))
        ;; As an older gr8s stored them.
        (strip-template-defaults (template-spec (gr8s::get-core-resource-unlocked store "deployments" "alpha" "web")))
        (strip-template-defaults (template-spec (gr8s::get-core-resource-unlocked store "replicasets" "alpha" set)))
        ;; Its next write stores the defaults; that is not a new template.
        (gr8s::update-core-resource store "deployments" "alpha" "web"
          (lambda (object) (setf (gethash "annotations" (gethash "metadata" object)) (gr8s::core-object "touched" "yes")) object))
        (is (equal "IfNotPresent" (gethash "imagePullPolicy" (aref (gethash "containers" (template-spec (gr8s::get-core-resource store "deployments" "alpha" "web"))) 0))))
        (run-workload-passes reconciler)
        (is (equal (list set) (mapcar (lambda (object) (gethash "name" (gethash "metadata" object)))
                                      (gr8s::list-core-resources store "replicasets" "alpha"))))
        (is (equal (sort (copy-list pods) #'string<) (sort (mapcar #'pod-uid (list-pods store "alpha")) #'string<)))))))

(test a-daemonset-gaining-template-defaults-keeps-its-revision
  (with-temporary-store (store path)
    (values path)
    (register-test-nodes store "node-a")
    (let* ((runtime (make-fake-runtime)) (reconciler (make-reconciler store runtime)))
      (gr8s::create-core-resource store "daemonsets" (daemonset-fixture "ds") "alpha")
      (run-workload-passes reconciler)
      (mark-all-pods-ready store runtime "alpha")
      (run-workload-passes reconciler)
      (let ((pods (mapcar #'pod-uid (live-pods store "alpha")))
            (revision (first (gr8s::list-core-resources store "controllerrevisions" "alpha"))))
        (is (= 1 (length pods)))
        (strip-template-defaults (template-spec (gr8s::get-core-resource-unlocked store "daemonsets" "alpha" "ds")))
        (strip-template-defaults
         (gethash "spec" (gethash "template" (gethash "spec" (gethash "data" (gr8s::get-core-resource-unlocked
                                                                              store "controllerrevisions" "alpha"
                                                                              (gethash "name" (gethash "metadata" revision))))))))
        (gr8s::update-core-resource store "daemonsets" "alpha" "ds"
          (lambda (object) (setf (gethash "annotations" (gethash "metadata" object)) (gr8s::core-object "touched" "yes")) object))
        (run-workload-passes reconciler)
        (is (= 1 (length (gr8s::list-core-resources store "controllerrevisions" "alpha"))))
        (is (equal pods (mapcar #'pod-uid (live-pods store "alpha"))))))))

(test a-job-gaining-template-defaults-is-not-a-template-change
  (with-temporary-store (store path)
    (values path)
    (gr8s::create-core-resource
     store "jobs" (gr8s::core-object "apiVersion" "batch/v1" "kind" "Job" "metadata" (gr8s::core-object "name" "j")
                                     "spec" (gr8s::core-object "template" (gr8s::core-object "spec" (minimal-pod-spec "Never"))))
     "alpha")
    (strip-template-defaults (template-spec (gr8s::get-core-resource-unlocked store "jobs" "alpha" "j")))
    (finishes
      (gr8s::update-core-resource store "jobs" "alpha" "j"
        (lambda (object) (setf (gethash "annotations" (gethash "metadata" object)) (gr8s::core-object "touched" "yes")) object)))))
