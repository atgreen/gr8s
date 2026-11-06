;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Verify StatefulSet admission and the controller's ordered and parallel Pod
;;;; management, stable identity, partitioned rolling updates, rollback to an
;;;; earlier ControllerRevision and claims bound through the storage controller.

(in-package #:gr8s/tests)
(def-suite statefulsets :in gr8s)
(in-suite statefulsets)

(defun stateful-fixture (name &key (replicas 3) policy partition claims update-type retention start)
  "Build a StatefulSet with the given policies in the test namespace's style."
  (let ((spec (gr8s::core-object
               "replicas" replicas "serviceName" "svc"
               "selector" (gr8s::core-object "matchLabels" (gr8s::core-object "app" name))
               "template" (gr8s::core-object
                           "metadata" (gr8s::core-object "labels" (gr8s::core-object "app" name))
                           "spec" (gr8s::core-object "nodeName" "gr8s-local" "terminationGracePeriodSeconds" 0
                                                     "containers" (vector (gr8s::core-object "name" "main" "image" "busybox:1.36.1")))))))
    (when policy (setf (gethash "podManagementPolicy" spec) policy))
    (when (or partition update-type)
      (let ((strategy (gr8s::core-object "type" (or update-type "RollingUpdate"))))
        (when partition (setf (gethash "rollingUpdate" strategy) (gr8s::core-object "partition" partition)))
        (setf (gethash "updateStrategy" spec) strategy)))
    (when claims (setf (gethash "volumeClaimTemplates" spec) claims))
    (when retention (setf (gethash "persistentVolumeClaimRetentionPolicy" spec) retention))
    (when start (setf (gethash "ordinals" spec) (gr8s::core-object "start" start)))
    (gr8s::core-object "apiVersion" "apps/v1" "kind" "StatefulSet" "metadata" (gr8s::core-object "name" name) "spec" spec)))

(defun stateful-claim-template (name)
  "Build a volume claim template requesting one GiB with no storage class."
  (gr8s::core-object "metadata" (gr8s::core-object "name" name)
                     "spec" (gr8s::core-object "accessModes" #("ReadWriteOnce") "storageClassName" ""
                                               "resources" (gr8s::core-object "requests" (gr8s::core-object "storage" "1Gi")))))

(defun stateful-pod-names (store)
  "Return the sorted names of the test namespace's Pods."
  (sort (mapcar #'pod-name (list-pods store "alpha")) #'string<))

(defun stateful-pass (reconciler &optional ready)
  "Run one controller pass, then mark Pods ready when READY so the next pass may advance."
  (let ((store (gr8s::reconciler-store reconciler)) (runtime (gr8s::reconciler-runtime reconciler)))
    (gr8s::reconcile-workloads reconciler)
    (reconcile-all reconciler)
    (when ready (mark-workload-pods-ready store runtime) (reconcile-all reconciler))))

(defun stateful-settle (reconciler &optional (passes 12))
  "Run enough passes with every Pod ready for the controller to converge."
  (dotimes (index passes) (stateful-pass reconciler t))
  (gr8s::reconcile-workloads reconciler))

(defun stateful-set-image (store name image)
  "Change the set's only container image through an ordinary update."
  (gr8s::update-core-resource store "statefulsets" "alpha" name
    (lambda (object)
      (setf (gethash "image" (aref (gethash "containers" (gethash "spec" (gethash "template" (gethash "spec" object)))) 0)) image)
      object)))

(defun stateful-pod-image (store name)
  "Return the image of the named Pod's only container."
  (gethash "image" (aref (gethash "containers" (gethash "spec" (pod-to-object (get-pod store "alpha" name)))) 0)))

(defun stateful-pod-label (store name label)
  "Return one label of the named Pod."
  (gethash label (gethash "labels" (gethash "metadata" (pod-to-object (get-pod store "alpha" name))))))

(test statefulset-admission-defaults-and-refuses-what-cannot-work
  (with-temporary-store (store path)
    (values path)
    (let* ((created (gr8s::create-core-resource store "statefulsets" (stateful-fixture "web") "alpha"))
           (spec (gethash "spec" created)))
      (is (equal "OrderedReady" (gethash "podManagementPolicy" spec)))
      (is (equal "RollingUpdate" (gethash "type" (gethash "updateStrategy" spec))))
      (is (zerop (gethash "partition" (gethash "rollingUpdate" (gethash "updateStrategy" spec)))))
      (is (= 10 (gethash "revisionHistoryLimit" spec)))
      (is (equal "Retain" (gethash "whenDeleted" (gethash "persistentVolumeClaimRetentionPolicy" spec))))
      (is (= 1 (gethash "generation" (gethash "metadata" created)))))
    (flet ((refused (&rest arguments)
             (signals gr8s::kubernetes-error
               (gr8s::create-core-resource store "statefulsets" (apply #'stateful-fixture "bad" arguments) "alpha"))))
      (refused :policy "Sometimes")
      (refused :update-type "Recreate")
      (refused :partition -1)
      (refused :start -1)
      (refused :retention (gr8s::core-object "whenDeleted" "Maybe"))
      (refused :claims (vector (gr8s::core-object "metadata" (gr8s::core-object "name" "NOT_A_LABEL") "spec" (gr8s::core-object))))
      (refused :claims (vector (stateful-claim-template "a") (stateful-claim-template "a"))))
    (signals gr8s::kubernetes-error
      (gr8s::create-core-resource store "statefulsets"
                                  (stateful-fixture (make-string 53 :initial-element #\a)) "alpha"))
    (let ((rolling (stateful-fixture "surge")))
      (setf (gethash "updateStrategy" (gethash "spec" rolling))
            (gr8s::core-object "type" "RollingUpdate" "rollingUpdate" (gr8s::core-object "maxUnavailable" 2)))
      (signals gr8s::kubernetes-error (gr8s::create-core-resource store "statefulsets" rolling "alpha")))
    ;; Only upstream's listed fields may change after creation.
    (signals gr8s::kubernetes-error
      (gr8s::update-core-resource store "statefulsets" "alpha" "web"
        (lambda (object) (setf (gethash "serviceName" (gethash "spec" object)) "other") object)))
    (let ((scaled (gr8s::update-core-resource store "statefulsets" "alpha" "web"
                    (lambda (object) (setf (gethash "replicas" (gethash "spec" object)) 5) object))))
      (is (= 2 (gethash "generation" (gethash "metadata" scaled)))))))

(test statefulset-creates-pods-in-order-with-stable-identity
  (with-budget-cluster (store runtime reconciler)
    (gr8s::create-core-resource store "statefulsets" (stateful-fixture "web") "alpha")
    ;; Each successor waits until its predecessor is ready.
    (stateful-pass reconciler)
    (stateful-pass reconciler)
    (is (equal '("web-0") (stateful-pod-names store)))
    (mark-workload-pods-ready store runtime)
    (reconcile-all reconciler)
    (stateful-pass reconciler)
    (stateful-pass reconciler)
    (is (equal '("web-0" "web-1") (stateful-pod-names store)))
    (stateful-settle reconciler)
    (is (equal '("web-0" "web-1" "web-2") (stateful-pod-names store)))
    (let* ((pod (pod-to-object (get-pod store "alpha" "web-1"))) (spec (gethash "spec" pod)))
      (is (equal "web-1" (gethash "hostname" spec)))
      (is (equal "svc" (gethash "subdomain" spec)))
      (is (equal "web-1" (stateful-pod-label store "web-1" "statefulset.kubernetes.io/pod-name")))
      (is (equal "1" (stateful-pod-label store "web-1" "apps.kubernetes.io/pod-index"))))
    (let ((status (gethash "status" (gr8s::get-core-resource store "statefulsets" "alpha" "web"))))
      (is (= 3 (gethash "replicas" status)))
      (is (= 3 (gethash "readyReplicas" status)))
      (is (= 3 (gethash "currentReplicas" status)))
      (is (= 3 (gethash "updatedReplicas" status)))
      (is (equal (gethash "currentRevision" status) (gethash "updateRevision" status)))
      (is (equal (gethash "currentRevision" status) (stateful-pod-label store "web-0" "controller-revision-hash")))
      (is (= 1 (gethash "observedGeneration" status))))))

(test statefulset-scales-down-highest-first-and-halts-when-unhealthy
  (with-budget-cluster (store runtime reconciler)
    (gr8s::create-core-resource store "statefulsets" (stateful-fixture "web") "alpha")
    (stateful-settle reconciler)
    (gr8s::update-core-resource store "statefulsets" "alpha" "web"
      (lambda (object) (setf (gethash "replicas" (gethash "spec" object)) 1) object))
    ;; An unready Pod that is not the first unhealthy one halts the scale down.
    (let ((observed (gr8s::runtime-observe runtime (pod-uid (get-pod store "alpha" "web-0")))))
      (setf (gr8s::runtime-pod-status observed)
            (gr8s::core-object "phase" "Running" "containerStatuses"
                               (vector (gr8s::core-object "name" "main" "ready" nil "state" (gr8s::core-object "running" (gr8s::core-object)))))))
    (let ((observed (gr8s::runtime-observe runtime (pod-uid (get-pod store "alpha" "web-2")))))
      (setf (gr8s::runtime-pod-status observed)
            (gr8s::core-object "phase" "Running" "containerStatuses"
                               (vector (gr8s::core-object "name" "main" "ready" nil "state" (gr8s::core-object "running" (gr8s::core-object)))))))
    (gr8s::reconcile-workloads reconciler)
    (is (equal '("web-0" "web-1" "web-2") (stateful-pod-names store)))
    (mark-workload-pods-ready store runtime)
    (reconcile-all reconciler)
    (gr8s::reconcile-workloads reconciler)
    (is (equal '("web-0" "web-1") (stateful-pod-names store)))
    (stateful-settle reconciler)
    (is (equal '("web-0") (stateful-pod-names store)))
    (is (= 1 (gethash "replicas" (gethash "status" (gr8s::get-core-resource store "statefulsets" "alpha" "web")))))))

(test statefulset-parallel-policy-does-not-wait
  (with-budget-cluster (store runtime reconciler)
    (gr8s::create-core-resource store "statefulsets" (stateful-fixture "web" :policy "Parallel") "alpha")
    (stateful-pass reconciler)
    (is (equal '("web-0" "web-1" "web-2") (stateful-pod-names store)))
    (gr8s::update-core-resource store "statefulsets" "alpha" "web"
      (lambda (object) (setf (gethash "replicas" (gethash "spec" object)) 0) object))
    (stateful-pass reconciler)
    (is (null (stateful-pod-names store)))))

(test statefulset-honors-its-start-ordinal
  (with-budget-cluster (store runtime reconciler)
    (gr8s::create-core-resource store "statefulsets" (stateful-fixture "web" :replicas 2 :start 5) "alpha")
    (stateful-settle reconciler)
    (is (equal '("web-5" "web-6") (stateful-pod-names store)))))

(defstruct (stateful-held-runtime (:include gr8s::fake-runtime)
                                  (:constructor make-stateful-held-runtime ()))
  "A runtime that leaves a Pod in the phase it reached, as a node does with one it refused.")

(defmethod gr8s::runtime-reconcile-containers ((runtime stateful-held-runtime) pod observed)
  "Report OBSERVED unchanged rather than restarting it."
  (declare (ignore pod))
  observed)

(test statefulset-replaces-a-failed-pod-under-its-own-name
  (with-temporary-store (store path)
    (values path)
    (let* ((runtime (make-stateful-held-runtime)) (reconciler (make-reconciler store runtime)))
      (gr8s::create-core-resource store "statefulsets" (stateful-fixture "web" :replicas 1) "alpha")
      (stateful-pass reconciler)
      (let* ((pod (get-pod store "alpha" "web-0")) (uid (pod-uid pod))
             (observed (gr8s::runtime-observe runtime uid)))
        (setf (gr8s::runtime-pod-phase observed) "Failed"
              (gr8s::runtime-pod-status observed) (gr8s::core-object "phase" "Failed" "reason" "NodePorts"))
        (gr8s::reconcile-workloads reconciler)
        (signals gr8s::kubernetes-error (get-pod store "alpha" "web-0"))
        (gr8s::reconcile-workloads reconciler)
        (is (not (equal uid (pod-uid (get-pod store "alpha" "web-0")))))))))

(test statefulset-rolls-in-reverse-order-and-rolls-back-to-the-prior-revision
  (with-budget-cluster (store runtime reconciler)
    (gr8s::create-core-resource store "statefulsets" (stateful-fixture "web") "alpha")
    (stateful-settle reconciler)
    (let ((first (gethash "currentRevision" (gethash "status" (gr8s::get-core-resource store "statefulsets" "alpha" "web")))))
      (stateful-set-image store "web" "busybox:2")
      (gr8s::reconcile-workloads reconciler)
      (let* ((status (gethash "status" (gr8s::get-core-resource store "statefulsets" "alpha" "web")))
             (second (gethash "updateRevision" status)))
        (is (equal first (gethash "currentRevision" status)))
        (is (not (equal first second)))
        ;; The highest ordinal goes first, and the lowest stays on the old image for now.
        (is (equal "busybox:1.36.1" (stateful-pod-image store "web-0")))
        (stateful-settle reconciler)
        (dolist (name '("web-0" "web-1" "web-2")) (is (equal "busybox:2" (stateful-pod-image store name))))
        (let ((done (gethash "status" (gr8s::get-core-resource store "statefulsets" "alpha" "web"))))
          (is (equal second (gethash "currentRevision" done)))
          (is (= 3 (gethash "currentReplicas" done))))
        (stateful-set-image store "web" "busybox:1.36.1")
        (gr8s::reconcile-workloads reconciler)
        (let ((rolling (gethash "status" (gr8s::get-core-resource store "statefulsets" "alpha" "web"))))
          (is (equal first (gethash "updateRevision" rolling)) "A rollback reuses the earlier revision")
          (is (equal second (gethash "currentRevision" rolling))))
        (stateful-settle reconciler)
        (is (equal first (gethash "currentRevision" (gethash "status" (gr8s::get-core-resource store "statefulsets" "alpha" "web")))))
        (is (= 2 (length (gr8s::list-core-resources store "controllerrevisions" "alpha"))))))))

(test statefulset-partition-holds-lower-ordinals-even-when-recreated
  (with-budget-cluster (store runtime reconciler)
    (gr8s::create-core-resource store "statefulsets" (stateful-fixture "web" :partition 3) "alpha")
    (stateful-settle reconciler)
    (stateful-set-image store "web" "busybox:2")
    (stateful-settle reconciler)
    (dolist (name '("web-0" "web-1" "web-2")) (is (equal "busybox:1.36.1" (stateful-pod-image store name))))
    (gr8s::update-core-resource store "statefulsets" "alpha" "web"
      (lambda (object) (setf (gethash "partition" (gethash "rollingUpdate" (gethash "updateStrategy" (gethash "spec" object)))) 2) object))
    (stateful-settle reconciler)
    (is (equal "busybox:2" (stateful-pod-image store "web-2")))
    (is (equal "busybox:1.36.1" (stateful-pod-image store "web-1")))
    ;; A Pod recreated below the partition returns to the old revision.
    (gr8s::delete-reconciled-pod reconciler "alpha" "web-0" :grace-period 0)
    (stateful-settle reconciler)
    (is (equal "busybox:1.36.1" (stateful-pod-image store "web-0")))
    (let ((status (gethash "status" (gr8s::get-core-resource store "statefulsets" "alpha" "web"))))
      (is (not (equal (gethash "currentRevision" status) (gethash "updateRevision" status))))
      (is (= 2 (gethash "currentReplicas" status)))
      (is (= 1 (gethash "updatedReplicas" status))))))

(test statefulset-ondelete-waits-for-a-client-to-delete
  (with-budget-cluster (store runtime reconciler)
    (gr8s::create-core-resource store "statefulsets" (stateful-fixture "web" :replicas 1 :update-type "OnDelete") "alpha")
    (stateful-settle reconciler)
    (stateful-set-image store "web" "busybox:2")
    (stateful-settle reconciler)
    (is (equal "busybox:1.36.1" (stateful-pod-image store "web-0")))
    (gr8s::delete-reconciled-pod reconciler "alpha" "web-0" :grace-period 0)
    (stateful-settle reconciler)
    (is (equal "busybox:2" (stateful-pod-image store "web-0")))))

(test statefulset-adopts-orphans-and-releases-mismatches
  (with-budget-cluster (store runtime reconciler)
    (let ((set (gr8s::create-core-resource store "statefulsets" (stateful-fixture "web" :replicas 1) "alpha")))
      (stateful-settle reconciler)
      (let* ((pod (get-pod store "alpha" "web-0")) (object (gr8s::copy-core-object (pod-to-object pod))))
        (setf (gethash "ownerReferences" (gethash "metadata" object)) #())
        (update-pod store (parse-pod object) (pod-resource-version pod)))
      (gr8s::reconcile-workloads reconciler)
      (is (gr8s::workload-owned-p (pod-to-object (get-pod store "alpha" "web-0")) set))
      (let* ((pod (get-pod store "alpha" "web-0")) (object (gr8s::copy-core-object (pod-to-object pod))))
        (setf (gethash "labels" (gethash "metadata" object)) (gr8s::core-object "app" "other"))
        (update-pod store (parse-pod object) (pod-resource-version pod)))
      (gr8s::reconcile-workloads reconciler)
      (is (null (gr8s::workload-controller-reference (pod-to-object (get-pod store "alpha" "web-0"))))))))

(test statefulset-binds-real-claims-through-the-storage-controller
  (with-budget-cluster (store runtime reconciler)
    (gr8s::create-core-resource store "persistentvolumes"
      (gr8s::core-object "apiVersion" "v1" "kind" "PersistentVolume" "metadata" (gr8s::core-object "name" "pv-0")
                         "spec" (gr8s::core-object "capacity" (gr8s::core-object "storage" "1Gi") "accessModes" #("ReadWriteOnce")
                                                   "hostPath" (gr8s::core-object "path" "/tmp/gr8s-stateful-0" "type" "DirectoryOrCreate")))
      nil)
    (gr8s::create-core-resource store "statefulsets"
                                (stateful-fixture "web" :replicas 1 :claims (vector (stateful-claim-template "data"))) "alpha")
    (gr8s::reconcile-workloads reconciler)
    (let ((claim (gr8s::get-core-resource store "persistentvolumeclaims" "alpha" "data-web-0")))
      (is (equal "web" (gethash "app" (gethash "labels" (gethash "metadata" claim))))))
    (let ((volume (find "data" (gethash "volumes" (gethash "spec" (pod-to-object (get-pod store "alpha" "web-0"))))
                        :test #'equal :key (lambda (entry) (gethash "name" entry)))))
      (is (equal "data-web-0" (gethash "claimName" (gethash "persistentVolumeClaim" volume)))))
    (gr8s::reconcile-storage-bindings store)
    (let ((claim (gr8s::get-core-resource store "persistentvolumeclaims" "alpha" "data-web-0")))
      (is (equal "pv-0" (gethash "volumeName" (gethash "spec" claim))))
      (is (equal "Bound" (gethash "phase" (gethash "status" claim)))))
    ;; The same Pod name finds the same claim after it is replaced.
    (stateful-settle reconciler)
    (let ((uid (gethash "uid" (gethash "metadata" (gr8s::get-core-resource store "persistentvolumeclaims" "alpha" "data-web-0")))))
      (gr8s::delete-reconciled-pod reconciler "alpha" "web-0" :grace-period 0)
      (stateful-settle reconciler)
      (is (equal uid (gethash "uid" (gethash "metadata" (gr8s::get-core-resource store "persistentvolumeclaims" "alpha" "data-web-0"))))))))

(test statefulset-retention-keeps-or-deletes-claims-on-scale-down
  (flet ((claim-after-scale-down (retention)
           (with-budget-cluster (store runtime reconciler)
             (gr8s::create-core-resource store "statefulsets"
                                         (stateful-fixture "web" :replicas 1 :policy "Parallel" :retention retention
                                                                 :claims (vector (stateful-claim-template "data"))) "alpha")
             (stateful-settle reconciler 3)
             (gr8s::update-core-resource store "statefulsets" "alpha" "web"
               (lambda (object) (setf (gethash "replicas" (gethash "spec" object)) 0) object))
             (stateful-settle reconciler 3)
             (is (null (stateful-pod-names store)))
             (gr8s::reconcile-storage-bindings store)
             (not (null (find "data-web-0" (gr8s::list-core-resources store "persistentvolumeclaims" "alpha")
                              :test #'equal :key (lambda (claim) (gethash "name" (gethash "metadata" claim)))))))))
    (is-true (claim-after-scale-down nil))
    (is-false (claim-after-scale-down (gr8s::core-object "whenScaled" "Delete")))))

(test statefulset-retention-collects-claims-with-the-set
  (with-budget-cluster (store runtime reconciler)
    (gr8s::create-core-resource store "statefulsets"
                                (stateful-fixture "web" :replicas 1 :retention (gr8s::core-object "whenDeleted" "Delete")
                                                        :claims (vector (stateful-claim-template "data"))) "alpha")
    (stateful-settle reconciler 3)
    (gr8s::delete-workload-resource store "statefulsets" "alpha" "web")
    (dotimes (index 3) (run-workload-passes reconciler 1) (gr8s::reconcile-storage-bindings store))
    (is (null (gr8s::list-core-resources store "persistentvolumeclaims" "alpha")))
    (is (null (stateful-pod-names store)))))

(test pod-lists-come-back-in-key-order-whatever-the-creation-order
  (with-budget-api (store runtime reconciler)
    (values runtime)
    (dolist (name '("web-2" "web-0" "web-1")) (budget-test-pod store name))
    (gr8s::delete-reconciled-pod reconciler "alpha" "web-0" :grace-period 0)
    (budget-test-pod store "web-0")
    (is (equal '("web-0" "web-1" "web-2")
               (map 'list (lambda (pod) (gethash "name" (gethash "metadata" pod)))
                    (gethash "items" (check-core-status 200 "/api/v1/namespaces/alpha/pods")))))))

(test statefulset-http-serves-status-scale-and-keeps-client-conditions
  (with-budget-api (store runtime reconciler)
    (let* ((collection "/apis/apps/v1/namespaces/alpha/statefulsets")
           (item (concatenate 'string collection "/web")))
      (check-core-status 201 collection :method :post :object (stateful-fixture "web" :replicas 1))
      (is (find "statefulsets/scale" (gethash "resources" (check-core-status 200 "/apis/apps/v1"))
                :test #'equal :key (lambda (entry) (gethash "name" entry))))
      (stateful-settle reconciler)
      (let ((scale (check-core-status 200 (concatenate 'string item "/scale"))))
        (is (= 1 (gethash "replicas" (gethash "status" scale))))
        (setf (gethash "replicas" (gethash "spec" scale)) 2)
        (remhash "resourceVersion" (gethash "metadata" scale))
        (check-core-status 200 (concatenate 'string item "/scale") :method :put :object scale))
      (is (= 2 (gethash "replicas" (gethash "spec" (check-core-status 200 item)))))
      (check-core-status 200 (concatenate 'string item "/status") :method :patch :content-type "application/merge-patch+json"
                         :object (gr8s::core-object "status" (gr8s::core-object "conditions" (vector (gr8s::core-object "type" "StatusPatched" "status" "True")))))
      (stateful-settle reconciler 2)
      (is (find "StatusPatched" (gethash "conditions" (gethash "status" (check-core-status 200 item)))
                :test #'equal :key (lambda (entry) (gethash "type" entry))))
      (check-core-status 200 collection :method :delete)
      (is (null (gr8s::list-core-resources store "statefulsets" "alpha"))))))

(test statefulset-claims-pass-admission-as-the-controller
  ;; A claim from a volumeClaimTemplate goes through admission as upstream's controller's
  ;; create does, so a policy that refuses it holds the Pod back.
  (with-budget-cluster (store runtime reconciler)
    (gr8s::create-core-resource store "validatingadmissionpolicies"
      (gr8s::core-object
       "apiVersion" "admissionregistration.k8s.io/v1" "kind" "ValidatingAdmissionPolicy"
       "metadata" (gr8s::core-object "name" "no-claims")
       "spec" (gr8s::core-object
               "matchConstraints" (gr8s::core-object
                                   "resourceRules" (vector (gr8s::core-object "apiGroups" #("") "apiVersions" #("v1")
                                                                              "operations" #("CREATE")
                                                                              "resources" #("persistentvolumeclaims"))))
               "validations" (vector (gr8s::core-object
                                      "expression" "request.userInfo.username != 'system:serviceaccount:kube-system:statefulset-controller'"
                                      "message" "no claims from the controller"))))
      nil)
    (gr8s::create-core-resource store "validatingadmissionpolicybindings"
      (gr8s::core-object
       "apiVersion" "admissionregistration.k8s.io/v1" "kind" "ValidatingAdmissionPolicyBinding"
       "metadata" (gr8s::core-object "name" "no-claims")
       "spec" (gr8s::core-object "policyName" "no-claims" "validationActions" #("Deny")))
      nil)
    (gr8s::create-core-resource store "statefulsets"
                                (stateful-fixture "web" :replicas 1 :claims (vector (stateful-claim-template "data"))) "alpha")
    (ignore-errors (gr8s::reconcile-workloads reconciler))
    (is (null (gr8s::list-core-resources store "persistentvolumeclaims" "alpha")))
    (is (null (ignore-errors (get-pod store "alpha" "web-0"))))
    (gr8s::delete-core-resource store "validatingadmissionpolicybindings" nil "no-claims")
    (gr8s::reconcile-workloads reconciler)
    (is (gr8s::get-core-resource store "persistentvolumeclaims" "alpha" "data-web-0"))
    (is (get-pod store "alpha" "web-0"))))
