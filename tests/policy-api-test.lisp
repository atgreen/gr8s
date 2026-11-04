;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Verify quota accounting and enforcement, LimitRange defaulting, RuntimeClass
;;;; resolution and PriorityClass rules against the real store and HTTP routes.

(in-package #:gr8s/tests)
(def-suite policy-apis :in gr8s)
(in-suite policy-apis)

(defun policy-test-pod (name &key (namespace "team") requests limits spec-fields)
  "Build an unassigned one-container Pod declaring REQUESTS and LIMITS plists."
  (flet ((resource-list (plist)
           (let ((table (gr8s::core-object)))
             (loop for (key value) on plist by #'cddr do (setf (gethash key table) value))
             table)))
    (let* ((resources (gr8s::core-object))
           (spec (gr8s::core-object "containers" (vector (gr8s::core-object "name" "main" "image" "busybox:latest" "resources" resources)))))
      (when requests (setf (gethash "requests" resources) (resource-list requests)))
      (when limits (setf (gethash "limits" resources) (resource-list limits)))
      (loop for (key value) on spec-fields by #'cddr do (setf (gethash key spec) value))
      (parse-pod (gr8s::core-object "apiVersion" "v1" "kind" "Pod"
                                    "metadata" (gr8s::core-object "name" name "namespace" namespace)
                                    "spec" spec)))))

(defun policy-test-quota (store name hard &key scopes)
  "Create a ResourceQuota with the HARD plist in the team namespace."
  (let ((table (gr8s::core-object)))
    (loop for (key value) on hard by #'cddr do (setf (gethash key table) value))
    (gr8s::create-core-resource
     store "resourcequotas"
     (gr8s::core-object "metadata" (gr8s::core-object "name" name)
                        "spec" (if scopes
                                   (gr8s::core-object "hard" table "scopes" scopes)
                                   (gr8s::core-object "hard" table)))
     "team")))

(defun policy-test-used (store name)
  "Reconcile quotas and return NAME's status.used table."
  (gr8s::reconcile-resource-quotas store)
  (gethash "used" (gethash "status" (gr8s::get-core-resource store "resourcequotas" "team" name))))

(defun policy-test-forbidden-p (function)
  "Return whether calling FUNCTION signals a 403 Kubernetes error."
  (handler-case (progn (funcall function) nil)
    (kubernetes-error (condition) (= 403 (gr8s::kubernetes-error-status-code condition)))))

(test quota-status-counts-objects-and-enforces-hard-limits
  (with-temporary-store (store path)
    (values path)
    (policy-test-quota store "objects" '("secrets" "1" "configmaps" "1" "resourcequotas" "1" "count/replicasets.apps" "2"))
    (let ((used (policy-test-used store "objects")))
      (is (equal "1" (gethash "resourcequotas" used)))
      (is (equal "0" (gethash "secrets" used)))
      (is (equal "0" (gethash "count/replicasets.apps" used))))
    (is-true (policy-test-forbidden-p
              (lambda () (policy-test-quota store "second" '("pods" "1")))))
    (gr8s::create-core-resource store "secrets" (gr8s::core-object "metadata" (gr8s::core-object "name" "one")) "team")
    (is (equal "1" (gethash "secrets" (policy-test-used store "objects"))))
    (is-true (policy-test-forbidden-p
              (lambda ()
                (gr8s::create-core-resource store "secrets" (gr8s::core-object "metadata" (gr8s::core-object "name" "two")) "team"))))
    (gr8s::delete-core-resource store "secrets" "team" "one")
    (is (equal "0" (gethash "secrets" (policy-test-used store "objects"))))))

(test quota-accounts-pod-compute-and-extended-resources
  (with-temporary-store (store path)
    (values path)
    (policy-test-quota store "compute" '("pods" "2" "cpu" "1" "memory" "500Mi" "ephemeral-storage" "50Gi"
                                         "requests.example.com/dongle" "3"))
    (create-pod store (policy-test-pod "fits" :requests '("cpu" "500m" "memory" "252Mi" "ephemeral-storage" "30Gi" "example.com/dongle" "2")
                                              :limits '("example.com/dongle" "2")))
    (let ((used (policy-test-used store "compute")))
      (is (equal "1" (gethash "pods" used)))
      (is (equal "500m" (gethash "cpu" used)))
      (is (equal "252Mi" (gethash "memory" used)))
      (is (equal "30Gi" (gethash "ephemeral-storage" used)))
      (is (equal "2" (gethash "requests.example.com/dongle" used))))
    (is-true (policy-test-forbidden-p
              (lambda () (create-pod store (policy-test-pod "too-much-cpu" :requests '("cpu" "600m" "memory" "10Mi"))))))
    (is-true (policy-test-forbidden-p
              (lambda () (create-pod store (policy-test-pod "too-many-dongles"
                                                            :requests '("cpu" "100m" "memory" "10Mi" "example.com/dongle" "2")
                                                            :limits '("example.com/dongle" "2"))))))
    ;; A quota on CPU and memory requires every container to declare them.
    (is-true (policy-test-forbidden-p
              (lambda () (create-pod store (policy-test-pod "undeclared")))))))

(test quota-scopes-separate-terminating-and-best-effort-pods
  (with-temporary-store (store path)
    (values path)
    (policy-test-quota store "long" '("pods" "5") :scopes #("NotTerminating"))
    (policy-test-quota store "short" '("pods" "5") :scopes #("Terminating"))
    (policy-test-quota store "free" '("pods" "5") :scopes #("BestEffort"))
    (policy-test-quota store "paid" '("pods" "5") :scopes #("NotBestEffort"))
    (create-pod store (policy-test-pod "plain"))
    (is (equal "1" (gethash "pods" (policy-test-used store "long"))))
    (is (equal "0" (gethash "pods" (policy-test-used store "short"))))
    (is (equal "1" (gethash "pods" (policy-test-used store "free"))))
    (is (equal "0" (gethash "pods" (policy-test-used store "paid"))))
    (create-pod store (policy-test-pod "deadline" :requests '("cpu" "1") :spec-fields (list "activeDeadlineSeconds" 3600)))
    (is (equal "1" (gethash "pods" (policy-test-used store "short"))))
    (is (equal "1" (gethash "pods" (policy-test-used store "paid"))))
    (signals kubernetes-error
      (policy-test-quota store "conflict" '("pods" "1") :scopes #("BestEffort" "NotBestEffort")))
    (signals kubernetes-error
      (policy-test-quota store "bad" '("cpu" "1") :scopes #("BestEffort")))))

(test quota-status-write-cannot-change-spec-and-reconcile-restores-status
  (with-temporary-store (store path)
    (values path)
    (policy-test-quota store "q" '("cpu" "1"))
    (gr8s::reconcile-resource-quotas store)
    (let ((gr8s::*policy-status-write* t))
      (gr8s::update-core-resource store "resourcequotas" "team" "q"
                                  (lambda (old)
                                    (setf (gethash "status" old) (gr8s::core-object "hard" (gr8s::core-object "cpu" "2")))
                                    old)))
    (is (equal "2" (gethash "cpu" (gethash "hard" (gethash "status" (gr8s::get-core-resource store "resourcequotas" "team" "q"))))))
    ;; An ordinary update keeps the server-owned status.
    (let ((updated (gr8s::update-core-resource store "resourcequotas" "team" "q"
                                               (lambda (old)
                                                 (setf (gethash "cpu" (gethash "hard" (gethash "spec" old))) "3"
                                                       (gethash "status" old) (gr8s::core-object))
                                                 old))))
      (is (equal "2" (gethash "cpu" (gethash "hard" (gethash "status" updated))))))
    (gr8s::reconcile-resource-quotas store)
    (is (equal "3" (gethash "cpu" (gethash "hard" (gethash "status" (gr8s::get-core-resource store "resourcequotas" "team" "q"))))))))

(defun policy-test-limit-range (store name limit)
  "Create a one-item LimitRange in the team namespace."
  (gr8s::create-core-resource
   store "limitranges"
   (gr8s::core-object "metadata" (gr8s::core-object "name" name)
                      "spec" (gr8s::core-object "limits" (vector limit)))
   "team"))

(defun policy-test-container-resources (pod)
  "Return POD's first container's requests and limits tables."
  (let ((resources (gethash "resources" (aref (gethash "containers" (gethash "spec" (pod-to-object pod))) 0))))
    (values (gethash "requests" resources) (gethash "limits" resources))))

(test limit-range-defaults-and-bounds-container-resources
  (with-temporary-store (store path)
    (values path)
    (policy-test-limit-range
     store "bounds"
     (gr8s::core-object "type" "Container"
                        "min" (gr8s::core-object "cpu" "50m" "memory" "100Mi" "ephemeral-storage" "100Gi")
                        "max" (gr8s::core-object "cpu" "500m" "memory" "500Mi" "ephemeral-storage" "500Gi")
                        "default" (gr8s::core-object "cpu" "500m" "memory" "500Mi" "ephemeral-storage" "500Gi")
                        "defaultRequest" (gr8s::core-object "cpu" "100m" "memory" "200Mi" "ephemeral-storage" "200Gi")))
    (multiple-value-bind (requests limits)
        (policy-test-container-resources (gr8s::admit-pod-policies store (policy-test-pod "none")))
      (is (equal "100m" (gethash "cpu" requests)))
      (is (equal "200Gi" (gethash "ephemeral-storage" requests)))
      (is (equal "500Mi" (gethash "memory" limits))))
    ;; A declared limit became the request before admission, as upstream defaulting does.
    (multiple-value-bind (requests limits)
        (policy-test-container-resources
         (gr8s::admit-pod-policies store (policy-test-pod "partial" :requests '("memory" "150Mi" "ephemeral-storage" "150Gi")
                                                                    :limits '("cpu" "300m"))))
      (is (equal "300m" (gethash "cpu" requests)))
      (is (equal "150Mi" (gethash "memory" requests)))
      (is (equal "300m" (gethash "cpu" limits)))
      (is (equal "500Gi" (gethash "ephemeral-storage" limits))))
    (is-true (policy-test-forbidden-p
              (lambda () (gr8s::admit-pod-policies store (policy-test-pod "small" :requests '("cpu" "10m"))))))
    (is-true (policy-test-forbidden-p
              (lambda () (gr8s::admit-pod-policies store (policy-test-pod "big" :requests '("cpu" "600m"))))))))

(test limit-range-api-defaults-validates-and-enforces-claims
  (with-temporary-store (store path)
    (values path)
    (let* ((created (policy-test-limit-range
                     store "defaulted"
                     (gr8s::core-object "type" "Container" "max" (gr8s::core-object "cpu" "2"))))
           (item (aref (gethash "limits" (gethash "spec" created)) 0)))
      (is (equal "2" (gethash "cpu" (gethash "default" item))))
      (is (equal "2" (gethash "cpu" (gethash "defaultRequest" item)))))
    (signals kubernetes-error
      (policy-test-limit-range store "inverted"
                               (gr8s::core-object "type" "Container"
                                                  "min" (gr8s::core-object "cpu" "2")
                                                  "max" (gr8s::core-object "cpu" "1"))))
    (signals kubernetes-error
      (policy-test-limit-range store "unknown" (gr8s::core-object "type" "Banana")))
    (policy-test-limit-range store "claims"
                             (gr8s::core-object "type" "PersistentVolumeClaim"
                                                "max" (gr8s::core-object "storage" "1Gi")))
    (is-true (policy-test-forbidden-p
              (lambda ()
                (gr8s::create-core-resource
                 store "persistentvolumeclaims"
                 (gr8s::core-object "metadata" (gr8s::core-object "name" "big")
                                    "spec" (gr8s::core-object "accessModes" #("ReadWriteOnce")
                                                              "resources" (gr8s::core-object "requests" (gr8s::core-object "storage" "2Gi"))))
                 "team"))))))

(test limit-range-enforces-pod-totals-and-request-ratio
  (with-temporary-store (store path)
    (values path)
    (policy-test-limit-range store "pods" (gr8s::core-object "type" "Pod" "max" (gr8s::core-object "cpu" "1")))
    (is-true (policy-test-forbidden-p
              (lambda () (gr8s::admit-pod-policies store (policy-test-pod "unlimited")))))
    (is-false (policy-test-forbidden-p
               (lambda () (gr8s::admit-pod-policies store (policy-test-pod "ok" :limits '("cpu" "1"))))))
    (policy-test-limit-range store "ratio" (gr8s::core-object "type" "Container" "maxLimitRequestRatio" (gr8s::core-object "cpu" "2")))
    (is-true (policy-test-forbidden-p
              (lambda () (gr8s::admit-pod-policies store (policy-test-pod "wide" :requests '("cpu" "100m") :limits '("cpu" "1"))))))))

(defun policy-test-runtime-class (store name &rest fields)
  "Create a RuntimeClass NAME with extra top-level FIELDS."
  (let ((object (gr8s::core-object "metadata" (gr8s::core-object "name" name) "handler" "runc")))
    (loop for (key value) on fields by #'cddr do (setf (gethash key object) value))
    (gr8s::create-core-resource store "runtimeclasses" object nil)))

(test runtime-class-admission-resolves-handler-overhead-and-scheduling
  (with-temporary-store (store path)
    (values path)
    (is-true (policy-test-forbidden-p
              (lambda () (gr8s::admit-pod-policies store (policy-test-pod "missing" :spec-fields (list "runtimeClassName" "absent"))))))
    (policy-test-runtime-class store "fast"
                               "overhead" (gr8s::core-object "podFixed" (gr8s::core-object "cpu" "10m" "memory" "1Mi"))
                               "scheduling" (gr8s::core-object "nodeSelector" (gr8s::core-object "disk" "ssd")))
    (let* ((pod (gr8s::admit-pod-policies store (policy-test-pod "using" :spec-fields (list "runtimeClassName" "fast"))))
           (spec (gethash "spec" (pod-to-object pod))))
      (is (equal "runc" (gr8s::pod-runtime-handler pod)))
      (is (equal "10m" (gethash "cpu" (gethash "overhead" spec))))
      (is (equal "ssd" (gethash "disk" (gethash "nodeSelector" spec))))
      ;; Overhead is charged to the Pod's effective requests.
      (is (= 1/100 (gethash "cpu" (gr8s::pod-spec-resource-totals spec)))))
    (is-true (policy-test-forbidden-p
              (lambda () (gr8s::admit-pod-policies
                          store (policy-test-pod "conflict" :spec-fields (list "runtimeClassName" "fast"
                                                                               "nodeSelector" (gr8s::core-object "disk" "hdd")))))))
    (is-true (policy-test-forbidden-p
              (lambda () (gr8s::admit-pod-policies
                          store (policy-test-pod "stray" :spec-fields (list "overhead" (gr8s::core-object "cpu" "1")))))))
    (signals kubernetes-error
      (gr8s::update-core-resource store "runtimeclasses" nil "fast"
                                  (lambda (old) (setf (gethash "handler" old) "other") old)))
    (signals kubernetes-error (policy-test-runtime-class store "Bad_Handler" "handler" "Not A Label"))))

(test priority-class-rules-and-pod-resolution
  (with-temporary-store (store path)
    (values path)
    (gr8s::ensure-system-priority-classes store)
    (flet ((class (name value &rest fields)
             (let ((object (gr8s::core-object "metadata" (gr8s::core-object "name" name) "value" value)))
               (loop for (key field-value) on fields by #'cddr do (setf (gethash key object) field-value))
               (gr8s::create-core-resource store "priorityclasses" object nil))))
      (let ((pod (gr8s::admit-pod-policies store (policy-test-pod "plain"))))
        (is (= 0 (gethash "priority" (gethash "spec" (pod-to-object pod)))))
        (is (equal "PreemptLowerPriority" (gethash "preemptionPolicy" (gethash "spec" (pod-to-object pod))))))
      (is (= 2000000000
             (gethash "priority" (gethash "spec" (pod-to-object
                                                  (gr8s::admit-pod-policies store (policy-test-pod "critical" :spec-fields (list "priorityClassName" "system-cluster-critical"))))))))
      (is-true (policy-test-forbidden-p
                (lambda () (gr8s::admit-pod-policies store (policy-test-pod "absent" :spec-fields (list "priorityClassName" "nope"))))))
      (is-true (policy-test-forbidden-p (lambda () (class "too-high" 1000000001))))
      (is-true (policy-test-forbidden-p (lambda () (class "system-mine" 1))))
      (is-true (policy-test-forbidden-p (lambda () (gr8s::delete-core-resource store "priorityclasses" nil "system-node-critical"))))
      (class "gentle" 5 "preemptionPolicy" "Never" "globalDefault" t)
      (signals kubernetes-error (class "second-default" 6 "globalDefault" t))
      (signals kubernetes-error
        (gr8s::update-core-resource store "priorityclasses" nil "gentle"
                                    (lambda (old) (setf (gethash "value" old) 7) old)))
      (is (equal "edited"
                 (gethash "description"
                          (gr8s::update-core-resource store "priorityclasses" nil "gentle"
                                                      (lambda (old) (setf (gethash "description" old) "edited") old)))))
      (let* ((pod (gr8s::admit-pod-policies store (policy-test-pod "defaulted")))
             (spec (gethash "spec" (pod-to-object pod))))
        (is (= 5 (gethash "priority" spec)))
        (is (equal "gentle" (gethash "priorityClassName" spec)))
        (is (equal "Never" (gethash "preemptionPolicy" spec))))
      (is-true (policy-test-forbidden-p
                (lambda () (gr8s::admit-pod-policies store (policy-test-pod "lying" :spec-fields (list "priority" 99)))))))))

(test pod-updates-keep-admission-fields-and-requirements-immutable
  (with-temporary-store (store path)
    (values path)
    (let* ((pod (create-pod store (gr8s::admit-pod-policies store (policy-test-pod "held" :requests '("cpu" "100m")))))
           (changed (gr8s::copy-core-object (pod-to-object pod))))
      (setf (gethash "cpu" (gethash "requests" (gethash "resources" (aref (gethash "containers" (gethash "spec" changed)) 0)))) "200m")
      (signals kubernetes-error (update-pod store (parse-pod changed) (pod-resource-version pod)))
      (let ((omitted (gr8s::copy-core-object (pod-to-object pod))))
        (remhash "priority" (gethash "spec" omitted))
        (let ((updated (update-pod store (parse-pod omitted) (pod-resource-version pod))))
          (is (= 0 (gethash "priority" (gethash "spec" (pod-to-object updated))))))))))

(test extended-resources-must-be-whole-and-not-overcommitted
  (signals kubernetes-error (policy-test-pod "request-only" :requests '("example.com/gpu" "1")))
  (signals kubernetes-error (policy-test-pod "unequal" :requests '("example.com/gpu" "1") :limits '("example.com/gpu" "2")))
  (signals kubernetes-error (policy-test-pod "fractional" :limits '("example.com/gpu" "500m")))
  (signals kubernetes-error (policy-test-pod "reserved" :requests '("kubernetes.io/magic" "1")))
  (let ((pod (policy-test-pod "ok" :limits '("example.com/gpu" "2"))))
    (is (equal "2" (gethash "example.com/gpu" (policy-test-container-resources pod))))))

(test active-deadline-fails-a-pod-without-restarting-it
  (with-temporary-store (store path)
    (values path)
    (let* ((runtime (make-fake-runtime))
           (reconciler (make-reconciler store runtime))
           (pod (create-pod store (policy-test-pod "brief" :spec-fields (list "activeDeadlineSeconds" 100)))))
      (is (equal "Running" (gethash "phase" (gr8s::reconcile-pod reconciler "team" "brief"))))
      (let ((gr8s::*pod-deletion-clock*
              (lambda () (+ 200 (gr8s::pod-deletion-time (gethash "creationTimestamp" (gethash "metadata" (pod-to-object pod))))))))
        (let ((status (gr8s::reconcile-pod reconciler "team" "brief")))
          (is (equal "Failed" (gethash "phase" status)))
          (is (equal "DeadlineExceeded" (gethash "reason" status))))
        (is (null (gr8s::runtime-observe runtime (pod-uid pod))))))))

(defun policy-test-node (store name &key extended capacity)
  "Register ready node NAME with EXTENDED advertised and CAPACITY measured quantity tables."
  (gr8s:register-node store (gr8s:make-node-record :id (concatenate 'string "id-" name) :name name
                                                   :pod-cidr (format nil "10.88.~D.0/24" (random 200))))
  (gr8s:mark-node-ready store name (get-universal-time) :lease-duration 3600)
  (when extended (gr8s::update-node-extended-resources store name extended))
  (when capacity (gr8s::update-node-capacity store name capacity)))

(defun policy-test-class (store name value)
  "Create a PriorityClass NAME with VALUE."
  (gr8s::create-core-resource store "priorityclasses"
                              (gr8s::core-object "metadata" (gr8s::core-object "name" name) "value" value) nil))

(defun policy-test-priority-pod (store name class dongles)
  "Admit and store a Pod in CLASS using DONGLES of the extended test resource."
  (create-pod store (gr8s::admit-pod-policies
                     store (policy-test-pod name :limits (list "example.com/dongle" (write-to-string dongles))
                                                 :spec-fields (list "priorityClassName" class)))))

(defun policy-test-deleting-p (store name)
  "Return whether the team Pod NAME has begun deletion."
  (gr8s::deletion-requested-p (get-pod store "team" name)))

(test scheduler-charges-requests-against-node-resources
  (with-temporary-store (store path)
    (values path)
    (policy-test-node store "small" :capacity (gr8s::core-object "cpu" "1" "pods" "2"))
    (let ((pod (create-pod store (policy-test-pod "dongle" :limits '("example.com/dongle" "1")))))
      (is (null (gr8s::schedule-pod store pod))))
    (gr8s::update-node-extended-resources store "small" (gr8s::core-object "example.com/dongle" "1"))
    (is (equal "small" (gr8s:node-record-name
                        (gr8s::schedule-pod store (get-pod store "team" "dongle")))))
    (is (equal "1" (gethash "example.com/dongle"
                            (gethash "allocatable" (gethash "status" (gr8s::node-api-object (gr8s::get-node store "small")))))))
    (is (null (gr8s::schedule-pod store (create-pod store (policy-test-pod "second-dongle" :limits '("example.com/dongle" "1"))))))
    (is (null (gr8s::schedule-pod store (create-pod store (policy-test-pod "too-big" :requests '("cpu" "2"))))))
    (is-true (gr8s::schedule-pod store (create-pod store (policy-test-pod "fits" :requests '("cpu" "1")))))
    ;; The node's two Pod slots are now taken.
    (is (null (gr8s::schedule-pod store (create-pod store (policy-test-pod "third")))))))

(test node-affinity-selects-and-refuses-nodes
  (with-temporary-store (store path)
    (values path)
    (policy-test-node store "alpha")
    (policy-test-node store "beta")
    (flet ((term (key operator value)
             (gr8s::core-object (if (uiop:string-prefix-p "metadata." key) "matchFields" "matchExpressions")
                                (vector (gr8s::core-object "key" key "operator" operator "values" (vector value))))))
      (let ((required (lambda (key operator value)
                        (gr8s::core-object "nodeAffinity"
                                           (gr8s::core-object "requiredDuringSchedulingIgnoredDuringExecution"
                                                              (gr8s::core-object "nodeSelectorTerms" (vector (term key operator value))))))))
        (is (equal "beta"
                   (gr8s:node-record-name
                    (gr8s::schedule-pod store (create-pod store (policy-test-pod "named" :spec-fields (list "affinity" (funcall required "metadata.name" "In" "beta"))))))))
        (is (null (gr8s::schedule-pod store (create-pod store (policy-test-pod "absent" :spec-fields (list "affinity" (funcall required "metadata.name" "In" "gamma")))))))
        (is (equal "alpha"
                   (gr8s:node-record-name
                    (gr8s::schedule-pod store (create-pod store (policy-test-pod "label" :spec-fields (list "affinity" (funcall required "kubernetes.io/hostname" "NotIn" "beta"))))))))
        (signals kubernetes-error (policy-test-pod "bad-field" :spec-fields (list "affinity" (funcall required "metadata.labels" "In" "x"))))))
    (signals kubernetes-error
      (policy-test-pod "pod-affinity" :spec-fields (list "affinity" (gr8s::core-object "podAffinity" (gr8s::core-object)))))
    (let ((preferred (gr8s::core-object "nodeAffinity"
                                        (gr8s::core-object "preferredDuringSchedulingIgnoredDuringExecution"
                                                           (vector (gr8s::core-object "weight" 10
                                                                                      "preference" (gr8s::core-object "matchFields" (vector (gr8s::core-object "key" "metadata.name" "operator" "In" "values" #("alpha"))))))))))
      (is (equal "alpha"
                 (gr8s:node-record-name
                  (gr8s::schedule-pod store (create-pod store (policy-test-pod "favored" :spec-fields (list "affinity" preferred))))))))))

(test preemption-removes-only-enough-lower-priority-pods
  (with-temporary-store (store path)
    (values path)
    (policy-test-node store "only" :extended (gr8s::core-object "example.com/dongle" "1000"))
    (loop for (name value) in '(("p1" 1) ("p2" 2) ("p3" 3) ("p4" 4)) do (policy-test-class store name value))
    (loop for (name class dongles) in '(("low" "p1" 200) ("mid" "p2" 300) ("high" "p3" 450))
          do (is-true (gr8s::schedule-pod store (policy-test-priority-pod store name class dongles))))
    (let ((preemptor (policy-test-priority-pod store "preemptor" "p4" 500)))
      (is (null (gr8s::schedule-pod store preemptor)))
      (is-true (policy-test-deleting-p store "low"))
      (is-true (policy-test-deleting-p store "mid"))
      (is-false (policy-test-deleting-p store "high"))
      (is (equal "only" (gethash (gr8s::pod-uid preemptor) (gr8s::pod-store-nominated-nodes store))))
      ;; Victims still hold their resources; nothing further is preempted meanwhile.
      (is (null (gr8s::schedule-pod store preemptor)))
      (is-false (policy-test-deleting-p store "high"))
      (dolist (name '("low" "mid")) (gr8s::remove-pod store "team" name))
      ;; A lesser Pod cannot use the space reserved for the nominated preemptor.
      (is (null (gr8s::schedule-pod store (policy-test-priority-pod store "latecomer" "p1" 100))))
      (is-true (gr8s::schedule-pod store preemptor)))))

(test preemption-respects-policy-and-equal-priority
  (with-temporary-store (store path)
    (values path)
    (policy-test-node store "only" :extended (gr8s::core-object "example.com/dongle" "1"))
    (policy-test-class store "same" 5)
    (gr8s::create-core-resource store "priorityclasses"
                                (gr8s::core-object "metadata" (gr8s::core-object "name" "polite") "value" 9 "preemptionPolicy" "Never") nil)
    (is-true (gr8s::schedule-pod store (policy-test-priority-pod store "resident" "same" 1)))
    (is (null (gr8s::schedule-pod store (policy-test-priority-pod store "equal" "same" 1))))
    (is-false (policy-test-deleting-p store "resident"))
    (is (null (gr8s::schedule-pod store (policy-test-priority-pod store "never" "polite" 1))))
    (is-false (policy-test-deleting-p store "resident"))))

(test preempted-pod-reports-disruption-condition
  (with-temporary-store (store path)
    (values path)
    (policy-test-node store "only" :extended (gr8s::core-object "example.com/dongle" "1"))
    (policy-test-class store "low" 1)
    (policy-test-class store "high" 2)
    (is-true (gr8s::schedule-pod store (policy-test-priority-pod store "victim" "low" 1)))
    (is (null (gr8s::schedule-pod store (policy-test-priority-pod store "attacker" "high" 1))))
    (let* ((victim (get-pod store "team" "victim"))
           (status (gr8s::add-pod-status-conditions store victim (gr8s::pod-status "Running")))
           (condition (gr8s::find-pod-condition (gethash "conditions" status) "DisruptionTarget")))
      (is (equal "True" (gethash "status" condition)))
      (is (equal "PreemptionByScheduler" (gethash "reason" condition))))
    (let ((status (gr8s::add-pod-status-conditions store (get-pod store "team" "attacker") (gr8s::pod-status "Pending"))))
      (is (equal "only" (gethash "nominatedNodeName" status))))))

(defstruct (policy-storage-runtime (:include gr8s::fake-runtime)
                                   (:constructor make-policy-storage-runtime ()))
  "A fake runtime reporting a settable local storage measurement."
  (layers nil) (volume-bytes 0))

(defmethod gr8s::runtime-ephemeral-usage ((runtime policy-storage-runtime) pod)
  "Report RUNTIME's configured measurement for any POD."
  (declare (ignore pod))
  (values (policy-storage-runtime-layers runtime) (policy-storage-runtime-volume-bytes runtime)))

(test node-evicts-pods-exceeding-ephemeral-storage-limits
  (with-temporary-store (store path)
    (values path)
    (let* ((runtime (make-policy-storage-runtime))
           (reconciler (make-reconciler store runtime))
           (pod (create-pod store (policy-test-pod "writer" :requests '("ephemeral-storage" "1Ki")
                                                            :limits '("ephemeral-storage" "1Mi"))))
           (clock 1000)
           (gr8s::*pod-deletion-clock* (lambda () clock)))
      (setf (policy-storage-runtime-layers runtime) (list (cons "main" 1024)))
      (is (equal "Running" (gethash "phase" (gr8s::reconcile-pod reconciler "team" "writer"))))
      (setf (policy-storage-runtime-layers runtime) (list (cons "main" (* 2 1024 1024))))
      ;; Measured on a schedule, not on every pass.
      (is (equal "Running" (gethash "phase" (gr8s::reconcile-pod reconciler "team" "writer"))))
      (incf clock 11)
      (let ((status (gr8s::reconcile-pod reconciler "team" "writer")))
        (is (equal "Failed" (gethash "phase" status)))
        (is (equal "Evicted" (gethash "reason" status))))
      (is (null (gr8s::runtime-observe runtime (pod-uid pod))))
      (let ((count (fake-runtime-ensure-count runtime)))
        (is (equal "Evicted" (gethash "reason" (gr8s::reconcile-pod reconciler "team" "writer"))))
        (is (= count (fake-runtime-ensure-count runtime)))))))

(test ephemeral-violations-cover-containers-and-pod-totals
  (let ((pod (policy-test-pod "two" :limits '("ephemeral-storage" "1Ki"))))
    (is (null (gr8s::pod-ephemeral-violation pod (list (cons "main" 1024)) 0)))
    (is (search "Container main" (gr8s::pod-ephemeral-violation pod (list (cons "main" 1025)) 0)))
    (is (search "total limit" (gr8s::pod-ephemeral-violation pod (list (cons "main" 1000)) 100)))))
