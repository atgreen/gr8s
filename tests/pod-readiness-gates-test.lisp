;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Verify Pod readiness gates hold Ready until the conditions they name are
;;;; True, that strategic status patches change one condition and keep the rest,
;;;; that Pods naming another scheduler wait for it, and that a changed image
;;;; restarts a crashing container without its accumulated back-off.

(in-package #:gr8s/tests)
(in-suite pod-status-http)

(defun gated-pod-json (name &key (gates '("k8s.io/test-condition1" "k8s.io/test-condition2")) scheduler node)
  "Return a Pod named NAME whose readiness waits for GATES, optionally for SCHEDULER or on NODE."
  (format nil "{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"name\":~S,\"namespace\":\"default\"},\"spec\":{~@[\"schedulerName\":~S,~]~@[\"nodeName\":~S,~]\"readinessGates\":[~{{\"conditionType\":~S}~^,~}],\"containers\":[{\"name\":\"web\",\"image\":\"busybox:latest\"}]}}"
          name scheduler node gates))

(test readiness-gates-are-validated-and-immutable
  (let ((pod (parse-pod (gated-pod-json "gated"))))
    (is (equal '("k8s.io/test-condition1" "k8s.io/test-condition2") (gr8s::pod-readiness-gate-types pod))))
  (signals kubernetes-error (parse-pod (gated-pod-json "bad" :gates '("not a/valid/name"))))
  (signals kubernetes-error
    (parse-pod "{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"name\":\"x\"},\"spec\":{\"readinessGates\":[{\"conditionType\":\"a\",\"extra\":1}],\"containers\":[{\"name\":\"web\",\"image\":\"busybox\"}]}}"))
  (with-temporary-store (store path)
    (values path)
    (let* ((pod (create-pod store (parse-pod (gated-pod-json "gated"))))
           (changed (parse-pod (gated-pod-json "gated" :gates '("k8s.io/other")))))
      (signals kubernetes-error (update-pod store changed (pod-resource-version pod)))
      ;; A PUT that omits them keeps them, as for the other fields admission resolved.
      (let ((omitted (parse-pod (gated-pod-json "gated" :gates nil))))
        (remhash "readinessGates" (gethash "spec" (pod-to-object omitted)))
        (is (equal '("k8s.io/test-condition1" "k8s.io/test-condition2")
                   (gr8s::pod-readiness-gate-types (update-pod store omitted (pod-resource-version pod)))))))))

(test ready-waits-for-every-readiness-gate-condition
  (with-temporary-store (store path)
    (values path)
    (let* ((pod (create-pod store (parse-pod (gated-pod-json "gated" :node "worker-a"))))
           (status (gr8s::add-pod-status-conditions store pod (running-status-for-test "web")))
           (ready (condition-status-for-test status "Ready")))
      (is (equal "True" (gethash "status" (condition-status-for-test status "ContainersReady"))))
      (is (equal "False" (gethash "status" ready)))
      (is (equal "ReadinessGatesNotReady" (gethash "reason" ready)))
      (is (search "corresponding condition of pod readiness gate \"k8s.io/test-condition1\" does not exist."
                  (gethash "message" ready)))
      (flet ((client (&rest pairs)
               (gr8s::save-pod-client-status
                store pod (gr8s::core-object "conditions"
                                             (coerce (loop for (type value) on pairs by #'cddr
                                                           collect (gr8s::core-object "type" type "status" value))
                                                     'vector)))
               (condition-status-for-test (gr8s::add-pod-status-conditions store pod (running-status-for-test "web"))
                                          "Ready")))
        (let ((one (client "k8s.io/test-condition1" "True")))
          (is (equal "False" (gethash "status" one)))
          (is (search "\"k8s.io/test-condition2\" does not exist" (gethash "message" one))))
        (is (equal "True" (gethash "status" (client "k8s.io/test-condition1" "True" "k8s.io/test-condition2" "True"))))
        (let ((false (client "k8s.io/test-condition1" "False" "k8s.io/test-condition2" "True")))
          (is (equal "False" (gethash "status" false)))
          (is (search "the status of pod readiness gate \"k8s.io/test-condition1\" is not \"True\", but False"
                      (gethash "message" false))))))))

(test strategic-status-patches-merge-conditions-by-type
  (with-core-api (store path)
    (values path)
    (status-test-pod store "web")
    (dolist (type '("k8s.io/test-condition1" "k8s.io/test-condition2"))
      (multiple-value-bind (object code)
          (pod-api "/web/status" :method :patch :content-type "application/strategic-merge-patch+json"
                   :content (format nil "{\"status\":{\"conditions\":[{\"type\":~S,\"status\":\"True\"}]}}" type))
        (is (= 200 code))
        (is (equal "True" (pod-condition-status object type)))))
    (let ((later (pod-api "/web")))
      (is (equal "True" (pod-condition-status later "k8s.io/test-condition1")))
      (is (equal "True" (pod-condition-status later "k8s.io/test-condition2"))))
    (pod-api "/web/status" :method :patch :content-type "application/strategic-merge-patch+json"
             :content "{\"status\":{\"conditions\":[{\"type\":\"k8s.io/test-condition1\",\"status\":\"False\"}]}}")
    (let ((later (pod-api "/web")))
      (is (equal "False" (pod-condition-status later "k8s.io/test-condition1")))
      (is (equal "True" (pod-condition-status later "k8s.io/test-condition2"))))
    ;; A JSON merge patch replaces the list, as Kubernetes does.
    (pod-api "/web/status" :method :patch :content-type "application/merge-patch+json"
             :content "{\"status\":{\"conditions\":[{\"type\":\"k8s.io/test-condition2\",\"status\":\"True\"}]}}")
    (is (null (pod-condition-status (pod-api "/web") "k8s.io/test-condition1")))))

(test scheduler-name-defaults-and-another-schedulers-pods-wait-for-it
  (let ((pod (parse-pod *valid-pod-json*)))
    (is (equal "default-scheduler" (gethash "schedulerName" (gethash "spec" (pod-to-object pod)))))
    (is (gr8s::pod-for-this-scheduler-p pod)))
  (signals kubernetes-error (parse-pod (gated-pod-json "bad" :gates nil :scheduler "Not_A_Name")))
  (with-temporary-store (store path)
    (values path)
    (ready-node store "worker-a" "a" "10.64.0.0/20")
    (let ((foreign (create-pod store (parse-pod (gated-pod-json "foreign" :gates nil :scheduler "my-scheduler"))))
          (own (create-pod store (parse-pod (gated-pod-json "own" :gates nil)))))
      (is (not (gr8s::pod-for-this-scheduler-p foreign)))
      (is (null (gr8s::schedule-pod store foreign)))
      (is (null (gr8s::pod-node-name (get-pod store "default" "foreign"))))
      (is (null (condition-status-for-test
                 (gr8s::add-pod-status-conditions store foreign (gr8s::pod-status "Pending")) "PodScheduled")))
      (is (gr8s::schedule-pod store own))
      ;; schedulerName cannot change once the Pod exists.
      (signals kubernetes-error
        (update-pod store (parse-pod (gated-pod-json "foreign" :gates nil :scheduler "other-scheduler"))
                    (pod-resource-version foreign))))))

(test a-changed-image-restarts-without-the-old-back-off
  (let* ((now 4000000000) (state (gr8s::core-object "containers" (gr8s::core-object)))
         (spec (gr8s::make-container-spec :name "side" :image "busybox")))
    (flet ((exit (attempt image)
             (gr8s::record-container-applied-spec state "side" (gr8s::core-object "image" image))
             (incf now)
             (gr8s::prepare-container-restart
              state (lifecycle-info "side" attempt gr8s.cri.v1::+containerstate-container_exited+ now 7) now)))
      (exit 0 "busybox")
      (let ((entry (loop for attempt from 1 to 5 for entry = (exit attempt "busybox") finally (return entry))))
        (is (< 60 (- (gethash "nextStart" entry) now)))
        (is (gr8s::container-backoff-waiting-p entry spec now))
        ;; The new declaration does not wait out the old image's back-off...
        (is (not (gr8s::container-backoff-waiting-p entry (gr8s::make-container-spec :name "side" :image "nginx") now))))
      ;; ...and its own first exit starts a fresh one.
      (let ((entry (exit 6 "nginx")))
        (is (= now (gethash "nextStart" entry)))
        (is (= 10 (gethash "backoff" entry)))))))

(defun gated-scheduling-pod-json (name gates &key node)
  "Return a Pod named NAME held by scheduling GATES, optionally naming NODE."
  (format nil "{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"name\":~S,\"namespace\":\"default\"},\"spec\":{~@[\"nodeName\":~S,~]\"schedulingGates\":[~{{\"name\":~S}~^,~}],\"containers\":[{\"name\":\"web\",\"image\":\"busybox:latest\"}]}}"
          name node gates))

(test scheduling-gates-hold-a-pod-until-they-are-all-removed
  (signals kubernetes-error (parse-pod (gated-scheduling-pod-json "dup" '("foo" "foo"))))
  (signals kubernetes-error (parse-pod (gated-scheduling-pod-json "bad" '("not a name"))))
  ;; A node cannot be named while gates remain.
  (signals kubernetes-error (parse-pod (gated-scheduling-pod-json "named" '("foo") :node "worker-a")))
  (with-temporary-store (store path)
    (values path)
    (ready-node store "worker-a" "a" "10.64.0.0/20")
    (let ((pod (create-pod store (parse-pod (gated-scheduling-pod-json "held" '("foo" "bar"))))))
      (is (null (gr8s::schedule-pod store pod)))
      (let ((condition (condition-status-for-test
                        (gr8s::add-pod-status-conditions store pod (gr8s::pod-status "Pending")) "PodScheduled")))
        (is (equal "False" (gethash "status" condition)))
        (is (equal "SchedulingGated" (gethash "reason" condition)))
        (is (equal "Scheduling is blocked due to non-empty scheduling gates" (gethash "message" condition))))
      ;; Gates can only be removed.
      (signals kubernetes-error
        (update-pod store (parse-pod (gated-scheduling-pod-json "held" '("foo" "baz"))) (pod-resource-version pod)))
      (setf pod (update-pod store (parse-pod (gated-scheduling-pod-json "held" '("bar"))) (pod-resource-version pod)))
      (is (null (gr8s::schedule-pod store pod)))
      (setf pod (update-pod store (parse-pod (gated-scheduling-pod-json "held" nil)) (pod-resource-version pod)))
      (is (gr8s::schedule-pod store pod)))))
