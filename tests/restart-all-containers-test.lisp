;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; The RestartAllContainers restart rule action, against the deterministic CRI
;;;; fixture: every init, sidecar and application container stops and runs again as
;;;; its next attempt in the same sandbox, once, with its last exit kept.

(in-package #:gr8s/tests)
(def-suite restart-all-containers :in gr8s)
(in-suite restart-all-containers)

(defun restart-all-rule ()
  "Return the RestartAllContainers rule upstream's specs use: exit code 42."
  (gr8s::core-object "action" "RestartAllContainers"
                     "exitCodes" (gr8s::core-object "operator" "In" "values" #(42))))

(defun restart-all-pod (store)
  "Create upstream's \"restart all containers on regular container exit\" Pod."
  (create-pod store
              (parse-pod
               (gr8s::core-object
                "apiVersion" "v1" "kind" "Pod" "metadata" (gr8s::core-object "name" "restart-all" "namespace" "default")
                "spec" (gr8s::core-object
                        "restartPolicy" "Never"
                        "initContainers" (vector (gr8s::core-object "name" "init" "image" "busybox")
                                                 (gr8s::core-object "name" "sidecar" "image" "busybox" "restartPolicy" "Always"))
                        "containers" (vector (gr8s::core-object "name" "source" "image" "busybox" "restartPolicy" "Never"
                                                                "restartPolicyRules" (vector (restart-all-rule)))
                                             (gr8s::core-object "name" "regular" "image" "busybox")))))))

(defun restart-all-status (observed name)
  "Return container NAME's status, init or application, from OBSERVED."
  (let ((status (gr8s::runtime-pod-status observed)))
    (find name (concatenate 'vector (gethash "initContainerStatuses" status #()) (gethash "containerStatuses" status #()))
          :test #'equal :key (lambda (item) (gethash "name" item)))))

(test restart-all-containers-runs-the-pod-again-in-its-sandbox
  (with-temporary-store (store directory)
    (let* ((now 4000000000) (gr8s::*container-lifecycle-clock* (lambda () now))
           (pod (restart-all-pod store))
           (runtime (gr8s::make-containerd-runtime :log-root directory))
           (running gr8s.cri.v1::+containerstate-container_running+)
           (exited gr8s.cri.v1::+containerstate-container_exited+))
      (with-lifecycle-cri (fixture pod (list (lifecycle-info "init" 0 exited now 0)
                                             (lifecycle-info "sidecar" 0 running now)
                                             (lifecycle-info "source" 0 exited now 42)
                                             (lifecycle-info "regular" 0 running now)))
        (flet ((reconcile ()
                 (let ((observed (runtime-observe runtime (pod-uid pod))))
                   (gr8s::runtime-reconcile-containers runtime pod observed)))
               (calls (kind) (remove kind (lifecycle-cri-fixture-calls fixture) :key #'first :test-not #'eq)))
          (let ((observed (runtime-observe runtime (pod-uid pod))))
            ;; Exit 42 restarts everything, so the Pod is neither finished nor failed.
            (is (not (equal "Failed" (gr8s::runtime-pod-phase observed))))
            (is (gr8s::native-container-progress-required-p pod observed)))
          (reconcile)
          ;; The running containers were stopped, every old attempt removed, all in the same sandbox.
          (is (equal '("regular-0" "sidecar-0") (sort (mapcar #'second (calls :stop)) #'string<)))
          (is (equal '("init-0" "regular-0" "sidecar-0" "source-0") (sort (mapcar #'second (calls :delete)) #'string<)))
          (is (null (calls :new-sandbox)))
          ;; Initialization starts over: the first init container runs as its next attempt.
          (is (equal '((:create "init" 1 "same-sandbox")) (calls :create)))
          ;; It finishes; the sidecar and then the applications follow.
          (setf (gr8s::cri-container-info-state (find "init-1" (lifecycle-cri-fixture-infos fixture)
                                                      :key #'gr8s::cri-container-info-id :test #'equal))
                exited)
          (dotimes (pass 3) (reconcile))
          (is (equal '(("init" 1) ("regular" 1) ("sidecar" 1) ("source" 1))
                     (sort (mapcar (lambda (call) (list (second call) (third call))) (calls :create))
                           #'string< :key #'first)))
          (let ((observed (runtime-observe runtime (pod-uid pod))))
            (dolist (name '("init" "sidecar" "source" "regular"))
              (let ((status (restart-all-status observed name)))
                (is (eql 1 (gethash "restartCount" status)) "~A restartCount" name)
                (is (hash-table-p (gethash "terminated" (gethash "lastState" status (gr8s::core-object))))
                    "~A keeps its last exit" name)))
            (is (= 42 (gethash "exitCode" (gethash "terminated" (gethash "lastState" (restart-all-status observed "source"))))))
            ;; The new attempts run on; nothing triggers another restart.
            (is (not (gr8s::restart-all-containers-trigger
                      pod (gr8s::current-container-infos
                           (lifecycle-cri-fixture-infos fixture)
                           (gr8s::load-container-lifecycle-state runtime (pod-uid pod)))
                      (gr8s::load-container-lifecycle-state runtime (pod-uid pod)))))))))))

(test init-container-restart-rules-are-honoured
  (let ((pod (parse-pod
              (gr8s::core-object
               "apiVersion" "v1" "kind" "Pod" "metadata" (gr8s::core-object "name" "init-rules")
               "spec" (gr8s::core-object
                       "restartPolicy" "Never"
                       "initContainers" (vector (gr8s::core-object "name" "source-init" "image" "busybox" "restartPolicy" "Never"
                                                                   "restartPolicyRules" (vector (restart-all-rule))))
                       "containers" (vector (gr8s::core-object "name" "regular" "image" "busybox")))))))
    (is (gr8s::container-exit-restarts-all-p pod "source-init" 42))
    (is (not (gr8s::container-exit-restarts-all-p pod "source-init" 1)))
    (flet ((status (code) (vector (gr8s::core-object "name" "source-init"
                                                     "state" (gr8s::core-object "terminated" (gr8s::core-object "exitCode" code))))))
      ;; Exit 42 restarts the Pod; any other failure ends it, as the Pod's policy says.
      (is (not (gr8s::pod-init-failed-for-good-p pod (status 42))))
      (is (gr8s::pod-init-failed-for-good-p pod (status 1))))))
