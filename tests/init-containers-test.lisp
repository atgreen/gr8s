;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Exercise production init ordering and restart recovery through the shared
;;;; deterministic CRI fixture, including negative exits, durable retry timing,
;;;; ambiguous Created attempts and application gating. No test supplies a
;;;; synthetic successful init status to the production reconciler.

(in-package #:gr8s/tests)
(def-suite init-containers :in gr8s)
(in-suite init-containers)

(defun init-test-pod (store &optional (policy "Always"))
  "Create a Pod declaring two ordered init containers and one application."
  (let* ((object (com.inuoe.jzon:parse *valid-pod-json*)) (spec (gethash "spec" object)))
    (setf (gethash "restartPolicy" spec) policy
          (gethash "initContainers" spec)
          (vector (gr8s.resources::core-object "name" "init-first" "image" "busybox")
                  (gr8s.resources::core-object "name" "init-second" "image" "busybox"))
          (gethash "containers" spec) (vector (gr8s.resources::core-object "name" "app" "image" "busybox")))
    (create-pod store (parse-pod object))))

(defun init-test-status (observed name &optional (kind "initContainerStatuses"))
  "Find one status by declaration name in an actual runtime observation."
  (find name (gethash kind (gr8s.runtime::runtime-pod-status observed)) :test #'equal
        :key (lambda (item) (gethash "name" item))))

(test native-init-containers-gate-applications-in-order-and-survive-reopen
  (with-temporary-store (store directory)
    (let* ((now 4000000000) (gr8s.kubelet::*container-lifecycle-clock* (lambda () now))
           (pod (init-test-pod store)) (runtime (gr8s.runtime.containerd::make-containerd-runtime :log-root directory)))
      (with-lifecycle-cri (fixture pod nil)
        (let ((observed (gr8s.runtime::runtime-ensure runtime pod)))
          (is (equal '((:create "init-first" 0 "same-sandbox")) (lifecycle-cri-fixture-calls fixture)))
          (is (equal "Pending" (gr8s.runtime::runtime-pod-phase observed)))
          (is (equal "PodInitializing" (gethash "reason" (gethash "waiting" (gethash "state" (init-test-status observed "app" "containerStatuses"))))))
          (is (not (gr8s.kubelet::pod-initialization-complete-p pod (gr8s.runtime::runtime-pod-status observed)))))
        (setf (lifecycle-cri-fixture-infos fixture)
              (list (lifecycle-info "init-first" 0 gr8s.cri.v1::+containerstate-container_exited+ now)))
        (let ((observed (gr8s.runtime::runtime-ensure runtime pod)))
          (is (= 2 (count :create (lifecycle-cri-fixture-calls fixture) :key #'first)))
          (is (equal '(:create "init-second" 0 "same-sandbox") (first (lifecycle-cri-fixture-calls fixture))))
          (is (eq t (gethash "ready" (init-test-status observed "init-first"))))
          (is (equal "Pending" (gr8s.runtime::runtime-pod-phase observed))))
        (setf (lifecycle-cri-fixture-infos fixture)
              (list (lifecycle-info "init-first" 0 gr8s.cri.v1::+containerstate-container_exited+ now)
                    (lifecycle-info "init-second" 0 gr8s.cri.v1::+containerstate-container_exited+ now)))
        (let* ((reopened (gr8s.runtime.containerd::make-containerd-runtime :log-root directory))
               (observed (gr8s.runtime::runtime-ensure reopened pod)))
          (is (= 3 (count :create (lifecycle-cri-fixture-calls fixture) :key #'first)))
          (is (equal '(:create "app" 0 "same-sandbox") (first (lifecycle-cri-fixture-calls fixture))))
          (is (equal "Running" (gr8s.runtime::runtime-pod-phase observed)))
          (is (= 2 (length (gethash "initContainerStatuses" (gr8s.runtime::runtime-pod-status observed)))))
          (is (= 1 (length (gethash "containerStatuses" (gr8s.runtime::runtime-pod-status observed)))))
          (is (gr8s.kubelet::pod-initialization-complete-p pod (gr8s.runtime::runtime-pod-status observed)))
          (setf (gr8s.model::pod-node-name pod) "worker")
          (let ((status (gr8s.kubelet::add-pod-status-conditions store pod (gr8s.kubelet::observed-status observed))))
            (is (equal "True" (gethash "status" (gr8s.kubelet::find-pod-condition (gethash "conditions" status) "Initialized")))))
          ;; Lose completed init CRI metadata after its terminal observations
          ;; were checkpointed; the live application must not be interrupted.
          (setf (lifecycle-cri-fixture-infos fixture)
                (remove-if (lambda (info) (gr8s.kubelet::pod-init-container-p pod (gr8s.runtime.containerd::cri-container-info-name info)))
                           (lifecycle-cri-fixture-infos fixture)))
          (gr8s.runtime::runtime-ensure reopened pod)
          (is (= 3 (count :create (lifecycle-cri-fixture-calls fixture) :key #'first))))))))

(test native-failed-init-never-starts-the-app-and-keeps-terminal-failure
  (with-temporary-store (store directory)
    (let* ((now 4000000000) (pod (init-test-pod store "Never"))
           (runtime (gr8s.runtime.containerd::make-containerd-runtime :log-root directory)))
      (with-lifecycle-cri (fixture pod (list (lifecycle-info "init-first" 0 gr8s.cri.v1::+containerstate-container_exited+ now)
                                           (lifecycle-info "init-second" 0 gr8s.cri.v1::+containerstate-container_exited+ now 17)))
        (let* ((observed (gr8s.runtime::runtime-ensure runtime pod))
               (status (gr8s.kubelet::observed-status observed)))
          (setf (gr8s.model::pod-node-name pod) "worker")
          (gr8s.kubelet::add-pod-status-conditions store pod status)
          (is (equal "Failed" (gr8s.runtime::runtime-pod-phase observed)))
          (is (null (lifecycle-cri-fixture-calls fixture)))
          (is (= 17 (gethash "exitCode" (gethash "terminated" (gethash "state" (init-test-status observed "init-second"))))))
          (is (equal "PodInitializing" (gethash "reason" (gethash "waiting" (gethash "state" (init-test-status observed "app" "containerStatuses"))))))
          (let ((condition (gr8s.kubelet::find-pod-condition (gethash "conditions" status) "Initialized")))
            (is (equal "False" (gethash "status" condition)))
            (is (equal "ContainersNotInitialized" (gethash "reason" condition)))
            (is (equal "containers with incomplete status: [init-second]" (gethash "message" condition)))
            (is (stringp (gethash "lastTransitionTime" condition))))
          (is (not (gr8s.kubelet::native-container-progress-required-p pod observed))))))))

(test failed-never-init-is-not-resurrected-after-sandbox-metadata-disappears
  (with-temporary-store (store directory)
    (let* ((pod (init-test-pod store "Never")) (runtime (gr8s.runtime.containerd::make-containerd-runtime :log-root directory)))
      (with-lifecycle-cri (fixture pod (list (lifecycle-info "init-first" 0 gr8s.cri.v1::+containerstate-container_exited+ 4000000000 23)))
        (gr8s.runtime::runtime-ensure runtime pod)
        (setf (lifecycle-cri-fixture-infos fixture) nil (lifecycle-cri-fixture-sandbox fixture) nil)
        (let ((observed (gr8s.runtime::runtime-ensure (gr8s.runtime.containerd::make-containerd-runtime :log-root directory) pod)))
          (is (equal "Failed" (gr8s.runtime::runtime-pod-phase observed)))
          (is (null (lifecycle-cri-fixture-calls fixture)))
          (is (= 23 (gethash "exitCode" (gethash "terminated" (gethash "state" (init-test-status observed "init-first")))))))))))

(test replacement-sandbox-reexecutes-init-before-restarting-apps
  (with-temporary-store (store directory)
    (let* ((now 4000000000) (gr8s.kubelet::*container-lifecycle-clock* (lambda () now))
           (pod (init-test-pod store)) (runtime (gr8s.runtime.containerd::make-containerd-runtime :log-root directory)))
      (with-lifecycle-cri (fixture pod (list (lifecycle-info "init-first" 0 gr8s.cri.v1::+containerstate-container_exited+ now)
                                           (lifecycle-info "init-second" 0 gr8s.cri.v1::+containerstate-container_exited+ now)
                                           (lifecycle-info "app" 0 gr8s.cri.v1::+containerstate-container_running+ now)))
        (gr8s.runtime::runtime-ensure runtime pod)
        (setf (lifecycle-cri-fixture-infos fixture) nil (lifecycle-cri-fixture-sandbox fixture) nil)
        (let ((observed (gr8s.runtime::runtime-ensure runtime pod)))
          (is (equal "Pending" (gr8s.runtime::runtime-pod-phase observed)))
          (is (equal '(:create "init-first" 1 "new-sandbox") (first (lifecycle-cri-fixture-calls fixture))))
          (is (not (find "app" (lifecycle-cri-fixture-calls fixture) :test #'equal :key #'second)))
          (is (= 1 (length (lifecycle-cri-fixture-infos fixture)))))))))

(test protobuf-init-container-declarations-reach-the-executable-model
  (let* ((init (core-test-protobuf '((1 "prepare") (2 "busybox") (3 "/bin/true"))))
         (app (core-test-protobuf '((1 "application") (2 "busybox"))))
         (spec (core-test-protobuf (list (list 2 app) (list 20 init))))
         (raw (core-test-protobuf (list (list 1 (core-test-protobuf '((1 "init-wire")))) (list 2 spec))))
         (pod (parse-pod (gr8s.resources::decode-pod-protobuf raw))))
    (is (= 1 (length (gr8s.model::pod-init-containers pod))))
    (is (equal "prepare" (container-spec-name (aref (gr8s.model::pod-init-containers pod) 0))))
    (is (equal '("/bin/true") (coerce (gr8s.model::container-spec-command (aref (gr8s.model::pod-init-containers pod) 0)) 'list)))))

(test finalizer-shutdown-retains-real-interrupted-init-as-terminal-failed
  (with-temporary-store (store directory)
    (let* ((now 4000000000) (pod (init-test-pod store))
           (runtime (gr8s.runtime.containerd::make-containerd-runtime :log-root directory))
           (info (lifecycle-info "init-first" 0 gr8s.cri.v1::+containerstate-container_running+ now)))
      (with-lifecycle-cri (fixture pod (list info))
        (gr8s.runtime::runtime-ensure runtime pod)
        (gr8s.kubelet::capture-containerd-finalized-pod runtime pod now)
        (let ((before (runtime-observe runtime (pod-uid pod))))
          (is (equal "Failed" (gr8s.runtime::runtime-pod-phase before)))
          (is (= 137 (gethash "exitCode" (gethash "terminated" (gethash "state" (init-test-status before "init-first"))))))
          (is (not (gr8s.kubelet::pod-initialization-complete-p pod (gr8s.runtime::runtime-pod-status before)))))
        (gr8s.runtime.containerd::containerd-delete-uid runtime (pod-uid pod) now :preserve-lifecycle t)
        (let ((after (runtime-observe (gr8s.runtime.containerd::make-containerd-runtime :log-root directory) (pod-uid pod))))
          (is (equal "Failed" (gr8s.runtime::runtime-pod-phase after)))
          (is (= 137 (gethash "exitCode" (gethash "terminated" (gethash "state" (init-test-status after "init-first"))))))
          (is (null (lifecycle-cri-fixture-sandbox fixture)))
          (is (not (find "app" (lifecycle-cri-fixture-calls fixture) :test #'equal :key #'second))))))))

(test native-failed-init-always-retries-with-durable-backoff-before-any-app
  (with-temporary-store (store directory)
    (let* ((now 4000000000) (gr8s.kubelet::*container-lifecycle-clock* (lambda () now))
           (pod (init-test-pod store)) (runtime (gr8s.runtime.containerd::make-containerd-runtime :log-root directory)))
      (with-lifecycle-cri (fixture pod (list (lifecycle-info "init-first" 0 gr8s.cri.v1::+containerstate-container_exited+ now 7)))
        (gr8s.runtime::runtime-ensure runtime pod)
        (is (equal '((:create "init-first" 1 "same-sandbox")) (lifecycle-cri-fixture-calls fixture)))
        (incf now)
        (setf (lifecycle-cri-fixture-infos fixture)
              (list (lifecycle-info "init-first" 1 gr8s.cri.v1::+containerstate-container_exited+ now 9)))
        (let* ((observed (gr8s.runtime::runtime-ensure runtime pod)) (status (init-test-status observed "init-first")))
          (is (equal "Pending" (gr8s.runtime::runtime-pod-phase observed)))
          (is (equal "CrashLoopBackOff" (gethash "reason" (gethash "waiting" (gethash "state" status)))))
          (is (= 9 (gethash "exitCode" (gethash "terminated" (gethash "lastState" status)))))
          (is (= 1 (gethash "restartCount" status)))
          (is (= 0 (gethash "restartCount" (init-test-status observed "app" "containerStatuses")))))
        (incf now 9)
        (let ((reopened (gr8s.runtime.containerd::make-containerd-runtime :log-root directory)))
          (gr8s.runtime::runtime-ensure reopened pod)
          (is (= 1 (count :create (lifecycle-cri-fixture-calls fixture) :key #'first)))
          (incf now)
          (gr8s.runtime::runtime-ensure reopened pod)
          (is (= 2 (count :create (lifecycle-cri-fixture-calls fixture) :key #'first)))
          (is (equal '(:create "init-first" 2 "same-sandbox") (first (lifecycle-cri-fixture-calls fixture)))))))))

(test native-init-created-attempt-is-adopted-without-creating-a-sibling
  (with-temporary-store (store directory)
    (let* ((pod (init-test-pod store)) (runtime (gr8s.runtime.containerd::make-containerd-runtime :log-root directory)))
      (with-lifecycle-cri (fixture pod (list (lifecycle-info "init-first" 0 gr8s.cri.v1::+containerstate-container_created+ 4000000000)))
        (gr8s.runtime::runtime-ensure runtime pod)
        (is (equal '((:start "init-first-0")) (lifecycle-cri-fixture-calls fixture)))
        (is (= 1 (length (lifecycle-cri-fixture-infos fixture))))))))

(test init-admission-shares-container-name-and-volume-invariants
  (dolist (scenario '("duplicate" "probe" "unknown-volume"))
    (let* ((object (com.inuoe.jzon:parse *valid-pod-json*))
           (spec (gethash "spec" object))
           (init (gr8s.resources::core-object "name" "init" "image" "busybox")))
      (setf (gethash "initContainers" spec) (vector init))
      (cond ((equal scenario "duplicate")
             (setf (gethash "name" init) (gethash "name" (aref (gethash "containers" spec) 0))))
            ((equal scenario "probe") (setf (gethash "readinessProbe" init) (gr8s.resources::core-object)))
            (t (setf (gethash "volumeMounts" init)
                     (vector (gr8s.resources::core-object "name" "missing" "mountPath" "/data")))))
      (signals kubernetes-error (parse-pod object)))))

(test a-final-init-failure-stops-sidecars-instead-of-restarting-them
  (let* ((object (gr8s.resources::core-object
                  "apiVersion" "v1" "kind" "Pod" "metadata" (gr8s.resources::core-object "name" "failing")
                  "spec" (gr8s.resources::core-object
                          "restartPolicy" "Never"
                          "initContainers" (vector (gr8s.resources::core-object "name" "sidecar" "image" "busybox" "restartPolicy" "Always")
                                                   (gr8s.resources::core-object "name" "setup" "image" "busybox"))
                          "containers" (vector (gr8s.resources::core-object "name" "main" "image" "busybox")))))
         (pod (parse-pod object)))
    (flet ((status (name state) (gr8s.resources::core-object "name" name "state" state))
           (exited (code) (gr8s.resources::core-object "terminated" (gr8s.resources::core-object "exitCode" code)))
           (running () (gr8s.resources::core-object "running" (gr8s.resources::core-object))))
      (let ((failed (vector (status "sidecar" (running)) (status "setup" (exited 3))))
            (working (vector (status "sidecar" (running)) (status "setup" (running))))
            (sidecar-crash (vector (status "sidecar" (exited 3)) (status "setup" (running)))))
        (is-true (gr8s.kubelet::pod-init-failed-for-good-p pod failed))
        (is-false (gr8s.kubelet::pod-init-failed-for-good-p pod working))
        ;; A sidecar's own exit is restarted, whatever the Pod's policy says.
        (is-false (gr8s.kubelet::pod-init-failed-for-good-p pod sidecar-crash))
        ;; A running sidecar needs stopping; a stopped one does not need restarting.
        (is-true (gr8s.kubelet::pod-sidecar-progress-required-p pod (gr8s.resources::core-object "initContainerStatuses" failed)))
        (is-false (gr8s.kubelet::pod-sidecar-progress-required-p
                   pod (gr8s.resources::core-object "initContainerStatuses"
                                          (vector (status "sidecar" (exited 137)) (status "setup" (exited 3))))))
        (is-true (gr8s.kubelet::pod-sidecar-progress-required-p pod (gr8s.resources::core-object "initContainerStatuses" sidecar-crash)))))
    ;; Other policies retry the init container, so nothing is final.
    (setf (gethash "restartPolicy" (gethash "spec" object)) "OnFailure")
    (is-false (gr8s.kubelet::pod-init-failed-for-good-p
               (parse-pod object)
               (vector (gr8s.resources::core-object "name" "setup" "state"
                                          (gr8s.resources::core-object "terminated" (gr8s.resources::core-object "exitCode" 3))))))))
