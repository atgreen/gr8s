;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Prove shared Pod finalizer admission, irreversible deletion, real terminal
;;;; observation retention, exact UID recovery and final removal independently
;;;; of Job controller accounting and native probe scheduling.

(in-package #:gr8s/tests)
(def-suite pod-finalizers :in gr8s)
(in-suite pod-finalizers)

(defun finalized-test-pod (&optional (names #("example.com/cleanup")))
  "Create a normal scheduled Pod carrying real API finalizers."
  (let ((object (gr8s::copy-core-object (pod-to-object (grace-pod)))))
    (setf (gethash "finalizers" (gethash "metadata" object)) names)
    (parse-pod object)))

(defun test-terminal-pod-status ()
  "Provide an explicit failed runtime observation, including its real test exit status."
  (gr8s::core-object "phase" "Failed" "containerStatuses"
    (vector (gr8s::core-object "name" "hello" "restartCount" 0 "ready" nil
                              "state" (gr8s::core-object "terminated"
                                         (gr8s::core-object "exitCode" 17 "reason" "Error"))))))

(test pod-finalizer-admission-and-irreversible-updates
  (dolist (names (list #() #("cleanup") #("batch.kubernetes.io/job-tracking") 'null))
    (is (typep (finalized-test-pod names) 'gr8s::pod)))
  (dolist (names (list "cleanup" #(1) #("bad name") #("bad/prefix/name") #("")))
    (signals kubernetes-error (finalized-test-pod names)))
  (with-temporary-store (store directory)
    (declare (ignore directory))
    (let* ((created (create-pod store (finalized-test-pod #("example.com/one" "example.com/two"))))
           (deleting (mark-pod-deleting store "default" "hello" :grace-period 0))
           (object (gr8s::copy-core-object (pod-to-object deleting))))
      (setf (gethash "finalizers" (gethash "metadata" object)) #("example.com/new"))
      (signals kubernetes-error (update-pod store (parse-pod object) (pod-resource-version deleting)))
      (setf (gethash "finalizers" (gethash "metadata" object)) #("example.com/one"))
      (let ((updated (update-pod store (parse-pod object) (pod-resource-version deleting))))
        (is (equal (pod-uid created) (pod-uid updated)))
        (is (equal (gethash "deletionTimestamp" (gethash "metadata" (pod-to-object deleting)))
                   (gethash "deletionTimestamp" (gethash "metadata" (pod-to-object updated))))))
      (signals kubernetes-error (gr8s::remove-pod store "default" "hello"))
      (is (equal (pod-uid created) (pod-uid (get-pod store "default" "hello")))))))

(test forced-deletion-retains-terminal-status-until-last-finalizer-across-reopen
  (with-temporary-store (store directory)
    (let* ((pod (create-pod store (finalized-test-pod)))
           (runtime (make-fake-runtime)) (reconciler (make-reconciler store runtime))
           (status (test-terminal-pod-status))
           (observed (gr8s::make-runtime-pod :uid (pod-uid pod) :resource-version (pod-resource-version pod)
                       :phase "Failed" :status status)))
      (setf (gethash (pod-uid pod) (gr8s::fake-runtime-pods runtime)) observed)
      (let ((actual (gr8s::delete-reconciled-pod reconciler "default" "hello" :uid (pod-uid pod) :grace-period 0)))
        (is (equal "Failed" (gethash "phase" actual)))
        (is (= 17 (gethash "exitCode" (gethash "terminated" (gethash "state" (aref (gethash "containerStatuses" actual) 0)))))))
      (is-false (runtime-observe runtime (pod-uid pod)))
      (is (equal (pod-uid pod) (pod-uid (get-pod store "default" "hello"))))
      (is-false (gethash (pod-uid pod) (gr8s::pod-store-pod-observed-resource-versions store)))
      (let* ((reopened (open-store directory)) (fresh-runtime (make-fake-runtime))
             (fresh-reconciler (make-reconciler reopened fresh-runtime))
             (retained (get-pod reopened "default" "hello")))
        (is-true (gethash "runtimeDeleted" (gr8s::pod-finalization-state reopened retained)))
        (is (equal "Failed" (gethash "phase" (reconcile-pod fresh-reconciler "default" "hello"))))
        (is (= 0 (gr8s::fake-runtime-ensure-count fresh-runtime)))
        (let ((object (gr8s::copy-core-object (pod-to-object retained))))
          (setf (gethash "finalizers" (gethash "metadata" object)) #())
          (update-pod reopened (parse-pod object) (pod-resource-version retained)))
        (reconcile-pod fresh-reconciler "default" "hello")
        (signals kubernetes-error (get-pod reopened "default" "hello"))
        (is-false (probe-file (gr8s::pod-status-state-path reopened (pod-uid pod))))
        (let ((replacement (create-pod reopened (finalized-test-pod))))
          (is-false (equal (pod-uid pod) (pod-uid replacement)))
          (is-false (gr8s::pod-finalization-state reopened replacement))
          (signals kubernetes-error (gr8s::remove-pod reopened "default" "hello" :uid (pod-uid pod))))))))

(test deletion-completion-does-not-invent-an-unobserved-terminal-success
  (with-temporary-store (store directory)
    (declare (ignore directory))
    (let* ((pod (create-pod store (finalized-test-pod))) (runtime (make-fake-runtime))
           (reconciler (make-reconciler store runtime)))
      (runtime-ensure runtime pod)
      (let ((status (gr8s::delete-reconciled-pod reconciler "default" "hello" :grace-period 0)))
        (is-false (gr8s::pod-terminal-status-p status))
        (is-true (gethash "runtimeDeleted" (gr8s::pod-finalization-state store (get-pod store "default" "hello")))))
        (is-false (gethash "status" (gr8s::pod-finalization-state store (get-pod store "default" "hello")))))))

(test native-finalizers-retain-actual-exits-after-all-cri-objects-disappear
  (with-temporary-store (store directory)
    (let* ((now (get-universal-time)) (gr8s::*container-lifecycle-clock* (lambda () now))
           (pod (lifecycle-pod store)) (runtime (gr8s::make-containerd-runtime :log-root directory))
           (object (gr8s::copy-core-object (pod-to-object pod))))
      (setf (gethash "finalizers" (gethash "metadata" object)) #("example.com/cleanup")
            pod (update-pod store (parse-pod object) (pod-resource-version pod)))
      (with-lifecycle-cri (fixture pod (list (lifecycle-info "main" 0 gr8s.cri.v1::+containerstate-container_running+ now)
                                           (lifecycle-info "side" 0 gr8s.cri.v1::+containerstate-container_running+ now)))
        (gr8s::runtime-terminate-pod runtime pod now)
        (is-false (lifecycle-cri-fixture-sandbox fixture))
        (is (null (lifecycle-cri-fixture-infos fixture)))
        (let ((actual (runtime-observe runtime (pod-uid pod))))
          (is (equal "Failed" (gr8s::runtime-pod-phase actual)))
          (let ((statuses (gethash "containerStatuses" (gr8s::runtime-pod-status actual))))
            (is (= 2 (length statuses)))
            (loop for status across statuses
                  do (is (= 137 (gethash "exitCode" (gethash "terminated" (gethash "state" status)))))
                     (is (search "containerd://" (gethash "containerID" status))))))
        (is (probe-file (gr8s::container-lifecycle-path runtime (pod-uid pod))))
        (gr8s::runtime-forget-pod-finalization runtime (pod-uid pod))
        (is-false (runtime-observe runtime (pod-uid pod)))
        (is-false (probe-file (gr8s::container-lifecycle-path runtime (pod-uid pod))))))))

(test failure-to-checkpoint-actual-finalized-exits-prevents-native-removal
  (with-temporary-store (store directory)
    (let* ((now (get-universal-time)) (gr8s::*container-lifecycle-clock* (lambda () now))
           (pod (lifecycle-pod store)) (runtime (gr8s::make-containerd-runtime :log-root directory))
           (object (gr8s::copy-core-object (pod-to-object pod)))
           (save (symbol-function 'gr8s::save-container-lifecycle-state)))
      (setf (gethash "finalizers" (gethash "metadata" object)) #("example.com/cleanup")
            pod (update-pod store (parse-pod object) (pod-resource-version pod)))
      (with-lifecycle-cri (fixture pod (list (lifecycle-info "main" 0 gr8s.cri.v1::+containerstate-container_running+ now)))
        (unwind-protect
             (progn
               (setf (symbol-function 'gr8s::save-container-lifecycle-state)
                     (lambda (&rest args) (declare (ignore args)) (error "Checkpoint write failed")))
               (signals error (gr8s::runtime-terminate-pod runtime pod now))
               (is-true (lifecycle-cri-fixture-sandbox fixture))
               (is (= 1 (length (lifecycle-cri-fixture-infos fixture))))
               (is-false (find :delete (lifecycle-cri-fixture-calls fixture) :key #'car))
               (is-false (find :delete-sandbox (lifecycle-cri-fixture-calls fixture) :key #'car)))
          (setf (symbol-function 'gr8s::save-container-lifecycle-state) save))))))
