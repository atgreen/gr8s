;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Exercise real Job-owned Pod creation/adoption and durable terminal UID
;;;; handoff before finalizer removal, including write failure, process reopen,
;;;; name reuse and preservation of user finalizers/healthy runtime identities.

(in-package #:gr8s/tests)
(def-suite job-controller :in gr8s)
(in-suite job-controller)

(defmacro with-job-controller-fixture ((store runtime reconciler directory) &body body)
  "Enable the private Job type only inside focused controller tests before public API wiring."
  `(let ((gr8s::*stored-resource-types*
           (cons '("jobs" "Job" "batch/v1" t) gr8s::*stored-resource-types*)))
     (with-temporary-store (,store ,directory)
       (let* ((,runtime (make-fake-runtime)) (,reconciler (make-reconciler ,store ,runtime)))
         ,@body))))

(defun create-controller-job (store &optional (name "work"))
  "Create through production admission with a user finalizer on the Pod template."
  (let* ((input (batch-test-job name)) (metadata (gethash "metadata" (gethash "template" (gethash "spec" input)))))
    (setf (gethash "finalizers" metadata) #("example.com/user"))
    (gr8s::create-core-resource store "jobs" input "alpha")))

(defun observe-job-pod-terminal (reconciler runtime pod phase exit-code finish-time)
  "Provide a concrete runtime exit observation without mutating the Job's controller status."
  (gr8s::reconcile-pod reconciler (pod-namespace pod) (pod-name pod))
  (let* ((actual (gr8s:runtime-observe runtime (pod-uid pod)))
         (status (job-test-finish finish-time phase))
         (container (aref (gethash "containerStatuses" status) 0)))
    (setf (gethash "exitCode" (gethash "terminated" (gethash "state" container))) exit-code
          (gethash "name" container) "web"
          (gethash "containerID" container) (concatenate 'string "fake://" (pod-uid pod))
          (gr8s::runtime-pod-phase actual) phase (gr8s::runtime-pod-status actual) status)
    actual))

(defun current-job-status (store)
  "Read the actual durable Job status used by the controller tests."
  (gethash "status" (gr8s::get-core-resource store "jobs" "alpha" "work")))

(defun current-job-pod (store pod)
  "Read the same named dependent and let each test verify its exact identity."
  (get-pod store (pod-namespace pod) (pod-name pod)))

(test job-creates-real-unique-uid-owned-tracked-pods
  (with-job-controller-fixture (store runtime reconciler directory)
    (declare (ignore directory))
    (let* ((job (create-controller-job store))
           (first (gr8s::create-job-pod store job))
           (second (gr8s::create-job-pod store job))
           (reference (gr8s::workload-controller-reference (pod-to-object first))))
      (is (= 2 (length (list-pods store "alpha"))))
      (is-false (equal (pod-uid first) (pod-uid second)))
      (is-true (gr8s::workload-owned-p (pod-to-object first) job))
      (is-true (gethash "blockOwnerDeletion" reference))
      (is-true (gr8s::job-pod-tracked-p first))
      (is (find "example.com/user" (gr8s::pod-finalizers first) :test #'equal))
      (reconcile-all reconciler)
      (is (= 2 (gr8s::fake-runtime-ensure-count runtime))))))

(test job-terminal-accounting-does-not-release-tracking-before-durable-write
  (with-job-controller-fixture (store runtime reconciler directory)
    (let* ((job (create-controller-job store))
           (pod (gr8s::create-job-pod store job))
           (persist (symbol-function 'gr8s::write-private-text-atomically)))
      (gr8s::flush-job-terminal-accounting reconciler job (gr8s::job-observations reconciler job))
      (is (= 0 (gethash "succeeded" (current-job-status store) 0)))
      (is-false (gr8s::job-terminal-condition (current-job-status store)))
      (observe-job-pod-terminal reconciler runtime pod "Succeeded" 0 4000000000)
      (let ((terminal (gr8s::job-observations reconciler job)))
        (unwind-protect
             (progn
               (setf (symbol-function 'gr8s::write-private-text-atomically)
                     (lambda (&rest arguments) (declare (ignore arguments))
                       (error "Simulated Job checkpoint failure")))
               (signals error (gr8s::flush-job-terminal-accounting reconciler job terminal))
               (is-true (gr8s::job-pod-tracked-p (current-job-pod store pod))))
          (setf (symbol-function 'gr8s::write-private-text-atomically) persist))
        (gr8s::flush-job-terminal-accounting reconciler job terminal)
        (gr8s::flush-job-terminal-accounting reconciler job terminal)
        (let ((status (current-job-status store)) (retained (current-job-pod store pod)))
          (is (= 1 (gethash "succeeded" status)))
          (is (null (gr8s::job-uncounted-uids status "succeeded")))
          (is-false (gr8s::job-pod-tracked-p retained))
          (is (equalp #("example.com/user") (gr8s::pod-finalizers retained))))
        (let* ((reopened (open-store directory))
               (fresh (make-reconciler reopened runtime))
               (current (gr8s::get-core-resource reopened "jobs" "alpha" "work")))
          (gr8s::flush-job-terminal-accounting fresh current (gr8s::job-observations fresh current))
          (is (= 1 (gethash "succeeded" (current-job-status reopened)))))))))

(test job-reopen-recovers-a-committed-uncounted-failure-before-finalizer-removal
  (with-job-controller-fixture (store runtime reconciler directory)
    (let* ((job (create-controller-job store)) (pod (gr8s::create-job-pod store job)))
      (observe-job-pod-terminal reconciler runtime pod "Failed" 17 4000000000)
      (gr8s::account-job-observations reconciler job (gr8s::job-observations reconciler job))
      (let ((status (current-job-status store)))
        (is (= 0 (gethash "failed" status)))
        (is (equal (list (pod-uid pod)) (gr8s::job-uncounted-uids status "failed"))))
      (is-true (gr8s::job-pod-tracked-p (current-job-pod store pod)))
      (let* ((reopened (open-store directory))
             (fresh (make-reconciler reopened runtime))
             (current (gr8s::get-core-resource reopened "jobs" "alpha" "work"))
             (uid (gethash "uid" (gethash "metadata" current))))
        (gr8s::flush-job-terminal-accounting fresh current (gr8s::job-observations fresh current))
        (let ((status (current-job-status reopened))
              (backoff (gethash uid (gr8s::pod-store-job-controller-states reopened))))
          (is (= 1 (gethash "failed" status)))
          (is (null (gr8s::job-uncounted-uids status "failed")))
          (is (= 1 (gethash "failuresAfterLastSuccess" backoff))))))))

(test stale-job-name-reuse-cannot-create-adopt-or-release-a-replacement-owner
  (with-job-controller-fixture (store runtime reconciler directory)
    (declare (ignore runtime directory))
    (let* ((old (create-controller-job store))
           (old-uid (gethash "uid" (gethash "metadata" old)))
           (pod (gr8s::create-job-pod store old)))
      (gr8s::delete-core-resource store "jobs" "alpha" "work")
      (let* ((replacement (create-controller-job store))
             (new-uid (gethash "uid" (gethash "metadata" replacement))))
        (is-false (equal old-uid new-uid))
        (is-false (gr8s::create-job-pod store old))
        (is (null (gr8s::job-owned-pods reconciler replacement :claim t)))
        (is-false (gr8s::remove-accounted-job-finalizer store old pod :deleting t))
        (is-true (gr8s::job-pod-tracked-p (current-job-pod store pod)))))))
