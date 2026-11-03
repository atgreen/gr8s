;;;; SPDX-FileCopyrightText: 2026 gr8s contributors
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Verify durable Pod deadlines, irreversible deletion, exact agent completion
;;;; acknowledgements and cancellable asynchronous shutdown through the API.

(in-package #:gr8s/tests)
(in-suite gr8s)

(defun grace-pod (&optional (grace 30))
  "Construct a scheduled Pod with an explicit termination grace period."
  (let ((object (com.inuoe.jzon:parse *valid-pod-json*)))
    (setf (gethash "terminationGracePeriodSeconds" (gethash "spec" object)) grace
          (gethash "nodeName" (gethash "spec" object)) "worker-a")
    (parse-pod object)))

(test pod-grace-defaults-validates-and-does-not-restart-containers
  (let* ((pod (parse-pod *valid-pod-json*))
         (spec (gethash "spec" (pod-to-object pod)))
         (fingerprint (gr8s::pod-runtime-spec-fingerprint pod)))
    (is (= 30 (gethash "terminationGracePeriodSeconds" spec)))
    (dolist (value '(0 1 600))
      (setf (gethash "terminationGracePeriodSeconds" spec) value)
      (is (equal fingerprint (gr8s::pod-runtime-spec-fingerprint pod))))
    (remhash "terminationGracePeriodSeconds" spec)
    (is (equal fingerprint (gr8s::pod-runtime-spec-fingerprint pod)))
    (dolist (value '(-1 1.5 "10" t 9223372036854775808))
      (setf (gethash "terminationGracePeriodSeconds" spec) value)
      (signals kubernetes-error (parse-pod (gr8s::copy-json-object (pod-to-object pod)))))))

(test pod-deletion-deadline-survives-restart-and-only-shortens-from-original-start
  (with-temporary-store (store path)
    (let* ((now 4000000000) (gr8s::*pod-deletion-clock* (lambda () now)))
      (create-pod store (grace-pod))
      (let ((first (mark-pod-deleting store "default" "hello")))
        (is (= (+ now 30) (gr8s::pod-deletion-deadline first)))
        (is (= 30 (gethash "deletionGracePeriodSeconds" (gethash "metadata" (pod-to-object first)))))
        (incf now 10)
        (let ((reopened (open-store path)))
          (is (= 20 (gr8s::pod-remaining-deletion-grace (get-pod reopened "default" "hello")))))
        (dolist (args '(nil (:grace-period 90) (:grace-period 30)))
          (let ((same (apply #'mark-pod-deleting store "default" "hello" args)))
            (is (equal (pod-resource-version first) (pod-resource-version same)))
            (is (= 4000000030 (gr8s::pod-deletion-deadline same)))))
        (let ((shorter (mark-pod-deleting store "default" "hello" :grace-period 15)))
          (is (= 4000000015 (gr8s::pod-deletion-deadline shorter)))
          (is (= 5 (gr8s::pod-remaining-deletion-grace shorter))))
        (let ((elapsed (mark-pod-deleting store "default" "hello" :grace-period 5)))
          (is (= now (gr8s::pod-deletion-deadline elapsed)))
          (is (= 1 (gethash "deletionGracePeriodSeconds" (gethash "metadata" (pod-to-object elapsed))))))
        (let ((forced (mark-pod-deleting store "default" "hello" :grace-period 0)))
          (is (= now (gr8s::pod-deletion-deadline forced)))
          (is (= 0 (gethash "deletionGracePeriodSeconds" (gethash "metadata" (pod-to-object forced))))))))))

(test pod-deletion-preconditions-dry-run-and-updates-cannot-resurrect
  (with-temporary-store (store path)
    (let* ((pod (create-pod store (grace-pod)))
           (before (com.inuoe.jzon:stringify (pod-to-object pod))))
      (signals kubernetes-error (mark-pod-deleting store "default" "hello" :uid "stale"))
      (signals kubernetes-error (mark-pod-deleting store "default" "hello" :resource-version "0"))
      (signals kubernetes-error (mark-pod-deleting store "default" "hello" :grace-period "bad"))
      (let ((preview (mark-pod-deleting store "default" "hello" :dry-run t)))
        (is (gr8s::deletion-requested-p preview)))
      (is (equal before (com.inuoe.jzon:stringify (pod-to-object (get-pod store "default" "hello")))))
      (let* ((deleting (mark-pod-deleting store "default" "hello"))
             (replacement (grace-pod 900))
             (metadata (gethash "metadata" (pod-to-object deleting))))
        (update-pod store replacement (pod-resource-version deleting))
        (is (equal (gethash "deletionTimestamp" metadata)
                   (gethash "deletionTimestamp" (gethash "metadata" (pod-to-object replacement)))))
        (is (= 30 (gethash "deletionGracePeriodSeconds" (gethash "metadata" (pod-to-object replacement)))))))))

(test unscheduled-and-terminal-pods-delete-without-grace
  (with-temporary-store (store path)
    (create-pod store (parse-pod *valid-pod-json*))
    (is (= 0 (gr8s::pod-remaining-deletion-grace (mark-pod-deleting store "default" "hello"))))
    (delete-pod store "default" "hello")
    (let ((pod (create-pod store (grace-pod))))
      (gr8s::update-pod-observed-status store pod (gr8s::pod-status "Succeeded"))
      (is (= 0 (gr8s::pod-remaining-deletion-grace (mark-pod-deleting store "default" "hello" :grace-period 100)))))))

(defun grace-snapshot-without-network (snapshot)
  "Copy assignment transport fields for a fake agent without native networking."
  (make-instance 'gr8s.node.v1::desired-state-snapshot
                 :revision (slot-value snapshot 'gr8s.node.v1::revision)
                 :pods (slot-value snapshot 'gr8s.node.v1::pods)))

(test graceful-control-plane-deletion-waits-for-exact-agent-acknowledgement
  (with-temporary-store (store path)
    (let* ((server (gr8s::%make-node-grpc-server :store store))
           (runtime (gr8s::make-control-plane-runtime store server))
           (reconciler (make-reconciler store runtime))
           (agent (gr8s::make-node-runtime (merge-pathnames "agent/" path) (make-fake-runtime) nil))
           (pod (create-pod store (grace-pod))))
      (gr8s::register-node store (gr8s::make-node-record :id "worker-a" :name "worker-a" :pod-cidr "10.88.0.0/24"))
      (gr8s::mark-node-ready store "worker-a" (get-universal-time))
      (unwind-protect
           (progn
             (gr8s::start-node-runtime agent)
             (reconcile-pod reconciler "default" "hello")
             (gr8s::reconcile-node-snapshot agent (grace-snapshot-without-network (gr8s::current-node-snapshot server "worker-a")))
             (let ((old-version (pod-resource-version pod)))
               (is (equal "Terminating" (gethash "reason" (gr8s::delete-reconciled-pod reconciler "default" "hello"))))
               (let* ((deleting (get-pod store "default" "hello"))
                      (snapshot (gr8s::current-node-snapshot server "worker-a")))
                 (is (slot-value (first (slot-value snapshot 'gr8s.node.v1::pods)) 'gr8s.node.v1::deleting))
                 (gr8s::reconcile-node-snapshot agent (grace-snapshot-without-network snapshot))
                 ;; Fake containers exit immediately. The local record is gone,
                 ;; but its final status must survive until the CP withdraws it.
                 (signals kubernetes-error (get-pod (gr8s::node-runtime-store agent) "default" "hello"))
                 (let* ((status (gr8s::node-runtime-status agent))
                        (message (first (slot-value status 'gr8s.node.v1::pods))))
                   (is (equal "Deleted" (slot-value message 'gr8s.node.v1::reason)))
                   (setf (slot-value message 'gr8s.node.v1::resource-version) old-version)
                   (gr8s::handle-node-agent-envelope server "worker-a" (gr8s::make-agent-envelope :status status))
                   (is (equal "Terminating" (gethash "reason" (reconcile-pod reconciler "default" "hello"))))
                   (setf (slot-value message 'gr8s.node.v1::resource-version) (pod-resource-version deleting))
                   (gr8s::handle-node-agent-envelope server "worker-a" (gr8s::make-agent-envelope :status status))
                   (is (equal "Deleted" (gethash "reason" (reconcile-pod reconciler "default" "hello"))))
                   (signals kubernetes-error (get-pod store "default" "hello"))
                   (gr8s::reconcile-node-snapshot agent (grace-snapshot-without-network (gr8s::current-node-snapshot server "worker-a")))
                   (is (null (slot-value (gr8s::node-runtime-status agent) 'gr8s.node.v1::pods)))))))
        (gr8s::stop-node-runtime agent)))))

(defstruct (gated-deletion-runtime (:include gr8s::fake-runtime)
                                  (:constructor make-gated-deletion-runtime ()))
  (controller (gr8s::make-deletion-controller))
  (gate-lock (bt:make-lock "test shutdown gate"))
  (changed (bt:make-condition-variable))
  (entered 0))

(defmethod gr8s::runtime-delete-pod ((runtime gated-deletion-runtime) pod)
  "Exercise the real background controller with controllable container termination."
  (gr8s::poll-runtime-pod-deletion (gated-deletion-runtime-controller runtime) runtime pod))

(defmethod gr8s::runtime-terminate-pod ((runtime gated-deletion-runtime) pod deadline)
  "Wait for cancellation during graceful shutdown; force shutdown completes immediately."
  (let ((cancelled nil))
    (gr8s::register-runtime-deletion-cancel
     (lambda ()
       (bt:with-lock-held ((gated-deletion-runtime-gate-lock runtime))
         (setf cancelled t)
         (bt:condition-notify (gated-deletion-runtime-changed runtime)))))
    (bt:with-lock-held ((gated-deletion-runtime-gate-lock runtime))
      (incf (gated-deletion-runtime-entered runtime))
      (loop while (and (> deadline (get-universal-time)) (not cancelled))
            do (bt:condition-wait (gated-deletion-runtime-changed runtime)
                                  (gated-deletion-runtime-gate-lock runtime) :timeout .05)))
    ;; A cancelled generation must not remove runtime state after being replaced.
    (gr8s::register-runtime-deletion-cancel (constantly nil))
    (runtime-delete runtime (pod-uid pod))))

(defmethod gr8s::stop-runtime-deletions ((runtime gated-deletion-runtime))
  "Release and join test jobs through the production shutdown path."
  (gr8s::stop-runtime-deletion-controller (gated-deletion-runtime-controller runtime)))

(defun await-grace-test (predicate)
  "Wait up to five seconds for an independently running deletion operation."
  (loop repeat 500 when (funcall predicate) return t do (sleep .01)))

(test pod-http-deletion-is-asynchronous-preconditioned-and-force-shortenable
  (with-temporary-store (store path)
    (let* ((runtime (make-gated-deletion-runtime))
           (reconciler (make-reconciler store runtime))
           (server (start-server :port 18089 :store store :runtime runtime :reconciler reconciler))
           (pod (create-pod store (grace-pod))))
      (unwind-protect
           (progn
             (reconcile-pod reconciler "default" "hello")
             (check-core-status 409 "/api/v1/namespaces/default/pods/hello" :method :delete
                                :object (gr8s::json-object "preconditions" (gr8s::json-object "uid" "stale")))
             (check-core-status 200 "/api/v1/namespaces/default/pods/hello?dryRun=All" :method :delete
                                :object (gr8s::json-object "gracePeriodSeconds" 0))
             (is (not (gr8s::deletion-requested-p (get-pod store "default" "hello"))))
             (let ((started (get-internal-real-time)))
               (check-core-status 200 "/api/v1/namespaces/default/pods/hello" :method :delete
                                  :content-type "application/vnd.kubernetes.protobuf"
                                  :octets (core-test-protobuf-envelope "DeleteOptions" '((1 30))))
               (is (< (/ (- (get-internal-real-time) started) internal-time-units-per-second) 1)))
             (is (await-grace-test (lambda () (plusp (gated-deletion-runtime-entered runtime)))))
             (let ((terminating (check-core-status 200 "/api/v1/namespaces/default/pods/hello")))
               (is (= 30 (gethash "deletionGracePeriodSeconds" (gethash "metadata" terminating)))))
             (check-core-status 200 "/api/v1/namespaces/default/pods/hello" :method :delete
                                :object (gr8s::json-object "gracePeriodSeconds" 0))
             (is (await-grace-test
                  (lambda () (equal "Deleted" (gethash "reason" (reconcile-pod reconciler "default" "hello"))))))
             (signals kubernetes-error (get-pod store "default" "hello"))
             (is (null (runtime-observe runtime (pod-uid pod)))))
        (stop-server server)
        (gr8s::stop-runtime-deletions runtime)))))

(test runtime-shutdown-cancels-and-joins-active-pod-deletions
  (with-temporary-store (store path)
    (let* ((runtime (make-gated-deletion-runtime))
           (reconciler (make-reconciler store runtime)))
      (create-pod store (grace-pod 120))
      (reconcile-pod reconciler "default" "hello")
      (gr8s::delete-reconciled-pod reconciler "default" "hello")
      (is (await-grace-test (lambda () (plusp (gated-deletion-runtime-entered runtime)))))
      (gr8s::stop-runtime-deletions runtime)
      (is (= 0 (hash-table-count (gr8s::deletion-controller-jobs (gated-deletion-runtime-controller runtime)))))
      (is (null (gr8s::deletion-controller-retired (gated-deletion-runtime-controller runtime)))))))
