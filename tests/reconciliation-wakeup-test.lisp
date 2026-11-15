;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
(in-package #:gr8s/tests)
(def-suite reconciliation-wakeup :in gr8s)
(in-suite reconciliation-wakeup)

(defun wakeup-configmap (store name &key dry-run)
  (gr8s.resources::create-core-resource
   store "configmaps" (core-fixture "ConfigMap" name "data" (gr8s.resources::core-object "value" "one"))
   "default" :dry-run dry-run))

(test desired-resource-notifications-follow-commit-and-ignore-bookkeeping
  (with-temporary-store (store path)
    (values path)
    (gwc-seed store)
    (let* ((notifications 0)
           (observer (lambda () (incf notifications))))
      (gr8s.resources::add-core-resource-change-observer store observer)
      (unwind-protect
           (progn
             (wakeup-configmap store "dry" :dry-run t)
             (is (= 0 notifications))
             (with-failing-core-writes ("injected write failure")
               (signals error (wakeup-configmap store "failed")))
             (is (= 0 notifications))
             (wakeup-configmap store "settings")
             (is (= 1 notifications))
             (signals kubernetes-error (wakeup-configmap store "settings"))
             (is (= 1 notifications))
             (gr8s.resources::update-core-resource
              store "configmaps" "default" "settings" #'identity)
             (is (= 1 notifications))
             ;; Gateway status is real stored status, but is not desired configuration.
             (gr8s.resources::update-core-resource
              store "gateways" "default" "web"
              (lambda (object)
                (setf (gethash "status" object) (gr8s.resources::core-object "listeners" #())) object))
             (is (= 1 notifications))
             (gr8s.resources::update-core-resource
              store "configmaps" "default" "settings"
              (lambda (object) (setf (gethash "value" (gethash "data" object)) "ONE") object))
             (is (= 2 notifications))
             (gr8s.resources::update-core-resource
              store "configmaps" "default" "settings"
              (lambda (object)
                (setf (gethash "labels" (gethash "metadata" object))
                      (gr8s.resources::core-object "route" "selected")) object))
             (is (= 3 notifications))
             (gr8s.resources::delete-core-resource store "configmaps" "default" "settings")
             (is (= 4 notifications)))
        (gr8s.resources::remove-core-resource-change-observer store observer))
      (wakeup-configmap store "after-unsubscribe")
      (is (= 4 notifications)))))

(test desired-resource-notifications-wait-for-raft-apply
  (with-temporary-store (store path)
    (values path)
    (let ((notifications 0) (command nil))
      (gr8s.resources::add-core-resource-change-observer store (lambda () (incf notifications)))
      (setf (gr8s.store::pod-store-consensus-commit-fn store)
            (lambda (kind payload) (setf command (list kind payload)) '(:core-ok)))
      (wakeup-configmap store "replicated")
      (is (eq :core-delta (first command)))
      (is (= 0 notifications))
      (gr8s.resources::install-core-state-delta store (second command))
      (is (= 1 notifications))
      (gr8s.resources::install-core-state-delta store (second command))
      (is (= 1 notifications)))))

(test resource-change-wakes-worker-and-coalesces-writes-during-pass
  (with-temporary-store (store path)
    (values path)
    (let* ((passes 0) (block nil) (entered nil)
           (release (bt:make-condition-variable)) (lock (bt:make-lock "wakeup test"))
           (worker (start-reconciliation-worker
                    (make-reconciler store (make-fake-runtime)) :interval 30.0 :watch-resources t
                    :before-reconcile
                    (lambda ()
                      (bt:with-lock-held (lock)
                        (incf passes)
                        (when block
                          (setf entered t)
                          (loop while block do (bt:condition-wait release lock :timeout 5))))))))
      (unwind-protect
           (progn
             (is (poll-until (lambda () (= passes 1)) :timeout 2))
             (bt:with-lock-held (lock) (setf block t))
             (wakeup-configmap store "first")
             (is (poll-until (lambda () entered) :timeout 2))
             ;; Every write below is after the pass consumed its original wakeup.
             (dotimes (i 10) (wakeup-configmap store (format nil "burst-~D" i)))
             (bt:with-lock-held (lock) (setf block nil) (bt:condition-notify release))
             (is (poll-until (lambda () (>= passes 3)) :timeout 2))
             (sleep 0.1)
             (is (= 3 passes)))
        (bt:with-lock-held (lock) (setf block nil) (bt:condition-notify release))
        (stop-reconciliation-worker worker))
      ;; A stopped worker must release its observer and accept no new work.
      (wakeup-configmap store "after-stop")
      (is (= 3 passes)))))

(test snapshot-install-notifies-only-for-new-desired-content
  (with-temporary-store (source source-path)
    (values source-path)
    (with-temporary-store (target target-path)
      (values target-path)
      (wakeup-configmap source "snapshot")
      (let* ((notifications 0)
             (snapshot (gr8s.resources::core-state-json
                        source (gr8s.store::pod-store-resources source)
                        (gr8s.store::pod-store-resource-revision source)
                        (gr8s.store::pod-store-workload-deletions source)
                        (gr8s.store::pod-store-job-controller-states source))))
        (gr8s.resources::add-core-resource-change-observer target (lambda () (incf notifications)))
        (gr8s.resources::install-core-state-blob target snapshot)
        (is (= 1 notifications))
        (gr8s.resources::install-core-state-blob target snapshot)
        (is (= 1 notifications))))))

(test event-driven-worker-preserves-leadership-and-ignores-status-churn
  (with-temporary-store (store path)
    (values path)
    (gwc-seed store)
    (let* ((leader nil) (passes 0)
           (worker (start-reconciliation-worker
                    (make-reconciler store (make-fake-runtime)) :interval 30.0 :watch-resources t
                    :leader-gate (lambda () leader) :before-reconcile (lambda () (incf passes)))))
      (unwind-protect
           (progn
             (wakeup-configmap store "follower")
             (sleep 0.05)
             (is (= 0 passes))
             (setf leader t)
             (wakeup-configmap store "leader")
             (is (poll-until (lambda () (= passes 1)) :timeout 2))
             (dotimes (i 10)
               (gr8s.resources::update-core-resource
                store "gateways" "default" "web"
                (lambda (object)
                  (setf (gethash "status" object) (gr8s.resources::core-object "listeners" #())) object)))
             (gr8s.resources::create-core-resource store "events" (event-fixture "no-wakeup") "alpha")
             (gr8s.resources::create-core-resource
              store "leases" (gr8s.resources::core-object
                              "metadata" (gr8s.resources::core-object "name" "heartbeat")
                              "spec" (gr8s.resources::core-object "holderIdentity" "worker")) "default")
             ;; A condition-variable notification alone is not work.
             (bt:with-lock-held ((gr8s.server::reconciliation-worker-lock worker))
               (bt:condition-notify (gr8s.server::reconciliation-worker-wake-up worker)))
             (sleep 0.1)
             (is (= 1 passes))
             (setf leader nil)
             (wakeup-configmap store "demoted")
             (sleep 0.05)
             (is (= 1 passes)))
        (stop-reconciliation-worker worker)))))

(test periodic-repair-survives-resource-subscription
  (with-temporary-store (store path)
    (values path)
    (let* ((passes 0)
           (worker (start-reconciliation-worker
                    (make-reconciler store (make-fake-runtime)) :interval 0.03 :watch-resources t
                    :before-reconcile (lambda () (incf passes)))))
      (unwind-protect
           (is (poll-until (lambda () (>= passes 2)) :timeout 2))
        (stop-reconciliation-worker worker)))))

(test observer-failure-does-not-reject-committed-writes-or-other-observers
  (with-temporary-store (store path)
    (values path)
    (let ((notifications 0))
      (gr8s.resources::add-core-resource-change-observer store (lambda () (incf notifications)))
      (gr8s.resources::add-core-resource-change-observer store (lambda () (error "subscriber failed")))
      (let ((*error-output* (make-string-output-stream)))
        (wakeup-configmap store "committed"))
      (is (= 1 notifications))
      (is (equal "committed" (gethash "name" (gethash "metadata"
                                  (gr8s.resources::get-core-resource store "configmaps" "default" "committed"))))))))

(test wakeup-deadlines-retain-precision-in-long-running-processes
  ;; Converting the running clock to a single float loses subsecond precision.
  (let ((now (+ (expt 2 55) 123)))
    (is (= (+ now (round (* 0.005 internal-time-units-per-second)))
           (gr8s.server::reconciliation-deadline 0.005 now)))
    (is (= (+ now internal-time-units-per-second)
           (gr8s.server::reconciliation-deadline 1.0 now)))))

(test gateway-wakeup-selects-targeted-pass-but-keeps-full-repair
  (with-temporary-store (store path)
    (values path)
    (gwc-seed store)
    (let* ((full 0) (gateway 0)
           (worker (start-reconciliation-worker
                    (make-reconciler store (make-fake-runtime))
                    :watch-resources t :interval 0.05
                    :before-reconcile (lambda () (incf full))
                    :gateway-reconcile (lambda () (incf gateway)))))
      (unwind-protect
           (progn
             (is (poll-until (lambda () (>= full 1)) :timeout 2))
             ;; Continuous Gateway updates must not postpone full repair forever.
             (dotimes (i 20)
               (gr8s.resources::update-core-resource
                store "httproutes" "default" "app"
                (lambda (object)
                  (setf (gethash "annotations" (gethash "metadata" object))
                        (gr8s.resources::core-object "test" (write-to-string i))) object))
               (sleep 0.01))
             (is (> gateway 0))
             (is (>= full 3))
             (let ((before full))
               (wakeup-configmap store "non-gateway")
               (is (poll-until (lambda () (> full before)) :timeout 2))))
        (stop-reconciliation-worker worker)))))

(test pending-full-work-dominates-gateway-wakeups
  (let ((worker (gr8s.server::make-reconciliation-worker)))
    (gr8s.server::request-reconciliation worker :scope :gateway)
    (gr8s.server::request-reconciliation worker :scope :full)
    (gr8s.server::request-reconciliation worker :scope :gateway)
    (is (eq :full (gr8s.server::reconciliation-worker-pending-scope worker)))))

(test promotion-wakes-a-full-pass-before-targeted-gateway-work
  (with-temporary-store (store path)
    (values path)
    (gwc-seed store)
    (let* ((leader nil) (full 0) (gateway 0)
           (worker (start-reconciliation-worker
                    (make-reconciler store (make-fake-runtime)) :watch-resources t :interval 30.0
                    :leader-gate (lambda () leader)
                    :before-reconcile (lambda () (incf full))
                    :gateway-reconcile (lambda () (incf gateway)))))
      (unwind-protect
           (progn
             (sleep 0.05)
             (setf leader t)
             (gr8s.resources::update-core-resource
              store "httproutes" "default" "app"
              (lambda (object) (setf (gethash "hostnames" (gethash "spec" object)) #("promoted.example.com")) object))
             (is (poll-until (lambda () (> (+ full gateway) 0)) :timeout 2))
             (is (= 1 full))
             (is (= 0 gateway)))
        (stop-reconciliation-worker worker)))))
