;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
(in-package #:gr8s/tests)
(def-suite store-access-gate :in gr8s)
(in-suite store-access-gate)

(defun assert-store-access-503 (function)
  (handler-case (progn (funcall function) (fail "Expected store access to be unavailable"))
    (gr8s:kubernetes-error (condition)
      (is (= 503 (gr8s::kubernetes-error-status-code condition))))))

(defun wait-for-store-access-block (store)
  (let ((deadline (+ (get-internal-real-time) (* 3 internal-time-units-per-second))))
    (loop
      (when (bt:with-lock-held ((gr8s::pod-store-lock store))
              (gr8s.store::pod-store-access-blocked store)) (return t))
      (when (> (get-internal-real-time) deadline) (error "Store never entered quiescence"))
      (sleep 0.005))))

(test quiescence-blocks-new-readers-and-writers-while-existing-request-drains
  (with-temporary-store (store root)
    (declare (ignore root))
    (ha-make-pod store "before")
    (let* ((entered (bt:make-semaphore)) (release (bt:make-semaphore))
           (request-result nil) (drain-result nil)
           (request (bt:make-thread
                     (lambda ()
                       (setf request-result
                             (handler-case
                                 (gr8s.store::call-with-store-request
                                  store (lambda ()
                                          (bt:signal-semaphore entered)
                                          (unless (bt:wait-on-semaphore release :timeout 5) (error "Lease release timeout"))
                                          (ha-make-pod store "inflight-write")))
                               (error (condition) condition))))))
           (drain nil))
      (unwind-protect
           (progn
             (is-true (bt:wait-on-semaphore entered :timeout 5))
             (setf drain (bt:make-thread
                          (lambda () (setf drain-result
                                           (handler-case (gr8s.store::quiesce-store-access store :timeout 5)
                                             (error (condition) condition))))))
             (wait-for-store-access-block store)
             (assert-store-access-503 (lambda () (gr8s.store::resume-store-access store)))
             (assert-store-access-503 (lambda () (gr8s:get-pod store "default" "before")))
             (assert-store-access-503 (lambda () (ha-make-pod store "rejected")))
             (assert-store-access-503 (lambda () (gr8s.store::call-with-store-request store (lambda () t))))
             (bt:signal-semaphore release)
             (bt:join-thread request)
             (bt:join-thread drain)
             (is (typep request-result 'gr8s.model:pod))
             (is (eq store drain-result))
             (assert-store-access-503 (lambda () (gr8s:get-pod store "default" "inflight-write")))
             (gr8s.store::resume-store-access store)
             (is (gr8s:get-pod store "default" "inflight-write"))
             (signals gr8s:kubernetes-error (gr8s:get-pod store "default" "rejected")))
        (bt:signal-semaphore release)
        (when (bt:thread-alive-p request) (bt:join-thread request))
        (when (and drain (bt:thread-alive-p drain)) (bt:join-thread drain))))))

(test request-errors-and-nested-routing-do-not-leak-access-leases
  (with-temporary-store (store root)
    (declare (ignore root))
    (signals error
      (gr8s.store::call-with-store-request
       store (lambda () (gr8s.store::call-with-store-request store (lambda () (error "Handler failed"))))))
    (is (gr8s.store::quiesce-store-access store :timeout 0))
    (assert-store-access-503 (lambda () (gr8s.store::quiesce-store-access store :timeout 0)))
    (gr8s.store::resume-store-access store)
    (is (gr8s.store::call-with-store-request store (lambda () t)))))

(test drain-timeout-reopens-unchanged-store-and-request-can-finish
  (with-temporary-store (store root)
    (declare (ignore root))
    (ha-make-pod store "unchanged")
    (let* ((entered (bt:make-semaphore)) (release (bt:make-semaphore))
           (thread (bt:make-thread
                    (lambda ()
                      (gr8s.store::call-with-store-request
                       store (lambda () (bt:signal-semaphore entered)
                               (bt:wait-on-semaphore release :timeout 5)))))))
      (unwind-protect
           (progn
             (is-true (bt:wait-on-semaphore entered :timeout 5))
             (assert-store-access-503 (lambda () (gr8s.store::quiesce-store-access store :timeout 0.02)))
             (is (gr8s:get-pod store "default" "unchanged")))
        (bt:signal-semaphore release)
        (bt:join-thread thread))
      (is (gr8s.store::quiesce-store-access store :timeout 0))
      (gr8s.store::resume-store-access store))))

(test pending-restore-intent-prevents-reopening-access
  (with-temporary-store (store root)
    (let* ((descriptor (make-restore-intent-fixture store root))
           (id (gethash "generation" descriptor)))
      (gr8s.store::quiesce-store-access store :timeout 0)
      (gr8s.store::begin-store-restore root id)
      (assert-store-access-503 (lambda () (gr8s.store::resume-store-access store)))
      (assert-store-access-503 (lambda () (gr8s:get-pod store "default" "snapshot-pod")))
      (is (gr8s:open-store root))
      (assert-store-access-503 (lambda () (gr8s.store::resume-store-access store)))
      (assert-store-access-503 (lambda () (gr8s:get-pod store "default" "snapshot-pod"))))))

(test blocked-store-http-request-returns-kubernetes-service-unavailable
  (with-temporary-store (store root)
    (declare (ignore root))
    (let ((server (start-http-test-server :store store :runtime (make-fake-runtime))))
      (unwind-protect
           (progn
             (gr8s.store::quiesce-store-access store :timeout 0)
             (multiple-value-bind (body status) (request "/api/v1/namespaces/default/pods")
               (is (= 503 status))
               (is (equal "ServiceUnavailable" (gethash "reason" (response-object body)))))
             (multiple-value-bind (body status) (request "/readyz")
               (declare (ignore body))
               (is (= 503 status)))
             (multiple-value-bind (body status) (request "/livez")
               (declare (ignore body))
               (is (= 200 status)))
             (gr8s.store::resume-store-access store)
             (multiple-value-bind (body status) (request "/api/v1/namespaces/default/pods")
               (declare (ignore body))
               (is (= 200 status))))
        (stop-server server)))))

(test blocked-ha-writes-never-propose-consensus-commands
  (with-temporary-store (store root)
    (declare (ignore root))
    (let ((proposals 0))
      (setf (gr8s::pod-store-consensus-commit-fn store)
            (lambda (&rest args) (declare (ignore args)) (incf proposals)))
      (gr8s.store::quiesce-store-access store :timeout 0)
      (assert-store-access-503 (lambda () (ha-make-pod store "blocked-ha")))
      (assert-store-access-503
       (lambda () (gr8s::create-core-resource store "configmaps" (core-fixture "ConfigMap" "blocked-ha") "default")))
      (assert-store-access-503
       (lambda () (gr8s:register-node store (gr8s:make-node-record :id "blocked-ha" :name "blocked-ha" :pod-cidr "10.89.0.0/20"))))
      (is (= 0 proposals))
      (gr8s.store::resume-store-access store))))
