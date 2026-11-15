;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
(in-package #:gr8s/tests)
(def-suite gateway-fast-path :in gr8s)
(in-suite gateway-fast-path)

(test discovery-serialization-is-reused-only-with-consistent-inputs
  (with-temporary-store (store path)
    (values path)
    (gwc-seed store)
    (gr8s.kubelet::call-with-discovery-projection-cache
     (lambda ()
       (let ((first (gr8s.kubelet::service-discovery-projection store)))
         (is (eq first (gr8s.kubelet::service-discovery-projection store)))
         (gr8s.resources::update-core-resource
          store "httproutes" "default" "app"
          (lambda (object) (setf (gethash "hostnames" (gethash "spec" object)) #("changed.example.com")) object))
         (let ((changed (gr8s.kubelet::service-discovery-projection store)))
           (is (not (equalp first changed)))
           (is (eq changed (gr8s.kubelet::service-discovery-projection store)))
           ;; Pod changes can affect resolved NetworkPolicy projections.
           (create-pod store (parse-pod *valid-pod-json*))
           (is (not (eq changed (gr8s.kubelet::service-discovery-projection store))))))))))

(test cached-discovery-preserves-unchanged-journal-objects
  (with-temporary-store (source source-path)
    (values source-path)
    (gwc-seed source)
    (with-temporary-store (target target-path)
      (multiple-value-bind (index cache)
          (gr8s.kubelet::decode-service-discovery-projection
           (gr8s.kubelet::service-discovery-projection source))
        (gr8s.kubelet::install-assigned-resource-objects target nil nil :public-resources index)
        (let ((revision (gr8s.store::pod-store-resource-revision target)))
          (gr8s.resources::update-core-resource
           source "httproutes" "default" "app"
           (lambda (object)
             (setf (gethash "hostnames" (gethash "spec" object)) #("new.example.com")) object))
          (multiple-value-bind (next next-cache)
              (gr8s.kubelet::decode-service-discovery-projection
               (mapcar #'copy-seq (gr8s.kubelet::service-discovery-projection source)) cache)
            (gr8s.kubelet::install-assigned-resource-objects target nil nil :public-resources next)
            (let ((events (gr8s.resources::template-history-after target revision)))
              (is (= 1 (length events)))
              (is (equal "httproutes" (gethash "resource" (first events)))))
            (is (= (hash-table-count next) (hash-table-count next-cache)))
            (let ((reopened (open-store target-path)))
              (is (equalp #("new.example.com")
                          (gethash "hostnames" (gethash "spec"
                            (gr8s.resources::get-core-resource reopened "httproutes" "default" "app"))))))))))))

(test discovery-cache-does-not-accept-unvalidated-input
  (with-temporary-store (store path)
    (values path)
    (gwc-seed store)
    (multiple-value-bind (index cache)
        (gr8s.kubelet::decode-service-discovery-projection
         (gr8s.kubelet::service-discovery-projection store))
      (let ((size (hash-table-count cache)))
        (signals error
          (gr8s.kubelet::decode-service-discovery-projection
           (list (trivial-utf-8:string-to-utf-8-bytes "{}")) cache))
        (is (= size (hash-table-count cache)))
        (is (= size (hash-table-count index)))))))

(test projection-cache-invalidates-on-snapshot-replacement-with-equal-clocks
  (with-temporary-store (source source-path)
    (values source-path)
    (with-temporary-store (target target-path)
      (values target-path)
      (gwc-seed source)
      (gwc-seed target)
      (gr8s.resources::update-core-resource
       source "httproutes" "default" "app"
       (lambda (object) (setf (gethash "hostnames" (gethash "spec" object)) #("restored.example.com")) object))
      (wakeup-configmap target "same-clock")
      (is (= (gr8s.store::pod-store-resource-revision source) (gr8s.store::pod-store-resource-revision target)))
      (let ((snapshot (gr8s.resources::core-state-json
                       source (gr8s.store::pod-store-resources source)
                       (gr8s.store::pod-store-resource-revision source)
                       (gr8s.store::pod-store-workload-deletions source)
                       (gr8s.store::pod-store-job-controller-states source))))
        (gr8s.kubelet::call-with-discovery-projection-cache
         (lambda ()
           (let ((before (gr8s.kubelet::service-discovery-projection target)))
             (gr8s.resources::install-core-state-blob target snapshot)
             (is (not (equalp before (gr8s.kubelet::service-discovery-projection target)))))))))))

(test projection-cache-does-not-bypass-the-store-access-gate
  (with-temporary-store (store path)
    (values path)
    (gwc-seed store)
    (gr8s.kubelet::call-with-discovery-projection-cache
     (lambda ()
       (gr8s.kubelet::service-discovery-projection store)
       (gr8s.store::quiesce-store-access store :timeout 0)
       (unwind-protect
            (signals kubernetes-error (gr8s.kubelet::service-discovery-projection store))
         (gr8s.store::resume-store-access store))))))

(test gateway-node-guard-requires-unchanged-dependencies-and-recent-full-apply
  (let* ((now (get-internal-real-time))
         (old (desired-snapshot-for-test))
         (new (desired-snapshot-for-test))
         (resources (make-hash-table :test 'equal))
         (agent (gr8s.agent::%make-node-runtime :state :running)))
    (is (not (gr8s.agent::node-gateway-update-p agent new resources now)))
    (setf (gr8s.agent::node-runtime-applied-snapshot agent) old
          (gr8s.agent::node-runtime-full-snapshot-applied-at agent) now
          (gr8s.agent::node-runtime-discovery-resources agent) resources)
    (is (not (gr8s.agent::node-gateway-update-p agent new resources now)))
    (let ((changed (alexandria:copy-hash-table resources)))
      (setf (gethash '("httproutes" "default" "new") changed)
            (gr8s.resources::core-object "metadata" (gr8s.resources::core-object "name" "new")))
      (is (gr8s.agent::node-gateway-update-p agent new changed now))
      (setf (gethash '("services" "default" "new") changed)
            (gr8s.resources::core-object "metadata" (gr8s.resources::core-object "name" "new")))
      (is (not (gr8s.agent::node-gateway-update-p agent new changed now))))
    (is (not (gr8s.agent::node-gateway-update-p agent new resources (+ now internal-time-units-per-second))))
    (setf (slot-value new 'gr8s.node.v1::network) (make-instance 'gr8s.node.v1::node-network-config))
    (is (not (gr8s.agent::node-gateway-update-p agent new resources now)))
    (setf (slot-value new 'gr8s.node.v1::network) nil
          (slot-value new 'gr8s.node.v1::pods)
          (list (pod-assignment-for-test (parse-pod *valid-pod-json*))))
    (is (not (gr8s.agent::node-gateway-update-p agent new resources now)))))

(test gateway-node-update-skips-network-but-expiry-and-failure-force-full-work
  (with-temporary-store (source path)
    (gwc-seed source)
    (let* ((agent (gr8s.agent::make-node-runtime (merge-pathnames "agent/" path) (make-fake-runtime) nil))
           (network-calls 0) (fail nil)
           (original (symbol-function 'gr8s.agent::apply-node-runtime-network)))
      (setf (gr8s.agent::node-runtime-state agent) :running
            (gr8s.agent::node-runtime-gateway-controller agent)
            (gr8s.controllers::make-gateway-controller
             (gr8s.agent::node-runtime-store agent)
             :start-fn (lambda (&rest args) (declare (ignore args)) :listener)
             :swap-fn (lambda (&rest args) (declare (ignore args)))
             :stop-fn (lambda (&rest args) (declare (ignore args)))))
      (labels ((snapshot (revision)
                 (let ((result (desired-snapshot-for-test)))
                   (setf (slot-value result 'gr8s.node.v1::revision) revision
                         (slot-value result 'gr8s.node.v1::service-discovery-objects-json)
                         (gr8s.kubelet::service-discovery-projection source)) result))
               (change-route (host)
                 (gr8s.resources::update-core-resource
                  source "httproutes" "default" "app"
                  (lambda (object) (setf (gethash "hostnames" (gethash "spec" object)) (vector host)) object))))
        (unwind-protect
             (progn
               (setf (symbol-function 'gr8s.agent::apply-node-runtime-network)
                     (lambda (&rest args)
                       (incf network-calls)
                       (when fail (error "injected network failure"))
                       (apply original args)))
               (gr8s.agent::reconcile-node-snapshot agent (snapshot 1))
               (is (= 1 network-calls))
               (change-route "two.example.com")
               (gr8s.agent::reconcile-node-snapshot agent (snapshot 2))
               (is (= 1 network-calls))
               (setf (gr8s.agent::node-runtime-full-snapshot-applied-at agent)
                     (- (get-internal-real-time) (* 2 internal-time-units-per-second)))
               (change-route "three.example.com")
               (setf fail t)
               (signals error (gr8s.agent::reconcile-node-snapshot agent (snapshot 3)))
               (is (null (gr8s.agent::node-runtime-applied-snapshot agent)))
               (setf fail nil
                     (gr8s.agent::node-runtime-full-snapshot-applied-at agent) (get-internal-real-time))
               (gr8s.agent::reconcile-node-snapshot agent (snapshot 3))
               (is (= 3 network-calls)))
          (setf (symbol-function 'gr8s.agent::apply-node-runtime-network) original))))))

(test gateway-node-guard-requires-exact-cached-pod-observations
  (with-temporary-store (store path)
    (values path)
    (let* ((pod (create-pod store (parse-pod *valid-pod-json*)))
           (old (desired-snapshot-for-test pod)) (new (desired-snapshot-for-test pod))
           (now (get-internal-real-time)) (resources (make-hash-table :test 'equal))
           (agent (gr8s.agent::%make-node-runtime :state :running
                   :applied-snapshot old :full-snapshot-applied-at now
                   :discovery-resources (make-hash-table :test 'equal)))
           (uid (gr8s.model::pod-uid pod)) (version (gr8s.model::pod-resource-version pod)))
      (setf (gethash '("httproutes" "default" "new") resources)
            (gr8s.resources::core-object "spec" (gr8s.resources::core-object)))
      (is (not (gr8s.agent::node-gateway-update-p agent new resources now)))
      (setf (gethash uid (gr8s.agent::node-runtime-assigned-versions agent)) version
            (gethash uid (gr8s.agent::node-runtime-observed-statuses agent))
            (make-instance 'gr8s.node.v1::pod-observed-status :uid uid :resource-version version))
      (is (gr8s.agent::node-gateway-update-p agent new resources now))
      (setf (slot-value (gethash uid (gr8s.agent::node-runtime-observed-statuses agent))
                       'gr8s.node.v1::resource-version) "wrong-version")
      (is (not (gr8s.agent::node-gateway-update-p agent new resources now))))))

(test failed-dataplane-convergence-does-not-authorize-the-gateway-shortcut
  (with-temporary-store (store path)
    (values store)
    (let* ((agent (gr8s.agent::make-node-runtime (merge-pathnames "agent/" path) (make-fake-runtime) nil))
           (original (symbol-function 'gr8s.agent::converge-node-port-forwarders))
           (fail t) (calls 0))
      (setf (gr8s.agent::node-runtime-state agent) :running)
      (unwind-protect
           (progn
             (setf (symbol-function 'gr8s.agent::converge-node-port-forwarders)
                   (lambda (&rest args)
                     (incf calls)
                     (when fail (error "injected node-port convergence failure"))
                     (apply original args)))
             (let ((*error-output* (make-string-output-stream)))
               (gr8s.agent::reconcile-node-snapshot agent (desired-snapshot-for-test)))
             (is (null (gr8s.agent::node-runtime-applied-snapshot agent)))
             (setf fail nil)
             (gr8s.agent::reconcile-node-snapshot agent (desired-snapshot-for-test))
             (is (= 2 calls))
             (is (gr8s.agent::node-runtime-applied-snapshot agent)))
        (setf (symbol-function 'gr8s.agent::converge-node-port-forwarders) original)))))

(test gateway-shortcut-still-checks-service-selection-before-acknowledgement
  (with-temporary-store (store path)
    (values store)
    (let* ((agent (gr8s.agent::make-node-runtime (merge-pathnames "agent/" path) (make-fake-runtime) nil))
           (original (symbol-function 'gr8s.agent::ensure-node-snapshot-service-selection-ready))
           (fail nil) (calls 0))
      (setf (gr8s.agent::node-runtime-state agent) :running)
      (unwind-protect
           (progn
             (setf (symbol-function 'gr8s.agent::ensure-node-snapshot-service-selection-ready)
                   (lambda (&rest args)
                     (incf calls)
                     (when fail (error 'gr8s.agent::node-snapshot-incomplete :message "selection not ready"))
                     (apply original args)))
             (gr8s.agent::reconcile-node-snapshot agent (desired-snapshot-for-test))
             ;; A Gateway withdrawal makes the next snapshot eligible for the shortcut.
             (setf (gethash '("httproutes" "default" "removed")
                            (gr8s.agent::node-runtime-discovery-resources agent))
                   (gr8s.resources::core-object "spec" (gr8s.resources::core-object)))
             (is (gr8s.agent::node-gateway-update-p
                  agent (desired-snapshot-for-test) (make-hash-table :test 'equal)))
             (setf fail t)
             (signals gr8s.agent::node-snapshot-incomplete
               (gr8s.agent::reconcile-node-snapshot agent (desired-snapshot-for-test)))
             (is (= 2 calls))
             (is (null (gr8s.agent::node-runtime-applied-snapshot agent))))
        (setf (symbol-function 'gr8s.agent::ensure-node-snapshot-service-selection-ready) original)))))
