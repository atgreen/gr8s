;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
(in-package #:gr8s/tests)
(def-suite gateway-fast-path :in gr8s)
(in-suite gateway-fast-path)

(test failed-gateway-listener-retries-without-another-desired-snapshot
  (with-temporary-store (source path)
    (gwc-seed source)
    (let* ((agent (gr8s.agent::make-node-runtime (merge-pathnames "agent/" path) (make-fake-runtime) nil))
           (snapshot (desired-snapshot-for-test))
           (identity (gr8s.resources::core-object "lastAppliedRevision" 0))
           (identity-path (merge-pathnames "identity.json" path))
           (lock (bt:make-lock "listener retry test"))
           (changed (bt:make-condition-variable))
           (starts 0) (release nil) (sent nil) (closed nil) (worker nil)
           (send (symbol-function 'gr8s.agent::send-agent-session-envelope)))
      (setf (slot-value snapshot 'gr8s.node.v1::service-discovery-objects-json)
            (gr8s.kubelet::service-discovery-projection source)
            (gr8s.agent::node-runtime-state agent) :running
            (gr8s.agent::node-runtime-gateway-controller agent)
            (gr8s.controllers::make-gateway-controller
             (gr8s.agent::node-runtime-store agent)
             :start-fn (lambda (&rest arguments)
                         (declare (ignore arguments))
                         (bt:with-lock-held (lock)
                           (incf starts)
                           (when (= starts 1) (error "transient listener bind failure"))
                           ;; Hold the retry before activation to inspect the failed attempt's ACK state.
                           (loop until release do (bt:condition-wait changed lock)))
                         :listener)
             :swap-fn (lambda (&rest arguments) (declare (ignore arguments)))
             :stop-fn (lambda (&rest arguments) (declare (ignore arguments)))))
      (unwind-protect
           (progn
             (setf (symbol-function 'gr8s.agent::send-agent-session-envelope)
                   (lambda (session variant payload)
                     (declare (ignore session))
                     (bt:with-lock-held (lock) (push (cons variant payload) sent))))
             (setf worker
                   (gr8s.agent::start-agent-snapshot-worker
                    (lambda (update replay)
                      (gr8s.agent::apply-node-snapshot-and-respond
                       nil identity identity-path update
                       (lambda (value) (gr8s.agent::reconcile-node-snapshot agent value)) :replay replay))
                    (lambda () (bt:with-lock-held (lock) (setf closed t)))))
             ;; Queue once: an unchanged periodic publication may be deduplicated by the server.
             (gr8s.agent::queue-agent-snapshot-work worker snapshot)
             (is (poll-until (lambda () (bt:with-lock-held (lock) (or sent (> starts 1)))) :timeout 5))
             (is (= 0 (gethash "lastAppliedRevision" identity)))
             (is (not (probe-file identity-path)))
             (bt:with-lock-held (lock)
               (is (null sent))
               (setf release t)
               (bt:condition-notify changed))
             (is (poll-until (lambda () (bt:with-lock-held (lock) (and (= starts 2) sent))) :timeout 5))
             (is (gr8s.agent::node-runtime-gateway-synchronized-p agent))
             (is (= 1 (gethash "lastAppliedRevision" identity)))
             (bt:with-lock-held (lock)
               (is (not closed))
               (is (= 1 (length sent)))
               (when sent (is (eq :snapshot-ack (caar sent))))))
        (bt:with-lock-held (lock) (setf release t) (bt:condition-notify changed))
        (when worker (gr8s.agent::stop-agent-snapshot-worker worker))
        (setf (symbol-function 'gr8s.agent::send-agent-session-envelope) send)))))

(test failed-gateway-swap-on-shortcut-retains-a-full-retry
  (with-temporary-store (source path)
    (gwc-seed source)
    (let* ((agent (gr8s.agent::make-node-runtime (merge-pathnames "agent/" path) (make-fake-runtime) nil))
           (fail nil) (swaps 0) (starts 0) (stops 0))
      (setf (gr8s.agent::node-runtime-state agent) :running
            (gr8s.agent::node-runtime-gateway-controller agent)
            (gr8s.controllers::make-gateway-controller
             (gr8s.agent::node-runtime-store agent)
             :start-fn (lambda (&rest arguments) (declare (ignore arguments)) (incf starts) :listener)
             :swap-fn (lambda (&rest arguments)
                        (declare (ignore arguments))
                        (incf swaps)
                        (when fail (error "transient dispatcher swap failure")))
             :stop-fn (lambda (&rest arguments) (declare (ignore arguments)) (incf stops))))
      (labels ((snapshot (revision)
                 (let ((result (desired-snapshot-for-test)))
                   (setf (slot-value result 'gr8s.node.v1::revision) revision
                         (slot-value result 'gr8s.node.v1::service-discovery-objects-json)
                         (gr8s.kubelet::service-discovery-projection source))
                   result)))
        (gr8s.agent::reconcile-node-snapshot agent (snapshot 1))
        (gr8s.resources::update-core-resource
         source "httproutes" "default" "app"
         (lambda (object)
           (setf (gethash "hostnames" (gethash "spec" object)) #("retry.example.com")) object))
        (let* ((next (snapshot 2))
               (resources (gr8s.kubelet::decode-service-discovery-projection
                           (slot-value next 'gr8s.node.v1::service-discovery-objects-json))))
          (setf (gr8s.agent::node-runtime-full-snapshot-applied-at agent) (get-internal-real-time)
                fail t)
          (is (gr8s.agent::node-gateway-update-p agent next resources))
          (signals gr8s.agent::node-snapshot-incomplete
            (gr8s.agent::reconcile-node-snapshot agent next))
          (is (null (gr8s.agent::node-runtime-applied-snapshot agent)))
          (is (not (gr8s.agent::node-runtime-gateway-synchronized-p agent)))
          (is (= 1 swaps))
          (is (= 1 stops))
          (setf fail nil)
          (gr8s.agent::reconcile-node-snapshot agent next)
          ;; Failed publication closes the old listener; recovery starts a new one.
          (is (= 2 starts))
          (is (eq next (gr8s.agent::node-runtime-applied-snapshot agent)))
          (is (gr8s.agent::node-runtime-gateway-synchronized-p agent)))))))

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

(test discovery-repair-reuses-unchanged-encoded-rows-across-passes
  (with-temporary-store (store path)
    (values path)
    (gwc-seed store)
    (let* ((before (gr8s.kubelet::service-discovery-projection store))
           (again (gr8s.kubelet::service-discovery-projection store)))
      (is (every #'eq before again))
      (gr8s.resources::update-core-resource
       store "httproutes" "default" "app"
       (lambda (object)
         (setf (gethash "hostnames" (gethash "spec" object)) #("changed.example.com")) object))
      (let ((after (gr8s.kubelet::service-discovery-projection store)))
        (is (= (length before) (length after)))
        (is (= 1 (count nil (mapcar #'eq before after))))
        (is (not (equalp before after)))
        ;; Cold encoding of the same captured view is the byte-for-byte reference.
        (is (equalp after (gr8s.kubelet::build-service-discovery-projection
                           (gr8s.kubelet::capture-service-discovery-store store))))))))

(test discovery-encoding-cache-releases-deleted-rows-and-reload-payload
  (with-temporary-store (store path)
    (values path)
    (gwc-seed store)
    (let ((old (gethash '("httproutes" "default" "app") (gr8s.store::pod-store-resources store))))
      (gr8s.kubelet::service-discovery-projection store)
      (is (gethash old (gr8s.store::pod-store-discovery-encoding-cache store)))
      (gr8s.resources::delete-core-resource store "httproutes" "default" "app")
      (let ((projection (gr8s.kubelet::service-discovery-projection store)))
        (is (not (gethash old (gr8s.store::pod-store-discovery-encoding-cache store))))
        (is (= (length projection) (hash-table-count (gr8s.store::pod-store-discovery-encoding-cache store)))))
      (gr8s.store::reset-store-application store)
      (is (null (gr8s.store::pod-store-discovery-encoding-cache store))))))

(test discovery-encoding-rechecks-tls-rotation-and-reference-removal
  (with-temporary-store (store path)
    (values path)
    (seed-ingress-controller-test store)
    (labels ((secret ()
               (gethash '("secrets" "default" "web-tls")
                        (gr8s.kubelet::decode-service-discovery-projection
                         (gr8s.kubelet::service-discovery-projection store)))))
      (is (equal "Y2VydA==" (gethash "tls.crt" (gethash "data" (secret)))))
      (gr8s.resources::update-core-resource
       store "secrets" "default" "web-tls"
       (lambda (object) (setf (gethash "tls.crt" (gethash "data" object)) "bmV3LWNlcnQ=") object))
      (is (equal "bmV3LWNlcnQ=" (gethash "tls.crt" (gethash "data" (secret)))))
      (gr8s.resources::update-core-resource
       store "ingresses" "default" "web"
       (lambda (object) (remhash "tls" (gethash "spec" object)) object))
      (is (null (secret)))
      (is (not (loop for object being the hash-keys of (gr8s.store::pod-store-discovery-encoding-cache store)
                     thereis (equal "Secret" (gethash "kind" object))))))))

(test discovery-encoding-resolves-policy-peers-after-pod-address-change
  (with-temporary-store (store path)
    (values path)
    (gr8s.resources::create-core-resource
     store "namespaces"
     (gr8s.resources::core-object "metadata"
                                 (gr8s.resources::core-object "name" "default" "labels"
                                                             (gr8s.resources::core-object "env" "allowed"))) nil)
    (let ((pod (create-pod store (parse-pod *valid-pod-json*))))
      (gr8s.resources::create-core-resource
       store "networkpolicies"
       (npr-policy "default" "{\"podSelector\":{},\"ingress\":[{\"from\":[{\"podSelector\":{},\"namespaceSelector\":{\"matchLabels\":{\"env\":\"allowed\"}}}]}]}") "default")
      (labels ((peers ()
                 (let* ((resources (gr8s.kubelet::decode-service-discovery-projection
                                    (gr8s.kubelet::service-discovery-projection store)))
                        (policy (gethash '("networkpolicies" "default" "p") resources))
                        (rules (gethash "ingress" (gethash "spec" policy))))
                   (when (plusp (length rules)) (npr-peers (aref rules 0) "from")))))
        (is (null (peers)))
        ;; Policy identity and spec stay fixed; only a captured Pod observation changes.
        (setf (gethash (pod-uid pod) (gr8s.store::pod-store-pod-observed-statuses store))
              (gr8s.resources::core-object "podIP" "10.80.0.7" "phase" "Running"))
        (is (equal '("10.80.0.7/32") (peers)))
        (setf (gethash (pod-uid pod) (gr8s.store::pod-store-pod-observed-statuses store))
              (gr8s.resources::core-object "podIP" "10.80.0.8" "phase" "Running"))
        (is (equal '("10.80.0.8/32") (peers)))
        (gr8s.resources::update-core-resource
         store "namespaces" nil "default"
         (lambda (object)
           (setf (gethash "env" (gethash "labels" (gethash "metadata" object))) "blocked") object))
        (is (null (peers)))))))

(test discovery-concurrent-captures-keep-their-own-immutable-rows
  (with-temporary-store (store path)
    (values path)
    (gwc-seed store)
    (gr8s.kubelet::service-discovery-projection store)
    (let ((original (symbol-function 'gr8s.kubelet::build-service-discovery-projection))
          (lock (bt:make-lock "projection capture test")) (changed (bt:make-condition-variable))
          (pause-next t) (waiting nil) (release nil) (thread nil) (old-result nil) (failure nil))
      (unwind-protect
           (progn
             (setf (symbol-function 'gr8s.kubelet::build-service-discovery-projection)
                   (lambda (&rest arguments)
                     (bt:with-lock-held (lock)
                       (when pause-next
                         (setf pause-next nil waiting t)
                         (loop until release do (bt:condition-wait changed lock))))
                     (apply original arguments)))
             (setf thread
                   (bt:make-thread (lambda ()
                                     (handler-case
                                         (setf old-result (gr8s.kubelet::service-discovery-projection store))
                                       (error (condition) (setf failure condition))))))
             (is (poll-until (lambda () (bt:with-lock-held (lock) waiting)) :timeout 5))
             (gr8s.resources::update-core-resource
              store "httproutes" "default" "app"
              (lambda (object) (setf (gethash "hostnames" (gethash "spec" object)) #("concurrent.example.com")) object))
             (let ((new-result (gr8s.kubelet::service-discovery-projection store)))
               (bt:with-lock-held (lock) (setf release t) (bt:condition-notify changed))
               (bt:join-thread thread)
               (is (null failure))
               (is (not (equalp old-result new-result)))
               (is (every #'eq new-result (gr8s.kubelet::service-discovery-projection store)))
               (is (equalp new-result (funcall original (gr8s.kubelet::capture-service-discovery-store store))))))
        (bt:with-lock-held (lock) (setf release t) (bt:condition-notify changed))
        (when (and thread (bt:thread-alive-p thread)) (bt:join-thread thread))
        (setf (symbol-function 'gr8s.kubelet::build-service-discovery-projection) original)))))

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
