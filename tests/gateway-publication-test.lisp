;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0

(in-package #:gr8s/tests)
(def-suite gateway-publication :in gr8s)
(in-suite gateway-publication)

(defun gateway-publication-fixture (store &key (capable t) (observe t))
  (gr8s.controllers::register-node store (gr8s.model::make-node-record
                                        :id "worker" :name "worker" :pod-cidr "10.88.1.0/24"
                                        :underlay-address "192.0.2.10"))
  (let* ((server (gr8s.apiserver::%make-node-grpc-server
                  :store store :cluster-pod-cidr "10.88.0.0/16" :cluster-pod-cidrs '("10.88.0.0/16")))
         (runtime (gr8s.controllers::make-control-plane-runtime store server))
         (session (gr8s.apiserver::make-node-agent-session nil))
         (snapshot (gr8s.controllers::node-desired-state-snapshot store "worker")))
    (setf (slot-value snapshot 'gr8s.node.v1::revision) 7
          (gr8s.apiserver::node-agent-session-gateway-deltas-p session) capable
          (gr8s.apiserver::node-agent-session-deltas-p session) t
          (gr8s.apiserver::node-agent-session-delivered session) snapshot
          (gethash "worker" (gr8s.apiserver::node-grpc-server-sessions server)) session
          (gethash "worker" (gr8s.apiserver::node-grpc-server-snapshots server)) snapshot
          (gethash "worker" (gr8s.apiserver::node-grpc-server-revisions server)) 7
          (gethash "worker" (gr8s.apiserver::node-grpc-server-acknowledged-revisions server)) 7)
    (gr8s.apiserver::install-node-gateway-baseline session snapshot)
    (when observe
      (gr8s.resources::add-core-resource-change-observer
       store (lambda () (gr8s.controllers::note-gateway-resource-changes runtime gr8s.resources::*core-resource-changes*))))
    (values runtime server session)))

(defun change-published-route-host (store host)
  (gr8s.resources::update-core-resource
   store "httproutes" "default" "app"
   (lambda (object) (setf (gethash "hostnames" (gethash "spec" object)) (vector host)) object)))

(test one-route-publication-does-not-rebuild-discovery-even-with-three-thousand-routes
  (with-temporary-store (store path)
    (values path)
    (gwc-seed store)
    ;; Populate a large already validated desired set in one fixture transaction.
    (let ((template (gr8s.resources::get-core-resource store "httproutes" "default" "app")))
      (dotimes (index 2999)
        (let* ((name (format nil "scale-~D" index))
               (route (gr8s.resources::copy-core-object template))
               (metadata (gethash "metadata" route)))
          (setf (gethash "name" metadata) name (gethash "uid" metadata) name
                (gethash (list "httproutes" "default" name) (gr8s.store::pod-store-resources store)) route))))
    (multiple-value-bind (runtime server session) (gateway-publication-fixture store)
      (let ((send (symbol-function 'ag-grpc:stream-send))
            (project (symbol-function 'gr8s.kubelet::service-discovery-projection))
            (sent nil))
        (unwind-protect
             (progn
               (setf (symbol-function 'ag-grpc:stream-send)
                     (lambda (stream envelope) (declare (ignore stream)) (push envelope sent))
                     (symbol-function 'gr8s.kubelet::service-discovery-projection)
                     (lambda (&rest args) (declare (ignore args)) (error "Gateway edit rebuilt complete discovery")))
               (change-published-route-host store "changed.example.com")
               (gr8s.controllers::publish-gateway-resource-changes runtime)
               (is (= 1 (length sent)))
               (is (eq :gateway-config (slot-value (first sent) 'gr8s.node.v1::payload-case)))
               (let ((update (slot-value (first sent) 'gr8s.node.v1::gateway-config)))
                 (is (= 1 (length (slot-value update 'gr8s.node.v1::changes))))
                 (is (equal "app" (slot-value (first (slot-value update 'gr8s.node.v1::changes)) 'gr8s.node.v1::name))))
               (is (< (length (ag-proto:serialize-to-bytes (first sent))) 8192))
               (is (= 7 (gethash "worker" (gr8s.apiserver::node-grpc-server-revisions server))))
               (is (= 7 (gr8s.apiserver::node-session-acknowledged-revision server "worker")))
               (is (= 1 (gr8s.apiserver::node-agent-session-gateway-revision session))))
          (setf (symbol-function 'ag-grpc:stream-send) send
                (symbol-function 'gr8s.kubelet::service-discovery-projection) project))))))

(test legacy-agents-and-changed-node-dependencies-require-full-publication
  (dolist (capable '(nil t))
    (with-temporary-store (store path)
      (values path)
      (gwc-seed store)
      (multiple-value-bind (runtime server session) (gateway-publication-fixture store :capable capable)
        (declare (ignore server session))
        (let ((publish (symbol-function 'gr8s.controllers::publish-node-snapshot))
              (send (symbol-function 'ag-grpc:stream-send)) (full 0) (sent nil))
          (unwind-protect
               (progn
                 (setf (symbol-function 'gr8s.controllers::publish-node-snapshot)
                       (lambda (&rest args) (declare (ignore args)) (incf full) 8)
                       (symbol-function 'ag-grpc:stream-send)
                       (lambda (stream envelope) (declare (ignore stream)) (push envelope sent)))
                 (when capable
                   (gr8s.resources::create-core-resource
                    store "services"
                    (com.inuoe.jzon:parse "{\"apiVersion\":\"v1\",\"kind\":\"Service\",\"metadata\":{\"name\":\"dep\"},\"spec\":{\"ports\":[{\"port\":80}]}}") "default"))
                 (change-published-route-host store "changed.example.com")
                 (gr8s.controllers::publish-gateway-resource-changes runtime)
                 (is (= 1 full))
                 (is (null sent)))
            (setf (symbol-function 'gr8s.controllers::publish-node-snapshot) publish
                  (symbol-function 'ag-grpc:stream-send) send)))))))

(test full-repair-keeps-dirty-writes-that-arrive-after-its-capture-watermark
  (with-temporary-store (store path)
    (values path)
    (gwc-seed store)
    (multiple-value-bind (runtime server session) (gateway-publication-fixture store)
      (declare (ignore server session))
      (change-published-route-host store "before.example.com")
      (let ((publish (symbol-function 'gr8s.controllers::publish-node-snapshot)))
        (unwind-protect
             (progn
               (setf (symbol-function 'gr8s.controllers::publish-node-snapshot)
                     (lambda (&rest args) (declare (ignore args))
                       (change-published-route-host store "after.example.com") 8))
               (gr8s.controllers::publish-service-discovery-snapshots runtime)
               (is (= 1 (hash-table-count (gr8s.controllers::control-plane-runtime-gateway-dirty runtime))))
               (is (> (gethash '("httproutes" "default" "app")
                               (gr8s.controllers::control-plane-runtime-gateway-dirty runtime)) 1)))
          (setf (symbol-function 'gr8s.controllers::publish-node-snapshot) publish))))))

(test a-new-tls-reference-travels-with-its-certificate-in-one-gateway-batch
  (with-temporary-store (store path)
    (values path)
    (gwc-seed store)
    (gr8s.resources::create-core-resource
     store "secrets"
     (com.inuoe.jzon:parse "{\"apiVersion\":\"v1\",\"kind\":\"Secret\",\"metadata\":{\"name\":\"edge-cert\"},\"type\":\"kubernetes.io/tls\",\"data\":{\"tls.crt\":\"Y2VydA==\",\"tls.key\":\"a2V5\"}}") "default")
    (multiple-value-bind (runtime server session) (gateway-publication-fixture store)
      (declare (ignore server session))
      (let ((send (symbol-function 'ag-grpc:stream-send)) (sent nil))
        (unwind-protect
             (progn
               (setf (symbol-function 'ag-grpc:stream-send)
                     (lambda (stream envelope) (declare (ignore stream)) (push envelope sent)))
               (gr8s.resources::update-core-resource
                store "gateways" "default" "web"
                (lambda (object)
                  (let ((listener (aref (gethash "listeners" (gethash "spec" object)) 0)))
                    (setf (gethash "protocol" listener) "HTTPS"
                          (gethash "tls" listener) (gr8s.resources::core-object
                                                   "mode" "Terminate" "certificateRefs"
                                                   (vector (gr8s.resources::core-object "name" "edge-cert"))))) object))
               (gr8s.controllers::publish-gateway-resource-changes runtime)
               (is (= 1 (length sent)))
               (let ((changes (slot-value (slot-value (first sent) 'gr8s.node.v1::gateway-config) 'gr8s.node.v1::changes)))
                 (is (= 2 (length changes)))
                 (is (member "gateways" changes :test #'equal :key (lambda (change) (slot-value change 'gr8s.node.v1::resource))))
                 (is (member "secrets" changes :test #'equal :key (lambda (change) (slot-value change 'gr8s.node.v1::resource))))))
          (setf (symbol-function 'ag-grpc:stream-send) send))))))

(test an-unusable-certificate-reference-does-not-poison-full-repair
  (with-temporary-store (store path)
    (values path)
    (gwc-seed store)
    (gr8s.resources::create-core-resource
     store "secrets" (com.inuoe.jzon:parse "{\"apiVersion\":\"v1\",\"kind\":\"Secret\",\"metadata\":{\"name\":\"wrong-type\"},\"type\":\"Opaque\"}") "default")
    (gr8s.resources::update-core-resource
     store "gateways" "default" "web"
     (lambda (object)
       (let ((listener (aref (gethash "listeners" (gethash "spec" object)) 0)))
         (setf (gethash "protocol" listener) "HTTPS"
               (gethash "tls" listener) (gr8s.resources::core-object "mode" "Terminate" "certificateRefs"
                                                                   (vector (gr8s.resources::core-object "name" "wrong-type"))))) object))
    (let ((objects (mapcar (lambda (bytes) (com.inuoe.jzon:parse (trivial-utf-8:utf-8-bytes-to-string bytes)))
                           (gr8s.kubelet::service-discovery-projection store))))
      (is (find "Gateway" objects :test #'equal :key (lambda (object) (gethash "kind" object))))
      (is (not (find "Secret" objects :test #'equal :key (lambda (object) (gethash "kind" object))))))))

(test committed-resource-wakeups-publish-gateway-deltas-through-the-production-worker-hook
  (with-temporary-store (store path)
    (values path)
    (gwc-seed store)
    (multiple-value-bind (runtime server session) (gateway-publication-fixture store :observe nil)
      (declare (ignore session))
      (let ((send (symbol-function 'ag-grpc:stream-send)) (sent nil) (worker nil))
        (unwind-protect
             (progn
               (setf (symbol-function 'ag-grpc:stream-send)
                     (lambda (stream envelope) (declare (ignore stream)) (push envelope sent)))
               (setf worker
                     (gr8s.server::start-reconciliation-worker
                      (make-reconciler store runtime) :interval 5 :watch-resources t
                      :resource-change-handler
                      (lambda (changes) (gr8s.controllers::note-gateway-resource-changes runtime changes))
                      :before-reconcile (lambda () (gr8s.controllers::publish-service-discovery-snapshots runtime))
                      :gateway-reconcile (lambda () (gr8s.controllers::publish-gateway-resource-changes runtime))))
               (is (poll-until (lambda () (plusp (gr8s.server::reconciliation-worker-metrics-completed worker))) :timeout 5))
               (let ((node-revision (gethash "worker" (gr8s.apiserver::node-grpc-server-revisions server))))
                 (setf sent nil)
                 (change-published-route-host store "through-worker.example.com")
                 (is (poll-until (lambda () (find :gateway-config sent :key (lambda (envelope) (slot-value envelope 'gr8s.node.v1::payload-case)))) :timeout 5))
                 (is (= node-revision (gethash "worker" (gr8s.apiserver::node-grpc-server-revisions server))))
                 (is (= 1 (length sent)))))
          (when worker (gr8s.server::stop-reconciliation-worker worker))
          (setf (symbol-function 'ag-grpc:stream-send) send))))))

(test a-failed-full-send-evicts-the-session-so-reconnect-cannot-skip-repair
  (with-temporary-store (store path)
    (values path)
    (gwc-seed store)
    (multiple-value-bind (runtime server session) (gateway-publication-fixture store)
      (declare (ignore server))
      (let ((send (symbol-function 'ag-grpc:stream-send)))
        (unwind-protect
             (progn
               (setf (symbol-function 'ag-grpc:stream-send)
                     (lambda (&rest args) (declare (ignore args)) (error "injected full send failure")))
               (gr8s.controllers::publish-node-snapshot runtime "worker")
               (is (gr8s.apiserver::node-agent-session-evicted-p session)))
          (setf (symbol-function 'ag-grpc:stream-send) send))))))

(test committed-route-deletion-publishes-a-keyed-delete-without-full-repair
  (with-temporary-store (store path)
    (values path)
    (gwc-seed store)
    (multiple-value-bind (runtime server session) (gateway-publication-fixture store)
      (declare (ignore server session))
      (let ((send (symbol-function 'ag-grpc:stream-send))
            (project (symbol-function 'gr8s.kubelet::service-discovery-projection))
            (sent nil))
        (unwind-protect
             (progn
               (setf (symbol-function 'ag-grpc:stream-send)
                     (lambda (stream envelope) (declare (ignore stream)) (push envelope sent))
                     (symbol-function 'gr8s.kubelet::service-discovery-projection)
                     (lambda (&rest args) (declare (ignore args)) (error "Deletion rebuilt full discovery")))
               (gr8s.resources::delete-core-resource store "httproutes" "default" "app")
               (is (= 1 (hash-table-count (gr8s.controllers::control-plane-runtime-gateway-dirty runtime))))
               (gr8s.controllers::publish-gateway-resource-changes runtime)
               (is (= 1 (length sent)))
               (when sent
                 (is (eq :gateway-config (slot-value (first sent) 'gr8s.node.v1::payload-case)))
                 (let* ((update (slot-value (first sent) 'gr8s.node.v1::gateway-config))
                        (change (first (slot-value update 'gr8s.node.v1::changes))))
                   (is (= 1 (length (slot-value update 'gr8s.node.v1::changes))))
                   (is (slot-value change 'gr8s.node.v1::deleted))
                   (is (equal "app" (slot-value change 'gr8s.node.v1::name))))))
          (setf (symbol-function 'ag-grpc:stream-send) send
                (symbol-function 'gr8s.kubelet::service-discovery-projection) project))))))

(test route-count-retains-captured-index-through-a-committed-edit
  (with-temporary-store (store path)
    (values path)
    (gwc-seed store)
    (let ((second (gr8s.resources::get-core-resource store "httproutes" "default" "app")))
      (dolist (field '("resourceVersion" "uid" "creationTimestamp" "generation" "managedFields"))
        (remhash field (gethash "metadata" second)))
      (setf (gethash "name" (gethash "metadata" second)) "app-two")
      (gr8s.resources::create-core-resource store "httproutes" second "default"))
    (let* ((gateway (gr8s.resources::get-core-resource store "gateways" "default" "web"))
           (listener (aref (gethash "listeners" (gethash "spec" gateway)) 0))
           (kinds (vector (gr8s.resources::core-object "kind" "HTTPRoute")))
           (allows (symbol-function 'gr8s.apiserver::gateway-listener-allows-namespace-p))
           (changed nil))
      (unwind-protect
           (progn
             (setf (symbol-function 'gr8s.apiserver::gateway-listener-allows-namespace-p)
                   (lambda (current gateway listener namespace)
                     (when (and (eq current store) (not changed))
                       (setf changed t)
                       (gr8s.resources::update-core-resource
                        store "httproutes" "default" "app-two"
                        (lambda (object)
                          (setf (gethash "parentRefs" (gethash "spec" object))
                                (vector (gr8s.resources::core-object "name" "unmanaged")))
                          object)))
                     (funcall allows current gateway listener namespace)))
             (is (= 2 (gr8s.apiserver::gateway-listener-attached-routes store gateway listener kinds)))
             (is (= 1 (gr8s.apiserver::gateway-listener-attached-routes store gateway listener kinds))))
        (setf (symbol-function 'gr8s.apiserver::gateway-listener-allows-namespace-p) allows)))))
