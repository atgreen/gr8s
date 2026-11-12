;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
(in-package #:gr8s/tests)
(in-suite gr8s)

(defun translation-fixture-pod (store name &optional (node "worker-a"))
  (let ((object (com.inuoe.jzon:parse *valid-pod-json*)))
    (setf (gethash "name" (gethash "metadata" object)) name
          (gethash "nodeName" (gethash "spec" object)) node)
    (create-pod store (parse-pod (com.inuoe.jzon:stringify object)))))

(defun translation-fixture-status (&optional (primary "10.88.1.2") (alias "10.88.1.8"))
  (let ((status (gr8s.resources::core-object "phase" "Running" "podIP" primary)))
    (when alias
      (setf (gethash "gr8sServiceTranslation" status)
            (gr8s.resources::core-object "podIP" primary "address" alias
                              "sandboxID" "sandbox-a" "interfaceName" "eth0"
                              "nodeID" "worker-a"
                              "nodeName" "forged-node" "podUID" "forged-uid")))
    status))

(defun translation-fixture-server (store)
  (dolist (entry '(("worker-a" "10.88.1.0/24") ("worker-b" "10.88.2.0/24")))
    (unless (ignore-errors (gr8s.controllers::get-node store (first entry)))
      (gr8s.controllers::register-node store (gr8s.model::make-node-record :id (first entry) :name (first entry)
                                                      :pod-cidr (second entry)))))
  (gr8s.apiserver::%make-node-grpc-server :store store :port 0 :cluster-pod-cidr "10.88.0.0/16"
                               :cluster-pod-cidrs '("10.88.0.0/16")))

(defun translation-fixture-report (server pod status &key (node "worker-a") uid revision)
  (let* ((observation (gr8s.agent::pod-observed-status-message pod status))
         (message (gr8s.protocol::make-agent-envelope
                   :status (make-instance 'gr8s.node.v1::node-status :pods (list observation)))))
    (when uid (setf (slot-value observation 'gr8s.node.v1::uid) uid))
    (when revision (setf (slot-value observation 'gr8s.node.v1::resource-version) revision))
    ;; Use the actual decoder/dispatch path; NODE is the already authenticated peer.
    (gr8s.apiserver::handle-node-agent-envelope
     server node (ag-proto:deserialize-from-bytes 'gr8s.node.v1::agent-envelope
                                                 (ag-proto:serialize-to-bytes message)))))

(test translation-identities-survive-restart-and-replication-without-publication
  (with-temporary-store (store path)
    (let* ((server (translation-fixture-server store))
           (pod (translation-fixture-pod store "translation-client")))
      (translation-fixture-report server pod (translation-fixture-status))
      (let* ((observed (gr8s.controllers::pod-observed-status store pod))
             (identity (gethash "gr8sServiceTranslation" observed)))
        (is (equal "10.88.1.8" (gethash "address" identity)))
        (is (equal (pod-uid pod) (gethash "podUID" identity)))
        (is (equal "worker-a" (gethash "nodeName" identity)))
        (is-false (gethash "gr8sServiceTranslation"
                          (gethash "status" (gr8s.apiserver::pod-response-object pod observed))))
        (is-false (gethash "gr8sServiceTranslation"
                          (gethash "status" (gr8s.store::pod-published-view store pod))))
        (is (gethash "gr8sServiceTranslation" (gr8s.controllers::pod-observed-status store pod))))
      (let* ((reopened (gr8s.store::open-store path))
             (network (gr8s.apiserver::assigned-node-network (translation-fixture-server reopened) "worker-b"))
             (wire (ag-proto:deserialize-from-bytes 'gr8s.node.v1::node-network-config
                                                   (ag-proto:serialize-to-bytes network)))
             (records (slot-value wire 'gr8s.node.v1::service-translations))
             (object (gr8s.agent::node-network-object wire)))
        (is (= 1 (length records)))
        (is (equal (pod-uid pod) (slot-value (first records) 'gr8s.node.v1::pod-uid)))
        (is (equal "sandbox-a" (slot-value (first records) 'gr8s.node.v1::sandbox-id)))
        (is (equal "10.88.1.8" (gethash "address" (aref (gethash "serviceTranslations" object) 0))))
        (is (eq object (gr8s.agent::validate-node-network-object object))))
      (with-temporary-store (follower ignored)
        (declare (ignore ignored))
        (translation-fixture-server follower)
        (gr8s.store::install-pod-state-blob follower (gr8s.store::pod-state-json store))
        (is (= 1 (length (gr8s.network::service-translation-identity-messages follower))))))))

(test translation-status-rejects-stale-or-unowned-reports-and-withdraws
  (with-temporary-store (store ignored)
    (declare (ignore ignored))
    (let* ((server (translation-fixture-server store))
           (pod (translation-fixture-pod store "translation-client")))
      (translation-fixture-report server pod (translation-fixture-status))
      (let ((changed (translation-fixture-status "10.88.1.2" "10.88.1.9")))
        (translation-fixture-report server pod changed :node "worker-b")
        (translation-fixture-report server pod changed :uid "old-uid")
        (translation-fixture-report server pod changed :revision "0")
        (is (equal "10.88.1.8" (gethash "address" (gethash "gr8sServiceTranslation"
                                                          (gr8s.controllers::pod-observed-status store pod))))))
      (dolist (alias '("10.88.2.8" "10.88.1.0" "10.88.1.255" "10.88.1.2" "10.88.1.08" "bad"))
        (let ((*error-output* (make-broadcast-stream)))
          (translation-fixture-report server pod (translation-fixture-status "10.88.1.2" alias)))
        (is (equal "10.88.1.8" (gethash "address" (gethash "gr8sServiceTranslation"
                                                          (gr8s.controllers::pod-observed-status store pod))))))
      (translation-fixture-report server pod (translation-fixture-status "10.88.1.2" nil))
      (is-false (gethash "gr8sServiceTranslation" (gr8s.controllers::pod-observed-status store pod)))
      (is (null (gr8s.network::service-translation-identity-messages store))))))

(test translation-status-ownership-checks-both-directions
  (with-temporary-store (store ignored)
    (declare (ignore ignored))
    (let* ((server (translation-fixture-server store))
           (a (translation-fixture-pod store "client-a"))
           (b (translation-fixture-pod store "client-b")))
      (translation-fixture-report server a (translation-fixture-status))
      (translation-fixture-report server b (translation-fixture-status "10.88.1.4" nil))
      (dolist (status (list (translation-fixture-status "10.88.1.4" "10.88.1.8")
                            (translation-fixture-status "10.88.1.2" "10.88.1.9")
                            (translation-fixture-status "10.88.1.8" nil)))
        (let ((*error-output* (make-broadcast-stream))) (translation-fixture-report server b status))
        (is (equal "10.88.1.4" (gethash "podIP" (gr8s.controllers::pod-observed-status store b)))))
      (let ((*error-output* (make-broadcast-stream)))
        (translation-fixture-report server a (translation-fixture-status "10.88.1.2" "10.88.1.4")))
      (is (equal "10.88.1.8" (gethash "address" (gethash "gr8sServiceTranslation"
                                                        (gr8s.controllers::pod-observed-status store a))))))))

(test translation-node-inventory-is-validated-before-application
  (with-temporary-store (store ignored)
    (declare (ignore ignored))
    (let* ((server (translation-fixture-server store))
           (pod (translation-fixture-pod store "translation-client")))
      (translation-fixture-report server pod (translation-fixture-status))
      (let* ((valid (gr8s.agent::node-network-object (gr8s.apiserver::assigned-node-network server "worker-b")))
             (record (aref (gethash "serviceTranslations" valid) 0)))
        (dolist (entry '(("address" "10.90.1.3") ("address" "10.88.1.2")
                         ("sandboxID" "") ("podUID" "") ("nodeName" "")))
          (let* ((copy (gr8s.resources::copy-core-object valid))
                 (identity (aref (gethash "serviceTranslations" copy) 0)))
            (setf (gethash (first entry) identity) (second entry))
            (signals gr8s.network::cni-error (gr8s.agent::validate-node-network-object copy))))
        (let ((copy (gr8s.resources::copy-core-object valid)))
          (setf (gethash "serviceTranslations" copy) (vector record record))
          (signals gr8s.network::cni-error (gr8s.agent::validate-node-network-object copy)))
        ;; Public status writes cannot manufacture this private observed identity.
        (is-false (gethash "gr8sServiceTranslation"
                          (gr8s.apiserver::pod-client-status-from (translation-fixture-status))))))))

(test translation-agent-reports-only-current-sandbox-owned-ipam-lease
  (with-temporary-store (store directory)
    (let* ((ipam (gr8s.network::open-node-ipam (merge-pathnames "ipam/" directory) "10.88.1.0/24"))
           (pod (translation-fixture-pod store "translation-client"))
           (runtime (gr8s.agent::%make-node-runtime :node-name "worker-a" :node-id "worker-a" :ipam ipam))
           (primary (gr8s.network::allocate-pod-address ipam "sandbox-a" "eth0"))
           (alias (gr8s.network::allocate-service-snat-address ipam "sandbox-a" "eth0"))
           (status (translation-fixture-status primary nil))
           (record (gr8s.agent::node-runtime-service-translation-record runtime pod status :sandbox-id "sandbox-a")))
      (is (equal alias (gethash "address" record)))
      (is (equal (pod-uid pod) (gethash "podUID" record)))
      (is (equal (gr8s.network::pod-address-incarnation ipam "sandbox-a" "eth0")
                 (gethash "incarnationGeneration" record)))
      (is-false (gr8s.agent::node-runtime-service-translation-record runtime pod status :sandbox-id "sandbox-b"))
      (is-false (gr8s.agent::node-runtime-service-translation-record
                 runtime pod (translation-fixture-status "10.88.1.99" nil) :sandbox-id "sandbox-a"))
      (gr8s.network::release-pod-address ipam "sandbox-a" "eth0")
      (is-false (gr8s.agent::node-runtime-service-translation-record runtime pod status :sandbox-id "sandbox-a")))))

(test translation-generation-matches-local-and-replicated-owner-epochs
  (with-temporary-store (store directory)
    (let* ((server (translation-fixture-server store))
           (ipam (gr8s.network::open-node-ipam (merge-pathnames "ipam/" directory) "10.88.1.0/24"))
           (pod (translation-fixture-pod store "generated-client"))
           (runtime (gr8s.agent::%make-node-runtime :node-name "worker-a" :node-id "worker-a" :ipam ipam))
           (primary (gr8s.network::allocate-pod-address ipam "sandbox-a" "eth0"))
           (alias (gr8s.network::allocate-service-snat-address ipam "sandbox-a" "eth0"))
           (status (translation-fixture-status primary nil))
           (claim (gr8s.agent::node-runtime-service-translation-record
                   runtime pod status :sandbox-id "sandbox-a"))
           (generation (gethash "incarnationGeneration" claim)))
      (setf (gethash "gr8sServiceTranslation" status) claim)
      (translation-fixture-report server pod status)
      (let* ((wire (gr8s.apiserver::assigned-node-network server "worker-b"))
             (roundtrip (ag-proto:deserialize-from-bytes
                         'gr8s.node.v1::node-network-config
                         (ag-proto:serialize-to-bytes wire)))
             (object (gr8s.agent::node-network-object roundtrip))
             (record (aref (gethash "serviceTranslations" object) 0))
             (local (gr8s.network::service-nat-identity-pair
                     "worker-a" "sandbox-a" "eth0" primary alias generation))
             (replicated (gr8s.network::service-nat-identity-rows record)))
        (is (equal generation (gethash "incarnationGeneration" record)))
        (is (every #'equalp (mapcar #'cdr local) (mapcar #'cdr replicated)))
        (is (eq object (gr8s.agent::validate-node-network-object object)))
        (let ((bad (gr8s.resources::copy-core-object object)))
          (setf (gethash "incarnationGeneration"
                         (aref (gethash "serviceTranslations" bad) 0)) "invalid")
          (signals gr8s.network::cni-error (gr8s.agent::validate-node-network-object bad))))
      (gr8s.network::release-pod-address ipam "sandbox-a" "eth0")
      (is (equal primary (gr8s.network::allocate-pod-address ipam "sandbox-a" "eth0")))
      (is (not (equalp
                (gr8s.network::service-translation-incarnation-token
                 "worker-a" "sandbox-a" "eth0" primary alias generation)
                (gr8s.network::service-translation-incarnation-token
                 "worker-a" "sandbox-a" "eth0" primary alias
                 (gr8s.network::pod-address-incarnation ipam "sandbox-a" "eth0"))))))))

(test translation-inventory-retains-unready-peers-and-fences-replaced-node-records
  (with-temporary-store (store ignored)
    (declare (ignore ignored))
    (let* ((server (translation-fixture-server store))
           (pod (translation-fixture-pod store "translation-client")))
      (translation-fixture-report server pod (translation-fixture-status))
      ;; Readiness loss does not withdraw a running Pod's source identity.
      (is-false (gr8s.model::node-record-ready-p (gr8s.controllers::get-node store "worker-a")))
      (is (= 1 (length (gr8s.network::service-translation-identity-messages store))))
      (let* ((before (gr8s.model::pod-status-revision (gr8s.store::get-pod store (pod-namespace pod) (pod-name pod))))
             (changed (translation-fixture-status "10.88.1.2" "10.88.1.9")))
        (translation-fixture-report server pod changed)
        (is (= before (gr8s.model::pod-status-revision (gr8s.store::get-pod store (pod-namespace pod) (pod-name pod)))))
        (is (equal "10.88.1.9" (gethash "address" (gethash "gr8sServiceTranslation"
                                                          (gr8s.controllers::pod-observed-status store pod))))))
      (gr8s.store::with-store-lock (store)
        (gr8s.apiserver::remove-node-unlocked store (gr8s.controllers::get-node-unlocked store "worker-a")))
      (is (null (gr8s.network::service-translation-identity-messages store)))
      (gr8s.controllers::register-node store (gr8s.model::make-node-record :id "new-incarnation" :name "worker-a"
                                                      :pod-cidr "10.88.1.0/24"))
      (is (null (gr8s.network::service-translation-identity-messages store)))
      (let ((*error-output* (make-broadcast-stream)))
        (translation-fixture-report server pod (translation-fixture-status)))
      (is (null (gr8s.network::service-translation-identity-messages store)))
      (let* ((status (translation-fixture-status))
             (claim (gethash "gr8sServiceTranslation" status)))
        (setf (gethash "nodeID" claim) "new-incarnation"
              (gethash "sandboxID" claim) "replacement-sandbox")
        (translation-fixture-report server pod status)
        (let ((identity (first (gr8s.network::service-translation-identity-messages store))))
          (is (equal "new-incarnation" (slot-value identity 'gr8s.node.v1::node-id)))
          (is (equal "replacement-sandbox" (slot-value identity 'gr8s.node.v1::sandbox-id))))))))

(test translation-agent-uses-ipv4-lease-when-the-primary-family-is-ipv6
  (with-temporary-store (store directory)
    (let* ((ipam (gr8s.network::open-node-ipam (merge-pathnames "dual-ipam/" directory)
                                      '("fd88::/125" "10.88.1.0/29")))
           (pod (translation-fixture-pod store "dual-client"))
           (runtime (gr8s.agent::%make-node-runtime :node-name "worker-a" :node-id "worker-a" :ipam ipam))
           (addresses (gr8s.network::allocate-pod-addresses ipam "dual-sandbox" "eth0"))
           (alias (gr8s.network::allocate-service-snat-address ipam "dual-sandbox" "eth0"))
           (status (gr8s.resources::core-object "phase" "Running" "podIP" (first addresses)
                                     "podIPs" (map 'vector (lambda (ip) (gr8s.resources::core-object "ip" ip)) addresses)))
           (record (gr8s.agent::node-runtime-service-translation-record
                    runtime pod status :sandbox-id "dual-sandbox")))
      (is (equal "10.88.1.1" (gethash "podIP" record)))
      (is (equal alias (gethash "address" record)))
      (is (equal "fd88::1" (gethash "podIP" status))))))

(test translation-identities-survive-streamed-store-artifact-materialization
  (with-temporary-store (source source-root)
    (let* ((server (translation-fixture-server source))
           (pod (translation-fixture-pod source "artifact-client"))
           (artifact (merge-pathnames "translation-source.jsonl" source-root)))
      (translation-fixture-report server pod (translation-fixture-status))
      (gr8s.resources::capture-store-snapshot source artifact 42 7)
      (with-temporary-store (sink sink-root)
        (declare (ignore sink))
        (multiple-value-bind (path descriptor)
            (gr8s.resources::materialize-store-snapshot
             sink-root artifact (gr8s.raft.transport::raft-snapshot-file-digest artifact)
             :expected-index 42 :expected-term 7)
          (declare (ignore path))
          (gr8s.store::publish-store-generation sink-root (gethash "generation" descriptor)))
        (let* ((restored (gr8s.store::open-store sink-root))
               (current (gr8s.store::get-pod restored (pod-namespace pod) (pod-name pod)))
               (records (gr8s.network::service-translation-identity-messages restored)))
          (is (= 1 (length records)))
          (is (equal (pod-uid pod) (slot-value (first records) 'gr8s.node.v1::pod-uid)))
          (is (equal "10.88.1.8" (gethash "address" (gethash "gr8sServiceTranslation"
                                                            (gr8s.controllers::pod-observed-status restored current)))))
          (is-false (gethash "gr8sServiceTranslation"
                            (gethash "status" (gr8s.store::pod-published-view restored current)))))))))
