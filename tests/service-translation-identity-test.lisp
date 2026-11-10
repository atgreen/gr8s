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
  (let ((status (gr8s::core-object "phase" "Running" "podIP" primary)))
    (when alias
      (setf (gethash "gr8sServiceTranslation" status)
            (gr8s::core-object "podIP" primary "address" alias
                              "sandboxID" "sandbox-a" "interfaceName" "eth0"
                              "nodeID" "worker-a"
                              "nodeName" "forged-node" "podUID" "forged-uid")))
    status))

(defun translation-fixture-server (store)
  (dolist (entry '(("worker-a" "10.88.1.0/24") ("worker-b" "10.88.2.0/24")))
    (unless (ignore-errors (gr8s:get-node store (first entry)))
      (gr8s:register-node store (gr8s:make-node-record :id (first entry) :name (first entry)
                                                      :pod-cidr (second entry)))))
  (gr8s::%make-node-grpc-server :store store :port 0 :cluster-pod-cidr "10.88.0.0/16"
                               :cluster-pod-cidrs '("10.88.0.0/16")))

(defun translation-fixture-report (server pod status &key (node "worker-a") uid revision)
  (let* ((observation (gr8s::pod-observed-status-message pod status))
         (message (gr8s::make-agent-envelope
                   :status (make-instance 'gr8s.node.v1::node-status :pods (list observation)))))
    (when uid (setf (slot-value observation 'gr8s.node.v1::uid) uid))
    (when revision (setf (slot-value observation 'gr8s.node.v1::resource-version) revision))
    ;; Use the actual decoder/dispatch path; NODE is the already authenticated peer.
    (gr8s::handle-node-agent-envelope
     server node (ag-proto:deserialize-from-bytes 'gr8s.node.v1::agent-envelope
                                                 (ag-proto:serialize-to-bytes message)))))

(test translation-identities-survive-restart-and-replication-without-publication
  (with-temporary-store (store path)
    (let* ((server (translation-fixture-server store))
           (pod (translation-fixture-pod store "translation-client")))
      (translation-fixture-report server pod (translation-fixture-status))
      (let* ((observed (gr8s::pod-observed-status store pod))
             (identity (gethash "gr8sServiceTranslation" observed)))
        (is (equal "10.88.1.8" (gethash "address" identity)))
        (is (equal (pod-uid pod) (gethash "podUID" identity)))
        (is (equal "worker-a" (gethash "nodeName" identity)))
        (is-false (gethash "gr8sServiceTranslation"
                          (gethash "status" (gr8s::pod-response-object pod observed))))
        (is-false (gethash "gr8sServiceTranslation"
                          (gethash "status" (gr8s::pod-published-view store pod))))
        (is (gethash "gr8sServiceTranslation" (gr8s::pod-observed-status store pod))))
      (let* ((reopened (gr8s:open-store path))
             (network (gr8s::assigned-node-network (translation-fixture-server reopened) "worker-b"))
             (wire (ag-proto:deserialize-from-bytes 'gr8s.node.v1::node-network-config
                                                   (ag-proto:serialize-to-bytes network)))
             (records (slot-value wire 'gr8s.node.v1::service-translations))
             (object (gr8s::node-network-object wire)))
        (is (= 1 (length records)))
        (is (equal (pod-uid pod) (slot-value (first records) 'gr8s.node.v1::pod-uid)))
        (is (equal "sandbox-a" (slot-value (first records) 'gr8s.node.v1::sandbox-id)))
        (is (equal "10.88.1.8" (gethash "address" (aref (gethash "serviceTranslations" object) 0))))
        (is (eq object (gr8s::validate-node-network-object object))))
      (with-temporary-store (follower ignored)
        (declare (ignore ignored))
        (translation-fixture-server follower)
        (gr8s::install-pod-state-blob follower (gr8s::pod-state-json store))
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
                                                          (gr8s::pod-observed-status store pod))))))
      (dolist (alias '("10.88.2.8" "10.88.1.0" "10.88.1.255" "10.88.1.2" "10.88.1.08" "bad"))
        (let ((*error-output* (make-broadcast-stream)))
          (translation-fixture-report server pod (translation-fixture-status "10.88.1.2" alias)))
        (is (equal "10.88.1.8" (gethash "address" (gethash "gr8sServiceTranslation"
                                                          (gr8s::pod-observed-status store pod))))))
      (translation-fixture-report server pod (translation-fixture-status "10.88.1.2" nil))
      (is-false (gethash "gr8sServiceTranslation" (gr8s::pod-observed-status store pod)))
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
        (is (equal "10.88.1.4" (gethash "podIP" (gr8s::pod-observed-status store b)))))
      (let ((*error-output* (make-broadcast-stream)))
        (translation-fixture-report server a (translation-fixture-status "10.88.1.2" "10.88.1.4")))
      (is (equal "10.88.1.8" (gethash "address" (gethash "gr8sServiceTranslation"
                                                        (gr8s::pod-observed-status store a))))))))

(test translation-node-inventory-is-validated-before-application
  (with-temporary-store (store ignored)
    (declare (ignore ignored))
    (let* ((server (translation-fixture-server store))
           (pod (translation-fixture-pod store "translation-client")))
      (translation-fixture-report server pod (translation-fixture-status))
      (let* ((valid (gr8s::node-network-object (gr8s::assigned-node-network server "worker-b")))
             (record (aref (gethash "serviceTranslations" valid) 0)))
        (dolist (entry '(("address" "10.90.1.3") ("address" "10.88.1.2")
                         ("sandboxID" "") ("podUID" "") ("nodeName" "")))
          (let* ((copy (gr8s::copy-core-object valid))
                 (identity (aref (gethash "serviceTranslations" copy) 0)))
            (setf (gethash (first entry) identity) (second entry))
            (signals gr8s::cni-error (gr8s::validate-node-network-object copy))))
        (let ((copy (gr8s::copy-core-object valid)))
          (setf (gethash "serviceTranslations" copy) (vector record record))
          (signals gr8s::cni-error (gr8s::validate-node-network-object copy)))
        ;; Public status writes cannot manufacture this private observed identity.
        (is-false (gethash "gr8sServiceTranslation"
                          (gr8s::pod-client-status-from (translation-fixture-status))))))))

(test translation-agent-reports-only-current-sandbox-owned-ipam-lease
  (with-temporary-store (store directory)
    (let* ((ipam (gr8s::open-node-ipam (merge-pathnames "ipam/" directory) "10.88.1.0/24"))
           (pod (translation-fixture-pod store "translation-client"))
           (runtime (gr8s::%make-node-runtime :node-name "worker-a" :node-id "worker-a" :ipam ipam))
           (primary (gr8s::allocate-pod-address ipam "sandbox-a" "eth0"))
           (alias (gr8s.network::allocate-service-snat-address ipam "sandbox-a" "eth0"))
           (status (translation-fixture-status primary nil))
           (record (gr8s.agent::node-runtime-service-translation-record runtime pod status :sandbox-id "sandbox-a")))
      (is (equal alias (gethash "address" record)))
      (is (equal (pod-uid pod) (gethash "podUID" record)))
      (is-false (gr8s.agent::node-runtime-service-translation-record runtime pod status :sandbox-id "sandbox-b"))
      (is-false (gr8s.agent::node-runtime-service-translation-record
                 runtime pod (translation-fixture-status "10.88.1.99" nil) :sandbox-id "sandbox-a"))
      (gr8s::release-pod-address ipam "sandbox-a" "eth0")
      (is-false (gr8s.agent::node-runtime-service-translation-record runtime pod status :sandbox-id "sandbox-a")))))

(test translation-inventory-retains-unready-peers-and-fences-replaced-node-records
  (with-temporary-store (store ignored)
    (declare (ignore ignored))
    (let* ((server (translation-fixture-server store))
           (pod (translation-fixture-pod store "translation-client")))
      (translation-fixture-report server pod (translation-fixture-status))
      ;; Readiness loss does not withdraw a running Pod's source identity.
      (is-false (gr8s:node-record-ready-p (gr8s:get-node store "worker-a")))
      (is (= 1 (length (gr8s.network::service-translation-identity-messages store))))
      (let* ((before (gr8s::pod-status-revision (gr8s:get-pod store (pod-namespace pod) (pod-name pod))))
             (changed (translation-fixture-status "10.88.1.2" "10.88.1.9")))
        (translation-fixture-report server pod changed)
        (is (= before (gr8s::pod-status-revision (gr8s:get-pod store (pod-namespace pod) (pod-name pod)))))
        (is (equal "10.88.1.9" (gethash "address" (gethash "gr8sServiceTranslation"
                                                          (gr8s::pod-observed-status store pod))))))
      (gr8s::with-store-lock (store)
        (gr8s.apiserver::remove-node-unlocked store (gr8s::get-node-unlocked store "worker-a")))
      (is (null (gr8s.network::service-translation-identity-messages store)))
      (gr8s:register-node store (gr8s:make-node-record :id "new-incarnation" :name "worker-a"
                                                      :pod-cidr "10.88.1.0/24"))
      (is (null (gr8s.network::service-translation-identity-messages store))))))
