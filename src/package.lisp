(defpackage #:gr8s.cri.v1
  (:use #:cl)
  (:shadow #:labels #:some))

(defpackage #:gr8s.csi.v1
  (:use #:cl)
  (:shadow #:type #:labels #:some #:block))

(defpackage #:gr8s.pluginregistration.v1
  (:use #:cl)
  (:shadow #:type #:block))

(defpackage #:gr8s.containerd.tasks.v1
  (:use #:cl)
  (:shadow #:signal))

(defpackage #:gr8s.containerd.transfer.v1
  (:use #:cl))

(defpackage #:gr8s.node.v1
  (:use #:cl)
  (:shadow #:labels #:phase))

(defpackage #:gr8s
  (:use #:cl)
  (:export
   #:+gr8s-version+
   #:+node-protocol-version+
   #:container-spec-args
   #:container-spec-command
   #:container-spec-env
   #:container-spec-image
   #:container-spec-name
   #:container-spec-ports
   #:allocate-node-pod-cidr
   #:cluster-pki-ca-certificate-path
   #:cluster-pki-ca-fingerprint
   #:cluster-pki-ca-private-key-path
   #:create-join-token
   #:kubernetes-error
   #:kubernetes-error-reason
   #:create-pod
   #:cri-create-container
   #:cri-container-info-exit-code
   #:cri-container-info-state
   #:cri-container-status
   #:cri-delete-container
   #:cri-delete-pod-sandbox
   #:cri-pull-image
   #:cri-run-pod-sandbox
   #:cri-runtime-version
   #:cri-start-container
   #:cri-version-info-runtime-api-version
   #:cri-version-info-runtime-name
   #:cri-version-info-runtime-version
   #:cri-version-info-version
   #:delete-pod
   #:fake-runtime-ensure-count
   #:get-pod
   #:get-node
   #:list-pods
   #:list-nodes
   #:make-fake-runtime
   #:make-node-record
   #:make-containerd-runtime
   #:make-agent-envelope
   #:make-reconciler
   #:make-server-envelope
   #:mark-pod-deleting
   #:mark-node-not-ready
   #:mark-node-ready
   #:node-record-id
   #:node-record-last-heartbeat
   #:node-record-name
   #:node-record-pod-cidr
   #:node-record-ready-p
   #:node-grpc-server-port
   #:node-session-acknowledged-revision
   #:main
   #:open-store
   #:parse-cli-options
   #:parse-pod
   #:pod-containers
   #:pod-name
   #:pod-node-name
   #:pod-namespace
   #:pod-restart-policy
   #:pod-resource-version
   #:pod-to-object
   #:pod-uid
   #:pod-scheduling-phase
   #:register-node
   #:publish-node-desired-state
   #:reconcile-all
   #:reconcile-pod
   #:reconciler-logs
   #:remove-pod
   #:runtime-delete
   #:runtime-ensure
   #:runtime-error
   #:runtime-error-message
   #:runtime-logs
   #:runtime-observe
   #:runtime-pod-resource-version
   #:runtime-pod-phase
   #:runtime-pod-uid
   #:schedule-pod
   #:run-node-session
   #:set-fake-runtime-failure
   #:update-pod-observed-phase
   #:ensure-node-protocol-version
   #:ensure-cluster-pki
   #:enroll-node-csr
   #:enroll-node-over-grpc
   #:expire-node-heartbeats
   #:generate-node-key-and-csr
   #:pki-error
   #:pki-error-reason
   #:update-pod
   #:start-server
   #:start-node-grpc-server
   #:start-reconciliation-worker
   #:stop-reconciliation-worker
   #:stop-server
   #:stop-node-grpc-server
   #:unsupported-node-protocol-version
   #:unsupported-node-protocol-version-received
   #:unsupported-node-protocol-version-supported
   #:verify-node-certificate
   #:write-kubeconfig))
