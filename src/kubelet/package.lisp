;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Package boundary for node-side Pod and container orchestration.

(defpackage #:gr8s.kubelet
  (:use #:cl)
  (:import-from #:gr8s.model
   #:container-spec-image
   #:container-spec-name
   #:dns-label-p
   #:invalid-pod
   #:node-record-labels
   #:node-record-name
   #:optional-vector
   #:pod
   #:pod-containers
   #:pod-ephemeral-containers
   #:pod-init-containers
   #:pod-name
   #:pod-namespace
   #:pod-node-name
   #:pod-resource-version
   #:pod-to-object
   #:pod-uid
   #:reject-unsupported-fields
   #:require-dns-label
   #:require-dns-subdomain
   #:require-nonempty-string
   #:require-object
   #:require-string-vector)
  (:import-from #:gr8s.runtime
   #:container-config-error
   #:runtime-delete-pod
   #:runtime-error
   #:runtime-forget-pod-finalization
   #:runtime-observe
   #:runtime-terminate-pod)
  (:local-nicknames (#:dp #:gr8s.deviceplugin.v1beta1)
                    (#:pr #:gr8s.podresources.v1))
  (:shadow
   #:cleanup-pod-volumes
   #:ensure-container-probe-manager
   #:kubelet-instrumentation-text
   #:make-reconciler
   #:reconcile-pod)
  (:export
   #:cleanup-pod-volumes
   #:ensure-container-probe-manager
   #:kubelet-instrumentation-text
   #:make-reconciler
   #:reconcile-pod))
