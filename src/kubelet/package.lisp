;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Package boundary for node-side Pod and container orchestration.

(defpackage #:gr8s.kubelet
  (:use #:cl)
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
