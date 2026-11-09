;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Package boundary for node-side Pod and container orchestration.

(defpackage #:gr8s.kubelet
  (:use #:cl #:gr8s)
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

(eval-when (:compile-toplevel :load-toplevel :execute)
  (let ((kubelet (find-package '#:gr8s.kubelet))
        (composition (find-package '#:gr8s)))
    (dolist (name '("CLEANUP-POD-VOLUMES"
                    "ENSURE-CONTAINER-PROBE-MANAGER"
                    "KUBELET-INSTRUMENTATION-TEXT"
                    "MAKE-RECONCILER"
                    "RECONCILE-POD"))
      (multiple-value-bind (old old-status)
          (find-symbol name composition)
        (let ((new (find-symbol name kubelet)))
          (dolist (user (package-used-by-list composition))
            (when (eq old (find-symbol name user))
              (shadowing-import new user)))
          (shadowing-import new composition)
          (export new kubelet)
          (when (eq :external old-status)
            (export new composition)))))))
