;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Bind the durable store to gr8s's Kubernetes admission and API-resource
;;;; policy. Keeping this composition in the façade preserves a one-way package
;;;; dependency: GR8S may use GR8S.STORE, while GR8S.STORE never reaches upward.

(in-package #:gr8s.apiserver)

(gr8s.store:configure-store-policy
 :node-view #'node-api-object
 :node-event #'record-node-watch-event-unlocked
 :parse-pod #'parse-pod
 :load-resources #'load-core-resources
 :prepare-create
 (lambda (store pod)
   (default-created-pod pod)
   (enforce-resource-quotas-unlocked
    store "pods" (pod-namespace pod) (pod-to-object pod))
   (merge-topology-spread-match-label-keys pod))
 :track-create
 (lambda (pod)
   (let ((tracked (copy-json-object (pod-to-object pod))))
     (apply-track-write nil tracked "pods")
     (multiple-value-bind (entries present)
         (gethash "managedFields" (gethash "metadata" tracked))
       (if present
           (setf (gethash "managedFields"
                          (gethash "metadata" (pod-to-object pod)))
                 entries)
           (remhash "managedFields" (gethash "metadata" (pod-to-object pod)))))))
 :prepare-update
 (lambda (existing replacement)
   (validate-pod-hostname-update existing replacement)
   (validate-pod-dns-update existing replacement)
   (validate-pod-finalizer-update existing replacement)
   (validate-pod-policy-update existing replacement)
   (preserve-pod-ephemeral-containers existing replacement)
   (default-updated-pod existing replacement))
 :track-update
 (lambda (existing replacement)
   (let ((before (copy-json-object (pod-to-object existing))))
     (remhash "status" before)
     (apply-track-write before (pod-to-object replacement) "pods")))
 :unchanged-p #'core-write-unchanged-p
 :retained-p #'pod-finalizers-present-p
 :prepare-deletion #'prepare-pod-deletion)
