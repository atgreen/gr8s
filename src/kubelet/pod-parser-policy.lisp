;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Compose MODEL's structural Pod parser with gr8s validation policy. This is
;;;; the compatibility facade; MODEL itself has no dependency on these layers.

(in-package #:gr8s.kubelet)

(defparameter *gr8s-pod-parser-policy*
  (gr8s.model:make-pod-parser-policy
   :environment-reference-validator
   (lambda (variable) (validate-pod-field-reference variable))
   :container-validator
   (lambda (object)
     (validate-container-restart-rules object)
     (normalize-container-resources object)
     (validate-runtime-container object))
   :metadata-validator
   (lambda (metadata) (validate-pod-finalizers metadata))
   :spec-validator
   (lambda (spec)
     (validate-pod-host-settings spec)
     (validate-pod-hostname-fields spec)
     (validate-runtime-pod-spec spec)
     (validate-pod-dns-spec spec)
     (default-host-network-ports spec))
   :resource-validator
   (lambda (spec) (validate-pod-level-resources spec) (validate-pod-hugepages spec))))

(defun parse-pod (input &key allow-generate-name)
  "Parse INPUT through MODEL with gr8s's complete Kubernetes validation policy."
  (gr8s.model:parse-pod-with-policy
   input *gr8s-pod-parser-policy* :allow-generate-name allow-generate-name))
