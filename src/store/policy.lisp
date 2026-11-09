;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Dependency-inversion boundary between durable storage and Kubernetes API
;;;; admission. The resource layer installs these operations after its policy
;;;; modules load; the store invokes only this narrow lifecycle contract.

(in-package #:gr8s.store)

(defun missing-store-policy-operation (&rest arguments)
  "Signal that the API integration has not installed the store lifecycle policy."
  (declare (ignore arguments))
  (error "The gr8s store lifecycle policy is not configured"))

(defstruct (store-policy (:constructor %make-store-policy))
  (parse-pod #'missing-store-policy-operation :type function)
  (load-resources #'missing-store-policy-operation :type function)
  (prepare-create #'missing-store-policy-operation :type function)
  (track-create #'missing-store-policy-operation :type function)
  (prepare-update #'missing-store-policy-operation :type function)
  (track-update #'missing-store-policy-operation :type function)
  (unchanged-p #'missing-store-policy-operation :type function)
  (retained-p #'missing-store-policy-operation :type function)
  (prepare-deletion #'missing-store-policy-operation :type function))

(defvar *store-policy* (%make-store-policy)
  "Kubernetes lifecycle operations supplied by the API resource layer.")

(defun configure-store-policy (&rest arguments)
  "Install the resource layer's complete Pod lifecycle policy."
  (setf *store-policy* (apply #'%make-store-policy arguments)))

(defun store-parse-pod (input &key allow-generate-name)
  "Parse INPUT with the configured Kubernetes Pod policy."
  (funcall (store-policy-parse-pod *store-policy*)
           input :allow-generate-name allow-generate-name))

(defvar *pod-write-context* nil
  "Per-key staged HA Pod state, bound by the store transaction wrapper.")
