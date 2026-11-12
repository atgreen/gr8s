;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Public controller boundary for Pod placement policy.

(in-package #:gr8s.controllers)

(defun schedule-pod (store pod)
  "Choose and persist POD's node assignment in STORE."
  (gr8s.controllers::%schedule-pod store pod))
