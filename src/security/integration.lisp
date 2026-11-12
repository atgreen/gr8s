;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Explicit cross-module imports for GR8S.SECURITY.
;;;;
;;;; GR8S.SECURITY no longer (:use #:gr8s); it imports exactly the sibling
;;;; symbols its implementation references.  Loaded after the stage-1 ownership
;;;; declarations, so every owner symbol is already interned in its home package.
;;;; (Generated seed from tools/refactor; maintained by hand as the module
;;;; evolves.)

(in-package #:gr8s.security)

(eval-when (:compile-toplevel :load-toplevel :execute)
  (dolist (spec '(("CL-RAFT" "RAFT-CURRENT-CONFIG" "RAFT-NODE-ID"
                   "RAFT-NODE-PEER-ADDRESSES")
                  ("GR8S.AGENT" "VERIFY-ENROLLMENT-CA-PIN")
                  ("GR8S.APISERVER" "CERTIFICATE-RENEWAL-DUE-P"
                   "FINISH-PENDING-LEAF-ROTATION" "ISSUE-CLUSTER-CERTIFICATE")
                  ("GR8S.MODEL" "KUBERNETES-ERROR")
                  ("GR8S.RAFT.TRANSPORT" "OCTETS->RAFT-MESSAGE"
                   "RAFT-MEMBER-CREDENTIALS" "RAFT-MEMBER-LOCK" "RAFT-MEMBER-NODE"
                   "RAFT-MEMBER-RUNNING")
                  ("GR8S.RESOURCES" "CORE-BASE64-BYTES" "CORE-RESOURCE-ERROR"
                   "INSTALL-SHARED-SERVICE-ACCOUNT-SIGNING-KEY"
                   "SERVICE-ACCOUNT-SIGNING-KEY-PATH-UNDER-PKI-ROOT")
                  ("GR8S.SERVER" "CERTIFICATE-PEM")))
    (let ((pkg (find-package (first spec))))
      (unless pkg (error "GR8S.SECURITY imports from missing package ~A" (first spec)))
      (dolist (name (rest spec))
        ;; INTERN rather than FIND-SYMBOL: some collaborators (e.g. apiserver
        ;; certificate rotation) load later in the serial system, so this is a
        ;; forward reference -- the owner defines the function on this very
        ;; symbol when it loads.
        (shadowing-import (intern name pkg) '#:gr8s.security)))))
