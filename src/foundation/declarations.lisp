;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Mirror the GR8S.FOUNDATION API into the historical GR8S composition package.
;;;;
;;;; GR8S.FOUNDATION now owns the symbols that used to be defined directly in
;;;; GR8S (version reporting, JSON-OBJECT, the cluster DNS constants, network
;;;; steering).  While GR8S remains the facade, un-migrated callers still reach
;;;; these through GR8S::NAME, so we shadowing-import the owner's bindings into
;;;; GR8S immediately after the foundation files load -- long before any consumer
;;;; -- and re-export the one that is part of the public GR8S API (+GR8S-VERSION+).
;;;; This replaces the compat.lisp push that other modules do later in load order.

(in-package #:gr8s.foundation)

(eval-when (:compile-toplevel :load-toplevel :execute)
  (let ((owner (find-package '#:gr8s.foundation))
        (facade (find-package '#:gr8s))
        ;; Every symbol GR8S.FOUNDATION owns (generated: tools/refactor stage-1 map).
        (owned '("+DNS-CLUSTER-ZONE+" "+DNS-KUBERNETES-SERVICE+"
                 "+DNS-KUBERNETES-SERVICE-ADDRESS+" "+DNS-NAME-ERROR+"
                 "+DNS-POD-OPTIONS+" "+DNS-POD-SEARCHES+" "+DNS-POD-SERVER-ADDRESS+"
                 "+GR8S-VERSION+" "JSON-OBJECT" "KUBERNETES-API-VERSION-COMPONENTS"
                 "KUBERNETES-GIT-VERSION" "KUBERNETES-SERVICE-ANSWER"
                 "NETWORK-STEERING-CANDIDATE-LESS-P" "NETWORK-STEERING-SCORE"
                 "NODE-STEERING-CAPACITY-SCORE" "RANK-NETWORK-STEERING-CANDIDATES"
                 "STEERING-BOUNDED-INTEGER"))
        ;; Of those, the names that are part of the public GR8S facade :export.
        (facade-exported '("+GR8S-VERSION+")))
    (dolist (name owned)
      (let ((sym (find-symbol name owner)))
        (unless sym
          (error "GR8S.FOUNDATION is expected to own ~A but does not." name))
        (export sym owner)
        ;; Replace any placeholder the GR8S facade defpackage interned.
        (shadowing-import sym facade)
        (when (member name facade-exported :test #'string=)
          (export sym facade))))))
