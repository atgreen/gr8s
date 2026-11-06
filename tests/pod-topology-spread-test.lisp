;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Check topologySpreadConstraints against the scheduler's PodTopologySpread plugin:
;;;; validation, matchLabelKeys merged at creation, DoNotSchedule filtering with
;;;; maxSkew, minDomains and the node inclusion policies, and ScheduleAnyway scoring.

(in-package #:gr8s/tests)
(def-suite pod-topology-spread :in gr8s)
(in-suite pod-topology-spread)

(defun register-spread-nodes (store &rest nodes)
  "Register NODES, each (NAME . LABEL-PLIST), as ready workers."
  (loop for (name . labels) in nodes for index from 0
        do (let ((table (gr8s::core-object)))
             (loop for (key value) on labels by #'cddr do (setf (gethash key table) value))
             (gr8s:register-node store (gr8s:make-node-record :id (format nil "id-~A" name) :name name :labels table
                                                              :pod-cidr (format nil "10.88.~D.0/24" index)))
             (gr8s:mark-node-ready store name (get-universal-time)))))

(defun spread-constraint (key &rest fields)
  "Return a DoNotSchedule maxSkew 1 constraint over KEY selecting app=web, with FIELDS overriding."
  (let ((constraint (gr8s::core-object "maxSkew" 1 "topologyKey" key "whenUnsatisfiable" "DoNotSchedule"
                                       "labelSelector" (gr8s::core-object "matchLabels" (gr8s::core-object "app" "web")))))
    (loop for (field value) on fields by #'cddr do (setf (gethash field constraint) value))
    constraint))

(defun spread-pod (store name &key (app "web") constraints node (namespace "team") spec-fields labels)
  "Create a Pod labelled app=APP with CONSTRAINTS; with NODE it is already assigned there."
  (let ((pod (policy-test-pod name :namespace namespace
                                   :spec-fields (append (when constraints (list "topologySpreadConstraints" (coerce constraints 'vector)))
                                                        (when node (list "nodeName" node))
                                                        spec-fields))))
    (setf (gethash "labels" (gethash "metadata" (gr8s::pod-to-object pod)))
          (let ((table (gr8s::core-object "app" app)))
            (loop for (key value) on labels by #'cddr do (setf (gethash key table) value))
            table))
    (create-pod store pod)))

(defun spread-placement (store name &rest arguments)
  "Create and schedule a Pod, returning its node's name or NIL."
  (let ((node (gr8s::schedule-pod store (apply #'spread-pod store name arguments))))
    (and node (gr8s:node-record-name node))))

(defun spread-pod-object (constraints)
  "Return a Pod object carrying CONSTRAINTS, for validation."
  (gr8s::pod-to-object (policy-test-pod "check" :spec-fields (list "topologySpreadConstraints" (coerce constraints 'vector)))))

(test topology-spread-constraints-are-validated-as-the-api-server-does
  (is (gr8s::pod-name (parse-pod (spread-pod-object (list (spread-constraint "topology.kubernetes.io/zone" "minDomains" 2
                                                                             "nodeAffinityPolicy" "Ignore" "nodeTaintsPolicy" "Honor"
                                                                             "matchLabelKeys" #("pod-template-hash")))))))
  (dolist (bad (list (spread-constraint "zone" "maxSkew" 0)
                     (spread-constraint "")
                     (spread-constraint "not a key")
                     (spread-constraint "zone" "whenUnsatisfiable" "Sometimes")
                     (spread-constraint "zone" "minDomains" 0)
                     (spread-constraint "zone" "minDomains" 2 "whenUnsatisfiable" "ScheduleAnyway")
                     (spread-constraint "zone" "nodeAffinityPolicy" "Maybe")
                     (spread-constraint "zone" "nodeTaintsPolicy" "honor")
                     (spread-constraint "zone" "matchLabelKeys" #("app"))
                     (spread-constraint "zone" "labelSelector" 'null "matchLabelKeys" #("hash"))
                     (spread-constraint "zone" "unknownField" 1)))
    (signals kubernetes-error (parse-pod (spread-pod-object (list bad)))))
  ;; One topologyKey may appear once per whenUnsatisfiable.
  (signals kubernetes-error (parse-pod (spread-pod-object (list (spread-constraint "zone") (spread-constraint "zone")))))
  (is (gr8s::pod-name (parse-pod (spread-pod-object (list (spread-constraint "zone")
                                                          (spread-constraint "zone" "whenUnsatisfiable" "ScheduleAnyway")))))))

(test match-label-keys-are-merged-into-the-selector-at-creation
  (with-temporary-store (store path)
    (values path)
    (let* ((pod (spread-pod store "merged" :labels '("pod-template-hash" "abc")
                                           :constraints (list (spread-constraint "zone" "matchLabelKeys" #("pod-template-hash" "absent")))))
           (constraint (aref (gethash "topologySpreadConstraints" (gethash "spec" (gr8s::pod-to-object pod))) 0))
           (expressions (gethash "matchExpressions" (gethash "labelSelector" constraint))))
      ;; A key the Pod lacks adds nothing; the field itself is kept.
      (is (= 1 (length expressions)))
      (is (equal "pod-template-hash" (gethash "key" (aref expressions 0))))
      (is (equal "In" (gethash "operator" (aref expressions 0))))
      (is (equalp #("abc") (gethash "values" (aref expressions 0))))
      (is (equalp #("pod-template-hash" "absent") (gethash "matchLabelKeys" constraint))))))

(test a-node-without-a-required-topology-key-is-refused
  (with-temporary-store (store path)
    (values path)
    (register-spread-nodes store '("alpha"))
    ;; Every node has a hostname, but no node has a zone.
    (is (equal "alpha" (spread-placement store "host" :constraints (list (spread-constraint "kubernetes.io/hostname")))))
    (let ((pod (spread-pod store "zoned" :constraints (list (spread-constraint "topology.kubernetes.io/zone")))))
      (is (null (gr8s::schedule-pod store pod)))
      (is (equal "0/1 nodes are available: 1 node(s) didn't match pod topology spread constraints (missing required label)."
                 (gr8s::with-store-lock (store) (gr8s::pod-unschedulable-message store pod)))))
    ;; ScheduleAnyway only prefers; the Pod still runs.
    (is (equal "alpha" (spread-placement store "anyway" :constraints (list (spread-constraint "topology.kubernetes.io/zone"
                                                                                               "whenUnsatisfiable" "ScheduleAnyway")))))))

(test do-not-schedule-keeps-domains-within-max-skew
  (with-temporary-store (store path)
    (values path)
    (register-spread-nodes store '("alpha" "zone" "a") '("beta" "zone" "a") '("gamma" "zone" "b"))
    (spread-pod store "web-1" :node "alpha")
    (spread-pod store "web-2" :node "beta")
    ;; Zone a holds 2 and zone b none: only gamma keeps the skew within 1.
    (dotimes (attempt 2)
      (is (equal "gamma" (spread-placement store (format nil "web-~D" (+ 3 attempt))
                                           :constraints (list (spread-constraint "zone"))))))
    ;; Pods the selector doesn't select, in other namespaces, or terminating don't count.
    (spread-pod store "db" :app "db" :node "gamma")
    (spread-pod store "elsewhere" :namespace "other" :node "gamma")
    (spread-pod store "leaving" :node "gamma")
    (mark-pod-deleting store "team" "leaving")
    (let* ((constraint (spread-constraint "zone"))
           (pod (spread-pod store "web-5" :constraints (list constraint)))
           (counts (gr8s::with-store-lock (store)
                     (gr8s::topology-spread-domain-counts-unlocked store pod constraint '("zone")))))
      (is (= 2 (hash-table-count counts)))
      (is (= 2 (gethash "a" counts)))
      (is (= 2 (gethash "b" counts)))
      ;; Now 2 and 2: either zone is fine.
      (is-true (gr8s::schedule-pod store pod)))))

(test min-domains-counts-missing-domains-as-empty
  (with-temporary-store (store path)
    (values path)
    (register-spread-nodes store '("alpha"))
    (spread-pod store "web-1" :node "alpha")
    ;; With one domain the global minimum is its own count, so the skew is 1.
    (is (equal "alpha" (spread-placement store "web-2" :constraints (list (spread-constraint "kubernetes.io/hostname")))))
    ;; Asking for two domains when one exists makes the minimum 0, and 2 + 1 exceeds maxSkew.
    (is (null (spread-placement store "web-3" :constraints (list (spread-constraint "kubernetes.io/hostname" "minDomains" 2)))))
    (is (equal "alpha" (spread-placement store "web-4" :constraints (list (spread-constraint "kubernetes.io/hostname"
                                                                                               "minDomains" 2 "maxSkew" 5)))))))

(test node-inclusion-policies-choose-which-domains-count
  (with-temporary-store (store path)
    (values path)
    (register-spread-nodes store '("alpha" "zone" "a") '("gamma" "zone" "b"))
    (spread-pod store "web-1" :node "alpha")
    (let ((selector (list "nodeSelector" (gr8s::core-object "zone" "a"))))
      ;; Honor (the default): gamma fails the Pod's nodeSelector, so zone b isn't a domain.
      (is (equal "alpha" (spread-placement store "web-2" :spec-fields selector
                                                         :constraints (list (spread-constraint "zone")))))
      ;; Ignore: zone b counts as an empty domain, so alpha would make the skew 2.
      (is (null (spread-placement store "web-3" :spec-fields selector
                                                :constraints (list (spread-constraint "zone" "nodeAffinityPolicy" "Ignore"))))))
    ;; nodeTaintsPolicy Honor leaves out a node whose taints the Pod doesn't tolerate.
    (gr8s::with-store-lock (store)
      (setf (gr8s::node-record-taints (gr8s::get-node-unlocked store "gamma"))
            (vector (gr8s::core-object "key" "dedicated" "value" "x" "effect" "NoSchedule"))))
    (let ((pod (spread-pod store "web-4" :constraints (list (spread-constraint "zone" "nodeTaintsPolicy" "Honor"))))
          (ignoring (spread-pod store "web-5" :constraints (list (spread-constraint "zone")))))
      (gr8s::with-store-lock (store)
        (let ((alpha (gr8s::get-node-unlocked store "alpha")))
          (is (null (gr8s::pod-topology-spread-failure-unlocked store pod alpha)))
          (is (equal gr8s::+topology-spread-failure+
                     (gr8s::pod-topology-spread-failure-unlocked store ignoring alpha))))))))

(test schedule-anyway-prefers-the-least-crowded-domain
  (with-temporary-store (store path)
    (values path)
    (register-spread-nodes store '("alpha") '("beta"))
    (spread-pod store "web-1" :node "alpha")
    (spread-pod store "db-1" :app "db" :node "beta")
    (spread-pod store "db-2" :app "db" :node "beta")
    ;; Alone, the fewest Pods decide: alpha.
    (is (equal "alpha" (spread-placement store "plain" :app "other")))
    ;; Spreading web Pods outweighs that.
    (is (equal "beta" (spread-placement store "web-2" :constraints (list (spread-constraint "kubernetes.io/hostname"
                                                                                              "whenUnsatisfiable" "ScheduleAnyway")))))))
