;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Verify a node's heartbeats publish and renew its kube-node-lease Lease, with
;;;; the node as holder and owner, without rewriting it on every heartbeat.

(in-package #:gr8s/tests)
(in-suite gr8s)

(test node-heartbeats-publish-and-renew-the-node-lease
  (with-temporary-store (store path)
    (values path)
    (gr8s:register-node store (make-test-node "worker-a" "node-a" "10.64.0.0/20"))
    (let ((now 4000000000))
      (gr8s::renew-node-lease store "worker-a" now)
      (let* ((lease (gr8s::get-core-resource store "leases" "kube-node-lease" "worker-a"))
             (spec (gethash "spec" lease))
             (owner (aref (gethash "ownerReferences" (gethash "metadata" lease)) 0)))
        (is (equal "worker-a" (gethash "holderIdentity" spec)))
        (is (= 40 (gethash "leaseDurationSeconds" spec)))
        (is (equal (gr8s::node-lease-micro-time now) (gethash "renewTime" spec)))
        (is (equal "Node" (gethash "kind" owner)))
        (is (equal "v1" (gethash "apiVersion" owner)))
        (is (equal "worker-a" (gethash "name" owner)))
        (is (equal "node-a" (gethash "uid" owner)))
        (let ((version (gethash "resourceVersion" (gethash "metadata" lease))))
          ;; A heartbeat within the renew interval leaves the Lease alone.
          (gr8s::renew-node-lease store "worker-a" (+ now 5))
          (is (equal version (gethash "resourceVersion"
                                      (gethash "metadata" (gr8s::get-core-resource store "leases" "kube-node-lease" "worker-a")))))
          (gr8s::renew-node-lease store "worker-a" (+ now 10))
          (let ((renewed (gr8s::get-core-resource store "leases" "kube-node-lease" "worker-a")))
            (is (not (equal version (gethash "resourceVersion" (gethash "metadata" renewed)))))
            (is (equal (gr8s::node-lease-micro-time (+ now 10)) (gethash "renewTime" (gethash "spec" renewed))))))))
    ;; An unknown node publishes nothing, and a failed write never escapes a heartbeat.
    (gr8s::note-node-heartbeat-lease store "missing" 4000000000)
    (signals kubernetes-error (gr8s::get-core-resource store "leases" "kube-node-lease" "missing"))))
