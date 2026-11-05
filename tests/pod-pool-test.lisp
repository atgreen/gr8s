;;;; SPDX-FileCopyrightText: 2026 gr8s contributors
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Verify durable pool geometry, legacy assignment compatibility, CLI settings,
;;;; reserved-range rejection and collision-free allocation across prefix sizes.

(in-package #:gr8s/tests)
(in-suite gr8s)

(defun ensure-test-controller-node-pool (store path options)
  "Test pool persistence without depending on the machine's actual host routes."
  (gr8s::ensure-controller-node-pool store path options :route-reader (constantly nil)))

(test pod-pool-defaults-support-256-nodes-with-fixed-20-bit-blocks
  (with-temporary-store (store path)
    (let* ((options (parse-cli-options '("serve")))
           (pool (ensure-test-controller-node-pool store path options)))
      (is (string= "10.80.0.0/12" (gethash "clusterPodCIDR" pool)))
      (is (= 20 (gethash "nodePrefix" pool)))
      (is (string= "10.80.0.0/20" (gr8s:allocate-node-pod-cidr store "10.80.0.0/12" 20)))
      (is (= 256 (expt 2 (- 20 12))))
      (is (= #o600 (logand #o777 (sb-posix:stat-mode
                                  (sb-posix:stat (merge-pathnames "network/pool.json" path))))))
      ;; Pool metadata is not mistaken for a Pod when rebuilding the store.
      (is (null (list-pods (open-store path) "default")))
      (is (equalp pool (ensure-test-controller-node-pool
                       (open-store path) path options))))))

(test explicit-pod-pool-persists-and-cannot-change-after-node-allocation
  (with-temporary-store (store path)
    (let* ((options (parse-cli-options '("serve" "--cluster-pod-cidr" "10.112.0.0/12"
                                       "--node-pod-prefix" "22")))
           (pool (ensure-test-controller-node-pool store path options))
           (node-cidr (gr8s:allocate-node-pod-cidr store "10.112.0.0/12" 22)))
      (gr8s:register-node store (make-test-node "worker" "node-1" node-cidr))
      (is (string= "10.112.0.0/22" node-cidr))
      (is (equalp pool (ensure-test-controller-node-pool
                       (open-store path) path (parse-cli-options '("serve")))))
      (let ((original (uiop:read-file-string (merge-pathnames "network/pool.json" path))))
        (signals gr8s::cni-error
          (ensure-test-controller-node-pool
           store path (parse-cli-options '("serve" "--cluster-pod-cidr" "10.128.0.0/12"))))
        (signals gr8s::cni-error
          (ensure-test-controller-node-pool
           store path (parse-cli-options '("serve" "--node-pod-prefix" "20"))))
        (is (string= original (uiop:read-file-string (merge-pathnames "network/pool.json" path))))
        (is (string= node-cidr (gr8s:node-record-pod-cidr (gr8s:get-node store "worker"))))))))

(test previous-default-pool-and-node-identities-survive-upgrade
  (with-temporary-store (store path)
    (gr8s:register-node store (make-test-node "old-worker" "old-node" "10.88.3.0/24"))
    (let ((pool (ensure-test-controller-node-pool store path (parse-cli-options '("serve")))))
      (is (string= "10.88.0.0/16" (gethash "clusterPodCIDR" pool)))
      (is (= 24 (gethash "nodePrefix" pool)))
      (is (string= "10.88.3.0/24" (gr8s:node-record-pod-cidr (gr8s:get-node store "old-worker"))))
      (is (equalp pool (ensure-test-controller-node-pool
                       (open-store path) path (parse-cli-options '("serve"))))))))

(test existing-custom-node-blocks-require-explicit-pool-adoption
  (with-temporary-store (store path)
    (gr8s:register-node store (make-test-node "custom-worker" "custom-node" "10.112.16.0/20"))
    (signals gr8s::cni-error
      (ensure-test-controller-node-pool store path (parse-cli-options '("serve"))))
    (is-false (probe-file (merge-pathnames "network/pool.json" path)))
    (let ((pool (ensure-test-controller-node-pool
                 store path (parse-cli-options '("serve" "--cluster-pod-cidr" "10.112.0.0/12"
                                                "--node-pod-prefix" "20")))))
      (is (string= "10.112.0.0/12" (gethash "clusterPodCIDR" pool))))))

(test invalid-pod-pool-geometry-and-reserved-ranges-fail-closed
  (dolist (parameters '(("10.80.0.1/12" 20) ("10.80.0.0/12" 8) ("10.80.0.0/12" 31)
                        ("10.96.0.0/12" 20) ("127.0.0.0/16" 20) ("169.254.0.0/16" 20)
                        ("224.0.0.0/8" 20) ("240.0.0.0/4" 20) ("0.0.0.0/0" 20)))
    (signals gr8s::cni-error
      (gr8s::validate-node-pool-config (apply #'gr8s::make-node-pool-config parameters))))
  (dolist (prefix '("0" "31" "garbage"))
    (signals error (parse-cli-options (list "serve" "--node-pod-prefix" prefix)))))

(test allocator-skips-overlapping-blocks-with-different-prefixes
  (with-temporary-store (store path)
    (values path)
    (gr8s:register-node store (make-test-node "narrow" "node-1" "10.80.8.0/21"))
    (is (string= "10.80.16.0/20" (gr8s:allocate-node-pod-cidr store "10.80.0.0/12" 20))))
  (is-true (gr8s::ipv4-prefixes-overlap-p "10.80.0.0/12" "10.95.255.255/32"))
  (is-false (gr8s::ipv4-prefixes-overlap-p "10.80.0.0/12" "10.96.0.0/32")))

(defun pool-test-network (routes &optional (underlay "192.0.2.1"))
  "Create a canonical durable network object for route-ownership tests."
  (gr8s::node-network-object
   (make-instance 'gr8s.node.v1::node-network-config
                  :cluster-pod-cidr "10.80.0.0/12" :node-pod-cidr "10.80.0.0/20"
                  :underlay-address underlay :dns-address "169.254.1.1" :mtu 1450 :vni 42)
   routes))

(defun pool-test-link-attributes (name owner mac kind &optional network)
  "Model Linux link identity attributes, including nested VXLAN parameters."
  (let ((attributes (make-hash-table)))
    (setf (gethash 3 attributes) (gr8s::netlink-string name)
          (gethash 20 attributes) (gr8s::netlink-string owner)
          (gethash 1 attributes) mac
          (gethash 18 attributes)
          (gr8s::netlink-octets
           (gr8s::netlink-attribute 1 (gr8s::netlink-string kind))
           (if network
               (gr8s::netlink-attribute
                2 (gr8s::netlink-octets
                   (gr8s::netlink-attribute 1 (gr8s::netlink-integer (gethash "vni" network) 4))
                   (gr8s::netlink-attribute 4 (gr8s::ipv4-network-octets (gethash "underlayAddress" network)))
                   (gr8s::netlink-attribute 15 #(18 181))))
               #())))
    attributes))

(test host-route-conflicts-include-host-and-policy-table-routes
  (with-temporary-store (store path)
    (dolist (route '((:cidr "10.84.0.0/24" :index 7 :table 254)
                     (:cidr "10.95.255.255/32" :index 7 :table 255)
                     (:cidr "10.80.0.0/16" :index 0 :table 100)))
      (signals gr8s::cni-error
        (gr8s::ensure-controller-node-pool
         store path (parse-cli-options '("serve"))
         :route-reader (lambda () (list route)))))
    (is-false (probe-file (merge-pathnames "network/pool.json" path)))
    (is-true
     (gr8s::validate-pod-pool-host-routes
      "10.80.0.0/12" path :route-reader
      (lambda () '((:cidr "0.0.0.0/0" :index 2 :table 254)
                    (:cidr "192.0.2.0/24" :index 2 :table 254)))))))

(test only-exact-journal-owned-pod-routes-are-exempt-from-overlap-rejection
  (with-temporary-store (store path)
    (values store)
    (let* ((node-root (merge-pathnames "node/" path))
           (network (pool-test-network nil ""))
           (ipam (gr8s::open-node-ipam (merge-pathnames "ipam/" node-root) "10.80.0.0/20"))
           (address (gr8s::allocate-pod-address ipam "owned-sandbox" "eth0"))
           (context (gr8s::make-cni-context :container-id "owned-sandbox" :interface-name "eth0"))
           (owner (gr8s::routed-cni-owner context))
           (attributes (pool-test-link-attributes
                        (gr8s::routed-cni-host-name context) owner
                        (gr8s::routed-veth-mac owner "host") "veth"))
           (route (list :cidr (format nil "~A/32" address) :index 7 :table 254)))
      (gr8s::write-private-text-atomically (merge-pathnames "network.json" node-root)
                                         (com.inuoe.jzon:stringify network))
      (flet ((validate (route)
               (gr8s::validate-pod-pool-host-routes
                "10.80.0.0/12" node-root :route-reader (lambda () (list route))
                :link-reader (lambda (index) (is (= 7 index)) attributes))))
        (is-true (validate route))
        ;; Owning a link does not authorize a wider or different destination.
        (signals gr8s::cni-error (validate '(:cidr "10.80.0.0/20" :index 7 :table 254)))
        (signals gr8s::cni-error (validate '(:cidr "10.80.0.2/32" :index 7 :table 254)))
        (setf (gethash 20 attributes) (gr8s::netlink-string "foreign-owner"))
        (signals gr8s::cni-error (validate route))
        (setf (gethash 20 attributes) (gr8s::netlink-string owner)
              (gethash 1 attributes) #(2 0 0 0 0 99))
        (signals gr8s::cni-error (validate route))))))

;; podster-uqb.121: this ran during CNI DEL or ADD, 12 times in run 13, and ended a node
;; session each time. Once that session did not end for 5 minutes.
(test host-route-validation-tolerates-pods-coming-and-going-while-it-reads
  (with-temporary-store (store path)
    (values store)
    (let* ((node-root (merge-pathnames "node/" path))
           (network (pool-test-network nil ""))
           (ipam (gr8s::open-node-ipam (merge-pathnames "ipam/" node-root) "10.80.0.0/20"))
           (address (gr8s::allocate-pod-address ipam "held" "eth0"))
           (route (list :cidr (format nil "~A/32" address) :index 7 :table 254))
           (context (gr8s::make-cni-context :container-id "added" :interface-name "eth0"))
           (owner (gr8s::routed-cni-owner context))
           (attributes (pool-test-link-attributes
                        (gr8s::routed-cni-host-name context) owner
                        (gr8s::routed-veth-mac owner "host") "veth"))
           (link-gone (lambda (index) (declare (ignore index)) (gr8s::fail-rtnetlink "link lookup" 19))))
      (gr8s::write-private-text-atomically (merge-pathnames "network.json" node-root)
                                           (com.inuoe.jzon:stringify network))
      (flet ((validate (route-reader link-reader)
               (gr8s::validate-pod-pool-host-routes
                "10.80.0.0/12" node-root :route-reader route-reader :link-reader link-reader)))
        ;; DEL removed the link after the route dump, and its lease is still held.
        (is-true (validate (lambda () (list route)) link-gone))
        ;; DEL also released the lease by the time the journal is next read.
        (is-true (validate (lambda ()
                             (gr8s::release-pod-address ipam "held" "eth0")
                             (list route))
                           link-gone))
        ;; ADD persisted its lease and installed its route after the journal was first read.
        (is-true (validate (lambda ()
                             (list (list :cidr (format nil "~A/32" (gr8s::allocate-pod-address ipam "added" "eth0"))
                                         :index 8 :table 254)))
                           (lambda (index) (is (= 8 index)) attributes)))
        ;; With no lease on either side a route is foreign, whatever its link is doing.
        (let ((foreign '(:cidr "10.80.9.9/32" :index 7 :table 254)))
          (signals gr8s::cni-error (validate (lambda () (list foreign)) link-gone))
          (signals gr8s::cni-error (validate (lambda () (list foreign)) (lambda (index) (declare (ignore index)) attributes))))
        ;; Only a link that has gone is excused. Failing to read one proves nothing.
        (let ((held (list :cidr (format nil "~A/32" (gr8s::allocate-pod-address ipam "kept" "eth0")) :index 7 :table 254)))
          (signals gr8s::cni-error
            (validate (lambda () (list held))
                      (lambda (index) (declare (ignore index)) (gr8s::fail-rtnetlink "link lookup" 1)))))))))

(test pending-and-applied-vxlan-identities-both-survive-host-route-validation
  (with-temporary-store (store path)
    (values store)
    (let* ((route (make-instance 'gr8s.node.v1::node-route :node-id "peer"
                                :pod-cidr "10.80.16.0/20" :underlay-address "192.0.2.2"))
           (old (pool-test-network (list route)))
           (new (pool-test-network (list route) "192.0.2.3"))
           (attributes nil))
      (gr8s::write-private-text-atomically (merge-pathnames "network.json" path) (com.inuoe.jzon:stringify old))
      (gr8s::write-private-text-atomically (merge-pathnames "network-pending.json" path) (com.inuoe.jzon:stringify new))
      (flet ((validate ()
               (gr8s::validate-pod-pool-host-routes
                "10.80.0.0/12" path
                :route-reader (lambda () '((:cidr "10.80.16.0/20" :index 9 :table 254)))
                :link-reader (lambda (index) (declare (ignore index)) attributes))))
        (dolist (network (list old new))
          (setf attributes (pool-test-link-attributes
                            "gr8s-vxlan" (gr8s::node-vxlan-owner network)
                            (gr8s::vxlan-router-mac "10.80.0.0/20") "vxlan" network))
          (is-true (validate)))
        (let ((unowned (pool-test-network (list route) "192.0.2.9")))
          (setf attributes (pool-test-link-attributes
                            "gr8s-vxlan" "" (gr8s::vxlan-router-mac "10.80.0.0/20") "vxlan" unowned))
          (signals gr8s::cni-error (validate)))))))
