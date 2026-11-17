;;;; SPDX-FileCopyrightText: 2026 gr8s contributors
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Verify durable pool geometry, legacy assignment compatibility, CLI settings,
;;;; reserved-range rejection and collision-free allocation across prefix sizes.

(in-package #:gr8s/tests)
(in-suite gr8s)

(defun ensure-test-controller-node-pool (store path options)
  "Test pool persistence without depending on the machine's actual host routes."
  (gr8s.agent::ensure-controller-node-pool store path options :route-reader (constantly nil)))

(test pod-pool-defaults-support-256-nodes-with-fixed-20-bit-blocks
  (with-temporary-store (store path)
    (let* ((options (parse-cli-options '("serve")))
           (pool (ensure-test-controller-node-pool store path options)))
      (is (string= "10.80.0.0/12" (gethash "clusterPodCIDR" pool)))
      (is (= 20 (gethash "nodePrefix" pool)))
      (is (string= "10.80.0.0/20" (gr8s.controllers::allocate-node-pod-cidr store "10.80.0.0/12" 20)))
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
           (node-cidr (gr8s.controllers::allocate-node-pod-cidr store "10.112.0.0/12" 22)))
      (gr8s.controllers::register-node store (make-test-node "worker" "node-1" node-cidr))
      (is (string= "10.112.0.0/22" node-cidr))
      (is (equalp pool (ensure-test-controller-node-pool
                       (open-store path) path (parse-cli-options '("serve")))))
      (let ((original (uiop:read-file-string (merge-pathnames "network/pool.json" path))))
        (signals gr8s.network::cni-error
          (ensure-test-controller-node-pool
           store path (parse-cli-options '("serve" "--cluster-pod-cidr" "10.128.0.0/12"))))
        (signals gr8s.network::cni-error
          (ensure-test-controller-node-pool
           store path (parse-cli-options '("serve" "--node-pod-prefix" "20"))))
        (is (string= original (uiop:read-file-string (merge-pathnames "network/pool.json" path))))
        (is (string= node-cidr (gr8s.model::node-record-pod-cidr (gr8s.controllers::get-node store "worker"))))))))

(test explicit-dual-stack-pool-persists-both-family-geometries
  (with-temporary-store (store path)
    (let* ((options (parse-cli-options
                     '("serve" "--cluster-pod-cidr" "10.112.0.0/12,fd70::/48"
                       "--node-pod-prefix" "22" "--node-pod-prefix-ipv6" "64")))
           (pool (ensure-test-controller-node-pool store path options)))
      (is (equalp #("10.112.0.0/12" "fd70::/48")
                  (gr8s.agent::node-pool-cluster-cidrs pool)))
      (is (equalp #(22 64) (gr8s.agent::node-pool-prefixes pool)))
      (is (equalp pool (ensure-test-controller-node-pool
                        (open-store path) path (parse-cli-options '("serve"))))))))

(test explicit-dual-stack-pool-derives-default-prefix-for-every-family
  (with-temporary-store (store path)
    (let ((pool (ensure-test-controller-node-pool
                 store path
                 (parse-cli-options
                  '("serve" "--cluster-pod-cidr" "10.112.0.0/12,fd70::/48")))))
      (is (equalp #("10.112.0.0/12" "fd70::/48")
                  (gr8s.agent::node-pool-cluster-cidrs pool)))
      (is (equalp #(20 64) (gr8s.agent::node-pool-prefixes pool))))))

(test previous-default-pool-and-node-identities-survive-upgrade
  (with-temporary-store (store path)
    (gr8s.controllers::register-node store (make-test-node "old-worker" "old-node" "10.88.3.0/24"))
    (let ((pool (ensure-test-controller-node-pool store path (parse-cli-options '("serve")))))
      (is (string= "10.88.0.0/16" (gethash "clusterPodCIDR" pool)))
      (is (= 24 (gethash "nodePrefix" pool)))
      (is (string= "10.88.3.0/24" (gr8s.model::node-record-pod-cidr (gr8s.controllers::get-node store "old-worker"))))
      (is (equalp pool (ensure-test-controller-node-pool
                       (open-store path) path (parse-cli-options '("serve"))))))))

(test existing-custom-node-blocks-require-explicit-pool-adoption
  (with-temporary-store (store path)
    (gr8s.controllers::register-node store (make-test-node "custom-worker" "custom-node" "10.112.16.0/20"))
    (signals gr8s.network::cni-error
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
    (signals gr8s.network::cni-error
      (gr8s.agent::validate-node-pool-config (apply #'gr8s.agent::make-node-pool-config parameters))))
  (dolist (prefix '("0" "31" "garbage"))
    (signals error (parse-cli-options (list "serve" "--node-pod-prefix" prefix)))))

(test allocator-skips-overlapping-blocks-with-different-prefixes
  (with-temporary-store (store path)
    (values path)
    (gr8s.controllers::register-node store (make-test-node "narrow" "node-1" "10.80.8.0/21"))
    (is (string= "10.80.16.0/20" (gr8s.controllers::allocate-node-pod-cidr store "10.80.0.0/12" 20))))
  (is-true (gr8s.controllers::ipv4-prefixes-overlap-p "10.80.0.0/12" "10.95.255.255/32"))
  (is-false (gr8s.controllers::ipv4-prefixes-overlap-p "10.80.0.0/12" "10.96.0.0/32")))

(test dual-stack-node-block-allocation-is-stable-and-family-independent
  (with-temporary-store (store path)
    (values path)
    (let ((first (gr8s.controllers::allocate-node-pod-cidrs
                  store '("10.80.0.0/12" "fd80::/48") '(20 64))))
      (is (equalp #("10.80.0.0/20" "fd80::/64") first))
      (gr8s.controllers::register-node
       store (gr8s.model::make-node-record :id "node-1" :name "worker-1"
                                    :pod-cidr (aref first 0) :pod-cidrs first)))
    (let ((second (gr8s.controllers::allocate-node-pod-cidrs
                   store '("10.80.0.0/12" "fd80::/48") '(20 64))))
      (is (equalp #("10.80.16.0/20" "fd80:0:0:1::/64") second))
      ;; Reopening the committed state chooses the same next pair.
      (is (equalp second
                  (gr8s.controllers::allocate-node-pod-cidrs
                   (open-store path) '("10.80.0.0/12" "fd80::/48") '(20 64)))))))

(defun pool-test-network (routes &optional (underlay "192.0.2.1"))
  "Create a canonical durable network object for route-ownership tests."
  (gr8s.agent::node-network-object
   (make-instance 'gr8s.node.v1::node-network-config
                  :cluster-pod-cidr "10.80.0.0/12" :node-pod-cidr "10.80.0.0/20"
                  :underlay-address underlay :dns-address "169.254.1.1" :mtu 1450 :vni 42)
   routes))

(defun dual-pool-test-network ()
  "Create a canonical dual-family network object for route-ownership tests."
  (gr8s.agent::node-network-object
   (make-instance 'gr8s.node.v1::node-network-config
                  :cluster-pod-cidr "10.80.0.0/12"
                  :node-pod-cidr "10.80.0.0/20"
                  :cluster-pod-cidrs '("10.80.0.0/12" "fd80::/48")
                  :node-pod-cidrs '("10.80.0.0/20" "fd80::/64")
                  :underlay-address "" :dns-address "169.254.1.1" :mtu 1450 :vni 42)
   nil))

(defun pool-test-link-attributes (name owner mac kind &optional network)
  "Model Linux link identity attributes, including nested VXLAN parameters."
  (let ((attributes (make-hash-table)))
    (setf (gethash 3 attributes) (cl-rtnetlink::netlink-string name)
          (gethash 20 attributes) (cl-rtnetlink::netlink-string owner)
          (gethash 1 attributes) mac
          (gethash 18 attributes)
          (cl-rtnetlink::netlink-octets
           (cl-rtnetlink::netlink-attribute 1 (cl-rtnetlink::netlink-string kind))
           (if network
               (cl-rtnetlink::netlink-attribute
                2 (cl-rtnetlink::netlink-octets
                   (cl-rtnetlink::netlink-attribute 1 (cl-rtnetlink::netlink-integer (gethash "vni" network) 4))
                   (cl-rtnetlink::netlink-attribute 4 (cl-rtnetlink::ipv4-network-octets (gethash "underlayAddress" network)))
                   (cl-rtnetlink::netlink-attribute 15 #(18 181))))
               #())))
    attributes))

(test host-route-conflicts-include-host-and-policy-table-routes
  (with-temporary-store (store path)
    (dolist (route '((:cidr "10.84.0.0/24" :index 7 :table 254)
                     (:cidr "10.95.255.255/32" :index 7 :table 255)
                     (:cidr "10.80.0.0/16" :index 0 :table 100)))
      (signals gr8s.network::cni-error
        (gr8s.agent::ensure-controller-node-pool
         store path (parse-cli-options '("serve"))
         :route-reader (lambda () (list route)))))
    (is-false (probe-file (merge-pathnames "network/pool.json" path)))
    (is-true
     (gr8s.agent::validate-pod-pool-host-routes
      "10.80.0.0/12" path :route-reader
      (lambda () '((:cidr "0.0.0.0/0" :index 2 :table 254)
                    (:cidr "192.0.2.0/24" :index 2 :table 254)))))))

(test only-exact-journal-owned-pod-routes-are-exempt-from-overlap-rejection
  (with-temporary-store (store path)
    (values store)
    (let* ((node-root (merge-pathnames "node/" path))
           (network (pool-test-network nil ""))
           (ipam (gr8s.network::open-node-ipam (merge-pathnames "ipam/" node-root) "10.80.0.0/20"))
           (address (gr8s.network::allocate-pod-address ipam "owned-sandbox" "eth0"))
           (context (gr8s.network::make-cni-context :container-id "owned-sandbox" :interface-name "eth0"))
           (owner (gr8s.network::routed-cni-owner context))
           (attributes (pool-test-link-attributes
                        (gr8s.network::routed-cni-host-name context) owner
                        (gr8s.network::routed-veth-mac owner "host") "veth"))
           (route (list :cidr (format nil "~A/32" address) :index 7 :table 254)))
      (gr8s.security::write-private-text-atomically (merge-pathnames "network.json" node-root)
                                         (com.inuoe.jzon:stringify network))
      (flet ((validate (route)
               (gr8s.agent::validate-pod-pool-host-routes
                "10.80.0.0/12" node-root :route-reader (lambda () (list route))
                :link-reader (lambda (index) (is (= 7 index)) attributes))))
        (is-true (validate route))
        ;; Owning a link does not authorize a wider or different destination.
        (signals gr8s.network::cni-error (validate '(:cidr "10.80.0.0/20" :index 7 :table 254)))
        (signals gr8s.network::cni-error (validate '(:cidr "10.80.0.2/32" :index 7 :table 254)))
        (setf (gethash 20 attributes) (cl-rtnetlink::netlink-string "foreign-owner"))
        (signals gr8s.network::cni-error (validate route))
        (setf (gethash 20 attributes) (cl-rtnetlink::netlink-string owner)
              (gethash 1 attributes) #(2 0 0 0 0 99))
        (signals gr8s.network::cni-error (validate route))))))

(test dual-stack-pod-route-identities-survive-restart
  (with-temporary-store (store path)
    (values store)
    (let* ((node-root (merge-pathnames "node/" path))
           (network (dual-pool-test-network))
           (ipam (gr8s.network::open-node-ipam
                  (merge-pathnames "ipam/" node-root)
                  '("10.80.0.0/20" "fd80::/64")))
           (addresses (gr8s.network::allocate-pod-addresses ipam "dual-sandbox" "eth0"))
           (context (gr8s.network::make-cni-context
                     :container-id "dual-sandbox" :interface-name "eth0"))
           (owner (gr8s.network::routed-cni-owner context)))
      (gr8s.security::write-private-text-atomically
       (merge-pathnames "network.json" node-root)
       (com.inuoe.jzon:stringify network))
      (let ((identities (gr8s.agent::persisted-node-route-identities node-root)))
        (is (= 2 (length identities)))
        (is (equal '("10.80.0.1/32" "fd80::1/128")
                   (mapcar (lambda (identity) (getf identity :cidr))
                           (reverse identities))))
        (is (every (lambda (identity)
                     (and (string= owner (getf identity :owner))
                          (string= (gr8s.network::routed-cni-host-name context)
                                   (getf identity :name))))
                   identities))
        (is (equal addresses '("10.80.0.1" "fd80::1")))))))

(test dual-stack-overlay-route-identities-survive-restart
  (with-temporary-store (store path)
    (values store)
    (let* ((node-root (merge-pathnames "node-overlay/" path))
           (network (dual-pool-test-network))
           (route (gr8s.foundation::json-object
                   "nodeID" "peer" "podCIDR" "10.80.16.0/20"
                   "podCIDRs" (vector "10.80.16.0/20" "fd80:0:0:1::/64")
                   "underlayAddress" "192.0.2.2")))
      (setf (gethash "underlayAddress" network) "192.0.2.1"
            (gethash "routes" network) (vector route))
      (gr8s.security::write-private-text-atomically
       (merge-pathnames "network.json" node-root)
       (com.inuoe.jzon:stringify network))
      (let ((cidrs (mapcar (lambda (identity) (getf identity :cidr))
                           (gr8s.agent::persisted-node-route-identities node-root))))
        (dolist (cidr '("10.80.0.0/32" "fd80::/128"
                        "10.80.16.0/20" "10.80.16.0/32"
                        "fd80:0:0:1::/64" "fd80:0:0:1::/128"))
          (is (member cidr cidrs :test #'string=) "missing route identity ~A" cidr))))))

;; podster-uqb.121: this ran during CNI DEL or ADD, 12 times in run 13, and ended a node
;; session each time. Once that session did not end for 5 minutes.
(test host-route-validation-tolerates-pods-coming-and-going-while-it-reads
  (with-temporary-store (store path)
    (values store)
    (let* ((node-root (merge-pathnames "node/" path))
           (network (pool-test-network nil ""))
           (ipam (gr8s.network::open-node-ipam (merge-pathnames "ipam/" node-root) "10.80.0.0/20"))
           (address (gr8s.network::allocate-pod-address ipam "held" "eth0"))
           (route (list :cidr (format nil "~A/32" address) :index 7 :table 254))
           (context (gr8s.network::make-cni-context :container-id "added" :interface-name "eth0"))
           (owner (gr8s.network::routed-cni-owner context))
           (attributes (pool-test-link-attributes
                        (gr8s.network::routed-cni-host-name context) owner
                        (gr8s.network::routed-veth-mac owner "host") "veth"))
           (link-gone (lambda (index) (declare (ignore index)) (cl-rtnetlink::fail-rtnetlink "link lookup" 19))))
      (gr8s.security::write-private-text-atomically (merge-pathnames "network.json" node-root)
                                           (com.inuoe.jzon:stringify network))
      (flet ((validate (route-reader link-reader)
               (gr8s.agent::validate-pod-pool-host-routes
                "10.80.0.0/12" node-root :route-reader route-reader :link-reader link-reader)))
        ;; DEL removed the link after the route dump, and its lease is still held.
        (is-true (validate (lambda () (list route)) link-gone))
        ;; DEL also released the lease by the time the journal is next read.
        (is-true (validate (lambda ()
                             (gr8s.network::release-pod-address ipam "held" "eth0")
                             (list route))
                           link-gone))
        ;; ADD persisted its lease and installed its route after the journal was first read.
        (is-true (validate (lambda ()
                             (list (list :cidr (format nil "~A/32" (gr8s.network::allocate-pod-address ipam "added" "eth0"))
                                         :index 8 :table 254)))
                           (lambda (index) (is (= 8 index)) attributes)))
        ;; With no lease on either side a route is foreign, whatever its link is doing.
        (let ((foreign '(:cidr "10.80.9.9/32" :index 7 :table 254)))
          (signals gr8s.network::cni-error (validate (lambda () (list foreign)) link-gone))
          (signals gr8s.network::cni-error (validate (lambda () (list foreign)) (lambda (index) (declare (ignore index)) attributes))))
        ;; Only a link that has gone is excused. Failing to read one proves nothing.
        (let ((held (list :cidr (format nil "~A/32" (gr8s.network::allocate-pod-address ipam "kept" "eth0")) :index 7 :table 254)))
          (signals gr8s.network::cni-error
            (validate (lambda () (list held))
                      (lambda (index) (declare (ignore index)) (cl-rtnetlink::fail-rtnetlink "link lookup" 1)))))))))

(test host-route-validation-rejects-foreign-ipv6-pod-routes
  (with-temporary-store (store path)
    (values store)
    (signals gr8s.network::cni-error
      (gr8s.agent::validate-pod-pool-host-routes
       '("10.80.0.0/12" "fd80::/48") path
       :route-reader (lambda () '((:cidr "fd80::1234/128" :index 7 :table 254)))
       :link-reader (lambda (index) (declare (ignore index)) nil)))))

(test pending-and-applied-vxlan-identities-both-survive-host-route-validation
  (with-temporary-store (store path)
    (values store)
    (let* ((route (make-instance 'gr8s.node.v1::node-route :node-id "peer"
                                :pod-cidr "10.80.16.0/20" :underlay-address "192.0.2.2"))
           (old (pool-test-network (list route)))
           (new (pool-test-network (list route) "192.0.2.3"))
           (attributes nil))
      (gr8s.security::write-private-text-atomically (merge-pathnames "network.json" path) (com.inuoe.jzon:stringify old))
      (gr8s.security::write-private-text-atomically (merge-pathnames "network-pending.json" path) (com.inuoe.jzon:stringify new))
      (flet ((validate ()
               (gr8s.agent::validate-pod-pool-host-routes
                "10.80.0.0/12" path
                :route-reader (lambda () '((:cidr "10.80.16.0/20" :index 9 :table 254)))
                :link-reader (lambda (index) (declare (ignore index)) attributes))))
        (dolist (network (list old new))
          (setf attributes (pool-test-link-attributes
                            "gr8s-vxlan" (gr8s.network::node-vxlan-owner network)
                            (gr8s.network::vxlan-router-mac "10.80.0.0/20") "vxlan" network))
          (is-true (validate)))
        (let ((unowned (pool-test-network (list route) "192.0.2.9")))
          (setf attributes (pool-test-link-attributes
                            "gr8s-vxlan" "" (gr8s.network::vxlan-router-mac "10.80.0.0/20") "vxlan" unowned))
          (signals gr8s.network::cni-error (validate)))))))

(test owned-wireguard-router-address-survives-host-route-validation
  (with-temporary-store (store path)
    (values store)
    (let* ((network (pool-test-network nil))
           (route '(:cidr "10.80.0.0/32" :index 11 :table 255)))
      (setf (gethash "overlayBackend" network) "wireguard"
            (gethash "wireguardListenPort" network) 51820)
      (gr8s.security::write-private-text-atomically
       (merge-pathnames "network.json" path) (com.inuoe.jzon:stringify network))
      (is-true
       (gr8s.agent::validate-pod-pool-host-routes
        "10.80.0.0/12" path
        :route-reader (lambda () (list route))
        :link-reader
        (lambda (index)
          (is (= 11 index))
          (pool-test-link-attributes
           "gr8s-wg" (gr8s.network::node-wireguard-owner network) nil "wireguard")))))))

(test service-translation-route-ownership-restores-private-ipam-leases
  (with-temporary-store (store path)
    (declare (ignore store))
    (let* ((root (merge-pathnames "translation-routes/" path))
           (network (dual-pool-test-network))
           (ipam (gr8s.network::open-node-ipam (merge-pathnames "ipam/" root)
                                      '("10.80.0.0/20" "fd80::/64")))
           (addresses (gr8s.network::allocate-pod-addresses ipam "translation-sandbox" "eth0"))
           (alias (gr8s.network::allocate-service-snat-address ipam "translation-sandbox" "eth0"))
           (context (gr8s.network::make-cni-context :container-id "translation-sandbox" :interface-name "eth0")))
      (gr8s.security::write-private-text-atomically (merge-pathnames "network.json" root)
                                        (com.inuoe.jzon:stringify network))
      (let* ((identities (gr8s.agent::persisted-node-route-identities root))
             (cidrs (mapcar (lambda (row) (getf row :cidr)) identities)))
        (is (= 3 (length identities)))
        (is (member (format nil "~A/32" alias) cidrs :test #'equal))
        (is (every (lambda (row)
                     (and (equal (getf row :owner) (gr8s.network::routed-cni-owner context))
                          (equal (getf row :name) (gr8s.network::routed-cni-host-name context)))) identities))
        (is (equal '("10.80.0.1" "fd80::1") addresses)))
      ;; A private lease cannot gain route ownership merely by naming the pool.
      (let* ((state (gr8s.network::node-ipam-state-object ipam))
             (record (aref (gethash "serviceSNATAllocations" state) 0)))
        (setf (gethash "address" record) (first addresses))
        (with-open-file (s (gr8s.network::node-ipam-state-path ipam) :direction :output :if-exists :supersede)
          (com.inuoe.jzon:stringify state :stream s))
        (signals gr8s.network::cni-error (gr8s.agent::persisted-node-route-identities root))))))

;;; podster-a5g: the refusal must name the offending link so an operator (or
;;; `gr8s doctor --fix`) knows what to delete, instead of a bare CIDR.

(test host-route-violations-name-the-offending-interface
  (with-temporary-store (store path)
    (values store)
    (let* ((attributes (pool-test-link-attributes
                        "gr8s-vxlan" "gr8s:vxlan:stale" #(2 0 0 0 0 1) "vxlan"))
           (route-reader (lambda () '((:cidr "10.80.0.0/32" :index 7 :table 255))))
           (link-reader (lambda (index) (declare (ignore index)) attributes)))
      (let ((violations (gr8s.agent::pod-pool-host-route-violations
                         "10.80.0.0/12" path
                         :route-reader route-reader :link-reader link-reader)))
        (is (= 1 (length violations)))
        (let ((violation (first violations)))
          (is (equal "10.80.0.0/32" (getf violation :cidr)))
          (is (eql 255 (getf violation :table)))
          (is (equal "gr8s-vxlan" (getf violation :interface)))
          (is (eq attributes (getf violation :attributes)))))
      (handler-case
          (progn (gr8s.agent::validate-pod-pool-host-routes
                  "10.80.0.0/12" path
                  :route-reader route-reader :link-reader link-reader)
                 (fail "an overlapping stale route must be refused"))
        (gr8s.network::cni-error (condition)
          (let ((text (princ-to-string condition)))
            (is (search "interface gr8s-vxlan" text))
            (is (search "doctor --fix" text)))))
      ;; A clean host reports no violations.
      (is (null (gr8s.agent::pod-pool-host-route-violations
                 "10.80.0.0/12" path
                 :route-reader (lambda () '((:cidr "192.0.2.0/24" :index 2 :table 254)))
                 :link-reader link-reader))))))
