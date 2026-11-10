(in-package #:gr8s/tests)

(in-suite gr8s)

(test rtnetlink-acknowledgements-and-kernel-errors
  (let ((ack (gr8s::netlink-message 2 0 (gr8s::netlink-integer 0 4))))
    (multiple-value-bind (messages acknowledged)
        (gr8s::parse-netlink-reply ack (length ack) 1)
      (is (null messages))
      (is (eq t acknowledged))))
  (let ((failure (gr8s::netlink-message
                  2 0 (gr8s::netlink-integer -1 4))))
    (handler-case
        (progn
          (gr8s::parse-netlink-reply failure (length failure) 1)
          (fail "kernel EPERM must fail the transaction"))
      (gr8s::rtnetlink-error (condition)
        (is (= 1 (gr8s::rtnetlink-error-errno condition)))))))

(test rtnetlink-rejects-truncated-and-malformed-replies
  (signals gr8s::cni-error
    (gr8s::parse-netlink-reply #(0 0 0) 3 1))
  (let ((message (gr8s::netlink-message 2 0 #())))
    (signals gr8s::cni-error
      (gr8s::parse-netlink-reply message (length message) 1)))
  (let ((message (gr8s::netlink-message 16 0 #(1 2 3 4))))
    (signals gr8s::cni-error
      (gr8s::parse-netlink-reply message (1- (length message)) 1))))

(test rtnetlink-correlates-replies-and-keeps-data-before-ack
  (let* ((unrelated (gr8s::netlink-message 2 0
                      (gr8s::netlink-integer -1 4) 2))
         (data (gr8s::netlink-message 16 0 #(1 2 3 4)))
         (ack (gr8s::netlink-message 2 0 (gr8s::netlink-integer 0 4)))
         (batch (gr8s::netlink-octets unrelated data ack)))
    (multiple-value-bind (messages acknowledged)
        (gr8s::parse-netlink-reply batch (length batch) 1)
      (is-true acknowledged)
      (is (= 1 (length messages)))
      (is (equalp data (first messages))))))

(test routed-endpoint-names-are-stable-and-separated-by-owner
  (let ((name (gr8s::routed-veth-name "sandbox-a" "eth0")))
    (is (= 15 (length name)))
    (is (string= name (gr8s::routed-veth-name "sandbox-a" "eth0")))
    (is (not (string= name (gr8s::routed-veth-name "sandbox-b" "eth0"))))
    (is (not (string= name (gr8s::routed-veth-name "sandbox-a" "eth1"))))))

(test rtnetlink-interface-names-and-addresses-are-validated
  (dolist (name '("" "." ".." "veth/unsafe" "a b" "1234567890123456"))
    (signals gr8s::cni-error (gr8s::validate-network-interface-name name)))
  (is (equalp #(192 0 2 17) (gr8s::ipv4-network-octets "192.0.2.17"))))

(test rtnetlink-encodes-both-ip-address-families
  (multiple-value-bind (family bytes bits)
      (gr8s::network-address-wire-values "192.0.2.17")
    (is (= 2 family))
    (is (= 32 bits))
    (is (equalp #(192 0 2 17) bytes)))
  (multiple-value-bind (family bytes bits)
      (gr8s::network-address-wire-values "fd42::17")
    (is (= 10 family))
    (is (= 128 bits))
    (is (= 16 (length bytes)))
    (is (equalp (0conf:parse-ipv6 "fd42::17") bytes))))

(test routed-veth-retains-interface-scoped-ipv6-gateway
  (is (null (gr8s::veth-scoped-gateway-addresses '("169.254.1.1"))))
  (is (equal '("fe80::1")
             (gr8s::veth-scoped-gateway-addresses
              '("169.254.1.1" "fe80::1")))))

(test rtnetlink-decodes-abbreviated-network-prefixes-at-the-high-order-end
  ;; RTA_DST is permitted to omit trailing zero octets. Those bytes remain the
  ;; most-significant part of the address, for both address families.
  (is (string= "10.80.0.0"
               (gr8s::format-pod-address
                :ipv4 (gr8s::network-prefix-octets-integer #(10 80) 32))))
  (is (string= "fd80::"
               (gr8s::format-pod-address
                :ipv6 (gr8s::network-prefix-octets-integer #(253 128) 128)))))

(test rtnetlink-reads-real-kernel-link-without-privileges
  ;; This exercises the actual ABI, socket, message parser, and ACK handling.
  ;; RTM_GETLINK is read-only and does not require CAP_NET_ADMIN.
  (let* ((index (gr8s::native-interface-index "lo"))
         (messages
           (gr8s::call-rtnetlink
            18 0 (gr8s::netlink-interface-message :index index))))
    (is (plusp index))
    (is (= 1 (length messages)))
    (is (= 16 (gr8s::netlink-read-integer (first messages) 4 2)))
    (is (= index (gr8s::netlink-read-integer (first messages) 20 4))))
  (is-true (gr8s::network-address-present-p "lo" "::1" 128)))

(test routed-cni-keeps-durable-lease-until-endpoint-cleanup-succeeds
  (let* ((directory (merge-pathnames
                     (format nil "gr8s-routed-cni-~36R/" (random (expt 36 8)))
                     (uiop:temporary-directory)))
         (context (gr8s::make-cni-context
                   :container-id "sandbox-a" :interface-name "eth0"
                   :netns "/fake/netns"))
         (configuration (com.inuoe.jzon:parse *valid-cni-config*))
         (fail-policy t)
         (fail-delete t)
         (events nil))
    (remhash "prevResult" configuration)
    (unwind-protect
         (let* ((ipam (gr8s::open-node-ipam directory "10.42.0.0/29"))
                (policy
                  (gr8s::make-cni-operations
                   :add (lambda (config ctx map-path link-path)
                          (declare (ignore map-path))
                          (is (string= "ingress" (gr8s::cni-configuration-direction config)))
                          (is (string= (gr8s::routed-cni-host-name ctx)
                                       (gr8s::cni-configuration-policy-interface-name config)))
                          (is (string= "tcx-ingress" (file-namestring link-path)))
                          (push :policy-add events)
                          (when fail-policy (error "injected BPF failure")))
                   :check (lambda (&rest args) (declare (ignore args)))
                   :delete (lambda (&rest args)
                             (declare (ignore args))
                             (push :policy-delete events))))
                (operations
                  (gr8s::make-routed-cni-operations
                   ipam :policy policy
                   :install-link (lambda (ctx address)
                                   (declare (ignore ctx address))
                                   (push :link-add events)
                                   "gr-test")
                   :check-link (lambda (&rest args) (declare (ignore args)))
                   :remove-link (lambda (ctx)
                                  (declare (ignore ctx))
                                  (push :link-delete events)
                                  (when fail-delete
                                    (error "injected link deletion failure")))))
                (text (com.inuoe.jzon:stringify configuration)))
           (flet ((invoke (command)
                    (gr8s::dispatch-cni-command command text context operations
                                                :chained nil)))
             (signals error (invoke "ADD"))
             (is (equal '(:link-add :policy-add) (reverse events)))
             ;; Reopening proves the failed ADD lease reached disk.
             (is (string= "10.42.0.1"
                          (gr8s::check-pod-address
                           (gr8s::open-node-ipam directory "10.42.0.0/29")
                           "sandbox-a" "eth0")))
             (setf fail-policy nil)
             (let* ((result (invoke "ADD"))
                    (ip (aref (gethash "ips" result) 0)))
               (is (string= "10.42.0.1/32" (gethash "address" ip)))
               (is (= 1 (gethash "interface" ip))))
             (is (null (invoke "CHECK")))
             (signals error (invoke "DEL"))
             (is (string= "10.42.0.1"
                          (gr8s::check-pod-address ipam "sandbox-a" "eth0")))
             (setf fail-delete nil events nil)
             ;; DEL has no usable namespace after containerd removes it.
             (setf (gr8s::cni-context-netns context) "")
             (is (null (invoke "DEL")))
             (is (equal '(:policy-delete :link-delete) (reverse events)))
             (signals gr8s::cni-error
               (gr8s::check-pod-address
                (gr8s::open-node-ipam directory "10.42.0.0/29")
                "sandbox-a" "eth0"))
             (is (null (invoke "DEL")))))
      (when (probe-file directory)
        (uiop:delete-directory-tree directory :validate t)))))

(test routed-cni-result-describes-both-pod-address-families
  (let* ((context (gr8s::make-cni-context
                   :container-id "sandbox-dual" :interface-name "eth0"
                   :netns "/fake/netns"))
         (configuration (gr8s::parse-cni-configuration *valid-cni-config*))
         (result (gr8s::routed-cni-result
                  configuration context "gr-test"
                  '("10.42.0.1" "fd42::1") "169.254.1.1"))
         (ips (gethash "ips" result))
         (routes (gethash "routes" result)))
    (is (= 2 (length ips)))
    (is (string= "10.42.0.1/32" (gethash "address" (aref ips 0))))
    (is (string= "169.254.1.1" (gethash "gateway" (aref ips 0))))
    (is (string= "fd42::1/128" (gethash "address" (aref ips 1))))
    (is (string= "fe80::1" (gethash "gateway" (aref ips 1))))
    (is (= 1 (gethash "interface" (aref ips 0))))
    (is (= 1 (gethash "interface" (aref ips 1))))
    (is (= 2 (length routes)))
    (is (string= "0.0.0.0/0" (gethash "dst" (aref routes 0))))
    (is (string= "169.254.1.1" (gethash "gw" (aref routes 0))))
    (is (string= "::/0" (gethash "dst" (aref routes 1))))
    (is (string= "fe80::1" (gethash "gw" (aref routes 1))))))

(test service-return-mac-requires-both-endpoint-owners-before-reading-the-peer
  (let* ((context (gr8s::make-cni-context :container-id "return-owner" :interface-name "eth0" :netns "/fake/ns"))
         (mac #(2 1 2 3 4 5)) (reads 0) (namespace-calls 0) (foreign nil))
    (flet ((read-mac ()
             (gr8s::routed-service-return-mac
              context :link-owned (lambda (name owner)
                                    (is (equal (gr8s::routed-cni-owner context) owner))
                                    (not (equal foreign name)))
              :call-in-netns (lambda (ns function)
                               (is (equal "/fake/ns" ns)) (incf namespace-calls) (funcall function))
              :link-attributes (lambda (name)
                                 (is (equal "eth0" name)) (incf reads)
                                 (let ((table (make-hash-table))) (setf (gethash 1 table) mac) table)))))
      (is (equalp mac (read-mac)))
      (setf foreign (gr8s::routed-cni-host-name context))
      (signals gr8s::cni-error (read-mac))
      (is (= 1 namespace-calls))
      (setf foreign "eth0")
      (signals gr8s::cni-error (read-mac))
      (is (= 1 reads))
      (setf foreign nil mac #(2 1))
      (signals gr8s::cni-error (read-mac)))))

(test service-return-route-publication-is-exclusive-and-check-requires-neighbor
  (let* ((context (gr8s::make-cni-context :container-id "return-path" :interface-name "eth0"))
         (host (gr8s::routed-cni-host-name context))
         (mac #(2 1 2 3 4 5)) (events nil) (present nil) (neighbor nil) (fail-route nil))
    (labels ((mac-reader (ctx) (is (eq context ctx)) mac)
             (route-reader (address prefix interface &key source)
               (is (equal "10.42.0.2" address)) (is (= 32 prefix))
               (is (equal host interface)) (is (equal "169.254.1.1" source)) present)
             (install ()
               (gr8s::install-routed-service-return-path
                context "10.42.0.2" :endpoint-mac #'mac-reader :route-present #'route-reader
                :install-neighbor (lambda (interface address value)
                                    (is (equal host interface)) (is (equal "10.42.0.2" address))
                                    (is (equalp mac value)) (push :neighbor events) (setf neighbor t))
                :install-route (lambda (address prefix interface &key source exclusive)
                                 (route-reader address prefix interface :source source)
                                 (is-true exclusive) (push :route events)
                                 (when (eq fail-route :raced) (setf present t))
                                 (when fail-route (gr8s::fail-rtnetlink "private return route" 17))
                                 (setf present t))))
             (check ()
               (gr8s::check-routed-service-return-path
                context "10.42.0.2" :endpoint-mac #'mac-reader :route-present #'route-reader
                :neighbor-present (lambda (interface address value)
                                    (is (equal host interface)) (is (equal "10.42.0.2" address))
                                    (is (equalp mac value)) neighbor))))
      (is (equal "10.42.0.2" (install)))
      (is (equal '(:neighbor :route) (reverse events)))
      (is-true (check))
      (setf events nil)
      (install)
      (is (equal '(:neighbor) events))
      (setf neighbor nil)
      (signals gr8s::cni-error (check))
      (setf present nil fail-route t)
      (signals gr8s::rtnetlink-error (install))
      (is-false present)
      (setf fail-route :raced)
      (is (equal "10.42.0.2" (install)))
      (signals error (gr8s::install-routed-service-return-path context "010.42.0.2")))))

(test packet-cni-private-return-lease-survives-partial-add-check-and-delete
  (with-temporary-store (store directory)
    (declare (ignore store))
    (let* ((context (gr8s::make-cni-context :container-id "return-lease" :interface-name "eth0" :netns "/fake/ns"))
           (object (com.inuoe.jzon:parse *valid-cni-config*))
           (ipam (gr8s::open-node-ipam directory '("fd42::/125" "10.42.0.0/29")))
           (events nil) (failure :policy) (fail-delete t) (fail-check nil)
           (policy
             (gr8s::make-cni-operations
              :add (lambda (config &rest rest)
                     (declare (ignore rest))
                     (is (equal '("fd42::1" "10.42.0.1") (gr8s::cni-configuration-endpoint-addresses config)))
                     (is (equal "node-1" (gr8s::cni-configuration-service-node-id config)))
                     (is (equal "10.42.0.2" (gr8s::cni-configuration-service-return-address config)))
                     (push :policy events) (when (eq failure :policy) (error "policy failed")))
              :check (lambda (config &rest rest)
                       (declare (ignore rest))
                       (is (equal "node-1" (gr8s::cni-configuration-service-node-id config)))
                       (is (equal "10.42.0.2" (gr8s::cni-configuration-service-return-address config)))
                       (push :policy-check events))
              :delete (lambda (&rest rest) (declare (ignore rest)) (push :policy-delete events))))
           (operations
             (gr8s::make-routed-cni-operations
              ipam :node-id "node-1" :policy policy
              :install-link (lambda (ctx addresses)
                              (declare (ignore ctx)) (is (equal '("fd42::1" "10.42.0.1") addresses))
                              (push :link events) "gr-test")
              :check-link (lambda (&rest rest) (declare (ignore rest)) (push :link-check events))
              :install-service-return (lambda (ctx address)
                                        (is (eq context ctx)) (is (equal "10.42.0.2" address))
                                        (push :return events) (when (eq failure :return) (error "route failed")))
              :check-service-return (lambda (ctx address)
                                      (is (eq context ctx)) (is (equal "10.42.0.2" address))
                                      (push :return-check events) (when fail-check (error "neighbor missing")))
              :remove-link (lambda (ctx)
                             (declare (ignore ctx)) (push :delete-link events)
                             (when fail-delete (error "delete failed"))))))
      (remhash "prevResult" object)
      (setf (gethash "servicePacketRoot" object) "/pins/shared/")
      (labels ((invoke (command)
                 (gr8s::dispatch-cni-command command (com.inuoe.jzon:stringify object) context operations :chained nil))
               (retained ()
                 (gr8s::service-snat-address
                  (gr8s::open-node-ipam directory '("fd42::/125" "10.42.0.0/29")) "return-lease" "eth0")))
        (signals error (invoke "ADD"))
        (is (equal '(:link :policy) (reverse events)))
        (is (equal "10.42.0.2" (retained)))
        (setf events nil failure :return)
        (signals error (invoke "ADD"))
        (is (equal '(:link :policy :return) (reverse events)))
        (is (equal "10.42.0.2" (retained)))
        (setf failure nil)
        (let ((result (invoke "ADD")))
          (is (= 2 (length (gethash "ips" result))))
          (is-false (search "10.42.0.2" (com.inuoe.jzon:stringify result))))
        (setf events nil fail-check t)
        (signals error (invoke "CHECK"))
        (is (equal '(:link-check :policy-check :return-check) (reverse events)))
        (setf fail-check nil)
        (is (null (invoke "CHECK")))
        (signals error (invoke "DEL"))
        (is (equal "10.42.0.2" (retained)))
        (setf fail-delete nil events nil)
        (is (null (invoke "DEL")))
        (is (equal '(:policy-delete :delete-link) (reverse events)))
        (is (null (retained)))))))

(test cni-return-path-keeps-default-and-ipv6-only-allocation-behavior
  (dolist (scenario '(("10.42.0.0/29" nil nil) ("fd42::/125" t nil) ("10.42.0.0/29" nil t)))
    (destructuring-bind (cidr packet-p retained-p) scenario
      (with-temporary-store (store directory)
        (declare (ignore store))
        (let* ((ipam (gr8s::open-node-ipam directory cidr))
               (context (gr8s::make-cni-context :container-id "optional-return" :interface-name "eth0" :netns "/fake/ns"))
               (config (gr8s::parse-cni-configuration *valid-cni-config*))
               (installed 0) (checked 0)
               (policy (gr8s::make-cni-operations :add (lambda (&rest args) (declare (ignore args)))
                                                  :check (lambda (&rest args) (declare (ignore args)))))
               (operations
                 (gr8s::make-routed-cni-operations
                  ipam :policy policy :install-link (lambda (&rest args) (declare (ignore args)) "gr-test")
                  :check-link (lambda (&rest args) (declare (ignore args)))
                  :install-service-return (lambda (&rest args) (declare (ignore args)) (incf installed))
                  :check-service-return (lambda (&rest args) (declare (ignore args)) (incf checked)))))
          (when packet-p (setf (gr8s::cni-configuration-service-packet-root config) "/pins/shared/"))
          (when retained-p
            (gr8s::allocate-pod-addresses ipam "optional-return" "eth0")
            (gr8s::allocate-service-snat-address ipam "optional-return" "eth0"))
          (funcall (gr8s::cni-operations-add operations) config context "/pins/map" "/pins/link")
          (funcall (gr8s::cni-operations-check operations) config context "/pins/map" "/pins/link")
          (is (= (if retained-p 1 0) installed))
          (is (= (if retained-p 1 0) checked))
          (is (= (if retained-p 1 0) (hash-table-count (gr8s::node-ipam-service-snat-allocations ipam))))
          (is (= 1 (length (gr8s::cni-configuration-endpoint-addresses config)))))))))
