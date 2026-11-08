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
