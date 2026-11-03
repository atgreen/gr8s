(in-package #:gr8s)

(defparameter +node-vxlan-interface+ "gr8s-vxlan")

(defun vxlan-router-address (pod-cidr)
  ;; IPAM excludes the network address. Use that reserved /32 as the node's
  ;; overlay router address, without consuming any Pod allocation.
  (multiple-value-bind (address prefix) (parse-ipv4-cidr pod-cidr)
    (declare (ignore prefix))
    (format-ipv4-integer address)))

(defun vxlan-router-mac (pod-cidr)
  (netlink-octets
   #(2) ; locally administered, unicast
   (subseq (ironclad:digest-sequence
            :sha256 (trivial-utf-8:string-to-utf-8-bytes pod-cidr)) 0 5)))

(defun create-node-vxlan (local-address pod-cidr vni mtu)
  (call-rtnetlink
   16 #x600
   (netlink-octets
    (netlink-interface-message)
    (netlink-attribute 3 (netlink-string +node-vxlan-interface+))
    (netlink-attribute 1 (vxlan-router-mac pod-cidr))
    (netlink-attribute 4 (netlink-integer mtu 4))
    (netlink-attribute
     18 (netlink-octets
         (netlink-attribute 1 (netlink-string "vxlan"))
         (netlink-attribute
          #x8002 (netlink-octets
                  (netlink-attribute 1 (netlink-integer vni 4))
                  (netlink-attribute 4 (ipv4-network-octets local-address))
                  (netlink-attribute 7 #(0)) ; disable dynamic MAC learning
                  (netlink-attribute 15 #(18 181))))))))) ; UDP port 4789

(defun node-vxlan-owned-or-adoptable-p (network)
  (let* ((name +node-vxlan-interface+)
         (owner (node-vxlan-owner network))
         (attributes (network-link-attributes name))
         (info (gethash 18 attributes))
         (data (and info (gethash 2 (netlink-attributes info 0))))
         (vxlan (and data (netlink-attributes data 0))))
    (cond
      ((equalp (gethash 20 attributes) (netlink-string owner)) t)
      ((and vxlan
            (plusp (length (gethash "underlayAddress" network "")))
            (network-link-untagged-p attributes)
            (network-link-kind-p attributes "vxlan")
            (equalp (gethash 1 attributes) (vxlan-router-mac (gethash "nodePodCIDR" network)))
            (equalp (gethash 1 vxlan) (netlink-integer (gethash "vni" network) 4))
            (equalp (gethash 4 vxlan) (ipv4-network-octets (gethash "underlayAddress" network)))
            (equalp (gethash 15 vxlan) #(18 181)))
       (set-network-link-owner name owner)
       t))))

(defun ensure-node-vxlan (local-address pod-cidr vni mtu)
  (let ((owner (format nil "gr8s:vxlan:~A:~D:~A" pod-cidr vni local-address)))
    (when (zerop (native-interface-index +node-vxlan-interface+))
      (create-node-vxlan local-address pod-cidr vni mtu)
      (handler-case
          (set-network-link-owner +node-vxlan-interface+ owner)
        (error (condition)
          (ignore-errors (delete-network-link +node-vxlan-interface+))
          (error condition))))
    (unless (node-vxlan-owned-or-adoptable-p
             (json-object "nodePodCIDR" pod-cidr "vni" vni "underlayAddress" local-address))
      (invalid-cni "VXLAN interface belongs to another node network"))
    (set-network-link-mtu +node-vxlan-interface+ mtu)
    (add-network-address +node-vxlan-interface+ (vxlan-router-address pod-cidr) 32)
    (set-network-link-up +node-vxlan-interface+)
    (enable-node-ipv4-forwarding))
  +node-vxlan-interface+)

(defun replace-vxlan-peer (pod-cidr underlay-address)
  (let ((interface +node-vxlan-interface+)
        (router (vxlan-router-address pod-cidr))
        (mac (vxlan-router-mac pod-cidr)))
    ;; AF_BRIDGE FDB: remote router MAC -> underlay IPv4 destination.
    (call-rtnetlink
     28 #x500
     (netlink-octets
      (netlink-neighbor-message 7 interface 128 2) ; PERMANENT, SELF
      (netlink-attribute 2 mac)
      (netlink-attribute 1 (ipv4-network-octets underlay-address))))
    ;; Static ARP avoids floods and prevents a peer from changing its router MAC.
    (call-rtnetlink
     28 #x500
     (netlink-octets
      (netlink-neighbor-message 2 interface 128 0)
      (netlink-attribute 1 (ipv4-network-octets router))
      (netlink-attribute 2 mac)))
    (replace-network-route router 32 interface)
    (multiple-value-bind (address prefix) (parse-ipv4-cidr pod-cidr)
      (replace-network-route (format-ipv4-integer address) prefix interface
                             :gateway router)))
  nil)

(defun call-rtnetlink-delete (type payload)
  (handler-case (call-rtnetlink type 0 payload)
    (rtnetlink-error (condition)
      (unless (member (rtnetlink-error-errno condition) '(2 3 19))
        (error condition)))))

(defun delete-network-route (destination prefix interface)
  (call-rtnetlink-delete
   25 (netlink-octets
       (vector 2 prefix 0 0 254 4 255 1) ; scope NOWHERE accepts any old scope
       (netlink-integer 0 4)
       (netlink-attribute 1 (ipv4-network-octets destination))
       (netlink-attribute 4 (netlink-integer (cni-interface-index interface) 4)))))

(defun remove-vxlan-peer (pod-cidr underlay-address)
  (unless (zerop (native-interface-index +node-vxlan-interface+))
    (let ((interface +node-vxlan-interface+)
          (router (vxlan-router-address pod-cidr)))
      (multiple-value-bind (address prefix) (parse-ipv4-cidr pod-cidr)
        (delete-network-route (format-ipv4-integer address) prefix interface))
      (delete-network-route router 32 interface)
      (call-rtnetlink-delete
       29 (netlink-octets
           (netlink-neighbor-message 2 interface 128 0)
           (netlink-attribute 1 (ipv4-network-octets router))))
      (call-rtnetlink-delete
       29 (netlink-octets
           (netlink-neighbor-message 7 interface 128 2)
           (netlink-attribute 2 (vxlan-router-mac pod-cidr))
           (netlink-attribute 1 (ipv4-network-octets underlay-address))))))
  nil)

(defun node-vxlan-owner (network)
  (format nil "gr8s:vxlan:~A:~D:~A" (gethash "nodePodCIDR" network)
          (gethash "vni" network) (gethash "underlayAddress" network "")))

(defun node-vxlan-route-pairs (network)
  (loop for route across (gethash "routes" network #())
        collect (cons (gethash "podCIDR" route) (gethash "underlayAddress" route))))

(defun reconcile-node-vxlan-network (network previous-networks)
  (let* ((local (gethash "underlayAddress" network ""))
         (wanted (node-vxlan-route-pairs network))
         (previous
           (remove-duplicates (mapcan #'node-vxlan-route-pairs previous-networks)
                              :test #'equal)))
    (when (and (string= local "")
               (notany (lambda (old)
                         (plusp (length (gethash "underlayAddress" old ""))))
                       previous-networks))
      (return-from reconcile-node-vxlan-network nil))
    (unless (zerop (native-interface-index +node-vxlan-interface+))
      (unless (node-vxlan-owned-or-adoptable-p network)
        ;; An underlay/VNI change requires replacing our tunnel. The durable
        ;; journal retains both identities if the process stops halfway.
        (unless (some (lambda (old)
                        (and (plusp (length (gethash "underlayAddress" old "")))
                             (node-vxlan-owned-or-adoptable-p old)))
                      previous-networks)
          (invalid-cni "refusing to replace an unowned VXLAN interface"))
        (delete-network-link +node-vxlan-interface+)
        (setf previous nil)))
    (cond
      ((string= local "")
       (delete-network-link +node-vxlan-interface+))
      (t
       (ensure-node-vxlan local (gethash "nodePodCIDR" network)
                          (gethash "vni" network) (gethash "mtu" network))
       ;; Remove changed FDB entries before reusing their router MAC/address.
       (dolist (route previous)
         (unless (member route wanted :test #'equal)
           (remove-vxlan-peer (car route) (cdr route))))
       (dolist (route wanted) (replace-vxlan-peer (car route) (cdr route)))))))
