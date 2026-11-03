(in-package #:whistler)

(defmap rejected-spoofs :type :array
  :key-size 4 :value-size 8 :max-entries 1)

;;; Pod egress is allowed only when its IPv4 source belongs to the network
;;; assigned by the managed bridge CNI. ARP and non-IPv4 traffic pass through.
(defprog gr8s-egress-guard (:type :tc :section "classifier" :license "GPL")
  (with-tc-ipv4 (data data-end ip)
    (let ((source u32 (ntohl (ipv4-src-addr ip))))
      (when (/= (logand source #xffff0000) #x0a580000)
        (incf (getmap rejected-spoofs 0))
        (return TC_ACT_SHOT))))
  TC_ACT_OK)
