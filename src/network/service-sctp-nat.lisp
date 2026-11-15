;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; SCTP ClusterIP translation for the CNI agent.
;;;;
;;;; The socket load balancer (cgroup/connect4) cannot translate SCTP: the
;;;; kernel never runs the connect4 hook for SCTP sockets, so SCTP traffic to a
;;;; ClusterIP is emitted with the Service VIP as destination and never reaches a
;;;; backend. These two TC classifiers close that gap on the client Pod's veth,
;;;; reusing the shared gr8s_service_v4 / gr8s_backend_v4 maps the socket LB
;;;; already populates (service-lb-protocol-number maps SCTP to 132).
;;;;
;;;; Only the IPv4 address is rewritten, never the transport port. SCTP carries a
;;;; CRC32c checksum over the SCTP packet -- the common header (including the
;;;; ports) and all chunks -- but NOT the IP header, so changing only the
;;;; destination (or source, on the reverse path) address leaves the checksum
;;;; valid and needs no recomputation. A Service whose port differs from its
;;;; targetPort would require rewriting a port inside the checksummed region; that
;;;; CRC32c case is deferred and such packets are dropped, which matches Cilium's
;;;; documented SCTP behaviour ("targetPort MUST equal the port").
;;;;
;;;; Forward (egress, client -> VIP): look the VIP up, pick a backend, record a
;;;; conntrack entry keyed by the post-DNAT tuple, rewrite the destination to the
;;;; backend. Reverse (ingress, backend -> client): recover the VIP from conntrack
;;;; and rewrite the source back to it so the client sees replies from the VIP.
(in-package #:gr8s.network)

(defparameter *service-sctp-map-form*
  '(whistler::defmap whistler::gr8s-sctp-ct :type :lru-hash
    :key-size 16 :value-size 8 :max-entries 65536)
  "Conntrack for in-flight SCTP associations: the post-DNAT reply tuple -> VIP.
An LRU map because SCTP associations are long-lived but need no explicit teardown
here; an evicted entry only costs a dropped reply on an idle association.")

(defparameter *service-sctp-struct-forms*
  '((whistler::defstruct whistler::sctp-ct-key
      (whistler::client whistler::u32) (whistler::backend whistler::u32)
      (whistler::cport whistler::u16) (whistler::bport whistler::u16)
      (whistler::pad whistler::u32))
    (whistler::defstruct whistler::sctp-ct-val
      (whistler::cluster whistler::u32) (whistler::pad whistler::u32))
    (whistler::defstruct whistler::sctp-addr
      (whistler::value whistler::u32) (whistler::pad whistler::u32)))
  "Stack scratch: the 16-byte conntrack key, its 8-byte value, and a 4-byte
address holder passed by pointer to skb-store-bytes.")

(defun service-sctp-map-forms ()
  "The shared Service/backend schemas plus the SCTP conntrack map."
  (append (remove-if-not
           (lambda (form) (member (symbol-name (second form))
                                  '("GR8S-SERVICE-V4" "GR8S-BACKEND-V4")
                                  :test #'equal))
           *service-lb-map-forms*)
          (list *service-sctp-map-form*)))

(defun service-sctp-map-specs ()
  "CNI map schemas, derived from the forms the compiler consumes. The Service and
backend maps are shared (pinned by the socket LB); only gr8s_sctp_ct is new."
  (mapcar (lambda (form)
            (let ((options (cddr form)))
              (list (substitute #\_ #\- (string-downcase (symbol-name (second form))))
                    (whistler/compiler:resolve-map-type (getf options :type))
                    (getf options :key-size) (getf options :value-size)
                    (getf options :max-entries) (or (getf options :map-flags) 0))))
          (service-sctp-map-forms)))

(in-package #:whistler)

(defun gr8s.network::service-sctp-dnat-form ()
  "Forward: on Pod egress, DNAT an SCTP packet bound for a ClusterIP to a backend.
Runs before the egress policy guard so policy evaluates the real backend address."
  '(defprog gr8s-sctp-dnat (:type :tc :section "classifier" :license "GPL")
    (let ((data u64 (tc-data)) (data-end u64 (tc-data-end)))
      (when (> (+ data 14) data-end) (return TC_ACT_OK))
      (when (/= (eth-type data) #x0800) (return TC_ACT_OK))
      (when (> (+ data 34) data-end) (return TC_ACT_OK))
      ;; SCTP only; leave TCP/UDP to the socket LB. No IP options (IHL 5).
      (when (/= (load u8 data 23) 132) (return TC_ACT_OK))
      (when (/= (logand (load u8 data 14) 15) 5) (return TC_ACT_OK))
      ;; SCTP common header is 12 bytes: src port, dst port, verification tag, CRC.
      (when (> (+ data 46) data-end) (return TC_ACT_OK))
      (let ((dstip u32 (load u32 data 30))
            (dport u16 (load u16 data 36)))
        (let ((key u64 (logior (<< (cast u64 132) 48)
                               (logior (<< (cast u64 dstip) 16) (cast u64 dport)))))
          (let ((service (map-lookup gr8s-service-v4 key)))
            (when (= service 0) (return TC_ACT_OK))
            (let ((count u32 (load u16 service 0)))
              (when (= count 0) (return TC_ACT_OK))
              ;; One backend per association: SCTP keeps no affinity map here.
              ;; A VIP with several backends spreads associations by source port.
              (let ((offset u32 (mod (cast u32 (load u16 data 34)) count))
                    (base u32 (load u32 service 4)))
                (let ((backend (map-lookup gr8s-backend-v4 (+ base offset))))
                  (when (= backend 0) (return TC_ACT_OK))
                  (let ((podip u32 (load u32 backend 0))
                        (podport u16 (load u16 backend 4)))
                    (when (= podip 0) (return TC_ACT_OK))
                    ;; Port rewrite would fall inside the CRC32c region: deferred.
                    (when (/= podport dport) (return TC_ACT_SHOT))
                    (let ((ct (make-sctp-ct-key)))
                      (setf (sctp-ct-key-client ct) (load u32 data 26)
                            (sctp-ct-key-backend ct) podip
                            (sctp-ct-key-cport ct) (load u16 data 34)
                            (sctp-ct-key-bport ct) podport
                            (sctp-ct-key-pad ct) 0)
                      (let ((val (make-sctp-ct-val)))
                        (setf (sctp-ct-val-cluster val) dstip
                              (sctp-ct-val-pad val) 0)
                        (map-update-ptr gr8s-sctp-ct ct val 0)))
                    (when (/= (l3-csum-replace (ctx-ptr) 24 dstip podip 4) 0)
                      (return TC_ACT_SHOT))
                    (let ((newaddr (make-sctp-addr)))
                      (setf (sctp-addr-value newaddr) podip
                            (sctp-addr-pad newaddr) 0)
                      (when (/= (skb-store-bytes (ctx-ptr) 30 newaddr 4 2) 0)
                        (return TC_ACT_SHOT)))
                    (return TC_ACT_OK)))))))))))

(defun gr8s.network::service-sctp-snat-form ()
  "Reverse: on Pod ingress, restore the VIP as the source of an SCTP reply from a
backend, so the client's association (opened to the VIP) accepts it."
  '(defprog gr8s-sctp-snat (:type :tc :section "classifier" :license "GPL")
    (let ((data u64 (tc-data)) (data-end u64 (tc-data-end)))
      (when (> (+ data 14) data-end) (return TC_ACT_OK))
      (when (/= (eth-type data) #x0800) (return TC_ACT_OK))
      (when (> (+ data 38) data-end) (return TC_ACT_OK))
      (when (/= (load u8 data 23) 132) (return TC_ACT_OK))
      (when (/= (logand (load u8 data 14) 15) 5) (return TC_ACT_OK))
      (let ((ct (make-sctp-ct-key)))
        (setf (sctp-ct-key-client ct) (load u32 data 30)
              (sctp-ct-key-backend ct) (load u32 data 26)
              (sctp-ct-key-cport ct) (load u16 data 36)
              (sctp-ct-key-bport ct) (load u16 data 34)
              (sctp-ct-key-pad ct) 0)
        (let ((val (map-lookup-ptr gr8s-sctp-ct ct)))
          (when (= val 0) (return TC_ACT_OK))
          (let ((cluster u32 (load u32 val 0))
                (oldsrc u32 (load u32 data 26)))
            (when (/= (l3-csum-replace (ctx-ptr) 24 oldsrc cluster 4) 0)
              (return TC_ACT_SHOT))
            (let ((newaddr (make-sctp-addr)))
              (setf (sctp-addr-value newaddr) cluster
                    (sctp-addr-pad newaddr) 0)
              (when (/= (skb-store-bytes (ctx-ptr) 26 newaddr 4 2) 0)
                (return TC_ACT_SHOT)))
            (return TC_ACT_OK)))))))

(in-package #:gr8s.network)

(defun compile-service-sctp-nat ()
  "Compile the SCTP forward (DNAT) and reverse (SNAT) TC classifiers over the
shared Service maps plus the SCTP conntrack map."
  (compile-whistler-program
   (service-sctp-map-forms)
   (append *service-sctp-struct-forms*
           (list (service-sctp-dnat-form)
                 (service-sctp-snat-form)))))
