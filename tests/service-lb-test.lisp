;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Pin the byte-order contract between the control-plane map encoders
;;;; (src/service-lb.lisp) and the cgroup/connect4 program that reads them
;;;; (src/service-lb-program.lisp), and prove the program JIT-compiles in-process
;;;; to loadable specs with no ELF and no kernel privileges.

(in-package #:gr8s/tests)
(def-suite service-lb :in gr8s)
(in-suite service-lb)

(test service-packet-and-socket-programs-share-map-schemas
  ;; These maps are shared by FD, so both compiled programs must agree on
  ;; their full schemas. Packet connection/affinity state is separate.
  (multiple-value-bind (packet-maps packet-programs)
      (gr8s.network::compile-service-packet-lb)
    (multiple-value-bind (socket-maps ignored)
        (gr8s::compile-service-lb)
      (declare (ignore ignored))
      (dolist (name '("gr8s_service_v4" "gr8s_backend_v4" "gr8s_backend_index_v4"))
        (is (equalp (find name socket-maps :test #'equal :key (lambda (spec) (getf spec :name)))
                    (find name packet-maps :test #'equal :key (lambda (spec) (getf spec :name)))))))
    (is (equal '("gr8s_packet_forward" "gr8s_packet_reverse")
               (mapcar (lambda (spec) (getf spec :name)) packet-programs)))
    (dolist (program packet-programs)
      (is (equal "classifier" (getf program :section)))
      (is (plusp (length (getf program :insns)))))))

;;; Byte-order contract.  A ClusterIP:port and a backend addr:port encode to the
;;; exact octets the eBPF program composes and copies into the socket address.

(test service-lb-vip-key-byte-layout
  ;; (protocol << 48) | (vip << 16) | htons(port), serialized little-endian, where
  ;; vip is the address octets read little-endian (network-order bytes on a LE host).
  (is (equalp #(#x00 #x50 #x0A #x60 #x00 #x0A #x06 #x00)
              (gr8s::service-lb-vip-key "10.96.0.10" 80)))
  (is (equalp #(#x00 #x50 #x0A #x60 #x00 #x0A #x11 #x00)
              (gr8s::service-lb-vip-key "10.96.0.10" 80 "UDP")))
  ;; Distinct ports and addresses must not collide into the same key.
  (is (not (equalp (gr8s::service-lb-vip-key "10.96.0.10" 80)
                   (gr8s::service-lb-vip-key "10.96.0.10" 443))))
  (is (not (equalp (gr8s::service-lb-vip-key "10.96.0.10" 80)
                   (gr8s::service-lb-vip-key "10.96.0.11" 80)))))

(test service-lb-ipv6-key-and-backend-byte-layout
  (is (equalp #(#xfd #x00 #x00 #x00 #x00 #x00 #x00 #x00
                #x00 #x00 #x00 #x00 #x00 #x00 #x00 #x0a
                #x00 #x50 #x06 #x00)
              (gr8s::service-lb-vip-key "fd00::a" 80)))
  (is (equalp #(#xfd #x88 #x00 #x00 #x00 #x00 #x00 #x00
                #x00 #x00 #x00 #x00 #x00 #x00 #x00 #x05
                #x1f #x90 #x00 #x00)
              (gr8s::service-lb-backend-value "fd88::5" 8080))))

(test service-risk-key-byte-layout
  (is (equalp #(#x0a #x58 #x01 #x05 #x1f #x90 #x06 #x00)
              (gr8s::service-lb-risk-key "10.88.1.5" 8080 "TCP")))
  (is (equalp #(#x0a #x58 #x01 #x05 #x1f #x90 #x11 #x00)
              (gr8s::service-lb-risk-key "10.88.1.5" 8080 "UDP"))))

(test service-lb-service-value-byte-layout
  ;; count u16 @0, affinity u16 @2, base slot u32 @4, timeout u32 @8, reserved u32 @12,
  ;; all little-endian (logical integers).
  (is (equalp #(#x01 #x00 #x00 #x00 #x07 #x00 #x00 #x00 #x00 #x00 #x00 #x00 #x00 #x00 #x00 #x00)
              (gr8s::service-lb-service-value 1 7)))
  (is (equalp #(#x00 #x02 #x01 #x00 #xD2 #x04 #x00 #x00 #x10 #x0E #x00 #x00 #x00 #x00 #x00 #x00)
              (gr8s::service-lb-service-value 512 1234 :affinity-timeout 3600))))

(test service-lb-plan-keys-by-protocol-and-carries-affinity
  ;; The same port over two protocols gets two VIP entries, and ClientIP affinity
  ;; reaches the program with its timeout.
  (let* ((service (fake-lb-service "10.96.0.10" :ports '(80 81)))
         (spec (gethash "spec" service)))
    (setf (gethash "protocol" (aref (gethash "ports" spec) 0)) "TCP"
          (gethash "port" (aref (gethash "ports" spec) 1)) 80
          (gethash "protocol" (aref (gethash "ports" spec) 1)) "UDP"
          (gethash "sessionAffinity" spec) "ClientIP"
          (gethash "sessionAffinityConfig" spec)
          (gr8s::core-object "clientIP" (gr8s::core-object "timeoutSeconds" 30)))
    (let ((service-entries
            (gr8s::service-lb-plan (list service) (lambda (s p) (declare (ignore s p)) '(("10.88.1.5" 8080))))))
      (is (equalp (gr8s::service-lb-vip-key "10.96.0.10" 80 "TCP") (car (first service-entries))))
      (is (equalp (gr8s::service-lb-vip-key "10.96.0.10" 80 "UDP") (car (second service-entries))))
      (let ((value (cdr (first service-entries))))
        (is (= 1 (aref value 2)))
        (is (= 30 (aref value 8)))))))

(test service-lb-backend-byte-layout
  ;; Backend slot key is little-endian; addr u32 @0 and port u16 @4 are network
  ;; byte order so the program copies them verbatim into user_ip4 / user_port.
  (is (equalp #(#x07 #x00 #x00 #x00) (gr8s::service-lb-backend-key 7)))
  (is (equalp #(#x0A #x58 #x01 #x05 #x1F #x90 #x00 #x00)
              (gr8s::service-lb-backend-value "10.88.1.5" 8080))))

(test service-lb-ports-are-validated
  (signals error (gr8s::service-lb-vip-key "10.96.0.10" 0))
  (signals error (gr8s::service-lb-vip-key "10.96.0.10" 70000))
  (signals error (gr8s::service-lb-backend-value "10.88.1.5" 0)))

(test service-lb-entries-assign-consecutive-slots
  (multiple-value-bind (vip-key service-value backends)
      (gr8s::service-lb-entries "10.96.0.10" 80 5
                                '(("10.88.1.5" . 8080) ("10.88.2.7" . 8080)))
    (is (equalp (gr8s::service-lb-vip-key "10.96.0.10" 80) vip-key))
    ;; Two backends, base slot 5.
    (is (equalp (gr8s::service-lb-service-value 2 5) service-value))
    (is (= 2 (length backends)))
    (is (equalp (gr8s::service-lb-backend-key 5) (car (first backends))))
    (is (equalp (gr8s::service-lb-backend-value "10.88.1.5" 8080) (cdr (first backends))))
    (is (equalp (gr8s::service-lb-backend-key 6) (car (second backends))))
    (is (equalp (gr8s::service-lb-backend-value "10.88.2.7" 8080) (cdr (second backends))))))

;;; In-process JIT: the program compiles to loadable specs with no ELF. Pure
;;; userspace; needs no CAP_BPF and no kernel, so it runs in the ordinary suite.

(test service-lb-program-compiles-in-process
  (multiple-value-bind (map-specs prog-specs) (gr8s::compile-service-lb)
    ;; Five maps per family, with the key/value sizes the encoders target.
    (is (= 10 (length map-specs)))
    (let ((service (find "gr8s_service_v4" map-specs
                         :key (lambda (s) (getf s :name)) :test #'string=))
          (backend (find "gr8s_backend_v4" map-specs
                         :key (lambda (s) (getf s :name)) :test #'string=))
          (service-v6 (find "gr8s_service_v6" map-specs
                            :key (lambda (s) (getf s :name)) :test #'string=))
          (backend-v6 (find "gr8s_backend_v6" map-specs
                            :key (lambda (s) (getf s :name)) :test #'string=)))
      (is (not (null service)))
      (is (not (null backend)))
      (is (= 8 (getf service :key-size)))
      (is (= 16 (getf service :value-size)))
      (is (= 4 (getf backend :key-size)))
      (is (= 8 (getf backend :value-size)))
      (is (= 20 (getf service-v6 :key-size)))
      (is (= 16 (getf service-v6 :value-size)))
      (is (= 4 (getf backend-v6 :key-size)))
      (is (= 20 (getf backend-v6 :value-size))))
    ;; Three hooks per family, with real, 8-byte-aligned
    ;; instruction bytes and the map-fd relocations the loader patches in (one per map
    ;; lookup, at least).
    (is (= 6 (length prog-specs)))
    (let* ((prog (first prog-specs))
           (insns (getf prog :insns)))
      (is (string= "cgroup/connect4" (getf prog :section)))
      (is (plusp (length insns)))
      (is (zerop (mod (length insns) 8)))
      (is (>= (length (getf prog :relocs)) 2)))))

(test service-lb-program-compiles-every-ipv4-and-ipv6-socket-hook
  (multiple-value-bind (maps programs) (gr8s::compile-service-lb)
    (is (= 10 (length maps)))
    (dolist (name '("gr8s_service_v6" "gr8s_backend_v6"
                    "gr8s_backend_index_v6" "gr8s_affinity_v6"
                    "gr8s_reverse_v6"))
      (is (find name maps :key (lambda (spec) (getf spec :name)) :test #'string=)))
    (is (equal '("cgroup/connect4" "cgroup/sendmsg4" "cgroup/recvmsg4"
                 "cgroup/connect6" "cgroup/sendmsg6" "cgroup/recvmsg6")
               (mapcar (lambda (spec) (getf spec :section)) programs)))))

(test service-lb-v2-staging-pins-shared-maps-without-changing-socket-hooks
  (multiple-value-bind (maps programs)
      (gr8s::compile-service-lb :packet-services :v2)
    (let ((names (mapcar (lambda (spec) (getf spec :name)) maps)))
      (is (= (length names) (length (remove-duplicates names :test #'equal))))
      (dolist (name '("gr8s_nat_fwd_v2" "gr8s_nat_rev_v2"
                      "gr8s_nat_id_v2" "gr8s_nat_risk_v2" "gr8s_nat_pod_v2"))
        (is (member name names :test #'equal)))
      (is (not (member "gr8s_nat_stages" names :test #'equal)))
      (let ((risk (find "gr8s_nat_risk_v2" maps :key (lambda (spec) (getf spec :name))
                        :test #'equal)))
        (is (= 8 (getf risk :key-size)))
        (is (= 4 (getf risk :value-size)))
        (is (= 65536 (getf risk :max-entries)))))
    (is (= 7 (length programs)))
    (is (= 6 (count-if (lambda (spec) (search "cgroup/" (getf spec :section))) programs)))))

(test service-nat-managed-pod-cidrs-publish-as-v2-lpm-entries
  (let ((writes nil))
    (is (= 2 (gr8s.network::publish-service-nat-managed-cidrs
              :map '("10.80.0.0/12" "fd80::/48" "10.96.0.0/16")
              :update (lambda (map key value)
                        (is (eq :map map))
                        (is (typep key '(simple-array (unsigned-byte 8) (8))))
                        (is (typep value '(simple-array (unsigned-byte 8) (1))))
                        (push (cons key value) writes)))))
    (is (equalp (mapcar #'gr8s.network::netpol-cidr-lpm-key
                       '("10.80.0.0/12" "10.96.0.0/16"))
                (mapcar #'car (nreverse writes))))
    (is (every (lambda (write) (= 1 (aref (cdr write) 0))) writes)))
  (signals error
    (gr8s.network::publish-service-nat-managed-cidrs
     :map '("10.80.0.0/12")
     :update (lambda (&rest ignored) (declare (ignore ignored)) (error "map update failed")))))

(test service-nat-identity-rows-bind-primary-alias-and-incarnation
  (let* ((record (gr8s::json-object
                  "podIP" "10.88.1.2" "address" "10.88.1.9"
                  "nodeID" "node-1" "podUID" "pod-1"
                  "sandboxID" "sandbox-1" "interfaceName" "eth0"))
         (rows (gr8s.network::service-nat-identity-rows record))
         (primary (first rows)) (alias (second rows)))
    (is (= 2 (length rows)))
    (is (equalp #(10 88 1 2) (car primary)))
    (is (equalp #(10 88 1 9) (car alias)))
    (dolist (row rows)
      (is (typep (car row) '(simple-array (unsigned-byte 8) (4))))
      (is (typep (cdr row) '(simple-array (unsigned-byte 8) (32))))
      (is (equalp #(10 88 1 9) (subseq (cdr row) 0 4)))
      (is (= #x20001 (gr8s::netlink-read-integer (cdr row) 4 4)))
      (is (equalp #(10 88 1 2) (subseq (cdr row) 24 28))))
    (is (= 1 (gr8s::netlink-read-integer (cdr primary) 28 4)))
    (is (= 2 (gr8s::netlink-read-integer (cdr alias) 28 4)))
    (is (equalp (subseq (cdr primary) 8 24) (subseq (cdr alias) 8 24)))
    (is (equalp rows (gr8s.network::service-nat-identity-rows record)))
    (let ((local (gr8s::encode-cni-endpoint-identity-v2
                  "10.88.1.2" #(2 17 34 51 68 85)
                  "node-1" "sandbox-1" "eth0" "10.88.1.9")))
      (is (= 48 (length local)))
      (is (equalp (subseq (cdr primary) 8 24) (subseq local 32 48)))
      (is (equalp (subseq (gr8s::encode-cni-endpoint-identity
                          "10.88.1.2" #(2 17 34 51 68 85)) 0 32)
                  (subseq local 0 32)))
      (is (not (equalp (subseq local 32 48)
                       (subseq (gr8s::encode-cni-endpoint-identity-v2
                                "10.88.1.2" #(2 17 34 51 68 85)
                                "node-1" "sandbox-2" "eth0" "10.88.1.9") 32 48)))))
    (setf (gethash "podUID" record) "pod-2")
    (is (equalp (subseq (cdr primary) 8 24)
                (subseq (cdr (first (gr8s.network::service-nat-identity-rows record))) 8 24)))
    (setf (gethash "sandboxID" record) "sandbox-2")
    (is (not (equalp (subseq (cdr primary) 8 24)
                     (subseq (cdr (first (gr8s.network::service-nat-identity-rows record))) 8 24)))))
  (let ((writes nil)
        (record (gr8s::json-object
                 "podIP" "10.88.1.2" "address" "10.88.1.9"
                 "nodeID" "node-1" "podUID" "pod-1"
                 "sandboxID" "sandbox-1" "interfaceName" "eth0")))
    (is (= 2 (gr8s.network::publish-service-nat-identities
              :map (vector record)
              :lookup (lambda (map key)
                        (declare (ignore map key)) nil)
              :update (lambda (map key value)
                        (is (eq :map map)) (push (cons key value) writes)))))
    (is (= 2 (length writes)))))

(test v2-owner-republish-preserves-readiness-only-for-the-same-pair
  (let* ((record (gr8s::json-object
                  "podIP" "10.88.1.2" "address" "10.88.1.9"
                  "nodeID" "node-1" "podUID" "pod-1"
                  "sandboxID" "sandbox-1" "interfaceName" "eth0"))
         (values (make-hash-table :test #'equalp)))
    (labels ((publish ()
               (gr8s.network::publish-service-nat-identities
                :map (vector record)
                :lookup (lambda (map key)
                          (declare (ignore map)) (gethash key values))
                :update (lambda (map key value)
                          (declare (ignore map))
                          (setf (gethash key values) (copy-seq value)))))
             (flags (key)
               (gr8s::netlink-read-integer (gethash key values) 4 4)))
      (let* ((rows (gr8s.network::service-nat-identity-rows record))
             (primary (caar rows)) (alias (caadr rows)))
        (is (= 2 (publish)))
        (is (= #x20001 (flags primary)))
        (dolist (key (list primary alias))
          (replace (gethash key values) (gr8s::service-lb-bytes #x20007 4) :start1 4))
        (is (= 2 (publish)))
        (is (= #x20007 (flags primary)))
        (is (= #x20007 (flags alias)))
        (remhash alias values)
        (is (= 2 (publish)))
        (is (= #x20001 (flags primary)))
        (is (= #x20001 (flags alias)))
        (dolist (key (list primary alias))
          (replace (gethash key values) (gr8s::service-lb-bytes #x20007 4) :start1 4))
        (setf (gethash "sandboxID" record) "sandbox-2")
        (is (= 2 (publish)))
        (is (= #x20001 (flags primary)))
        (is (= #x20001 (flags alias)))))))

(test v2-owner-startup-clears-readiness-across-retained-map
  (let* ((rows (gr8s.network::service-nat-identity-pair
                "node-1" "sandbox-1" "eth0" "10.88.1.2" "10.88.1.9"))
         (primary (caar rows)) (alias (caadr rows))
         (values (make-hash-table :test #'equalp)))
    (dolist (row rows)
      (let ((value (copy-seq (cdr row))))
        (replace value (gr8s::service-lb-bytes #x20007 4) :start1 4)
        (setf (gethash (car row) values) value)))
    (is (= 2 (gr8s.network::clear-service-nat-owner-readiness
              :map
              :next-key (lambda (map previous)
                          (is (eq :map map))
                          (cond ((null previous) primary)
                                ((equalp previous primary) alias)))
              :lookup (lambda (map key)
                        (is (eq :map map)) (gethash key values))
              :update (lambda (map key value)
                        (is (eq :map map))
                        (setf (gethash key values) (copy-seq value))))))
    (dolist (key (list primary alias))
      (is (= #x20001 (gr8s::netlink-read-integer (gethash key values) 4 4))))))

(test cni-v2-owner-publication-writes-the-replicated-pair-before-attachment
  (let* ((configuration (gr8s::make-cni-configuration
                         :service-packet-root "/pins/shared/" :service-packet-profile :v2
                         :service-node-id "node-1"))
         (context (gr8s::make-cni-context :container-id "sandbox-1" :interface-name "eth0"))
         (record (gr8s::json-object
                  "podIP" "10.88.1.2" "address" "10.88.1.9"
                  "nodeID" "node-1" "podUID" "pod-1"
                  "sandboxID" "sandbox-1" "interfaceName" "eth0"))
         (expected (gr8s.network::service-nat-identity-rows record))
         (writes nil) (closed nil))
    (is (equalp expected
                (gr8s.network::publish-cni-service-nat-owner
                 configuration context '("10.88.1.2") "10.88.1.9"
                 :open (lambda (path)
                         (is (equal "/pins/shared/gr8s_nat_id_v2" path)) 7)
                 :map-info (lambda (fd name &key profile)
                             (is (= 7 fd)) (is (equal "gr8s_nat_id_v2" name))
                             (is (eq :v2 profile)) :map)
                 :lookup (lambda (map key)
                           (declare (ignore map key)) nil)
                 :update (lambda (map key value)
                           (is (eq :map map)) (push (cons key value) writes))
                 :close (lambda (fd) (setf closed fd)))))
    (is (= 7 closed))
    (is (equalp (reverse expected) (reverse writes)))
    (signals error
      (gr8s.network::publish-cni-service-nat-owner
       (gr8s::make-cni-configuration :service-packet-root "/pins/shared/")
       context '("10.88.1.2") "10.88.1.9"
       :open (lambda (&rest ignored)
               (declare (ignore ignored)) (error "must reject v1 before map open"))))))

(test cni-v2-owner-check-rejects-missing-and-stale-incarnations
  (let* ((configuration (gr8s::make-cni-configuration
                         :service-packet-root "/pins/shared/" :service-packet-profile :v2
                         :service-node-id "node-1"))
         (context (gr8s::make-cni-context :container-id "sandbox-1" :interface-name "eth0"))
         (rows (gr8s.network::service-nat-identity-pair
                "node-1" "sandbox-1" "eth0" "10.88.1.2" "10.88.1.9"))
         (values (make-hash-table :test #'equalp))
         (closed 0))
    (dolist (row rows)
      (let ((value (copy-seq (cdr row))))
        (replace value (gr8s::service-lb-bytes #x20007 4) :start1 4)
        (setf (gethash (car row) values) value)))
    (labels ((check ()
               (gr8s.network::check-cni-service-nat-owner
                configuration context '("10.88.1.2") "10.88.1.9"
                :open (lambda (path)
                        (is (equal "/pins/shared/gr8s_nat_id_v2" path)) 7)
                :map-info (lambda (fd name &key profile)
                            (is (= 7 fd)) (is (equal "gr8s_nat_id_v2" name))
                            (is (eq :v2 profile)) :map)
                :lookup (lambda (map key) (is (eq :map map)) (gethash key values))
                :close (lambda (fd) (is (= 7 fd)) (incf closed)))))
      (is (null (check)))
      (remhash (car (second rows)) values)
      (signals gr8s::cni-error (check))
      (setf (gethash (car (second rows)) values) (copy-seq (cdr (second rows))))
      (let ((stale (gethash (car (first rows)) values)))
        (setf (aref stale 8) (logxor 1 (aref stale 8))))
      (signals gr8s::cni-error (check))
      (is (= 3 closed)))))

(test service-lb-plan-publishes-each-cluster-ip-to-same-family-backends
  (let* ((service (fake-lb-service "10.96.0.10"))
         (spec (gethash "spec" service)))
    (setf (gethash "clusterIPs" spec) #("10.96.0.10" "fd96::a")
          (gethash "ipFamilies" spec) #("IPv4" "IPv6"))
    (multiple-value-bind (services backends)
        (gr8s::service-lb-plan
         (list service)
         (lambda (ignored-service ignored-port)
           (declare (ignore ignored-service ignored-port))
           '(("10.88.1.5" 8080) ("fd88::5" 8080))))
      (is (= 2 (length services)))
      (is (= 2 (length backends)))
      (is (find (gr8s::service-lb-vip-key "10.96.0.10" 80)
                services :key #'car :test #'equalp))
      (is (find (gr8s::service-lb-vip-key "fd96::a" 80)
                services :key #'car :test #'equalp))
      (is (find (gr8s::service-lb-backend-value "10.88.1.5" 8080)
                backends :key #'cdr :test #'equalp))
      (is (find (gr8s::service-lb-backend-value "fd88::5" 8080)
                backends :key #'cdr :test #'equalp)))))

(test service-lb-consumes-ipv4-and-ipv6-endpoint-slices
  (with-temporary-store (store directory)
    (declare (ignore directory))
    (let* ((service (fake-lb-service "10.96.0.10"))
           (port (aref (gethash "ports" (gethash "spec" service)) 0))
           (v4 (endpointslice-test-object "v4" "10.88.1.5" 8080))
           (v6 (endpointslice-test-object "v6" "fd88::5" 8080)))
      (dolist (slice (list v4 v6))
        (setf (gethash "kubernetes.io/service-name"
                       (gethash "labels" (gethash "metadata" slice)))
              "svc"))
      (setf (gethash "addressType" v6) "IPv6")
      (gr8s::create-core-resource store "endpointslices" v4 "default")
      (gr8s::create-core-resource store "endpointslices" v6 "default")
      (multiple-value-bind (endpoints found)
          (gr8s::service-slice-endpoints store service port)
        (is-true found)
        (is (equal '(("10.88.1.5" 8080) ("fd88::5" 8080)) endpoints))))))

(test service-risk-inventory-includes-unready-advertised-backend
  (with-temporary-store (store directory)
    (declare (ignore directory))
    (let* ((service (fake-lb-service "10.96.0.10"))
           (port (aref (gethash "ports" (gethash "spec" service)) 0))
           (slice (endpointslice-test-object "unready" "10.88.1.5" 8080))
           (endpoint (aref (gethash "endpoints" slice) 0)))
      (setf (gethash "kubernetes.io/service-name"
                     (gethash "labels" (gethash "metadata" slice))) "svc"
            (gethash "conditions" endpoint) (gr8s::core-object "ready" nil "serving" t))
      (gr8s::create-core-resource store "endpointslices" slice "default")
      (multiple-value-bind (selected)
          (gr8s::service-port-backends store service port :node-name "here")
        (is (null selected)))
      (is (equal '(("10.88.1.5" 8080))
                 (gr8s::service-risk-raw-backends store service port))))))

;;; Dataplane lifecycle.  Every kernel operation (map creation, pinning,
;;; program load, cgroup attach, detach) is injected, so the orchestration is
;;; exercised without CAP_BPF.  Fake fds use large numbers that cannot collide
;;; with a real descriptor, so the ignored sb-posix:close calls are harmless.

(defun fake-lb-map (name fd)
  (cons name (whistler/loader::make-map-info
              :name name :type 2 :key-size 8 :value-size 8
              :max-entries 1 :flags 0 :fd fd)))

(defun fake-lb-program (fd)
  (whistler/loader::make-prog-info
   :name "gr8s_service_lb" :section-name "cgroup/connect4"
   :type 18 :insns #() :fd fd))

(test service-lb-dataplane-start-pins-then-loads-then-attaches
  (let ((pinned nil) (attach-args nil) (load-saw-maps nil))
    (let ((dataplane
            (gr8s::start-service-lb-dataplane
             "/sys/fs/cgroup/gr8s" "/run/gr8s/bpf/service-lb"
             :compile (lambda ()
                        (values (list '(:name "gr8s_service_v4")
                                      '(:name "gr8s_backend_v4"))
                                :program-specs))
             :create-maps (lambda (specs)
                            (is (equal (list '(:name "gr8s_service_v4")
                                             '(:name "gr8s_backend_v4"))
                                       specs))
                            (list (fake-lb-map "gr8s_service_v4" 900001)
                                  (fake-lb-map "gr8s_backend_v4" 900002)))
             :ensure-directory (lambda (path) (declare (ignore path)) t)
             :pin-map (lambda (map path)
                        (push (cons (whistler/loader:map-info-fd map) (namestring path)) pinned))
             :load-programs (lambda (specs maps)
                              (is (eq :program-specs specs))
                              (setf load-saw-maps maps)
                              (list (cons "gr8s_service_lb" (fake-lb-program 900003))))
             :attach (lambda (program-fd cgroup attach-type)
                       (setf attach-args (list program-fd cgroup attach-type)) :attachment))))
      (is-false (gr8s::service-lb-dataplane-reopened-p dataplane))
      ;; Both maps are pinned, under the given bpffs directory, by their names.
      (is (= 2 (length pinned)))
      (is (member "/run/gr8s/bpf/service-lb/gr8s_service_v4" pinned
                  :key #'cdr :test #'string=))
      (is (member "/run/gr8s/bpf/service-lb/gr8s_backend_v4" pinned
                  :key #'cdr :test #'string=))
      ;; Pinning happens before the program load (so a failed load leaves
      ;; discoverable maps): the loader sees the already-created maps.
      (is (= 2 (length load-saw-maps)))
      ;; The program is attached to the given cgroup by its loaded fd.
      (is (equal (list 900003 "/sys/fs/cgroup/gr8s" whistler/loader:+bpf-cgroup-inet4-connect+) attach-args))
      (is (equal '(:attachment) (gr8s::service-lb-dataplane-attachment dataplane)))
      (is (not (null (gr8s::service-lb-service-table dataplane))))
      (is (not (null (gr8s::service-lb-backend-table dataplane)))))))

(test service-lb-dataplane-staging-mode-reaches-compiler
  (let ((profile nil))
    (gr8s::start-service-lb-dataplane
     "/sys/fs/cgroup/gr8s" "/run/gr8s/bpf/service-lb"
     :packet-services :v2
     :compile (lambda (&key packet-services)
                (setf profile packet-services)
                (values (list '(:name "gr8s_nat_risk_v2")) :program-specs))
     :create-maps (lambda (specs)
                    (declare (ignore specs))
                    (list (fake-lb-map "gr8s_nat_risk_v2" 900021)))
     :ensure-directory (lambda (path) (declare (ignore path)) t)
     :pin-map (lambda (map path) (declare (ignore map path)) t)
     :load-programs (lambda (specs maps)
                      (declare (ignore specs maps))
                      (list (cons "gr8s_service_lb" (fake-lb-program 900022))))
     :attach (lambda (&rest ignored) (declare (ignore ignored)) :attachment))
    (is (eq :v2 profile))))

(test service-lb-dataplane-start-reuses-compatible-pinned-maps
  (let ((created nil) (pinned nil) (opened nil) (validated nil)
        (existing (list (fake-lb-map "gr8s_service_v4" 900011)
                        (fake-lb-map "gr8s_backend_v4" 900012))))
    (let ((dataplane
            (gr8s::start-service-lb-dataplane
             "/sys/fs/cgroup/gr8s" "/run/gr8s/bpf/service-lb"
             :compile (lambda ()
                        (values (list '(:name "gr8s_service_v4")
                                      '(:name "gr8s_backend_v4"))
                                :program-specs))
             :create-maps (lambda (specs)
                            (setf created specs)
                            (error "must not create replacement maps"))
             :ensure-directory (lambda (path) (declare (ignore path)) t)
             :path-exists-p (lambda (path)
                              (member (pathname-name path)
                                      '("gr8s_service_v4" "gr8s_backend_v4")
                                      :test #'string=))
             :open-pinned (lambda (path)
                            (let ((entry (assoc (pathname-name path) existing
                                                :test #'string=)))
                              (push (pathname-name path) opened)
                              (whistler/loader:map-info-fd (cdr entry))))
             :validate-map (lambda (fd spec)
                             (push (list fd (getf spec :name)) validated)
                             (cdr (assoc (getf spec :name) existing :test #'string=)))
             :pin-map (lambda (map path)
                        (declare (ignore map path))
                        (push t pinned))
             :load-programs (lambda (specs maps)
                              (is (eq :program-specs specs))
                              (is (equal existing maps))
                              (list (cons "gr8s_service_lb" (fake-lb-program 900013))))
             :attach (lambda (program-fd cgroup attach-type)
                       (declare (ignore program-fd cgroup attach-type))
                       :attachment))))
      (is (gr8s::service-lb-dataplane-reopened-p dataplane))
      (is (null created))
      (is (null pinned))
      (is (equal '("gr8s_backend_v4" "gr8s_service_v4") opened))
      (is (equal '((900012 "gr8s_backend_v4")
                   (900011 "gr8s_service_v4"))
                 validated))
      (is (= 900011 (whistler/loader:map-info-fd
                     (gr8s::service-lb-service-table dataplane)))))))

(test service-lb-dataplane-start-rolls-back-pins-on-load-failure
  (let ((removed nil))
    (signals error
      (gr8s::start-service-lb-dataplane
       "/sys/fs/cgroup/gr8s" "/run/gr8s/bpf/service-lb"
       :compile (lambda ()
                  (values (list '(:name "gr8s_service_v4")
                                '(:name "gr8s_backend_v4"))
                          :program-specs))
       :create-maps (lambda (specs) (declare (ignore specs))
                      (list (fake-lb-map "gr8s_service_v4" 900001)
                            (fake-lb-map "gr8s_backend_v4" 900002)))
       :ensure-directory (lambda (path) (declare (ignore path)) t)
       :pin-map (lambda (map path) (declare (ignore map path)) t)
       :remove-path (lambda (path) (push (namestring path) removed))
       :load-programs (lambda (specs maps) (declare (ignore specs maps))
                        (error "verifier rejected the program"))
       :attach (lambda (program-fd cgroup attach-type) (declare (ignore program-fd cgroup attach-type)) :attachment)))
    ;; A failed load removes every pin it had created.
    (is (= 2 (length removed)))
    (is (member "/run/gr8s/bpf/service-lb/gr8s_service_v4" removed :test #'string=))
    (is (member "/run/gr8s/bpf/service-lb/gr8s_backend_v4" removed :test #'string=))))

(test service-lb-dataplane-stop-detaches-and-removes-pins
  (let ((detached nil) (removed nil)
        (dataplane (gr8s::%make-service-lb-dataplane
                    :cgroup-path "/sys/fs/cgroup/gr8s"
                    :pin-directory "/run/gr8s/bpf/service-lb/"
                    :maps (list (fake-lb-map "gr8s_service_v4" 900001)
                                (fake-lb-map "gr8s_backend_v4" 900002))
                    :program (fake-lb-program 900003)
                    :attachment '(:attachment))))
    (gr8s::stop-service-lb-dataplane
     dataplane
     :detach (lambda (attachment) (push attachment detached))
     :remove-path (lambda (path) (push (namestring path) removed)))
    (is (equal '(:attachment) detached))
    (is (null (gr8s::service-lb-dataplane-attachment dataplane)))
    (is (= 2 (length removed)))
    (is (member "/run/gr8s/bpf/service-lb/gr8s_service_v4" removed :test #'string=))))

(test service-lb-dataplane-stop-can-keep-pins
  (let ((removed nil)
        (dataplane (gr8s::%make-service-lb-dataplane
                    :pin-directory "/run/gr8s/bpf/service-lb/"
                    :maps (list (fake-lb-map "gr8s_service_v4" 900001))
                    :program (fake-lb-program 900003)
                    :attachment :attachment)))
    (gr8s::stop-service-lb-dataplane
     dataplane :remove-pins nil
     :detach (lambda (attachment) (declare (ignore attachment)) t)
     :remove-path (lambda (path) (push (namestring path) removed)))
    ;; Keeping pins across a restart removes nothing.
    (is (null removed))))

(test service-lb-write-service-fills-backends-before-vip
  ;; Backends must land before the service entry, so the program never reads a
  ;; VIP whose slots are missing.  Record the update order and payloads.
  (let ((writes nil)
        (dataplane (gr8s::%make-service-lb-dataplane
                    :maps (list (fake-lb-map "gr8s_service_v4" 900001)
                                (fake-lb-map "gr8s_backend_v4" 900002)
                                (fake-lb-map "gr8s_backend_index_v4" 900003)))))
    (gr8s::service-lb-write-service
     dataplane "10.96.0.10" 80 3 '(("10.88.1.5" . 8080) ("10.88.2.7" . 8080))
     :update (lambda (map key value)
               (push (list (whistler/loader:map-info-fd map) key value) writes)))
    (setf writes (nreverse writes))
    ;; Backends, membership entries (even without affinity), then the Service.
    (is (equal '(900002 900002 900003 900003 900001) (mapcar #'first writes)))
    (is (equalp (gr8s::service-lb-backend-key 3) (second (first writes))))
    (is (equalp (gr8s::service-lb-backend-value "10.88.1.5" 8080) (third (first writes))))
    (is (equalp (gr8s::service-lb-index-key
                (gr8s::service-lb-vip-key "10.96.0.10" 80)
                (gr8s::service-lb-backend-value "10.88.1.5" 8080))
               (second (third writes))))
    (is (equalp (gr8s::service-lb-vip-key "10.96.0.10" 80) (second (fifth writes))))
    (is (equalp (gr8s::service-lb-service-value 2 3) (third (fifth writes))))))

(test service-lb-write-service-selects-the-ipv6-map-pair
  (let ((writes nil)
        (dataplane (gr8s::%make-service-lb-dataplane
                    :maps (list (fake-lb-map "gr8s_service_v4" 900001)
                                (fake-lb-map "gr8s_backend_v4" 900002)
                                (fake-lb-map "gr8s_service_v6" 900003)
                                (fake-lb-map "gr8s_backend_v6" 900004)
                                (fake-lb-map "gr8s_backend_index_v6" 900005)))))
    (gr8s::service-lb-write-service
     dataplane "fd96::a" 80 3 '(("fd88::5" . 8080))
     :update (lambda (map key value)
               (push (list (whistler/loader:map-info-fd map) key value) writes)))
    (setf writes (nreverse writes))
    (is (equal '(900004 900005 900003) (mapcar #'first writes)))
    (is (equalp (gr8s::service-lb-backend-value "fd88::5" 8080)
                (third (first writes))))
    (is (equalp (gr8s::service-lb-vip-key "fd96::a" 80)
                (second (third writes))))))

(test service-lb-pin-directory-is-under-state
  (is (string= "/var/lib/gr8s/containerd/bpf/service-lb/"
               (gr8s::service-lb-pin-directory "/var/lib/gr8s"))))

;;; Controller: converge Service/endpoint state into the maps.  Services are
;;; plain core objects and the endpoint lookup and map ops are injected, so no
;;; store and no kernel are needed.

(defun fake-lb-service (cluster-ip &key (ports '(80)) external-name)
  (let ((spec (gr8s::core-object
               "clusterIP" cluster-ip
               "type" (if external-name "ExternalName" "ClusterIP")
               "selector" (gr8s::core-object "app" "web")
               "ports" (coerce (mapcar (lambda (p) (gr8s::core-object "port" p)) ports) 'vector))))
    (when external-name (setf (gethash "externalName" spec) external-name))
    (gr8s::core-object
     "metadata" (gr8s::core-object "name" "svc" "namespace" "default" "uid" cluster-ip)
     "spec" spec)))

(test service-risk-plan-keeps-unready-and-topology-filtered-backends
  (let* ((first (fake-lb-service "10.96.0.10"))
         (second (fake-lb-service "10.96.0.11"))
         (udp (aref (gethash "ports" (gethash "spec" second)) 0)))
    (setf (gethash "protocol" udp) "UDP")
    (let ((keys (gr8s::service-risk-keys
                 (list second first)
                 (lambda (service port)
                   (declare (ignore service port))
                   ;; These raw advertised endpoints include one that this
                   ;; node's traffic-policy/topology plan would omit.
                   '(("10.88.1.5" 8080) ("10.88.1.6" 8080)
                     ("fd88::5" 8080))))))
      (is (= 4 (length keys)))
      (dolist (address '("10.88.1.5" "10.88.1.6"))
        (dolist (protocol '("TCP" "UDP"))
          (is (member (gr8s::service-lb-risk-key address 8080 protocol)
                      keys :test #'equalp)))))))

(test service-lb-status-advertises-ready-node-addresses
  (with-temporary-store (store directory)
    (declare (ignore directory))
    (dolist (node (list (gr8s:make-node-record :id "node-a" :name "node-a"
                                               :pod-cidr "10.88.0.0/24" :underlay-address "192.0.2.10")
                        (gr8s:make-node-record :id "node-b" :name "node-b"
                                               :pod-cidr "10.88.1.0/24" :underlay-address "192.0.2.11")))
      (gr8s:register-node store node))
    (gr8s:mark-node-ready store "node-b" (get-universal-time))
    (labels ((load-balancer (name &optional class)
               (let ((service (service-test-object name)))
                 (setf (gethash "type" (gethash "spec" service)) "LoadBalancer")
                 (when class (setf (gethash "loadBalancerClass" (gethash "spec" service)) class))
                 (gr8s::create-core-resource store "services" service "default")))
             (addresses (name)
               (let* ((service (gr8s::get-core-resource store "services" "default" name))
                      (status (gethash "status" service))
                      (balancer (gethash "loadBalancer" status)))
                 (map 'list (lambda (entry) (gethash "ip" entry))
                      (gethash "ingress" balancer #())))))
      (load-balancer "managed")
      (load-balancer "custom" "example.test/controller")
      (gr8s::reconcile-service-load-balancer-status store)
      (is (equal '("192.0.2.11") (addresses "managed")))
      (is (null (addresses "custom")))
      (let ((revision (gr8s::pod-store-resource-revision store)))
        (gr8s::reconcile-service-load-balancer-status store)
        (is (= revision (gr8s::pod-store-resource-revision store))))
      (gr8s:mark-node-ready store "node-a" (get-universal-time))
      (gr8s::reconcile-service-load-balancer-status store)
      (is (equal '("192.0.2.10" "192.0.2.11") (addresses "managed"))))))

(test service-lb-status-advertises-the-local-node-discovered-address
  (with-temporary-store (store directory)
    (declare (ignore directory))
    ;; The in-process local agent intentionally reports no explicit underlay
    ;; address. Its Kubernetes InternalIP is the host's discovered primary IP.
    (gr8s:register-node store (gr8s:make-node-record :id "local" :name "local"
                                                     :pod-cidr "10.88.0.0/24"))
    (gr8s:mark-node-ready store "local" (get-universal-time))
    (let* ((gr8s::*local-primary-ipv4* "192.0.2.12")
           (service (service-test-object "managed")))
      (setf (gethash "type" (gethash "spec" service)) "LoadBalancer")
      (gr8s::create-core-resource store "services" service "default")
      (gr8s::reconcile-service-load-balancer-status store)
      (let* ((stored (gr8s::get-core-resource store "services" "default" "managed"))
             (ingress (gethash "ingress" (gethash "loadBalancer" (gethash "status" stored)))))
        (is (equal '(("192.0.2.12" "Proxy"))
                   (map 'list (lambda (entry)
                                (list (gethash "ip" entry) (gethash "ipMode" entry)))
                        ingress)))))))

(test service-lb-status-withdraws-a-service-whose-node-port-collides
  (with-temporary-store (store directory)
    (declare (ignore directory))
    (gr8s:register-node store (gr8s:make-node-record :id "node-a" :name "node-a"
                                                     :pod-cidr "10.88.0.0/24"
                                                     :underlay-address "192.0.2.10"))
    (gr8s:mark-node-ready store "node-a" (get-universal-time))
    (dolist (name '("alpha" "beta"))
      (let ((service (service-test-object name)))
        (setf (gethash "type" (gethash "spec" service)) "LoadBalancer")
        (gr8s::create-core-resource store "services" service "default")))
    (gr8s::reconcile-service-load-balancer-status store)
    (flet ((ingress (name)
             (gethash "ingress"
                      (gethash "loadBalancer"
                               (gethash "status"
                                        (gr8s::get-core-resource store "services" "default" name))))))
      (is (= 1 (length (ingress "alpha"))))
      (is (null (ingress "beta"))))))

(test service-lb-plan-excludes-ineligible-services
  ;; Headless (None), the API Service, and ExternalName never reach the maps.
  (let ((services (list (fake-lb-service "None")
                        (fake-lb-service "10.96.0.1")
                        (fake-lb-service "10.96.0.9" :external-name "db.example.com")
                        (fake-lb-service "10.96.0.10"))))
    (multiple-value-bind (service-entries backend-entries slots)
        (gr8s::service-lb-plan services (lambda (s p) (declare (ignore s p)) '(("10.88.1.5" 8080))))
      (is (= 1 (length service-entries)))
      (is (= 1 (length backend-entries)))
      (is (= 1 slots))
      (is (equalp (gr8s::service-lb-vip-key "10.96.0.10" 80) (car (first service-entries)))))))

(test service-lb-plan-packs-backends-deterministically
  (let ((services (list (fake-lb-service "10.96.0.10" :ports '(80))
                        (fake-lb-service "10.96.0.5" :ports '(80 443)))))
    (flet ((endpoints (service port)
             (let ((ip (gethash "clusterIP" (gethash "spec" service)))
                   (number (gethash "port" port)))
               (cond ((and (equal ip "10.96.0.10") (= number 80))
                      '(("10.88.1.5" 8080) ("10.88.1.6" 8080)))
                     ((and (equal ip "10.96.0.5") (= number 80)) '(("10.88.2.1" 9090)))
                     (t '())))))               ; 10.96.0.5:443 has no ready backends
      (multiple-value-bind (service-entries backend-entries slots)
          (gr8s::service-lb-plan services #'endpoints)
        ;; "10.96.0.10" sorts before "10.96.0.5"; slots pack 0,1 then 2.
        (is (= 3 (length service-entries)))
        (is (= 3 (length backend-entries)))
        (is (= 3 slots))
        (is (equalp (gr8s::service-lb-vip-key "10.96.0.10" 80) (car (first service-entries))))
        (is (equalp (gr8s::service-lb-service-value 2 0) (cdr (first service-entries))))
        (is (equalp (gr8s::service-lb-backend-value "10.88.1.5" 8080) (cdr (first backend-entries))))
        ;; A port with no ready backends still gets a zero-count entry (passthrough);
        ;; its base is the slot counter after the two populated ports (0,1 then 2).
        (is (equalp (gr8s::service-lb-service-value 0 3) (cdr (third service-entries))))))))

(defun make-fake-lb-controller ()
  (gr8s::make-service-lb-controller
   nil
   (gr8s::%make-service-lb-dataplane
    :maps (list (fake-lb-map "gr8s_service_v4" 1) (fake-lb-map "gr8s_backend_v4" 2)))))

(test service-lb-converge-writes-backends-before-services-then-is-idempotent
  (let ((controller (make-fake-lb-controller))
        (one-service (lambda () (list (fake-lb-service "10.96.0.10" :ports '(80)))))
        (two-backends (lambda (s p) (declare (ignore s p)) '(("10.88.1.5" 8080) ("10.88.1.6" 8080)))))
    (let ((writes nil) (deletes nil))
      (gr8s::converge-service-lb-controller
       controller :list-services one-service :endpoints-of two-backends
       :update (lambda (m k v) (declare (ignore k v)) (push (whistler/loader:map-info-fd m) writes))
       :delete (lambda (m k) (declare (ignore k)) (push (whistler/loader:map-info-fd m) deletes)))
      ;; Two backend writes (map fd 2) then the one service write (map fd 1).
      (is (equal '(2 2 1) (nreverse writes)))
      (is (null deletes)))
    ;; Re-converging an unchanged plan writes and deletes nothing.
    (let ((touched nil))
      (gr8s::converge-service-lb-controller
       controller :list-services one-service :endpoints-of two-backends
       :update (lambda (m k v) (declare (ignore m k v)) (push t touched))
       :delete (lambda (m k) (declare (ignore m k)) (push t touched)))
      (is (null touched)))))

(test service-lb-converge-routes-each-family-to-its-own-maps
  (let* ((dataplane (gr8s::%make-service-lb-dataplane
                     :maps (list (fake-lb-map "gr8s_service_v4" 1)
                                 (fake-lb-map "gr8s_backend_v4" 2)
                                 (fake-lb-map "gr8s_backend_index_v4" 3)
                                 (fake-lb-map "gr8s_service_v6" 4)
                                 (fake-lb-map "gr8s_backend_v6" 5)
                                 (fake-lb-map "gr8s_backend_index_v6" 6))))
         (controller (gr8s::make-service-lb-controller nil dataplane))
         (service (fake-lb-service "10.96.0.10"))
         (writes nil))
    (setf (gethash "clusterIPs" (gethash "spec" service))
          #("10.96.0.10" "fd96::a"))
    (gr8s::converge-service-lb-controller
     controller
     :list-services (lambda () (list service))
     :endpoints-of (lambda (ignored-service ignored-port)
                     (declare (ignore ignored-service ignored-port))
                     '(("10.88.1.5" 8080) ("fd88::5" 8080)))
     :update (lambda (map key value)
               (declare (ignore key value))
               (push (whistler/loader:map-info-fd map) writes))
     :delete (constantly nil))
    ;; One backend and one Service entry land in each family's maps.
    (is (equal '(2 5 3 6 1 4) (nreverse writes)))))

(test service-lb-converge-frees-slots-when-a-backend-leaves
  (let ((controller (make-fake-lb-controller)))
    ;; Start with two backends.
    (gr8s::converge-service-lb-controller
     controller
     :list-services (lambda () (list (fake-lb-service "10.96.0.10" :ports '(80))))
     :endpoints-of (lambda (s p) (declare (ignore s p)) '(("10.88.1.5" 8080) ("10.88.1.6" 8080)))
     :update (constantly nil) :delete (constantly nil))
    ;; Drop to one backend: slot 1 must be deleted from the backend map (fd 2).
    (let ((deletes nil))
      (gr8s::converge-service-lb-controller
       controller
       :list-services (lambda () (list (fake-lb-service "10.96.0.10" :ports '(80))))
       :endpoints-of (lambda (s p) (declare (ignore s p)) '(("10.88.1.5" 8080)))
       :update (constantly nil)
       :delete (lambda (m k) (push (list (whistler/loader:map-info-fd m) k) deletes)))
      (is (member (list 2 (gr8s::service-lb-backend-key 1)) deletes :test #'equalp)))))

(test service-lb-converge-withdraws-a-removed-service
  (let ((controller (make-fake-lb-controller)))
    (gr8s::converge-service-lb-controller
     controller
     :list-services (lambda () (list (fake-lb-service "10.96.0.10" :ports '(80))))
     :endpoints-of (lambda (s p) (declare (ignore s p)) '(("10.88.1.5" 8080)))
     :update (constantly nil) :delete (constantly nil))
    ;; Remove the Service entirely: its VIP key (fd 1) and freed slot 0 (fd 2) go.
    (let ((deletes nil))
      (gr8s::converge-service-lb-controller
       controller
       :list-services (lambda () nil)
       :endpoints-of (lambda (s p) (declare (ignore s p)) nil)
       :update (constantly nil)
       :delete (lambda (m k) (push (list (whistler/loader:map-info-fd m) k) deletes)))
      (is (member (list 1 (gr8s::service-lb-vip-key "10.96.0.10" 80)) deletes :test #'equalp))
      (is (member (list 2 (gr8s::service-lb-backend-key 0)) deletes :test #'equalp)))))

(defun service-lb-cleanup-fixture ()
  "Model actual hash-map ENOENT semantics for both address families."
  (let* ((entries (make-hash-table :test #'equalp))
         (maps (loop for name in '("gr8s_service_v4" "gr8s_backend_v4" "gr8s_backend_index_v4"
                                  "gr8s_service_v6" "gr8s_backend_v6" "gr8s_backend_index_v6")
                     for fd from 1 collect (fake-lb-map name fd))))
    (flet ((key (map bytes) (list (whistler/loader:map-info-name map) (copy-seq bytes))))
      (values
       (gr8s::make-service-lb-controller nil (gr8s::%make-service-lb-dataplane :maps maps))
       entries
       (lambda (map bytes value) (setf (gethash (key map bytes) entries) (copy-seq value)))
       (lambda (map bytes)
         (unless (remhash (key map bytes) entries)
           (error 'whistler/loader:bpf-error :context "map-delete" :errno 2)))))))

(test service-lb-cleanup-skips-absent-address-family-slots
  (multiple-value-bind (controller entries update delete) (service-lb-cleanup-fixture)
    (let ((services (list (fake-lb-service "10.96.0.10" :ports '(80)))))
      (flet ((converge (backends)
               (gr8s::converge-service-lb-controller
                controller :list-services (constantly services) :endpoints-of (constantly backends)
                :update update :delete delete)))
        (converge '(("10.88.1.5" 8080) ("10.88.1.6" 8080)))
        ;; IPv6 maps exist, but never contained the retired IPv4 slot.
        (converge '(("10.88.1.5" 8080)))
        (is (= 3 (hash-table-count entries)))
        (is (= 1 (gr8s::service-lb-controller-applied-slot-count controller)))
        (let ((touched nil))
          (gr8s::converge-service-lb-controller
           controller :list-services (constantly services)
           :endpoints-of (constantly '(("10.88.1.5" 8080)))
           :update (lambda (&rest ignored) (declare (ignore ignored)) (setf touched t))
           :delete (lambda (&rest ignored) (declare (ignore ignored)) (setf touched t)))
          (is-false touched))))))

(test service-lb-cleanup-retries-partial-deletion-and-preserves-other-errors
  (multiple-value-bind (controller entries update delete) (service-lb-cleanup-fixture)
    (gr8s::converge-service-lb-controller
     controller :list-services (constantly (list (fake-lb-service "10.96.0.10" :ports '(80))))
     :endpoints-of (constantly '(("10.88.1.5" 8080) ("10.88.1.6" 8080)))
     :update update :delete delete)
    (let* ((signature (gr8s::service-lb-controller-applied-signature controller))
           (condition
             (handler-case
                 (gr8s::converge-service-lb-controller
                  controller :list-services (constantly nil) :endpoints-of (constantly nil)
                  :update update
                  :delete (lambda (map key)
                            (when (equal "gr8s_backend_index_v4" (whistler/loader:map-info-name map))
                              (error 'whistler/loader:bpf-error :context "map-delete" :errno 5))
                            (funcall delete map key)))
               (whistler/loader:bpf-error (error) error))))
      (is (typep condition 'whistler/loader:bpf-error))
      (when condition (is (= 5 (whistler/loader::bpf-error-errno condition))))
      (is (eq signature (gr8s::service-lb-controller-applied-signature controller)))
      (is (= 2 (hash-table-count entries))))
    ;; Retry must tolerate the already removed VIP and slots, then finish
    ;; deleting membership entries and commit the empty desired state.
    (gr8s::converge-service-lb-controller
     controller :list-services (constantly nil) :endpoints-of (constantly nil)
     :update update :delete delete)
    (is (zerop (hash-table-count entries)))
    (is (zerop (gr8s::service-lb-controller-applied-slot-count controller)))
    (let ((touched nil))
      (gr8s::converge-service-lb-controller
       controller :list-services (constantly nil) :endpoints-of (constantly nil)
       :update (lambda (&rest ignored) (declare (ignore ignored)) (setf touched t))
       :delete (lambda (&rest ignored) (declare (ignore ignored)) (setf touched t)))
      (is-false touched))))

(test service-lb-cleanup-does-not-ignore-missing-key-write-errors
  (multiple-value-bind (controller entries update delete) (service-lb-cleanup-fixture)
    (declare (ignore update))
    (signals whistler/loader:bpf-error
      (gr8s::converge-service-lb-controller
       controller :list-services (constantly (list (fake-lb-service "10.96.0.10" :ports '(80))))
       :endpoints-of (constantly '(("10.88.1.5" 8080))) :delete delete
       :update (lambda (&rest ignored) (declare (ignore ignored))
                 (error 'whistler/loader:bpf-error :context "map-update" :errno 2))))
    (is (zerop (hash-table-count entries)))
    (is-false (gr8s::service-lb-controller-applied-signature controller))))

(defun service-lb-fixture-next-key (entries)
  (lambda (map previous)
    (let ((keys (loop for entry being the hash-keys of entries
                      when (equal (first entry) (whistler/loader:map-info-name map))
                        collect (second entry))))
      (if previous
          (second (member previous keys :test #'equalp))
          (first keys)))))

(test service-risk-publication-precedes-services-and-survives-restart
  (let* ((entries (make-hash-table :test #'equalp))
         (maps (list (fake-lb-map "gr8s_service_v4" 1)
                     (fake-lb-map "gr8s_backend_v4" 2)
                     (fake-lb-map "gr8s_backend_index_v4" 3)
                     (fake-lb-map "gr8s_nat_risk_v2" 4)))
         (dataplane (gr8s::%make-service-lb-dataplane :maps maps))
         (controller (gr8s::make-service-lb-controller nil dataplane))
         (service (fake-lb-service "10.96.0.10"))
         (writes nil)
         (update (lambda (map key value)
                   (when (equal "gr8s_nat_risk_v2" (whistler/loader:map-info-name map))
                     (is (typep value '(simple-array (unsigned-byte 8) (4)))))
                   (push (whistler/loader:map-info-name map) writes)
                   (setf (gethash (list (whistler/loader:map-info-name map) (copy-seq key)) entries)
                         (copy-seq value))))
         (delete (lambda (map key)
                   (remhash (list (whistler/loader:map-info-name map) key) entries)))
         (risk-backends (lambda (ignored-service ignored-port)
                          (declare (ignore ignored-service ignored-port))
                          '(("10.88.1.5" 8080) ("10.88.1.6" 8080)))))
    ;; The socket plan selects only one endpoint. Both advertised backend
    ;; tuples must be published to the risk map before any Service map write.
    (gr8s::converge-service-lb-controller
     controller :list-services (constantly (list service))
     :endpoints-of (constantly '(("10.88.1.5" 8080)))
     :risk-backends-of risk-backends :update update :delete delete)
    (is (equal '("gr8s_nat_risk_v2" "gr8s_nat_risk_v2"
                 "gr8s_backend_v4" "gr8s_backend_index_v4" "gr8s_service_v4")
               (nreverse writes)))
    (is (= 2 (length (gr8s::service-lb-controller-applied-risk-keys controller))))
    (setf writes nil)
    (gr8s::converge-service-lb-controller
     controller :list-services (constantly nil) :endpoints-of (constantly nil)
     :risk-backends-of (constantly nil) :update update :delete delete)
    (is (null writes))
    ;; Retain risk until old return-state owners can be proved drained.
    (is (= 2 (hash-table-count entries)))
    (setf (gr8s::service-lb-dataplane-reopened-p dataplane) t)
    (let ((reopened (gr8s::make-service-lb-controller nil dataplane)))
      (setf writes nil)
      (gr8s::converge-service-lb-controller
       reopened :list-services (constantly (list service))
       :endpoints-of (constantly '(("10.88.1.5" 8080)))
       :risk-backends-of risk-backends :next-key (service-lb-fixture-next-key entries)
       :update update :delete delete)
      (is (not (member "gr8s_nat_risk_v2" writes :test #'equal)))
      (is (= 2 (length (gr8s::service-lb-controller-applied-risk-keys reopened)))))))

(test service-risk-publication-failure-does-not-expose-service
  (let* ((dataplane (gr8s::%make-service-lb-dataplane
                     :maps (list (fake-lb-map "gr8s_service_v4" 1)
                                 (fake-lb-map "gr8s_backend_v4" 2)
                                 (fake-lb-map "gr8s_backend_index_v4" 3)
                                 (fake-lb-map "gr8s_nat_risk_v2" 4))))
         (controller (gr8s::make-service-lb-controller nil dataplane))
         (other-writes nil))
    (signals whistler/loader:bpf-error
      (gr8s::converge-service-lb-controller
       controller
       :list-services (constantly (list (fake-lb-service "10.96.0.10")))
       :endpoints-of (constantly '(("10.88.1.5" 8080)))
       :risk-backends-of (constantly '(("10.88.1.5" 8080)))
       :update (lambda (map key value)
                 (declare (ignore key value))
                 (if (equal "gr8s_nat_risk_v2" (whistler/loader:map-info-name map))
                     (error 'whistler/loader:bpf-error :context "map-update" :errno 28)
                     (push (whistler/loader:map-info-name map) other-writes)))))
    (is (null other-writes))
    (is-false (gr8s::service-lb-controller-applied-signature controller))))

(test service-lb-restart-inventories-both-families-and-sparse-backends
  (multiple-value-bind (old entries update delete) (service-lb-cleanup-fixture)
    (let* ((dataplane (gr8s::service-lb-controller-dataplane old))
           (service (fake-lb-service "10.96.0.10" :ports '(80)))
           (next-key (service-lb-fixture-next-key entries)))
      (setf (gethash "clusterIPs" (gethash "spec" service)) #("10.96.0.10" "fd96::a"))
      (gr8s::converge-service-lb-controller
       old :list-services (constantly (list service))
       :endpoints-of (constantly '(("10.88.1.5" 8080) ("fd88::5" 8080)))
       :update update :delete delete)
      ;; Retained keys need not occupy a dense slot range, and the same slot
      ;; may exist in both families after an interrupted prior update.
      (dolist (family '(:ipv4 :ipv6))
        (funcall update (gr8s::service-lb-family-map dataplane family :backend)
                 (gr8s::service-lb-backend-key #xffffffff) #(0)))
      (is (= 8 (hash-table-count entries)))
      (setf (gr8s::service-lb-dataplane-reopened-p dataplane) t)
      (let ((controller (gr8s::make-service-lb-controller nil dataplane))
            (touched nil))
        (is-false (gr8s::service-lb-controller-map-state-adopted-p controller))
        ;; A failure after the first map was read must publish no inventory,
        ;; perform no writes, and leave the next tick able to retry all maps.
        (signals whistler/loader:bpf-error
          (gr8s::converge-service-lb-controller
           controller :list-services (constantly nil) :endpoints-of (constantly nil)
           :next-key (lambda (map previous)
                       (when (equal "gr8s_backend_v4" (whistler/loader:map-info-name map))
                         (error 'whistler/loader:bpf-error :context "map-get-next-key" :errno 5))
                       (funcall next-key map previous))
           :update (lambda (&rest ignored) (declare (ignore ignored)) (setf touched t))
           :delete (lambda (&rest ignored) (declare (ignore ignored)) (setf touched t))))
        (is-false touched)
        (is-false (gr8s::service-lb-controller-map-state-adopted-p controller))
        (is-false (gr8s::service-lb-controller-applied-service-keys controller))
        (is-false (gr8s::service-lb-controller-applied-backend-keys controller))
        (is-false (gr8s::service-lb-controller-applied-index-keys controller))
        ;; Inventory succeeds; fail cleanup after deleting the VIPs/backends.
        (signals whistler/loader:bpf-error
          (gr8s::converge-service-lb-controller
           controller :list-services (constantly nil) :endpoints-of (constantly nil)
           :next-key next-key :update update
           :delete (lambda (map key)
                     (when (search "backend_index" (whistler/loader:map-info-name map))
                       (error 'whistler/loader:bpf-error :context "map-delete" :errno 5))
                     (funcall delete map key))))
        (is (gr8s::service-lb-controller-map-state-adopted-p controller))
        (is (= 2 (hash-table-count entries)))
        (is-false (gr8s::service-lb-controller-applied-signature controller))
        (gr8s::converge-service-lb-controller
         controller :list-services (constantly nil) :endpoints-of (constantly nil)
         :next-key next-key :update update :delete delete)
        (is (zerop (hash-table-count entries)))
        (is (eq dataplane (gr8s::service-lb-controller-dataplane controller)))
        (gr8s::converge-service-lb-controller
         controller :list-services (constantly nil) :endpoints-of (constantly nil)
         :next-key (lambda (&rest ignored) (declare (ignore ignored)) (setf touched t))
         :update (lambda (&rest ignored) (declare (ignore ignored)) (setf touched t))
         :delete (lambda (&rest ignored) (declare (ignore ignored)) (setf touched t)))
        (is-false touched)))))

(test service-lb-repacking-removes-backends-from-the-old-family
  (multiple-value-bind (controller entries update delete) (service-lb-cleanup-fixture)
    (flet ((converge (address endpoint)
             (gr8s::converge-service-lb-controller
              controller :list-services (constantly (list (fake-lb-service address :ports '(80))))
              :endpoints-of (constantly (list (list endpoint 8080)))
              :update update :delete delete)))
      (converge "10.96.0.10" "10.88.1.5")
      (converge "fd96::a" "fd88::5")
      (is (= 3 (hash-table-count entries)))
      (is-false (loop for entry being the hash-keys of entries
                      thereis (search "_v4" (first entry))))
      (is (= 1 (gr8s::service-lb-controller-applied-slot-count controller))))))

;;; Traffic policies and topology, as kube-proxy's CategorizeEndpoints decides them.

(defun endpoint-record (address &key (ready t) (serving t) terminating node zone zone-hints node-hints)
  (list :address address :port 80 :ready ready :serving serving :terminating terminating
        :node node :zone zone :zone-hints zone-hints :node-hints node-hints))

(defun traffic-spec (&rest pairs)
  (let ((spec (gr8s::core-object "type" "ClusterIP" "internalTrafficPolicy" "Cluster")))
    (loop for (key value) on pairs by #'cddr do (setf (gethash key spec) value))
    spec))

(test endpoints-categorize-by-traffic-policy
  (let ((records (list (endpoint-record "10.0.0.1" :node "here")
                       (endpoint-record "10.0.1.1" :node "there")
                       (endpoint-record "10.0.0.2" :node "here" :ready nil :serving nil))))
    (multiple-value-bind (cluster local ready-local)
        (gr8s::categorize-service-endpoints records (traffic-spec) :node-name "here")
      (is (equal '(("10.0.0.1" 80) ("10.0.1.1" 80)) cluster))
      (is (null local))
      (is (= 1 ready-local)))
    (multiple-value-bind (cluster local)
        (gr8s::categorize-service-endpoints records (traffic-spec "internalTrafficPolicy" "Local") :node-name "here")
      (is (null cluster))
      (is (equal '(("10.0.0.1" 80)) local)))
    ;; A Local node port Service still keeps cluster endpoints for its ClusterIP.
    (multiple-value-bind (cluster local)
        (gr8s::categorize-service-endpoints records (traffic-spec "type" "NodePort" "externalTrafficPolicy" "Local")
                                            :node-name "elsewhere")
      (is (= 2 (length cluster)))
      (is (null local)))))

(test endpoints-fall-back-to-serving-terminating-ones
  (let ((records (list (endpoint-record "10.0.0.1" :node "here" :ready nil :serving t :terminating t)
                       (endpoint-record "10.0.1.1" :node "there" :ready nil :serving t :terminating t)
                       (endpoint-record "10.0.1.2" :node "there" :ready nil :serving nil :terminating t))))
    (multiple-value-bind (cluster local ready-local)
        (gr8s::categorize-service-endpoints records (traffic-spec "internalTrafficPolicy" "Local") :node-name "here")
      (is (null cluster))
      (is (equal '(("10.0.0.1" 80)) local))
      ;; Terminating endpoints still serve, but a health check reports none ready.
      (is (= 0 ready-local)))
    (is (equal '(("10.0.0.1" 80) ("10.0.1.1" 80))
               (gr8s::categorize-service-endpoints records (traffic-spec) :node-name "here")))))

(test endpoints-follow-topology-hints-only-when-every-ready-one-has-them
  (let ((hinted (list (endpoint-record "10.0.0.1" :node "a" :zone "z1" :zone-hints '("z1") :node-hints '("a"))
                      (endpoint-record "10.0.1.1" :node "b" :zone "z2" :zone-hints '("z2") :node-hints '("b")))))
    (is (equal '(("10.0.0.1" 80)) (gr8s::categorize-service-endpoints hinted (traffic-spec) :node-name "a" :zone "z1")))
    ;; Zone hints apply when no node hint names this node.
    (is (equal '(("10.0.1.1" 80)) (gr8s::categorize-service-endpoints hinted (traffic-spec) :node-name "c" :zone "z2")))
    ;; Hints that name neither this node nor its zone are ignored.
    (is (= 2 (length (gr8s::categorize-service-endpoints hinted (traffic-spec) :node-name "c" :zone "z3")))))
  (let ((partly (list (endpoint-record "10.0.0.1" :node "a" :zone-hints '("z1"))
                      (endpoint-record "10.0.1.1" :node "b"))))
    (is (= 2 (length (gr8s::categorize-service-endpoints partly (traffic-spec) :node-name "a" :zone "z1"))))))

(test service-lb-plan-serves-external-addresses-from-shared-slots
  (let ((service (fake-lb-service "10.96.0.10" :ports '(80))))
    (setf (gethash "externalIPs" (gethash "spec" service)) #("203.0.113.250")
          (gethash "status" service)
          (gr8s::core-object "loadBalancer"
                             (gr8s::core-object "ingress" (vector (gr8s::core-object "ip" "198.51.100.9")
                                                                  (gr8s::core-object "ip" "198.51.100.10" "ipMode" "Proxy")))))
    ;; The same backends: every address points at slot 0.
    (multiple-value-bind (service-entries backend-entries slots)
        (gr8s::service-lb-plan (list service) (lambda (s p) (declare (ignore s p))
                                                (values '(("10.88.1.5" 8080)) '(("10.88.1.5" 8080)))))
      (is (= 3 (length service-entries)))
      (is (= 1 (length backend-entries)))
      (is (= 1 slots))
      (is (equalp (gr8s::service-lb-vip-key "203.0.113.250" 80) (car (second service-entries))))
      (is (equalp (gr8s::service-lb-vip-key "198.51.100.9" 80) (car (third service-entries))))
      (is (equalp (gr8s::service-lb-service-value 1 0) (cdr (third service-entries)))))
    ;; internalTrafficPolicy Local on a node without endpoints: the ClusterIP has none, the
    ;; external addresses still reach every endpoint.
    (multiple-value-bind (service-entries backend-entries)
        (gr8s::service-lb-plan (list service) (lambda (s p) (declare (ignore s p))
                                                (values nil '(("10.88.1.5" 8080)))))
      (is (equalp (gr8s::service-lb-service-value 0 0) (cdr (first service-entries))))
      (is (equalp (gr8s::service-lb-service-value 1 0) (cdr (second service-entries))))
      (is (= 1 (length backend-entries))))))

(test services-labelled-for-another-proxy-are-left-alone
  (let ((other (fake-lb-service "10.96.0.11")) (headless (fake-lb-service "10.96.0.12")))
    (setf (gethash "labels" (gethash "metadata" other))
          (gr8s::core-object "service.kubernetes.io/service-proxy-name" "foo-bar")
          (gethash "labels" (gethash "metadata" headless))
          (gr8s::core-object "service.kubernetes.io/headless" ""))
    (is (null (gr8s::service-lb-plan (list other headless) (lambda (s p) (declare (ignore s p)) '(("10.88.1.5" 8080))))))))

;;; Unconnected UDP and affinity that follows its backend

(test service-lb-program-compiles-every-socket-hook
  ;; Both families steer connect/sendmsg and restore the Service address on UDP replies.
  (multiple-value-bind (maps programs) (gr8s::compile-service-lb)
    (is (equal '("gr8s_service_v4" "gr8s_backend_v4" "gr8s_backend_index_v4" "gr8s_affinity_v4" "gr8s_reverse_v4"
                 "gr8s_service_v6" "gr8s_backend_v6" "gr8s_backend_index_v6" "gr8s_affinity_v6" "gr8s_reverse_v6")
               (mapcar (lambda (spec) (getf spec :name)) maps)))
    (is (equal '("cgroup/connect4" "cgroup/sendmsg4" "cgroup/recvmsg4"
                 "cgroup/connect6" "cgroup/sendmsg6" "cgroup/recvmsg6")
               (mapcar (lambda (spec) (getf spec :section)) programs)))
    (is (equal (list whistler/loader:+bpf-cgroup-inet4-connect+
                     whistler/loader:+bpf-cgroup-udp4-sendmsg+ 19
                     whistler/loader:+bpf-cgroup-inet6-connect+
                     whistler/loader:+bpf-cgroup-udp6-sendmsg+ 20)
               (mapcar (lambda (spec) (gr8s::service-lb-attach-type (getf spec :section))) programs)))))

(test service-lb-affinity-index-finds-each-backend-by-identity
  ;; An affinity Service indexes each backend's offset by (service key, backend value), so
  ;; a client's held backend is found again wherever a change to the set moved it.
  (multiple-value-bind (vip-key value backends indexed)
      (gr8s::service-lb-entries "10.96.0.10" 80 5 '(("10.88.1.5" . 8080) ("10.88.1.6" . 8080)) :affinity-timeout 60)
    (declare (ignore value))
    (is (= 2 (length backends)))
    (is (equalp (gr8s::service-lb-index-key vip-key (gr8s::service-lb-backend-value "10.88.1.6" 8080))
                (car (second indexed))))
    (is (equalp #(1 0 0 0) (cdr (second indexed))))
    (is (= 16 (length (car (first indexed))))))
  ;; Membership is checked even without affinity, to reject another Service's
  ;; backend while shared slots are being repacked.
  (is (= 1 (length (nth-value 3 (gr8s::service-lb-entries "10.96.0.10" 80 0 '(("10.88.1.5" . 8080))))))))

(test service-lb-converge-retires-index-entries-of-departed-backends
  (let* ((index-map (fake-lb-map "gr8s_backend_index_v4" 3))
         (controller (gr8s::make-service-lb-controller
                      nil (gr8s::%make-service-lb-dataplane
                           :maps (list (fake-lb-map "gr8s_service_v4" 1) (fake-lb-map "gr8s_backend_v4" 2) index-map))))
         (service (fake-lb-service "10.96.0.10" :ports '(80))))
    (setf (gethash "sessionAffinity" (gethash "spec" service)) "ClientIP")
    (let ((writes nil))
      (gr8s::converge-service-lb-controller
       controller :list-services (lambda () (list service))
       :endpoints-of (lambda (s p) (declare (ignore s p)) '(("10.88.1.5" 8080) ("10.88.1.6" 8080)))
       :update (lambda (m k v) (declare (ignore k v)) (push (whistler/loader:map-info-fd m) writes))
       :delete (constantly nil))
      ;; Backends, then their index entries, then the Service.
      (is (equal '(2 2 3 3 1) (nreverse writes))))
    (let ((deletes nil))
      (gr8s::converge-service-lb-controller
       controller :list-services (lambda () (list service))
       :endpoints-of (lambda (s p) (declare (ignore s p)) '(("10.88.1.6" 8080)))
       :update (constantly nil)
       :delete (lambda (m k) (push (list (whistler/loader:map-info-fd m) k) deletes)))
      (is (member (list 3 (gr8s::service-lb-index-key (gr8s::service-lb-vip-key "10.96.0.10" 80)
                                                      (gr8s::service-lb-backend-value "10.88.1.5" 8080)))
                  deletes :test #'equalp)))))

;;; A Service with no endpoints anywhere is refused, as kube-proxy rejects it.

(test service-lb-refuses-a-service-with-no-endpoints-anywhere
  (is (= 1 (aref (gr8s::service-lb-service-value 0 0 :refuse t) 12)))
  ;; Refusal never applies while there are backends.
  (is (= 0 (aref (nth-value 1 (gr8s::service-lb-entries "10.96.0.10" 80 0 '(("10.88.1.5" . 8080)) :refuse t)) 12)))
  (let ((service (fake-lb-service "10.96.0.10" :ports '(80))))
    ;; No endpoints at all: refused.
    (is (= 1 (aref (cdr (first (gr8s::service-lb-plan (list service) (lambda (s p) (declare (ignore s p))
                                                                         (values nil nil t)))))
                   12)))
    ;; Endpoints only on other nodes (internalTrafficPolicy Local): left to time out, as kube-proxy drops it.
    (is (= 0 (aref (cdr (first (gr8s::service-lb-plan (list service) (lambda (s p) (declare (ignore s p))
                                                                         (values nil '(("10.88.1.5" 8080)) nil)))))
                   12)))))

(test endpoints-report-whether-any-exist
  (is (null (nth-value 3 (gr8s::categorize-service-endpoints
                          (list (endpoint-record "10.0.0.1" :ready nil :serving nil)) (traffic-spec)))))
  (is (eq t (nth-value 3 (gr8s::categorize-service-endpoints
                          (list (endpoint-record "10.0.1.1" :node "there"))
                          (traffic-spec "internalTrafficPolicy" "Local") :node-name "here")))))

(test service-lb-program-compiles-the-refusal
  ;; The refusal calls bpf_set_retval (helper 187) in the connect4 and sendmsg4 hooks.
  (multiple-value-bind (maps programs) (gr8s::compile-service-lb)
    (declare (ignore maps))
    (flet ((calls-helper-p (spec id)
             (let ((insns (getf spec :insns)))
               (loop for offset from 0 below (length insns) by 8
                     thereis (and (= #x85 (aref insns offset)) (zerop (logand (aref insns (1+ offset)) #xf0))
                                  (= id (aref insns (+ offset 4))))))))
      (is (calls-helper-p (first programs) 187))
      (is (calls-helper-p (second programs) 187))
      (is (not (calls-helper-p (third programs) 187))))))


(test service-packet-maintenance-is-loaded-but-never-attached
  (let ((attached nil))
    (let ((dataplane
            (gr8s::start-service-lb-dataplane
             "/fake/cgroup" "/fake/pins"
             :compile (lambda () (values nil nil)) :ensure-directory (constantly nil)
             :load-programs (lambda (&rest ignored)
                              (declare (ignore ignored))
                              (list (cons "gr8s_service_lb" (fake-lb-program 900021))
                                    (cons "gr8s_packet_gc" (whistler/loader::make-prog-info
                                                           :name "gr8s_packet_gc" :section-name "classifier"
                                                           :type 3 :fd 900022))))
             :attach (lambda (fd &rest ignored)
                       (declare (ignore ignored)) (push fd attached) :attachment))))
      (is (equal '(900021) attached))
      (is (= 2 (length (gr8s::service-lb-dataplane-programs dataplane)))))))

(test service-packet-maintenance-loader-uses-tc-without-cgroup-attach-type
  (let ((calls nil))
    (gr8s::load-service-lb-programs
     (list (list :name "gr8s_packet_gc" :section "classifier" :license "GPL" :insns #())
           (list :name "gr8s_service_lb" :section "cgroup/connect4" :license "GPL" :insns #()))
     nil :load-program (lambda (insns type license &key expected-attach-type)
                         (declare (ignore insns license))
                         (push (list type expected-attach-type) calls) 900023))
    (is (equal (list (list 18 whistler/loader:+bpf-cgroup-inet4-connect+) '(3 0)) calls))))

(defun service-packet-gc-fixture ()
  (let ((keys (make-hash-table :test #'equal)))
    (loop for name in '("gr8s_pkt_forward" "gr8s_pkt_reverse") for count in '(4 3)
          do (setf (gethash name keys)
                   (loop for i from 1 to count
                         collect (let ((key (make-array 16 :element-type '(unsigned-byte 8)
                                                       :initial-element 0)))
                                   (setf (aref key 0) i (aref key 12) 17) key))))
    (values
     (gr8s::%make-service-lb-dataplane
      :programs (list (cons "gr8s_packet_gc" (fake-lb-program 900031)))
      :maps (list (fake-lb-map "gr8s_pkt_forward" 900032)
                  (fake-lb-map "gr8s_pkt_reverse" 900033)))
     keys
     (lambda (map previous)
       (let ((entries (gethash (whistler/loader:map-info-name map) keys)))
         (if previous (second (member previous entries :test #'equalp)) (first entries)))))))

(test service-packet-gc-bounds-batches-and-resumes-through-deletion
  (multiple-value-bind (dataplane keys next-key) (service-packet-gc-fixture)
    (let ((seen nil))
      (flet ((gc-run (fd direction key)
               (is (= 900031 fd))
               (push (list direction (aref key 0)) seen)
               (let ((name (if (zerop direction) "gr8s_pkt_forward" "gr8s_pkt_reverse")))
                 (setf (gethash name keys) (remove key (gethash name keys) :test #'equalp)))
               1))
        (dotimes (i 4)
          (declare (ignore i))
          (multiple-value-bind (scanned reclaimed deferred)
              (gr8s.network:sweep-service-packet-state dataplane :budget 1 :next-key next-key :run #'gc-run)
            (is (<= scanned 2))
            (is (= scanned reclaimed))
            (is (zerop deferred))))
        (is (equal '((0 1) (1 1) (0 2) (1 2) (0 3) (1 3) (0 4)) (nreverse seen)))
        (is (= 7 (gr8s::service-lb-dataplane-gc-scanned dataplane)))
        (is (= 7 (gr8s::service-lb-dataplane-gc-reclaimed dataplane)))
        (is (every #'null (loop for value being the hash-values of keys collect value)))))))

(test service-packet-gc-defers-contention-and-recovers-after-run-failure
  (multiple-value-bind (dataplane keys next-key) (service-packet-gc-fixture)
    (declare (ignore keys))
    (let ((seen nil))
      (signals simple-error
        (gr8s.network:sweep-service-packet-state
         dataplane :budget 1 :next-key next-key
         :run (lambda (&rest ignored) (declare (ignore ignored)) (error "syscall interrupted"))))
      (is (= 1 (gr8s::service-lb-dataplane-gc-failures dataplane)))
      (multiple-value-bind (scanned reclaimed deferred)
          (gr8s.network:sweep-service-packet-state
           dataplane :budget 1 :next-key next-key
           :run (lambda (fd direction key)
                  (declare (ignore fd)) (push (list direction (aref key 0)) seen) 2))
        (is (= 2 scanned))
        (is (zerop reclaimed))
        (is (= 2 deferred)))
      (is (equal '((1 1) (0 2)) seen))
      (is (= 2 (gr8s::service-lb-dataplane-gc-deferred dataplane)))
      (signals type-error
        (gr8s.network:sweep-service-packet-state dataplane :budget 0)))))

(test service-packet-gc-is-idle-without-a-maintenance-program
  (let ((called nil))
    (is (zerop (gr8s.network:sweep-service-packet-state
                (gr8s::%make-service-lb-dataplane)
                :next-key (lambda (&rest ignored) (declare (ignore ignored)) (setf called t))
                :run (lambda (&rest ignored) (declare (ignore ignored)) (setf called t)))))
    (is-false called)))

(defun service-nat-gc-fixture ()
  (let ((keys (make-hash-table :test #'equal))
        (names '("gr8s_nat_fwd_v2" "gr8s_nat_rev_v2" "gr8s_nat_tcp_v2")))
    (loop for name in names for count in '(4 3 5) for width in '(16 16 32)
          do (setf (gethash name keys)
                   (loop for i from 1 to count
                         collect (let ((key (make-array width :element-type '(unsigned-byte 8)
                                                             :initial-element i)))
                                   (setf (aref key 12) 6 (aref key 13) 0
                                         (aref key 14) 0 (aref key 15) 0) key))))
    (values
     (gr8s::%make-service-lb-dataplane
      :programs (list (cons "gr8s_nat_gc" (fake-lb-program 900101)))
      :maps (loop for name in names for fd from 900102 collect (fake-lb-map name fd)))
     keys
     (lambda (map previous)
       (let ((entries (gethash (whistler/loader:map-info-name map) keys)))
         (if previous (second (member previous entries :test #'equalp)) (first entries)))))))

(test service-nat-gc-bounds-all-three-maps-and-retains-full-incarnation-keys
  (multiple-value-bind (dataplane keys next-key) (service-nat-gc-fixture)
    (let ((seen nil))
      (dotimes (tick 6)
        (declare (ignore tick))
        (multiple-value-bind (scanned reclaimed deferred)
            (gr8s.network::sweep-service-nat-state
             dataplane :budget 1 :next-key next-key
             :run (lambda (fd direction key)
                    (is (= fd 900101))
                    (is (= (length key) (if (= direction 2) 32 16)))
                    (when (= direction 2)
                      (is (= (aref key 31) (aref key 0))))
                    (push (list direction (aref key 0)) seen)
                    (let ((name (nth direction '("gr8s_nat_fwd_v2" "gr8s_nat_rev_v2" "gr8s_nat_tcp_v2"))))
                      (setf (gethash name keys) (remove key (gethash name keys) :test #'equalp)))
                    1))
          (is (<= scanned 3))
          (is (= scanned reclaimed))
          (is (zerop deferred))))
      (is (equal '((0 1) (1 1) (2 1) (0 2) (1 2) (2 2)
                   (0 3) (1 3) (2 3) (0 4) (2 4) (2 5)) (nreverse seen)))
      (is (= 12 (gr8s::service-lb-dataplane-gc-scanned dataplane)))
      (is (= 12 (gr8s::service-lb-dataplane-gc-reclaimed dataplane)))
      (is (every #'null (loop for value being the hash-values of keys collect value))))))

(test service-nat-gc-defers-contention-and-advances-failing-cursors
  (multiple-value-bind (dataplane keys next-key) (service-nat-gc-fixture)
    (declare (ignore keys))
    (let ((seen nil))
      (signals simple-error
        (gr8s.network::sweep-service-nat-state
         dataplane :budget 1 :next-key next-key
         :run (lambda (&rest ignored) (declare (ignore ignored)) (error "collector syscall failed"))))
      (is (= 1 (gr8s::service-lb-dataplane-gc-failures dataplane)))
      (multiple-value-bind (scanned reclaimed deferred)
          (gr8s.network::sweep-service-nat-state
           dataplane :budget 1 :next-key next-key
           :run (lambda (fd direction key)
                  (declare (ignore fd)) (push (list direction (aref key 0)) seen) 2))
        (is (= scanned 3))
        (is (= reclaimed 0))
        (is (= deferred 3)))
      (is (equal '((2 1) (1 1) (0 2)) seen))
      (is (= 3 (gr8s::service-lb-dataplane-gc-deferred dataplane)))
      (signals type-error (gr8s.network::sweep-service-nat-state dataplane :budget 0)))))

(test service-nat-gc-does-not-use-the-v1-maintenance-program
  (multiple-value-bind (dataplane keys next-key) (service-packet-gc-fixture)
    (declare (ignore keys next-key))
    (let ((called nil))
      (is (zerop (gr8s.network::sweep-service-nat-state
                  dataplane :next-key (lambda (&rest ignored) (declare (ignore ignored)) (setf called t))
                  :run (lambda (&rest ignored) (declare (ignore ignored)) (setf called t)))))
      (is-false called))))

(test service-nat-gc-envelope-preserves-epochs-and-rejects-the-wrong-abi
  (dolist (direction '(0 1 2))
    (let* ((width (if (= direction 2) 32 16))
           (key (make-array width :element-type '(unsigned-byte 8) :initial-element 0)))
      (dotimes (i width) (setf (aref key i) i))
      (let ((packet (gr8s.network::service-gc-envelope direction key)))
        (is (= (+ 36 width) (length packet)))
        (is (= (aref packet 17) (- (length packet) 14)))
        (is (= direction (aref packet 34)))
        (is (equalp key (subseq packet 36))))))
  (signals type-error (gr8s.network::run-service-nat-gc-key 0 3 #()))
  (signals simple-error (gr8s.network::run-service-nat-gc-key 0 2 (make-array 16)))
  (signals simple-error (gr8s.network::run-service-nat-gc-key 0 0 (make-array 32)))
  (signals type-error (gr8s.network:run-service-packet-gc-key 0 2 (make-array 32))))


(test service-packet-gc-defers-uncoordinated-retained-endpoints
  (multiple-value-bind (dataplane keys next-key) (service-packet-gc-fixture)
    (declare (ignore keys next-key))
    (dolist (entry '(("gr8s_pkt_fwd_lock" . 900034) ("gr8s_pkt_rev_lock" . 900035)
                     ("gr8s_pkt_tcp" . 900036)))
      (push (fake-lb-map (car entry) (cdr entry))
            (gr8s::service-lb-dataplane-maps dataplane)))
    (let ((legacy t) (queries 0) (*error-output* (make-string-output-stream)))
      (flet ((verify ()
               (gr8s.network:service-packet-gc-compatible-p
                dataplane :paths (constantly '("endpoint/gr8s_pkt_stages"))
                :refresh (constantly t)
                :map-id #'whistler/loader:map-info-fd
                :stage-map-ids (lambda (path)
                                 (declare (ignore path)) (incf queries)
                                 (list (if legacy '(900032 900033)
                                           '(900032 900033 900034 900035 900036))
                                       '(900032 900033 900034 900035 900036))))))
        (is-false (verify))
        (is-false (gr8s::service-lb-dataplane-gc-compatible-p dataplane))
        (is (search "Service flow GC deferred:" (get-output-stream-string *error-output*)))
        (is-false (verify))
        (is (equal "" (get-output-stream-string *error-output*)))
        (setf legacy nil)
        (is-true (verify))
        (is (= 1 (gr8s::service-lb-dataplane-gc-compatible-stage-count dataplane)))
        (is (null (gr8s::service-lb-dataplane-gc-warning dataplane)))
        (is-true (verify))
        (is (= 3 queries))))))


(test service-packet-maintenance-load-failure-closes-earlier-hooks
  (let ((closed nil))
    (signals simple-error
      (gr8s::load-service-lb-programs
       (list (list :name "gr8s_service_lb" :section "cgroup/connect4" :license "GPL" :insns #())
             (list :name "gr8s_packet_gc" :section "classifier" :license "GPL" :insns #()))
       nil :load-program (lambda (insns type license &key expected-attach-type)
                           (declare (ignore insns license expected-attach-type))
                           (if (= type 3) (error "collector rejected") 900041))
       :close-fd (lambda (fd) (push fd closed))))
    (is (equal '(900041) closed))))

(test service-packet-gc-does-not-reuse-a-successful-check-while-an-upgrade-is-pending
  (multiple-value-bind (dataplane keys next-key) (service-packet-gc-fixture)
    (declare (ignore keys next-key))
    (setf (gr8s::service-lb-dataplane-gc-compatible-p dataplane) t)
    (let ((*error-output* (make-string-output-stream)))
      (is-false (gr8s.network:service-packet-gc-compatible-p
                 dataplane :paths (constantly nil) :refresh (constantly nil)
                 :map-id (lambda (map) (declare (ignore map)) (error "must defer before map checks"))))
      (is-false (gr8s::service-lb-dataplane-gc-compatible-p dataplane))
      (is (search "packet pipeline upgrades are pending" (get-output-stream-string *error-output*))))))

(test service-packet-load-diagnostics-retain-gc-gating-until-verified-recovery
  (multiple-value-bind (dataplane keys next-key) (service-packet-gc-fixture)
    (declare (ignore keys next-key))
    (dolist (entry '(("gr8s_pkt_fwd_lock" . 900034) ("gr8s_pkt_rev_lock" . 900035)
                     ("gr8s_pkt_tcp" . 900036)))
      (push (fake-lb-map (car entry) (cdr entry)) (gr8s::service-lb-dataplane-maps dataplane)))
    (setf (gr8s::service-lb-dataplane-gc-compatible-p dataplane) t)
    (let ((failed t) (verified 0) (*error-output* (make-string-output-stream)))
      (labels ((refresh-endpoint (directory shared cache allow-load)
                 (declare (ignore directory shared cache allow-load))
                 (if failed
                     (error 'whistler/loader:bpf-verifier-error
                            :context "prog-load" :errno 28 :log "retained-program trace"
                            :log-buf-size 32
                            :initial-error (make-condition 'whistler/loader:bpf-error
                                                           :context "prog-load" :errno 13))
                     :current))
               (verify ()
                 (gr8s.network:service-packet-gc-compatible-p
                  dataplane :paths (constantly '("endpoint/gr8s_pkt_stages"))
                  :refresh (lambda (plane paths)
                             (gr8s.network::refresh-service-packet-pipelines
                              plane paths :refresh #'refresh-endpoint))
                  :map-id #'whistler/loader:map-info-fd
                  :stage-map-ids (lambda (path)
                                   (declare (ignore path)) (incf verified)
                                   (list '(900032 900033 900034 900035 900036)
                                         '(900032 900033 900034 900035 900036))))))
        (is-false (verify))
        (is-false (gr8s::service-lb-dataplane-gc-compatible-p dataplane))
        (is (= 0 verified))
        (let ((diagnostic (get-output-stream-string *error-output*)))
          (is (search "errno 13" diagnostic))
          (is (search "errno 28" diagnostic))
          (is (search "retained-program trace" diagnostic))
          (is (search "Service flow GC deferred" diagnostic)))
        (is-false (verify))
        (is (equal "" (get-output-stream-string *error-output*)))
        (setf failed nil)
        (is-true (verify))
        (is (= 1 verified))
        (is (= 0 (hash-table-count (gr8s::service-lb-dataplane-upgrade-warnings dataplane))))
        (is (null (gr8s::service-lb-dataplane-gc-warning dataplane)))))))

(test service-nat-policy-schema-is-separate-from-legacy-policy-state
  (let* ((legacy (copy-tree gr8s.network::*egress-guard-map-forms*))
         (forms (gr8s.network::service-nat-policy-map-forms)))
    (flet ((spec (name) (find name forms :key #'second)))
      (is (= 48 (getf (cddr (spec 'whistler::endpoint-identity)) :value-size)))
      (is (= 32 (getf (cddr (spec 'whistler::netpol-flows-v2)) :key-size)))
      (is (= 8 (getf (cddr (spec 'whistler::netpol-flows-v2)) :value-size)))
      (is (= 128 (getf (cddr (spec 'whistler::gr8s-nat-id-v2)) :map-flags)))
      (is (= 129 (getf (cddr (spec 'whistler::gr8s-nat-pod-v2)) :map-flags)))
      (is-false (spec 'whistler::netpol-flows)))
    (is (equal legacy gr8s.network::*egress-guard-map-forms*))
    (is (= 32 (getf (cddr (find 'whistler::endpoint-identity legacy :key #'second)) :value-size)))
    (is (= 12 (getf (cddr (find 'whistler::netpol-flows legacy :key #'second)) :key-size)))))

(test legacy-policy-adoption-rejects-the-v2-local-identity-width
  (let ((info (make-array 256 :element-type '(unsigned-byte 8) :initial-element 0)))
    (loop for (offset value) in '((0 2) (8 4) (12 48) (16 1) (20 128))
          do (replace info (gr8s::netlink-integer value 4) :start1 offset))
    (signals gr8s::cni-error
      (gr8s::cni-policy-map-info 42 "endpoint_identity"
                               :object-info (lambda (fd) (declare (ignore fd)) info)))))
