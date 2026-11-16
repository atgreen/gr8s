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
;;;; CRC32c case is deferred and such packets are dropped, which matches the
;;;; SCTP behaviour documented by other eBPF dataplanes ("targetPort MUST equal the port").
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
      (when (> (+ data 14) data-end) (return TCX-NEXT))
      (when (/= (eth-type data) #x0800) (return TCX-NEXT))
      (when (> (+ data 34) data-end) (return TCX-NEXT))
      ;; SCTP only; leave TCP/UDP to the socket LB. No IP options (IHL 5).
      (when (/= (load u8 data 23) 132) (return TCX-NEXT))
      (when (/= (logand (load u8 data 14) 15) 5) (return TCX-NEXT))
      ;; SCTP common header is 12 bytes: src port, dst port, verification tag, CRC.
      (when (> (+ data 46) data-end) (return TCX-NEXT))
      (let ((dstip u32 (load u32 data 30))
            (dport u16 (load u16 data 36)))
        (let ((key u64 (logior (<< (cast u64 132) 48)
                               (logior (<< (cast u64 dstip) 16) (cast u64 dport)))))
          (let ((service (map-lookup gr8s-service-v4 key)))
            (when (= service 0) (return TCX-NEXT))
            (let ((count u32 (load u16 service 0)))
              (when (= count 0) (return TCX-NEXT))
              ;; One backend per association: SCTP keeps no affinity map here.
              ;; A VIP with several backends spreads associations by source port.
              (let ((offset u32 (mod (cast u32 (load u16 data 34)) count))
                    (base u32 (load u32 service 4)))
                (let ((backend (map-lookup gr8s-backend-v4 (+ base offset))))
                  (when (= backend 0) (return TCX-NEXT))
                  (let ((podip u32 (load u32 backend 0))
                        (podport u16 (load u16 backend 4)))
                    (when (= podip 0) (return TCX-NEXT))
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
                    (return TCX-NEXT)))))))))))

(defun gr8s.network::service-sctp-snat-form ()
  "Reverse: on Pod ingress, restore the VIP as the source of an SCTP reply from a
backend, so the client's association (opened to the VIP) accepts it."
  '(defprog gr8s-sctp-snat (:type :tc :section "classifier" :license "GPL")
    (let ((data u64 (tc-data)) (data-end u64 (tc-data-end)))
      (when (> (+ data 14) data-end) (return TCX-NEXT))
      (when (/= (eth-type data) #x0800) (return TCX-NEXT))
      (when (> (+ data 38) data-end) (return TCX-NEXT))
      (when (/= (load u8 data 23) 132) (return TCX-NEXT))
      (when (/= (logand (load u8 data 14) 15) 5) (return TCX-NEXT))
      (let ((ct (make-sctp-ct-key)))
        (setf (sctp-ct-key-client ct) (load u32 data 30)
              (sctp-ct-key-backend ct) (load u32 data 26)
              (sctp-ct-key-cport ct) (load u16 data 36)
              (sctp-ct-key-bport ct) (load u16 data 34)
              (sctp-ct-key-pad ct) 0)
        (let ((val (map-lookup-ptr gr8s-sctp-ct ct)))
          (when (= val 0) (return TCX-NEXT))
          (let ((cluster u32 (load u32 val 0))
                (oldsrc u32 (load u32 data 26)))
            (when (/= (l3-csum-replace (ctx-ptr) 24 oldsrc cluster 4) 0)
              (return TC_ACT_SHOT))
            (let ((newaddr (make-sctp-addr)))
              (setf (sctp-addr-value newaddr) cluster
                    (sctp-addr-pad newaddr) 0)
              (when (/= (skb-store-bytes (ctx-ptr) 26 newaddr 4 2) 0)
                (return TC_ACT_SHOT)))
            (return TCX-NEXT)))))))

(in-package #:gr8s.network)

(defconstant +tcx-next+ -1
  "The TCX chain-continue action. A TCX program that returns TC_ACT_OK (0) is
TCX_PASS: it accepts the packet and STOPS the chain, so the policy guard sharing
the hook would never run. Returning TCX_NEXT (-1) continues to the next program.
The SCTP classifiers therefore return TCX-NEXT on every pass path and attach
ahead of the guard, so the guard still enforces policy on the translated packet.")

(defun compile-service-sctp-nat ()
  "Compile the SCTP forward (DNAT) and reverse (SNAT) TC classifiers over the
shared Service maps plus the SCTP conntrack map. The TCX-NEXT sentinel in the
program source is the chain-continue return value (-1); substitute it here so the
program text stays legible rather than carrying a bare -1."
  (compile-whistler-program
   (service-sctp-map-forms)
   (append *service-sctp-struct-forms*
           (mapcar (lambda (form) (subst +tcx-next+ 'whistler::tcx-next form))
                   (list (service-sctp-dnat-form)
                         (service-sctp-snat-form))))))

(defparameter +sctp-nat-shared-map-names+ '("gr8s_service_v4" "gr8s_backend_v4")
  "Node-shared Service maps the socket LB pins; the SCTP classifiers only read them.")

(defun sctp-nat-link-path (link-path name)
  "Pin path for an SCTP classifier's TCX link, beside the policy guard links.
bpffs rejects a dot in a pin basename, so the program name (with its underscore)
is used verbatim."
  (format nil "~A_~A" link-path name))

(defun open-sctp-shared-maps (pin-directory map-specs
                              &key (open-pinned #'whistler/loader:open-pinned-object))
  "Open the socket LB's pinned Service/backend maps as (name . map-info), typed
from the compiled MAP-SPECS so relocation sees the right descriptors."
  (loop for name in +sctp-nat-shared-map-names+
        for spec = (find name map-specs :key (lambda (s) (getf s :name)) :test #'equal)
        for path = (namestring (merge-pathnames name (uiop:ensure-directory-pathname pin-directory)))
        collect (cons name (whistler/loader::make-map-info
                            :name name
                            :type (whistler/compiler:resolve-map-type (getf spec :type))
                            :key-size (getf spec :key-size) :value-size (getf spec :value-size)
                            :max-entries (getf spec :max-entries) :flags (or (getf spec :flags) 0)
                            :fd (funcall open-pinned path)))))

(defun relocate-sctp-program (spec maps descriptors)
  "Return a copy of SPEC's instructions with each map relocation patched to its
descriptor, as Whistler's session loader does."
  (let ((instructions (copy-seq (getf spec :insns))))
    (loop for (offset index) in (getf spec :relocs)
          for descriptor = (cdr (assoc (car (nth index maps)) descriptors :test #'string=))
          do (setf (aref instructions (+ offset 1))
                   (logior (logand (aref instructions (+ offset 1)) #x0f) (ash 1 4)))
             (loop for byte from 0 below 4
                   do (setf (aref instructions (+ offset 4 byte))
                            (ldb (byte 8 (* 8 byte)) descriptor))))
    instructions))

(defun install-cni-sctp-nat
    (configuration context pin-directory link-path
     &key (open-pinned #'whistler/loader:open-pinned-object)
          (create-maps (lambda (specs) (whistler/loader::session-create-maps specs)))
          (load-program #'whistler/loader::load-program)
          (attach-tcx (lambda (fd index direction)
                        (whistler/loader:attach-tcx fd index :direction direction)))
          (pin-object #'whistler/loader:pin-bpf-object)
          (remove-path #'uiop:delete-file-if-exists)
          (call-in-netns #'call-with-cni-network-namespace)
          (interface-index #'cni-interface-index)
          (close-fd #'sb-posix:close))
  "Attach the SCTP ClusterIP DNAT and SNAT classifiers on this Pod's own veth,
inside its network namespace, where no policy guard shares the TCX hook -- so the
classifiers never have to chain with the guard. DNAT runs on Pod egress (Pod ->
ClusterIP) and rewrites the destination to a backend before the packet reaches
the host veth, so the egress guard there still sees the real backend address;
SNAT runs on Pod ingress and restores the VIP as the reply's source.

The conntrack map is created per-Pod (forward and reverse both run on this veth);
the Service/backend maps are opened from the node's shared socket-LB pins. Each
TCX link is pinned so it survives this process and can be removed on DEL. The
caller treats this as best-effort: a missing socket LB must never wedge ADD."
  (declare (ignore configuration))
  (multiple-value-bind (map-specs program-specs) (compile-service-sctp-nat)
    (let* ((ct-spec (find "gr8s_sctp_ct" map-specs :key (lambda (s) (getf s :name)) :test #'equal))
           (shared (open-sctp-shared-maps pin-directory map-specs :open-pinned open-pinned))
           (ct (funcall create-maps (list ct-spec)))
           ;; The relocation index follows service-sctp-map-forms order exactly:
           ;; gr8s_service_v4, gr8s_backend_v4, then gr8s_sctp_ct.
           (maps (append shared ct))
           (descriptors (mapcar (lambda (e) (cons (car e) (whistler/loader:map-info-fd (cdr e)))) maps))
           (map-fds (mapcar (lambda (e) (whistler/loader:map-info-fd (cdr e))) ct))
           (pinned nil) (program-fds nil) (committed nil)
           ;; DNAT on Pod egress, SNAT on Pod ingress -- the Pod-side veth directions.
           (loaded (loop for (name . dir) in '(("gr8s_sctp_dnat" . "egress")
                                               ("gr8s_sctp_snat" . "ingress"))
                         for spec = (or (find name program-specs
                                             :key (lambda (s) (getf s :name)) :test #'equal)
                                        (invalid-cni "SCTP program ~A missing from compile" name))
                         for fd = (funcall load-program (relocate-sctp-program spec maps descriptors)
                                           whistler/loader::+bpf-prog-type-sched-cls+
                                           (getf spec :license))
                         do (push fd program-fds)
                         collect (list fd dir name))))
      (unwind-protect
           (progn
             (funcall call-in-netns (cni-context-netns context)
                      (lambda ()
                        (let ((index (funcall interface-index (cni-context-interface-name context))))
                          (dolist (item loaded)
                            (destructuring-bind (fd dir name) item
                              (let ((link-fd (funcall attach-tcx fd index dir))
                                    (path (sctp-nat-link-path link-path name)))
                                (funcall pin-object link-fd path)
                                (push path pinned)
                                (funcall close-fd link-fd)))))))
             (setf committed t))
        (dolist (fd program-fds) (ignore-errors (funcall close-fd fd)))
        (dolist (entry shared) (ignore-errors (funcall close-fd (whistler/loader:map-info-fd (cdr entry)))))
        (unless committed
          (dolist (path pinned) (ignore-errors (funcall remove-path path)))
          (dolist (fd map-fds) (ignore-errors (funcall close-fd fd))))))
    (values)))

(defun remove-cni-sctp-nat (link-path &key (remove-path #'uiop:delete-file-if-exists))
  "Remove the SCTP classifier link pins on DEL. The TCX links detach with the
host veth; unpinning only clears the bpffs entries."
  (dolist (name '("gr8s_sctp_dnat" "gr8s_sctp_snat"))
    (ignore-errors (funcall remove-path (sctp-nat-link-path link-path name))))
  (values))
