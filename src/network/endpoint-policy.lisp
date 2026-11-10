;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Endpoint policy state for the Whistler eBPF CNI data path.
;;;;
;;;; Each Pod endpoint pins a small set of Whistler maps and a TCX link under its
;;;; sandbox directory. This file is the control-plane side of that state: it
;;;; verifies a pinned object really matches the schema gr8s expects before
;;;; trusting it (BPF_OBJ_GET_INFO_BY_FD, because the kernel copies its own
;;;; value_size, not ours), writes and checks the endpoint identity -- the Pod's
;;;; IPv4 address and MAC -- that the datapath enforces against spoofing, confirms
;;;; the TCX link is attached to the intended interface and direction, and reads
;;;; back the spoof and traffic counters for status reporting.

(in-package #:gr8s.network)

(defun cni-policy-map-path (map-path name)
  "Resolve the pin path for the Whistler map NAME. The \"rejected_spoofs\" map
   lives at MAP-PATH itself; any other map is a sibling file of that name in the
   same directory."
  (if (string= name "rejected_spoofs") map-path
      (namestring (merge-pathnames name (uiop:pathname-directory-pathname map-path)))))

(defun bpf-object-kernel-info (fd)
  "Query the kernel's info record for the BPF object FD (BPF_OBJ_GET_INFO_BY_FD)
   and return it as a 256-byte vector, so a pinned object's real schema can be
   checked before buffers are handed to it."
  ;; BPF_OBJ_GET_INFO_BY_FD. Validate pinned map sizes before passing buffers to
  ;; map-lookup/update: the kernel copies its actual value_size, not ours.
  (let ((attribute (whistler/loader::make-attr-buf))
        (info (make-array 256 :element-type '(unsigned-byte 8) :initial-element 0)))
    (whistler/loader::put-u32 attribute 0 fd)
    (whistler/loader::put-u32 attribute 4 (length info))
    (sb-sys:with-pinned-objects (info)
      (whistler/loader::put-ptr attribute 8 (sb-sys:vector-sap info))
      (whistler/loader::%bpf 15 attribute 16 "gr8s object-info"))
    info))

(defun cni-policy-map-info (fd name &key (object-info #'bpf-object-kernel-info)
                                        (profile *cni-policy-profile*))
  "Return a Whistler MAP-INFO for the pinned map FD named NAME, after verifying
   its kernel type, key and value sizes, capacity and flags against the expected
   spec in +CNI-POLICY-MAP-SPECS+. Signals INVALID-CNI on any schema mismatch.
   OBJECT-INFO is the info query, injectable for tests."
  (let* ((info (funcall object-info fd))
         (legacy (append +cni-policy-map-specs+
                         '(("gr8s_pkt_stages" 3 4 4 8 0))
                         (service-packet-map-specs)))
         (candidates (case profile
                       (:v1 legacy)
                       (:v2 (service-nat-map-specs))
                       (otherwise (append legacy (service-nat-map-specs)))))
         (spec (find-if
                (lambda (candidate)
                  (and (string= name (first candidate))
                       (>= (length info) 24)
                       (= (second candidate) (netlink-read-integer info 0 4))
                       (= (third candidate) (netlink-read-integer info 8 4))
                       (= (fourth candidate) (netlink-read-integer info 12 4))
                       (= (fifth candidate) (netlink-read-integer info 16 4))
                       (= (sixth candidate) (netlink-read-integer info 20 4))))
                candidates)))
    (unless spec
      (invalid-cni "pinned Whistler map ~A has an incompatible schema" name))
    (destructuring-bind (&optional sname type key-size value-size max-entries flags) spec
      (declare (ignore sname))
      (whistler/loader::make-map-info
       :name name :type type :key-size key-size :value-size value-size
       :max-entries max-entries :flags flags :fd fd))))

(defconstant +cni-policy-native-attachment+ 1)
(defconstant +cni-policy-chained-attachment+ 2)

(defun cni-policy-attachment-mode (configuration)
  "Return the datapath attachment mode for CONFIGURATION. Native routing guards
   a host veth and may use host-interface redirects; a chained CNI guard runs on
   the Pod interface and must leave delivery to the primary plugin."
  (if (cni-configuration-policy-interface-name configuration)
      +cni-policy-native-attachment+
      +cni-policy-chained-attachment+))

(defun encode-cni-endpoint-identity
    (addresses mac &optional (attachment-mode +cni-policy-native-attachment+))
  "Encode Pod IPv4/IPv6 addresses, MAC, and attachment mode for the datapath."
  (unless (and mac (= 6 (length mac)))
    (invalid-cni "the Pod interface has no Ethernet identity"))
  (let* ((items (if (stringp addresses) (list addresses) addresses))
         (ipv4 (find-if-not (lambda (address) (find #\: address)) items))
         (ipv6 (find-if (lambda (address) (find #\: address)) items)))
    (netlink-octets
     (netlink-integer (if ipv4 (parse-ipv4-integer ipv4) 0) 4)
     (netlink-integer (loop for index below 4 sum (ash (aref mac index) (- 24 (* index 8)))) 4)
     (netlink-integer (+ (ash (aref mac 4) 8) (aref mac 5)) 4)
     (netlink-integer attachment-mode 4)
     (if ipv6 (0conf:parse-ipv6 ipv6)
         (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0)))))

(defun cni-endpoint-identity (configuration context)
  "Build the endpoint-identity value for the Pod described by CONFIGURATION and
   CONTEXT, reading the Pod interface's MAC from inside its network namespace.
   Signals INVALID-CNI when the agent has assigned no endpoint address."
  (let ((addresses (or (cni-configuration-endpoint-addresses configuration)
                       (let ((address (cni-configuration-endpoint-address configuration)))
                         (and address (list address))))))
    (unless addresses (invalid-cni "the agent has not assigned an endpoint address"))
    (encode-cni-endpoint-identity
     addresses
     (call-with-cni-network-namespace
      (cni-context-netns context)
      (lambda () (gethash 1 (network-link-attributes (cni-context-interface-name context)))))
     (cni-policy-attachment-mode configuration))))

(defun initialize-cni-identity (map configuration context)
  "Write the Pod's endpoint identity into MAP at key 0, the entry the datapath
   checks on every packet."
  (whistler/loader:map-update map (netlink-integer 0 4)
                              (cni-endpoint-identity configuration context)))

(defun check-cni-identity (map configuration context)
  "Signal INVALID-CNI unless MAP's key-0 identity equals the one derived from
   CONFIGURATION and CONTEXT -- i.e. the pinned map still matches the agent's
   IPAM and the live Pod link."
  (unless (equalp (whistler/loader:map-lookup map (netlink-integer 0 4))
                  (cni-endpoint-identity configuration context))
    (invalid-cni "Whistler endpoint identity does not match agent IPAM and the Pod link")))

(defun check-cni-tcx-link (fd index direction &key (object-info #'bpf-object-kernel-info))
  "Signal INVALID-CNI unless the pinned link FD is a TCX link attached to
   interface INDEX in DIRECTION (\"egress\", otherwise ingress), confirming the
   policy program guards the intended Pod interface. OBJECT-INFO is injectable for
   tests."
  (let ((info (funcall object-info fd)))
    (unless (and (>= (length info) 24)
                 (= 11 (netlink-read-integer info 0 4)) ; TCX
                 (= index (netlink-read-integer info 16 4))
                 (= (if (string= direction "egress") 47 46)
                    (netlink-read-integer info 20 4)))
      (invalid-cni "pinned TCX link does not enforce the selected Pod interface"))))

(defun cni-policy-staged-links (link-path)
  "List the staged (not-yet-committed) link pins for LINK-PATH -- the files
   matching its \"_pending_*\" suffix."
  (directory (concatenate 'string link-path "_pending_*")))

(defun read-cni-policy-counters (root sandbox-id)
  "Read the Whistler policy counters for SANDBOX-ID under ROOT and return them in
   a hash table keyed by status-field name: \"rejectedSpoofs\" from the spoof map,
   and the six allowed/dropped/malformed/unsupported packet and byte counters
   from the traffic-stats map. Opens and closes each pinned map."
  (multiple-value-bind (map-path link-path directory) (cni-pin-paths root sandbox-id)
    (declare (ignore link-path directory))
    (let ((result (make-hash-table :test #'equal)))
      (dolist (name '("rejected_spoofs" "traffic_stats"))
        (let* ((path (cni-policy-map-path map-path name))
               (fd (whistler/loader:open-pinned-object path)))
          (unwind-protect
               (let ((map (cni-policy-map-info fd name)))
                 (if (string= name "rejected_spoofs")
                     (setf (gethash "rejectedSpoofs" result) (whistler/loader:map-lookup-int map 0))
                     (loop for key in '("allowedPackets" "allowedBytes" "droppedPackets"
                                        "droppedBytes" "malformedPackets" "unsupportedPackets")
                           for index from 0
                           do (setf (gethash key result)
                                    (whistler/loader:map-lookup-int map index)))))
            (sb-posix:close fd))))
      result)))

(defun detach-cni-tcx-link (fd &key (bpf #'whistler/loader::%bpf))
  "Synchronously detach an owned TCX link and drain its preexisting executions."
  (let ((attribute (whistler/loader::make-attr-buf)))
    (whistler/loader::put-u32 attribute 0 fd)
    (funcall bpf 34 attribute 4 "detach CNI TCX link")))

(defun retire-cni-tcx-link
    (path &key (open-pinned #'whistler/loader:open-pinned-object)
               (object-info #'bpf-object-kernel-info) (detach #'detach-cni-tcx-link)
               (close-fd #'sb-posix:close))
  "Stop a pinned guard before unpinning; other open FDs cannot keep it executing."
  (let ((fd (funcall open-pinned path)))
    (unwind-protect
         (progn
           (unless (= 11 (netlink-read-integer (funcall object-info fd) 0 4))
             (invalid-cni "refusing to retire a non-TCX policy pin ~A" path))
           (funcall detach fd))
      (funcall close-fd fd))))
