;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Agent side of cross-node Pod->Pod delivery, send path (epic podster-pnd,
;;;; podster-xuc). The egress guard (egress-guard-program.lisp) redirects a
;;;; packet whose destination is a Pod on ANOTHER node straight to the local
;;;; gr8s-vxlan device, after rewriting its L2 header to that peer's VXLAN router
;;;; MAC. The kernel VXLAN driver then FDB-resolves the peer's underlay VTEP and
;;;; encapsulates, so the frame never crosses the host firewall's FORWARD reject.
;;;;
;;;; That fast path is driven by the remote_pod_v4 map: an LPM key per peer Pod
;;;; CIDR -> {gr8s-vxlan ifindex, VXLAN router dst MAC, gr8s-vxlan src MAC}. The
;;;; router MAC is vxlan-router-mac of the peer CIDR -- the same deterministic MAC
;;;; replace-vxlan-peer installs in the kernel FDB and static ARP -- so the
;;;; redirected frame resolves to exactly the VTEP the kernel would have chosen.
;;;;
;;;; On every node reconcile the agent rebuilds the node's remote-CIDR table from
;;;; the peer routes already driving the VXLAN tunnel and writes it into each
;;;; local Pod's pinned remote_pod_v4 (every Pod's table is the same peer set).

(in-package #:gr8s)

(defun remote-pod-cidr-value (vxlan-ifindex router-mac vxlan-mac)
  "The 16-byte remote_pod_v4 value: the gr8s-vxlan IFINDEX (u32, native order),
   the peer's 6-byte VXLAN ROUTER-MAC (the redirected frame's dst), and the local
   6-byte gr8s-vxlan VXLAN-MAC (its src) -- the same layout encode-local-pod-value
   writes and the egress guard reads at offsets 0 / 4 / 10."
  (encode-local-pod-value vxlan-ifindex router-mac vxlan-mac))

(defun node-remote-pod-table
    (cidrs &key (interface-index #'native-interface-index)
                (link-attributes #'network-link-attributes))
  "Build the node-wide cross-node delivery table (alist of 8-byte LPM CIDR key ->
   16-byte value) from the peer Pod CIDRS. Returns NIL when gr8s-vxlan is not up
   yet (no ifindex/MAC), so a reconcile before the tunnel exists is a no-op."
  (let* ((ifindex (funcall interface-index +node-vxlan-interface+))
         (vxlan-mac (and (plusp ifindex)
                         (gethash 1 (funcall link-attributes +node-vxlan-interface+)))))
    (when (and (plusp ifindex) vxlan-mac (= 6 (length vxlan-mac)))
      (loop for cidr in cidrs
            collect (cons (netpol-cidr-lpm-key cidr)
                          (remote-pod-cidr-value ifindex (vxlan-router-mac cidr) vxlan-mac))))))

(defun write-remote-pod-table
    (directory table
     &key (open #'whistler/loader:open-pinned-object)
          (map-info #'cni-policy-map-info)
          (update #'whistler/loader:map-update)
          (close #'sb-posix:close))
  "Write the node-wide TABLE (alist of 8-byte key -> 16-byte value) into the
   remote_pod_v4 map pinned under DIRECTORY. Idempotent."
  (let ((fd nil))
    (unwind-protect
         (progn
           (setf fd (funcall open (concatenate 'string (namestring directory) "remote_pod_v4")))
           (let ((info (funcall map-info fd "remote_pod_v4")))
             (loop for (key . value) in table do (funcall update info key value))))
      (when fd (ignore-errors (funcall close fd))))))

(defun converge-node-remote-pod-delivery
    (sandboxes cidrs &key directory-fn
                          (table-fn #'node-remote-pod-table)
                          (writer #'write-remote-pod-table))
  "Rebuild the node's cross-node delivery table from the peer Pod CIDRS and write
   it into every local Pod's pinned remote_pod_v4. SANDBOXES is the list of local
   Pod sandbox ids; DIRECTORY-FN maps a sandbox to its bpffs pin directory.
   Fail-soft per Pod; returns the sandboxes written. A nil/empty table still runs,
   clearing stale peers is left to the map's natural overwrite on the next peer."
  (let ((table (funcall table-fn cidrs))
        (written '()))
    (when table
      (dolist (sandbox sandboxes)
        (handler-case
            (progn (funcall writer (funcall directory-fn sandbox) table)
                   (push sandbox written))
          (error () nil))))
    (nreverse written)))
