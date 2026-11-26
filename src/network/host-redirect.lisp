;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Agent side of Pod->host delivery (epic podster-pnd, podster-9b1).
;;;; The egress guard (egress-guard-program.lisp) redirects a packet to the
;;;; loopback ingress -- iif=lo, which the host firewall trusts -- when its
;;;; destination is a host-local address, so Pod traffic to the API server
;;;; (10.96.0.1:443) or to this node's own IP never crosses the host firewall's
;;;; INPUT path. That fast path is driven by the host_redirect_v4 map: the
;;;; destination IPv4 (network order) as a 4-byte key -> a presence byte.
;;;;
;;;; On every node reconcile the agent rebuilds the node's host-local set and
;;;; writes it into each local Pod's pinned host_redirect_v4 (every Pod's table
;;;; is the same set of host-local destinations). The API server address is
;;;; fixed; the node's own IP comes from the runtime.

(in-package #:gr8s.network)

(defun host-redirect-key (address)
  "The 4-byte host_redirect_v4 key the egress guard looks up: the destination
   address in network byte order -- the same bytes the program's (load u32 ip 16)
   spills as the scalar key."
  (ipv4-network-octets address))

(defun node-host-redirect-table (node-address &key confined)
  "The node-wide host-local destination table (alist of 4-byte key -> 1-byte
   presence value): the API server ClusterIP, the egress proxy address, and this
   node's own IP when known. A CONFINED Pod's (a gr8 sandbox's) holds the egress
   proxy alone: the redirect passes before policy, so the API server and the
   node's own services would be reachable whatever it denied (podster-1mzb).
   A hit means the destination is served by this host and must reach it via lo."
  (let ((value (make-array 1 :element-type '(unsigned-byte 8) :initial-element 1))
        (addresses (if confined
                       (list +egress-proxy-address+)
                       (list (format nil "~{~A~^.~}" (coerce +dns-kubernetes-service-address+ 'list))
                             ;; The egress proxy and DNS gate (podster-wv1w.2).
                             +egress-proxy-address+))))
    (when (and (not confined) node-address (plusp (length node-address)))
      (pushnew node-address addresses :test #'string=))
    (loop for address in addresses
          collect (cons (host-redirect-key address) value))))

(defun write-host-redirect-table
    (directory table
     &key (open #'whistler/loader:open-pinned-object)
          (map-info #'cni-policy-map-info)
          (update #'whistler/loader:map-update)
          (close #'sb-posix:close))
  "Write the node-wide TABLE (alist of 4-byte key -> 1-byte value) into the
   host_redirect_v4 map pinned under DIRECTORY. Idempotent."
  (let ((fd nil))
    (unwind-protect
         (progn
           (setf fd (funcall open (concatenate 'string (namestring directory) "host_redirect_v4")))
           (let ((info (funcall map-info fd "host_redirect_v4")))
             (loop for (key . value) in table do (funcall update info key value))))
      (when fd (ignore-errors (funcall close fd))))))

(defun converge-node-host-redirect
    (sandboxes node-address &key directory-fn
                                 (confined-p (constantly nil))
                                 (table-fn #'node-host-redirect-table)
                                 (writer #'write-host-redirect-table))
  "Rebuild the node's host-local destination table from NODE-ADDRESS and write
   it into every local Pod's pinned host_redirect_v4. SANDBOXES is the list of
   local Pod sandbox ids; DIRECTORY-FN maps a sandbox to its bpffs pin directory;
   CONFINED-P is true of a sandbox whose Pod gets the confined table.
   Fail-soft per Pod; returns the sandboxes written."
  (let ((table (funcall table-fn node-address))
        (confined-table (funcall table-fn node-address :confined t))
        (written '()))
    (dolist (sandbox sandboxes (nreverse written))
      (handler-case
          (progn (funcall writer (funcall directory-fn sandbox)
                          (if (funcall confined-p sandbox) confined-table table))
                 (push sandbox written))
        (error () nil)))))
