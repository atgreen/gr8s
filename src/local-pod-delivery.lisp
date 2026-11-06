;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Agent side of same-node Pod->Pod delivery (epic podster-pnd, podster-3yi).
;;;; The egress guard (egress-guard-program.lisp) redirects a packet straight to
;;;; a destination Pod's veth when the destination is a local Pod, bypassing the
;;;; kernel forward path and the host firewall's FORWARD reject. That fast path
;;;; is driven by the local_pod_v4 map: destination Pod IPv4 (network order) ->
;;;; {dest host-veth ifindex (u32, native), dest Pod MAC, dest host-veth MAC}.
;;;;
;;;; On every node reconcile the agent rebuilds the node's local-Pod table and
;;;; writes it into each local Pod's pinned local_pod_v4 (every Pod's table is the
;;;; same set of on-node Pods). Each Pod's own MAC is read back from its pinned
;;;; endpoint_identity map, so no Pod network namespace is entered here.

(in-package #:gr8s)

(defun encode-local-pod-value (ifindex pod-mac veth-mac)
  "The 16-byte local_pod_v4 value the egress guard reads: dest host-veth IFINDEX
   (u32, native byte order), then the 6-byte POD-MAC and 6-byte VETH-MAC in wire
   order (copied verbatim into the redirected frame's dst/src MAC)."
  (let ((value (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0)))
    (setf (aref value 0) (ldb (byte 8 0) ifindex)
          (aref value 1) (ldb (byte 8 8) ifindex)
          (aref value 2) (ldb (byte 8 16) ifindex)
          (aref value 3) (ldb (byte 8 24) ifindex))
    (replace value pod-mac :start1 4 :end1 10)
    (replace value veth-mac :start1 10 :end1 16)
    value))

(defun decode-endpoint-identity-mac (value)
  "Recover the 6 wire MAC bytes from a 16-byte endpoint_identity value, the
   inverse of encode-cni-endpoint-identity (IPv4, MAC-high u32 LE, MAC-low u32 LE,
   version). The MAC the agent stored there is the Pod's own eth0 address."
  (flet ((le32 (offset)
           (+ (aref value offset)
              (ash (aref value (+ offset 1)) 8)
              (ash (aref value (+ offset 2)) 16)
              (ash (aref value (+ offset 3)) 24))))
    (let ((high (le32 4)) (low (le32 8)))
      (make-array 6 :element-type '(unsigned-byte 8)
                    :initial-contents (list (ldb (byte 8 24) high) (ldb (byte 8 16) high)
                                            (ldb (byte 8 8) high)  (ldb (byte 8 0) high)
                                            (ldb (byte 8 8) low)   (ldb (byte 8 0) low))))))

(defun local-pod-ipv4-key (address)
  "The 4-byte network-order key the egress guard looks up (it uses the raw
   on-the-wire destination address)."
  (let ((n (parse-ipv4-integer address)))
    (make-array 4 :element-type '(unsigned-byte 8)
                  :initial-contents (list (ldb (byte 8 24) n) (ldb (byte 8 16) n)
                                          (ldb (byte 8 8) n)  (ldb (byte 8 0) n)))))

(defun local-pod-endpoint-value
    (sandbox interface
     &key (interface-index #'native-interface-index)
          (link-attributes #'network-link-attributes)
          (open #'whistler/loader:open-pinned-object)
          (map-info #'cni-policy-map-info)
          (lookup #'whistler/loader:map-lookup)
          (close #'sb-posix:close)
          directory)
  "Build the local_pod_v4 value for one local Pod: its host-veth ifindex and MAC
   (rtnetlink) plus its own Pod MAC read back from its pinned endpoint_identity."
  (let* ((veth (routed-veth-name sandbox interface))
         (ifindex (funcall interface-index veth))
         (veth-mac (gethash 1 (funcall link-attributes veth)))
         (identity-fd (funcall open (concatenate 'string (namestring directory) "endpoint_identity")))
         (identity (unwind-protect
                        (funcall lookup (funcall map-info identity-fd "endpoint_identity")
                                 (netlink-integer 0 4))
                     (ignore-errors (funcall close identity-fd)))))
    (unless (and veth-mac (= 6 (length veth-mac)) identity (>= (length identity) 12))
      (error "incomplete link/identity data for sandbox ~A" sandbox))
    (encode-local-pod-value ifindex (decode-endpoint-identity-mac identity) veth-mac)))

(defun write-local-pod-table
    (directory table
     &key (open #'whistler/loader:open-pinned-object)
          (map-info #'cni-policy-map-info)
          (update #'whistler/loader:map-update)
          (close #'sb-posix:close))
  "Write the node-wide TABLE (alist of 4-byte IPv4 key -> 16-byte value) into the
   local_pod_v4 map pinned under DIRECTORY. Idempotent."
  (let ((fd nil))
    (unwind-protect
         (progn
           (setf fd (funcall open (concatenate 'string (namestring directory) "local_pod_v4")))
           (let ((info (funcall map-info fd "local_pod_v4")))
             (loop for (key . value) in table do (funcall update info key value))))
      (when fd (ignore-errors (funcall close fd))))))

(defun converge-node-local-pod-delivery
    (endpoints &key directory-fn
                    (value-fn (lambda (sandbox interface directory)
                                (local-pod-endpoint-value sandbox interface :directory directory)))
                    (writer #'write-local-pod-table))
  "Rebuild the node's local-Pod delivery table from ENDPOINTS -- each a
   (SANDBOX INTERFACE ADDRESS) -- and write the whole table into every local
   Pod's pinned local_pod_v4. DIRECTORY-FN maps a sandbox to its bpffs pin
   directory. Fail-soft per endpoint; returns the sandboxes written."
  (let ((table '()) (dirs '()) (written '()))
    ;; Pass 1: compute each Pod's value and remember its pin directory.
    (dolist (endpoint endpoints)
      (handler-case
          (destructuring-bind (sandbox interface address) endpoint
            (let ((directory (funcall directory-fn sandbox)))
              (push (cons (local-pod-ipv4-key address)
                          (funcall value-fn sandbox interface directory))
                    table)
              (push (cons sandbox directory) dirs)))
        (error () nil)))
    ;; Pass 2: every local Pod gets the same full table.
    (dolist (entry (nreverse dirs) (nreverse written))
      (handler-case
          (progn (funcall writer (cdr entry) table)
                 (push (car entry) written))
        (error () nil)))))
