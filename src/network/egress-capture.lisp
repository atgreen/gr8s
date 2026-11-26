;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Agent side of egress capture (podster-wv1w.2). The socket load balancer's
;;;; connect hook sends a captured Pod's outbound TCP to the node egress proxy, and
;;;; it knows a Pod only by its network namespace cookie: a socket hook runs before
;;;; any source address exists. So CNI ADD, which is handed the Pod's namespace,
;;;; records the cookie by the Pod's IPv4 address in gr8s_pod_netns_v4, pinned with
;;;; the load balancer's maps so it outlives an agent restart. Each convergence then
;;;; writes the cookies of the captured Pods into gr8s_egress_capture, each with its
;;;; mode, and the cluster's own prefixes into gr8s_egress_exempt_v4. Mode 1 sends a
;;;; Pod's public TCP to the proxy, which admits it by SNI/Host; mode 2, for a Pod with
;;;; a hostname allowlist, lets it reach only the synthetic addresses its DNS answers
;;;; with (podster-wv1w.8), and refuses the rest.

(in-package #:gr8s.network)

(defconstant +so-netns-cookie+ 71 "SO_NETNS_COOKIE, Linux 5.14.")

(sb-alien:define-alien-routine ("getsockopt" %egress-getsockopt) sb-alien:int
  (fd sb-alien:int) (level sb-alien:int) (name sb-alien:int)
  (value (* (sb-alien:unsigned 64))) (length (* sb-alien:unsigned-int)))

(defun current-netns-cookie ()
  "The cookie of the calling thread's network namespace."
  (let ((socket (make-instance 'sb-bsd-sockets:inet-socket :type :datagram :protocol :udp)))
    (unwind-protect
         (sb-alien:with-alien ((value (sb-alien:unsigned 64) 0) (length sb-alien:unsigned-int 8))
           (unless (zerop (%egress-getsockopt (sb-bsd-sockets:socket-file-descriptor socket) 1 +so-netns-cookie+
                                              (sb-alien:addr value) (sb-alien:addr length)))
             (error "SO_NETNS_COOKIE: ~A" (sb-int:strerror (sb-alien:get-errno))))
           value)
      (sb-bsd-sockets:socket-close socket))))

(defun netns-cookie (netns-path &key (call-in-netns #'call-with-cni-network-namespace))
  "The cookie of the network namespace at NETNS-PATH."
  (let ((cookie nil))
    (funcall call-in-netns netns-path (lambda () (setf cookie (current-netns-cookie))))
    cookie))

(defun %egress-u64-le (value)
  (let ((octets (make-array 8 :element-type '(unsigned-byte 8))))
    (dotimes (i 8 octets) (setf (aref octets i) (ldb (byte 8 (* 8 i)) value)))))

(defun %egress-u64-from-le (octets)
  (loop for i below 8 sum (ash (aref octets i) (* 8 i))))

(defun %call-with-pinned-map (pin-directory name function
                              &key (open #'whistler/loader:open-pinned-object)
                                   (map-info #'cni-policy-map-info) (close #'sb-posix:close))
  (let ((fd (funcall open (concatenate 'string (namestring (uiop:ensure-directory-pathname pin-directory)) name))))
    (unwind-protect (funcall function (funcall map-info fd name))
      (ignore-errors (funcall close fd)))))

(defun record-pod-netns-cookie (pin-directory address netns-path
                                &key (cookie-of #'netns-cookie) (update #'whistler/loader:map-update)
                                     (open #'whistler/loader:open-pinned-object))
  "Record the cookie of the Pod namespace NETNS-PATH by its IPv4 ADDRESS. Best-effort:
returns the cookie, or NIL when the load balancer's maps aren't pinned."
  (unless (find #\: address)
    (handler-case
        (let ((cookie (funcall cookie-of netns-path)))
          (%call-with-pinned-map pin-directory "gr8s_pod_netns_v4"
                                 (lambda (map) (funcall update map (ipv4-network-octets address) (%egress-u64-le cookie)))
                                 :open open)
          cookie)
      (error () nil))))

(defun forget-pod-netns-cookie (pin-directory address &key (delete #'whistler/loader::map-delete))
  "Forget the cookie recorded for ADDRESS. Best-effort."
  (unless (find #\: address)
    (ignore-errors
     (%call-with-pinned-map pin-directory "gr8s_pod_netns_v4"
                            (lambda (map) (funcall delete map (ipv4-network-octets address)))))))

(defun egress-capture-contents (captured cookies)
  "The gr8s_egress_capture contents for CAPTURED, a list of (address . mode): a list of
(key . value), the key the cookie COOKIES (a function from address to cookie or NIL)
gives the address, the value its mode."
  (remove-duplicates
   (loop for (address . mode) in captured
         for cookie = (funcall cookies address)
         when cookie collect (cons (%egress-u64-le cookie)
                                   (make-array 1 :element-type '(unsigned-byte 8) :initial-element mode)))
   :test #'equalp :key #'car :from-end t))

(defun egress-exempt-contents (cidrs)
  "The gr8s_egress_exempt_v4 contents for the IPv4 CIDRS the cluster owns."
  (let ((present (make-array 1 :element-type '(unsigned-byte 8) :initial-element 1)))
    (loop for cidr in (remove-duplicates cidrs :test #'equal)
          unless (find #\: cidr) collect (cons (netpol-cidr-lpm-key cidr) present))))

(defun write-egress-capture (pin-directory captured exempt-cidrs
                             &key (update #'whistler/loader:map-update)
                                  (delete #'whistler/loader::map-delete)
                                  (keys #'netpol-map-keys)
                                  (lookup #'whistler/loader:map-lookup))
  "Make gr8s_egress_capture hold exactly the cookies and modes of CAPTURED and
gr8s_egress_exempt_v4 exactly EXEMPT-CIDRS. The exempt prefixes are written first, so a
newly captured Pod never has its cluster traffic sent to the proxy."
  (flet ((replace-contents (map contents)
           (dolist (entry contents) (funcall update map (car entry) (cdr entry)))
           (dolist (key (funcall keys map))
             (unless (find key contents :key #'car :test #'equalp) (funcall delete map key)))))
    (%call-with-pinned-map pin-directory "gr8s_egress_exempt_v4"
                           (lambda (map) (replace-contents map (egress-exempt-contents exempt-cidrs))))
    (%call-with-pinned-map
     pin-directory "gr8s_pod_netns_v4"
     (lambda (netns)
       (%call-with-pinned-map
        pin-directory "gr8s_egress_capture"
        (lambda (map)
          (replace-contents
           map (egress-capture-contents
                captured
                (lambda (address)
                  (let ((value (ignore-errors (funcall lookup netns (ipv4-network-octets address)))))
                    (and value (%egress-u64-from-le value))))))))))))

(defparameter +egress-exempt-cidrs+
  '("10.0.0.0/8" "172.16.0.0/12" "192.168.0.0/16" "100.64.0.0/10" "169.254.0.0/16" "127.0.0.0/8")
  "Destinations a captured Pod reaches without the proxy, under address policy alone: the
private, shared and link-local ranges cluster Pods, Services and nodes live in. Public
destinations go through the proxy, which admits them by name.")

(defun converge-egress-capture (pin-directory endpoints cluster-policies &key pod-finder profiles)
  "Capture the local ENDPOINTS (sandbox interface address) whose Pod's egress policy among
CLUSTER-POLICIES names domains (mode 2), or that a SecurityProfile among PROFILES selects
for credential injection (mode 1). Best-effort; returns the captured (address . mode)."
  (let ((captured (loop for (nil nil address) in endpoints
                        for pod = (and address (funcall pod-finder address))
                        when (and pod (pod-egress-captured-p pod cluster-policies profiles))
                          collect (cons address (if (pod-egress-synthetic-p pod cluster-policies) 2 1)))))
    (handler-case (progn (write-egress-capture pin-directory captured +egress-exempt-cidrs+) captured)
      (error (condition)
        (format *error-output* "gr8s: egress capture not written: ~A~%" condition)
        nil))))
