;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Resolve reverse IPv4/IPv6 DNS records from actual Service cluster addresses
;;;; and ready headless EndpointSlice targets; leave unrelated reverse queries upstream.

(in-package #:gr8s)

(defun service-dns-ip-bytes (address)
  "Normalize an actual IP address for equality across IPv6 textual representations."
  (if (find #\: address) (0conf:parse-ipv6 address) (0conf:parse-ipv4 address)))

(defun service-dns-reverse-address (name)
  "Decode a valid IPv4 or IPv6 reverse DNS owner name into network-order bytes."
  (handler-case
      (let ((labels (uiop:split-string (canonical-dns-name name) :separator ".")))
        (cond
          ((and (= 6 (length labels)) (equal (last labels 2) '("in-addr" "arpa")))
           (let ((parts (reverse (subseq labels 0 4))))
             (when (every (lambda (label) (and (plusp (length label))
                                               (every (lambda (char) (digit-char-p char 10)) label)
                                               (<= (parse-integer label) 255))) parts)
               (map 'vector #'parse-integer parts))))
          ((and (= 34 (length labels)) (equal (last labels 2) '("ip6" "arpa")))
           (let ((digits (reverse (subseq labels 0 32))))
             (when (every (lambda (label) (and (= 1 (length label)) (digit-char-p (char label 0) 16))) digits)
               (coerce (loop for (high low) on digits by #'cddr
                             collect (+ (* 16 (digit-char-p (char high 0) 16))
                                        (digit-char-p (char low 0) 16))) 'vector))))))
    (error () nil)))

(defun resolve-store-service-ptr (store question)
  "Answer only actual allocated Service or ready headless addresses authoritatively."
  (let ((address (service-dns-reverse-address (0conf:question-name question))) (targets nil) (owned-address nil))
    (unless address (return-from resolve-store-service-ptr (values nil nil nil)))
    (when (equalp address +dns-kubernetes-service-address+)
      (setf owned-address t) (push +dns-kubernetes-service+ targets))
    (dolist (service (list-core-resources store "services"))
      (let* ((metadata (gethash "metadata" service)) (name (gethash "name" metadata))
             (namespace (gethash "namespace" metadata)) (spec (gethash "spec" service))
             (fqdn (format nil "~A.~A.svc.cluster.local" name namespace)))
        (if (equal "None" (gethash "clusterIP" spec))
            (dolist (slice (list-core-resources store "endpointslices" namespace))
              (when (and (member (gethash "addressType" slice) '("IPv4" "IPv6") :test #'equal)
                         (equal name (gethash "kubernetes.io/service-name"
                                              (gethash "labels" (gethash "metadata" slice) (core-object)))))
                (loop for endpoint across (gethash "endpoints" slice #())
                      do (loop for ip across (gethash "addresses" endpoint #())
                               when (equalp address (service-dns-ip-bytes ip))
                                 do (setf owned-address t)
                                    (unless (service-dns-endpoint-unready-p endpoint)
                                      (pushnew (format nil "~A.~A" (service-dns-endpoint-hostname endpoint ip) fqdn)
                                               targets :test #'equal))))))
            (loop for ip across (gethash "clusterIPs" spec (vector (gethash "clusterIP" spec)))
                  when (and (stringp ip) (equalp address (service-dns-ip-bytes ip)))
                    do (setf owned-address t) (pushnew fqdn targets :test #'equal)))))
    (values (mapcar (lambda (target) (make-instance '0conf:ptr-record
                                                   :name (0conf:question-name question) :target target :ttl 5))
                    (sort targets #'string<))
            (not (null targets)) owned-address)))
