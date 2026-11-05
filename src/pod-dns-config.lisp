;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Validate per-Pod DNS policies and resolver configuration, merge real node and
;;;; Pod settings, and supply the actual CRI sandbox servers, searches and options.

(in-package #:gr8s)

(defparameter *pod-dns-host-resolv-conf* #P"/etc/resolv.conf")

(defun valid-pod-dns-address-p (value)
  "Recognize literal IPv4/IPv6 resolver addresses without accepting hostnames or CIDRs."
  (and (stringp value) (plusp (length value))
       (handler-case
           (progn (if (find #\: value) (0conf:parse-ipv6 value) (0conf:parse-ipv4 value)) t)
         (error () nil))))

(defun valid-pod-dns-search-p (value)
  "Accept relaxed Kubernetes DNS searches, including underscores, root and one terminal dot."
  (and (stringp value) (plusp (length value))
       (or (equal value ".")
           (let ((name (if (char= #\. (char value (1- (length value))))
                           (subseq value 0 (1- (length value))) value)))
             (and (plusp (length name)) (dns-subdomain-p (substitute #\a #\_ name)))))))

(defun validate-pod-dns-spec (spec)
  "Validate actual DNS policy/config semantics and normalize nullable repeated fields."
  (when (eq 'null (gethash "dnsPolicy" spec)) (remhash "dnsPolicy" spec))
  (when (eq 'null (gethash "dnsConfig" spec)) (remhash "dnsConfig" spec))
  (let ((policy (gethash "dnsPolicy" spec "ClusterFirst")) (config (gethash "dnsConfig" spec)))
    (unless (member policy '("ClusterFirst" "Default" "None" "ClusterFirstWithHostNet") :test #'equal)
      (invalid-pod "Invalid spec.dnsPolicy"))
    (when (nth-value 1 (gethash "dnsConfig" spec))
      (require-object config "spec.dnsConfig")
      (reject-unsupported-fields config '("nameservers" "searches" "options") "spec.dnsConfig")
      (dolist (field '("nameservers" "searches" "options"))
        (when (eq 'null (gethash field config)) (setf (gethash field config) #())))
      (let ((servers (optional-vector config "nameservers" "spec.dnsConfig"))
            (searches (optional-vector config "searches" "spec.dnsConfig"))
            (options (optional-vector config "options" "spec.dnsConfig")))
        (setf (gethash "nameservers" config) servers (gethash "searches" config) searches (gethash "options" config) options)
        (unless (and (<= (length servers) 3) (every #'valid-pod-dns-address-p servers))
          (invalid-pod "dnsConfig.nameservers requires at most three literal IP addresses"))
        (unless (and (<= (length searches) 32) (every #'valid-pod-dns-search-p searches)
                     (<= (+ (reduce #'+ searches :key #'length :initial-value 0) (max 0 (1- (length searches)))) 2048))
          (invalid-pod "dnsConfig.searches exceeds DNS name, count or combined length limits"))
        (loop for option across options
              do (require-object option "DNS option")
                 (reject-unsupported-fields option '("name" "value") "DNS option")
                 (let ((name (gethash "name" option)))
                   (unless (and (stringp name) (plusp (length name))) (invalid-pod "DNS option name must not be empty")))
                 (when (eq 'null (gethash "value" option)) (remhash "value" option))
                 (when (and (nth-value 1 (gethash "value" option)) (not (stringp (gethash "value" option))))
                   (invalid-pod "DNS option value must be a string")))))
    (when (and (equal policy "None")
               (or (null config) (zerop (length (gethash "nameservers" config #())))))
      (invalid-pod "dnsPolicy None requires dnsConfig with at least one nameserver")))
  spec)

(defun merge-pod-dns-options (existing additions)
  "Merge resolver options by option name, with later Pod values overriding node defaults."
  (let ((values (make-hash-table :test #'equal)) (order nil))
    (dolist (option (append existing additions))
      (let* ((colon (position #\: option)) (name (if colon (subseq option 0 colon) option)))
        (unless (nth-value 1 (gethash name values)) (push name order))
        (setf (gethash name values) option)))
    (mapcar (lambda (name) (gethash name values)) (nreverse order))))

(defun read-host-pod-dns-configuration ()
  "Read actual node resolver servers/searches/options for Default policy and cluster suffixes."
  (let ((servers nil) (searches nil) (options nil))
    (with-open-file (stream *pod-dns-host-resolv-conf* :direction :input)
      (loop for raw = (read-line stream nil nil) while raw
            for comment = (position-if (lambda (char) (member char '(#\# #\;))) raw)
            for line = (if comment (subseq raw 0 comment) raw)
            for fields = (remove "" (uiop:split-string line :separator '(#\Space #\Tab)) :test #'equal)
            do (cond ((equal "nameserver" (first fields)) (when (second fields) (push (second fields) servers)))
                     ((equal "search" (first fields))
                      (setf searches (loop for name in (rest fields) unless (equal name ".")
                                           collect (string-right-trim "." name))))
                     ((equal "options" (first fields)) (setf options (merge-pod-dns-options options (rest fields)))))))
    (values (nreverse servers) searches options)))

(defun pod-dns-fit-limits (pod servers searches options)
  "Apply actual kubelet resolver size limits and report real configuration truncation."
  (let ((original-servers (length servers)) (original-searches (length searches)))
    (setf servers (subseq servers 0 (min 3 (length servers)))
          searches (remove-if (lambda (name) (> (length name) 253)) searches)
          searches (subseq searches 0 (min 32 (length searches))))
    (loop while (> (+ (reduce #'+ searches :key #'length :initial-value 0) (max 0 (1- (length searches)))) 2048)
          do (setf searches (butlast searches)))
    (when (or (/= original-servers (length servers)) (/= original-searches (length searches)))
      (format *error-output* "gr8s DNSConfigForming for ~A/~A: resolver settings were truncated to supported limits~%"
              (pod-namespace pod) (pod-name pod)))
    (values servers searches options)))

(defun containerd-pod-dns-configuration (runtime pod)
  "Choose None, actual host Default or namespace-correct cluster DNS, then merge Pod overrides."
  (let* ((spec (gethash "spec" (pod-to-object pod))) (policy (gethash "dnsPolicy" spec "ClusterFirst"))
         (config (gethash "dnsConfig" spec)) (servers nil) (searches nil) (options nil))
    (cond
      ((equal policy "None"))
      ((or (equal policy "Default")
           (and (equal policy "ClusterFirst") (containerd-pod-host-network-p runtime pod)))
       (multiple-value-setq (servers searches options) (read-host-pod-dns-configuration)))
      (t
       (if (containerd-runtime-dns-servers runtime)
           (progn
             (setf servers (copy-list (containerd-runtime-dns-servers runtime))
                   searches (when (containerd-runtime-dns-searches runtime)
                              (cons (format nil "~A.svc.cluster.local" (pod-namespace pod))
                                    (cdr (containerd-runtime-dns-searches runtime))))
                   options (copy-list (containerd-runtime-dns-options runtime)))
             (let ((host-searches (nth-value 1 (read-host-pod-dns-configuration))))
               (setf searches (append searches host-searches))))
           (multiple-value-setq (servers searches options) (read-host-pod-dns-configuration)))))
    (when config
      (setf servers (append servers (coerce (gethash "nameservers" config #()) 'list))
            searches (append searches (coerce (gethash "searches" config #()) 'list))
            options (merge-pod-dns-options options
                      (loop for option across (gethash "options" config #())
                            for name = (gethash "name" option) for value = (gethash "value" option)
                            collect (if (and value (plusp (length value))) (format nil "~A:~A" name value) name)))))
    (pod-dns-fit-limits pod (remove-duplicates servers :test #'equal :from-end t)
                            (remove-duplicates searches :test #'equal :from-end t) options)))

(defun validate-pod-dns-update (existing replacement)
  "Reject resolver policy/config changes after Pod creation, including before scheduling."
  (let ((before (gethash "spec" (pod-to-object existing))) (after (gethash "spec" (pod-to-object replacement))))
    (unless (and (equal (gethash "dnsPolicy" before "ClusterFirst") (gethash "dnsPolicy" after "ClusterFirst"))
                 (equal (endpointslice-canonical-json (gethash "dnsConfig" before))
                        (endpointslice-canonical-json (gethash "dnsConfig" after))))
      (error 'kubernetes-error :status-code 422 :reason "Invalid" :message "Pod DNS policy and configuration are immutable"))
    ;; Preserve legacy default representation so equivalent typed/JSON metadata
    ;; updates cannot alter the runtime fingerprint and restart a healthy Pod.
    (if (nth-value 1 (gethash "dnsPolicy" before))
        (setf (gethash "dnsPolicy" after) (gethash "dnsPolicy" before))
        (remhash "dnsPolicy" after))))
