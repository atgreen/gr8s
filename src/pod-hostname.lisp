;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Execute Pod hostname/subdomain semantics in the actual sandbox UTS name and
;;;; a Pod-owned hosts mount derived from the real assigned sandbox address.

(in-package #:gr8s)

(defun pod-hostname-override (pod)
  "Return POD's spec.hostnameOverride, which replaces its hostname and drops its domain, or NIL."
  (let ((override (gethash "hostnameOverride" (gethash "spec" (pod-to-object pod)))))
    (and (stringp override) override)))

(defun pod-runtime-hostname (pod)
  "Choose hostnameOverride, the explicit DNS-label hostname or the Pod name, bounded as a kubelet does."
  (let* ((spec (gethash "spec" (pod-to-object pod)))
         (hostname (gethash "hostname" spec))
         (chosen (cond ((pod-hostname-override pod))
                       ((and (stringp hostname) (plusp (length hostname))) hostname)
                       (t (pod-name pod)))))
    (if (> (length chosen) 63) (string-right-trim "-." (subseq chosen 0 63)) chosen)))

(defun pod-runtime-domain (pod)
  "Return the Pod's DNS subdomain namespace suffix, independent of Service existence.
A hostnameOverride leaves the Pod without one."
  (let ((subdomain (gethash "subdomain" (gethash "spec" (pod-to-object pod)) "")))
    (when (and (plusp (length subdomain)) (not (pod-hostname-override pod)))
      (format nil "~A.~A.svc.cluster.local" subdomain (pod-namespace pod)))))

(defun pod-sandbox-hostname (pod)
  "Return the kernel hostname of POD's sandbox: its FQDN under setHostnameAsFQDN, else its hostname."
  (let ((hostname (pod-runtime-hostname pod)) (domain (pod-runtime-domain pod)))
    (if (and domain (eq t (gethash "setHostnameAsFQDN" (gethash "spec" (pod-to-object pod)))))
        (let ((fqdn (format nil "~A.~A" hostname domain)))
          (when (> (length fqdn) 64)
            (error 'runtime-error
                   :message (format nil "failed to construct FQDN from pod hostname and cluster domain, FQDN ~A is too long (64 characters is the max, ~D characters requested)"
                                    fqdn (length fqdn))))
          fqdn)
        hostname)))

(defun validate-pod-hostname-fields (spec)
  "Validate setHostnameAsFQDN and hostnameOverride, which the kernel hostname is derived from."
  (dolist (field '("setHostnameAsFQDN" "hostnameOverride"))
    (when (eq (gethash field spec) 'null) (remhash field spec)))
  (multiple-value-bind (value present) (gethash "setHostnameAsFQDN" spec)
    (when (and present (not (member value '(t nil))))
      (invalid-pod "spec.setHostnameAsFQDN must be boolean")))
  (multiple-value-bind (override present) (gethash "hostnameOverride" spec)
    (when present
      (when (eq t (gethash "setHostnameAsFQDN" spec))
        (invalid-pod "spec.hostnameOverride: Forbidden: may not be specified when setHostnameAsFQDN is true"))
      (when (eq t (gethash "hostNetwork" spec))
        (invalid-pod "spec.hostnameOverride: Forbidden: may not be specified when hostNetwork is true"))
      (unless (stringp override) (invalid-pod "spec.hostnameOverride must be a string"))
      (when (> (length override) 64)
        (invalid-pod "spec.hostnameOverride: Too long: may not be more than 64 bytes"))
      (unless (and (plusp (length override)) (dns-subdomain-p override))
        (invalid-pod "spec.hostnameOverride: Invalid value: ~S: a lowercase RFC 1123 subdomain must consist of lower case alphanumeric characters, '-' or '.'"
                     override)))))

(defun validate-pod-hostname-update (existing replacement)
  "Keep Pod hostname/subdomain immutable after creation, including before scheduling."
  (dolist (field '("hostname" "subdomain" "hostnameOverride" "setHostnameAsFQDN"))
    (unless (equal (gethash field (gethash "spec" (pod-to-object existing)) "")
                   (gethash field (gethash "spec" (pod-to-object replacement)) ""))
      (error 'kubernetes-error :status-code 422 :reason "Invalid"
             :message (format nil "spec.~A is immutable" field)))))

(defun pod-managed-hosts-content (pod address)
  "Generate standard local aliases and the actual Pod IP's short/FQDN hostname aliases."
  (let ((hostname (pod-runtime-hostname pod)) (domain (pod-runtime-domain pod)))
    (with-output-to-string (out)
      (format out "# Kubernetes-managed hosts file.~%127.0.0.1~Clocalhost~%::1~Clocalhost ip6-localhost ip6-loopback~%" #\Tab #\Tab)
      (format out "fe00::0~Cip6-localnet~%ff00::0~Cip6-mcastprefix~%ff02::1~Cip6-allnodes~%ff02::2~Cip6-allrouters~%"
              #\Tab #\Tab #\Tab #\Tab)
      (if domain (format out "~A~C~A.~A~C~A~%" address #\Tab hostname domain #\Tab hostname)
          (format out "~A~C~A~%" address #\Tab hostname))
      (write-string (pod-host-aliases-content pod) out))))

(defparameter *node-hosts-path* #P"/etc/hosts"
  "The node's own hosts file, which a hostNetwork Pod sees.")

(defun write-pod-hosts-file (runtime pod content)
  "Publish CONTENT as POD's hosts file and return the mount that presents it at /etc/hosts."
  (let ((target (merge-pathnames "hosts" (containerd-pod-log-directory runtime (pod-uid pod)))))
    (write-projected-volume-file target (trivial-utf-8:string-to-utf-8-bytes content) #o644 nil)
    (make-instance 'gr8s.cri.v1::mount :container-path "/etc/hosts" :host-path (namestring target) :readonly nil)))

(defun containerd-container-mounts (runtime pod container sandbox-id &optional environment)
  "Append the real Pod hosts mount unless an explicit user mount applies.
A hostNetwork Pod sees the node's file, which the runtime supplies unless aliases extend it."
  (let ((mounts (containerd-pod-mounts runtime pod container environment)))
    (cond
      ((find "/etc/hosts" mounts :test #'equal
             :key (lambda (mount) (slot-value mount 'gr8s.cri.v1::container-path)))
       mounts)
      ((containerd-pod-host-network-p runtime pod)
       (let ((aliases (pod-host-aliases-content pod)))
         (if (zerop (length aliases))
             mounts
             (append mounts
                     (list (write-pod-hosts-file
                            runtime pod
                            (concatenate 'string
                                         (if (probe-file *node-hosts-path*) (uiop:read-file-string *node-hosts-path*) "")
                                         aliases)))))))
      (t
       (let ((address (cri-pod-sandbox-ip (containerd-runtime-socket-path runtime) sandbox-id)))
         (unless (and (stringp address) (plusp (length address)))
           (error 'runtime-error :message "Pod hosts file requires the actual sandbox IP"))
         (if (find #\: address) (0conf:parse-ipv6 address) (0conf:parse-ipv4 address))
         (append mounts (list (write-pod-hosts-file runtime pod (pod-managed-hosts-content pod address)))))))))
