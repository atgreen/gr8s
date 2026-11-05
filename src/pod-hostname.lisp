;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Execute Pod hostname/subdomain semantics in the actual sandbox UTS name and
;;;; a Pod-owned hosts mount derived from the real assigned sandbox address.

(in-package #:gr8s)

(defun pod-runtime-hostname (pod)
  "Choose the explicit DNS-label hostname or the existing bounded Pod-name default."
  (let* ((spec (gethash "spec" (pod-to-object pod)))
         (hostname (gethash "hostname" spec)))
    (if (and (stringp hostname) (plusp (length hostname))) hostname
        (let ((name (pod-name pod)))
          (if (> (length name) 63) (string-right-trim "-." (subseq name 0 63)) name)))))

(defun pod-runtime-domain (pod)
  "Return the Pod's DNS subdomain namespace suffix, independent of Service existence."
  (let ((subdomain (gethash "subdomain" (gethash "spec" (pod-to-object pod)) "")))
    (when (plusp (length subdomain))
      (format nil "~A.~A.svc.cluster.local" subdomain (pod-namespace pod)))))

(defun validate-pod-hostname-update (existing replacement)
  "Keep Pod hostname/subdomain immutable after creation, including before scheduling."
  (dolist (field '("hostname" "subdomain"))
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
          (format out "~A~C~A~%" address #\Tab hostname)))))

(defun containerd-container-mounts (runtime pod container sandbox-id &optional environment)
  "Append the real Pod hosts mount unless host networking or an explicit user mount applies."
  (let ((mounts (containerd-pod-mounts runtime pod container environment)))
    (if (or (containerd-pod-host-network-p runtime pod)
            (find "/etc/hosts" mounts :test #'equal
                  :key (lambda (mount) (slot-value mount 'gr8s.cri.v1::container-path))))
        mounts
        (let* ((address (cri-pod-sandbox-ip (containerd-runtime-socket-path runtime) sandbox-id))
               (target (merge-pathnames "hosts" (containerd-pod-log-directory runtime (pod-uid pod)))))
          (unless (and (stringp address) (plusp (length address)))
            (error 'runtime-error :message "Pod hosts file requires the actual sandbox IP"))
          (if (find #\: address) (0conf:parse-ipv6 address) (0conf:parse-ipv4 address))
          (write-projected-volume-file target
            (trivial-utf-8:string-to-utf-8-bytes (pod-managed-hosts-content pod address)) #o644 nil)
          (append mounts (list (make-instance 'gr8s.cri.v1::mount
                                              :container-path "/etc/hosts" :host-path (namestring target)
                                              :readonly nil)))))))
