;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Validate and apply the Pod settings that reach below the container: the
;;;; node's network, PID and IPC namespaces, namespaced kernel sysctls and
;;;; /etc/hosts aliases. Also derive status.qosClass and the node address a
;;;; hostNetwork Pod shares, so both come from what the Pod actually declares.

(in-package #:gr8s)

(defparameter +safe-pod-sysctls+
  '("kernel.shm_rmid_forced" "net.ipv4.ip_local_port_range" "net.ipv4.tcp_syncookies"
    "net.ipv4.ping_group_range" "net.ipv4.ip_unprivileged_port_start" "net.ipv4.ip_local_reserved_ports"
    "net.ipv4.tcp_keepalive_time" "net.ipv4.tcp_fin_timeout" "net.ipv4.tcp_keepalive_intvl"
    "net.ipv4.tcp_keepalive_probes" "net.ipv4.tcp_rmem" "net.ipv4.tcp_wmem")
  "The sysctls a kubelet allows by default: namespaced, and unable to affect other Pods.")

(defun pod-spec-flag-p (pod field)
  "Return whether POD's spec sets the boolean FIELD to true."
  (eq t (gethash field (gethash "spec" (pod-to-object pod)))))

(defun pod-pid-namespace-mode (pod)
  "Return POD's CRI PID namespace mode: each container alone unless the spec shares one."
  (cond ((pod-spec-flag-p pod "hostPID") gr8s.cri.v1::+namespacemode-node+)
        ((pod-spec-flag-p pod "shareProcessNamespace") gr8s.cri.v1::+namespacemode-pod+)
        (t gr8s.cri.v1::+namespacemode-container+)))

(defun pod-host-network-p (pod)
  "Return whether POD shares its node's network namespace."
  (pod-spec-flag-p pod "hostNetwork"))

(defun valid-sysctl-name-p (name)
  "Match Kubernetes' sysctl name grammar, with either separator, within its 253 limit."
  (and (stringp name) (<= 1 (length name) 253)
       (cl-ppcre:scan "^([a-z0-9]([-_a-z0-9]*[a-z0-9])?[\\./])*[a-z0-9]([-_a-z0-9]*[a-z0-9])?$" name)
       t))

(defun canonical-sysctl-name (name)
  "Return NAME in dotted form; the kernel's own slash separator means the same variable."
  (if (find #\/ name)
      (let ((dot (position #\. name)) (slash (position #\/ name)))
        ;; A name starting with a slash-separated path treats dots as literal
        ;; characters, which must stay distinct from the path separators.
        (if (or (null dot) (< slash dot))
            (map 'string (lambda (character)
                           (case character (#\/ #\.) (#\. #\/) (t character)))
                 name)
            name))
      name))

(defun validate-pod-sysctls (context)
  "Reject every malformed sysctl name at once, in the form Kubernetes reports them."
  (let ((invalid
          (loop for entry across (optional-vector context "sysctls" "securityContext")
                for index from 0
                do (drop-null-fields (require-object entry "sysctl"))
                   (reject-unsupported-fields entry '("name" "value") "sysctl")
                   (unless (stringp (gethash "value" entry "")) (invalid-pod "sysctl value must be a string"))
                unless (valid-sysctl-name-p (gethash "name" entry))
                  collect (format nil "spec.securityContext.sysctls[~D].name: Invalid value: ~S: must have at most 253 characters and match regex ^([a-z0-9]([-_a-z0-9]*[a-z0-9])?[\\./])*[a-z0-9]([-_a-z0-9]*[a-z0-9])?$"
                                  index (gethash "name" entry)))))
    (when invalid (invalid-pod "Pod is invalid: [~{~A~^, ~}]" invalid))
    (let ((names (map 'list (lambda (entry) (canonical-sysctl-name (gethash "name" entry)))
                      (optional-vector context "sysctls" "securityContext"))))
      (unless (= (length names) (length (remove-duplicates names :test #'equal)))
        (invalid-pod "spec.securityContext.sysctls: Duplicate value")))))

(defun pod-sysctls (pod)
  "Return POD's sysctls as (dotted-name . value) entries for its sandbox."
  (let ((context (gethash "securityContext" (gethash "spec" (pod-to-object pod)))))
    (when context
      (map 'list (lambda (entry) (cons (canonical-sysctl-name (gethash "name" entry))
                                       (gethash "value" entry "")))
           (gethash "sysctls" context #())))))

(defun pod-forbidden-sysctl-failure (pod)
  "Return why a node refuses POD's sysctls as (message . reason), or NIL.
Net sysctls cannot be set in the node's own namespace, and others need the node's consent."
  (loop for (name) in (pod-sysctls pod)
        unless (member name +safe-pod-sysctls+ :test #'equal)
          return (cons (format nil "forbidden sysctl: ~S not allowlisted" name) "SysctlForbidden")
        when (and (pod-host-network-p pod) (uiop:string-prefix-p "net." name))
          return (cons (format nil "forbidden sysctl: ~S not allowed with host net enabled" name) "SysctlForbidden")))

(defparameter *apparmor-enabled-path* #P"/sys/module/apparmor/parameters/enabled"
  "Where the kernel says whether AppArmor is enforcing, as runc's apparmor.IsEnabled reads it.")

(defun host-apparmor-enabled-p ()
  "Return whether this host's kernel enforces AppArmor."
  (let ((value (ignore-errors (uiop:read-file-string *apparmor-enabled-path*))))
    (and value (plusp (length value)) (char-equal #\Y (char value 0)))))

(defun pod-effective-apparmor-profiles (pod)
  "Return each container's effective appArmorProfile: its own, or else the Pod's."
  (let* ((spec (gethash "spec" (pod-to-object pod)))
         (pod-profile (gethash "appArmorProfile" (gethash "securityContext" spec (core-object)))))
    (loop for container across (concatenate 'vector (gethash "initContainers" spec #()) (gethash "containers" spec #())
                                            (gethash "ephemeralContainers" spec #()))
          for profile = (or (gethash "appArmorProfile" (gethash "securityContext" container (core-object))) pod-profile)
          when profile collect profile)))

(defun pod-apparmor-failure (pod)
  "Return why a node refuses POD's AppArmor profiles as (message . reason), or NIL.
As a kubelet does, a node without AppArmor refuses any profile other than Unconfined."
  (when (and (or (some (lambda (profile) (not (equal "Unconfined" (gethash "type" profile))))
                       (pod-effective-apparmor-profiles pod))
                 (let ((profile (gethash "appArmorProfile"
                                         (gethash "securityContext" (gethash "spec" (pod-to-object pod)) (core-object)))))
                   (and profile (not (equal "Unconfined" (gethash "type" profile))))))
             (not (host-apparmor-enabled-p)))
    (cons "Cannot enforce AppArmor: AppArmor is not enabled on the host" "AppArmor")))

(defun validate-windows-pod-spec (spec)
  "Refuse the Linux-only settings upstream forbids for a Pod whose os.name is windows."
  (dolist (field '("hostPID" "hostIPC" "shareProcessNamespace" "hostUsers"))
    (when (eq t (gethash field spec))
      (invalid-pod "spec.~A: Forbidden: cannot be set for a windows pod" field)))
  (let ((context (gethash "securityContext" spec)))
    (when (hash-table-p context)
      (dolist (field '("appArmorProfile" "seLinuxOptions" "seccompProfile" "fsGroup" "fsGroupChangePolicy" "sysctls"
                       "runAsUser" "runAsGroup" "supplementalGroups" "supplementalGroupsPolicy" "seLinuxChangePolicy"))
        (unless (member (gethash field context) '(nil null) :test #'equal)
          (invalid-pod "spec.securityContext.~A: Forbidden: cannot be set for a windows pod" field)))))
  (loop for container across (concatenate 'vector (optional-vector spec "initContainers" "spec")
                                          (optional-vector spec "containers" "spec")
                                          (optional-vector spec "ephemeralContainers" "spec"))
        for context = (and (hash-table-p container) (gethash "securityContext" container))
        when (hash-table-p context)
          do (dolist (field '("appArmorProfile" "seLinuxOptions" "seccompProfile" "capabilities" "readOnlyRootFilesystem"
                              "privileged" "allowPrivilegeEscalation" "procMount" "runAsUser" "runAsGroup"))
               (unless (member (gethash field context) '(nil null) :test #'equal)
                 (invalid-pod "securityContext.~A: Forbidden: cannot be set for a windows pod" field)))))

(defun pod-os-failure (pod)
  "Return why this Linux node refuses POD as (message . reason) when POD declares another OS, as a kubelet does."
  (let ((os (gethash "os" (gethash "spec" (pod-to-object pod)))))
    (when (and (hash-table-p os) (not (equal "linux" (gethash "name" os))))
      (cons "Failed to admit pod as the OS field doesn't match node OS" "PodOSNotSupported"))))

(defun validate-pod-host-aliases (spec)
  "Validate hostAliases, each one IP address and at least one hostname."
  (loop for alias across (optional-vector spec "hostAliases" "spec")
        do (drop-null-fields (require-object alias "hostAlias"))
           (reject-unsupported-fields alias '("ip" "hostnames") "hostAlias")
           (let ((ip (gethash "ip" alias)))
             (unless (and (stringp ip)
                          (or (ignore-errors (parse-ipv4-integer ip))
                              (and (find #\: ip) (ignore-errors (0conf:parse-ipv6 ip)))))
               (invalid-pod "spec.hostAliases.ip must be an IP address")))
           (loop for hostname across (optional-vector alias "hostnames" "hostAlias")
                 do (require-dns-subdomain hostname "spec.hostAliases.hostnames"))))

(defun validate-pod-host-settings (spec)
  "Validate node namespace flags, the Pod's declared OS and its hosts aliases."
  (dolist (field '("hostNetwork" "hostPID" "hostIPC" "shareProcessNamespace"))
    (when (eq (gethash field spec) 'null) (remhash field spec))
    (multiple-value-bind (value present) (gethash field spec)
      (when (and present (not (member value '(t nil))))
        (invalid-pod "spec.~A must be boolean" field))))
  (when (and (eq t (gethash "hostPID" spec)) (eq t (gethash "shareProcessNamespace" spec)))
    (invalid-pod "spec.shareProcessNamespace cannot be set with spec.hostPID"))
  (when (eq (gethash "os" spec) 'null) (remhash "os" spec))
  (let ((os (gethash "os" spec)))
    (when os
      (drop-null-fields (require-object os "spec.os"))
      (reject-unsupported-fields os '("name") "spec.os")
      (unless (member (gethash "name" os) '("linux" "windows") :test #'equal)
        (invalid-pod "spec.os.name: Unsupported value: ~S: supported values: \"linux\", \"windows\"" (gethash "name" os)))
      (when (equal "windows" (gethash "name" os)) (validate-windows-pod-spec spec))))
  (when (eq (gethash "hostAliases" spec) 'null) (remhash "hostAliases" spec))
  (validate-pod-host-aliases spec))

(defun default-host-network-ports (spec)
  "A hostNetwork container's port is also its host port; a different one could never work."
  (when (eq t (gethash "hostNetwork" spec))
    (loop for container across (concatenate 'vector (optional-vector spec "initContainers" "spec")
                                            (optional-vector spec "containers" "spec"))
          do (loop for port across (optional-vector container "ports" "container")
                   for number = (gethash "containerPort" port)
                   for host = (gethash "hostPort" port 0)
                   do (cond ((member host '(0 null)) (setf (gethash "hostPort" port) number))
                            ((not (eql host number))
                             (invalid-pod "hostPort must match containerPort when hostNetwork is true")))))))

(defun pod-host-aliases-content (pod)
  "Render POD's hostAliases as the block a kubelet appends to its managed hosts file."
  (let ((aliases (gethash "hostAliases" (gethash "spec" (pod-to-object pod)) #())))
    (if (zerop (length aliases))
        ""
        (with-output-to-string (out)
          (format out "~%# Entries added by HostAliases.~%")
          (loop for alias across aliases
                do (format out "~A~{~C~A~}~%" (gethash "ip" alias)
                           (loop for hostname across (gethash "hostnames" alias #())
                                 collect #\Tab collect hostname)))))))

(defun pod-resource-class-amounts (container)
  "Return CONTAINER's nonzero (requests limits) CPU and memory as (name . quantity) lists."
  (flet ((amounts (kind)
           (loop for name in '("cpu" "memory")
                 for value = (gethash name (container-resource-map container kind))
                 for quantity = (and value (parse-container-quantity value))
                 when (and quantity (plusp (container-quantity-coefficient quantity)))
                   collect (cons name quantity))))
    (values (amounts "requests") (amounts "limits"))))

(defun pod-spec-qos-class (spec)
  "Classify a Pod spec as Kubernetes does: from its CPU and memory requests and limits alone.
Pod-level resources, when set, decide it on their own."
  (when (pod-level-resources-set-p spec)
    (return-from pod-spec-qos-class (pod-level-requirements-qos (gethash "resources" spec))))
  (let ((guaranteed t) (any nil))
    (loop for container across (concatenate 'vector (gethash "initContainers" spec #()) (gethash "containers" spec #()))
          do (multiple-value-bind (requests limits) (pod-resource-class-amounts container)
               (when (or requests limits) (setf any t))
               (unless (and (assoc "cpu" limits :test #'equal) (assoc "memory" limits :test #'equal))
                 (setf guaranteed nil))
               (loop for (name . quantity) in requests
                     for limit = (cdr (assoc name limits :test #'equal))
                     unless (and limit (zerop (container-quantity-compare quantity limit)))
                       do (setf guaranteed nil))))
    (cond ((not any) "BestEffort") (guaranteed "Guaranteed") (t "Burstable"))))

