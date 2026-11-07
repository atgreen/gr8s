;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Built-in Pod Security Admission. The checks mirror the upstream baseline
;;;; and restricted standards and are selected by namespace labels.

(in-package #:gr8s.apiserver)

(defparameter *pod-security-exempt-namespaces* nil)
(defparameter *pod-security-exempt-usernames* nil)
(defparameter *pod-security-exempt-runtime-classes* nil)

(defparameter +psa-baseline-capabilities+
  '("AUDIT_WRITE" "CHOWN" "DAC_OVERRIDE" "FOWNER" "FSETID" "KILL" "MKNOD"
    "NET_BIND_SERVICE" "SETFCAP" "SETGID" "SETPCAP" "SETUID" "SYS_CHROOT"))

(defparameter +psa-restricted-volume-types+
  '("configMap" "csi" "downwardAPI" "emptyDir" "ephemeral" "persistentVolumeClaim"
    "projected" "secret"))

(defun psa-field (object name)
  (and (hash-table-p object) (gethash name object)))

(defun psa-vector-list (value)
  (if (and (vectorp value) (not (stringp value))) (coerce value 'list) nil))

(defun psa-containers (spec)
  (append (psa-vector-list (psa-field spec "containers"))
          (psa-vector-list (psa-field spec "initContainers"))
          (psa-vector-list (psa-field spec "ephemeralContainers"))))

(defun psa-version-minor (version)
  (cond ((or (null version) (equal version "latest")) 37)
        ((and (stringp version) (cl-ppcre:scan "^v1\\.[0-9]+$" version))
         (parse-integer version :start 3))
        (t (error 'kubernetes-error :status-code 400 :reason "BadRequest"
                  :message (format nil "invalid Pod Security version ~S" version)))))

(defun psa-security-value (pod-security container-security name)
  (multiple-value-bind (value present) (and (hash-table-p container-security)
                                             (gethash name container-security))
    (if present value (psa-field pod-security name))))

(defun psa-field-present-p (object name)
  (and (hash-table-p object) (nth-value 1 (gethash name object))))

(defun psa-windows-p (spec)
  (equal "windows" (psa-field (psa-field spec "os") "name")))

(defun psa-user-namespace-p (spec minor)
  (and (>= minor 35)
       (psa-field-present-p spec "hostUsers")
       (eq nil (psa-field spec "hostUsers"))))

(defun psa-host-probe-p (container)
  (labels ((host-set-p (action)
             (loop for protocol in '("httpGet" "tcpSocket")
                   for host = (psa-field (psa-field action protocol) "host")
                   thereis (and (stringp host) (plusp (length host))))))
    (or (loop for name in '("livenessProbe" "readinessProbe" "startupProbe")
              thereis (host-set-p (psa-field container name)))
        (let ((lifecycle (psa-field container "lifecycle")))
          (or (host-set-p (psa-field lifecycle "postStart"))
              (host-set-p (psa-field lifecycle "preStop")))))))

(defun psa-safe-sysctls (minor)
  (append '("kernel.shm_rmid_forced" "net.ipv4.ip_local_port_range"
            "net.ipv4.ip_unprivileged_port_start" "net.ipv4.tcp_syncookies"
            "net.ipv4.ping_group_range")
          (when (>= minor 27) '("net.ipv4.ip_local_reserved_ports"))
          (when (>= minor 29) '("net.ipv4.tcp_keepalive_time" "net.ipv4.tcp_fin_timeout"
                                "net.ipv4.tcp_keepalive_intvl" "net.ipv4.tcp_keepalive_probes"))
          (when (>= minor 32) '("net.ipv4.tcp_rmem" "net.ipv4.tcp_wmem"))
          (when (>= minor 37) '("net.ipv4.tcp_slow_start_after_idle" "net.ipv4.tcp_notsent_lowat"))))

(defun psa-selinux-violations (pod-security containers minor)
  (let ((allowed (append '(nil "" "container_t" "container_init_t" "container_kvm_t")
                         (when (>= minor 31) '("container_engine_t"))))
        (violations nil))
    (dolist (security (cons pod-security (mapcar (lambda (container) (psa-field container "securityContext"))
                                                  containers)))
      (let ((options (psa-field security "seLinuxOptions")))
        (when (hash-table-p options)
          (unless (member (psa-field options "type") allowed :test #'equal)
            (pushnew "SELinux type is forbidden" violations :test #'equal))
          (when (or (let ((user (psa-field options "user"))) (and (stringp user) (plusp (length user))))
                    (let ((role (psa-field options "role"))) (and (stringp role) (plusp (length role)))))
            (pushnew "SELinux user and role must not be set" violations :test #'equal)))))
    violations))

(defun psa-baseline-violations (pod minor)
  (let* ((spec (psa-field pod "spec"))
         (pod-security (psa-field spec "securityContext"))
         (containers (psa-containers spec))
         (violations (psa-selinux-violations pod-security containers minor)))
    (flet ((violate (message) (pushnew message violations :test #'equal)))
      (dolist (field '("hostNetwork" "hostPID" "hostIPC" "shareProcessNamespace"))
        (when (eq t (psa-field spec field)) (violate (format nil "~A must not be true" field))))
      (dolist (volume (psa-vector-list (psa-field spec "volumes")))
        (when (psa-field volume "hostPath") (violate "hostPath volumes are forbidden")))
      (dolist (container containers)
        (let* ((security (psa-field container "securityContext"))
               (capabilities (psa-field security "capabilities")))
          (when (eq t (psa-field security "privileged"))
            (violate "privileged containers are forbidden"))
          (when (eq t (psa-field (psa-field security "windowsOptions") "hostProcess"))
            (violate "Windows HostProcess containers are forbidden"))
          (dolist (port (psa-vector-list (psa-field container "ports")))
            (let ((host-port (psa-field port "hostPort")))
              (when (and (integerp host-port) (not (zerop host-port)))
                (violate "hostPort must be zero"))))
          (dolist (capability (psa-vector-list (psa-field capabilities "add")))
            (unless (member capability +psa-baseline-capabilities+ :test #'equal)
              (violate (format nil "capability ~A is not allowed" capability))))
          (let ((profile (and (>= minor 19) (psa-security-value pod-security security "seccompProfile"))))
            (when (equal "Unconfined" (psa-field profile "type"))
              (violate "seccompProfile type Unconfined is forbidden")))
          (when (and (not (psa-user-namespace-p spec minor))
                     (equal "Unmasked" (psa-field security "procMount")))
            (violate "procMount type Unmasked is forbidden"))
          (when (equal "Unconfined" (psa-field (psa-field security "appArmorProfile") "type"))
            (violate "AppArmor profile Unconfined is forbidden"))
          (when (and (>= minor 34) (psa-host-probe-p container))
            (violate "probe host must be empty"))))
      (let ((sysctls (psa-vector-list (psa-field pod-security "sysctls"))))
        (dolist (sysctl sysctls)
          (unless (member (psa-field sysctl "name") (psa-safe-sysctls minor) :test #'equal)
            (violate (format nil "unsafe sysctl ~A" (psa-field sysctl "name"))))))
      (nreverse violations))))

(defun psa-restricted-violations (pod minor)
  (let* ((spec (psa-field pod "spec"))
         (pod-security (psa-field spec "securityContext"))
         (windows (and (>= minor 25) (psa-windows-p spec)))
         (user-namespace (psa-user-namespace-p spec minor))
         (violations (psa-baseline-violations pod minor)))
    (flet ((violate (message) (pushnew message violations :test #'equal)))
      (dolist (volume (psa-vector-list (psa-field spec "volumes")))
        (unless (loop for type in +psa-restricted-volume-types+ thereis (psa-field volume type))
          (violate "volume type is not allowed by the restricted profile")))
      (dolist (container (psa-containers spec))
        (let* ((security (psa-field container "securityContext"))
               (capabilities (psa-field security "capabilities"))
               (drops (psa-vector-list (psa-field capabilities "drop")))
               (adds (psa-vector-list (psa-field capabilities "add"))))
          (when (and (>= minor 8) (not windows)
                     (not (and (psa-field-present-p security "allowPrivilegeEscalation")
                               (eq nil (psa-field security "allowPrivilegeEscalation")))))
            (violate "allowPrivilegeEscalation must be false"))
          (unless (or user-namespace (eq t (psa-security-value pod-security security "runAsNonRoot")))
            (violate "runAsNonRoot must be true"))
          (when (and (>= minor 23) (not user-namespace)
                     (eql 0 (psa-security-value pod-security security "runAsUser")))
            (violate "runAsUser must not be zero"))
          (when (and (>= minor 22) (not windows))
            (unless (member "ALL" drops :test #'equal)
              (violate "capabilities must drop ALL"))
            (dolist (capability adds)
              (unless (equal capability "NET_BIND_SERVICE")
                (violate (format nil "restricted capability ~A is forbidden" capability)))))
          (when (and (>= minor 19) (not windows))
            (let* ((profile (psa-security-value pod-security security "seccompProfile"))
                   (type (psa-field profile "type")))
              (unless (member type '("RuntimeDefault" "Localhost") :test #'equal)
                (violate "seccompProfile type must be RuntimeDefault or Localhost"))))
          (when (and (>= minor 35) (equal "Unmasked" (psa-field security "procMount")))
            (violate "procMount type Unmasked is forbidden"))))
      (nreverse violations))))

(defun pod-security-violations (level version pod)
  "Return human-readable violations of LEVEL at VERSION for POD."
  (let ((minor (psa-version-minor version)))
    (cond ((equal level "privileged") nil)
          ((equal level "baseline") (psa-baseline-violations pod minor))
          ((equal level "restricted") (psa-restricted-violations pod minor))
          (t (error 'kubernetes-error :status-code 400 :reason "BadRequest"
                    :message (format nil "invalid Pod Security level ~S" level))))))

(defun pod-security-label-errors (namespace)
  "Return invalid Pod Security namespace label descriptions for NAMESPACE."
  (let ((labels (psa-field (psa-field namespace "metadata") "labels"))
        (errors nil))
    (dolist (mode '("enforce" "audit" "warn"))
      (let* ((level-key (format nil "pod-security.kubernetes.io/~A" mode))
             (version-key (format nil "~A-version" level-key))
             (level (psa-field labels level-key))
             (version (psa-field labels version-key)))
        (when (and level (not (member level '("privileged" "baseline" "restricted") :test #'equal)))
          (push (format nil "~A must be privileged, baseline, or restricted" level-key) errors))
        (when version
          (handler-case (psa-version-minor version)
            (kubernetes-error ()
              (push (format nil "~A must be latest or a version like v1.34" version-key) errors))))))
    (nreverse errors)))

(defun admit-pod-security-namespace (operation namespace &optional old-namespace)
  "Validate Pod Security labels on a Namespace CREATE or UPDATE.
An UPDATE may preserve an already-invalid set of labels, matching upstream's
grandfathering behavior, but cannot introduce a different invalid set."
  (let ((errors (pod-security-label-errors namespace)))
    (when (and errors
               (or (equal operation "CREATE")
                   (not (equal errors (pod-security-label-errors old-namespace)))))
      (error 'kubernetes-error :status-code 422 :reason "Invalid"
             :message (format nil "Namespace has invalid Pod Security labels: ~{~A~^; ~}" errors))))
  t)

(defun psa-exempt-p (attributes pod)
  (let* ((username (psa-field (admission-user-info attributes) "username"))
         (runtime-class (psa-field (psa-field pod "spec") "runtimeClassName")))
    (or (member (admission-namespace attributes) *pod-security-exempt-namespaces* :test #'equal)
        (member username *pod-security-exempt-usernames* :test #'equal)
        (member runtime-class *pod-security-exempt-runtime-classes* :test #'equal))))

(defun admit-pod-security (store attributes pod)
  "Apply namespace enforce/audit/warn Pod Security labels to POD."
  (when (or (not (member (admission-operation attributes) '("CREATE" "UPDATE") :test #'equal))
            (psa-exempt-p attributes pod))
    (return-from admit-pod-security t))
  (let* ((namespace (handler-case
                        (get-core-resource store "namespaces" nil (admission-namespace attributes))
                      (kubernetes-error () nil)))
         (labels (psa-field (psa-field namespace "metadata") "labels")))
    (labels ((setting (mode suffix default)
               (or (psa-field labels (format nil "pod-security.kubernetes.io/~A~A" mode suffix)) default))
             (violations (mode)
               (let ((level (setting mode "" "privileged")))
                 (values level (pod-security-violations level (setting mode "-version" "latest") pod)))))
      (multiple-value-bind (level found) (violations "warn")
        (when found
          (push (format nil "would violate PodSecurity ~A: ~{~A~^, ~}" level found)
                (admission-warnings attributes))))
      (multiple-value-bind (level found) (violations "audit")
        (when found
          (format *error-output* "~&Audit annotation pod-security.kubernetes.io/audit-violations: ~A: ~{~A~^, ~}~%"
                  level found)))
      (multiple-value-bind (level found) (violations "enforce")
        (when found
          (error 'kubernetes-error :status-code 403 :reason "Forbidden"
                 :message (format nil "pods ~S is forbidden: violates PodSecurity ~A: ~{~A~^, ~}"
                                  (admission-name attributes) level found))))))
  t)
