;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Verify Kubernetes Pod Security Admission profiles, namespace modes,
;;;; version selection, exemptions, and warning behavior.

(in-package #:gr8s/tests)

(def-suite pod-security-admission :in gr8s)
(in-suite pod-security-admission)

(defun psa-pod (&rest security-fields)
  (gr8s::core-object
   "apiVersion" "v1" "kind" "Pod"
   "metadata" (gr8s::core-object "name" "p" "namespace" "team")
   "spec" (gr8s::core-object
           "containers" (vector (gr8s::core-object
                                  "name" "c" "image" "example"
                                  "securityContext" (apply #'gr8s::core-object security-fields))))))

(test pod-security-profiles-follow-upstream-boundaries
  (let ((privileged (psa-pod "privileged" t)))
    (is (null (gr8s::pod-security-violations "privileged" "latest" privileged)))
    (is (find "privileged" (gr8s::pod-security-violations "baseline" "latest" privileged)
              :test #'search)))
  (let ((restricted (psa-pod "allowPrivilegeEscalation" nil "runAsNonRoot" t
                             "capabilities" (gr8s::core-object "drop" #("ALL"))
                             "seccompProfile" (gr8s::core-object "type" "RuntimeDefault"))))
    (is (null (gr8s::pod-security-violations "restricted" "latest" restricted)))))

(test restricted-requires-explicitly-disabled-privilege-escalation
  (let ((violations (gr8s::pod-security-violations
                     "restricted" "latest"
                     (psa-pod "runAsNonRoot" t
                              "capabilities" (gr8s::core-object "drop" #("ALL"))
                              "seccompProfile" (gr8s::core-object "type" "RuntimeDefault")))))
    (is (find "allowPrivilegeEscalation" violations :test #'search))))

(test pod-security-version-selects-versioned-checks
  (let* ((pod (psa-pod))
         (spec (gethash "spec" pod))
         (container (aref (gethash "containers" spec) 0)))
    (setf (gethash "livenessProbe" container)
          (gr8s::core-object "httpGet" (gr8s::core-object "port" 80 "host" "127.0.0.1")))
    (is (null (gr8s::pod-security-violations "baseline" "v1.33" pod)))
    (is (find "host" (gr8s::pod-security-violations "baseline" "v1.34" pod)
              :test #'search))))

(test pod-security-versioned-policy-fixtures-match-upstream-boundaries
  (labels ((violates-p (text level version pod)
             (find text (gr8s::pod-security-violations level version pod) :test #'search))
           (pod-security (pod)
             (let ((spec (gethash "spec" pod)))
               (or (gethash "securityContext" spec)
                   (setf (gethash "securityContext" spec) (gr8s::core-object))))))
    (let ((pod (psa-pod)))
      (setf (gethash "seLinuxOptions" (pod-security pod))
            (gr8s::core-object "type" "container_engine_t"))
      (is (violates-p "SELinux type" "baseline" "v1.30" pod))
      (is-false (violates-p "SELinux type" "baseline" "v1.31" pod))
      (setf (gethash "user" (gethash "seLinuxOptions" (pod-security pod))) "custom")
      (is (violates-p "SELinux user" "baseline" "v1.31" pod)))
    (let ((pod (psa-pod)))
      (setf (gethash "sysctls" (pod-security pod))
            (vector (gr8s::core-object "name" "net.ipv4.tcp_rmem")))
      (is (violates-p "unsafe sysctl" "baseline" "v1.31" pod))
      (is-false (violates-p "unsafe sysctl" "baseline" "v1.32" pod))
      (setf (gethash "name" (aref (gethash "sysctls" (pod-security pod)) 0))
            "net.ipv4.tcp_slow_start_after_idle")
      (is (violates-p "unsafe sysctl" "baseline" "v1.36" pod))
      (is-false (violates-p "unsafe sysctl" "baseline" "v1.37" pod)))
    (let* ((pod (psa-pod))
           (container (aref (gethash "containers" (gethash "spec" pod)) 0)))
      (setf (gethash "lifecycle" container)
            (gr8s::core-object
             "preStop" (gr8s::core-object
                        "tcpSocket" (gr8s::core-object "port" 80 "host" "127.0.0.1"))))
      (is-false (violates-p "host" "baseline" "v1.33" pod))
      (is (violates-p "host" "baseline" "v1.34" pod)))
    (let* ((pod (psa-pod "allowPrivilegeEscalation" nil
                         "capabilities" (gr8s::core-object "drop" #("ALL"))
                         "seccompProfile" (gr8s::core-object "type" "RuntimeDefault")
                         "runAsUser" 0))
           (spec (gethash "spec" pod)))
      (setf (gethash "hostUsers" spec) nil)
      (is (violates-p "runAsNonRoot" "restricted" "v1.34" pod))
      (is (violates-p "runAsUser" "restricted" "v1.34" pod))
      (is-false (violates-p "runAsNonRoot" "restricted" "v1.35" pod))
      (is-false (violates-p "runAsUser" "restricted" "v1.35" pod)))
    (let ((pod (psa-pod "runAsNonRoot" t)))
      (is-false (violates-p "allowPrivilegeEscalation" "restricted" "v1.7" pod))
      (is (violates-p "allowPrivilegeEscalation" "restricted" "v1.8" pod)))))

(test pod-security-namespace-labels-validate-create-and-update
  (let ((valid (gr8s::core-object
                "metadata" (gr8s::core-object
                            "labels" (gr8s::core-object
                                      "pod-security.kubernetes.io/enforce" "restricted"
                                      "pod-security.kubernetes.io/enforce-version" "v1.34"))))
        (bad-level (gr8s::core-object
                    "metadata" (gr8s::core-object
                                "labels" (gr8s::core-object
                                          "pod-security.kubernetes.io/enforce" "maximum"))))
        (bad-version (gr8s::core-object
                      "metadata" (gr8s::core-object
                                  "labels" (gr8s::core-object
                                            "pod-security.kubernetes.io/warn-version" "1.34")))))
    (is-true (gr8s::admit-pod-security-namespace "CREATE" valid))
    (signals gr8s::kubernetes-error
      (gr8s::admit-pod-security-namespace "CREATE" bad-level))
    (signals gr8s::kubernetes-error
      (gr8s::admit-pod-security-namespace "CREATE" bad-version))
    (is-true (gr8s::admit-pod-security-namespace "UPDATE" bad-level bad-level))
    (signals gr8s::kubernetes-error
      (gr8s::admit-pod-security-namespace "UPDATE" bad-version bad-level))))

(test namespace-write-path-enforces-pod-security-labels
  (with-temporary-store (store directory)
    (declare (ignore directory))
    (let ((gr8s::*admission-controller* "pod-security-test"))
      (signals gr8s::kubernetes-error
        (gr8s::admitted-create-core-resource
         store "namespaces"
         (gr8s::core-object
          "metadata" (gr8s::core-object
                      "name" "invalid"
                      "labels" (gr8s::core-object
                                "pod-security.kubernetes.io/enforce" "maximum")))
         nil))
      (gr8s::admitted-create-core-resource
       store "namespaces" (gr8s::core-object "metadata" (gr8s::core-object "name" "team")) nil)
      (signals gr8s::kubernetes-error
        (gr8s::admitted-update-core-resource
         store "namespaces" nil "team"
         (lambda (namespace)
           (setf (gethash "labels" (gethash "metadata" namespace))
                 (gr8s::core-object "pod-security.kubernetes.io/audit-version" "v2"))
           namespace))))))

(test pod-security-is-enforced-through-the-http-api
  (with-core-api (store path)
    (values store path)
    (check-core-status
     422 "/api/v1/namespaces" :method :post
     :object (gr8s::core-object
              "apiVersion" "v1" "kind" "Namespace"
              "metadata" (gr8s::core-object
                          "name" "bad"
                          "labels" (gr8s::core-object
                                    "pod-security.kubernetes.io/enforce" "maximum"))))
    (check-core-status
     201 "/api/v1/namespaces" :method :post
     :object (gr8s::core-object
              "apiVersion" "v1" "kind" "Namespace"
              "metadata" (gr8s::core-object
                          "name" "team"
                          "labels" (gr8s::core-object
                                    "pod-security.kubernetes.io/enforce" "baseline"
                                    "pod-security.kubernetes.io/warn" "restricted"))))
    (check-core-status 403 "/api/v1/namespaces/team/pods" :method :post
                       :object (psa-pod "privileged" t))
    (multiple-value-bind (body status headers)
        (drakma:http-request
         (core-api-url "/api/v1/namespaces/team/pods")
         :method :post :content-type "application/json"
         :content (com.inuoe.jzon:stringify (psa-pod)))
      (declare (ignore body))
      (is (= 201 status))
      (is (assoc :warning headers)))))

(test pod-security-namespace-modes-enforce-warn-and-exempt
  (with-temporary-store (store directory)
    (declare (ignore directory))
    (let ((gr8s::*admission-controller* "pod-security-test"))
      (gr8s::create-core-resource
       store "namespaces"
       (gr8s::core-object
        "apiVersion" "v1" "kind" "Namespace"
        "metadata" (gr8s::core-object
                    "name" "team" "labels"
                    (gr8s::core-object
                     "pod-security.kubernetes.io/enforce" "baseline"
                     "pod-security.kubernetes.io/warn" "restricted"
                     "pod-security.kubernetes.io/audit" "restricted")))
       nil)
      (let ((attributes (gr8s::admission-attributes-for store "CREATE" "pods" "team" "p"))
            (pod (psa-pod "privileged" t)))
        (signals gr8s::kubernetes-error
          (gr8s::admit-pod-security store attributes pod)))
      (let* ((attributes (gr8s::admission-attributes-for store "CREATE" "pods" "team" "p"))
             (pod (psa-pod))
             (audit (with-output-to-string (stream)
                      (let ((*error-output* stream))
                        (gr8s::admit-pod-security store attributes pod)))))
        (is (= 1 (length (gr8s::admission-warnings attributes))))
        (is (search "pod-security.kubernetes.io/audit-violations" audit)))
      (let ((gr8s::*pod-security-exempt-namespaces* '("team")))
        (is (eq t (gr8s::admit-pod-security
                   store (gr8s::admission-attributes-for store "CREATE" "pods" "team" "p")
                   (psa-pod "privileged" t)))))
      (let* ((attributes (gr8s::admission-attributes-for store "UPDATE" "pods" "team" "p"))
             (pod (psa-pod "privileged" t)))
        (signals gr8s::kubernetes-error
          (gr8s::admit-pod-security store attributes pod)))
      (let* ((gr8s::*pod-security-exempt-usernames* '("alice"))
             (attributes (gr8s::admission-attributes-for store "CREATE" "pods" "team" "p")))
        (setf (gr8s::admission-user-info attributes) (gr8s::core-object "username" "alice"))
        (is-true (gr8s::admit-pod-security store attributes (psa-pod "privileged" t))))
      (let* ((gr8s::*pod-security-exempt-runtime-classes* '("trusted"))
             (attributes (gr8s::admission-attributes-for store "CREATE" "pods" "team" "p"))
             (pod (psa-pod "privileged" t)))
        (setf (gethash "runtimeClassName" (gethash "spec" pod)) "trusted")
        (is-true (gr8s::admit-pod-security store attributes pod))))))
