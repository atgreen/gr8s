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
