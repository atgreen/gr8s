;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Verify the Pod and container security context fields beyond identities:
;;;; their validation, AppArmor admission on a node without AppArmor, and the
;;;; supplemental groups policy and AppArmor profile handed to the runtime.

(in-package #:gr8s/tests)
(in-suite gr8s)

(defun security-context-test-object (&key pod container)
  "Return a Pod object whose Pod and first container security contexts are POD and CONTAINER JSON."
  (let ((object (com.inuoe.jzon:parse *valid-pod-json*)))
    (when pod (setf (gethash "securityContext" (gethash "spec" object)) (com.inuoe.jzon:parse pod)))
    (when container
      (setf (gethash "securityContext" (aref (gethash "containers" (gethash "spec" object)) 0))
            (com.inuoe.jzon:parse container)))
    object))

(test security-context-policy-fields-are-validated
  (dolist (pod '("{\"fsGroup\":2000,\"fsGroupChangePolicy\":\"OnRootMismatch\"}"
                 "{\"fsGroupChangePolicy\":\"Always\",\"supplementalGroupsPolicy\":\"Strict\"}"
                 "{\"seLinuxChangePolicy\":\"MountOption\",\"appArmorProfile\":{\"type\":\"RuntimeDefault\"}}"
                 "{\"windowsOptions\":{\"runAsUserName\":\"ContainerUser\"}}"))
    (finishes (parse-pod (security-context-test-object :pod pod))))
  (dolist (container '("{\"procMount\":\"Default\"}"
                       "{\"appArmorProfile\":{\"type\":\"Localhost\",\"localhostProfile\":\"k8s-deny-write\"}}"
                       "{\"appArmorProfile\":{\"type\":\"Unconfined\"}}"))
    (finishes (parse-pod (security-context-test-object :container container))))
  (dolist (pod '("{\"fsGroupChangePolicy\":\"Sometimes\"}" "{\"supplementalGroupsPolicy\":\"Loose\"}"
                 "{\"seLinuxChangePolicy\":\"Never\"}" "{\"appArmorProfile\":{}}"
                 "{\"appArmorProfile\":{\"type\":\"Localhost\"}}"
                 "{\"appArmorProfile\":{\"type\":\"Localhost\",\"localhostProfile\":\" padded\"}}"
                 "{\"appArmorProfile\":{\"type\":\"RuntimeDefault\",\"localhostProfile\":\"x\"}}"
                 "{\"windowsOptions\":{\"hostProcess\":\"yes\"}}"))
    (signals kubernetes-error (parse-pod (security-context-test-object :pod pod))))
  ;; Unmasked /proc needs a user namespace, which hostUsers=true Pods do not have.
  (signals kubernetes-error (parse-pod (security-context-test-object :container "{\"procMount\":\"Unmasked\"}")))
  (signals kubernetes-error (parse-pod (security-context-test-object :container "{\"procMount\":\"Other\"}")))
  (let ((linux (security-context-test-object :pod "{\"windowsOptions\":{\"runAsUserName\":\"ContainerUser\"}}")))
    (setf (gethash "os" (gethash "spec" linux)) (gr8s::core-object "name" "linux"))
    (signals kubernetes-error (parse-pod linux))))

(test a-node-without-apparmor-refuses-pods-that-require-it
  (let ((gr8s::*apparmor-enabled-path* #P"/nonexistent/apparmor/enabled"))
    (is (not (gr8s::host-apparmor-enabled-p)))
    (is (null (gr8s::pod-apparmor-failure (parse-pod *valid-pod-json*))))
    (is (null (gr8s::pod-apparmor-failure
               (parse-pod (security-context-test-object :pod "{\"appArmorProfile\":{\"type\":\"Unconfined\"}}")))))
    (let ((failure (gr8s::pod-apparmor-failure
                    (parse-pod (security-context-test-object
                                :container "{\"appArmorProfile\":{\"type\":\"RuntimeDefault\"}}")))))
      (is (equal "AppArmor" (cdr failure)))
      (is (equal "Cannot enforce AppArmor: AppArmor is not enabled on the host" (car failure))))
    (is (gr8s::pod-apparmor-failure
         (parse-pod (security-context-test-object :pod "{\"appArmorProfile\":{\"type\":\"RuntimeDefault\"}}"))))
    ;; Without AppArmor nothing is handed to the runtime.
    (is (null (gr8s::cri-apparmor-profile (gr8s::core-object "appArmorProfile" (gr8s::core-object "type" "Unconfined"))))))
  (with-temporary-store (store path)
    (values path)
    (let ((gr8s::*apparmor-enabled-path* #P"/nonexistent/apparmor/enabled")
          (object (security-context-test-object :pod "{\"appArmorProfile\":{\"type\":\"RuntimeDefault\"}}")))
      (setf (gethash "nodeName" (gethash "spec" object)) "worker-a")
      (let ((pod (create-pod store (parse-pod object))))
        (is-false (gr8s::admit-assigned-pod store pod))
        (let ((status (gr8s::pod-observed-status store pod)))
          (is (equal "Failed" (gethash "phase" status)))
          (is (equal "AppArmor" (gethash "reason" status))))
        (is-false (gr8s::admit-assigned-pod store pod))))))

(test apparmor-profiles-and-supplemental-group-policy-reach-the-runtime
  (let ((enabled (merge-pathnames "apparmor-enabled" (uiop:temporary-directory))))
    (with-open-file (out enabled :direction :output :if-exists :supersede) (write-line "Y" out))
    (unwind-protect
         (let* ((gr8s::*apparmor-enabled-path* enabled)
                (pod (parse-pod (security-context-test-object
                                 :pod "{\"supplementalGroupsPolicy\":\"Strict\",\"appArmorProfile\":{\"type\":\"RuntimeDefault\"}}"
                                 :container "{\"appArmorProfile\":{\"type\":\"Localhost\",\"localhostProfile\":\"k8s-deny-write\"}}")))
                (context (gr8s::containerd-pod-security-context pod (aref (pod-containers pod) 0)))
                (profile (gr8s.cri.v1::apparmor context)))
           (is (gr8s::host-apparmor-enabled-p))
           (is (null (gr8s::pod-apparmor-failure pod)))
           (is (= gr8s.cri.v1::|+PROFILETYPE-Localhost+| (gr8s.cri.v1::profile-type profile)))
           (is (equal "k8s-deny-write" (gr8s.cri.v1::localhost-ref profile)))
           (is (= gr8s.cri.v1::|+SUPPLEMENTALGROUPSPOLICY-Strict+| (gr8s.cri.v1::supplemental-groups-policy context)))
           (is (= gr8s.cri.v1::|+PROFILETYPE-RuntimeDefault+|
                  (gr8s.cri.v1::profile-type (getf (gr8s::containerd-pod-sandbox-security pod) :apparmor)))))
      (delete-file enabled)))
  (let ((context (gr8s::containerd-pod-security-context (parse-pod *valid-pod-json*)
                                                        (aref (pod-containers (parse-pod *valid-pod-json*)) 0))))
    (is (= gr8s.cri.v1::|+SUPPLEMENTALGROUPSPOLICY-Merge+| (gr8s.cri.v1::supplemental-groups-policy context)))))

(test run-as-non-root-is-verified-against-the-image-user-when-the-container-is-created
  (flet ((context (container &optional (uid nil uid-p) (username ""))
           (let ((pod (parse-pod (security-context-test-object :container container))) (asked nil))
             (handler-case
                 (progn (gr8s::containerd-pod-security-context
                         pod (aref (pod-containers pod) 0)
                         :image-user (lambda () (setf asked t) (values (if uid-p uid nil) username)))
                        (values :created asked))
               (gr8s::container-config-error (condition)
                 (values (princ-to-string condition) asked))))))
    ;; An explicit non-root user needs no look at the image.
    (multiple-value-bind (result asked) (context "{\"runAsNonRoot\":true,\"runAsUser\":1000}")
      (is (eq :created result))
      (is (not asked)))
    ;; An explicit root user is accepted by the API and refused when the container is created.
    (is (search "container's runAsUser breaks non-root policy"
                (context "{\"runAsNonRoot\":true,\"runAsUser\":0}")))
    (is (eq :created (context "{\"runAsNonRoot\":true}" 1234)))
    (is (search "image will run as root" (context "{\"runAsNonRoot\":true}" 0)))
    ;; An image that names no user runs as root.
    (is (search "image will run as root" (context "{\"runAsNonRoot\":true}" nil "")))
    (is (search "non-numeric user (nobody)" (context "{\"runAsNonRoot\":true}" nil "nobody")))
    (multiple-value-bind (result asked) (context "{\"runAsUser\":0}")
      (is (eq :created result))
      (is (not asked)))))

(test downward-api-reports-ephemeral-storage-requests-and-limits
  (let* ((object (com.inuoe.jzon:parse *valid-pod-json*))
         (container (aref (gethash "containers" (gethash "spec" object)) 0)))
    (setf (gethash "resources" container)
          (gr8s::core-object "requests" (gr8s::core-object "ephemeral-storage" "32Mi")
                             "limits" (gr8s::core-object "ephemeral-storage" "64Mi")))
    (let ((pod (parse-pod object)))
      (flet ((value (resource &optional divisor)
               (gr8s::downward-resource-value
                pod (let ((reference (gr8s::core-object "containerName" "web" "resource" resource)))
                      (when divisor (setf (gethash "divisor" reference) divisor))
                      reference))))
        (is (equal (write-to-string (* 32 1024 1024)) (value "requests.ephemeral-storage")))
        (is (equal "64" (value "limits.ephemeral-storage" "1Mi"))))))
  ;; Without a limit the node's storage capacity is reported, as for cpu and memory.
  (let ((pod (parse-pod *valid-pod-json*)))
    (is (plusp (parse-integer (gr8s::downward-resource-value
                               pod (gr8s::core-object "containerName" "web" "resource" "limits.ephemeral-storage"))))))
  (finishes (parse-pod (let ((object (com.inuoe.jzon:parse *valid-pod-json*)))
                         (setf (gethash "env" (aref (gethash "containers" (gethash "spec" object)) 0))
                               (vector (gr8s::core-object "name" "EPHEMERAL"
                                                          "valueFrom" (gr8s::core-object "resourceFieldRef"
                                                                                         (gr8s::core-object "resource" "limits.ephemeral-storage")))))
                         object))))

(test localhost-seccomp-profiles-are-read-from-the-kubelet-profile-root
  (let* ((pod (parse-pod (security-context-test-object
                          :container "{\"seccompProfile\":{\"type\":\"Localhost\",\"localhostProfile\":\"operator/default/profile.json\"}}")))
         (profile (gr8s.cri.v1::seccomp (gr8s::containerd-pod-security-context pod (aref (pod-containers pod) 0)))))
    (is (= gr8s.cri.v1::|+PROFILETYPE-Localhost+| (gr8s.cri.v1::profile-type profile)))
    (is (equal "/var/lib/kubelet/seccomp/operator/default/profile.json" (gr8s.cri.v1::localhost-ref profile))))
  (dolist (container '("{\"seccompProfile\":{\"type\":\"Localhost\"}}"
                       "{\"seccompProfile\":{\"type\":\"Localhost\",\"localhostProfile\":\"../escape.json\"}}"
                       "{\"seccompProfile\":{\"type\":\"Localhost\",\"localhostProfile\":\"/abs.json\"}}"
                       "{\"seccompProfile\":{\"type\":\"RuntimeDefault\",\"localhostProfile\":\"x.json\"}}"
                       "{\"seccompProfile\":{\"type\":\"Other\"}}"))
    (signals kubernetes-error (parse-pod (security-context-test-object :container container)))))
