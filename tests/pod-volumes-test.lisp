;;;; SPDX-FileCopyrightText: 2026 gr8s contributors
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Verify resource projection is scoped to assigned Pods, volume paths cannot
;;;; escape the agent directory, and CRI security and environment settings reflect
;;;; the validated Pod rather than merely accepting unsupported fields.

(in-package #:gr8s/tests)
(def-suite pod-volumes :in gr8s)
(in-suite pod-volumes)

(defun volume-test-pod ()
  "Return a Pod using projected data, an emptyDir and downward environment."
  (parse-pod "{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"name\":\"projection\",\"namespace\":\"sonobuoy\"},\"spec\":{\"securityContext\":{\"runAsUser\":1000,\"runAsGroup\":3000,\"fsGroup\":2000},\"serviceAccountName\":\"sonobuoy-serviceaccount\",\"nodeSelector\":{\"kubernetes.io/os\":\"linux\"},\"volumes\":[{\"name\":\"config\",\"configMap\":{\"name\":\"settings\"}},{\"name\":\"secret\",\"secret\":{\"secretName\":\"credentials\",\"items\":[{\"key\":\"binary\",\"path\":\"nested/binary\",\"mode\":256}]}},{\"name\":\"work\",\"emptyDir\":{}}],\"containers\":[{\"name\":\"reader\",\"image\":\"busybox:latest\",\"imagePullPolicy\":\"IfNotPresent\",\"env\":[{\"name\":\"NS\",\"valueFrom\":{\"fieldRef\":{\"fieldPath\":\"metadata.namespace\"}}},{\"name\":\"LITERAL\",\"value\":\"ok\"}],\"volumeMounts\":[{\"name\":\"config\",\"mountPath\":\"/config\"},{\"name\":\"secret\",\"mountPath\":\"/secret\"},{\"name\":\"work\",\"mountPath\":\"/work\"}],\"securityContext\":{\"runAsUser\":1001,\"allowPrivilegeEscalation\":false,\"readOnlyRootFilesystem\":true}}]}}"))

(defun create-volume-test-data (store namespace)
  "Create ConfigMap and Secret fixtures in NAMESPACE."
  (gr8s::create-core-resource store "configmaps"
    (gr8s::core-object "metadata" (gr8s::core-object "name" "settings")
                       "data" (gr8s::core-object "message" "hello projection")) namespace)
  (gr8s::create-core-resource store "secrets"
    (gr8s::core-object "metadata" (gr8s::core-object "name" "credentials")
                       "data" (gr8s::core-object "binary" "AP8=")) namespace))

(test assigned-projections-include-only-referenced-namespace-data
  (with-temporary-store (store directory)
    (create-volume-test-data store "sonobuoy")
    (create-volume-test-data store "other")
    (let* ((pod (create-pod store (volume-test-pod)))
           (assignment (gr8s::pod-assignment pod store))
           (agent-store (open-store (merge-pathnames "agent/" directory))))
      (is (= 2 (length (slot-value assignment 'gr8s.node.v1::resource-objects-json))))
      (gr8s::install-assigned-resource-objects agent-store (list assignment))
      (is (equal "hello projection"
                 (gethash "message" (gethash "data" (gr8s::get-core-resource agent-store "configmaps" "sonobuoy" "settings")))))
      (signals kubernetes-error (gr8s::get-core-resource agent-store "configmaps" "other" "settings"))
      (let ((foreign (gr8s::get-core-resource store "configmaps" "other" "settings")))
        (setf (slot-value assignment 'gr8s.node.v1::resource-objects-json)
              (list (trivial-utf-8:string-to-utf-8-bytes (com.inuoe.jzon:stringify foreign))))
        (signals kubernetes-error (gr8s::install-assigned-resource-objects agent-store (list assignment))))
      (is (= 1 (length (gr8s::list-core-resources agent-store "configmaps"))))
      (gr8s::install-assigned-resource-objects agent-store nil)
      (is (null (gr8s::list-core-resources agent-store "secrets"))))))

(test projected-files-and-emptydir-have-real-mount-content
  (with-temporary-store (store directory)
    (create-volume-test-data store "sonobuoy")
    (let* ((pod (create-pod store (volume-test-pod)))
           (runtime (gr8s::make-containerd-runtime :log-root (merge-pathnames "volumes/" directory)))
           (spec (gethash "spec" (pod-to-object pod))))
      ;; Keep this test runnable as an unprivileged developer. Native coverage
      ;; exercises fsGroup ownership and nonroot container access in the VM.
      (remhash "fsGroup" (gethash "securityContext" spec))
      (setf (gr8s::containerd-runtime-resource-store runtime) store)
      (let* ((mounts (gr8s::containerd-pod-mounts runtime pod (aref (pod-containers pod) 0)))
             (config (first mounts)) (secret (second mounts)) (work (third mounts)))
        (is (= 3 (length mounts)))
        (is (gr8s.cri.v1::readonly config))
        (is (gr8s.cri.v1::readonly secret))
        (is (not (gr8s.cri.v1::readonly work)))
        (is (equal "hello projection" (uiop:read-file-string
                                      (merge-pathnames "message" (gr8s.cri.v1::host-path config)))))
        (is (equalp #(0 255) (gr8s::read-file-octets
                             (merge-pathnames "nested/binary" (gr8s.cri.v1::host-path secret)))))
        (let ((file (merge-pathnames "retained" (gr8s.cri.v1::host-path work))))
          (with-open-file (stream file :direction :output) (write-string "keep" stream))
          (gr8s::containerd-pod-mounts runtime pod (aref (pod-containers pod) 0))
          (is (equal "keep" (uiop:read-file-string file))))))))

(test effective-cri-identity-and-downward-environment-follow-pod-fields
  (let* ((pod (volume-test-pod)) (container (aref (pod-containers pod) 0))
         (context (gr8s::containerd-pod-security-context pod container)))
    (is (= 1001 (gr8s.cri.v1::value (gr8s.cri.v1::run-as-user context))))
    (is (= 3000 (gr8s.cri.v1::value (gr8s.cri.v1::run-as-group context))))
    (is (equal '(2000) (gr8s.cri.v1::supplemental-groups context)))
    (is (gr8s.cri.v1::no-new-privs context))
    (is (gr8s.cri.v1::readonly-rootfs context))
    (is (equal '(("NS" . "sonobuoy") ("LITERAL" . "ok"))
               (gr8s::containerd-pod-environment nil pod container nil)))))

(test invalid-projections-are-rejected-before-runtime-or-filesystem-access
  (dolist (path '("../escape" "/absolute" "nested/../escape" "" "./escape"))
    (is (not (gr8s::safe-volume-relative-path-p path))))
  (let* ((pod (volume-test-pod)) (object (pod-to-object pod))
         (spec (gethash "spec" object))
         (source (gethash "secret" (aref (gethash "volumes" spec) 1))))
    (setf (gethash "path" (aref (gethash "items" source) 0)) "../escape")
    (signals kubernetes-error (parse-pod object)))
  (let* ((object (pod-to-object (volume-test-pod)))
         (spec (gethash "spec" object)))
    (setf (gethash "nodeSelector" spec) (gr8s::core-object "disk" "ssd"))
    (signals kubernetes-error (parse-pod object))))

(test scheduler-honors-supported-node-label-selectors
  (with-temporary-store (store directory)
    (values directory)
    (gr8s:register-node store (gr8s:make-node-record :id "node-a" :name "worker-a" :pod-cidr "10.88.0.0/24"))
    (gr8s:mark-node-ready store "worker-a" (get-universal-time))
    (let* ((object (pod-to-object (volume-test-pod)))
           (spec (gethash "spec" object)))
      (setf (gethash "nodeSelector" spec) (gr8s::core-object "kubernetes.io/os" "windows"))
      (is (null (gr8s::schedule-pod store (create-pod store (parse-pod object)))))
      (setf (gethash "nodeSelector" spec) (gr8s::core-object "kubernetes.io/hostname" "worker-a")
            (gethash "name" (gethash "metadata" object)) "selected")
      (is (equal "worker-a" (gr8s:node-record-name (gr8s::schedule-pod store (create-pod store (parse-pod object)))))))))
