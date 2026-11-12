;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
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

(defun volume-test-pod-named (name)
  "Return a copy of the volume test Pod called NAME."
  (let ((object (pod-to-object (volume-test-pod))))
    (setf (gethash "name" (gethash "metadata" object)) name)
    (parse-pod (com.inuoe.jzon:stringify object))))

(defun create-volume-test-data (store namespace)
  "Create ConfigMap and Secret fixtures in NAMESPACE."
  (gr8s.resources::create-core-resource store "configmaps"
    (gr8s.resources::core-object "metadata" (gr8s.resources::core-object "name" "settings")
                       "data" (gr8s.resources::core-object "message" "hello projection")) namespace)
  (gr8s.resources::create-core-resource store "secrets"
    (gr8s.resources::core-object "metadata" (gr8s.resources::core-object "name" "credentials")
                       "data" (gr8s.resources::core-object "binary" "AP8=")) namespace))

(test assigned-projections-include-only-referenced-namespace-data
  (with-temporary-store (store directory)
    (create-volume-test-data store "sonobuoy")
    (create-volume-test-data store "other")
    (let* ((pod (create-pod store (volume-test-pod)))
           (assignment (gr8s.controllers::pod-assignment pod store))
           (agent-store (open-store (merge-pathnames "agent/" directory))))
      (is (= 2 (length (slot-value assignment 'gr8s.node.v1::resource-objects-json))))
      (gr8s.kubelet::install-assigned-resource-objects agent-store (list assignment))
      (is (equal "hello projection"
                 (gethash "message" (gethash "data" (gr8s.resources::get-core-resource agent-store "configmaps" "sonobuoy" "settings")))))
      (signals kubernetes-error (gr8s.resources::get-core-resource agent-store "configmaps" "other" "settings"))
      (let ((foreign (gr8s.resources::get-core-resource store "configmaps" "other" "settings")))
        (setf (slot-value assignment 'gr8s.node.v1::resource-objects-json)
              (list (trivial-utf-8:string-to-utf-8-bytes (com.inuoe.jzon:stringify foreign))))
        (let ((*error-output* (make-broadcast-stream)))
          (gr8s.kubelet::install-assigned-resource-objects agent-store (list assignment))))
      (signals kubernetes-error (gr8s.resources::get-core-resource agent-store "configmaps" "other" "settings"))
      (gr8s.kubelet::install-assigned-resource-objects agent-store nil)
      (is (null (gr8s.resources::list-core-resources agent-store "secrets"))))))

(test one-pods-bad-resource-object-does-not-stop-the-others
  (with-temporary-store (store directory)
    (create-volume-test-data store "sonobuoy")
    (let* ((good (gr8s.controllers::pod-assignment (create-pod store (volume-test-pod)) store))
           (bad (gr8s.controllers::pod-assignment (create-pod store (volume-test-pod-named "projection-bad")) store))
           (agent-store (open-store (merge-pathnames "agent/" directory))))
      ;; An object the agent would reject on arrival, as a token Secret named after an
      ;; uppercase Pod UID once was.
      (setf (slot-value bad 'gr8s.node.v1::resource-objects-json)
            (list (trivial-utf-8:string-to-utf-8-bytes
                   "{\"kind\":\"Secret\",\"metadata\":{\"namespace\":\"sonobuoy\"}}")))
      (let ((*error-output* (make-broadcast-stream)))
        (finishes (gr8s.kubelet::install-assigned-resource-objects agent-store (list bad good))))
      (is (equal "hello projection"
                 (gethash "message" (gethash "data" (gr8s.resources::get-core-resource agent-store "configmaps" "sonobuoy" "settings"))))))))

(test one-pods-missing-reference-does-not-stop-the-nodes-snapshot
  (with-temporary-store (store directory)
    (create-volume-test-data store "sonobuoy")
    (let ((missing (create-pod store (volume-test-pod-named "projection-missing")))
          (present (create-pod store (volume-test-pod))))
      (gr8s.controllers::persist-pod-assignment store missing "node-a")
      (gr8s.controllers::persist-pod-assignment store present "node-a")
      ;; A namespace being torn down deletes its Secrets before its Pods.
      (gr8s.resources::delete-core-resource store "secrets" "sonobuoy" "credentials")
      (is (= 1 (length (slot-value (gr8s.controllers::pod-assignment missing store) 'gr8s.node.v1::resource-objects-json))))
      (is (= 2 (length (slot-value (gr8s.controllers::node-desired-state-snapshot store "node-a") 'gr8s.node.v1::pods)))))))

(test projected-files-and-emptydir-have-real-mount-content
  (with-temporary-store (store directory)
   ;; Secret/projected volumes are tmpfs-backed in production, which needs root;
   ;; stub the mount so this stays runnable as an unprivileged developer. Files
   ;; still land in the (unmounted) directory, so the content checks hold.
   (with-fake-pod-mounts (mounted options directory)
    (create-volume-test-data store "sonobuoy")
    (let* ((pod (create-pod store (volume-test-pod)))
           (runtime (gr8s.runtime.containerd::make-containerd-runtime :log-root (merge-pathnames "volumes/" directory)))
           (spec (gethash "spec" (pod-to-object pod))))
      ;; Keep this test runnable as an unprivileged developer. Native coverage
      ;; exercises fsGroup ownership and nonroot container access in the VM.
      (remhash "fsGroup" (gethash "securityContext" spec))
      (setf (gr8s.runtime.containerd::containerd-runtime-resource-store runtime) store)
      (let* ((mounts (gr8s.kubelet::containerd-pod-mounts runtime pod (aref (pod-containers pod) 0)))
             (config (first mounts)) (secret (second mounts)) (work (third mounts)))
        (is (= 3 (length mounts)))
        (is (gr8s.cri.v1::readonly config))
        (is (gr8s.cri.v1::readonly secret))
        (is (not (gr8s.cri.v1::readonly work)))
        (is (equal "hello projection" (uiop:read-file-string
                                      (merge-pathnames "message" (gr8s.cri.v1::host-path config)))))
        (is (equalp #(0 255) (gr8s.runtime::read-file-octets
                             (merge-pathnames "nested/binary" (gr8s.cri.v1::host-path secret)))))
        (let ((file (merge-pathnames "retained" (gr8s.cri.v1::host-path work))))
          (with-open-file (stream file :direction :output) (write-string "keep" stream))
          (gr8s.kubelet::containerd-pod-mounts runtime pod (aref (pod-containers pod) 0))
          (is (equal "keep" (uiop:read-file-string file)))))))))

(test effective-cri-identity-and-downward-environment-follow-pod-fields
  (let* ((pod (volume-test-pod)) (container (aref (pod-containers pod) 0))
         (context (gr8s.kubelet::containerd-pod-security-context pod container)))
    (is (= 1001 (gr8s.cri.v1::value (gr8s.cri.v1::run-as-user context))))
    (is (= 3000 (gr8s.cri.v1::value (gr8s.cri.v1::run-as-group context))))
    (is (equal '(2000) (gr8s.cri.v1::supplemental-groups context)))
    (is (gr8s.cri.v1::no-new-privs context))
    (is (gr8s.cri.v1::readonly-rootfs context))
    (is (equal '(("NS" . "sonobuoy") ("LITERAL" . "ok"))
               (gr8s.kubelet::containerd-pod-environment nil pod container nil)))))

(test invalid-projections-are-rejected-before-runtime-or-filesystem-access
  (dolist (path '("../escape" "/absolute" "nested/../escape" "" "./escape"))
    (is (not (gr8s.kubelet::safe-volume-relative-path-p path))))
  (let* ((pod (volume-test-pod)) (object (pod-to-object pod))
         (spec (gethash "spec" object))
         (source (gethash "secret" (aref (gethash "volumes" spec) 1))))
    (setf (gethash "path" (aref (gethash "items" source) 0)) "../escape")
    (signals kubernetes-error (parse-pod object)))
  (let* ((object (pod-to-object (volume-test-pod)))
         (spec (gethash "spec" object)))
    (setf (gethash "nodeSelector" spec) (gr8s.resources::core-object "bad key!" "ssd"))
    (signals kubernetes-error (parse-pod object))))

(test scheduler-honors-node-label-selectors
  (with-temporary-store (store directory)
    (values directory)
    (gr8s.controllers::register-node store (gr8s.model::make-node-record :id "node-a" :name "worker-a" :pod-cidr "10.88.0.0/24"))
    (gr8s.controllers::mark-node-ready store "worker-a" (get-universal-time))
    (let* ((object (pod-to-object (volume-test-pod)))
           (spec (gethash "spec" object)))
      (setf (gethash "nodeSelector" spec) (gr8s.resources::core-object "kubernetes.io/os" "windows"))
      (is (null (gr8s.controllers::schedule-pod store (create-pod store (parse-pod object)))))
      ;; A label no node carries is valid and leaves the Pod pending.
      (setf (gethash "nodeSelector" spec) (gr8s.resources::core-object "x-test.k8s.io/unsatisfiable" "not-schedulable")
            (gethash "name" (gethash "metadata" object)) "unsatisfiable")
      (is (null (gr8s.controllers::schedule-pod store (create-pod store (parse-pod object)))))
      (setf (gethash "nodeSelector" spec) (gr8s.resources::core-object "kubernetes.io/hostname" "worker-a")
            (gethash "name" (gethash "metadata" object)) "selected")
      (is (equal "worker-a" (gr8s.model::node-record-name (gr8s.controllers::schedule-pod store (create-pod store (parse-pod object))))))
      ;; A label written through the API counts exactly like a derived one.
      (remhash "nodeName" spec)
      (setf (gethash "nodeSelector" spec) (gr8s.resources::core-object "disk" "ssd")
            (gethash "name" (gethash "metadata" object)) "needs-disk")
      (let ((pod (create-pod store (parse-pod object))))
        (is (null (gr8s.controllers::schedule-pod store pod)))
        (setf (gr8s.model::node-record-labels (gr8s.controllers::get-node store "worker-a")) (gr8s.resources::core-object "disk" "ssd"))
        (is (equal "worker-a" (gr8s.model::node-record-name (gr8s.controllers::schedule-pod store pod))))))))

(test key-environment-references-project-only-needed-objects-and-omit-optional-values
  (with-temporary-store (store directory)
    (gr8s.resources::create-core-resource store "secrets"
      (gr8s.resources::core-object "metadata" (gr8s.resources::core-object "name" "env-secret")
                         "data" (gr8s.resources::core-object "key" "c2VjcmV0LXZhbHVl")) "sonobuoy")
    (gr8s.resources::create-core-resource store "configmaps"
      (gr8s.resources::core-object "metadata" (gr8s.resources::core-object "name" "env-config")
                         "data" (gr8s.resources::core-object "key" "config-value")) "sonobuoy")
    (let* ((object (com.inuoe.jzon:parse *valid-pod-json*))
           (container (aref (gethash "containers" (gethash "spec" object)) 0))
           (agent-store (open-store (merge-pathnames "agent/" directory)))
           (runtime (gr8s.runtime.containerd::make-containerd-runtime)))
      (setf (gethash "namespace" (gethash "metadata" object)) "sonobuoy"
            (gethash "env" container)
            (vector
             (gr8s.resources::core-object "name" "SECRET" "valueFrom" (gr8s.resources::core-object "secretKeyRef" (gr8s.resources::core-object "name" "env-secret" "key" "key")))
             (gr8s.resources::core-object "name" "CONFIG" "valueFrom" (gr8s.resources::core-object "configMapKeyRef" (gr8s.resources::core-object "name" "env-config" "key" "key")))
             (gr8s.resources::core-object "name" "OPTIONAL_KEY" "valueFrom" (gr8s.resources::core-object "secretKeyRef" (gr8s.resources::core-object "name" "env-secret" "key" "missing" "optional" t)))
             (gr8s.resources::core-object "name" "OPTIONAL_OBJECT" "valueFrom" (gr8s.resources::core-object "secretKeyRef" (gr8s.resources::core-object "name" "missing" "key" "missing" "optional" t)))))
      (let* ((pod (create-pod store (parse-pod object))) (assignment (gr8s.controllers::pod-assignment pod store)))
        (is (= 2 (length (slot-value assignment 'gr8s.node.v1::resource-objects-json))))
        (gr8s.kubelet::install-assigned-resource-objects agent-store (list assignment))
        (setf (gr8s.runtime.containerd::containerd-runtime-resource-store runtime) agent-store)
        (is (equal '(("SECRET" . "secret-value") ("CONFIG" . "config-value"))
                   (gr8s.kubelet::containerd-pod-environment runtime pod (aref (pod-containers pod) 0) nil)))
        (signals gr8s.runtime::runtime-error
          (gr8s.kubelet::containerd-key-environment-value runtime pod "secrets" (gr8s.resources::core-object "name" "env-secret" "key" "missing")))))))

(defun security-profile-test-pod ()
  "Return a Pod shaped like the e2e framework's restricted security mixin output."
  (parse-pod "{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"name\":\"restricted\"},\"spec\":{\"securityContext\":{\"runAsNonRoot\":true,\"runAsUser\":1000,\"fsGroup\":2000,\"supplementalGroups\":[3000,2000],\"seccompProfile\":{\"type\":\"RuntimeDefault\"},\"seLinuxOptions\":{\"level\":\"s0:c1,c2\"}},\"containers\":[{\"name\":\"inherits\",\"image\":\"busybox:latest\",\"securityContext\":{\"allowPrivilegeEscalation\":false,\"capabilities\":{\"drop\":[\"ALL\"],\"add\":[\"NET_BIND_SERVICE\"]}}},{\"name\":\"overrides\",\"image\":\"busybox:latest\",\"securityContext\":{\"seccompProfile\":{\"type\":\"Unconfined\"},\"seLinuxOptions\":{\"type\":\"spc_t\"}}}]}}"))

(test effective-confinement-reaches-the-cri-container-and-sandbox
  (let* ((pod (security-profile-test-pod))
         (inherits (gr8s.kubelet::containerd-pod-security-context pod (aref (pod-containers pod) 0)))
         (overrides (gr8s.kubelet::containerd-pod-security-context pod (aref (pod-containers pod) 1)))
         (sandbox (gr8s.kubelet::containerd-pod-sandbox-security pod)))
    (is (= gr8s.cri.v1::|+PROFILETYPE-RuntimeDefault+|
           (gr8s.cri.v1::profile-type (gr8s.cri.v1::seccomp inherits))))
    (is (= gr8s.cri.v1::|+PROFILETYPE-Unconfined+|
           (gr8s.cri.v1::profile-type (gr8s.cri.v1::seccomp overrides))))
    (is (equal "s0:c1,c2" (gr8s.cri.v1::level (gr8s.cri.v1::selinux-options inherits))))
    ;; seLinuxOptions replaces as a whole rather than merging label components.
    (is (equal "spc_t" (gr8s.cri.v1::proto-se-linux-option-type (gr8s.cri.v1::selinux-options overrides))))
    (is (equal "" (gr8s.cri.v1::level (gr8s.cri.v1::selinux-options overrides))))
    (is (equal '("ALL") (gr8s.cri.v1::drop-capabilities (gr8s.cri.v1::capabilities inherits))))
    (is (equal '("NET_BIND_SERVICE") (gr8s.cri.v1::add-capabilities (gr8s.cri.v1::capabilities inherits))))
    (is (null (gr8s.cri.v1::capabilities overrides)))
    (is (equal '(3000 2000) (gr8s.cri.v1::supplemental-groups inherits)))
    (is (equal '(3000 2000) (getf sandbox :supplemental-groups)))
    (is (= gr8s.cri.v1::|+PROFILETYPE-RuntimeDefault+| (gr8s.cri.v1::profile-type (getf sandbox :seccomp))))
    (is (equal "s0:c1,c2" (gr8s.cri.v1::level (getf sandbox :selinux-options))))))

(test runtime-default-seccomp-survives-the-cri-wire
  ;; RuntimeDefault is enum zero: the profile must still be present on the wire,
  ;; or containerd would silently run the container Unconfined.
  (let* ((pod (security-profile-test-pod))
         (context (gr8s.kubelet::containerd-pod-security-context pod (aref (pod-containers pod) 0)))
         (decoded (ag-proto:deserialize-from-bytes
                   'gr8s.cri.v1::linux-container-security-context
                   (ag-proto:serialize-to-bytes context))))
    (is (not (null (gr8s.cri.v1::seccomp decoded))))
    (is (= gr8s.cri.v1::|+PROFILETYPE-RuntimeDefault+|
           (or (gr8s.cri.v1::profile-type (gr8s.cri.v1::seccomp decoded)) 0)))
    (is (equal '("ALL") (gr8s.cri.v1::drop-capabilities (gr8s.cri.v1::capabilities decoded))))))

(test sandbox-config-carries-pod-confinement
  (let* ((pod (security-profile-test-pod))
         (config (gr8s.runtime.containerd::make-cri-pod-sandbox-config
                  "restricted" "uid" "default" 0 "/tmp/logs" nil
                  :security (gr8s.kubelet::containerd-pod-sandbox-security pod)))
         (context (gr8s.cri.v1::security-context (gr8s.cri.v1::linux config))))
    (is (not (null (gr8s.cri.v1::seccomp context))))
    (is (equal "s0:c1,c2" (gr8s.cri.v1::level (gr8s.cri.v1::selinux-options context))))
    (is (not (null (gr8s.cri.v1::namespace-options context))))))

(test unenforceable-security-and-volume-requests-are-refused
  (flet ((pod-with (spec-json)
           (format nil "{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"name\":\"refused\"},\"spec\":{~A,\"containers\":[{\"name\":\"c\",\"image\":\"busybox:latest\"}]}}" spec-json)))
    (dolist (spec '("\"securityContext\":{\"seccompProfile\":{\"type\":\"Localhost\"}}"
                    "\"securityContext\":{\"seccompProfile\":{}}"
                    "\"securityContext\":{\"seccompProfile\":{\"type\":\"RuntimeDefault\",\"localhostProfile\":\"p\"}}"
                    "\"securityContext\":{\"seLinuxOptions\":{\"level\":7}}"
                    "\"securityContext\":{\"supplementalGroups\":[-1]}"
                    "\"securityContext\":{\"capabilities\":{\"drop\":[\"ALL\"]}}"
                    "\"volumes\":[{\"name\":\"v\",\"emptyDir\":{\"medium\":\"HugePages\"}}]"
                    "\"volumes\":[{\"name\":\"v\",\"emptyDir\":{\"sizeLimit\":\"lots\"}}]"
                    "\"volumes\":[{\"name\":\"v\",\"emptyDir\":{\"medium\":\"Memory\",\"sizeLimit\":\"lots\"}}]"))
      (signals kubernetes-error (parse-pod (pod-with spec))))
    ;; Go clients serialize unset emptyDir fields, so these empty forms stay valid.
    (dolist (spec '("\"volumes\":[{\"name\":\"v\",\"emptyDir\":{\"medium\":\"\"}}]"
                    "\"volumes\":[{\"name\":\"v\",\"emptyDir\":{\"sizeLimit\":\"1Gi\"}}]"
                    "\"volumes\":[{\"name\":\"v\",\"emptyDir\":{\"medium\":\"Memory\",\"sizeLimit\":null}}]"
                    "\"volumes\":[{\"name\":\"v\",\"emptyDir\":{\"medium\":\"\",\"sizeLimit\":\"0\"}}]"
                    "\"securityContext\":{\"seLinuxOptions\":null,\"seccompProfile\":null}"))
      (is (not (null (parse-pod (pod-with spec))))))))

(defun memory-volume-test-pod (&optional (source "{\"medium\":\"Memory\",\"sizeLimit\":\"64Mi\"}"))
  "Return a Pod with one Memory emptyDir built from the JSON SOURCE."
  (parse-pod (format nil "{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"name\":\"memory\",\"uid\":\"memory-uid\"},\"spec\":{\"volumes\":[{\"name\":\"scratch\",\"emptyDir\":~A}],\"containers\":[{\"name\":\"c\",\"image\":\"busybox:latest\",\"volumeMounts\":[{\"name\":\"scratch\",\"mountPath\":\"/scratch\"}]}]}}" source)))

(defmacro with-fake-pod-mounts ((mounted mount-options directory) &body body)
  "Run BODY with tmpfs operations recorded against a fake mountinfo file in DIRECTORY."
  (let ((table (gensym "TABLE")))
    `(let* ((,mounted nil) (,mount-options nil)
            (,table (merge-pathnames "mountinfo" ,directory)))
       (flet ((write-table ()
                (with-open-file (stream ,table :direction :output :if-exists :supersede)
                  (format stream "22 1 0:21 / /proc rw - proc proc rw~%")
                  (dolist (target ,mounted)
                    (format stream "90 1 0:50 / ~A rw - tmpfs gr8s-pod-volume rw~%"
                            (string-right-trim "/" target))))))
         (write-table)
         (let ((gr8s.kubelet::*pod-mount-table-path* ,table)
               (gr8s.kubelet::*pod-tmpfs-mount*
                 (lambda (target requested)
                   (push target ,mounted) (push requested ,mount-options) (write-table) 0))
               (gr8s.kubelet::*pod-tmpfs-unmount*
                 (lambda (target)
                   (setf ,mounted (remove (string-right-trim "/" target) ,mounted :test #'equal
                                          :key (lambda (item) (string-right-trim "/" item))))
                   (write-table) 0)))
           ,@body)))))

(defun memory-volume-object (pod)
  "Return POD's single declared volume object."
  (aref (gethash "volumes" (gethash "spec" (pod-to-object pod))) 0))

(test memory-emptydir-mounts-once-and-keeps-contents-across-container-attempts
  (with-temporary-store (store directory)
    (declare (ignorable store))
    (with-fake-pod-mounts (mounted options directory)
      (let* ((runtime (gr8s.runtime.containerd::make-containerd-runtime :log-root (merge-pathnames "logs/" directory)))
             (pod (memory-volume-test-pod))
             (volume (memory-volume-object pod))
             (path (gr8s.kubelet::materialize-pod-volume runtime pod volume)))
        (is (= 1 (length mounted)))
        (is (equal '("size=67108864") options))
        (is (equal (namestring (truename path)) (first mounted)))
        (is (= #o777 (logand #o777 (sb-posix:stat-mode (sb-posix:stat (namestring path))))))
        (with-open-file (stream (merge-pathnames "kept" path) :direction :output) (write-string "x" stream))
        ;; A restarted container materializes again against the same live tmpfs.
        (gr8s.kubelet::materialize-pod-volume runtime pod volume)
        (is (= 1 (length mounted)))
        (is (probe-file (merge-pathnames "kept" path)))))))

(test unbounded-and-disk-emptydirs-choose-the-right-backing
  (with-temporary-store (store directory)
    (declare (ignorable store))
    (with-fake-pod-mounts (mounted options directory)
      (let ((runtime (gr8s.runtime.containerd::make-containerd-runtime :log-root (merge-pathnames "logs/" directory))))
        (let ((pod (memory-volume-test-pod "{\"medium\":\"\"}")))
          (gr8s.kubelet::materialize-pod-volume runtime pod (memory-volume-object pod))
          (is (null mounted)))
        (let ((pod (memory-volume-test-pod "{\"medium\":\"Memory\"}")))
          (gr8s.kubelet::materialize-pod-volume runtime pod (memory-volume-object pod))
          (is (equal '("") options)))))))

(test pod-termination-unmounts-then-removes-only-volume-data
  (with-temporary-store (store directory)
    (declare (ignorable store))
    (with-fake-pod-mounts (mounted options directory)
      (let* ((runtime (gr8s.runtime.containerd::make-containerd-runtime :log-root (merge-pathnames "logs/" directory)))
             (pod (memory-volume-test-pod))
             (path (gr8s.kubelet::materialize-pod-volume runtime pod (memory-volume-object pod)))
             (pod-directory (gr8s.runtime.containerd::containerd-pod-log-directory runtime (pod-uid pod)))
             (log (merge-pathnames "c.0.log" pod-directory))
             (outside (merge-pathnames "outside" directory)))
        (declare (ignorable options))
        (with-open-file (stream log :direction :output) (write-string "kept" stream))
        (with-open-file (stream outside :direction :output) (write-string "host" stream))
        ;; A container can plant symlinks in its volume; removal must not follow them.
        (sb-posix:symlink (namestring outside) (namestring (merge-pathnames "escape" path)))
        (gr8s.kubelet::cleanup-pod-volumes runtime (pod-uid pod))
        (is (null mounted))
        (is (null (probe-file (merge-pathnames "volumes/" pod-directory))))
        (is (probe-file log))
        (is (equal "host" (uiop:read-file-string outside)))
        ;; Retrying after a crash, or for a Pod that never ran here, is harmless.
        (gr8s.kubelet::cleanup-pod-volumes runtime (pod-uid pod))
        (gr8s.kubelet::cleanup-pod-volumes runtime "never-ran")))))

(test failed-unmount-keeps-volume-data-for-retry
  (with-temporary-store (store directory)
    (declare (ignorable store))
    (with-fake-pod-mounts (mounted options directory)
      (let* ((runtime (gr8s.runtime.containerd::make-containerd-runtime :log-root (merge-pathnames "logs/" directory)))
             (pod (memory-volume-test-pod))
             (path (gr8s.kubelet::materialize-pod-volume runtime pod (memory-volume-object pod))))
        (declare (ignorable options))
        (with-open-file (stream (merge-pathnames "kept" path) :direction :output) (write-string "x" stream))
        (let ((gr8s.kubelet::*pod-tmpfs-unmount* (lambda (target) (declare (ignore target)) -1)))
          (signals gr8s.runtime::runtime-error (gr8s.kubelet::cleanup-pod-volumes runtime (pod-uid pod))))
        (is (probe-file (merge-pathnames "kept" path)))
        (is (= 1 (length mounted)))
        (gr8s.kubelet::cleanup-pod-volumes runtime (pod-uid pod))
        (is (null mounted))
        (is (null (probe-file path)))))))

(test sandbox-replacement-keeps-volumes-but-pod-deletion-removes-them
  (let ((calls nil)
        (runtime (gr8s.runtime.containerd::make-containerd-runtime :log-root "/tmp/gr8s-unused-volume-logs/"))
        (delete-uid (symbol-function 'gr8s.runtime.containerd::containerd-delete-uid))
        (cleanup (symbol-function 'gr8s.kubelet::cleanup-pod-volumes)))
    (unwind-protect
         (progn
           (setf (symbol-function 'gr8s.runtime.containerd::containerd-delete-uid)
                 (lambda (&rest arguments) (declare (ignore arguments)) (push :sandbox calls) nil)
                 (symbol-function 'gr8s.kubelet::cleanup-pod-volumes)
                 (lambda (&rest arguments) (declare (ignore arguments)) (push :volumes calls) nil))
           (gr8s.runtime.containerd::containerd-replace-uid runtime "uid")
           (is (equal '(:sandbox) calls))
           (setf calls nil)
           (gr8s.runtime::runtime-delete runtime "uid")
           ;; Volumes go only after the sandbox can no longer be holding them.
           (is (equal '(:volumes :sandbox) calls)))
      (setf (symbol-function 'gr8s.runtime.containerd::containerd-delete-uid) delete-uid
            (symbol-function 'gr8s.kubelet::cleanup-pod-volumes) cleanup))))

(defun environment-test-pod (container-fields &optional spec-fields)
  "Return an unsaved sonobuoy Pod with extra JSON CONTAINER-FIELDS and SPEC-FIELDS."
  (parse-pod (format nil "{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"name\":\"env\",\"namespace\":\"sonobuoy\"},\"spec\":{~@[~A,~]\"containers\":[{\"name\":\"c\",\"image\":\"busybox:latest\"~@[,~A~]}]}}" spec-fields container-fields)))

(defun environment-test-service (store namespace name address ports-json)
  "Create a Service directly, as the agent's discovery projection provides one."
  (gr8s.resources::create-core-resource
   store "services"
   (com.inuoe.jzon:parse (format nil "{\"apiVersion\":\"v1\",\"kind\":\"Service\",\"metadata\":{\"name\":~S},\"spec\":{\"clusterIP\":~S,\"ports\":~A}}" name address ports-json))
   namespace))

(defmacro with-environment-runtime ((runtime store) &body body)
  "Run BODY with a containerd runtime reading resources from a fresh store."
  (let ((directory (gensym "DIRECTORY")))
    `(with-temporary-store (,store ,directory)
       (create-volume-test-data ,store "sonobuoy")
       (let ((,runtime (gr8s.runtime.containerd::make-containerd-runtime :log-root (merge-pathnames "logs/" ,directory))))
         (setf (gr8s.runtime.containerd::containerd-runtime-resource-store ,runtime) ,store)
         ,@body))))

(defun environment-of (runtime store pod)
  "Return the created POD's resolved variables for its only container."
  (let ((created (create-pod store pod)))
    (gr8s.kubelet::containerd-pod-environment runtime created (aref (pod-containers created) 0) nil)))

(defun environment-value (name environment)
  "Return one variable's value."
  (cdr (assoc name environment :test #'equal)))

(test service-pairs-match-the-kubernetes-names-and-formats
  (let ((pairs (gr8s.kubelet::service-environment-pairs
                (com.inuoe.jzon:parse "{\"metadata\":{\"name\":\"foo-service\"},\"spec\":{\"clusterIP\":\"10.96.0.9\",\"ports\":[{\"name\":\"http-web\",\"port\":8765,\"protocol\":\"TCP\"},{\"port\":53,\"protocol\":\"UDP\"}]}}"))))
    (is (equal "10.96.0.9" (environment-value "FOO_SERVICE_SERVICE_HOST" pairs)))
    (is (equal "8765" (environment-value "FOO_SERVICE_SERVICE_PORT" pairs)))
    (is (equal "8765" (environment-value "FOO_SERVICE_SERVICE_PORT_HTTP_WEB" pairs)))
    (is (equal "tcp://10.96.0.9:8765" (environment-value "FOO_SERVICE_PORT" pairs)))
    (is (equal "tcp://10.96.0.9:8765" (environment-value "FOO_SERVICE_PORT_8765_TCP" pairs)))
    (is (equal "tcp" (environment-value "FOO_SERVICE_PORT_8765_TCP_PROTO" pairs)))
    (is (equal "8765" (environment-value "FOO_SERVICE_PORT_8765_TCP_PORT" pairs)))
    (is (equal "10.96.0.9" (environment-value "FOO_SERVICE_PORT_8765_TCP_ADDR" pairs)))
    (is (equal "udp://10.96.0.9:53" (environment-value "FOO_SERVICE_PORT_53_UDP" pairs))))
  ;; Headless Services have no address to advertise.
  (is (null (gr8s.kubelet::service-environment-pairs
             (com.inuoe.jzon:parse "{\"metadata\":{\"name\":\"h\"},\"spec\":{\"clusterIP\":\"None\",\"ports\":[{\"port\":80}]}}")))))

(test containers-get-services-from-their-namespace-and-the-api-service
  (with-environment-runtime (runtime store)
    (environment-test-service store "sonobuoy" "local" "10.96.1.1" "[{\"port\":80,\"protocol\":\"TCP\"}]")
    (environment-test-service store "other" "foreign" "10.96.1.2" "[{\"port\":81,\"protocol\":\"TCP\"}]")
    (environment-test-service store "default" "kubernetes" "10.96.0.1" "[{\"port\":443,\"protocol\":\"TCP\"}]")
    (environment-test-service store "default" "unrelated" "10.96.1.3" "[{\"port\":82,\"protocol\":\"TCP\"}]")
    (let ((environment (environment-of runtime store (environment-test-pod nil))))
      (is (equal "10.96.1.1" (environment-value "LOCAL_SERVICE_HOST" environment)))
      (is (equal "10.96.0.1" (environment-value "KUBERNETES_SERVICE_HOST" environment)))
      (is (null (environment-value "FOREIGN_SERVICE_HOST" environment)))
      (is (null (environment-value "UNRELATED_SERVICE_HOST" environment))))))

(test disabling-service-links-keeps-only-the-api-service
  (with-environment-runtime (runtime store)
    (environment-test-service store "sonobuoy" "local" "10.96.1.1" "[{\"port\":80,\"protocol\":\"TCP\"}]")
    (environment-test-service store "default" "kubernetes" "10.96.0.1" "[{\"port\":443,\"protocol\":\"TCP\"}]")
    (let ((environment (environment-of runtime store (environment-test-pod nil "\"enableServiceLinks\":false"))))
      (is (null (environment-value "LOCAL_SERVICE_HOST" environment)))
      (is (equal "10.96.0.1" (environment-value "KUBERNETES_SERVICE_HOST" environment))))))

(test env-from-prefixes-keys-and-explicit-env-wins
  (with-environment-runtime (runtime store)
    (gr8s.resources::create-core-resource store "configmaps"
      (gr8s.resources::core-object "metadata" (gr8s.resources::core-object "name" "vars")
                         "data" (gr8s.resources::core-object "shared" "from-config" "only" "c")) "sonobuoy")
    (gr8s.resources::create-core-resource store "secrets"
      (gr8s.resources::core-object "metadata" (gr8s.resources::core-object "name" "sec")
                         "data" (gr8s.resources::core-object "token" "c2VjcmV0")) "sonobuoy")
    (let ((environment
            (environment-of runtime store
              (environment-test-pod "\"envFrom\":[{\"configMapRef\":{\"name\":\"vars\"}},{\"prefix\":\"p_\",\"secretRef\":{\"name\":\"sec\"}}],\"env\":[{\"name\":\"shared\",\"value\":\"explicit\"}]"))))
      (is (equal "explicit" (environment-value "shared" environment)))
      (is (equal "c" (environment-value "only" environment)))
      (is (equal "secret" (environment-value "p_token" environment)))
      (is (= 1 (count "shared" environment :key #'car :test #'equal))))))

(test env-from-optional-and-required-sources
  (with-environment-runtime (runtime store)
    (is (null (environment-value
               "x" (environment-of runtime store
                     (environment-test-pod "\"envFrom\":[{\"configMapRef\":{\"name\":\"absent\",\"optional\":true}}]"))))))
  (with-environment-runtime (runtime store)
    (let ((required (create-pod store (environment-test-pod "\"envFrom\":[{\"secretRef\":{\"name\":\"missing\"}}]"))))
      (signals gr8s.runtime::runtime-error
        (gr8s.kubelet::containerd-pod-environment runtime required (aref (pod-containers required) 0) nil)))))

(test env-from-references-reach-the-agent-including-init-containers
  (let ((declared (gr8s.kubelet::pod-resource-reference-declarations
                   (parse-pod "{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"name\":\"e\"},\"spec\":{\"initContainers\":[{\"name\":\"i\",\"image\":\"b\",\"env\":[{\"name\":\"K\",\"valueFrom\":{\"secretKeyRef\":{\"name\":\"init-sec\",\"key\":\"k\"}}}]}],\"containers\":[{\"name\":\"c\",\"image\":\"b\",\"envFrom\":[{\"configMapRef\":{\"name\":\"cm\",\"optional\":true}},{\"secretRef\":{\"name\":\"sec\"}}]}]}}"))))
    (is (member '("configmaps" "cm" t) declared :test #'equal))
    (is (member '("secrets" "sec" nil) declared :test #'equal))
    (is (member '("secrets" "init-sec" nil) declared :test #'equal))))

(test invalid-env-from-is-refused
  (dolist (fields '("\"envFrom\":[{}]"
                    "\"envFrom\":[{\"configMapRef\":{\"name\":\"a\"},\"secretRef\":{\"name\":\"b\"}}]"
                    "\"envFrom\":[{\"prefix\":\"a=b\",\"configMapRef\":{\"name\":\"a\"}}]"
                    "\"envFrom\":[{\"configMapRef\":{\"name\":\"Not_Valid\"}}]"
                    "\"envFrom\":[{\"configMapRef\":{\"name\":\"a\",\"optional\":\"yes\"}}]"))
    (signals kubernetes-error (environment-test-pod fields))))

;;; Image volumes

(defun image-volume-test-pod (source &optional (mount-fields ""))
  "Return a Pod mounting image volume SOURCE, plus an image volume no container mounts."
  (parse-pod (format nil "{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"name\":\"image-volume\",\"namespace\":\"sonobuoy\",\"uid\":\"image-volume-uid\"},\"spec\":{\"volumes\":[{\"name\":\"data\",\"image\":~A},{\"name\":\"unused\",\"image\":{\"reference\":\"unused:1\"}}],\"containers\":[{\"name\":\"c\",\"image\":\"busybox:1\",\"volumeMounts\":[{\"name\":\"data\",\"mountPath\":\"/data\"~A}]}]}}" source mount-fields)))

(test pods-reject-malformed-image-volumes
  (dolist (source '("{}" "{\"reference\":\"\"}" "{\"reference\":7}"
                    "{\"reference\":\"a:1\",\"pullPolicy\":\"Sometimes\"}"
                    "{\"reference\":\"a:1\",\"other\":1}"))
    (signals kubernetes-error (image-volume-test-pod source)))
  (signals kubernetes-error
    (parse-pod "{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"name\":\"p\"},\"spec\":{\"volumes\":[{\"name\":\"v\",\"image\":{\"reference\":\"a:1\"},\"emptyDir\":{}}],\"containers\":[{\"name\":\"c\",\"image\":\"busybox\"}]}}"))
  (is (not (null (image-volume-test-pod "{\"reference\":\"a:1\",\"pullPolicy\":\"Never\"}")))))

(test image-pull-policies-default-as-kubernetes-does
  (dolist (image '("a" "a:latest" "registry:5000/a" "registry:5000/a:latest"))
    (is (equal "Always" (gr8s.kubelet::default-image-pull-policy image)) "~A" image))
  (dolist (image '("a:1" "registry:5000/a:1" "a@sha256:abc"))
    (is (equal "IfNotPresent" (gr8s.kubelet::default-image-pull-policy image)) "~A" image)))

(test image-volumes-mount-the-pulled-image-read-only
  (let* ((runtime (gr8s.runtime.containerd::make-containerd-runtime :log-root "/nonexistent/"))
         (pod (image-volume-test-pod "{\"reference\":\"a:1\"}"
                                     ",\"subPathExpr\":\"$(DIR)/x\",\"mountPropagation\":\"HostToContainer\""))
         (present nil) (pulls nil))
    (with-replaced-functions ((gr8s.runtime.containerd::cri-image-present-p (lambda (socket image &rest options)
                                                           (declare (ignore socket options))
                                                           (member image present :test #'equal)))
                              (gr8s.runtime.containerd::cri-image-id (lambda (socket image &rest options)
                                                    (declare (ignore socket options))
                                                    (format nil "sha256:~A" image)))
                              (gr8s.runtime.containerd::cri-pull-image (lambda (socket image &rest options)
                                                      (declare (ignore socket options))
                                                      (push image pulls))))
      (flet ((mounts ()
               (gr8s.kubelet::containerd-pod-mounts runtime pod (aref (pod-containers pod) 0) '(("DIR" . "dir")))))
        (signals gr8s.runtime::container-image-pending (mounts))
        (gap-wait-for-pull runtime "a:1")
        (is (equal '("a:1") pulls) "only the mounted image is pulled")
        (setf present '("a:1"))
        (let ((mount (first (mounts))))
          (is (equal "/data" (gr8s.cri.v1::container-path mount)))
          (is (equal "" (gr8s.cri.v1::host-path mount)) "the image and a host path are mutually exclusive")
          (is (equal "sha256:a:1" (gr8s.cri.v1::image (gr8s.cri.v1::image mount))))
          (is (equal "dir/x" (gr8s.cri.v1::image-sub-path mount)))
          (is (eq t (gr8s.cri.v1::readonly mount)) "image volumes are always read-only")
          (is (= gr8s.cri.v1::+mountpropagation-propagation_host_to_container+
                 (gr8s.cri.v1::propagation mount))))))))

(test image-volume-pull-failures-hold-the-container-as-its-own-image-would
  (let* ((runtime (gr8s.runtime.containerd::make-containerd-runtime :log-root "/nonexistent/"))
         (missing (image-volume-test-pod "{\"reference\":\"a:1\",\"pullPolicy\":\"Never\"}"))
         (failing (image-volume-test-pod "{\"reference\":\"b:1\"}"))
         (now 4000000000) (gr8s.kubelet::*container-lifecycle-clock* (lambda () now)))
    (with-replaced-functions ((gr8s.runtime.containerd::cri-image-present-p (constantly nil))
                              (gr8s.runtime.containerd::cri-pull-image (lambda (&rest arguments)
                                                      (declare (ignore arguments))
                                                      (error "registry says no"))))
      (signals gr8s.runtime::container-config-error
        (gr8s.kubelet::containerd-pod-mounts runtime missing (aref (pod-containers missing) 0)))
      (signals gr8s.runtime::container-image-pending
        (gr8s.kubelet::containerd-pod-mounts runtime failing (aref (pod-containers failing) 0)))
      (gap-wait-for-pull runtime "b:1")
      (let ((condition (handler-case (gr8s.kubelet::containerd-pod-mounts runtime failing (aref (pod-containers failing) 0))
                         (gr8s.runtime::container-image-pull-error (condition) condition))))
        (is (equal "ErrImagePull" (gr8s.kubelet::container-config-error-reason condition)))))))

(test secret-volumes-are-backed-by-tmpfs
  ;; Secret / projected / serviceAccountToken bytes must never touch persistent
  ;; disk, so the volume directory is a tmpfs just like an emptyDir{Memory}.
  (with-temporary-store (store directory)
    (with-fake-pod-mounts (mounted options directory)
      (declare (ignorable options))
      (let* ((runtime (gr8s.runtime.containerd::make-containerd-runtime :log-root (merge-pathnames "logs/" directory)))
             (object (com.inuoe.jzon:parse *valid-pod-json*))
             (spec (gethash "spec" object)))
        (setf (gr8s.runtime.containerd::containerd-runtime-resource-store runtime) store)
        (gr8s.resources::create-core-resource store "secrets"
          (gr8s.resources::core-object "metadata" (gr8s.resources::core-object "name" "creds")
            "data" (gr8s.resources::core-object "k" "dg==")) "default")
        (setf (gethash "name" (gethash "metadata" object)) "sec-pod"
              (gethash "namespace" (gethash "metadata" object)) "default"
              (gethash "volumes" spec)
              (vector (gr8s.resources::core-object "name" "s"
                        "secret" (gr8s.resources::core-object "secretName" "creds"))))
        (let* ((pod (parse-pod object))
               (volume (aref (gethash "volumes" (gethash "spec" (pod-to-object pod))) 0))
               (path (gr8s.kubelet::materialize-pod-volume runtime pod volume)))
          (is (member (namestring (truename path)) mounted :test #'equal)))))))

(test fsgroup-volumes-keep-other-access-and-gain-setgid
  ;; The kubelet ORs fsGroup's group bits and setgid into an emptyDir's 0777, giving 02777.
  (with-temporary-store (store directory)
    (declare (ignorable store))
    (let* ((object (com.inuoe.jzon:parse *valid-pod-json*))
           (spec (gethash "spec" object))
           (runtime (gr8s.runtime.containerd::make-containerd-runtime :log-root (merge-pathnames "logs/" directory))))
      (setf (gethash "name" (gethash "metadata" object)) "fsgroup"
            (gethash "securityContext" spec) (gr8s.resources::core-object "fsGroup" (sb-posix:getgid))
            (gethash "volumes" spec) (vector (gr8s.resources::core-object "name" "data" "emptyDir" (gr8s.resources::core-object))))
      (let* ((pod (parse-pod object))
             (path (gr8s.kubelet::materialize-pod-volume runtime pod (aref (gethash "volumes" (gethash "spec" (pod-to-object pod))) 0)))
             (stat (sb-posix:stat (namestring path))))
        (is (= #o2777 (logand #o7777 (sb-posix:stat-mode stat))))
        (is (= (sb-posix:getgid) (sb-posix:stat-gid stat)))
        ;; A tmpfs root starts sticky (1777), and keeps it: 03777.
        (sb-posix:chmod (namestring path) #o1777)
        (gr8s.kubelet::materialize-pod-volume runtime pod (aref (gethash "volumes" (gethash "spec" (pod-to-object pod))) 0))
        (is (= #o3777 (logand #o7777 (sb-posix:stat-mode (sb-posix:stat (namestring path))))))))))

(test managed-emptydirs-use-real-kubelet-paths-and-clean-up-by-uid
  (with-temporary-store (store directory)
    (let* ((pod (create-pod store (parse-pod
                  "{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"name\":\"socket-pod\"},\"spec\":{\"volumes\":[{\"name\":\"sockets\",\"emptyDir\":{}}],\"containers\":[{\"name\":\"main\",\"image\":\"busybox\"}]}}")))
           (root (merge-pathnames "kubelet/" directory))
           (runtime (gr8s.runtime.containerd::make-containerd-runtime :log-root (merge-pathnames "logs/" directory)))
           (gr8s.kubelet::*csi-kubelet-root* (namestring root))
           (expected (merge-pathnames (format nil "pods/~A/volumes/kubernetes.io~~empty-dir/sockets/" (gr8s.model::pod-uid pod)) root))
           (other (merge-pathnames "pods/another-pod/keep" root)))
      (setf (gr8s.runtime.containerd::containerd-runtime-kubelet-root runtime) root)
      (ensure-directories-exist other)
      (with-open-file (out other :direction :output :if-does-not-exist :create) (write-string "keep" out))
      (is (equal expected (gr8s.kubelet::materialize-pod-volume runtime pod (aref (gethash "volumes" (gethash "spec" (pod-to-object pod))) 0))))
      (is (= sb-posix:s-ifdir (logand sb-posix:s-ifmt (sb-posix:stat-mode (sb-posix:lstat expected)))))
      (is (= #o700 (logand #o777 (sb-posix:stat-mode
                                 (sb-posix:stat (merge-pathnames (format nil "pods/~A/" (gr8s.model::pod-uid pod)) root))))))
      (gr8s.kubelet::cleanup-pod-volumes runtime (gr8s.model::pod-uid pod))
      (is-false (probe-file expected))
      (is-true (probe-file other)))))
