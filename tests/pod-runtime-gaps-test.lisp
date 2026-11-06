;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Exercise Pod settings that reach below the container: node namespaces, sysctls,
;;;; hosts aliases, QoS, termination messages, unresolvable container configuration,
;;;; lifecycle hooks, restartable sidecars, ephemeral containers and Node taints,
;;;; through their production functions and the shared deterministic CRI fixture.

(in-package #:gr8s/tests)
(def-suite pod-runtime-gaps :in gr8s)
(in-suite pod-runtime-gaps)

(defun gap-pod-object (&rest spec-fields)
  "Return a valid Pod object with SPEC-FIELDS set in its spec."
  (let* ((object (com.inuoe.jzon:parse *valid-pod-json*)) (spec (gethash "spec" object)))
    (loop for (key value) on spec-fields by #'cddr do (setf (gethash key spec) value))
    object))

(defun gap-container (name &rest fields)
  "Return a container object called NAME with FIELDS set."
  (let ((container (gr8s::core-object "name" name "image" "busybox")))
    (loop for (key value) on fields by #'cddr do (setf (gethash key container) value))
    container))

(defun gap-sysctl-security (&rest names)
  "Return a Pod security context requesting sysctls NAMES, each set to 1."
  (gr8s::core-object "sysctls" (map 'vector (lambda (name) (gr8s::core-object "name" name "value" "1")) names)))

(test scheduler-name-default-and-custom-ones-are-accepted
  ;; Controller-generated specs routinely set schedulerName: default-scheduler,
  ;; which gr8s's scheduler is. As upstream, a Pod may name another scheduler,
  ;; which binds it through pods/binding; gr8s's scheduler leaves it alone.
  (is (gr8s::pod-name (parse-pod (gap-pod-object "schedulerName" "default-scheduler"))))
  (is (not (gr8s::pod-for-this-scheduler-p (parse-pod (gap-pod-object "schedulerName" "custom-scheduler")))))
  ;; topologySpreadConstraints is admitted (unhonored on a single node) rather
  ;; than blocking an otherwise valid Pod.
  (is (gr8s::pod-name
       (parse-pod (gap-pod-object "topologySpreadConstraints"
                                  (vector (gr8s::core-object "maxSkew" 1 "topologyKey" "kubernetes.io/hostname"
                                                             "whenUnsatisfiable" "ScheduleAnyway")))))))

(test fs-group-change-policy-is-accepted
  ;; A standard pod securityContext knob controller-generated StatefulSets set
  ;; (ate's postgres); gr8s applies fsGroup ownership and accepts the policy.
  (is (gr8s::pod-name (parse-pod (gap-pod-object "securityContext"
                                 (gr8s::core-object "fsGroup" 2000 "fsGroupChangePolicy" "OnRootMismatch")))))
  (signals kubernetes-error
    (parse-pod (gap-pod-object "securityContext"
               (gr8s::core-object "fsGroupChangePolicy" "Sometimes")))))

(test run-as-non-root-is-verified-against-the-image-user
  ;; runAsNonRoot with an explicit runAsUser only needs that uid nonzero; without
  ;; one, the image's own user decides -- a non-root image (ko builds run as
  ;; 65532) passes, a root image is refused. This is what let ate's
  ;; podcertcontroller (runAsNonRoot, no runAsUser, image user 65532) run.
  (flet ((ok (user uid name) (finishes (gr8s::verify-run-as-non-root user uid name)))
         (bad (user uid name) (signals gr8s::container-config-error (gr8s::verify-run-as-non-root user uid name))))
    (ok 1000 nil nil)          ; explicit non-root uid
    (bad 0 nil nil)            ; explicit uid 0
    (ok nil 65532 "")          ; image's non-root uid
    (bad nil 0 "")             ; image runs as root uid 0
    (ok nil nil "nonroot")     ; image's non-root username
    (bad nil nil "root")       ; image username root
    (bad nil nil "")))         ; nothing proves non-root

(test sysctl-names-are-validated-together-and-either-separator-means-the-same-variable
  (is (gr8s::pod-name (parse-pod (gap-pod-object "securityContext" (gap-sysctl-security "kernel.shm_rmid_forced")))))
  (let ((message (handler-case
                     (parse-pod (gap-pod-object "securityContext"
                                                (gap-sysctl-security "foo-" "kernel.shmmax" "safe-and-unsafe" "bar..")))
                   (kubernetes-error (condition) (gr8s::kubernetes-error-message condition)))))
    (is (search "Invalid value: \"foo-\"" message))
    (is (search "Invalid value: \"bar..\"" message))
    (is (not (search "safe-and-unsafe" message)))
    (is (not (search "kernel.shmmax" message))))
  (is (equal "kernel.shm_rmid_forced" (gr8s::canonical-sysctl-name "kernel/shm_rmid_forced")))
  (is (equal "kernel.shm_rmid_forced" (gr8s::canonical-sysctl-name "kernel.shm_rmid_forced")))
  (signals kubernetes-error
    (parse-pod (gap-pod-object "securityContext" (gap-sysctl-security "kernel.shm_rmid_forced" "kernel/shm_rmid_forced")))))

(test nodes-refuse-sysctls-beyond-the-safe-set
  (flet ((failure (&rest options)
           (gr8s::pod-forbidden-sysctl-failure (parse-pod (apply #'gap-pod-object options)))))
    (is (null (failure "securityContext" (gap-sysctl-security "kernel.shm_rmid_forced"))))
    (is (equal "SysctlForbidden" (cdr (failure "securityContext" (gap-sysctl-security "kernel.msgmax")))))
    (is (null (failure "securityContext" (gap-sysctl-security "net.ipv4.tcp_syncookies"))))
    (is (equal "SysctlForbidden" (cdr (failure "hostNetwork" t "securityContext" (gap-sysctl-security "net.ipv4.tcp_syncookies")))))))

(test sandbox-config-carries-sysctls-and-node-namespaces
  (let* ((config (gr8s::make-cri-pod-sandbox-config
                  "pod" "uid" "ns" 0 "/logs" t :sysctls '(("kernel.shm_rmid_forced" . "1"))
                  :pid-mode gr8s.cri.v1::+namespacemode-node+))
         (linux (gr8s.cri.v1::linux config))
         (options (gr8s.cri.v1::namespace-options (gr8s.cri.v1::security-context linux))))
    (is (equal '(("kernel.shm_rmid_forced" . "1")) (gr8s.cri.v1::sysctls linux)))
    (is (= gr8s.cri.v1::+namespacemode-node+ (slot-value options 'gr8s.cri.v1::network)))
    (is (= gr8s.cri.v1::+namespacemode-node+ (slot-value options 'gr8s.cri.v1::pid)))
    (is (= gr8s.cri.v1::+namespacemode-pod+ (slot-value options 'gr8s.cri.v1::ipc)))
    (is (assoc gr8s::+gr8s-host-network-label+ (gr8s.cri.v1::labels config) :test #'equal))))

(test host-aliases-extend-the-managed-hosts-file
  (let ((pod (parse-pod (gap-pod-object "hostAliases"
                                        (vector (gr8s::core-object "ip" "123.45.67.89" "hostnames" #("foo" "bar")))))))
    (setf (gr8s::pod-uid pod) "uid")
    (is (search (format nil "123.45.67.89~Cfoo~Cbar~%" #\Tab #\Tab)
                (gr8s::pod-managed-hosts-content pod "10.0.0.1"))))
  (signals kubernetes-error
    (parse-pod (gap-pod-object "hostAliases" (vector (gr8s::core-object "ip" "not-an-ip" "hostnames" #("foo")))))))

(test host-network-containers-publish-their-ports-on-the-host
  (let* ((pod (parse-pod (gap-pod-object "hostNetwork" t
                                         "containers" (vector (gap-container "web" "ports" (vector (gr8s::core-object "containerPort" 8080)))))))
         (port (aref (gethash "ports" (aref (gethash "containers" (gethash "spec" (pod-to-object pod))) 0)) 0)))
    (is (= 8080 (gethash "hostPort" port)))
    (is (gr8s::pod-host-network-p pod)))
  (signals kubernetes-error
    (parse-pod (gap-pod-object "hostNetwork" t
                               "containers" (vector (gap-container "web" "ports" (vector (gr8s::core-object "containerPort" 8080 "hostPort" 81))))))))

(test pod-os-accepts-only-the-operating-system-nodes-run
  (is (gr8s::pod-name (parse-pod (gap-pod-object "os" (gr8s::core-object "name" "linux")))))
  (signals kubernetes-error (parse-pod (gap-pod-object "os" (gr8s::core-object "name" "windows")))))

(test qos-class-follows-cpu-and-memory-requests-and-limits
  (flet ((qos (&optional resources)
           (let ((container (gap-container "c")))
             (when resources (setf (gethash "resources" container) resources))
             (gr8s::pod-spec-qos-class
              (gethash "spec" (pod-to-object (parse-pod (gap-pod-object "containers" (vector container)))))))))
    (is (equal "BestEffort" (qos)))
    (is (equal "Burstable" (qos (gr8s::core-object "requests" (gr8s::core-object "cpu" "100m")))))
    (is (equal "Burstable" (qos (gr8s::core-object "limits" (gr8s::core-object "cpu" "100m")))))
    (is (equal "Guaranteed" (qos (gr8s::core-object "limits" (gr8s::core-object "cpu" "100m" "memory" "100Mi")))))
    (is (equal "Guaranteed" (qos (gr8s::core-object "limits" (gr8s::core-object "cpu" "100m" "memory" "100Mi")
                                                    "requests" (gr8s::core-object "cpu" "100m" "memory" "100Mi")))))
    (is (equal "Burstable" (qos (gr8s::core-object "limits" (gr8s::core-object "cpu" "200m" "memory" "100Mi")
                                                   "requests" (gr8s::core-object "cpu" "100m" "memory" "100Mi")))))))

(defun gap-exited-info (&key (exit-code 0) file policy log)
  "Build an exited attempt whose labels name its termination FILE and POLICY."
  (let ((info (lifecycle-info "main" 0 gr8s.cri.v1::+containerstate-container_exited+ 4000000000 exit-code)))
    (setf (gr8s::cri-container-info-log-path info) log
          (gr8s::cri-container-info-labels info)
          (append (when file (list (cons gr8s::+gr8s-termination-file-label+ (namestring file))))
                  (when policy (list (cons gr8s::+gr8s-termination-policy-label+ policy)))))
    info))

(test termination-messages-come-from-the-file-then-the-log-tail-on-failure
  (uiop:with-temporary-file (:pathname file :keep nil)
    (uiop:with-temporary-file (:pathname log :keep nil)
      (with-open-file (out log :direction :output :if-exists :supersede)
        (format out "2026-01-01T00:00:00.000000000Z stdout F from the log~%"))
      (flet ((message (&rest options) (gr8s::container-termination-message (apply #'gap-exited-info :file file options))))
        (is (null (message :policy "File")))
        (is (null (message :policy "FallbackToLogsOnError" :log log)) "a success does not fall back")
        (is (null (message :policy "File" :exit-code 1 :log log)))
        (is (search "from the log" (message :policy "FallbackToLogsOnError" :exit-code 1 :log log)))
        (with-open-file (out file :direction :output :if-exists :supersede) (write-string "DONE" out))
        (is (equal "DONE" (message :policy "FallbackToLogsOnError" :exit-code 1 :log log)) "the file wins")
        (is (equal "DONE" (gethash "message" (gethash "terminated" (gethash "state"
              (gr8s::containerd-container-status-object (gap-exited-info :file file :policy "File")))))))))))

(test sub-path-expressions-that-expand-outside-the-volume-are-configuration-errors
  (flet ((expand (value)
           (gr8s::container-mount-subpath (gr8s::core-object "subPathExpr" "$(POD_NAME)") (list (cons "POD_NAME" value)))))
    (is (equal "safe/dir" (expand "safe/dir")))
    (signals gr8s::container-config-error (expand ".."))
    (signals gr8s::container-config-error (expand "/tmp"))
    (signals gr8s::container-config-error (expand ""))))

(test unresolvable-configuration-reports-a-waiting-container-and-spares-its-siblings
  (with-temporary-store (store directory)
    (let* ((now 4000000000) (gr8s::*container-lifecycle-clock* (lambda () now))
           (pod (lifecycle-pod store "Never"))
           (runtime (gr8s::make-containerd-runtime :log-root directory)))
      (with-lifecycle-cri (fixture pod nil)
        (let ((create (symbol-function 'gr8s::containerd-create-container)))
          (setf (symbol-function 'gr8s::containerd-create-container)
                (lambda (runtime desired sandbox config spec &key (attempt 0))
                  (when (equal "side" (container-spec-name spec))
                    (gr8s::container-config-error "bad subPath"))
                  (funcall create runtime desired sandbox config spec :attempt attempt))))
        (let* ((observed (gr8s::runtime-ensure runtime pod))
               (statuses (gethash "containerStatuses" (gr8s::runtime-pod-status observed)))
               (side (find "side" statuses :test #'equal :key (lambda (item) (gethash "name" item)))))
          (is (equal '((:create "main" 0 "same-sandbox")) (lifecycle-cri-fixture-calls fixture)))
          (is (equal "CreateContainerConfigError"
                     (gethash "reason" (gethash "waiting" (gethash "state" side)))))
          (is (equal "bad subPath" (gethash "message" (gethash "waiting" (gethash "state" side)))))
          (is (eql 0 (gethash "restartCount" side))))))))

(test lifecycle-handlers-need-one-supported-action
  (flet ((pod-with (lifecycle)
           (parse-pod (gap-pod-object "containers" (vector (gap-container "c" "lifecycle" lifecycle))))))
    (is (gr8s::pod-name (pod-with (gr8s::core-object
                                   "postStart" (gr8s::core-object "exec" (gr8s::core-object "command" #("true")))
                                   "preStop" (gr8s::core-object "httpGet" (gr8s::core-object "port" 80))))))
    (is (gr8s::pod-name (pod-with (gr8s::core-object "preStop" (gr8s::core-object "sleep" (gr8s::core-object "seconds" 1))))))
    (signals kubernetes-error (pod-with (gr8s::core-object "postStart" (gr8s::core-object))))
    (signals kubernetes-error (pod-with (gr8s::core-object "postStart" (gr8s::core-object "tcpSocket" (gr8s::core-object "port" 80)))))))

(test init-containers-may-only-be-restartable-sidecars
  (is (gr8s::pod-name
       (parse-pod (gap-pod-object "initContainers"
                                  (vector (gap-container "side" "restartPolicy" "Always"
                                                         "startupProbe" (gr8s::core-object "exec" (gr8s::core-object "command" #("true")))))))))
  (signals kubernetes-error
    (parse-pod (gap-pod-object "initContainers"
                               (vector (gap-container "plain" "lifecycle" (gr8s::core-object))))))
  (signals kubernetes-error
    (parse-pod (gap-pod-object "initContainers"
                               (vector (gap-container "plain" "startupProbe" (gr8s::core-object "exec" (gr8s::core-object "command" #("true"))))))))
  (signals kubernetes-error
    (parse-pod (gap-pod-object "initContainers" (vector (gap-container "plain" "restartPolicy" "OnFailure")))))
  (signals kubernetes-error
    (parse-pod (gap-pod-object "containers" (vector (gap-container "app" "restartPolicy" "Always"))))))

(defun gap-sidecar-pod (store &optional (policy "Always"))
  "Create a Pod: sidecar, ordinary init container, then one application."
  (create-pod store
              (parse-pod (gap-pod-object "restartPolicy" policy
                                         "initContainers" (vector (gap-container "side" "restartPolicy" "Always")
                                                                  (gap-container "setup"))
                                         "containers" (vector (gap-container "app"))))))

(test sidecars-start-first-and-keep-running-beside-later-containers
  (with-temporary-store (store directory)
    (let* ((now 4000000000) (gr8s::*container-lifecycle-clock* (lambda () now))
           (pod (gap-sidecar-pod store)) (runtime (gr8s::make-containerd-runtime :log-root directory)))
      (with-lifecycle-cri (fixture pod nil)
        (let ((observed (gr8s::runtime-ensure runtime pod)))
          (is (equal '((:create "side" 0 "same-sandbox")) (lifecycle-cri-fixture-calls fixture)))
          (is (equal "Pending" (gr8s::runtime-pod-phase observed))))
        ;; The running sidecar admits the next init container, still before the application.
        (setf (lifecycle-cri-fixture-calls fixture) nil)
        (gr8s::runtime-ensure runtime pod)
        (is (equal '((:create "setup" 0 "same-sandbox")) (lifecycle-cri-fixture-calls fixture)))
        (setf (lifecycle-cri-fixture-calls fixture) nil)
        (let ((setup (find "setup-0" (lifecycle-cri-fixture-infos fixture) :key #'gr8s::cri-container-info-id :test #'equal)))
          (setf (gr8s::cri-container-info-state setup) gr8s.cri.v1::+containerstate-container_exited+
                (gr8s::cri-container-info-exit-code setup) 0))
        (let ((observed (gr8s::runtime-ensure runtime pod)))
          (is (equal '((:create "app" 0 "same-sandbox")) (lifecycle-cri-fixture-calls fixture)))
          (is (gr8s::pod-initialization-complete-p pod (gr8s::runtime-pod-status observed)))
          (is (equal "Running" (gr8s::runtime-pod-phase observed)))
          (let ((inits (gethash "initContainerStatuses" (gr8s::runtime-pod-status observed))))
            (is (equal '("side" "setup") (map 'list (lambda (item) (gethash "name" item)) inits)))
            (is (eq t (gethash "ready" (aref inits 0))) "a started sidecar counts as ready")))))))

(test a-crashed-sidecar-restarts-under-any-pod-restart-policy
  (with-temporary-store (store directory)
    (let* ((now 4000000000) (gr8s::*container-lifecycle-clock* (lambda () now))
           (pod (gap-sidecar-pod store "Never")))
      (is (equal "Always" (gr8s::container-effective-restart-policy pod "side")))
      (is (equal "Never" (gr8s::container-effective-restart-policy pod "setup")))
      (is (equal "Never" (gr8s::container-effective-restart-policy pod "app"))))))

(defun runtime-observe-with-declarations (runtime pod)
  "Observe POD after checkpointing its init declarations, as convergence does."
  (let ((state (gr8s::load-container-lifecycle-state runtime (pod-uid pod))))
    (gr8s::remember-init-container-declarations state pod)
    (gr8s::save-container-lifecycle-state runtime (pod-uid pod) state))
  (runtime-observe runtime (pod-uid pod)))

(test finished-applications-end-the-pod-only-after-its-sidecars-stop
  (with-temporary-store (store directory)
    (let* ((now 4000000000) (gr8s::*container-lifecycle-clock* (lambda () now))
           (pod (gap-sidecar-pod store "Never")) (runtime (gr8s::make-containerd-runtime :log-root directory)))
      (with-lifecycle-cri (fixture pod
                           (list (lifecycle-info "side" 0 gr8s.cri.v1::+containerstate-container_running+ now)
                                 (lifecycle-info "setup" 0 gr8s.cri.v1::+containerstate-container_exited+ now)
                                 (lifecycle-info "app" 0 gr8s.cri.v1::+containerstate-container_exited+ now)))
        ;; While the sidecar runs the Pod is unfinished, whatever its applications did.
        (is (equal "Running" (gr8s::runtime-pod-phase (runtime-observe-with-declarations runtime pod))))
        (gr8s::runtime-ensure runtime pod)
        (is (null (remove :stop (lifecycle-cri-fixture-calls fixture) :key #'first)) "nothing starts again")
        ;; The shutdown runs outside reconciliation; wait for it to take effect.
        (loop repeat 100 until (find "side-0" (lifecycle-cri-fixture-calls fixture) :key #'second :test #'equal)
              do (sleep 0.05))
        (is (find "side-0" (lifecycle-cri-fixture-calls fixture) :key #'second :test #'equal))
        (loop repeat 100 while (gr8s::container-hook-manager-busy-p runtime) do (sleep 0.05))
        (is (equal "Succeeded" (gr8s::runtime-pod-phase (runtime-observe runtime (pod-uid pod)))))))))

(test deletion-stops-applications-before-sidecars-and-runs-pre-stop-hooks
  (with-temporary-store (store directory)
    (let* ((now 4000000000) (gr8s::*container-lifecycle-clock* (lambda () now))
           (pod (create-pod store
                            (parse-pod (gap-pod-object
                                        "initContainers" (vector (gap-container "first" "restartPolicy" "Always")
                                                                 (gap-container "second" "restartPolicy" "Always"))
                                        "containers" (vector (gap-container
                                                              "app" "lifecycle"
                                                              (gr8s::core-object
                                                               "preStop" (gr8s::core-object
                                                                          "exec" (gr8s::core-object "command" #("hook"))))))))))
           (runtime (gr8s::make-containerd-runtime :log-root directory))
           (exec-calls nil)
           (exec (symbol-function 'gr8s::cri-exec-sync)))
      (with-lifecycle-cri (fixture pod
                           (list (lifecycle-info "first" 0 gr8s.cri.v1::+containerstate-container_running+ now)
                                 (lifecycle-info "second" 0 gr8s.cri.v1::+containerstate-container_running+ now)
                                 (lifecycle-info "app" 0 gr8s.cri.v1::+containerstate-container_running+ now)))
        (unwind-protect
             (progn
               (setf (symbol-function 'gr8s::cri-exec-sync)
                     (lambda (socket id command &rest options)
                       (declare (ignore socket options))
                       (push (list id command) exec-calls)
                       (gr8s::make-runtime-exec-result)))
               (gr8s::stop-pod-containers-in-order runtime pod (+ (funcall gr8s::*pod-deletion-clock*) 30)))
          (setf (symbol-function 'gr8s::cri-exec-sync) exec))
        (is (equal '(("app-0" ("hook"))) exec-calls))
        (is (equal '("app-0" "second-0" "first-0")
                   (reverse (loop for call in (lifecycle-cri-fixture-calls fixture)
                                  when (eq :stop (first call)) collect (second call)))))))))

(test post-start-hooks-hold-back-the-container-until-they-finish
  (with-temporary-store (store directory)
    (let* ((now 4000000000) (gr8s::*container-lifecycle-clock* (lambda () now))
           (runtime (gr8s::make-containerd-runtime :log-root directory))
           (manager (gr8s::containerd-runtime-hooks runtime))
           (info (lifecycle-info "main" 0 gr8s.cri.v1::+containerstate-container_running+ now)))
      (declare (ignorable store))
      (is (= gr8s.cri.v1::+containerstate-container_running+
             (gr8s::cri-container-info-state (first (gr8s::mask-post-start-containers runtime (list info))))))
      (setf (gethash "main-0" (gr8s::container-hook-manager-jobs manager))
            (gr8s::make-container-hook-job :uid "uid" :container-id "main-0"))
      (is (gr8s::pod-post-start-pending-p runtime "uid"))
      (is (not (gr8s::pod-post-start-pending-p runtime "other")))
      (let ((masked (first (gr8s::mask-post-start-containers runtime (list info)))))
        (is (= gr8s.cri.v1::+containerstate-container_created+ (gr8s::cri-container-info-state masked)))
        (is (= gr8s.cri.v1::+containerstate-container_running+ (gr8s::cri-container-info-state info)) "CRI truth is untouched")
        (is (null (gethash "running" (gethash "state" (gr8s::containerd-container-status-object masked)))))))))

(test ephemeral-containers-may-only-be-added
  (let* ((debugger (gap-container "debugger" "tty" t "stdin" t))
         (base (gap-pod-object))
         (added (gap-pod-object "ephemeralContainers" (vector debugger))))
    (let ((before (parse-pod base)) (after (parse-pod added)))
      (is (= 1 (length (gr8s::pod-ephemeral-containers after))))
      (is (find "debugger" (gr8s::pod-all-containers after) :key #'container-spec-name :test #'equal))
      (is (null (gr8s::validate-pod-ephemeral-update before after)))
      (signals kubernetes-error (gr8s::validate-pod-ephemeral-update after before))
      (let ((typed (parse-pod (gap-pod-object "ephemeralContainers"
                                              (vector (gap-container "debugger" "tty" t "stdin" t "workingDir" nil
                                                                     "env" #() "resources" (gr8s::core-object)))))))
        (remhash "workingDir" (aref (gethash "ephemeralContainers" (gethash "spec" (pod-to-object typed))) 0))
        (is (null (gr8s::validate-pod-ephemeral-update after typed)) "unset fields do not count as changes"))
      (let ((changed (parse-pod (gap-pod-object "ephemeralContainers" (vector (gap-container "debugger" "image" "other"))))))
        (signals kubernetes-error (gr8s::validate-pod-ephemeral-update after changed)))
      (is (equal (gr8s::pod-runtime-spec-fingerprint before) (gr8s::pod-runtime-spec-fingerprint after))
          "adding one must not restart the workload")))
  (dolist (field '("ports" "livenessProbe" "lifecycle"))
    (signals kubernetes-error
      (parse-pod (gap-pod-object "ephemeralContainers" (vector (gap-container "debugger" field #()))))))
  (signals kubernetes-error
    (parse-pod (gap-pod-object "ephemeralContainers" (vector (gap-container "debugger" "targetContainerName" "nobody"))))))

(test ordinary-updates-keep-the-stored-ephemeral-containers
  (with-temporary-store (store directory)
    (declare (ignorable directory))
    (let* ((pod (create-pod store (parse-pod (gap-pod-object))))
           (object (gr8s::copy-json-object (pod-to-object pod))))
      (setf (gethash "ephemeralContainers" (gethash "spec" object)) (vector (gap-container "debugger")))
      (let ((added (let ((gr8s::*pod-ephemeral-update* t))
                     (update-pod store (parse-pod (gr8s::copy-json-object object)) (pod-resource-version pod)))))
        (is (= 2 (gethash "generation" (gethash "metadata" (pod-to-object added)))))
        (let ((plain (gr8s::copy-json-object (pod-to-object pod))))
          (setf (gethash "resourceVersion" (gethash "metadata" plain)) (pod-resource-version added))
          (let ((updated (update-pod store (parse-pod plain) (pod-resource-version added))))
            (is (= 1 (length (gethash "ephemeralContainers" (gethash "spec" (pod-to-object updated))))))))))))

(test ephemeral-statuses-stay-apart-from-the-workload
  (let ((state (gr8s::core-object "ephemeralNames" #("debugger")))
        (statuses (vector (gr8s::core-object "name" "app") (gr8s::core-object "name" "debugger"))))
    (multiple-value-bind (workload ephemeral) (gr8s::separate-ephemeral-statuses statuses state)
      (is (equal '("app") (map 'list (lambda (item) (gethash "name" item)) workload)))
      (is (equal '("debugger") (map 'list (lambda (item) (gethash "name" item)) ephemeral))))))

(defun gap-node (&rest taints)
  "Return a node record carrying TAINTS as (key effect) lists."
  (gr8s::make-node-record
   :id "id" :name "node" :pod-cidr "10.80.0.0/20" :ready-p t
   :taints (map 'vector (lambda (taint)
                          (gr8s::core-object "key" (first taint) "effect" (second taint) "value" "v"))
                taints)))

(defun gap-toleration (&rest fields)
  "Return a toleration object from FIELDS."
  (apply #'gr8s::core-object fields))

(test tolerations-match-taints-as-kubernetes-defines
  (let ((taint (gr8s::core-object "key" "k" "value" "v" "effect" "NoExecute")))
    (is (gr8s::toleration-matches-taint-p (gap-toleration "key" "k" "value" "v" "effect" "NoExecute") taint))
    (is (gr8s::toleration-matches-taint-p (gap-toleration "key" "k" "value" "v") taint) "an empty effect matches all")
    (is (gr8s::toleration-matches-taint-p (gap-toleration "key" "k" "operator" "Exists") taint))
    (is (gr8s::toleration-matches-taint-p (gap-toleration "operator" "Exists") taint) "an empty key with Exists matches all")
    (is (not (gr8s::toleration-matches-taint-p (gap-toleration "key" "k" "value" "other") taint)))
    (is (not (gr8s::toleration-matches-taint-p (gap-toleration "key" "other" "operator" "Exists") taint)))
    (is (not (gr8s::toleration-matches-taint-p (gap-toleration "key" "k" "operator" "Exists" "effect" "NoSchedule") taint)))))

(test the-scheduler-refuses-untolerated-taints-and-cordoned-nodes
  (let ((plain (gr8s::make-pod :object (gr8s::core-object "spec" (gr8s::core-object))))
        (tolerant (gr8s::make-pod :object (gr8s::core-object "spec" (gr8s::core-object
                                                               "tolerations" (vector (gap-toleration "operator" "Exists")))))))
    (is (gr8s::pod-node-taints-allow-p plain (gap-node)))
    (is (not (gr8s::pod-node-taints-allow-p plain (gap-node '("k" "NoSchedule")))))
    (is (not (gr8s::pod-node-taints-allow-p plain (gap-node '("k" "NoExecute")))))
    (is (gr8s::pod-node-taints-allow-p plain (gap-node '("k" "PreferNoSchedule"))))
    (is (gr8s::pod-node-taints-allow-p tolerant (gap-node '("k" "NoSchedule"))))
    (let ((cordoned (gap-node)))
      (setf (gr8s::node-record-unschedulable cordoned) t)
      (is (not (gr8s::pod-node-taints-allow-p tolerant cordoned))))))

(test no-execute-toleration-seconds-take-the-tightest-limit
  (flet ((seconds (node &rest tolerations)
           (gr8s::pod-no-execute-toleration-seconds
            (gr8s::core-object "tolerations" (coerce tolerations 'vector)) node)))
    (let ((node (gap-node '("k" "NoExecute"))))
      (is (eql 0 (seconds node)) "no toleration means at once")
      (is (null (seconds node (gap-toleration "key" "k" "value" "v"))) "no limit means forever")
      (is (eql 5 (seconds node (gap-toleration "key" "k" "value" "v" "tolerationSeconds" 5))))
      (is (eql 0 (seconds node (gap-toleration "key" "k" "value" "v" "tolerationSeconds" -1))))
      (is (eql 5 (seconds node (gap-toleration "key" "k" "value" "v" "tolerationSeconds" 9)
                          (gap-toleration "key" "k" "operator" "Exists" "tolerationSeconds" 5)))))
    (is (null (seconds (gap-node '("k" "NoSchedule")))) "only NoExecute evicts")))

(test node-taint-evictions-wait-for-the-toleration-and-removing-the-taint-cancels-them
  (with-temporary-store (store directory)
    (declare (ignorable directory))
    (let* ((runtime (gr8s::make-fake-runtime))
           (reconciler (gr8s::make-reconciler store runtime))
           (node (gr8s::register-node store (gap-node)))
           (pod (create-pod store (parse-pod (gap-pod-object
                                              "nodeName" "node"
                                              "tolerations" (vector (gap-toleration "key" "k" "value" "v" "tolerationSeconds" 10)))))))
      (setf (gr8s::node-record-taints node)
            (vector (gr8s::core-object "key" "k" "value" "v" "effect" "NoExecute")))
      (gr8s::reconcile-node-taint-evictions reconciler 1000)
      (gr8s::reconcile-node-taint-evictions reconciler 1005)
      (is (not (gr8s::deletion-requested-p (gr8s::get-pod store (pod-namespace pod) (pod-name pod)))))
      ;; A removed taint forgets the timer, so a new taint starts counting afresh.
      (setf (gr8s::node-record-taints node) #())
      (gr8s::reconcile-node-taint-evictions reconciler 1006)
      (is (zerop (hash-table-count (gr8s::reconciler-taint-timers reconciler))))
      (setf (gr8s::node-record-taints node)
            (vector (gr8s::core-object "key" "k" "value" "v" "effect" "NoExecute")))
      (gr8s::reconcile-node-taint-evictions reconciler 1011)
      (is (not (gr8s::deletion-requested-p (gr8s::get-pod store (pod-namespace pod) (pod-name pod)))))
      (gr8s::reconcile-node-taint-evictions reconciler 1021)
      (let ((evicted (handler-case (gr8s::deletion-requested-p (gr8s::get-pod store (pod-namespace pod) (pod-name pod)))
                       (kubernetes-error () t))))
        (is-true evicted "the toleration has run out")))))

(test nodes-can-be-created-labelled-tainted-and-deleted-through-the-api
  (with-core-api (store path)
    (values store path)
    (let* ((body (gr8s::core-object "apiVersion" "v1" "kind" "Node" "metadata" (gr8s::core-object "name" "fake")
                                    "spec" (gr8s::core-object "unschedulable" t)
                                    "status" (gr8s::core-object
                                              "phase" "Running"
                                              "conditions" (vector (gr8s::core-object "type" "Ready" "status" "True")))))
           (created (check-core-status 201 "/api/v1/nodes" :method :post
                                       :object body))
           (version (parse-integer (gethash "resourceVersion" (gethash "metadata" created)))))
      (is (eq t (gethash "unschedulable" (gethash "spec" created))))
      (is (equal "True" (gethash "status" (aref (gethash "conditions" (gethash "status" created)) 0))))
      (is (not (gr8s::node-record-ready-p (gr8s::get-node store "fake"))) "no agent means it cannot run Pods")
      (check-core-status 409 "/api/v1/nodes" :method :post :object body)
      (let ((patched (check-core-status 200 "/api/v1/nodes/fake" :method :patch
                                        :content-type "application/strategic-merge-patch+json"
                                        :octets "{\"metadata\":{\"labels\":{\"fake\":\"patched\"}},\"spec\":{\"taints\":[{\"key\":\"k\",\"effect\":\"NoExecute\"}]}}")))
        (is (> (parse-integer (gethash "resourceVersion" (gethash "metadata" patched))) version))
        (is (equal "patched" (gethash "fake" (gethash "labels" (gethash "metadata" patched)))))
        (is (stringp (gethash "timeAdded" (aref (gethash "taints" (gethash "spec" patched)) 0)))))
      (is (= 1 (length (gethash "items" (check-core-status 200 "/api/v1/nodes" :parameters '(("labelSelector" . "fake=patched")))))))
      (let ((cleared (check-core-status 200 "/api/v1/nodes/fake" :method :patch
                                        :content-type "application/strategic-merge-patch+json"
                                        :octets "{\"spec\":{\"taints\":null}}")))
        (is (null (gethash "taints" (gethash "spec" cleared)))))
      (check-core-status 200 "/api/v1/nodes/fake" :method :delete)
      (check-core-status 404 "/api/v1/nodes/fake"))))

(defmacro with-replaced-functions ((&rest bindings) &body body)
  "Run BODY with each (NAME FUNCTION) binding replacing the global function NAME."
  (let ((names (mapcar #'first bindings)) (saved (gensym "SAVED")))
    `(let ((,saved (list ,@(mapcar (lambda (name) `(symbol-function ',name)) names))))
       (unwind-protect
            (progn ,@(mapcar (lambda (binding) `(setf (symbol-function ',(first binding)) ,(second binding))) bindings)
                   ,@body)
         (loop for name in ',names for function in ,saved
               do (setf (symbol-function name) function))))))

(defun gap-wait-for-pull (runtime image)
  "Wait until the background pull of IMAGE has finished."
  (let ((manager (gr8s::containerd-runtime-images runtime)))
    (loop repeat 200
          until (not (eq :pulling (gr8s::image-pull-job-state (gethash image (gr8s::image-pull-manager-jobs manager)))))
          do (sleep 0.01))))

(test image-pulls-run-in-the-background-and-report-failures
  (let* ((now 4000000000) (gr8s::*container-lifecycle-clock* (lambda () now))
         (runtime (gr8s::make-containerd-runtime :log-root "/nonexistent/"))
         (pulls nil) (failure nil))
    (with-replaced-functions ((gr8s::cri-image-present-p (lambda (socket image &rest options)
                                                           (declare (ignore socket options))
                                                           (equal image "present")))
                              (gr8s::cri-pull-image (lambda (socket image &rest options)
                                                      (declare (ignore socket options))
                                                      (push image pulls)
                                                      (when failure (error "registry says no")))))
      (is (gr8s::ensure-container-image runtime "present" "IfNotPresent") "nothing to pull")
      (signals gr8s::container-config-error (gr8s::ensure-container-image runtime "absent" "Never"))
      (is (null pulls))
      (signals gr8s::container-image-pending (gr8s::ensure-container-image runtime "new" "IfNotPresent"))
      (gap-wait-for-pull runtime "new")
      (is (equal '("new") pulls))
      (is (gr8s::ensure-container-image runtime "new" "IfNotPresent") "the finished pull is enough")
      (is (equal '("new") pulls))
      (is (gr8s::ensure-container-image runtime "new" "Always") "a fresh pull satisfies Always")
      (incf now 120)
      (signals gr8s::container-image-pending (gr8s::ensure-container-image runtime "new" "Always"))
      (gap-wait-for-pull runtime "new")
      (is (= 2 (count "new" pulls :test #'equal)))
      (setf failure t)
      (signals gr8s::container-image-pending (gr8s::ensure-container-image runtime "bad" "IfNotPresent"))
      (gap-wait-for-pull runtime "bad")
      (let ((condition (handler-case (gr8s::ensure-container-image runtime "bad" "IfNotPresent")
                         (gr8s::container-config-error (condition) condition))))
        (is (typep condition 'gr8s::container-image-pull-error))
        (is (equal "ErrImagePull" (gr8s::container-config-error-reason condition)))
        (is (search "registry says no" (gr8s::runtime-error-message condition))))
      (is (= 1 (count "bad" pulls :test #'equal)) "no new pull during the backoff")
      (incf now (1+ gr8s::+image-pull-backoff-seconds+))
      (signals gr8s::container-image-pending (gr8s::ensure-container-image runtime "bad" "IfNotPresent"))
      (gap-wait-for-pull runtime "bad")
      (is (= 2 (count "bad" pulls :test #'equal))))))

(defun gap-resources (cpu memory)
  "Return resources with equal CPU and memory requests and limits."
  (let ((list (gr8s::core-object "cpu" cpu "memory" memory)))
    (gr8s::core-object "limits" list "requests" (gr8s::copy-core-object list))))

(test the-fingerprint-ignores-what-changes-in-place
  (flet ((print-of (&rest fields)
           (gr8s::pod-runtime-spec-fingerprint
            (parse-pod (gap-pod-object "containers" (vector (apply #'gap-container "c" fields)))))))
    (is (equal (print-of) (print-of "image" "other")))
    (is (equal (print-of) (print-of "resources" (gap-resources "100m" "10Mi"))))
    (is (equal (print-of) (print-of "resizePolicy" (vector (gr8s::core-object "resourceName" "cpu" "restartPolicy" "NotRequired")))))
    (is (not (equal (print-of) (print-of "command" #("true")))))))

(test resizes-may-not-change-qos-or-remove-limits-or-touch-other-resources
  (flet ((pod (resources &rest fields)
           (let ((pod (parse-pod (gap-pod-object
                                  "restartPolicy" (or (getf fields :restart) "Always")
                                  "containers" (vector (gap-container "c" "resources" resources))))))
             (setf (gethash "resizePolicy" (aref (gethash "containers" (gethash "spec" (pod-to-object pod))) 0))
                   (getf fields :policy #()))
             pod)))
    (let ((base (pod (gap-resources "100m" "10Mi"))))
      (is (null (gr8s::validate-pod-resize base (pod (gap-resources "200m" "20Mi")))))
      (signals kubernetes-error
        (gr8s::validate-pod-resize base (pod (gr8s::core-object
                                              "requests" (gr8s::core-object "cpu" "100m" "memory" "10Mi")
                                              "limits" (gr8s::core-object "cpu" "200m" "memory" "10Mi")))))
      (signals kubernetes-error
        (gr8s::validate-pod-resize base (pod (gr8s::core-object "requests" (gr8s::core-object "cpu" "100m" "memory" "10Mi"))))))
    (signals kubernetes-error
      (gr8s::validate-pod-resize
       (pod (gap-resources "100m" "10Mi") :restart "Never")
       (pod (gap-resources "200m" "10Mi") :restart "Never"
            :policy (vector (gr8s::core-object "resourceName" "cpu" "restartPolicy" "RestartContainer")))))))

(test resize-policies-decide-between-updating-and-restarting
  (let ((restart-memory (gr8s::core-object "resizePolicy"
                                           (vector (gr8s::core-object "resourceName" "memory" "restartPolicy" "RestartContainer")
                                                   (gr8s::core-object "resourceName" "cpu" "restartPolicy" "NotRequired"))))
        (before (gap-resources "100m" "10Mi")))
    (is (gr8s::container-resize-restart-required-p restart-memory before (gap-resources "100m" "20Mi")))
    (is (not (gr8s::container-resize-restart-required-p restart-memory before (gap-resources "200m" "10Mi"))))
    (is (not (gr8s::container-resize-restart-required-p restart-memory before (gap-resources "0.1" "10485760"))) "the same amounts")
    (is (not (gr8s::container-resize-restart-required-p (gr8s::core-object) before (gap-resources "100m" "20Mi"))))))

(defun gap-resized-pod (store resources)
  "Create a one-container Pod declaring RESOURCES."
  (create-pod store (parse-pod (gap-pod-object "containers" (vector (gap-container "main" "resources" resources))))))

(test running-containers-take-new-resources-in-place-and-report-what-was-applied
  (with-temporary-store (store directory)
    (let* ((now 4000000000) (gr8s::*container-lifecycle-clock* (lambda () now))
           (pod (gap-resized-pod store (gap-resources "100m" "10Mi")))
           (runtime (gr8s::make-containerd-runtime :log-root directory))
           (updates nil))
      (with-lifecycle-cri (fixture pod nil)
        (with-replaced-functions ((gr8s::cri-update-container-resources
                                   (lambda (socket id resources &rest options)
                                     (declare (ignore socket options))
                                     (push (list id (gr8s.cri.v1::memory-limit-in-bytes resources)) updates))))
          (let* ((observed (gr8s::runtime-ensure runtime pod))
                 (status (aref (gethash "containerStatuses" (gr8s::runtime-pod-status observed)) 0)))
            (is (equal "10Mi" (gethash "memory" (gethash "limits" (gethash "resources" status)))))
            (is (equal "100m" (gethash "cpu" (gethash "allocatedResources" status)))))
          (let* ((object (gr8s::copy-json-object (pod-to-object pod)))
                 (container (aref (gethash "containers" (gethash "spec" object)) 0)))
            (setf (gethash "resources" container) (gap-resources "200m" "20Mi"))
            (let* ((resized (let ((gr8s::*pod-resize-update* t))
                              (update-pod store (parse-pod object) (pod-resource-version pod))))
                   (before (runtime-observe runtime (pod-uid pod))))
              (is (equal (gr8s::pod-runtime-spec-fingerprint pod) (gr8s::pod-runtime-spec-fingerprint resized)))
              (is (gr8s::pod-resize-in-progress-p resized (gr8s::runtime-pod-status before)) "not carried out yet")
              (let* ((after (gr8s::runtime-reconcile-containers runtime resized before))
                     (status (aref (gethash "containerStatuses" (gr8s::runtime-pod-status after)) 0)))
                (is (equal (list (list "main-0" (* 20 1024 1024))) updates))
                (is (equal "20Mi" (gethash "memory" (gethash "limits" (gethash "resources" status)))))
                (is (not (gr8s::pod-resize-in-progress-p resized (gr8s::runtime-pod-status after))))
                (is (null (remove :create (lifecycle-cri-fixture-calls fixture) :key #'first)) "no stop or restart"))
              (gr8s::runtime-reconcile-containers runtime resized (runtime-observe runtime (pod-uid pod)))
              (is (= 1 (length updates)) "already applied"))))))))

(test a-changed-image-restarts-only-that-container-even-under-restart-policy-never
  (with-temporary-store (store directory)
    ;; The stop runs in a background thread, so the test keeps to the real clock.
    (let* ((pod (lifecycle-pod store "Never"))
           (runtime (gr8s::make-containerd-runtime :log-root directory)))
      (with-lifecycle-cri (fixture pod nil)
        (gr8s::runtime-ensure runtime pod)
        (setf (lifecycle-cri-fixture-calls fixture) nil)
        (let* ((object (gr8s::copy-json-object (pod-to-object pod)))
               (container (aref (gethash "containers" (gethash "spec" object)) 0)))
          (setf (gethash "image" container) "nginx")
          (let ((updated (update-pod store (parse-pod object) (pod-resource-version pod))))
            (gr8s::runtime-reconcile-containers runtime updated (runtime-observe runtime (pod-uid pod)))
            (loop repeat 100
                  until (find :stop (lifecycle-cri-fixture-calls fixture) :key #'first)
                  do (sleep 0.05))
            (is (equal '((:stop "main-0")) (lifecycle-cri-fixture-calls fixture)) "only the changed container")
            (gr8s::stop-container-probes runtime (pod-uid pod))
            (setf (lifecycle-cri-fixture-calls fixture) nil)
            (gr8s::runtime-reconcile-containers runtime updated (runtime-observe runtime (pod-uid pod)))
            (is (find-if (lambda (call) (and (eq :create (first call)) (equal "main" (second call))))
                         (lifecycle-cri-fixture-calls fixture)))))))))

(test the-scheduler-records-why-a-pod-did-or-did-not-land
  (with-temporary-store (store directory)
    (declare (ignorable directory))
    (let ((pod (create-pod store (parse-pod (gap-pod-object "nodeSelector" (gr8s::core-object "wanted" "yes")))))
          (node (gr8s::register-node store (gap-node))))
      (gr8s::mark-node-ready store (gr8s::node-record-name node) (get-universal-time))
      (flet ((events ()
               (remove-if-not (lambda (event) (uiop:string-prefix-p (pod-name pod) (gethash "name" (gethash "metadata" event))))
                              (gr8s::list-core-resources store "events" (pod-namespace pod)))))
        (gr8s::schedule-pod store pod)
        (gr8s::schedule-pod store pod)
        (let ((failed (first (events))))
          (is (= 1 (length (events))) "an unchanged reason is not repeated at once")
          (is (equal "Warning" (gethash "type" failed)))
          (is (equal "FailedScheduling" (gethash "reason" failed))))
        (setf (gr8s::node-record-labels node) (gr8s::core-object "wanted" "yes"))
        (is (gr8s::schedule-pod store pod))
        (let ((scheduled (find "Scheduled" (events) :test #'equal :key (lambda (event) (gethash "reason" event)))))
          (is (equal "Normal" (gethash "type" scheduled)))
          (is (search "Successfully assigned default/hello to node" (gethash "message" scheduled))))))))

(test environment-values-may-refer-to-earlier-variables
  (let* ((runtime (gr8s::make-containerd-runtime :log-root "/nonexistent/"))
         (pod (parse-pod (gap-pod-object
                          "containers"
                          (vector (gap-container
                                   "c" "env" (vector (gr8s::core-object "name" "FOO" "value" "foo-value")
                                                     (gr8s::core-object "name" "BAR" "value" "bar-value")
                                                     (gr8s::core-object "name" "FOOBAR" "value" "$(FOO);;$(BAR)")
                                                     (gr8s::core-object "name" "EARLY" "value" "$(LATER)")
                                                     (gr8s::core-object "name" "LATER" "value" "set")
                                                     (gr8s::core-object "name" "ESCAPED" "value" "$$(FOO)")))))))
         (environment (gr8s::containerd-pod-environment runtime pod (aref (gr8s::pod-containers pod) 0) "sandbox")))
    (flet ((value (name) (cdr (assoc name environment :test #'equal))))
      (is (equal "foo-value;;bar-value" (value "FOOBAR")))
      (is (equal "$(LATER)" (value "EARLY")) "only earlier variables are known")
      (is (equal "$(FOO)" (value "ESCAPED"))))))

(test http-hooks-and-probes-send-their-declared-path-as-written
  (let* ((listener (usocket:socket-listen "127.0.0.1" 0 :reuse-address t))
         (port (usocket:get-local-port listener))
         (line nil)
         (server (bt:make-thread
                  (lambda ()
                    (let* ((socket (usocket:socket-accept listener)) (stream (usocket:socket-stream socket)))
                      (setf line (read-line stream))
                      (usocket:socket-close socket))))))
    (unwind-protect
         (progn
           (ignore-errors
            (gr8s::run-http-container-probe
             (gr8s::core-object "path" "/dial?host=a&request=echo%3Fmsg%3Dhi" "scheme" "HTTP") "127.0.0.1" port 3))
           (bt:join-thread server)
           (is (search "GET /dial?host=a&request=echo%3Fmsg%3Dhi HTTP/1.1" line)))
      (usocket:socket-close listener))))

(test container-occurrences-become-node-events
  (with-temporary-store (store directory)
    (let* ((pod (create-pod store (parse-pod (gap-pod-object))))
           (runtime (gr8s::make-containerd-runtime :log-root directory))
           (name (container-spec-name (aref (gr8s::pod-containers pod) 0))))
      (gr8s::record-container-lifecycle-event runtime (pod-uid pod) name 0 "Started" "Started container")
      (let ((events (gr8s::runtime-events runtime (pod-uid pod))))
        (is (= 1 (length events)))
        (gr8s::record-node-runtime-events store pod "node" events)
        (gr8s::record-node-runtime-events store pod "node" events))
      (let ((stored (gr8s::list-core-resources store "events" (pod-namespace pod))))
        (is (= 1 (length stored)) "a replayed page does not repeat the Event")
        (is (equal "Started" (gethash "reason" (first stored))))
        (is (equal "Normal" (gethash "type" (first stored))))
        (is (equal (pod-uid pod) (gethash "uid" (gethash "involvedObject" (first stored)))))))))

(test previous-logs-come-from-the-attempt-before-the-current-one
  (with-temporary-store (store directory)
    (let* ((now 4000000000) (gr8s::*container-lifecycle-clock* (lambda () now))
           (pod (lifecycle-pod store))
           (runtime (gr8s::make-containerd-runtime :log-root directory))
           (log-directory (gr8s::containerd-pod-log-directory runtime (pod-uid pod))))
      (ensure-directories-exist log-directory)
      (flet ((write-log (name text)
               (with-open-file (out (merge-pathnames name log-directory) :direction :output :if-exists :supersede)
                 (write-string text out))))
        (write-log "main.log" "first attempt")
        (with-lifecycle-cri (fixture pod (list (lifecycle-info "main" 0 gr8s.cri.v1::+containerstate-container_running+ now)))
          (values fixture)
          (is (equal "first attempt" (gr8s::runtime-logs runtime (pod-uid pod) "main")))
          (signals kubernetes-error (gr8s::runtime-logs runtime (pod-uid pod) "main" :previous t)))
        (write-log "main.1.log" "second attempt")
        (with-lifecycle-cri (fixture pod (list (lifecycle-info "main" 1 gr8s.cri.v1::+containerstate-container_running+ now)))
          (values fixture)
          (is (equal "second attempt" (gr8s::runtime-logs runtime (pod-uid pod) "main")))
          (is (equal "first attempt" (gr8s::runtime-logs runtime (pod-uid pod) "main" :previous t))))))))

(test followed-logs-end-when-the-container-does
  (with-temporary-store (store directory)
    (declare (ignorable directory))
    (let ((pod (create-pod store (parse-pod (gap-pod-object)))))
      (is (not (gr8s::pod-container-finished-p store pod "main")))
      (gr8s::save-pod-observation
       store pod (gr8s::core-object "phase" "Running"
                                    "containerStatuses"
                                    (vector (gr8s::core-object "name" "main" "state" (gr8s::core-object "running" (gr8s::core-object))))))
      (is (not (gr8s::pod-container-finished-p store pod "main")))
      (gr8s::save-pod-observation
       store pod (gr8s::core-object "phase" "Running"
                                    "containerStatuses"
                                    (vector (gr8s::core-object "name" "main" "state" (gr8s::core-object "terminated" (gr8s::core-object "exitCode" 0))))))
      (is-true (gr8s::pod-container-finished-p store pod "main"))
      (gr8s::remove-pod store (pod-namespace pod) (pod-name pod))
      (is-true (gr8s::pod-container-finished-p store pod "main")))))

(test pods-get-private-pid-namespaces-unless-their-spec-shares-one
  (flet ((pid-mode (&rest options)
           (let* ((pod (parse-pod (apply #'gap-pod-object options)))
                  (context (gr8s::containerd-pod-security-context pod (aref (pod-containers pod) 0))))
             (values (gr8s::pod-pid-namespace-mode pod)
                     (slot-value (gr8s.cri.v1::namespace-options context) 'gr8s.cri.v1::pid)))))
    (is (equal (list gr8s.cri.v1::+namespacemode-container+ gr8s.cri.v1::+namespacemode-container+)
               (multiple-value-list (pid-mode))))
    (is (equal (list gr8s.cri.v1::+namespacemode-pod+ gr8s.cri.v1::+namespacemode-pod+)
               (multiple-value-list (pid-mode "shareProcessNamespace" t))))
    (is (equal (list gr8s.cri.v1::+namespacemode-node+ gr8s.cri.v1::+namespacemode-node+)
               (multiple-value-list (pid-mode "hostPID" t)))))
  (signals gr8s::kubernetes-error
    (parse-pod (gap-pod-object "hostPID" t "shareProcessNamespace" t))))

(test ephemeral-containers-join-their-target-pid-namespace
  (let* ((pod (parse-pod (gap-pod-object)))
         (options (gr8s.cri.v1::namespace-options
                   (gr8s::containerd-pod-security-context pod (aref (pod-containers pod) 0) :target-id "abc"))))
    (is (= gr8s.cri.v1::+namespacemode-target+ (slot-value options 'gr8s.cri.v1::pid)))
    (is (equal "abc" (slot-value options 'gr8s.cri.v1::target-id))))
  (let* ((pod (parse-pod (gap-pod-object "shareProcessNamespace" t)))
         (options (gr8s.cri.v1::namespace-options
                   (gr8s::containerd-pod-security-context pod (aref (pod-containers pod) 0) :target-id "abc"))))
    (is (= gr8s.cri.v1::+namespacemode-pod+ (slot-value options 'gr8s.cri.v1::pid)))))

(test node-judges-a-resize-against-its-capacity-and-other-pods
  (flet ((table (&rest pairs)
           (let ((result (make-hash-table :test #'equal)))
             (loop for (name value) on pairs by #'cddr do (setf (gethash name result) value))
             result)))
    (let ((capacity (table "cpu" 4 "memory" 1000)))
      ;; Within what the node has left.
      (is (null (gr8s::pod-resize-verdict (table "cpu" 2) (table "cpu" 1) (table "cpu" 2) capacity)))
      ;; More than the node could ever give.
      (multiple-value-bind (reason message)
          (gr8s::pod-resize-verdict (table "cpu" 5) (table "cpu" 1) (table) capacity)
        (is (equal "Infeasible" reason))
        (is (search "cpu" message)))
      ;; Possible once others let go.
      (multiple-value-bind (reason message)
          (gr8s::pod-resize-verdict (table "memory" 800) (table "memory" 100) (table "memory" 300) capacity)
        (is (equal "Deferred" reason))
        (is (search "memory" message)))
      ;; Shrinking never waits, even on an overcommitted node.
      (is (null (gr8s::pod-resize-verdict (table "cpu" 1) (table "cpu" 2) (table "cpu" 9) capacity))))))

(test pending-resize-is-recorded-once-and-cleared
  (let ((state (gr8s::core-object)))
    (is-true (gr8s::note-pod-resize-pending state "Deferred" "wait"))
    (is (equal "Deferred" (gethash "reason" (gethash "resizePending" state))))
    (is-false (gr8s::note-pod-resize-pending state "Deferred" "wait"))
    (is-true (gr8s::note-pod-resize-pending state "Infeasible" "never"))
    (is-true (gr8s::note-pod-resize-pending state nil nil))
    (is-false (nth-value 1 (gethash "resizePending" state)))
    (is-false (gr8s::note-pod-resize-pending state nil nil))))

(test a-node-reported-resize-wait-becomes-the-pod-condition
  (with-temporary-store (store path)
    (values path)
    (let* ((pod (create-pod store (parse-pod (gap-pod-object))))
           (status (gr8s::core-object
                    "phase" "Running"
                    "conditions" (vector (gr8s::core-object "type" "PodResizePending" "status" "True"
                                                            "reason" "Deferred" "message" "wait"))))
           (conditions (gethash "conditions" (gr8s::add-pod-status-conditions store pod status)))
           (pending (gr8s::find-pod-condition conditions "PodResizePending")))
      (is (equal "Deferred" (gethash "reason" pending)))
      (is (equal "wait" (gethash "message" pending)))
      (is (null (gr8s::find-pod-condition conditions "PodResizeInProgress"))))))

(test the-api-refuses-a-resize-beyond-the-node
  (with-temporary-store (store path)
    (values path)
    (gr8s:register-node store (gr8s:make-node-record :id "id-worker" :name "worker" :pod-cidr "10.88.7.0/24"))
    (gr8s:mark-node-ready store "worker" (get-universal-time))
    (gr8s::update-node-capacity store "worker" (gr8s::core-object "cpu" "2" "memory" "1Gi" "pods" "10"))
    (flet ((pod (cpu)
             (let ((object (gap-pod-object "nodeName" "worker")))
               (setf (gethash "resources" (aref (gethash "containers" (gethash "spec" object)) 0))
                     (gr8s::core-object "requests" (gr8s::core-object "cpu" cpu)))
               (parse-pod object))))
      (let ((pod (create-pod store (pod "1"))))
        (is (null (gr8s::refuse-pod-resize-beyond-node store pod (pod "2"))))
        (let ((condition (handler-case (gr8s::refuse-pod-resize-beyond-node store pod (pod "3"))
                           (kubernetes-error (condition) condition))))
          (is (= 403 (gr8s::kubernetes-error-status-code condition)))
          (is (search "enough allocatable" (gr8s::kubernetes-error-message condition)))
          (is (equal "NodeCapacity"
                     (gethash "reason" (aref (gethash "causes" (gr8s::kubernetes-error-details condition)) 0)))))))))
