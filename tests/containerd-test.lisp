(in-package #:gr8s/tests)

(in-suite gr8s)

(test containerd-runtime-has-an-explicit-package-boundary
  (let ((package (find-package "GR8S.RUNTIME.CONTAINERD")))
    (is (not (null package)))
    (dolist (name '("MAKE-CONTAINERD-RUNTIME" "CONTAINERD-RUNTIME"
                    "CONTAINERD-RUNTIME-P" "CRI-CONTAINER-INFO"
                    "CRI-CONTAINER-STATUS"))
      (multiple-value-bind (symbol status) (and package (find-symbol name package))
        (is (not (null symbol)) "~A is present in GR8S.RUNTIME.CONTAINERD" name)
        (is (eq :external status) "~A is exported from GR8S.RUNTIME.CONTAINERD" name)
        (is (eq symbol (find-symbol name "GR8S"))
            "GR8S preserves ~A's containerd symbol identity" name)))))

(test containerd-reports-real-running-and-terminated-container-states
  (let* ((info (gr8s.runtime.containerd::make-cri-container-info
                :id "actual-id" :name "e2e" :attempt 2 :image "registry.k8s.io/conformance:v1.36.0"
                :image-ref "sha256:actual" :state gr8s.cri.v1::+containerstate-container_running+
                :started-at 1793729722000000000))
         (running (gr8s.runtime.containerd::containerd-container-status-object info)))
    (is (gethash "running" (gethash "state" running)))
    (is (null (gethash "terminated" (gethash "state" running))))
    (is (gethash "ready" running))
    (is (equal "containerd://actual-id" (gethash "containerID" running)))
    (is (= 2 (gethash "restartCount" running)))
    (is (equal "2026-11-03T18:15:22Z" (gethash "startedAt" (gethash "running" (gethash "state" running)))))
    (setf (gr8s.runtime.containerd::cri-container-info-state info) gr8s.cri.v1::+containerstate-container_exited+
          (gr8s.runtime.containerd::cri-container-info-exit-code info) 7
          (gr8s.runtime.containerd::cri-container-info-finished-at info) 1793729752000000000
          (gr8s.runtime.containerd::cri-container-info-reason info) "Error")
    (let* ((status (gr8s.runtime.containerd::containerd-container-status-object info))
           (terminated (gethash "terminated" (gethash "state" status))))
      (is (null (gethash "ready" status)))
      (is (null (gethash "running" (gethash "state" status))))
      (is (= 7 (gethash "exitCode" terminated)))
      (is (equal "Error" (gethash "reason" terminated)))
      (is (equal "2026-11-03T18:15:52Z" (gethash "finishedAt" terminated))))))

(test containerd-runtime-satisfies-the-pod-runtime-protocol
  (if (string= "1"
               (or (uiop:getenv "GR8S_RUN_CONTAINERD_LIFECYCLE_TESTS") ""))
      (with-temporary-store (store path)
        (let* ((pod
                 (create-pod
                  store
                  (parse-pod
                   "{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"name\":\"cri-runtime\"},\"spec\":{\"restartPolicy\":\"Never\",\"containers\":[{\"name\":\"main\",\"image\":\"docker.io/library/busybox:1.37.0\",\"command\":[\"/bin/sh\",\"-c\",\"echo gr8s-runtime-ok\"]}]}}")))
               (runtime
                 (gr8s.runtime.containerd::make-containerd-runtime
                  :socket-path
                  (or (uiop:getenv "GR8S_CONTAINERD_SOCKET")
                      "/tmp/gr8s-containerd.sock")
                  :log-root "/tmp/gr8s-runtime-logs/"
                  :host-network nil)))
          (unwind-protect
               (progn
                 (runtime-ensure runtime pod)
                 (let ((observed
                         (loop repeat 50
                               for current =
                                 (runtime-observe runtime (pod-uid pod))
                               when (and current
                                         (string= "Succeeded"
                                                  (runtime-pod-phase current)))
                                 return current
                               do (sleep 0.1))))
                   (is (not (null observed)))
                   (is (string= (pod-resource-version pod)
                                (runtime-pod-resource-version observed))))
                 (is (search "gr8s-runtime-ok"
                             (runtime-logs runtime (pod-uid pod) "main"))))
            (runtime-delete runtime (pod-uid pod)))
          (is (null (runtime-observe runtime (pod-uid pod))))))
      (skip "Set GR8S_RUN_CONTAINERD_LIFECYCLE_TESTS=1 to run the containerd runtime test")))
