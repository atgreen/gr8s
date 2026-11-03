(in-package #:gr8s/tests)

(in-suite gr8s)

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
                 (gr8s::make-containerd-runtime
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
