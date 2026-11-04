(in-package #:gr8s/tests)

(in-suite gr8s)

(test cri-user-decodes-packed-and-unpacked-supplemental-groups
  ;; Captured from containerd's real conformance ContainerStatus response.
  (let ((user (ag-proto:deserialize-from-bytes 'gr8s.cri.v1::linux-container-user #(26 1 0))))
    (is (equal '(0) (gr8s.cri.v1::supplemental-groups user))))
  (let ((user (ag-proto:deserialize-from-bytes 'gr8s.cri.v1::linux-container-user
                #(8 232 7 16 184 23 26 3 0 208 15 24 42 26 0))))
    (is (= 1000 (gr8s.cri.v1::uid user)))
    (is (= 3000 (gr8s.cri.v1::gid user)))
    (is (equal '(0 2000 42) (gr8s.cri.v1::supplemental-groups user))))
  (signals error (ag-proto:deserialize-from-bytes 'gr8s.cri.v1::linux-container-user #(26 1 128))))

(test cri-version-reports-containerd-over-a-unix-socket
  (if (string= "1" (or (uiop:getenv "GR8S_RUN_CONTAINERD_TESTS") ""))
      (if (not (fboundp 'gr8s::cri-runtime-version))
          (is (fboundp 'gr8s::cri-runtime-version))
          (let ((version
                  (gr8s::cri-runtime-version
                   (or (uiop:getenv "GR8S_CONTAINERD_SOCKET")
                       "/tmp/gr8s-containerd.sock"))))
            (is (string= "containerd"
                         (gr8s::cri-version-info-runtime-name version)))
            (is (string= "v1"
                         (gr8s::cri-version-info-runtime-api-version version)))
            (is (search "2.4.2"
                        (gr8s::cri-version-info-runtime-version version)))))
      (skip "Set GR8S_RUN_CONTAINERD_TESTS=1 to run the containerd CRI test")))

(test host-network-cri-sandbox-does-not-request-a-hostname-change
  (let ((config
          (gr8s::make-cri-pod-sandbox-config
           "gr8s-cri-test"
           "gr8s-cri-test-uid"
           "default"
           0
           "/tmp/gr8s-cri-logs"
           t)))
    (is (string= "" (gr8s.cri.v1::hostname config)))))

(test cri-sandbox-carries-the-cluster-dns-configuration
  (let* ((config
           (gr8s::make-cri-pod-sandbox-config
            "dns-test" "dns-test-uid" "default" 0 "/tmp/gr8s-dns-test" nil
            :dns-servers '("10.88.0.1")
            :dns-searches '("default.svc.cluster.local"
                            "svc.cluster.local"
                            "cluster.local")
            :dns-options '("ndots:5")))
         (dns (gr8s.cri.v1::dns-config config)))
    (is (equal '("10.88.0.1") (gr8s.cri.v1::servers dns)))
    (is (equal '("default.svc.cluster.local"
                 "svc.cluster.local"
                 "cluster.local")
               (gr8s.cri.v1::searches dns)))
    (is (equal '("ndots:5") (gr8s.cri.v1::options dns)))))

(test cri-exec-request-preserves-command-and-stream-selection
  (let ((request
          (gr8s::make-cri-exec-request
           "container-id" '("sh" "-c" "echo ok")
           :stdin nil :stdout t :stderr t :tty nil)))
    (is (string= "container-id" (gr8s.cri.v1::container-id request)))
    (is (equal '("sh" "-c" "echo ok") (gr8s.cri.v1::cmd request)))
    (is (not (gr8s.cri.v1::stdin request)))
    (is (gr8s.cri.v1::stdout request))
    (is (gr8s.cri.v1::stderr request))
    (is (not (gr8s.cri.v1::tty request)))))

(test cri-exec-sync-request-preserves-container-command-and-timeout
  (let ((request
          (gr8s::make-cri-exec-sync-request
           "container-id" '("sh" "-c" "exit 7") 19)))
    (is (string= "container-id" (gr8s.cri.v1::container-id request)))
    (is (equal '("sh" "-c" "exit 7") (gr8s.cri.v1::cmd request)))
    (is (= 19 (gr8s.cri.v1::timeout request)))))

(test cri-runs-and-removes-a-host-network-pod-sandbox
  (if (string= "1"
               (or (uiop:getenv "GR8S_RUN_CONTAINERD_LIFECYCLE_TESTS") ""))
      (if (not (fboundp 'gr8s::cri-run-pod-sandbox))
          (is (fboundp 'gr8s::cri-run-pod-sandbox))
          (let* ((socket-path
                   (or (uiop:getenv "GR8S_CONTAINERD_SOCKET")
                       "/tmp/gr8s-containerd.sock"))
                 (uid (format nil "gr8s-cri-test-~D" (get-universal-time)))
                 (sandbox-id nil))
            (ensure-directories-exist "/tmp/gr8s-cri-logs/")
            (unwind-protect
                 (progn
                   (setf sandbox-id
                         (gr8s::cri-run-pod-sandbox
                          socket-path
                          :name "gr8s-cri-test"
                          :uid uid
                          :namespace "default"
                          :log-directory "/tmp/gr8s-cri-logs"
                          :host-network t))
                   (is (plusp (length sandbox-id))))
              (when sandbox-id
                (gr8s::cri-delete-pod-sandbox socket-path sandbox-id)))))
      (skip "Set GR8S_RUN_CONTAINERD_LIFECYCLE_TESTS=1 to run the CRI lifecycle test")))

(test cri-pulls-runs-logs-and-removes-a-container
  (if (string= "1"
               (or (uiop:getenv "GR8S_RUN_CONTAINERD_LIFECYCLE_TESTS") ""))
      (let* ((socket-path
               (or (uiop:getenv "GR8S_CONTAINERD_SOCKET")
                   "/tmp/gr8s-containerd.sock"))
             (uid (format nil "gr8s-cri-container-~D" (get-universal-time)))
             (log-directory (format nil "/tmp/gr8s-cri-logs/~A/" uid))
             (sandbox-config
               (gr8s::make-cri-pod-sandbox-config
                "gr8s-cri-container-test" uid "default" 0 log-directory nil))
             (sandbox-id nil)
             (container-id nil))
        (ensure-directories-exist log-directory)
        (unwind-protect
             (let ((image-ref
                     (gr8s::cri-pull-image
                      socket-path "docker.io/library/busybox:1.37.0")))
               (is (plusp (length image-ref)))
               (setf sandbox-id
                     (gr8s::cri-run-pod-sandbox
                      socket-path
                      :name "gr8s-cri-container-test"
                      :uid uid
                      :namespace "default"
                      :log-directory log-directory
                      :host-network nil))
               (setf container-id
                     (gr8s::cri-create-container
                      socket-path sandbox-id sandbox-config
                      :name "main"
                      :image "docker.io/library/busybox:1.37.0"
                      :command '("/bin/sh" "-c" "echo gr8s-cri-container-ok")
                      :log-path "main.log"))
               (gr8s::cri-start-container socket-path container-id)
               (let ((status
                       (loop repeat 50
                             for current =
                               (gr8s::cri-container-status
                                socket-path container-id)
                             when (= gr8s.cri.v1::+containerstate-container_exited+
                                     (gr8s::cri-container-info-state current))
                               return current
                             do (sleep 0.1))))
                 (is (not (null status)))
                 (is (= 0 (gr8s::cri-container-info-exit-code status))))
               (loop repeat 50
                     until (probe-file (merge-pathnames "main.log" log-directory))
                     do (sleep 0.1))
               (is (search "gr8s-cri-container-ok"
                           (uiop:read-file-string
                            (merge-pathnames "main.log" log-directory)))))
          (when container-id
            (gr8s::cri-delete-container socket-path container-id))
          (when sandbox-id
            (gr8s::cri-delete-pod-sandbox socket-path sandbox-id))))
      (skip "Set GR8S_RUN_CONTAINERD_LIFECYCLE_TESTS=1 to run the CRI lifecycle test")))

(test cri-sandbox-network-status-carries-the-observed-pod-ip
  (let* ((response (make-instance
                    'gr8s.cri.v1::pod-sandbox-status-response
                    :status (make-instance 'gr8s.cri.v1::pod-sandbox-status
                                           :network (make-instance 'gr8s.cri.v1::pod-sandbox-network-status
                                                                   :ip "10.88.1.2"))))
         (decoded (ag-proto:deserialize-from-bytes 'gr8s.cri.v1::pod-sandbox-status-response
                                                  (ag-proto:serialize-to-bytes response))))
    (is (string= "10.88.1.2" (gr8s::cri-pod-sandbox-ip-from-response decoded))))
  (is (string= "" (gr8s::cri-pod-sandbox-ip-from-response
                    (make-instance 'gr8s.cri.v1::pod-sandbox-status-response)))))
