;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
(in-package #:gr8s/tests)
(def-suite device-plugins :in gr8s)
(in-suite device-plugins)

(defun plugin-wire (type &rest fields)
  "Build a standard device-plugin message for the fixture."
  (apply #'make-instance (find-symbol type :gr8s.deviceplugin.v1beta1) fields))

(defun plugin-fixture (manager)
  "Advertise two distinct allocatable IDs for the same host device."
  (setf (gethash "devices.example.test/kvm" (gr8s.kubelet::device-plugin-manager-plugins manager))
        (gr8s.kubelet::make-device-plugin
         :resource "devices.example.test/kvm" :endpoint "/fixture.sock"
         :devices (list (plugin-wire "DEVICE" :id "kvm0" :health "Healthy")
                        (plugin-wire "DEVICE" :id "kvm1" :health "Healthy")))))

(test device-allocations-are-exclusive-durable-and-reused-on-retry
  (with-temporary-store (store path)
    (declare (ignore store))
    (let* ((manager (gr8s.kubelet::make-device-plugin-manager path))
           (pod1 (gr8s::make-pod :uid "one" :name "one"))
           (pod2 (gr8s::make-pod :uid "two" :name "two"))
           (pod3 (gr8s::make-pod :uid "three" :name "three"))
           (container (gr8s::core-object "name" "compute" "resources"
                        (gr8s::core-object "limits" (gr8s::core-object "devices.example.test/kvm" "1"))))
           (calls 0) (ids nil)
           (gr8s.kubelet::*device-plugin-call*
             (lambda (plugin method request type)
               (declare (ignore plugin type))
               (is (equal "Allocate" method))
               (incf calls)
               (push (gr8s.deviceplugin.v1beta1::devices-ids
                       (first (gr8s.deviceplugin.v1beta1::container-requests request))) ids)
               (plugin-wire "ALLOCATE-RESPONSE" :container-responses
                 (list (plugin-wire "CONTAINER-ALLOCATE-RESPONSE"
                         :envs '(("DEVICE_ENV" . "present"))
                         :devices (list (plugin-wire "DEVICE-SPEC" :host-path "/dev/kvm"
                                                      :container-path "/dev/kvm" :permissions "rw"))))))))
      (plugin-fixture manager)
      (let ((config (gr8s.kubelet::device-plugin-container-config manager pod1 container)))
        (is (equal '(("DEVICE_ENV" . "present")) (getf config :env)))
        (is (equal "/dev/kvm" (gr8s.cri.v1::host-path (first (getf config :devices))))))
      (gr8s.kubelet::device-plugin-container-config manager pod1 container)
      (is (= 1 calls))
      (gr8s.kubelet::device-plugin-container-config manager pod2 container)
      (is (equal '(("kvm1") ("kvm0")) ids))
      (signals gr8s.runtime:runtime-error
        (gr8s.kubelet::device-plugin-container-config manager pod3 container))
      (let ((restored (gr8s.kubelet::make-device-plugin-manager path)))
        (is (equal '(("devices.example.test/kvm" . "0")) (gr8s.kubelet::device-plugin-resource-entries restored)))
        (plugin-fixture restored)
        (gr8s.kubelet::device-plugin-container-config restored pod1 container)
        (is (= 2 calls))
        (gr8s.kubelet::release-plugin-devices restored pod1)
        (gr8s.kubelet::device-plugin-container-config restored pod3 container)
        (is (= 3 calls))
        (is (equal '("kvm0") (first ids)))
        (is (equal '(("devices.example.test/kvm" . "2")) (gr8s.kubelet::device-plugin-resource-entries restored)))))))

(test device-registry-is-a-real-unix-grpc-service-and-releases-its-socket
  (with-temporary-store (store path)
    (declare (ignore store))
    (let* ((directory (merge-pathnames "plugins/" path))
           (manager (gr8s.kubelet::make-device-plugin-manager path :directory directory))
           (socket (merge-pathnames "kubelet.sock" directory)))
      (unwind-protect
           (progn
             (gr8s.kubelet::start-device-plugin-manager manager)
             (is-true (probe-file socket))
             (let ((channel (gr8s::make-unix-grpc-channel (namestring socket) :timeout 5)))
               (unwind-protect
                    (signals ag-grpc:grpc-status-error
                      (ag-grpc:call-unary channel "/v1beta1.Registration/Register"
                                  (plugin-wire "REGISTER-REQUEST" :version "wrong" :endpoint "bad.sock"
                                                                  :resource-name "devices.example.test/kvm")
                                  :response-type 'gr8s.deviceplugin.v1beta1::empty :timeout 5))
                 (ag-grpc:channel-close channel))))
        (gr8s.kubelet::stop-device-plugin-manager manager))
      (is-false (probe-file socket)))))

(test registered-plugins-stream-health-and-return-real-allocation-rpcs
  (with-temporary-store (store path)
    (declare (ignore store))
    (let* ((directory (merge-pathnames "registry/" path))
           (manager (gr8s.kubelet::make-device-plugin-manager path :directory directory))
           (allocated-ids nil)
           (plugin-server (gr8s.kubelet::make-device-plugin-manager
                           (merge-pathnames "fake-state/" path) :directory (merge-pathnames "fake/" path))))
      (unwind-protect
           (progn
             (gr8s.kubelet::start-device-plugin-manager manager)
             (gr8s.kubelet::start-device-plugin-manager plugin-server)
             (rename-file (merge-pathnames "kubelet.sock" (gr8s.kubelet::device-plugin-manager-directory plugin-server))
                          (merge-pathnames "fake.sock" directory))
             (setf (gr8s.kubelet::device-plugin-manager-socket-path plugin-server) (merge-pathnames "fake.sock" directory))
             (let ((server (gr8s.kubelet::device-plugin-manager-server plugin-server)))
               (ag-grpc:server-register-handler server "/v1beta1.DevicePlugin/ListAndWatch"
                 (lambda (request context stream)
                   (declare (ignore request context))
                   (ag-grpc:stream-send stream (plugin-wire "LIST-AND-WATCH-RESPONSE" :devices
                                                 (list (plugin-wire "DEVICE" :id "gpu0" :health "Healthy"))))
                   (loop while (gr8s.kubelet::device-plugin-manager-running plugin-server) do (sleep .05)))
                 :request-type 'gr8s.deviceplugin.v1beta1::empty
                 :response-type 'gr8s.deviceplugin.v1beta1::list-and-watch-response :server-streaming t)
               (ag-grpc:server-register-handler server "/v1beta1.DevicePlugin/Allocate"
                 (lambda (request context)
                   (declare (ignore context))
                   (setf allocated-ids (gr8s.deviceplugin.v1beta1::devices-ids
                                        (first (gr8s.deviceplugin.v1beta1::container-requests request))))
                   (plugin-wire "ALLOCATE-RESPONSE" :container-responses
                     (list (plugin-wire "CONTAINER-ALLOCATE-RESPONSE" :envs '(("ALLOCATED_GPU" . "gpu0"))))))
                 :request-type 'gr8s.deviceplugin.v1beta1::allocate-request
                 :response-type 'gr8s.deviceplugin.v1beta1::allocate-response))
             (let ((channel (gr8s::make-unix-grpc-channel (namestring (merge-pathnames "kubelet.sock" directory)) :timeout 5)))
               (unwind-protect
                    (ag-grpc:call-unary channel "/v1beta1.Registration/Register"
                      (plugin-wire "REGISTER-REQUEST" :version "v1beta1" :endpoint "fake.sock" :resource-name "devices.example.test/gpu")
                      :response-type 'gr8s.deviceplugin.v1beta1::empty :timeout 5)
                 (ag-grpc:channel-close channel)))
             (is-true (wait-until (lambda () (equal '(("devices.example.test/gpu" . "1"))
                                                    (gr8s.kubelet::device-plugin-resource-entries manager)))))
             (let ((config (gr8s.kubelet::device-plugin-container-config manager (gr8s::make-pod :uid "rpc-pod")
                             (gr8s::core-object "name" "gpu" "resources" (gr8s::core-object "limits"
                                                                                         (gr8s::core-object "devices.example.test/gpu" "1"))))))
               (is (equal '(("ALLOCATED_GPU" . "gpu0")) (getf config :env)))
             (is (equal '("gpu0") allocated-ids))))
        (gr8s.kubelet::stop-device-plugin-manager manager)
        (gr8s.kubelet::stop-device-plugin-manager plugin-server)))))
