;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Pod-level spec.resources: validation and defaulting as the API server does them,
;;;; the Pod's requests and limits for scheduling and QoS, and a container without
;;;; limits of its own taking the Pod's in the downward API and its cgroup.

(in-package #:gr8s/tests)
(def-suite pod-level-resources :in gr8s)
(in-suite pod-level-resources)

(defun plr-list (&rest plist)
  "Return a resource list from PLIST."
  (let ((table (gr8s::core-object)))
    (loop for (key value) on plist by #'cddr do (setf (gethash key table) value))
    table))

(defun plr-pod (&key requests limits (containers (list (gr8s::core-object "name" "app" "image" "busybox"))))
  "Parse a Pod with pod-level REQUESTS and LIMITS plists and CONTAINERS."
  (let ((resources (gr8s::core-object)))
    (when requests (setf (gethash "requests" resources) (apply #'plr-list requests)))
    (when limits (setf (gethash "limits" resources) (apply #'plr-list limits)))
    (parse-pod (gr8s::core-object "apiVersion" "v1" "kind" "Pod"
                                  "metadata" (gr8s::core-object "name" "plr" "namespace" "default")
                                  "spec" (gr8s::core-object "resources" resources
                                                            "containers" (coerce containers 'vector))))))

(defun plr-container (name &key requests limits)
  "Return a container NAME declaring REQUESTS and LIMITS plists."
  (let ((resources (gr8s::core-object)))
    (when requests (setf (gethash "requests" resources) (apply #'plr-list requests)))
    (when limits (setf (gethash "limits" resources) (apply #'plr-list limits)))
    (gr8s::core-object "name" name "image" "busybox" "resources" resources)))

(defun plr-spec (pod) (gethash "spec" (gr8s::pod-to-object pod)))

(test pod-level-resources-are-validated-as-the-api-server-does
  (is (gr8s::pod-name (plr-pod :requests '("cpu" "250m" "memory" "32Mi") :limits '("cpu" "1250m" "memory" "64Mi"))))
  (dolist (bad (list (lambda () (plr-pod :requests '("ephemeral-storage" "1Gi")))
                     (lambda () (plr-pod :limits '("nvidia.com/gpu" "1")))
                     (lambda () (plr-pod :limits '("hugepages-2Mi" "2Mi")))
                     (lambda () (plr-pod :requests '("cpu" "-1")))
                     ;; A request above its limit.
                     (lambda () (plr-pod :requests '("cpu" "2") :limits '("cpu" "1")))
                     ;; Below what the containers request together.
                     (lambda () (plr-pod :requests '("memory" "32Mi")
                                         :containers (list (plr-container "a" :requests '("memory" "20Mi"))
                                                           (plr-container "b" :requests '("memory" "20Mi")))))
                     ;; A container limit above the Pod's.
                     (lambda () (plr-pod :limits '("cpu" "1")
                                         :containers (list (plr-container "a" :limits '("cpu" "2")))))))
    (signals kubernetes-error (funcall bad)))
  (signals kubernetes-error
    (parse-pod (gr8s::core-object "apiVersion" "v1" "kind" "Pod" "metadata" (gr8s::core-object "name" "c")
                                  "spec" (gr8s::core-object "resources" (gr8s::core-object "claims" (vector (gr8s::core-object "name" "x")))
                                                            "containers" (vector (gr8s::core-object "name" "a" "image" "b")))))))

(test pod-level-requests-default-from-containers-then-limits
  (let* ((pod (plr-pod :limits '("cpu" "2" "memory" "64Mi")
                       :containers (list (plr-container "a" :requests '("cpu" "250m"))
                                         (plr-container "b" :requests '("cpu" "500m")))))
         (requests (gethash "requests" (gethash "resources" (plr-spec pod)))))
    ;; The containers ask for CPU together; nothing asks for memory, so its limit stands in.
    (is (equal "750m" (gethash "cpu" requests)))
    (is (equal "64Mi" (gethash "memory" requests))))
  ;; Without pod-level limits nothing is defaulted.
  (is (null (gethash "requests" (gethash "resources" (plr-spec (plr-pod :requests nil :limits nil)))))))

(test pod-level-resources-replace-the-container-sums
  (let ((pod (plr-pod :requests '("cpu" "1" "memory" "1Gi") :limits '("cpu" "2")
                      :containers (list (plr-container "a" :requests '("cpu" "100m" "memory" "10Mi")
                                                           :limits '("cpu" "500m" "memory" "20Mi"))))))
    (multiple-value-bind (requests limits) (gr8s::pod-spec-resource-totals (plr-spec pod))
      (is (= 1 (gethash "cpu" requests)))
      (is (= (* 1024 1024 1024) (gethash "memory" requests)))
      (is (= 2 (gethash "cpu" limits)))
      ;; Only what the Pod declares replaces the containers'.
      (is (= (* 20 1024 1024) (gethash "memory" limits))))
    (is (= 1 (gethash "cpu" (gr8s::pod-requests-table pod))))))

(test pod-level-resources-decide-the-qos-class
  (flet ((qos (pod) (gr8s::pod-spec-qos-class (plr-spec pod))))
    (is (equal "Guaranteed" (qos (plr-pod :requests '("cpu" "1" "memory" "1Gi") :limits '("cpu" "1" "memory" "1Gi")))))
    (is (equal "Burstable" (qos (plr-pod :requests '("cpu" "250m" "memory" "32Mi") :limits '("cpu" "1250m" "memory" "64Mi")))))
    ;; Containers that would be Guaranteed don't override a Burstable Pod.
    (is (equal "Burstable" (qos (plr-pod :requests '("cpu" "1") :limits '("cpu" "2")
                                         :containers (list (plr-container "a" :requests '("cpu" "1" "memory" "1Mi")
                                                                              :limits '("cpu" "1" "memory" "1Mi")))))))
    ;; With CPU only it is Burstable, as memory is then BestEffort.
    (is (equal "Burstable" (qos (plr-pod :requests '("cpu" "1") :limits '("cpu" "1")))))))

(test a-container-without-limits-takes-the-pods-own
  (let* ((pod (plr-pod :requests '("cpu" "250m" "memory" "32Mi") :limits '("cpu" "1250m" "memory" "64Mi")
                       :containers (list (gr8s::core-object "name" "dapi-container" "image" "busybox")
                                         (plr-container "own" :limits '("cpu" "200m" "memory" "16Mi")))))
         (spec (plr-spec pod)))
    (flet ((downward (container resource &optional divisor)
             (gr8s::downward-resource-value
              pod (let ((reference (gr8s::core-object "containerName" container "resource" resource)))
                    (when divisor (setf (gethash "divisor" reference) divisor))
                    reference))))
      ;; As upstream's "should provide default limits.cpu/memory from pod level resources".
      (is (equal "2" (downward "dapi-container" "limits.cpu")))
      (is (equal "67108864" (downward "dapi-container" "limits.memory")))
      (is (equal "1" (downward "own" "limits.cpu")))
      (is (equal "16777216" (downward "own" "limits.memory")))
      (is (equal "0" (downward "dapi-container" "requests.cpu"))))
    (let ((resources (gr8s::cri-linux-container-resources
                      (gr8s::container-with-pod-level-limits spec (aref (gethash "containers" spec) 0)))))
      (is (= 125000 (slot-value resources 'gr8s.cri.v1::cpu-quota)))
      (is (= 67108864 (slot-value resources 'gr8s.cri.v1::memory-limit-in-bytes))))
    ;; The Pod object itself is not changed.
    (is (null (gethash "resources" (aref (gethash "containers" spec) 0)))))
  ;; Without a pod-level memory limit, node allocatable remains the default.
  (let ((pod (plr-pod :requests '("cpu" "250m" "memory" "32Mi") :limits '("cpu" "1250m"))))
    (is (equal (write-to-string (gr8s::node-allocatable-memory))
               (gr8s::downward-resource-value pod (gr8s::core-object "containerName" "app" "resource" "limits.memory"))))))
