;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Verify exact Kubernetes quantity handling, honest refusal of resources with
;;;; no enforcement, and the kubelet's CFS and memory formulas sent through CRI.

(in-package #:gr8s/tests)
(def-suite container-resources :in gr8s)
(in-suite container-resources)

(defun resource-test-pod (resources-json)
  "Return a Pod whose only container declares the RESOURCES-JSON object."
  (parse-pod (format nil "{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"name\":\"limited\"},\"spec\":{\"containers\":[{\"name\":\"c\",\"image\":\"busybox:latest\",\"resources\":~A}]}}" resources-json)))

(defun resource-test-container (pod)
  "Return POD's only container JSON object."
  (aref (gethash "containers" (gethash "spec" (pod-to-object pod))) 0))

(defun resource-test-cri (resources-json)
  "Return the CRI resources derived from RESOURCES-JSON."
  (gr8s::cri-linux-container-resources (resource-test-container (resource-test-pod resources-json))))

(test quantities-round-trip-exactly-without-floating-point
  (loop for (input expected) in '(("100m" 100) ("1" 1000) ("0.5" 500) ("1.5" 1500) ("2k" 2000000)
                                  ("1e3" 1000000) ("0.0001" 1) ("1001u" 2))
        do (is (= expected (gr8s::container-milli-cpu (gr8s::parse-container-quantity input))) input))
  (loop for (input expected) in '(("128Mi" 134217728) ("1Gi" 1073741824) ("1G" 1000000000)
                                  ("1500M" 1500000000) ("64" 64) ("1.5Ki" 1536))
        do (is (= expected (gr8s::container-quantity-integer (gr8s::parse-container-quantity input))) input))
  (dolist (bad '("" "1x" "abc" "1.2.3" "--1"))
    (signals kubernetes-error (gr8s::parse-container-quantity bad)))
  ;; An enormous exponent must be refused rather than computed.
  (signals kubernetes-error (gr8s::container-quantity-integer (gr8s::parse-container-quantity "1e4000"))))

(test limits-become-the-kubelets-cgroup-values
  (let ((cri (resource-test-cri "{\"limits\":{\"cpu\":\"250m\",\"memory\":\"64Mi\"},\"requests\":{\"cpu\":\"100m\"}}")))
    (is (= 100000 (gr8s.cri.v1::cpu-period cri)))
    (is (= 25000 (gr8s.cri.v1::cpu-quota cri)))
    (is (= 102 (gr8s.cri.v1::cpu-shares cri)))
    (is (= 67108864 (gr8s.cri.v1::memory-limit-in-bytes cri))))
  ;; A request alone sets shares but imposes no throttling or memory limit.
  (let ((cri (resource-test-cri "{\"requests\":{\"cpu\":\"2\",\"memory\":\"64Mi\"}}")))
    (is (= 2048 (gr8s.cri.v1::cpu-shares cri)))
    (is (= 0 (gr8s.cri.v1::cpu-quota cri)))
    (is (= 0 (gr8s.cri.v1::cpu-period cri)))
    (is (= 0 (gr8s.cri.v1::memory-limit-in-bytes cri))))
  ;; Very small limits keep the kubelet's floors.
  (let ((cri (resource-test-cri "{\"limits\":{\"cpu\":\"1m\"}}")))
    (is (= 1000 (gr8s.cri.v1::cpu-quota cri)))
    (is (= 2 (gr8s.cri.v1::cpu-shares cri)))))

(test empty-resources-stay-unlimited-with-the-minimum-cpu-share
  (dolist (resources '("{}" "{\"limits\":{},\"requests\":{}}" "{\"limits\":null}"))
    (let ((cri (resource-test-cri resources)))
      (is (= 2 (gr8s.cri.v1::cpu-shares cri)) "the minimum share, as a kubelet gives")
      (is (= 0 (gr8s.cri.v1::cpu-quota cri)))
      (is (= 0 (gr8s.cri.v1::memory-limit-in-bytes cri))))))

(test pods-default-requests-from-limits-and-keep-declared-requests
  (let* ((pod (resource-test-pod "{\"limits\":{\"cpu\":\"1\",\"memory\":\"1Gi\"},\"requests\":{\"cpu\":\"500m\"}}"))
         (requests (gethash "requests" (gethash "resources" (resource-test-container pod)))))
    (is (equal "500m" (gethash "cpu" requests)))
    (is (equal "1Gi" (gethash "memory" requests)))))

(test unenforceable-or-inconsistent-resources-are-refused
  (dolist (resources '("{\"limits\":{\"hugepages-2Mi\":\"1Gi\"}}"
                       "{\"requests\":{\"nvidia.com/gpu\":\"1\"}}"
                       "{\"limits\":{\"cpu\":\"-1\"}}"
                       "{\"limits\":{\"cpu\":\"100m\"},\"requests\":{\"cpu\":\"200m\"}}"
                       "{\"claims\":[{\"name\":\"gpu\"}]}"
                       "{\"limits\":{\"cpu\":\"lots\"}}"
                       "{\"unknown\":{}}"))
    (signals kubernetes-error (resource-test-pod resources))))

(test init-containers-get-their-own-cgroup-values
  (let* ((pod (parse-pod "{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"name\":\"i\"},\"spec\":{\"initContainers\":[{\"name\":\"init\",\"image\":\"busybox:latest\",\"resources\":{\"limits\":{\"cpu\":\"100m\"}}}],\"containers\":[{\"name\":\"c\",\"image\":\"busybox:latest\"}]}}"))
         (init (aref (gethash "initContainers" (gethash "spec" (pod-to-object pod))) 0)))
    (is (= 10000 (gr8s.cri.v1::cpu-quota (gr8s::cri-linux-container-resources init))))))
