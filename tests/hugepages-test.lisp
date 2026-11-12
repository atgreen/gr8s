;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
(in-package #:gr8s/tests)
(def-suite hugepages :in gr8s)
(in-suite hugepages)

(defun hugepage-test-pod (&key (size "6Mi") requests (page "2Mi") medium)
  (let* ((limits (gr8s.resources::core-object "memory" "32Mi" (concatenate 'string "hugepages-" page) size))
         (resources (gr8s.resources::core-object "limits" limits))
         (spec (gr8s.resources::core-object "containers" (vector (gr8s.resources::core-object "name" "main" "image" "busybox" "resources" resources)))))
    (when requests (setf (gethash "requests" resources) requests))
    (when medium (setf (gethash "volumes" spec) (vector (gr8s.resources::core-object "name" "pages" "emptyDir" (gr8s.resources::core-object "medium" medium)))))
    (parse-pod (gr8s.resources::core-object "apiVersion" "v1" "kind" "Pod" "metadata" (gr8s.resources::core-object "name" "pages") "spec" spec))))

(test hugepages-are-defaulted-indivisible-and-enforced-in-cri
  (let* ((pod (hugepage-test-pod))
         (container (aref (gethash "containers" (gethash "spec" (pod-to-object pod))) 0))
         (cri (gr8s.kubelet::cri-linux-container-resources container))
         (limits (gr8s.cri.v1::hugepage-limits cri)))
    (is (equal "6Mi" (gethash "hugepages-2Mi" (gethash "requests" (gethash "resources" container)))))
    (is-true (plusp (length limits)))
    (setf limits (remove-if-not (lambda (limit) (equal "2MB" (gr8s.cri.v1::page-size limit))) limits))
    (is (equal "2MB" (gr8s.cri.v1::page-size (first limits))))
    (is (= (* 6 1024 1024) (gr8s.cri.v1::limit (first limits)))))
  (dolist (pod (list (lambda () (hugepage-test-pod :size "3Mi"))
                    (lambda () (hugepage-test-pod :page "2048Ki"))
                    (lambda () (hugepage-test-pod :size "-2Mi"))
                    (lambda () (hugepage-test-pod :requests (gr8s.resources::core-object "hugepages-2Mi" "4Mi")))))
    (signals kubernetes-error (funcall pod))))

(test hugepage-capacity-quota-and-scheduling-use-the-real-pool
  (with-temporary-store (store directory)
    (declare (ignore store))
    (let* ((root (merge-pathnames "hugepages/" directory))
           (file (merge-pathnames "hugepages-2048kB/nr_hugepages" root))
           (gr8s.kubelet::*hugepage-sysfs-directory* root))
      (ensure-directories-exist file)
      (with-open-file (out file :direction :output :if-does-not-exist :create) (write-line "32" out))
      (is (equal "67108864" (gethash "hugepages-2Mi" (gr8s.kubelet::node-hugepage-capacity))))))
  (let ((requests (gr8s.resources::core-object "hugepages-2Mi" (* 6 1024 1024))))
    (is-false (gr8s.resources::resource-fit-p requests (gr8s.resources::core-object) nil))
    (is-false (gr8s.resources::resource-fit-p requests (gr8s.resources::core-object "hugepages-2Mi" (* 4 1024 1024)) nil))
    (is-true (gr8s.resources::resource-fit-p requests (gr8s.resources::core-object "hugepages-2Mi" (* 8 1024 1024)) nil))
    (is (= (* 6 1024 1024) (gr8s.resources::quota-pod-usage "requests.hugepages-2Mi" requests (gr8s.resources::core-object))))))

(test hugetlbfs-volume-mounts-the-requested-page-size-and-reservation
  (with-temporary-store (store directory)
    (let* ((pod (create-pod store (hugepage-test-pod :medium "HugePages-2Mi")))
           (runtime (gr8s.runtime.containerd::make-containerd-runtime :log-root (merge-pathnames "logs/" directory)))
           (options nil)
           (gr8s.kubelet::*pod-hugetlbfs-mount* (lambda (path data) (declare (ignore path)) (setf options data) 0)))
      (gr8s.kubelet::materialize-pod-volume runtime pod (aref (gethash "volumes" (gethash "spec" (pod-to-object pod))) 0))
      (is (equal "pagesize=2097152,size=6291456" options))))
  (signals kubernetes-error (hugepage-test-pod :medium "HugePages-1Gi")))

(test hugepage-downward-references-use-byte-reservations-and-zero-for-unset-sizes
  (let* ((pod (hugepage-test-pod :size "6Mi"))
         (reference (gr8s.resources::core-object "containerName" "main" "resource" "limits.hugepages-2Mi" "divisor" "2Mi")))
    (gr8s.kubelet::validate-resource-field-reference reference)
    (is (equal "3" (gr8s.kubelet::downward-resource-value pod reference)))
    (setf (gethash "resource" reference) "limits.hugepages-1Gi")
    (is (equal "0" (gr8s.kubelet::downward-resource-value pod reference)))))

(test cri-hugepage-units-cover-sub-mib-and-large-pools
  (is (equal "64KB" (gr8s.kubelet::cri-hugepage-size (* 64 1024)))))
