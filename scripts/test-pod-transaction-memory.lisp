;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;; sbcl --dynamic-space-size 384 --noinform --non-interactive
;;;;   --load scripts/test-pod-transaction-memory.lisp
(require :asdf)
(asdf:load-asd (truename "gr8s.asd"))
(asdf:load-system "gr8s")
(when (uiop:getenv "GR8S_POD_LEGACY_SOURCE") (load (uiop:getenv "GR8S_POD_LEGACY_SOURCE")))
(let* ((root (uiop:ensure-directory-pathname (sb-posix:mkdtemp "/tmp/gr8s-pod-memory-XXXXXX")))
       (store (gr8s:open-store root))
       (population 1024)
       (template "{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"name\":\"sample\",\"namespace\":\"default\"},\"spec\":{\"containers\":[{\"name\":\"main\",\"image\":\"busybox\"}]}}")
       (payload (make-string (* 64 1024) :element-type 'base-char :initial-element #\x))
       (sent nil))
  (unwind-protect
       (progn
         ;; Seed distinct real Pod files and model objects without retaining a
         ;; second full population in watch history or measuring admission setup.
         (sb-ext:gc :full t)
         (dotimes (i population)
           (when (zerop (mod i 64)) (sb-ext:gc :full t))
           (let* ((pod (gr8s:parse-pod template))
                  (metadata (gethash "metadata" (gr8s:pod-to-object pod)))
                  (name (format nil "sample-~D" i)) (uid (format nil "uid-~D" i))
                  (version (write-to-string (1+ i))))
             (setf (gr8s:pod-name pod) name (gethash "name" metadata) name
                   (gr8s:pod-uid pod) uid (gethash "uid" metadata) uid
                   (gr8s:pod-resource-version pod) version (gethash "resourceVersion" metadata) version
                   (gethash "annotations" metadata) (gr8s::core-object "example.com/data" (copy-seq payload)))
             (gr8s::persist-pod store pod)
             (gr8s::index-pod store pod)))
         (setf (gr8s::pod-store-pod-revision store) population
               (gr8s::pod-store-pod-revision-ceiling store) population
               (gr8s::pod-store-consensus-commit-fn store)
               (lambda (kind json)
                 (push (list kind (length json)) sent)
                 (case kind
                   (:pod-delta (gr8s::install-pod-state-delta store json))
                   (:core-delta (gr8s::install-core-state-delta store json)))))
         (sb-ext:gc :full t)
         (let* ((pod (gr8s:get-pod store "default" "sample-0"))
                (object (gr8s::copy-pod-status-value (gr8s:pod-to-object pod)))
                (started (get-internal-real-time)))
           (setf (gethash "labels" (gethash "metadata" object)) (gr8s::core-object "updated" "yes"))
           (gr8s:update-pod store (gr8s:parse-pod object) (gr8s:pod-resource-version pod))
           (assert (= population (hash-table-count (gr8s::pod-store-pods store))))
           (assert (= 1 (length sent)))
           (assert (eq :pod-delta (caar sent)))
           (assert (< (second (first sent)) (* 80 1024)))
           (assert (equal "yes" (gethash "updated" (gethash "labels" (gethash "metadata"
                             (gr8s:pod-to-object (gr8s:get-pod store "default" "sample-0")))))))
           (format t "~&~A~%" (com.inuoe.jzon:stringify
                               (gr8s::core-object "passed" t "population" population
                                                  "annotationBytesPerPod" (length payload)
                                                  "commands" (length sent) "commandCharacters" (second (first sent))
                                                  "heapLimitMiB" (/ (sb-ext:dynamic-space-size) (* 1024 1024))
                                                  "seconds" (/ (- (get-internal-real-time) started)
                                                               (float internal-time-units-per-second)))))))
    (uiop:delete-directory-tree root :validate t :if-does-not-exist :ignore)))
