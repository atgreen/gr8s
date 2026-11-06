;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; volumeMount.recursiveReadOnly: validation as the API server does it, and the
;;;; CRI mount it asks the runtime for.

(in-package #:gr8s/tests)
(def-suite recursive-read-only :in gr8s)
(in-suite recursive-read-only)

(defun rro-pod-object (&rest mount-fields)
  "Return a Pod object mounting emptyDir data at /data with MOUNT-FIELDS."
  (let ((mount (gr8s::core-object "name" "data" "mountPath" "/data")))
    (loop for (key value) on mount-fields by #'cddr do (setf (gethash key mount) value))
    (gr8s::core-object
     "apiVersion" "v1" "kind" "Pod" "metadata" (gr8s::core-object "name" "rro" "namespace" "default")
     "spec" (gr8s::core-object
             "volumes" (vector (gr8s::core-object "name" "data" "emptyDir" (gr8s::core-object)))
             "containers" (vector (gr8s::core-object "name" "app" "image" "busybox" "volumeMounts" (vector mount)))))))

(test recursive-read-only-mounts-are-validated-as-the-api-server-does
  (dolist (mode '("Disabled" "IfPossible" "Enabled"))
    (is (gr8s::pod-name (parse-pod (rro-pod-object "readOnly" t "recursiveReadOnly" mode)))))
  (is (gr8s::pod-name (parse-pod (rro-pod-object "recursiveReadOnly" "Disabled"))))
  (is (gr8s::pod-name (parse-pod (rro-pod-object "readOnly" t "recursiveReadOnly" "Enabled" "mountPropagation" "None"))))
  (dolist (fields '(("readOnly" t "recursiveReadOnly" "Always")
                    ("recursiveReadOnly" "Enabled")
                    ("readOnly" nil "recursiveReadOnly" "IfPossible")
                    ("readOnly" t "recursiveReadOnly" "Enabled" "mountPropagation" "HostToContainer")))
    (signals kubernetes-error (parse-pod (apply #'rro-pod-object fields)))))

(test recursive-read-only-reaches-the-cri-mount
  (flet ((rro (&rest fields)
           (gr8s::container-mount-recursive-read-only-p
            (aref (gethash "volumeMounts" (aref (gethash "containers" (gethash "spec" (gr8s::pod-to-object (parse-pod (apply #'rro-pod-object fields))))) 0)) 0))))
    (is (rro "readOnly" t "recursiveReadOnly" "Enabled"))
    (is (eq (gr8s::recursive-read-only-mounts-supported-p) (rro "readOnly" t "recursiveReadOnly" "IfPossible")))
    (is (not (rro "readOnly" t "recursiveReadOnly" "Disabled")))
    (is (not (rro "readOnly" t))))
  (let* ((root (uiop:ensure-directory-pathname
                (format nil "/tmp/gr8s-rro-~36R" (random (expt 36 8) (make-random-state t)))))
         (runtime (gr8s::make-containerd-runtime :log-root root))
         (pod (let ((pod (parse-pod (rro-pod-object "readOnly" t "recursiveReadOnly" "Enabled"))))
                (setf (gr8s::pod-uid pod) "uid-rro")
                pod)))
    (unwind-protect
         (let ((mount (first (gr8s::containerd-pod-mounts runtime pod (aref (pod-containers pod) 0)))))
           (is (slot-value mount 'gr8s.cri.v1::readonly))
           (is (slot-value mount 'gr8s.cri.v1::recursive-read-only))
           (is (equal "/data" (slot-value mount 'gr8s.cri.v1::container-path))))
      (uiop:delete-directory-tree root :validate t :if-does-not-exist :ignore))))
