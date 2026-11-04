;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Verify admitted Pod hostname/subdomain fields execute through CRI UTS names,
;;;; immutable updates and actual Pod-owned hosts files using real sandbox addresses.

(in-package #:gr8s/tests)
(def-suite pod-hostname :in gr8s)
(in-suite pod-hostname)

(defun hostname-test-object (&optional (hostname "short") (subdomain "headless"))
  "Build an ordinary Pod with explicit hostname and DNS subdomain."
  (let ((object (com.inuoe.jzon:parse *valid-pod-json*)))
    (setf (gethash "hostname" (gethash "spec" object)) hostname
          (gethash "subdomain" (gethash "spec" object)) subdomain)
    object))

(test pod-hostname-validation-and-real-sandbox-configuration
  (let* ((pod (parse-pod (hostname-test-object)))
         (runtime (gr8s::make-containerd-runtime :host-network nil))
         (config (gr8s::containerd-sandbox-config runtime pod)))
    (is (equal "short" (gr8s::pod-runtime-hostname pod)))
    (is (equal "headless.default.svc.cluster.local" (gr8s::pod-runtime-domain pod)))
    (is (equal "short" (slot-value config 'gr8s.cri.v1::hostname)))
    (setf (gr8s::containerd-runtime-host-network runtime) t)
    (is (equal "" (slot-value (gr8s::containerd-sandbox-config runtime pod) 'gr8s.cri.v1::hostname))))
  (is (equal "hello" (gr8s::pod-runtime-hostname (parse-pod (hostname-test-object "" "")))))
  (dolist (value (list "Upper" "a.b" "a/b" "has space" (format nil "bad~%line")))
    (signals gr8s:kubernetes-error (parse-pod (hostname-test-object value)))
    (signals gr8s:kubernetes-error (parse-pod (hostname-test-object "short" value))))
  (signals gr8s:kubernetes-error (parse-pod (hostname-test-object (make-string 64 :initial-element #\a)))))

(test pod-hostname-and-subdomain-are-immutable-before-scheduling
  (with-temporary-store (store directory)
    (let* ((pod (create-pod store (parse-pod (hostname-test-object))))
           (object (gr8s::copy-core-object (pod-to-object pod))))
      (setf (gethash "hostname" (gethash "spec" object)) "changed")
      (signals gr8s:kubernetes-error (gr8s::update-pod store (parse-pod object) (pod-resource-version pod)))
      (setf (gethash "hostname" (gethash "spec" object)) "short"
            (gethash "subdomain" (gethash "spec" object)) "changed")
      (signals gr8s:kubernetes-error (gr8s::update-pod store (parse-pod object) (pod-resource-version pod)))
      (is (equal "short" (gethash "hostname" (gethash "spec" (pod-to-object (get-pod store "default" "hello")))))))))

(test pod-hosts-file-is-actually-written-from-the-sandbox-ip
  (with-temporary-store (store directory)
    (let* ((pod (create-pod store (parse-pod (hostname-test-object))))
           (runtime (gr8s::%make-containerd-runtime :host-network nil :log-root directory :resource-store store))
           (original (symbol-function 'gr8s::cri-pod-sandbox-ip))
           (calls 0))
      (unwind-protect
           (progn
             (setf (symbol-function 'gr8s::cri-pod-sandbox-ip)
                   (lambda (socket sandbox-id)
                     (declare (ignore socket)) (is (equal "actual-sandbox" sandbox-id))
                     (incf calls) "192.0.2.55"))
             (let* ((mounts (gr8s::containerd-container-mounts runtime pod (aref (pod-containers pod) 0) "actual-sandbox"))
                    (mount (first mounts))
                    (content (uiop:read-file-string (slot-value mount 'gr8s.cri.v1::host-path))))
               (is (= 1 (length mounts)))
               (is (equal "/etc/hosts" (slot-value mount 'gr8s.cri.v1::container-path)))
               (is (search (format nil "192.0.2.55~Cshort.headless.default.svc.cluster.local~Cshort" #\Tab #\Tab) content))
               (is (search "localhost" content)))
             (setf (gr8s::containerd-runtime-host-network runtime) t)
             (is (null (gr8s::containerd-container-mounts runtime pod (aref (pod-containers pod) 0) "actual-sandbox")))
             (is (= 1 calls)))
        (setf (symbol-function 'gr8s::cri-pod-sandbox-ip) original)))))
