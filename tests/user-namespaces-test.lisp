;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; spec.hostUsers: validation as the API server does it, the distinct and stable
;;;; host ID block each user-namespaced Pod gets, and the CRI namespace options
;;;; that carry it to the sandbox and every container.

(in-package #:gr8s/tests)
(def-suite user-namespaces :in gr8s)
(in-suite user-namespaces)

(defun userns-pod (name &rest spec-fields)
  "Parse a Pod NAME with SPEC-FIELDS, giving it a UID of its own."
  (let ((object (com.inuoe.jzon:parse *valid-pod-json*)))
    (setf (gethash "name" (gethash "metadata" object)) name)
    (loop for (key value) on spec-fields by #'cddr do (setf (gethash key (gethash "spec" object)) value))
    (let ((pod (parse-pod object)))
      (setf (gr8s::pod-uid pod) (format nil "uid-~A" name))
      pod)))

(test host-users-is-validated-as-the-api-server-does
  (is (gr8s::pod-host-users-p (userns-pod "default")))
  (is (gr8s::pod-host-users-p (userns-pod "shared" "hostUsers" t)))
  (is (not (gr8s::pod-host-users-p (userns-pod "own" "hostUsers" nil))))
  (dolist (field '("hostNetwork" "hostPID" "hostIPC"))
    (signals kubernetes-error (userns-pod "conflict" "hostUsers" nil field t))
    (is (gr8s::pod-name (userns-pod "allowed" "hostUsers" t field t))))
  (signals kubernetes-error (userns-pod "bad" "hostUsers" "no")))

(test each-user-namespaced-pod-gets-a-distinct-stable-block
  (let* ((root (uiop:ensure-directory-pathname
                (format nil "/tmp/gr8s-userns-~36R" (random (expt 36 8) (make-random-state t)))))
         (runtime (gr8s::make-containerd-runtime :log-root root))
         (first (userns-pod "first" "hostUsers" nil))
         (second (userns-pod "second" "hostUsers" nil)))
    (unwind-protect
         (flet ((host-id (pod)
                  (let ((namespace (gr8s::containerd-pod-user-namespace runtime pod)))
                    (is (= gr8s.cri.v1::+namespacemode-pod+ (gr8s.cri.v1::mode namespace)))
                    (dolist (mappings (list (gr8s.cri.v1::uids namespace) (gr8s.cri.v1::gids namespace)))
                      (is (= 1 (length mappings)))
                      (is (= 0 (gr8s.cri.v1::container-id (first mappings))))
                      (is (= 65536 (gr8s.cri.v1::proto-id-mapping-length (first mappings)))))
                    (gr8s.cri.v1::host-id (first (gr8s.cri.v1::uids namespace))))))
           (let ((one (host-id first)) (two (host-id second)))
             ;; Host ID 0 is never mapped, and two Pods never share a block.
             (is (= 65536 one))
             (is (= 131072 two))
             ;; A Pod keeps its block, and a restarted agent finds it again.
             (is (= one (host-id first)))
             (let ((restarted (gr8s::make-containerd-runtime :log-root root)))
               (is (= two (gr8s.cri.v1::host-id
                           (first (gr8s.cri.v1::uids (gr8s::containerd-pod-user-namespace restarted second)))))))
             ;; Once its Pod is gone, a block is free again.
             (gr8s::cleanup-pod-volumes runtime (pod-uid first))
             (is (= one (host-id (userns-pod "third" "hostUsers" nil)))))
           ;; A Pod in the node's user namespace asks for none.
           (is (null (gr8s::containerd-pod-user-namespace runtime (userns-pod "host")))))
      (uiop:delete-directory-tree root :validate t :if-does-not-exist :ignore))))

(test the-sandbox-and-every-container-use-the-pods-user-namespace
  (let* ((namespace (make-instance 'gr8s.cri.v1::user-namespace :mode gr8s.cri.v1::+namespacemode-pod+))
         (pod (userns-pod "own" "hostUsers" nil))
         (sandbox (gr8s::make-cri-pod-sandbox-config "own" "uid-own" "default" 0 "/tmp/logs" nil :userns namespace))
         (container (gr8s::containerd-pod-security-context pod (aref (pod-containers pod) 0) :userns namespace)))
    (is (eq namespace (gr8s.cri.v1::userns-options
                       (gr8s.cri.v1::namespace-options
                        (gr8s.cri.v1::security-context (gr8s.cri.v1::linux sandbox))))))
    (is (eq namespace (gr8s.cri.v1::userns-options (gr8s.cri.v1::namespace-options container))))))

(test every-mount-of-a-user-namespaced-pod-is-idmapped
  ;; As the kubelet's applyPlatformSpecificContainerConfig does, so files keep their owners inside.
  (let* ((mapping (make-instance 'gr8s.cri.v1::id-mapping :host-id 65536 :container-id 0 :length 65536))
         (own (make-instance 'gr8s.cri.v1::user-namespace :mode gr8s.cri.v1::+namespacemode-pod+
                                                          :uids (list mapping) :gids (list mapping)))
         (mounts (list (make-instance 'gr8s.cri.v1::mount :container-path "/a" :host-path "/x")
                       (make-instance 'gr8s.cri.v1::mount :container-path "/b" :host-path "/y"))))
    (gr8s::map-mounts-into-user-namespace mounts own)
    (dolist (mount mounts)
      (is (equal (list mapping) (gr8s.cri.v1::uidmappings mount)))
      (is (equal (list mapping) (gr8s.cri.v1::gidmappings mount))))
    ;; A Pod in the node's user namespace mounts as it always did.
    (let ((plain (list (make-instance 'gr8s.cri.v1::mount :container-path "/a" :host-path "/x"))))
      (gr8s::map-mounts-into-user-namespace plain nil)
      (is (null (gr8s.cri.v1::uidmappings (first plain)))))))

(test user-namespaced-pod-starts-are-counted-as-the-kubelet-counts-them
  (let ((gr8s::*kubelet-instrumentation* (gr8s::make-kubelet-instrumentation)))
    (gr8s::note-user-namespaced-pod-start t)
    (gr8s::note-user-namespaced-pod-start nil)
    (let ((text (gr8s::kubelet-instrumentation-text)))
      (is (search (format nil "kubelet_started_user_namespaced_pods_total 2~%") text))
      (is (search (format nil "kubelet_started_user_namespaced_pods_errors_total 1~%") text)))))
