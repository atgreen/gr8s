;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; env valueFrom.fileKeyRef: validation as the API server does it, the env file
;;;; format the kubelet's ParseEnv reads, and resolution from a Pod's emptyDir.

(in-package #:gr8s/tests)
(def-suite env-files :in gr8s)
(in-suite env-files)

(defun file-key-pod-object (selector &key (volume (gr8s.resources::core-object "name" "config" "emptyDir" (gr8s.resources::core-object))))
  "Return a Pod object whose container reads CONFIG from SELECTOR, with VOLUME."
  (gr8s.resources::core-object
   "apiVersion" "v1" "kind" "Pod" "metadata" (gr8s.resources::core-object "name" "files" "namespace" "default")
   "spec" (gr8s.resources::core-object
           "volumes" (if volume (vector volume) #())
           "containers" (vector (gr8s.resources::core-object
                                 "name" "app" "image" "busybox"
                                 "env" (vector (gr8s.resources::core-object "name" "CONFIG"
                                                                  "valueFrom" (gr8s.resources::core-object "fileKeyRef" selector))))))))

(defun file-key-selector (&rest fields)
  "Return a fileKeyRef reading CONFIG_1 from config.env in volume config, with FIELDS overriding."
  (let ((selector (gr8s.resources::core-object "volumeName" "config" "path" "config.env" "key" "CONFIG_1")))
    (loop for (key value) on fields by #'cddr do (setf (gethash key selector) value))
    selector))

(test file-key-references-are-validated-as-the-api-server-does
  (is (gr8s.model::pod-name (parse-pod (file-key-pod-object (file-key-selector "optional" t)))))
  (dolist (selector (list (file-key-selector "key" "")
                          (file-key-selector "key" "A=B")
                          (file-key-selector "volumeName" "")
                          (file-key-selector "volumeName" "Not_A_Label")
                          (file-key-selector "path" "")
                          (file-key-selector "path" "../escape.env")
                          (file-key-selector "optional" "yes")
                          (file-key-selector "extra" 1)))
    (signals kubernetes-error (parse-pod (file-key-pod-object selector))))
  ;; The volume must exist and be an emptyDir.
  (signals kubernetes-error (parse-pod (file-key-pod-object (file-key-selector "volumeName" "missing"))))
  (signals kubernetes-error
    (parse-pod (file-key-pod-object (file-key-selector)
                                    :volume (gr8s.resources::core-object "name" "config"
                                                               "hostPath" (gr8s.resources::core-object "path" "/tmp"))))))

(test env-files-are-read-as-the-kubelets-parse-env-reads-them
  (flet ((value (text key) (gr8s.kubelet::parse-environment-file-value text key)))
    (let ((text (format nil "# settings~%~%CONFIG_1='value1'~%  CONFIG_2='two words' # note~%MULTI='a~%b'~%EMPTY= 'ignored'~%")))
      (is (equal "value1" (value text "CONFIG_1")))
      (is (equal "two words" (value text "CONFIG_2")))
      (is (equal (format nil "a~%b") (value text "MULTI")))
      ;; Whitespace after '=' leaves the variable empty, as bash does.
      (is (equal "" (value text "EMPTY")))
      (is (null (value text "MISSING"))))
    ;; A key found before a malformed line is still read.
    (is (equal "x" (value (format nil "A='x'~%broken~%") "A")))
    (dolist (bad (list "NOEQUALS" "A=unquoted" "A ='spaced'" "A='x' trailing" "A='unclosed" "='nameless'"))
      (signals error (value bad "B")))))

(test file-key-values-come-from-the-pods-empty-dir
  (let* ((root (uiop:ensure-directory-pathname
                (format nil "/tmp/gr8s-env-files-~36R" (random (expt 36 8) (make-random-state t)))))
         (runtime (gr8s.runtime.containerd::make-containerd-runtime :log-root root))
         (pod (let ((pod (parse-pod (file-key-pod-object (file-key-selector)))))
                (setf (gr8s.model::pod-uid pod) "uid-env-files")
                pod)))
    (unwind-protect
         (let ((file (merge-pathnames "config.env" (gr8s.kubelet::pod-volume-directory runtime pod "config"))))
           ;; Before anything writes the file, the container cannot be configured.
           (signals gr8s.runtime::container-config-error
             (gr8s.kubelet::containerd-file-key-environment-value runtime pod (file-key-selector)))
           (ensure-directories-exist file)
           (with-open-file (out file :direction :output :if-exists :supersede)
             (format out "CONFIG_1='value1'~%"))
           (is (equal '("value1" t) (multiple-value-list
                                      (gr8s.kubelet::containerd-file-key-environment-value runtime pod (file-key-selector)))))
           (is (equal '(nil nil) (multiple-value-list
                                  (gr8s.kubelet::containerd-file-key-environment-value
                                   runtime pod (file-key-selector "key" "MISSING" "optional" t)))))
           (signals gr8s.runtime::container-config-error
             (gr8s.kubelet::containerd-file-key-environment-value runtime pod (file-key-selector "key" "MISSING")))
           ;; The environment the container gets carries the value.
           (is (equal "value1" (cdr (assoc "CONFIG" (gr8s.kubelet::containerd-pod-environment runtime pod (aref (pod-containers pod) 0) nil)
                                           :test #'equal)))))
      (uiop:delete-directory-tree root :validate t :if-does-not-exist :ignore))))

(test fields-off-by-default-in-v1-37-are-dropped-not-refused
  ;; ContainerStopSignals (alpha) and GenericWorkload (beta) are off by default, so the API
  ;; server's dropDisabledPodFields clears lifecycle.stopSignal and spec.schedulingGroup.
  (let* ((object (file-key-pod-object (file-key-selector)))
         (spec (gethash "spec" object))
         (container (aref (gethash "containers" spec) 0)))
    (setf (gethash "lifecycle" container) (gr8s.resources::core-object "stopSignal" "SIGUSR1")
          (gethash "schedulingGroup" spec) (gr8s.resources::core-object "podGroupName" "group"))
    (let ((parsed (gethash "spec" (gr8s.model::pod-to-object (parse-pod object)))))
      (is (null (nth-value 1 (gethash "schedulingGroup" parsed))))
      (is (null (nth-value 1 (gethash "stopSignal" (gethash "lifecycle" (aref (gethash "containers" parsed) 0)))))))))

(test container-stop-signals-arrive-with-v1-38
  ;; podster-i18c.4: ContainerStopSignals is beta and on by default from v1.38. The API keeps
  ;; lifecycle.stopSignal, checks it against the Pod's OS as upstream does, and the runtime
  ;; stops the container with it.
  (is-true (gr8s.foundation::kubernetes-minor-at-least-p 37))
  (is-false (gr8s.foundation::kubernetes-minor-at-least-p 99))
  (flet ((pod-with (signal &optional os)
           (let* ((object (file-key-pod-object (file-key-selector)))
                  (spec (gethash "spec" object)))
             (setf (gethash "lifecycle" (aref (gethash "containers" spec) 0))
                   (gr8s.resources::core-object "stopSignal" signal))
             (when os (setf (gethash "os" spec) (gr8s.resources::core-object "name" os)))
             object))
         (kept-signal (object)
           (gethash "stopSignal" (gethash "lifecycle" (aref (gethash "containers"
                                                                     (gethash "spec" (gr8s.model::pod-to-object (parse-pod object))))
                                                              0)))))
    (with-replaced-functions ((gr8s.foundation::kubernetes-minor-at-least-p (lambda (minor) (<= minor 38))))
      (is (equal "SIGUSR1" (kept-signal (pod-with "SIGUSR1" "linux"))))
      (is (equal "SIGRTMIN+3" (kept-signal (pod-with "SIGRTMIN+3" "linux"))))
      (is (equal "SIGTERM" (kept-signal (pod-with "SIGTERM" "windows"))))
      (signals gr8s.model:kubernetes-error (parse-pod (pod-with "SIGUSR1")))
      (signals gr8s.model:kubernetes-error (parse-pod (pod-with "SIGUSR1" "windows")))
      (signals gr8s.model:kubernetes-error (parse-pod (pod-with "SIGNOPE" "linux")))))
  ;; The runtime's names for them, both ways.
  (is (= 23 (gr8s.runtime.containerd::cri-stop-signal "SIGTERM")))
  (is (= gr8s.cri.v1::+signal-sigrtminplus1+ (gr8s.runtime.containerd::cri-stop-signal "SIGRTMIN+1")))
  (is (= gr8s.cri.v1::+signal-sigrtmaxminus1+ (gr8s.runtime.containerd::cri-stop-signal "SIGRTMAX-1")))
  (is (= 0 (gr8s.runtime.containerd::cri-stop-signal nil)))
  (is (every (lambda (name) (plusp (gr8s.runtime.containerd::cri-stop-signal name)))
             gr8s.runtime.containerd::+linux-stop-signals+))
  (is (= (length gr8s.runtime.containerd::+linux-stop-signals+)
         (length (remove-duplicates (mapcar #'gr8s.runtime.containerd::cri-stop-signal
                                            gr8s.runtime.containerd::+linux-stop-signals+)))))
  (is (equal "SIGRTMAX-1" (gr8s.runtime.containerd::cri-stop-signal-name gr8s.cri.v1::+signal-sigrtmaxminus1+)))
  (is (null (gr8s.runtime.containerd::cri-stop-signal-name 0)))
  ;; The container's config carries it.
  (is (= gr8s.cri.v1::+signal-sigusr1+ (gr8s.cri.v1::stop-signal
             (gr8s.runtime.containerd::make-cri-container-config :name "c" :image "i" :stop-signal "SIGUSR1"))))
  (is (= 0 (gr8s.cri.v1::stop-signal (gr8s.runtime.containerd::make-cri-container-config :name "c" :image "i")))))
