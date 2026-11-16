;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Pull images in the background, so a slow registry holds up only the containers
;;;; waiting for that image and never reconciliation of other Pods on the node. A
;;;; container waits while its image arrives; a failed pull is reported as a kubelet
;;;; reports it and retried after a backoff, without consuming a container attempt.

(in-package #:gr8s.kubelet)

(defparameter +image-pull-backoff-seconds+ 10
  "How long a failed pull is reported before another is attempted.")

(defparameter +image-pull-always-freshness-seconds+ 60
  "How long a finished pull satisfies pull policy Always, so a Pod's containers share one.")

(defstruct image-pull-job
  "Track the one background pull of an image: :pulling, :done or :failed.
REPORTED holds the containers already told of its failure, which then see a back-off."
  (state :pulling) message finished-at thread (reported (make-hash-table :test #'equal)))

(defstruct image-pull-manager
  "Own one runtime's background image pulls by image name."
  (jobs (make-hash-table :test #'equal))
  (lock (bt:make-lock "native image pulls")))

(defun prepare-image-mirror-host (runtime image)
  "Install IMAGE's containerd hosts.toml just before PullImage. A runtime with
no managed mirror fields retains the previous external-containerd behavior."
  (let ((directory
          (gr8s.runtime.containerd::containerd-runtime-registry-host-config-directory runtime))
        (port (gr8s.runtime.containerd::containerd-runtime-image-mirror-port runtime)))
    (when (and directory port)
      (let* ((repository (image-repository image))
             (slash (position #\/ repository))
             (host (if slash (subseq repository 0 slash) repository)))
        (gr8s.image-distribution::ensure-containerd-registry-host-config
         directory host port)))))

(defun start-image-pull (runtime manager image credentials)
  "Replace the pull record of IMAGE and CREDENTIALS with a running background pull."
  (let ((job (make-image-pull-job)) (clock *container-lifecycle-clock*))
    (setf (gethash (image-pull-job-key image credentials) (image-pull-manager-jobs manager)) job
          (image-pull-job-thread job)
          (bt:make-thread
           (lambda ()
             (handler-case
                 (progn
                   (prepare-image-mirror-host runtime image)
                   (pull-image-with-credentials (containerd-runtime-socket-path runtime) image credentials)
                   (bt:with-lock-held ((image-pull-manager-lock manager))
                     (setf (image-pull-job-state job) :done
                           (image-pull-job-finished-at job) (funcall clock))))
               (error (condition)
                 (bt:with-lock-held ((image-pull-manager-lock manager))
                   (setf (image-pull-job-state job) :failed
                         (image-pull-job-message job) (princ-to-string condition)
                         (image-pull-job-finished-at job) (funcall clock))))))
           :name (format nil "image pull ~A" image)))
    job))

(defun default-image-pull-policy (image)
  "Return the pull policy SetDefaults_Container gives IMAGE: Always when its tag is latest,
which an image naming neither a tag nor a digest has (parsers.ParseImageName), else IfNotPresent."
  (let* ((at (position #\@ image))
         (name (if at (subseq image 0 at) image))
         (slash (position #\/ name :from-end t))
         (colon (position #\: name :start (if slash (1+ slash) 0)))
         (tag (and colon (subseq name (1+ colon)))))
    (if (or (equal tag "latest") (and (null tag) (null at))) "Always" "IfNotPresent")))

(defun ensure-container-image (runtime image policy &optional (credentials (constantly nil)) requester)
  "Return once IMAGE may be used under pull POLICY, or signal why its container must wait.
CREDENTIALS is called for the registry credentials only if a pull is needed. A failed pull is
reported to REQUESTER, its container, as ErrImagePull once and then as ImagePullBackOff until
the next pull, as a kubelet reports it."
  (let ((socket (containerd-runtime-socket-path runtime)))
    (when (or (equal policy "Never")
              (and (equal policy "IfNotPresent") (cri-image-present-p socket image)))
      (when (and (equal policy "Never") (not (cri-image-present-p socket image)))
        (error 'gr8s.runtime:container-image-never-pull
               :message (format nil "Container image ~S is not present with pull policy of Never" image)))
      (return-from ensure-container-image t))
    (let ((manager (containerd-runtime-images runtime)) (now (funcall *container-lifecycle-clock*))
          (credentials (funcall credentials)))
      (bt:with-lock-held ((image-pull-manager-lock manager))
        (let* ((job (gethash (image-pull-job-key image credentials) (image-pull-manager-jobs manager)))
               (age (and job (image-pull-job-finished-at job) (- now (image-pull-job-finished-at job)))))
          (cond
            ((null job) (start-image-pull runtime manager image credentials))
            ((eq :pulling (image-pull-job-state job)))
            ((eq :done (image-pull-job-state job))
             (when (or (equal policy "IfNotPresent") (< age +image-pull-always-freshness-seconds+))
               (return-from ensure-container-image t))
             (start-image-pull runtime manager image credentials))
            ((< age +image-pull-backoff-seconds+)
             (let ((reported (and requester (gethash requester (image-pull-job-reported job)))))
               (when requester (setf (gethash requester (image-pull-job-reported job)) t))
               (if reported
                   (error 'gr8s.runtime:container-image-pull-backoff
                          :image image
                          :message (format nil "Back-off pulling image ~S: ErrImagePull: ~A"
                                           image (image-pull-job-message job)))
                   (error 'container-image-pull-error :image image :message (image-pull-job-message job)))))
            (t (start-image-pull runtime manager image credentials)))))
      (error 'container-image-pending :message (format nil "Pulling image ~S" image)))))
