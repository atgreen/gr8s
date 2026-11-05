;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Pull images in the background, so a slow registry holds up only the containers
;;;; waiting for that image and never reconciliation of other Pods on the node. A
;;;; container waits while its image arrives; a failed pull is reported as a kubelet
;;;; reports it and retried after a backoff, without consuming a container attempt.

(in-package #:gr8s)

(defparameter +image-pull-backoff-seconds+ 10
  "How long a failed pull is reported before another is attempted.")

(defparameter +image-pull-always-freshness-seconds+ 60
  "How long a finished pull satisfies pull policy Always, so a Pod's containers share one.")

(defstruct image-pull-job
  "Track the one background pull of an image: :pulling, :done or :failed."
  (state :pulling) message finished-at thread)

(defstruct image-pull-manager
  "Own one runtime's background image pulls by image name."
  (jobs (make-hash-table :test #'equal))
  (lock (bt:make-lock "native image pulls")))

(defun start-image-pull (runtime manager image)
  "Replace IMAGE's pull record with a running background pull."
  (let ((job (make-image-pull-job)) (clock *container-lifecycle-clock*))
    (setf (gethash image (image-pull-manager-jobs manager)) job
          (image-pull-job-thread job)
          (bt:make-thread
           (lambda ()
             (handler-case
                 (progn
                   (cri-pull-image (containerd-runtime-socket-path runtime) image)
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

(defun ensure-container-image (runtime image policy)
  "Return once IMAGE may be used under pull POLICY, or signal why its container must wait."
  (let ((socket (containerd-runtime-socket-path runtime)))
    (when (or (equal policy "Never")
              (and (equal policy "IfNotPresent") (cri-image-present-p socket image)))
      (when (and (equal policy "Never") (not (cri-image-present-p socket image)))
        (error 'container-config-error
               :message (format nil "Container image ~S is not present with pull policy of Never" image)))
      (return-from ensure-container-image t))
    (let ((manager (containerd-runtime-images runtime)) (now (funcall *container-lifecycle-clock*)))
      (bt:with-lock-held ((image-pull-manager-lock manager))
        (let* ((job (gethash image (image-pull-manager-jobs manager)))
               (age (and job (image-pull-job-finished-at job) (- now (image-pull-job-finished-at job)))))
          (cond
            ((null job) (start-image-pull runtime manager image))
            ((eq :pulling (image-pull-job-state job)))
            ((eq :done (image-pull-job-state job))
             (when (or (equal policy "IfNotPresent") (< age +image-pull-always-freshness-seconds+))
               (return-from ensure-container-image t))
             (start-image-pull runtime manager image))
            ((< age +image-pull-backoff-seconds+)
             (error 'container-image-pull-error :message (image-pull-job-message job)))
            (t (start-image-pull runtime manager image)))))
      (error 'container-image-pending :message (format nil "Pulling image ~S" image)))))
