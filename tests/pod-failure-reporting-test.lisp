;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Verify a Pod that can't run says why, in the fields and Events kubectl already
;;;; shows, worded as a kubelet words them: missing volumes, failed and backed-off
;;;; image pulls, refused creates, crash loops and evictions.

(in-package #:gr8s/tests)
(def-suite pod-failure-reporting :in gr8s)
(in-suite pod-failure-reporting)

(defun configmap-volume-pod (store &key optional)
  "Create a Pod mounting ConfigMap \"missing\", which doesn't exist, as volume \"cfg\"."
  (create-pod store
              (parse-pod (format nil "{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"name\":\"cfg\",\"namespace\":\"default\"},\"spec\":{\"volumes\":[{\"name\":\"cfg\",\"configMap\":{\"name\":\"missing\"~:[~;,\"optional\":true~]}}],\"containers\":[{\"name\":\"main\",\"image\":\"busybox:1\",\"volumeMounts\":[{\"name\":\"cfg\",\"mountPath\":\"/cfg\"}]}]}}" optional))))

(defun pod-events-with (runtime pod reason)
  "Return the queued node Events for POD with REASON."
  (remove-if-not (lambda (event) (equal reason (gethash "reason" event)))
                 (coerce (gr8s.runtime::runtime-events runtime (pod-uid pod)) 'list)))

(defun container-waiting (observed name)
  (let ((status (find name (gethash "containerStatuses" (gr8s.runtime::runtime-pod-status observed))
                      :key (lambda (status) (gethash "name" status)) :test #'equal)))
    (and status (gethash "waiting" (gethash "state" status)))))

;;; A missing ConfigMap volume

(test a-missing-configmap-volume-says-so-instead-of-failing-the-sync
  (with-temporary-store (store directory)
    (let* ((pod (configmap-volume-pod store))
           (runtime (gr8s.runtime.containerd::make-containerd-runtime :log-root (merge-pathnames "logs/" directory))))
      (setf (gr8s.runtime.containerd::containerd-runtime-resource-store runtime) store)
      (let ((condition (handler-case (progn (gr8s.kubelet::containerd-pod-mounts runtime pod (aref (pod-containers pod) 0)) nil)
                         (error (condition) condition))))
        ;; Before, this was a bare 404 that nothing reported: the Pod said nothing at all.
        (is (typep condition 'gr8s.runtime:volume-mount-error))
        (is (typep condition 'gr8s.runtime:container-config-error) "so the create path catches it")
        (is (equal "MountVolume.SetUp failed for volume \"cfg\" : configmap \"missing\" not found"
                   (gr8s.runtime:runtime-error-message condition)))
        (is (equal "ContainerCreating" (gr8s.kubelet::container-config-error-reason condition)))
        (is (equal '("FailedMount" "Warning")
                   (subseq (multiple-value-list (gr8s.kubelet::container-config-error-event condition)) 0 2)))))))

(test an-optional-missing-configmap-still-mounts
  (with-temporary-store (store directory)
    (let* ((pod (configmap-volume-pod store :optional t))
           (runtime (gr8s.runtime.containerd::make-containerd-runtime :log-root (merge-pathnames "logs/" directory))))
      (setf (gr8s.runtime.containerd::containerd-runtime-resource-store runtime) store)
      (is (= 1 (length (gr8s.kubelet::containerd-pod-mounts runtime pod (aref (pod-containers pod) 0))))))))

;;; How each failure is reported

(defun report-create-failure (condition)
  "Run real convergence while every create fails with CONDITION. Return the runtime, Pod and observation."
  (with-temporary-store (store directory)
    (let* ((now 4000000000) (gr8s.kubelet::*container-lifecycle-clock* (lambda () now))
           (pod (lifecycle-pod store))
           (runtime (gr8s.runtime.containerd::make-containerd-runtime :log-root directory)))
      (with-lifecycle-cri (fixture pod nil)
        (with-replaced-functions ((gr8s.runtime.containerd::containerd-create-container
                                   (lambda (&rest arguments) (declare (ignore arguments)) (error condition))))
          (let ((observed (gr8s.runtime::runtime-ensure runtime pod)))
            (values runtime pod observed (lifecycle-cri-fixture-calls fixture))))))))

(test each-create-failure-has-the-kubelets-reason-and-event
  (loop for (condition reason message event-reason event-type event-message)
          in `((,(make-condition 'gr8s.runtime:volume-mount-error :volume "cfg"
                                 :message "MountVolume.SetUp failed for volume \"cfg\" : configmap \"missing\" not found")
                "ContainerCreating" "MountVolume.SetUp failed for volume \"cfg\" : configmap \"missing\" not found"
                "FailedMount" "Warning" "MountVolume.SetUp failed for volume \"cfg\" : configmap \"missing\" not found")
               (,(make-condition 'gr8s.runtime:container-create-error :message "mount source path does not exist")
                "CreateContainerError" "mount source path does not exist"
                "Failed" "Warning" "Error: mount source path does not exist")
               (,(make-condition 'gr8s.runtime:container-image-pull-error :image "registry.test/app:1" :message "not found")
                "ErrImagePull" "not found"
                "Failed" "Warning" "Failed to pull image \"registry.test/app:1\": not found")
               (,(make-condition 'gr8s.runtime:container-image-pull-backoff :image "registry.test/app:1"
                                 :message "Back-off pulling image \"registry.test/app:1\": ErrImagePull: not found")
                "ImagePullBackOff" "Back-off pulling image \"registry.test/app:1\": ErrImagePull: not found"
                "BackOff" "Normal" "Back-off pulling image \"registry.test/app:1\"")
               (,(make-condition 'gr8s.runtime:container-image-never-pull
                                 :message "Container image \"app:1\" is not present with pull policy of Never")
                "ErrImageNeverPull" "Container image \"app:1\" is not present with pull policy of Never"
                "ErrImageNeverPull" "Warning" "Container image \"app:1\" is not present with pull policy of Never")
               (,(make-condition 'gr8s.runtime:container-config-error :message "secret \"db\" not found")
                "CreateContainerConfigError" "secret \"db\" not found"
                "Failed" "Warning" "Error: secret \"db\" not found"))
        do (multiple-value-bind (runtime pod observed) (report-create-failure condition)
             (let ((waiting (container-waiting observed "main")))
               (is (equal reason (gethash "reason" waiting)) "~A" reason)
               (is (equal message (gethash "message" waiting)) "~A" reason))
             (let ((events (remove "main" (pod-events-with runtime pod event-reason)
                                   :key (lambda (event) (gethash "container" event)) :test-not #'equal)))
               (is (= 1 (length events)) "one ~A Event for ~A" event-reason reason)
               (when events
                 (is (equal event-type (gethash "type" (first events))) "~A" reason)
                 (is (equal event-message (gethash "message" (first events))) "~A" reason))))))

(test a-persisting-failure-stays-one-event
  (with-temporary-store (store directory)
    (let* ((now 4000000000) (gr8s.kubelet::*container-lifecycle-clock* (lambda () now))
           (pod (lifecycle-pod store))
           (runtime (gr8s.runtime.containerd::make-containerd-runtime :log-root directory))
           (condition (make-condition 'gr8s.runtime:volume-mount-error :volume "cfg" :message "not ready")))
      (with-lifecycle-cri (fixture pod nil)
        (with-replaced-functions ((gr8s.runtime.containerd::containerd-create-container
                                   (lambda (&rest arguments) (declare (ignore arguments)) (error condition))))
          (dotimes (pass 5) (gr8s.runtime::runtime-ensure runtime pod) (incf now))
          ;; Two containers, each with one Event, however many passes.
          (is (= 2 (length (pod-events-with runtime pod "FailedMount")))))))))

;;; Image pulls

(test a-failed-pull-is-errimagepull-once-then-imagepullbackoff
  (let* ((now 4000000000) (gr8s.kubelet::*container-lifecycle-clock* (lambda () now))
         (runtime (gr8s.runtime.containerd::make-containerd-runtime :log-root "/nonexistent/")))
    (with-replaced-functions ((gr8s.runtime.containerd::cri-image-present-p (constantly nil))
                              (gr8s.kubelet::pull-image-with-credentials
                               (lambda (&rest arguments) (declare (ignore arguments)) (error "manifest unknown"))))
      (flet ((attempt (requester)
               (handler-case (progn (gr8s.kubelet::ensure-container-image runtime "app:1" "IfNotPresent"
                                                                          (constantly nil) requester)
                                    :ready)
                 (gr8s.runtime:container-image-pull-backoff (condition) (list :backoff (gr8s.runtime:runtime-error-message condition)))
                 (gr8s.runtime:container-image-pull-error (condition) (list :error (gr8s.runtime:runtime-error-message condition)))
                 (gr8s.runtime:container-image-pending () :pending))))
        (is (eq :pending (attempt '("uid" "main"))))
        (gap-wait-for-pull runtime "app:1")
        (is (equal '(:error "manifest unknown") (attempt '("uid" "main"))))
        (is (equal '(:backoff "Back-off pulling image \"app:1\": ErrImagePull: manifest unknown")
                   (attempt '("uid" "main")))
            "the same container then waits out the back-off")
        (is (eq :error (first (attempt '("uid" "side")))) "each container hears of the failure itself first")
        (incf now 11)
        (is (eq :pending (attempt '("uid" "main"))) "after the back-off it pulls again")))))

(test a-missing-image-under-never-is-errimageneverpull
  (let ((runtime (gr8s.runtime.containerd::make-containerd-runtime :log-root "/nonexistent/")))
    (with-replaced-functions ((gr8s.runtime.containerd::cri-image-present-p (constantly nil)))
      (let ((condition (handler-case (progn (gr8s.kubelet::ensure-container-image runtime "app:1" "Never") nil)
                         (error (condition) condition))))
        (is (typep condition 'gr8s.runtime:container-image-never-pull))
        (is (equal "Container image \"app:1\" is not present with pull policy of Never"
                   (gr8s.runtime:runtime-error-message condition)))))))

;;; Crash loops

(test a-crash-loop-says-how-long-it-is-backing-off
  (with-temporary-store (store directory)
    (let* ((now 4000000000) (gr8s.kubelet::*container-lifecycle-clock* (lambda () now))
           (pod (lifecycle-pod store))
           (runtime (gr8s.runtime.containerd::make-containerd-runtime :log-root directory)))
      (with-lifecycle-cri (fixture pod (list (lifecycle-info "main" 0 gr8s.cri.v1::+containerstate-container_running+ now)
                                           (lifecycle-info "side" 0 gr8s.cri.v1::+containerstate-container_exited+ now 7)))
        ;; The first exit restarts at once; a second soon after waits 10 seconds.
        (gr8s.runtime::runtime-ensure runtime pod)
        (incf now)
        (setf (lifecycle-cri-fixture-infos fixture)
              (cons (lifecycle-info "side" 1 gr8s.cri.v1::+containerstate-container_exited+ now 9)
                    (remove "side-1" (lifecycle-cri-fixture-infos fixture) :test #'equal
                            :key #'gr8s.runtime.containerd::cri-container-info-id)))
        (let ((waiting (container-waiting (gr8s.runtime::runtime-ensure runtime pod) "side")))
          (is (equal "CrashLoopBackOff" (gethash "reason" waiting)))
          (is (equal (format nil "back-off 10s restarting failed container=side pod=~A_default(~A)"
                             (pod-name pod) (pod-uid pod))
                     (gethash "message" waiting))))
        (let ((events (pod-events-with runtime pod "BackOff")))
          (is (= 1 (length events)))
          (when events
            (is (equal "Warning" (gethash "type" (first events))))
            (is (equal (format nil "Back-off restarting failed container side in pod ~A_default(~A)"
                               (pod-name pod) (pod-uid pod))
                       (gethash "message" (first events))))
            (is (<= (length (gethash "id" (first events))) 128) "the control plane keeps only short IDs")))))))

(test back-off-durations-print-as-go-prints-them
  (loop for (seconds text) in '((10 "10s") (40 "40s") (80 "1m20s") (160 "2m40s") (300 "5m0s"))
        do (is (equal text (gr8s.kubelet::go-duration-text seconds)))))

;;; Events reaching the API

(test new-node-event-reasons-are-published
  (with-temporary-store (store directory)
    (let* ((pod (create-pod store (parse-pod (gap-pod-object))))
           (runtime (gr8s.runtime.containerd::make-containerd-runtime :log-root directory))
           (name (container-spec-name (aref (gr8s.model::pod-containers pod) 0))))
      (dolist (reason '("BackOff" "FailedMount" "ErrImageNeverPull" "FailedToRetrieveImagePullSecret"
                        "RestartingAllContainers"))
        (gr8s.kubelet::record-container-lifecycle-event runtime (pod-uid pod) name 0 reason "message" "Warning"))
      (gr8s.kubelet::record-container-lifecycle-event runtime (pod-uid pod) name 0 "MadeUpReason" "message" "Warning")
      (gr8s.resources::record-node-runtime-events store pod "node" (gr8s.runtime::runtime-events runtime (pod-uid pod)))
      (let ((reasons (mapcar (lambda (event) (gethash "reason" event))
                             (gr8s.resources::list-core-resources store "events" (pod-namespace pod)))))
        (is (= 5 (length reasons)))
        (is (null (member "MadeUpReason" reasons :test #'equal)) "unknown reasons are still dropped")))))

(test an-eviction-is-an-event-on-the-pod
  (with-temporary-store (store directory)
    (let* ((pod (create-pod store (parse-pod (gap-pod-object))))
           (runtime (gr8s.runtime.containerd::make-containerd-runtime :log-root directory))
           (reconciler (make-reconciler store runtime))
           (message "The node was low on resource: memory. Threshold 104857600 bytes, 52428800 available."))
      (with-replaced-functions ((gr8s.runtime::runtime-delete (lambda (&rest arguments) (declare (ignore arguments)) nil)))
        (gr8s.kubelet::evict-pod-for-storage reconciler pod message))
      (gr8s.resources::record-node-runtime-events store pod "node" (gr8s.runtime::runtime-events runtime (pod-uid pod)))
      (let ((event (find "Evicted" (gr8s.resources::list-core-resources store "events" (pod-namespace pod))
                         :key (lambda (event) (gethash "reason" event)) :test #'equal)))
        (is (not (null event)))
        (when event
          (is (equal message (gethash "message" event)))
          (is (equal "Warning" (gethash "type" event)))
          (is (equal (pod-uid pod) (gethash "uid" (gethash "involvedObject" event))))
          (is (null (gethash "fieldPath" (gethash "involvedObject" event))) "it's about the Pod, not a container"))))))

(test pod-level-events-need-a-known-reason
  (with-temporary-store (store directory)
    (let* ((pod (create-pod store (parse-pod (gap-pod-object))))
           (runtime (gr8s.runtime.containerd::make-containerd-runtime :log-root directory)))
      (gr8s.runtime:runtime-record-pod-event runtime (pod-uid pod) "Killing" "not a Pod-level reason")
      (gr8s.resources::record-node-runtime-events store pod "node" (gr8s.runtime::runtime-events runtime (pod-uid pod)))
      (is (null (gr8s.resources::list-core-resources store "events" (pod-namespace pod)))))))
