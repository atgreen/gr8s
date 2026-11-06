;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; A Pod being deleted keeps reporting its real container statuses, never
;;;; reverts a terminal phase, and ends with the terminal status a kubelet sends
;;;; before removal, as upstream's "Pods Extended Pod Container Status" checks.

(in-package #:gr8s/tests)
(def-suite pod-terminating-status :in gr8s)
(in-suite pod-terminating-status)

(defun terminating-test-pod (json-spec)
  "Parse a Pod named t with JSON-SPEC as its spec, assigned to worker-a."
  (parse-pod (format nil "{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"name\":\"t\",\"namespace\":\"default\"},\"spec\":~A}"
                     json-spec)))

(defparameter +fail-pod-spec+
  "{\"restartPolicy\":\"Never\",\"nodeName\":\"worker-a\",\"containers\":[{\"name\":\"fail\",\"image\":\"agnhost\"}]}")

(defparameter +init-fail-pod-spec+
  "{\"restartPolicy\":\"Never\",\"nodeName\":\"worker-a\",\"initContainers\":[{\"name\":\"fail\",\"image\":\"agnhost\"}],\"containers\":[{\"name\":\"blocked\",\"image\":\"agnhost\"}]}")

(defun test-container-status (name state &rest fields)
  "Return a container status for NAME in STATE, a (KEY . OBJECT) pair such as (\"running\" . {})."
  (let ((status (gr8s::core-object "name" name "image" "agnhost" "restartCount" 0
                                   "state" (gr8s::core-object (car state) (cdr state)))))
    (loop for (key value) on fields by #'cddr do (setf (gethash key status) value))
    status))

(defun status-state-name (status name &optional (field "containerStatuses"))
  "Return the state key (running, terminated or waiting) of container NAME in STATUS."
  (let ((item (find name (gethash field status #()) :test #'equal :key (lambda (entry) (gethash "name" entry)))))
    (and item (loop for key being the hash-keys of (gethash "state" item) return key))))

(test a-running-container-is-reported-terminated-once-its-pod-is-gone
  (let* ((pod (terminating-test-pod +fail-pod-spec+))
         (last (gr8s::core-object "phase" "Running"
                                  "containerStatuses" (vector (test-container-status "fail" (cons "running" (gr8s::core-object))
                                                                                     "ready" t "started" t))))
         (final (gr8s::terminating-pod-status pod nil last :gone t))
         (item (aref (gethash "containerStatuses" final) 0))
         (terminated (gethash "terminated" (gethash "state" item))))
    (is (equal "Failed" (gethash "phase" final)))
    (is (= 137 (gethash "exitCode" terminated)))
    (is (equal "ContainerStatusUnknown" (gethash "reason" terminated)))
    (is (null (gethash "started" item)))
    (is (null (gethash "ready" item)))
    ;; The last report itself is left alone.
    (is (equal "running" (status-state-name last "fail")))))

(test a-container-that-never-started-leaves-a-gone-pod-pending
  (let ((pod (terminating-test-pod +fail-pod-spec+)))
    (dolist (last (list nil (gr8s::core-object "phase" "Pending")))
      (let ((final (gr8s::terminating-pod-status pod nil last :gone t)))
        (is (equal "Pending" (gethash "phase" final)))
        (is (equal "waiting" (status-state-name final "fail")))
        (is (equal "ContainerCreating"
                   (gethash "reason" (gethash "waiting" (gethash "state" (aref (gethash "containerStatuses" final) 0))))))))))

(test a-failed-init-container-keeps-the-pod-failed-and-its-application-waiting
  (let* ((pod (terminating-test-pod +init-fail-pod-spec+))
         (last (gr8s::core-object
                "phase" "Failed"
                "initContainerStatuses" (vector (test-container-status "fail" (cons "terminated" (gr8s::core-object "exitCode" 1))))
                "containerStatuses" (vector (test-container-status "blocked" (cons "waiting" (gr8s::core-object "reason" "PodInitializing"))))))
         (shutting-down (gr8s::terminating-pod-status pod (gr8s::core-object "phase" "Unknown") last))
         (final (gr8s::terminating-pod-status pod nil last :gone t)))
    (dolist (status (list shutting-down final))
      (is (equal "Failed" (gethash "phase" status)))
      (is (= 1 (length (gethash "initContainerStatuses" status))))
      (is (equal "terminated" (status-state-name status "fail" "initContainerStatuses")))
      (is (equal "waiting" (status-state-name status "blocked"))))
    ;; Without a report from before, the phase still follows the kubelet's rules.
    (is (equal "Failed" (gethash "phase" (gr8s::terminating-pod-status
                                           pod (gr8s::core-object "phase" "Unknown"
                                                                  "initContainerStatuses" (gethash "initContainerStatuses" last)
                                                                  "containerStatuses" (gethash "containerStatuses" last))
                                           nil))))))

(test shutdown-never-forgets-a-container-or-reverts-a-termination
  (let* ((pod (terminating-test-pod +fail-pod-spec+))
         (exited (test-container-status "fail" (cons "terminated" (gr8s::core-object "exitCode" 1))))
         (last (gr8s::core-object "phase" "Failed" "containerStatuses" (vector exited))))
    ;; The runtime lost the container, or reports it waiting again: the exit stands.
    (dolist (current (list (gr8s::core-object "phase" "Running")
                           (gr8s::core-object "phase" "Pending" "containerStatuses"
                                              (vector (test-container-status "fail" (cons "waiting" (gr8s::core-object "reason" "ContainerCreating")))))))
      (let ((status (gr8s::terminating-pod-status pod current last)))
        (is (equal "Failed" (gethash "phase" status)))
        (is (equal "terminated" (status-state-name status "fail")))
        (is (= 1 (gethash "exitCode" (gethash "terminated" (gethash "state" (aref (gethash "containerStatuses" status) 0))))))))
    ;; A container still running during grace stays running until it is gone.
    (let ((status (gr8s::terminating-pod-status
                   pod (gr8s::core-object "phase" "Running"
                                          "containerStatuses" (vector (test-container-status "fail" (cons "running" (gr8s::core-object)))))
                   (gr8s::core-object "phase" "Running"))))
      (is (equal "Running" (gethash "phase" status)))
      (is (equal "running" (status-state-name status "fail"))))))

(test kubelet-phase-follows-restart-policy-for-stopped-containers
  (let ((always (terminating-test-pod "{\"restartPolicy\":\"Always\",\"containers\":[{\"name\":\"a\",\"image\":\"x\"},{\"name\":\"b\",\"image\":\"x\"}]}"))
        (status (gr8s::core-object "containerStatuses"
                                   (vector (test-container-status "a" (cons "terminated" (gr8s::core-object "exitCode" 0)))
                                           (test-container-status "b" (cons "terminated" (gr8s::core-object "exitCode" 0)))))))
    ;; Restarting containers keep a live Pod Running; once terminal it has succeeded.
    (is (equal "Running" (gr8s::kubelet-pod-phase always status nil)))
    (is (equal "Succeeded" (gr8s::kubelet-pod-phase always status t)))
    (setf (gethash "exitCode" (gethash "terminated" (gethash "state" (aref (gethash "containerStatuses" status) 1)))) 2)
    (is (equal "Failed" (gr8s::kubelet-pod-phase always status t)))
    ;; A container not reported at all leaves the phase Pending.
    (is (equal "Pending" (gr8s::kubelet-pod-phase always (gr8s::core-object "containerStatuses" (vector (aref (gethash "containerStatuses" status) 0))) t)))))

(test the-deleted-watch-event-carries-the-terminal-status-the-agent-reported
  (with-temporary-store (store path)
    (let* ((server (gr8s::%make-node-grpc-server :store store))
           (runtime (gr8s::make-control-plane-runtime store server))
           (reconciler (make-reconciler store runtime))
           (fake (make-fake-runtime))
           (agent (gr8s::make-node-runtime (merge-pathnames "agent/" path) fake nil))
           (pod (create-pod store (grace-pod))))
      (gr8s::register-node store (gr8s::make-node-record :id "worker-a" :name "worker-a" :pod-cidr "10.88.0.0/24"))
      (gr8s::mark-node-ready store "worker-a" (get-universal-time))
      (flet ((sync-agent ()
               (gr8s::reconcile-node-snapshot agent (grace-snapshot-without-network (gr8s::current-node-snapshot server "worker-a")))
               (gr8s::handle-node-agent-envelope server "worker-a"
                                                 (gr8s::make-agent-envelope :status (gr8s::node-runtime-status agent)))))
        (unwind-protect
             (progn
               (gr8s::start-node-runtime agent)
               (reconcile-pod reconciler "default" "hello")
               (sync-agent)
               ;; The container is really running when deletion begins.
               (let ((actual (runtime-observe fake (pod-uid pod))))
                 (setf (gr8s::runtime-pod-status actual)
                       (gr8s::core-object "containerStatuses"
                                          (vector (test-container-status "web" (cons "running" (gr8s::core-object))
                                                                         "ready" t "started" t)))))
               (sync-agent)
               (is (equal "running" (status-state-name (reconcile-pod reconciler "default" "hello") "web")))
               (let ((revision (gr8s::pod-store-pod-revision store)))
                 (gr8s::delete-reconciled-pod reconciler "default" "hello")
                 (sync-agent)
                 (is (equal "Deleted" (gethash "reason" (reconcile-pod reconciler "default" "hello"))))
                 (signals kubernetes-error (get-pod store "default" "hello"))
                 (let* ((events (gr8s::pod-watch-events store "default" "" "" revision))
                        (deleted (find "DELETED" events :test #'equal :key (lambda (event) (gethash "type" event))))
                        (status (gethash "status" (gethash "object" deleted))))
                   (is (eq deleted (car (last events))))
                   (is (equal "Failed" (gethash "phase" status)))
                   (is (null (gethash "reason" status)))
                   (is (equal "terminated" (status-state-name status "web")))
                   ;; No event during shutdown dropped the container or called the phase Unknown.
                   (dolist (event events)
                     (let ((seen (gethash "status" (gethash "object" event))))
                       (is (not (equal "Unknown" (gethash "phase" seen))))
                       (is (= 1 (length (gethash "containerStatuses" seen #())))))))))
          (gr8s::stop-node-runtime agent))))))

(test the-control-plane-never-publishes-less-than-clients-saw-at-removal
  (with-temporary-store (store path)
    (values path)
    (let* ((server (gr8s::%make-node-grpc-server :store store))
           (reconciler (make-reconciler store (gr8s::make-control-plane-runtime store server)))
           (pod (create-pod store (terminating-test-pod +fail-pod-spec+)))
           (exited (gr8s::core-object "phase" "Failed" "containerStatuses"
                                      (vector (test-container-status "fail" (cons "terminated" (gr8s::core-object "exitCode" 1))))))
           (running (gr8s::core-object "phase" "Running" "containerStatuses"
                                       (vector (test-container-status "fail" (cons "running" (gr8s::core-object)))))))
      (flet ((publish (status) (gr8s::with-store-lock (store) (gr8s::publish-pod-status-unlocked store pod status)))
             (final (observation)
               (gr8s::save-pod-observation store pod observation)
               (gr8s::deleted-pod-final-status reconciler pod (gr8s::pod-observed-status store pod))))
        ;; A node that rebuilt its acknowledgement after losing its last report says less than clients saw.
        (publish exited)
        (let ((status (final (gr8s::core-object "phase" "Pending" "reason" "Deleted" "containerStatuses"
                                                (vector (test-container-status "fail" (cons "waiting" (gr8s::core-object "reason" "ContainerCreating"))))))))
          (is (equal "Failed" (gethash "phase" status)))
          (is (equal "terminated" (status-state-name status "fail"))))
        ;; A Pod already terminal on its node is removed at once: its last report is still published.
        (publish running)
        (let ((status (final exited)))
          (is (equal "Failed" (gethash "phase" status)))
          (is (equal "terminated" (status-state-name status "fail"))))
        ;; Without the node's acknowledgement, a running container is not declared gone.
        (let ((status (final running)))
          (is (equal "Running" (gethash "phase" status)))
          (is (equal "running" (status-state-name status "fail"))))))))

(test a-container-clients-saw-terminated-stays-terminated-until-a-new-attempt-runs
  ;; As the kubelet's status manager refuses the transition (checkContainerStateTransition).
  (with-temporary-store (store path)
    (values path)
    (let* ((pod (create-pod store (terminating-test-pod +fail-pod-spec+)))
           (exited (test-container-status "fail" (cons "terminated" (gr8s::core-object "exitCode" 1))
                                          "containerID" "containerd://first")))
      (gr8s::add-pod-status-conditions store pod (gr8s::core-object "phase" "Failed" "containerStatuses" (vector exited)))
      ;; A report missing the container, or still about the exited attempt, keeps the exit.
      (dolist (report (list (gr8s::core-object "phase" "Pending")
                            (gr8s::core-object "phase" "Running" "containerStatuses"
                                               (vector (test-container-status "fail" (cons "running" (gr8s::core-object))
                                                                              "containerID" "containerd://first")))))
        (is (equal "terminated" (status-state-name (gr8s::add-pod-status-conditions store pod report) "fail"))))
      ;; A new attempt that really runs is reported as it is.
      (is (equal "running" (status-state-name
                            (gr8s::add-pod-status-conditions
                             store pod (gr8s::core-object "phase" "Running" "containerStatuses"
                                                          (vector (test-container-status "fail" (cons "running" (gr8s::core-object))
                                                                                         "containerID" "containerd://second"))))
                            "fail"))))))

(test a-terminal-phase-clients-saw-stays-terminal
  (with-temporary-store (store path)
    (values path)
    (let ((pod (create-pod store (terminating-test-pod +fail-pod-spec+))))
      (gr8s::add-pod-status-conditions store pod (gr8s::core-object "phase" "Failed"))
      (is (equal "Failed" (gethash "phase" (gr8s::add-pod-status-conditions store pod (gr8s::core-object "phase" "Pending"))))))))
