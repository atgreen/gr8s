;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Exercise actual native lifecycle reconciliation against deterministic CRI
;;;; observations: healthy siblings, policy, restart history, durable backoff,
;;;; ambiguous creation recovery, bounded history and current-attempt logs.

(in-package #:gr8s/tests)
(def-suite container-lifecycle :in gr8s)
(in-suite container-lifecycle)

(test cri-wire-defaults-zero-enum-states-without-erasing-explicit-values
  (dolist (type-and-tag '((gr8s.cri.v1::pod-sandbox 24) (gr8s.cri.v1::container 48)
                        (gr8s.cri.v1::container-status 24)))
    (destructuring-bind (type tag) type-and-tag
      (is (eql 0 (gr8s::cri-protobuf-state (ag-proto:deserialize-from-bytes type #()))))
      (is (eql 1 (gr8s::cri-protobuf-state (ag-proto:deserialize-from-bytes type (vector tag 1))))))))

(defstruct lifecycle-cri-fixture
  "Hold deterministic CRI state and the calls made by native reconciliation."
  pod sandbox infos calls (lock (bt:make-lock "lifecycle fixture")))

(defun lifecycle-info (name attempt state now &optional (exit-code 0))
  "Build one concrete CRI attempt with stable identity and Unix timestamps."
  (gr8s::make-cri-container-info
   :id (format nil "~A-~D" name attempt) :name name :attempt attempt :state state
   :started-at (* (- now 2208988800) 1000000000)
   :finished-at (if (= state gr8s.cri.v1::+containerstate-container_exited+)
                    (* (- now 2208988800) 1000000000) 0)
   :exit-code exit-code :image "busybox" :image-ref "sha256:fixture"
   :labels (list (cons gr8s::+gr8s-container-label+ name))))

(defun lifecycle-pod (store &optional (policy "OnFailure"))
  "Create a two-container desired Pod with a chosen restart policy."
  (let* ((object (com.inuoe.jzon:parse *valid-pod-json*))
         (spec (gethash "spec" object)))
    (setf (gethash "restartPolicy" spec) policy
          (gethash "containers" spec)
          (vector (gr8s::core-object "name" "main" "image" "busybox")
                  (gr8s::core-object "name" "side" "image" "busybox")))
    (create-pod store (parse-pod object))))

(defmacro with-lifecycle-cri ((fixture pod infos) &body body)
  "Temporarily supply CRI replies while running the production lifecycle functions."
  (let ((originals (gensym "ORIGINALS")))
    `(let* ((,fixture (make-lifecycle-cri-fixture
                      :pod ,pod :infos ,infos
                      :sandbox (gr8s::make-cri-pod-sandbox-info
                                :id "same-sandbox"
                                :labels (list (cons gr8s::+gr8s-spec-fingerprint-label+
                                                    (gr8s::pod-runtime-spec-fingerprint ,pod))))))
            (,originals nil))
       (labels ((replace-function (symbol function)
                  (push (cons symbol (symbol-function symbol)) ,originals)
                  (setf (symbol-function symbol) function)))
         (unwind-protect
              (progn
                (replace-function 'gr8s::containerd-owned-sandbox
                  (lambda (runtime uid) (declare (ignore runtime uid)) (lifecycle-cri-fixture-sandbox ,fixture)))
                (replace-function 'gr8s::containerd-containers
                  (lambda (runtime sandbox)
                    (declare (ignore runtime sandbox))
                    (mapcar (lambda (info) (gr8s::make-cri-container-summary
                                           :id (gr8s::cri-container-info-id info) :state (gr8s::cri-container-info-state info)
                                           :labels (gr8s::cri-container-info-labels info)))
                            (lifecycle-cri-fixture-infos ,fixture))))
                (replace-function 'gr8s::cri-container-status
                  (lambda (socket id &rest options)
                    (declare (ignore socket options))
                    (or (find id (lifecycle-cri-fixture-infos ,fixture) :key #'gr8s::cri-container-info-id :test #'equal)
                        (error "Absent fixture container ~A" id))))
                (replace-function 'gr8s::cri-pod-sandbox-ip
                  (lambda (&rest options) (declare (ignore options)) "10.88.0.2"))
                (replace-function 'gr8s::containerd-create-container
                  (lambda (runtime desired sandbox config spec &key (attempt 0))
                    (declare (ignore runtime desired config))
                    (push (list :create (container-spec-name spec) attempt sandbox) (lifecycle-cri-fixture-calls ,fixture))
                    (push (lifecycle-info (container-spec-name spec) attempt gr8s.cri.v1::+containerstate-container_running+
                                          (funcall gr8s::*container-lifecycle-clock*))
                          (lifecycle-cri-fixture-infos ,fixture))))
                (replace-function 'gr8s::cri-start-container
                  (lambda (socket id &rest options)
                    (declare (ignore socket options))
                    (push (list :start id) (lifecycle-cri-fixture-calls ,fixture))
                    (setf (gr8s::cri-container-info-state
                           (find id (lifecycle-cri-fixture-infos ,fixture) :key #'gr8s::cri-container-info-id :test #'equal))
                          gr8s.cri.v1::+containerstate-container_running+)))
                (replace-function 'gr8s::cri-delete-container
                  (lambda (socket id &rest options)
                    (declare (ignore socket options))
                    (bt:with-lock-held ((lifecycle-cri-fixture-lock ,fixture))
                      (push (list :delete id) (lifecycle-cri-fixture-calls ,fixture))
                      (setf (lifecycle-cri-fixture-infos ,fixture)
                            (remove id (lifecycle-cri-fixture-infos ,fixture) :key #'gr8s::cri-container-info-id :test #'equal)))))
                (replace-function 'gr8s::cri-stop-container
                  (lambda (socket id &rest options)
                    (declare (ignore socket options))
                    (let ((info (find id (lifecycle-cri-fixture-infos ,fixture) :key #'gr8s::cri-container-info-id :test #'equal)))
                      (push (list :stop id) (lifecycle-cri-fixture-calls ,fixture))
                      (setf (gr8s::cri-container-info-state info) gr8s.cri.v1::+containerstate-container_exited+
                            (gr8s::cri-container-info-exit-code info) 137
                            (gr8s::cri-container-info-finished-at info)
                            (* (- (funcall gr8s::*container-lifecycle-clock*) 2208988800) 1000000000)))))
                (replace-function 'gr8s::cri-delete-pod-sandbox
                  (lambda (socket id &rest options)
                    (declare (ignore socket options))
                    (push (list :delete-sandbox id) (lifecycle-cri-fixture-calls ,fixture))
                    (setf (lifecycle-cri-fixture-sandbox ,fixture) nil)))
                (replace-function 'gr8s::containerd-start-sandbox
                  (lambda (runtime desired)
                    (declare (ignore runtime))
                    (push (list :new-sandbox) (lifecycle-cri-fixture-calls ,fixture))
                    (setf (lifecycle-cri-fixture-sandbox ,fixture)
                          (gr8s::make-cri-pod-sandbox-info
                           :id "new-sandbox" :labels (list (cons gr8s::+gr8s-spec-fingerprint-label+
                                                                (gr8s::pod-runtime-spec-fingerprint desired)))))))
                ,@body)
           (dolist (pair ,originals) (setf (symbol-function (car pair)) (cdr pair))))))))

;; Run 14: Variable Expansion's Pod went to Failed in 3 seconds, its only container having
;; "exited" 128 with this message when its StartContainer call was cancelled.
(defun cancelled-start-info (name now &optional (message "failed to create containerd task: failed to create shim task: context canceled"))
  (let ((info (lifecycle-info name 0 gr8s.cri.v1::+containerstate-container_exited+ now 128)))
    (setf (gr8s::cri-container-info-reason info) "StartError"
          (gr8s::cri-container-info-message info) message
          (gr8s::cri-container-info-started-at info) 0)
    info))

(test cancelled-container-start-is-retried-however-the-pod-restarts
  (with-temporary-store (store directory)
    (let* ((now 4000000000) (gr8s::*container-lifecycle-clock* (lambda () now))
           (pod (lifecycle-pod store "Never"))
           (runtime (gr8s::make-containerd-runtime :log-root directory))
           (healthy (lifecycle-info "main" 0 gr8s.cri.v1::+containerstate-container_running+ now))
           (cancelled (cancelled-start-info "side" now))
           (log (merge-pathnames "side.log" (gr8s::containerd-pod-log-directory runtime (pod-uid pod)))))
      (ensure-directories-exist log)
      (with-open-file (stream log :direction :output :if-does-not-exist :create) (declare (ignorable stream)))
      (with-lifecycle-cri (fixture pod (list healthy cancelled))
        (let ((observed (runtime-observe runtime (pod-uid pod))))
          (is (not (equal "Failed" (gr8s::runtime-pod-phase observed))))
          (is (gr8s::native-container-progress-required-p pod observed))
          (let* ((after (gr8s::runtime-reconcile-containers runtime pod observed))
                 (status (find "side" (gethash "containerStatuses" (gr8s::runtime-pod-status after))
                               :test #'equal :key (lambda (item) (gethash "name" item)))))
            (is (member '(:delete "side-0") (lifecycle-cri-fixture-calls fixture) :test #'equal))
            (is (member '(:create "side" 0 "same-sandbox") (lifecycle-cri-fixture-calls fixture) :test #'equal))
            (is (eql 0 (gethash "restartCount" status)))
            (is (gethash "running" (gethash "state" status)))))))))

(test start-abandoned-by-the-client-timeout-is-retried-too
  (with-temporary-store (store directory)
    (let* ((now 4000000000) (gr8s::*container-lifecycle-clock* (lambda () now))
           (pod (lifecycle-pod store "Never"))
           (runtime (gr8s::make-containerd-runtime :log-root directory))
           (healthy (lifecycle-info "main" 0 gr8s.cri.v1::+containerstate-container_running+ now))
           (abandoned (cancelled-start-info "side" now "failed to create containerd task: context deadline exceeded")))
      (with-lifecycle-cri (fixture pod (list healthy abandoned))
        (let ((observed (runtime-observe runtime (pod-uid pod))))
          (is (not (equal "Failed" (gr8s::runtime-pod-phase observed))))
          (gr8s::runtime-reconcile-containers runtime pod observed)
          (is (member '(:create "side" 0 "same-sandbox") (lifecycle-cri-fixture-calls fixture) :test #'equal)))))))

;; podster-uqb.126: the abandoned start's task may still be running, and containerd refuses
;; to remove it. The Pod then waits with a runtime error rather than failing.
(test abandoned-start-that-cannot-be-removed-leaves-the-pod-waiting
  (with-temporary-store (store directory)
    (let* ((now 4000000000) (gr8s::*container-lifecycle-clock* (lambda () now))
           (pod (lifecycle-pod store "Never"))
           (runtime (gr8s::make-containerd-runtime :log-root directory))
           (healthy (lifecycle-info "main" 0 gr8s.cri.v1::+containerstate-container_running+ now))
           (cancelled (cancelled-start-info "side" now)))
      (with-lifecycle-cri (fixture pod (list healthy cancelled))
        (let ((original (symbol-function 'gr8s::cri-delete-container)))
          (setf (symbol-function 'gr8s::cri-delete-container)
                (lambda (&rest arguments) (declare (ignore arguments))
                  (error "failed to remove container: cannot delete running task")))
          (unwind-protect
               (let ((observed (runtime-observe runtime (pod-uid pod))))
                 (is (not (equal "Failed" (gr8s::runtime-pod-phase observed))))
                 (signals gr8s::runtime-error (gr8s::runtime-reconcile-containers runtime pod observed))
                 (is (null (find :create (lifecycle-cri-fixture-calls fixture) :key #'first))))
            (setf (symbol-function 'gr8s::cri-delete-container) original)))))))

(test container-start-that-really-failed-stays-terminal
  (with-temporary-store (store directory)
    (let* ((now 4000000000) (gr8s::*container-lifecycle-clock* (lambda () now))
           (pod (lifecycle-pod store "Never"))
           (runtime (gr8s::make-containerd-runtime :log-root directory))
           (failed (cancelled-start-info "side" now "failed to create containerd task: exec: no such file"))
           (done (lifecycle-info "main" 0 gr8s.cri.v1::+containerstate-container_exited+ now)))
      (with-lifecycle-cri (fixture pod (list done failed))
        (let ((observed (runtime-observe runtime (pod-uid pod))))
          (is (equal "Failed" (gr8s::runtime-pod-phase observed)))
          (gr8s::runtime-reconcile-containers runtime pod observed)
          (is (null (lifecycle-cri-fixture-calls fixture))))))))

(test native-restarts-only-the-failed-sibling-while-pod-is-running
  (with-temporary-store (store directory)
    (let* ((now 4000000000) (gr8s::*container-lifecycle-clock* (lambda () now))
           (pod (lifecycle-pod store))
           (runtime (gr8s::make-containerd-runtime :log-root directory))
           (healthy (lifecycle-info "main" 0 gr8s.cri.v1::+containerstate-container_running+ now))
           (failed (lifecycle-info "side" 0 gr8s.cri.v1::+containerstate-container_exited+ now 7)))
      (with-lifecycle-cri (fixture pod (list healthy failed))
        (let* ((observed (runtime-observe runtime (pod-uid pod)))
               (after (gr8s::runtime-reconcile-containers runtime pod observed))
               (statuses (gethash "containerStatuses" (gr8s::runtime-pod-status after)))
               (side (find "side" statuses :key (lambda (status) (gethash "name" status)) :test #'equal)))
          (is (equal "Running" (gr8s::runtime-pod-phase observed)))
          (is (equal '((:create "side" 1 "same-sandbox")) (lifecycle-cri-fixture-calls fixture)))
          (is (eq healthy (find "main-0" (lifecycle-cri-fixture-infos fixture) :key #'gr8s::cri-container-info-id :test #'equal)))
          (is (= 2 (length statuses)))
          (is (= 1 (gethash "restartCount" side)))
          (is (= 7 (gethash "exitCode" (gethash "terminated" (gethash "lastState" side))))))))))

(test native-policy-applies-to-successful-and-failed-exits
  (dolist (scenario '(("Always" 0 1) ("Always" 7 1) ("OnFailure" 0 0) ("OnFailure" 7 1) ("Never" 0 0) ("Never" 7 0)))
    (destructuring-bind (policy exit-code starts) scenario
      (with-temporary-store (store directory)
        (let* ((pod (lifecycle-pod store policy)) (runtime (gr8s::make-containerd-runtime :log-root directory))
               (now 4000000000) (gr8s::*container-lifecycle-clock* (lambda () now)))
          (with-lifecycle-cri (fixture pod (list (lifecycle-info "main" 0 gr8s.cri.v1::+containerstate-container_running+ now)
                                               (lifecycle-info "side" 0 gr8s.cri.v1::+containerstate-container_exited+ now exit-code)))
            (gr8s::runtime-ensure runtime pod)
            (is (= starts (count :create (lifecycle-cri-fixture-calls fixture) :key #'first)))))))))

(test restart-deadline-and-last-state-survive-runtime-reconstruction
  (with-temporary-store (store directory)
    (let* ((now 4000000000) (gr8s::*container-lifecycle-clock* (lambda () now))
           (pod (lifecycle-pod store)) (runtime (gr8s::make-containerd-runtime :log-root directory)))
      (with-lifecycle-cri (fixture pod (list (lifecycle-info "main" 0 gr8s.cri.v1::+containerstate-container_running+ now)
                                           (lifecycle-info "side" 0 gr8s.cri.v1::+containerstate-container_exited+ now 7)))
        (gr8s::runtime-ensure runtime pod)
        (incf now)
        (setf (lifecycle-cri-fixture-infos fixture)
              (cons (lifecycle-info "side" 1 gr8s.cri.v1::+containerstate-container_exited+ now 9)
                    (remove "side-1" (lifecycle-cri-fixture-infos fixture) :key #'gr8s::cri-container-info-id :test #'equal)))
        (let* ((waiting (gr8s::runtime-ensure runtime pod))
               (side (find "side" (gethash "containerStatuses" (gr8s::runtime-pod-status waiting))
                           :key (lambda (status) (gethash "name" status)) :test #'equal)))
          (is (equal "CrashLoopBackOff" (gethash "reason" (gethash "waiting" (gethash "state" side))))))
        (let* ((reopened (gr8s::make-containerd-runtime :log-root directory))
               (state (gr8s::load-container-lifecycle-state reopened (pod-uid pod)))
               (entry (gethash "side" (gethash "containers" state))))
          (is (= (+ now 10) (gethash "nextStart" entry)))
          (is (= 2 (gethash "nextAttempt" entry)))
          (is (= 9 (gethash "exitCode" (gethash "lastTermination" entry))))
          (incf now 9)
          (gr8s::runtime-ensure reopened pod)
          (is (= 1 (count :create (lifecycle-cri-fixture-calls fixture) :key #'first)))
          (incf now)
          (gr8s::runtime-ensure reopened pod)
          (is (= 2 (count :create (lifecycle-cri-fixture-calls fixture) :key #'first)))
          (is (find '(:create "side" 2 "same-sandbox") (lifecycle-cri-fixture-calls fixture) :test #'equal))
          (is (= 3 (length (lifecycle-cri-fixture-infos fixture)))))))))

(test created-attempt-is-started-again-without-duplicate-create
  (with-temporary-store (store directory)
    (let* ((now 4000000000) (gr8s::*container-lifecycle-clock* (lambda () now))
           (pod (lifecycle-pod store)) (runtime (gr8s::make-containerd-runtime :log-root directory)))
      (with-lifecycle-cri (fixture pod (list (lifecycle-info "main" 0 gr8s.cri.v1::+containerstate-container_running+ now)
                                           (lifecycle-info "side" 3 gr8s.cri.v1::+containerstate-container_created+ now)))
        (gr8s::runtime-ensure runtime pod)
        (is (equal '((:start "side-3")) (lifecycle-cri-fixture-calls fixture)))))))

(test native-log-reader-uses-the-latest-attempt-independent-of-cri-list-order
  (with-temporary-store (store directory)
    (let* ((pod (lifecycle-pod store)) (runtime (gr8s::make-containerd-runtime :log-root directory))
           (now 4000000000) (log-directory (gr8s::containerd-pod-log-directory runtime (pod-uid pod))))
      (ensure-directories-exist log-directory)
      (with-open-file (out (merge-pathnames "side.log" log-directory) :direction :output :if-exists :supersede) (write-string "old" out))
      (with-open-file (out (merge-pathnames "side.2.log" log-directory) :direction :output :if-exists :supersede) (write-string "latest" out))
      (with-lifecycle-cri (fixture pod (list (lifecycle-info "side" 0 gr8s.cri.v1::+containerstate-container_exited+ now 7)
                                           (lifecycle-info "side" 2 gr8s.cri.v1::+containerstate-container_running+ now)))
        (is (equal "latest" (gr8s::runtime-logs runtime (pod-uid pod) "side")))
        (is (equal "side-2" (gr8s::cri-container-summary-id (gr8s::containerd-owned-container runtime (pod-uid pod) "side"))))))))

(test repeated-exits-back-off-with-a-cap-and-reset-after-a-long-run
  (let* ((now 4000000000) (state (gr8s::core-object "containers" (gr8s::core-object)))
         (first (gr8s::prepare-container-restart state (lifecycle-info "side" 0 gr8s.cri.v1::+containerstate-container_exited+ now 7) now)))
    (is (= now (gethash "nextStart" first)))
    (loop for attempt from 1 to 8
          for delay in '(10 20 40 80 160 300 300 300)
          do (incf now)
             (let* ((info (lifecycle-info "side" attempt gr8s.cri.v1::+containerstate-container_exited+ now 7))
                    (entry (gr8s::prepare-container-restart state info now))
                    (deadline (gethash "nextStart" entry)))
               (is (= (+ now delay) deadline))
               (is (<= (gethash "backoff" entry) 300))
               (gr8s::prepare-container-restart state info (+ now 3))
               (is (= deadline (gethash "nextStart" entry)))))
    (incf now 601)
    (let ((long-run (lifecycle-info "side" 9 gr8s.cri.v1::+containerstate-container_exited+ now 7)))
      (decf (gr8s::cri-container-info-started-at long-run) (* 601 1000000000))
      (let ((entry (gr8s::prepare-container-restart state long-run now)))
        (is (= now (gethash "nextStart" entry)))
        (is (= 10 (gethash "backoff" entry)))))))

(test checkpoint-failure-cannot-launch-an-unrecorded-restart
  (with-temporary-store (store directory)
    (let* ((now 4000000000) (gr8s::*container-lifecycle-clock* (lambda () now))
           (pod (lifecycle-pod store)) (runtime (gr8s::make-containerd-runtime :log-root directory))
           (healthy (lifecycle-info "main" 0 gr8s.cri.v1::+containerstate-container_running+ now)))
      (with-lifecycle-cri (fixture pod (list healthy (lifecycle-info "side" 0 gr8s.cri.v1::+containerstate-container_exited+ now 7)))
        (let ((original (symbol-function 'gr8s::save-container-lifecycle-state)))
          (unwind-protect
               (progn
                 (setf (symbol-function 'gr8s::save-container-lifecycle-state)
                       (lambda (&rest values) (declare (ignore values)) (error "checkpoint disk failure")))
                 (signals gr8s::runtime-error (gr8s::runtime-ensure runtime pod))
                 (is (null (lifecycle-cri-fixture-calls fixture)))
                 (is (member healthy (lifecycle-cri-fixture-infos fixture))))
            (setf (symbol-function 'gr8s::save-container-lifecycle-state) original)))))))

(test partial-initial-creation-failure-preserves-the-already-running-container
  (with-temporary-store (store directory)
    (let* ((now 4000000000) (gr8s::*container-lifecycle-clock* (lambda () now))
           (pod (lifecycle-pod store)) (runtime (gr8s::make-containerd-runtime :log-root directory))
           (healthy (lifecycle-info "main" 0 gr8s.cri.v1::+containerstate-container_running+ now)))
      (with-lifecycle-cri (fixture pod (list healthy))
        (let ((original (symbol-function 'gr8s::containerd-create-container)))
          (unwind-protect
               (progn
                 (setf (symbol-function 'gr8s::containerd-create-container)
                       (lambda (&rest values) (declare (ignore values)) (error "image pull failure")))
                 (signals gr8s::runtime-error (gr8s::runtime-ensure runtime pod))
                 (is (equal "same-sandbox" (gr8s::cri-pod-sandbox-info-id (lifecycle-cri-fixture-sandbox fixture))))
                 (is (eq healthy (first (lifecycle-cri-fixture-infos fixture)))))
            (setf (symbol-function 'gr8s::containerd-create-container) original)))
        (gr8s::runtime-ensure runtime pod)
        (is (equal '((:create "side" 0 "same-sandbox")) (lifecycle-cri-fixture-calls fixture)))))))

(test an-unavailable-sandbox-is-never-reported-as-a-healthy-pod
  (with-temporary-store (store directory)
    (let* ((now 4000000000) (pod (lifecycle-pod store)) (runtime (gr8s::make-containerd-runtime :log-root directory)))
      (with-lifecycle-cri (fixture pod (list (lifecycle-info "main" 0 gr8s.cri.v1::+containerstate-container_running+ now)))
        (setf (gr8s::cri-pod-sandbox-info-state (lifecycle-cri-fixture-sandbox fixture)) gr8s.cri.v1::+podsandboxstate-sandbox_notready+)
        (let ((observed (runtime-observe runtime (pod-uid pod))))
          (is (equal "Unknown" (gr8s::runtime-pod-phase observed)))
          (is (gr8s::native-container-progress-required-p pod observed)))))))

(defun lifecycle-side-status (observed)
  "Read the side container status from a real lifecycle observation fixture."
  (find "side" (gethash "containerStatuses" (gr8s::runtime-pod-status observed))
        :test #'equal :key (lambda (status) (gethash "name" status))))

(test missing-current-metadata-never-reuses-a-consumed-attempt
  (with-temporary-store (store directory)
    (let* ((now 4000000000) (gr8s::*container-lifecycle-clock* (lambda () now))
           (pod (lifecycle-pod store)) (runtime (gr8s::make-containerd-runtime :log-root directory)))
      (with-lifecycle-cri (fixture pod (list (lifecycle-info "main" 0 gr8s.cri.v1::+containerstate-container_running+ now)
                                           (lifecycle-info "side" 0 gr8s.cri.v1::+containerstate-container_exited+ now 7)))
        (gr8s::runtime-ensure runtime pod)
        ;; The predecessor still exists; it must not be selected for exec or
        ;; restarted as if attempt 1 had never been successfully observed.
        (setf (lifecycle-cri-fixture-infos fixture)
              (remove "side-1" (lifecycle-cri-fixture-infos fixture) :test #'equal :key #'gr8s::cri-container-info-id))
        (let* ((reopened (gr8s::make-containerd-runtime :log-root directory))
               (missing (lifecycle-side-status (runtime-observe reopened (pod-uid pod)))))
          (is (= 1 (gethash "restartCount" missing)))
          (is (equal "ContainerStatusUnknown" (gethash "reason" (gethash "waiting" (gethash "state" missing))))))
        (is (null (gr8s::containerd-owned-container runtime (pod-uid pod) "side")))
        (let ((after (gr8s::runtime-ensure (gr8s::make-containerd-runtime :log-root directory) pod)))
          (is (= 2 (gethash "restartCount" (lifecycle-side-status after))))
          (is (find '(:create "side" 2 "same-sandbox") (lifecycle-cri-fixture-calls fixture) :test #'equal))
          (is (= 1 (count '(:create "side" 1 "same-sandbox") (lifecycle-cri-fixture-calls fixture) :test #'equal))))))))

(test missing-metadata-during-durable-backoff-keeps-waiting-history
  (with-temporary-store (store directory)
    (let* ((now 4000000000) (gr8s::*container-lifecycle-clock* (lambda () now))
           (pod (lifecycle-pod store)) (runtime (gr8s::make-containerd-runtime :log-root directory)))
      (with-lifecycle-cri (fixture pod (list (lifecycle-info "main" 0 gr8s.cri.v1::+containerstate-container_running+ now)
                                           (lifecycle-info "side" 0 gr8s.cri.v1::+containerstate-container_exited+ now 7)))
        (gr8s::runtime-ensure runtime pod)
        (incf now)
        (setf (lifecycle-cri-fixture-infos fixture)
              (cons (lifecycle-info "side" 1 gr8s.cri.v1::+containerstate-container_exited+ now 9)
                    (remove "side-1" (lifecycle-cri-fixture-infos fixture) :test #'equal :key #'gr8s::cri-container-info-id)))
        (gr8s::runtime-ensure runtime pod)
        (setf (lifecycle-cri-fixture-infos fixture)
              (remove "side" (lifecycle-cri-fixture-infos fixture) :test #'equal :key #'gr8s::cri-container-info-name))
        (let* ((reopened (gr8s::make-containerd-runtime :log-root directory))
               (after (gr8s::runtime-ensure reopened pod)) (side (lifecycle-side-status after)))
          (is (= 2 (length (gethash "containerStatuses" (gr8s::runtime-pod-status after)))))
          (is (equal "CrashLoopBackOff" (gethash "reason" (gethash "waiting" (gethash "state" side)))))
          (is (= 1 (gethash "restartCount" side)))
          (is (= 9 (gethash "exitCode" (gethash "terminated" (gethash "lastState" side)))))
          (is (= 1 (count :create (lifecycle-cri-fixture-calls fixture) :key #'first)))
          (incf now 10)
          (is (= 2 (gethash "restartCount" (lifecycle-side-status (gr8s::runtime-ensure reopened pod))))))))))

(test retained-log-attempts-recover-count-without-reusing-log-path
  (with-temporary-store (store directory)
    (let* ((now 4000000000) (pod (lifecycle-pod store))
           (runtime (gr8s::make-containerd-runtime :log-root directory))
           (path (merge-pathnames "side.4.log.20261104" (gr8s::containerd-pod-log-directory runtime (pod-uid pod)))))
      (ensure-directories-exist path)
      (with-open-file (out path :direction :output :if-exists :supersede) (write-string "real rotated bytes" out))
      (with-lifecycle-cri (fixture pod (list (lifecycle-info "main" 0 gr8s.cri.v1::+containerstate-container_running+ now)))
        (is (= 5 (gethash "restartCount" (lifecycle-side-status (gr8s::runtime-ensure runtime pod)))))
        (is (find '(:create "side" 5 "same-sandbox") (lifecycle-cri-fixture-calls fixture) :test #'equal))
        (is (equal "real rotated bytes" (uiop:read-file-string path)))))))

(test terminal-checkpoints-survive-collected-cri-rows-and-sandbox
  (dolist (policy '("Never" "OnFailure"))
    (with-temporary-store (store directory)
      (let* ((now 4000000000) (pod (lifecycle-pod store policy))
             (runtime (gr8s::make-containerd-runtime :log-root directory)))
        (with-lifecycle-cri (fixture pod (list (lifecycle-info "main" 0 gr8s.cri.v1::+containerstate-container_exited+ now)
                                             (lifecycle-info "side" 2 gr8s.cri.v1::+containerstate-container_exited+ now)))
          (gr8s::runtime-ensure runtime pod)
          (setf (lifecycle-cri-fixture-infos fixture) nil)
          (let ((after (gr8s::runtime-ensure runtime pod)))
            (is (null (lifecycle-cri-fixture-calls fixture)))
            (is (equal "Succeeded" (gr8s::runtime-pod-phase after)))
            (is (= 2 (gethash "restartCount" (lifecycle-side-status after)))))
          (setf (lifecycle-cri-fixture-sandbox fixture) nil)
          (let ((after (runtime-observe runtime (pod-uid pod))))
            (is (equal "Succeeded" (gr8s::runtime-pod-phase after)))
            (is (= 2 (length (gethash "containerStatuses" (gr8s::runtime-pod-status after)))))))))))

(test retained-logs-require-owned-checkpoint-and-remain-read-only
  (with-temporary-store (store directory)
    (let* ((now 4000000000) (pod (lifecycle-pod store))
           (runtime (gr8s::make-containerd-runtime :log-root directory))
           (path (merge-pathnames "side.2.log" (gr8s::containerd-pod-log-directory runtime (pod-uid pod)))))
      (ensure-directories-exist path)
      (with-open-file (out path :direction :output :if-exists :supersede) (write-string "actual current bytes" out))
      (with-lifecycle-cri (fixture pod (list (lifecycle-info "side" 2 gr8s.cri.v1::+containerstate-container_running+ now)))
        (gr8s::runtime-ensure runtime pod)
        (setf (lifecycle-cri-fixture-infos fixture) nil (lifecycle-cri-fixture-sandbox fixture) nil)
        (let ((before (uiop:read-file-string (gr8s::container-lifecycle-path runtime (pod-uid pod)))))
          (is (equal "actual current bytes" (gr8s::runtime-logs runtime (pod-uid pod) "side")))
          (runtime-observe runtime (pod-uid pod))
          (is (equal before (uiop:read-file-string (gr8s::container-lifecycle-path runtime (pod-uid pod))))))
        ;; After deletion, orphaned log files cannot resurrect ownership.
        (gr8s::forget-container-lifecycle-state runtime (pod-uid pod))
        (signals gr8s::runtime-error (gr8s::runtime-logs runtime (pod-uid pod) "side"))
        (is (null (runtime-observe runtime (pod-uid pod))))
        (is (null (probe-file (gr8s::container-lifecycle-path runtime (pod-uid pod)))))))))
(test never-policy-does-not-recreate-terminal-containers-in-a-dead-sandbox
  (with-temporary-store (store directory)
    (let* ((now 4000000000) (gr8s::*container-lifecycle-clock* (lambda () now))
           (pod (lifecycle-pod store "Never")) (runtime (gr8s::make-containerd-runtime :log-root directory)))
      (with-lifecycle-cri (fixture pod (list (lifecycle-info "main" 0 gr8s.cri.v1::+containerstate-container_exited+ now)
                                           (lifecycle-info "side" 0 gr8s.cri.v1::+containerstate-container_exited+ now)))
        (setf (gr8s::cri-pod-sandbox-info-state (lifecycle-cri-fixture-sandbox fixture)) gr8s.cri.v1::+podsandboxstate-sandbox_notready+)
        (gr8s::runtime-ensure runtime pod)
        (is (null (lifecycle-cri-fixture-calls fixture)))
        (let ((saved (gr8s::load-container-lifecycle-state runtime (pod-uid pod))))
          (is (gr8s::lifecycle-all-containers-suppressed-p pod saved)))
        (is (equal "same-sandbox" (gr8s::cri-pod-sandbox-info-id (lifecycle-cri-fixture-sandbox fixture))))))))

(test failed-sandbox-recreation-does-not-rerun-a-successful-onfailure-container
  (with-temporary-store (store directory)
    (let* ((now 4000000000) (gr8s::*container-lifecycle-clock* (lambda () now))
           (pod (lifecycle-pod store)) (runtime (gr8s::make-containerd-runtime :log-root directory)))
      (with-lifecycle-cri (fixture pod (list (lifecycle-info "main" 0 gr8s.cri.v1::+containerstate-container_exited+ now)
                                           (lifecycle-info "side" 0 gr8s.cri.v1::+containerstate-container_exited+ now 7)))
        (setf (gr8s::cri-pod-sandbox-info-state (lifecycle-cri-fixture-sandbox fixture)) gr8s.cri.v1::+podsandboxstate-sandbox_notready+)
        (gr8s::runtime-ensure runtime pod)
        (is (equal '((:create "side" 1 "new-sandbox"))
                   (remove-if-not (lambda (call) (eq :create (first call))) (lifecycle-cri-fixture-calls fixture))))
        (is (gethash "restartSuppressed" (gethash "main" (gethash "containers" (gr8s::load-container-lifecycle-state runtime (pod-uid pod))))))))))

(test dead-sandbox-capture-does-not-adopt-an-obsolete-successful-predecessor
  (with-temporary-store (store directory)
    (let* ((now 4000000000) (gr8s::*container-lifecycle-clock* (lambda () now))
           (pod (lifecycle-pod store)) (runtime (gr8s::make-containerd-runtime :log-root directory)))
      (with-lifecycle-cri (fixture pod (list (lifecycle-info "main" 0 gr8s.cri.v1::+containerstate-container_running+ now)
                                           (lifecycle-info "side" 0 gr8s.cri.v1::+containerstate-container_exited+ now)
                                           (lifecycle-info "side" 1 gr8s.cri.v1::+containerstate-container_running+ now)))
        (gr8s::runtime-ensure runtime pod)
        (setf (lifecycle-cri-fixture-infos fixture)
              (remove "side-1" (lifecycle-cri-fixture-infos fixture) :test #'equal :key #'gr8s::cri-container-info-id)
              (gr8s::cri-pod-sandbox-info-state (lifecycle-cri-fixture-sandbox fixture))
              gr8s.cri.v1::+podsandboxstate-sandbox_notready+)
        (let* ((after (gr8s::runtime-ensure runtime pod))
               (entry (gethash "side" (gethash "containers" (gr8s::load-container-lifecycle-state runtime (pod-uid pod))))))
          (is (not (gethash "restartSuppressed" entry)))
          (is (= 2 (gethash "restartCount" (lifecycle-side-status after))))
          (is (find '(:create "side" 2 "new-sandbox") (lifecycle-cri-fixture-calls fixture) :test #'equal))
          (is (null (gethash "terminated" (gethash "state" (gethash "lastStatus" entry))))))))))

(test explicit-unknown-attempt-is-stopped-before-applying-restart-policy
  (dolist (policy '("Always" "OnFailure" "Never"))
    (with-temporary-store (store directory)
      (let* ((now 4000000000) (gr8s::*container-lifecycle-clock* (lambda () now))
             (pod (lifecycle-pod store policy)) (runtime (gr8s::make-containerd-runtime :log-root directory))
             (healthy (lifecycle-info "main" 0 gr8s.cri.v1::+containerstate-container_running+ now)))
        (with-lifecycle-cri (fixture pod (list healthy (lifecycle-info "side" 0 gr8s.cri.v1::+containerstate-container_unknown+ now)))
          (let* ((after (gr8s::runtime-reconcile-containers runtime pod (runtime-observe runtime (pod-uid pod))))
                 (side (lifecycle-side-status after)))
            (is (find '(:stop "side-0") (lifecycle-cri-fixture-calls fixture) :test #'equal))
            (is (eq healthy (find "main-0" (lifecycle-cri-fixture-infos fixture) :key #'gr8s::cri-container-info-id :test #'equal)))
            (is (equal "same-sandbox" (gr8s::cri-pod-sandbox-info-id (lifecycle-cri-fixture-sandbox fixture))))
            (if (equal "Never" policy)
                (progn
                  (is (notany (lambda (call) (eq :create (first call))) (lifecycle-cri-fixture-calls fixture)))
                  (is (= 137 (gethash "exitCode" (gethash "terminated" (gethash "state" side))))))
                (progn
                  (is (equal '((:create "side" 1 "same-sandbox") (:stop "side-0")) (lifecycle-cri-fixture-calls fixture)))
                  (is (= 137 (gethash "exitCode" (gethash "terminated" (gethash "lastState" side)))))))))))))

(test unknown-attempt-stop-must-obtain-a-real-exit-before-restarting
  (with-temporary-store (store directory)
    (let* ((now 4000000000) (pod (lifecycle-pod store)) (runtime (gr8s::make-containerd-runtime :log-root directory)))
      (with-lifecycle-cri (fixture pod (list (lifecycle-info "main" 0 gr8s.cri.v1::+containerstate-container_running+ now)
                                           (lifecycle-info "side" 0 gr8s.cri.v1::+containerstate-container_unknown+ now)))
        (replace-function 'gr8s::cri-stop-container
          (lambda (&rest args) (declare (ignore args)) (push '(:stop "side-0") (lifecycle-cri-fixture-calls fixture))))
        (let ((after (gr8s::runtime-ensure runtime pod)))
          (is (equal '((:stop "side-0")) (lifecycle-cri-fixture-calls fixture)))
          (is (equal "ContainerStatusUnknown" (gethash "reason" (gethash "waiting" (gethash "state" (lifecycle-side-status after))))))
          (is (null (gethash "lastTermination" (gethash "side" (gethash "containers" (gr8s::load-container-lifecycle-state runtime (pod-uid pod))))))))))))

(test cancelled-create-recovers-the-owned-created-attempt-without-duplicating-siblings
  (with-temporary-store (store directory)
    (let* ((pod (lifecycle-pod store))
           (runtime (gr8s::make-containerd-runtime :log-root directory))
           (now 4000000000) (gr8s::*container-lifecycle-clock* (lambda () now))
           (healthy (lifecycle-info "side" 0 gr8s.cri.v1::+containerstate-container_running+ now)))
      (with-lifecycle-cri (fixture pod (list healthy))
        (let ((create (symbol-function 'gr8s::containerd-create-container)))
          (unwind-protect
               (progn
                 (setf (symbol-function 'gr8s::containerd-create-container)
                       (lambda (&rest arguments)
                         ;; CRI committed the labeled attempt, but the client
                         ;; never received its reply or saved its watermark.
                         (apply create arguments)
                         (setf (gr8s::cri-container-info-state (first (lifecycle-cri-fixture-infos fixture)))
                               gr8s.cri.v1::+containerstate-container_created+)
                         (error 'gr8s::pod-reconciliation-superseded)))
                 (signals gr8s::pod-reconciliation-superseded (gr8s::runtime-ensure runtime pod)))
            (setf (symbol-function 'gr8s::containerd-create-container) create)))
        (gr8s::runtime-ensure runtime pod)
        (is (= 1 (count :create (lifecycle-cri-fixture-calls fixture) :key #'first)))
        (is (= 1 (count '(:start "main-0") (lifecycle-cri-fixture-calls fixture) :test #'equal)))
        (is (= 2 (length (lifecycle-cri-fixture-infos fixture))))
        (is (eq healthy (find "side-0" (lifecycle-cri-fixture-infos fixture)
                             :key #'gr8s::cri-container-info-id :test #'equal)))
        (is (null (find :stop (lifecycle-cri-fixture-calls fixture) :key #'first)))
        (is (null (find :new-sandbox (lifecycle-cri-fixture-calls fixture) :key #'first)))))))

(defun restart-rules-pod (pod-policy &rest side-fields)
  "Return a parsed Pod with POD-POLICY whose side container carries SIDE-FIELDS."
  (let* ((object (com.inuoe.jzon:parse *valid-pod-json*)) (spec (gethash "spec" object))
         (side (gr8s::core-object "name" "side" "image" "busybox")))
    (loop for (key value) on side-fields by #'cddr do (setf (gethash key side) value))
    (setf (gethash "restartPolicy" spec) pod-policy
          (gethash "containers" spec) (vector (gr8s::core-object "name" "main" "image" "busybox") side))
    (parse-pod object)))

(defun exit-code-rule (operator &rest values)
  "Return a Restart rule matching exit codes VALUES under OPERATOR."
  (gr8s::core-object "action" "Restart" "exitCodes" (gr8s::core-object "operator" operator "values" (coerce values 'vector))))

(test container-restart-rules-and-policy-override-the-pods
  (flet ((restarts (pod code &optional killed) (gr8s::container-restarts-after-exit-p pod "side" code killed)))
    ;; Without container settings the Pod's policy decides, as before.
    (is-true (restarts (restart-rules-pod "Always") 0))
    (is-true (restarts (restart-rules-pod "OnFailure") 1))
    (is-false (restarts (restart-rules-pod "OnFailure") 0))
    (is-true (restarts (restart-rules-pod "OnFailure") 0 t))
    (is-false (restarts (restart-rules-pod "Never") 1))
    ;; A container's own policy wins over the Pod's.
    (is-true (restarts (restart-rules-pod "Never" "restartPolicy" "Always") 0))
    (is-false (restarts (restart-rules-pod "Always" "restartPolicy" "Never") 1))
    ;; Rules are tried first, then the container's policy.
    (let ((pod (restart-rules-pod "Never" "restartPolicy" "Never" "restartPolicyRules" (vector (exit-code-rule "In" 42)))))
      (is-true (restarts pod 42))
      (is-false (restarts pod 1)))
    (let ((pod (restart-rules-pod "Never" "restartPolicy" "Never" "restartPolicyRules" (vector (exit-code-rule "NotIn" 0)))))
      (is-true (restarts pod 3))
      (is-false (restarts pod 0)))
    ;; The sibling without settings keeps the Pod's policy.
    (is-false (gr8s::container-restarts-after-exit-p
               (restart-rules-pod "Never" "restartPolicy" "Always") "main" 1)))
  (with-temporary-store (store directory)
    (values directory)
    (let* ((now 4000000000)
           (pod (create-pod store (restart-rules-pod "Never" "restartPolicy" "Never"
                                                     "restartPolicyRules" (vector (exit-code-rule "In" 42))))))
      (is-true (gr8s::container-restart-eligible-p
                pod (lifecycle-info "side" 0 gr8s.cri.v1::+containerstate-container_exited+ now 42)))
      (is-false (gr8s::container-restart-eligible-p
                 pod (lifecycle-info "side" 0 gr8s.cri.v1::+containerstate-container_exited+ now 1)))
      (is-false (gr8s::pod-applications-finished-p
                 pod (vector (gr8s::core-object "name" "main" "state" (gr8s::core-object "terminated" (gr8s::core-object "exitCode" 0)))
                             (gr8s::core-object "name" "side" "state" (gr8s::core-object "terminated" (gr8s::core-object "exitCode" 42)))))))))

(test container-restart-rules-are-validated
  (dolist (fields (list (list "restartPolicy" "Sometimes")
                        ;; Rules need an explicit container policy.
                        (list "restartPolicyRules" (vector (exit-code-rule "In" 42)))
                        (list "restartPolicy" "Never" "restartPolicyRules" (vector (exit-code-rule "Between" 42)))
                        (list "restartPolicy" "Never"
                              "restartPolicyRules" (vector (gr8s::core-object "action" "Restart")))
                        (list "restartPolicy" "Never"
                              "restartPolicyRules" (vector (gr8s::core-object "action" "RestartEverything"
                                                                              "exitCodes" (gr8s::core-object "operator" "In" "values" #(42)))))))
    (signals kubernetes-error (apply #'restart-rules-pod "Never" fields)))
  ;; RestartAllContainersOnContainerExits is beta and on in v1.37, so validateContainerRestartPolicy
  ;; (pkg/apis/core/validation/validation.go) accepts the RestartAllContainers action.
  (finishes (restart-rules-pod "Never" "restartPolicy" "Never"
                               "restartPolicyRules" (vector (gr8s::core-object "action" "RestartAllContainers"
                                                                               "exitCodes" (gr8s::core-object "operator" "In" "values" #(42))))))
  (finishes (restart-rules-pod "Never" "restartPolicy" "OnFailure"
                               "restartPolicyRules" (vector (exit-code-rule "In" 42 43) (exit-code-rule "NotIn" 1)))))
