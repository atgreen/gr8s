;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
(in-package #:gr8s.store)

(defparameter *store-application-reload-fields*
  '(pod-store-pods pod-store-nodes pod-store-resources pod-store-resource-revision
    pod-store-template-history pod-store-template-history-recent pod-store-template-history-maintained-at
    pod-store-template-history-floor pod-store-resource-history-start pod-store-template-token-key
    pod-store-secret-encryption-config
    pod-store-event-expirations pod-store-core-journal-bytes pod-store-core-checkpoint-bytes pod-store-core-checkpoint-needed
    pod-store-verified-tokens pod-store-projected-tokens pod-store-pod-certificates
    pod-store-workload-deletions pod-store-job-controller-states
    pod-store-pod-finalization-states pod-store-pod-observed-phases pod-store-pod-observed-statuses
    pod-store-pod-observed-resource-versions pod-store-pod-condition-histories
    pod-store-consensus-pod-revision pod-store-pod-revision pod-store-pod-revision-ceiling pod-store-pod-revision-epoch-floor
    pod-store-pod-watch-floor pod-store-pod-watch-journal pod-store-pod-watch-journal-length
    pod-store-pod-watch-journal-bytes pod-store-pod-watch-views
    pod-store-node-watch-floor pod-store-node-watch-journal pod-store-node-watch-journal-length pod-store-node-watch-journal-bytes
    pod-store-pod-published-statuses pod-store-pod-client-statuses
    pod-store-nominated-nodes pod-store-scheduling-notes)
  "Reset only application payload/index state and caches derived from it.")

(defparameter *store-member-reload-fields*
  '(pod-store-path pod-store-data-root pod-store-access-blocked pod-store-application-loaded-p
    pod-store-active-requests pod-store-access-condition pod-store-in-cluster-config
    pod-store-credential-lock pod-store-service-account-signing-key pod-store-workload-lock
    pod-store-watch-journal-p pod-store-lock pod-store-image-tracker pod-store-consensus-commit-fn pod-store-consensus-write-lock)
  "Member-owned fields retained across reload; DATA-ROOT/LOADED-P are explicitly transitioned.")

(defun reset-store-application (store)
  "Drop old application references without constructing a second loaded store. Caller owns all barriers."
  (let ((empty (make-pod-store (pod-store-path store))))
    (dolist (accessor *store-application-reload-fields*)
      (funcall (fdefinition (list 'setf accessor)) (funcall accessor empty) store)))
  (gr8s.image-distribution::clear-image-tracker-state (pod-store-image-tracker store))
  store)

(defun require-store-reload-quiescence (store)
  (unless (and (eq :blocked (pod-store-access-blocked store))
               (zerop (pod-store-active-requests store)))
    (store-access-unavailable "Application reload requires a drained access gate")))

(defun check-store-reload-revisions (store id descriptor)
  "Reject stale staged clocks BEFORE intent or selection changes. Caller holds all barriers."
  (let* ((path (store-generation-root (pod-store-path store) id))
         (boundary (progn (check-store-generation-directory (merge-pathnames "metadata/" path))
                          (read-private-generation-json (merge-pathnames "metadata/snapshot-boundary.json" path)))))
    (unless (and (hash-table-p boundary) (= 7 (hash-table-count boundary))
                 (eql 1 (gethash "version" boundary))
                 (eql (gethash "index" descriptor) (gethash "index" boundary))
                 (eql (gethash "term" descriptor) (gethash "term" boundary))
                 (typep (gethash "resourceRevision" boundary) '(unsigned-byte 64))
                 (typep (gethash "resourceEpochFloor" boundary) `(integer 0 ,(gethash "resourceRevision" boundary)))
                 (typep (gethash "podRevision" boundary) '(unsigned-byte 64))
                 (typep (gethash "podEpochFloor" boundary) `(integer 0 ,(gethash "podRevision" boundary))))
      (error "Invalid materialized snapshot revision boundary"))
    ;; A failed load may already have installed these exact clocks. Retry the
    ;; pending generation without demanding another revision bump.
    (unless (and (not (pod-store-application-loaded-p store)) (equal path (store-data-path store)))
      (unless (and (> (gethash "resourceEpochFloor" boundary) (pod-store-resource-revision store))
                   (> (gethash "podEpochFloor" boundary) (max (pod-store-pod-revision store)
                                                           (pod-store-pod-revision-ceiling store))))
        (error "Snapshot generation must be rematerialized above the member's revision clocks")))
    boundary))

(defun reload-store-application (store id &key call-with-member-lock commit-recovery)
  "Replace application state on STORE itself, leaving access blocked on success or failure.
Caller has quiesced remaining node/controller/retained-reference ingress. Lock order:
workload -> credentials -> consensus writer -> supplied member barrier -> raw store.
HA requires both callbacks. COMMIT-RECOVERY receives descriptor/STORE after load and
must durably coordinate member snapshot/applied/WAL state before intent removal.
It runs under the barriers and must not reenter public store operations."
  (when (or *core-write-active* (eq store *store-request-lease*))
    (error "Cannot reload application state from a transaction or leased request"))
  (when (or (and call-with-member-lock (not (functionp call-with-member-lock)))
            (and commit-recovery (not (functionp commit-recovery)))
            (and (pod-store-consensus-commit-fn store)
                 (not (and call-with-member-lock commit-recovery))))
    (error "HA application reload requires member barrier and durable recovery callbacks"))
  (bt:with-lock-held ((pod-store-lock store)) (require-store-reload-quiescence store))
  (let ((thread (bt:current-thread)) (started nil) (loaded nil) (descriptor nil) (boundary nil))
    (bt:with-lock-held ((pod-store-workload-lock store))
      (bt:with-lock-held ((pod-store-credential-lock store))
        (bt:with-lock-held ((pod-store-consensus-write-lock store))
          (funcall
           (or call-with-member-lock #'funcall)
           (lambda ()
             (unless (and (eq thread (bt:current-thread)) (not started))
               (error "Member barrier must invoke reload synchronously exactly once"))
             (setf started t)
             (bt:with-lock-held ((pod-store-lock store))
               (require-store-reload-quiescence store)
               (setf descriptor (checked-store-generation-descriptor (pod-store-path store) id))
               (setf boundary (check-store-reload-revisions store id descriptor))
               ;; Validate and durably announce target BEFORE releasing old data.
               (setf descriptor (begin-store-restore (pod-store-path store) id))
               (setf (pod-store-application-loaded-p store) nil)
               (resume-store-restore-selection (pod-store-path store))
               (let ((*core-write-active* nil) (*pod-write-context* nil)
                     (*pending-consensus-commit* nil) (*pending-pod-commit* nil) (*pending-node-commit* nil))
                 (reset-store-application store)
                 (setf (pod-store-data-root store) (store-generation-root (pod-store-path store) id))
                 ;; Reclaim released payloads before allocating the new application.
                 (sb-ext:gc :full t)
                 (load-store-application-files store))
               (unless (and (= (pod-store-resource-revision store) (gethash "resourceRevision" boundary))
                            (>= (pod-store-template-history-floor store) (gethash "resourceEpochFloor" boundary))
                            (= (pod-store-pod-revision-epoch-floor store) (gethash "podEpochFloor" boundary))
                            (>= (pod-store-pod-revision store) (gethash "podRevision" boundary)))
                 (error "Loaded application clocks disagree with staged snapshot boundary"))
               (when commit-recovery (funcall commit-recovery descriptor store))
               (finish-store-restore store descriptor)
               (setf (pod-store-application-loaded-p store) t loaded t)))))))
    (unless loaded (error "Member barrier did not complete application reload"))
    (values store descriptor)))
