;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
(in-package #:gr8s.store)

(defstruct pod-write-context store revision (changes (make-hash-table :test #'equal)) journal)
(defstruct pod-write-change old desired status snapshots)
(defparameter *pod-transaction-tables*
  (list #'pod-store-pod-observed-statuses #'pod-store-pod-observed-resource-versions
        #'pod-store-pod-observed-phases #'pod-store-pod-published-statuses
        #'pod-store-pod-condition-histories #'pod-store-pod-client-statuses
        #'pod-store-pod-finalization-states #'pod-store-pod-watch-views
        #'pod-store-nominated-nodes #'pod-store-scheduling-notes))

(defun pod-stage-active-p (store)
  (and *core-write-active* *pod-write-context*
       (eq store (pod-write-context-store *pod-write-context*))))

(defun stage-pod-write (store pod &key desired status)
  "Remember only the affected key's committed pointers before a private mutation."
  (when (pod-stage-active-p store)
    (let* ((context *pod-write-context*)
           (key (pod-key (pod-namespace pod) (pod-name pod)))
           (change (gethash key (pod-write-context-changes context))))
      (unless (pod-write-context-journal context)
        (setf (pod-write-context-journal context)
              (list (pod-store-pod-watch-journal store) (pod-store-pod-watch-floor store)
                    (pod-store-pod-watch-journal-length store) (pod-store-pod-watch-journal-bytes store))))
      (unless change
        (setf change (make-pod-write-change :old (gethash key (pod-store-pods store)))
              (gethash key (pod-write-context-changes context)) change))
      (dolist (uid (remove-duplicates
                    (remove nil (list (pod-uid pod)
                                      (and (pod-write-change-old change)
                                           (pod-uid (pod-write-change-old change))))) :test #'equal))
        (dolist (getter *pod-transaction-tables*)
          (let ((table (funcall getter store)))
            (unless (find-if (lambda (saved) (and (eq table (first saved)) (equal uid (second saved))))
                             (pod-write-change-snapshots change))
              (multiple-value-bind (value present) (gethash uid table)
                (push (list table uid value present) (pod-write-change-snapshots change)))))))
      (when desired (setf (pod-write-change-desired change) t))
      (when status (setf (pod-write-change-status change) t))
      (setf *pending-pod-commit* (pod-write-context-changes context)))))

(defun restore-staged-pods (context)
  "Restore committed pointers before releasing the lock, including on nonlocal exit."
  (let ((store (pod-write-context-store context)))
    (setf (pod-store-pod-revision store) (pod-write-context-revision context))
    (maphash
     (lambda (key change)
       (if (pod-write-change-old change)
           (setf (gethash key (pod-store-pods store)) (pod-write-change-old change))
           (remhash key (pod-store-pods store)))
       (dolist (saved (pod-write-change-snapshots change))
         (destructuring-bind (table uid value present) saved
           (if present (setf (gethash uid table) value) (remhash uid table)))))
     (pod-write-context-changes context))
    (when (pod-write-context-journal context)
      (destructuring-bind (journal floor count bytes) (pod-write-context-journal context)
        (setf (pod-store-pod-watch-journal store) journal
              (pod-store-pod-watch-floor store) floor
              (pod-store-pod-watch-journal-length store) count
              (pod-store-pod-watch-journal-bytes store) bytes)))))

(defun pod-checkpoint-object (store pod)
  (let ((uid (pod-uid pod)))
    (store-json-object
     "conditions" (or (gethash uid (pod-store-pod-condition-histories store)) #())
     "clientStatus" (gethash uid (pod-store-pod-client-statuses store))
     "finalization" (gethash uid (pod-store-pod-finalization-states store))
     "status" (gethash uid (pod-store-pod-observed-statuses store))
     "observedResourceVersion" (gethash uid (pod-store-pod-observed-resource-versions store)))))

(defun pod-publication-object (store pod)
  (store-json-object "uid" (pod-uid pod)
                     "resourceVersion" (write-to-string
                                         (or (pod-status-revision pod)
                                             (parse-integer (pod-resource-version pod))))
                     "status" (or (gethash (pod-uid pod) (pod-store-pod-published-statuses store))
                                  (pending-pod-status))))

(defun pod-state-delta-json (store context)
  "Freeze only changed Pods. Status-only changes never carry desired objects."
  (let ((changes nil))
    (maphash
     (lambda (key change)
       (let* ((pod (gethash key (pod-store-pods store)))
              (old (pod-write-change-old change))
              (identity (or pod old))
              (entry (store-json-object
                      "namespace" (pod-namespace identity) "name" (pod-name identity)
                      "uid" (pod-uid identity) "desired" (pod-write-change-desired change)
                      "expectedUID" (and old (pod-uid old))
                      "expectedResourceVersion" (and old (pod-resource-version old)))))
         (when (pod-write-change-desired change)
           (setf (gethash "object" entry) (if pod (pod-to-object pod) 'null)))
         (when (and pod (pod-write-change-status change))
           (setf (gethash "desiredResourceVersion" entry) (pod-resource-version pod)
                 (gethash "checkpoint" entry) (pod-checkpoint-object store pod)
                 (gethash "publication" entry) (pod-publication-object store pod)))
         (push entry changes)))
     (pod-write-context-changes context))
    (com.inuoe.jzon:stringify
     (store-json-object "version" 1 "resourceVersion" (write-to-string (pod-store-pod-revision store))
                        "changes" (coerce (nreverse changes) 'vector)))))

(defun call-with-store-transaction (store function)
  (if (pod-store-consensus-commit-fn store)
      (bt:with-lock-held ((pod-store-consensus-write-lock store))
        (let ((*pending-consensus-commit* nil) (*pending-pod-commit* nil) (*pending-node-commit* nil)
              (*core-write-active* t) (*pod-write-context* (make-pod-write-context :store store))
              (payload nil) (node-payload nil))
          (multiple-value-prog1
              (bt:with-lock-held ((pod-store-lock store))
                (unless (pod-store-consensus-pod-revision store)
                  (save-consensus-pod-revision-unlocked store))
                (setf (pod-write-context-revision *pod-write-context*) (pod-store-pod-revision store))
                (unwind-protect
                     (multiple-value-prog1 (funcall function)
                       (when *pending-pod-commit*
                         (setf payload (pod-state-delta-json store *pod-write-context*)))
                       (when *pending-node-commit*
                         (setf node-payload (node-state-delta-json *pending-node-commit* (pod-store-pod-revision store)))))
                  (restore-staged-pods *pod-write-context*)))
            (let ((*pod-write-context* nil))
              (when *pending-consensus-commit*
                (funcall (pod-store-consensus-commit-fn store) :core-delta *pending-consensus-commit*))
              (when payload
                (let ((result (funcall (pod-store-consensus-commit-fn store) :pod-delta payload)))
                  (when (and (consp result) (eq :pod-conflict (first result)))
                    (error 'kubernetes-error :status-code 409 :reason "Conflict"
                           :message "Pod changed before its consensus transaction committed"))))
              (when node-payload
                (funcall (pod-store-consensus-commit-fn store) :node-delta node-payload))))))
      (bt:with-lock-held ((pod-store-lock store)) (funcall function))))

(defun pod-delta-current (store entry)
  (gethash (pod-key (gethash "namespace" entry) (gethash "name" entry)) (pod-store-pods store)))

(defun pod-delta-precondition-p (current entry)
  (let ((uid (gethash "expectedUID" entry)) (version (gethash "expectedResourceVersion" entry)))
    (if uid
        (and current (equal uid (pod-uid current)) (equal version (pod-resource-version current)))
        (null current))))

(defun pod-delta-already-applied-p (current entry)
  "Recognize this exact desired result after an interrupted local application."
  (let ((object (gethash "object" entry)))
    (if (eq object 'null)
        (null current)
        (and current (equal (gethash "uid" entry) (pod-uid current))
             (json-value-equal-p object (pod-to-object current))))))

(defun install-pod-state-delta (store json)
  "Apply explicit Pod keys in consensus order; never delete an unmentioned Pod.
Desired preconditions are checked before any key is changed. Observations target
an exact UID and desired revision, so delayed reports cannot recreate a Pod."
  (bt:with-lock-held ((pod-store-lock store))
    (let* ((*core-write-active* nil)
           (delta (com.inuoe.jzon:parse json))
           (changes (gethash "changes" delta)))
      (unless (and (eql 1 (gethash "version" delta)) (vectorp changes) (not (stringp changes)))
        (error "Invalid Pod delta"))
      (let ((seen (make-hash-table :test #'equal)))
        (loop for entry across changes do
          (unless (and (hash-table-p entry)
                       (every (lambda (field) (stringp (gethash field entry))) '("namespace" "name" "uid")))
            (error "Invalid Pod delta identity"))
          (let ((key (pod-key (gethash "namespace" entry) (gethash "name" entry)))
                (object (gethash "object" entry)))
            (when (gethash key seen) (error "Duplicate Pod delta key"))
            (setf (gethash key seen) t)
            (when (and (gethash "desired" entry) (not (eq object 'null)))
              (let ((metadata (and (hash-table-p object) (gethash "metadata" object))))
                (unless (and (hash-table-p metadata)
                             (every (lambda (field) (equal (gethash field entry) (gethash field metadata)))
                                    '("namespace" "name" "uid")))
                  (error "Pod delta object differs from its declared identity")))))))
      (loop for entry across changes
            when (and (gethash "desired" entry)
                      (not (or (pod-delta-precondition-p (pod-delta-current store entry) entry)
                               (pod-delta-already-applied-p (pod-delta-current store entry) entry))))
              do (return-from install-pod-state-delta (list :pod-conflict)))
      (loop for entry across changes
            for old = (pod-delta-current store entry)
            for desired = (gethash "desired" entry)
            for object = (gethash "object" entry)
            do (cond
                 ((and desired (eq object 'null))
                  (when old (remove-pod-unlocked store (pod-namespace old) (pod-name old) :uid (pod-uid old))))
                 ((or desired
                      (and old (equal (gethash "uid" entry) (pod-uid old))
                           (equal (gethash "desiredResourceVersion" entry) (pod-resource-version old))))
                  (let* ((uid (gethash "uid" entry))
                         (same-identity (and old (equal uid (pod-uid old))))
                         (checkpoint (or (gethash "checkpoint" entry)
                                         (and same-identity (pod-checkpoint-object store old))))
                         (publication (or (gethash "publication" entry)
                                          (and same-identity (pod-publication-object store old))))
                         (status (and checkpoint (gethash "status" checkpoint)))
                         (snapshot (store-json-object
                                    "pods" (vector (if desired object (pod-to-object old)))
                                    "observations" (if status
                                                       (vector (store-json-object
                                                                "uid" uid "status" status
                                                                "resourceVersion" (gethash "observedResourceVersion" checkpoint))) #())
                                    "published" (if publication (vector publication) #())
                                    "resourceVersion" (gethash "resourceVersion" delta))))
                    (when (and old (not same-identity))
                      (remove-pod-unlocked store (pod-namespace old) (pod-name old) :uid (pod-uid old)))
                    (install-pod-state-object-unlocked store snapshot :partial t)
                    (let ((pod (pod-delta-current store entry)))
                      (when checkpoint
                        (dolist (field '(("conditions" . pod-store-pod-condition-histories)
                                         ("clientStatus" . pod-store-pod-client-statuses)
                                         ("finalization" . pod-store-pod-finalization-states)))
                          (let ((table (funcall (cdr field) store)) (value (gethash (car field) checkpoint)))
                            (if value (setf (gethash uid table) value) (remhash uid table))))
                        (persist-pod-status-state store pod)))))))
      (advance-replicated-pod-revision-unlocked store (replicated-pod-revision (gethash "resourceVersion" delta)))
      (save-consensus-pod-revision-unlocked store)
      (list :pod-ok))))

(defun consensus-pod-revision-path (store)
  (merge-pathnames "metadata/consensus-pod-revision.txt" (pod-store-path store)))

(defun save-consensus-pod-revision-unlocked (store)
  "Persist the committed clock, independent of speculative reservation ceilings."
  (let ((revision (pod-store-pod-revision store)))
    (unless (eql revision (pod-store-consensus-pod-revision store))
      (let* ((target (consensus-pod-revision-path store))
             (temporary (make-pathname :name (format nil ".clock-~A" (generate-uid))
                                        :type "tmp" :defaults target)))
        (ensure-directories-exist target)
        (unwind-protect
             (progn
               (let ((fd (sb-posix:open (namestring temporary)
                                       (logior sb-posix:o-wronly sb-posix:o-creat sb-posix:o-excl) #o600))
                     (stream nil))
                 (unwind-protect
                      (progn
                        (setf stream (sb-sys:make-fd-stream fd :output t :element-type 'character :auto-close t))
                        (write-string (write-to-string revision) stream)
                        (finish-output stream)
                        (sb-posix:fsync fd))
                   (if stream (close stream) (sb-posix:close fd))))
               (uiop:rename-file-overwriting-target temporary target)
               (let ((fd (sb-posix:open (namestring (uiop:pathname-directory-pathname target)) sb-posix:o-rdonly 0)))
                 (unwind-protect (sb-posix:fsync fd) (sb-posix:close fd)))
               (setf (pod-store-consensus-pod-revision store) revision))
          (when (probe-file temporary) (delete-file temporary)))))))

(defun load-consensus-pod-revision (store)
  "Resume a replicated store from its committed clock, not unused reservations."
  (let ((path (consensus-pod-revision-path store)))
    (when (probe-file path)
      (let ((revision (parse-integer (uiop:read-file-string path))))
        (unless (and (not (minusp revision))
                     (loop for pod being the hash-values of (pod-store-pods store)
                           always (<= (parse-integer (pod-resource-version pod)) revision))
                     (loop for node being the hash-values of (pod-store-nodes store)
                           always (<= (parse-integer (node-record-resource-version node)) revision)))
          (error "Committed revision clock disagrees with durable objects; recover the Raft state"))
        (setf (pod-store-pod-revision store) revision
              (pod-store-consensus-pod-revision store) revision
              (pod-store-pod-watch-floor store) revision
              (pod-store-node-watch-floor store) revision))))
  store)
