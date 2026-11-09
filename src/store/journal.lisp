;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Monotonic Pod revisions and bounded in-memory watch journals. The store
;;;; owns the snapshots in these journals; API filtering and response encoding
;;;; remain in the resource layer.

(in-package #:gr8s.store)

(defparameter *pod-revision-reservation* 1024
  "Durably reserve this many revisions at once, so restarts never reuse a number.")

(defparameter *pod-watch-journal-limit* 16384
  "The most Pod events kept for resuming watches, however recent.")

(defparameter +pod-watch-journal-minimum+ 4096
  "Keep this many Pod events however old, for a cluster too quiet to fill the time window.")

(defparameter *pod-watch-journal-bytes* (* 96 1024 1024)
  "The most estimated memory that the Pod journal may retain.")

(defparameter +revision-journal-trim-interval+ 1024
  "Events between looks for what has aged out of a journal.")

(defparameter *watch-history-seconds* 600
  "Serve watches from revisions at least this old when journal limits permit.")

(defparameter *podtemplate-clock* #'get-universal-time
  "Clock shared by resource and Pod watch retention.")

(defun approximate-heap-bytes (value)
  "Estimate the memory a parsed JSON VALUE occupies, erring high, without allocating."
  (labels ((walk (value)
             (typecase value
               (hash-table
                (let ((bytes (+ 480 (* 40 (hash-table-count value)))))
                  (maphash (lambda (key item)
                             (incf bytes (+ (walk key) (walk item))))
                           value)
                  bytes))
               (string (+ 16 (* (if (typep value 'base-string) 1 4)
                                (length value))))
               (cons (+ 16 (walk (car value)) (walk (cdr value))))
               (vector (+ 16 (* 8 (length value))
                          (reduce #'+ value :key #'walk)))
               ((or fixnum symbol character) 0)
               (t 16))))
    (walk value)))

(defun json-value-equal-p (left right)
  "Return true when two parsed JSON values have the same structure and values."
  (cond
    ((and (hash-table-p left) (hash-table-p right))
     (and (= (hash-table-count left) (hash-table-count right))
          (loop for key being the hash-keys of left using (hash-value value)
                always (and (nth-value 1 (gethash key right))
                            (json-value-equal-p value (gethash key right))))))
    ((or (stringp left) (stringp right)) (equal left right))
    ((and (vectorp left) (vectorp right))
     (and (= (length left) (length right))
          (every #'json-value-equal-p left right)))
    ((and (numberp left) (numberp right)) (= left right))
    (t (eql left right))))

(defun write-text-atomically (path text)
  "Replace PATH with TEXT through a temporary sibling."
  (let ((temporary
          (make-pathname :name (format nil ".~A-~36R" (pathname-name path)
                                       (random (expt 36 12)))
                         :type "tmp" :defaults path)))
    (ensure-directories-exist path)
    (unwind-protect
         (progn
           (with-open-file (stream temporary :direction :output
                                            :if-exists :error
                                            :if-does-not-exist :create
                                            :external-format :utf-8)
             (write-string text stream))
           (uiop:rename-file-overwriting-target temporary path))
      (when (probe-file temporary) (delete-file temporary))))
  path)

(defun pod-revision-ceiling-path (store)
  "Return STORE's durable revision ceiling."
  (merge-pathnames "pod-revision.ceiling" (store-data-path store)))

(defun load-pod-revision (store)
  "Resume above every revision that could have been issued before the last shutdown."
  (let* ((path (pod-revision-ceiling-path store))
         (ceiling (if (probe-file path)
                      (parse-integer (uiop:read-file-string path))
                      0))
         (revision
           (reduce #'max
                   (append
                    (loop for pod being the hash-values of (pod-store-pods store)
                          collect (parse-integer (pod-resource-version pod)))
                    (loop for node being the hash-values of (pod-store-nodes store)
                          collect (parse-integer
                                   (node-record-resource-version node))))
                   :initial-value ceiling)))
    (setf (pod-store-pod-revision store) revision
          (pod-store-pod-revision-ceiling store) revision
          (pod-store-pod-watch-floor store) revision
          (pod-store-node-watch-floor store) revision)
    store))

(defun next-pod-revision-unlocked (store)
  "Allocate the next revision, durably reserving a new block before first use."
  (let ((next (1+ (pod-store-pod-revision store))))
    (when (> next (pod-store-pod-revision-ceiling store))
      (let ((ceiling (+ next *pod-revision-reservation*)))
        (write-text-atomically (pod-revision-ceiling-path store)
                               (write-to-string ceiling))
        (setf (pod-store-pod-revision-ceiling store) ceiling)))
    (setf (pod-store-pod-revision store) next)))

(defun pod-revision-satisfied-p (store expected actual)
  "Accept EXPECTED when it was issued at or after ACTUAL, the Pod's last spec write."
  (or (equal expected actual)
      (let ((number (and (stringp expected) (plusp (length expected))
                         (every #'digit-char-p expected)
                         (parse-integer expected))))
        (and number
             (>= number (parse-integer actual))
             (<= number (pod-store-pod-revision store))))))

(defun pod-published-view (store pod)
  "Return an independent API snapshot of POD using its last published status."
  (let ((object (copy-pod-status-value (pod-to-object pod)))
        (status (or (gethash (pod-uid pod)
                             (pod-store-pod-published-statuses store))
                    (let ((pending (make-hash-table :test #'equal)))
                      (setf (gethash "phase" pending) "Pending")
                      pending))))
    (setf (gethash "status" object) status)
    (when (pod-status-revision pod)
      (setf (gethash "resourceVersion" (gethash "metadata" object))
            (write-to-string (pod-status-revision pod))))
    object))

(defun trim-revision-journal (journal length bytes limit minimum byte-limit)
  "Return the newest entries worth keeping and their count, floor, and bytes."
  (when (or (> length (* 2 limit)) (> bytes byte-limit)
            (zerop (mod length +revision-journal-trim-interval+)))
    (let* ((minimum (min minimum limit))
           (budget (if (> bytes byte-limit)
                       (- byte-limit (floor byte-limit 8))
                       byte-limit))
           (now (funcall *podtemplate-clock*))
           (kept 0)
           (keep (or (loop for (nil nil nil time size) in journal
                           for count from 0
                           when (or (>= count limit)
                                    (and (plusp count) (> (+ kept size) budget))
                                    (and (>= count minimum)
                                         (> (- now time) *watch-history-seconds*)))
                             return count
                           do (incf kept size))
                     length)))
      (when (< keep length)
        (let ((retained (subseq journal 0 keep)))
          (values retained keep
                  (1- (first (car (last retained))))
                  kept))))))

(defun record-revision-journal-event (journal revision old new previous)
  "Add a revision transition to JOURNAL, sharing the preceding immutable view."
  (let ((shared (and old previous (json-value-equal-p old previous))))
    (cons (list revision (if shared previous old) new
                (funcall *podtemplate-clock*)
                (+ 64
                   (if (or shared (not (hash-table-p old)))
                       0
                       (approximate-heap-bytes old))
                   (if (hash-table-p new)
                       (approximate-heap-bytes new)
                       0)))
          journal)))

(defun pod-watch-view-uid (view)
  "Return the UID of the Pod API VIEW, or NIL."
  (and (hash-table-p view)
       (gethash "uid" (gethash "metadata" view))))

(defun record-pod-watch-event-unlocked (store revision old new)
  "Append one transition and compact entries outside the retention limits."
  (unless (pod-store-watch-journal-p store)
    (setf (pod-store-pod-watch-floor store) revision)
    (return-from record-pod-watch-event-unlocked nil))
  (let* ((uid (or (pod-watch-view-uid new) (pod-watch-view-uid old)))
         (views (pod-store-pod-watch-views store))
         (journal
           (record-revision-journal-event
            (pod-store-pod-watch-journal store) revision old new
            (and uid (gethash uid views)))))
    (setf (pod-store-pod-watch-journal store) journal)
    (when uid
      (if new
          (setf (gethash uid views) new)
          (remhash uid views)))
    (multiple-value-bind (retained length floor bytes)
        (trim-revision-journal
         journal
         (incf (pod-store-pod-watch-journal-length store))
         (incf (pod-store-pod-watch-journal-bytes store)
               (fifth (first journal)))
         *pod-watch-journal-limit* +pod-watch-journal-minimum+
         *pod-watch-journal-bytes*)
      (when retained
        (setf (pod-store-pod-watch-floor store) floor
              (pod-store-pod-watch-journal store) retained
              (pod-store-pod-watch-journal-length store) length
              (pod-store-pod-watch-journal-bytes store) bytes)))))

(defun publish-pod-spec-change-unlocked (store old pod)
  "Journal POD at its current revision; OLD is its prior API view."
  (record-pod-watch-event-unlocked
   store (parse-integer (pod-resource-version pod)) old
   (and (pod-store-watch-journal-p store)
        (pod-published-view store pod))))

(defun publish-pod-status-unlocked (store pod status)
  "Journal STATUS when it differs from what clients last saw for the current Pod."
  (let ((current (gethash (pod-key (pod-namespace pod) (pod-name pod))
                          (pod-store-pods store)))
        (uid (pod-uid pod)))
    (when (and current
               (equal uid (pod-uid current))
               (not (equalp status
                            (gethash uid
                                     (pod-store-pod-published-statuses store)))))
      (when (pod-stage-active-p store)
        (stage-pod-write store current :status t)
        ;; Readers may retain the committed Pod object beyond the lock.
        (setf current (gr8s.model::copy-pod current)
              (gethash (pod-key (pod-namespace current) (pod-name current))
                       (pod-store-pods store)) current))
      (let ((old (and (pod-store-watch-journal-p store)
                      (pod-published-view store current)))
            (revision (next-pod-revision-unlocked store)))
        (setf (gethash uid (pod-store-pod-published-statuses store))
              (copy-pod-status-value status)
              (pod-status-revision current) revision)
        (record-pod-watch-event-unlocked
         store revision old (and old (pod-published-view store current)))))))

(defun publish-pod-removal-unlocked (store pod)
  "Journal POD's final API view as a deletion at a fresh revision."
  (let ((old (and (pod-store-watch-journal-p store)
                  (pod-published-view store pod))))
    (record-pod-watch-event-unlocked
     store (next-pod-revision-unlocked store) old nil)
    (remhash (pod-uid pod) (pod-store-pod-published-statuses store))))
