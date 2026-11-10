;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
(in-package #:gr8s.resources)

(defparameter +core-checkpoint-fields+
  '("version" "revision" "workloadDeletions" "jobControllerStates" "templateHistory"
    "templateHistoryFloor" "templateTokenKey" "secretsEncryption" "resourceHistoryStart"
    "eventExpirations" "items" "customResourceItems"))

(defun skip-core-checkpoint-value (parser)
  "Consume one value without retaining its containers, keys or earlier strings."
  (loop with depth = 0
        for token = (progn (maybe-collect-core-recovery-garbage) (com.inuoe.jzon:parse-next parser))
        do (case token
             ((:begin-array :begin-object)
              (when (> (incf depth) 127) (error "Core checkpoint nesting exceeds limit")))
             ((:end-array :end-object) (when (zerop (decf depth)) (return)))
             (:value (when (zerop depth) (return)))
             ((nil) (error "Truncated core checkpoint value")))))

(defun map-core-checkpoint-fields (stream visitor)
  "VISITOR consumes each field value. Reject duplicate known fields and trailing input."
  ;; A parser-wide key pool would retain keys from already discarded history.
  (com.inuoe.jzon:with-parser (parser stream :key-fn nil :max-string-length (* 2 1024 1024))
    (unless (eq :begin-object (com.inuoe.jzon:parse-next parser))
      (error "Core checkpoint must be an object"))
    (let ((seen (make-hash-table :test 'equal)))
      (loop
        (multiple-value-bind (token key) (com.inuoe.jzon:parse-next parser)
          (case token
            (:object-key
             (when (member key +core-checkpoint-fields+ :test #'equal)
               (when (gethash key seen) (error "Duplicate core checkpoint field ~A" key))
               (setf (gethash key seen) t))
             (funcall visitor parser key))
            (:end-object
             (when (com.inuoe.jzon:parse-next parser) (error "Trailing core checkpoint content"))
             (return))
            (t (error "Incomplete core checkpoint object"))))))))

(defun map-core-checkpoint-array (parser visitor)
  (unless (eq :begin-array (com.inuoe.jzon:parse-next parser))
    (error "Core checkpoint collection must be an array"))
  (loop with end = (gensym "ARRAY-END")
        for value = (progn (maybe-collect-core-recovery-garbage)
                           (com.inuoe.jzon:parse-next-element parser :max-depth 126
                                                                  :eof-error-p nil :eof-value end))
        until (eq value end) do (funcall visitor value)))

(defun core-checkpoint-history-key (entry)
  ;; Version 1 PodTemplate history predates the explicit resource field.
  (let ((resource (gethash "resource" entry "podtemplates"))
        (namespace (gethash "namespace" entry)) (name (gethash "name" entry)))
    (unless (and (stringp resource) (stringp name)) (error "Invalid checkpoint history identity"))
    (core-resource-key resource (unless (member namespace '(nil null)) namespace) name)))

(defun read-core-checkpoint (store path)
  "Load schema 1/2 without an aggregate parse or duplicated history versions.
Read encryption metadata first, then rewind the same descriptor. History is
decrypted, deduplicated by exact value and trimmed while records are consumed."
  (with-open-file (stream path :external-format :utf-8)
    (let ((config nil))
      (map-core-checkpoint-fields stream
        (lambda (parser key)
          (if (equal key "secretsEncryption")
              (setf config (com.inuoe.jzon:parse-next-element parser :max-depth 127))
              (skip-core-checkpoint-value parser))))
      (unless (file-position stream 0) (error "Cannot rewind core checkpoint"))
      ;; Decryption needs paths/config, not a second copy of application state.
      ;; Keep STORE unchanged if parsing or authentication fails.
      (let ((crypto-store (gr8s.store::copy-pod-store store))
            (state (make-hash-table :test 'equal))
            (history nil) (tail nil) (history-count 0) (history-bytes 0) (floor 0)
            (versions (make-hash-table :test 'equal))
            (items (make-hash-table :test 'equal)))
        (setf (pod-store-secret-encryption-config crypto-store) config)
        (labels ((same-value (value candidate)
                   (if (and (hash-table-p value) (hash-table-p candidate)
                            (gr8s.store::json-value-equal-p value candidate)) candidate value))
                 (drop-entry (entry)
                   (decf history-count)
                   (decf history-bytes (template-history-entry-bytes entry))
                   (setf floor (max floor (gethash "revision" entry)))
                   (let ((key (core-checkpoint-history-key entry)))
                     (when (eq entry (gethash key versions)) (remhash key versions))))
                 (add-history (raw)
                   (unless (and (hash-table-p raw) (typep (gethash "revision" raw) '(integer 0 *)))
                     (error "Invalid checkpoint history revision"))
                   ;; Authenticate even an entry that retention will discard.
                   (let* ((entry (decrypt-secret-history-entry crypto-store raw))
                          (key (core-checkpoint-history-key entry))
                          (previous (gethash key versions)) (current (gethash key items)))
                     (dolist (field '("old" "new"))
                       (let ((value (gethash field entry)))
                         (unless (or (hash-table-p value) (member value '(nil null)))
                           (error "Invalid checkpoint history object"))
                         (setf (gethash field entry)
                               (same-value (same-value value (and previous (gethash "new" previous))) current))))
                     ;; Wire caches can describe another representation; measure
                     ;; the actual decrypted/shared objects once on this host.
                     (setf (gethash "bytes" entry) (template-history-old-bytes (gethash "old" entry))
                           (gethash "bytesVersion" entry) +resource-history-bytes-version+)
                     (when (> (gethash "revision" entry) floor)
                       (let ((cell (list entry)))
                         (if tail (setf (cdr tail) cell) (setf history cell))
                         (setf tail cell))
                       (incf history-count)
                       (incf history-bytes (template-history-entry-bytes entry))
                       (if (hash-table-p (gethash "new" entry))
                           (setf (gethash key versions) entry) (remhash key versions))
                       (loop while (and history
                                        (or (> history-count *podtemplate-history-limit*)
                                            (> history-bytes *resource-watch-history-bytes*)
                                            (<= (gethash "revision" (first history)) floor)))
                             do (drop-entry (pop history)))
                       (unless history (setf tail nil)))))
                 (add-item (resource object)
                   (unless (hash-table-p object) (error "Invalid checkpoint item"))
                   (let* ((key (core-resource-key-from-object resource object))
                          (entry (gethash key versions))
                          (value (same-value object (and entry (gethash "new" entry)))))
                     (when (gethash key items) (error "Duplicate checkpoint resource ~S" key))
                     (setf (gethash key items) value)
                     value)))
          (map-core-checkpoint-fields stream
            (lambda (parser key)
              (cond
                ((equal key "templateHistory") (map-core-checkpoint-array parser #'add-history))
                ((member key '("items" "customResourceItems") :test #'equal)
                 (let ((values (make-array 0 :adjustable t :fill-pointer 0)))
                   (map-core-checkpoint-array parser
                     (lambda (raw)
                       (if (equal key "items")
                           (let* ((kind (and (hash-table-p raw) (gethash "kind" raw)))
                                  (resource (or (first (or (find kind *stored-resource-types* :key #'second :test #'equal)
                                                          (find kind *internal-stored-resource-types* :key #'second :test #'equal)))
                                                (error "Invalid stored resource kind")))
                                  (object (decrypt-secret-object crypto-store resource raw)))
                             (vector-push-extend (add-item resource object) values))
                           (progn
                             (unless (hash-table-p raw) (error "Invalid custom checkpoint item"))
                             (setf (gethash "object" raw) (add-item (gethash "resource" raw) (gethash "object" raw)))
                             (vector-push-extend raw values)))))
                   (setf (gethash key state) values)))
                ((equal key "secretsEncryption")
                 (skip-core-checkpoint-value parser) (setf (gethash key state) config))
                ((member key +core-checkpoint-fields+ :test #'equal)
                 (setf (gethash key state) (com.inuoe.jzon:parse-next-element parser :max-depth 127)))
                (t (skip-core-checkpoint-value parser)))))
          (unless (and (member (gethash "version" state) '(1 2))
                       (typep (gethash "revision" state) '(integer 0 *)))
            (error "Invalid checkpoint version or revision"))
          (when (and (eql 2 (gethash "version" state))
                     (not (typep (gethash "resourceHistoryStart" state) `(integer 0 ,(gethash "revision" state)))))
            (error "Invalid checkpoint resource history start"))
          (let ((original (gethash "templateHistoryFloor" state (gethash "revision" state))))
            (unless (typep original `(integer 0 ,(gethash "revision" state))) (error "Invalid checkpoint history floor"))
            (setf floor (max floor original)))
          (unless (and (<= floor (gethash "revision" state))
                       (every (lambda (entry) (<= (gethash "revision" entry) (gethash "revision" state))) history))
            (error "Checkpoint history is ahead of its revision"))
          ;; Keep whole transactions even when a root floor follows the array.
          (setf history (remove-if (lambda (entry) (<= (gethash "revision" entry) floor)) history))
          (setf (gethash "templateHistory" state) (coerce history 'vector)
                (gethash "templateHistoryFloor" state) floor)
          (unless (nth-value 1 (gethash "items" state)) (setf (gethash "items" state) #()))
          ;; Items may precede history in legacy/arbitrarily ordered objects.
          ;; Reuse their exact values there too, without altering public values.
          (dolist (entry history)
            (let ((current (gethash (core-checkpoint-history-key entry) items)))
              (dolist (field '("old" "new"))
                (setf (gethash field entry) (same-value (gethash field entry) current)))))
          state)))))
