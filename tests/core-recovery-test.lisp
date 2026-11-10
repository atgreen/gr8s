;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
(in-package #:gr8s/tests)
(def-suite core-recovery :in gr8s)
(in-suite core-recovery)

(defun recovery-record (revision &optional (value "value"))
  (gr8s::core-object
   "revision" revision "time" revision
   "changes" (vector (gr8s::core-object
                     "resource" "configmaps" "namespace" "default" "name" "sample"
                     "object" (gr8s::core-object
                               "apiVersion" "v1" "kind" "ConfigMap"
                               "metadata" (gr8s::core-object "name" "sample" "namespace" "default")
                               "data" (gr8s::core-object "key" value))))))

(test journal-reader-preserves-utf8-offsets-and-ignores-torn-tail
  (with-temporary-store (store path)
    (declare (ignore path))
    (let* ((journal (gr8s::core-journal-path store))
           (line (concatenate 'string (com.inuoe.jzon:stringify (recovery-record 1 "λ魚")) (string #\Newline)))
           (bytes (trivial-utf-8:string-to-utf-8-bytes line)))
      (ensure-directories-exist journal)
      (with-open-file (output journal :direction :output :if-exists :supersede :element-type '(unsigned-byte 8))
        (write-sequence bytes output)
        ;; Even malformed UTF-8 is harmless in an unterminated final record.
        (write-sequence #(123 34 255) output))
      (multiple-value-bind (records torn complete) (gr8s::read-core-journal-records journal)
        (is (= 1 (length records)))
        (is-true torn)
        (is (= (length bytes) complete)))
      (with-open-file (output journal :direction :output :if-exists :append :element-type '(unsigned-byte 8))
        (write-byte 10 output))
      ;; The same corruption is fatal once its record is newline-terminated.
      (signals error (gr8s::read-core-journal-records journal)))))

(test recovery-streams-records-and-trims-history-during-replay
  (with-temporary-store (store path)
    (declare (ignore path))
    (gr8s::create-core-resource store "configmaps" (configmap-input "sample" "key" "base") "default")
    (let ((gr8s::*podtemplate-history-limit* 2)
          (journal (gr8s::core-journal-path store))
          (original (symbol-function 'gr8s::read-core-journal-records)))
      (with-open-file (output journal :direction :output :if-exists :supersede)
        (loop for revision from 2 to 15 do
          (com.inuoe.jzon:stringify (recovery-record revision (write-to-string revision)) :stream output)
          (terpri output)))
      (unwind-protect
           (progn
             (setf (symbol-function 'gr8s::read-core-journal-records)
                   (lambda (&rest args) (declare (ignore args)) (error "Eager reader used")))
             (multiple-value-bind (state torn complete) (gr8s::read-durable-core-state store)
               (is (= 15 (gethash "revision" state)))
               (is-false torn)
               (is (= (sb-posix:stat-size (sb-posix:stat (namestring journal))) complete))
               (is (= 2 (length (gethash "templateHistory" state))))
               (is (= 13 (gethash "templateHistoryFloor" state)))
               (let ((object (gethash '("configmaps" "default" "sample") (gr8s::core-state-index state))))
                 (is (equal "15" (gethash "key" (gethash "data" object)))))))
        (setf (symbol-function 'gr8s::read-core-journal-records) original)))))

(test replay-retires-event-expirations-before-the-next-record
  (with-temporary-store (store root)
    (declare (ignore root))
    (let* ((expirations (gr8s::core-object "initial" 10000))
           (records nil) (revision 1) (reads 0) (maximum 0))
      (labels ((event (uid)
                 (gr8s::core-object "apiVersion" "v1" "kind" "Event"
                   "metadata" (gr8s::core-object "name" "sample" "namespace" "default" "uid" uid)))
               (record (object &optional uid expiry)
                 (push (gr8s::core-object "revision" (incf revision) "time" 10
                         "changes" (vector (gr8s::core-object "resource" "events"
                                             "namespace" "default" "name" "sample" "object" object))
                         "eventExpirations" (if uid (gr8s::core-object uid expiry) (gr8s::core-object)))
                       records)))
        ;; Preserve legacy same-UID updates without an explicit expiry delta,
        ;; then remove the replaced UID and the replacement's deletion.
        (record (event "initial"))
        (record (event "replacement") "replacement" 20000)
        (record 'null)
        (dotimes (i 32)
          (let ((uid (format nil "churn-~D" i)))
            (record (event uid) uid (+ 30000 i))
            (record 'null)))
        (setf records (nreverse records))
        (let* ((state (gr8s::core-object "version" 2 "revision" 1 "templateHistoryFloor" 1
                        "items" (vector (event "initial")) "templateHistory" #()
                        "eventExpirations" expirations))
               (recovered
                 (gr8s::replay-core-journal
                  store state
                  (lambda ()
                    ;; Observe the map while replay still owns it, rather than
                    ;; accepting the existing final EOF-only filtering.
                    (setf maximum (max maximum (hash-table-count expirations)))
                    (case reads
                      (1 (is (= 10000 (gethash "initial" expirations))))
                      (2 (is-false (gethash "initial" expirations))
                         (is (= 20000 (gethash "replacement" expirations))))
                      (3 (is (= 0 (hash-table-count expirations)))))
                    (incf reads)
                    (pop records)))))
          (is (= 1 maximum))
          (is (= 68 reads))
          (is (= 0 (hash-table-count (gethash "eventExpirations" recovered)))))))))

(test journal-reader-empty-and-complete-eof
  (with-temporary-store (store path)
    (declare (ignore path))
    (let ((journal (gr8s::core-journal-path store)))
      (ensure-directories-exist journal)
      (with-open-file (output journal :direction :output :if-exists :supersede))
      (multiple-value-bind (records torn complete) (gr8s::read-core-journal-records journal)
        (is (null records)) (is-false torn) (is (= 0 complete))))))

(test replay-releases-checkpoint-collections-and-preserves-empty-or-stale-baselines
  (with-temporary-store (store root)
    (declare (ignore root))
    (dolist (stale '(nil t))
      (let* ((object (configmap-input "sample" "key" "baseline"))
             (custom (configmap-input "custom" "key" "custom-baseline"))
             (entry (gr8s::core-object "revision" 1 "time" 10 "resource" "configmaps"
                      "namespace" "default" "name" "sample" "old" 'null "new" object))
             (state (gr8s::core-object "version" 2 "revision" 1 "templateHistoryFloor" 0
                      "templateHistory" (vector entry) "items" (vector object)
                      "customResourceItems" (vector (gr8s::core-object
                        "resource" "custom:example.com/widgets" "object" custom))))
             (calls 0))
        (gr8s::replay-core-journal store state
          (lambda ()
            (is (zerop (length (gethash "items" state))))
            (is (zerop (length (gethash "customResourceItems" state))))
            (is (zerop (length (gethash "templateHistory" state))))
            (incf calls)
            (values (when (and stale (= calls 1)) (recovery-record 1 "ignored")) nil 0)))
        (is (eq object (aref (gethash "items" state) 0)))
        (is (eq custom (gethash "object" (aref (gethash "customResourceItems" state) 0))))
        (is (eq entry (aref (gethash "templateHistory" state) 0)))))))

(test recent-history-cache-cannot-retain-byte-evicted-objects-or-survive-replacement
  (with-temporary-store (store root)
    (declare (ignore root))
    (let ((gr8s::*resource-watch-history-bytes* (* 4 sb-vm:gencgc-page-bytes)))
      (dotimes (i 8)
        (gr8s::create-core-resource store "configmaps"
          (configmap-input "cache" "key" (make-array 65536 :element-type 'base-char :initial-element #\x)) "default")
        (gr8s::delete-core-resource store "configmaps" "default" "cache"))
      (let ((history (gr8s::pod-store-template-history store))
            (recent (gr8s::pod-store-template-history-recent store)))
        (is (= 2 (length history)))
        (is (= 2 (length recent)))
        (is (every (lambda (entry) (member entry history :test #'eq)) recent)))
      (gr8s::load-core-resources store)
      (is (every (lambda (entry) (member entry (gr8s::pod-store-template-history store) :test #'eq))
                 (gr8s::pod-store-template-history-recent store))))))
(test oversized-core-transaction-retires-its-entire-recent-history
  (with-temporary-store (store root)
    (declare (ignore root))
    (let ((gr8s::*resource-watch-history-bytes* (* 4 sb-vm:gencgc-page-bytes)))
      (dotimes (i 3)
        (gr8s::create-core-resource store "configmaps"
          (configmap-input (format nil "large-~D" i) "key"
            (make-array 65536 :element-type 'base-char :initial-element #\x)) "default"))
      (let ((revision (1+ (gr8s::pod-store-resource-revision store))))
        ;; Commit three deletions at one boundary, exceeding the history byte
        ;; budget even though only three entries are added to the recent cache.
        (gr8s::with-core-write (store)
          (let ((resources (gr8s::copy-core-resource-index store)))
            (dotimes (i 3)
              (remhash (gr8s::core-resource-key "configmaps" "default" (format nil "large-~D" i)) resources))
            (gr8s::commit-core-resources store resources revision)))
        (is (= revision (gr8s::pod-store-template-history-floor store)))
        (is (null (gr8s::pod-store-template-history store)))
        (is (null (gr8s::pod-store-template-history-recent store)))
        (gr8s::create-core-resource store "configmaps" (configmap-input "after" "key" "small") "default")
        (is (= 1 (length (gr8s::pod-store-template-history-recent store))))
        (is (> (gethash "revision" (first (gr8s::pod-store-template-history-recent store))) revision))))))

(test durable-history-obeys-byte-budget
  (let* ((gr8s::*podtemplate-clock* (constantly 10))
         (gr8s::*resource-watch-history-bytes* 1024)
         (history (loop for revision from 1 to 10 collect
                    (gr8s::core-object "revision" revision "time" 10 "bytes" 512))))
    (multiple-value-bind (kept floor) (gr8s::durable-template-history history 0)
      (is (= 2 (length kept)))
      (is (= 8 floor)))))

(test history-byte-estimates-include-large-string-pages-and-remeasure-legacy-cache
  (let* ((page sb-vm:gencgc-page-bytes)
         (base (make-array 65536 :element-type 'base-char :initial-element #\x))
         (wide (make-array 65536 :element-type 'character :initial-element #\x))
         (small (make-array 10 :element-type 'base-char :initial-element #\x)))
    (is (= (* 3 page) (gr8s::approximate-heap-bytes base)))
    (is (= (* page (ceiling (sb-ext:primitive-object-size wide) page))
           (gr8s::approximate-heap-bytes wide)))
    (is (< (gr8s::approximate-heap-bytes small) page))
    (let* ((old (gr8s::core-object "data" base))
           (entry (gr8s::core-object "revision" 1 "time" 10 "old" old "bytes" 512))
           (bytes (gr8s::template-history-old-bytes old)))
      (is (= bytes (gr8s::template-history-entry-bytes entry)))
      (is (= 512 (gethash "bytes" entry)))
      (let ((gr8s::*podtemplate-clock* (constantly 10))
            (gr8s::*resource-watch-history-bytes* (* 2 page)))
        (multiple-value-bind (kept floor) (gr8s::durable-template-history (list entry) 0)
          (is (null kept)) (is (= 1 floor)))))))
(test torn-journal-tail-forces-checkpoint-before-further-writes
  (with-temporary-store (store path)
    (gr8s::create-core-resource store "configmaps" (configmap-input "sample" "key" "base") "default")
    (let ((journal (gr8s::core-journal-path store)))
      (with-open-file (output journal :direction :output :if-exists :supersede)
        (com.inuoe.jzon:stringify (recovery-record 2 "recovered") :stream output)
        (terpri output)
        (write-string "{torn" output))
      (let ((reopened (open-store path)))
        (is (equal "recovered" (configmap-value reopened "sample" "key")))
        (is-true (gr8s::pod-store-core-checkpoint-needed reopened))
        (gr8s::create-core-resource reopened "configmaps" (configmap-input "next" "key" "committed") "default")
        (is-false (probe-file journal))
        (let ((again (open-store path)))
          (is (equal "recovered" (configmap-value again "sample" "key")))
          (is (equal "committed" (configmap-value again "next" "key"))))))))
(in-suite gr8s)

(in-suite core-recovery)
(test checkpoint-writer-streams-transforms-and-preserves-the-checkpoint-schema
  (with-temporary-store (store root)
    (gr8s::create-core-resource store "configmaps" (configmap-input "stream-a" "k" "a") "default")
    (gr8s::create-core-resource store "configmaps" (configmap-input "stream-b" "k" "b") "default")
    (let* ((arguments (list store (gr8s::pod-store-resources store) (gr8s::pod-store-resource-revision store)
                            (gr8s::pod-store-workload-deletions store) (gr8s::pod-store-job-controller-states store)
                            (gr8s::pod-store-template-history store) (gr8s::pod-store-template-history-floor store)
                            (gr8s::pod-store-template-token-key store) (gr8s::pod-store-event-expirations store)))
           (expected (apply #'gr8s::core-checkpoint-object arguments))
           (writer (apply #'gr8s.resources::core-checkpoint-writer arguments))
           (path (merge-pathnames "streamed-checkpoint.json" root))
           (original (symbol-function 'gr8s.resources::encrypt-secret-history-entry))
           (positions nil))
      (unwind-protect
           (with-open-file (stream path :direction :output :if-exists :supersede)
             (setf (symbol-function 'gr8s.resources::encrypt-secret-history-entry)
                   (lambda (incoming entry)
                     (push (file-position stream) positions)
                     (funcall original incoming entry)))
             (funcall writer stream))
        (setf (symbol-function 'gr8s.resources::encrypt-secret-history-entry) original))
      (is (gr8s.store::json-value-equal-p expected (com.inuoe.jzon:parse path)))
      (is (>= (length positions) 2))
      (is (every #'< (reverse positions) (rest (reverse positions)))))))

(test ordinary-checkpoints-do-not-build-the-whole-state-object
  (with-temporary-store (store root)
    (let ((original (symbol-function 'gr8s::core-checkpoint-object)))
      (unwind-protect
           (progn
             (setf (symbol-function 'gr8s::core-checkpoint-object)
                   (lambda (&rest args) (declare (ignore args)) (error "Aggregate checkpoint object forbidden"))
                   (gr8s::pod-store-core-checkpoint-needed store) t)
             (gr8s::create-core-resource store "configmaps" (configmap-input "stream-only" "k" "persisted") "default")
             (is (equal "persisted" (configmap-value (gr8s:open-store root) "stream-only" "k"))))
        (setf (symbol-function 'gr8s::core-checkpoint-object) original)))))

(in-suite core-recovery)
(test unchanged-history-transforms-preserve-immutable-payload-sharing
  (with-temporary-store (store root)
    (declare (ignore root))
    (let* ((object (configmap-input "shared" "k" (make-string 65536 :initial-element #\x)))
           (entry (gr8s::core-object "resource" "configmaps" "old" object "new" object))
           (history (vector entry))
           (items (vector object))
           (state (gr8s::core-object "templateHistory" history "items" items)))
      (is (eq entry (gr8s.resources::encrypt-secret-history-entry store entry)))
      (is (eq entry (gr8s.resources::decrypt-secret-history-entry store entry)))
      (is (eq state (gr8s.resources::decrypt-core-state-secrets store state)))
      (is (eq items (gethash "items" state)))
      (is (eq history (gethash "templateHistory" state)))
      (is (eq object (gethash "old" (aref history 0))))
      (is (eq object (gethash "new" (aref history 0)))))))
