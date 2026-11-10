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

(test journal-reader-empty-and-complete-eof
  (with-temporary-store (store path)
    (declare (ignore path))
    (let ((journal (gr8s::core-journal-path store)))
      (ensure-directories-exist journal)
      (with-open-file (output journal :direction :output :if-exists :supersede))
      (multiple-value-bind (records torn complete) (gr8s::read-core-journal-records journal)
        (is (null records)) (is-false torn) (is (= 0 complete))))))
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
