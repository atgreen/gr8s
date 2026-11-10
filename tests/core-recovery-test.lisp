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
(test durable-history-obeys-byte-budget
  (let* ((gr8s::*podtemplate-clock* (constantly 10))
         (gr8s::*resource-watch-history-bytes* 1024)
         (history (loop for revision from 1 to 10 collect
                    (gr8s::core-object "revision" revision "time" 10 "bytes" 512))))
    (multiple-value-bind (kept floor) (gr8s::durable-template-history history 0)
      (is (= 2 (length kept)))
      (is (= 8 floor)))))
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
