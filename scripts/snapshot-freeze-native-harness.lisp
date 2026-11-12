;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;; Standalone full-history freeze/stream probe; not HA or serve acceptance.
(in-package #:cl-user)

(defun snapshot-freeze-native-main ()
  (gr8s.server::install-memory-hooks)
  (destructuring-bind (root-text clock-text) (uiop:command-line-arguments)
    (let* ((root (uiop:ensure-directory-pathname root-text))
           (target (merge-pathnames "frozen.jsonl" root))
           (result (gr8s.resources::core-object "passed" nil "nativeHarness" t
                     "productionServe" nil "haAcceptance" nil "vmAcceptance" nil
                     "heapLimitMiB" (/ (sb-ext:dynamic-space-size) (* 1024 1024)))))
      (handler-case
          (progn
            (assert (= 384 (gethash "heapLimitMiB" result)))
            (setf gr8s.store::*podtemplate-clock* (constantly (parse-integer clock-text))
                  (sb-ext:gc-logfile) (namestring (merge-pathnames "gc.log" root)))
            (let* ((store (gr8s.store::open-store root))
                   (history-bytes (reduce #'+ (gr8s.store::pod-store-template-history store)
                                          :key #'gr8s.resources::template-history-entry-bytes))
                   (history-count (length (gr8s.store::pod-store-template-history store)))
                   (revision (gr8s.store::pod-store-resource-revision store))
                   (view nil) (records 0) (history-records 0) (sentinel nil))
              (setf (gethash "loadedHistoryEstimatedBytes" result) history-bytes)
              (assert (>= history-bytes (- gr8s.resources::*resource-watch-history-bytes* (* 2 65536))))
              (gr8s.store::quiesce-store-access store :timeout 0)
              (unwind-protect
                   (setf view (gr8s.store::call-with-store-application-barriers
                               store (lambda () (gr8s.resources::freeze-store-snapshot store 42 7))))
                (gr8s.store::resume-store-access store))
              ;; An ordinary post-freeze transaction must remain absent from
              ;; the captured boundary, even while the live store retains it.
              (gr8s.resources::create-core-resource
               store "configmaps"
               (gr8s.resources::core-object "apiVersion" "v1" "kind" "ConfigMap"
                 "metadata" (gr8s.resources::core-object "name" "after-freeze")
                 "data" (gr8s.resources::core-object "value" "live-only")) "default")
              (gr8s.resources::capture-frozen-store-snapshot view target)
              (gr8s.resources::validate-store-snapshot
               target :expected-index 42 :expected-term 7
               :function
               (lambda (row)
                 (incf records)
                 (let ((kind (gethash "kind" row)))
                   (when (equal kind "clocks")
                     (assert (= revision (gethash "resourceRevision" row))))
                   (when (equal kind "history") (incf history-records))
                   (when (equal kind "resource")
                     (assert (not (equal "after-freeze" (gethash "name" row))))
                     (when (equal "sentinel" (gethash "name" row))
                       (assert (equal "preserved" (gethash "value" (gethash "data" (gethash "object" row)))))
                       (setf sentinel t))))))
              (assert (= history-count history-records))
              (assert sentinel)
              (assert (gr8s.resources::get-core-resource store "configmaps" "default" "after-freeze"))
              (setf (gethash "frozenHistoryRecords" result) history-records
                    (gethash "records" result) records
                    (gethash "frozenRevision" result) revision
                    (gethash "liveRevision" result) (gr8s.store::pod-store-resource-revision store)
                    (gethash "artifactBytes" result) (sb-posix:stat-size (sb-posix:stat (namestring target)))
                    (gethash "artifactSha256" result)
                    (ironclad:byte-array-to-hex-string (ironclad:digest-file :sha256 target))
                    (gethash "sentinelPreserved" result) t
                    (gethash "postFreezeWriteExcluded" result) t
                    (gethash "passed" result) t)))
        (error (condition) (setf (gethash "error" result) (princ-to-string condition))))
      (write-line (com.inuoe.jzon:stringify result))
      (uiop:quit (if (gethash "passed" result) 0 1)))))
