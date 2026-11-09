;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;; Run from the release checkout:
;;;; sbcl --dynamic-space-size 384 --noinform --non-interactive
;;;;   --load scripts/test-core-recovery-memory.lisp
;;;; Set GR8S_RECOVERY_LEGACY_SOURCE to an old core-resources.lisp to verify regression.
(require :asdf)
(asdf:load-asd (truename "gr8s.asd"))
(asdf:load-system "gr8s")
(when (uiop:getenv "GR8S_RECOVERY_LEGACY_SOURCE")
  (load (uiop:getenv "GR8S_RECOVERY_LEGACY_SOURCE")))
(let* ((root (uiop:ensure-directory-pathname (sb-posix:mkdtemp "/tmp/gr8s-memory-XXXXXX")))
       (store (gr8s:open-store root))
       ;; The journal exceeds the entire allowed heap, but its live state is small.
       (records (parse-integer (or (uiop:getenv "GR8S_RECOVERY_RECORDS") "2048")))
       (payload (make-string (* 256 1024) :initial-element #\x))
       (object (gr8s::core-object "apiVersion" "v1" "kind" "ConfigMap"
                                  "metadata" (gr8s::core-object "name" "sample" "namespace" "default")
                                  "data" (gr8s::core-object "key" payload)))
       (journal (gr8s::core-journal-path store)))
  (unwind-protect
       (progn
         (gr8s::create-core-resource store "configmaps" object "default")
         (with-open-file (output journal :direction :output :if-exists :supersede)
           (loop for revision from 2 to (1+ records) do
             (com.inuoe.jzon:stringify
              (gr8s::core-object
               "revision" revision "time" revision
               "changes" (vector (gr8s::core-object "resource" "configmaps" "namespace" "default"
                                                    "name" "sample" "object" object)))
              :stream output)
             (terpri output)))
         (sb-ext:gc :full t)
         (let* ((bytes (sb-posix:stat-size (sb-posix:stat (namestring journal))))
                (started (get-internal-real-time))
                (state (gr8s::read-durable-core-state store)))
           (assert (= (1+ records) (gethash "revision" state)))
           (assert (<= (length (gethash "templateHistory" state)) gr8s::*podtemplate-history-limit*))
           (assert (<= (reduce #'+ (gethash "templateHistory" state)
                               :key #'gr8s::template-history-entry-bytes)
                       gr8s::*resource-watch-history-bytes*))
           (let* ((index (gr8s::core-state-index state))
                  (recovered (gethash '("configmaps" "default" "sample") index)))
             (assert (equal payload (gethash "key" (gethash "data" recovered)))))
           (format t "~&~A~%"
                   (com.inuoe.jzon:stringify
                    (gr8s::core-object "passed" t "journalBytes" bytes "records" records
                                       "retainedHistory" (length (gethash "templateHistory" state))
                                       "seconds" (/ (- (get-internal-real-time) started)
                                                    (float internal-time-units-per-second))
                                       "heapLimitMiB" (/ (sb-ext:dynamic-space-size) (* 1024 1024)))))))
    (uiop:delete-directory-tree root :validate t :if-does-not-exist :ignore)))
