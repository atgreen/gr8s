;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;; Stream committed application records without a whole-store JSON/Lisp value.
(in-package #:gr8s.resources)

(defun write-store-snapshot-records (store stream index term)
  "Write the versioned application artifact under STORE's raw lock.
The caller must hold the Raft member lock and supply its exact applied boundary.
This function neither compacts Raft nor captures member-local credentials."
  (let ((count 0))
    (labels ((emit (kind &rest fields)
               (com.inuoe.jzon:stringify (apply #'core-object "kind" kind fields) :stream stream)
               (terpri stream)
               (incf count))
             (entries (kind table)
               (maphash (lambda (key value) (emit kind "key" key "value" value)) table)))
      (emit "header" "format" "gr8s-store-snapshot" "version" 1 "index" index "term" term)
      (emit "clocks" "resourceRevision" (pod-store-resource-revision store)
            "podRevision" (pod-store-pod-revision store)
            "resourceHistoryStart" (pod-store-resource-history-start store)
            "templateHistoryFloor" (pod-store-template-history-floor store)
            "templateTokenKey" (let ((key (pod-store-template-token-key store)))
                                 (when key (ag-grpc:base64-encode key))))
      (maphash (lambda (key object)
                 (unless (local-plane-resource-p (first key))
                   (emit "resource" "resource" (first key)
                         "namespace" (or (second key) 'null) "name" (third key) "object" object)))
               (pod-store-resources store))
      (entries "workloadDeletion" (pod-store-workload-deletions store))
      (entries "jobControllerState" (pod-store-job-controller-states store))
      ;; Retain the existing bounded watch history, without constructing a vector.
      (dolist (entry (pod-store-template-history store))
        (unless (local-plane-resource-p (gethash "resource" entry))
          (emit "history" "entry" entry)))
      (maphash (lambda (key pod)
                 (declare (ignore key))
                 (emit "pod" "object" (pod-to-object pod)
                       "checkpoint" (gr8s.store::pod-checkpoint-object store pod)
                       "publication" (gr8s.store::pod-publication-object store pod)))
               (pod-store-pods store))
      (maphash (lambda (name node)
                 (declare (ignore name))
                 (emit "node" "object" (gr8s.store::node-replicated-object node)))
               (pod-store-nodes store))
      (emit "end" "records" count)
      count)))

(defun capture-store-snapshot (store path index term)
  "Publish a new immutable mode0600 JSON-lines artifact, returning PATH and record count.
No existing artifact may be replaced. The source store is never modified."
  (unless (and (typep index '(integer 0 *)) (typep term '(integer 0 *)))
    (error "Invalid store snapshot boundary"))
  (when (gr8s.store::pod-stage-active-p store)
    (error "Cannot snapshot a speculative store transaction"))
  (let* ((path (pathname path)) (temporary (gr8s.security::private-temporary-path path)) (count nil))
    (ensure-directories-exist path)
    (unwind-protect
         (progn
           (bt:with-lock-held ((pod-store-lock store))
             (gr8s.security::write-private-text-exclusively
              temporary
              (lambda (stream)
                (setf count (write-store-snapshot-records store stream index term))
                (finish-output stream)
                (sb-posix:fsync (sb-sys:fd-stream-fd stream)))))
           ;; Linux RENAME_NOREPLACE: immutable generations must never overwrite
           ;; an existing artifact, including a dangling symlink.
           (unless (zerop (cffi:foreign-funcall "renameat2" :int -100 :string (namestring temporary)
                                               :int -100 :string (namestring path) :uint 1 :int))
             (error "Cannot publish immutable store snapshot ~A" path))
           (let ((fd (sb-posix:open (namestring (uiop:pathname-directory-pathname path))
                                    (logior sb-posix:o-rdonly sb-posix:o-directory) 0)))
             (unwind-protect (sb-posix:fsync fd) (sb-posix:close fd)))
           (values path count))
      (when (probe-file temporary) (delete-file temporary)))))
