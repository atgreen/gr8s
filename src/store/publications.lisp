;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
(in-package #:gr8s.store)

(defun pod-publication-path (store uid)
  (unless (and (stringp uid) (<= 1 (length uid) 250)
               (not (member uid '("." "..") :test #'equal))
               (every (lambda (c) (find c "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_.")) uid))
    (error "Invalid Pod publication identity"))
  (merge-pathnames (format nil "publications/~A.json" uid) (store-data-path store)))

(defun persist-pod-publication (store pod &key
                                    (status (or (gethash (pod-uid pod) (pod-store-pod-published-statuses store))
                                                (pending-pod-status)))
                                    (revision (or (pod-status-revision pod) (parse-integer (pod-resource-version pod)))))
  "Synchronize the API publication before announcing its watch event."
  (when (pod-stage-active-p store)
    (stage-pod-write store pod :status t)
    (return-from persist-pod-publication pod))
  (unless (and (hash-table-p status) (typep revision '(integer 0 *)))
    (error "Invalid Pod publication"))
  (let* ((target (pod-publication-path store (pod-uid pod)))
         (directory (uiop:pathname-directory-pathname target))
         (temporary (make-pathname :name (format nil ".publication-~A" (generate-uid))
                                   :type "tmp" :defaults target)))
    (ensure-store-generation-directory directory (store-data-path store))
    (unwind-protect
         (progn
           (gr8s.security::write-private-text-exclusively
            temporary
            (lambda (stream)
              (com.inuoe.jzon:stringify
               (store-json-object "formatVersion" 1 "uid" (pod-uid pod) "namespace" (pod-namespace pod)
                                  "name" (pod-name pod) "desiredResourceVersion" (pod-resource-version pod)
                                  "resourceVersion" (write-to-string revision) "status" status)
               :stream stream)
              (when (> (file-position stream) (* 16 1024 1024)) (error "Pod publication exceeds byte limit"))
              (finish-output stream)
              (sb-posix:fsync (sb-sys:fd-stream-fd stream))))
           (sb-posix:rename (namestring temporary) (namestring target))
           (sync-store-generation-directory directory))
      (when (store-generation-stat temporary) (sb-posix:unlink (namestring temporary)))))
  pod)

(defun read-pod-publication (path)
  (let ((fd (sb-posix:open (namestring path) (logior sb-posix:o-rdonly sb-posix:o-nofollow sb-posix:o-nonblock) 0))
        (stream nil))
    (unwind-protect
         (progn
           (let ((stat (sb-posix:fstat fd)))
             (unless (and (sb-posix:s-isreg (sb-posix:stat-mode stat))
                          (= 1 (sb-posix:stat-nlink stat)) (= (sb-posix:geteuid) (sb-posix:stat-uid stat))
                          (= #o600 (logand #o777 (sb-posix:stat-mode stat)))
                          (<= 1 (sb-posix:stat-size stat) (* 16 1024 1024)))
               (error "Unsafe Pod publication file")))
           (setf stream (sb-sys:make-fd-stream fd :input t :element-type 'character :external-format :utf-8 :auto-close t))
           (com.inuoe.jzon:parse stream :max-depth 128 :max-string-length (* 2 1024 1024)))
      (if stream (close stream) (sb-posix:close fd)))))

(defun load-pod-publications (store)
  "Older stores need no publication files. Ignore obsolete desired revisions/UIDs."
  (let ((directory (merge-pathnames "publications/" (store-data-path store))))
    (when (store-generation-stat directory)
      (check-store-generation-directory directory)
      (dolist (path (directory (merge-pathnames "*.json" directory) :resolve-symlinks nil))
        (let* ((record (read-pod-publication path))
               (uid (and (hash-table-p record) (gethash "uid" record)))
               (revision (and (hash-table-p record) (gethash "resourceVersion" record)))
               (desired (and (hash-table-p record) (gethash "desiredResourceVersion" record)))
               (pod (and (hash-table-p record)
                         (gethash (pod-key (gethash "namespace" record) (gethash "name" record))
                                  (pod-store-pods store)))))
          (unless (and (hash-table-p record) (eql 1 (gethash "formatVersion" record))
                       (stringp uid) (equal uid (pathname-name path))
                       (stringp revision) (plusp (length revision)) (every #'digit-char-p revision)
                       (stringp desired) (plusp (length desired)) (every #'digit-char-p desired)
                       (hash-table-p (gethash "status" record)))
            (error "Invalid Pod publication checkpoint"))
          (when (and pod (equal uid (pod-uid pod)) (equal desired (pod-resource-version pod)))
            (let ((number (parse-integer revision)))
              (when (> number (pod-store-pod-revision store))
                (error "Pod publication exceeds durable revision clock; recover Raft state"))
              (setf (pod-status-revision pod) number
                    (gethash uid (pod-store-pod-published-statuses store)) (gethash "status" record))))))))
  store)
