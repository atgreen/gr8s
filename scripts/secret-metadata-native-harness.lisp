;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;; Internal standalone store/key-rotation memory probe, not serve or HA acceptance.
(in-package #:cl-user)

(defun secret-metadata-native-digest (path)
  (ironclad:byte-array-to-hex-string (ironclad:digest-file :sha256 path)))

(defun secret-metadata-native-payload ()
  (ag-grpc:base64-encode
   (make-array (* 1024 1024) :element-type '(unsigned-byte 8) :initial-element 17)))

(defun secret-metadata-native-history-bytes (store)
  (reduce #'+ (gr8s.store::pod-store-template-history store)
          :key #'gr8s.resources::template-history-entry-bytes))

(defun secret-metadata-native-verify (store)
  (assert (equal (secret-metadata-native-payload)
                 (gethash "value" (gethash "data"
                   (gr8s.resources::get-core-resource store "secrets" "default" "rotation-boundary")))))
  (assert (equal "preserved" (gethash "value" (gethash "data"
                  (gr8s.resources::get-core-resource store "configmaps" "default" "sentinel")))))
  (dolist (name '("before-metadata" "before-finalize"))
    (assert (equal "journal-preserved" (gethash "value" (gethash "data"
                    (gr8s.resources::get-core-resource store "configmaps" "default" name))))))
  (let ((status (gr8s.resources::secret-encryption-status store)))
    (assert (eq t (gethash "enabled" status)))
    (assert (= 1 (length (gethash "keys" status))))
    (assert (equal "ready" (gethash "phase" status))))
  t)

(defun secret-metadata-native-main ()
  (gr8s.server::install-memory-hooks)
  (destructuring-bind (root-text clock-text mode) (uiop:command-line-arguments)
    (let* ((root (uiop:ensure-directory-pathname root-text))
           (result (gr8s.resources::core-object "passed" nil "mode" mode "nativeHarness" t
                     "productionServe" nil "haAcceptance" nil "vmAcceptance" nil
                     "heapLimitMiB" (/ (sb-ext:dynamic-space-size) (* 1024 1024))))
           (store nil))
      (handler-case
          (progn
            (assert (= 384 (gethash "heapLimitMiB" result)))
            (assert (member mode '("rotate" "verify") :test #'equal))
            (setf gr8s.store::*podtemplate-clock* (constantly (parse-integer clock-text))
                  (sb-ext:gc-logfile) (namestring (merge-pathnames (format nil "~A-gc.log" mode) root))
                  store (gr8s.store::open-store root))
            (let ((bytes (secret-metadata-native-history-bytes store)))
              (setf (gethash "loadedHistoryEstimatedBytes" result) bytes)
              (assert (>= bytes (- gr8s.resources::*resource-watch-history-bytes* (* 2 65536)))))
            (when (equal mode "rotate")
              (assert (not (gr8s.resources::secret-encryption-enabled-p store)))
              (gr8s.resources::create-core-resource store "secrets"
                (gr8s.resources::core-object "apiVersion" "v1" "kind" "Secret"
                  "metadata" (gr8s.resources::core-object "name" "rotation-boundary")
                  "data" (gr8s.resources::core-object "value" (secret-metadata-native-payload))) "default")
              (gr8s.resources::enable-secret-encryption store)
              (labels ((marker (name)
                         (gr8s.resources::create-core-resource store "configmaps"
                           (gr8s.resources::core-object "apiVersion" "v1" "kind" "ConfigMap"
                             "metadata" (gr8s.resources::core-object "name" name)
                             "data" (gr8s.resources::core-object "value" "journal-preserved")) "default"))
                       (metadata (name function)
                         (format *error-output* "~&Secret metadata phase: ~A~%" name)
                         (finish-output *error-output*)
                         (let* ((journal (gr8s.resources::core-journal-path store))
                                (digest (secret-metadata-native-digest journal))
                                (revision (gr8s.store::pod-store-resource-revision store)))
                           (assert (plusp (sb-posix:stat-size (sb-posix:stat (namestring journal)))))
                           (funcall function store)
                           (assert (equal digest (secret-metadata-native-digest journal)))
                           (assert (= revision (gr8s.store::pod-store-resource-revision store)))
                           (assert (>= (secret-metadata-native-history-bytes store)
                                       (- gr8s.resources::*resource-watch-history-bytes* (* 2 65536)))))))
                (marker "before-metadata")
                (metadata "prepare" #'gr8s.resources::prepare-secret-encryption-key)
                (metadata "promote" #'gr8s.resources::promote-secret-encryption-key)
                (gr8s.resources::reencrypt-secrets store)
                (marker "before-finalize")
                (metadata "finalize" #'gr8s.resources::finalize-secret-encryption-key))
              (setf (gethash "metadataJournalPreserved" result) t
                    (gethash "rotationCompleted" result) t))
            (secret-metadata-native-verify store)
            (setf (gethash "secretBoundaryRecovered" result) t
                  (gethash "sentinelRecovered" result) t
                  (gethash "passed" result) t))
        (error (condition) (setf (gethash "error" result) (princ-to-string condition))))
      (write-line (com.inuoe.jzon:stringify result))
      (uiop:quit (if (gethash "passed" result) 0 1)))))
