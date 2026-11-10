;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;; Native internal HA compaction acceptance; no containers, BPF, or serve.
(in-package #:cl-user)

(defun compaction-native-await (function)
  (let ((deadline (+ (get-internal-real-time) (* 30 internal-time-units-per-second))))
    (loop for result = (funcall function)
          when result return result
          when (> (get-internal-real-time) deadline) do (error "Compaction acceptance timed out")
          do (sleep 0.01))))

(defun compaction-native-write (function)
  (compaction-native-await
   (lambda () (handler-case (progn (funcall function) t)
                (gr8s:kubernetes-error (condition)
                  (unless (= 503 (gr8s::kubernetes-error-status-code condition)) (error condition))
                  nil)))))

(defun compaction-native-main ()
  (destructuring-bind (root-text rounds-text) (uiop:command-line-arguments)
    (let* ((root (uiop:ensure-directory-pathname root-text)) (rounds (parse-integer rounds-text))
           (store (gr8s:open-store root)) (ha nil) (port nil)
           (max-wal 0) (max-artifacts 0) (checkpoints 0) (samples 0)
           (result (gr8s::core-object "passed" nil "nativeHarness" t "productionServe" nil
                     "vmAcceptance" nil "automaticWorker" t "productionDefaultEnabled" nil
                     "rounds" rounds "payloadBytesWritten" (* rounds 65536)
                     "walTriggerBytes" (* 16 1024 1024)
                     "heapLimitMiB" (/ (sb-ext:dynamic-space-size) (* 1024 1024)))))
      (labels ((ready () (gr8s::ha-control-plane-leader-p ha))
               (sample ()
                 (let ((member (gr8s::ha-control-plane-member ha)))
                   (bt:with-lock-held ((gr8s::raft-member-lock member))
                     (setf max-wal (max max-wal (sb-posix:stat-size
                                                (sb-posix:stat (merge-pathnames "raft/control-plane.log" root))))
                           max-artifacts (max max-artifacts (length (uiop:directory-files
                                                                     (merge-pathnames "snapshot-artifacts/" root))))))
                   (incf samples))))
        (unwind-protect
             (handler-case
                 (progn
                   (assert (= 384 (gethash "heapLimitMiB" result)))
                   (setf ha (gr8s::start-ha-control-plane store :id "compact-native" :init t
                             :compaction-bytes (* 16 1024 1024) :compaction-entries 100000 :compaction-interval 0.01)
                         port (gr8s::raft-member-port (gr8s::ha-control-plane-member ha)))
                   (compaction-native-await #'ready)
                   (compaction-native-write
                    (lambda () (gr8s::create-core-resource store "namespaces"
                                  (gr8s::core-object "apiVersion" "v1" "kind" "Namespace"
                                    "metadata" (gr8s::core-object "name" "default")) nil)))
                   (compaction-native-write
                    (lambda () (gr8s::create-core-resource store "configmaps"
                                  (gr8s::core-object "apiVersion" "v1" "kind" "ConfigMap"
                                    "metadata" (gr8s::core-object "name" "sentinel")
                                    "data" (gr8s::core-object "value" "preserved")) "default")))
                   (dotimes (i rounds)
                     (compaction-native-write
                      (lambda () (gr8s::create-core-resource store "configmaps"
                                    (gr8s::core-object "apiVersion" "v1" "kind" "ConfigMap"
                                      "metadata" (gr8s::core-object "name" "churn")
                                      "data" (gr8s::core-object "value" (make-string 65536 :initial-element #\x))) "default")))
                     (compaction-native-write (lambda () (gr8s::delete-core-resource store "configmaps" "default" "churn")))
                     (when (zerop (mod i 32)) (sample)))
                   (compaction-native-await #'ready)
                   (sample)
                   (bt:with-lock-held ((gr8s.ha::ha-control-plane-compaction-lock ha))
                     (setf checkpoints (gr8s.ha::ha-control-plane-compaction-count ha))
                     (assert (null (gr8s.ha::ha-control-plane-compaction-error ha))))
                   (assert (>= checkpoints 2))
                   (assert (< max-wal (* 32 1024 1024)))
                   (assert (<= max-artifacts 2))
                   (gr8s::stop-ha-control-plane ha)
                   (assert (null (gr8s.ha::ha-control-plane-compaction-thread ha)))
                   (setf store (gr8s:open-store root :defer-restore-completion t)
                         ha (gr8s::start-ha-control-plane store :id "compact-native" :init t :port port))
                   (compaction-native-await #'ready)
                   (assert (equal "preserved" (gethash "value" (gethash "data"
                             (gr8s::get-core-resource store "configmaps" "default" "sentinel")))))
                   (setf (gethash "passed" result) t
                         (gethash "checkpoints" result) checkpoints
                         (gethash "sampledMaxWalBytes" result) max-wal
                         (gethash "sampledMaxArtifactCount" result) max-artifacts
                         (gethash "samples" result) samples
                         (gethash "sentinelRecovered" result) t))
               (error (condition) (setf (gethash "error" result) (princ-to-string condition))))
          (when ha (gr8s::stop-ha-control-plane ha)))
        (write-line (com.inuoe.jzon:stringify result))
        (uiop:quit (if (gethash "passed" result) 0 1))))))
