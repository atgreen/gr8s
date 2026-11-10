;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;; Real-process publication interruption and production startup-hook probe.
(require :asdf)
(asdf:load-asd (truename "gr8s.asd"))
(asdf:load-system "gr8s")
(in-package #:cl-user)
(defun scratch-probe-json (path object)
  (with-open-file (out path :direction :output :if-exists :error)
    (com.inuoe.jzon:stringify object :stream out)))
(handler-case
    (destructuring-bind (mode base-text port-text &optional (iteration "1")) (uiop:command-line-arguments)
      (let* ((base (uiop:ensure-directory-pathname base-text))
             (root (merge-pathnames "state/" base))
             (control (merge-pathnames (format nil "attempt-~A/" iteration) base))
             (options (gr8s::parse-serve-options '("--raft-init" "--node-name" "scratch-crash" "--listen" "127.0.0.1"))))
        (ensure-directories-exist (merge-pathnames "marker" control))
        (setf (getf options :state-directory) root (getf options :raft-port) (parse-integer port-text))
        (gr8s.server::call-with-serve-state-ownership
         options
         (lambda ()
           (let* ((store (gr8s:open-store root :defer-restore-completion t))
                  (ha (gr8s.server::maybe-start-ha-control-plane store nil options)))
             (unwind-protect
                  (progn
                    (loop with deadline = (+ (get-internal-real-time) (* 30 internal-time-units-per-second))
                          until (gr8s::ha-control-plane-leader-p ha)
                          do (when (> (get-internal-real-time) deadline) (error "Leader readiness timed out"))
                             (sleep 0.02))
                    (cond
                      ((equal mode "hold")
                       (handler-case (gr8s::get-core-resource store "namespaces" nil "default")
                         (gr8s:kubernetes-error (condition)
                           (unless (= 404 (gr8s::kubernetes-error-status-code condition)) (error condition))
                           (gr8s::create-core-resource store "namespaces"
                             (gr8s::core-object "apiVersion" "v1" "kind" "Namespace"
                               "metadata" (gr8s::core-object "name" "default")) nil)))
                       (handler-case (gr8s::get-core-resource store "configmaps" "default" "scratch-sentinel")
                         (gr8s:kubernetes-error (condition)
                           (unless (= 404 (gr8s::kubernetes-error-status-code condition)) (error condition))
                           (gr8s::create-core-resource store "configmaps"
                             (gr8s::core-object "apiVersion" "v1" "kind" "ConfigMap"
                               "metadata" (gr8s::core-object "name" "scratch-sentinel")
                               "data" (gr8s::core-object "value" "preserved")) "default")))
                       (let* ((source (merge-pathnames "source.jsonl" control))
                              (completed (merge-pathnames (format nil "raft/capture-~A.jsonl" (gr8s.store:generate-uid)) root))
                              (incomplete (merge-pathnames (format nil "raft/capture-~A.jsonl" (gr8s.store:generate-uid)) root))
                              (registry (gr8s.resources::store-snapshot-registry-directory root))
                              (original (symbol-function 'gr8s.resources::validate-store-snapshot))
                              (lock (bt:make-lock "scratch readiness")) (partial nil) (part nil))
                         (gr8s.resources::capture-store-snapshot store source 100 7)
                         (gr8s.resources::capture-store-snapshot store completed 100 7)
                         (let ((digest (ironclad:byte-array-to-hex-string (ironclad:digest-file :sha256 source))))
                           (setf (symbol-function 'gr8s.resources::validate-store-snapshot)
                                 (lambda (path &rest arguments)
                                   (multiple-value-prog1 (apply original path arguments)
                                     (when (gr8s.resources::store-snapshot-startup-temporary-name-p (file-namestring path) t)
                                       (bt:with-lock-held (lock) (setf part (namestring path)))
                                       (loop (sleep 1))))))
                           (bt:make-thread
                            (lambda () (gr8s.resources::retain-store-snapshot-artifact root source 100 7 digest))
                            :name "paused artifact retention"))
                         (bt:make-thread
                          (lambda ()
                            (gr8s.resources::publish-store-snapshot
                             incomplete
                             (lambda (out)
                               (write-string "partial capture" out)
                               (finish-output out)
                               (sb-posix:fsync (sb-sys:fd-stream-fd out))
                               (bt:with-lock-held (lock)
                                 (setf partial (sb-posix:readlink (format nil "/proc/self/fd/~D" (sb-sys:fd-stream-fd out)))))
                               (loop (sleep 1)))))
                          :name "paused capture publication")
                         (loop until (bt:with-lock-held (lock) (and partial part)) do (sleep 0.02))
                         (scratch-probe-json
                          (merge-pathnames "ready.json" control)
                          (gr8s::core-object "pid" (sb-posix:getpid) "orphans" (vector partial part (namestring completed))
                            "artifacts" (coerce (loop for name in (gr8s.raft.transport::raft-snapshot-directory-names registry)
                                                       when (and (> (length name) 6) (string= ".jsonl" name :start2 (- (length name) 6)))
                                                         collect (namestring (merge-pathnames name registry))) 'vector)))
                         (loop (sleep 1))))
                      ((equal mode "recover")
                       (let* ((record (com.inuoe.jzon:parse (uiop:read-file-string (merge-pathnames "ready.json" control))))
                              (object (gr8s::get-core-resource store "configmaps" "default" "scratch-sentinel")))
                         (loop for path across (gethash "orphans" record)
                               do (assert (null (gr8s.store::store-generation-stat (pathname path)))))
                         (assert (equal "preserved" (gethash "value" (gethash "data" object))))
                         (scratch-probe-json (merge-pathnames "recovered.json" control)
                                             (gr8s::core-object "recovered" t "orphansRemoved" 3 "sentinelPreserved" t))))
                      (t (error "Unknown scratch probe mode"))))
               (gr8s::stop-ha-control-plane ha)))))))
  (error (condition) (format *error-output* "Scratch probe failed: ~A~%" condition) (uiop:quit 1)))
