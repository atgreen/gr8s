;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
(in-package #:gr8s/tests)
(def-suite pod-publications :in gr8s)
(in-suite pod-publications)

(test pod-publication-survives-reopen-and-subsequent-status-update
  (with-temporary-store (store directory)
    (let ((pod (ha-make-pod store "published")))
      (gr8s.store:with-store-lock (store)
        (gr8s.store:publish-pod-status-unlocked store pod (gr8s::core-object "phase" "Running" "message" "published")))
      (let* ((current (gr8s:get-pod store "default" "published"))
             (view (gr8s::pod-published-view store current))
             (reopened (gr8s:open-store directory))
             (restored (gr8s:get-pod reopened "default" "published")))
        (is (equalp view (gr8s::pod-published-view reopened restored)))
        (is (= (gr8s::pod-status-revision current) (gr8s::pod-status-revision restored)))
        (is (= #o600 (logand #o777 (sb-posix:stat-mode (sb-posix:stat (namestring (gr8s.store::pod-publication-path store (gr8s:pod-uid pod))))))))
        (gr8s.store:with-store-lock (reopened)
          (gr8s.store:publish-pod-status-unlocked reopened restored (gr8s::core-object "phase" "Succeeded")))
        (let ((again (gr8s:open-store directory)))
          (is (equal "Succeeded" (gethash "phase" (gethash "status" (gr8s::pod-published-view again (gr8s:get-pod again "default" "published")))))))))))

(test pod-publication-consensus-apply-survives-reopen
  (with-temporary-store (store directory)
    (setf (gr8s::pod-store-consensus-commit-fn store)
          (lambda (kind json) (apply-pod-test-command store kind json)))
    (let ((pod (ha-make-pod store "replicated")))
      (gr8s.store:with-store-lock (store)
        (gr8s.store:publish-pod-status-unlocked store pod (gr8s::core-object "phase" "Running")))
      (let ((reopened (gr8s:open-store directory)))
        (is (equalp (gr8s::pod-published-view store (gr8s:get-pod store "default" "replicated"))
                    (gr8s::pod-published-view reopened (gr8s:get-pod reopened "default" "replicated"))))))))

(test publication-write-failure-does-not-publish-status-or-watch-event
  (with-temporary-store (store directory)
    (declare (ignore directory))
    (let* ((pod (ha-make-pod store "failure"))
           (before (gr8s::pod-published-view store pod))
           (events (gr8s::pod-store-pod-watch-journal-length store))
           (original (symbol-function 'gr8s.security::write-private-text-exclusively)))
      (unwind-protect
           (progn
             (setf (symbol-function 'gr8s.security::write-private-text-exclusively)
                   (lambda (&rest args) (declare (ignore args)) (error "Injected private write failure")))
             (signals error
               (gr8s.store:with-store-lock (store)
                 (gr8s.store:publish-pod-status-unlocked store pod (gr8s::core-object "phase" "Running")))))
        (setf (symbol-function 'gr8s.security::write-private-text-exclusively) original))
      (is (equalp before (gr8s::pod-published-view store pod)))
      (is (= events (gr8s::pod-store-pod-watch-journal-length store))))))

(test publication-stale-desired-version-is-ignored-and-legacy-store-still-opens
  (with-temporary-store (store directory)
    (let* ((pod (ha-make-pod store "stale"))
           (path (gr8s.store::pod-publication-path store (gr8s:pod-uid pod)))
           (record (gr8s.store::read-pod-publication path)))
      (setf (gethash "desiredResourceVersion" record) "0"
            (gethash "status" record) (gr8s::core-object "phase" "Succeeded"))
      (gr8s.store::write-text-atomically path (com.inuoe.jzon:stringify record))
      (sb-posix:chmod (namestring path) #o600)
      (let ((reopened (gr8s:open-store directory)))
        (is (equal "Pending" (gethash "phase" (gethash "status" (gr8s::pod-published-view reopened (gr8s:get-pod reopened "default" "stale")))))))
      (delete-file path)
      (is (gr8s:open-store directory)))))

(test pod-spec-update-persists-the-current-publication-and-delete-removes-it
  (with-temporary-store (store directory)
    (let ((pod (ha-make-pod store "spec-update")))
      (gr8s.store:with-store-lock (store)
        (gr8s.store:publish-pod-status-unlocked store pod (gr8s::core-object "phase" "Running")))
      (let* ((updated (gr8s:update-pod store (changed-pod-label pod "next") (gr8s:pod-resource-version pod)))
             (view (gr8s::pod-published-view store updated))
             (reopened (gr8s:open-store directory)))
        (is (equalp view (gr8s::pod-published-view reopened (gr8s:get-pod reopened "default" "spec-update"))))
        (gr8s:remove-pod reopened "default" "spec-update")
        (is (null (probe-file (gr8s.store::pod-publication-path reopened (gr8s:pod-uid updated)))))))))

(test publication-loader-rejects-link-and-future-revision
  (with-temporary-store (store directory)
    (let* ((pod (ha-make-pod store "unsafe"))
           (path (gr8s.store::pod-publication-path store (gr8s:pod-uid pod)))
           (outside (merge-pathnames (format nil "outside/~A.json" (gr8s:pod-uid pod)) directory))
           (record (gr8s.store::read-pod-publication path)))
      (ensure-directories-exist outside)
      (sb-posix:rename (namestring path) (namestring outside))
      (sb-posix:symlink (namestring outside) (namestring path))
      (signals error (gr8s:open-store directory))
      (sb-posix:unlink (namestring path))
      (setf (gethash "resourceVersion" record) (write-to-string (+ 10000 (gr8s::pod-store-pod-revision-ceiling store))))
      (gr8s.security::write-private-text-exclusively path (com.inuoe.jzon:stringify record))
      (signals error (gr8s:open-store directory)))))
