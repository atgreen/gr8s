;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
(in-package #:gr8s/tests)
(def-suite store-application-reload :in gr8s)
(in-suite store-application-reload)

(test every-store-slot-has-an-explicit-reload-classification
  (let* ((slots (mapcar (lambda (slot) (symbol-name (sb-mop:slot-definition-name slot)))
                       (sb-mop:class-slots (find-class 'gr8s.store:pod-store))))
         (fields (append gr8s.store::*store-application-reload-fields* gr8s.store::*store-member-reload-fields*))
         (names (mapcar (lambda (field) (subseq (symbol-name field) (length "POD-STORE-"))) fields)))
    (is (= (length names) (length (remove-duplicates names :test #'equal))))
    (is (null (set-difference slots names :test #'equal)))
    (is (null (set-difference names slots :test #'equal)))))

(test application-reload-reuses-store-preserves-member-state-and-clears-caches
  (with-temporary-store (store root)
    (let* ((key (gr8s::load-service-account-signing-key store))
           (key-path (gr8s::service-account-signing-key-path store))
           (key-bytes (uiop:read-file-string key-path))
           (descriptor (make-restore-intent-fixture store root))
           (id (gethash "generation" descriptor))
           (lock (gr8s::pod-store-lock store))
           (credential-lock (gr8s::pod-store-credential-lock store))
           (writer-lock (gr8s::pod-store-consensus-write-lock store))
           (workload-lock (gr8s::pod-store-workload-lock store))
           (config (list :api-url "member-api" :ca-pem "member-ca")))
      (setf (gr8s::pod-store-in-cluster-config store) config
            (gr8s::pod-store-watch-journal-p store) nil
            (gethash "old" (gr8s::pod-store-verified-tokens store)) :cached
            (gethash "old" (gr8s::pod-store-projected-tokens store)) :cached
            (gethash "old" (gr8s::pod-store-pod-certificates store)) :cached
            (gethash "old" (gr8s::pod-store-nominated-nodes store)) "old-node"
            (gethash "old" (gr8s::pod-store-scheduling-notes store)) "old-note"
            (gethash "old" (gr8s::pod-store-job-controller-states store)) (gr8s::core-object)
            (gethash '("events" "default" "old") (gr8s::pod-store-resources store)) (gr8s::core-object "message" "old"))
      (gr8s.store::quiesce-store-access store :timeout 0)
      (is (eq store (gr8s.store::reload-store-application store id)))
      (is (gr8s.store::store-access-blocked-p store))
      (is (gr8s.store::pod-store-application-loaded-p store))
      (is (null (gr8s.store::read-store-restore-intent root)))
      (assert-store-access-503 (lambda () (gr8s:get-pod store "default" "snapshot-pod")))
      (is (eq lock (gr8s::pod-store-lock store)))
      (is (eq credential-lock (gr8s::pod-store-credential-lock store)))
      (is (eq writer-lock (gr8s::pod-store-consensus-write-lock store)))
      (is (eq workload-lock (gr8s::pod-store-workload-lock store)))
      (is (eq config (gr8s::pod-store-in-cluster-config store)))
      (is (eq key (gr8s::pod-store-service-account-signing-key store)))
      (is (equal key-bytes (uiop:read-file-string key-path)))
      (is (null (gr8s::pod-store-watch-journal-p store)))
      (is (every #'zerop (mapcar (lambda (accessor) (hash-table-count (funcall accessor store)))
                                '(gr8s::pod-store-verified-tokens gr8s::pod-store-projected-tokens
                                  gr8s::pod-store-pod-certificates gr8s::pod-store-nominated-nodes
                                  gr8s::pod-store-scheduling-notes gr8s::pod-store-job-controller-states))))
      (is (not (gethash '("events" "default" "old") (gr8s::pod-store-resources store))))
      (is (zerop (gr8s::pod-store-pod-watch-journal-length store)))
      (is (zerop (gr8s::pod-store-node-watch-journal-length store)))
      (is (= (gr8s::pod-store-pod-revision store) (gr8s::pod-store-pod-watch-floor store)))
      (is (= (gr8s::pod-store-pod-revision store) (gr8s::pod-store-node-watch-floor store)))
      (gr8s.store::resume-store-access store)
      (is (gr8s:get-pod store "default" "snapshot-pod"))
      (signals gr8s:kubernetes-error (gr8s:get-pod store "default" "legacy-later"))
      (is (gr8s::get-core-resource store "configmaps" "default" "snapshot-config")))))

(test reload-failure-keeps-access-blocked-and-intent-pending-until-same-object-retry
  (with-temporary-store (store root)
    (let* ((descriptor (make-restore-intent-fixture store root))
           (id (gethash "generation" descriptor))
           (original (symbol-function 'gr8s.store::load-store-application-files)))
      (gr8s.store::quiesce-store-access store :timeout 0)
      (unwind-protect
           (progn
             (setf (symbol-function 'gr8s.store::load-store-application-files)
                   (lambda (target) (funcall original target) (error "Injected failure after application load")))
             (signals error (gr8s.store::reload-store-application store id)))
        (setf (symbol-function 'gr8s.store::load-store-application-files) original))
      (is (not (gr8s.store::pod-store-application-loaded-p store)))
      (is (gr8s.store::read-store-restore-intent root))
      (assert-store-access-503 (lambda () (gr8s.store::resume-store-access store)))
      (assert-store-access-503 (lambda () (gr8s:get-pod store "default" "snapshot-pod")))
      (is (eq store (gr8s.store::reload-store-application store id)))
      (gr8s.store::resume-store-access store)
      (is (gr8s:get-pod store "default" "snapshot-pod")))))

(test ha-reload-requires-member-barrier-and-durable-acknowledgement
  (with-temporary-store (store root)
    (let* ((descriptor (make-restore-intent-fixture store root))
           (id (gethash "generation" descriptor))
           (proposals 0) (barrier-held nil) (acks 0)
           (commit (lambda (&rest args) (declare (ignore args)) (incf proposals))))
      (setf (gr8s::pod-store-consensus-commit-fn store) commit)
      (gr8s.store::quiesce-store-access store :timeout 0)
      (signals error (gr8s.store::reload-store-application store id))
      (is (null (gr8s.store::read-store-restore-intent root)))
      (signals error (gr8s.store::reload-store-application store id :call-with-member-lock #'funcall))
      (is (eq store
              (gr8s.store::reload-store-application
               store id :call-with-member-lock
               (lambda (function) (let ((prior barrier-held))
                                    (unwind-protect (progn (setf barrier-held t) (funcall function))
                                      (setf barrier-held prior))))
               :commit-recovery
               (lambda (incoming target)
                 (unless (and barrier-held (eq store target) (= 42 (gethash "index" incoming)))
                   (error "Recovery callback outside member barrier"))
                 (incf acks)))))
      (is (= 1 acks))
      (is (= 0 proposals))
      (is (eq commit (gr8s::pod-store-consensus-commit-fn store)))
      (gr8s.store::resume-store-access store))))

(test recovery-ack-failure-cannot-reopen-partially-acknowledged-application
  (with-temporary-store (store root)
    (let* ((descriptor (make-restore-intent-fixture store root)) (id (gethash "generation" descriptor)))
      (gr8s.store::quiesce-store-access store :timeout 0)
      (signals error
        (gr8s.store::reload-store-application
         store id :commit-recovery (lambda (&rest args) (declare (ignore args)) (error "WAL acknowledgement failed"))))
      (is (gr8s.store::read-store-restore-intent root))
      (is (not (gr8s.store::pod-store-application-loaded-p store)))
      (assert-store-access-503 (lambda () (gr8s.store::resume-store-access store)))
      (is (eq store (gr8s.store::reload-store-application store id)))
      (gr8s.store::resume-store-access store))))

(test reload-rejects-undrained-access-and-barriers-that-skip-the-operation
  (with-temporary-store (store root)
    (let* ((descriptor (make-restore-intent-fixture store root)) (id (gethash "generation" descriptor)))
      (signals gr8s:kubernetes-error (gr8s.store::reload-store-application store id))
      (is (null (gr8s.store::read-store-restore-intent root)))
      (gr8s.store::quiesce-store-access store :timeout 0)
      (signals error (gr8s.store::reload-store-application store id :call-with-member-lock (lambda (fn) (declare (ignore fn)) nil)))
      (is (null (gr8s.store::read-store-restore-intent root)))
      (gr8s.store::resume-store-access store))))

(test reloaded-store-continues-consensus-writes-in-selected-generation
  (with-temporary-store (store root)
    (let* ((descriptor (make-restore-intent-fixture store root))
           (id (gethash "generation" descriptor))
           (proposals 0))
      (setf (gr8s::pod-store-consensus-commit-fn store)
            (lambda (kind payload) (incf proposals) (apply-pod-test-command store kind payload)))
      (gr8s.store::quiesce-store-access store :timeout 0)
      (gr8s.store::reload-store-application
       store id :call-with-member-lock #'funcall
       :commit-recovery (lambda (&rest args) (declare (ignore args)) t))
      (is (= 0 proposals))
      (gr8s.store::resume-store-access store)
      (let* ((pod (ha-make-pod store "after-reload")) (uid (gr8s:pod-uid pod)))
        (is (= 1 proposals))
        (is (uiop:subpathp (gr8s::pod-path store pod) (gr8s.store::store-generation-root root id)))
        (is (not (probe-file (merge-pathnames (format nil "~A.json" uid) root))))
        (let ((reopened (gr8s:open-store root)))
          (is (equal uid (gr8s:pod-uid (gr8s:get-pod reopened "default" "after-reload")))))))))

(test intent-unlink-sync-failure-still-requires-successful-reload-before-resume
  (with-temporary-store (store root)
    (let* ((descriptor (make-restore-intent-fixture store root))
           (id (gethash "generation" descriptor))
           (intent (gr8s.store::store-restore-intent-path root))
           (metadata (uiop:pathname-directory-pathname intent))
           (original (symbol-function 'gr8s.store::sync-store-generation-directory)))
      (gr8s.store::quiesce-store-access store :timeout 0)
      (unwind-protect
           (progn
             (setf (symbol-function 'gr8s.store::sync-store-generation-directory)
                   (lambda (directory)
                     (when (and (equal directory metadata) (not (gr8s.store::store-generation-stat intent)))
                       (error "Injected intent cleanup sync failure after reload"))
                     (funcall original directory)))
             (signals error (gr8s.store::reload-store-application store id)))
        (setf (symbol-function 'gr8s.store::sync-store-generation-directory) original))
      (is (null (probe-file intent)))
      (is (not (gr8s.store::pod-store-application-loaded-p store)))
      (assert-store-access-503 (lambda () (gr8s.store::resume-store-access store)))
      (is (eq store (gr8s.store::reload-store-application store id)))
      (gr8s.store::resume-store-access store)
      (is (gr8s:get-pod store "default" "snapshot-pod")))))

(test encrypted-secret-generation-reloads-policy-and-keeps-member-key
  (with-temporary-store (store root)
    (let* ((config (gr8s::enable-secret-encryption store))
           (ca-path (merge-pathnames "pki/cluster-ca.key" root))
           (ca-bytes (uiop:read-file-string ca-path))
           (sentinel "cmVsb2FkLXNlY3JldC1zZW50aW5lbA==")
           (source (merge-pathnames "encrypted-reload.jsonl" root)))
      (gr8s::create-core-resource store "secrets"
                                  (core-fixture "Secret" "reload-secret" "data"
                                                (gr8s::core-object "password" sentinel)) "default")
      (gr8s.resources::capture-store-snapshot store source 42 7)
      (is (not (search sentinel (uiop:read-file-string source))))
      (multiple-value-bind (path descriptor)
          (gr8s.resources::materialize-store-snapshot root source (snapshot-test-digest source))
        (is (not (search sentinel (uiop:read-file-string (merge-pathnames "objects/state.json" path)))))
        ;; A different currently loaded policy must not survive the generation change.
        (setf (gr8s.store:pod-store-secret-encryption-config store) (gr8s.resources::new-secret-encryption-config))
        (gr8s.store::quiesce-store-access store :timeout 0)
        (gr8s.store::reload-store-application store (gethash "generation" descriptor))
        (gr8s.store::resume-store-access store)
        (is (equalp config (gr8s.store:pod-store-secret-encryption-config store)))
        (is (equal ca-bytes (uiop:read-file-string ca-path)))
        (dolist (target (list store (gr8s:open-store root)))
          (let ((secret (gr8s::get-core-resource target "secrets" "default" "reload-secret")))
            (is (equal sentinel (gethash "password" (gethash "data" secret))))))))))
