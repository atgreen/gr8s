;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
(in-package #:gr8s/tests)
(def-suite store-member-bootstrap :in gr8s)
(in-suite store-member-bootstrap)

(defun call-with-bootstrap-barriers (store function)
  (gr8s.store::quiesce-store-access store)
  (unwind-protect (gr8s.store::call-with-store-application-barriers store function)
    (gr8s.store::resume-store-access store)))

(test bootstrap-founder-and-learner-publish-exact-pristine-artifacts
  (dolist (role '(:founder :learner))
    (with-temporary-store (store root)
      (gr8s::create-core-resource store "configmaps" (configmap-input "recover" "k" "A") "default")
      (let ((wal nil) (reference nil))
        (call-with-bootstrap-barriers
         store (lambda ()
                 (multiple-value-setq (wal reference)
                   (gr8s.resources::bootstrap-store-member-wal store "fresh" :role role :api-url "http://127.0.0.1:8080"))))
        (let* ((recovered (gr8s::load-raft-log wal))
               (state (gr8s::raft-recovered-snapshot-state recovered)))
          (is (= (if (eq role :founder) 1 0) (gr8s::raft-recovered-snapshot-index recovered)))
          (is (= 0 (gr8s::raft-recovered-term recovered)))
          (is (null (gr8s::raft-recovered-entries recovered)))
          (is (equal reference (getf (cddr state) :application)))
          (is (equal (list (cons "fresh" (if (eq role :founder) :voter :learner))) (getf (cddr state) :members)))
          (is (probe-file (gr8s.resources::checked-store-snapshot-artifact-path root reference)))
          (is (equal "A" (startup-store-raw-value store))))
        (let ((before (uiop:read-file-string wal)))
          (call-with-bootstrap-barriers store
           (lambda () (gr8s.resources::bootstrap-store-member-wal store "fresh" :role role :api-url "http://127.0.0.1:8080")))
          (is (equal before (uiop:read-file-string wal))))))))

(test bootstrap-refuses-unowned-barriers-existing-wals-and-identity-changes
  (with-temporary-store (store root)
    (let ((wal (merge-pathnames "raft/control-plane.log" root)))
      (signals error (gr8s.resources::bootstrap-store-member-wal store "fresh"))
      (is (not (probe-file wal)))
      (ensure-directories-exist wal)
      (with-open-file (out wal :direction :output :if-does-not-exist :create) (declare (ignore out)))
      (call-with-bootstrap-barriers store (lambda () (signals error (gr8s.resources::bootstrap-store-member-wal store "fresh"))))
      (is (= 0 (raft-wal-size wal)))
      (is (not (probe-file (merge-pathnames "raft/bootstrap.json" root))))))
  (with-temporary-store (store root)
    (let ((wal (merge-pathnames "raft/control-plane.log" root)))
      (call-with-bootstrap-barriers store (lambda () (gr8s.resources::bootstrap-store-member-wal store "fresh")))
      (let ((before (uiop:read-file-string wal)))
        (call-with-bootstrap-barriers store
         (lambda ()
           (signals error (gr8s.resources::bootstrap-store-member-wal store "other"))
           (signals error (gr8s.resources::bootstrap-store-member-wal store "fresh" :role :learner))))
        (is (equal before (uiop:read-file-string wal))))
      (let ((storage (gr8s::open-file-raft-storage wal)))
        (unwind-protect (gr8s.raft:raft-storage-save-hard-state storage 9 "acknowledged")
          (gr8s::close-file-raft-storage storage)))
      (let ((before (uiop:read-file-string wal)))
        (call-with-bootstrap-barriers store (lambda () (signals error (gr8s.resources::bootstrap-store-member-wal store "fresh"))))
        (is (equal before (uiop:read-file-string wal)))))))

(test fresh-founder-and-learner-start-through-the-recovery-gate
  (with-temporary-store (source source-root)
    (with-temporary-store (sink sink-root)
      (gr8s::create-core-resource source "configmaps" (configmap-input "recover" "k" "A") "default")
      (let ((founder nil) (learner nil))
        (unwind-protect
             (progn
               (setf founder (gr8s.resources::start-store-member-from-wal
                              source "founder" (merge-pathnames "raft/control-plane.log" source-root)
                              :bootstrap-role :founder))
               (is-true (gr8s.store::store-access-blocked-p source))
               (gr8s::raft-member-start founder)
               (is (poll-until (lambda () (not (gr8s.store::store-access-blocked-p source))) :timeout 15))
               (is (equal "A" (startup-store-raw-value source)))
               (setf learner (gr8s.resources::start-store-member-from-wal
                              sink "learner" (merge-pathnames "raft/control-plane.log" sink-root)
                              :bootstrap-role :learner))
               (is (= 0 (gr8s::raft-node-snapshot-index (gr8s::raft-member-node learner))))
               (is (eq :learner (gr8s::raft-node-self-role (gr8s::raft-member-node learner))))
               (gr8s::raft-member-start learner)
               (sleep 0.2)
               (is-true (gr8s.store::store-access-blocked-p sink))
               (is (gr8s::raft-cluster-join learner "127.0.0.1" (gr8s::raft-member-port founder)))
               (is (poll-until (lambda () (not (gr8s.store::store-access-blocked-p sink))) :timeout 20))
               (is (equal "A" (startup-store-raw-value sink)))
               (is (= 1 (gr8s::raft-node-snapshot-index (gr8s::raft-member-node learner))))
               (is (eq :voter (gr8s::raft-node-self-role (gr8s::raft-member-node learner))))
               (gr8s::create-core-resource source "configmaps" (configmap-input "after" "k" "replicated") "default")
               (is (poll-until (lambda () (equal "replicated" (configmap-value sink "after" "k"))) :timeout 15)))
          (when learner (gr8s::stop-raft-member learner))
          (when founder (gr8s::stop-raft-member founder)))))))

(test wal-preparation-holds-ownership-before-creating-the-data-file
  (with-raft-temp-dir (path)
    (let ((called 0) (second 0) (storage nil))
      (unwind-protect
           (progn
             (setf storage
                   (gr8s::open-file-raft-storage
                    path :prepare-fn
                    (lambda (canonical)
                      (incf called)
                      (is (not (probe-file canonical)))
                      (signals error (gr8s::open-file-raft-storage path :prepare-fn
                                      (lambda (ignored) (declare (ignore ignored)) (incf second)))))))
             (is (= 1 called))
             (is (= 0 second)))
        (when storage (gr8s::close-file-raft-storage storage)))))
  (with-raft-temp-dir (path)
    (signals error (gr8s::open-file-raft-storage path :prepare-fn
                    (lambda (ignored) (declare (ignore ignored)) (error "Injected prepare failure"))))
    (is (not (probe-file path)))
    (let ((storage (gr8s::open-file-raft-storage path)))
      (is (not (null storage)))
      (gr8s::close-file-raft-storage storage))))

(test bootstrap-journal-survives-process-kills-at-every-publication-boundary
  (dolist (phase '("before-open" "prepared" "wal-published" "published"))
    (with-temporary-store (store root)
      (gr8s::ensure-cluster-pki root)
      (gr8s::create-core-resource store "configmaps" (configmap-input "recover" "k" "A") "default")
      (let* ((key (merge-pathnames "pki/cluster-ca.key" root))
             (identity (snapshot-test-digest key))
             (script (namestring (merge-pathnames "scripts/store-member-bootstrap-test-child.lisp" (asdf:system-source-directory :gr8s))))
             (ready (merge-pathnames "bootstrap-ready.txt" root))
             (log (merge-pathnames "bootstrap-child.log" root))
             (wal (merge-pathnames "raft/control-plane.log" root))
             (process (sb-ext:run-program "sbcl"
                       (list "--dynamic-space-size" "384" "--noinform" "--non-interactive" "--load" script "--"
                             (namestring root) (namestring ready) phase)
                       :search t :wait nil :input nil :output log :error :output))
             (member nil))
        (unwind-protect
             (progn
               (poll-until (lambda () (or (probe-file ready) (not (sb-ext:process-alive-p process)))) :timeout 60)
               (unless (probe-file ready) (error "Bootstrap child failed:~%~A" (uiop:read-file-string log)))
               (is (sb-ext:process-alive-p process))
               (call-with-bootstrap-barriers store (lambda () (signals error (gr8s.resources::bootstrap-store-member-wal store "fresh"))))
               (sb-ext:process-kill process sb-posix:sigkill)
               (sb-ext:process-wait process)
               (is (eq :signaled (sb-ext:process-status process)))
               (sb-ext:process-close process)
               (setf process nil)
               (let* ((journal (gr8s.store::read-private-generation-json (merge-pathnames "raft/bootstrap.json" root)))
                      (digest (gethash "sha256" (gethash "application" journal))))
                 (when (equal phase "before-open") (is (not (probe-file wal))))
                 (unless (equal phase "before-open")
                   ;; Later files must never replace the already retained baseline.
                   (gr8s::update-core-resource store "configmaps" "default" "recover"
                     (lambda (object) (setf (gethash "k" (gethash "data" object)) "B") object)))
                 (call-with-bootstrap-barriers store
                  (lambda ()
                    (multiple-value-bind (path reference) (gr8s.resources::bootstrap-store-member-wal store "fresh")
                      (is (equal wal path))
                      (unless (equal phase "before-open") (is (equal digest (eighth reference)))))))
               (is (equal identity (snapshot-test-digest key)))
               (setf member (gr8s.resources::start-store-member-from-wal store "fresh" wal))
               (is (equal "A" (startup-store-raw-value store)))
               (is-true (gr8s.store::store-access-blocked-p store))
               (gr8s::raft-member-start member)
               (is (poll-until (lambda () (not (gr8s.store::store-access-blocked-p store))) :timeout 15))
               (is (equal identity (snapshot-test-digest key))))
          (when member (gr8s::stop-raft-member member))
          (when process
            (when (sb-ext:process-alive-p process)
              (sb-ext:process-kill process sb-posix:sigkill)
              (sb-ext:process-wait process))
            (sb-ext:process-close process))))))))

(test published-bootstrap-never-rebuilds-a-lost-empty-or-corrupt-wal
  (dolist (failure '(:missing :empty :corrupt))
    (with-temporary-store (store root)
      (let ((wal (merge-pathnames "raft/control-plane.log" root))
            (journal (merge-pathnames "raft/bootstrap.json" root)))
        (call-with-bootstrap-barriers store (lambda () (gr8s.resources::bootstrap-store-member-wal store "fresh")))
        (if (eq failure :missing)
            (delete-file wal)
            (with-open-file (out wal :direction :output :if-exists :supersede)
              (when (eq failure :corrupt) (write-string "not a WAL" out))))
        (let ((before (when (probe-file wal) (uiop:read-file-string wal)))
              (marker (uiop:read-file-string journal)))
          (call-with-bootstrap-barriers store (lambda () (signals error (gr8s.resources::bootstrap-store-member-wal store "fresh"))))
          (is (equal marker (uiop:read-file-string journal)))
          (if (eq failure :missing)
              (is (not (probe-file wal)))
              (is (equal before (uiop:read-file-string wal)))))))))

(test learner-zero-boundary-is-always-the-canonical-zero-term
  (let ((digest (make-string 64 :initial-element #\a)))
    (is (equal (list :gr8s-store-artifact 1 :index 0 :term 0 :sha256 digest)
               (gr8s.resources::store-snapshot-artifact-reference 0 0 digest)))
    (signals error (gr8s.resources::store-snapshot-artifact-reference 0 1 digest))
    (signals error (gr8s.ha::make-member-generation-validator
                    (gr8s::make-raft-member) 1 0 1 digest :recover t))))
