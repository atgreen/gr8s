;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
(in-package #:gr8s/tests)
(def-suite backup-state :in gr8s)
(in-suite backup-state)

(defun write-backup-fixture (root relative &optional (value "preserved"))
  (let ((path (merge-pathnames relative root)))
    (ensure-directories-exist path)
    (with-open-file (out path :direction :output :if-exists :supersede) (write-string value out))
    (sb-posix:chmod path #o600)
    path))

(test backup-inventory-keeps-all-identity-and-application-roots
  (with-temporary-store (store root)
    (declare (ignore store))
    (let ((required '("pki/cluster-ca.key" "pki/raft/pki/cluster-ca.key"
                      "pki/cluster-ca-next.key" "pki/service-account-signing-key.json"
                      "metadata/application-generation.json" "metadata/application-restore.json"
                      "application-generations/fixture/generation.meta"
                      "raft/bootstrap.json" "raft/control-plane.log"
                      "snapshot-artifacts/fixture.jsonl"
                      "agent/pki/node.key" "network/pool.json" "storage/default-class-seeded"
                      ".extra-identity"))
          (seen nil))
      (dolist (name required) (write-backup-fixture root name))
      (multiple-value-bind (count bytes excluded)
          (gr8s.server::map-offline-backup-files
           root (lambda (name path stat)
                  (declare (ignore path stat)) (push name seen)))
        (is (= count (length seen)))
        (is (plusp bytes))
        (is (member ".gr8s-serve.lock" excluded :test #'equal)))
      (dolist (name required) (is (member name seen :test #'equal))))))

(test backup-inventory-skips-runtime-trees-without-traversing-them
  (with-temporary-store (store root)
    (declare (ignore store))
    (dolist (name '("agent/containerd/" "agent/runtime/" "agent/pods/" "containerd/" "raft/transfers/"))
      (let ((path (merge-pathnames name root)))
        (ensure-directories-exist (merge-pathnames "marker" path))
        (sb-posix:symlink "/dev/null" (merge-pathnames "socket-placeholder" path))))
    (let ((seen nil))
      (multiple-value-bind (count bytes excluded)
          (gr8s.server::map-offline-backup-files root (lambda (name path stat) (declare (ignore path stat)) (push name seen)))
        (declare (ignore count bytes))
        (dolist (prefix gr8s.server::+backup-runtime-prefixes+)
          (is (member prefix excluded :test #'equal)))
        (is (notany (lambda (name) (gr8s.server::backup-excluded-path-p name)) seen))))))

(test backup-inventory-refuses-links-and-special-files
  (dolist (kind '(:symlink :hardlink :fifo))
    (with-temporary-store (store root)
      (declare (ignore store))
      (let ((bad (merge-pathnames "unsafe" root)))
        (ecase kind
          (:symlink (sb-posix:symlink "/dev/null" bad))
          (:hardlink (sb-posix:link (write-backup-fixture root "original") bad))
          (:fifo (sb-posix:mkfifo bad #o600)))
        (signals error (gr8s.server::map-offline-backup-files root (lambda (&rest values) (declare (ignore values)))))))))

(test backup-inventory-excludes-live-serve-writers
  (with-temporary-store (store root)
    (declare (ignore store))
    (gr8s.server::call-with-serve-state-ownership
     (list :state-directory root)
     (lambda ()
       (signals error (gr8s.server::map-offline-backup-files root (lambda (&rest args) (declare (ignore args)))))))))
