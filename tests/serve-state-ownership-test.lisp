;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
(in-package #:gr8s/tests)
(def-suite serve-state-ownership :in gr8s)
(in-suite serve-state-ownership)

(test serve-owns-state-before-open-store-and-releases-on-initializer-failure
  (let* ((root (uiop:ensure-directory-pathname (sb-posix:mkdtemp "/tmp/gr8s-owner-XXXXXX")))
         (options (list :state-directory root))
         (original (symbol-function 'gr8s.store::open-store)) (opened 0))
    (unwind-protect
         (progn
           (signals error (gr8s.server::serve-owned options))
           (setf (symbol-function 'gr8s.store::open-store)
                 (lambda (path &key defer-restore-completion)
                   (is (null defer-restore-completion))
                   (incf opened)
                   (is (equal root (truename path)))
                   (is (not (null (gr8s.server::require-serve-state-ownership options))))
                   (signals error (gr8s.server::call-with-serve-state-ownership options (lambda () (fail "second owner entered"))))
                   (error "Injected open-store initialization failure")))
           (signals error (gr8s.server::serve options))
           (is (= 1 opened))
           (is (eq :released (gr8s.server::call-with-serve-state-ownership options (lambda () :released)))))
      (setf (symbol-function 'gr8s.store::open-store) original)
      (uiop:delete-directory-tree root :validate t))))

(test serve-lease-covers-unwind-cleanup-and-canonical-aliases
  (with-temporary-store (store root)
    (declare (ignore store))
    (let ((alias (merge-pathnames "alias/" root)) (options (list :state-directory root)) (cleaned nil))
      (sb-posix:symlink (namestring root) (string-right-trim "/" (namestring alias)))
      (unwind-protect
           (progn
             (gr8s.server::call-with-serve-state-ownership
              options
              (lambda ()
                (unwind-protect :body
                  (setf cleaned t)
                  (signals error (gr8s.server::call-with-serve-state-ownership
                                  (list :state-directory alias) (lambda () (fail "alias bypassed ownership")))))))
             (is-true cleaned)
             (is (eq :released (gr8s.server::call-with-serve-state-ownership options (lambda () :released)))))
        (sb-posix:unlink (string-right-trim "/" (namestring alias)))))))

(test ha-mode-survives-failure-and-refuses-standalone-fallback
  (with-temporary-store (store root)
    (declare (ignore store))
    (let ((ha (list :state-directory root :raft-init t)) (plain (list :state-directory root)))
      (gr8s.server::call-with-serve-state-ownership plain (lambda () nil))
      (signals error (gr8s.server::call-with-serve-state-ownership ha (lambda () (error "startup interrupted"))))
      (let* ((path (merge-pathnames "metadata/server-mode.json" root)) (before (uiop:read-file-string path)))
        (signals error (gr8s.server::call-with-serve-state-ownership plain (lambda () (fail "HA opened as standalone"))))
        (is (equal before (uiop:read-file-string path)))
        (is (eq :ha (gr8s.server::call-with-serve-state-ownership ha (lambda () :ha)))))))
  (dolist (evidence '("raft/control-plane.log" "raft/bootstrap.json" "pki/raft/pki/cluster-ca.crt" "raft/witness.log"))
    (with-temporary-store (store root)
      (declare (ignore store))
      (let ((path (merge-pathnames evidence root)))
        (ensure-directories-exist path)
        (with-open-file (out path :direction :output :if-does-not-exist :create) (write-line "existing" out))
        (signals error (gr8s.server::call-with-serve-state-ownership
                        (list :state-directory root) (lambda () (fail "legacy Raft state opened as standalone"))))
        (is (equal (format nil "existing~%") (uiop:read-file-string path)))))))

(test serve-ownership-refuses-links-and-unsafe-mode-descriptors
  (dolist (failure '(:symlink :hardlink :permissions :mode))
    (with-temporary-store (store root)
      (declare (ignore store))
      (let ((path (merge-pathnames ".gr8s-serve.lock" root)))
        (gr8s.server::call-with-serve-state-ownership (list :state-directory root) (lambda () nil))
        (ecase failure
          (:symlink (delete-file path) (sb-posix:symlink "missing" (namestring path)))
          (:hardlink (sb-posix:link (namestring path) (namestring (merge-pathnames "other.lock" root))))
          (:permissions (sb-posix:chmod (namestring path) #o644))
          (:mode (with-open-file (out (merge-pathnames "metadata/server-mode.json" root) :direction :output :if-exists :supersede)
                   (write-string "{}" out))))
        (signals error (gr8s.server::call-with-serve-state-ownership
                        (list :state-directory root) (lambda () (fail "unsafe owner state accepted"))))))))

(test serve-process-death-releases-state-ownership
  (with-temporary-store (store root)
    (declare (ignore store))
    (let* ((script (namestring (merge-pathnames "scripts/serve-state-owner-test-child.lisp" (asdf:system-source-directory :gr8s))))
           (ready (merge-pathnames "owner-ready.txt" root))
           (log (merge-pathnames "owner-child.log" root))
           (process (sb-ext:run-program "sbcl"
                     (list "--dynamic-space-size" "384" "--noinform" "--non-interactive" "--load" script "--" (namestring root) (namestring ready))
                     :search t :wait nil :input nil :output log :error :output)))
      (unwind-protect
           (progn
             (poll-until (lambda () (or (probe-file ready) (not (sb-ext:process-alive-p process)))) :timeout 60)
             (unless (probe-file ready) (error "Ownership child failed: ~A" (uiop:read-file-string log)))
             (signals error (gr8s.server::call-with-serve-state-ownership
                             (list :state-directory root) (lambda () (fail "competing process entered"))))
             (sb-ext:process-kill process sb-posix:sigkill)
             (sb-ext:process-wait process)
             (is (eq :signaled (sb-ext:process-status process)))
             (is (eq :released (gr8s.server::call-with-serve-state-ownership
                                (list :state-directory root) (lambda () :released)))))
        (when (sb-ext:process-alive-p process)
          (sb-ext:process-kill process sb-posix:sigkill) (sb-ext:process-wait process))
        (sb-ext:process-close process)))))

(test invalid-ha-options-do-not-change-the-persisted-mode
  (with-temporary-store (store root)
    (declare (ignore store))
    (gr8s.server::call-with-serve-state-ownership (list :state-directory root) (lambda () nil))
    (let* ((path (merge-pathnames "metadata/server-mode.json" root)) (before (uiop:read-file-string path)))
      (dolist (flags '((:raft-init t :raft-join "host:7449") (:raft-join "host:not-a-port")))
        (signals error (gr8s.server::call-with-serve-state-ownership
                        (append (list :state-directory root) flags) (lambda () (fail "invalid request entered")))))
      (is (equal before (uiop:read-file-string path))))))

(test metadata-directory-link-cannot-redirect-mode-publication
  (let* ((root (uiop:ensure-directory-pathname (sb-posix:mkdtemp "/tmp/gr8s-owner-XXXXXX")))
         (outside (uiop:ensure-directory-pathname (sb-posix:mkdtemp "/tmp/gr8s-owner-XXXXXX")))
         (alias (merge-pathnames "metadata" root))
         (mode (merge-pathnames "server-mode.json" outside)))
    (unwind-protect
         (progn
           (gr8s.server::write-serve-state-mode mode "standalone")
           (sb-posix:symlink (namestring outside) (namestring alias))
           (let ((before (uiop:read-file-string mode)))
             (signals error (gr8s.server::call-with-serve-state-ownership
                             (list :state-directory root :raft-init t) (lambda () (fail "linked metadata accepted"))))
             (is (equal before (uiop:read-file-string mode)))))
      (when (gr8s.store::store-generation-stat alias) (sb-posix:unlink (namestring alias)))
      (uiop:delete-directory-tree root :validate t)
      (uiop:delete-directory-tree outside :validate t))))

(test serve-command-owns-state-during-startup-and-shutdown
  (with-temporary-store (store root)
    (declare (ignore store))
    (let* ((options (list :state-directory root))
           (original (symbol-function 'gr8s.server::serve-owned))
           (events nil))
      (flet ((owned (event)
               (push event events)
               (is (not (null (gr8s.server::require-serve-state-ownership options))))
               (signals error (gr8s.server::call-with-serve-state-ownership
                               options (lambda () (fail "serve lifecycle lost ownership"))))))
        (unwind-protect
             (progn
               (setf (symbol-function 'gr8s.server::serve-owned)
                     (lambda (ignored) (declare (ignore ignored)) (owned :serve) (error "initializer failure")))
               (signals error (gr8s.server::run-serve-command options))
               (is (equal '(:serve) events))
               (is (eq :released (gr8s.server::call-with-serve-state-ownership options (lambda () :released)))))
          (setf (symbol-function 'gr8s.server::serve-owned) original))))))

(test ha-endpoint-is-stable-before-application-initialization
  (with-temporary-store (store root)
    (declare (ignore store))
    (let* ((options (list :state-directory root :raft-init t :raft-id "cp1"))
           (path (merge-pathnames "metadata/server-ha-endpoint.json" root))
           (open-original (symbol-function 'gr8s.store::open-store))
           (opened 0))
      (unwind-protect
           (progn
             (setf (symbol-function 'gr8s.store::open-store)
                   (lambda (ignored &key defer-restore-completion)
                     (declare (ignore ignored))
                     (is (eq t defer-restore-completion))
                     (incf opened)
                     (let ((record (gr8s.store::read-private-generation-json path)))
                       (is (= 7000 (gethash "port" record)))
                       (is (equal "cp1" (gethash "memberId" record))))
                     (error "interrupted application initialization")))
             (signals error (gr8s.server::serve options))
             (is (= 1 opened))
             (let ((before (uiop:read-file-string path)))
               ;; A retry reuses the same descriptor, including after failure.
               (signals error (gr8s.server::serve options))
               (is (= 2 opened))
               (dolist (change '((:raft-id "cp2") (:raft-port 7001) (:raft-listen "127.0.0.2")
                                 (:listen "127.0.0.2") (:port 8081)))
                 (let ((changed (copy-list options)))
                   (setf (getf changed (first change)) (second change))
                   (signals error (gr8s.server::run-serve-command changed))))
               (is (= 2 opened))
               (is (equal before (uiop:read-file-string path))))
             ;; Join/founder flags are startup intent, not a new member identity.
             (is (eq :same (gr8s.server::call-with-serve-state-ownership
                            (list :state-directory root :raft-join "127.0.0.1:7000" :raft-id "cp1")
                            (lambda () :same)))))
        (setf (symbol-function 'gr8s.store::open-store) open-original)))))

(test ha-endpoint-rejects-unsafe-or-invalid-descriptors
  (dolist (failure '(:symlink :hardlink :permissions :null :extra :zero :wildcard))
    (with-temporary-store (store root)
      (declare (ignore store))
      (let* ((options (list :state-directory root :raft-init t))
             (path (merge-pathnames "metadata/server-ha-endpoint.json" root)))
        (gr8s.server::call-with-serve-state-ownership options (lambda () nil))
        (ecase failure
          (:symlink (delete-file path) (sb-posix:symlink "missing" (namestring path)))
          (:hardlink (sb-posix:link (namestring path) (namestring (merge-pathnames "linked.json" root))))
          (:permissions (sb-posix:chmod (namestring path) #o644))
          (:null (with-open-file (out path :direction :output :if-exists :supersede) (write-string "null" out)))
          (:extra (let ((record (gr8s.store::read-private-generation-json path)))
                    (setf (gethash "extra" record) t) (gr8s.server::write-serve-state-record path record)))
          (:zero (setf (getf options :raft-port) 0))
          (:wildcard (setf (getf options :raft-listen) "0.0.0.0")))
        (signals error (gr8s.server::call-with-serve-state-ownership
                        options (lambda () (fail "invalid endpoint entered startup"))))))))

(test null-serve-mode-cannot-be-overwritten-as-uninitialized-state
  (with-temporary-store (store root)
    (declare (ignore store))
    (let ((options (list :state-directory root)))
      (gr8s.server::call-with-serve-state-ownership options (lambda () nil))
      (let ((path (merge-pathnames "metadata/server-mode.json" root)))
        (with-open-file (out path :direction :output :if-exists :supersede) (write-string "null" out))
        (signals error (gr8s.server::call-with-serve-state-ownership options (lambda () (fail "null mode accepted"))))
        (is (equal "null" (uiop:read-file-string path)))))))

(test legacy-in-memory-ha-cannot-silently-bootstrap-a-new-quorum
  (dolist (evidence '(:mode :credentials :endpoint))
    (with-temporary-store (store root)
      (declare (ignore store))
      (let* ((metadata (merge-pathnames "metadata/" root))
             (mode (merge-pathnames "server-mode.json" metadata))
             (options (list :state-directory root :raft-init t)))
        (gr8s.store::ensure-store-generation-directory metadata root :metadata t)
        (ecase evidence
          (:mode (gr8s.server::write-serve-state-record mode
                   (gr8s.resources::core-object "format" "gr8s-serve-mode" "version" 1 "mode" "ha")))
          (:credentials (ensure-directories-exist (merge-pathnames "pki/raft/" root)))
          (:endpoint (gr8s.server::check-serve-ha-endpoint root options)))
        (let ((before (and (probe-file mode) (uiop:read-file-string mode))))
          (signals error (gr8s.server::call-with-serve-state-ownership
                          options (lambda () (fail "legacy HA was treated as fresh"))))
          (is (equal before (and (probe-file mode) (uiop:read-file-string mode)))))
        (is (not (probe-file (merge-pathnames "raft/control-plane.log" root))))))))

(test fresh-ha-genesis-intent-survives-interruption-before-endpoint-publication
  (with-temporary-store (store root)
    (declare (ignore store))
    (let ((options (list :state-directory root :raft-init t)))
      (gr8s.server::call-with-serve-state-ownership options (lambda () nil))
      (delete-file (merge-pathnames "metadata/server-ha-endpoint.json" root))
      (ensure-directories-exist (merge-pathnames "pki/raft/" root))
      (is (eq :resumed (gr8s.server::call-with-serve-state-ownership options (lambda () :resumed))))
      (is (eql 2 (gethash "version" (gr8s.store::read-private-generation-json
                                    (merge-pathnames "metadata/server-mode.json" root))))))))

(test recovered-serve-reclaims-only-private-recognized-snapshot-scratch-before-listening
  (with-temporary-store (store root)
    (let* ((options (gr8s.server::parse-serve-options '("--raft-init" "--node-name" "scratch-cp")))
           (registry (gr8s.resources::store-snapshot-registry-directory root))
           (raft (merge-pathnames "raft/" root))
           (id (gr8s.store::generate-uid))
           (capture (merge-pathnames (format nil "capture-~A.jsonl" id) raft))
           (partial (gr8s.security::private-temporary-path capture))
           (part (merge-pathnames (format nil "~A.part" id) registry))
           (unsafe (merge-pathnames (format nil "~A.part" (gr8s.store::generate-uid)) registry))
           (linked (merge-pathnames (format nil "~A.part" (gr8s.store::generate-uid)) registry))
           (symbolic (merge-pathnames (format nil "~A.part" (gr8s.store::generate-uid)) registry))
           (unknown (merge-pathnames "not-a-uuid.part" registry))
           (protected (merge-pathnames "protected" root))
           (ha nil))
      (setf (getf options :state-directory) root)
      (let ((listener (usocket:socket-listen "127.0.0.1" 0 :reuse-address t)))
        (unwind-protect (setf (getf options :raft-port) (usocket:get-local-port listener))
          (usocket:socket-close listener)))
      (ensure-directories-exist capture)
      (sb-posix:chmod (namestring raft) #o700)
      (dolist (path (list capture partial part unsafe unknown protected))
        (gr8s.security::write-private-text-exclusively path "scratch"))
      (sb-posix:chmod (namestring unsafe) #o644)
      (sb-posix:link (namestring protected) (namestring linked))
      (sb-posix:symlink (namestring protected) (namestring symbolic))
      (unwind-protect
           (gr8s.server::call-with-serve-state-ownership
            options
            (lambda ()
              (setf ha (gr8s.server::maybe-start-ha-control-plane store nil options))
              (dolist (path (list capture partial part))
                (is (null (gr8s.store::store-generation-stat path))))
              (dolist (path (list unsafe linked symbolic unknown protected))
                (is (not (null (gr8s.store::store-generation-stat path)))))
              (is (equal "scratch" (uiop:read-file-string protected)))
              ;; The same entry point cannot reap a running member's live files.
              (gr8s.security::write-private-text-exclusively part "live")
              (let ((member (gr8s.ha::ha-control-plane-member ha)))
                (bt:with-lock-held ((gr8s.raft.transport::raft-member-lock member))
                  (signals error (gr8s.resources::reap-store-snapshot-startup-temporaries-unlocked member store))))
              (is (not (null (probe-file part))))
              (gr8s.ha::stop-ha-control-plane ha)
              (setf ha nil)))
        (when ha (gr8s.ha::stop-ha-control-plane ha))))))

(test after-recovery-hook-runs-before-listener-and-failure-releases-wal
  (with-temporary-store (store root)
    (declare (ignore store))
    (let ((path (merge-pathnames "hook.log" root)) (called nil))
      (signals error
        (gr8s.raft.transport::start-raft-member "hook" :storage-path path
          :after-recovery-fn
          (lambda (member)
            (setf called t)
            (is (sb-thread:holding-mutex-p (gr8s.raft.transport::raft-member-lock member)))
            (is (null (gr8s.raft.transport::raft-member-grpc-server member)))
            (is (not (gr8s.raft.transport::raft-member-running member)))
            (is (not (null (gr8s.raft.transport::raft-member-owned-storage member))))
            (error "Injected pre-listener cleanup failure"))))
      (is (eq t called))
      (let ((storage (cl-raft::open-file-raft-storage path)))
        (cl-raft::close-file-raft-storage storage)))))

(test external-api-covers-in-cluster-endpoint-picks-one-listener-on-6443
  "podster-o2h: the dedicated in-cluster apiserver listener is started only when the
   external control-plane listener does not already serve the in-cluster endpoint, so
   a default single-host `gr8s serve` no longer binds 0.0.0.0:6443 twice."
  ;; Default serve: external 0.0.0.0:6443 already covers the in-cluster 6443 endpoint.
  (is-true (gr8s.server::external-api-covers-in-cluster-endpoint-p
            "0.0.0.0" 6443 "10.0.0.5" 6443))
  (is-true (gr8s.server::external-api-covers-in-cluster-endpoint-p
            "::" 6443 "10.0.0.5" 6443))
  ;; External bound to exactly the advertised address on the same port -> covered.
  (is-true (gr8s.server::external-api-covers-in-cluster-endpoint-p
            "10.0.0.5" 6443 "10.0.0.5" 6443))
  ;; The documented workaround (--port 16443) moves the external API off 6443, so the
  ;; dedicated in-cluster listener is still needed and no longer collides.
  (is-false (gr8s.server::external-api-covers-in-cluster-endpoint-p
             "0.0.0.0" 16443 "10.0.0.5" 6443))
  ;; External bound to a specific non-advertised address -> not covered, keep both.
  (is-false (gr8s.server::external-api-covers-in-cluster-endpoint-p
             "10.0.0.9" 6443 "10.0.0.5" 6443))
  ;; An unset external port never counts as covering the endpoint.
  (is-false (gr8s.server::external-api-covers-in-cluster-endpoint-p
             "0.0.0.0" nil "10.0.0.5" 6443)))

(test serve-requires-root-fails-fast-with-an-actionable-message
  "A privileged (managed-containerd) serve/agent must refuse a non-root euid up
front with one clear line, rather than failing deep in startup (podster-983-adjacent)."
  ;; Root passes.
  (is-true (gr8s.server::ensure-running-as-root :command "serve" :euid 0))
  ;; A non-root euid raises the clean runtime-error with an actionable message.
  (let ((condition (handler-case
                       (progn (gr8s.server::ensure-running-as-root :command "serve" :euid 1000) nil)
                     (gr8s.server::runtime-error (c) c))))
    (is (not (null condition)) "non-root serve signalled runtime-error")
    (let ((message (gr8s.runtime:runtime-error-message condition)))
      (is (search "must run as root" message))
      (is (search "1000" message))
      (is (search "--disable-agent" message))))
  ;; The agent variant omits the serve-only --disable-agent hint.
  (let ((message (handler-case
                     (progn (gr8s.server::ensure-running-as-root :command "agent" :euid 1000) "")
                   (gr8s.server::runtime-error (c) (gr8s.runtime:runtime-error-message c)))))
    (is (search "gr8s agent must run as root" message))
    (is (not (search "--disable-agent" message)))))
