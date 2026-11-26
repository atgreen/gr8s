;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Prove binary-scoped egress (podster-wv1w.13): the program behind a proxied
;;;; connection is found from the Pod's /proc (its socket by the client's address, the
;;;; process holding it, that program and its parents), a SandboxProfile's
;;;; egress.binaries narrows a host to the programs it lists, and the proxy refuses or,
;;;; under Audit, reports the rest.

(in-package #:gr8s/tests)
(def-suite egress-process :in gr8s)
(in-suite egress-process)

(defun ep-fake-proc (processes)
  "A /proc tree under a fresh directory. PROCESSES lists (pid ppid exe sockets), SOCKETS
the inodes its fds hold. The first process's net/tcp lists every socket, the client's
at 10.80.32.7:39352 with the first inode. Returns the root, ending in /."
  (let ((root (namestring (uiop:ensure-directory-pathname
                           (sb-posix:mkdtemp (namestring (merge-pathnames "gr8s-proc-XXXXXX" (uiop:temporary-directory))))))))
    (loop for (pid ppid exe sockets) in processes
          for directory = (format nil "~A~D/" root pid)
          do (ensure-directories-exist (format nil "~Afd/" directory))
             (with-open-file (out (format nil "~Astat" directory) :direction :output)
               (format out "~D (a name) S ~D 1 1 0 -1~%" pid ppid))
             (sb-posix:symlink exe (format nil "~Aexe" directory))
             (loop for inode in sockets for fd from 3
                   do (sb-posix:symlink (format nil "socket:[~D]" inode) (format nil "~Afd/~D" directory fd))))
    (ensure-directories-exist (format nil "~A~D/net/" root (first (first processes))))
    (with-open-file (out (format nil "~A~D/net/tcp" root (first (first processes))) :direction :output)
      (format out "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode~%")
      (format out "   0: 00000000:7530 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 111 1 0 100 0 0 10 0~%")
      (format out "   1: ~A 010012C6:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 ~D 1 0 100 0 0 10 0~%"
              (gr8s.network::proc-net-tcp-address "10.80.32.7" 39352) (first (fourth (car (last processes))))))
    root))

(test ep-the-program-behind-a-connection-and-its-parents
  (is (equal "0720500A:99B8" (gr8s.network::proc-net-tcp-address "10.80.32.7" 39352)))
  ;; hold (1) runs the launcher (20), which runs a shell (30), which runs git (40):
  ;; git's socket, so git, then the shell, launcher and hold, and nothing outside the Pod.
  (let ((root (ep-fake-proc '((1 0 "/host/usr/bin/gr8" ()) (20 1 "/usr/bin/gr8" ())
                              (30 20 "/usr/bin/bash" (555)) (40 30 "/usr/bin/git (deleted)" (777))))))
    (unwind-protect
         (progn
           (is (= 777 (gr8s.network::proc-net-tcp-inode
                       (uiop:read-file-string (format nil "~A1/net/tcp" root)) "10.80.32.7" 39352)))
           (is (= 40 (gr8s.network::process-holding-socket '(1 20 30 40) 777 :proc-root root)))
           (is (equal '("/usr/bin/git" "/usr/bin/bash" "/usr/bin/gr8" "/host/usr/bin/gr8")
                      (gr8s.network::connection-executables '(20 30 40 1) "10.80.32.7" 39352 :proc-root root)))
           ;; Outside the Pod's processes, the chain stops.
           (is (equal '("/usr/bin/git" "/usr/bin/bash")
                      (gr8s.network::connection-executables '(30 40 1) "10.80.32.7" 39352 :proc-root root)))
           (is (null (gr8s.network::connection-executables '(30 40 1) "10.80.32.7" 1 :proc-root root))))
      (uiop:delete-directory-tree (uiop:ensure-directory-pathname root) :validate t))))

(test ep-executable-patterns
  (is-true (gr8s.network::executable-pattern-matches-p "/usr/bin/gh" "/usr/bin/gh"))
  (is-false (gr8s.network::executable-pattern-matches-p "/usr/bin/gh" "/usr/bin/ghx"))
  (is-true (gr8s.network::executable-pattern-matches-p "/usr/bin/python3*" "/usr/bin/python3.12"))
  (is-false (gr8s.network::executable-pattern-matches-p "/usr/*/gh" "/usr/local/bin/gh"))
  (is-true (gr8s.network::executable-pattern-matches-p "/home/**/node" "/home/u/.nvm/versions/v22/bin/node"))
  (is-false (gr8s.network::executable-pattern-matches-p "/usr/bin/g.h" "/usr/bin/gxh")))

(defun ep-profile (binaries &optional (enforcement "Enforce"))
  (com.inuoe.jzon:parse
   (format nil "{\"apiVersion\":\"gr8.gr8s.io/v1alpha1\",\"kind\":\"SandboxProfile\",\"metadata\":{\"name\":\"claude\"},
                 \"spec\":{\"commands\":[\"claude\"],\"egress\":{\"enforcement\":~S,\"binaries\":~A}}}" enforcement binaries)))

(test ep-a-profile-narrows-a-host-to-its-programs
  (let ((pod (gr8s.network::make-np-pod :name "gr8-claude-x" :namespace "gr8"
                                        :labels (gr8s.network::np-labels "gr8s.io/gr8-command" "claude")))
        (profiles (list (ep-profile "[{\"hosts\":[\"api.github.com\"],\"paths\":[\"/usr/bin/gh\",\"/usr/bin/git\"]}]"))))
    (flet ((verdict (host executables)
             (multiple-value-list (gr8s.network::gr8-sandbox-binary-verdict pod profiles host executables))))
      (is (equal '(t) (verdict "api.github.com" '("/usr/bin/gh"))))
      ;; A parent counts: git run from a script, or gh from claude.
      (is (equal '(t) (verdict "api.github.com" '("/usr/bin/bash" "/usr/bin/git"))))
      (is (equal '(nil "api.github.com may be reached only by /usr/bin/gh, /usr/bin/git, not /usr/bin/curl under /usr/bin/bash")
                 (verdict "api.github.com" '("/usr/bin/curl" "/usr/bin/bash"))))
      (is (null (first (verdict "api.github.com" '()))))
      ;; Hosts no entry names are left to policy.
      (is (equal '(t) (verdict "example.com" '("/usr/bin/curl")))))
    (is (eq :audit (gr8s.network::gr8-sandbox-enforcement pod (list (ep-profile "[]" "Audit")))))
    (is (eq :enforce (gr8s.network::gr8-sandbox-enforcement pod '())))))

(test ep-binaries-are-validated
  (flet ((normalize (binaries)
           (gr8s.resources::normalize-core-resource "sandboxprofiles" (ep-profile binaries) nil "claude" nil)))
    (is (normalize "[{\"hosts\":[\"*.github.com\"],\"paths\":[\"/usr/bin/**\"]}]"))
    (dolist (bad '("{}" "[{\"hosts\":[\"api.github.com\"]}]" "[{\"hosts\":[\"x\"],\"paths\":[\"gh\"]}]"
                   "[{\"hosts\":[\"https://x\"],\"paths\":[\"/gh\"]}]" "[{\"hosts\":[\"x\"],\"paths\":[\"/gh\"],\"binary\":1}]"))
      (signals gr8s.resources::kubernetes-error (normalize bad)))))

(test ep-the-proxy-refuses-a-program-a-rule-doesnt-list-or-reports-it-under-audit
  (multiple-value-bind (stop backend) (l4-start-tag-backend "UP")
    (unwind-protect
         (dolist (case '((:enforce "" nil) (:audit "UP" t)))
           (destructuring-bind (enforcement expected allowed) case
             (let* ((reports '())
                    (table (gr8s.network::make-egress-name-table
                            :resolve (lambda (name) (declare (ignore name)) (values '("203.0.113.5") 30 0))))
                    (proxy (gr8s.controllers::start-egress-proxy
                            :decide (lambda (peer host address port) (declare (ignore peer host address port)) (values t "rule"))
                            :connect (lambda (address port) (declare (ignore address port))
                                       (gr8s.controllers::egress-default-connect "127.0.0.1" backend))
                            :binaries (lambda (peer peer-port host)
                                        (declare (ignore peer))
                                        (values nil (format nil "~A only for gh" host)
                                                (list (format nil "/usr/bin/curl:~:[none~;port~]" peer-port))
                                                enforcement))
                            :report (lambda (peer host address port allowed rule &optional program audit)
                                      (declare (ignore peer address port))
                                      (push (list host allowed rule program audit) reports))
                            :names table
                            :dialed (let ((address (gr8s.network::egress-name-answer table "db.example.com")))
                                      (lambda (socket) (declare (ignore socket)) (values address 6379))))))
               (unwind-protect
                    (is (equal expected (l4-client-read-tag (gr8s.controllers::egress-proxy-port proxy))))
                 (gr8s.controllers::stop-egress-proxy proxy))
               (sleep 0.1)
               (let ((report (first reports)))
                 (is (eq allowed (second report)))
                 (is (equal "/usr/bin/curl:port" (fourth report)))
                 (if allowed
                     (is (equal "db.example.com only for gh" (fifth report)))
                     (is (equal "db.example.com only for gh" (third report))))))))
      (funcall stop))))

(test ep-a-gr8-sandboxs-programs-are-named-as-it-sees-them
  (is (equal "/usr/bin/curl" (gr8s.agent::gr8-sandbox-program-path "/host/usr/bin/curl")))
  (is (equal "/usr/bin/curl" (gr8s.agent::gr8-sandbox-program-path "/usr/bin/curl")))
  (is (equal "/hostname" (gr8s.agent::gr8-sandbox-program-path "/hostname"))))
