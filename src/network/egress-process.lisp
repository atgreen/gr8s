;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Which program opened a connection the node egress proxy received (podster-wv1w.13),
;;;; so a policy can say not just where a sandbox may go but what in it may go there:
;;;; gh may reach api.github.com, curl may not.
;;;;
;;;; The proxy knows the client's address and port. In the client's network namespace,
;;;; as /proc/PID/net/tcp shows it to any process of the Pod, that pair names one
;;;; socket inode; among the Pod's processes (its containers' cgroup.procs) the one
;;;; holding socket:[inode] opened it, and /proc/PID/exe names its program. Its parents
;;;; within the Pod are kept too: a rule may name an interpreter or a launcher, and a
;;;; script runs as its interpreter. Everything is read from PROC-ROOT, so tests use a
;;;; tree of their own. A lookup that finds nothing returns NIL, which a rule that
;;;; needs a program treats as no match.

(in-package #:gr8s.network)

(defun proc-net-tcp-address (address port)
  "ADDRESS:PORT as /proc/net/tcp writes a local address: the IPv4 address as the
host-order 32-bit word of its network-order bytes, then the port, in upper-case hex."
  (let ((octets (ipv4-network-octets address)))
    (format nil "~2,'0X~2,'0X~2,'0X~2,'0X:~4,'0X"
            (aref octets 3) (aref octets 2) (aref octets 1) (aref octets 0) port)))

(defun proc-net-tcp-inode (text address port)
  "The inode of the socket TEXT (a /proc/net/tcp) lists with local ADDRESS:PORT, or NIL."
  (let ((local (proc-net-tcp-address address port)))
    (dolist (line (rest (uiop:split-string text :separator '(#\Newline))))
      (let ((fields (remove "" (uiop:split-string line :separator '(#\Space #\Tab)) :test #'equal)))
        (when (and (>= (length fields) 10) (string-equal local (second fields)))
          (let ((inode (parse-integer (nth 9 fields) :junk-allowed t)))
            (when (and inode (plusp inode)) (return inode))))))))

(defun %proc-path (proc-root pid &rest parts)
  (format nil "~A~D/~{~A~^/~}" proc-root pid parts))

(defun %readlink (path)
  (ignore-errors (sb-posix:readlink path)))

(defun %directory-names (path)
  "The entries of directory PATH by name, without . and ..; NIL when it can't be read.
Read with readdir: a socket fd is a link to nothing a pathname can name, which
DIRECTORY leaves out."
  (let ((directory (ignore-errors (sb-posix:opendir path))))
    (when directory
      (unwind-protect
           (loop for entry = (sb-posix:readdir directory)
                 until (sb-alien:null-alien entry)
                 for name = (sb-posix:dirent-name entry)
                 unless (member name '("." "..") :test #'equal) collect name)
        (sb-posix:closedir directory)))))

(defun process-holding-socket (pids inode &key (proc-root "/proc/"))
  "The first of PIDS with a file descriptor on socket INODE, or NIL."
  (let ((target (format nil "socket:[~D]" inode)))
    (dolist (pid pids)
      (dolist (fd (%directory-names (%proc-path proc-root pid "fd")))
        (when (equal target (%readlink (%proc-path proc-root pid "fd" fd)))
          (return-from process-holding-socket pid))))))

(defun process-parent (pid &key (proc-root "/proc/"))
  "PID's parent, from /proc/PID/stat (whose second field may hold spaces), or NIL."
  (let* ((stat (ignore-errors (uiop:read-file-string (%proc-path proc-root pid "stat"))))
         (close (and stat (position #\) stat :from-end t))))
    (when close
      (let ((fields (uiop:split-string (string-trim " " (subseq stat (1+ close))) :separator " ")))
        (and (second fields) (parse-integer (second fields) :junk-allowed t))))))

(defun process-executables (pid pids &key (proc-root "/proc/"))
  "PID's program and those of its parents while they are among PIDS, nearest first."
  (loop for current = pid then (process-parent current :proc-root proc-root)
        while (and current (member current pids))
        for exe = (%readlink (%proc-path proc-root current "exe"))
        when exe collect (if (and (> (length exe) 10) (string= " (deleted)" exe :start2 (- (length exe) 10)))
                             (subseq exe 0 (- (length exe) 10))
                             exe)))

(defun connection-executables (pids address port &key (proc-root "/proc/"))
  "The programs, nearest first, of the process among PIDS (one Pod's) whose socket has
local ADDRESS:PORT, or NIL when none is found."
  (let ((inode (loop for pid in pids
                     for text = (ignore-errors (uiop:read-file-string (%proc-path proc-root pid "net/tcp")))
                     thereis (and text (proc-net-tcp-inode text address port)))))
    (when inode
      (let ((holder (process-holding-socket pids inode :proc-root proc-root)))
        (and holder (process-executables holder pids :proc-root proc-root))))))

(defun executable-pattern-matches-p (pattern path)
  "True when PATH matches PATTERN: an absolute path where * stands for any characters
within one path segment and ** for any across segments."
  (let ((regex (with-output-to-string (out)
                 (write-char #\^ out)
                 (loop with i = 0
                       while (< i (length pattern))
                       do (let ((c (char pattern i)))
                            (cond ((and (char= c #\*) (< (1+ i) (length pattern)) (char= #\* (char pattern (1+ i))))
                                   (write-string ".*" out) (incf i))
                                  ((char= c #\*) (write-string "[^/]*" out))
                                  (t (write-string (cl-ppcre:quote-meta-chars (string c)) out))))
                          (incf i))
                 (write-char #\$ out))))
    (and (stringp path) (cl-ppcre:scan regex path) t)))

(defun gr8-sandbox-binary-verdict (pod sandbox-profiles host executables
                                   &optional (namespace-labels (make-hash-table :test #'equal)))
  "Whether gr8 sandbox POD's connection to HOST, opened by EXECUTABLES (nearest first),
is allowed by its SandboxProfile's spec.egress.binaries (podster-wv1w.13). Returns
(values allowed-p reason): T when no entry names HOST, or when one does and lists a
pattern one of EXECUTABLES matches; else NIL with why. Policy still decides first:
this only narrows what it allows."
  (let* ((profile (gr8-sandbox-profile pod sandbox-profiles namespace-labels))
         (egress (and profile (gethash "egress" (gethash "spec" profile (core-object)))))
         (entries (and (hash-table-p egress)
                       (remove-if-not (lambda (entry)
                                        (some (lambda (pattern) (egress-domain-matches-p pattern host))
                                              (coerce (gethash "hosts" entry #()) 'list)))
                                      (coerce (gethash "binaries" egress #()) 'list)))))
    (cond ((null entries) t)
          ((some (lambda (entry)
                   (some (lambda (pattern) (some (lambda (exe) (executable-pattern-matches-p pattern exe)) executables))
                         (coerce (gethash "paths" entry #()) 'list)))
                 entries)
           t)
          (t (values nil (format nil "~A may be reached only by ~{~A~^, ~}~:[, and the connecting program is unknown~;, not ~:*~{~A~^ under ~}~]"
                                 host
                                 (remove-duplicates (loop for entry in entries
                                                          append (coerce (gethash "paths" entry #()) 'list))
                                                    :test #'equal)
                                 executables))))))
