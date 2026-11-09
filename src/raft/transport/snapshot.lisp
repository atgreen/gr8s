;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;; File-backed, bounded RPC transfer for immutable Raft snapshot envelopes.
(in-package #:gr8s.raft.transport)

(defconstant +raft-snapshot-chunk-bytes+ 65536)
(defstruct raft-snapshot-receiver from term index last-term token digest total path stream (offset 0)
  (activity (get-internal-real-time)))

(defparameter *raft-snapshot-root-prefix* ".raft-transfer-v2-")

(defun raft-snapshot-map-directory (directory function)
  "Read literal names without resolving symlinks or traversing child directories."
  (let ((handle (sb-posix:opendir (namestring directory))))
    (unwind-protect
         (loop for entry = (sb-posix:readdir handle) until (sb-alien:null-alien entry)
               for name = (sb-posix:dirent-name entry)
               unless (member name '("." "..") :test #'string=) do (funcall function name))
      (sb-posix:closedir handle))))

(defun raft-snapshot-directory-names (directory)
  (let ((names nil))
    (raft-snapshot-map-directory directory (lambda (name) (push name names)))
    (nreverse names)))

(defun raft-snapshot-private-stat-p (stat directory-p)
  (and (= (sb-posix:stat-uid stat) (sb-posix:geteuid))
       (= (logand #o777 (sb-posix:stat-mode stat)) (if directory-p #o700 #o600))
       (if directory-p (sb-posix:s-isdir (sb-posix:stat-mode stat))
           (and (sb-posix:s-isreg (sb-posix:stat-mode stat)) (= 1 (sb-posix:stat-nlink stat))))))

(defun raft-snapshot-close-on-exec (fd)
  (unless (zerop (cffi:foreign-funcall "fcntl" :int fd :int 2 :int 1 :int)) ; F_SETFD, FD_CLOEXEC
    (error "Cannot protect snapshot ownership descriptor across exec")))

(defun raft-snapshot-flock (fd &optional nonblocking)
  (zerop (cffi:foreign-funcall "flock" :int fd :int (if nonblocking 6 2) :int))) ; LOCK_EX [| LOCK_NB]

(defun raft-snapshot-with-base-lock (base function)
  "Serialize root creation/reaping without creating a shared lock file in /tmp."
  (let ((fd (sb-posix:open (string-right-trim "/" (namestring base))
                           (logior sb-posix:o-rdonly sb-posix:o-directory sb-posix:o-nofollow) 0)))
    (unwind-protect
         (progn
           (raft-snapshot-close-on-exec fd)
           (unless (raft-snapshot-private-stat-p (sb-posix:fstat fd) t)
             (error "Snapshot transfer namespace is not private to this user"))
           (unless (raft-snapshot-flock fd) (error "Cannot lock snapshot transfer directory"))
           (funcall function))
      (sb-posix:close fd))))

(defun raft-snapshot-remove-owned-root (root)
  "Remove only our flat scratch format. Caller owns its lifetime lock and base lock.
Unknown files, directories, symlinks, hard links or permissions preserve the root."
  (when (raft-snapshot-private-stat-p (sb-posix:lstat (string-right-trim "/" (namestring root))) t)
    (let ((names (raft-snapshot-directory-names root)))
      (when (every (lambda (name)
                     (and (or (string= name ".owner")
                              (and (or (uiop:string-prefix-p "in-" name) (uiop:string-prefix-p "out-" name))
                                   (uiop:string-suffix-p name ".snapshot")))
                          (raft-snapshot-private-stat-p (sb-posix:lstat (namestring (merge-pathnames name root))) nil)))
                   names)
        (dolist (name (remove ".owner" names :test #'string=))
          (sb-posix:unlink (namestring (merge-pathnames name root))))
        (when (member ".owner" names :test #'string=)
          (sb-posix:unlink (namestring (merge-pathnames ".owner" root))))
        (sb-posix:rmdir (namestring root))
        t))))

(defun raft-snapshot-reap-root (root)
  (handler-case
      (let ((stat (sb-posix:lstat (string-right-trim "/" (namestring root)))))
        (when (raft-snapshot-private-stat-p stat t)
          (let ((names (raft-snapshot-directory-names root)))
            (cond
              ;; A creator killed before installing .owner cannot have written
              ;; payload. The base lock excludes every live v2 root creator.
              ((null names) (sb-posix:rmdir (namestring root)) t)
              ((and (member ".owner" names :test #'string=)
                    (raft-snapshot-private-stat-p (sb-posix:lstat (namestring (merge-pathnames ".owner" root))) nil))
               (let ((fd (sb-posix:open (namestring (merge-pathnames ".owner" root))
                                         (logior sb-posix:o-rdwr sb-posix:o-nofollow) 0)))
                 (unwind-protect
                      (when (and (raft-snapshot-private-stat-p (sb-posix:fstat fd) nil)
                                 (raft-snapshot-flock fd t))
                        (raft-snapshot-remove-owned-root root))
                   (sb-posix:close fd))))))))
    (sb-posix:syscall-error () nil)))

(defun raft-snapshot-reap-orphans-unlocked (base)
  "Caller holds the base lock. Live roots stay protected even in the same PID."
  (let ((count 0))
    (raft-snapshot-map-directory
     base (lambda (name)
            (when (and (uiop:string-prefix-p *raft-snapshot-root-prefix* name)
                       (= (length name) (+ (length *raft-snapshot-root-prefix*) 6))
                       (every #'alphanumericp (subseq name (length *raft-snapshot-root-prefix*)))
                       (raft-snapshot-reap-root (uiop:ensure-directory-pathname (merge-pathnames name base))))
              (incf count))))
    count))

(defun raft-snapshot-private-base (directory)
  "Use a private per-user namespace even when DIRECTORY is a shared temporary directory."
  (let ((base (merge-pathnames (format nil ".gr8s-raft-transfers-v2-~D/" (sb-posix:geteuid)) directory)))
    (handler-case (sb-posix:mkdir (namestring base) #o700)
      (sb-posix:syscall-error (condition)
        (unless (= sb-posix:eexist (sb-posix:syscall-errno condition)) (error condition))))
    (unless (raft-snapshot-private-stat-p (sb-posix:lstat (string-right-trim "/" (namestring base))) t)
      (error "Snapshot transfer namespace is not a private owned directory"))
    base))

(defun raft-member-snapshot-base (member)
  (let ((storage (raft-node-storage (raft-member-node member))))
    (uiop:ensure-directory-pathname
     (or (raft-member-snapshot-directory member)
         (when (typep storage 'file-raft-storage)
           (uiop:pathname-directory-pathname (merge-pathnames (file-raft-storage-path storage))))
         (uiop:temporary-directory)))))

(defun raft-reap-snapshot-directory (directory)
  "Reclaim abandoned scratch before startup needs to write credentials or the store."
  (ensure-directories-exist directory)
  (let ((base (raft-snapshot-private-base directory)))
    (raft-snapshot-with-base-lock base (lambda () (raft-snapshot-reap-orphans-unlocked base)))))

(defun raft-member-reap-snapshot-orphans (member)
  (raft-reap-snapshot-directory (raft-member-snapshot-base member)))

(defun raft-member-snapshot-root-unlocked (member)
  (or (raft-member-snapshot-root member)
      (let ((base (raft-member-snapshot-base member)))
        (ensure-directories-exist base)
        (setf base (raft-snapshot-private-base base))
        (raft-snapshot-with-base-lock
         base (lambda ()
                (raft-snapshot-reap-orphans-unlocked base)
                (let ((root (uiop:ensure-directory-pathname
                             (sb-posix:mkdtemp (namestring (merge-pathnames
                                                           (concatenate 'string *raft-snapshot-root-prefix* "XXXXXX") base)))))
                      (fd nil) (complete nil))
                  (unwind-protect
                       (progn
                         (setf fd (sb-posix:open (namestring (merge-pathnames ".owner" root))
                                                (logior sb-posix:o-rdwr sb-posix:o-creat sb-posix:o-excl sb-posix:o-nofollow) #o600))
                         (raft-snapshot-close-on-exec fd)
                         (unless (raft-snapshot-flock fd) (error "Cannot own snapshot transfer root"))
                         (sb-sys:without-interrupts
                           (setf (raft-member-snapshot-root member) root
                                 (raft-member-snapshot-owner-fd member) fd complete t))
                         root)
                    (unless complete
                      (when fd (ignore-errors (sb-posix:close fd)))
                      (ignore-errors (sb-posix:unlink (namestring (merge-pathnames ".owner" root))))
                      (ignore-errors (sb-posix:rmdir (namestring root)))))))))))

(defun raft-member-close-snapshot-root (member)
  "Keep ownership until deletion finishes, so another member cannot reap live IO."
  (let ((root (raft-member-snapshot-root member)) (fd (raft-member-snapshot-owner-fd member)))
    (unwind-protect
         (progn
           (setf (raft-member-snapshot-root member) nil (raft-member-snapshot-owner-fd member) nil)
           (when (and root fd)
             (raft-snapshot-with-base-lock (uiop:pathname-parent-directory-pathname root)
                                          (lambda () (raft-snapshot-remove-owned-root root)))))
      (when fd (sb-posix:close fd)))))

(defun raft-snapshot-new-path (member prefix)
  (merge-pathnames (format nil "~A-~A.snapshot" prefix (gr8s::generate-uid))
                   (raft-member-snapshot-root-unlocked member)))

(defun raft-snapshot-create-file (path)
  (sb-posix:close (sb-posix:open (namestring path)
                                (logior sb-posix:o-wronly sb-posix:o-creat sb-posix:o-excl) #o600)))

(defun raft-snapshot-file-digest (path)
  (let ((hash (ironclad:make-digest :sha256))
        (buffer (make-array +raft-snapshot-chunk-bytes+ :element-type '(unsigned-byte 8))))
    (with-open-file (stream path :element-type '(unsigned-byte 8))
      (loop for count = (read-sequence buffer stream) while (plusp count)
            do (ironclad:update-digest hash buffer :end count)))
    (ironclad:byte-array-to-hex-string (ironclad:produce-digest hash))))

(defun raft-link-deliver-message (stub message)
  (gr8s.node.v1::raft-transport-deliver
   stub (make-instance 'gr8s.node.v1::raft-envelope
                       :protocol-version 1 :payload (raft-message->octets message)) :timeout 2))

(defun raft-link-send-snapshot (member stub message)
  "Serialize to a private file and send at most 64 KiB of file data per RPC.
The immutable application snapshot is provided by the core; no complete wire
string or byte vector is constructed. The normal peer retry restarts a failed transfer."
  (let ((path (bt:with-lock-held ((raft-member-lock member)) (raft-snapshot-new-path member "out")))
        (created nil))
    (unwind-protect
         (progn
           (raft-snapshot-create-file path)
           (setf created t)
           (with-open-file (stream path :direction :output :if-exists :overwrite :external-format :utf-8)
             (with-standard-io-syntax
               (let ((*print-pretty* nil) (*print-circle* nil) (*read-eval* nil))
                 (prin1 message stream))))
           (let ((digest (raft-snapshot-file-digest path)) (token (gr8s::generate-uid)))
             (with-open-file (stream path :element-type '(unsigned-byte 8))
               (let ((total (file-length stream)) (offset 0)
                     (buffer (make-array +raft-snapshot-chunk-bytes+ :element-type '(unsigned-byte 8))))
                 (when (> total (raft-member-snapshot-max-bytes member)) (error "Snapshot exceeds transfer limit"))
                 (loop for count = (read-sequence buffer stream) while (plusp count) do
                   (unless (raft-member-running member) (error "Snapshot sender stopped"))
                   (raft-link-deliver-message
                    stub (list :type :snapshot-chunk :term (getf message :term) :from (getf message :from)
                               :last-index (getf message :last-index) :last-term (getf message :last-term)
                               :token token :digest digest :total total :offset offset
                               :data (if (= count (length buffer)) buffer (subseq buffer 0 count))
                               :done (= (+ offset count) total)))
                   (incf offset count))))))
      (when (and created (probe-file path)) (delete-file path)))))

(defun raft-member-expire-snapshot-receiver (member)
  (let ((receiver (raft-member-snapshot-receiver member)))
    (when (and receiver (> (- (get-internal-real-time) (raft-snapshot-receiver-activity receiver))
                          (* 60 internal-time-units-per-second)))
      (raft-member-clear-snapshot-receiver member))))

(defun raft-member-clear-snapshot-receiver (member)
  (let ((receiver (raft-member-snapshot-receiver member)))
    (setf (raft-member-snapshot-receiver member) nil)
    (when receiver
      (when (raft-snapshot-receiver-stream receiver)
        (ignore-errors (close (raft-snapshot-receiver-stream receiver) :abort t)))
      (when (probe-file (raft-snapshot-receiver-path receiver))
        (delete-file (raft-snapshot-receiver-path receiver))))))

(defun raft-snapshot-chunk-matches-p (receiver message)
  (and (equal (raft-snapshot-receiver-from receiver) (getf message :from))
       (= (raft-snapshot-receiver-term receiver) (getf message :term))
       (= (raft-snapshot-receiver-index receiver) (getf message :last-index))
       (= (raft-snapshot-receiver-last-term receiver) (getf message :last-term))
       (equal (raft-snapshot-receiver-token receiver) (getf message :token))
       (equal (raft-snapshot-receiver-digest receiver) (getf message :digest))
       (= (raft-snapshot-receiver-total receiver) (getf message :total))))

(defun raft-member-complete-snapshot (member receiver)
  (let ((path (raft-snapshot-receiver-path receiver)))
    (finish-output (raft-snapshot-receiver-stream receiver))
    (close (raft-snapshot-receiver-stream receiver))
    (setf (raft-snapshot-receiver-stream receiver) nil)
    (unless (equal (raft-snapshot-receiver-digest receiver) (raft-snapshot-file-digest path))
      (error "Snapshot transfer checksum mismatch"))
    ;; Application callbacks currently receive their opaque Lisp snapshot. A
    ;; production large-store callback must use a streamed artifact descriptor;
    ;; chunking the wire alone does not bound application reconstruction memory.
    (let ((message
            (with-open-file (stream path :external-format :utf-8)
              (with-standard-io-syntax
                (let* ((*read-eval* nil) (message (read stream nil :eof)))
                  (unless (eq :eof (read stream nil :eof)) (error "Trailing snapshot data"))
                  message)))))
      (unless (and (eq :install-snapshot (getf message :type))
                   (equal (raft-snapshot-receiver-from receiver) (getf message :from))
                   (= (raft-snapshot-receiver-term receiver) (getf message :term))
                   (= (raft-snapshot-receiver-index receiver) (getf message :last-index))
                   (= (raft-snapshot-receiver-last-term receiver) (getf message :last-term)))
        (error "Snapshot header differs from transfer identity"))
      (raft-handle-message (raft-member-node member) message))))

(defun raft-member-receive-snapshot-chunk (member message)
  "Handle one authenticated chunk while holding MEMBER's lock. One partial file
is retained per member; a fresh transfer replaces it. Core installation persists
the complete snapshot and suffix before acknowledging its applied boundary."
  (unless (raft-member-running member) (error "Snapshot receiver stopped"))
  (let* ((node (raft-member-node member)) (from (getf message :from)) (term (getf message :term))
         (index (getf message :last-index)) (last-term (getf message :last-term))
         (offset (getf message :offset)) (total (getf message :total)) (data (getf message :data))
         (token (getf message :token)) (digest (getf message :digest)))
    (unless (and (stringp from) (typep term '(integer 0 *)) (typep index '(integer 1 *))
                 (typep last-term '(integer 0 *)) (<= last-term term) (typep offset '(integer 0 *))
                 (typep total '(integer 1 *)) (<= total (raft-member-snapshot-max-bytes member))
                 (vectorp data) (not (stringp data)) (<= 1 (length data) +raft-snapshot-chunk-bytes+)
                 (every (lambda (byte) (typep byte '(unsigned-byte 8))) data)
                 (<= (+ offset (length data)) total)
                 (eq (not (null (getf message :done))) (= (+ offset (length data)) total))
                 (stringp token) (<= 1 (length token) 128) (stringp digest) (= 64 (length digest)))
      (error "Invalid snapshot chunk"))
    (raft-step-down-if-stale node term)
    (when (< term (raft-node-current-term node))
      (raft-send node from (list :type :install-snapshot-reply :term (raft-node-current-term node)
                                :from (raft-node-id node) :success nil :match-index 0))
      (error "Stale snapshot sender"))
    (unless (eq :follower (raft-node-role node)) (raft-become-follower node term from))
    (setf (raft-node-leader-id node) from (raft-node-leader-contact-elapsed node) 0)
    (raft-reset-election-timer node)
    (when (raft-node-snapshot-pending node) (gr8s.raft::raft-resume-snapshot-install node))
    (when (<= index (raft-node-commit-index node))
      (raft-send node from (list :type :install-snapshot-reply :term (raft-node-current-term node)
                                :from (raft-node-id node) :success t :match-index index))
      (return-from raft-member-receive-snapshot-chunk nil))
    (when (zerop offset)
      (let ((old (raft-member-snapshot-receiver member)))
        (when (and old (= term (raft-snapshot-receiver-term old))
                   (> (raft-snapshot-receiver-index old) index))
          (error "A newer snapshot transfer is already active")))
      (raft-member-clear-snapshot-receiver member)
      (let ((path (raft-snapshot-new-path member "in")))
        (raft-snapshot-create-file path)
        (setf (raft-member-snapshot-receiver member)
              (make-raft-snapshot-receiver :from from :term term :index index :last-term last-term
                :token token :digest digest :total total :path path
                :stream (open path :direction :output :if-exists :overwrite :element-type '(unsigned-byte 8))))))
    (let ((receiver (raft-member-snapshot-receiver member)))
      (unless (and receiver (raft-snapshot-chunk-matches-p receiver message)
                   (= offset (raft-snapshot-receiver-offset receiver)))
        (error "Snapshot chunk is out of order or belongs to another transfer"))
      (handler-case
          (progn
            (write-sequence (coerce data '(vector (unsigned-byte 8))) (raft-snapshot-receiver-stream receiver))
            (incf (raft-snapshot-receiver-offset receiver) (length data))
            (setf (raft-snapshot-receiver-activity receiver) (get-internal-real-time))
            (when (getf message :done)
              (unwind-protect (raft-member-complete-snapshot member receiver)
                (raft-member-clear-snapshot-receiver member))))
        (error (condition)
          (raft-member-clear-snapshot-receiver member)
          (error condition))))))
