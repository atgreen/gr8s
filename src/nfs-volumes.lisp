;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Mount NFS shares for Pods through mount(2), without mount.nfs on the host.
;;;; A hard mount of an unreachable server can block its caller indefinitely, so
;;;; every call that may touch the server runs on its own thread with a bounded
;;;; wait: one dead server delays its own Pods, never the agent's other work.

(in-package #:gr8s)

(defparameter +nfs-mount-flag-options+
  '(("ro" . 1) ("rw" . 0) ("noexec" . #x8) ("exec" . 0) ("sync" . #x10) ("async" . 0)
    ("noatime" . #x400) ("nodiratime" . #x800) ("relatime" . #x200000) ("nosuid" . 0) ("nodev" . 0))
  "Options mount(8) turns into MS_ flags, which the kernel NFS option parser would reject.
NOSUID and NODEV are always set, so asking for them changes nothing.")

(defparameter +nfs-kernel-options+
  '("hard" "soft" "softerr" "nolock" "lock" "noac" "ac" "cto" "nocto" "noresvport" "resvport"
    "sharecache" "nosharecache" "tcp" "rdma" "fsc" "nofsc")
  "Bare options handed to the kernel NFS client unchanged.")

(defparameter +nfs-kernel-value-options+
  '("timeo" "retrans" "rsize" "wsize" "acregmin" "acregmax" "acdirmin" "acdirmax" "actimeo"
    "sec" "proto" "port" "nconnect" "lookupcache" "local_lock" "minorversion" "max_connect")
  "Options with a value handed to the kernel NFS client unchanged.")

(defparameter +nfs-versions+ '("3" "4" "4.0" "4.1" "4.2"))

(defparameter +nfs-default-version-attempts+ '("4.2" "4.1" "4.0")
  "NFSv4 versions tried in turn when a mount names none, newest first.")

(defun nfs-mount-option-tokens (mount-options)
  "Split MOUNT-OPTIONS entries on commas, as mount(8) would, dropping empty items."
  (loop for entry across (or mount-options #())
        nconc (loop for token in (uiop:split-string entry :separator '(#\,))
                    for trimmed = (string-trim " " token)
                    when (plusp (length trimmed)) collect trimmed)))

(defun nfs-option-name-and-value (token)
  "Return TOKEN's option name and its value, or NIL for a bare option."
  (let ((separator (position #\= token)))
    (if separator
        (values (subseq token 0 separator) (subseq token (1+ separator)))
        (values token nil))))

(defun nfs-mount-option-valid-p (token)
  "Accept only known options whose value cannot smuggle in another option."
  (multiple-value-bind (name value) (nfs-option-name-and-value token)
    (cond ((member name '("vers" "nfsvers") :test #'equal)
           (member value +nfs-versions+ :test #'equal))
          (value (and (member name +nfs-kernel-value-options+ :test #'equal)
                      (plusp (length value))
                      (every (lambda (char) (or (alphanumericp char) (find char "._:-"))) value)))
          (t (or (assoc name +nfs-mount-flag-options+ :test #'equal)
                 (member name +nfs-kernel-options+ :test #'equal))))))

(defun nfs-server-name-valid-p (server)
  "Accept an IPv4 address or host name, which cannot carry mount-option syntax."
  (and (stringp server) (<= 1 (length server) 253)
       (every (lambda (char) (or (alphanumericp char) (find char ".-"))) server)))

(defun validate-nfs-source (source)
  "Validate an NFS server, exported path and read-only flag from a Pod or PV."
  (require-object source "nfs")
  (unless (nfs-server-name-valid-p (gethash "server" source))
    (core-resource-error 422 "Invalid" "nfs.server must be an IPv4 address or host name"))
  (unless (storage-absolute-path-p (gethash "path" source))
    (core-resource-error 422 "Invalid" "nfs.path must be absolute without traversal"))
  (multiple-value-bind (value present) (gethash "readOnly" source)
    (when (and present (not (member value '(t nil))))
      (core-resource-error 422 "Invalid" "nfs.readOnly must be boolean"))))

(defun validate-nfs-mount-options (mount-options)
  "Reject mount options the agent would not pass safely to the kernel."
  (dolist (token (nfs-mount-option-tokens mount-options))
    (unless (nfs-mount-option-valid-p token)
      (core-resource-error 422 "Invalid" "Unsupported NFS mount option ~S" token))))

(defun nfs-mount-attempts (tokens address)
  "Return (FILESYSTEM-TYPE . DATA) attempts and the MS_ flags for one mount.
NFSv3 defaults to nolock because no rpc.statd is assumed on the host; a mount
that needs NFSv3 locks asks for them with the lock option."
  (let ((flags #x6) (kernel nil) (version nil))
    (dolist (token tokens)
      (multiple-value-bind (name value) (nfs-option-name-and-value token)
        (let ((flag (and (null value) (assoc name +nfs-mount-flag-options+ :test #'equal))))
          (cond (flag (setf flags (logior flags (cdr flag))))
                ((member name '("vers" "nfsvers") :test #'equal) (setf version value))
                (t (push token kernel))))))
    (setf kernel (nreverse kernel))
    (flet ((attempt (vers)
             (let ((three (equal vers "3")))
               (cons (if three "nfs" "nfs4")
                     (format nil "~{~A~^,~}"
                             (append (list (format nil "vers=~A" vers) (format nil "addr=~A" address))
                                     (when (and three (not (intersection '("lock" "nolock") kernel :test #'equal)))
                                       '("nolock"))
                                     kernel))))))
      (values (mapcar #'attempt (if version (list version) +nfs-default-version-attempts+)) flags))))

(define-condition nfs-mount-error (runtime-error)
  ((errno :initarg :errno :reader nfs-mount-error-errno)))

(defun %call-nfs-mount (source target filesystem-type flags data)
  "Call mount(2), returning the errno, or 0 for success."
  (if (zerop (%linux-mount source target filesystem-type flags data)) 0 (sb-alien:get-errno)))

(defun %call-nfs-unmount (target flags)
  "Call umount2(2), returning the errno, or 0 for success."
  (if (zerop (%linux-umount target flags)) 0 (sb-alien:get-errno)))

(defparameter *nfs-mount-call* #'%call-nfs-mount
  "Call mount(2) for NFS, taking the source, target, type, flags and data; returns an errno or 0.")
(defparameter *nfs-unmount-call* #'%call-nfs-unmount
  "Call umount2(2) for NFS, taking the target and flags; returns an errno or 0.")
(defparameter *nfs-address-resolver* nil
  "Resolve an NFS server's name to an IPv4 address; NIL uses the host's resolver.")
(defparameter *nfs-operation-wait-seconds* 5
  "How long a caller waits on one operation before leaving it to finish in the background.")

(defparameter *nfs-operations* (make-hash-table :test #'equal)
  "Background NFS operations by key, so a retry joins a blocked call instead of adding another.")
(defvar *nfs-operations-lock* (bt:make-lock "gr8s NFS operations"))

(defun nfs-server-address (server)
  "Return SERVER's IPv4 address, resolved on the node as a kubelet's mount would."
  (cond (*nfs-address-resolver* (funcall *nfs-address-resolver* server))
        ((cl-ppcre:scan "^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$" server) server)
        (t (format nil "~{~D~^.~}"
                   (coerce (sb-bsd-sockets:host-ent-address (sb-bsd-sockets:get-host-by-name server)) 'list)))))

(defun bounded-nfs-operation (key thunk &key (wait *nfs-operation-wait-seconds*))
  "Run THUNK on its own thread, signalling a retryable error if it outlasts WAIT.
A later call with the same KEY collects the result instead of starting another."
  (let ((thread
          (bt:with-lock-held (*nfs-operations-lock*)
            (or (gethash key *nfs-operations*)
                (setf (gethash key *nfs-operations*)
                      (sb-thread:make-thread
                       (lambda () (handler-case (funcall thunk) (error (condition) condition)))
                       :name "gr8s NFS operation"))))))
    (let ((result (sb-thread:join-thread thread :timeout wait :default :in-progress)))
      (when (eq result :in-progress)
        (error 'runtime-error :message (format nil "NFS operation on ~A is still waiting for its server" key)))
      (bt:with-lock-held (*nfs-operations-lock*)
        (when (eq thread (gethash key *nfs-operations*))
          (remhash key *nfs-operations*)))
      (when (typep result 'condition) (error result))
      result)))

(defun nfs-target-mounted-p (target)
  "Read the kernel's mount table, because stat on a dead server's mount would block."
  (loop for line in (uiop:read-file-lines *pod-mount-table-path*)
        for fields = (uiop:split-string line :separator '(#\Space))
        thereis (and (>= (length fields) 5)
                     (equal (string-right-trim "/" target) (decode-mountinfo-path (nth 4 fields))))))

(defun mount-nfs-filesystem (server path target tokens &key wait)
  "Mount SERVER:PATH at TARGET, trying each allowed version the server may refuse."
  (let* ((source (format nil "~A:~A" server path))
         (mount-call *nfs-mount-call*)
         (address-of (let ((resolver *nfs-address-resolver*))
                       (lambda ()
                         (let ((*nfs-address-resolver* resolver)) (nfs-server-address server)))))
         (code
           (bounded-nfs-operation
            target
            (lambda ()
              (multiple-value-bind (attempts flags) (nfs-mount-attempts tokens (funcall address-of))
                (loop with last = 0
                      for (filesystem-type . data) in attempts
                      do (setf last (funcall mount-call source target filesystem-type flags data))
                      ;; Only a refused version moves on; any other answer is final.
                      until (not (member last (list sb-posix:eprotonosupport sb-posix:einval)))
                      finally (return last))))
            :wait (or wait *nfs-operation-wait-seconds*))))
    (unless (zerop code)
      (error 'nfs-mount-error :errno code
             :message (format nil "Could not mount NFS share ~A: ~A" source (sb-int:strerror code))))))

(defun unmount-nfs-filesystem (target)
  "Unmount TARGET, detaching it when its server no longer answers."
  (let* ((unmount *nfs-unmount-call*)
         (code (handler-case
                   (bounded-nfs-operation (format nil "unmount ~A" target)
                                          (lambda () (funcall unmount target 0)))
                 (runtime-error () :blocked))))
    (unless (eql code 0)
      ;; MNT_FORCE|MNT_DETACH: the Pod is gone, so nothing can still need this mount.
      (let ((forced (funcall unmount target 3)))
        (unless (zerop forced)
          (error 'runtime-error :message (format nil "Could not unmount NFS share at ~A: ~A"
                                                 target (sb-int:strerror forced))))))))

(defun ensure-provisioned-nfs-directory (server share name staging tokens &key wait)
  "Create dynamically provisioned directory NAME in SHARE, mounted briefly at STAGING."
  (let ((target (string-right-trim "/" (namestring staging))))
    (ensure-directories-exist (uiop:ensure-directory-pathname staging))
    (unless (nfs-target-mounted-p target)
      (mount-nfs-filesystem server share target tokens :wait wait))
    (unwind-protect
         (bounded-nfs-operation
          (format nil "mkdir ~A" target)
          (lambda ()
            (let ((path (format nil "~A/~A" target name)))
              (handler-case (sb-posix:mkdir path #o777)
                (sb-posix:syscall-error (condition)
                  (unless (= sb-posix:eexist (sb-posix:syscall-errno condition)) (error condition))))
              ;; The process umask narrows mkdir; workloads run as arbitrary users.
              (sb-posix:chmod path #o777)))
          :wait (or wait *nfs-operation-wait-seconds*))
      (unmount-nfs-filesystem target))
    (ignore-errors (sb-posix:rmdir target))))

(defun safe-delete-volume-tree (path)
  "Delete PATH's tree as root without following links or crossing into another filesystem.
Tenants control these names, so a planted symbolic link must never redirect a deletion."
  (let* ((root (string-right-trim "/" path))
         (root-stat (handler-case (sb-posix:lstat root)
                      (sb-posix:syscall-error (condition)
                        (if (= sb-posix:enoent (sb-posix:syscall-errno condition))
                            (return-from safe-delete-volume-tree nil)
                            (error condition)))))
         (device (sb-posix:stat-dev root-stat)))
    (labels ((directory-p (stat)
               (= sb-posix:s-ifdir (logand (sb-posix:stat-mode stat) sb-posix:s-ifmt)))
             (children (directory)
               (let ((handle (sb-posix:opendir directory)))
                 (unwind-protect
                      (loop for entry = (sb-posix:readdir handle)
                            until (sb-alien:null-alien entry)
                            for name = (sb-posix:dirent-name entry)
                            unless (member name '("." "..") :test #'equal) collect name)
                   (sb-posix:closedir handle))))
             (remove-entry (entry stat)
               (cond ((not (directory-p stat)) (sb-posix:unlink entry))
                     ((/= device (sb-posix:stat-dev stat))
                      (error 'runtime-error :message "Refusing to delete a volume tree across a mount"))
                     (t (dolist (name (children entry))
                          (let ((child (format nil "~A/~A" entry name)))
                            (remove-entry child (sb-posix:lstat child))))
                        (sb-posix:rmdir entry)))))
      (remove-entry root root-stat))))
