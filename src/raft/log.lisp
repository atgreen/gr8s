;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Durable, crash-recoverable persistence for the Raft core (podster-c2d.2).
;;;; Raft must persist currentTerm, votedFor and the log before acting on them,
;;;; or a crashed-then-recovered member can violate safety. This is a Clobber-
;;;; style append-only write-ahead log: each mutation is one readable Lisp record
;;;; flushed (and fsync'd) to a per-member file; recovery replays the records.
;;;; Snapshot records fold a committed prefix into compacted state so the log
;;;; does not grow without bound.
;;;;
;;;; Record forms:
;;;;   (:hard term vote)
;;;;   (:entry index term command)
;;;;   (:truncate index)             ; drop entries at/after INDEX
;;;;   (:snapshot index term state)  ; compaction boundary + state-machine image

(in-package #:gr8s.raft)

(defclass file-raft-storage ()
  ((path :initarg :path :reader file-raft-storage-path)
   (stream :initarg :stream :accessor file-raft-storage-stream)))

(defun open-file-raft-storage (path)
  "Open (creating) an append-only Raft WAL at PATH for continued writes.
It holds replicated state including Secrets, so only its owner may read it."
  (ensure-directories-exist path)
  (let ((fd (sb-posix:open (namestring path) (logior sb-posix:o-wronly sb-posix:o-creat) #o600)))
    (unwind-protect
         (progn
           (sb-posix:fchmod fd #o600)
           (sb-posix:fsync fd))
      (sb-posix:close fd)))
  ;; A fsynced hard-state record is not durable if a newly created WAL's
  ;; directory entry can disappear. Publish that entry before serving peers.
  (let ((fd (sb-posix:open
             (namestring (uiop:pathname-directory-pathname (merge-pathnames path)))
             (logior sb-posix:o-rdonly sb-posix:o-directory) 0)))
    (unwind-protect (sb-posix:fsync fd) (sb-posix:close fd)))
  (make-instance 'file-raft-storage
                 :path path
                 :stream (open path :direction :output :element-type 'character
                                    :if-exists :append :if-does-not-exist :create)))

(defun file-raft-write (storage form)
  "Append FORM to STORAGE's WAL as one compact, single-line record (printer
   specials bound off), then terminate the line, flush, and fsync so a
   committed record survives a crash."
  (let ((stream (file-raft-storage-stream storage))
        (*print-readably* nil) (*print-circle* nil) (*print-pretty* nil))
    (unless (and stream (open-stream-p stream))
      (error "Raft WAL is closed; recover it before writing"))
    (prin1 form stream)
    (terpri stream)
    (finish-output stream)
    (sb-posix:fsync (sb-sys:fd-stream-fd stream))))

(defmethod raft-storage-save-hard-state ((storage file-raft-storage) term vote)
  (file-raft-write storage (list :hard term vote)))

(defmethod raft-storage-append-entry ((storage file-raft-storage) entry)
  (file-raft-write storage (list :entry (raft-entry-index entry)
                                 (raft-entry-term entry) (raft-entry-command entry))))

(defmethod raft-storage-truncate ((storage file-raft-storage) index)
  (file-raft-write storage (list :truncate index)))

(defmethod raft-storage-save-snapshot ((storage file-raft-storage) index term state)
  (file-raft-write storage (list :snapshot index term state)))

(defgeneric file-raft-checkpoint-sync (storage phase fd)
  (:documentation "Synchronize a checkpoint file or its containing directory.")
  (:method ((storage file-raft-storage) phase fd)
    (declare (ignore storage phase))
    (sb-posix:fsync fd)))

(defmethod raft-storage-replace-snapshot
    ((storage file-raft-storage) index term state hard-term vote entries)
  "Replace the WAL without reading or retaining discarded historical records.
The old WAL remains usable on a pre-rename failure. A post-rename failure closes
both streams: its durable outcome is uncertain and requires recovery before use."
  (when (and (raft-snapshot-envelope-p state) (not (getf (cddr state) :application-present)))
    (error "Cannot discard a durable log without an exact application/configuration snapshot"))
  (unless (and (file-raft-storage-stream storage)
               (open-stream-p (file-raft-storage-stream storage)))
    (error "Raft WAL is closed; recover it before checkpointing"))
  (let* ((target (namestring (merge-pathnames (file-raft-storage-path storage))))
         (temporary (format nil "~A.checkpoint-~36R" target (random (expt 36 20))))
         (old (file-raft-storage-stream storage))
         (stream nil) (created nil) (renamed nil) (completed nil))
    (unwind-protect
         (progn
           (let ((fd (sb-posix:open temporary
                                    (logior sb-posix:o-wronly sb-posix:o-creat sb-posix:o-excl) #o600)))
             (setf created t)
             (handler-case
                 (setf stream (sb-sys:make-fd-stream fd :output t :element-type 'character
                                                    :external-format :utf-8 :auto-close t))
               (error (condition) (sb-posix:close fd) (error condition))))
           (let ((*print-readably* t) (*print-circle* nil) (*print-pretty* nil)
                 (*read-eval* nil))
             (flet ((record (form) (prin1 form stream) (terpri stream)))
               (record (list :hard hard-term vote))
               (record (list :snapshot index term state))
               (map nil (lambda (entry)
                          (when (> (raft-entry-index entry) index)
                            (record (list :entry (raft-entry-index entry)
                                          (raft-entry-term entry) (raft-entry-command entry)))))
                    entries)))
           (finish-output stream)
           (file-raft-checkpoint-sync storage :file (sb-sys:fd-stream-fd stream))
           ;; RENAME takes exact path strings, including extensionless WAL names.
           (sb-sys:without-interrupts
             (sb-posix:rename temporary target)
             (setf renamed t (file-raft-storage-stream storage) stream))
           (let ((fd (sb-posix:open
                      (namestring (uiop:pathname-directory-pathname target)) sb-posix:o-rdonly 0)))
             (unwind-protect (file-raft-checkpoint-sync storage :directory fd)
               (sb-posix:close fd)))
           (close old)
           (setf completed t))
      (unless completed
        (when stream (ignore-errors (close stream :abort t)))
        (when renamed
          (ignore-errors (close old :abort t))
          (setf (file-raft-storage-stream storage) nil)))
      (when (and created (probe-file temporary)) (delete-file temporary)))))

(defun close-file-raft-storage (storage)
  "Close STORAGE's WAL stream, ignoring any error."
  (when (file-raft-storage-stream storage)
    (ignore-errors (close (file-raft-storage-stream storage))))
  (setf (file-raft-storage-stream storage) nil))

;;; ---------------------------------------------------------------------------
;;; Recovery: replay the WAL into the persisted Raft fields.

(defstruct raft-recovered
  (term 0) (vote nil)
  (entries '())                         ; ordered RAFT-ENTRYs with index > snapshot-index
  (snapshot-index 0) (snapshot-term 0) (snapshot-state nil))

(defun load-raft-log (path)
  "Replay the WAL at PATH and return a RAFT-RECOVERED with the durable state.
   A missing file recovers empty state."
  (let ((*read-eval* nil)
        (term 0) (vote nil)
        (by-index (make-hash-table))    ; index -> (term . command)
        (snapshot-index 0) (snapshot-term 0) (snapshot-state nil))
    (when (probe-file path)
      (with-open-file (in path :direction :input :element-type 'character :if-does-not-exist nil)
        (when in
          (loop for form = (read in nil :eof)
                until (eq form :eof)
                do (ecase (first form)
                     (:hard (setf term (second form) vote (third form)))
                     (:entry (setf (gethash (second form) by-index)
                                   (cons (third form) (fourth form))))
                     (:truncate (loop for k being the hash-keys of by-index
                                      when (>= k (second form)) do (remhash k by-index)))
                     (:snapshot
                      (setf snapshot-index (second form) snapshot-term (third form)
                            snapshot-state (fourth form))
                      (loop for k being the hash-keys of by-index
                            when (<= k snapshot-index) do (remhash k by-index))))))))
    (let ((entries (loop for index in (sort (loop for k being the hash-keys of by-index collect k) #'<)
                         for cell = (gethash index by-index)
                         collect (make-raft-entry :index index :term (car cell) :command (cdr cell)))))
      (make-raft-recovered :term term :vote vote :entries entries
                           :snapshot-index snapshot-index :snapshot-term snapshot-term
                           :snapshot-state snapshot-state))))

(defun recover-raft-node (node path)
  "Load the WAL at PATH into NODE (currentTerm/votedFor/log/snapshot), restore
   the state machine from the snapshot image via the node's restore-fn, and
   attach an append-only storage for continued operation. Returns NODE."
  (let ((recovered (load-raft-log path)))
    (setf (raft-node-current-term node) (raft-recovered-term recovered)
          (raft-node-voted-for node) (raft-recovered-vote recovered)
          (raft-node-snapshot-index node) (raft-recovered-snapshot-index recovered)
          (raft-node-snapshot-term node) (raft-recovered-snapshot-term recovered)
          (raft-node-snapshot-state node) (raft-recovered-snapshot-state recovered)
          (raft-node-last-applied node) (raft-recovered-snapshot-index recovered)
          (raft-node-commit-index node) (raft-recovered-snapshot-index recovered))
    (when (raft-recovered-snapshot-state recovered)
      (raft-restore-snapshot-contents node (raft-recovered-snapshot-state recovered)))
    (let ((v (raft-node-log node)))
      (setf (fill-pointer v) 0)
      (dolist (entry (raft-recovered-entries recovered)) (vector-push-extend entry v)))
    (setf (raft-node-storage node) (open-file-raft-storage path))
    node))
