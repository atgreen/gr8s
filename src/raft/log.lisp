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
  (sb-posix:close (sb-posix:open (namestring path) (logior sb-posix:o-wronly sb-posix:o-creat) #o600))
  (sb-posix:chmod (namestring path) #o600)
  (make-instance 'file-raft-storage
                 :path path
                 :stream (open path :direction :output :element-type 'character
                                    :if-exists :append :if-does-not-exist :create)))

(defun file-raft-write (storage form)
  "Append FORM to STORAGE's WAL as one compact, single-line record (printer
   specials bound off), then terminate the line, flush, and best-effort fsync so a
   committed record survives a crash."
  (let ((stream (file-raft-storage-stream storage))
        (*print-readably* nil) (*print-circle* nil) (*print-pretty* nil))
    (prin1 form stream)
    (terpri stream)
    (finish-output stream)
    (ignore-errors (sb-posix:fsync (sb-sys:fd-stream-fd stream)))))

(defmethod raft-storage-save-hard-state ((storage file-raft-storage) term vote)
  (file-raft-write storage (list :hard term vote)))

(defmethod raft-storage-append-entry ((storage file-raft-storage) entry)
  (file-raft-write storage (list :entry (raft-entry-index entry)
                                 (raft-entry-term entry) (raft-entry-command entry))))

(defmethod raft-storage-truncate ((storage file-raft-storage) index)
  (file-raft-write storage (list :truncate index)))

(defmethod raft-storage-save-snapshot ((storage file-raft-storage) index term state)
  (file-raft-write storage (list :snapshot index term state)))

(defun close-file-raft-storage (storage)
  "Close STORAGE's WAL stream, ignoring any error."
  (ignore-errors (close (file-raft-storage-stream storage))))

;;; ---------------------------------------------------------------------------
;;; Recovery: replay the WAL into the persisted Raft fields.

(defstruct raft-recovered
  (term 0) (vote nil)
  (entries '())                         ; ordered RAFT-ENTRYs with index > snapshot-index
  (snapshot-index 0) (snapshot-term 0) (snapshot-state nil))

(defun load-raft-log (path)
  "Replay the WAL at PATH and return a RAFT-RECOVERED with the durable state.
   A missing file recovers empty state."
  (let ((term 0) (vote nil)
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
          (raft-node-last-applied node) (raft-recovered-snapshot-index recovered)
          (raft-node-commit-index node) (raft-recovered-snapshot-index recovered))
    (when (and (raft-recovered-snapshot-state recovered) (raft-node-restore-fn node))
      (funcall (raft-node-restore-fn node) (raft-recovered-snapshot-state recovered)))
    (let ((v (raft-node-log node)))
      (setf (fill-pointer v) 0)
      (dolist (entry (raft-recovered-entries recovered)) (vector-push-extend entry v)))
    (setf (raft-node-storage node) (open-file-raft-storage path))
    node))
