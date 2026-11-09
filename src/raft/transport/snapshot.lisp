;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;; File-backed, bounded RPC transfer for immutable Raft snapshot envelopes.
(in-package #:gr8s.raft.transport)

(defconstant +raft-snapshot-chunk-bytes+ 65536)
(defstruct raft-snapshot-receiver from term index last-term token digest total path stream (offset 0)
  (activity (get-internal-real-time)))

(defun raft-member-snapshot-root-unlocked (member)
  (or (raft-member-snapshot-root member)
      (let* ((storage (raft-node-storage (raft-member-node member)))
             (base (uiop:ensure-directory-pathname
                    (or (raft-member-snapshot-directory member)
                        (when (typep storage 'file-raft-storage)
                          (uiop:pathname-directory-pathname (merge-pathnames (file-raft-storage-path storage))))
                        (uiop:temporary-directory)))))
        (ensure-directories-exist base)
        (setf (raft-member-snapshot-root member)
              (uiop:ensure-directory-pathname
               (sb-posix:mkdtemp (namestring (merge-pathnames ".raft-transfer-XXXXXX" base))))))))

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
