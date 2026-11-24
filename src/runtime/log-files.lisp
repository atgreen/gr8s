;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Read a container's CRI log file from where a request's selection begins, a
;;;; piece at a time. A log can be far larger than the heap, so nothing here holds
;;;; more of it than one piece: the last lines are found by reading back from the
;;;; end, and a starting time by bisecting the file.

(in-package #:gr8s.runtime)

(defparameter +log-piece-bytes+ (* 64 1024)
  "How much of a log file one read, and one message, carries.")

(defun read-log-bytes (stream position count)
  "Up to COUNT bytes of STREAM from POSITION."
  (file-position stream position)
  (let* ((buffer (make-array count :element-type '(unsigned-byte 8)))
         (end (read-sequence buffer stream)))
    (if (= end count) buffer (subseq buffer 0 end))))

(defun log-line-time (prefix)
  "The universal time a CRI log line beginning with the octets PREFIX was written, or NIL.
Only UTC times count, as the API server's sinceTime filter reads them."
  (flet ((at (index octet) (and (> (length prefix) index) (= octet (aref prefix index))))
         (digits (start count)
           (parse-integer (map 'string #'code-char (subseq prefix start (+ start count))))))
    (let ((space (position 32 prefix)))
      (when (and space (>= space 20) (= (char-code #\Z) (aref prefix (1- space)))
                 (at 4 45) (at 7 45) (at 10 84) (at 13 58) (at 16 58))
        (ignore-errors
         (encode-universal-time (digits 17 2) (digits 14 2) (digits 11 2)
                                (digits 8 2) (digits 5 2) (digits 0 4) 0))))))

(defun log-line-partial-p (prefix)
  "Whether the CRI log line beginning with PREFIX is tagged P: its entry goes on in the next line."
  (let* ((first (position 32 prefix))
         (second (and first (position 32 prefix :start (1+ first)))))
    (and second (log-line-time prefix)
         (> (length prefix) (1+ second))
         (= (char-code #\P) (aref prefix (1+ second)))
         (or (= (length prefix) (+ 2 second)) (= 32 (aref prefix (+ 2 second)))))))

(defun log-line-prefix (stream position)
  "The start of the log line at POSITION of STREAM: enough for its time, stream and tag."
  (read-log-bytes stream position 64))

(defun log-tail-offset (stream size lines)
  "An offset of STREAM, a log file SIZE bytes long, at the start of a line no later than
its last LINES entries. A line tagged P doesn't end its entry, so it isn't counted."
  (when (zerop lines) (return-from log-tail-offset size))
  (let* ((end (if (and (plusp size) (= 10 (aref (read-log-bytes stream (1- size) 1) 0))) (1- size) size))
         (line-end end)
         (entries 0))
    ;; Each newline found ends the line before it and starts the one after, which is
    ;; then whole: if it ends an entry, one more of the last entries is behind us.
    (loop for block-end = end then block-start
          for block-start = (max 0 (- block-end +log-piece-bytes+))
          while (plusp block-end)
          do (let ((block (read-log-bytes stream block-start (- block-end block-start))))
               (loop for index from (1- (length block)) downto 0
                     when (= 10 (aref block index))
                       do (let ((line-start (+ block-start index 1)))
                            (when (and (< line-start line-end)
                                       (not (log-line-partial-p (log-line-prefix stream line-start)))
                                       (> (incf entries) lines))
                              (return-from log-tail-offset (1+ line-end)))
                            (setf line-end (+ block-start index))))))
    0))

(defun log-line-time-after (stream position size)
  "The time of the first log line of STREAM to begin after POSITION, or NIL."
  (let* ((piece (read-log-bytes stream position (min +log-piece-bytes+ (- size position))))
         (newline (position 10 piece)))
    (when (and newline (< (+ position newline 1) size))
      (log-line-time (log-line-prefix stream (+ position newline 1))))))

(defun log-since-offset (stream size since)
  "An offset of STREAM, a log file SIZE bytes long, at the start of a line no later than
its first entry written at or after the universal time SINCE."
  (let ((low 0) (high size))
    ;; Lines are written in time order. A line whose time can't be read gives no
    ;; reason to look later.
    (loop while (> (- high low) +log-piece-bytes+)
          do (let* ((middle (floor (+ low high) 2))
                    (time (log-line-time-after stream middle size)))
               (if (and time (< time since)) (setf low middle) (setf high middle))))
    (if (zerop low)
        0
        (let ((newline (position 10 (read-log-bytes stream (1- low) (min +log-piece-bytes+ (- size (1- low)))))))
          (if newline (+ low newline) low)))))

(defun send-log-file (path function &key tail-lines since (start-offset 0))
  "Call FUNCTION with the log file at PATH a piece at a time, and the file offset each
begins at, until the file's end as it was when this began. Begin no later than the
file's last TAIL-LINES entries, else its first entry at or after the universal time
SINCE, else START-OFFSET; a START-OFFSET past the end means the file was replaced, so
begin at its start. FUNCTION is called at least once, perhaps with nothing, where the
file begins to be read. Return the offset after the last byte sent."
  (with-open-file (stream path :element-type '(unsigned-byte 8) :if-does-not-exist nil)
    (unless stream
      (funcall function (make-array 0 :element-type '(unsigned-byte 8)) 0)
      (return-from send-log-file 0))
    (let* ((size (file-length stream))
           (start (cond (tail-lines (log-tail-offset stream size tail-lines))
                        (since (log-since-offset stream size since))
                        ((> start-offset size) 0)
                        (t start-offset))))
      (loop for position = start then (+ position (length piece))
            for piece = (read-log-bytes stream position (min +log-piece-bytes+ (- size position)))
            for first = t then nil
            when (or first (plusp (length piece)))
              do (funcall function piece position)
            while (< (+ position (length piece)) size)
            finally (return (+ position (length piece)))))))

(defgeneric runtime-log-file (runtime uid container &key previous)
  (:documentation "The file CONTAINER of the Pod UID writes its CRI log to, or its PREVIOUS
instance did, or NIL when RUNTIME keeps no log files: then RUNTIME-LOGS has them, whole.")
  (:method ((runtime t) uid container &key previous)
    (declare (ignore uid container previous))
    nil))

(defgeneric runtime-send-logs (runtime uid container function &key previous tail-lines since start-offset)
  (:documentation "Call FUNCTION with CONTAINER's CRI log a piece at a time, as SEND-LOG-FILE
does, and return the offset after the last byte sent. The selection may begin earlier than
asked, never later: whoever shows the log applies it exactly."))

(defmethod runtime-send-logs ((runtime t) uid container function
                              &key previous tail-lines since (start-offset 0))
  (let ((path (runtime-log-file runtime uid container :previous previous)))
    (if path
        (send-log-file path function :tail-lines tail-lines :since since :start-offset start-offset)
        (let* ((bytes (trivial-utf-8:string-to-utf-8-bytes
                       (or (runtime-logs runtime uid container :previous previous) "")))
               (start (if (> start-offset (length bytes)) 0 start-offset)))
          (funcall function (subseq bytes start) start)
          (length bytes)))))

;;; A container writes its log for as long as it runs, so a log is rotated as kubelet
;;; rotates one: past a size it is renamed with the time, the container starts a new
;;; file, and only the newest rotated files are kept. Reading a log reads the file being
;;; written, as kubelet's does.

(defparameter *container-log-max-bytes* (* 10 1024 1024)
  "The size past which a container's log is rotated, as kubelet's containerLogMaxSize.")

(defparameter *container-log-max-files* 5
  "How many files of a container's log are kept, the one being written among them, as
kubelet's containerLogMaxFiles.")

(defun rotated-log-files (path)
  "The rotated files of the log at PATH, oldest first."
  (sort (mapcar #'namestring
                (remove-if-not (lambda (file)
                                 (let ((name (file-namestring file)) (base (file-namestring path)))
                                   (and (> (length name) (1+ (length base)))
                                        (uiop:string-prefix-p (concatenate 'string base ".") name)
                                        (every (lambda (char) (or (digit-char-p char) (char= char #\-)))
                                               (subseq name (1+ (length base)))))))
                               (directory (concatenate 'string (namestring path) ".*"))))
        #'string<))

(defun rotate-log-file (path reopen &key (max-bytes *container-log-max-bytes*)
                                         (max-files *container-log-max-files*))
  "Rotate the log at PATH once it is larger than MAX-BYTES: rename it with the time, then
call REOPEN to have its writer begin a new file there, keeping MAX-FILES files in all.
When REOPEN fails, the file gets its name back, and the error is signalled. Return
whether it was rotated."
  (let ((size (handler-case (sb-posix:stat-size (sb-posix:stat (namestring path)))
                (sb-posix:syscall-error () 0))))
    (when (> size max-bytes)
      (let ((rotated (rotated-log-files path)))
        (loop while (> (length rotated) (max 0 (- max-files 2)))
              do (ignore-errors (delete-file (pop rotated)))))
      ;; A UTC time, so that the names sort in the order the files were rotated; a
      ;; second rotation within a second takes a count after it.
      (let* ((stamp (multiple-value-bind (seconds minutes hours day month year)
                        (decode-universal-time (get-universal-time) 0)
                      (format nil "~A.~4,'0D~2,'0D~2,'0D-~2,'0D~2,'0D~2,'0D"
                              (namestring path) year month day hours minutes seconds)))
             (target (loop for count from 0
                           for name = (if (zerop count) stamp (format nil "~A-~D" stamp count))
                           unless (probe-file name) return name)))
        (sb-posix:rename (namestring path) target)
        (handler-bind ((error (lambda (condition)
                                (declare (ignore condition))
                                (ignore-errors (sb-posix:rename target (namestring path))))))
          (funcall reopen))
        t))))

(defgeneric runtime-rotate-logs (runtime)
  (:documentation "Rotate the logs of RUNTIME's running containers that have grown past
*CONTAINER-LOG-MAX-BYTES*, as ROTATE-LOG-FILE does.")
  (:method ((runtime t)) nil))
