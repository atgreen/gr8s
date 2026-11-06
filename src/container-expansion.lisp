;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Expand Kubernetes command/argument variable references from the actual resolved
;;;; container environment once, consuming doubled dollars without recursive expansion.

(in-package #:gr8s)

(defun expand-container-command-argument (argument environment)
  "Expand known $(VAR) references once, preserve unknown references and unescape $$ once."
  (with-output-to-string (out)
    (loop with index = 0 while (< index (length argument))
          do (cond
               ((and (char= #\$ (char argument index)) (< (1+ index) (length argument))
                     (char= #\$ (char argument (1+ index))))
                (write-char #\$ out) (incf index 2))
               ((and (char= #\$ (char argument index)) (< (1+ index) (length argument))
                     (char= #\( (char argument (1+ index)))
                     (position #\) argument :start (+ index 2)))
                (let* ((end (position #\) argument :start (+ index 2)))
                       (name (subseq argument (+ index 2) end))
                       (entry (find name environment :key #'car :test #'equal :from-end t)))
                  (write-string (if entry (or (cdr entry) "") (subseq argument index (1+ end))) out)
                  (setf index (1+ end))))
               (t (write-char (char argument index) out) (incf index))))))

(defun expand-container-command (arguments environment)
  "Expand each container command or argument using the same resolved runtime environment."
  (map 'list (lambda (argument) (expand-container-command-argument argument environment)) arguments))
