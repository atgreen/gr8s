;;;; SPDX-License-Identifier: MIT
(in-package #:gr8s-diagnose)

;;; A survey reads for many seconds before it has anything to say. Someone
;;; watching a terminal is shown what it is reading meanwhile. That goes to
;;; standard error and is wiped before the report, so standard output is the
;;; same with or without it.

(defun terminal-p (stream)
  "Whether STREAM writes to a terminal."
  (loop while (typep stream 'synonym-stream)
        do (setf stream (symbol-value (synonym-stream-symbol stream))))
  (and (typep stream 'sb-sys:fd-stream)
       (eql 1 (sb-unix:unix-isatty (sb-sys:fd-stream-fd stream)))))

(defun plain-terminal-p ()
  "Whether the terminal asks for no styles."
  (or (uiop:getenvp "NO_COLOR") (equal "dumb" (uiop:getenv "TERM"))))

(defvar *progress* nil "A function of a step's description while someone is watching, else NIL.")

(defun progress (control &rest arguments)
  "Say what the doctor is doing now."
  (when *progress* (funcall *progress* (apply #'format nil control arguments))))

(defun call-with-progress (function &key (stream *error-output*))
  "Call FUNCTION. While it runs, a STREAM that is a terminal shows a spinner
and the step last given to PROGRESS, on one line that is wiped afterwards."
  (if (or (not (terminal-p stream)) (equal "dumb" (uiop:getenv "TERM")))
      (funcall function)
      (let* ((step "Starting") (done nil)
             (width (max 20 (- (car (tuition:get-terminal-size)) 3)))
             (frames (mapcar (lambda (frame)
                               (if (plain-terminal-p) frame
                                   (tuition:render-styled (tuition:make-style :foreground tuition:*fg-cyan*) frame)))
                             tuition.components.spinner:*spinner-minidot*))
             (spinner (sb-thread:make-thread
                       (lambda ()
                         (loop until done
                               do (dolist (frame frames)
                                    (when done (return))
                                    (let ((text step))
                                      (format stream "~C~A ~A~C[K" #\Return frame
                                              (subseq text 0 (min width (length text))) #\Escape))
                                    (finish-output stream)
                                    (sleep 0.08))))
                       :name "doctor progress")))
        (unwind-protect (let ((*progress* (lambda (text) (setf step text)))) (funcall function))
          (setf done t)
          (sb-thread:join-thread spinner :default nil)
          (format stream "~C~C[K" #\Return #\Escape)
          (finish-output stream)))))
