;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Turn CRI log files into the text Kubernetes clients expect: strip each line's
;;;; timestamp, stream and tag, rejoin partial lines and apply selection options.
;;;; Also serve finished logs over the binary.k8s.io WebSocket protocols.

(in-package #:gr8s)

(defparameter +cri-log-line+
  "^(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(?:\\.\\d+)?(?:Z|[+-]\\d{2}:\\d{2})) (?:stdout|stderr) ([PF]) (.*)$"
  "One CRI log line: its RFC 3339 time, stream, partial or full tag, and content.")

(defun parse-pod-log-entries (raw)
  "Return (time . text) entries from RAW, with text ending in the line's newline.
A partial line joins the next one and keeps the first part's time. A line that is
not in CRI format is kept whole, with a NIL time."
  (let ((entries nil) (pending nil) (pending-time nil))
    (dolist (line (uiop:split-string (string-right-trim '(#\Newline) raw) :separator '(#\Newline)))
      (multiple-value-bind (match groups) (cl-ppcre:scan-to-strings +cri-log-line+ line)
        (if match
            (let ((time (aref groups 0)) (tag (aref groups 1)) (content (aref groups 2)))
              (unless pending-time (setf pending-time time))
              (push content pending)
              (when (equal tag "F")
                (push (cons pending-time
                            (format nil "~{~A~}~%" (reverse pending)))
                      entries)
                (setf pending nil pending-time nil)))
            (push (cons nil (format nil "~A~%" line)) entries))))
    (when pending
      (push (cons pending-time (format nil "~{~A~}" (reverse pending))) entries))
    (nreverse entries)))

(defun pod-log-entry-seconds (time)
  "Return a log TIME as universal time, or NIL when it is absent or not in UTC."
  (when (and time (> (length time) 19) (char= #\Z (char time (1- (length time)))))
    (pod-deletion-time (concatenate 'string (subseq time 0 19) "Z"))))

(defun truncate-log-bytes (text limit)
  "Keep at most LIMIT bytes of TEXT, never splitting a UTF-8 character."
  (let ((bytes (trivial-utf-8:string-to-utf-8-bytes text)))
    (if (<= (length bytes) limit)
        text
        (let ((end limit))
          (loop while (and (plusp end) (= #x80 (logand #xC0 (aref bytes end))))
                do (decf end))
          (trivial-utf-8:utf-8-bytes-to-string (subseq bytes 0 end))))))

(defun format-pod-logs (raw &key tail-lines limit-bytes timestamps since)
  "Return RAW as clean log text, applying the selection options.
Text with no CRI lines, as from a non-CRI runtime, passes through unless a filter applies."
  (let ((entries (parse-pod-log-entries raw)))
    (when (and (notany #'car entries) (not (or tail-lines limit-bytes timestamps since)))
      (return-from format-pod-logs raw))
    (when since
      (setf entries (remove-if (lambda (entry)
                                 (let ((seconds (pod-log-entry-seconds (car entry))))
                                   (and seconds (< seconds since))))
                               entries)))
    (when (and tail-lines (> (length entries) tail-lines))
      (setf entries (last entries tail-lines)))
    (let ((text (format nil "~{~A~}"
                        (mapcar (lambda (entry)
                                  (if (and timestamps (car entry))
                                      (concatenate 'string (car entry) " " (cdr entry))
                                      (cdr entry)))
                                entries))))
      (if limit-bytes (truncate-log-bytes text limit-bytes) text))))

(defun log-integer-parameter (name minimum)
  "Read an optional integer query parameter NAME of at least MINIMUM."
  (let ((text (hunchentoot:parameter name)))
    (when text
      (let ((value (ignore-errors (parse-integer text))))
        (unless (and value (>= value minimum))
          (core-resource-error 400 "BadRequest" "Invalid ~A" name))
        value))))

(defun pod-logs-since ()
  "Return the universal time selected by sinceSeconds or sinceTime, if either is given."
  (let ((seconds (log-integer-parameter "sinceSeconds" 1))
        (time (hunchentoot:parameter "sinceTime")))
    (when (and seconds time)
      (core-resource-error 400 "BadRequest" "sinceSeconds and sinceTime are mutually exclusive"))
    (cond (seconds (- (get-universal-time) seconds))
          (time (or (ignore-errors (pod-deletion-time time))
                    (core-resource-error 400 "BadRequest" "Invalid sinceTime"))))))

(defun format-pod-logs-for-request (raw)
  "Apply the current request's log options to RAW."
  (format-pod-logs raw
                   :tail-lines (log-integer-parameter "tailLines" 0)
                   :limit-bytes (log-integer-parameter "limitBytes" 1)
                   :timestamps (true-parameter-p (hunchentoot:parameter "timestamps"))
                   :since (pod-logs-since)))

(defun serve-pod-logs-websocket (text)
  "Answer an upgraded log request with TEXT in the protocol the client asked for."
  (let* ((key (hunchentoot:header-in* :sec-websocket-key))
         (requested (uiop:split-string (or (hunchentoot:header-in* :sec-websocket-protocol) "")
                                       :separator '(#\, #\Space #\Tab)))
         (protocol (find-if (lambda (name) (find name requested :test #'string-equal))
                            '("binary.k8s.io" "base64.binary.k8s.io")))
         (bytes (trivial-utf-8:string-to-utf-8-bytes text)))
    (unless (and key (plusp (length key)))
      (bad-exec-request "Pod logs over WebSocket require Sec-WebSocket-Key"))
    (unless protocol
      (bad-exec-request "Pod logs over WebSocket require a supported protocol"))
    (setf (hunchentoot:return-code*) 101
          (hunchentoot:content-type*) nil
          (hunchentoot:header-out :connection) "Upgrade"
          (hunchentoot:header-out :upgrade) "websocket"
          (hunchentoot:header-out :sec-websocket-accept) (websocket-accept-value key)
          (hunchentoot:header-out :sec-websocket-protocol) protocol)
    (let ((client (hunchentoot::start-output 101 nil)))
      (finish-output client)
      (when (plusp (length bytes))
        (if (equal protocol "binary.k8s.io")
            (write-websocket-frame client 2 bytes)
            (write-websocket-frame client 1 (trivial-utf-8:string-to-utf-8-bytes
                                             (ag-grpc:base64-encode bytes)))))
      (write-websocket-frame client 8 (make-array 2 :element-type '(unsigned-byte 8)
                                                    :initial-contents '(3 232))))
    nil))
