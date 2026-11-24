;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Turn CRI log files into the text Kubernetes clients expect: strip each line's
;;;; timestamp, stream and tag, rejoin partial lines and apply selection options.
;;;; Also serve finished logs over the binary.k8s.io WebSocket protocols.

(in-package #:gr8s.apiserver)

(defparameter +cri-log-line+
  "^(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(?:\\.\\d+)?(?:Z|[+-]\\d{2}:\\d{2})) (?:stdout|stderr) ([PF]) (.*)$"
  "One CRI log line: its RFC 3339 time, stream, partial or full tag, and content.")

(defstruct (log-entry-joiner (:constructor make-log-entry-joiner ()))
  "The parts of an entry whose lines, tagged P, wait for the line that ends it."
  (parts nil)
  (time nil))

(defun join-log-line (joiner line function &key (terminated t))
  "Call FUNCTION with the (time . text) entry that LINE, one log line without its newline,
completes, if any; its text ends in a newline. A partial line joins the next one and keeps
the first part's time. A line that is not in CRI format is an entry of its own, with a NIL
time and, unless it was TERMINATED, no newline."
  (multiple-value-bind (match groups) (cl-ppcre:scan-to-strings +cri-log-line+ line)
    (if match
        (progn
          (unless (log-entry-joiner-time joiner) (setf (log-entry-joiner-time joiner) (aref groups 0)))
          (push (aref groups 2) (log-entry-joiner-parts joiner))
          (when (equal (aref groups 1) "F")
            (funcall function (cons (log-entry-joiner-time joiner)
                                    (format nil "~{~A~}~%" (reverse (log-entry-joiner-parts joiner)))))
            (setf (log-entry-joiner-parts joiner) nil (log-entry-joiner-time joiner) nil)))
        (funcall function (cons nil (if terminated (format nil "~A~%" line) line))))))

(defun finish-log-entries (joiner function)
  "Call FUNCTION with the unfinished entry JOINER holds, without a newline, if any."
  (when (log-entry-joiner-parts joiner)
    (funcall function (cons (log-entry-joiner-time joiner)
                            (format nil "~{~A~}" (reverse (log-entry-joiner-parts joiner)))))
    (setf (log-entry-joiner-parts joiner) nil (log-entry-joiner-time joiner) nil)))

(defun parse-pod-log-entries (raw)
  "Return (time . text) entries from RAW, as JOIN-LOG-LINE makes them."
  (let ((entries nil) (joiner (make-log-entry-joiner)))
    (flet ((collect (entry) (push entry entries)))
      (dolist (line (uiop:split-string (string-right-trim '(#\Newline) raw) :separator '(#\Newline)))
        (join-log-line joiner line #'collect))
      (finish-log-entries joiner #'collect))
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

(defun pod-log-request-options ()
  "The current request's log selection, as keyword arguments of SEND-POD-LOGS."
  (list :tail-lines (log-integer-parameter "tailLines" 0)
        :limit-bytes (log-integer-parameter "limitBytes" 1)
        :timestamps (true-parameter-p (hunchentoot:parameter "timestamps"))
        :since (pod-logs-since)))

(defparameter +log-write-batch-bytes+ (* 64 1024)
  "How much clean log text SEND-POD-LOGS gathers before passing it on.")

(defun send-pod-logs (reconciler pod container write
                      &key previous tail-lines limit-bytes timestamps since (start-offset 0) (last-line t))
  "Call WRITE with CONTAINER's log for POD as clean text, a string at a time, as the
selection options ask, reading the log a piece at a time: only TAIL-LINES entries are
ever held. Begin at byte START-OFFSET of the log file, and with LAST-LINE take a last line
that has no newline yet. Return the offset after the last line taken, from which a follow
goes on, whether LIMIT-BYTES was reached, and how many bytes were written."
  (let ((joiner (make-log-entry-joiner))
        (line (make-array 0 :element-type '(unsigned-byte 8) :adjustable t :fill-pointer 0))
        ;; The file offset after the last whole line, and where LINE's bytes begin.
        (taken start-offset)
        (tail nil) (tail-end nil) (tail-count 0)
        (written 0)
        ;; Text on its way to WRITE, which takes it in batches rather than line by line.
        (batch (make-string-output-stream)) (batched 0))
    (labels ((flush ()
               (when (plusp batched)
                 (funcall write (get-output-stream-string batch))
                 (setf batched 0)))
             (out (text size)
               (write-string text batch)
               (when (>= (incf batched size) +log-write-batch-bytes+) (flush)))
             (show (entry)
               (let* ((text (if (and timestamps (car entry)) (concatenate 'string (car entry) " " (cdr entry)) (cdr entry)))
                      (size (trivial-utf-8:utf-8-byte-length text)))
                 (when (and limit-bytes (>= (+ written size) limit-bytes))
                   (let ((rest (truncate-log-bytes text (- limit-bytes written))))
                     (out rest (trivial-utf-8:utf-8-byte-length rest))
                     (flush)
                     (setf written limit-bytes)
                     (throw 'pod-log-limit t)))
                 (out text size)
                 (incf written size)))
             (select (entry)
               (let ((seconds (and since (pod-log-entry-seconds (car entry)))))
                 (cond ((and seconds (< seconds since)))
                       ((null tail-lines) (show entry))
                       ((zerop tail-lines))
                       (t (let ((cell (list entry)))
                            (if tail-end (setf (cdr tail-end) cell) (setf tail cell))
                            (setf tail-end cell)
                            (when (> (incf tail-count) tail-lines)
                              (pop tail)
                              (decf tail-count)))))))
             (take-line (bytes start end &key (terminated t))
               (join-log-line joiner (sb-ext:octets-to-string bytes :start start :end end
                                                                    :external-format '(:utf-8 :replacement #\?))
                              #'select :terminated terminated)))
      (let ((limited
              (catch 'pod-log-limit
                (reconciler-send-logs
                 reconciler (pod-uid pod) container
                 (lambda (piece offset)
                   ;; A piece that doesn't go on from the last one starts the file again.
                   (unless (= offset (+ taken (length line)))
                     (setf (fill-pointer line) 0 taken offset))
                   (loop for start = 0 then (1+ newline)
                         for newline = (position 10 piece :start start)
                         while newline
                         do (if (zerop (length line))
                                (take-line piece start newline)
                                (progn
                                  (loop for index from start below newline do (vector-push-extend (aref piece index) line))
                                  (take-line line 0 (length line))
                                  (setf (fill-pointer line) 0)))
                            (setf taken (+ offset newline 1))
                         finally (loop for index from start below (length piece)
                                       do (vector-push-extend (aref piece index) line)))
                   (flush))
                 :previous previous :tail-lines tail-lines :since since :start-offset start-offset)
                (when (and last-line (plusp (length line)))
                  (take-line line 0 (length line) :terminated nil)
                  (incf taken (length line)))
                (finish-log-entries joiner #'select)
                (mapc #'show tail)
                (flush)
                nil)))
        (values taken limited written)))))

(defun pod-container-finished-p (store pod container)
  "Return whether CONTAINER's latest report shows it terminated, or POD is gone or finished."
  (let ((current (handler-case (get-pod store (pod-namespace pod) (pod-name pod))
                   (kubernetes-error () nil))))
    (or (null current)
        (not (equal (pod-uid current) (pod-uid pod)))
        (let* ((status (pod-observed-status store current))
               (item (and status
                          (find container
                                (concatenate 'vector (gethash "containerStatuses" status #())
                                             (gethash "initContainerStatuses" status #())
                                             (gethash "ephemeralContainerStatuses" status #()))
                                :test #'equal :key (lambda (entry) (gethash "name" entry))))))
          (or (and status (member (gethash "phase" status) '("Succeeded" "Failed") :test #'equal))
              (and item (hash-table-p (gethash "state" item)) (gethash "terminated" (gethash "state" item))))))))

(defun serve-followed-pod-logs (store reconciler pod container options)
  "Send CONTAINER's log as OPTIONS select it, then whole new lines as they are written,
until the container ends, the client leaves, or OPTIONS' limitBytes is reached."
  (let ((stream nil) (limit (getf options :limit-bytes)))
    (flet ((send-text (text)
             (unless stream
               (setf (hunchentoot:content-type*) "text/plain; charset=utf-8"
                     stream (hunchentoot:send-headers))
               ;; A follow lasts as long as its client likes; it must not hold the
               ;; request lease a checkpoint waits for.
               (gr8s.store::release-store-request))
             (when (plusp (length text))
               (write-sequence (trivial-utf-8:string-to-utf-8-bytes text) stream)
               (finish-output stream))))
      (multiple-value-bind (offset limited written)
          (apply #'send-pod-logs reconciler pod container #'send-text :last-line nil options)
        (send-text "")
        (handler-case
            (loop
              (when (or limited
                        ;; A quiet container sends nothing, so a failed send would never
                        ;; tell us the client has gone.
                        (api-watch-client-departed-p))
                (return))
              (let ((finished (handler-case (pod-container-finished-p store pod container)
                                ;; The store is closed for a moment; ask again next time.
                                (kubernetes-error () nil))))
                (handler-case
                    (multiple-value-bind (next now-limited more)
                        (send-pod-logs reconciler pod container #'send-text
                                       :last-line nil :start-offset offset
                                       :timestamps (getf options :timestamps)
                                       :limit-bytes (and limit (- limit written)))
                      (setf offset next limited now-limited)
                      (incf written more))
                  (runtime-error () nil))
                (when finished (return)))
              (sleep 1))
          ;; The headers have gone, so nothing can be reported; a client hanging
          ;; up, whatever the transport makes of it, is how a follow usually ends.
          (error () nil)))))
  nil)

(defun serve-pod-logs-websocket (send)
  "Answer an upgraded log request in the protocol the client asked for, with what SEND
writes: SEND is called with a function of one string."
  (let* ((key (hunchentoot:header-in* :sec-websocket-key))
         (requested (uiop:split-string (or (hunchentoot:header-in* :sec-websocket-protocol) "")
                                       :separator '(#\, #\Space #\Tab)))
         (protocol (find-if (lambda (name) (find name requested :test #'string-equal))
                            '("binary.k8s.io" "base64.binary.k8s.io")))
         (client nil))
    (unless (and key (plusp (length key)))
      (bad-exec-request "Pod logs over WebSocket require Sec-WebSocket-Key"))
    (unless protocol
      (bad-exec-request "Pod logs over WebSocket require a supported protocol"))
    (flet ((send-text (text)
             ;; The upgrade waits for the log to be found: until then, an error can
             ;; still be answered as one.
             (unless client
               (setf (hunchentoot:return-code*) 101
                     (hunchentoot:content-type*) nil
                     (hunchentoot:header-out :connection) "Upgrade"
                     (hunchentoot:header-out :upgrade) "websocket"
                     (hunchentoot:header-out :sec-websocket-accept) (websocket-accept-value key)
                     (hunchentoot:header-out :sec-websocket-protocol) protocol
                     client (hunchentoot::start-output 101 nil))
               (finish-output client)
               (gr8s.store::release-store-request))
             (let ((bytes (trivial-utf-8:string-to-utf-8-bytes text)))
               (when (plusp (length bytes))
                 (if (equal protocol "binary.k8s.io")
                     (write-websocket-frame client 2 bytes)
                     (write-websocket-frame client 1 (trivial-utf-8:string-to-utf-8-bytes
                                                      (ag-grpc:base64-encode bytes))))))))
      (funcall send #'send-text)
      (send-text "")
      (write-websocket-frame client 8 (make-array 2 :element-type '(unsigned-byte 8)
                                                    :initial-contents '(3 232))))
    nil))
