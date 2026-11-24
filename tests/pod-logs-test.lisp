;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Verify CRI framing is removed from Pod logs, selection options behave as
;;;; Kubernetes defines them, and logs and exec answer the older WebSocket protocols.

(in-package #:gr8s/tests)
(def-suite pod-logs :in gr8s)
(in-suite pod-logs)

(defparameter *cri-log*
  (format nil "~{~A~%~}"
          '("2026-11-04T08:00:00.000000001Z stdout F first"
            "2026-11-04T08:00:01.000000001Z stderr P par"
            "2026-11-04T08:00:01.500000001Z stderr F tial"
            "2026-11-04T08:00:02.000000001Z stdout F "
            "2026-11-04T08:00:03.000000001Z stdout F last line")))

(test framing-is-removed-and-partial-lines-rejoined
  (is (equal (format nil "first~%partial~%~%last line~%") (gr8s.apiserver::format-pod-logs *cri-log*))))

(test text-without-cri-lines-passes-through-unchanged
  (is (equal "plain bytes" (gr8s.apiserver::format-pod-logs "plain bytes")))
  (is (equal "" (gr8s.apiserver::format-pod-logs ""))))

(test an-unfinished-partial-line-keeps-no-newline
  (is (equal (format nil "done~%rest")
             (gr8s.apiserver::format-pod-logs (format nil "2026-11-04T08:00:00Z stdout F done~%2026-11-04T08:00:01Z stdout P rest~%")))))

(test tail-lines-count-rejoined-lines
  (is (equal (format nil "~%last line~%") (gr8s.apiserver::format-pod-logs *cri-log* :tail-lines 2)))
  (is (equal "" (gr8s.apiserver::format-pod-logs *cri-log* :tail-lines 0)))
  (is (equal (gr8s.apiserver::format-pod-logs *cri-log*) (gr8s.apiserver::format-pod-logs *cri-log* :tail-lines 99))))

(test timestamps-restore-the-original-time
  (is (equal (format nil "2026-11-04T08:00:03.000000001Z last line~%")
             (gr8s.apiserver::format-pod-logs *cri-log* :tail-lines 1 :timestamps t))))

(test since-selects-by-log-time
  (let ((cutoff (gr8s.kubelet::pod-deletion-time "2026-11-04T08:00:02Z")))
    (is (equal (format nil "~%last line~%") (gr8s.apiserver::format-pod-logs *cri-log* :since cutoff)))))

(test limit-bytes-never-splits-a-character
  (is (equal "fir" (gr8s.apiserver::format-pod-logs *cri-log* :limit-bytes 3)))
  (let ((snowman (format nil "2026-11-04T08:00:00Z stdout F ab~A~%" (code-char #x2603))))
    (is (equal "ab" (gr8s.apiserver::format-pod-logs snowman :limit-bytes 3)))
    (is (equal (format nil "ab~A" (code-char #x2603)) (gr8s.apiserver::format-pod-logs snowman :limit-bytes 5)))))

(defun canned-log-sender (raw &optional (counter (constantly nil)))
  "An encapsulation of RECONCILER-SEND-LOGS that has RAW for its whole log file."
  (lambda (f reconciler uid container function &key start-offset &allow-other-keys)
    (declare (ignore f reconciler uid container))
    (funcall counter)
    (let* ((bytes (trivial-utf-8:string-to-utf-8-bytes raw))
           (start (min (or start-offset 0) (length bytes))))
      (funcall function (subseq bytes start) start)
      (length bytes))))

(defun websocket-handshake (path protocol)
  "Send an upgrade request for PATH and return its status line and the following bytes."
  (let* ((socket (usocket:socket-connect "127.0.0.1" *core-api-port* :element-type '(unsigned-byte 8)))
         (stream (usocket:socket-stream socket)))
    (unwind-protect
         (sb-sys:with-deadline (:seconds 10)
           (write-sequence
            (trivial-utf-8:string-to-utf-8-bytes
             (format nil "GET ~A HTTP/1.1~C~CHost: 127.0.0.1~C~CConnection: Upgrade~C~CUpgrade: websocket~C~CSec-WebSocket-Version: 13~C~CSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==~C~CSec-WebSocket-Protocol: ~A~C~C~C~C"
                     path #\Return #\Newline #\Return #\Newline #\Return #\Newline #\Return #\Newline
                     #\Return #\Newline #\Return #\Newline protocol #\Return #\Newline #\Return #\Newline))
            stream)
           (finish-output stream)
           (let ((received (make-array 0 :element-type '(unsigned-byte 8) :adjustable t :fill-pointer t)))
             ;; An upgrade ends with the server closing. Anything else stays open,
             ;; so stop once its headers have arrived.
             (handler-case
                 (loop for byte = (read-byte stream nil nil) while byte
                       do (vector-push-extend byte received)
                       until (let ((text (map 'string #'code-char received)))
                               (and (not (search " 101 " text))
                                    (search (format nil "~C~C~C~C" #\Return #\Newline #\Return #\Newline) text))))
               (error () nil))
             (let* ((text (map 'string #'code-char received))
                    (end (search (format nil "~C~C~C~C" #\Return #\Newline #\Return #\Newline) text)))
               (values (subseq text 0 (position #\Return text))
                       (if end (subseq text 0 end) text)
                       (if end (subseq received (+ end 4)) #())))))
      (usocket:socket-close socket))))

(defun first-websocket-payload (bytes)
  "Return the opcode and payload of the first short frame in BYTES."
  (let ((length (logand #x7f (aref bytes 1))))
    (values (logand #x0f (aref bytes 0)) (subseq bytes 2 (+ 2 length)))))

(test logs-answer-binary-websockets-with-clean-text
  (with-core-api (store path)
    (values path)
    (let* ((pod (create-pod store (parse-pod *valid-pod-json*)))
           (raw (format nil "2026-11-04T08:00:00Z stdout F container is alive~%")))
      (declare (ignorable pod))
      (sb-int:encapsulate 'gr8s.kubelet::reconciler-send-logs 'canned (canned-log-sender raw))
      (unwind-protect
           (multiple-value-bind (status headers body)
               (websocket-handshake "/api/v1/namespaces/default/pods/hello/log" "binary.k8s.io")
             (is (search "101" status))
             (is (search "binary.k8s.io" headers))
             (multiple-value-bind (opcode payload) (first-websocket-payload body)
               (is (= 2 opcode))
               (is (equal (format nil "container is alive~%") (trivial-utf-8:utf-8-bytes-to-string payload)))))
        (sb-int:unencapsulate 'gr8s.kubelet::reconciler-send-logs 'canned)))))

(test logs-refuse-an-unknown-websocket-protocol
  (with-core-api (store path)
    (values path)
    (create-pod store (parse-pod *valid-pod-json*))
    (sb-int:encapsulate 'gr8s.kubelet::reconciler-send-logs 'canned (canned-log-sender ""))
    (unwind-protect
         (is (search "400" (websocket-handshake "/api/v1/namespaces/default/pods/hello/log" "unknown.example")))
      (sb-int:unencapsulate 'gr8s.kubelet::reconciler-send-logs 'canned))))

(test invalid-log-options-are-refused
  (with-core-api (store path)
    (values path)
    (create-pod store (parse-pod *valid-pod-json*))
    (sb-int:encapsulate 'gr8s.kubelet::reconciler-send-logs 'canned (canned-log-sender ""))
    (unwind-protect
         (dolist (query '("tailLines=-1" "tailLines=x" "limitBytes=0" "sinceSeconds=0" "sinceTime=yesterday"
                          "sinceSeconds=5&sinceTime=2026-01-01T00:00:00Z"))
           (is (= 400 (nth-value 1 (drakma:http-request
                                    (core-api-url (format nil "/api/v1/namespaces/default/pods/hello/log?~A" query)))))
               query))
      (sb-int:unencapsulate 'gr8s.kubelet::reconciler-send-logs 'canned))))

(test exec-status-frames-depend-on-the-negotiated-protocol
  (flet ((frame (protocol exit-code)
           (let ((gr8s.apiserver::*kubernetes-websocket-protocols* (list protocol)))
             (sb-int:encapsulate 'gr8s.apiserver::requested-kubernetes-websocket-protocol 'fixed
                                 (lambda (f) (declare (ignore f)) protocol))
             (unwind-protect (gr8s.apiserver::exec-status-frame-bytes exit-code)
               (sb-int:unencapsulate 'gr8s.apiserver::requested-kubernetes-websocket-protocol 'fixed)))))
    ;; The upstream client fails on any multi-byte frame that is not stdout.
    (is (null (frame "channel.k8s.io" 0)))
    (is (search "exit code 3" (trivial-utf-8:utf-8-bytes-to-string (frame "channel.k8s.io" 3))))
    (is (search "Success" (trivial-utf-8:utf-8-bytes-to-string (frame "v5.channel.k8s.io" 0))))))

(test boolean-parameters-accept-what-kubernetes-clients-send
  (dolist (value '("1" "t" "T" "true" "TRUE" "True"))
    (is-true (gr8s.apiserver::true-parameter-p value) value))
  (dolist (value '(nil "" "0" "f" "false" "yes" "tRuE"))
    (is-false (gr8s.apiserver::true-parameter-p value)))
  ;; Upstream's WebSocket exec spec sends stdout=1 and needs stdout back.
  (let ((options (gr8s.apiserver::exec-options-from-parameters
                  '(("command" . "echo") ("stdout" . "1") ("stderr" . "1")))))
    (is-true (gr8s.apiserver::exec-options-stdout options))
    (is-true (gr8s.apiserver::exec-options-stderr options))))


(test a-followed-log-neither-holds-up-a-checkpoint-nor-outlives-its-client
  ;; One `kubectl logs -f` kept every checkpoint waiting out its drain limit, and
  ;; with it the whole API; and a quiet container's follow ran on after its
  ;; client had gone, because nothing was ever sent to fail (podster-cwj).
  (with-core-api (store path)
    (values path)
    (create-pod store (parse-pod *valid-pod-json*))
    (let ((fetches 0)
          (raw (format nil "2026-11-04T08:00:00Z stdout F container is alive~%"))
          (socket (usocket:socket-connect "127.0.0.1" *core-api-port* :element-type '(unsigned-byte 8))))
      (sb-int:encapsulate 'gr8s.kubelet::reconciler-send-logs 'canned
                          (canned-log-sender raw (lambda () (incf fetches))))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (write-sequence
              (trivial-utf-8:string-to-utf-8-bytes
               (format nil "GET /api/v1/namespaces/default/pods/hello/log?follow=true HTTP/1.1~C~CHost: 127.0.0.1~C~C~C~C"
                       #\Return #\Newline #\Return #\Newline #\Return #\Newline))
              stream)
             (finish-output stream)
             ;; The first lines arriving means the follow loop is running.
             (is-true (wait-until
                       (lambda ()
                         (and (>= fetches 2)
                              (zerop (gr8s.store::pod-store-active-requests store))))
                       :timeout 10)
                      "the follow gives its lease up once it is streaming")
             (is (eq store (gr8s.store::quiesce-store-access store :timeout 1 :brief t))
                 "a checkpoint does not wait for the follow")
             (gr8s.store::resume-store-access store)
             (usocket:socket-close socket)
             (setf socket nil)
             (sleep 3)
             (let ((after-leaving fetches))
               (sleep 3)
               (is (= after-leaving fetches) "the follow stops once its client has gone")))
        (when socket (ignore-errors (usocket:socket-close socket)))
        (sb-int:unencapsulate 'gr8s.kubelet::reconciler-send-logs 'canned)))))

;;; A log is read a piece at a time, from where the selection begins: one of 471 MB,
;;; read whole for each request, exhausted the heap and stopped the server (podster-0gf).

(defun write-cri-log (path count)
  "Write COUNT CRI entries to PATH, one a second from 2026-11-04T08:00:00Z, every tenth
split across a P and an F line. Return the log's text."
  (let ((text (with-output-to-string (out)
                (dotimes (index count)
                  (multiple-value-bind (minutes seconds) (floor index 60)
                    (multiple-value-bind (hours minutes) (floor minutes 60)
                      (let ((time (format nil "2026-11-04T~2,'0D:~2,'0D:~2,'0D.000000001Z" (+ 8 hours) minutes seconds)))
                        (if (zerop (mod index 10))
                            (format out "~A stdout P entry ~D, ~A stdout F continued~%" time index time)
                            (format out "~A stdout F entry ~D~%" time index)))))))))
    (with-open-file (out path :direction :output :if-exists :supersede :element-type '(unsigned-byte 8))
      (write-sequence (trivial-utf-8:string-to-utf-8-bytes text) out))
    text))

(defun log-file-pieces (path &rest selection)
  "What SEND-LOG-FILE sends of PATH: the text, the pieces' sizes and offsets, and the end."
  (let ((pieces nil) (offsets nil))
    (let ((end (apply #'gr8s.runtime:send-log-file path
                      (lambda (piece offset) (push piece pieces) (push offset offsets))
                      selection)))
      (values (trivial-utf-8:utf-8-bytes-to-string (apply #'concatenate '(vector (unsigned-byte 8)) (reverse pieces)))
              (mapcar #'length (reverse pieces)) (reverse offsets) end))))

(test a-log-file-is-sent-from-where-the-selection-begins
  (uiop:with-temporary-file (:pathname path)
    (let* ((raw (write-cri-log path 20000))
           (size (length (trivial-utf-8:string-to-utf-8-bytes raw))))
      (multiple-value-bind (text sizes offsets end) (log-file-pieces path)
        (is (equal raw text))
        (is (every (lambda (n) (<= n gr8s.runtime::+log-piece-bytes+)) sizes))
        (is (zerop (first offsets)))
        (is (= size end)))
      ;; The last lines are found from the end, and little more is read.
      (multiple-value-bind (text sizes) (log-file-pieces path :tail-lines 3)
        (is (< (reduce #'+ sizes) 300))
        (is (equal (gr8s.apiserver::format-pod-logs raw :tail-lines 3)
                   (gr8s.apiserver::format-pod-logs text :tail-lines 3))))
      ;; A tail that starts at a split entry takes all of it.
      (multiple-value-bind (text) (log-file-pieces path :tail-lines 10)
        (is (equal (gr8s.apiserver::format-pod-logs raw :tail-lines 10)
                   (gr8s.apiserver::format-pod-logs text :tail-lines 10))))
      (is (equal "" (log-file-pieces path :tail-lines 0)))
      (is (equal raw (log-file-pieces path :tail-lines 30000)))
      ;; A time is found by bisecting, and at most a piece more is read.
      (let ((since (gr8s.kubelet::pod-deletion-time "2026-11-04T13:00:00Z")))
        (multiple-value-bind (text sizes) (log-file-pieces path :since since)
          (is (< (reduce #'+ sizes) (+ (- size (search "2026-11-04T13:00:00" raw)) gr8s.runtime::+log-piece-bytes+ 200)))
          (is (equal (gr8s.apiserver::format-pod-logs raw :since since)
                     (gr8s.apiserver::format-pod-logs text :since since)))))
      ;; A follow goes on from its offset; one past the end means the file was replaced.
      (multiple-value-bind (text sizes offsets) (log-file-pieces path :start-offset (- size 10))
        (declare (ignore sizes))
        (is (equal (subseq raw (- (length raw) 10)) text))
        (is (equal (list (- size 10)) offsets)))
      (multiple-value-bind (text sizes offsets) (log-file-pieces path :start-offset size)
        (is (equal "" text))
        (is (equal '(0) sizes))
        (is (equal (list size) offsets)))
      (is (zerop (first (nth-value 2 (log-file-pieces path :start-offset (1+ size)))))))))

(test a-missing-log-file-is-sent-as-nothing
  (multiple-value-bind (text sizes offsets end)
      (log-file-pieces (merge-pathnames "no-such-gr8s-log.log" (uiop:temporary-directory)))
    (is (equal "" text))
    (is (equal '(0) sizes))
    (is (equal '(0) offsets))
    (is (zerop end))))

(defun chunked-log-sender (raw piece-size &optional (counter (constantly nil)))
  "An encapsulation of RECONCILER-SEND-LOGS that sends RAW PIECE-SIZE bytes at a time."
  (lambda (f reconciler uid container function &key (start-offset 0) &allow-other-keys)
    (declare (ignore f reconciler uid container))
    (let ((bytes (trivial-utf-8:string-to-utf-8-bytes raw)))
      (loop for start from (min start-offset (length bytes)) below (length bytes) by piece-size
            do (funcall counter)
               (funcall function (subseq bytes start (min (length bytes) (+ start piece-size))) start))
      (length bytes))))

(defun streamed-pod-logs (raw piece-size &rest options)
  "SEND-POD-LOGS's text and values for RAW, sent PIECE-SIZE bytes at a time."
  (sb-int:encapsulate 'gr8s.kubelet::reconciler-send-logs 'chunked (chunked-log-sender raw piece-size))
  (unwind-protect
       (let ((text (make-string-output-stream)))
         (multiple-value-bind (offset limited)
             (apply #'gr8s.apiserver::send-pod-logs nil (gr8s.model::make-pod :uid "uid") "main"
                    (lambda (string) (write-string string text)) options)
           (values (get-output-stream-string text) offset limited)))
    (sb-int:unencapsulate 'gr8s.kubelet::reconciler-send-logs 'chunked)))

(test streamed-logs-read-as-the-whole-log-would
  (let ((cutoff (gr8s.kubelet::pod-deletion-time "2026-11-04T08:00:02Z"))
        (snowman (format nil "2026-11-04T08:00:00Z stdout F ab~A~%2026-11-04T08:00:01Z stdout F cd~%" (code-char #x2603))))
    ;; Pieces split lines, and characters, anywhere.
    (dolist (size '(1 3 7 64 65536))
      (dolist (options (list nil '(:tail-lines 2) '(:tail-lines 0) '(:tail-lines 99) '(:timestamps t)
                             (list :since cutoff) '(:limit-bytes 3) '(:limit-bytes 9)))
        (is (equal (apply #'gr8s.apiserver::format-pod-logs *cri-log* options)
                   (apply #'streamed-pod-logs *cri-log* size options))
            "~S in pieces of ~D" options size))
      (is (equal (gr8s.apiserver::format-pod-logs snowman :limit-bytes 5)
                 (streamed-pod-logs snowman size :limit-bytes 5))))
    (is (equal (gr8s.apiserver::format-pod-logs "plain bytes") (streamed-pod-logs "plain bytes" 4)))))

(test streamed-logs-stop-reading-at-their-limit
  (let ((raw (format nil "~{2026-11-04T08:00:00Z stdout F line ~D~%~}" (loop for index below 1000 collect index)))
        (pieces 0))
    (sb-int:encapsulate 'gr8s.kubelet::reconciler-send-logs 'chunked
                        (chunked-log-sender raw 64 (lambda () (incf pieces))))
    (unwind-protect
         (multiple-value-bind (offset limited)
             (gr8s.apiserver::send-pod-logs nil (gr8s.model::make-pod :uid "uid") "main" (constantly nil) :limit-bytes 10)
           (declare (ignore offset))
           (is-true limited)
           ;; Ten bytes are two lines, which two pieces hold, of a thousand lines.
           (is (= 2 pieces)))
      (sb-int:unencapsulate 'gr8s.kubelet::reconciler-send-logs 'chunked))))

(test a-follow-goes-on-after-the-last-whole-line
  ;; An unfinished line waits for its end, and the next pass begins with it.
  (let ((raw (format nil "2026-11-04T08:00:00Z stdout F one~%2026-11-04T08:00:01Z stdout F tw")))
    (multiple-value-bind (text offset) (streamed-pod-logs raw 5 :last-line nil)
      (is (equal (format nil "one~%") text))
      (is (= (1+ (position #\Newline raw)) offset)))
    (multiple-value-bind (text offset) (streamed-pod-logs raw 5)
      (is (equal (format nil "one~%tw~%") text))
      (is (= (length raw) offset)))))

(test logs-stream-over-http-as-they-are-read
  (with-core-api (store path)
    (values path)
    (create-pod store (parse-pod *valid-pod-json*))
    (sb-int:encapsulate 'gr8s.kubelet::reconciler-send-logs 'chunked (chunked-log-sender *cri-log* 5))
    (unwind-protect
         (flet ((logs (query)
                  (multiple-value-bind (body status)
                      (drakma:http-request (core-api-url (format nil "/api/v1/namespaces/default/pods/hello/log~A" query)))
                    ;; An empty body comes as octets, which trivial-utf-8 can't decode.
                    (values (if (stringp body) body (map 'string #'code-char body)) status))))
           (multiple-value-bind (body status) (logs "")
             (is (= 200 status))
             (is (equal (gr8s.apiserver::format-pod-logs *cri-log*) body)))
           (is (equal (format nil "last line~%") (logs "?tailLines=1")))
           (is (equal "fir" (logs "?limitBytes=3")))
           ;; Nothing selected is still an answer.
           (multiple-value-bind (body status) (logs "?tailLines=0")
             (is (= 200 status))
             (is (equal "" body))))
      (sb-int:unencapsulate 'gr8s.kubelet::reconciler-send-logs 'chunked))))

(test a-log-past-its-size-is-rotated-and-the-newest-kept
  ;; A container's log grew without bound, to 471 MB in a day and a half (podster-xps).
  (let ((directory (uiop:ensure-directory-pathname
                    (merge-pathnames (format nil "gr8s-rotate-~36R/" (random (expt 36 8))) (uiop:temporary-directory)))))
    (ensure-directories-exist directory)
    (unwind-protect
         (let ((path (merge-pathnames "main.log" directory))
               (reopened 0))
           (flet ((grow (bytes)
                    (with-open-file (out path :direction :output :if-exists :append :if-does-not-exist :create)
                      (write-string (make-string bytes :initial-element #\x) out)))
                  (reopen ()
                    (incf reopened)
                    (with-open-file (out path :direction :output :if-does-not-exist :create) (declare (ignore out)))))
             (grow 100)
             (is-false (gr8s.runtime:rotate-log-file path #'reopen :max-bytes 100 :max-files 3))
             (is (zerop reopened))
             (dotimes (index 4)
               (grow 101)
               (is-true (gr8s.runtime:rotate-log-file path #'reopen :max-bytes 100 :max-files 3)))
             (is (= 4 reopened))
             ;; The file being written and the two newest rotated ones.
             (is (= 2 (length (gr8s.runtime::rotated-log-files path))))
             (is (probe-file path))
             ;; A writer that can't begin a new file keeps the one it has.
             (grow 101)
             (signals error (gr8s.runtime:rotate-log-file path (lambda () (error "no reopen")) :max-bytes 100 :max-files 3))
             (is (= 101 (with-open-file (in path) (file-length in))))))
      (uiop:delete-directory-tree directory :validate t :if-does-not-exist :ignore))))
