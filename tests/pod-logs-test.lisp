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
      (sb-int:encapsulate 'gr8s.kubelet::reconciler-logs 'canned (lambda (f &rest arguments) (declare (ignore f arguments)) raw))
      (unwind-protect
           (multiple-value-bind (status headers body)
               (websocket-handshake "/api/v1/namespaces/default/pods/hello/log" "binary.k8s.io")
             (is (search "101" status))
             (is (search "binary.k8s.io" headers))
             (multiple-value-bind (opcode payload) (first-websocket-payload body)
               (is (= 2 opcode))
               (is (equal (format nil "container is alive~%") (trivial-utf-8:utf-8-bytes-to-string payload)))))
        (sb-int:unencapsulate 'gr8s.kubelet::reconciler-logs 'canned)))))

(test logs-refuse-an-unknown-websocket-protocol
  (with-core-api (store path)
    (values path)
    (create-pod store (parse-pod *valid-pod-json*))
    (sb-int:encapsulate 'gr8s.kubelet::reconciler-logs 'canned (lambda (f &rest arguments) (declare (ignore f arguments)) ""))
    (unwind-protect
         (is (search "400" (websocket-handshake "/api/v1/namespaces/default/pods/hello/log" "unknown.example")))
      (sb-int:unencapsulate 'gr8s.kubelet::reconciler-logs 'canned))))

(test invalid-log-options-are-refused
  (with-core-api (store path)
    (values path)
    (create-pod store (parse-pod *valid-pod-json*))
    (sb-int:encapsulate 'gr8s.kubelet::reconciler-logs 'canned (lambda (f &rest arguments) (declare (ignore f arguments)) ""))
    (unwind-protect
         (dolist (query '("tailLines=-1" "tailLines=x" "limitBytes=0" "sinceSeconds=0" "sinceTime=yesterday"
                          "sinceSeconds=5&sinceTime=2026-01-01T00:00:00Z"))
           (is (= 400 (nth-value 1 (drakma:http-request
                                    (core-api-url (format nil "/api/v1/namespaces/default/pods/hello/log?~A" query)))))
               query))
      (sb-int:unencapsulate 'gr8s.kubelet::reconciler-logs 'canned))))

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

