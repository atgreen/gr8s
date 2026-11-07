;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; HTTP/1.1 framing shared by runtime streaming protocols.

(in-package #:gr8s.protocol)

(defun parse-runtime-stream-url (url)
  "Split a containerd streaming URL into (values HOST PORT TARGET)."
  (let ((prefix "http://"))
    (unless (and (>= (length url) (length prefix))
                 (string-equal prefix url :end2 (length prefix)))
      (error 'runtime-error :message "containerd returned a non-HTTP streaming URL"))
    (let* ((authority-start (length prefix))
           (target-start (or (position #\/ url :start authority-start) (length url)))
           (authority (subseq url authority-start target-start))
           (colon (position #\: authority :from-end t))
           (host (and colon (subseq authority 0 colon)))
           (port-text (and colon (subseq authority (1+ colon))))
           (target (if (< target-start (length url)) (subseq url target-start) "/")))
      (unless (and host
                   (member host '("127.0.0.1" "localhost" "[::1]") :test #'string-equal)
                   (plusp (length port-text)))
        (error 'runtime-error :message "containerd returned a non-loopback streaming URL"))
      (let ((port (parse-integer port-text :junk-allowed t)))
        (unless (and port (<= 1 port 65535))
          (error 'runtime-error :message "containerd returned an invalid streaming port"))
        (values host port target)))))

(defun ascii-octets (string)
  "Return STRING's characters as a vector of their byte codes."
  (let ((octets (make-array (length string) :element-type '(unsigned-byte 8))))
    (loop for character across string
          for index from 0
          do (setf (aref octets index) (char-code character)))
    octets))

(defun octets-as-ascii (octets)
  "Return OCTETS as a string, one character per byte."
  (map 'string #'code-char octets))

(defun read-http-response-head (stream)
  "Read and return the octets through an HTTP response's terminating blank line."
  (let ((head (make-array 512 :element-type '(unsigned-byte 8)
                          :adjustable t :fill-pointer 0))
        (state 0))
    (loop
      (let ((octet (read-byte stream nil nil)))
        (unless octet
          (error 'runtime-error :message "containerd closed the exec stream before replying"))
        (vector-push-extend octet head)
        (setf state
              (case state
                (0 (if (= octet 13) 1 0))
                (1 (cond ((= octet 10) 2) ((= octet 13) 1) (t 0)))
                (2 (if (= octet 13) 3 0))
                (3 (if (= octet 10) 4 0))))
        (when (= state 4) (return head))
        (when (> (length head) 65536)
          (error 'runtime-error :message "containerd returned oversized exec headers"))))))

(defun trim-http-line (line)
  "Return LINE without its trailing carriage return or line feed."
  (string-right-trim '(#\Return #\Linefeed) line))

(defun parse-http-response-head (octets)
  "Parse OCTETS into (values STATUS-CODE HEADERS)."
  (with-input-from-string (input (octets-as-ascii octets))
    (let* ((status-line (trim-http-line (or (read-line input nil) "")))
           (first-space (position #\Space status-line))
           (second-space (and first-space
                              (position #\Space status-line :start (1+ first-space))))
           (status (and first-space
                        (parse-integer status-line :start (1+ first-space)
                                      :end second-space :junk-allowed t)))
           (headers nil))
      (unless status
        (error 'runtime-error :message "containerd returned an invalid exec response"))
      (loop for raw = (read-line input nil nil)
            while raw
            for line = (trim-http-line raw)
            until (zerop (length line))
            do (let ((colon (position #\: line)))
                 (when colon
                   (push (cons (intern (string-upcase (subseq line 0 colon)) :keyword)
                               (string-trim '(#\Space #\Tab) (subseq line (1+ colon))))
                         headers))))
      (values status (nreverse headers)))))
