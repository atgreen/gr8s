;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Verify the debug server stays off by default, always requires a fresh private
;;;; secret over a real socket even with no ~/.sly-secret, and evaluates forms
;;;; without ever leaving a remote client in a debugger.

(in-package #:gr8s/tests)
(def-suite debug-server :in gr8s)
(in-suite debug-server)

(defun slynk-frame (text)
  "Encode TEXT as one length-prefixed Slynk protocol message."
  (let ((payload (trivial-utf-8:string-to-utf-8-bytes text)))
    (concatenate '(vector (unsigned-byte 8))
                 (trivial-utf-8:string-to-utf-8-bytes (format nil "~(~6,'0X~)" (length payload)))
                 payload)))

(defun slynk-read-frame (stream)
  "Read one message from STREAM, returning NIL once the server closes the connection."
  (let ((header (make-array 6 :element-type '(unsigned-byte 8))))
    (when (= 6 (read-sequence header stream))
      (let ((payload (make-array (parse-integer (trivial-utf-8:utf-8-bytes-to-string header) :radix 16)
                                 :element-type '(unsigned-byte 8))))
        (read-sequence payload stream)
        (trivial-utf-8:utf-8-bytes-to-string payload)))))

(defun slynk-exchange (port &key secret (form "(+ 1 2)"))
  "Connect, optionally authenticate, request FORM, and return the frames received until close or reply."
  (let* ((socket (usocket:socket-connect "127.0.0.1" port :element-type '(unsigned-byte 8)))
         (stream (usocket:socket-stream socket)))
    (unwind-protect
         (sb-sys:with-deadline (:seconds 10)
           (handler-case
               (progn
                 (when secret
                   (write-sequence (slynk-frame secret) stream)
                   (finish-output stream))
                 (write-sequence (slynk-frame (format nil "(:emacs-rex (gr8s::debug-eval ~S) \"GR8S\" t 1)" form)) stream)
                 (finish-output stream)
                 (loop for frame = (slynk-read-frame stream)
                       while frame
                       collect frame into frames
                       when (uiop:string-prefix-p "(:return " frame)
                         return frames
                       finally (return frames)))
             (stream-error () nil)
             (usocket:socket-error () nil)))
      (usocket:socket-close socket))))

(defmacro with-debug-server ((port secret directory) &body body)
  "Run BODY with a real debug server on PORT, restoring Slynk's original secret function."
  (let ((original (gensym "ORIGINAL")))
    `(with-temporary-store (store ,directory)
       (let ((,original (symbol-function 'slynk::sly-secret)))
         (unwind-protect
              (let* ((,port (gr8s::start-debug-server 0 ,directory :store store))
                     (,secret (uiop:read-file-string (gr8s::debug-secret-path ,directory))))
                (unwind-protect (progn ,@body)
                  (gr8s::stop-debug-server ,port)))
           (setf (symbol-function 'slynk::sly-secret) ,original))))))

(test debug-server-is-off-unless-a-port-is-requested
  (is (null (getf (parse-cli-options '("serve")) :debug-slynk-port)))
  (is (= 4105 (getf (parse-cli-options '("serve" "--debug-slynk-port" "4105")) :debug-slynk-port)))
  (signals error (parse-cli-options '("serve" "--debug-slynk-port" "nope"))))

(test each-start-writes-a-new-private-secret
  (with-temporary-store (store directory)
    (declare (ignorable store))
    (let ((original (symbol-function 'slynk::sly-secret)))
      (unwind-protect
           (let* ((first (gr8s::install-debug-secret directory))
                  (path (gr8s::debug-secret-path directory))
                  (mode (logand #o777 (sb-posix:stat-mode (sb-posix:stat (namestring path))))))
             (is (= 64 (length first)))
             (is (every (lambda (character) (digit-char-p character 16)) first))
             (is (= #o600 mode))
             (is (equal first (uiop:read-file-string path)))
             (is (equal first (slynk::sly-secret)))
             (is (not (equal first (gr8s::install-debug-secret directory)))))
        (setf (symbol-function 'slynk::sly-secret) original)))))

(test clients-must-present-the-secret-on-a-real-socket
  (with-debug-server (port secret directory)
    (values directory)
    ;; This is the case Slynk alone leaves open when no ~/.sly-secret exists.
    (is (notany (lambda (frame) (search ":ok" frame)) (slynk-exchange port)))
    (is (notany (lambda (frame) (search ":ok" frame)) (slynk-exchange port :secret "wrong")))
    ;; Rejections leave the server accepting; only the right secret evaluates.
    (dotimes (attempt 3)
      (is (notany (lambda (frame) (search ":ok" frame)) (slynk-exchange port :secret "wrong"))))
    (let* ((hook sb-ext:*invoke-debugger-hook*)
           (frames (slynk-exchange port :secret secret)))
      (is (some (lambda (frame) (and (search ":ok" frame) (search "3" frame))) frames))
      ;; A connected client must leave process-wide error handling alone.
      (is (eq hook sb-ext:*invoke-debugger-hook*)))))

(test the-server-binds-to-loopback-only
  (with-debug-server (port secret directory)
    (values secret directory)
    (let ((listening (with-open-file (in "/proc/net/tcp")
                       (loop for line = (read-line in nil) while line
                             when (search (format nil ":~4,'0X " port) line) collect line))))
      (is (plusp (length listening)))
      ;; Little-endian 127.0.0.1 in the local-address column.
      (is (every (lambda (line) (search "0100007F:" line)) listening)))))

(test debug-eval-returns-text-and-never-enters-a-debugger
  (is (equal (format nil "3~%") (gr8s::debug-eval "(+ 1 2)")))
  (is (search "printed" (gr8s::debug-eval "(progn (princ \"printed\") nil)")))
  (let ((failure (gr8s::debug-eval "(error \"boom ~A\" 1)")))
    (is (uiop:string-prefix-p "ERROR: boom 1" failure))
    (is (search "DEBUG-EVAL" failure)))
  (is (uiop:string-prefix-p "ERROR: " (gr8s::debug-eval "(unclosed"))))

(test debug-helpers-read-live-state
  (with-temporary-store (store directory)
    (declare (ignorable directory))
    (let ((gr8s::*debug-store* store)
          (pod (create-pod store (parse-pod *valid-pod-json*))))
      (is (member "main thread" (gr8s::debug-threads) :test #'equal))
      (let ((text (gr8s::debug-eval "(debug-pod \"default\" \"hello\")")))
        (is (search (pod-uid pod) text))
        (is (search "\"observed\"" text)))
      (is (search "no Pod" (gr8s::debug-eval "(debug-pod \"default\" \"missing\")")))
      (is (search "ADDED default/hello" (gr8s::debug-eval "(debug-journal)")))
      ;; Output stays machine-readable: no trailing printed value.
      (is (com.inuoe.jzon:parse (gr8s::debug-eval "(debug-pod \"default\" \"hello\")"))))))

(test thread-backtraces-come-back-even-from-a-blocked-thread
  (let* ((gate (sb-thread:make-semaphore))
         (thread (sb-thread:make-thread (lambda () (sb-thread:wait-on-semaphore gate)) :name "gr8s-blocked-for-test")))
    (sleep 0.5) ; Let the new thread reach its wait before interrupting it.
    (unwind-protect
         (let ((text (gr8s::debug-eval "(debug-backtraces \"gr8s-blocked-for-test\")")))
           (is (search "gr8s-blocked-for-test" text))
           (is (search "WAIT-ON-SEMAPHORE" (string-upcase text))))
      (sb-thread:signal-semaphore gate)
      (sb-thread:join-thread thread))))
