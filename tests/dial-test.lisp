;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Verify that a control plane reaches Pods through their node's agent: a real
;;;; agent session connects to a local server and carries its bytes both ways,
;;;; far past one credit window, TLS runs over the result as over a socket, and
;;;; the agent refuses an address that isn't one of its Pods.

(in-package #:gr8s/tests)
(def-suite dial :in gr8s)
(in-suite dial)

(defmacro with-dialing-agent ((runtime) &body body)
  "Run BODY with a real agent behind control-plane RUNTIME, which may dial loopback addresses."
  (let ((pod (gensym "POD")) (listener (gensym "LISTENER")) (saved (gensym "SAVED")))
    ;; Set, not bound: the agent checks the address on its own threads.
    `(let ((,saved gr8s.agent::*dial-address-allowed-call*))
       (setf gr8s.agent::*dial-address-allowed-call*
             (lambda (node-runtime address) (declare (ignore node-runtime)) (equal address "127.0.0.1")))
       (unwind-protect
            (with-forwarding-agent (,runtime ,pod ,listener)
              (values ,pod ,listener)
              ,@body)
         (setf gr8s.agent::*dial-address-allowed-call* ,saved)))))

(defun dial-test-exchange (stream octets)
  "Send OCTETS over STREAM from another thread, and read back as many."
  (let* ((sender (bt:make-thread (lambda ()
                                   (handler-case (progn (write-sequence octets stream) (finish-output stream) nil)
                                     (error (condition) condition)))
                                 :name "gr8s test dial sender"))
         (received (make-array (length octets) :element-type '(unsigned-byte 8))))
    (let ((count (read-sequence received stream)))
      (is (null (bt:join-thread sender)))
      (subseq received 0 count))))

(test node-dial-allows-only-the-nodes-pods-and-its-own-address
  (let ((node (gr8s.agent::%make-node-runtime)))
    (is-false (gr8s.agent::node-dial-address-allowed-p node "10.88.7.5") "no network yet, so nothing")
    (setf (gr8s.agent::node-runtime-network node)
          (gr8s.foundation:json-object "nodePodCIDRs" #("10.88.7.0/24" "fd00:88:7::/64")
                                       "underlayAddress" "192.168.1.20"))
    (is-true (gr8s.agent::node-dial-address-allowed-p node "10.88.7.5"))
    (is-true (gr8s.agent::node-dial-address-allowed-p node "fd00:88:7::12"))
    (is-true (gr8s.agent::node-dial-address-allowed-p node "192.168.1.20"))
    (is-false (gr8s.agent::node-dial-address-allowed-p node "10.88.8.5"))
    (is-false (gr8s.agent::node-dial-address-allowed-p node "127.0.0.1"))
    (is-false (gr8s.agent::node-dial-address-allowed-p node "169.254.169.254"))
    (is-false (gr8s.agent::node-dial-address-allowed-p node ""))))

(test a-dialled-connection-carries-bytes-both-ways-past-the-window
  (with-dialing-agent (runtime)
    (multiple-value-bind (listener thread) (start-echo-server)
      (declare (ignore thread))
      (let ((stream (gr8s.runtime:open-dial-stream runtime "worker-forward" "127.0.0.1"
                                                   (usocket:get-local-port listener))))
        (unwind-protect
             (progn
               (is (equalp (trivial-utf-8:string-to-utf-8-bytes "ping")
                           (dial-test-exchange stream (trivial-utf-8:string-to-utf-8-bytes "ping"))))
               (let ((octets (random-octets (* 3 gr8s.runtime::+port-forward-window-bytes+))))
                 (is (equalp octets (dial-test-exchange stream octets)))))
          (close stream)
          (ignore-errors (usocket:socket-close listener)))))))

(test the-agent-refuses-an-address-that-is-not-its-pods
  (with-forwarding-agent (runtime pod listener)
    (values pod listener)
    (let ((stream (gr8s.runtime:open-dial-stream runtime "worker-forward" "169.254.169.254" 80)))
      (unwind-protect
           (handler-case (progn (read-byte stream nil nil) (fail "the dial was not refused"))
             (gr8s.runtime:runtime-error (condition)
               (is (search "not an address of a Pod on this node" (princ-to-string condition)))))
        (close stream)))))

(test tls-requests-run-over-a-dialled-connection
  (with-dialing-agent (runtime)
    (let* ((root (uiop:ensure-directory-pathname
                  (sb-posix:mkdtemp (namestring (merge-pathnames "gr8s-dial-XXXXXX" (uiop:temporary-directory))))))
           (pki (gr8s.security::ensure-cluster-pki (merge-pathnames "pki/" root)))
           (dialled nil))
      (unwind-protect
           (multiple-value-bind (certificate key) (admission-test-credentials pki)
             (multiple-value-bind (listener stop)
                 (admission-test-backend certificate key
                                         (lambda (path request) (declare (ignore request))
                                           (admission-test-deny (format nil "reached ~A" path))))
               (unwind-protect
                    (multiple-value-bind (code headers body)
                        (gr8s.http-client:https-request
                         :host "127.0.0.1" :port (usocket:get-local-port listener)
                         :server-name "hook.alpha.svc" :method :post :target "/through-agent"
                         :body (trivial-utf-8:string-to-utf-8-bytes "{\"request\":{\"uid\":\"u1\"}}")
                         :trust-certificates (gr8s.resources::admission-ca-certificates
                                              (trivial-utf-8:string-to-utf-8-bytes
                                               (uiop:read-file-string
                                                (gr8s.security::cluster-pki-ca-certificate-path pki))))
                         :dial (lambda (address port timeout)
                                 (declare (ignore timeout))
                                 (setf dialled t)
                                 (gr8s.runtime:open-dial-stream runtime "worker-forward" address port)))
                      (declare (ignore headers))
                      (is-true dialled)
                      (is (= 200 code))
                      (is (search "reached /through-agent" (trivial-utf-8:utf-8-bytes-to-string body))))
                 (funcall stop))))
        (uiop:delete-directory-tree root :validate t :if-does-not-exist :ignore)))))

(defclass recording-dial-runtime () ((sends :initform nil :accessor recording-dial-runtime-sends)))
(defmethod gr8s.runtime:runtime-port-forward-send ((runtime recording-dial-runtime) session data &key eof)
  (declare (ignore session eof))
  (push (copy-seq data) (recording-dial-runtime-sends runtime)))

(test a-dialled-connection-sends-a-request-written-in-pieces-at-once
  ;; Each send is a frame, a round trip when another member relays it (podster-tjp).
  (let* ((runtime (make-instance 'recording-dial-runtime))
         (stream (make-instance 'gr8s.runtime::dial-stream :runtime runtime :session nil)))
    (dolist (piece '("GET" " " "/" " " "HTTP/1.1" (13 10) "Host: pod" (13 10) (13 10)))
      (if (stringp piece)
          (write-sequence (trivial-utf-8:string-to-utf-8-bytes piece) stream)
          (dolist (octet piece) (write-byte octet stream))))
    (is (null (recording-dial-runtime-sends runtime)))
    (finish-output stream)
    (is (equal (list (format nil "GET / HTTP/1.1~C~CHost: pod~C~C~C~C" #\Return #\Linefeed
                             #\Return #\Linefeed #\Return #\Linefeed))
               (mapcar #'trivial-utf-8:utf-8-bytes-to-string (recording-dial-runtime-sends runtime))))
    ;; A large write still goes without waiting to be asked.
    (write-sequence (make-array (* 2 gr8s.runtime::+dial-stream-buffer-bytes+)
                                :element-type '(unsigned-byte 8) :initial-element 65)
                    stream)
    (is (= 2 (length (recording-dial-runtime-sends runtime))))))
