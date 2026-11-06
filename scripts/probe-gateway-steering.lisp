;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Privileged probe (root) for the Gateway sk_lookup steering MODULE
;;;; (src/gateway-sklookup.lisp, podster-43k.5). Proves the productionized,
;;;; multi-port form: two listeners bound on ports A/B, and the SOCKMAP steers two
;;;; *other* ports C/D onto them by destination port. Mirrors the original spike
;;;; but drives the real gr8s module, not inline code.
;;;;
;;;;   sudo sbcl --noinform --script scripts/probe-gateway-steering.lisp
;;;;
;;;; Exit 0 = all checks passed.

(require :asdf)
(require :sb-bsd-sockets)
(require :sb-posix)
(let ((project (truename (merge-pathnames "../" (uiop:pathname-directory-pathname *load-truename*)))))
  (asdf:initialize-source-registry
   `(:source-registry (:directory ,project) (:tree ,(merge-pathnames "ocicl/" project))
     :inherit-configuration)))
(handler-bind ((warning #'muffle-warning))
  (asdf:load-system :gr8s :verbose nil))

(in-package #:gr8s)

(sb-alien:define-alien-routine ("unshare" %unshare) sb-alien:int (flags sb-alien:int))
(defconstant +clone-newnet+ #x40000000)

(defvar *failures* 0)
(defun check (label got expected)
  (if (equal got expected)
      (format t "  ok   ~A -> ~S~%" label got)
      (progn (incf *failures*) (format t "  FAIL ~A -> got ~S, expected ~S~%" label got expected))))

(defun make-listener (port)
  (let ((s (make-instance 'sb-bsd-sockets:inet-socket :type :stream :protocol :tcp)))
    (setf (sb-bsd-sockets:sockopt-reuse-address s) t)
    (sb-bsd-sockets:socket-bind s #(127 0 0 1) port)
    (sb-bsd-sockets:socket-listen s 8)
    s))

(defun try-connect (port)
  (let ((s (make-instance 'sb-bsd-sockets:inet-socket :type :stream :protocol :tcp)))
    (unwind-protect
         (handler-case (sb-ext:with-timeout 3 (sb-bsd-sockets:socket-connect s #(127 0 0 1) port) t)
           (sb-bsd-sockets:connection-refused-error () nil)
           (sb-ext:timeout () nil))
      (ignore-errors (sb-bsd-sockets:socket-close s)))))

(defun accept-into (listener flag)
  (sb-thread:make-thread
   (lambda ()
     (ignore-errors
      (sb-ext:with-timeout 3
        (let ((peer (sb-bsd-sockets:socket-accept listener)))
          (when peer (setf (symbol-value flag) t) (sb-bsd-sockets:socket-close peer))))))))

(defun run ()
  (format t "~%=== Gateway sk_lookup steering module probe ===~%")
  (unless (zerop (%unshare +clone-newnet+)) (error "unshare(CLONE_NEWNET) failed (need root)"))
  (sb-ext:run-program "ip" '("link" "set" "lo" "up") :search t :wait t)
  (format t "fresh netns, lo up; steering supported: ~A~%" (gateway-steering-supported-p))
  (let ((la (make-listener 9001)) (lb (make-listener 9002))
        (steering nil))
    (defvar *a-accepted* nil) (defvar *b-accepted* nil)
    (unwind-protect
         (progn
           (check "baseline connect :8001 refused" (try-connect 8001) nil)
           (check "baseline connect :8002 refused" (try-connect 8002) nil)
           (setf steering (start-gateway-steering))
           (gateway-steering-register steering 8001 (sb-bsd-sockets:socket-file-descriptor la))
           (gateway-steering-register steering 8002 (sb-bsd-sockets:socket-file-descriptor lb))
           (format t "registered 8001->:9001, 8002->:9002~%")
           (setf *a-accepted* nil *b-accepted* nil)
           (let ((ta (accept-into la '*a-accepted*)))
             (check "connect :8001 steered (accepted)" (try-connect 8001) t)
             (ignore-errors (sb-thread:join-thread ta :timeout 3)))
           (let ((tb (accept-into lb '*b-accepted*)))
             (check "connect :8002 steered (accepted)" (try-connect 8002) t)
             (ignore-errors (sb-thread:join-thread tb :timeout 3)))
           (check "listener :9001 accepted the :8001 connection" *a-accepted* t)
           (check "listener :9002 accepted the :8002 connection" *b-accepted* t)
           ;; Unregister 8001; it should stop steering (refused again).
           (gateway-steering-unregister steering 8001)
           (check "after unregister, :8001 refused" (try-connect 8001) nil))
      (ignore-errors (when steering (stop-gateway-steering steering)))
      (ignore-errors (sb-bsd-sockets:socket-close la))
      (ignore-errors (sb-bsd-sockets:socket-close lb)))
    (format t "~%RESULT: ~:[ALL CHECKS PASSED~;~:*~D CHECK(S) FAILED~]~%"
            (when (plusp *failures*) *failures*))
    (sb-ext:exit :code (if (plusp *failures*) 1 0))))

(run)
