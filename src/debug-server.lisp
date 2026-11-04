;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Offer an opt-in Slynk server for inspecting a running control plane. It is
;;;; arbitrary root code execution, so it starts only with an explicit port, binds
;;;; to loopback and always requires a fresh secret. Slynk alone skips
;;;; authentication when ~/.sly-secret is absent, and hostNetwork Pods share
;;;; loopback. A process modified through this server is not conformance evidence.

(in-package #:gr8s)

(defvar *debug-store* nil "The live store of the process running a debug server.")
(defvar *debug-reconciler* nil "The live reconciler of the process running a debug server.")

(defun debug-secret-path (state-directory)
  "Return the private file a local client reads the session secret from.
It needs a file type, since atomic renames merge a missing one from the temporary file."
  (merge-pathnames "debug/slynk.secret" (uiop:ensure-directory-pathname state-directory)))

(defun generate-debug-secret ()
  "Return 256 random bits as hex text."
  (format nil "~(~{~2,'0X~}~)" (coerce (secure-random-octets 32) 'list)))

(defvar *slynk-accept-connections* nil "Slynk's original connection acceptor.")
(defvar *slynk-authenticate-client* nil "Slynk's original client authentication.")

(defun guard-slynk-connections ()
  "Keep a failed client from ending the accept loop, or the process with it.
Slynk lets authentication errors escape its accept thread into the debugger, so
anyone able to connect could otherwise stop the server by sending a wrong secret."
  (unless *slynk-accept-connections*
    (setf *slynk-accept-connections* (symbol-function 'slynk::accept-connections)
          *slynk-authenticate-client* (symbol-function 'slynk::authenticate-client)
          (symbol-function 'slynk::authenticate-client)
          (lambda (stream)
            (handler-bind ((error (lambda (condition)
                                    (declare (ignore condition))
                                    (ignore-errors (close stream :abort t)))))
              (funcall *slynk-authenticate-client* stream)))
          (symbol-function 'slynk::accept-connections)
          (lambda (socket style dont-close)
            (handler-case (funcall *slynk-accept-connections* socket style dont-close)
              (error (condition)
                (format *error-output* "gr8s rejected a debug client: ~A~%" condition)))))))

(defun install-debug-secret (state-directory)
  "Persist a new secret and make Slynk require it, regardless of any home directory file."
  (let ((secret (generate-debug-secret)) (path (debug-secret-path state-directory)))
    (ensure-directories-exist path)
    (write-private-text-atomically path secret)
    (setf (symbol-function 'slynk::sly-secret) (lambda () secret))
    secret))

(defun start-debug-server (port state-directory &key store reconciler)
  "Start an authenticated, loopback-only Slynk server on PORT, returning the bound port."
  (install-debug-secret state-directory)
  (guard-slynk-connections)
  (setf *debug-store* store *debug-reconciler* reconciler)
  (let ((bound (slynk:create-server :port port :interface "127.0.0.1" :style :spawn :dont-close t)))
    (format *error-output* "gr8s WARNING: debug Slynk server on 127.0.0.1:~D allows root code execution; ~
                            this process is not valid conformance evidence~%" bound)
    bound))

(defun stop-debug-server (port)
  "Stop the debug server and forget the live objects it exposed."
  (slynk:stop-server port)
  (setf *debug-store* nil *debug-reconciler* nil))

(defun debug-eval (text)
  "Evaluate one form from TEXT in this package, returning its printed output and value.
Errors come back as text with a backtrace, so a client never lands in a debugger."
  (let ((*package* (find-package '#:gr8s)))
    (with-output-to-string (*standard-output*)
      (block evaluation
        (handler-bind
            ((error (lambda (condition)
                      (format t "ERROR: ~A~%" condition)
                      (sb-debug:print-backtrace :count 30 :stream *standard-output*)
                      (return-from evaluation))))
          (format t "~{~S~%~}" (multiple-value-list (eval (read-from-string text)))))))))

(defun debug-threads ()
  "Return the name of every live thread."
  (sort (mapcar #'sb-thread:thread-name (sb-thread:list-all-threads))
        (lambda (left right) (string< (or left "") (or right "")))))

(defun debug-thread-backtrace (thread seconds)
  "Interrupt THREAD for its backtrace, or report it as unresponsive after SECONDS."
  (let ((done (sb-thread:make-semaphore)) (result nil))
    (handler-case
        (progn
          (sb-thread:interrupt-thread
           thread (lambda ()
                    (setf result (with-output-to-string (out)
                                   (sb-debug:print-backtrace :count 40 :stream out)))
                    (sb-thread:signal-semaphore done)))
          (if (sb-thread:wait-on-semaphore done :timeout seconds)
              result
              "(no answer: interrupts are disabled, for example inside a lock or foreign call)"))
      (sb-thread:interrupt-thread-error () "(thread exited)"))))

(defun debug-backtraces (&optional (name-filter "") (seconds 2))
  "Print a backtrace for each other thread whose name contains NAME-FILTER."
  (dolist (thread (sb-thread:list-all-threads))
    (let ((name (or (sb-thread:thread-name thread) "")))
      (when (and (not (eq thread sb-thread:*current-thread*)) (search name-filter name))
        (format t "=== ~A~%~A~%" name (debug-thread-backtrace thread seconds))))))

(defun debug-pod (namespace name)
  "Print a Pod's stored object with its observed, published and finalization state."
  (let* ((store *debug-store*)
         (pod (with-store-lock (store) (gethash (pod-key namespace name) (pod-store-pods store)))))
    (if (null pod)
        (format t "no Pod ~A/~A~%" namespace name)
        (let ((uid (pod-uid pod)))
          (with-store-lock (store)
            (format t "~A~%" (com.inuoe.jzon:stringify
                              (core-object
                               "object" (pod-to-object pod)
                               "statusRevision" (pod-status-revision pod)
                               "observed" (gethash uid (pod-store-pod-observed-statuses store) 'null)
                               "observedResourceVersion" (gethash uid (pod-store-pod-observed-resource-versions store) 'null)
                               "published" (gethash uid (pod-store-pod-published-statuses store) 'null)
                               "finalization" (gethash uid (pod-store-pod-finalization-states store) 'null))
                              :pretty t)))))))

(defun debug-journal (&optional (count 20))
  "Print the newest COUNT Pod watch events, newest first, with the journal's bounds."
  (let ((store *debug-store*))
    (with-store-lock (store)
      (format t "revision=~D floor=~D length=~D~%" (pod-store-pod-revision store)
              (pod-store-pod-watch-floor store) (pod-store-pod-watch-journal-length store))
      (loop for (revision old new) in (pod-store-pod-watch-journal store)
            repeat count
            do (let* ((view (or new old)) (metadata (gethash "metadata" view)))
                 (format t "~D ~A ~A/~A phase=~A~%" revision
                         (cond ((null old) "ADDED") ((null new) "DELETED") (t "MODIFIED"))
                         (gethash "namespace" metadata) (gethash "name" metadata)
                         (gethash "phase" (gethash "status" view (core-object)))))))))
