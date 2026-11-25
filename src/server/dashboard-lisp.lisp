;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; The REPL tab of `gr8s dashboard': ICL's browser REPL, connected to a running
;;;; gr8s process -- a control-plane member or a node's agent -- as `gr8s debug icl'
;;;; connects it, shown in the tab. The dashboard opens the same authenticated Slynk
;;;; tunnel through the cluster API, starts ICL on this machine (`icl -b --lisp sbcl
;;;; --connect'), and frames ICL's page, which `--embed-origin' lets this dashboard's
;;;; origin frame. A session outlives the page that shows it; it ends on Disconnect,
;;;; when its tunnel closes, or with the dashboard.

(in-package #:gr8s.server)

(defparameter +dashboard-lisp-html+ #.(dashboard-agent-asset-text "dashboard-lisp.html"))

(defstruct (lisp-session (:constructor %make-lisp-session (target)))
  "ICL connected to TARGET, (kind name), through a Slynk tunnel."
  target url process listener remote remote-socket
  (lock (bt:make-lock "gr8s dashboard lisp session")))

(defstruct (dashboard-lisp (:constructor make-dashboard-lisp
                               (config &key (icl (dashboard-find-program "icl"))
                                            (start #'start-lisp-session))))
  "The REPL tab: the cluster it reaches, ICL, and the sessions running."
  config icl
  ;; (dashboard-lisp target origin) -> a started LISP-SESSION, or an error.
  start
  (sessions nil)
  (lock (bt:make-lock "gr8s dashboard lisp")))

(defun icl-embeds-p (icl)
  "Whether ICL takes --embed-origin, which a dashboard needs to frame it."
  (and icl (search "--embed-origin"
                   (ignore-errors (uiop:run-program (list icl "--help") :output :string :error-output nil
                                                                        :ignore-error-status t)))))

(defun icl-browser-url (line)
  "The browser URL ICL announces on LINE (\"Direct your browser to URL\"), or NIL."
  (multiple-value-bind (start end) (cl-ppcre:scan "http://127\\.0\\.0\\.1:[0-9]+/icl/[A-Za-z0-9]+" line)
    (and start (subseq line start end))))

(defun icl-arguments (port origin)
  "ICL's command line, after the program, to show a REPL on Slynk at PORT in a frame on ORIGIN.
SBCL, whatever the reader's ICL configuration names: with --connect ICL starts no Lisp of its
own, and if it ever did, it would be the one gr8s runs on."
  (list "-b" "--no-open" "--no-banner" "--lisp" "sbcl" "--embed-origin" origin
        "--connect" (format nil "127.0.0.1:~D" port)))

(defun lisp-target-path (target)
  (destructuring-bind (kind name) target
    (format nil "/apis/gr8s.io/v1/~A/~A/slynk" (if (equal kind "member") "controlplanemembers" "nodes") name)))

(defun stop-lisp-session (session)
  (with-slots (process listener remote remote-socket) session
    (when process (ignore-errors (sb-ext:process-kill process sb-unix:sigterm)))
    (when listener (ignore-errors (usocket:socket-close listener)))
    (when remote
      (ignore-errors (gr8s.protocol::write-websocket-frame
                      remote 8 (make-array 2 :element-type '(unsigned-byte 8) :initial-contents '(3 232)) :masked-p t))
      (ignore-errors (close remote)))
    (when remote-socket (ignore-errors (usocket:socket-close remote-socket)))))

(defun start-lisp-session (lisp target origin)
  "Open a Slynk tunnel to TARGET and start ICL on it for a frame on ORIGIN; return the
session once ICL has said where its page is."
  (let* ((session (%make-lisp-session target))
         (config (dashboard-lisp-config lisp))
         (write-lock (bt:make-lock "gr8s dashboard lisp tunnel")))
    (handler-bind ((error (lambda (condition) (declare (ignore condition)) (stop-lisp-session session))))
      (multiple-value-bind (remote remote-socket) (open-debug-websocket config (lisp-target-path target))
        (setf (lisp-session-remote session) remote (lisp-session-remote-socket session) remote-socket
              (lisp-session-listener session) (usocket:socket-listen "127.0.0.1" 0 :reuse-address t
                                                                                  :element-type '(unsigned-byte 8))))
      ;; ICL's one connection, relayed through the tunnel until either side ends.
      (bt:make-thread
       (lambda ()
         (let ((local-socket (ignore-errors (usocket:socket-accept (lisp-session-listener session)))))
           (ignore-errors (usocket:socket-close (lisp-session-listener session)))
           (when local-socket
             (let ((local (usocket:socket-stream local-socket)))
               (bt:make-thread (lambda ()
                                 (ignore-errors (relay-local-slynk-to-websocket local (lisp-session-remote session) write-lock))
                                 (ignore-errors (usocket:socket-shutdown (lisp-session-remote-socket session) :io)))
                               :name "gr8s dashboard lisp local")
               (ignore-errors (relay-websocket-to-local-slynk (lisp-session-remote session) local write-lock))
               (ignore-errors (usocket:socket-close local-socket))))
           ;; The tunnel is gone, and with it the session.
           (stop-lisp-session session)
           (bt:with-lock-held ((dashboard-lisp-lock lisp))
             (setf (dashboard-lisp-sessions lisp) (remove session (dashboard-lisp-sessions lisp))))))
       :name "gr8s dashboard lisp tunnel")
      (let* ((process (sb-ext:run-program (dashboard-lisp-icl lisp)
                                          (icl-arguments (usocket:get-local-port (lisp-session-listener session)) origin)
                                          :wait nil :input nil :output :stream :error :output
                                          :directory (uiop:getcwd)))
             (found nil) (lock (bt:make-lock)) (changed (bt:make-condition-variable)))
        (setf (lisp-session-process session) process)
        ;; ICL's output, read to the end so it never waits on us; its URL is in it.
        (bt:make-thread
         (lambda ()
           (ignore-errors
            (loop for line = (read-line (sb-ext:process-output process) nil)
                  while line
                  do (let ((url (icl-browser-url line)))
                       (when url
                         (bt:with-lock-held (lock) (setf found url) (bt:condition-notify changed))))))
           (bt:with-lock-held (lock) (bt:condition-notify changed)))
         :name "gr8s dashboard icl output")
        (bt:with-lock-held (lock)
          (loop with deadline = (+ (get-internal-real-time) (* 60 internal-time-units-per-second))
                until (or found (not (sb-ext:process-alive-p process))
                          (> (get-internal-real-time) deadline))
                do (bt:condition-wait changed lock :timeout 1)))
        (unless found
          (error "ICL did not start its browser interface~:[; it exited~;~]."
                 (sb-ext:process-alive-p process)))
        (setf (lisp-session-url session) found)
        session))))

(defun stop-dashboard-lisp (lisp)
  "End every ICL session the tab started."
  (mapc #'stop-lisp-session (bt:with-lock-held ((dashboard-lisp-lock lisp)) (dashboard-lisp-sessions lisp))))

(defun dashboard-lisp-targets (lisp)
  "The processes the tab can connect to: control-plane members, then nodes."
  (let ((config (dashboard-lisp-config lisp)) (targets nil))
    (multiple-value-bind (body status)
        (ignore-errors (debug-api-request-json config "GET" "/apis/gr8s.io/v1/controlplanemembers"))
      (when (eql status 200)
        (loop for item across (gethash "items" body #())
              unless (equal "witness" (gethash "role" (gethash "spec" item)))
                do (push (gr8s-diagnose::object "kind" "member" "name" (gethash "name" (gethash "metadata" item))
                                                "leader" (eq t (gethash "leader" (gethash "status" item))))
                         targets))))
    (multiple-value-bind (body status) (ignore-errors (debug-api-request-json config "GET" "/api/v1/nodes"))
      (when (eql status 200)
        (loop for node across (gethash "items" body #())
              do (push (gr8s-diagnose::object "kind" "node" "name" (gethash "name" (gethash "metadata" node))) targets))))
    (coerce (nreverse targets) 'vector)))

(defun dashboard-lisp-dispatch (lisp base request)
  "Serve the REPL tab under BASE, /lisp/<token>/."
  (let ((rest (subseq (hunchentoot:script-name request) (min (length base) (length (hunchentoot:script-name request))))))
    (setf (hunchentoot:header-out :cache-control) "no-store")
    (flet ((json (status value)
             (setf (hunchentoot:return-code*) status (hunchentoot:content-type*) "application/json")
             (com.inuoe.jzon:stringify value))
           (session-object (session)
             (gr8s-diagnose::object "kind" (first (lisp-session-target session))
                                    "name" (second (lisp-session-target session))
                                    "url" (lisp-session-url session)))
           (sessions () (bt:with-lock-held ((dashboard-lisp-lock lisp)) (copy-list (dashboard-lisp-sessions lisp)))))
      (cond
        ((member rest '("" "index.html") :test #'equal)
         (setf (hunchentoot:content-type*) "text/html; charset=utf-8"
               (hunchentoot:header-out :referrer-policy) "no-referrer")
         +dashboard-lisp-html+)
        ((equal rest "targets")
         (json 200 (gr8s-diagnose::object "icl" (and (dashboard-lisp-icl lisp) t)
                                          "embeds" (and (icl-embeds-p (dashboard-lisp-icl lisp)) t)
                                          "targets" (dashboard-lisp-targets lisp)
                                          "sessions" (coerce (mapcar #'session-object (sessions)) 'vector))))
        ((member rest '("connect" "disconnect") :test #'equal)
         (let* ((kind (hunchentoot:get-parameter "kind" request))
                (name (hunchentoot:get-parameter "name" request))
                (target (list kind name))
                (running (find target (sessions) :key #'lisp-session-target :test #'equal)))
           (cond ((not (eq :post (hunchentoot:request-method request)))
                  (json 405 (gr8s-diagnose::object "error" "POST it")))
                 ;; Only this dashboard's page may start or stop a REPL.
                 ((not (dashboard-agent-same-origin-p request))
                  (json 403 (gr8s-diagnose::object "error" "a REPL starts only from the dashboard's own page")))
                 ((not (and (member kind '("member" "node") :test #'equal) (stringp name) (dns-subdomain-p name)))
                  (json 400 (gr8s-diagnose::object "error" "name a member or node")))
                 ((equal rest "disconnect")
                  (when running
                    (stop-lisp-session running)
                    (bt:with-lock-held ((dashboard-lisp-lock lisp))
                      (setf (dashboard-lisp-sessions lisp) (remove running (dashboard-lisp-sessions lisp)))))
                  (json 200 (gr8s-diagnose::object "stopped" (and running t))))
                 (running (json 200 (session-object running)))
                 ((null (dashboard-lisp-icl lisp))
                  (json 409 (gr8s-diagnose::object "error" "ICL is not installed: see https://github.com/atgreen/icl")))
                 (t (handler-case
                        (let ((session (funcall (dashboard-lisp-start lisp) lisp target
                                                (hunchentoot:header-in :origin request))))
                          (bt:with-lock-held ((dashboard-lisp-lock lisp))
                            (push session (dashboard-lisp-sessions lisp)))
                          (json 200 (session-object session)))
                      (error (condition)
                        (json 502 (gr8s-diagnose::object "error" (princ-to-string condition)))))))))
        (t (setf (hunchentoot:return-code*) hunchentoot:+http-not-found+ (hunchentoot:content-type*) "text/plain")
           "gr8s dashboard: not found")))))
