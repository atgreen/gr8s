;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; The Agent tab of `gr8s dashboard' (podster-2ry): a terminal in the page running
;;;; an AI coding agent the reader has installed -- Claude Code, Codex, Gemini CLI --
;;;; or a shell, on the reader's own machine. The dashboard is already a local
;;;; process holding the reader's kubeconfig, so the agent runs here, as the reader
;;;; would run it from a terminal, with the reader's own agent login, and with
;;;; KUBECONFIG naming the dashboard's cluster. Nothing is deployed to the cluster.
;;;;
;;;; The page at /agent/<token>/ is xterm.js (assets/xterm/, `make xterm-assets');
;;;; /agent/<token>/pty?agent=ID is a WebSocket to a pseudo-terminal running that
;;;; agent. Only commands from this file's catalogue run, never one a page names.
;;;; Binary frames carry the terminal's bytes both ways; the page's text frames are
;;;; JSON control ({"type":"resize","cols":C,"rows":R}), and the server's last text
;;;; frame reports the exit ({"type":"exit","code":N}). A WebSocket's agent ends
;;;; when it closes, and every agent ends with the dashboard.

(in-package #:gr8s.server)

(eval-when (:compile-toplevel :load-toplevel :execute)
  (defun dashboard-agent-asset-text (name)
    "The text of NAME beside this file, or under assets/xterm/, read when it is compiled; NIL
when that asset was not fetched."
    (let* ((here (or *compile-file-truename* *load-truename*))
           (path (if (search "/" name)
                     (merge-pathnames (concatenate 'string "../../" name) here)
                     (merge-pathnames name here))))
      (and (probe-file path) (uiop:read-file-string path)))))

(defparameter +dashboard-agent-html+ #.(dashboard-agent-asset-text "dashboard-agent.html"))

(defparameter +dashboard-agent-assets+
  (list (list "xterm.js" "text/javascript; charset=utf-8" #.(dashboard-agent-asset-text "assets/xterm/xterm.js"))
        (list "xterm.css" "text/css; charset=utf-8" #.(dashboard-agent-asset-text "assets/xterm/xterm.css"))
        (list "addon-fit.js" "text/javascript; charset=utf-8" #.(dashboard-agent-asset-text "assets/xterm/addon-fit.js")))
  "xterm.js's files, (name content-type text), each NIL when `make xterm-assets' has not run.")

(defparameter +dashboard-agent-catalogue+
  '(("claude" "Claude Code" "claude")
    ("codex" "Codex" "codex")
    ("gemini" "Gemini CLI" "gemini"))
  "The agents the tab offers, (id label program), when PROGRAM is on the reader's PATH.
A shell is offered as well.")

(defun dashboard-find-program (name)
  "The full path of executable NAME on PATH, or NIL."
  (loop for directory in (uiop:split-string (or (uiop:getenv "PATH") "") :separator ":")
        for candidate = (and (plusp (length directory))
                             (concatenate 'string (string-right-trim "/" directory) "/" name))
        when (and candidate (ignore-errors (sb-posix:access candidate sb-posix:x-ok) t))
          return candidate))

(defun gr8s-program ()
  "This gr8s executable, or, run from source, the one on PATH; NIL if neither."
  (let ((runtime sb-ext:*runtime-pathname*))
    (if (and runtime (not (search "sbcl" (pathname-name runtime))))
        runtime
        (dashboard-find-program "gr8s"))))

(defun agent-arguments (id gr8s kubeconfig)
  "The arguments that start agent ID knowing gr8s: the guide `gr8s skill' prints, in its
context from the start, and `gr8s mcp' for KUBECONFIG, run by GR8S when there is one, as a
tool server. NIL for an agent that takes neither on its command line (Gemini CLI)."
  (let ((arguments (list "mcp" "--kubeconfig" kubeconfig))
        (guide (with-output-to-string (out) (print-skill out))))
    (cond ((equal id "claude")
           (list* "--append-system-prompt" guide
                  ;; --mcp-config takes several values, so it comes last.
                  (when gr8s
                    (list "--mcp-config"
                 (com.inuoe.jzon:stringify
                  (gr8s-diagnose::object "mcpServers"
                                         (gr8s-diagnose::object "gr8s" (gr8s-diagnose::object "type" "stdio" "command" gr8s
                                                                                              "args" (coerce arguments 'vector)))))))))
          ;; Codex reads each -c value as TOML; a JSON string or array of strings is one.
          ((equal id "codex")
           (list* "-c" (format nil "developer_instructions=~A" (com.inuoe.jzon:stringify guide))
                  (when gr8s
                    (list "-c" (format nil "mcp_servers.gr8s.command=~A" (com.inuoe.jzon:stringify gr8s))
                          "-c" (format nil "mcp_servers.gr8s.args=~A" (com.inuoe.jzon:stringify (coerce arguments 'vector))))))))))

(defun installed-agent-choices (kubeconfig &key (gr8s (gr8s-program)))
  "(id label argv) for each agent installed here, given `gr8s mcp' for KUBECONFIG when it
can be, then the reader's shell."
  (append (loop for (id label program) in +dashboard-agent-catalogue+
                for path = (dashboard-find-program program)
                when path collect (list id label (list* path (agent-arguments id (and gr8s (namestring gr8s)) kubeconfig))))
          (let ((shell (or (uiop:getenv "SHELL") (dashboard-find-program "bash") "/bin/sh")))
            (list (list "shell" "Shell" (list shell "-l"))))))

(defstruct (dashboard-agent (:constructor make-dashboard-agent
                                (kubeconfig &key (choices (lambda () (installed-agent-choices kubeconfig))))))
  "The Agent tab: what it runs and the sessions running."
  kubeconfig
  ;; () -> (id label argv) list.
  choices
  (sessions nil)
  (lock (bt:make-lock "gr8s dashboard agent")))

(defun dashboard-agent-environment (agent)
  "The agent's environment: the dashboard's, with KUBECONFIG naming its cluster and a
terminal xterm.js can draw."
  (let ((replaced '("KUBECONFIG" "TERM" "COLORTERM")))
    (append (remove-if (lambda (entry) (member (subseq entry 0 (or (position #\= entry) 0)) replaced :test #'string=))
                       (sb-ext:posix-environ))
            (list (format nil "KUBECONFIG=~A" (dashboard-agent-kubeconfig agent))
                  "TERM=xterm-256color" "COLORTERM=truecolor"))))

(defun set-pty-size (fd rows columns)
  "Tell the pseudo-terminal on FD it has ROWS and COLUMNS (TIOCSWINSZ, Linux)."
  (sb-alien:with-alien ((size (array (sb-alien:unsigned 16) 4)))
    (setf (sb-alien:deref size 0) rows (sb-alien:deref size 1) columns
          (sb-alien:deref size 2) 0 (sb-alien:deref size 3) 0)
    (sb-alien:alien-funcall
     (sb-alien:extern-alien "ioctl" (function sb-alien:int sb-alien:int sb-alien:unsigned-long
                                              sb-sys:system-area-pointer))
     fd #x5414 (sb-alien:alien-sap size))))

(defun start-dashboard-agent-process (agent argv)
  "Run ARGV on a new pseudo-terminal, as the leader of a session whose controlling terminal
it is, so that resizes and job control reach it; return the process. setsid waits for it,
so the process ends when the agent does; closing the terminal hangs its session up."
  (let ((setsid (dashboard-find-program "setsid")))
    (sb-ext:run-program (if setsid setsid (first argv))
                        (if setsid (list* "--ctty" "--wait" argv) (rest argv))
                        :pty t :wait nil :input t :output t :error nil
                        :directory (uiop:getcwd)
                        :environment (dashboard-agent-environment agent))))

(defun dashboard-agent-websocket (request)
  "Complete REQUEST's WebSocket upgrade and return the raw connection stream."
  (setf (hunchentoot:return-code*) 101
        (hunchentoot:content-type*) nil
        (hunchentoot:header-out :connection) "Upgrade"
        (hunchentoot:header-out :upgrade) "websocket"
        (hunchentoot:header-out :sec-websocket-accept)
        (gr8s.apiserver::websocket-accept-value (hunchentoot:header-in :sec-websocket-key request)))
  (let ((stream (hunchentoot::start-output 101 nil)))
    (finish-output stream)
    stream))

(defun dashboard-agent-same-origin-p (request)
  "Whether REQUEST's page is this dashboard's: a browser sends Origin with every WebSocket,
so another site's page can't open a terminal here even if it learned the path."
  (let ((origin (hunchentoot:header-in :origin request))
        (host (hunchentoot:header-in :host request)))
    (and origin host (string= origin (concatenate 'string "http://" host)))))

(defun run-dashboard-agent-session (agent stream argv)
  "Relay STREAM, a WebSocket, to a new pseudo-terminal running ARGV until either ends."
  (let* ((process (start-dashboard-agent-process agent argv))
         (fd (sb-sys:fd-stream-fd (sb-ext:process-pty process)))
         (write-lock (bt:make-lock "gr8s dashboard agent writer")))
    (flet ((send (opcode payload)
             (bt:with-lock-held (write-lock)
               (gr8s.protocol::write-websocket-frame stream opcode payload)))
           (to-pty (octets)
             (sb-sys:with-pinned-objects (octets)
               (loop with done = 0
                     while (< done (length octets))
                     do (let ((n (sb-unix:unix-write fd octets done (- (length octets) done))))
                          (unless (and n (plusp n)) (return))
                          (incf done n))))))
      (bt:with-lock-held ((dashboard-agent-lock agent))
        (push process (dashboard-agent-sessions agent)))
      (let ((reader
              ;; The terminal's output, as it comes, until the agent ends.
              (bt:make-thread
               (lambda ()
                 (let ((buffer (make-array 16384 :element-type '(unsigned-byte 8))))
                   (handler-case
                       (loop (let ((n (sb-sys:with-pinned-objects (buffer)
                                        (sb-unix:unix-read fd (sb-sys:vector-sap buffer) (length buffer)))))
                               (unless (and n (plusp n)) (return))
                               (send 2 (subseq buffer 0 n))))
                     (error () nil)))
                 (sb-ext:process-wait process)
                 (ignore-errors
                  (send 1 (trivial-utf-8:string-to-utf-8-bytes
                           (com.inuoe.jzon:stringify
                            (gr8s-diagnose::object "type" "exit" "code" (or (sb-ext:process-exit-code process) 0))))))
                 (ignore-errors (send 8 (make-array 0 :element-type '(unsigned-byte 8)))))
               :name "gr8s dashboard agent output")))
        (unwind-protect
             ;; The page's keys, and its control messages.
             (handler-case
                 (loop (multiple-value-bind (opcode payload) (gr8s.protocol::read-websocket-frame stream)
                         (case opcode
                           (2 (to-pty payload))
                           (1 (let ((message (ignore-errors (com.inuoe.jzon:parse payload))))
                                (when (and (hash-table-p message) (equal "resize" (gethash "type" message)))
                                  (let ((columns (gethash "cols" message)) (rows (gethash "rows" message)))
                                    (when (and (typep columns '(integer 1 1000)) (typep rows '(integer 1 1000)))
                                      (set-pty-size fd rows columns)
                                      ;; Without setsid it isn't the controlling terminal; say so ourselves.
                                      (ignore-errors (sb-ext:process-kill process sb-unix:sigwinch)))))))
                           (8 (return))
                           (9 (send 10 payload)))))
               (error () nil))
          ;; Closing the terminal hangs up the agent's session; setsid then exits too.
          (ignore-errors (close (sb-ext:process-pty process)))
          (when (sb-ext:process-alive-p process)
            (ignore-errors (sb-ext:process-kill process sb-unix:sighup)))
          (ignore-errors (bt:join-thread reader))
          (ignore-errors (sb-ext:process-close process))
          (ignore-errors (close stream))
          (bt:with-lock-held ((dashboard-agent-lock agent))
            (setf (dashboard-agent-sessions agent) (remove process (dashboard-agent-sessions agent)))))))))

(defun stop-dashboard-agents (agent)
  "End every agent the tab started, by hanging up its terminal."
  (dolist (process (bt:with-lock-held ((dashboard-agent-lock agent)) (dashboard-agent-sessions agent)))
    (ignore-errors (close (sb-ext:process-pty process)))
    (ignore-errors (sb-ext:process-kill process sb-unix:sighup))))

(defun dashboard-agent-dispatch (agent base request)
  "Serve the Agent tab under BASE, /agent/<token>/: the page, its assets, the agents
installed, and a terminal."
  (let ((rest (subseq (hunchentoot:script-name request) (min (length base) (length (hunchentoot:script-name request))))))
    (setf (hunchentoot:header-out :cache-control) "no-store")
    (flet ((not-found ()
             (setf (hunchentoot:return-code*) hunchentoot:+http-not-found+
                   (hunchentoot:content-type*) "text/plain")
             "gr8s dashboard: not found"))
      (cond
        ((member rest '("" "index.html") :test #'equal)
         (setf (hunchentoot:content-type*) "text/html; charset=utf-8"
               (hunchentoot:header-out :referrer-policy) "no-referrer")
         +dashboard-agent-html+)
        ((equal rest "agents")
         (setf (hunchentoot:content-type*) "application/json")
         (com.inuoe.jzon:stringify
          (coerce (loop for (id label) in (funcall (dashboard-agent-choices agent))
                        collect (gr8s-diagnose::object "id" id "label" label))
                  'vector)))
        ((equal rest "pty")
         (let ((choice (assoc (hunchentoot:get-parameter "agent" request) (funcall (dashboard-agent-choices agent))
                              :test #'equal)))
           (cond ((not (and (string-equal (hunchentoot:header-in :upgrade request) "websocket")
                            (hunchentoot:header-in :sec-websocket-key request)))
                  (setf (hunchentoot:return-code*) hunchentoot:+http-bad-request+ (hunchentoot:content-type*) "text/plain")
                  "a terminal needs a WebSocket")
                 ((not (dashboard-agent-same-origin-p request))
                  (setf (hunchentoot:return-code*) hunchentoot:+http-forbidden+ (hunchentoot:content-type*) "text/plain")
                  "a terminal opens only from the dashboard's own page")
                 ((null choice) (not-found))
                 (t (run-dashboard-agent-session agent (dashboard-agent-websocket request) (third choice))
                    ""))))
        (t (let ((asset (assoc rest +dashboard-agent-assets+ :test #'equal)))
             (if (and asset (third asset))
                 (progn (setf (hunchentoot:content-type*) (second asset)) (third asset))
                 (not-found))))))))
