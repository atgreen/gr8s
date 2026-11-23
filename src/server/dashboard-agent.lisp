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
;;;; /agent/<token>/pty?agent=ID starts that agent on a pseudo-terminal and attaches a
;;;; WebSocket to it; ?session=ID attaches to one already running, which keeps running
;;;; when its page goes. Only commands from this file's catalogue run, never one a page names.
;;;; Binary frames carry the terminal's bytes both ways; the page's text frames are
;;;; JSON control ({"type":"resize","cols":C,"rows":R}), and the server's last text
;;;; frame reports the exit ({"type":"exit","code":N}). An agent ends when it exits, when a
;;;; page sends {"type":"stop"}, or with the dashboard; never because a page went away.

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

(defparameter +agent-backlog-bytes+ (* 1024 1024)
  "How much of an agent's latest output a session keeps, to show a page that attaches.")

(defstruct (agent-session (:constructor %make-agent-session (id choice label process fd)))
  "One agent on its pseudo-terminal. It outlives the pages that show it: a page attaches,
and leaves, and the agent runs on until it exits, a page stops it, or the dashboard ends."
  id choice label process fd
  ;; The latest output, at most +AGENT-BACKLOG-BYTES+, for the next page that attaches.
  (backlog (make-array 0 :element-type '(unsigned-byte 8) :adjustable t :fill-pointer 0))
  ;; The attached page's WebSocket stream, or NIL.
  client
  (lock (bt:make-lock "gr8s dashboard agent session")))

(defun new-agent-session-id ()
  (format nil "~(~{~2,'0X~}~)" (coerce (secure-random-octets 16) 'list)))

(defun agent-session-send (session opcode payload)
  "Send a frame to SESSION's page, if one is attached and still listening; the caller holds
SESSION's lock. A page that can't be written to is detached, never the agent ended."
  (let ((client (agent-session-client session)))
    (when client
      (handler-case (gr8s.protocol::write-websocket-frame client opcode payload)
        (error () (setf (agent-session-client session) nil))))))

(defun agent-session-control (session &rest pairs)
  (agent-session-send session 1 (trivial-utf-8:string-to-utf-8-bytes
                                 (com.inuoe.jzon:stringify (apply #'gr8s-diagnose::object pairs)))))

(defun hang-up-agent-session (session)
  "End SESSION's agent: closing its terminal hangs up the agent's session, and setsid exits."
  (let ((process (agent-session-process session)))
    (ignore-errors (close (sb-ext:process-pty process)))
    (when (sb-ext:process-alive-p process)
      (ignore-errors (sb-ext:process-kill process sb-unix:sighup)))))

(defun start-agent-session (agent choice)
  "Start CHOICE, (id label argv), on a new pseudo-terminal, as a session of AGENT."
  (let* ((process (start-dashboard-agent-process agent (third choice)))
         (session (%make-agent-session (new-agent-session-id) (first choice) (second choice) process
                                       (sb-sys:fd-stream-fd (sb-ext:process-pty process)))))
    (bt:with-lock-held ((dashboard-agent-lock agent))
      (push session (dashboard-agent-sessions agent)))
    ;; The terminal's output, kept and shown to the page attached, until the agent ends.
    (bt:make-thread
     (lambda ()
       (let ((buffer (make-array 16384 :element-type '(unsigned-byte 8)))
             (fd (agent-session-fd session)))
         (handler-case
             (loop (let ((n (sb-sys:with-pinned-objects (buffer)
                              (sb-unix:unix-read fd (sb-sys:vector-sap buffer) (length buffer)))))
                     (unless (and n (plusp n)) (return))
                     (let ((data (subseq buffer 0 n)))
                       (bt:with-lock-held ((agent-session-lock session))
                         (let* ((backlog (agent-session-backlog session))
                                (over (- (+ (length backlog) n) +agent-backlog-bytes+)))
                           (when (plusp over)
                             (replace backlog backlog :start2 over)
                             (decf (fill-pointer backlog) over))
                           (loop for octet across data do (vector-push-extend octet backlog)))
                         (agent-session-send session 2 data)))))
           (error () nil)))
       (sb-ext:process-wait process)
       (bt:with-lock-held ((dashboard-agent-lock agent))
         (setf (dashboard-agent-sessions agent) (remove session (dashboard-agent-sessions agent))))
       (bt:with-lock-held ((agent-session-lock session))
         (agent-session-control session "type" "exit" "code" (or (sb-ext:process-exit-code process) 0))
         (agent-session-send session 8 (make-array 0 :element-type '(unsigned-byte 8))))
       (ignore-errors (sb-ext:process-close process)))
     :name "gr8s dashboard agent output")
    session))

(defun attach-agent-session (session stream)
  "Show SESSION on STREAM, a page's WebSocket, until the page leaves or stops the agent:
first who it is and its latest output, then all it writes; the page's keys and resizes go
to the agent. A page that attaches takes over from one attached before it."
  (bt:with-lock-held ((agent-session-lock session))
    (agent-session-send session 8 (make-array 0 :element-type '(unsigned-byte 8)))
    (setf (agent-session-client session) stream)
    (agent-session-control session "type" "session" "id" (agent-session-id session)
                           "agent" (agent-session-choice session) "label" (agent-session-label session))
    (let ((backlog (agent-session-backlog session)))
      (when (plusp (length backlog))
        (agent-session-send session 2 (coerce backlog '(simple-array (unsigned-byte 8) (*)))))))
  (let ((fd (agent-session-fd session)) (process (agent-session-process session)))
    (flet ((to-pty (octets)
             (sb-sys:with-pinned-objects (octets)
               (loop with done = 0
                     while (< done (length octets))
                     do (let ((n (sb-unix:unix-write fd octets done (- (length octets) done))))
                          (unless (and n (plusp n)) (return))
                          (incf done n))))))
      (unwind-protect
           (handler-case
               (loop (multiple-value-bind (opcode payload) (gr8s.protocol::read-websocket-frame stream)
                       (case opcode
                         (2 (to-pty payload))
                         (1 (let* ((message (ignore-errors (com.inuoe.jzon:parse payload)))
                                   (type (and (hash-table-p message) (gethash "type" message))))
                              (cond ((equal type "stop") (hang-up-agent-session session))
                                    ((equal type "resize")
                                     (let ((columns (gethash "cols" message)) (rows (gethash "rows" message)))
                                       (when (and (typep columns '(integer 1 1000)) (typep rows '(integer 1 1000)))
                                         (set-pty-size fd rows columns)
                                         ;; Without setsid it isn't the controlling terminal; say so ourselves.
                                         (ignore-errors (sb-ext:process-kill process sb-unix:sigwinch))))))))
                         (8 (return))
                         (9 (bt:with-lock-held ((agent-session-lock session))
                              (when (eq stream (agent-session-client session))
                                (agent-session-send session 10 payload)))))))
             (error () nil))
        ;; The page has gone; the agent runs on.
        (bt:with-lock-held ((agent-session-lock session))
          (when (eq stream (agent-session-client session))
            (setf (agent-session-client session) nil)))
        (ignore-errors (close stream))))))

(defun stop-dashboard-agents (agent)
  "End every agent the tab started."
  (mapc #'hang-up-agent-session (bt:with-lock-held ((dashboard-agent-lock agent)) (dashboard-agent-sessions agent))))

(defun dashboard-agent-websocket (request)
  "Complete REQUEST's WebSocket upgrade and return the raw connection stream, which may then
stay quiet as long as the agent does: the server's idle timeout would hang up a terminal
whose reader is only watching."
  (setf (hunchentoot:return-code*) 101
        (hunchentoot:content-type*) nil
        (hunchentoot:header-out :connection) "Upgrade"
        (hunchentoot:header-out :upgrade) "websocket"
        (hunchentoot:header-out :sec-websocket-accept)
        (gr8s.apiserver::websocket-accept-value (hunchentoot:header-in :sec-websocket-key request)))
  (let ((stream (hunchentoot::start-output 101 nil)))
    (finish-output stream)
    (loop for inner = stream then (cond ((typep inner 'flexi-streams:flexi-stream) (flexi-streams:flexi-stream-stream inner))
                                        ((typep inner 'chunga:chunked-stream) (chunga:chunked-stream-stream inner)))
          while inner
          when (typep inner 'sb-sys:fd-stream)
            do (setf (sb-impl::fd-stream-timeout inner) nil) (return))
    stream))

(defun dashboard-agent-same-origin-p (request)
  "Whether REQUEST's page is this dashboard's: a browser sends Origin with every WebSocket,
so another site's page can't open a terminal here even if it learned the path."
  (let ((origin (hunchentoot:header-in :origin request))
        (host (hunchentoot:header-in :host request)))
    (and origin host (string= origin (concatenate 'string "http://" host)))))

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
        ((equal rest "sessions")
         (setf (hunchentoot:content-type*) "application/json")
         (com.inuoe.jzon:stringify
          (coerce (loop for session in (reverse (bt:with-lock-held ((dashboard-agent-lock agent))
                                                  (copy-list (dashboard-agent-sessions agent))))
                        collect (gr8s-diagnose::object "id" (agent-session-id session)
                                                       "agent" (agent-session-choice session)
                                                       "label" (agent-session-label session)))
                  'vector)))
        ((equal rest "pty")
         ;; ?agent=ID starts that agent; ?session=ID attaches to one running.
         (let* ((wanted (hunchentoot:get-parameter "session" request))
                (session (and wanted (find wanted (bt:with-lock-held ((dashboard-agent-lock agent))
                                                    (copy-list (dashboard-agent-sessions agent)))
                                           :key #'agent-session-id :test #'equal)))
                (choice (and (null wanted)
                             (assoc (hunchentoot:get-parameter "agent" request) (funcall (dashboard-agent-choices agent))
                                    :test #'equal))))
           (cond ((not (and (string-equal (hunchentoot:header-in :upgrade request) "websocket")
                            (hunchentoot:header-in :sec-websocket-key request)))
                  (setf (hunchentoot:return-code*) hunchentoot:+http-bad-request+ (hunchentoot:content-type*) "text/plain")
                  "a terminal needs a WebSocket")
                 ((not (dashboard-agent-same-origin-p request))
                  (setf (hunchentoot:return-code*) hunchentoot:+http-forbidden+ (hunchentoot:content-type*) "text/plain")
                  "a terminal opens only from the dashboard's own page")
                 ((not (or session choice)) (not-found))
                 (t (let ((stream (dashboard-agent-websocket request)))
                      (attach-agent-session (or session (start-agent-session agent choice)) stream))
                    ""))))
        (t (let ((asset (assoc rest +dashboard-agent-assets+ :test #'equal)))
             (if (and asset (third asset))
                 (progn (setf (hunchentoot:content-type*) (second asset)) (third asset))
                 (not-found))))))))
