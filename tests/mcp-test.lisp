;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; `gr8s mcp' (podster-j53): the JSON-RPC conversation an MCP client has with it
;;;; on stdio, and the checks its tools make before they read a cluster.

(in-package #:gr8s/tests)
(def-suite mcp :in gr8s)
(in-suite mcp)

(defun mcp-conversation (lines &key (tools (gr8s.server::mcp-tools)))
  "The responses, parsed, that gr8s mcp writes for LINES, each one message."
  (let ((output (make-string-output-stream)))
    (gr8s.server::serve-mcp (make-string-input-stream (format nil "~{~A~%~}" lines)) output "/no/kubeconfig"
                            :tools tools)
    (mapcar #'com.inuoe.jzon:parse
            (remove "" (uiop:split-string (get-output-stream-string output) :separator '(#\Newline)) :test #'equal))))

(defun mcp-call (name arguments)
  (format nil "{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"tools/call\",\"params\":{\"name\":~S,\"arguments\":~A}}"
          name arguments))

(test mcp-speaks-json-rpc-on-stdio-and-nothing-else
  (let* ((tools (list (list "echo" "Echo" "Say it back." (gr8s.server::mcp-schema '(("text" "string" "What to say.")))
                            (lambda (arguments kubeconfig)
                              ;; Anything a tool prints must stay off the protocol channel.
                              (format t "noise on stdout~%")
                              (format nil "~A from ~A" (gethash "text" arguments) kubeconfig)))
                      (list "broken" "Broken" "Fail." (gr8s.server::mcp-schema nil)
                            (lambda (arguments kubeconfig) (declare (ignore arguments kubeconfig))
                              (error "the cluster is unreachable")))))
         (responses
           (mcp-conversation
            (list "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-06-18\",\"capabilities\":{},\"clientInfo\":{\"name\":\"t\",\"version\":\"1\"}}}"
                  "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}"
                  ""
                  "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"ping\"}"
                  (mcp-call "echo" "{\"text\":\"hello\"}")
                  (mcp-call "broken" "{}")
                  (mcp-call "missing" "{}")
                  "{\"jsonrpc\":\"2.0\",\"id\":\"x\",\"method\":\"resources/list\"}"
                  "not json"
                  "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"1999-01-01\"}}")
            :tools tools)))
    ;; The notification and the blank line have no answer.
    (is (= 8 (length responses)))
    (destructuring-bind (initialize ping echo broken missing unknown unparsed old) responses
      (let ((result (gethash "result" initialize)))
        (is (equal "2025-06-18" (gethash "protocolVersion" result)))
        (is (equal "gr8s" (gethash "name" (gethash "serverInfo" result))))
        (is (hash-table-p (gethash "tools" (gethash "capabilities" result))))
        (is (search "doctor_diagnose" (gethash "instructions" result))))
      (is (= 0 (hash-table-count (gethash "result" ping))))
      (is (equal "hello from /no/kubeconfig"
                 (gethash "text" (aref (gethash "content" (gethash "result" echo)) 0))))
      (is (eq nil (gethash "isError" (gethash "result" echo))))
      ;; A tool that fails says why, as its result.
      (is (eq t (gethash "isError" (gethash "result" broken))))
      (is (search "unreachable" (gethash "text" (aref (gethash "content" (gethash "result" broken)) 0))))
      (is (= -32602 (gethash "code" (gethash "error" missing))))
      (is (equal "x" (gethash "id" unknown)))
      (is (= -32601 (gethash "code" (gethash "error" unknown))))
      (is (= -32700 (gethash "code" (gethash "error" unparsed))))
      (is (eq 'null (gethash "id" unparsed)))
      ;; A revision it doesn't speak is answered with the newest it does.
      (is (equal "2025-06-18" (gethash "protocolVersion" (gethash "result" old)))))))

(test mcp-lists-its-tools-and-checks-their-arguments-first
  (let ((listed (first (mcp-conversation '("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}")))))
    (is (equal '("gr8s_guide" "doctor_diagnose" "doctor_impact" "observe_flows" "cluster_status")
               (map 'list (lambda (tool) (gethash "name" tool)) (gethash "tools" (gethash "result" listed)))))
    (is (every (lambda (tool) (equal "object" (gethash "type" (gethash "inputSchema" tool))))
               (gethash "tools" (gethash "result" listed)))))
  ;; The guide is `gr8s skill', and the instructions send an agent to it first.
  (let ((guide (gethash "result" (first (mcp-conversation (list (mcp-call "gr8s_guide" "{}")))))))
    (is (uiop:string-prefix-p "# gr8s operator and agent guide"
                              (gethash "text" (aref (gethash "content" guide) 0)))))
  (is (search "call gr8s_guide once" gr8s.server::+mcp-instructions+))
  ;; Each is refused, as the CLI would refuse it, before anything reads the cluster.
  (flet ((refusal (name arguments)
           (let ((result (gethash "result" (first (mcp-conversation (list (mcp-call name arguments)))))))
             (and (eq t (gethash "isError" result))
                  (gethash "text" (aref (gethash "content" result) 0))))))
    (is (search "namespace must be" (refusal "doctor_diagnose" "{\"namespace\":\"Not_A_Namespace\"}")))
    (is (search "KIND/NAME" (refusal "doctor_diagnose" "{\"target\":\"widget/x\"}")))
    (is (search "target is required" (refusal "doctor_impact" "{}")))
    (is (search "verdict must be" (refusal "observe_flows" "{\"verdict\":\"lost\"}")))
    (is (search "limit must be" (refusal "observe_flows" "{\"limit\":5000}")))))

(test the-agent-tab-gives-each-agent-gr8s-mcp
  ;; podster-j53: an agent the Agent tab starts has gr8s mcp, for the dashboard's cluster.
  (let* ((directory (uiop:ensure-directory-pathname
                     (sb-posix:mkdtemp (namestring (merge-pathnames "gr8s-agents-XXXXXX" (uiop:temporary-directory))))))
         (saved (uiop:getenv "PATH")))
    (unwind-protect
         (progn
           (dolist (name '("claude" "codex" "gemini"))
             (let ((path (merge-pathnames name directory)))
               (alexandria:write-string-into-file (format nil "#!/bin/sh~%") path)
               (sb-posix:chmod (namestring path) #o755)))
           (setf (uiop:getenv "PATH") (namestring directory))
           (let ((choices (gr8s.server::installed-agent-choices "/home/u/kc.yaml" :gr8s "/opt/gr8s")))
             (is (equal '("claude" "codex" "gemini" "shell") (mapcar #'first choices)))
             (destructuring-bind (claude codex gemini shell) (mapcar #'third choices)
               ;; Each starts with the guide in its context, then gr8s mcp.
               (is (equal "--append-system-prompt" (second claude)))
               (is (uiop:string-prefix-p "# gr8s operator and agent guide" (third claude)))
               (is (equal "--mcp-config" (fourth claude)))
               (let ((server (gethash "gr8s" (gethash "mcpServers" (com.inuoe.jzon:parse (fifth claude))))))
                 (is (equal "/opt/gr8s" (gethash "command" server)))
                 (is (equalp #("mcp" "--kubeconfig" "/home/u/kc.yaml") (gethash "args" server))))
               (is (equal "-c" (second codex)))
               (is (uiop:string-prefix-p "developer_instructions=\"# gr8s operator and agent guide" (third codex)))
               (is (equal (list "-c" "mcp_servers.gr8s.command=\"/opt/gr8s\""
                                "-c" "mcp_servers.gr8s.args=[\"mcp\",\"--kubeconfig\",\"/home/u/kc.yaml\"]")
                          (nthcdr 3 codex)))
               ;; Gemini CLI takes MCP servers only from its settings file.
               (is (= 1 (length gemini)))
               (is (equal "-l" (second shell)))))
           ;; Without a gr8s to run, they still start with the guide, and without gr8s mcp.
           (destructuring-bind (claude codex gemini shell)
               (mapcar #'third (gr8s.server::installed-agent-choices "/home/u/kc.yaml" :gr8s nil))
             (declare (ignore gemini shell))
             (is (= 3 (length claude)))
             (is (= 3 (length codex)))
             (is (notany (lambda (argument) (search "mcp_servers" argument)) codex))))
      (setf (uiop:getenv "PATH") saved)
      (uiop:delete-directory-tree directory :validate t))))
