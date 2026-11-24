;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; `gr8s mcp' (podster-j53): a Model Context Protocol server on stdio, so that an
;;;; AI agent -- Claude Code, Codex, any MCP client -- can ask gr8s what it knows
;;;; about a cluster rather than piece it together from kubectl: the doctor's
;;;; diagnosis and impact reports, recent flow events, and the control plane's
;;;; members and nodes. Every tool only reads, with the credentials of the
;;;; kubeconfig it is given; an agent changes the cluster with its own kubectl,
;;;; under its own permission prompts.
;;;;
;;;; The transport is MCP's stdio one: JSON-RPC 2.0 messages, one per line, on
;;;; stdin and stdout. Stdout carries nothing else: whatever any code prints while
;;;; a tool runs goes to stderr instead.

(in-package #:gr8s.server)

(defparameter +mcp-protocol-versions+ '("2025-06-18" "2025-03-26" "2024-11-05")
  "MCP revisions this server speaks, newest first.")

(defparameter +mcp-instructions+
  "Read-only tools for the gr8s cluster of this server's kubeconfig. Before
operating or troubleshooting gr8s, call gr8s_guide once: gr8s is
Kubernetes-compatible but not a stock distribution, and the guide says how it
differs and which commands to use. Then use doctor_diagnose to find what is wrong and why: it links resources and names
causes, with what each one holds up and the next step. doctor_impact says what
would stop working if a resource went away. observe_flows shows recent network
flows, including those a NetworkPolicy dropped. cluster_status shows the control
plane's members and leader and each node's readiness. Nothing here changes the
cluster.")

(defun mcp-object (&rest pairs)
  "A JSON object of PAIRS, key value ..."
  (let ((object (make-hash-table :test #'equal)))
    (loop for (key value) on pairs by #'cddr do (setf (gethash key object) value))
    object))

(defun mcp-schema (properties &optional required)
  "A JSON Schema for an object with PROPERTIES, (name type description), REQUIRED among them."
  (mcp-object "type" "object"
              "properties" (let ((object (mcp-object)))
                             (loop for (name type description) in properties
                                   do (setf (gethash name object) (mcp-object "type" type "description" description)))
                             object)
              "required" (coerce required 'vector)
              "additionalProperties" nil))

;;; Arguments, checked as the CLI checks them.

(defun mcp-string-argument (arguments name &key required)
  (let ((value (gethash name arguments)))
    (cond ((and (stringp value) (plusp (length value))) value)
          ((or (null value) (equal value "")) (when required (error "~A is required." name)))
          (t (error "~A must be a string." name)))))

(defun mcp-namespace-argument (arguments)
  (let ((namespace (mcp-string-argument arguments "namespace")))
    (when (and namespace (not (dns-label-p namespace)))
      (error "namespace must be a Namespace name."))
    namespace))

(defun mcp-target-argument (arguments &key required)
  (let ((target (mcp-string-argument arguments "target" :required required)))
    (when target
      (let ((slash (position #\/ target)))
        (unless (and slash (assoc (string-downcase (subseq target 0 slash)) gr8s-diagnose::*target-kinds* :test #'equal))
          (error "target must be KIND/NAME, such as pod/web-0 or deployment/api, of a kind the doctor reads.")))
      (string-downcase target :end (position #\/ target)))))

;;; The tools. Each takes the arguments object and the kubeconfig, and returns text.

(defun call-with-mcp-doctor-getter (kubeconfig function)
  "Call FUNCTION with a bounded doctor getter reading through gr8s's API client."
  (let ((gr8s-diagnose::*call-with-getter* #'call-with-doctor-api-getter))
    (gr8s-diagnose::call-with-doctor-getter kubeconfig nil function)))

(defun mcp-doctor-diagnose (arguments kubeconfig)
  (let* ((namespace (mcp-namespace-argument arguments))
         (target (mcp-target-argument arguments))
         (report (call-with-mcp-doctor-getter
                  kubeconfig
                  (lambda (getter)
                    (if target
                        (gr8s-diagnose::diagnose-target target namespace getter)
                        (gr8s-diagnose::checkup namespace getter))))))
    (gr8s-diagnose::survey-markdown report :notes (eq t (gethash "notes" arguments)))))

(defun mcp-doctor-impact (arguments kubeconfig)
  (let* ((target (mcp-target-argument arguments :required t))
         (namespace (mcp-namespace-argument arguments))
         (report (call-with-mcp-doctor-getter
                  kubeconfig
                  (lambda (getter) (gr8s-diagnose::impact-target target namespace getter)))))
    (with-output-to-string (*standard-output*)
      (gr8s-diagnose::print-impact report))))

(defun mcp-observe-flows (arguments kubeconfig)
  (let* ((namespace (mcp-namespace-argument arguments))
         (verdict (let ((value (mcp-string-argument arguments "verdict")))
                    (when value
                      (let ((upper (string-upcase value)))
                        (unless (member upper '("DROPPED" "FORWARDED") :test #'string=)
                          (error "verdict must be dropped or forwarded."))
                        upper))))
         (limit (let ((value (gethash "limit" arguments)))
                  (cond ((null value) 100)
                        ((typep value '(integer 1 1000)) value)
                        (t (error "limit must be a whole number from 1 to 1000.")))))
         (options (list :pod (mcp-string-argument arguments "pod") :node (mcp-string-argument arguments "node")
                        :verdict verdict))
         (lines nil) (count 0))
    (call-with-debug-kubeconfig
     kubeconfig
     (lambda (config)
       (call-with-api-flows
        config namespace nil
        (lambda (line)
          (let ((flow (ignore-errors (com.inuoe.jzon:parse line))))
            (when (and (hash-table-p flow) (flow-matches-options-p flow options))
              (incf count)
              (push (format-flow-line flow) lines)
              (when (> (length lines) limit) (setf lines (subseq lines 0 limit)))))))))
    (if (zerop count)
        (format nil "No recent flow events match.~%")
        (format nil "~D recent flow event~:P match~:[~;es~]~@[; the last ~D~]:~%~{~A~%~}"
                count (= count 1) (when (> count limit) limit) (reverse lines)))))

(defun mcp-cluster-status (arguments kubeconfig)
  (declare (ignore arguments))
  (call-with-debug-kubeconfig
   kubeconfig
   (lambda (config)
     (with-output-to-string (out)
       (multiple-value-bind (body status)
           (debug-api-request-json config "GET" "/apis/gr8s.io/v1/controlplanemembers")
         (cond ((= status 200)
                (format out "Control-plane members:~%")
                (loop for item across (gethash "items" body #())
                      for spec = (gethash "spec" item)
                      for item-status = (gethash "status" item)
                      do (format out "- ~A: ~A~@[ at ~A~], contact ~A~:[~;, leader~]~%"
                                 (gethash "name" (gethash "metadata" item)) (gethash "role" spec)
                                 (gethash "address" spec) (gethash "contact" item-status)
                                 (eq t (gethash "leader" item-status)))))
               ((= status 404) (format out "A single control plane (no HA members).~%"))
               (t (format out "Control-plane members could not be read (HTTP ~D).~%" status))))
       (multiple-value-bind (body status) (debug-api-request-json config "GET" "/api/v1/nodes")
         (if (/= status 200)
             (format out "Nodes could not be read (HTTP ~D).~%" status)
             (progn
               (format out "Nodes:~%")
               (loop for node across (gethash "items" body #())
                     for ready = (find "Ready" (gethash "conditions" (gethash "status" node) #())
                                       :test #'equal :key (lambda (condition) (gethash "type" condition)))
                     do (format out "- ~A: ~:[not ready~;ready~]~@[ (~A)~]~@[, last heard from at ~A~], kubelet ~A~%"
                                (gethash "name" (gethash "metadata" node))
                                (and ready (equal "True" (gethash "status" ready)))
                                (and ready (not (equal "True" (gethash "status" ready))) (gethash "reason" ready))
                                (and ready (or (gethash "lastHeartbeatTime" ready) (gethash "lastTransitionTime" ready)))
                                (gethash "kubeletVersion" (gethash "nodeInfo" (gethash "status" node))))))))))))

(defun mcp-gr8s-guide (arguments kubeconfig)
  (declare (ignore arguments kubeconfig))
  (with-output-to-string (out) (print-skill out)))

(defun mcp-tools ()
  "(name title description schema function) for each tool."
  (list
   (list "gr8s_guide" "How to operate gr8s"
         "Return the gr8s operator and agent guide, as `gr8s skill` prints it: how gr8s differs from other Kubernetes distributions, its commands, and how to troubleshoot it. Read it once before operating or troubleshooting gr8s."
         (mcp-schema nil)
         #'mcp-gr8s-guide)
   (list "doctor_diagnose" "Diagnose the cluster"
         "Run `gr8s doctor diagnose`: find what is wrong in the whole cluster, a namespace, or around one resource, and why. Returns a Markdown report: each problem with its cause, the resources it holds up, and what to do. A whole-cluster survey reads every resource and can take half a minute."
         (mcp-schema '(("namespace" "string" "Limit the survey to this namespace.")
                       ("target" "string" "One resource, KIND/NAME such as pod/web-0 or deployment/api; with namespace for a namespaced kind.")
                       ("notes" "boolean" "Also list configuration and history notes.")))
         #'mcp-doctor-diagnose)
   (list "doctor_impact" "What would losing a resource affect"
         "Run `gr8s doctor impact`: say what would stop working if a resource went away, such as a Node, Secret, ConfigMap or Service."
         (mcp-schema '(("target" "string" "The resource, KIND/NAME such as node/worker-1 or secret/db-credentials.")
                       ("namespace" "string" "Its namespace, for a namespaced kind."))
                     '("target"))
         #'mcp-doctor-impact)
   (list "observe_flows" "Recent network flows"
         "Show the cluster's recent flow events, as `gr8s doctor observe` does: connections and the drops NetworkPolicies cause, one line each, oldest first."
         (mcp-schema '(("namespace" "string" "Only flows either side of which is in this namespace.")
                       ("pod" "string" "Only flows to or from this Pod name.")
                       ("node" "string" "Only flows seen on this node.")
                       ("verdict" "string" "dropped or forwarded.")
                       ("limit" "integer" "At most this many, the most recent (default 100, at most 1000).")))
         #'mcp-observe-flows)
   (list "cluster_status" "Control plane and nodes"
         "Show the control plane's members (role, contact, which leads) and each node's readiness and kubelet version."
         (mcp-schema nil)
         #'mcp-cluster-status)))

;;; JSON-RPC over stdio.

(defun mcp-result (id result) (mcp-object "jsonrpc" "2.0" "id" id "result" result))
(defun mcp-error (id code message) (mcp-object "jsonrpc" "2.0" "id" id "error" (mcp-object "code" code "message" message)))

(defun mcp-handle (message kubeconfig tools)
  "The response to MESSAGE, a parsed JSON-RPC message, or NIL for a notification."
  (let* ((id (gethash "id" message))
         (notification (not (nth-value 1 (gethash "id" message))))
         (method (gethash "method" message))
         (params (let ((params (gethash "params" message))) (if (hash-table-p params) params (mcp-object)))))
    (flet ((answer (result) (unless notification (mcp-result id result)))
           (fail (code text) (unless notification (mcp-error id code text))))
      (cond
        ((not (stringp method)) (fail -32600 "Invalid request"))
        ((string= method "initialize")
         (let ((asked (gethash "protocolVersion" params)))
           (answer (mcp-object "protocolVersion" (if (member asked +mcp-protocol-versions+ :test #'equal)
                                                     asked (first +mcp-protocol-versions+))
                               "capabilities" (mcp-object "tools" (mcp-object "listChanged" nil))
                               "serverInfo" (mcp-object "name" "gr8s" "title" "gr8s" "version" +gr8s-version+)
                               "instructions" +mcp-instructions+))))
        ((string= method "ping") (answer (mcp-object)))
        ((string= method "tools/list")
         (answer (mcp-object "tools" (coerce (loop for (name title description schema) in tools
                                                   collect (mcp-object "name" name "title" title
                                                                       "description" description "inputSchema" schema))
                                             'vector))))
        ((string= method "tools/call")
         (let ((tool (assoc (gethash "name" params) tools :test #'equal))
               (arguments (let ((arguments (gethash "arguments" params)))
                            (if (hash-table-p arguments) arguments (mcp-object)))))
           (if (null tool)
               (fail -32602 (format nil "Unknown tool: ~A" (gethash "name" params)))
               ;; A tool that fails says why, as its result, so the agent can act on it.
               (answer (handler-case
                           (mcp-object "content" (vector (mcp-object "type" "text"
                                                                     "text" (funcall (fifth tool) arguments kubeconfig)))
                                       "isError" nil)
                         (error (condition)
                           (mcp-object "content" (vector (mcp-object "type" "text" "text" (princ-to-string condition)))
                                       "isError" t)))))))
        (notification nil)
        (t (fail -32601 (format nil "Method not found: ~A" method)))))))

(defun serve-mcp (input output kubeconfig &key (tools (mcp-tools)))
  "Answer JSON-RPC messages, one per line, from INPUT on OUTPUT until INPUT ends. OUTPUT
carries only those: what anything else prints meanwhile goes to stderr."
  (loop with *standard-output* = *error-output*
        for line = (read-line input nil)
        while line
        unless (zerop (length (string-trim '(#\Space #\Tab #\Return) line)))
          do (let* ((message (handler-case (com.inuoe.jzon:parse line) (error () :invalid)))
                    (response (cond ((eq message :invalid) (mcp-error 'null -32700 "Parse error"))
                                    ((not (hash-table-p message)) (mcp-error 'null -32600 "Invalid request"))
                                    (t (mcp-handle message kubeconfig tools)))))
               (when response
                 (com.inuoe.jzon:stringify response :stream output)
                 (terpri output)
                 (finish-output output)))))

(defun parse-mcp-options (arguments)
  "Parse `gr8s mcp' options."
  (let ((options (list :command :mcp :kubeconfig (default-client-kubeconfig))))
    (loop while arguments
          for option = (pop arguments)
          do (cond ((string= option "--kubeconfig")
                    (setf (getf options :kubeconfig) (or (pop arguments) (error "--kubeconfig requires a value"))))
                   (t (error "unknown mcp option: ~A" option))))
    options))

(defun run-mcp-command (options)
  "Serve MCP on stdin and stdout. Stdout carries only protocol messages: everything
else any code prints goes to stderr."
  (let ((input (sb-sys:make-fd-stream 0 :input t :external-format :utf-8 :buffering :full))
        (output (sb-sys:make-fd-stream 1 :output t :external-format :utf-8 :buffering :full)))
    (serve-mcp input output (getf options :kubeconfig))
    0))
