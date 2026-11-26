;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; `gr8s doctor observe' (podster-e9a.3): read the cluster's flow events from
;;;; /apis/gr8s.io/v1/flows with the kubeconfig's credentials and print them, one
;;;; per line, or as JSON. A policy drop names the policies isolating its Pod. A
;;;; foreign cluster has no such API; its gr8s-net agents serve them instead.

(in-package #:gr8s.server)

(defun parse-doctor-observe-options (arguments)
  "Parse `gr8s doctor observe' options."
  (let ((options (list :command :doctor-observe :kubeconfig (default-client-kubeconfig))))
    (loop while arguments
          for option = (pop arguments)
          do (flet ((value ()
                      (or (pop arguments) (error "~A requires a value" option))))
               (cond
                 ((member option '("-f" "--follow") :test #'string=) (setf (getf options :follow) t))
                 ((string= option "--json") (setf (getf options :json) t))
                 ((member option '("-n" "--namespace") :test #'string=)
                  (setf (getf options :namespace) (value)))
                 ((string= option "--pod") (setf (getf options :pod) (value)))
                 ((string= option "--node") (setf (getf options :node) (value)))
                 ((string= option "--verdict")
                  (let ((verdict (string-upcase (value))))
                    (unless (member verdict '("DROPPED" "FORWARDED") :test #'string=)
                      (error "--verdict must be dropped or forwarded"))
                    (setf (getf options :verdict) verdict)))
                 ((string= option "--kubeconfig") (setf (getf options :kubeconfig) (value)))
                 ;; Serve them as Hubble's Observer API instead, for the stock hubble CLI.
                 ((string= option "--serve") (setf (getf options :command) :hubble-serve))
                 ((string= option "--listen") (setf (getf options :listen) (value)))
                 (t (error "unknown doctor observe option: ~A" option)))))
    (let ((namespace (getf options :namespace)))
      (when (and namespace (not (dns-label-p namespace)))
        (error "--namespace must be a Namespace name")))
    (if (eq (getf options :command) :hubble-serve)
        (parse-hubble-listen options)
        options)))

(defun doctor-observe-path (options)
  "The flows URL path and query OPTIONS ask for."
  (format nil "/apis/gr8s.io/v1/~@[namespaces/~A/~]flows~:[~;?watch=true~]"
          (getf options :namespace) (getf options :follow)))

(defun flow-matches-options-p (flow options)
  "Whether FLOW passes the --pod, --node and --verdict filters."
  (let ((pod (getf options :pod)) (node (getf options :node)) (verdict (getf options :verdict)))
    (and (or (null pod) (equal pod (gethash "pod" flow)) (equal pod (gethash "peerPod" flow)))
         (or (null node) (equal node (gethash "node" flow)))
         (or (null verdict) (equal verdict (gethash "verdict" flow))))))

(defun flow-endpoint-text (namespace pod address port)
  "One side of a flow: its Pod when known, else its address, with its port."
  (format nil "~A~@[:~D~]"
          (cond ((and pod namespace) (format nil "~A/~A" namespace pod))
                (pod)
                (address)
                (t "?"))
          port))

(defun format-flow-line (flow)
  "FLOW as one line, the Pod's side first for traffic from it and last for traffic to it."
  (if (gethash "error" flow)
      (format nil "~A: unavailable: ~A" (gethash "node" flow) (gethash "error" flow))
      (let* ((time (gethash "time" flow ""))
             (clock (if (> (length time) 19) (subseq time 11 (min 23 (length time))) time))
             (pod (flow-endpoint-text (gethash "namespace" flow) (gethash "pod" flow)
                                      (gethash "podAddress" flow) (gethash "podPort" flow)))
             (peer (flow-endpoint-text (gethash "peerNamespace" flow) (gethash "peerPod" flow)
                                       (gethash "peerAddress" flow) (gethash "peerPort" flow)))
             (ingress (equal "ingress" (gethash "direction" flow)))
             (policies (coerce (gethash "policies" flow #()) 'list))
             (l7 (gethash "l7" flow)))
        (when (and l7 (equal "egress" (gethash "direction" flow)))
          ;; The node egress proxy's: a DNS answer, a connection, or a relayed request,
          ;; from the Pod to the name it asked for.
          (return-from format-flow-line
            (let ((head (format nil "~A ~A: ~A ->" clock (gethash "node" flow "?") pod))
                  (dropped (equal "DROPPED" (gethash "verdict" flow))))
              (cond ((equal "dns" (gethash "type" l7))
                     (format nil "~A DNS ~A ~:[answered~;REFUSED by policy~]" head (gethash "query" l7) dropped))
                    ((equal "egress" (gethash "type" l7))
                     (format nil "~A ~A (~A:~A) ~A~@[ by rule ~A~]~@[ from ~A~]~@[ AUDIT: ~A~]" head (gethash "host" l7 "?")
                             (gethash "peerAddress" flow "?") (gethash "peerPort" flow "?")
                             (gethash "verdict" flow) (gethash "rule" l7) (gethash "process" l7) (gethash "audit" l7)))
                    (t
                     (format nil "~A ~A ~A~A ~D~@[ injected ~A~]~@[ AUDIT: ~A~]" head
                             (gethash "method" l7) (gethash "host" l7) (gethash "path" l7) (gethash "code" l7)
                             (gethash "injected" l7) (gethash "audit" l7)))))))
        (when l7
          ;; A Gateway request: what was asked, of which backend, and how it went.
          (return-from format-flow-line
            (format nil "~A ~A: ~A -> ~A HTTP ~A ~A~A ~D ~,1Fms~@[ (~A)~]"
                    clock (gethash "node" flow "?") peer pod
                    (gethash "method" l7) (gethash "host" l7) (gethash "path" l7) (gethash "code" l7)
                    (/ (gethash "latencyNs" l7 0) 1000000.0) (gethash "route" l7))))
        (format nil "~A ~A: ~A -> ~A~@[ ~A~] ~A~@[ ~A~]~@[ (~{~A~^, ~})~]"
                clock (gethash "node" flow "?")
                (if ingress peer pod) (if ingress pod peer)
                (gethash "protocol" flow) (gethash "verdict" flow)
                (let ((reason (gethash "reason" flow)))
                  (and reason (if (equal reason "policy") "by policy" reason)))
                (and policies (mapcar (lambda (name) (format nil "~A/~A" (gethash "namespace" flow) name))
                                      policies))))))

(defun call-with-flow-lines (stream headers function)
  "Call FUNCTION with each line of the response body on STREAM, which HEADERS frame."
  (let* ((chunked (search "chunked" (string-downcase (or (cdr (assoc :transfer-encoding headers)) ""))))
         (body (if chunked
                   (let ((decoded (chunga:make-chunked-stream stream)))
                     (setf (chunga:chunked-stream-input-chunking-p decoded) t)
                     decoded)
                   stream))
         (text (flexi-streams:make-flexi-stream body :external-format :utf-8)))
    (loop for line = (handler-case (read-line text nil nil)
                       ;; A followed stream ends when the server closes it.
                       (end-of-file () nil))
          while line
          do (funcall function line))))

(defun gr8s-api-served-p (config)
  "Whether the cluster serves the gr8s.io/v1 API, as gr8s does and a foreign cluster doesn't."
  (/= 404 (nth-value 1 (debug-api-request-json config "GET" "/apis/gr8s.io/v1"))))

(defun call-with-api-flows (config namespace follow function &key on-open)
  "Call FUNCTION with each flow line, read with kubeconfig CONFIG, from NAMESPACE (every
one without it), until the stream ends; with FOLLOW, new ones until then too. ON-OPEN,
when given, receives a function that ends the stream from another thread. On a cluster
that isn't gr8s, the lines come from its gr8s-net agents."
  (multiple-value-bind (stream socket host port base-path) (open-debug-api-stream config)
    (unwind-protect
         (progn
           (write-debug-http-request stream "GET" host port
                                     (concatenate 'string base-path
                                                  (doctor-observe-path (list :namespace namespace :follow follow)))
                                     (getf config :token))
           (multiple-value-bind (status headers)
               (gr8s.protocol::parse-http-response-head (gr8s.protocol::read-http-response-head stream))
             (when (and (= status 404) (not (gr8s-api-served-p config)))
               (ignore-errors (close stream))
               (ignore-errors (usocket:socket-close socket))
               (return-from call-with-api-flows
                 (call-with-net-agent-flows config namespace follow function :on-open on-open)))
             (unless (= status 200)
               (error "the Kubernetes API answered HTTP ~D~:[~; (this cluster may not serve flow events, or you may not be allowed to list them)~]"
                      status (member status '(403 404))))
             (when on-open
               ;; Shut the socket down, never close it, from another thread.
               (funcall on-open (lambda () (ignore-errors (usocket:socket-shutdown socket :io)))))
             (call-with-flow-lines stream headers function)))
      (ignore-errors (close stream))
      (ignore-errors (usocket:socket-close socket)))))

(defun run-doctor-observe (options &optional (output *standard-output*))
  "Print the flow events OPTIONS select, until the stream ends; with --follow, until interrupted."
  (call-with-debug-kubeconfig
   (getf options :kubeconfig)
   (lambda (config)
     (call-with-api-flows
      config (getf options :namespace) (getf options :follow)
      (lambda (line)
        (let ((flow (ignore-errors (com.inuoe.jzon:parse line))))
          (when (and (hash-table-p flow) (flow-matches-options-p flow options))
            (if (getf options :json)
                (write-line line output)
                (write-line (format-flow-line flow) output))
            (force-output output)))))))
  0)
