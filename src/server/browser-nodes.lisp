;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Browser nodes: a browser session as a worker node (podster-57fv.2).
;;;;
;;;; A browser opens one WebSocket to serve's join listener. The server makes it a
;;;; virtual node (virtual-nodes.lisp) whose runtime is a BROWSER-RUNTIME: the
;;;; agent's Pod sync, leases and status run here, and only the containers run in the
;;;; browser (docs/design-browser-nodes.md). The session carries JSON text frames:
;;;; requests from the server with an "id" and the browser's replies to them, and
;;;; "status" messages the browser sends whenever a Pod's containers change, which
;;;; the runtime keeps for the agent to observe. Nothing the browser says is trusted
;;;; beyond its own Pods' status and output.

(in-package #:gr8s.server)

(defparameter +browser-node-request-seconds+ 120
  "How long a request waits for the browser: an ensure may boot a VM and fetch an image.")

(defstruct (browser-session (:constructor %make-browser-session (stream)))
  "One browser's connection: its raw WebSocket STREAM, outstanding requests by id, and
the handler for the messages it sends unasked."
  stream
  (write-lock (bt:make-lock "gr8s browser session writes"))
  (lock (bt:make-lock "gr8s browser session"))
  (changed (bt:make-condition-variable))
  (next-id 0)
  (replies (make-hash-table))
  (closed nil)
  (on-message nil))

(defun browser-session-send (session object)
  "Send OBJECT to SESSION's browser as one text frame. Signals when the connection is gone."
  (let ((octets (gr8s.resources:stringify-to-utf-8-bytes object)))
    (bt:with-lock-held ((browser-session-write-lock session))
      (gr8s.protocol::write-websocket-frame (browser-session-stream session) 1 octets)
      (force-output (browser-session-stream session)))))

(defun browser-session-call (session op &rest fields)
  "Ask SESSION's browser to do OP, with FIELDS (alternating keys and values), and return
its reply's result object. Signals a RUNTIME-ERROR carrying the browser's error, or when
the browser doesn't answer in time or goes away."
  (let ((id (bt:with-lock-held ((browser-session-lock session))
              (when (browser-session-closed session)
                (error 'runtime-error :message "The browser node is disconnected"))
              (let ((id (incf (browser-session-next-id session))))
                (setf (gethash id (browser-session-replies session)) :waiting)
                id)))
        (message (apply #'core-object "id" nil "op" op fields)))
    (setf (gethash "id" message) id)
    (handler-case (browser-session-send session message)
      (error (condition)
        (bt:with-lock-held ((browser-session-lock session))
          (remhash id (browser-session-replies session)))
        (error 'runtime-error :message (format nil "The browser node is disconnected: ~A" condition))))
    (let ((deadline (+ (get-internal-real-time)
                       (* +browser-node-request-seconds+ internal-time-units-per-second))))
      (bt:with-lock-held ((browser-session-lock session))
        (loop for reply = (gethash id (browser-session-replies session))
              until (or (not (eq reply :waiting)) (browser-session-closed session)
                        (>= (get-internal-real-time) deadline))
              do (bt:condition-wait (browser-session-changed session) (browser-session-lock session)
                                    :timeout 1))
        (let ((reply (gethash id (browser-session-replies session))))
          (remhash id (browser-session-replies session))
          (cond ((hash-table-p reply)
                 (if (gethash "error" reply)
                     (error 'runtime-error :message (format nil "~A" (gethash "error" reply)))
                     (gethash "result" reply (core-object))))
                ((browser-session-closed session)
                 (error 'runtime-error :message "The browser node disconnected"))
                (t (error 'runtime-error :message (format nil "The browser node didn't answer ~A in time" op)))))))))

(defun browser-session-receive (session message)
  "Deliver one MESSAGE from the browser: a reply to a waiting request, or to the session's
handler."
  (let ((id (gethash "id" message)))
    (if (integerp id)
        (bt:with-lock-held ((browser-session-lock session))
          ;; Only a reply someone waits for: an unknown or repeated id is dropped.
          (when (eq :waiting (gethash id (browser-session-replies session)))
            (setf (gethash id (browser-session-replies session)) message)
            (bt:condition-notify (browser-session-changed session))))
        (let ((handler (browser-session-on-message session)))
          (when handler (funcall handler message))))))

(defun run-browser-session (session)
  "Read SESSION's frames until the browser goes away, answering pings, then mark it closed
and wake every waiting request. Returns when the connection has ended."
  (let ((stream (browser-session-stream session)))
    (unwind-protect
         (handler-case
             (loop
               (multiple-value-bind (opcode payload) (gr8s.protocol::read-websocket-frame stream)
                 (case opcode
                   (1 (let ((message (ignore-errors (com.inuoe.jzon:parse payload))))
                        (when (hash-table-p message) (browser-session-receive session message))))
                   (8 (return))
                   (9 (bt:with-lock-held ((browser-session-write-lock session))
                        (gr8s.protocol::write-websocket-frame stream 10 payload)
                        (force-output stream))))))
           (error () nil))
      (bt:with-lock-held ((browser-session-lock session))
        (setf (browser-session-closed session) t)
        (bt:condition-notify (browser-session-changed session)))
      (ignore-errors (close stream)))))

;;; The runtime

(defstruct (browser-runtime (:include gr8s.runtime::fake-runtime)
                            (:constructor %make-browser-runtime (session endpoint)))
  "A runtime whose containers run in a browser: each call is a request over SESSION, and
the Pods it holds are what the browser last reported. ENDPOINT, (address port), is the
join listener, which also serves this runtime's exec streams."
  session endpoint
  (execs (make-hash-table :test #'equal :synchronized t))
  ;; "namespace/name" -> uid, for the Pod proxy.
  (names (make-hash-table :test #'equal :synchronized t)))

(defun make-browser-runtime (session &optional endpoint)
  "A runtime for SESSION's browser, keeping the status the browser reports for each Pod and
passing each running exec its output."
  (let ((runtime (%make-browser-runtime session endpoint)))
    (setf (browser-session-on-message session)
          (lambda (message)
            (let ((op (gethash "op" message)))
              (cond ((and (equal "status" op) (stringp (gethash "uid" message)))
                     (browser-runtime-note-status runtime (gethash "uid" message) (gethash "status" message)))
                    ((member op '("exec-output" "exec-exit") :test #'equal)
                     (let ((exec (gethash (gethash "exec" message) (browser-runtime-execs runtime))))
                       (when exec (browser-exec-deliver exec message))))))))
    runtime))

(defun browser-runtime-note-status (runtime uid status)
  "Record STATUS, a PodStatus object the browser reported, as what UID's Pod is now. A Pod
the runtime doesn't hold is ignored: the browser can't add Pods of its own."
  (let ((pod (gethash uid (gr8s.runtime::fake-runtime-pods runtime))))
    (when (and pod (hash-table-p status))
      (let ((phase (gethash "phase" status)))
        (when (member phase '("Pending" "Running" "Succeeded" "Failed") :test #'equal)
          (setf (gr8s.runtime::runtime-pod-phase pod) phase)))
      (setf (gr8s.runtime::runtime-pod-status pod) status))))

(defun browser-pod-request (pod)
  "What the browser needs to run POD: its identity and its spec."
  (let ((object (gr8s.model::pod-to-object pod)))
    (core-object "uid" (gr8s.model::pod-uid pod)
                 "name" (gethash "name" (gethash "metadata" object))
                 "namespace" (gethash "namespace" (gethash "metadata" object))
                 "spec" (gethash "spec" object))))

(defmethod gr8s.runtime::runtime-ensure ((runtime browser-runtime) pod)
  (let* ((result (browser-session-call (browser-runtime-session runtime) "ensure"
                                       "pod" (browser-pod-request pod)))
         (status (gethash "status" result))
         (runtime-pod (or (gethash (gr8s.model::pod-uid pod) (gr8s.runtime::fake-runtime-pods runtime))
                          (gr8s.runtime::make-runtime-pod :uid (gr8s.model::pod-uid pod)))))
    (let ((request (browser-pod-request pod)))
      (setf (gethash (format nil "~A/~A" (gethash "namespace" request) (gethash "name" request))
                     (browser-runtime-names runtime))
            (gr8s.model::pod-uid pod)))
    (setf (gr8s.runtime::runtime-pod-resource-version runtime-pod) (gr8s.model::pod-resource-version pod)
          (gr8s.runtime::runtime-pod-spec-fingerprint runtime-pod) (gr8s.runtime::pod-runtime-spec-fingerprint pod)
          (gethash (gr8s.model::pod-uid pod) (gr8s.runtime::fake-runtime-pods runtime)) runtime-pod)
    (browser-runtime-note-status runtime (gr8s.model::pod-uid pod) status)
    runtime-pod))

(defmethod gr8s.runtime::runtime-delete ((runtime browser-runtime) uid)
  ;; A browser that has gone has nothing left to stop.
  (ignore-errors (browser-session-call (browser-runtime-session runtime) "delete" "uid" uid))
  (remhash uid (gr8s.runtime::fake-runtime-pods runtime)))

(defmethod gr8s.runtime::runtime-logs ((runtime browser-runtime) uid container &key tail previous)
  (declare (ignore previous))
  (let ((result (browser-session-call (browser-runtime-session runtime) "logs"
                                      "uid" uid "container" container "tail" (or tail 'null))))
    (or (gethash "text" result) "")))

(defmethod gr8s.runtime::runtime-send-logs ((runtime browser-runtime) uid container function
                                            &key previous tail-lines since (start-offset 0))
  "The browser's log of CONTAINER as CRI log lines, the form every log reader here takes. The
browser keeps no timestamps, so every line is stamped now."
  (declare (ignore since))
  (let* ((text (gr8s.runtime::runtime-logs runtime uid container :tail tail-lines :previous previous))
         (stamp (gr8s.store::current-timestamp))
         (lines (uiop:split-string (string-right-trim '(#\Newline) text) :separator '(#\Newline)))
         (bytes (trivial-utf-8:string-to-utf-8-bytes
                 (if (equal text "")
                     ""
                     (format nil "~{~A~%~}" (mapcar (lambda (line) (format nil "~A stdout F ~A" stamp line)) lines)))))
         (start (if (> start-offset (length bytes)) 0 start-offset)))
    (funcall function (subseq bytes start) start)
    (length bytes)))

(defmethod gr8s.runtime::runtime-exec-sync ((runtime browser-runtime) uid container command &key timeout)
  (declare (ignore timeout))
  (let ((result (browser-session-call (browser-runtime-session runtime) "exec"
                                      "uid" uid "container" container
                                      "command" (coerce command 'vector))))
    (gr8s.runtime::make-runtime-exec-result
     :stdout (trivial-utf-8:string-to-utf-8-bytes (or (gethash "stdout" result) ""))
     :stderr (trivial-utf-8:string-to-utf-8-bytes (or (gethash "stderr" result) ""))
     :exit-code (or (gethash "exitCode" result) 0))))

;;; Exec: kubectl's streams, bridged to a program in the browser
;;;
;;; The agent streams an exec from a URL the runtime hands it, as from a CRI streaming
;;; server: it dials the URL and speaks SPDY remotecommand. A browser runtime's URL is a
;;; one-time path on the join listener, where the streams are bridged to the session:
;;; the browser runs the command and sends its output and exit status back.

(defvar *browser-exec-tokens* (make-hash-table :test #'equal :synchronized t)
  "One-time exec tokens to (runtime . request), until their stream is opened.")

(defstruct (browser-exec (:constructor make-browser-exec (id)))
  id
  (lock (bt:make-lock "gr8s browser exec"))
  (arrived (bt:make-condition-variable))
  (messages '()))

(defun browser-exec-deliver (exec message)
  "Queue MESSAGE, the browser's output or exit for EXEC."
  (bt:with-lock-held ((browser-exec-lock exec))
    (setf (browser-exec-messages exec) (append (browser-exec-messages exec) (list message)))
    (bt:condition-notify (browser-exec-arrived exec))))

(defun browser-exec-next (exec session)
  "The next message for EXEC, waiting for it; NIL once the browser has gone."
  (bt:with-lock-held ((browser-exec-lock exec))
    (loop until (or (browser-exec-messages exec) (browser-session-closed session))
          do (bt:condition-wait (browser-exec-arrived exec) (browser-exec-lock exec) :timeout 1))
    (pop (browser-exec-messages exec))))

(defmethod gr8s.runtime::runtime-exec-url ((runtime browser-runtime) uid container command
                                           &key stdin stdout stderr tty)
  (unless (browser-runtime-endpoint runtime)
    (error 'runtime-error :message "This browser node has no exec endpoint"))
  (let ((token (format nil "~(~{~2,'0x~}~)" (coerce (secure-random-octets 16) 'list))))
    (setf (gethash token *browser-exec-tokens*)
          (cons runtime (list :uid uid :container container :command command
                              :stdin stdin :stdout stdout :stderr stderr :tty tty)))
    (destructuring-bind (address port) (browser-runtime-endpoint runtime)
      (format nil "http://~A:~D/exec/~A" address port token))))

(defun octets-base64 (octets)
  (cl-base64:usb8-array-to-base64-string (coerce octets '(simple-array (unsigned-byte 8) (*)))))

(defun serve-browser-exec (token)
  "Serve the exec TOKEN names to the SPDY client on this request: open its streams, start
the command in the browser, and pass input one way and output and the exit status the
other until the command ends or the client goes."
  (let ((entry (gethash token *browser-exec-tokens*)))
    (remhash token *browser-exec-tokens*)
    (unless entry
      (setf (hunchentoot:return-code*) hunchentoot:+http-not-found+)
      (return-from serve-browser-exec "no such exec"))
    (destructuring-bind (runtime . request) entry
      (let* ((session (browser-runtime-session runtime))
             (tty (getf request :tty))
             (options (gr8s.apiserver::make-exec-options
                       :stdin (getf request :stdin) :stdout (getf request :stdout)
                       :stderr (and (getf request :stderr) (not tty)) :tty tty))
             (exec (make-browser-exec token))
             (input-thread nil))
        (multiple-value-bind (protocol named) (gr8s.apiserver::negotiate-spdy-remotecommand-protocol)
          (let ((server (gr8s.protocol:make-spdy-server
                         (gr8s.apiserver::begin-spdy-remotecommand protocol named))))
            (multiple-value-bind (streams early)
                (gr8s.apiserver::accept-remotecommand-streams
                 server (gr8s.apiserver::remotecommand-expected-streams options protocol))
              (flet ((stream-id (type) (cdr (assoc type streams :test #'equal)))
                     (send (&rest fields)
                       (ignore-errors (browser-session-send session (apply #'core-object "exec" token fields)))))
                (setf (gethash token (browser-runtime-execs runtime)) exec)
                (unwind-protect
                     (handler-case
                         (progn
                           (browser-session-call session "exec-start" "exec" token
                                                 "uid" (getf request :uid) "container" (getf request :container)
                                                 "command" (coerce (getf request :command) 'vector)
                                                 "tty" (and tty t) "stdin" (and (getf request :stdin) t))
                           (setf input-thread
                                 (bt:make-thread
                                  (lambda ()
                                    (let ((stdin (stream-id "stdin")) (resize (stream-id "resize"))
                                          (pending (make-array 0 :element-type '(unsigned-byte 8))))
                                      (flet ((take (id fin data)
                                               (cond ((eql id stdin)
                                                      (when (plusp (length data))
                                                        (send "op" "exec-input" "data" (octets-base64 data)))
                                                      (when fin (send "op" "exec-input" "eof" t)))
                                                     ((eql id resize)
                                                      (multiple-value-bind (sizes rest)
                                                          (gr8s.apiserver::remotecommand-terminal-sizes pending data)
                                                        (setf pending rest)
                                                        (loop for (rows . columns) in sizes
                                                              do (send "op" "exec-resize" "rows" rows "cols" columns)))))))
                                        (handler-case
                                            (progn
                                              (dolist (frame early) (apply #'take frame))
                                              (loop for frame = (gr8s.protocol::spdy-server-read-frame server)
                                                    do (case (first frame)
                                                         ((nil) (send "op" "exec-kill") (return))
                                                         (:data (apply #'take (rest frame)))
                                                         (:reset (when (eql (second frame) stdin)
                                                                   (send "op" "exec-input" "eof" t))))))
                                          (error () nil)))))
                                  :name "gr8s browser exec input"))
                           (loop for message = (browser-exec-next exec session)
                                 do (cond
                                      ((null message)
                                       (error 'runtime-error :message "The browser node disconnected"))
                                      ((equal "exec-output" (gethash "op" message))
                                       (let ((id (if (eql 2 (gethash "channel" message))
                                                     (or (stream-id "stderr") (stream-id "stdout"))
                                                     (stream-id "stdout"))))
                                         (when id
                                           (gr8s.protocol::spdy-server-write-data
                                            server id (cl-base64:base64-string-to-usb8-array (gethash "data" message ""))))))
                                      (t
                                       (let ((status (gr8s.apiserver::spdy-remotecommand-status-bytes
                                                      protocol (or (gethash "exitCode" message) 1))))
                                         (when status
                                           (gr8s.protocol::spdy-server-write-data server (stream-id "error") status)))
                                       (return))))
                           (dolist (type '("stdout" "stderr" "error"))
                             (when (stream-id type)
                               (gr8s.protocol::spdy-server-write-data
                                server (stream-id type) (make-array 0 :element-type '(unsigned-byte 8)) :fin t))))
                       (error (condition)
                         (ignore-errors
                          (gr8s.protocol::spdy-server-write-data
                           server (stream-id "error")
                           (gr8s.apiserver::spdy-remotecommand-failure-bytes protocol (princ-to-string condition))
                           :fin t))))
                  (remhash token (browser-runtime-execs runtime))
                  (send "op" "exec-kill")
                  (when input-thread (ignore-errors (bt:destroy-thread input-thread)))))))))))
  "")

;;; What the join page shows

(defparameter +browser-node-info-seconds+ 2
  "How often the server tells a browser how its node and the cluster are doing.")

(defun browser-node-info (store name)
  "A summary for NAME's page: the node itself, the Pods on it, and the cluster in counts.
A browser node is untrusted, so of other nodes and workloads it learns only totals."
  (let* ((nodes (gr8s.controllers::list-nodes store))
         (self (find name nodes :key #'gr8s.model::node-record-name :test #'equal))
         (pods (with-store-lock (store)
                 (loop for pod being the hash-values of (gr8s.store:pod-store-pods store) collect pod)))
         (running 0)
         (here '()))
    (dolist (pod pods)
      ;; What the nodes observed, which the API shows, not the stored spec's status.
      (let* ((object (gr8s.model::pod-to-object pod))
             (status (or (with-store-lock (store)
                           (gethash (gr8s.model::pod-uid pod) (gr8s.store:pod-store-pod-observed-statuses store)))
                         (gethash "status" object (core-object))))
             (phase (gr8s.controllers::pod-scheduling-phase store pod)))
        (when (equal phase "Running") (incf running))
        (when (equal name (gr8s.model::pod-node-name pod))
          (push (core-object
                 "name" (gethash "name" (gethash "metadata" object))
                 "namespace" (gethash "namespace" (gethash "metadata" object))
                 "phase" phase
                 "startTime" (gethash "startTime" status 'null)
                 "containers"
                 (map 'vector
                      (lambda (container)
                        (let ((state (find (gethash "name" container)
                                           (gethash "containerStatuses" status #())
                                           :key (lambda (s) (gethash "name" s)) :test #'equal)))
                          (core-object "name" (gethash "name" container)
                                       "image" (gethash "image" container "")
                                       "ports" (map 'vector (lambda (port) (gethash "containerPort" port))
                                                    (gethash "ports" container #()))
                                       "restartCount" (if state (gethash "restartCount" state 0) 0)
                                       "state" (if state (gethash "state" state (core-object)) (core-object)))))
                      (gethash "containers" (gethash "spec" object) #())))
                here))))
    (core-object
     "op" "info"
     "node" (if self
                (core-object "name" name
                             "ready" (and (gr8s.model::node-record-ready-p self) t)
                             "created" (or (gr8s.model::node-record-creation-timestamp self) 'null)
                             "podCIDR" (or (gr8s.model::node-record-pod-cidr self) "")
                             "labels" (gr8s.kubelet::node-labels self)
                             "taints" (or (gr8s.model::node-record-taints self) #()))
                (core-object "name" name "ready" nil))
     "pods" (coerce (sort here #'string< :key (lambda (p) (gethash "name" p))) 'vector)
     "cluster" (core-object
                "version" (gr8s.foundation::kubernetes-git-version)
                "nodes" (length nodes)
                "readyNodes" (count-if #'gr8s.model::node-record-ready-p nodes)
                "browserNodes" (count-if (lambda (node)
                                           (equal "true" (gethash "gr8s.io/browser"
                                                                  (or (gr8s.model::node-record-labels node)
                                                                      (core-object)))))
                                         nodes)
                "pods" (length pods)
                "runningPods" running))))

(defun start-browser-node-reporter (session store name &key pod-proxy)
  "Tell SESSION's browser how its node NAME and the cluster are doing until it goes, and
whether its Pods' ports are reachable through POD-PROXY."
  (bt:make-thread
   (lambda ()
     (loop until (browser-session-closed session)
           do (handler-case (let ((info (browser-node-info store name)))
                              (setf (gethash "podProxy" info) (and pod-proxy t))
                              (browser-session-send session info))
                (error () (return)))
              (loop repeat (* 10 +browser-node-info-seconds+)
                    until (browser-session-closed session) do (sleep 0.1))))
   :name "gr8s browser node reporter"))

;;; Joining: the listener a browser connects to

(defparameter +browser-node-runtime-js+ #.(dashboard-agent-asset-text "browser-node-runtime.mjs")
  "The browser's half of a browser node, served to the join page and used by tests under Node.")

(defparameter +browser-node-html+ #.(dashboard-agent-asset-text "browser-node.html")
  "The join page.")

(defparameter +browser-node-taint+
  '("key" "gr8s.io/browser" "value" "true" "effect" "NoSchedule")
  "The taint every browser node carries: only Pods that tolerate it run in a browser.")

(defclass browser-join-acceptor (hunchentoot:easy-acceptor)
  ((nodes :initarg :nodes :reader browser-join-nodes
          :documentation "The virtual-node-host browser nodes run on.")
   (distro :initarg :distro :initform nil :reader browser-join-distro
           :documentation "The root image file the page boots Pods from, or NIL.")
   (pod-proxy :initarg :pod-proxy :initform nil :reader browser-join-pod-proxy
              :documentation "Whether /pods/NS/NAME/PORT/ proxies HTTP to browser Pods. Anyone
who can reach the listener reaches those ports, so it is off unless asked for.")
   (runtimes :initform (make-hash-table :test #'equal :synchronized t) :reader browser-join-runtimes
             :documentation "Each connected browser node's runtime, by node name."))
  (:documentation "Serves the join page and accepts browser nodes' sessions."))

(defun browser-node-name ()
  "A fresh name for a browser node."
  (format nil "browser-~(~{~2,'0x~}~)" (coerce (secure-random-octets 3) 'list)))

(defun accept-browser-node (acceptor request)
  "Run one browser's session on REQUEST's upgraded connection: read its hello, make it a
node, answer with the node's name, and serve its runtime until the browser goes. The node
stops with the session."
  (let* ((stream (dashboard-agent-websocket request))
         (session (%make-browser-session stream))
         (host (browser-join-nodes acceptor))
         (name nil))
    (unwind-protect
         (handler-case
             (multiple-value-bind (opcode payload) (gr8s.protocol::read-websocket-frame stream)
               (let ((hello (and (= opcode 1) (ignore-errors (com.inuoe.jzon:parse payload)))))
                 (unless (and (hash-table-p hello) (equal "hello" (gethash "op" hello)))
                   (error "a browser node must say hello first"))
                 (let ((runtime (make-browser-runtime
                                 session (list (let ((address (hunchentoot:acceptor-address acceptor)))
                                                 (if (member address '(nil "0.0.0.0") :test #'equal)
                                                     "127.0.0.1" address))
                                               (hunchentoot:acceptor-port acceptor))))
                       (architecture (if (equal "amd64" (gethash "arch" hello)) "amd64" "arm64")))
                   (setf name (browser-node-name))
                   (start-virtual-node host name
                                       :labels (core-object "gr8s.io/browser" "true"
                                                            "gr8s.io/runtime" "unkernel")
                                       :taints (vector (apply #'core-object +browser-node-taint+))
                                       :runtime-options (list :runtime "browser" :runtime-object runtime
                                                             :architecture architecture))
                   (setf (gethash name (browser-join-runtimes acceptor)) runtime)
                   (browser-session-send session (core-object "op" "welcome" "node" name
                                                              "podProxy" (and (browser-join-pod-proxy acceptor) t)))
                   (format t "gr8s browser node ~A joined~%" name)
                   (start-browser-node-reporter session (virtual-node-host-store host) name
                                                :pod-proxy (browser-join-pod-proxy acceptor))
                   (run-browser-session session))))
           (error (condition)
             (format *error-output* "gr8s browser node~@[ ~A~]: ~A~%" name condition)))
      (when name
        (remhash name (browser-join-runtimes acceptor))
        (stop-virtual-node host name)
        (format t "gr8s browser node ~A left~%" name))
      (ignore-errors (close stream)))))

(defmethod hunchentoot:acceptor-dispatch-request ((acceptor browser-join-acceptor) request)
  (let ((path (hunchentoot:script-name request)))
    (cond ((and (uiop:string-prefix-p "/pods/" path) (browser-join-pod-proxy acceptor))
           (proxy-browser-pod acceptor request path))
          ((and (uiop:string-prefix-p "/exec/" path)
                (string-equal (hunchentoot:header-in :upgrade request) "SPDY/3.1"))
           (serve-browser-exec (subseq path 6)))
          ((and (equal path "/socket")
                (string-equal (hunchentoot:header-in :upgrade request) "websocket"))
           (accept-browser-node acceptor request)
           "")
          ((equal path "/")
           (setf (hunchentoot:content-type*) "text/html; charset=utf-8")
           +browser-node-html+)
          ((equal path "/browser-node-runtime.mjs")
           (setf (hunchentoot:content-type*) "text/javascript; charset=utf-8")
           +browser-node-runtime-js+)
          ((and (equal path "/distro.erofs") (browser-join-distro acceptor))
           ;; Read with range requests; hunchentoot answers those.
           (hunchentoot:handle-static-file (browser-join-distro acceptor) "application/octet-stream"))
          (t (setf (hunchentoot:return-code*) hunchentoot:+http-not-found+
                   (hunchentoot:content-type*) "text/plain")
             "not found"))))

(defun proxy-browser-pod (acceptor request path)
  "Answer REQUEST for /pods/NAMESPACE/NAME/PORT/REST by asking the Pod's browser to make it
to the Pod's PORT, and relay the response."
  (destructuring-bind (&optional namespace name port-text &rest rest)
      (uiop:split-string (subseq path (length "/pods/")) :separator '(#\/))
    (let* ((port (ignore-errors (parse-integer (or port-text ""))))
           (key (format nil "~A/~A" namespace name))
           (runtime (loop for runtime being the hash-values of (browser-join-runtimes acceptor)
                          when (gethash key (browser-runtime-names runtime)) return runtime)))
      (flet ((fail (code text)
               (setf (hunchentoot:return-code*) code (hunchentoot:content-type*) "text/plain")
               (return-from proxy-browser-pod text)))
        (unless (and port (< 0 port 65536)) (fail 400 "expected /pods/NAMESPACE/NAME/PORT/"))
        (unless runtime (fail 404 (format nil "no Pod ~A runs in a browser here" key)))
        (when (null rest)
          ;; Relative links in the page resolve under the Pod's path.
          (hunchentoot:redirect (format nil "~A/" path)))
        (let* ((query (hunchentoot:query-string request))
               (headers (let ((object (core-object)))
                          (loop for (header . value) in (hunchentoot:headers-in request)
                                unless (member header '(:host :connection :upgrade :content-length :accept-encoding))
                                  do (setf (gethash (string-downcase (symbol-name header)) object) value))
                          object))
               (body (hunchentoot:raw-post-data :request request :force-binary t))
               (result
                 (handler-case
                     (apply #'browser-session-call (browser-runtime-session runtime) "http"
                            "uid" (gethash key (browser-runtime-names runtime)) "port" port
                            "method" (string-upcase (symbol-name (hunchentoot:request-method request)))
                            "path" (format nil "/~{~A~^/~}~@[?~A~]" rest (and (plusp (length (or query ""))) query))
                            "headers" headers
                            (and body (plusp (length body)) (list "body" (octets-base64 body))))
                   (runtime-error (condition) (fail 502 (princ-to-string condition))))))
          (setf (hunchentoot:return-code*) (or (gethash "status" result) 502))
          (loop for pair across (gethash "headers" result #())
                for header = (string-downcase (aref pair 0))
                unless (member header '("connection" "transfer-encoding" "content-length" "keep-alive")
                               :test #'equal)
                  do (setf (hunchentoot:header-out header) (aref pair 1)))
          (cl-base64:base64-string-to-usb8-array (gethash "body" result "")))))))

(defun start-browser-join-listener (nodes address port &key distro pod-proxy)
  "Listen on ADDRESS:PORT for browsers joining as nodes on NODES, serving the join page and
DISTRO, the root image file Pods boot from, and with POD-PROXY, HTTP to their Pods.
Returns the acceptor."
  (hunchentoot:start (make-instance 'browser-join-acceptor
                                    :address address :port port :nodes nodes :pod-proxy pod-proxy
                                    :distro (and distro (pathname distro))
                                    :access-log-destination nil
                                    :message-log-destination *error-output*)))
