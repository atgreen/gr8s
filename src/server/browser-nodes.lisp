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
                            (:constructor %make-browser-runtime (session)))
  "A runtime whose containers run in a browser: each call is a request over SESSION, and
the Pods it holds are what the browser last reported."
  session)

(defun make-browser-runtime (session)
  "A runtime for SESSION's browser, keeping the status the browser reports for each Pod."
  (let ((runtime (%make-browser-runtime session)))
    (setf (browser-session-on-message session)
          (lambda (message)
            (when (and (equal "status" (gethash "op" message)) (stringp (gethash "uid" message)))
              (browser-runtime-note-status runtime (gethash "uid" message) (gethash "status" message)))))
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

(defun start-browser-node-reporter (session store name)
  "Tell SESSION's browser how its node NAME and the cluster are doing until it goes."
  (bt:make-thread
   (lambda ()
     (loop until (browser-session-closed session)
           do (handler-case (browser-session-send session (browser-node-info store name))
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
           :documentation "The root image file the page boots Pods from, or NIL."))
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
                 (let ((runtime (make-browser-runtime session))
                       (architecture (if (equal "amd64" (gethash "arch" hello)) "amd64" "arm64")))
                   (setf name (browser-node-name))
                   (start-virtual-node host name
                                       :labels (core-object "gr8s.io/browser" "true"
                                                            "gr8s.io/runtime" "unkernel")
                                       :taints (vector (apply #'core-object +browser-node-taint+))
                                       :runtime-options (list :runtime "browser" :runtime-object runtime
                                                             :architecture architecture))
                   (browser-session-send session (core-object "op" "welcome" "node" name))
                   (format t "gr8s browser node ~A joined~%" name)
                   (start-browser-node-reporter session (virtual-node-host-store host) name)
                   (run-browser-session session))))
           (error (condition)
             (format *error-output* "gr8s browser node~@[ ~A~]: ~A~%" name condition)))
      (when name
        (stop-virtual-node host name)
        (format t "gr8s browser node ~A left~%" name))
      (ignore-errors (close stream)))))

(defmethod hunchentoot:acceptor-dispatch-request ((acceptor browser-join-acceptor) request)
  (let ((path (hunchentoot:script-name request)))
    (cond ((and (equal path "/socket")
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

(defun start-browser-join-listener (nodes address port &key distro)
  "Listen on ADDRESS:PORT for browsers joining as nodes on NODES, serving the join page and
DISTRO, the root image file Pods boot from. Returns the acceptor."
  (hunchentoot:start (make-instance 'browser-join-acceptor
                                    :address address :port port :nodes nodes
                                    :distro (and distro (pathname distro))
                                    :access-log-destination nil
                                    :message-log-destination *error-output*)))
