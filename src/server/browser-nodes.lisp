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

(defvar *browser-session-call-seconds* +browser-node-request-seconds+
  "How long BROWSER-SESSION-CALL waits for the browser's answer.")

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
  ;; This session's epoch: every request carries it, and the browser acts only on its own.
  (epoch 0)
  (on-message nil)
  ;; Called with each binary message: an Ethernet frame from the browser's Pods.
  (on-frame nil))

(defun browser-session-send-frame (session frame)
  "Send FRAME, an Ethernet frame for the browser's Pods, as one binary message."
  (bt:with-lock-held ((browser-session-write-lock session))
    (gr8s.protocol::write-websocket-frame (browser-session-stream session) 2
                                          (coerce frame '(simple-array (unsigned-byte 8) (*))))
    (force-output (browser-session-stream session))))

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
    (setf (gethash "id" message) id
          (gethash "epoch" message) (browser-session-epoch session))
    (handler-case (browser-session-send session message)
      (error (condition)
        (bt:with-lock-held ((browser-session-lock session))
          (remhash id (browser-session-replies session)))
        (error 'runtime-error :message (format nil "The browser node is disconnected: ~A" condition))))
    (let ((deadline (+ (get-internal-real-time)
                       (* *browser-session-call-seconds* internal-time-units-per-second))))
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
                   (2 (let ((handler (browser-session-on-frame session)))
                        (when handler (ignore-errors (funcall handler payload)))))
                   (8 (return))
                   (9 (bt:with-lock-held ((browser-session-write-lock session))
                        (gr8s.protocol::write-websocket-frame stream 10 payload)
                        (force-output stream))))))
           (end-of-file () nil)
           (error (condition)
             (format *error-output* "gr8s browser session ended: ~A~%" condition)))
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
  ;; The node's Pod network (browser-network.lisp), or NIL when it has none.
  (network nil)
  ;; The server's image cache (browser-images.lisp), or NIL: containers then run in the
  ;; tab's own root file system.
  (images nil)
  ;; The cluster store, for Pods' pull Secrets.
  (store nil)
  ;; What the browser last reported (its "stats" answer) and how long asking took.
  (stats nil) (rtt nil)
  ;; The join listener's handler for this browser's messages to its peers ("signal",
  ;; "have"), and a function of a layer digest giving the other nodes that hold it.
  (peer-handler nil) (layer-holders nil)
  (execs (make-hash-table :test #'equal :synchronized t))
  ;; "namespace/name" -> uid, for the Pod proxy.
  (names (make-hash-table :test #'equal :synchronized t))
  ;; What browser the tab says it is ("Firefox on Linux"), and when it joined.
  (browser nil) (joined (get-universal-time)))

(defun make-browser-runtime (session &optional endpoint)
  "A runtime for SESSION's browser, keeping the status the browser reports for each Pod and
passing each running exec its output."
  (let ((runtime (%make-browser-runtime session endpoint)))
    (setf (browser-session-on-message session)
          (lambda (message)
            (let ((op (gethash "op" message)))
              (cond ((and (equal "status" op) (stringp (gethash "uid" message)))
                     (browser-runtime-note-status runtime (gethash "uid" message) (gethash "status" message)))
                    ((member op '("signal" "have" "service") :test #'equal)
                     (let ((handler (browser-runtime-peer-handler runtime)))
                       (when handler (funcall handler message))))
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

(defun browser-pod-pull-credential (store pod image)
  "The first credential POD's imagePullSecrets hold for IMAGE, as (username . password), or
NIL. It is the server's to use and never goes to the browser."
  (let ((entries
          (loop for reference across (gethash "imagePullSecrets" (gethash "spec" (gr8s.model::pod-to-object pod)) #())
                for name = (gethash "name" reference "")
                for secret = (and store (plusp (length name))
                                  (ignore-errors (gr8s.resources::get-core-resource
                                                  store "secrets" (gr8s.model::pod-namespace pod) name)))
                when secret
                  append (ignore-errors (gr8s.kubelet::pull-secret-entries secret)))))
    (first (gr8s.kubelet::matching-registry-credentials entries (gr8s.kubelet::image-repository image)))))

(defun browser-pod-request (pod &optional images store layer-holders)
  "What the browser needs to run POD: its identity and its spec, a copy, with each
container's image resolved through IMAGES, with POD's pull credentials from STORE, when
there are any."
  (let* ((object (gr8s.model::pod-to-object pod))
         (spec (gr8s.resources::copy-core-object (gethash "spec" object))))
    (when images
      (loop for container across (concatenate 'vector (gethash "initContainers" spec #())
                                              (gethash "containers" spec #()))
            do (let ((info (gr8s.resources::copy-core-object
                            (resolve-browser-image images (gethash "image" container)
                                                   (browser-pod-pull-credential store pod (gethash "image" container))))))
                 ;; Other tabs holding a layer can give it, checked against its digest.
                 (when layer-holders
                   (loop for layer across (gethash "layers" info #())
                         for holders = (funcall layer-holders (gethash "digest" layer))
                         when holders do (setf (gethash "peers" layer) (coerce holders 'vector))))
                 (setf (gethash "imageInfo" container) info))))
    (core-object "uid" (gr8s.model::pod-uid pod)
                 "name" (gethash "name" (gethash "metadata" object))
                 "namespace" (gethash "namespace" (gethash "metadata" object))
                 "spec" spec)))

(defmethod gr8s.runtime::runtime-ensure ((runtime browser-runtime) pod)
  (let* ((network (browser-runtime-network runtime))
         (address (and network (browser-network-address network (gr8s.model::pod-uid pod))))
         (request (browser-pod-request pod (browser-runtime-images runtime) (browser-runtime-store runtime)
                                       (browser-runtime-layer-holders runtime)))
         (result (progn
                   (when address
                     (setf (gethash "network" request)
                           (core-object "address" address "prefix" (browser-network-prefix network)
                                        "gateway" (browser-network-gateway network)
                                        ;; The hosting node answers cluster DNS, as for its own Pods.
                                        "dns" (core-object
                                               "nameservers" (vector gr8s.foundation::+dns-pod-server-address+)
                                               "searches" (coerce (cons (format nil "~A.svc.cluster.local"
                                                                                (gethash "namespace" request))
                                                                        (rest gr8s.foundation::+dns-pod-searches+))
                                                                  'vector)
                                               "options" (coerce gr8s.foundation::+dns-pod-options+ 'vector)))))
                   (browser-session-call (browser-runtime-session runtime) "ensure" "pod" request)))
         (status (gethash "status" result))
         (runtime-pod (or (gethash (gr8s.model::pod-uid pod) (gr8s.runtime::fake-runtime-pods runtime))
                          (gr8s.runtime::make-runtime-pod :uid (gr8s.model::pod-uid pod)))))
    (let ((request (browser-pod-request pod)))
      (setf (gethash (format nil "~A/~A" (gethash "namespace" request) (gethash "name" request))
                     (browser-runtime-names runtime))
            (gr8s.model::pod-uid pod)))
    (when address
      (setf (gr8s.runtime::runtime-pod-pod-ip runtime-pod) address
            (gr8s.runtime::runtime-pod-pod-ips runtime-pod) (vector address)))
    (setf (gr8s.runtime::runtime-pod-resource-version runtime-pod) (gr8s.model::pod-resource-version pod)
          (gr8s.runtime::runtime-pod-spec-fingerprint runtime-pod) (gr8s.runtime::pod-runtime-spec-fingerprint pod)
          (gethash (gr8s.model::pod-uid pod) (gr8s.runtime::fake-runtime-pods runtime)) runtime-pod)
    (browser-runtime-note-status runtime (gr8s.model::pod-uid pod) status)
    runtime-pod))

(defmethod gr8s.runtime::runtime-delete ((runtime browser-runtime) uid)
  ;; A browser that has gone has nothing left to stop.
  (ignore-errors (browser-session-call (browser-runtime-session runtime) "delete" "uid" uid))
  (when (browser-runtime-network runtime)
    (release-browser-network-address (browser-runtime-network runtime) uid))
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
                 "podIP" (gethash "podIP" status "")
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

(defun start-browser-policy-refresher (session network runtime store)
  "Keep NETWORK's policy for RUNTIME's Pods current with STORE's NetworkPolicies, Pods and
Namespaces, until SESSION ends."
  (bt:make-thread
   (lambda ()
     (loop until (browser-session-closed session)
           do (handler-case
                  (browser-policy-update
                   (browser-network-policy network) store
                   (loop for key being the hash-keys of (browser-runtime-names runtime) using (hash-value uid)
                         for address = (bt:with-lock-held ((browser-network-lock network))
                                         (gethash uid (browser-network-addresses network)))
                         for slash = (position #\/ key)
                         for pod = (and address (ignore-errors (gr8s.store:get-pod store (subseq key 0 slash)
                                                                                    (subseq key (1+ slash)))))
                         when pod collect (cons address (gr8s.model::pod-to-object pod))))
                (error (condition)
                  (format *error-output* "gr8s browser network policy: ~A~%" condition)))
              (loop repeat 20 until (browser-session-closed session) do (sleep 0.1))))
   :name "gr8s browser network policy"))

(defparameter +browser-node-stats-seconds+ 10
  "How often the server asks a browser for its Pods' VM statistics, for /metrics.")

(defun browser-peer-message (acceptor from message)
  "Handle MESSAGE, which the browser node FROM sent for its peers: relay a WebRTC \"signal\"
to the browser node it names, record the layers it says it holds, or tell it a Service
port's backends. Only connected browser nodes are reached, and each learns whom a signal
is from from this server."
  (let ((op (gethash "op" message)))
    (cond ((equal op "service")
           (let ((protocol (gethash "protocol" message))
                 (address (gethash "address" message))
                 (port (gethash "port" message))
                 (session (gethash from (browser-join-sessions acceptor))))
             (when (and session (member protocol '("TCP" "UDP") :test #'equal)
                        (stringp address) (integerp port))
               (ignore-errors
                (browser-session-send
                 session
                 (core-object "op" "service" "protocol" protocol "address" address "port" port
                              "backends" (coerce (mapcar (lambda (backend) (coerce backend 'vector))
                                                         (browser-service-backends
                                                          (virtual-node-host-store (browser-join-nodes acceptor))
                                                          from address port protocol))
                                                 'vector)))))))
          ((equal op "signal")
           (let* ((to (gethash "to" message))
                  (target (and (stringp to) (browser-peers-p acceptor from to)
                               (gethash to (browser-join-sessions acceptor)))))
             (when target
               (ignore-errors
                (browser-session-send target (core-object "op" "signal" "from" from
                                                          "data" (gethash "data" message 'null)))))))
          ((equal op "have")
           (let ((digests (gethash "digests" message)))
             (when (vectorp digests)
               (setf (gethash from (browser-join-holdings acceptor))
                     (loop for digest across digests
                           repeat 4096
                           when (and (stringp digest) (cl-ppcre:scan "^sha256:[0-9a-f]{64}$" digest))
                             collect digest))))))))

(defun browser-service-backends (store node address port protocol)
  "The ready backends, as (address port) lists, that the browser node NODE's Pods reach at
the Service ClusterIP ADDRESS on PORT and PROTOCOL (\"TCP\" or \"UDP\"), as a native node's
Service translation finds them; NIL when that is no Service's port or it has none."
  (dolist (service (gr8s.resources::list-core-resources store "services"))
    (when (and (gr8s.controllers::service-lb-eligible-p service)
               (member address (gr8s.controllers::service-cluster-addresses service) :test #'equal))
      (loop for entry across (gr8s.controllers::json-array (gethash "ports" (gethash "spec" service)))
            when (and (eql port (gethash "port" entry)) (equal protocol (gethash "protocol" entry "TCP")))
              do (return-from browser-service-backends
                   (remove-if (lambda (backend) (find #\: (first backend)))
                              (gr8s.controllers::service-port-backends store service entry :node-name node))))))
  nil)

(defun browser-service-cidrs (store)
  "The IPv4 ranges STORE's ClusterIPs come from, as CIDR strings, for tabs to translate."
  (loop for (nil family network prefix) in (gr8s.controllers::service-cidr-prefixes store)
        when (equal family "IPv4")
          collect (format nil "~A/~D" (gr8s.controllers::format-service-address family network) prefix)))

(defun browser-peers-p (acceptor one other)
  "Whether browser nodes ONE and OTHER may connect directly, by ACCEPTOR's peering."
  (and (not (equal one other))
       (case (browser-join-peering acceptor)
         (:all t)
         (:same-network (let ((address (gethash one (browser-join-clients acceptor))))
                          (and address (equal address (gethash other (browser-join-clients acceptor))))))
         (t nil))))

(defun browser-node-peers (acceptor self)
  "The other browser nodes connected through ACCEPTOR that SELF may reach directly, each with
its Pod CIDR."
  (coerce (loop for name being the hash-keys of (browser-join-runtimes acceptor) using (hash-value runtime)
                for network = (browser-runtime-network runtime)
                unless (or (not (browser-peers-p acceptor self name)) (null network))
                  collect (core-object "node" name "cidr" (browser-network-cidr network)))
          'vector))

(defun browser-node-ingress-policy (runtime)
  "RUNTIME's Pods' ingress policy, by address, for its tab to enforce on what peers send it:
each Pod's isolation and its allowed (cidr excepts ports) entries, ports \"all\" or a
list of (protocol first last)."
  (let ((network (browser-runtime-network runtime))
        (result (core-object)))
    (when (and network (browser-network-policy network))
      (let ((policy (browser-network-policy network)))
        (bt:with-lock-held ((browser-policy-lock policy))
          (loop for address being the hash-keys of (browser-policy-pods policy) using (hash-value entry)
                do (destructuring-bind (isolated entries &rest rest) entry
                     (declare (ignore rest))
                     (setf (gethash address result)
                           (core-object
                            "isolated" (and isolated t)
                            "entries" (coerce (loop for (cidr excepts ports) in entries
                                                    unless (find #\: cidr)
                                                      collect (core-object
                                                               "cidr" cidr "excepts" (coerce excepts 'vector)
                                                               "ports" (if (eq ports :all) "all"
                                                                           (coerce (mapcar (lambda (range)
                                                                                             (coerce (substitute 'null nil range) 'vector))
                                                                                           ports)
                                                                                   'vector))))
                                              'vector))))))))
    result))

(defun start-browser-node-reporter (session store name &key pod-proxy runtime acceptor)
  "Tell SESSION's browser how its node NAME and the cluster are doing until it goes, and
whether its Pods' ports are reachable through POD-PROXY; every +BROWSER-NODE-STATS-SECONDS+,
ask it for RUNTIME's statistics, timing the answer."
  (bt:make-thread
   (lambda ()
     (loop for tick from 0
           until (browser-session-closed session)
           ;; A tick whose summary can't be made, as while the leader checkpoints and
           ;; the store refuses access for a second, is skipped: the next one tells the
           ;; browser. Only a browser that can't be told ends the reporter.
           do (let ((info (ignore-errors
                           (let ((info (browser-node-info store name)))
                             (setf (gethash "podProxy" info) (and pod-proxy t))
                             (when (and acceptor runtime)
                               (setf (gethash "peers" info) (browser-node-peers acceptor name)
                                     (gethash "iceServers" info) (browser-join-ice-servers acceptor)
                                     (gethash "stunPort" info) (let ((stun (browser-join-stun acceptor)))
                                                                 (if stun (browser-stun-port stun) 'null))
                                     (gethash "peering" info) (string-downcase (browser-join-peering acceptor))
                                     (gethash "ingressPolicy" info) (browser-node-ingress-policy runtime)
                                     (gethash "serviceCidrs" info) (coerce (browser-service-cidrs store) 'vector)))
                             info))))
                (when info
                  (handler-case (browser-session-send session info)
                    (error () (return)))))
              (when (and runtime (zerop (mod tick (ceiling +browser-node-stats-seconds+ +browser-node-info-seconds+))))
                (let ((started (get-internal-real-time)))
                  (handler-case
                      ;; Counters, answered at once: a browser that doesn't mustn't hold up
                      ;; the reports.
                      (let ((stats (let ((*browser-session-call-seconds* 5))
                                     (browser-session-call session "stats"))))
                        (setf (browser-runtime-rtt runtime)
                              (/ (- (get-internal-real-time) started) (float internal-time-units-per-second 1d0))
                              (browser-runtime-stats runtime) stats))
                    (error () nil))))
              (loop repeat (* 10 +browser-node-info-seconds+)
                    until (browser-session-closed session) do (sleep 0.1))))
   :name "gr8s browser node reporter"))

;;; Joining: the listener a browser connects to

(defparameter +browser-node-runtime-js+ #.(dashboard-agent-asset-text "browser-node-runtime.mjs")
  "The browser's half of a browser node, served to the join page and used by tests under Node.")

(defparameter +browser-node-runtime-version+
  (subseq (ironclad:byte-array-to-hex-string
           (ironclad:digest-sequence :sha256 (sb-ext:string-to-octets +browser-node-runtime-js+ :external-format :utf-8)))
          0 16)
  "The runtime's content hash. The join page loads it at a URL naming this, so a browser
never runs a cached runtime from before an upgrade, and a tab that somehow does learns so
when it joins.")

(defparameter +browser-node-html+
  (let ((page #.(dashboard-agent-asset-text "browser-node.html")))
    (cl-ppcre:regex-replace "\\./browser-node-runtime\\.mjs\"" page
                            (format nil "./browser-node-runtime.mjs?v=~A\"" +browser-node-runtime-version+)))
  "The join page, loading this build's runtime.")

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
   (pod-network :initarg :pod-network :initform nil :reader browser-join-pod-network
                :documentation "Whether browser Pods get addresses in their node's Pod CIDR, routed
to a TAP device on this host (browser-network.lisp). It needs CAP_NET_ADMIN.")
   (images :initarg :images :initform nil :reader browser-join-images
           :documentation "The image cache browser Pods' layers come from, or NIL.")
   (ice-servers :initarg :ice-servers :initform #() :reader browser-join-ice-servers
                :documentation "ICE servers tabs use to reach each other (a vector of
RTCIceServer objects); none by default, so tabs on one network connect directly and
others go through this host.")
   (holdings :initform (make-hash-table :test #'equal :synchronized t) :reader browser-join-holdings
             :documentation "The layer digests each connected node holds, by node name.")
   (joins :initform 0 :accessor browser-join-joins
          :documentation "How many browsers have joined through this listener.")
   (sessions :initform (make-hash-table :test #'equal :synchronized t) :reader browser-join-sessions
             :documentation "Each connected browser node's session, by node name.")
   (epochs :initform (make-hash-table :test #'equal :synchronized t) :reader browser-join-epochs
           :documentation "The last epoch each node's session had.")
   (runtimes :initform (make-hash-table :test #'equal :synchronized t) :reader browser-join-runtimes
             :documentation "Each connected browser node's runtime, by node name.")
   (max-nodes :initarg :max-nodes :initform 64 :reader browser-join-max-nodes
              :documentation "How many browser nodes may be connected at once.")
   (max-per-client :initarg :max-per-client :initform 4 :reader browser-join-max-per-client
                   :documentation "How many of them may come from one client address.")
   (peering :initarg :peering :initform :same-network :reader browser-join-peering
            :documentation "Which tabs may connect to each other directly, and so learn each
other's public address: :all, :same-network (tabs whose browsers come from one client
address) or :none. Tabs that may not still reach each other through this server.")
   (forward-client-address :initarg :forward-client-address :initform t
                           :reader browser-join-forward-client-address
                           :documentation "Whether checked content tells a browser Pod the visitor's address.
Its tab's owner reads the Pod's logs: a cluster whose tabs are strangers' keeps it from them.")
   (stun :initform nil :accessor browser-join-stun
         :documentation "The STUN responder tabs learn their public addresses from, or NIL.")
   (exec-listener :initform nil :accessor browser-join-exec-listener
                  :documentation "The loopback listener serving this listener's exec streams, when
this one listens elsewhere: the kubelet takes only loopback streaming URLs.")
   (clients :initform (make-hash-table :test #'equal :synchronized t) :reader browser-join-clients
            :documentation "The client address of each connected browser node, by node name.")
   (verified :initform 0 :accessor browser-join-verified
             :documentation "How many responses of browser Pods' checked content passed.")
   (tampered :initform 0 :accessor browser-join-tampered
             :documentation "How many didn't, each tainting its node."))
  (:documentation "Serves the join page and accepts browser nodes' sessions."))

(defun browser-join-client-address (acceptor request)
  "The address of the browser behind REQUEST: the last hop of its X-Forwarded-For when the
connection comes from this host (the Gateway, on a node of this cluster, in front of the
listener), else the connection's own address. A client can't name itself another address
by sending the header, as only this host's proxies are believed."
  (let ((peer (hunchentoot:remote-addr request))
        (forwarded (hunchentoot:header-in :x-forwarded-for request)))
    (if (and forwarded
             (or (uiop:string-prefix-p "127." peer) (equal peer "::1")
                 (equal peer (hunchentoot:acceptor-address acceptor))))
        (string-trim " " (car (last (uiop:split-string forwarded :separator ","))))
        peer)))

(defun browser-join-refusal (acceptor name client)
  "Why the browser at CLIENT may not join as node NAME now, or NIL. A node already
connected may always come back, as a reload of its tab replaces its session."
  (unless (gethash name (browser-join-sessions acceptor))
    (cond ((>= (hash-table-count (browser-join-sessions acceptor)) (browser-join-max-nodes acceptor))
           "this cluster has as many browser nodes as it takes; try again later")
          ((>= (loop for address being the hash-values of (browser-join-clients acceptor)
                     count (equal address client))
               (browser-join-max-per-client acceptor))
           "this network already has as many browser nodes as one may; close another tab first"))))

(defun hex-prefix (octets count)
  (format nil "~(~{~2,'0x~}~)" (coerce (subseq octets 0 count) 'list)))

(defun browser-node-identity (session stream hello)
  "Prove the identity HELLO presents and return (values node-name zone): the browser must
sign a fresh challenge with the private half of its public key. The name comes from the
key and the tab, so a reload of the tab is the same node; the zone from the key alone,
so a browser's tabs share one failure domain. Signals when the proof fails."
  (let* ((identity (gethash "identity" hello))
         (encoded (and (hash-table-p identity) (gethash "publicKey" identity)))
         (tab (and (hash-table-p identity) (gethash "tab" identity)))
         (public-key (and (stringp encoded) (ignore-errors (cl-base64:base64-string-to-usb8-array encoded)))))
    (unless (and public-key (= 65 (length public-key)) (= 4 (aref public-key 0))
                 (stringp tab) (cl-ppcre:scan "^[0-9a-f]{1,16}$" tab))
      (error "a browser node presents a P-256 public key and a tab id"))
    (let ((nonce (secure-random-octets 32)))
      (browser-session-send session (core-object "op" "challenge" "nonce" (octets-base64 nonce)))
      (multiple-value-bind (opcode payload) (gr8s.protocol::read-websocket-frame stream)
        (let* ((proof (and (= opcode 1) (ignore-errors (com.inuoe.jzon:parse payload))))
               (signature (and (hash-table-p proof) (equal "proof" (gethash "op" proof))
                               (stringp (gethash "signature" proof))
                               (ignore-errors (cl-base64:base64-string-to-usb8-array (gethash "signature" proof))))))
          (unless (and signature
                       (ignore-errors
                        (ironclad:verify-signature (ironclad:make-public-key :secp256r1 :y public-key)
                                                   (ironclad:digest-sequence :sha256 nonce) signature)))
            (error "the browser could not prove its identity")))))
    (values (format nil "browser-~A"
                    (hex-prefix (ironclad:digest-sequence
                                 :sha256 (concatenate '(vector (unsigned-byte 8)) public-key
                                                      (trivial-utf-8:string-to-utf-8-bytes tab)))
                                3))
            (format nil "browser-~A" (hex-prefix (ironclad:digest-sequence :sha256 public-key) 4)))))

(defun browser-node-capacity (hello)
  "The capacity HELLO offers, as protocol map entries, within what a tab can give: at most
8 CPUs, 8Gi of memory and 16 Pods. It is what the browser said, not what it has."
  (let* ((offered (gethash "capacity" hello))
         (offered (if (hash-table-p offered) offered (core-object))))
    (flet ((bounded (key default limit)
             (let ((value (gethash key offered)))
               (if (and (stringp value) (cl-ppcre:scan "^[0-9]+$" value))
                   (princ-to-string (min (max 1 (parse-integer value)) limit))
                   default))))
      (append
       (list (cons "cpu" (bounded "cpu" "1" 8))
             (cons "memory" (let ((value (gethash "memory" offered)))
                              (if (and (stringp value) (cl-ppcre:scan "^[0-9]{1,5}Mi$" value)
                                       (<= 64 (parse-integer value :junk-allowed t) 8192))
                                  value
                                  "1024Mi")))
             (cons "pods" (bounded "pods" "4" 16)))
       ;; One GPU: the page's WebGPU device, which one Pod's VM has at a time.
       (when (browser-node-gpu hello) (list (cons "gr8s.io/gpu" "1")))))))

(defun browser-label-value (text)
  "TEXT as a label value: letters, digits, '-', '_' and '.', at most 63, starting and
ending with a letter or digit; NIL when nothing is left."
  (let* ((cleaned (substitute-if #\- (lambda (c) (not (or (alphanumericp c) (find c "-_.")))) (string-downcase text)))
         (cleaned (string-trim "-_." (subseq cleaned 0 (min 63 (length cleaned))))))
    (and (plusp (length cleaned)) (every (lambda (c) (< (char-code c) 128)) cleaned) cleaned)))

(defun browser-node-gpu (hello)
  "The GPU HELLO offers, a hardware WebGPU adapter, as a plist of :vendor and
:architecture label values; NIL when it offers none. Like its capacity, it is what the
browser said: a tab could claim a GPU it hasn't, and a Pod given it would fail there."
  (let ((gpu (gethash "gpu" hello)))
    (when (hash-table-p gpu)
      (list :vendor (or (browser-label-value (princ-to-string (gethash "vendor" gpu ""))) "unknown")
            :architecture (or (browser-label-value (princ-to-string (gethash "architecture" gpu ""))) "unknown")))))

(defun fence-browser-node (acceptor name)
  "End NAME's earlier session, if one is still open, and wait for its node to stop, so a
reconnecting browser never shares its node with the session it replaces."
  (let ((old (gethash name (browser-join-sessions acceptor))))
    (when old
      ;; Closing it wouldn't wake the session's blocked read; this does.
      (ignore-errors (stop-reading-websocket (browser-session-stream old))))
    ;; A reloaded page closes its old session itself, whose node may still be stopping.
    (loop repeat 150
          while (member name (virtual-node-names (browser-join-nodes acceptor)) :test #'equal)
          do (sleep 0.1))))

(defun accept-browser-node (acceptor request)
  "Run one browser's session on REQUEST's upgraded connection: read its hello, make it a
node, answer with the node's name, and serve its runtime until the browser goes. The node
stops with the session."
  (let* ((client (browser-join-client-address acceptor request))
         (stream (dashboard-agent-websocket request))
         (session (%make-browser-session stream))
         (host (browser-join-nodes acceptor))
         (name nil))
    (unwind-protect
         (handler-case
             (multiple-value-bind (opcode payload) (gr8s.protocol::read-websocket-frame stream)
               (let ((hello (and (= opcode 1) (ignore-errors (com.inuoe.jzon:parse payload)))))
                 (unless (and (hash-table-p hello) (equal "hello" (gethash "op" hello)))
                   (error "a browser node must say hello first"))
                 (multiple-value-bind (identity zone) (browser-node-identity session stream hello)
                   (let ((refusal (browser-join-refusal acceptor identity client)))
                     (when refusal
                       (browser-session-send session (core-object "op" "refused" "reason" refusal))
                       (error "refused ~A from ~A: ~A" identity client refusal)))
                   (fence-browser-node acceptor identity)
                   (setf (gethash identity (browser-join-clients acceptor)) client)
                   (setf name identity
                         (browser-session-epoch session)
                         (setf (gethash name (browser-join-epochs acceptor))
                               (1+ (gethash name (browser-join-epochs acceptor) 0)))
                         (gethash name (browser-join-sessions acceptor)) session)
                   (setf (gethash "zone" hello) zone))
                 (let ((runtime (make-browser-runtime session (browser-join-exec-endpoint acceptor)))
                       (architecture (if (equal "amd64" (gethash "arch" hello)) "amd64" "arm64")))
                   (start-virtual-node host name
                                       :labels (let ((labels (core-object "gr8s.io/browser" "true"
                                                                          "gr8s.io/runtime" "unkernel"
                                                                          "topology.kubernetes.io/zone" (gethash "zone" hello)))
                                                     (gpu (browser-node-gpu hello)))
                                                 (when gpu
                                                   (setf (gethash "gr8s.io/gpu-vendor" labels) (getf gpu :vendor)
                                                         (gethash "gr8s.io/gpu-architecture" labels) (getf gpu :architecture)))
                                                 labels)
                                       :taints (vector (apply #'core-object +browser-node-taint+))
                                       :runtime-options (list :runtime "browser" :runtime-object runtime
                                                             :architecture architecture
                                                             :capacity (browser-node-capacity hello)))
                   (setf (gethash name (browser-join-runtimes acceptor)) runtime
                         (browser-runtime-browser runtime) (browser-description hello)
                         (browser-runtime-images runtime) (browser-join-images acceptor)
                         (browser-runtime-store runtime) (virtual-node-host-store host))
                   ;; Its Pods' network: the node's Pod CIDR, routed to a device here.
                   (let* ((node (gr8s.controllers::get-node (virtual-node-host-store host) name))
                          (cidr (find-if (lambda (cidr) (not (find #\: cidr)))
                                         (gr8s.model::node-record-all-pod-cidrs node))))
                     (when (and cidr (browser-join-pod-network acceptor))
                       (let ((network (start-browser-network-device
                                       (make-browser-network cidr) name
                                       (lambda (frame) (browser-session-send-frame session frame)))))
                         (when network
                           (setf (browser-runtime-network runtime) network
                                 (browser-network-policy network) (make-browser-policy)
                                 (browser-session-on-frame session)
                                 (lambda (frame) (browser-network-receive network frame)))
                           (start-browser-policy-refresher session network runtime
                                                           (virtual-node-host-store host))))))
                   (browser-session-send session (core-object "op" "welcome" "node" name
                                                              "epoch" (browser-session-epoch session)
                                                              "podProxy" (and (browser-join-pod-proxy acceptor) t)
                                                              "runtime" +browser-node-runtime-version+))
                   (format t "gr8s browser node ~A joined~%" name)
                   (incf (browser-join-joins acceptor))
                   (setf (browser-runtime-peer-handler runtime)
                         (let ((from name))
                           (lambda (message) (browser-peer-message acceptor from message)))
                         (browser-runtime-layer-holders runtime)
                         (let ((self name))
                           (lambda (digest)
                             (loop for node being the hash-keys of (browser-join-holdings acceptor)
                                     using (hash-value digests)
                                   when (and (browser-peers-p acceptor self node) (gethash node (browser-join-sessions acceptor))
                                             (member digest digests :test #'equal))
                                     collect node))))
                   (start-browser-node-reporter session (virtual-node-host-store host) name
                                                :pod-proxy (browser-join-pod-proxy acceptor)
                                                :runtime runtime :acceptor acceptor)
                   (run-browser-session session))))
           (error (condition)
             (format *error-output* "gr8s browser node~@[ ~A~]: ~A~%" name condition)))
      (when (and name (eq session (gethash name (browser-join-sessions acceptor))))
        (remhash name (browser-join-sessions acceptor))
        (remhash name (browser-join-clients acceptor))
        (remhash name (browser-join-holdings acceptor)))
      (when name
        (let ((runtime (gethash name (browser-join-runtimes acceptor))))
          (when (and runtime (browser-runtime-network runtime))
            (stop-browser-network-device (browser-runtime-network runtime))))
        (remhash name (browser-join-runtimes acceptor))
        (stop-virtual-node host name)
        (format t "gr8s browser node ~A left~%" name))
      (ignore-errors (close stream)))))

(defmethod hunchentoot:acceptor-dispatch-request ((acceptor browser-join-acceptor) request)
  (let ((path (hunchentoot:script-name request)))
    (cond ((and (uiop:string-prefix-p "/verified/" path) (browser-join-images acceptor))
           (serve-browser-content acceptor request path))
          ((and (uiop:string-prefix-p "/pods/" path) (browser-join-pod-proxy acceptor))
           (proxy-browser-pod acceptor request path))
          ((and (uiop:string-prefix-p "/exec/" path) (null (browser-join-exec-listener acceptor))
                (string-equal (hunchentoot:header-in :upgrade request) "SPDY/3.1"))
           (serve-browser-exec (subseq path 6)))
          ((and (equal path "/socket")
                (string-equal (hunchentoot:header-in :upgrade request) "websocket"))
           (accept-browser-node acceptor request)
           "")
          ((equal path "/")
           ;; Never cached: after an upgrade, a reload must get the new page and runtime.
           (setf (hunchentoot:content-type*) "text/html; charset=utf-8"
                 (hunchentoot:header-out :cache-control) "no-store")
           +browser-node-html+)
          ((and (uiop:string-prefix-p "/blobs/" path) (browser-join-images acceptor))
           (let ((file (handler-case (browser-image-layer-file (browser-join-images acceptor) (subseq path 7))
                         (error (condition)
                           (format *error-output* "gr8s browser image layer ~A: ~A~%" (subseq path 7) condition)
                           nil))))
             (if file
                 (progn (setf (hunchentoot:header-out :cache-control) "max-age=31536000, immutable")
                        (hunchentoot:handle-static-file file "application/octet-stream"))
                 (progn (setf (hunchentoot:return-code*) hunchentoot:+http-not-found+
                              (hunchentoot:content-type*) "text/plain")
                        "no such layer"))))
          ((and (uiop:string-prefix-p "/torrents/" path) (browser-join-images acceptor))
           (let ((torrent (handler-case (browser-image-torrent (browser-join-images acceptor) (subseq path 10))
                            (error (condition)
                              (format *error-output* "gr8s browser layer torrent ~A: ~A~%" (subseq path 10) condition)
                              nil))))
             (setf (hunchentoot:content-type*) "application/json")
             (if torrent
                 (progn (setf (hunchentoot:header-out :cache-control) "max-age=31536000, immutable")
                        (com.inuoe.jzon:stringify torrent))
                 (progn (setf (hunchentoot:return-code*) hunchentoot:+http-not-found+)
                        "{}"))))
          ((equal path "/browser-node-runtime.mjs")
           (setf (hunchentoot:content-type*) "text/javascript; charset=utf-8"
                 (hunchentoot:header-out :cache-control) "no-store")
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

(defvar *browser-join-listeners* '()
  "The join listeners this process runs, whose browser nodes /metrics reports.")

(defun browser-node-metrics-text ()
  "Prometheus families for the browser nodes this process hosts: how many are connected
and have joined, and for each node its Pods, the time its browser takes to answer, its
machine's CPUs and tab heap, and the frames relayed to and from its Pods and dropped by their policy; for
each Pod, its VM's memory and uptime as the browser reports them. Empty when this
process hosts none."
  (let ((listeners (remove-if-not #'hunchentoot:started-p *browser-join-listeners*)))
    (if (null listeners)
        ""
        (with-output-to-string (out)
          (let ((nodes '()) (pods '()))
            (dolist (listener listeners)
              (loop for name being the hash-keys of (browser-join-runtimes listener) using (hash-value runtime)
                    do (push (cons name runtime) nodes)
                       (let ((stats (browser-runtime-stats runtime)))
                         (when (hash-table-p stats)
                           (loop for key being the hash-keys of (browser-runtime-names runtime) using (hash-value uid)
                                 for pod = (gethash uid (gethash "pods" stats (core-object)))
                                 for slash = (position #\/ key)
                                 when (hash-table-p pod)
                                   do (push (list (list (cons "namespace" (subseq key 0 slash)) (cons "node" name)
                                                        (cons "pod" (subseq key (1+ slash))))
                                                  pod)
                                            pods))))))
            (flet ((family (name help type samples)
                     ;; What the browser sends is JSON: whole numbers may arrive as doubles.
                     (gr8s.kubelet::write-prometheus-family
                      out name help type
                      (mapcar (lambda (sample)
                                (destructuring-bind (labels value) sample
                                  (list labels (if (and (floatp value) (< (abs value) 1d15) (= value (fround value)))
                                                   (round value) value))))
                              samples)))
                   (node-label (entry) (list (cons "node" (car entry))))
                   (network (entry) (browser-runtime-network (cdr entry))))
              (family "gr8s_browser_content_checked_total"
                      "Responses of browser Pods' checked content, by whether they were what the image holds."
                      "counter"
                      (list (list (list (cons "result" "verified"))
                                  (reduce #'+ listeners :key #'browser-join-verified))
                            (list (list (cons "result" "tampered"))
                                  (reduce #'+ listeners :key #'browser-join-tampered))))
              (family "gr8s_browser_nodes" "Browser nodes connected to this process." "gauge"
                      (list (list nil (length nodes))))
              (family "gr8s_browser_node_joins_total" "Browsers that have joined through this process." "counter"
                      (list (list nil (reduce #'+ listeners :key #'browser-join-joins))))
              (family "gr8s_browser_node_pods" "Pods each browser node runs." "gauge"
                      (loop for entry in nodes
                            collect (list (node-label entry)
                                          (hash-table-count (gr8s.runtime::fake-runtime-pods (cdr entry))))))
              (family "gr8s_browser_node_rtt_seconds" "How long each browser last took to answer the server." "gauge"
                      (loop for entry in nodes
                            when (browser-runtime-rtt (cdr entry))
                              collect (list (node-label entry) (browser-runtime-rtt (cdr entry)))))
              (family "gr8s_browser_node_host_cpus" "CPUs each browser's machine reports having." "gauge"
                      (loop for entry in nodes
                            for stats = (browser-runtime-stats (cdr entry))
                            for cores = (and (hash-table-p stats) (gethash "cores" (gethash "tab" stats (core-object))))
                            when (integerp cores) collect (list (node-label entry) cores)))
              (family "gr8s_browser_node_js_heap_bytes" "Each browser tab's JavaScript heap, where the browser tells." "gauge"
                      (loop for entry in nodes
                            for stats = (browser-runtime-stats (cdr entry))
                            for heap = (and (hash-table-p stats) (gethash "jsHeapBytes" (gethash "tab" stats (core-object))))
                            when (realp heap) collect (list (node-label entry) heap)))
              (dolist (counter '(("gr8s_browser_node_frames_total" "Ethernet frames relayed to and from each browser node's Pods."
                                  browser-network-frames-in browser-network-frames-out)
                                 ("gr8s_browser_node_frames_dropped_total" "Frames each browser node's Pod NetworkPolicy dropped."
                                  browser-network-dropped-in browser-network-dropped-out)))
                (destructuring-bind (name help in out-reader) counter
                  (family name help "counter"
                          (loop for entry in nodes
                                for network = (network entry)
                                when network
                                  collect (list (cons (cons "direction" "to_pods") (node-label entry))
                                                (funcall in network))
                                  and collect (list (cons (cons "direction" "from_pods") (node-label entry))
                                                    (funcall out-reader network))))))
              (dolist (gauge '(("gr8s_browser_pod_memory_limit_bytes" "Memory each browser Pod's VM has." "memoryLimitBytes")
                               ("gr8s_browser_pod_memory_used_bytes" "Memory in use in each browser Pod's VM, as its guest reports." "memoryUsedBytes")
                               ("gr8s_browser_pod_uptime_seconds" "How long each browser Pod's VM has run." "uptimeSeconds")))
                (destructuring-bind (name help field) gauge
                  (family name help "gauge"
                          (loop for (labels pod) in pods
                                for value = (gethash field pod)
                                when (realp value) collect (list labels value)))))))))))

(defun start-browser-join-listener (nodes address port &key distro pod-proxy pod-network images
                                                             (max-nodes 64) (max-per-client 4)
                                                             (peering :same-network) ice-servers stun
                                                             (forward-client-address t))
  "Listen on ADDRESS:PORT for browsers joining as nodes on NODES, serving the join page and
DISTRO, the root image file Pods boot from, and with POD-PROXY, HTTP to their Pods. With
POD-NETWORK, their Pods join the cluster network through this host. At most MAX-NODES are
connected at once, MAX-PER-CLIENT of them from one address. PEERING says which tabs connect
directly; they find each other with ICE-SERVERS (URLs) and, with STUN, (address port), a
STUN responder this listener runs. FORWARD-CLIENT-ADDRESS says whether checked content tells
a browser Pod the visitor's address. Returns the acceptor."
  (let ((acceptor (make-instance 'browser-join-acceptor
                                    :address address :port port :nodes nodes :pod-proxy pod-proxy
                                    :max-nodes max-nodes :max-per-client max-per-client :peering peering
                                    :forward-client-address forward-client-address
                                    :ice-servers (map 'vector (lambda (url) (core-object "urls" url)) ice-servers)
                                    :pod-network pod-network
                                    :images (and images (make-browser-images images))
                                    :distro (and distro (pathname distro))
                                    :access-log-destination nil
                                    :message-log-destination *error-output*)))
    (hunchentoot:start acceptor)
    (when stun
      (setf (browser-join-stun acceptor) (apply #'start-browser-stun stun)))
    (unless (loopback-address-p address)
      (let ((exec (make-instance 'browser-exec-acceptor :address "127.0.0.1" :port 0
                                                        :access-log-destination nil
                                                        :message-log-destination *error-output*)))
        (hunchentoot:start exec)
        (setf (browser-join-exec-listener acceptor) exec)))
    (push acceptor *browser-join-listeners*)
    acceptor))

(defun loopback-address-p (address)
  "Whether a listener on ADDRESS is reached at a streaming URL the kubelet takes
(gr8s.protocol's: 127.0.0.1 or localhost), as one on all addresses is."
  (member address '(nil "0.0.0.0" "127.0.0.1" "localhost") :test #'equal))

(defclass browser-exec-acceptor (hunchentoot:easy-acceptor) ()
  (:documentation "Serves browser Pods' exec streams on loopback, for the kubelet."))

(defmethod hunchentoot:acceptor-dispatch-request ((acceptor browser-exec-acceptor) request)
  (let ((path (hunchentoot:script-name request)))
    (if (and (uiop:string-prefix-p "/exec/" path)
             (string-equal (hunchentoot:header-in :upgrade request) "SPDY/3.1"))
        (serve-browser-exec (subseq path 6))
        (progn (setf (hunchentoot:return-code*) 404) ""))))

(defun browser-join-exec-endpoint (acceptor)
  "Where ACCEPTOR's exec streams are served, as (address port): always a loopback address."
  (let ((exec (browser-join-exec-listener acceptor)))
    (if exec
        (list "127.0.0.1" (usocket:get-local-port (hunchentoot::acceptor-listen-socket exec)))
        (list (let ((address (hunchentoot:acceptor-address acceptor)))
                (if (member address '(nil "0.0.0.0") :test #'equal) "127.0.0.1" address))
              (hunchentoot:acceptor-port acceptor)))))

(defmethod hunchentoot:stop :after ((acceptor browser-join-acceptor) &key soft)
  (declare (ignore soft))
  (let ((exec (shiftf (browser-join-exec-listener acceptor) nil))
        (stun (shiftf (browser-join-stun acceptor) nil)))
    (when exec (ignore-errors (hunchentoot:stop exec :soft nil)))
    (when stun (stop-browser-stun stun))))
