;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Virtual nodes: worker nodes whose agent runs inside serve (podster-57fv.1).
;;;;
;;;; A browser node (docs/design-browser-nodes.md) is a Kubernetes Node whose
;;;; containers run elsewhere but whose kubelet half -- enrollment, lease, Pod sync,
;;;; status -- is an ordinary gr8s agent running in the server process, with a runtime
;;;; that forwards to the browser. This file hosts such agents: each is the same
;;;; in-process agent serve runs for its own node (start-local-node-agent), in its own
;;;; state directory, so nothing about Pods or leases is reimplemented.
;;;;
;;;; The host enrolls each node itself before starting its agent, then writes the
;;;; node's labels and taints as an ordinary node write. A node therefore never runs
;;;; untainted: the agent, which is what makes it Ready, starts only afterwards. Doing
;;;; it at registration instead would put server-local state into an enrollment that
;;;; every HA replica replays.

(in-package #:gr8s.server)

(defstruct (virtual-node (:constructor %make-virtual-node (name directory worker)))
  "One hosted node: its NAME, its agent's state DIRECTORY, and the running WORKER."
  name directory worker)

(defstruct (virtual-node-host (:constructor %make-virtual-node-host
                                  (store server pki state-root host-node endpoint-slot reconciler)))
  "The virtual nodes one server hosts, each with its state under STATE-ROOT/NAME/.
HOST-NODE names the node of this process, through which their Pods are routed. RECONCILER,
the control plane's, deletes the Pods of a node removed for good."
  store server pki state-root host-node endpoint-slot reconciler
  (nodes (make-hash-table :test #'equal))
  (lock (bt:make-lock "gr8s virtual nodes"))
  ;; Nodes of this host found gone, by name, with when they were first found so.
  (gone (make-hash-table :test #'equal))
  sweeper (stopping nil))

(defun make-virtual-node-host (store server pki state-root &key host-node endpoint reconciler)
  "A host for virtual nodes enrolled through the node SERVER with PKI, storing each
one's agent state under STATE-ROOT. HOST-NODE, the node this process runs as, carries
their Pods' traffic: the cluster routes their Pod CIDRs to it. ENDPOINT, (address port), is
where the node server listens for agents, loopback by default. RECONCILER, the control
plane's, deletes the Pods of a node removed for good; without it, the Pod garbage
collector does once the Node has been gone a while."
  (%make-virtual-node-host store server pki (uiop:ensure-directory-pathname state-root) host-node endpoint
                           reconciler))

(defun virtual-node-host-endpoint (host)
  "The endpoint (ADDRESS PORT) of the node server its virtual nodes dial: the one it was
given, which follows serve's --node-listen, else loopback."
  (or (virtual-node-host-endpoint-slot host)
      (list "127.0.0.1" (node-grpc-server-port (virtual-node-host-server host)))))

(defun start-virtual-node (host name &key labels taints runtime-options)
  "Enroll NAME, set its LABELS (a hash; derived ones are left alone) and TAINTS (a
vector of taint objects), and start its in-process agent with RUNTIME-OPTIONS (the
fake runtime by default). A node enrolled before keeps its identity and gets the
labels and taints again. Signals an error when NAME is already running here, or when
enrollment fails. Returns the virtual-node."
  (bt:with-lock-held ((virtual-node-host-lock host))
    (when (gethash name (virtual-node-host-nodes host))
      (error "Virtual node ~A is already running" name)))
  (let* ((directory (merge-pathnames (format nil "~A/" name) (virtual-node-host-state-root host)))
         (key (merge-pathnames "node.key" directory))
         (certificate (merge-pathnames "node.crt" directory))
         (ca (merge-pathnames "ca.crt" directory))
         (pki (virtual-node-host-pki host)))
    (ensure-directories-exist directory)
    (unless (and (probe-file key) (probe-file certificate) (probe-file ca))
      (destructuring-bind (address port) (virtual-node-host-endpoint host)
        (gr8s.agent::enroll-node-over-grpc address port name (create-join-token pki name)
                               (cluster-pki-ca-fingerprint pki) key certificate ca)))
    (gr8s.resources::set-node-labels-and-taints
     (virtual-node-host-store host) name
     (let ((all (core-object "gr8s.io/virtual" "true")))
       (when (virtual-node-host-host-node host)
         (setf (gethash "gr8s.io/virtual-host" all) (virtual-node-host-host-node host)))
       (when labels (maphash (lambda (k v) (setf (gethash k all) v)) labels))
       all)
     taints)
    (let ((node (%make-virtual-node
                 name directory
                 (start-local-node-agent (virtual-node-host-server host) pki name directory
                                         (list* :virtual t (or runtime-options (list :runtime "fake")))
                                         :endpoints (list (virtual-node-host-endpoint host))))))
      (bt:with-lock-held ((virtual-node-host-lock host))
        (setf (gethash name (virtual-node-host-nodes host)) node))
      node)))

(defun stop-virtual-node (host name)
  "Stop NAME's agent, leaving its Node to go NotReady when its lease lapses, as any
node that stops does. Returns true when NAME was running here."
  (let ((node (bt:with-lock-held ((virtual-node-host-lock host))
                (prog1 (gethash name (virtual-node-host-nodes host))
                  (remhash name (virtual-node-host-nodes host))))))
    (when node
      (stop-local-node-agent (virtual-node-worker node))
      t)))

(defun forget-virtual-node (host name)
  "Remove NAME's Node, then the Pods bound to it, then its agent's state and so its
enrollment. The Node goes first, so the replacements its Pods' controllers make can't be
bound to it."
  (let ((store (virtual-node-host-store host))
        (reconciler (virtual-node-host-reconciler host)))
    (with-store-lock (store)
      (let ((current (gr8s.controllers::get-node-unlocked store name)))
        (when current (gr8s.apiserver::remove-node-unlocked store current))))
    (when reconciler
      ;; As Kubernetes' Pod garbage collector deletes the Pods of a deleted Node, but at
      ;; once: this Node isn't coming back.
      (dolist (pod (gr8s.controllers::list-pods store))
        (when (equal name (gr8s.model::pod-node-name pod))
          (handler-case (gr8s.apiserver::delete-controller-pod
                         reconciler (gr8s.model::pod-namespace pod) (gr8s.model::pod-name pod)
                         "pod-garbage-collector" :uid (gr8s.model::pod-uid pod))
            (error (condition)
              (format *error-output* "gr8s virtual node ~A: Pod ~A/~A: ~A~%" name
                      (gr8s.model::pod-namespace pod) (gr8s.model::pod-name pod) condition))))))
    (ignore-errors
     (uiop:delete-directory-tree
      (merge-pathnames (format nil "~A/" name) (virtual-node-host-state-root host))
      :validate t :if-does-not-exist :ignore))))

(defun remove-virtual-node (host name)
  "Stop NAME's agent and remove its Node, its Pods and its enrollment at once, for a node
gone for good, such as a browser node whose tab has closed. Its Pods' controllers replace
them elsewhere straight away, instead of after its lease lapses and its Pods are evicted.
NAME counts as running here until all that is done, so a reconnect waiting for it starts
afresh. Returns true when NAME was running here."
  (let ((node (bt:with-lock-held ((virtual-node-host-lock host))
                (gethash name (virtual-node-host-nodes host)))))
    (when node
      (unwind-protect
           (progn (stop-local-node-agent (virtual-node-worker node))
                  (forget-virtual-node host name))
        (bt:with-lock-held ((virtual-node-host-lock host))
          (remhash name (virtual-node-host-nodes host))))
      t)))

(defun virtual-node-names (host)
  "The names of the nodes running on HOST, sorted."
  (sort (bt:with-lock-held ((virtual-node-host-lock host))
          (loop for name being the hash-keys of (virtual-node-host-nodes host) collect name))
        #'string<))

(defun stop-virtual-nodes (host)
  "Stop every node HOST runs, and its sweeper."
  (setf (virtual-node-host-stopping host) t)
  (dolist (name (virtual-node-names host))
    (stop-virtual-node host name)))

;;; A browser node is as lasting as its tab: every new tab or browser is a new node, so
;;; one that is gone must not stay a NotReady Node forever. A tab that closes has its node
;;; removed at once (remove-virtual-node). One left behind otherwise, by a server that
;;; stopped with tabs joined, say, is removed once it has been neither running here nor
;;; Ready for a grace period, in which its tab may come back as the same node.

(defparameter +virtual-node-grace-seconds+ 300
  "How long a virtual node that has gone stays a Node, for its browser to come back.")

(defun virtual-node-host-sweep (host &key (now (get-universal-time)) (grace +virtual-node-grace-seconds+))
  "Remove HOST's virtual nodes that have been gone, not running here and not Ready, for
GRACE seconds by NOW, with their agent state. Returns the names removed."
  (let* ((store (virtual-node-host-store host))
         (running (virtual-node-names host))
         (gone (virtual-node-host-gone host))
         (removed '()))
    (dolist (node (gr8s.controllers::list-nodes store))
      (let* ((name (gr8s.model::node-record-name node))
             (labels (or (gr8s.model::node-record-labels node) (core-object)))
             (ours (and (equal "true" (gethash "gr8s.io/virtual" labels))
                        (equal (virtual-node-host-host-node host) (gethash "gr8s.io/virtual-host" labels)))))
        (cond ((or (not ours) (member name running :test #'equal) (gr8s.model::node-record-ready-p node))
               (remhash name gone))
              ((null (gethash name gone))
               (setf (gethash name gone) now))
              ((>= (- now (gethash name gone)) grace)
               (forget-virtual-node host name)
               (remhash name gone)
               (push name removed)))))
    (dolist (name removed)
      (format t "gr8s virtual node ~A removed after ~Ds gone~%" name grace))
    removed))

(defun start-virtual-node-sweeper (host &key (interval 60))
  "Sweep HOST's gone virtual nodes every INTERVAL seconds until its nodes are stopped."
  (setf (virtual-node-host-sweeper host)
        (bt:make-thread
         (lambda ()
           (loop until (virtual-node-host-stopping host)
                 do (handler-case (virtual-node-host-sweep host)
                      (error (condition)
                        (format *error-output* "gr8s virtual node sweep: ~A~%" condition)))
                    (loop repeat (* 10 interval) until (virtual-node-host-stopping host) do (sleep 0.1))))
         :name "gr8s virtual node sweeper")))
