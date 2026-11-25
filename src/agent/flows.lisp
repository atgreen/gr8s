;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Collect this node's flow events (podster-e9a.2). The endpoint guards write
;;;; drops, and isolated Pods' new connections, to one ring; a collector thread
;;;; reads it, names the local Pod each event belongs to, and keeps the most
;;;; recent ones. A FLOWS operation streams those to the control plane as JSON
;;;; lines, and with FLOWS_FOLLOW keeps streaming new ones until it's cancelled.
;;;; Nothing leaves the node unless someone asks. On a foreign cluster, where
;;;; there is no session, net-agent serves the same lines on a loopback port
;;;; that readers reach through the cluster's pods/portforward (podster-e9a.11).

(in-package #:gr8s.agent)

(defparameter +recent-flow-capacity+ 4096
  "How many recent flow events a node keeps.")

(defparameter +flow-batch-bytes+ (* 64 1024)
  "About how many bytes of lines a reader is sent at once. Each send to a control plane is one
operation frame, which a member that doesn't hold the node's session relays one RPC at a time.")

(defparameter +flow-follow-linger-seconds+ 0.1
  "How long a follower waits after new events arrive, so a burst goes as one send.")

(defstruct (flow-collector (:constructor %make-flow-collector
                               (ring node-name pod-lookup &optional (interface-address (constantly nil)))))
  ring node-name pod-lookup interface-address consumer thread config
  (records (make-array +recent-flow-capacity+ :initial-element nil))
  ;; Events ever recorded; record N is at (mod N capacity) while it's recent.
  (count 0)
  (stopping nil)
  (lock (bt:make-lock "gr8s flow collector"))
  (changed (bt:make-condition-variable :name "gr8s flow collector")))

(defun flow-timestamp ()
  "The current UTC time in RFC 3339 with microseconds, fine enough that Hubble UI, which
tells a node's flows apart by their time, keeps each one."
  (multiple-value-bind (seconds microseconds) (sb-ext:get-time-of-day)
    (multiple-value-bind (second minute hour day month year)
        (decode-universal-time (+ seconds (encode-universal-time 0 0 0 1 1 1970 0)) 0)
      (format nil "~4,'0D-~2,'0D-~2,'0DT~2,'0D:~2,'0D:~2,'0D.~6,'0DZ"
              year month day hour minute second microseconds))))

(defun flow-protocol-name (number)
  (case number (1 "ICMP") (6 "TCP") (17 "UDP") (58 "ICMPv6") (132 "SCTP") (t number)))

(defun pod-status-has-address-p (status address)
  "True when the Pod status STATUS lists ADDRESS among its podIP and podIPs."
  (or (equal address (gethash "podIP" status))
      (some (lambda (entry) (and (hash-table-p entry) (equal address (gethash "ip" entry))))
            (gethash "podIPs" status #()))))

(defun reported-pod-at-address (store address)
  "Return (values namespace name) of the Pod STORE reports at ADDRESS, or NIL. STORE
may be a foreign cluster's view. A host-network Pod's address is its node's, so it
names no Pod."
  (when address
    (dolist (pod (list-pods store))
      (let ((status (gr8s.store:pod-reported-status store pod)))
        (when (and (hash-table-p status) (pod-status-has-address-p status address)
                   (not (gr8s.controllers::host-network-pod-object-p (pod-to-object pod))))
          (return (values (pod-namespace pod) (pod-name pod))))))))

(defun node-pod-at-address (store address)
  "Return (values namespace name) of the Pod in STORE observed at ADDRESS, or NIL. A
host-network Pod's address is its node's, so it names no Pod."
  (when address
    (dolist (pod (list-pods store nil))
      (let ((status (pod-observed-status store pod)))
        (when (and (hash-table-p status) (pod-status-has-address-p status address)
                   (not (gr8s.controllers::host-network-pod-object-p (pod-to-object pod))))
          (return (values (pod-namespace pod) (pod-name pod))))))))

(defun make-interface-address-lookup (&key (read #'gr8s.network::pod-interface-addresses)
                                           (refresh-seconds 1))
  "Return a function of an interface index giving the Pod address routed over it.
It rereads the routes on a miss, at most once every REFRESH-SECONDS."
  (let ((addresses (make-hash-table)) (read-at nil) (lock (bt:make-lock "gr8s flow interfaces")))
    (lambda (ifindex)
      (bt:with-lock-held (lock)
        (or (gethash ifindex addresses)
            (let ((now (get-internal-real-time)))
              (when (or (null read-at)
                        (>= (- now read-at) (* refresh-seconds internal-time-units-per-second)))
                (setf read-at now
                      addresses (or (ignore-errors (funcall read)) addresses))
                (gethash ifindex addresses))))))))

(defun flow-record-object (record node-name pod-lookup &key (interface-address (constantly nil)))
  "The JSON object a FLOWS operation sends for RECORD, naming its local Pod. A record
without the Pod's address (an IPv6 Pod's) finds it by the interface it was seen on."
  (let ((endpoint (or (gr8s.network::flow-record-endpoint record)
                      (funcall interface-address (gr8s.network::flow-record-ifindex record))))
        (object (json-object "time" (flow-timestamp)
                             "node" node-name
                             "verdict" (if (eq :drop (gr8s.network::flow-record-kind record))
                                           "DROPPED" "FORWARDED")
                             "ifindex" (gr8s.network::flow-record-ifindex record)
                             "length" (gr8s.network::flow-record-length record))))
    (flet ((put (key value) (when value (setf (gethash key object) value))))
      (put "reason" (let ((reason (gr8s.network::flow-record-reason record)))
                      (and reason (string-downcase (symbol-name reason)))))
      (put "direction" (let ((direction (gr8s.network::flow-record-direction record)))
                         (and direction (string-downcase (symbol-name direction)))))
      (put "protocol" (let ((protocol (gr8s.network::flow-record-protocol record)))
                        (and protocol (flow-protocol-name protocol))))
      (put "podAddress" endpoint)
      (let ((port (gr8s.network::flow-record-pod-port record)))
        (put "podPort" (and (plusp port) port)))
      (put "peerAddress" (gr8s.network::flow-record-peer record))
      ;; The name a Pod on this node asked DNS for to reach the peer, as Hubble's DNS proxy
      ;; names a flow's destination.
      (put "peerName" (let ((peer (gr8s.network::flow-record-peer record)))
                        (and peer (gr8s.network::dns-name-for-address peer))))
      (let ((port (gr8s.network::flow-record-peer-port record)))
        (put "peerPort" (and (plusp port) port)))
      (multiple-value-bind (namespace name)
          (funcall pod-lookup endpoint)
        (put "namespace" namespace)
        (put "pod" name)))
    object))

(defun note-flow-object (collector object)
  "Keep flow OBJECT, as JSON octets, among the recent events and wake any follower. An
object from elsewhere than the ring (a Gateway request's) gets its time, the node, and
its Pod's name here."
  (unless (gethash "time" object)
    (setf (gethash "time" object) (flow-timestamp)
          (gethash "node" object) (flow-collector-node-name collector))
    (multiple-value-bind (namespace name)
        (funcall (flow-collector-pod-lookup collector) (gethash "podAddress" object))
      (when name
        (setf (gethash "namespace" object) namespace (gethash "pod" object) name))))
  (let ((line (concatenate '(vector (unsigned-byte 8))
                           (gr8s.resources:stringify-to-utf-8-bytes object)
                           #(10))))
    (bt:with-lock-held ((flow-collector-lock collector))
      (setf (aref (flow-collector-records collector)
                  (mod (flow-collector-count collector) +recent-flow-capacity+))
            (coerce line '(simple-array (unsigned-byte 8) (*))))
      (incf (flow-collector-count collector))
      (bt:condition-notify (flow-collector-changed collector)))))

(defun note-flow-record (collector record)
  "Keep ring event RECORD among the recent events and wake any follower."
  (note-flow-object collector
                    (flow-record-object record (flow-collector-node-name collector)
                                        (flow-collector-pod-lookup collector)
                                        :interface-address (flow-collector-interface-address collector))))

(defun flow-records-since (collector start)
  "Return (values lines next) for the recent events from number START on. START
before the oldest one kept begins at the oldest."
  (bt:with-lock-held ((flow-collector-lock collector))
    (let* ((count (flow-collector-count collector))
           (first (max start (- count +recent-flow-capacity+))))
      (values (loop for index from first below count
                    collect (aref (flow-collector-records collector) (mod index +recent-flow-capacity+)))
              count))))

(defun run-flow-collector (collector)
  "Read the ring until the collector is stopped."
  (loop until (flow-collector-stopping collector)
        do (handler-case (whistler/loader::ring-poll (flow-collector-consumer collector) :timeout-ms 250)
             (error (condition)
               (format *error-output* "gr8s: flow events: ~A~%" condition)
               (sleep 1)))))

(defun start-flow-collector (bpf-root node-name store &key (pod-lookup #'node-pod-at-address))
  "Create or reopen the node's flow-event ring under BPF-ROOT and start reading it.
POD-LOOKUP names the Pod in STORE at an address."
  (let* ((ring (gr8s.network::open-flow-events-ring bpf-root :create t))
         (config (handler-bind ((error (lambda (condition)
                                         (declare (ignore condition))
                                         (ignore-errors (sb-posix:close (whistler/loader:map-info-fd ring))))))
                   (let ((config (gr8s.network::open-flow-config bpf-root :create t)))
                     ;; Every start applies this node's setting, whatever an earlier run chose.
                     (gr8s.network::set-flow-reporting config gr8s.network::*report-every-connection*)
                     config)))
         (collector (%make-flow-collector
                     ring node-name (lambda (address) (funcall pod-lookup store address))
                     (make-interface-address-lookup))))
    (setf (flow-collector-config collector) config)
    (handler-bind ((error (lambda (condition)
                            (declare (ignore condition))
                            (ignore-errors (sb-posix:close (whistler/loader:map-info-fd ring))))))
      (setf (flow-collector-consumer collector)
            (whistler/loader::open-decoding-ring-consumer
             ring #'gr8s.network::decode-flow-event
             (lambda (record) (when record (note-flow-record collector record))))))
    (setf (flow-collector-thread collector)
          (bt:make-thread (lambda () (run-flow-collector collector)) :name "gr8s flow events")
          ;; The Gateway listeners in this process report each request as an L7 flow.
          gr8s.controllers::*gateway-flow-sink* (gateway-flow-sink collector))
    collector))

(defun gateway-flow-sink (collector)
  "A sink for the Gateway proxy's request flows that keeps them in COLLECTOR."
  (lambda (object) (note-flow-object collector object)))

(defun stop-flow-collector (collector)
  "Stop reading, and close the ring. Its pin stays, so guards keep writing to it and a
restarted agent reads on from where the kernel is."
  (setf (flow-collector-stopping collector) t
        gr8s.controllers::*gateway-flow-sink* nil)
  (bt:with-lock-held ((flow-collector-lock collector))
    (bt:condition-notify (flow-collector-changed collector)))
  (ignore-errors (bt:join-thread (flow-collector-thread collector)))
  (ignore-errors (whistler/loader::close-ring-consumer (flow-collector-consumer collector)))
  (ignore-errors (sb-posix:close (whistler/loader:map-info-fd (flow-collector-ring collector))))
  (when (flow-collector-config collector)
    (ignore-errors (sb-posix:close (whistler/loader:map-info-fd (flow-collector-config collector))))))

(defun call-with-flow-collector (node-runtime bpf-root function)
  "Run FUNCTION while NODE-RUNTIME collects flow events from BPF-ROOT. A node that
can't create the ring still runs; it just has no flow events."
  (let ((collector (handler-case
                       (start-flow-collector bpf-root (node-runtime-node-name node-runtime)
                                             (node-runtime-store node-runtime))
                     (error (condition)
                       (format *error-output* "gr8s: flow events unavailable: ~A~%" condition)
                       nil))))
    (setf (node-runtime-flow-collector node-runtime) collector)
    (unwind-protect (funcall function)
      (setf (node-runtime-flow-collector node-runtime) nil)
      (when collector (stop-flow-collector collector)))))

(defun flow-record-batches (lines)
  "Join LINES into octet vectors of whole lines, each about +FLOW-BATCH-BYTES+ at most."
  (let ((batches nil) (batch nil) (size 0))
    (flet ((close-batch ()
             (when batch
               (push (apply #'concatenate '(simple-array (unsigned-byte 8) (*)) (nreverse batch))
                     batches)
               (setf batch nil size 0))))
      (dolist (line lines)
        (when (and batch (> (+ size (length line)) +flow-batch-bytes+))
          (close-batch))
        (push line batch)
        (incf size (length line)))
      (close-batch))
    (nreverse batches)))

(defun send-flow-records (collector follow send finished-p)
  "Call SEND with the recent events' lines, then with FOLLOW the new ones, until
FINISHED-P is true or the collector stops. Each call carries one or more whole lines.
SEND returns NIL to stop early."
  (let ((next 0))
    (loop
      (multiple-value-bind (lines count) (flow-records-since collector next)
        (setf next count)
        (dolist (batch (flow-record-batches lines))
          (unless (funcall send batch)
            (return-from send-flow-records))))
      (unless follow (return))
      (bt:with-lock-held ((flow-collector-lock collector))
        (loop while (and (= next (flow-collector-count collector))
                         (not (funcall finished-p))
                         (not (flow-collector-stopping collector)))
              do (bt:condition-wait (flow-collector-changed collector)
                                    (flow-collector-lock collector) :timeout 0.5)))
      (when (or (funcall finished-p) (flow-collector-stopping collector))
        (return))
      (sleep +flow-follow-linger-seconds+))))

(defun run-node-flows-operation (operation collector follow)
  "Send the recent flow events, then with FOLLOW new ones, until the operation ends."
  (handler-case
      (progn
        (send-flow-records
         collector follow
         (lambda (lines)
           (when (wait-for-node-exec-output-window operation (length lines))
             (emit-node-exec-stream operation gr8s.node.v1::+streamchannel-stream_channel_stdout+ lines)
             t))
         (lambda () (node-exec-operation-finished-p operation)))
        (finish-node-exec-operation operation))
    (error (condition)
      (finish-node-exec-operation operation :error (princ-to-string condition)))))

(defun start-node-flows-operation (node-runtime request emit)
  "Stream this node's flow events for REQUEST."
  (let ((collector (node-runtime-flow-collector node-runtime)))
    (unless collector
      (error 'runtime-error :message "This node doesn't collect flow events"))
    (let ((operation (make-node-exec-operation node-runtime request nil nil emit)))
      (remember-node-exec-operation node-runtime operation)
      (emit-node-exec-response operation gr8s.node.v1::+operationstatus-operation_status_accepted+)
      (setf (node-exec-operation-thread operation)
            (bt:make-thread
             (lambda ()
               (run-node-flows-operation operation collector
                                         (slot-value request 'gr8s.node.v1::flows-follow)))
             :name "gr8s flow stream"))
      operation)))

;;; The loopback flow endpoint of net-agent. A client sends one JSON line, {"follow":
;;; true} or {}, and reads the node's flow events as JSON lines, as a FLOWS operation
;;; sends them, then an empty line at the end. It listens on loopback only: a reader reaches it through the cluster
;;; API's pods/portforward, which Kubernetes RBAC governs, and net-agent's Pod is on
;;; the host network, where port-forward dials loopback.

(defparameter +default-flow-listener-port+ 4246
  "net-agent's default loopback flow port, beside Hubble's 4244 and 4245.")

(defstruct (flow-listener (:constructor %make-flow-listener (collector socket)))
  collector socket thread (stopping nil))

(defun serve-flow-client (collector socket)
  "Answer one loopback client on SOCKET."
  (let ((stream (usocket:socket-stream socket)))
    (unwind-protect
         (handler-case
             (let* ((request (ignore-errors
                              (com.inuoe.jzon:parse
                               (coerce (loop for byte = (read-byte stream nil)
                                             for count from 0
                                             while (and byte (/= byte 10) (< count 4096))
                                             collect byte)
                                       '(vector (unsigned-byte 8))))))
                    (follow (and (hash-table-p request) (eq t (gethash "follow" request))))
                    (fd (sb-sys:fd-stream-fd stream)))
               (send-flow-records
                collector follow
                (lambda (lines) (write-sequence lines stream) (finish-output stream) t)
                (lambda () (gr8s.apiserver::client-connection-closed-p fd)))
               ;; An empty line ends the stream, whatever the port-forward does with a close.
               (write-byte 10 stream)
               (finish-output stream))
           (error () nil))
      (ignore-errors (usocket:socket-close socket)))))

(defun start-flow-listener (collector &key (host "127.0.0.1") (port +default-flow-listener-port+))
  "Serve COLLECTOR's flow events to loopback clients on PORT."
  (let* ((socket (usocket:socket-listen host port :reuse-address t :element-type '(unsigned-byte 8)))
         (listener (%make-flow-listener collector socket)))
    (setf (flow-listener-thread listener)
          (bt:make-thread
           (lambda ()
             (loop until (flow-listener-stopping listener)
                   do (let ((client (handler-case (usocket:socket-accept socket)
                                      (error () nil))))
                        (when client
                          (bt:make-thread (lambda () (serve-flow-client collector client))
                                          :name "gr8s flow client")))))
           :name "gr8s flow listener"))
    listener))

(defun stop-flow-listener (listener)
  "Stop accepting loopback clients. Ones already streaming end with the collector."
  (setf (flow-listener-stopping listener) t)
  (ignore-errors (usocket:socket-close (flow-listener-socket listener)))
  (ignore-errors (bt:join-thread (flow-listener-thread listener))))
