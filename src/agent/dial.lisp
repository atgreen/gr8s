;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Open a TCP connection to a Pod on this node for a control plane that can't
;;;; route to Pod IPs, and carry its bytes over the node session, as Kubernetes's
;;;; konnectivity agent does. The control plane calls webhooks and aggregated API
;;;; servers this way. The connection is a port-forward without the runtime: the
;;;; same credit windows hold each direction, but the bytes come from a socket.
;;;; Only this node's Pods and its own address may be dialled, so a control plane
;;;; can't use the agent to reach anything else on the node's network.

(in-package #:gr8s.agent)

(defparameter +dial-connect-timeout-seconds+ 10)

(defstruct (node-dial-operation
             (:include node-port-forward-operation)
             (:constructor make-node-dial-operation
                 (node-runtime request socket session emit data-stream error-stream))))

(defmethod deliver-port-forward-input ((operation node-dial-operation) data eof)
  (let ((stream (usocket:socket-stream (node-exec-operation-socket operation))))
    (when (plusp (length data))
      (write-sequence data stream)
      (finish-output stream))
    (when eof
      (usocket:socket-shutdown (node-exec-operation-socket operation) :output))))

(defun node-dial-address-allowed-p (node-runtime address)
  "Return whether ADDRESS is a Pod address of this node, or the node's own."
  (let ((network (node-runtime-network node-runtime)))
    (and network (plusp (length address))
         (or (equal address (gethash "underlayAddress" network))
             (some (lambda (cidr) (gr8s.network::network-address-in-cidr-p cidr address))
                   (persisted-node-network-cidrs network "nodePodCIDRs" "nodePodCIDR"))))))

(defparameter *dial-address-allowed-call* #'node-dial-address-allowed-p
  "Decide whether the node may dial an address, taking the node runtime and the address.")

(defun run-node-dial-reader (operation)
  "Forward what the connection sends until it ends, then report the outcome."
  (let ((buffer (make-array 65536 :element-type '(unsigned-byte 8)))
        (fd (sb-bsd-sockets:socket-file-descriptor
             (usocket::socket (node-exec-operation-socket operation)))))
    (handler-case
        (loop
          for count = (sb-sys:with-pinned-objects (buffer)
                        (multiple-value-bind (read errno)
                            (sb-unix:unix-read fd (sb-sys:vector-sap buffer) (length buffer))
                          (unless read
                            (error "connection read failed (errno ~D)" errno))
                          read))
          while (plusp count)
          do (when (wait-for-port-forward-output-window operation count)
               (emit-port-forward-stream operation :data (subseq buffer 0 count))))
      (error (condition)
        (finish-node-exec-operation operation :error (princ-to-string condition))
        (return-from run-node-dial-reader nil)))
    (finish-node-exec-operation operation)))

(defun start-node-dial-operation (node-runtime request emit)
  "Connect to REQUEST's address and port on this node, and start moving data."
  (let ((address (slot-value request 'gr8s.node.v1::dial-address))
        (port (slot-value request 'gr8s.node.v1::port)))
    (unless (<= 1 port 65535)
      (error 'runtime-error :message "Dialing requires a valid port"))
    (unless (funcall *dial-address-allowed-call* node-runtime address)
      (error 'runtime-error
             :message (format nil "~A is not an address of a Pod on this node" address)))
    ;; usocket's :timeout would also bound every read, ending an idle connection.
    (let* ((socket (handler-case
                       (sb-sys:with-deadline (:seconds +dial-connect-timeout-seconds+)
                         (usocket:socket-connect address port :element-type '(unsigned-byte 8)
                                                              :nodelay t))
                     (sb-sys:deadline-timeout ()
                       (error 'runtime-error
                              :message (format nil "timed out connecting to ~A:~D" address port)))))
           (operation (make-node-dial-operation node-runtime request socket nil emit nil nil)))
      (remember-node-exec-operation node-runtime operation)
      (emit-node-exec-response operation gr8s.node.v1::+operationstatus-operation_status_accepted+)
      (setf (node-exec-operation-thread operation)
            (bt:make-thread (lambda () (run-node-dial-reader operation))
                            :name "gr8s dial reader")
            (node-port-forward-operation-writer operation)
            (bt:make-thread (lambda () (run-node-port-forward-writer operation))
                            :name "gr8s dial writer"))
      operation)))
