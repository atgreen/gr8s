;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Make a container's hostPort and a Service's node port real. The agent listens
;;;; on the node's address and relays each TCP connection or UDP flow to a Pod, for
;;;; as long as that Pod is a current target. The relay is in userspace, so a Pod
;;;; sees the node rather than the original client as the source.

(in-package #:gr8s)

(defstruct host-port-forwarder
  "A listening port and where it currently relays to: an (address . port) TARGET,
or a (plan . chooser) whose function maps the client's address to one."
  listener thread (target nil) (stopping nil) (protocol "TCP"))

(defparameter +udp-relay-idle-seconds+ 30
  "A UDP flow's relay socket closes after this long without traffic.")

(defun forwarder-target-for (forwarder client-address)
  "Resolve FORWARDER's current destination for a client at CLIENT-ADDRESS, or NIL."
  (let ((target (host-port-forwarder-target forwarder)))
    (cond
          ;; A node port keeps the plan its chooser was made from beside it.
          ((and (consp target) (functionp (cdr target))) (funcall (cdr target) client-address))
          (t target))))

(defun host-port-relay (source destination)
  "Copy octets from SOURCE to DESTINATION until end of stream, then pass on the half-close."
  (let ((buffer (make-array 16384 :element-type '(unsigned-byte 8))))
    (handler-case
        (loop
          (multiple-value-bind (data length) (sb-bsd-sockets:socket-receive source buffer nil)
            (declare (ignore data))
            (when (or (null length) (zerop length)) (return))
            (let ((sent 0))
              (loop while (< sent length)
                    do (incf sent (sb-bsd-sockets:socket-send destination (subseq buffer sent length) (- length sent)))))))
      (error () nil))
    (ignore-errors (sb-bsd-sockets:socket-shutdown destination :direction :output))))

(defun host-port-serve-connection (client address port)
  "Connect CLIENT to the Pod at ADDRESS:PORT and relay both directions until both end."
  (let ((server (make-instance 'sb-bsd-sockets:inet-socket :type :stream :protocol :tcp)))
    (unwind-protect
         (handler-case
             (progn
               (sb-bsd-sockets:socket-connect server (sb-bsd-sockets:make-inet-address address) port)
               (let ((reverse (bt:make-thread (lambda () (host-port-relay server client))
                                              :name "gr8s host port relay")))
                 (host-port-relay client server)
                 (bt:join-thread reverse)))
           (error (condition)
             (format *error-output* "gr8s host port relay to ~A:~D failed: ~A~%" address port condition)))
      (ignore-errors (sb-bsd-sockets:socket-close server))
      (ignore-errors (sb-bsd-sockets:socket-close client)))))

(defun host-port-accept-loop (forwarder)
  "Accept connections for FORWARDER until it stops, sending each to its current target."
  (let* ((listener (host-port-forwarder-listener forwarder))
         (descriptor (sb-bsd-sockets:socket-file-descriptor listener)))
    (loop until (host-port-forwarder-stopping forwarder)
          do (when (sb-sys:wait-until-fd-usable descriptor :input 0.25)
               (let ((client (ignore-errors (sb-bsd-sockets:socket-accept listener))))
                 (when client
                   (let ((target (forwarder-target-for
                                  forwarder (ignore-errors (sb-bsd-sockets:socket-peername client)))))
                     (if target
                         (bt:make-thread (lambda () (host-port-serve-connection client (car target) (cdr target)))
                                         :name "gr8s host port connection")
                         (ignore-errors (sb-bsd-sockets:socket-close client))))))))))

(defun udp-flow-relay (forwarder flows key upstream)
  "Return a client's replies from UPSTREAM through the listener until the flow goes idle."
  (let ((buffer (make-array 65535 :element-type '(unsigned-byte 8)))
        (descriptor (sb-bsd-sockets:socket-file-descriptor upstream)))
    (unwind-protect
         (loop until (host-port-forwarder-stopping forwarder)
               do (unless (sb-sys:wait-until-fd-usable descriptor :input +udp-relay-idle-seconds+)
                    (return))
                  ;; An ICMP rejection from the Pod surfaces here; the client just times out.
                  (multiple-value-bind (data length) (ignore-errors (sb-bsd-sockets:socket-receive upstream buffer nil))
                    (declare (ignore data))
                    (when (and length (plusp length))
                      (ignore-errors
                       (sb-bsd-sockets:socket-send (host-port-forwarder-listener forwarder) buffer length
                                                   :address (list (car key) (cdr key)))))))
      (bt:with-lock-held ((car flows)) (remhash key (cdr flows)))
      (ignore-errors (sb-bsd-sockets:socket-close upstream)))))

(defun udp-flow-socket (forwarder flows key)
  "Return the relay socket of the client flow KEY, opening one to the current target if needed."
  (bt:with-lock-held ((car flows))
    (or (gethash key (cdr flows))
        (let ((target (forwarder-target-for forwarder (car key))))
          (when target
            (let ((upstream (make-instance 'sb-bsd-sockets:inet-socket :type :datagram :protocol :udp)))
              (handler-case
                  (progn
                    (setf (sb-bsd-sockets:non-blocking-mode upstream) t)
                    (sb-bsd-sockets:socket-connect upstream (sb-bsd-sockets:make-inet-address (car target)) (cdr target))
                    (setf (gethash key (cdr flows)) upstream)
                    (bt:make-thread (lambda () (udp-flow-relay forwarder flows key upstream))
                                    :name "gr8s UDP port flow")
                    upstream)
                (error (condition)
                  (ignore-errors (sb-bsd-sockets:socket-close upstream))
                  (format *error-output* "gr8s UDP relay to ~A:~D failed: ~A~%" (car target) (cdr target) condition)
                  nil))))))))

(defun udp-port-receive-loop (forwarder)
  "Relay each datagram to its client's flow until FORWARDER stops."
  (let* ((listener (host-port-forwarder-listener forwarder))
         (descriptor (sb-bsd-sockets:socket-file-descriptor listener))
         (buffer (make-array 65535 :element-type '(unsigned-byte 8)))
         (flows (cons (bt:make-lock "gr8s UDP port flows") (make-hash-table :test #'equalp))))
    (loop until (host-port-forwarder-stopping forwarder)
          do (when (sb-sys:wait-until-fd-usable descriptor :input 0.25)
               (multiple-value-bind (data length address port)
                   (ignore-errors (sb-bsd-sockets:socket-receive listener buffer nil))
                 (declare (ignore data))
                 (when (and length address)
                   (let ((upstream (udp-flow-socket forwarder flows (cons address port))))
                     (when upstream
                       (ignore-errors (sb-bsd-sockets:socket-send upstream buffer length))))))))))

(defun start-host-port-forwarder (ip port target &optional (protocol "TCP"))
  "Listen on IP:PORT/PROTOCOL, or every address when IP is unset, relaying to TARGET."
  (let* ((udp (equal protocol "UDP"))
         (listener (make-instance 'sb-bsd-sockets:inet-socket :type (if udp :datagram :stream)
                                                              :protocol (if udp :udp :tcp))))
    (handler-case
        (progn
          (setf (sb-bsd-sockets:sockopt-reuse-address listener) t
                (sb-bsd-sockets:non-blocking-mode listener) t)
          (sb-bsd-sockets:socket-bind listener
                                      (sb-bsd-sockets:make-inet-address (if (member ip '(nil "") :test #'equal) "0.0.0.0" ip))
                                      port)
          (unless udp (sb-bsd-sockets:socket-listen listener 128)))
      (error (condition)
        (ignore-errors (sb-bsd-sockets:socket-close listener))
        (error condition)))
    (let ((forwarder (make-host-port-forwarder :listener listener :target target :protocol protocol)))
      (setf (host-port-forwarder-thread forwarder)
            (bt:make-thread (lambda () (if udp (udp-port-receive-loop forwarder) (host-port-accept-loop forwarder)))
                            :name "gr8s host port listener"))
      forwarder)))

(defun stop-host-port-forwarder (forwarder)
  "Stop listening. Established connections carry on until they finish."
  (setf (host-port-forwarder-stopping forwarder) t)
  (ignore-errors (bt:join-thread (host-port-forwarder-thread forwarder)))
  (ignore-errors (sb-bsd-sockets:socket-close (host-port-forwarder-listener forwarder))))

(defun desired-host-port-targets (store)
  "Map (protocol ip . port) to (pod-address . container-port) for STORE's addressed, undeleted Pods.
SCTP host ports are scheduled but not relayed: this userspace relay carries only TCP and UDP."
  (let ((targets (make-hash-table :test #'equal)))
    (dolist (pod (list-pods store) targets)
      (let* ((status (with-store-lock (store) (gethash (pod-uid pod) (pod-store-pod-observed-statuses store))))
             (address (and status (gethash "podIP" status))))
        ;; A hostNetwork Pod binds its host ports itself.
        (when (and (stringp address) (plusp (length address)) (not (deletion-requested-p pod))
                   (not (pod-host-network-p pod))
                   (not (terminal-pod-phase-p (gethash "phase" status ""))))
          (loop for container across (gethash "containers" (gethash "spec" (pod-to-object pod)) #())
                do (loop for port across (gethash "ports" container #())
                         for host-port = (gethash "hostPort" port)
                         for protocol = (gethash "protocol" port "TCP")
                         do (when (and (integerp host-port) (plusp host-port)
                                       (member protocol '("TCP" "UDP") :test #'equal))
                              (setf (gethash (list* protocol (gethash "hostIP" port "") host-port) targets)
                                    (cons address (gethash "containerPort" port)))))))))))

(defun converge-port-forwarders (forwarders targets)
  "Make the FORWARDERS table match TARGETS, keyed by (protocol ip . port). A port the host already uses is reported and retried."
  (progn
    (loop for key being the hash-keys of forwarders using (hash-value forwarder)
          unless (gethash key targets)
            collect key into gone and do (stop-host-port-forwarder forwarder)
          finally (dolist (key gone) (remhash key forwarders)))
    (maphash (lambda (key target)
               (let ((forwarder (gethash key forwarders)))
                 (if forwarder
                     (setf (host-port-forwarder-target forwarder) target)
                     (handler-case
                         (setf (gethash key forwarders)
                               (start-host-port-forwarder (cadr key) (cddr key) target (car key)))
                       (error (condition)
                         (format *error-output* "gr8s ~A port ~A:~D is unavailable: ~A~%"
                                 (car key) (cadr key) (cddr key) condition))))))
             targets)))

(defun converge-host-port-forwarders (forwarders store)
  "Make the FORWARDERS table match the host ports of STORE's Pods."
  (converge-port-forwarders forwarders (desired-host-port-targets store)))

;;; Service node ports

(defun make-node-port-target (backends affinity-timeout)
  "Return a chooser spreading clients over (address . port) BACKENDS.
A nonnil AFFINITY-TIMEOUT holds each client address on one backend while it stays active."
  (let ((clients (make-hash-table :test #'equalp)) (lock (bt:make-lock "gr8s node port affinity")))
    (lambda (client)
      (flet ((any-backend () (nth (random (length backends)) backends)))
        (if (and affinity-timeout client)
            (bt:with-lock-held (lock)
              (let* ((now (get-universal-time))
                     (held (gethash client clients))
                     (backend (if (and held (<= (- now (cdr held)) affinity-timeout)
                                       (member (car held) backends :test #'equal))
                                  (car held)
                                  (any-backend))))
                (setf (gethash client clients) (cons backend now))
                backend))
            (any-backend))))))

(defun desired-node-port-targets (store)
  "Map (protocol \"\" . node-port) to the backends of STORE's Services with ready backends.
With none there is no listener, so a client is refused exactly as at a ClusterIP."
  (let ((targets (make-hash-table :test #'equal)))
    (dolist (service (list-core-resources store "services") targets)
      (loop for port across (gethash "ports" (gethash "spec" service) #())
            for node-port = (gethash "nodePort" port)
            for protocol = (gethash "protocol" port "TCP")
            do (when (and (integerp node-port) (member protocol '("TCP" "UDP") :test #'equal))
                 (let ((backends (sort (mapcar (lambda (endpoint) (cons (first endpoint) (second endpoint)))
                                               (service-pod-endpoints store service port))
                                       #'string< :key #'prin1-to-string)))
                   (when backends
                     (setf (gethash (list* protocol "" node-port) targets)
                           (list backends (service-affinity-timeout service))))))))))

(defun converge-node-port-forwarders (forwarders store)
  "Relay STORE's Service node ports, replacing a chooser only when its Service's plan changes,
so a client's affinity survives unrelated changes."
  (let ((plans (desired-node-port-targets store)) (targets (make-hash-table :test #'equal)))
    (maphash (lambda (key plan)
               (let* ((forwarder (gethash key forwarders))
                      (current (and forwarder (host-port-forwarder-target forwarder))))
                 (setf (gethash key targets)
                       (if (and (consp current) (equal (car current) plan))
                           current
                           (let ((chooser (make-node-port-target (first plan) (second plan))))
                             (cons plan chooser))))))
             plans)
    (converge-port-forwarders forwarders targets)))

(defun stop-host-port-forwarders (forwarders)
  "Stop every forwarder in the FORWARDERS table."
  (maphash (lambda (key forwarder) (declare (ignore key)) (stop-host-port-forwarder forwarder)) forwarders)
  (clrhash forwarders))
