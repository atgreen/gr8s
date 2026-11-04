;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Make a container's hostPort real. The agent listens on the node's address and
;;;; relays each TCP connection to the Pod, once the Pod has an address and for as
;;;; long as it is assigned here. The relay is in userspace, so a Pod sees the
;;;; node rather than the original client as a connection's source.

(in-package #:gr8s)

(defstruct host-port-forwarder
  "A listening host port and where it currently relays to."
  listener thread (target nil) (stopping nil))

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
               (let ((client (ignore-errors (sb-bsd-sockets:socket-accept listener)))
                     (target (host-port-forwarder-target forwarder)))
                 (when client
                   (if target
                       (bt:make-thread (lambda () (host-port-serve-connection client (car target) (cdr target)))
                                       :name "gr8s host port connection")
                       (ignore-errors (sb-bsd-sockets:socket-close client)))))))))

(defun start-host-port-forwarder (ip port target)
  "Listen on IP:PORT, or every address when IP is unset, relaying connections to TARGET."
  (let ((listener (make-instance 'sb-bsd-sockets:inet-socket :type :stream :protocol :tcp)))
    (handler-case
        (progn
          (setf (sb-bsd-sockets:sockopt-reuse-address listener) t
                (sb-bsd-sockets:non-blocking-mode listener) t)
          (sb-bsd-sockets:socket-bind listener
                                      (sb-bsd-sockets:make-inet-address (if (member ip '(nil "") :test #'equal) "0.0.0.0" ip))
                                      port)
          (sb-bsd-sockets:socket-listen listener 128))
      (error (condition)
        (ignore-errors (sb-bsd-sockets:socket-close listener))
        (error condition)))
    (let ((forwarder (make-host-port-forwarder :listener listener :target target)))
      (setf (host-port-forwarder-thread forwarder)
            (bt:make-thread (lambda () (host-port-accept-loop forwarder)) :name "gr8s host port listener"))
      forwarder)))

(defun stop-host-port-forwarder (forwarder)
  "Stop listening. Established connections carry on until they finish."
  (setf (host-port-forwarder-stopping forwarder) t)
  (ignore-errors (bt:join-thread (host-port-forwarder-thread forwarder)))
  (ignore-errors (sb-bsd-sockets:socket-close (host-port-forwarder-listener forwarder))))

(defun desired-host-port-targets (store)
  "Map (ip . port) to (pod-address . container-port) for STORE's addressed, undeleted Pods."
  (let ((targets (make-hash-table :test #'equal)))
    (dolist (pod (list-pods store) targets)
      (let* ((status (with-store-lock (store) (gethash (pod-uid pod) (pod-store-pod-observed-statuses store))))
             (address (and status (gethash "podIP" status))))
        (when (and (stringp address) (plusp (length address)) (not (deletion-requested-p pod))
                   (not (terminal-pod-phase-p (gethash "phase" status ""))))
          (loop for container across (gethash "containers" (gethash "spec" (pod-to-object pod)) #())
                do (loop for port across (gethash "ports" container #())
                         for host-port = (gethash "hostPort" port)
                         do (when (and (integerp host-port) (plusp host-port))
                              (setf (gethash (cons (gethash "hostIP" port "") host-port) targets)
                                    (cons address (gethash "containerPort" port)))))))))))

(defun converge-host-port-forwarders (forwarders store)
  "Make the FORWARDERS table match STORE's Pods. A port the host already uses is reported and retried."
  (let ((targets (desired-host-port-targets store)))
    (loop for key being the hash-keys of forwarders using (hash-value forwarder)
          unless (gethash key targets)
            collect key into gone and do (stop-host-port-forwarder forwarder)
          finally (dolist (key gone) (remhash key forwarders)))
    (maphash (lambda (key target)
               (let ((forwarder (gethash key forwarders)))
                 (if forwarder
                     (setf (host-port-forwarder-target forwarder) target)
                     (handler-case
                         (setf (gethash key forwarders) (start-host-port-forwarder (car key) (cdr key) target))
                       (error (condition)
                         (format *error-output* "gr8s host port ~A:~D is unavailable: ~A~%" (car key) (cdr key) condition))))))
             targets)))

(defun stop-host-port-forwarders (forwarders)
  "Stop every forwarder in the FORWARDERS table."
  (maphash (lambda (key forwarder) (declare (ignore key)) (stop-host-port-forwarder forwarder)) forwarders)
  (clrhash forwarders))
