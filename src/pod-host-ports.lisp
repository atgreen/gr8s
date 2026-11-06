;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Make a container's hostPort and a Service's node port real. The agent listens
;;;; on the node's address and relays each TCP connection, SCTP association or UDP
;;;; flow to a Pod, for
;;;; as long as that Pod is a current target. The relay is in userspace, so a Pod
;;;; sees the node rather than the original client as the source. Node ports honour
;;;; externalTrafficPolicy as kube-proxy does, and a Local LoadBalancer's
;;;; healthCheckNodePort answers whether this node has ready endpoints.

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

(defun host-port-socket-protocol (protocol)
  "The socket protocol keyword for a Kubernetes PROTOCOL."
  (cond ((equal protocol "UDP") :udp) ((equal protocol "SCTP") :sctp) (t :tcp)))

(defun host-port-serve-connection (client address port &optional (protocol "TCP"))
  "Connect CLIENT to the Pod at ADDRESS:PORT over PROTOCOL, TCP or SCTP, and relay both
directions until both end. An SCTP association is relayed as a stream: the octets arrive
in order, but not divided into the messages the client sent."
  (let ((server (make-instance 'sb-bsd-sockets:inet-socket :type :stream
                                                           :protocol (host-port-socket-protocol protocol))))
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
                         (bt:make-thread (lambda () (host-port-serve-connection client (car target) (cdr target)
                                                                               (host-port-forwarder-protocol forwarder)))
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
                                                              :protocol (host-port-socket-protocol protocol))))
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
  "Map (protocol ip . port) to (pod-address . container-port) for STORE's addressed, undeleted Pods."
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
                                       (member protocol '("TCP" "UDP" "SCTP") :test #'equal))
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

(defun host-local-address-p (address)
  "True when ADDRESS (four octets) is one of this host's own, which only a local socket can bind."
  (or (= 127 (aref address 0))
      (let ((socket (make-instance 'sb-bsd-sockets:inet-socket :type :datagram :protocol :udp)))
        (unwind-protect
             (handler-case (progn (sb-bsd-sockets:socket-bind socket address 0) t)
               (error () nil))
          (ignore-errors (sb-bsd-sockets:socket-close socket))))))

(defun make-node-port-target (backends affinity-timeout &key local-origin local-addresses)
  "Return a chooser spreading clients over (address . port) BACKENDS.
A client on this node itself, at one of LOCAL-ADDRESSES (dotted Pod addresses) or one of the
host's own addresses, is spread over LOCAL-ORIGIN instead when that is given, as kube-proxy
short-circuits node-local traffic to an externalTrafficPolicy Local node port. A nonnil
AFFINITY-TIMEOUT holds each client address on one backend while it stays active and still serves."
  (let ((clients (make-hash-table :test #'equalp)) (lock (bt:make-lock "gr8s node port affinity"))
        (locality (make-hash-table :test #'equalp)))
    (flet ((choices (client)
             (if (and local-origin client
                      (bt:with-lock-held (lock)
                        (multiple-value-bind (known present) (gethash client locality)
                          (if present known
                              (setf (gethash client locality)
                                    (or (and (member (format nil "~{~D~^.~}" (coerce client 'list)) local-addresses
                                                     :test #'equal)
                                             t)
                                        (host-local-address-p client)))))))
                 local-origin
                 backends)))
      (lambda (client)
        (let ((candidates (choices client)))
          (when candidates
            (flet ((any-backend () (nth (random (length candidates)) candidates)))
              (if (and affinity-timeout client)
                  (bt:with-lock-held (lock)
                    (let* ((now (get-universal-time))
                           (held (gethash client clients))
                           (backend (if (and held (<= (- now (cdr held)) affinity-timeout)
                                             (member (car held) candidates :test #'equal))
                                        (car held)
                                        (any-backend))))
                      (setf (gethash client clients) (cons backend now))
                      backend))
                  (any-backend)))))))))

(defun node-local-pod-addresses (store)
  "The addresses of the Pods this node runs, whose traffic to a node port is node-local."
  (let ((addresses nil))
    (dolist (pod (list-pods store) addresses)
      (let* ((status (with-store-lock (store) (gethash (pod-uid pod) (pod-store-pod-observed-statuses store))))
             (address (and status (gethash "podIP" status))))
        (when (and (stringp address) (plusp (length address)))
          (pushnew address addresses :test #'equal))))))

(defun desired-node-port-targets (store &key node-name)
  "Map (protocol \"\" . node-port) to a plan for each of STORE's proxied Services with backends:
(external local-origin affinity-timeout), where EXTERNAL are the backends for clients elsewhere,
which externalTrafficPolicy governs, and LOCAL-ORIGIN those for this node's own clients.
With neither there is no listener, so a client is refused exactly as at a ClusterIP."
  (let ((targets (make-hash-table :test #'equal))
        (zone (service-node-zone store node-name)))
    (dolist (service (list-core-resources store "services") targets)
      (when (service-proxied-p service)
        (loop for port across (gethash "ports" (gethash "spec" service) #())
              for node-port = (gethash "nodePort" port)
              for protocol = (gethash "protocol" port "TCP")
              do (when (and (integerp node-port) (member protocol '("TCP" "UDP" "SCTP") :test #'equal))
                   (multiple-value-bind (internal external local-origin)
                       (service-port-backends store service port :node-name node-name :zone zone)
                     (declare (ignore internal))
                     (flet ((ordered (endpoints)
                              (sort (mapcar (lambda (endpoint) (cons (first endpoint) (second endpoint))) endpoints)
                                    #'string< :key #'prin1-to-string)))
                       (let ((external (ordered external)) (local-origin (ordered local-origin)))
                         (when (or external local-origin)
                           (setf (gethash (list* protocol "" node-port) targets)
                                 (list external local-origin (service-affinity-timeout service)))))))))))))

(defun converge-node-port-forwarders (forwarders store &key node-name)
  "Relay STORE's Service node ports, replacing a chooser only when its Service's plan changes,
so a client's affinity survives unrelated changes."
  (let ((plans (desired-node-port-targets store :node-name node-name))
        (targets (make-hash-table :test #'equal))
        (local-addresses (node-local-pod-addresses store)))
    (maphash (lambda (key plan)
               (let* ((forwarder (gethash key forwarders))
                      (current (and forwarder (host-port-forwarder-target forwarder)))
                      (identity (list plan local-addresses)))
                 (setf (gethash key targets)
                       (if (and (consp current) (equal (car current) identity))
                           current
                           (destructuring-bind (external local-origin timeout) plan
                             (cons identity
                                   (make-node-port-target external timeout
                                                          :local-origin local-origin
                                                          :local-addresses local-addresses)))))))
             plans)
    (converge-port-forwarders forwarders targets)))

;;; Health check node ports

(defstruct health-check-server
  "A healthCheckNodePort listener answering, as kube-proxy does, whether this node has ready
endpoints for one externalTrafficPolicy Local LoadBalancer Service."
  listener thread (stopping nil) (namespace "") (name "") (count 0))

(defun health-check-response (namespace name count)
  "The HTTP response kube-proxy's service health server writes for a Service with COUNT local ready endpoints."
  (let ((body (format nil "{~%	\"service\": {~%		\"namespace\": ~S,~%		\"name\": ~S~%	},~%	\"localEndpoints\": ~D,~%	\"serviceProxyHealthy\": true~%}"
                      namespace name count)))
    (trivial-utf-8:string-to-utf-8-bytes
     (format nil "HTTP/1.1 ~A~C~CContent-Type: application/json~C~CX-Content-Type-Options: nosniff~C~CX-Load-Balancing-Endpoint-Weight: ~D~C~CContent-Length: ~D~C~CConnection: close~C~C~C~C~A"
             (if (plusp count) "200 OK" "503 Service Unavailable") #\Return #\Newline #\Return #\Newline
             #\Return #\Newline count #\Return #\Newline
             (length (trivial-utf-8:string-to-utf-8-bytes body)) #\Return #\Newline #\Return #\Newline
             #\Return #\Newline body))))

(defun health-check-serve-connection (server client)
  "Read one request head from CLIENT, answer it from SERVER's current count and close."
  (unwind-protect
       (handler-case
           (let ((buffer (make-array 4096 :element-type '(unsigned-byte 8))) (seen 0)
                 (descriptor (sb-bsd-sockets:socket-file-descriptor client)))
             ;; The answer doesn't depend on the request, but a client expects it read first.
             (loop while (and (< seen (length buffer)) (sb-sys:wait-until-fd-usable descriptor :input 5))
                   do (multiple-value-bind (data length)
                          (sb-bsd-sockets:socket-receive client buffer (- (length buffer) seen))
                        (declare (ignore data))
                        (when (or (null length) (zerop length)) (return))
                        (incf seen length)
                        (when (search #(13 10 13 10) buffer :end2 seen) (return))))
             (let ((response (health-check-response (health-check-server-namespace server)
                                                    (health-check-server-name server)
                                                    (health-check-server-count server)))
                   (sent 0))
               (loop while (< sent (length response))
                     do (incf sent (sb-bsd-sockets:socket-send client (subseq response sent) (- (length response) sent))))))
         (error () nil))
    (ignore-errors (sb-bsd-sockets:socket-close client))))

(defun start-health-check-server (port)
  "Listen for health checks on every address at PORT."
  (let ((listener (make-instance 'sb-bsd-sockets:inet-socket :type :stream :protocol :tcp)))
    (handler-case
        (progn
          (setf (sb-bsd-sockets:sockopt-reuse-address listener) t
                (sb-bsd-sockets:non-blocking-mode listener) t)
          (sb-bsd-sockets:socket-bind listener #(0 0 0 0) port)
          (sb-bsd-sockets:socket-listen listener 64))
      (error (condition)
        (ignore-errors (sb-bsd-sockets:socket-close listener))
        (error condition)))
    (let ((server (make-health-check-server :listener listener)))
      (setf (health-check-server-thread server)
            (bt:make-thread
             (lambda ()
               (let ((descriptor (sb-bsd-sockets:socket-file-descriptor listener)))
                 (loop until (health-check-server-stopping server)
                       do (when (sb-sys:wait-until-fd-usable descriptor :input 0.25)
                            (let ((client (ignore-errors (sb-bsd-sockets:socket-accept listener))))
                              (when client
                                (setf (sb-bsd-sockets:non-blocking-mode client) nil)
                                (bt:make-thread (lambda () (health-check-serve-connection server client))
                                                :name "gr8s health check connection")))))))
             :name "gr8s health check listener"))
      server)))

(defun stop-health-check-server (server)
  "Stop answering health checks on SERVER's port."
  (setf (health-check-server-stopping server) t)
  (ignore-errors (bt:join-thread (health-check-server-thread server)))
  (ignore-errors (sb-bsd-sockets:socket-close (health-check-server-listener server))))

(defun desired-health-checks (store &key node-name)
  "Map each healthCheckNodePort in STORE to (namespace name local-ready-count) for its Service."
  (let ((checks (make-hash-table)))
    (dolist (service (list-core-resources store "services") checks)
      (let* ((spec (gethash "spec" service)) (metadata (gethash "metadata" service))
             (port (gethash "healthCheckNodePort" spec)))
        (when (and (integerp port) (service-proxied-p service))
          (let ((addresses nil))
            (loop for service-port across (gethash "ports" spec #())
                  do (dolist (record (service-slice-endpoint-records store service service-port))
                       (when (and (getf record :ready) node-name (equal node-name (getf record :node)))
                         (pushnew (getf record :address) addresses :test #'equal))))
            (setf (gethash port checks)
                  (list (gethash "namespace" metadata) (gethash "name" metadata) (length addresses)))))))))

(defun converge-health-check-servers (servers store &key node-name)
  "Make the SERVERS table, keyed by port, answer for STORE's healthCheckNodePorts."
  (let ((checks (desired-health-checks store :node-name node-name)))
    (loop for port being the hash-keys of servers using (hash-value server)
          unless (gethash port checks)
            collect port into gone and do (stop-health-check-server server)
          finally (dolist (port gone) (remhash port servers)))
    (maphash (lambda (port check)
               (let ((server (or (gethash port servers)
                                 (handler-case (setf (gethash port servers) (start-health-check-server port))
                                   (error (condition)
                                     (format *error-output* "gr8s health check node port ~D is unavailable: ~A~%"
                                             port condition)
                                     nil)))))
                 (when server
                   (destructuring-bind (namespace name count) check
                     (setf (health-check-server-namespace server) namespace
                           (health-check-server-name server) name
                           (health-check-server-count server) count)))))
             checks)))

(defun stop-health-check-servers (servers)
  "Stop every health check server in the SERVERS table."
  (maphash (lambda (port server) (declare (ignore port)) (stop-health-check-server server)) servers)
  (clrhash servers))

(defun stop-host-port-forwarders (forwarders)
  "Stop every forwarder in the FORWARDERS table."
  (maphash (lambda (key forwarder) (declare (ignore key)) (stop-host-port-forwarder forwarder)) forwarders)
  (clrhash forwarders))
