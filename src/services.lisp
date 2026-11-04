;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Allocate durable single-stack ClusterIP Services and converge their native
;;;; TCP listeners to running, selector-matched Pod endpoints. Virtual addresses
;;;; live only on the cluster-owned service interface; the API listener owns the
;;;; reserved Kubernetes Service address and credentials remain separate.

(in-package #:gr8s)

(defun service-ip-index (address)
  "Return ADDRESS's usable index within the native 10.96.0.0/16 service pool."
  (when (stringp address)
    (let ((parts (uiop:split-string address :separator '(#\.))))
      (when (= 4 (length parts))
        (let ((numbers (mapcar (lambda (part) (ignore-errors (parse-integer part :junk-allowed nil))) parts)))
          (when (and (every (lambda (number) (typep number '(integer 0 255))) numbers)
                     (= 10 (first numbers)) (= 96 (second numbers))
                     (equal address (format nil "~{~D~^.~}" numbers)))
            (let ((index (+ (* 256 (third numbers)) (fourth numbers))))
              (when (<= 1 index 65534) index))))))))

(defun allocate-service-ip-unlocked (store)
  "Choose a free service IP while the caller holds the durable store transaction lock."
  (let ((used (make-hash-table :test #'equal)))
    (loop for object being the hash-values of (pod-store-resources store)
          when (equal "Service" (gethash "kind" object))
            do (setf (gethash (gethash "clusterIP" (gethash "spec" object)) used) t))
    (loop for index from 10 below 65535
          for address = (format nil "10.96.~D.~D" (floor index 256) (mod index 256))
          unless (gethash address used) return address
          finally (core-resource-error 503 "ServiceUnavailable" "Service address pool is exhausted"))))

(defun normalize-service-resource (input namespace name store)
  "Validate and default supported single-stack TCP ClusterIP Service specifications."
  (let* ((object (copy-core-object (require-object input "Service")))
         (metadata (require-object (gethash "metadata" object) "metadata"))
         (spec (require-object (gethash "spec" object) "Service.spec")))
    (unless (and (equal "v1" (gethash "apiVersion" object "v1"))
                 (equal "Service" (gethash "kind" object "Service")))
      (core-resource-error 400 "BadRequest" "Expected v1 Service"))
    (reject-unsupported-fields object '("apiVersion" "kind" "metadata" "spec" "status") "Service")
    (validate-core-metadata metadata namespace name)
    ;; Kubernetes 1.36 enables relaxed Service names, still bounded to one
    ;; 63-character DNS label rather than a general resource DNS subdomain.
    (require-dns-label (gethash "name" metadata) "Service.metadata.name")
    (setf (gethash "apiVersion" object) "v1" (gethash "kind" object) "Service"
          (gethash "namespace" metadata) namespace)
    (reject-unsupported-fields spec '("type" "ports" "selector" "clusterIP" "clusterIPs" "ipFamilies"
                                     "ipFamilyPolicy" "sessionAffinity" "internalTrafficPolicy" "publishNotReadyAddresses") "Service.spec")
    (unless (equal "ClusterIP" (gethash "type" spec "ClusterIP"))
      (invalid-pod "only ClusterIP Services are supported"))
    (unless (and (equal "None" (gethash "sessionAffinity" spec "None"))
                 (equal "Cluster" (gethash "internalTrafficPolicy" spec "Cluster")))
      (invalid-pod "only cluster traffic with no session affinity is supported"))
    (unless (and (equalp #("IPv4") (gethash "ipFamilies" spec #("IPv4")))
                 (equal "SingleStack" (gethash "ipFamilyPolicy" spec "SingleStack")))
      (invalid-pod "Services support only single-stack IPv4"))
    (when (and (nth-value 1 (gethash "publishNotReadyAddresses" spec))
               (not (member (gethash "publishNotReadyAddresses" spec) '(t nil))))
      (invalid-pod "publishNotReadyAddresses must be boolean"))
    (let ((selector (gethash "selector" spec)))
      (when selector
        (validate-core-string-map selector "Service.selector")
        (maphash (lambda (key value)
                   (unless (and (core-qualified-key-p key) (core-label-name-p value :empty t))
                     (invalid-pod "Service selector must contain valid label requirements"))) selector)))
    (let ((ports (optional-vector spec "ports" "Service.spec")) (names nil) (numbers nil))
      (unless (plusp (length ports)) (invalid-pod "Service requires at least one port"))
      (loop for port across ports
            do (reject-unsupported-fields port '("name" "port" "targetPort" "protocol" "appProtocol") "Service port")
               (let* ((number (gethash "port" port)) (name (gethash "name" port))
                      (target (gethash "targetPort" port number)))
                 (when (eql target 0) (setf target number))
                 (unless (typep number '(integer 1 65535)) (invalid-pod "Service port must be 1..65535"))
                 (when (member number numbers) (invalid-pod "Service port numbers must be unique"))
                 (push number numbers)
                 (when (or name (> (length ports) 1))
                   (require-dns-label name "Service port name")
                   (when (member name names :test #'equal) (invalid-pod "Service port names must be unique"))
                   (push name names))
                 (unless (or (typep target '(integer 1 65535)) (dns-label-p target))
                   (invalid-pod "targetPort must be a port number or a named container port"))
                 (when (and (gethash "appProtocol" port) (not (core-qualified-key-p (gethash "appProtocol" port))))
                   (invalid-pod "Service appProtocol must be a qualified name"))
                 (unless (equal "TCP" (gethash "protocol" port "TCP"))
                   (invalid-pod "only TCP Service ports are supported"))
                 (setf (gethash "targetPort" port) target (gethash "protocol" port) "TCP"))))
    (let* ((specified (gethash "clusterIP" spec))
           (address (if (or (null specified) (equal specified ""))
                        (if store (allocate-service-ip-unlocked store)
                            (invalid-pod "Service allocation requires the control-plane store")) specified)))
      (unless (or (equal address "None") (service-ip-index address))
        (invalid-pod "clusterIP must be in the native service pool or None"))
      (when (and (equal address "10.96.0.1")
                 (not (and (equal namespace "default") (equal (gethash "name" metadata) "kubernetes"))))
        (invalid-pod "the API service address is reserved"))
      (when (and store (not (equal address "None")))
        (loop for existing being the hash-values of (pod-store-resources store)
              for old-metadata = (gethash "metadata" existing)
              when (and (equal "Service" (gethash "kind" existing))
                        (equal address (gethash "clusterIP" (gethash "spec" existing)))
                        (not (and (equal namespace (gethash "namespace" old-metadata))
                                  (equal (gethash "name" metadata) (gethash "name" old-metadata)))))
                do (core-resource-error 422 "Invalid" "clusterIP is already allocated")))
      (when (equal address "10.96.0.1")
        (let ((ports (gethash "ports" spec)))
          (unless (and (= 1 (length ports)) (= 443 (gethash "port" (aref ports 0)))
                       (eql 443 (gethash "targetPort" (aref ports 0))))
            (invalid-pod "the API Service must retain its HTTPS port"))))
      (let ((addresses (gethash "clusterIPs" spec)))
        (when (and addresses
                   (not (and (vectorp addresses) (not (stringp addresses))
                             (or (zerop (length addresses)) (equalp addresses (vector address))))))
          (invalid-pod "clusterIPs must match the single clusterIP")))
      (setf (gethash "clusterIP" spec) address (gethash "clusterIPs" spec) (vector address)))
    (setf (gethash "type" spec) "ClusterIP" (gethash "sessionAffinity" spec) "None"
          (gethash "ipFamilies" spec) #("IPv4") (gethash "ipFamilyPolicy" spec) "SingleStack"
          (gethash "status" object) (core-object "loadBalancer" (core-object)))
    object))

(defun service-port-target (pod port)
  "Resolve an integer or named Service target against the Pod's real port declarations."
  (let ((target (gethash "targetPort" port (gethash "port" port))))
    (if (integerp target) target
        (loop for container across (gethash "containers" (gethash "spec" (pod-to-object pod)))
              thereis (loop for declared across (gethash "ports" container #())
                            when (and (equal target (gethash "name" declared))
                                      (equal "TCP" (gethash "protocol" declared "TCP")))
                              return (gethash "containerPort" declared))))))

(defun service-pod-endpoints (store service port)
  "Select running, nondeleting Pods in the Service namespace and resolve their target ports."
  (let* ((spec (gethash "spec" service)) (selector (gethash "selector" spec))
         (namespace (gethash "namespace" (gethash "metadata" service))))
    (multiple-value-bind (endpoints found) (service-slice-endpoints store service port)
      (when found (return-from service-pod-endpoints endpoints)))
    (when (and selector (plusp (hash-table-count selector)))
      (loop for pod in (sort (list-pods store namespace) #'string< :key #'pod-name)
            for labels = (gethash "labels" (gethash "metadata" (pod-to-object pod)))
            for status = (pod-observed-status store pod)
            for address = (and status (gethash "podIP" status))
            for target = (service-port-target pod port)
            when (and status (or (eq t (gethash "publishNotReadyAddresses" spec)) (pod-status-ready-p status)) (equal "Running" (pod-scheduling-phase store pod))
                      (not (deletion-requested-p pod)) address (plusp (length address)) target
                      (loop for key being the hash-keys of selector using (hash-value value)
                            always (and labels (equal value (gethash key labels)))))
              collect (list address target)))))

(defstruct tcp-service-proxy
  "Own one TCP Service listener, its accept thread and all active proxy connections."
  socket thread backend stop-requested
  (connections (make-hash-table :test #'eq))
  (lock (bt:make-lock "gr8s Service proxy")))

(defun service-proxy-close-connection (proxy connection)
  "Close both sides of CONNECTION and remove its ownership record."
  (let ((sockets nil))
    (bt:with-lock-held ((tcp-service-proxy-lock proxy))
      (setf sockets (gethash connection (tcp-service-proxy-connections proxy)))
      (remhash connection (tcp-service-proxy-connections proxy)))
    (dolist (socket sockets) (when socket (ignore-errors (usocket:socket-close socket))))))

(defun service-proxy-connection (proxy client)
  "Relay one TCP connection to an endpoint chosen from the live Service definition."
  (let ((upstream nil) (input-thread nil))
    (unwind-protect
         (handler-case
             (let ((endpoint (funcall (tcp-service-proxy-backend proxy))))
               (when (uiop:getenv "GR8S_TRACE_SERVICE_PROXY")
                 (format *error-output* "gr8s Service selected backend ~S~%" endpoint))
               (when endpoint
                 (setf upstream (usocket:socket-connect (first endpoint) (second endpoint)
                                                         :element-type '(unsigned-byte 8) :timeout 2))
                 (bt:with-lock-held ((tcp-service-proxy-lock proxy))
                   (when (tcp-service-proxy-stop-requested proxy) (return-from service-proxy-connection nil))
                   (setf (gethash client (tcp-service-proxy-connections proxy)) (list client upstream)))
                 (setf input-thread
                       (bt:make-thread
                        (lambda ()
                          (unwind-protect
                               (ignore-errors (copy-binary-stream (usocket:socket-stream client)
                                                                  (usocket:socket-stream upstream)))
                            (ignore-errors (usocket:socket-shutdown upstream :output))))
                        :name "gr8s Service request stream"))
                 (copy-binary-stream (usocket:socket-stream upstream) (usocket:socket-stream client))))
           (error (condition)
             (when (uiop:getenv "GR8S_TRACE_SERVICE_PROXY")
               (format *error-output* "gr8s Service backend connection failed: ~A~%" condition))))
      (service-proxy-close-connection proxy client)
      ;; The connection can be stopped while connect() is in progress, before
      ;; the upstream socket becomes visible in its ownership record.
      (when upstream (ignore-errors (usocket:socket-close upstream)))
      (when (and input-thread (bt:thread-alive-p input-thread))
        (loop repeat 100 while (bt:thread-alive-p input-thread) do (sleep .01))
        (when (bt:thread-alive-p input-thread) (bt:destroy-thread input-thread)))
      (when input-thread (ignore-errors (bt:join-thread input-thread))))))

(defun start-tcp-service-proxy (address port backend)
  "Bind a real TCP listener that resolves BACKEND for each accepted connection."
  (let* ((socket (usocket:socket-listen address port :reuse-address t :element-type '(unsigned-byte 8)))
         (proxy (make-tcp-service-proxy :socket socket :backend backend)))
    (setf (tcp-service-proxy-thread proxy)
          (bt:make-thread
           (lambda ()
             (loop
               (let ((client (handler-case (usocket:socket-accept socket :element-type '(unsigned-byte 8))
                               (error () nil))))
                 (unless client (return))
                 (bt:with-lock-held ((tcp-service-proxy-lock proxy))
                   (when (tcp-service-proxy-stop-requested proxy)
                     (ignore-errors (usocket:socket-close client)) (return))
                   (setf (gethash client (tcp-service-proxy-connections proxy)) (list client)))
                 (bt:make-thread (lambda () (service-proxy-connection proxy client))
                                 :name "gr8s Service connection"))))
           :name "gr8s Service TCP listener"))
    proxy))

(defun stop-tcp-service-proxy (proxy)
  "Stop accepting traffic and close every connection owned by PROXY."
  (let ((clients nil))
    (bt:with-lock-held ((tcp-service-proxy-lock proxy))
      (setf (tcp-service-proxy-stop-requested proxy) t
            clients (loop for client being the hash-keys of (tcp-service-proxy-connections proxy) collect client)))
    (ignore-errors (usocket:socket-close (tcp-service-proxy-socket proxy)))
    (dolist (client clients) (service-proxy-close-connection proxy client))
    (let ((thread (tcp-service-proxy-thread proxy)))
      (when thread
        (loop repeat 100 while (bt:thread-alive-p thread) do (sleep .01))
        (when (bt:thread-alive-p thread) (bt:destroy-thread thread))
        (ignore-errors (bt:join-thread thread))))
  nil))

(defstruct (native-service-controller (:constructor make-native-service-controller (store)))
  "Track native TCP Service listeners and virtual addresses owned by the cluster."
  store
  (proxies (make-hash-table :test #'equal))
  (addresses (make-hash-table :test #'equal)))

(defun native-service-backend-resolver (store namespace name uid port-number)
  "Build a round-robin resolver that follows the Service's current selector and targetPort."
  (let ((index 0) (lock (bt:make-lock "gr8s Service endpoint rotation")))
    (lambda ()
      (let* ((service (handler-case (get-core-resource store "services" namespace name) (kubernetes-error () nil)))
             (port (and service (equal uid (gethash "uid" (gethash "metadata" service)))
                        (find port-number (gethash "ports" (gethash "spec" service))
                              :key (lambda (port) (gethash "port" port)))))
             (endpoints (when port (service-pod-endpoints store service port))))
        (when endpoints
          (bt:with-lock-held (lock)
            (prog1 (nth (mod index (length endpoints)) endpoints) (incf index))))))))

(defun reconcile-native-services (controller)
  "Converge Service listeners, releasing old identities before reusing their sockets."
  (let* ((store (native-service-controller-store controller))
         (desired (make-hash-table :test #'equal)) (addresses (make-hash-table :test #'equal)))
    (dolist (service (list-core-resources store "services"))
      (let* ((metadata (gethash "metadata" service)) (spec (gethash "spec" service))
             (namespace (gethash "namespace" metadata)) (name (gethash "name" metadata))
             (uid (gethash "uid" metadata)) (address (gethash "clusterIP" spec)))
        (unless (or (equal address "None") (equal address "10.96.0.1"))
          (setf (gethash address addresses) t)
          (loop for port across (gethash "ports" spec)
                for number = (gethash "port" port)
                do (setf (gethash (list uid address number) desired) (list namespace name))))))
    ;; A deleted/recreated Service may receive exactly the same IP and port.
    ;; Release its old UID first or the new listener would fail forever at bind().
    (dolist (key (loop for key being the hash-keys of (native-service-controller-proxies controller)
                      unless (gethash key desired) collect key))
      (stop-tcp-service-proxy (gethash key (native-service-controller-proxies controller)))
      (remhash key (native-service-controller-proxies controller)))
    (maphash (lambda (address present)
               (declare (ignore present))
               (unless (network-address-present-p +service-network-interface+ address 32)
                 (add-network-address +service-network-interface+ address 32))
               (setf (gethash address (native-service-controller-addresses controller)) t)) addresses)
    (maphash (lambda (key identity)
               (unless (gethash key (native-service-controller-proxies controller))
                 (destructuring-bind (uid address number) key
                   (setf (gethash key (native-service-controller-proxies controller))
                         (start-tcp-service-proxy address number
                          (native-service-backend-resolver store (first identity) (second identity) uid number)))))) desired)
    (dolist (address (loop for address being the hash-keys of (native-service-controller-addresses controller)
                          unless (gethash address addresses) collect address))
      (remove-network-address +service-network-interface+ address 32)
      (remhash address (native-service-controller-addresses controller)))))

(defun stop-native-service-controller (controller)
  "Close Service listeners and remove their virtual IPs before the shared interface is removed."
  (maphash (lambda (key proxy) (declare (ignore key)) (stop-tcp-service-proxy proxy))
           (native-service-controller-proxies controller))
  (clrhash (native-service-controller-proxies controller))
  (maphash (lambda (address present) (declare (ignore present))
             (remove-network-address +service-network-interface+ address 32))
           (native-service-controller-addresses controller))
  (clrhash (native-service-controller-addresses controller)))

(defun ensure-native-api-service (store)
  "Publish the real native HTTPS listener as the reserved Kubernetes Service."
  (handler-case
      (create-core-resource store "services"
       (core-object "metadata" (core-object "name" "kubernetes")
                    "spec" (core-object "clusterIP" "10.96.0.1"
                                         "ports" (vector (core-object "name" "https" "port" 443 "targetPort" 443))))
       "default")
    (kubernetes-error (condition)
      (unless (= 409 (kubernetes-error-status-code condition)) (error condition))
      (let ((existing (get-core-resource store "services" "default" "kubernetes")))
        (unless (equal "10.96.0.1" (gethash "clusterIP" (gethash "spec" existing)))
          (error 'runtime-error :message "Kubernetes API Service has an unexpected clusterIP"))
        existing))))
