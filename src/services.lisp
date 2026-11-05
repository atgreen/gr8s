;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Allocate durable single-stack ClusterIP and node port Services and resolve
;;;; their ports to running, selector-matched Pod endpoints. Virtual addresses
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

(defun service-external-name-p (service)
  "Recognize a DNS-only Service without allocating a cluster address or listeners."
  (equal "ExternalName" (gethash "type" (gethash "spec" service))))

(defun normalize-external-name-service (object store)
  "Validate a real DNS alias and clear allocation fields only on a genuine type transition."
  (let* ((spec (gethash "spec" object)) (metadata (gethash "metadata" object))
         (name (gethash "externalName" spec))
         (target (and (stringp name) (if (and (plusp (length name)) (char= #\. (char name (1- (length name)))))
                                       (subseq name 0 (1- (length name))) name)))
         (existing (and store (gethash (core-resource-key "services" (gethash "namespace" metadata) (gethash "name" metadata))
                                      (pod-store-resources store))))
         (transition (and existing (not (service-external-name-p existing))
                          (gethash "resourceVersion" metadata))))
    (when (and (equal "default" (gethash "namespace" metadata)) (equal "kubernetes" (gethash "name" metadata)))
      (invalid-pod "the API Service must remain ClusterIP"))
    (unless (and (stringp target) (plusp (length target)) (dns-subdomain-p target))
      (invalid-pod "externalName must be a nonempty DNS subdomain"))
    (unless transition
      (when (or (and (nth-value 1 (gethash "clusterIP" spec))
                     (not (member (gethash "clusterIP" spec) '("" null) :test #'equal)))
                (plusp (length (optional-vector spec "clusterIPs" "Service.spec")))
                (plusp (length (optional-vector spec "ipFamilies" "Service.spec")))
                (and (nth-value 1 (gethash "ipFamilyPolicy" spec))
                     (not (eq 'null (gethash "ipFamilyPolicy" spec)))))
        (invalid-pod "ExternalName Services do not allocate cluster IPs or IP families")))
    (dolist (field '("clusterIP" "clusterIPs" "ipFamilies" "ipFamilyPolicy" "sessionAffinityConfig"
                     "internalTrafficPolicy" "externalTrafficPolicy" "allocateLoadBalancerNodePorts" "loadBalancerClass"))
      (remhash field spec))
    (setf (gethash "sessionAffinity" spec) "None")
    (loop for port across (gethash "ports" spec #()) do (remhash "nodePort" port))
    (setf (gethash "type" spec) "ExternalName" (gethash "externalName" spec) name
          (gethash "status" object) (core-object "loadBalancer" (core-object)))
    object))

(defparameter +node-port-minimum+ 30000 "The first port of the default NodePort range.")
(defparameter +node-port-maximum+ 32767 "The last port of the default NodePort range.")

(defun service-node-ports-needed-p (spec)
  "True when Service SPEC's ports must each own a port on every node."
  (let ((type (gethash "type" spec "ClusterIP")))
    (or (equal type "NodePort")
        (and (equal type "LoadBalancer")
             (not (eq nil (gethash "allocateLoadBalancerNodePorts" spec t)))))))

(defun service-node-ports-in-use-unlocked (store namespace name)
  "Return a table of the node ports other Services hold. The caller holds the store lock."
  (let ((used (make-hash-table)))
    (loop for object being the hash-values of (pod-store-resources store)
          for metadata = (gethash "metadata" object)
          when (and (equal "Service" (gethash "kind" object))
                    (not (and (equal namespace (gethash "namespace" metadata))
                              (equal name (gethash "name" metadata)))))
            do (loop for port across (gethash "ports" (gethash "spec" object) #())
                     when (integerp (gethash "nodePort" port))
                       do (setf (gethash (gethash "nodePort" port) used) t)))
    used))

(defun assign-service-node-ports (spec namespace name existing store)
  "Validate requested node ports and allocate the rest, keeping a port's current one across updates."
  (let* ((ports (gethash "ports" spec #()))
         (old-ports (and existing (gethash "ports" (gethash "spec" existing) #()))))
    (flet ((requested (port) (let ((value (gethash "nodePort" port))) (if (member value '(nil null 0)) nil value))))
      (unless (service-node-ports-needed-p spec)
        (let ((was-node-port (and existing (service-node-ports-needed-p (gethash "spec" existing)))))
          (loop for port across ports
                do (when (and (requested port) (not was-node-port)
                              (not (equal "LoadBalancer" (gethash "type" spec))))
                     (invalid-pod "nodePort may not be used when type is ~A" (gethash "type" spec "ClusterIP")))
                   (unless (and (requested port) (equal "LoadBalancer" (gethash "type" spec)))
                     (remhash "nodePort" port))))
        (return-from assign-service-node-ports spec))
      (unless store (invalid-pod "Service allocation requires the control-plane store"))
      (let ((used (service-node-ports-in-use-unlocked store namespace name)) (mine nil))
        (loop for port across ports
              for number = (or (requested port)
                               (loop for old across (or old-ports #())
                                     when (and (eql (gethash "port" old) (gethash "port" port))
                                               (equal (gethash "protocol" old "TCP") (gethash "protocol" port "TCP"))
                                               (integerp (gethash "nodePort" old)))
                                       return (gethash "nodePort" old)))
              do (if number
                     (progn
                       (unless (typep number `(integer ,+node-port-minimum+ ,+node-port-maximum+))
                         (invalid-pod "nodePort ~A is not in the valid range ~D-~D" number +node-port-minimum+ +node-port-maximum+))
                       (when (gethash number used)
                         (invalid-pod "nodePort ~A is already allocated" number))
                       (when (member (cons number (gethash "protocol" port)) mine :test #'equal)
                         (invalid-pod "nodePort ~A is duplicated for protocol ~A" number (gethash "protocol" port)))
                       (push (cons number (gethash "protocol" port)) mine)
                       (setf (gethash "nodePort" port) number))
                     (remhash "nodePort" port)))
        (loop for port across ports
              unless (gethash "nodePort" port)
                do (let ((number (loop for candidate from +node-port-minimum+ to +node-port-maximum+
                                       unless (or (gethash candidate used) (find candidate mine :key #'car))
                                         return candidate
                                       finally (core-resource-error 503 "ServiceUnavailable" "NodePort range is exhausted"))))
                     (push (cons number (gethash "protocol" port)) mine)
                     (setf (gethash "nodePort" port) number)))))
    spec))

(defun normalize-service-affinity (spec existing)
  "Apply the sessionAffinity defaults, and keep a client timeout only while affinity is on.
Turning affinity off clears the timeout a client read back with the Service."
  (when (member (gethash "sessionAffinity" spec) '(nil null "") :test #'equal)
    (setf (gethash "sessionAffinity" spec) "None"))
  (let ((affinity (gethash "sessionAffinity" spec)))
    (unless (member affinity '("None" "ClientIP") :test #'equal)
      (invalid-pod "sessionAffinity must be None or ClientIP"))
    (if (equal affinity "None")
        (let ((config (gethash "sessionAffinityConfig" spec)))
          (when (and (hash-table-p config) (hash-table-p (gethash "clientIP" config))
                     (gethash "timeoutSeconds" (gethash "clientIP" config))
                     (not (and existing (equal "ClientIP" (gethash "sessionAffinity" (gethash "spec" existing))))))
            (invalid-pod "sessionAffinityConfig must not be set when sessionAffinity is None"))
          (remhash "sessionAffinityConfig" spec))
        (let* ((config (if (hash-table-p (gethash "sessionAffinityConfig" spec))
                           (gethash "sessionAffinityConfig" spec)
                           (setf (gethash "sessionAffinityConfig" spec) (core-object))))
               (client (if (hash-table-p (gethash "clientIP" config))
                           (gethash "clientIP" config)
                           (setf (gethash "clientIP" config) (core-object))))
               (timeout (gethash "timeoutSeconds" client 10800)))
          (unless (typep timeout '(integer 1 86400))
            (invalid-pod "sessionAffinityConfig.clientIP.timeoutSeconds must be 1..86400"))
          (setf (gethash "timeoutSeconds" client) timeout)))))

(defun normalize-service-resource (input namespace name store)
  "Validate and default single-stack ClusterIP, NodePort, LoadBalancer and ExternalName Services."
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
    (drop-null-fields spec)
    (reject-unsupported-fields spec '("type" "ports" "selector" "clusterIP" "clusterIPs" "ipFamilies"
                                     "ipFamilyPolicy" "sessionAffinity" "sessionAffinityConfig" "internalTrafficPolicy"
                                     "externalTrafficPolicy" "allocateLoadBalancerNodePorts" "loadBalancerClass"
                                     "publishNotReadyAddresses" "externalName") "Service.spec")
    (unless (member (gethash "type" spec "ClusterIP") '("ClusterIP" "NodePort" "LoadBalancer" "ExternalName") :test #'equal)
      (invalid-pod "Service type must be ClusterIP, NodePort, LoadBalancer or ExternalName"))
    (normalize-service-affinity spec (and store (gethash (core-resource-key "services" namespace (gethash "name" metadata))
                                                         (pod-store-resources store))))
    (unless (equal "Cluster" (gethash "internalTrafficPolicy" spec "Cluster"))
      (invalid-pod "only cluster internal traffic policy is supported"))
    (unless (equal "Cluster" (gethash "externalTrafficPolicy" spec "Cluster"))
      (invalid-pod "only cluster external traffic policy is supported"))
    (unless (or (service-external-name-p object)
                (and (equalp #("IPv4") (gethash "ipFamilies" spec #("IPv4")))
                     (equal "SingleStack" (gethash "ipFamilyPolicy" spec "SingleStack"))))
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
    (let ((ports (optional-vector spec "ports" "Service.spec")) (names nil) (identities nil))
      (unless (or (service-external-name-p object) (plusp (length ports)))
        (invalid-pod "Service requires at least one port"))
      (loop for port across ports
            do (reject-unsupported-fields port '("name" "port" "targetPort" "protocol" "appProtocol" "nodePort") "Service port")
               (let* ((number (gethash "port" port)) (name (gethash "name" port))
                      (target (gethash "targetPort" port number))
                      (protocol (let ((value (gethash "protocol" port))) (if (member value '(nil null "") :test #'equal) "TCP" value))))
                 (when (eql target 0) (setf target number))
                 (unless (typep number '(integer 1 65535)) (invalid-pod "Service port must be 1..65535"))
                 (unless (member protocol '("TCP" "UDP" "SCTP") :test #'equal)
                   (invalid-pod "Service port protocol must be TCP, UDP or SCTP"))
                 (when (member (cons number protocol) identities :test #'equal)
                   (invalid-pod "Service port ~A/~A is duplicated" number protocol))
                 (push (cons number protocol) identities)
                 (when (or name (> (length ports) 1))
                   (require-dns-label name "Service port name")
                   (when (member name names :test #'equal) (invalid-pod "Service port names must be unique"))
                   (push name names))
                 (unless (or (typep target '(integer 1 65535)) (dns-label-p target))
                   (invalid-pod "targetPort must be a port number or a named container port"))
                 (when (and (gethash "appProtocol" port) (not (core-qualified-key-p (gethash "appProtocol" port))))
                   (invalid-pod "Service appProtocol must be a qualified name"))
                 (setf (gethash "targetPort" port) target (gethash "protocol" port) protocol))))
    (when (service-external-name-p object)
      (return-from normalize-service-resource (normalize-external-name-service object store)))
    (when (equal "" (gethash "externalName" spec)) (remhash "externalName" spec))
    (let ((existing (and store (gethash (core-resource-key "services" namespace (gethash "name" metadata))
                                        (pod-store-resources store))))
          (type (gethash "type" spec "ClusterIP")))
      (when (gethash "externalName" spec)
        (unless (and existing (service-external-name-p existing))
          (invalid-pod "externalName requires type ExternalName"))
        (remhash "externalName" spec))
      (if (equal type "LoadBalancer")
          (progn
            (unless (member (gethash "allocateLoadBalancerNodePorts" spec t) '(t nil))
              (invalid-pod "allocateLoadBalancerNodePorts must be boolean"))
            (setf (gethash "allocateLoadBalancerNodePorts" spec) (if (gethash "allocateLoadBalancerNodePorts" spec t) t nil))
            (let ((class (gethash "loadBalancerClass" spec)))
              (when (and class (not (and (core-qualified-key-p class) (position #\/ class))))
                (invalid-pod "loadBalancerClass must be a domain-prefixed path"))
              (when (and existing (equal "LoadBalancer" (gethash "type" (gethash "spec" existing)))
                         (not (equal class (gethash "loadBalancerClass" (gethash "spec" existing)))))
                (invalid-pod "loadBalancerClass is immutable while the type is LoadBalancer"))))
          (progn (remhash "allocateLoadBalancerNodePorts" spec) (remhash "loadBalancerClass" spec)))
      (if (member type '("NodePort" "LoadBalancer") :test #'equal)
          (setf (gethash "externalTrafficPolicy" spec) (gethash "externalTrafficPolicy" spec "Cluster"))
          (remhash "externalTrafficPolicy" spec))
      (let* ((specified (or (let ((given (gethash "clusterIP" spec))) (and (not (equal given "")) given))
                            ;; An update that omits the address keeps the allocated one.
                            (and existing (gethash "clusterIP" (gethash "spec" existing)))))
             (address (if (or (null specified) (equal specified ""))
                          (if store (allocate-service-ip-unlocked store)
                              (invalid-pod "Service allocation requires the control-plane store")) specified)))
        (unless (or (equal address "None") (service-ip-index address))
          (invalid-pod "clusterIP must be in the native service pool or None"))
        (when (and (equal address "None") (not (equal type "ClusterIP")))
          (invalid-pod "clusterIP may not be None for a ~A Service" type))
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
      (setf (gethash "type" spec) type
            (gethash "internalTrafficPolicy" spec) "Cluster"
            (gethash "ipFamilies" spec) #("IPv4") (gethash "ipFamilyPolicy" spec) "SingleStack")
      (assign-service-node-ports spec namespace (gethash "name" metadata)
                                 (and existing (not (service-external-name-p existing)) existing) store)
      (networking-keep-status object existing (core-object "loadBalancer" (core-object))))
    object))

(defun service-port-target (pod port)
  "Resolve an integer or named Service target against the Pod's real port declarations."
  (let ((target (gethash "targetPort" port (gethash "port" port))))
    (if (integerp target) target
        (loop for container across (gethash "containers" (gethash "spec" (pod-to-object pod)))
              thereis (loop for declared across (gethash "ports" container #())
                            when (and (equal target (gethash "name" declared))
                                      (equal (gethash "protocol" port "TCP") (gethash "protocol" declared "TCP")))
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

(defun ensure-native-api-endpoints (store)
  "Publish the API listener as the Kubernetes Service's Endpoints and EndpointSlice, as an API server does."
  (flet ((ensure (resource object)
           (handler-case (create-core-resource store resource object "default")
             (kubernetes-error (condition)
               (unless (= 409 (kubernetes-error-status-code condition)) (error condition))))))
    (ensure "endpoints"
            (core-object "metadata" (core-object "name" "kubernetes"
                                                 ;; This server writes the slice itself below.
                                                 "labels" (core-object "endpointslice.kubernetes.io/skip-mirror" "true"))
                         "subsets" (vector (core-object "addresses" (vector (core-object "ip" "10.96.0.1"))
                                                        "ports" (vector (core-object "name" "https" "port" 443 "protocol" "TCP"))))))
    (ensure "endpointslices"
            (core-object "metadata" (core-object "name" "kubernetes"
                                                 "labels" (core-object "kubernetes.io/service-name" "kubernetes"
                                                                       "endpointslice.kubernetes.io/managed-by" "gr8s-apiserver"))
                         "addressType" "IPv4"
                         "endpoints" (vector (core-object "addresses" (vector "10.96.0.1")
                                                          "conditions" (core-object "ready" t "serving" t "terminating" nil)))
                         "ports" (vector (core-object "name" "https" "port" 443 "protocol" "TCP"))))))

(defun ensure-native-api-service (store)
  "Publish the real native HTTPS listener as the reserved Kubernetes Service."
  (prog1
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
            existing)))
    (ensure-native-api-endpoints store)
    (ensure-default-service-cidr store)))
