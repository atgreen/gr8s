;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Allocate durable single-stack ClusterIP and node port Services and resolve
;;;; their ports to running, selector-matched Pod endpoints. ClusterIPs come from
;;;; every IPv4 ServiceCIDR, and each one is claimed by an IPAddress object, as
;;;; upstream's allocator does. Virtual addresses
;;;; live only on the cluster-owned service interface; the API listener owns the
;;;; reserved Kubernetes Service address and credentials remain separate.

(in-package #:gr8s)

(defparameter +ip-address-manager+ "ipallocator.k8s.io"
  "The manager label upstream's ClusterIP allocator puts on the IPAddress objects it owns.")

(defun service-cidr-prefixes (store)
  "Return the IPv4 ranges ClusterIPs come from, as (name network prefix-length) lists: those of
STORE's ServiceCIDRs not being deleted, the default first, then by name. Without any
ServiceCIDR, as before the default one is published, the native default range."
  (let ((result nil))
    (loop for object being the hash-values of (pod-store-resources store)
          for metadata = (gethash "metadata" object)
          when (and (equal "ServiceCIDR" (gethash "kind" object)) (not (gethash "deletionTimestamp" metadata)))
            do (loop for cidr across (gethash "cidrs" (gethash "spec" object) #())
                     for slash = (position #\/ cidr)
                     unless (or (find #\: cidr) (null slash))
                       do (push (list (gethash "name" metadata) (parse-ipv4-integer (subseq cidr 0 slash))
                                      (parse-integer cidr :start (1+ slash)))
                                result)))
    (or (sort result (lambda (left right)
                       (cond ((equal (first left) +default-service-cidr-name+) (not (equal (first right) +default-service-cidr-name+)))
                             ((equal (first right) +default-service-cidr-name+) nil)
                             (t (string< (first left) (first right))))))
        (let ((slash (position #\/ +default-service-cidr+)))
          (list (list +default-service-cidr-name+ (parse-ipv4-integer (subseq +default-service-cidr+ 0 slash))
                      (parse-integer +default-service-cidr+ :start (1+ slash))))))))

(defun service-cidr-index (value network prefix)
  "Return VALUE's offset in NETWORK/PREFIX when it may be a ClusterIP: inside the range and,
as upstream's allocator reserves them, neither its network nor its broadcast address."
  (let ((size (ash 1 (- 32 prefix))) (offset (- value network)))
    (when (and (<= 0 offset) (< offset size)
               (or (<= size 2) (< 0 offset (1- size))))
      offset)))

(defun service-ip-range (store address)
  "Return the name of the ServiceCIDR whose range holds ADDRESS, or NIL."
  (let ((value (and (networking-canonical-ip-p address) (not (find #\: address)) (parse-ipv4-integer address))))
    (when value
      (loop for (name network prefix) in (service-cidr-prefixes store)
            when (service-cidr-index value network prefix) return name))))

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

(defun ip-address-parent-service (object)
  "Return (namespace name) of the Service an IPAddress OBJECT names as its parent, or NIL."
  (let ((parent (gethash "parentRef" (gethash "spec" object))))
    (when (and (hash-table-p parent) (equal "services" (gethash "resource" parent))
               (member (gethash "group" parent "") '("" nil) :test #'equal))
      (list (gethash "namespace" parent) (gethash "name" parent)))))

(defun ip-address-stale-p (store object)
  "True for an IPAddress the allocator made whose Service is gone or no longer holds it, which
the repair pass removes and an allocation may take over meanwhile."
  (let ((labels (gethash "labels" (gethash "metadata" object)))
        (parent (ip-address-parent-service object)))
    (and (hash-table-p labels) (equal +ip-address-manager+ (gethash "ipaddress.kubernetes.io/managed-by" labels))
         parent
         (let ((service (gethash (core-resource-key "services" (first parent) (second parent)) (pod-store-resources store))))
           (not (and service (equal (gethash "name" (gethash "metadata" object))
                                    (gethash "clusterIP" (gethash "spec" service)))))))))

(defun service-ip-holder (store address namespace name)
  "Describe what, other than Service NAMESPACE/NAME, holds ADDRESS: another Service, or an
IPAddress object that isn't a stale one of the allocator's. NIL when it is free."
  (or (loop for object being the hash-values of (pod-store-resources store)
            for metadata = (gethash "metadata" object)
            thereis (and (equal "Service" (gethash "kind" object))
                         (equal address (gethash "clusterIP" (gethash "spec" object)))
                         (not (and (equal namespace (gethash "namespace" metadata))
                                   (equal name (gethash "name" metadata))))
                         (format nil "Service ~A/~A" (gethash "namespace" metadata) (gethash "name" metadata))))
      (let ((claim (gethash (core-resource-key "ipaddresses" nil address) (pod-store-resources store))))
        (when (and claim (not (ip-address-stale-p store claim))
                   (not (equal (ip-address-parent-service claim) (list namespace name))))
          (format nil "IPAddress ~A" address)))))

(defun allocate-service-ip-unlocked (store)
  "Choose a free service IP from STORE's ServiceCIDRs while the caller holds the durable store
transaction lock: the default range first, from offset 10 as before, then the others in name order.
An address is taken by a Service or by an IPAddress object that isn't a stale one of the allocator's."
  (let ((used (make-hash-table :test #'equal)))
    (loop for object being the hash-values of (pod-store-resources store)
          do (cond ((equal "Service" (gethash "kind" object))
                    (setf (gethash (gethash "clusterIP" (gethash "spec" object)) used) t))
                   ((and (equal "IPAddress" (gethash "kind" object)) (not (ip-address-stale-p store object)))
                    (setf (gethash (gethash "name" (gethash "metadata" object)) used) t))))
    (loop for (name network prefix) in (service-cidr-prefixes store)
          for size = (ash 1 (- 32 prefix))
          do (loop for offset from (if (equal name +default-service-cidr-name+) (min 10 (max 1 (- size 2))) 1)
                   below (if (<= size 2) size (1- size))
                   for value = (+ network offset)
                   for address = (format nil "~D.~D.~D.~D" (ldb (byte 8 24) value) (ldb (byte 8 16) value)
                                         (ldb (byte 8 8) value) (ldb (byte 8 0) value))
                   unless (gethash address used) do (return-from allocate-service-ip-unlocked address)))
    (core-resource-error 503 "ServiceUnavailable" "Service address pool is exhausted")))

(defun service-ip-address-object (address namespace name)
  "The IPAddress object upstream's allocator writes for Service NAMESPACE/NAME's ADDRESS."
  (core-object "apiVersion" "networking.k8s.io/v1" "kind" "IPAddress"
               "metadata" (core-object "name" address
                                       "labels" (core-object "ipaddress.kubernetes.io/ip-family" "IPv4"
                                                             "ipaddress.kubernetes.io/managed-by" +ip-address-manager+))
               "spec" (core-object "parentRef" (core-object "group" "" "resource" "services"
                                                            "namespace" namespace "name" name))))

(defun prepare-service-ip-address-writes (resources service existing revision)
  "Add to RESOURCES, the index a Service write is about to commit, the IPAddress object for
SERVICE's ClusterIP, and drop the one for the address EXISTING held if SERVICE no longer has it.
Returns the revision the commit then needs."
  (let* ((metadata (gethash "metadata" service))
         (namespace (gethash "namespace" metadata)) (name (gethash "name" metadata))
         (address (and (not (service-external-name-p service)) (gethash "clusterIP" (gethash "spec" service))))
         (old (and existing (not (service-external-name-p existing)) (gethash "clusterIP" (gethash "spec" existing)))))
    (when (and (stringp old) (not (equal old address)))
      (let* ((key (core-resource-key "ipaddresses" nil old)) (claim (gethash key resources)))
        (when (and claim (equal (ip-address-parent-service claim) (list namespace name)))
          (remhash key resources)
          (incf revision))))
    (when (and (stringp address) (not (equal address "None")))
      (let* ((key (core-resource-key "ipaddresses" nil address)) (claim (gethash key resources)))
        (unless (and claim (equal (ip-address-parent-service claim) (list namespace name)))
          (let ((object (service-ip-address-object address namespace name)))
            (prepare-core-resource-metadata object nil (incf revision))
            (setf (gethash key resources) object)))))
    revision))

(defun reconcile-service-ip-addresses (store)
  "Repair IPAddress objects as upstream's allocator repair loop does: give every ClusterIP Service
its IPAddress, and remove the allocator's own ones whose Service is gone or holds another address.
An address someone else's IPAddress already names is left alone."
  (with-store-lock (store)
    (let* ((index (pod-store-resources store))
           (stale (loop for object being the hash-values of index
                        when (and (equal "IPAddress" (gethash "kind" object)) (ip-address-stale-p store object))
                          collect (gethash "name" (gethash "metadata" object))))
           (unclaimed (loop for object being the hash-values of index
                            for address = (and (equal "Service" (gethash "kind" object))
                                               (not (service-external-name-p object))
                                               (gethash "clusterIP" (gethash "spec" object)))
                            when (and (stringp address) (not (equal address "None"))
                                      (or (member address stale :test #'equal)
                                          (null (gethash (core-resource-key "ipaddresses" nil address) index))))
                              collect object)))
      (when (or stale unclaimed)
        (let* ((revision (pod-store-resource-revision store))
               (resources (copy-core-resource-index store)))
          (dolist (address stale)
            (remhash (core-resource-key "ipaddresses" nil address) resources)
            (incf revision))
          (dolist (service unclaimed)
            (setf revision (prepare-service-ip-address-writes resources service nil revision)))
          (commit-core-resources store resources revision))))))

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
                     "internalTrafficPolicy" "externalTrafficPolicy" "allocateLoadBalancerNodePorts" "loadBalancerClass"
                     "healthCheckNodePort"))
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
                       do (setf (gethash (gethash "nodePort" port) used) t))
               ;; A health check node port comes from the same range.
               (let ((health (gethash "healthCheckNodePort" (gethash "spec" object))))
                 (when (integerp health) (setf (gethash health used) t))))
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
        (let ((health (gethash "healthCheckNodePort" spec)))
          (when (integerp health) (setf (gethash health used) t)))
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
                         (invalid-pod "spec.ports[].nodePort: Invalid value: ~A: provided port is not in the valid range. The range of valid ports is ~D-~D"
                                      number +node-port-minimum+ +node-port-maximum+))
                       (when (gethash number used)
                         (invalid-pod "spec.ports[].nodePort: Invalid value: ~A: provided port is already allocated" number))
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

;;; Traffic policies, external addresses and health check node ports

(defun service-externally-accessible-p (spec)
  "True, as upstream decides, for NodePort and LoadBalancer Services and a ClusterIP Service
with external IPs: these take an externalTrafficPolicy."
  (let ((type (gethash "type" spec "ClusterIP")))
    (or (member type '("NodePort" "LoadBalancer") :test #'equal)
        (and (equal type "ClusterIP") (plusp (length (gethash "externalIPs" spec #())))))))

(defun service-needs-health-check-p (spec)
  "True when a load balancer must ask each node whether it has local endpoints."
  (and (equal "LoadBalancer" (gethash "type" spec "ClusterIP"))
       (equal "Local" (gethash "externalTrafficPolicy" spec))))

(defun service-ip-special-reason (address)
  "Return why ADDRESS may not be a Service external IP, as upstream's endpoint IP check does, or NIL."
  (if (find #\: address)
      (let ((bytes (0conf:parse-ipv6 address)))
        (cond ((every #'zerop bytes) "may not be unspecified")
              ((and (every #'zerop (subseq bytes 0 15)) (= 1 (aref bytes 15)))
               "may not be in the loopback range (127.0.0.0/8, ::1/128)")
              ((and (= #xfe (aref bytes 0)) (= #x80 (logand #xc0 (aref bytes 1))))
               "may not be in the link-local range (169.254.0.0/16, fe80::/10)")
              ((and (= #xff (aref bytes 0)) (= #x02 (aref bytes 1)))
               "may not be in the link-local multicast range (224.0.0.0/24, ff02::/10)")))
      (let ((value (parse-ipv4-integer address)))
        (cond ((zerop value) "may not be unspecified")
              ((= 127 (ash value -24)) "may not be in the loopback range (127.0.0.0/8, ::1/128)")
              ((= #xa9fe (ash value -16)) "may not be in the link-local range (169.254.0.0/16, fe80::/10)")
              ((= #xe00000 (ash value -8))
               "may not be in the link-local multicast range (224.0.0.0/24, ff02::/10)")))))

(defun service-legacy-ip-p (text)
  "Recognize an IPv4 address without leading zeros, or any IPv6 address without a zone."
  (and (stringp text)
       (if (find #\: text)
           (and (not (find #\% text)) (not (find #\. text))
                (handler-case (and (0conf:parse-ipv6 text) t) (error () nil)))
           (networking-canonical-ip-p text))))

(defun service-legacy-cidr-p (text)
  "Recognize an address/prefix, allowing bits beyond the prefix as upstream's legacy fields do."
  (let ((slash (and (stringp text) (position #\/ text))))
    (when slash
      (let* ((address (subseq text 0 slash)) (digits (subseq text (1+ slash)))
             (prefix (and (plusp (length digits)) (<= (length digits) 3) (every #'digit-char-p digits)
                          (parse-integer digits))))
        (and prefix (service-legacy-ip-p address)
             (<= prefix (if (find #\: address) 128 32)))))))

(defun validate-service-addresses (spec existing)
  "Check externalIPs, loadBalancerIP and loadBalancerSourceRanges as upstream validation does.
Values already stored are accepted again unchanged, like upstream's legacy-field rule."
  (let ((old-spec (and existing (gethash "spec" existing))))
    (let ((addresses (require-string-vector (optional-vector spec "externalIPs" "Service.spec") "Service.spec.externalIPs"))
          (old (and old-spec (gethash "externalIPs" old-spec))))
      (loop for address across addresses
            unless (and old (find address old :test #'equal))
              do (unless (service-legacy-ip-p address)
                   (invalid-pod "spec.externalIPs: Invalid value: ~S: must be a valid IP address" address))
                 (let ((reason (service-ip-special-reason address)))
                   (when reason (invalid-pod "spec.externalIPs: Invalid value: ~S: ~A" address reason))))
      (if (plusp (length addresses))
          (setf (gethash "externalIPs" spec) addresses)
          (remhash "externalIPs" spec)))
    (let ((address (gethash "loadBalancerIP" spec)))
      (cond ((member address '(nil "") :test #'equal) (remhash "loadBalancerIP" spec))
            ((not (stringp address)) (invalid-pod "spec.loadBalancerIP must be a string"))))
    (let ((ranges (require-string-vector (optional-vector spec "loadBalancerSourceRanges" "Service.spec")
                                         "Service.spec.loadBalancerSourceRanges"))
          (old (and old-spec (map 'list (lambda (value) (string-trim " " value))
                                  (gethash "loadBalancerSourceRanges" old-spec #())))))
      (when (plusp (length ranges))
        (unless (equal "LoadBalancer" (gethash "type" spec "ClusterIP"))
          (invalid-pod "spec.loadBalancerSourceRanges: Forbidden: may only be used when `type` is 'LoadBalancer'"))
        (loop for range across ranges
              for trimmed = (string-trim " " range)
              unless (or (member trimmed old :test #'equal) (service-legacy-cidr-p trimmed))
                do (invalid-pod "spec.loadBalancerSourceRanges: Invalid value: ~S: must be a valid CIDR value" range)))
      (if (plusp (length ranges))
          (setf (gethash "loadBalancerSourceRanges" spec) ranges)
          (remhash "loadBalancerSourceRanges" spec)))))

(defun normalize-service-traffic-policies (spec existing)
  "Default and validate internal and external traffic policies and trafficDistribution.
An update that leaves a type which takes externalTrafficPolicy, and doesn't change it,
drops it as upstream's dropTypeDependentFields does; anything else that isn't allowed is refused."
  (dolist (field '("internalTrafficPolicy" "externalTrafficPolicy" "trafficDistribution"))
    (when (equal "" (gethash field spec)) (remhash field spec)))
  (setf (gethash "internalTrafficPolicy" spec) (gethash "internalTrafficPolicy" spec "Cluster"))
  (unless (member (gethash "internalTrafficPolicy" spec) '("Cluster" "Local") :test #'equal)
    (invalid-pod "spec.internalTrafficPolicy: Unsupported value: ~S: supported values: \"Cluster\", \"Local\""
                 (gethash "internalTrafficPolicy" spec)))
  (let* ((old-spec (and existing (gethash "spec" existing)))
         (policy (gethash "externalTrafficPolicy" spec)))
    (cond ((service-externally-accessible-p spec)
           (setf (gethash "externalTrafficPolicy" spec) (or policy "Cluster"))
           (unless (member (gethash "externalTrafficPolicy" spec) '("Cluster" "Local") :test #'equal)
             (invalid-pod "spec.externalTrafficPolicy: Unsupported value: ~S: supported values: \"Cluster\", \"Local\""
                          policy)))
          ((null policy))
          ((and old-spec (service-externally-accessible-p old-spec)
                (equal policy (gethash "externalTrafficPolicy" old-spec)))
           (remhash "externalTrafficPolicy" spec))
          (t (invalid-pod "spec.externalTrafficPolicy: Invalid value: ~S: may only be set for externally-accessible services"
                          policy))))
  (let ((distribution (gethash "trafficDistribution" spec)))
    (when (and distribution
               (not (member distribution '("PreferClose" "PreferSameZone" "PreferSameNode") :test #'equal)))
      (invalid-pod "spec.trafficDistribution: Unsupported value: ~S: supported values: \"PreferClose\", \"PreferSameNode\", \"PreferSameZone\""
                   distribution))))

(defun assign-service-health-check-node-port (spec namespace name existing store)
  "Allocate, keep or release a LoadBalancer Service's healthCheckNodePort from the node port range.
It is needed only by an externalTrafficPolicy Local LoadBalancer, and immutable while it is."
  (let* ((requested (let ((value (gethash "healthCheckNodePort" spec))) (if (member value '(nil null 0)) nil value)))
         (old-spec (and existing (gethash "spec" existing)))
         (old (and old-spec (service-needs-health-check-p old-spec) (gethash "healthCheckNodePort" old-spec))))
    (cond ((not (service-needs-health-check-p spec))
           (when (and requested (not (eql requested old)))
             (invalid-pod "spec.healthCheckNodePort: Invalid value: ~A: may only be set when `type` is 'LoadBalancer' and `externalTrafficPolicy` is 'Local'"
                          requested))
           (remhash "healthCheckNodePort" spec))
          (t
           (when (and old requested (/= old requested))
             (invalid-pod "spec.healthCheckNodePort: Forbidden: field is immutable"))
           (unless (or (null requested) (typep requested '(integer 1 65535)))
             (invalid-pod "spec.healthCheckNodePort: Invalid value: ~S: must be between 1 and 65535, inclusive" requested))
           (unless store (invalid-pod "Service allocation requires the control-plane store"))
           (let ((used (service-node-ports-in-use-unlocked store namespace name)))
             (loop for port across (gethash "ports" spec #())
                   when (integerp (gethash "nodePort" port)) do (setf (gethash (gethash "nodePort" port) used) t))
             (let ((port (or requested old)))
               (cond ((and old (eql port old)))
                     (port
                      (unless (typep port `(integer ,+node-port-minimum+ ,+node-port-maximum+))
                        (invalid-pod "spec.healthCheckNodePort: Invalid value: ~A: provided port is not in the valid range. The range of valid ports is ~D-~D"
                                     port +node-port-minimum+ +node-port-maximum+))
                      (when (gethash port used)
                        (invalid-pod "spec.healthCheckNodePort: Invalid value: ~A: provided port is already allocated" port)))
                     (t (setf port (loop for candidate from +node-port-minimum+ to +node-port-maximum+
                                         unless (gethash candidate used) return candidate
                                         finally (core-resource-error 503 "ServiceUnavailable" "NodePort range is exhausted")))))
               (setf (gethash "healthCheckNodePort" spec) port)))))
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
                                     "publishNotReadyAddresses" "externalName" "externalIPs" "loadBalancerIP"
                                     "loadBalancerSourceRanges" "healthCheckNodePort" "trafficDistribution") "Service.spec")
    (unless (member (gethash "type" spec "ClusterIP") '("ClusterIP" "NodePort" "LoadBalancer" "ExternalName") :test #'equal)
      (invalid-pod "Service type must be ClusterIP, NodePort, LoadBalancer or ExternalName"))
    (normalize-service-affinity spec (and store (gethash (core-resource-key "services" namespace (gethash "name" metadata))
                                                         (pod-store-resources store))))
    ;; DenyServiceExternalIPs is off by default upstream, so external IPs are admitted.
    (validate-service-addresses spec (and store (gethash (core-resource-key "services" namespace (gethash "name" metadata))
                                                         (pod-store-resources store))))
    ;; gr8s allocates single-stack IPv4 (normalized below). Accept a Service that
    ;; is satisfiable that way -- SingleStack, or PreferDualStack (best-effort, as
    ;; on any single-stack cluster; controller-generated Services such as ate's
    ;; api set it) as long as IPv4 is among its families -- and refuse only a hard
    ;; dual-stack or IPv6-only request gr8s cannot honor.
    (unless (or (service-external-name-p object)
                (let ((policy (gethash "ipFamilyPolicy" spec "SingleStack"))
                      (families (gethash "ipFamilies" spec #("IPv4"))))
                  (and (member policy '("SingleStack" "PreferDualStack") :test #'equal)
                       (or (zerop (length families)) (find "IPv4" families :test #'equal)))))
      (invalid-pod "Services support only single-stack IPv4 (SingleStack or PreferDualStack including IPv4)"))
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
      (normalize-service-traffic-policies spec (and existing (not (service-external-name-p existing)) existing))
      (let* ((specified (or (let ((given (gethash "clusterIP" spec))) (and (not (equal given "")) given))
                            ;; An update that omits the address keeps the allocated one.
                            (and existing (gethash "clusterIP" (gethash "spec" existing)))))
             (address (if (or (null specified) (equal specified ""))
                          (if store (allocate-service-ip-unlocked store)
                              (invalid-pod "Service allocation requires the control-plane store")) specified)))
        (unless (or (equal address "None")
                    (and existing (equal address (gethash "clusterIP" (gethash "spec" existing))))
                    (and store (service-ip-range store address))
                    (and (null store) (service-ip-index address)))
          (invalid-pod "spec.clusterIPs: Invalid value: [~S]: failed to allocate IP ~A: the provided IP (~A) is not in the valid range. The range of valid IPs is ~{~A~^, ~}"
                       address address address
                       (if store
                           (mapcar (lambda (range) (destructuring-bind (name network prefix) range
                                                     (declare (ignore name))
                                                     (format nil "~D.~D.~D.~D/~D" (ldb (byte 8 24) network) (ldb (byte 8 16) network)
                                                             (ldb (byte 8 8) network) (ldb (byte 8 0) network) prefix)))
                                   (service-cidr-prefixes store))
                           (list +default-service-cidr+))))
        (when (and (equal address "None") (not (equal type "ClusterIP")))
          (invalid-pod "clusterIP may not be None for a ~A Service" type))
        (when (and (equal address "10.96.0.1")
                   (not (and (equal namespace "default") (equal (gethash "name" metadata) "kubernetes"))))
          (invalid-pod "the API service address is reserved"))
        (when (and store (not (equal address "None")))
          (let ((holder (service-ip-holder store address namespace (gethash "name" metadata))))
            (when holder
              (core-resource-error 422 "Invalid" "spec.clusterIPs: Invalid value: [~S]: failed to allocate IP ~A: provided IP is already allocated (by ~A)"
                                   address address holder))))
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
            (gethash "ipFamilies" spec) #("IPv4") (gethash "ipFamilyPolicy" spec) "SingleStack")
      (assign-service-node-ports spec namespace (gethash "name" metadata)
                                 (and existing (not (service-external-name-p existing)) existing) store)
      (assign-service-health-check-node-port spec namespace (gethash "name" metadata)
                                             (and existing (not (service-external-name-p existing)) existing) store)
      (networking-keep-status object existing (core-object "loadBalancer" (core-object))))
    object))

(defun service-port-target (pod port)
  "Resolve an integer or named Service target against the Pod's real port declarations: its
containers' and, as upstream's FindPort does, its restartable (sidecar) init containers'."
  (let ((target (gethash "targetPort" port (gethash "port" port)))
        (spec (gethash "spec" (pod-to-object pod))))
    (if (integerp target) target
        (loop for container across (concatenate 'vector (gethash "containers" spec #())
                                                (remove-if-not (lambda (init) (equal "Always" (gethash "restartPolicy" init)))
                                                               (gethash "initContainers" spec #())))
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
