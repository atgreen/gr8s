;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Allocate durable single- and dual-stack ClusterIP and node port Services and resolve
;;;; their ports to running, selector-matched Pod endpoints. ClusterIPs come from
;;;; every ServiceCIDR, and each one is claimed by an IPAddress object, as
;;;; upstream's allocator does. Virtual addresses
;;;; live only on the cluster-owned service interface; the API listener owns the
;;;; reserved Kubernetes Service address and credentials remain separate.

(in-package #:gr8s.controllers)

(defun json-array (value)
  "A JSON array as a vector; absent or JSON-null (which jzon parses as the symbol
NULL, defeating a GETHASH default) both read as empty.  A foreign cluster leaves
array fields explicitly null where gr8s's own serialization omits them."
  (if (vectorp value) value #()))

(defparameter +ip-address-manager+ "ipallocator.k8s.io"
  "The manager label upstream's ClusterIP allocator puts on the IPAddress objects it owns.")

(defun ipv6-integer (address)
  "Return canonical IPv6 ADDRESS as an unsigned 128-bit integer."
  (loop with value = 0
        for byte across (0conf:parse-ipv6 address)
        do (setf value (logior (ash value 8) byte))
        finally (return value)))

(defun format-ipv6-integer (value)
  "Format unsigned 128-bit VALUE in canonical RFC 5952 form."
  (let* ((groups (loop for shift from 112 downto 0 by 16 collect (ldb (byte 16 shift) value)))
         (best-start nil) (best-length 0))
    (loop with start = nil
          for group in groups
          for index from 0
          do (if (zerop group)
                 (unless start (setf start index))
                 (when start
                   (when (> (- index start) best-length)
                     (setf best-start start best-length (- index start)))
                   (setf start nil)))
          finally (when (and start (> (- 8 start) best-length))
                    (setf best-start start best-length (- 8 start))))
    (when (< best-length 2) (setf best-start nil best-length 0))
    (with-output-to-string (stream)
      (loop for group in groups
            for index from 0
            do (cond ((and best-start (= index best-start))
                      (write-string "::" stream))
                     ((and best-start (< best-start index (+ best-start best-length))))
                     (t
                      (when (and (plusp index)
                                 (not (and best-start (= index (+ best-start best-length)))))
                        (write-char #\: stream))
                      (write-string (string-downcase (format nil "~x" group)) stream)))))))

(defun service-address-family (address)
  "Return the Kubernetes family name for ADDRESS, or NIL when it is not a valid IP."
  (when (networking-canonical-ip-p address)
    (if (find #\: address) "IPv6" "IPv4")))

(defun parse-service-cidr (cidr)
  "Return CIDR's family, integer network, and prefix length."
  (let* ((slash (position #\/ cidr)) (address (subseq cidr 0 slash))
         (family (if (find #\: address) "IPv6" "IPv4")))
    (values family
            (if (equal family "IPv6") (ipv6-integer address) (parse-ipv4-integer address))
            (parse-integer cidr :start (1+ slash)))))

(defun format-service-address (family value)
  "Format integer VALUE as a canonical address in FAMILY."
  (if (equal family "IPv6") (format-ipv6-integer value) (format-ipv4-integer value)))

(defun service-cidr-prefixes (store)
  "Return the ranges ClusterIPs come from, as (name family network prefix-length) lists: those of
STORE's ServiceCIDRs not being deleted, the default first, then by name. Without any
ServiceCIDR, as before the default one is published, the native default range."
  (let ((result nil))
    (loop for object being the hash-values of (pod-store-resources store)
          for metadata = (gethash "metadata" object)
          when (and (equal "ServiceCIDR" (gethash "kind" object)) (not (gethash "deletionTimestamp" metadata)))
            do (loop for cidr across (json-array (gethash "cidrs" (gethash "spec" object) #()))
                     when (position #\/ cidr)
                       do (multiple-value-bind (family network prefix) (parse-service-cidr cidr)
                            (push (list (gethash "name" metadata) family network prefix) result))))
    (or (sort result (lambda (left right)
                       (cond ((equal (first left) +default-service-cidr-name+) (not (equal (first right) +default-service-cidr-name+)))
                             ((equal (first right) +default-service-cidr-name+) nil)
                             (t (string< (first left) (first right))))))
        (multiple-value-bind (family network prefix) (parse-service-cidr +default-service-cidr+)
          (list (list +default-service-cidr-name+ family network prefix))))))

(defun service-cidr-index (value network prefix bits)
  "Return VALUE's offset in NETWORK/PREFIX when it may be a ClusterIP: inside the range and,
as upstream's allocator reserves them, neither its network nor its broadcast address."
  (let ((size (ash 1 (- bits prefix))) (offset (- value network)))
    (when (and (<= 0 offset) (< offset size)
               (or (<= size 2) (< 0 offset (1- size))))
      offset)))

(defun service-ip-range (store address)
  "Return the name of the ServiceCIDR whose range holds ADDRESS, or NIL."
  (let* ((family (service-address-family address))
         (value (and family (if (equal family "IPv6") (ipv6-integer address) (parse-ipv4-integer address)))))
    (when family
      (loop for (name range-family network prefix) in (service-cidr-prefixes store)
            when (and (equal family range-family)
                      (service-cidr-index value network prefix (if (equal family "IPv6") 128 32)))
              return name))))

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
           (not (and service
                     (find (gethash "name" (gethash "metadata" object))
                           (gethash "clusterIPs" (gethash "spec" service) #()) :test #'equal)))))))

(defun service-ip-holder (store address namespace name)
  "Describe what, other than Service NAMESPACE/NAME, holds ADDRESS: another Service, or an
IPAddress object that isn't a stale one of the allocator's. NIL when it is free."
  (or (loop for object being the hash-values of (pod-store-resources store)
            for metadata = (gethash "metadata" object)
            thereis (and (equal "Service" (gethash "kind" object))
                         (find address (gethash "clusterIPs" (gethash "spec" object) #()) :test #'equal)
                         (not (and (equal namespace (gethash "namespace" metadata))
                                   (equal name (gethash "name" metadata))))
                         (format nil "Service ~A/~A" (gethash "namespace" metadata) (gethash "name" metadata))))
      (let ((claim (gethash (core-resource-key "ipaddresses" nil address) (pod-store-resources store))))
        (when (and claim (not (ip-address-stale-p store claim))
                   (not (equal (ip-address-parent-service claim) (list namespace name))))
          (format nil "IPAddress ~A" address)))))

(defun allocate-service-ip-unlocked (store family)
  "Choose a free service IP from STORE's ServiceCIDRs while the caller holds the durable store
transaction lock: the default range first, from offset 10 as before, then the others in name order.
An address is taken by a Service or by an IPAddress object that isn't a stale one of the allocator's."
  (let ((used (make-hash-table :test #'equal)))
    (loop for object being the hash-values of (pod-store-resources store)
          do (cond ((equal "Service" (gethash "kind" object))
                    (loop for address across (json-array (gethash "clusterIPs" (gethash "spec" object) #()))
                          do (setf (gethash address used) t)))
                   ((and (equal "IPAddress" (gethash "kind" object)) (not (ip-address-stale-p store object)))
                    (setf (gethash (gethash "name" (gethash "metadata" object)) used) t))))
    (loop for (name range-family network prefix) in (service-cidr-prefixes store)
          for bits = (if (equal range-family "IPv6") 128 32)
          for size = (ash 1 (- bits prefix))
          when (equal family range-family)
          do (loop for offset from (if (equal name +default-service-cidr-name+) (min 10 (max 1 (- size 2))) 1)
                   below (if (<= size 2) size (1- size))
                   for value = (+ network offset)
                   for address = (format-service-address family value)
                   unless (gethash address used) do (return-from allocate-service-ip-unlocked address)))
    (core-resource-error 503 "ServiceUnavailable" "~A Service address pool is exhausted" family)))

(defun service-ip-address-object (address namespace name)
  "The IPAddress object upstream's allocator writes for Service NAMESPACE/NAME's ADDRESS."
  (core-object "apiVersion" "networking.k8s.io/v1" "kind" "IPAddress"
               "metadata" (core-object "name" address
                                       "labels" (core-object "ipaddress.kubernetes.io/ip-family" (service-address-family address)
                                                             "ipaddress.kubernetes.io/managed-by" +ip-address-manager+))
               "spec" (core-object "parentRef" (core-object "group" "" "resource" "services"
                                                            "namespace" namespace "name" name))))

(defun prepare-service-ip-address-writes (resources service existing revision)
  "Add to RESOURCES, the index a Service write is about to commit, the IPAddress object for
SERVICE's ClusterIP, and drop the one for the address EXISTING held if SERVICE no longer has it.
Returns the revision the commit then needs."
  (let* ((metadata (gethash "metadata" service))
         (namespace (gethash "namespace" metadata)) (name (gethash "name" metadata))
         (addresses (if (service-external-name-p service) #() (gethash "clusterIPs" (gethash "spec" service) #())))
         (old (if (or (null existing) (service-external-name-p existing)) #()
                  (gethash "clusterIPs" (gethash "spec" existing) #()))))
    (loop for address across old
          unless (find address addresses :test #'equal)
            do (let* ((key (core-resource-key "ipaddresses" nil address)) (claim (gethash key resources)))
                 (when (and claim (equal (ip-address-parent-service claim) (list namespace name)))
                   (remhash key resources)
                   (incf revision))))
    (loop for address across addresses
          unless (equal address "None")
            do (let* ((key (core-resource-key "ipaddresses" nil address)) (claim (gethash key resources)))
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
                            when (and (equal "Service" (gethash "kind" object))
                                      (not (service-external-name-p object))
                                      (loop for address across (json-array (gethash "clusterIPs" (gethash "spec" object) #()))
                                            thereis (and (not (equal address "None"))
                                                         (or (member address stale :test #'equal)
                                                             (null (gethash (core-resource-key "ipaddresses" nil address) index))))))
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
    (loop for port across (json-array (gethash "ports" spec #())) do (remhash "nodePort" port))
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
            do (loop for port across (json-array (gethash "ports" (gethash "spec" object) #()))
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
             (loop for port across (json-array (gethash "ports" spec #()))
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

(defun service-available-families (store)
  "Return configured Service address families in allocator preference order."
  (remove-duplicates (mapcar #'second (service-cidr-prefixes store)) :test #'equal))

(defun service-cidr-description (range)
  "Render one SERVICE-CIDR-PREFIXES RANGE for an API validation message."
  (destructuring-bind (name family network prefix) range
    (declare (ignore name))
    (format nil "~A/~D" (format-service-address family network) prefix)))

(defun normalize-service-cluster-addresses (spec existing store namespace name type)
  "Allocate and validate SPEC's ordered clusterIPs/ipFamilies tuple."
  (let* ((old-spec (and existing (gethash "spec" existing)))
         (old-external-name-p (and old-spec (equal "ExternalName" (gethash "type" old-spec))))
         (policy (gethash "ipFamilyPolicy" spec
                          (if old-spec (gethash "ipFamilyPolicy" old-spec "SingleStack") "SingleStack")))
         (requested-families (optional-vector spec "ipFamilies" "Service.spec"))
         (specified-many (optional-vector spec "clusterIPs" "Service.spec"))
         (legacy (gethash "clusterIP" spec))
         (old-addresses (and old-spec (gethash "clusterIPs" old-spec #())))
         (old-families (and old-spec (gethash "ipFamilies" old-spec #())))
         (available (if store (service-available-families store) '("IPv4")))
         (addresses (cond ((plusp (length specified-many)) specified-many)
                          ((and (stringp legacy) (plusp (length legacy))) (vector legacy))
                          ((and old-addresses (plusp (length old-addresses))) old-addresses)
                          (t #())))
         (headless (and (= 1 (length addresses)) (equal "None" (aref addresses 0))))
         (families
           (cond ((plusp (length requested-families)) requested-families)
                 ((plusp (length addresses))
                  (if headless
                      (coerce (if (member policy '("PreferDualStack" "RequireDualStack") :test #'equal)
                                  available (list (first available))) 'vector)
                      (map 'vector #'service-address-family addresses)))
                 ((member policy '("PreferDualStack" "RequireDualStack") :test #'equal)
                  (coerce available 'vector))
                 (t (vector (first available))))))
    (when (and (stringp legacy) (plusp (length legacy)) (plusp (length specified-many))
               (not (equal legacy (aref specified-many 0))))
      (invalid-pod "clusterIP must match clusterIPs[0]"))
    (when (equal policy "PreferDualStack")
      (setf families (remove-if-not (lambda (family) (member family available :test #'equal)) families)))
    ;; Setting SingleStack on an unchanged dual-stack object is upstream's
    ;; explicit request to release its secondary family and address.
    (when (and old-spec (equal policy "SingleStack")
               (= 2 (length old-addresses)) (equalp addresses old-addresses)
               (= 2 (length old-families)) (equalp families old-families))
      (setf addresses (subseq addresses 0 1)
            families (subseq families 0 1)))
    (unless (member policy '("SingleStack" "PreferDualStack" "RequireDualStack") :test #'equal)
      (invalid-pod "ipFamilyPolicy must be SingleStack, PreferDualStack or RequireDualStack"))
    (unless (and (<= 1 (length families) 2)
                 (every (lambda (family) (member family '("IPv4" "IPv6") :test #'equal)) families)
                 (= (length families) (length (remove-duplicates (coerce families 'list) :test #'equal))))
      (invalid-pod "ipFamilies must contain one or two distinct supported families"))
    (unless (every (lambda (family) (member family available :test #'equal)) families)
      (invalid-pod "requested ipFamilies are not configured on this cluster"))
    (when (and (equal policy "SingleStack") (/= 1 (length families)))
      (invalid-pod "SingleStack Services require exactly one IP family"))
    (when (and (equal policy "RequireDualStack") (/= 2 (length families)))
      (invalid-pod "RequireDualStack Services require two configured IP families"))
    ;; On a single-to-dual update the client names the new family; the
    ;; allocator supplies its address while retaining the immutable primary.
    (when (and store old-spec (= 1 (length old-addresses))
               (= 1 (length addresses)) (= 2 (length families)))
      (setf addresses
            (concatenate 'vector addresses
                         (vector (allocate-service-ip-unlocked store (aref families 1))))))
    (when (and (plusp (length addresses)) (not headless) (/= (length addresses) (length families)))
      (invalid-pod "clusterIPs and ipFamilies must have the same length"))
    (when (zerop (length addresses))
      (unless store (invalid-pod "Service allocation requires the control-plane store"))
      (setf addresses (map 'vector (lambda (family) (allocate-service-ip-unlocked store family)) families)))
    (unless headless
      (loop for address across addresses
            for family across families
            do (unless (equal family (service-address-family address))
                 (invalid-pod "clusterIP ~A does not match ipFamily ~A" address family))
               (unless (or (and old-addresses (find address old-addresses :test #'equal))
                           (and store (service-ip-range store address))
                           (and (null store) (service-ip-index address)))
                 (invalid-pod "spec.clusterIPs: Invalid value: [~S]: the provided IP is not in the valid ranges ~{~A~^, ~}"
                              address (if store (mapcar #'service-cidr-description (service-cidr-prefixes store))
                                          (list +default-service-cidr+))))
               (when (and store (not (and old-addresses (find address old-addresses :test #'equal))))
                 (let ((holder (service-ip-holder store address namespace name)))
                   (when holder
                     (core-resource-error 422 "Invalid" "spec.clusterIPs: Invalid value: [~S]: provided IP is already allocated (by ~A)"
                                          address holder))))))
    ;; ExternalName Services own no cluster address. Leaving that type is an
    ;; allocation. Otherwise the primary is immutable, while an explicit
    ;; policy transition may add or release exactly one secondary address.
    (when (and old-addresses (plusp (length old-addresses)) (not old-external-name-p))
      (unless (and (equal (aref addresses 0) (aref old-addresses 0))
                   (or (equalp addresses old-addresses)
                       (and (= 1 (length old-addresses)) (= 2 (length addresses)))
                       (and (= 2 (length old-addresses)) (= 1 (length addresses))
                            (equal policy "SingleStack"))))
        (invalid-pod "clusterIPs may not change once set")))
    (when (and headless (not (equal type "ClusterIP")))
      (invalid-pod "clusterIP may not be None for a ~A Service" type))
    (setf (gethash "clusterIP" spec) (aref addresses 0)
          (gethash "clusterIPs" spec) addresses
          (gethash "ipFamilies" spec) families
          ;; PreferDualStack records the requested behavior even when only one
          ;; configured family is available to satisfy it.
          (gethash "ipFamilyPolicy" spec) policy)
    addresses))

(defun normalize-service-resource (input namespace name store)
  "Validate and default single-stack ClusterIP, NodePort, LoadBalancer and ExternalName Services."
  (let* ((object (copy-core-object (require-object input "Service")))
         (metadata (require-object (gethash "metadata" object) "metadata"))
         (spec (require-object (gethash "spec" object) "Service.spec")))
    (unless (and (equal "v1" (gethash "apiVersion" object "v1"))
                 (equal "Service" (gethash "kind" object "Service")))
      (core-resource-error 400 "BadRequest" "Expected v1 Service"))
    (reject-unsupported-fields object '("apiVersion" "kind" "metadata" "spec" "status") "Service")
    (validate-core-metadata metadata namespace name :allow-finalizers t)
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
      (let ((addresses (normalize-service-cluster-addresses
                        spec existing store namespace (gethash "name" metadata) type)))
        (when (and (find "10.96.0.1" addresses :test #'equal)
                   (not (and (equal namespace "default") (equal (gethash "name" metadata) "kubernetes"))))
          (invalid-pod "the API service address is reserved"))
        (when (equal "10.96.0.1" (aref addresses 0))
          (let ((ports (gethash "ports" spec)))
            (unless (and (= 1 (length ports)) (= 443 (gethash "port" (aref ports 0))))
              (invalid-pod "the API Service must retain its HTTPS port")))))
      (setf (gethash "type" spec) type)
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
              thereis (loop for declared across (json-array (gethash "ports" container #()))
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

(defun api-endpoint-order (endpoint)
  (format nil "~A:~5,'0D" (first endpoint) (second endpoint)))

(defun pod-reachable-api-endpoints (endpoints)
  "ENDPOINTS, (address port) pairs, each once and in a fixed order, without any a
Pod could not reach: a slice of IPv4 addresses holds no other kind, and a
loopback address is the Pod's own."
  (sort (remove-duplicates
         (remove-if-not (lambda (endpoint)
                          (and (cl-ppcre:scan "^\\d{1,3}(\\.\\d{1,3}){3}$" (first endpoint))
                               (not (uiop:string-prefix-p "127." (first endpoint)))))
                        endpoints)
         :test #'equal)
        #'string< :key #'api-endpoint-order))

(defun native-api-endpoints-by-port (endpoints)
  "ENDPOINTS as an alist of port to addresses, lowest port first."
  (let ((groups nil))
    (dolist (endpoint endpoints)
      (push (first endpoint) (alexandria:assoc-value groups (second endpoint))))
    (sort (mapcar (lambda (group) (cons (car group) (reverse (cdr group)))) groups) #'< :key #'car)))

(defun native-api-slice-name (port first-port)
  "A slice has one list of ports. Members nearly always share one; the slice for
that port is the one a client knows by the Service's name."
  (if (= port first-port) "kubernetes" (format nil "kubernetes-~D" port)))

(defun published-native-api-endpoints (store)
  "The (address port) pairs the kubernetes Service's Endpoints name, and those
its slices name, each ordered as POD-REACHABLE-API-ENDPOINTS orders them."
  (flet ((object (resource name)
           (handler-case (get-core-resource store resource "default" name)
             (kubernetes-error (condition)
               (unless (= 404 (kubernetes-error-status-code condition)) (error condition))
               nil))))
    (let ((endpoints (object "endpoints" "kubernetes")))
      (values
       (sort (loop for subset across (or (and endpoints (gethash "subsets" endpoints)) #())
                   append (loop for address across (gethash "addresses" subset #())
                                collect (list (gethash "ip" address)
                                              (gethash "port" (aref (gethash "ports" subset) 0)))))
             #'string< :key #'api-endpoint-order)
       (sort (loop for slice in (native-api-slices store)
                   append (loop for endpoint across (gethash "endpoints" slice #())
                                collect (list (aref (gethash "addresses" endpoint) 0)
                                              (gethash "port" (aref (gethash "ports" slice) 0)))))
             #'string< :key #'api-endpoint-order)))))

(defun native-api-slices (store)
  "The EndpointSlices this server wrote for the kubernetes Service."
  (remove-if-not (lambda (slice)
                   (let ((labels (gethash "labels" (gethash "metadata" slice))))
                     (and labels
                          (equal "kubernetes" (gethash "kubernetes.io/service-name" labels))
                          (equal "gr8s-apiserver" (gethash "endpointslice.kubernetes.io/managed-by" labels)))))
                 (list-core-resources store "endpointslices" "default")))

(defun publish-native-api-endpoints (store endpoints)
  "Publish ENDPOINTS, (address port) pairs as POD-REACHABLE-API-ENDPOINTS orders them, as the Kubernetes
Service's Endpoints and EndpointSlices, as an API server does."
  (flet ((ensure (resource name object)
           (handler-case (create-core-resource store resource object "default")
             (kubernetes-error (condition)
               (unless (= 409 (kubernetes-error-status-code condition)) (error condition))
               (update-core-resource
                store resource "default" name
                (lambda (existing)
                  (dolist (field (if (equal resource "endpoints")
                                     '("subsets") '("addressType" "endpoints" "ports")))
                    (setf (gethash field existing) (gethash field object)))
                  existing)))))
         (ports (port) (vector (core-object "name" "https" "port" port "protocol" "TCP"))))
    (let* ((groups (native-api-endpoints-by-port endpoints))
           (first-port (car (first groups)))
           (slice-names (mapcar (lambda (group) (native-api-slice-name (car group) first-port)) groups)))
      (ensure "endpoints" "kubernetes"
              (core-object "metadata" (core-object "name" "kubernetes"
                                                   ;; This server writes the slices itself below.
                                                   "labels" (core-object "endpointslice.kubernetes.io/skip-mirror" "true"))
                           "subsets" (map 'vector
                                          (lambda (group)
                                            (core-object "addresses" (map 'vector (lambda (address) (core-object "ip" address))
                                                                          (cdr group))
                                                         "ports" (ports (car group))))
                                          groups)))
      (loop for (port . addresses) in groups
            for name in slice-names
            do (ensure "endpointslices" name
                       (core-object "metadata" (core-object "name" name
                                                            "labels" (core-object "kubernetes.io/service-name" "kubernetes"
                                                                                  "endpointslice.kubernetes.io/managed-by" "gr8s-apiserver"))
                                    "addressType" "IPv4"
                                    "endpoints" (map 'vector
                                                     (lambda (address)
                                                       (core-object "addresses" (vector address)
                                                                    "conditions" (core-object "ready" t "serving" t "terminating" nil)))
                                                     addresses)
                                    "ports" (ports port))))
      (dolist (slice (native-api-slices store))
        (let ((name (gethash "name" (gethash "metadata" slice))))
          (unless (member name slice-names :test #'equal)
            (delete-core-resource store "endpointslices" "default" name)))))))

(defun ensure-native-api-endpoints (store api-address api-port)
  "Publish this server's API listener as the Kubernetes Service's only endpoint."
  (publish-native-api-endpoints store (list (list api-address api-port))))

(defun reconcile-native-api-endpoints (store endpoints)
  "Make the Kubernetes Service lead to ENDPOINTS, the (address port) API listeners
of the members that can answer a client now, and to no other (podster-bn8). It
was written once, by the member that founded the cluster, and went on leading
to that member alone whether or not it was running. A pass that finds nothing a
Pod could reach leaves what is published, and so does a store with no such
Service."
  (let ((wanted (pod-reachable-api-endpoints endpoints)))
    (when (and wanted
               (handler-case (get-core-resource store "services" "default" "kubernetes")
                 (kubernetes-error (condition)
                   (unless (= 404 (kubernetes-error-status-code condition)) (error condition))
                   nil)))
      (multiple-value-bind (endpoints slices) (published-native-api-endpoints store)
        (unless (and (equal wanted endpoints) (equal wanted slices))
          (publish-native-api-endpoints store wanted))))))

(defparameter +native-api-service-labels+ '(("component" . "apiserver") ("provider" . "kubernetes"))
  "The labels kube-apiserver gives the kubernetes Service, which monitoring finds the API
by (kube-prometheus-stack's apiserver ServiceMonitor selects on them).")

(defun ensure-native-api-service (store &optional (api-address "127.0.0.1") (api-port 6443))
  "Publish the real native HTTPS listener as the reserved Kubernetes Service, labelled as
kube-apiserver labels it; a Service made before it carried the labels gains them."
  (prog1
      (handler-case
          (create-core-resource store "services"
           (core-object "metadata" (core-object "name" "kubernetes"
                                                "labels" (let ((labels (core-object)))
                                                           (loop for (key . value) in +native-api-service-labels+
                                                                 do (setf (gethash key labels) value))
                                                           labels))
                        "spec" (core-object "clusterIP" "10.96.0.1"
                                             "ports" (vector (core-object "name" "https" "port" 443 "targetPort" api-port))))
           "default")
        (kubernetes-error (condition)
          (unless (= 409 (kubernetes-error-status-code condition)) (error condition))
          (let ((existing (get-core-resource store "services" "default" "kubernetes")))
            (unless (equal "10.96.0.1" (gethash "clusterIP" (gethash "spec" existing)))
              (error 'runtime-error :message "Kubernetes API Service has an unexpected clusterIP"))
            (update-core-resource
             store "services" "default" "kubernetes"
             (lambda (service)
               (let ((ports (gethash "ports" (gethash "spec" service)))
                     (metadata (gethash "metadata" service)))
                 (setf (gethash "targetPort" (aref ports 0)) api-port)
                 ;; Labels of the Service's own are kept; the standard two are added.
                 (let ((labels (or (gethash "labels" metadata) (setf (gethash "labels" metadata) (core-object)))))
                   (loop for (key . value) in +native-api-service-labels+
                         do (setf (gethash key labels) value))))
               service)))))
    (ensure-native-api-endpoints store api-address api-port)
    (ensure-default-service-cidr store)))
