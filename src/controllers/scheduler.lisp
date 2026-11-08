;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Manage node registration, readiness leases, PodCIDR allocation, underlay
;;;; identity, and deterministic Pod placement.  Scheduling prefers the ready
;;;; node with the fewest nonterminal Pods, preserves explicit assignments, and
;;;; keeps observed workload status separate from desired Pod objects.

(in-package #:gr8s)

(defparameter +default-cluster-pod-cidr+ "10.80.0.0/12")
(defparameter +default-node-pod-prefix+ 20)

(defun node-conflict (control &rest arguments)
  "Signal a Kubernetes Conflict error formatted by CONTROL and ARGUMENTS."
  (error 'kubernetes-error
         :status-code 409
         :reason "Conflict"
         :message (apply #'format nil control arguments)))

(defun same-node-identity-p (left right)
  "Return true when LEFT and RIGHT identify the same persisted node."
  (and (string= (node-record-id left) (node-record-id right))
       (string= (node-record-name left) (node-record-name right))
       (string= (node-record-pod-cidr left) (node-record-pod-cidr right))))

(defun register-node (store node)
  "Register NODE idempotently while rejecting identity and PodCIDR collisions."
  (with-store-lock (store)
    (let ((same-name (gethash (node-record-name node) (pod-store-nodes store))))
      (when same-name
        (if (same-node-identity-p same-name node)
            (return-from register-node same-name)
            (node-conflict "Node name ~A is already claimed"
                           (node-record-name node))))
      (loop for existing being the hash-values of (pod-store-nodes store)
            do (when (string= (node-record-id existing) (node-record-id node))
                 (node-conflict "Node identity ~A is already claimed"
                                (node-record-id node)))
               (when (and (plusp (length (node-record-pod-cidr node)))
                          (string= (node-record-pod-cidr existing) (node-record-pod-cidr node)))
                 (node-conflict "PodCIDR ~A is already claimed"
                                (node-record-pod-cidr node))))
      (setf (node-record-ready-p node) nil
            (node-record-last-heartbeat node) nil
            (node-record-creation-timestamp node) (or (node-record-creation-timestamp node) (current-timestamp))
            (gethash (node-record-name node) (pod-store-nodes store)) node)
      (publish-node-change-unlocked store nil node)
      ;; Desired write (the control-plane-assigned podCIDR): replicate (8ia.4).
      (note-node-desired-change store node)
      node)))

(defun get-node-unlocked (store name)
  "Return NAME's node record without acquiring STORE's lock."
  (gethash name (pod-store-nodes store)))

(defun get-node (store name)
  "Return NAME's node record, or signal a Kubernetes NotFound error."
  (with-store-lock (store)
    (or (get-node-unlocked store name)
        (error 'kubernetes-error
               :status-code 404
               :reason "NotFound"
               :message (format nil "Node ~A was not found" name)))))

(defun list-nodes (store)
  "Return STORE's nodes sorted by name."
  (with-store-lock (store)
    (sort (loop for node being the hash-values of (pod-store-nodes store)
                collect node)
          #'string< :key #'node-record-name)))

(defun mark-node-ready (store name heartbeat &key (lease-duration 15))
  "Mark NAME ready and record its HEARTBEAT lease timestamp."
  (with-store-lock (store)
    (let ((node (or (get-node-unlocked store name)
                    (error 'kubernetes-error
                           :status-code 404
                           :reason "NotFound"
                           :message (format nil "Node ~A was not found" name)))))
      (let ((updated (copy-node-record node))
            ;; Only the first heartbeat of a lease changes anything clients can see.
            (old (unless (node-record-ready-p node) (node-api-object node))))
        (setf (node-record-ready-p updated) t
              (node-record-last-heartbeat updated) heartbeat
              (node-record-lease-deadline updated) (+ heartbeat lease-duration))
        (persist-node store updated)
        (setf (node-record-ready-p node) t
              (node-record-last-heartbeat node) heartbeat
              (node-record-lease-deadline node) (node-record-lease-deadline updated))
        ;; A node an older gr8s registered has no creation time until its agent returns.
        (when (and old (null (node-record-creation-timestamp node)))
          (setf (node-record-creation-timestamp node) (current-timestamp))
          (note-node-desired-change store node))
        (when old
          (publish-node-change-unlocked store old node))
        ;; Every control-plane member runs the expiry monitor, while the live
        ;; agent stream belongs to only one member. Replicate the renewed
        ;; deadline even when the client-visible Ready condition is unchanged.
        (note-node-state-change store node))
      node)))

(defun note-node-runtime-health (store name runtime-down-message)
  "Record whether NAME's container runtime is down, as its agent's heartbeat reported.
NIL or an empty RUNTIME-DOWN-MESSAGE means the runtime is up. A node whose
runtime is down keeps its lease, and so its Pods' phases, but is NotReady and
receives no new Pods, as kubelet reports \"container runtime is down\"."
  (let ((message (and runtime-down-message (plusp (length runtime-down-message))
                      runtime-down-message)))
    (with-store-lock (store)
      (let ((node (get-node-unlocked store name)))
        (when (and node (not (equal message (node-record-runtime-down-message node))))
          (let ((old (node-api-object node)))
            (setf (node-record-runtime-down-message node) message)
            (publish-node-change-unlocked store old node)
            (note-node-state-change store node)))
        node))))

(defun mark-node-not-ready (store name)
  "Mark NAME not ready while preserving its registered identity."
  (with-store-lock (store)
    (let ((node (or (get-node-unlocked store name)
                    (error 'kubernetes-error
                           :status-code 404
                           :reason "NotFound"
                           :message (format nil "Node ~A was not found" name)))))
      (persist-node-unavailable store node)
      node)))

(defun persist-node-unavailable (store node)
  "Checkpoint unavailable state before changing NODE under STORE's lock."
  (let ((updated (copy-node-record node))
        (old (node-api-object node)))
    (setf (node-record-ready-p updated) nil
          (node-record-runtime-down-message updated) nil)
    (persist-node store updated)
    (setf (node-record-ready-p node) nil
          (node-record-runtime-down-message node) nil)
    (publish-node-change-unlocked store old node)
    (note-node-state-change store node)))

(defun expire-node-heartbeats (store oldest-acceptable-heartbeat &key now)
  "Mark stale ready nodes unavailable and return the records that expired."
  (with-store-lock (store)
    (loop for node being the hash-values of (pod-store-nodes store)
          when (and (node-record-ready-p node)
                    (if (and now (node-record-lease-deadline node))
                        (< (node-record-lease-deadline node) now)
                        (or (null (node-record-last-heartbeat node))
                            (< (node-record-last-heartbeat node) oldest-acceptable-heartbeat))))
            collect (progn (persist-node-unavailable store node) node))))

(defun parse-ipv4-integer (address)
  "Parse dotted-decimal ADDRESS into an unsigned 32-bit integer."
  (let ((parts (uiop:split-string address :separator '(#\.))))
    (unless (= 4 (length parts))
      (error "Invalid IPv4 address ~S" address))
    (reduce (lambda (result part)
              (let ((octet (parse-integer part :junk-allowed nil)))
                (unless (<= 0 octet 255)
                  (error "Invalid IPv4 address ~S" address))
                (+ (ash result 8) octet)))
            parts :initial-value 0)))

(defun format-ipv4-integer (address)
  "Render an unsigned 32-bit ADDRESS as dotted-decimal IPv4."
  (format nil "~D.~D.~D.~D"
          (ldb (byte 8 24) address)
          (ldb (byte 8 16) address)
          (ldb (byte 8 8) address)
          (ldb (byte 8 0) address)))

(defun parse-ipv4-cidr (cidr)
  "Return CIDR's IPv4 address integer and prefix length as two values."
  (let ((parts (uiop:split-string cidr :separator '(#\/))))
    (unless (= 2 (length parts))
      (error "Invalid IPv4 CIDR ~S" cidr))
    (let ((prefix (parse-integer (second parts) :junk-allowed nil)))
      (unless (<= 0 prefix 32)
        (error "Invalid IPv4 CIDR prefix ~S" cidr))
      (values (parse-ipv4-integer (first parts)) prefix))))

(defun ipv4-prefixes-overlap-p (left right)
  "Compare IPv4 prefixes, including /32 host routes, for any intersection."
  (multiple-value-bind (a a-prefix) (parse-ipv4-cidr left)
    (multiple-value-bind (b b-prefix) (parse-ipv4-cidr right)
      (let ((shift (- (min a-prefix b-prefix) 32)))
        (= (ash a shift) (ash b shift))))))

(defun canonical-node-underlay-address (address)
  "Validate and canonicalize a non-loopback unicast IPv4 underlay ADDRESS."
  (unless (and (stringp address) (plusp (length address)))
    (error "node underlay address must be a unicast IPv4 address"))
  (let ((integer (parse-ipv4-integer address)))
    (unless (and (<= #x01000000 integer) (< integer #xe0000000)
                 (/= 127 (ldb (byte 8 24) integer)))
      (error "node underlay address must be a non-loopback unicast IPv4 address"))
    (format-ipv4-integer integer)))

(defun update-node-underlay-address (store node-name address)
  "Persist NODE-NAME's unique underlay ADDRESS, returning true when changed."
  (unless (string= address "")
    (setf address (canonical-node-underlay-address address)))
  (with-store-lock (store)
    (let ((node (get-node-unlocked store node-name)))
      (unless node (node-conflict "Node ~A is not registered" node-name))
      (when (string= address (node-record-underlay-address node))
        (return-from update-node-underlay-address nil))
      (unless (string= address "")
        (maphash (lambda (name other)
                   (when (and (not (string= name node-name))
                              (string= address (node-record-underlay-address other)))
                     (node-conflict "Underlay address ~A is already claimed" address)))
                 (pod-store-nodes store)))
      (let ((previous (node-record-underlay-address node))
            (old (node-api-object node)))
        (setf (node-record-underlay-address node) address)
        (handler-case (persist-node store node)
          (error (condition)
            (setf (node-record-underlay-address node) previous)
            (error condition)))
        (publish-node-change-unlocked store old node))))
  t)

(defun update-node-wireguard-public-key (store node-name public-key)
  "Persist NODE-NAME's authenticated WireGuard PUBLIC-KEY, returning true when changed."
  (unless (or (zerop (length public-key)) (= 32 (length public-key)))
    (error "WireGuard public keys must be empty or exactly 32 bytes"))
  (let ((public-key (copy-seq public-key)))
    (with-store-lock (store)
      (let ((node (get-node-unlocked store node-name)))
        (unless node (node-conflict "Node ~A is not registered" node-name))
        (when (equalp public-key (node-record-wireguard-public-key node))
          (return-from update-node-wireguard-public-key nil))
        (let ((updated (copy-node-record node)))
          (setf (node-record-wireguard-public-key updated) public-key)
          (persist-node store updated)
          (setf (node-record-wireguard-public-key node) public-key)
          (note-node-state-change store node)))))
  t)

(defun allocate-node-pod-cidr-unlocked (store cluster-cidr node-prefix)
  "Return the first free NODE-PREFIX block within CLUSTER-CIDR. Caller holds STORE's lock."
  (multiple-value-bind (address cluster-prefix) (parse-ipv4-cidr cluster-cidr)
    (unless (<= cluster-prefix node-prefix 32)
      (error "Node prefix /~D does not fit cluster CIDR ~A"
             node-prefix cluster-cidr))
    (let* ((cluster-mask (if (zerop cluster-prefix)
                             0
                             (logand #xffffffff
                                     (ash #xffffffff (- 32 cluster-prefix)))))
           (base (logand address cluster-mask))
           (block-size (ash 1 (- 32 node-prefix)))
           (block-count (ash 1 (- node-prefix cluster-prefix))))
      (loop for index below block-count
            for candidate = (format nil "~A/~D"
                                    (format-ipv4-integer
                                     (+ base (* index block-size)))
                                    node-prefix)
            unless (loop for node being the hash-values
                           of (pod-store-nodes store)
                         thereis (and (plusp (length (node-record-pod-cidr node)))
                                      (ipv4-prefixes-overlap-p candidate (node-record-pod-cidr node))))
              return candidate
            finally (error "No free /~D PodCIDR remains in ~A"
                           node-prefix cluster-cidr)))))

(defun allocate-node-pod-cidr (store cluster-cidr node-prefix)
  "Return the first free NODE-PREFIX block within CLUSTER-CIDR."
  (with-store-lock (store)
    (allocate-node-pod-cidr-unlocked store cluster-cidr node-prefix)))

(defun install-node-enrollment-command
    (store node-id node-name cluster-cidr node-prefix creation-timestamp)
  "Apply one Raft-ordered node enrollment against STORE's committed node index.
Every replica allocates from the same preceding log state, so concurrent member
enrollments receive distinct PodCIDRs without replacing the complete node index."
  (bt:with-lock-held ((pod-store-lock store))
    (let ((existing (get-node-unlocked store node-name)))
      (when existing (return-from install-node-enrollment-command existing))
      (loop for node being the hash-values of (pod-store-nodes store)
            when (string= node-id (node-record-id node))
              do (node-conflict "Node identity ~A is already claimed" node-id))
      (let ((node
              (make-node-record
               :id node-id :name node-name
               :pod-cidr (allocate-node-pod-cidr-unlocked store cluster-cidr node-prefix)
               :creation-timestamp creation-timestamp)))
        (setf (gethash node-name (pod-store-nodes store)) node)
        (publish-node-change-unlocked store nil node)
        node))))

(defun terminal-pod-phase-p (phase)
  "Return true when PHASE is a terminal Kubernetes Pod phase."
  (member phase '("Succeeded" "Failed") :test #'string=))

(defun assigned-nonterminal-pod-count (store node-name)
  "Count nonterminal Pods currently assigned to NODE-NAME."
  (loop for pod being the hash-values of (pod-store-pods store)
        count (and (equal node-name (pod-node-name pod))
                   (not (terminal-pod-phase-p
                         (gethash (pod-uid pod)
                                  (pod-store-pod-observed-phases store)))))))

(defun pod-dra-claim-name-unlocked (store pod reference)
  "Resolve REFERENCE to its direct or controller-generated ResourceClaim name."
  (or (gethash "resourceClaimName" reference)
      (let* ((reference-name (gethash "name" reference))
             (client-status (gethash (pod-uid pod)
                                     (pod-store-pod-client-statuses store)
                                     (core-object)))
             (status (find reference-name
                           (gethash "resourceClaimStatuses" client-status #())
                           :test #'equal
                           :key (lambda (entry) (gethash "name" entry)))))
        (and status (gethash "resourceClaimName" status)))))

(defun pod-dra-claims-unlocked (store pod)
  "Return POD's resolved ResourceClaims and true, or NIL/NIL until every claim exists and is reservable."
  (let ((claims nil))
    (loop for reference across (gethash "resourceClaims" (gethash "spec" (pod-to-object pod)) #())
          for name = (pod-dra-claim-name-unlocked store pod reference)
          do (unless name (return-from pod-dra-claims-unlocked (values nil nil)))
             (let ((claim (gethash (core-resource-key "resourceclaims" (pod-namespace pod) name)
                                   (pod-store-resources store))))
               (unless claim
                 (return-from pod-dra-claims-unlocked (values nil nil)))
               (let ((reserved (gethash "reservedFor" (gethash "status" claim (core-object)) #())))
                 (when (and (plusp (length reserved))
                            (not (find (pod-uid pod) reserved :test #'equal
                                      :key (lambda (consumer) (gethash "uid" consumer)))))
                   (return-from pod-dra-claims-unlocked (values nil nil))))
               (push claim claims)))
    (values (nreverse claims) t)))

(defun dra-device-key (driver pool device)
  "Return the identity used to prevent one DRA device from being allocated twice."
  (list driver pool device))

(defun dra-allocated-device-keys-unlocked (store)
  "Return an EQUAL set of devices present in committed ResourceClaim allocations."
  (let ((used (make-hash-table :test #'equal)))
    (loop for object being the hash-values of (pod-store-resources store)
          when (equal "ResourceClaim" (gethash "kind" object))
            do (loop for result across (gethash "results"
                                                  (gethash "devices"
                                                           (gethash "allocation"
                                                                    (gethash "status" object (core-object))
                                                                    (core-object))
                                                           (core-object))
                                                  #())
                     do (setf (gethash (dra-device-key (gethash "driver" result)
                                                       (gethash "pool" result)
                                                       (gethash "device" result))
                                       used)
                              t)))
    used))

(defun dra-slice-available-on-node-p (slice node)
  "Return whether every device in SLICE is available on NODE."
  (let ((spec (gethash "spec" slice)))
    (cond ((gethash "allNodes" spec) t)
          ((gethash "nodeName" spec)
           (equal (gethash "nodeName" spec) (node-record-name node)))
          ((gethash "nodeSelector" spec)
           (some (lambda (term) (node-selector-term-matches-p term node))
                 (gethash "nodeSelectorTerms" (gethash "nodeSelector" spec) #())))
          ((gethash "perDeviceNodeSelection" spec) t)
          (t nil))))

(defun dra-device-available-on-node-p (slice device node)
  "Return whether DEVICE from SLICE is accessible on NODE."
  (if (not (gethash "perDeviceNodeSelection" (gethash "spec" slice)))
      t
      (cond ((gethash "allNodes" device) t)
            ((gethash "nodeName" device)
             (equal (gethash "nodeName" device) (node-record-name node)))
            ((gethash "nodeSelector" device)
             (some (lambda (term) (node-selector-term-matches-p term node))
                   (gethash "nodeSelectorTerms" (gethash "nodeSelector" device) #())))
            (t nil))))

(defun dra-current-complete-slices-unlocked (store node)
  "Return current-generation ResourceSlices whose pools are complete on NODE."
  (let ((pools (make-hash-table :test #'equal)) (complete nil))
    (loop for slice being the hash-values of (pod-store-resources store)
          when (equal "ResourceSlice" (gethash "kind" slice))
            do (let* ((spec (gethash "spec" slice))
                      (pool (gethash "pool" spec))
                      (key (list (gethash "driver" spec) (gethash "name" pool))))
                 (push slice (gethash key pools))))
    (maphash
     (lambda (key slices)
       (declare (ignore key))
       (let* ((generation (loop for slice in slices
                                maximize (gethash "generation" (gethash "pool" (gethash "spec" slice)))))
              (current (remove-if-not
                        (lambda (slice)
                          (= generation (gethash "generation" (gethash "pool" (gethash "spec" slice)))))
                        slices))
              (expected (gethash "resourceSliceCount"
                                 (gethash "pool" (gethash "spec" (first current))))))
         (when (= expected (length current))
           (dolist (slice current)
             (when (dra-slice-available-on-node-p slice node) (push slice complete))))))
     pools)
    complete))

(defun dra-device-attribute-value (attribute)
  "Return ATTRIBUTE's single Kubernetes DRA scalar value."
  (loop for field in '("int" "bool" "string" "version")
        do (multiple-value-bind (value present) (gethash field attribute)
             (when present (return value)))))

(defun dra-device-cel-object (driver device)
  "Build the CEL device binding for DRIVER's ResourceSlice DEVICE."
  (let ((attributes (core-object)))
    (maphash
     (lambda (qualified-name attribute)
       (let* ((slash (position #\/ qualified-name :from-end t))
              (domain (if slash (subseq qualified-name 0 slash) driver))
              (name (if slash (subseq qualified-name (1+ slash)) qualified-name))
              (domain-attributes
                (or (gethash domain attributes)
                    (setf (gethash domain attributes) (core-object)))))
         (setf (gethash name domain-attributes) (dra-device-attribute-value attribute))))
     (gethash "attributes" device (core-object)))
    (core-object "driver" driver "attributes" attributes
                 "capacity" (gethash "capacity" device (core-object))
                 "allowMultipleAllocations" (gethash "allowMultipleAllocations" device nil))))

(defun dra-device-matches-selectors-p (driver device selectors)
  "Return whether DRIVER's DEVICE satisfies every CEL selector."
  (let ((binding (dra-device-cel-object driver device)))
    (handler-case
        (loop for selector across selectors
              always (let ((gr8s.resources::*cel-declared-variables* '("device")))
                       (declare (special gr8s.resources::*cel-declared-variables*))
                       (gr8s.resources::evaluate-cel-condition
                        (gr8s.resources::compile-cel-condition
                         (gethash "expression" (gethash "cel" selector)))
                        (list (cons "device" binding)))))
      (error () nil))))

(defun dra-map-candidate-combinations (function candidates count)
  "Call FUNCTION for COUNT-sized combinations until it returns true."
  (labels ((visit (remaining remaining-count needed selected)
             (cond ((zerop needed) (funcall function (nreverse selected)))
                   ((< remaining-count needed) nil)
                   (t (or (visit (rest remaining) (1- remaining-count) (1- needed)
                                 (cons (first remaining) selected))
                          (visit (rest remaining) (1- remaining-count) needed selected))))))
    (visit candidates (length candidates) count nil)))

(defun dra-candidates-to-results (candidates result-name)
  "Convert allocation CANDIDATES into status results for RESULT-NAME."
  (map 'vector
       (lambda (candidate)
         (core-object "request" result-name
                      "driver" (first candidate) "pool" (second candidate)
                      "device" (third candidate)))
       candidates))

(defun dra-map-exact-request-options-unlocked (function store exact result-name node used)
  "Call FUNCTION for exact-request allocations until it returns true."
  (let* ((class-name (gethash "deviceClassName" exact))
         (class (gethash (core-resource-key "deviceclasses" nil class-name)
                         (pod-store-resources store)))
         (mode (gethash "allocationMode" exact "ExactCount"))
         (count (gethash "count" exact 1))
         (selectors (and class
                         (concatenate 'vector
                                      (gethash "selectors" (gethash "spec" class) #())
                                      (gethash "selectors" exact #()))))
         (matching nil))
    (unless (and class selectors (member mode '("ExactCount" "All") :test #'equal))
      (return-from dra-map-exact-request-options-unlocked nil))
    (dolist (slice (dra-current-complete-slices-unlocked store node))
      (let* ((spec (gethash "spec" slice))
             (driver (gethash "driver" spec))
             (pool (gethash "name" (gethash "pool" spec))))
        (loop for device across (gethash "devices" spec #())
              for name = (gethash "name" device)
              when (and (dra-device-available-on-node-p slice device node)
                        (dra-device-matches-selectors-p driver device selectors))
                do (push (list driver pool name
                               (gethash (dra-device-key driver pool name) used))
                         matching))))
    (setf matching (sort matching #'string<
                         :key (lambda (candidate)
                                (format nil "~A/~A/~A" (first candidate)
                                        (second candidate) (third candidate)))))
    (if (equal mode "All")
        (let ((pools (make-hash-table :test #'equal)) (options nil))
          (dolist (candidate matching)
            (push candidate (gethash (subseq candidate 0 2) pools)))
          (maphash
           (lambda (key candidates)
             (declare (ignore key))
             (unless (find t candidates :key #'fourth)
               (push (dra-candidates-to-results
                      (mapcar (lambda (candidate) (subseq candidate 0 3))
                              (nreverse candidates))
                      result-name)
                     options)))
           pools)
          (dolist (option (sort options #'string<
                                :key (lambda (option)
                                       (let ((first (aref option 0)))
                                         (format nil "~A/~A" (gethash "driver" first)
                                                 (gethash "pool" first))))))
            (when (funcall function option)
              (return-from dra-map-exact-request-options-unlocked t))))
        (dra-map-candidate-combinations
         (lambda (combination)
           (funcall function (dra-candidates-to-results combination result-name)))
         (loop for candidate in matching unless (fourth candidate)
               collect (subseq candidate 0 3))
         count))))

(defun dra-map-request-options-unlocked (function store request node used)
  "Call FUNCTION for REQUEST's allocations in Kubernetes preference order."
  (let ((name (gethash "name" request)) (exact (gethash "exactly" request)))
    (if exact
        (dra-map-exact-request-options-unlocked function store exact name node used)
        (loop for subrequest across (gethash "firstAvailable" request #())
              when (dra-map-exact-request-options-unlocked
                    function store subrequest
                    (format nil "~A/~A" name (gethash "name" subrequest))
                    node used)
                return t))))

(defun dra-result-device-unlocked (store node result)
  "Return RESULT's ResourceSlice device object on NODE."
  (dolist (slice (dra-current-complete-slices-unlocked store node))
    (let ((spec (gethash "spec" slice)))
      (when (and (equal (gethash "driver" result) (gethash "driver" spec))
                 (equal (gethash "pool" result) (gethash "name" (gethash "pool" spec))))
        (let ((device (find (gethash "device" result) (gethash "devices" spec #())
                            :test #'equal :key (lambda (candidate) (gethash "name" candidate)))))
          (when device (return device)))))))

(defun dra-device-qualified-attribute (device driver qualified-name)
  "Return DEVICE's scalar QUALIFIED-NAME attribute and whether it exists."
  (let* ((slash (position #\/ qualified-name :from-end t))
         (domain (and slash (subseq qualified-name 0 slash)))
         (name (if slash (subseq qualified-name (1+ slash)) qualified-name))
         (attributes (gethash "attributes" device (core-object))))
    (multiple-value-bind (attribute present)
        (gethash (if (and domain (not (equal domain driver))) qualified-name name) attributes)
      (values (and present (dra-device-attribute-value attribute)) present))))

(defun dra-constraint-includes-request-p (constraint result-name)
  "Return whether CONSTRAINT applies to RESULT-NAME."
  (let ((requests (gethash "requests" constraint #())))
    (or (zerop (length requests))
        (some (lambda (configured)
                (or (equal configured result-name)
                    (uiop:string-prefix-p (format nil "~A/" configured) result-name)))
              requests))))

(defun dra-constraints-satisfied-p (store claim node results)
  "Return whether RESULTS satisfy CLAIM's cross-device attribute constraints."
  (loop for constraint across (gethash "constraints"
                                       (gethash "devices" (gethash "spec" claim) (core-object))
                                       #())
        always
        (let* ((match-attribute (gethash "matchAttribute" constraint))
               (distinct-attribute (gethash "distinctAttribute" constraint))
               (attribute (or match-attribute distinct-attribute))
              (values nil) (complete t))
          (unless attribute (return-from dra-constraints-satisfied-p nil))
          (loop for result across results
                when (dra-constraint-includes-request-p constraint (gethash "request" result))
                  do (let ((device (dra-result-device-unlocked store node result)))
                       (multiple-value-bind (value present)
                           (and device
                                (dra-device-qualified-attribute
                                 device (gethash "driver" result) attribute))
                         (unless present (setf complete nil))
                         (when present (push value values)))))
          (and complete
               (if match-attribute
                   (or (null values)
                       (every (lambda (value) (equalp value (first values)))
                              (rest values)))
                   (= (length values)
                      (length (remove-duplicates values :test #'equalp))))))))

(defun dra-claim-results-unlocked (store claim node used)
  "Search REQUEST alternatives for the first constraint-satisfying allocation."
  (let ((requests (gethash "requests" (gethash "devices" (gethash "spec" claim) (core-object)) #()))
        (solution nil))
    (labels ((search-request (index results)
               (if (= index (length requests))
                   (let ((vector (coerce results 'vector)))
                     (when (dra-constraints-satisfied-p store claim node vector)
                       (setf solution vector)
                       t))
                   (dra-map-request-options-unlocked
                    (lambda (option)
                      (let ((keys (map 'list
                                       (lambda (result)
                                         (dra-device-key (gethash "driver" result)
                                                         (gethash "pool" result)
                                                         (gethash "device" result)))
                                       option)))
                        (unless (some (lambda (key) (gethash key used)) keys)
                          (dolist (key keys) (setf (gethash key used) t))
                          (unwind-protect
                               (search-request (1+ index)
                                               (append results (coerce option 'list)))
                            (dolist (key keys) (remhash key used))))))
                    store (aref requests index) node used))))
      (if (search-request 0 nil)
          (values solution t)
          (values nil nil)))))

(defun dra-selected-request-class (request result-name)
  "Return REQUEST's selected DeviceClass name for allocation RESULT-NAME."
  (let ((exact (gethash "exactly" request)))
    (if exact
        (and (equal result-name (gethash "name" request))
             (gethash "deviceClassName" exact))
        (let* ((prefix (format nil "~A/" (gethash "name" request)))
               (subrequest-name (and (uiop:string-prefix-p prefix result-name)
                                     (subseq result-name (length prefix))))
               (subrequest (and subrequest-name
                                (find subrequest-name (gethash "firstAvailable" request #())
                                      :test #'equal :key (lambda (candidate)
                                                           (gethash "name" candidate))))))
          (and subrequest (gethash "deviceClassName" subrequest))))))

(defun dra-allocation-config-unlocked (store claim results)
  "Return class and claim configuration captured for RESULTS."
  (let* ((devices (gethash "devices" (gethash "spec" claim) (core-object)))
         (requests (gethash "requests" devices #()))
         (classes (make-hash-table :test #'equal))
         (class-order nil)
         (selected-request-names
           (remove-duplicates (map 'list (lambda (result) (gethash "request" result)) results)
                              :test #'equal))
         (config nil))
    (dolist (result-name selected-request-names)
      (loop for request across requests
            for class-name = (dra-selected-request-class request result-name)
            when class-name
              do (unless (gethash class-name classes)
                   (push class-name class-order))
                 (pushnew result-name (gethash class-name classes) :test #'equal)
                 (loop-finish)))
    (dolist (class-name (nreverse class-order))
      (let ((class (gethash (core-resource-key "deviceclasses" nil class-name)
                            (pod-store-resources store)))
            (class-requests (coerce (nreverse (gethash class-name classes)) 'vector)))
        (loop for entry across (gethash "config" (gethash "spec" class) #())
              do (let ((copy (copy-core-object entry)))
                   (setf (gethash "source" copy) "FromClass"
                         (gethash "requests" copy) (copy-seq class-requests))
                   (push copy config)))))
    (loop for entry across (gethash "config" devices #())
          for requested = (gethash "requests" entry #())
          when (or (zerop (length requested))
                   (some (lambda (name)
                           (find name selected-request-names :test
                                 (lambda (configured selected)
                                   (or (equal configured selected)
                                       (uiop:string-prefix-p
                                        (format nil "~A/" configured) selected)))))
                         requested))
            do (let ((copy (copy-core-object entry)))
                 (setf (gethash "source" copy) "FromClaim")
                 (push copy config)))
    (coerce (nreverse config) 'vector)))

(defun dra-allocation-for-claim-unlocked (store claim node used)
  "Build CLAIM's structured allocation on NODE, returning it and success."
  (multiple-value-bind (results ready) (dra-claim-results-unlocked store claim node used)
    (unless ready (return-from dra-allocation-for-claim-unlocked (values nil nil)))
    (values
     (let ((results results))
       (core-object
        "devices" (core-object "results" results
                               "config" (dra-allocation-config-unlocked store claim results))
        "nodeSelector"
        (core-object
         "nodeSelectorTerms"
         (vector (core-object
                  "matchFields"
                  (vector (core-object "key" "metadata.name" "operator" "In"
                                       "values" (vector (node-record-name node)))))))))
     t)))

(defun pod-dra-allocation-plan-unlocked (store pod node)
  "Return POD's claim/allocation plan for NODE and true, or NIL/NIL when unavailable."
  (multiple-value-bind (claims ready) (pod-dra-claims-unlocked store pod)
    (unless ready (return-from pod-dra-allocation-plan-unlocked (values nil nil)))
    (let ((used (dra-allocated-device-keys-unlocked store)) (plan nil))
      (dolist (claim claims)
        (let ((allocation (gethash "allocation" (gethash "status" claim (core-object)))))
          (if allocation
              (unless (dra-allocation-available-on-node-p claim node)
                (return-from pod-dra-allocation-plan-unlocked (values nil nil)))
              (multiple-value-bind (new-allocation allocated)
                  (dra-allocation-for-claim-unlocked store claim node used)
                (unless allocated
                  (return-from pod-dra-allocation-plan-unlocked (values nil nil)))
                (setf allocation new-allocation)))
          (push (cons claim allocation) plan)))
      (values (nreverse plan) t))))

(defun dra-allocation-available-on-node-p (claim node)
  "Return whether CLAIM's committed allocation is available on NODE."
  (let* ((allocation (gethash "allocation" (gethash "status" claim)))
         (selector (gethash "nodeSelector" allocation)))
    (or (null selector)
        (some (lambda (term) (node-selector-term-matches-p term node))
              (gethash "nodeSelectorTerms" selector #())))))

(defun pod-dra-node-compatible-p (store pod node)
  "Return whether all claims of POD may be allocated or reserved and used on NODE.
Call with STORE's lock held."
  (nth-value 1 (pod-dra-allocation-plan-unlocked store pod node)))

(defun reserve-pod-dra-claims-unlocked (store pod node)
  "Atomically allocate NODE's devices and reserve every claim for POD. Caller holds STORE's lock."
  (multiple-value-bind (plan ready) (pod-dra-allocation-plan-unlocked store pod node)
    (unless ready (return-from reserve-pod-dra-claims-unlocked nil))
    (when plan
      (let* ((resources (copy-core-resource-index store))
             (revision (1+ (pod-store-resource-revision store))))
        (dolist (entry plan)
          (let* ((claim (car entry))
                 (object (copy-core-object claim))
                 (metadata (gethash "metadata" object))
                 (status (or (gethash "status" object)
                             (setf (gethash "status" object) (core-object))))
                 (reserved (gethash "reservedFor" status #())))
            (unless (gethash "allocation" status)
              (setf (gethash "allocation" status) (copy-core-object (cdr entry))))
            (unless (find (pod-uid pod) reserved :test #'equal
                          :key (lambda (consumer) (gethash "uid" consumer)))
              (setf (gethash "reservedFor" status)
                    (concatenate 'vector reserved
                                 (vector (core-object "resource" "pods" "name" (pod-name pod)
                                                      "uid" (pod-uid pod))))))
            (setf (gethash "resourceVersion" metadata) (write-to-string revision)
                  (gethash (core-resource-key "resourceclaims" (pod-namespace pod)
                                              (gethash "name" metadata)) resources) object)))
        (commit-core-resources store resources revision)))
    t))

(defun persist-pod-assignment (store pod node-name)
  "Assign POD to NODE-NAME, advance its resource version, and persist it."
  (unless (reserve-pod-dra-claims-unlocked store pod (get-node-unlocked store node-name))
    (error "ResourceClaims for ~A/~A changed during scheduling" (pod-namespace pod) (pod-name pod)))
  (let* ((object (pod-to-object pod))
         (spec (gethash "spec" object))
         (metadata (gethash "metadata" object))
         (old (pod-published-view store pod))
         (next-version (write-to-string (next-pod-revision-unlocked store))))
    (setf (pod-node-name pod) node-name
          (gethash "nodeName" spec) node-name
          (pod-resource-version pod) next-version
          (pod-status-revision pod) nil
          (gethash "resourceVersion" metadata) next-version)
    (persist-pod store pod)
    (publish-pod-spec-change-unlocked store old pod)
    ;; Assignment changes desired state just as create/update does. Replicate it
    ;; before a follower serves reads or a newly elected leader takes over.
    (note-pod-desired-change store)
    pod))

(defun update-node-kubelet-port (store node-name port)
  "Persist the port NODE-NAME's agent serves kubelet endpoints on, which its Node advertises."
  (with-store-lock (store)
    (let ((node (get-node-unlocked store node-name)))
      (when (and node (/= port (node-record-kubelet-port node)))
        (let ((updated (copy-node-record node))
              (old (node-api-object node)))
          (setf (node-record-kubelet-port updated) port)
          (persist-node store updated)
          (setf (node-record-kubelet-port node) port)
          (publish-node-change-unlocked store old node))))))

(defun update-node-capacity (store node-name capacity)
  "Persist the quantities NODE-NAME's agent measured, leaving a missing report unchanged."
  (with-store-lock (store)
    (let ((node (get-node-unlocked store node-name)))
      (when (and node capacity (plusp (hash-table-count capacity))
                 (not (equalp capacity (node-record-capacity node))))
        (let ((updated (copy-node-record node))
              (old (node-api-object node)))
          (setf (node-record-capacity updated) capacity)
          (persist-node store updated)
          (setf (node-record-capacity node) capacity)
          (publish-node-change-unlocked store old node))))))

(defun update-node-extended-resources (store node-name resources)
  "Replace the extended resources NODE-NAME advertises to the scheduler."
  (with-store-lock (store)
    (let* ((node (or (get-node-unlocked store node-name)
                     (error 'kubernetes-error :status-code 404 :reason "NotFound"
                                              :message (format nil "Node ~A was not found" node-name))))
           (updated (copy-node-record node))
           (old (node-api-object node)))
      (setf (node-record-extended-resources updated) resources)
      (persist-node store updated)
      (setf (node-record-extended-resources node) resources)
      (publish-node-change-unlocked store old node))))

(defun node-placement-better-p (store pod left right)
  "Prefer a node POD's affinity favors, then its least crowded spread domains, then the fewest Pods, then a stable name."
  (let ((left-score (+ (pod-node-preference-score pod left) (pod-affinity-preference-score-unlocked store pod left)))
        (right-score (+ (pod-node-preference-score pod right) (pod-affinity-preference-score-unlocked store pod right)))
        (left-spread (pod-topology-spread-penalty-unlocked store pod left))
        (right-spread (pod-topology-spread-penalty-unlocked store pod right))
        (left-count (assigned-nonterminal-pod-count store (node-record-name left)))
        (right-count (assigned-nonterminal-pod-count store (node-record-name right))))
    (cond ((/= left-score right-score) (> left-score right-score))
          ((/= left-spread right-spread) (< left-spread right-spread))
          ((/= left-count right-count) (< left-count right-count))
          (t (string< (node-record-name left) (node-record-name right))))))

(defparameter +failed-scheduling-event-interval+ 30
  "Seconds between repeats of one Pod's FailedScheduling Event while its reason is unchanged.")

(defun record-pod-scheduling-event (store pod type reason message)
  "Record the scheduler's Event about POD, counting repeats of the same reason."
  (handler-case
      (let* ((name (concatenate 'string (pod-name pod) "."
                                (string-downcase
                                 (subseq (octets-to-hex
                                          (ironclad:digest-sequence
                                           :sha256 (trivial-utf-8:string-to-utf-8-bytes
                                                    (format nil "~A/~A" (pod-uid pod) reason))))
                                         0 16))))
             (now (current-timestamp))
             (existing (handler-case (get-core-resource store "events" (pod-namespace pod) name)
                         (kubernetes-error (condition)
                           (unless (= 404 (kubernetes-error-status-code condition)) (error condition))
                           nil))))
        (if existing
            (update-core-resource store "events" (pod-namespace pod) name
              (lambda (old)
                (setf (gethash "count" old) (1+ (gethash "count" old 1))
                      (gethash "lastTimestamp" old) now
                      (gethash "message" old) message)
                old))
            (create-core-resource store "events"
              (core-object "apiVersion" "v1" "kind" "Event" "metadata" (core-object "name" name)
                           "involvedObject" (core-object "apiVersion" "v1" "kind" "Pod" "namespace" (pod-namespace pod)
                                                         "name" (pod-name pod) "uid" (pod-uid pod))
                           "reason" reason "message" message "type" type "count" 1
                           "firstTimestamp" now "lastTimestamp" now
                           "source" (core-object "component" "default-scheduler")
                           "reportingComponent" "default-scheduler" "reportingInstance" "default-scheduler")
              (pod-namespace pod))))
    (error (condition)
      (format *error-output* "gr8s scheduling Event for ~A/~A failed: ~A~%" (pod-namespace pod) (pod-name pod) condition))))

(defun note-pod-unschedulable (store pod)
  "Tell the Pod's owner why it cannot be placed, when the reason is new or a while has passed."
  (let* ((message (with-store-lock (store) (pod-unschedulable-message store pod)))
         (now (get-universal-time))
         (last (with-store-lock (store) (gethash (pod-uid pod) (pod-store-scheduling-notes store)))))
    (unless (and last (equal message (car last)) (< (- now (cdr last)) +failed-scheduling-event-interval+))
      (with-store-lock (store)
        (setf (gethash (pod-uid pod) (pod-store-scheduling-notes store)) (cons message now)))
      (record-pod-scheduling-event store pod "Warning" "FailedScheduling" message))))

(defun %schedule-pod (store pod)
  "Return POD's selected node, or preempt lower-priority Pods when no placeable node fits it.
Each call for an unbound Pod is a scheduling attempt, measured as kube-scheduler measures one."
  (let ((node nil) (victims nil) (started (get-internal-real-time)) (algorithm nil))
    (with-store-lock (store)
      (let ((requested-node (pod-node-name pod)))
        (when requested-node
          (return-from %schedule-pod (get-node-unlocked store requested-node)))
        ;; As kube-scheduler does, leave a Pod naming another scheduler for that one to bind.
        (unless (and (pod-for-this-scheduler-p pod) (not (pod-scheduling-gated-p pod)))
          (return-from %schedule-pod nil)))
      (let* ((placeable (loop for candidate being the hash-values of (pod-store-nodes store)
                              when (pod-node-placeable-p store pod candidate) collect candidate))
             (fitting (remove-if-not (lambda (candidate) (pod-fits-node-unlocked store pod candidate)) placeable)))
        (setf node (first (sort fitting (lambda (left right) (node-placement-better-p store pod left right))))
              algorithm (/ (- (get-internal-real-time) started) internal-time-units-per-second))
        (if node
            (progn
              (remhash (pod-uid pod) (pod-store-nominated-nodes store))
              (persist-pod-assignment store pod (node-record-name node)))
            (let ((plan (choose-preemption-unlocked store pod placeable)))
              (cond (plan
                     (setf victims (cdr plan)
                           (gethash (pod-uid pod) (pod-store-nominated-nodes store)) (node-record-name (car plan))))
                    ;; As upstream, a Pod still waiting for its victims keeps its nomination, while
                    ;; one whose preemption now finds nothing gives it up, so its reservation stops
                    ;; holding room against Pods of its own priority.
                    ((not (pod-awaiting-preemption-p store pod))
                     (remhash (pod-uid pod) (pod-store-nominated-nodes store))))))))
    (ignore-errors
     (note-scheduling-attempt (pod-uid pod)
                              (ignore-errors (pod-deletion-time (table-get (pod-to-object pod) "metadata" "creationTimestamp")))
                              (if node "scheduled" "unschedulable")
                              (/ (- (get-internal-real-time) started) internal-time-units-per-second)
                              (and node algorithm)))
    ;; Deletion takes the store lock itself and is retried by reconciliation.
    (dolist (victim victims)
      (unless (deletion-requested-p victim) (preempt-pod store victim)))
    (if node
        (progn
          (with-store-lock (store) (remhash (pod-uid pod) (pod-store-scheduling-notes store)))
          (record-pod-scheduling-event store pod "Normal" "Scheduled"
                                       (format nil "Successfully assigned ~A/~A to ~A" (pod-namespace pod) (pod-name pod)
                                               (node-record-name node))))
        (note-pod-unschedulable store pod))
    node))

(defun update-pod-observed-phase (store pod phase)
  "Record the agent-observed PHASE for POD."
  (let ((status (make-hash-table :test #'equal)))
    (setf (gethash "phase" status) phase)
    (save-pod-observation store pod status)))

(defun update-pod-observed-status (store pod status)
  "Record POD's complete observed STATUS and its derived phase."
  (save-pod-observation store pod status))

(defun pod-observed-status (store pod)
  "Return the latest agent-observed status object for POD, if any."
  (with-store-lock (store)
    (gethash (pod-uid pod) (pod-store-pod-observed-statuses store))))

(defun pod-scheduling-phase (store pod)
  "Derive POD's API phase from assignment, node readiness, and observation."
  (with-store-lock (store)
    (let* ((node-name (pod-node-name pod))
           (node (and node-name (get-node-unlocked store node-name))))
      (cond
        ((null node) "Pending")
        ((not (node-record-ready-p node)) "Unknown")
        (t (or (gethash (pod-uid pod) (pod-store-pod-observed-phases store))
               "Pending"))))))

(defun pod-observed-resource-version (store pod)
  "Return the resource version actually acknowledged in the agent observation."
  (with-store-lock (store)
    (gethash (pod-uid pod) (pod-store-pod-observed-resource-versions store) "")))
