;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Per-node IP address management (IPAM) for Pod interfaces.
;;;;
;;;; Each node owns a slice of the cluster Pod CIDR and hands addresses out of it
;;;; to Pod interfaces, keyed by (sandbox-id . interface-name). The allocation
;;;; table is the authority and is persisted to allocations.json in the node's
;;;; IPAM directory: every allocate and release rewrites the whole table
;;;; atomically (temp file then rename, owner-only mode), so it survives a restart
;;;; and so a CNI plugin running out of process and the long-running agent share
;;;; one view -- RELOAD-NODE-IPAM-ALLOCATIONS re-reads the file to pick up Pods
;;;; added since the ipam was opened. A lock guards the in-memory table, and a
;;;; failed persist is rolled back so disk and memory never disagree. The network
;;;; and broadcast addresses are reserved; exhaustion and malformed state signal
;;;; CNI errors. Optional Service SNAT leases use a separate table in version 3
;;;; of the same file; they consume IPv4 pool space but are not Pod interface IPs.

(in-package #:gr8s.network)

(defstruct (node-ipam (:constructor %make-node-ipam))
  directory
  cidr
  network
  prefix
  cidrs
  networks
  prefixes
  families
  allocations
  (incarnations (make-hash-table :test #'equal))
  (service-snat-allocations (make-hash-table :test #'equal))
  persister
  (lock (bt:make-lock "gr8s node IPAM")))

(defun node-ipam-state-path (ipam)
  "The path of IPAM's persisted allocations file (allocations.json in its
   directory)."
  (merge-pathnames "allocations.json" (node-ipam-directory ipam)))

(defun pod-address-key (sandbox-id interface-name)
  "The allocation-table key for a Pod interface: (SANDBOX-ID . INTERFACE-NAME)."
  (cons sandbox-id interface-name))

(defun node-ipam-allocation-object (key addresses &optional plural-p incarnation)
  "A JSON object for one allocation: KEY's sandbox id and interface name, and
   ADDRESSES."
  (let ((object (json-object "sandboxID" (car key)
                            "interfaceName" (cdr key))))
    (if plural-p
        (setf (gethash "addresses" object) (coerce addresses 'vector))
        (setf (gethash "address" object) (first addresses)))
    (when incarnation
      (setf (gethash "incarnation" object) incarnation))
    object))

(defun node-ipam-state-object (ipam)
  "IPAM's persisted state: version 1 for one CIDR, version 2 for ordered CIDRs,
   or version 3 when private Service SNAT leases exist. Its
   allocations sorted by (sandbox id, interface name) for a stable file."
  (let* ((snat-p (plusp (hash-table-count (node-ipam-service-snat-allocations ipam))))
         (plural-p (or snat-p (> (length (node-ipam-cidrs ipam)) 1)))
         (entries
          (sort
           (loop for key being the hash-keys of (node-ipam-allocations ipam)
                   using (hash-value addresses)
                 collect (node-ipam-allocation-object
                          key addresses plural-p
                          (gethash key (node-ipam-incarnations ipam))))
           #'string<
           :key (lambda (entry)
                  (format nil "~A~C~A"
                          (gethash "sandboxID" entry) #\Null
                          (gethash "interfaceName" entry))))))
    (let ((state
            (if plural-p
                (json-object "version" (if snat-p 3 2)
                             "cidrs" (coerce (node-ipam-cidrs ipam) 'vector)
                             "allocations" (coerce entries 'vector))
                (json-object "version" 1
                             "cidr" (node-ipam-cidr ipam)
                             "allocations" (coerce entries 'vector)))))
      (when snat-p
        (setf (gethash "serviceSNATAllocations" state)
              (coerce
               (sort (loop for key being the hash-keys of (node-ipam-service-snat-allocations ipam)
                             using (hash-value address)
                           collect (node-ipam-allocation-object key (list address)))
                     #'string< :key (lambda (entry)
                                      (format nil "~A~C~A" (gethash "sandboxID" entry)
                                              #\Null (gethash "interfaceName" entry))))
               'vector)))
      state)))

(defun persist-node-ipam-state (ipam)
  "Persist IPAM's state to its allocations file atomically -- write a uniquely
   named temp file, rename it over the target, then restrict it to owner-only --
   so a crash never leaves a half-written file. The default persister. Returns
   IPAM."
  (let* ((target (node-ipam-state-path ipam))
         (temporary
           (make-pathname
            :name (format nil "allocations-~36R" (random (expt 36 10)))
            :type "tmp"
            :defaults target)))
    (ensure-directories-exist target)
    (with-open-file (stream temporary
                            :direction :output
                            :if-exists :supersede
                            :if-does-not-exist :create)
      (com.inuoe.jzon:stringify (node-ipam-state-object ipam) :stream stream))
    (uiop:rename-file-overwriting-target temporary target)
    (sb-posix:chmod target #o600))
  ipam)

(defun persist-node-ipam (ipam)
  "Persist IPAM through its configured persister function, returning whatever that
   persister returns."
  (funcall (node-ipam-persister ipam) ipam))

(defun valid-pod-address-owner-p (value)
  "True when VALUE is a non-empty string -- the shape required of a sandbox id or
   interface name."
  (and (stringp value) (plusp (length value))))

(defun usable-node-ipam-address-p (address network prefix bits)
  "True when integer ADDRESS lies strictly between the network and broadcast
   addresses of NETWORK/PREFIX -- a usable host address, neither the network nor
   the broadcast."
  (let ((last (+ network (1- (ash 1 (- bits prefix))))))
    (if (= bits 32)
        (< network address last)
        (< network address (1+ last)))))

(defun restore-node-ipam-allocations (path cidrs networks prefixes families)
  "Return Pod and private Service SNAT allocation tables, keyed by endpoint owner.
   A missing file yields empty tables. Validate both before publishing either.
   Signals a CNI error when the file's version is unsupported, its CIDR is not
   CIDR, an entry is malformed, an address falls outside the usable range of
   NETWORK/PREFIX, or an owner or address is duplicated."
  (let ((allocations (make-hash-table :test #'equal))
        (snat-allocations (make-hash-table :test #'equal))
        (incarnations (make-hash-table :test #'equal))
        (addresses (make-hash-table :test #'equal)))
    (when (probe-file path)
      (handler-case
          (let* ((state (com.inuoe.jzon:parse path))
                 (version (and (hash-table-p state)
                               (gethash "version" state 0))))
            (unless (member version '(1 2 3))
              (invalid-cni "IPAM state has an unsupported format"))
            (when (and (/= version 3)
                       (nth-value 1 (gethash "serviceSNATAllocations" state)))
              (invalid-cni "IPAM Service SNAT leases require format 3"))
            (let ((stored-cidrs
                    (if (= version 1)
                        (list (gethash "cidr" state ""))
                        (let ((value (gethash "cidrs" state)))
                          (unless (vectorp value)
                            (invalid-cni "IPAM state CIDRs must be an array"))
                          (coerce value 'list)))))
              (unless (equal cidrs stored-cidrs)
                (invalid-cni "IPAM state belongs to ~{~A~^,~}, not ~{~A~^,~}"
                             stored-cidrs cidrs)))
            (let ((entries (gethash "allocations" state)))
              (unless (vectorp entries)
                (invalid-cni "IPAM state allocations must be an array"))
              (loop for entry across entries
                    for sandbox-id = (and (hash-table-p entry)
                                          (gethash "sandboxID" entry))
                    for interface-name = (and (hash-table-p entry)
                                              (gethash "interfaceName" entry))
                    for entry-addresses = (and (hash-table-p entry)
                                               (if (= version 1)
                                                   (let ((address (gethash "address" entry)))
                                                     (and address (list address)))
                                                   (let ((value (gethash "addresses" entry)))
                                                     (and (vectorp value)
                                                          (coerce value 'list)))))
                    for incarnation = (and (hash-table-p entry)
                                           (gethash "incarnation" entry))
                    do (unless (and (valid-pod-address-owner-p sandbox-id)
                                    (valid-pod-address-owner-p interface-name)
                                    (= (length cidrs) (length entry-addresses))
                                    (every #'stringp entry-addresses)
                                    (or (null incarnation)
                                        (and (stringp incarnation)
                                             (= (length incarnation) 32)
                                             (every (lambda (character)
                                                      (or (digit-char-p character)
                                                          (find character "abcdef")))
                                                    incarnation))))
                         (invalid-cni "IPAM state contains an invalid allocation"))
                       (let ((key (pod-address-key sandbox-id interface-name)))
                         (when (gethash key allocations)
                           (invalid-cni
                            "IPAM owner ~A/~A has duplicate allocations"
                            sandbox-id interface-name))
                         (loop for address in entry-addresses
                               for cidr in cidrs
                               for network in networks
                               for prefix in prefixes
                               for family in families
                               for bits = (if (eq family :ipv6) 128 32)
                               for numeric-address = (if (eq family :ipv6)
                                                         (ipv6-integer address)
                                                         (parse-ipv4-integer address))
                               do (unless (usable-node-ipam-address-p
                                           numeric-address network prefix bits)
                                    (invalid-cni
                                     "IPAM address ~A is outside usable CIDR ~A"
                                     address cidr))
                                  (when (gethash (list family numeric-address) addresses)
                                    (invalid-cni "IPAM address ~A has duplicate owners"
                                                 address))
                                  (setf (gethash (list family numeric-address) addresses) t))
                         (setf (gethash key allocations) entry-addresses)
                         (when incarnation
                           (setf (gethash key incarnations) incarnation)))))
            (when (= version 3)
              (let ((entries (gethash "serviceSNATAllocations" state))
                    (index (position :ipv4 families)))
                (unless (and index (vectorp entries))
                  (invalid-cni "IPAM Service SNAT state requires IPv4 and an allocation array"))
                (loop for entry across entries
                      for sandbox = (and (hash-table-p entry) (gethash "sandboxID" entry))
                      for interface = (and (hash-table-p entry) (gethash "interfaceName" entry))
                      for address = (and (hash-table-p entry) (gethash "address" entry))
                      for key = (pod-address-key sandbox interface)
                      do (unless (and (valid-pod-address-owner-p sandbox)
                                      (valid-pod-address-owner-p interface) (stringp address)
                                      (gethash key allocations) (not (gethash key snat-allocations)))
                           (invalid-cni "IPAM Service SNAT lease has an invalid or duplicate owner"))
                         (let ((numeric (parse-ipv4-integer address)))
                           (unless (and (equal address (format-pod-address :ipv4 numeric))
                                        (usable-node-ipam-address-p numeric (nth index networks)
                                                                    (nth index prefixes) 32)
                                        (not (gethash (list :ipv4 numeric) addresses)))
                             (invalid-cni "IPAM Service SNAT address ~A is unusable or already owned" address))
                           (setf (gethash (list :ipv4 numeric) addresses) t
                                 (gethash key snat-allocations) address))))))
        (cni-error (condition) (error condition))
        (error (condition)
          (invalid-cni "could not restore IPAM state: ~A" condition))))
    (values allocations snat-allocations incarnations)))

(defun open-node-ipam
    (directory cidr-or-cidrs &key (persister #'persist-node-ipam-state))
  "Open the node IPAM for CIDR under DIRECTORY, restoring any persisted
   allocations, and return the NODE-IPAM. PERSISTER is the function used to write
   state (the atomic file persister by default). Signals a CNI error when CIDR
   cannot be parsed or is not the network address of its prefix."
  (handler-case
      (let* ((cidrs (if (stringp cidr-or-cidrs)
                        (list cidr-or-cidrs)
                        (coerce cidr-or-cidrs 'list)))
             (descriptors
               (mapcar (lambda (cidr)
                         (multiple-value-bind (family address prefix bits)
                             (parse-pod-cidr cidr)
                           (let* ((host-bits (- bits prefix))
                                  (network (ash (ash address (- host-bits)) host-bits)))
                             (unless (= address network)
                               (invalid-cni "node Pod CIDR ~A is not a network address" cidr))
                             (list family network prefix))))
                       cidrs))
             (families (mapcar #'first descriptors))
             (networks (mapcar #'second descriptors))
             (prefixes (mapcar #'third descriptors))
             (root (uiop:ensure-directory-pathname directory))
             (state-path (merge-pathnames "allocations.json" root)))
          (unless (and cidrs (= (length families)
                                (length (remove-duplicates families))))
            (invalid-cni "node Pod CIDRs must contain each address family at most once"))
          (ensure-directories-exist root)
          (multiple-value-bind (allocations snat-allocations incarnations)
              (restore-node-ipam-allocations state-path cidrs networks prefixes families)
            (%make-node-ipam
             :directory root :cidr (first cidrs) :network (first networks)
             :prefix (first prefixes) :cidrs cidrs :networks networks
             :prefixes prefixes :families families
             :persister persister
             :allocations allocations :service-snat-allocations snat-allocations
             :incarnations incarnations)))
    (cni-error (condition) (error condition))
    (error (condition)
      (invalid-cni "invalid node Pod CIDR ~A: ~A" cidr-or-cidrs condition))))

(defun reload-node-ipam-allocations (ipam)
  "Re-read the persisted allocations file into IPAM's in-memory table. In managed
   mode the CNI plugin runs out of process and persists every allocation to that
   file, so a long-running agent must reload it to observe Pods added since the
   ipam was opened -- otherwise its dataplane maps only ever reflect the Pods that
   existed at startup. The file is the source of truth (allocate/release persist
   immediately), so a wholesale reload is safe in both managed and in-process modes."
  (bt:with-lock-held ((node-ipam-lock ipam))
    (multiple-value-bind (allocations snat-allocations incarnations)
        (restore-node-ipam-allocations (node-ipam-state-path ipam)
                                       (node-ipam-cidrs ipam)
                                       (node-ipam-networks ipam)
                                       (node-ipam-prefixes ipam)
                                       (node-ipam-families ipam))
      (setf (node-ipam-allocations ipam) allocations
            (node-ipam-service-snat-allocations ipam) snat-allocations
            (node-ipam-incarnations ipam) incarnations)))
  ipam)

(defun node-ipam-address-identity (address)
  "One key for every textual spelling of the same IP address."
  (if (find #\: address)
      (format-pod-address :ipv6 (ipv6-integer address))
      (format-pod-address :ipv4 (parse-ipv4-integer address))))

(defun node-ipam-used-addresses (ipam)
  "Snapshot numeric ownership across both lease tables. Caller holds the lock."
  (let ((used (make-hash-table :test #'equal)))
    (loop for allocated being the hash-values of (node-ipam-allocations ipam)
          do (dolist (address allocated)
               (setf (gethash (node-ipam-address-identity address) used) t)))
    (loop for address being the hash-values of (node-ipam-service-snat-allocations ipam)
          do (setf (gethash (node-ipam-address-identity address) used) t))
    used))

(defun node-ipam-address-in-use-p (ipam address)
  "True when either lease table owns ADDRESS. Caller holds the lock."
  (gethash (node-ipam-address-identity address) (node-ipam-used-addresses ipam)))

(defun allocate-service-snat-address (ipam sandbox-id interface-name)
  "Reserve an IPv4 return address for an existing endpoint, never a Pod address.
The lease shares the node pool and durable transaction with Pod allocations.
It is not configured in the Pod or exposed through the CNI IP result."
  (bt:with-lock-held ((node-ipam-lock ipam))
    (let* ((key (pod-address-key sandbox-id interface-name))
           (leases (node-ipam-service-snat-allocations ipam))
           (index (position :ipv4 (node-ipam-families ipam))))
      (unless (and index (gethash key (node-ipam-allocations ipam)))
        (invalid-cni "Service SNAT requires an allocated IPv4 Pod endpoint"))
      (or (gethash key leases)
          (let* ((used (node-ipam-used-addresses ipam))
                 (network (nth index (node-ipam-networks ipam)))
                 (prefix (nth index (node-ipam-prefixes ipam)))
                 (address
                   (loop for offset from 1 below (1- (ash 1 (- 32 prefix)))
                         for candidate = (format-pod-address :ipv4 (+ network offset))
                         unless (gethash candidate used) return candidate
                         finally (invalid-cni "Service SNAT IPv4 pool is exhausted"))))
            (setf (gethash key leases) address)
            (handler-case (persist-node-ipam ipam)
              (error (condition) (remhash key leases) (error condition)))
            address)))))

(defun service-snat-address (ipam sandbox-id interface-name)
  "Read an existing private return lease without allocating or changing it."
  (bt:with-lock-held ((node-ipam-lock ipam))
    (gethash (pod-address-key sandbox-id interface-name)
             (node-ipam-service-snat-allocations ipam))))

(defun allocate-pod-addresses (ipam sandbox-id interface-name)
  "Allocate or return the stable ordered address list for a Pod interface."
  (bt:with-lock-held ((node-ipam-lock ipam))
    (let* ((key (pod-address-key sandbox-id interface-name))
           (existing (gethash key (node-ipam-allocations ipam))))
      (when existing
        (return-from allocate-pod-addresses (copy-list existing)))
      (let* ((used (node-ipam-used-addresses ipam))
             (allocated
              (loop for cidr in (node-ipam-cidrs ipam)
                    for family in (node-ipam-families ipam)
                    for network in (node-ipam-networks ipam)
                    for prefix in (node-ipam-prefixes ipam)
                    for bits = (if (eq family :ipv6) 128 32)
                    for host-count = (ash 1 (- bits prefix))
                    for limit = (if (= bits 32) (1- host-count) host-count)
                    collect
                    (loop for offset from 1 below limit
                          for candidate = (format-pod-address family (+ network offset))
                          unless (gethash candidate used)
                            return candidate
                          finally
                             (invalid-cni "Pod CIDR ~A is exhausted" cidr)))))
        (setf (gethash key (node-ipam-allocations ipam)) allocated
              (gethash key (node-ipam-incarnations ipam))
              (ironclad:byte-array-to-hex-string (ironclad:random-data 16)))
        (handler-case
            (persist-node-ipam ipam)
          (error (condition)
            (remhash key (node-ipam-allocations ipam))
            (remhash key (node-ipam-incarnations ipam))
            (error condition)))
        (copy-list allocated)))))

(defun allocate-pod-address (ipam sandbox-id interface-name)
  "Allocate, or return the existing, Pod address for SANDBOX-ID/INTERFACE-NAME in
   IPAM, as a dotted string. Idempotent: an interface already allocated keeps its
   address. Otherwise picks the lowest free host address, skipping the network and
   broadcast, persists the new allocation before returning, and rolls it back out
   of memory if the persist fails. Signals a CNI error when the Pod CIDR is
   exhausted. Holds the IPAM lock."
  (first (allocate-pod-addresses ipam sandbox-id interface-name)))

(defun check-pod-addresses (ipam sandbox-id interface-name)
  "Return the ordered addresses allocated to a Pod interface."
  (bt:with-lock-held ((node-ipam-lock ipam))
    (let ((addresses (gethash (pod-address-key sandbox-id interface-name)
                              (node-ipam-allocations ipam))))
      (if addresses
          (copy-list addresses)
          (invalid-cni "no Pod address is allocated to ~A/~A"
                       sandbox-id interface-name)))))

(defun check-pod-address (ipam sandbox-id interface-name)
  "The address currently allocated to SANDBOX-ID/INTERFACE-NAME in IPAM, or signal
   a CNI error when none is. Holds the IPAM lock."
  (first (check-pod-addresses ipam sandbox-id interface-name)))

(defun pod-address-incarnation (ipam sandbox-id interface-name)
  "Return the durable generation of this lease, or NIL for a legacy lease.
The generation is minted only with a new allocation and never on ADD retry."
  (bt:with-lock-held ((node-ipam-lock ipam))
    (gethash (pod-address-key sandbox-id interface-name)
             (node-ipam-incarnations ipam))))

(defun release-pod-address (ipam sandbox-id interface-name)
  "Release the address allocated to SANDBOX-ID/INTERFACE-NAME in IPAM, persisting
   the change together with any Service SNAT lease; restore both if persist fails.
   Callers must retire routes and dataplane ownership before releasing addresses.
   A no-op when nothing is
   allocated for that key. Holds the IPAM lock. Returns NIL."
  (bt:with-lock-held ((node-ipam-lock ipam))
    (let* ((key (pod-address-key sandbox-id interface-name))
           (snat (gethash key (node-ipam-service-snat-allocations ipam)))
           (incarnation (gethash key (node-ipam-incarnations ipam))))
      (multiple-value-bind (address present-p)
          (gethash key (node-ipam-allocations ipam))
        (when present-p
          (remhash key (node-ipam-allocations ipam))
          (remhash key (node-ipam-service-snat-allocations ipam))
          (remhash key (node-ipam-incarnations ipam))
          (handler-case
              (persist-node-ipam ipam)
            (error (condition)
              (setf (gethash key (node-ipam-allocations ipam)) address)
              (when snat (setf (gethash key (node-ipam-service-snat-allocations ipam)) snat))
              (when incarnation
                (setf (gethash key (node-ipam-incarnations ipam)) incarnation))
              (error condition)))))))
  nil)
