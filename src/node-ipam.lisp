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
;;;; CNI errors.

(in-package #:gr8s)

(defstruct (node-ipam (:constructor %make-node-ipam))
  directory
  cidr
  network
  prefix
  allocations
  persister
  (lock (bt:make-lock "gr8s node IPAM")))

(defun node-ipam-state-path (ipam)
  "The path of IPAM's persisted allocations file (allocations.json in its
   directory)."
  (merge-pathnames "allocations.json" (node-ipam-directory ipam)))

(defun pod-address-key (sandbox-id interface-name)
  "The allocation-table key for a Pod interface: (SANDBOX-ID . INTERFACE-NAME)."
  (cons sandbox-id interface-name))

(defun node-ipam-allocation-object (key address)
  "A JSON object for one allocation: KEY's sandbox id and interface name, and
   ADDRESS."
  (json-object "sandboxID" (car key)
               "interfaceName" (cdr key)
               "address" address))

(defun node-ipam-state-object (ipam)
  "IPAM's full persisted state as a JSON object: version 1, its CIDR, and its
   allocations sorted by (sandbox id, interface name) for a stable file."
  (let ((entries
          (sort
           (loop for key being the hash-keys of (node-ipam-allocations ipam)
                   using (hash-value address)
                 collect (node-ipam-allocation-object key address))
           #'string<
           :key (lambda (entry)
                  (format nil "~A~C~A"
                          (gethash "sandboxID" entry) #\Null
                          (gethash "interfaceName" entry))))))
    (json-object "version" 1
                 "cidr" (node-ipam-cidr ipam)
                 "allocations" (coerce entries 'vector))))

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

(defun usable-node-ipam-address-p (address network prefix)
  "True when integer ADDRESS lies strictly between the network and broadcast
   addresses of NETWORK/PREFIX -- a usable host address, neither the network nor
   the broadcast."
  (let ((broadcast (+ network (1- (ash 1 (- 32 prefix))))))
    (< network address broadcast)))

(defun restore-node-ipam-allocations (path cidr network prefix)
  "Read the allocations file at PATH and return the allocation table (a hash table
   keyed by (sandbox-id . interface-name)). A missing file yields an empty table.
   Signals a CNI error when the file's version is unsupported, its CIDR is not
   CIDR, an entry is malformed, an address falls outside the usable range of
   NETWORK/PREFIX, or an owner or address is duplicated."
  (let ((allocations (make-hash-table :test #'equal))
        (addresses (make-hash-table :test #'equal)))
    (when (probe-file path)
      (handler-case
          (let ((state (com.inuoe.jzon:parse path)))
            (unless (and (hash-table-p state)
                         (= 1 (gethash "version" state 0)))
              (invalid-cni "IPAM state has an unsupported format"))
            (unless (string= cidr (gethash "cidr" state ""))
              (invalid-cni "IPAM state belongs to ~A, not ~A"
                           (gethash "cidr" state "") cidr))
            (let ((entries (gethash "allocations" state)))
              (unless (vectorp entries)
                (invalid-cni "IPAM state allocations must be an array"))
              (loop for entry across entries
                    for sandbox-id = (and (hash-table-p entry)
                                          (gethash "sandboxID" entry))
                    for interface-name = (and (hash-table-p entry)
                                              (gethash "interfaceName" entry))
                    for address = (and (hash-table-p entry)
                                       (gethash "address" entry))
                    do (unless (and (valid-pod-address-owner-p sandbox-id)
                                    (valid-pod-address-owner-p interface-name)
                                    (stringp address))
                         (invalid-cni "IPAM state contains an invalid allocation"))
                       (let* ((key (pod-address-key sandbox-id interface-name))
                              (numeric-address (parse-ipv4-integer address)))
                         (unless (usable-node-ipam-address-p
                                  numeric-address network prefix)
                           (invalid-cni
                            "IPAM address ~A is outside usable CIDR ~A"
                            address cidr))
                         (when (gethash key allocations)
                           (invalid-cni
                            "IPAM owner ~A/~A has duplicate allocations"
                            sandbox-id interface-name))
                         (when (gethash address addresses)
                           (invalid-cni "IPAM address ~A has duplicate owners"
                                        address))
                         (setf (gethash key allocations) address
                               (gethash address addresses) t)))))
        (cni-error (condition) (error condition))
        (error (condition)
          (invalid-cni "could not restore IPAM state: ~A" condition))))
    allocations))

(defun open-node-ipam
    (directory cidr &key (persister #'persist-node-ipam-state))
  "Open the node IPAM for CIDR under DIRECTORY, restoring any persisted
   allocations, and return the NODE-IPAM. PERSISTER is the function used to write
   state (the atomic file persister by default). Signals a CNI error when CIDR
   cannot be parsed or is not the network address of its prefix."
  (handler-case
      (multiple-value-bind (address prefix) (parse-ipv4-cidr cidr)
        (let* ((mask (if (zerop prefix)
                         0
                         (logand #xffffffff
                                 (ash #xffffffff (- 32 prefix)))))
               (network (logand address mask))
               (root (uiop:ensure-directory-pathname directory))
               (state-path (merge-pathnames "allocations.json" root)))
          (unless (= address network)
            (invalid-cni "node Pod CIDR ~A is not a network address" cidr))
          (ensure-directories-exist root)
          (%make-node-ipam
           :directory root :cidr cidr :network network :prefix prefix
           :persister persister
           :allocations
           (restore-node-ipam-allocations state-path cidr network prefix))))
    (cni-error (condition) (error condition))
    (error (condition)
      (invalid-cni "invalid node Pod CIDR ~A: ~A" cidr condition))))

(defun reload-node-ipam-allocations (ipam)
  "Re-read the persisted allocations file into IPAM's in-memory table. In managed
   mode the CNI plugin runs out of process and persists every allocation to that
   file, so a long-running agent must reload it to observe Pods added since the
   ipam was opened -- otherwise its dataplane maps only ever reflect the Pods that
   existed at startup. The file is the source of truth (allocate/release persist
   immediately), so a wholesale reload is safe in both managed and in-process modes."
  (bt:with-lock-held ((node-ipam-lock ipam))
    (setf (node-ipam-allocations ipam)
          (restore-node-ipam-allocations (node-ipam-state-path ipam)
                                         (node-ipam-cidr ipam)
                                         (node-ipam-network ipam)
                                         (node-ipam-prefix ipam))))
  ipam)

(defun node-ipam-address-in-use-p (ipam address)
  "True when ADDRESS (a dotted string) is currently allocated in IPAM. Reads the
   allocation table without locking; callers hold the IPAM lock."
  (loop for allocated being the hash-values of (node-ipam-allocations ipam)
        thereis (string= address allocated)))

(defun allocate-pod-address (ipam sandbox-id interface-name)
  "Allocate, or return the existing, Pod address for SANDBOX-ID/INTERFACE-NAME in
   IPAM, as a dotted string. Idempotent: an interface already allocated keeps its
   address. Otherwise picks the lowest free host address, skipping the network and
   broadcast, persists the new allocation before returning, and rolls it back out
   of memory if the persist fails. Signals a CNI error when the Pod CIDR is
   exhausted. Holds the IPAM lock."
  (bt:with-lock-held ((node-ipam-lock ipam))
    (let* ((key (pod-address-key sandbox-id interface-name))
           (existing (gethash key (node-ipam-allocations ipam))))
      (when existing
        (return-from allocate-pod-address existing))
      (let* ((host-count (ash 1 (- 32 (node-ipam-prefix ipam))))
             (address
               (loop for offset from 1 below (1- host-count)
                     for candidate = (format-ipv4-integer
                                      (+ (node-ipam-network ipam) offset))
                     unless (node-ipam-address-in-use-p ipam candidate)
                       return candidate
                     finally
                        (invalid-cni "Pod CIDR ~A is exhausted"
                                     (node-ipam-cidr ipam)))))
        (setf (gethash key (node-ipam-allocations ipam)) address)
        (handler-case
            (persist-node-ipam ipam)
          (error (condition)
            (remhash key (node-ipam-allocations ipam))
            (error condition)))
        address))))

(defun check-pod-address (ipam sandbox-id interface-name)
  "The address currently allocated to SANDBOX-ID/INTERFACE-NAME in IPAM, or signal
   a CNI error when none is. Holds the IPAM lock."
  (bt:with-lock-held ((node-ipam-lock ipam))
    (or (gethash (pod-address-key sandbox-id interface-name)
                 (node-ipam-allocations ipam))
        (invalid-cni "no Pod address is allocated to ~A/~A"
                     sandbox-id interface-name))))

(defun release-pod-address (ipam sandbox-id interface-name)
  "Release the address allocated to SANDBOX-ID/INTERFACE-NAME in IPAM, persisting
   the change; restores the entry if the persist fails. A no-op when nothing is
   allocated for that key. Holds the IPAM lock. Returns NIL."
  (bt:with-lock-held ((node-ipam-lock ipam))
    (let ((key (pod-address-key sandbox-id interface-name)))
      (multiple-value-bind (address present-p)
          (gethash key (node-ipam-allocations ipam))
        (when present-p
          (remhash key (node-ipam-allocations ipam))
          (handler-case
              (persist-node-ipam ipam)
            (error (condition)
              (setf (gethash key (node-ipam-allocations ipam)) address)
              (error condition)))))))
  nil)
