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
  (merge-pathnames "allocations.json" (node-ipam-directory ipam)))

(defun pod-address-key (sandbox-id interface-name)
  (cons sandbox-id interface-name))

(defun node-ipam-allocation-object (key address)
  (json-object "sandboxID" (car key)
               "interfaceName" (cdr key)
               "address" address))

(defun node-ipam-state-object (ipam)
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
  (funcall (node-ipam-persister ipam) ipam))

(defun valid-pod-address-owner-p (value)
  (and (stringp value) (plusp (length value))))

(defun usable-node-ipam-address-p (address network prefix)
  (let ((broadcast (+ network (1- (ash 1 (- 32 prefix))))))
    (< network address broadcast)))

(defun restore-node-ipam-allocations (path cidr network prefix)
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
  (loop for allocated being the hash-values of (node-ipam-allocations ipam)
        thereis (string= address allocated)))

(defun allocate-pod-address (ipam sandbox-id interface-name)
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
  (bt:with-lock-held ((node-ipam-lock ipam))
    (or (gethash (pod-address-key sandbox-id interface-name)
                 (node-ipam-allocations ipam))
        (invalid-cni "no Pod address is allocated to ~A/~A"
                     sandbox-id interface-name))))

(defun release-pod-address (ipam sandbox-id interface-name)
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
