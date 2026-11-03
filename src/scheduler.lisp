(in-package #:gr8s)

(defun node-conflict (control &rest arguments)
  (error 'kubernetes-error
         :status-code 409
         :reason "Conflict"
         :message (apply #'format nil control arguments)))

(defun same-node-identity-p (left right)
  (and (string= (node-record-id left) (node-record-id right))
       (string= (node-record-name left) (node-record-name right))
       (string= (node-record-pod-cidr left) (node-record-pod-cidr right))))

(defun register-node (store node)
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
               (when (string= (node-record-pod-cidr existing)
                              (node-record-pod-cidr node))
                 (node-conflict "PodCIDR ~A is already claimed"
                                (node-record-pod-cidr node))))
      (setf (node-record-ready-p node) nil
            (node-record-last-heartbeat node) nil
            (gethash (node-record-name node) (pod-store-nodes store)) node)
      (persist-node store node))))

(defun get-node-unlocked (store name)
  (gethash name (pod-store-nodes store)))

(defun get-node (store name)
  (with-store-lock (store)
    (or (get-node-unlocked store name)
        (error 'kubernetes-error
               :status-code 404
               :reason "NotFound"
               :message (format nil "Node ~A was not found" name)))))

(defun list-nodes (store)
  (with-store-lock (store)
    (sort (loop for node being the hash-values of (pod-store-nodes store)
                collect node)
          #'string< :key #'node-record-name)))

(defun mark-node-ready (store name heartbeat)
  (with-store-lock (store)
    (let ((node (or (get-node-unlocked store name)
                    (error 'kubernetes-error
                           :status-code 404
                           :reason "NotFound"
                           :message (format nil "Node ~A was not found" name)))))
      (setf (node-record-ready-p node) t
            (node-record-last-heartbeat node) heartbeat)
      node)))

(defun mark-node-not-ready (store name)
  (with-store-lock (store)
    (let ((node (or (get-node-unlocked store name)
                    (error 'kubernetes-error
                           :status-code 404
                           :reason "NotFound"
                           :message (format nil "Node ~A was not found" name)))))
      (setf (node-record-ready-p node) nil)
      node)))

(defun expire-node-heartbeats (store oldest-acceptable-heartbeat)
  (with-store-lock (store)
    (loop for node being the hash-values of (pod-store-nodes store)
          when (and (node-record-ready-p node)
                    (or (null (node-record-last-heartbeat node))
                        (< (node-record-last-heartbeat node)
                           oldest-acceptable-heartbeat)))
            collect (progn (setf (node-record-ready-p node) nil) node))))

(defun parse-ipv4-integer (address)
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
  (format nil "~D.~D.~D.~D"
          (ldb (byte 8 24) address)
          (ldb (byte 8 16) address)
          (ldb (byte 8 8) address)
          (ldb (byte 8 0) address)))

(defun parse-ipv4-cidr (cidr)
  (let ((parts (uiop:split-string cidr :separator '(#\/))))
    (unless (= 2 (length parts))
      (error "Invalid IPv4 CIDR ~S" cidr))
    (let ((prefix (parse-integer (second parts) :junk-allowed nil)))
      (unless (<= 0 prefix 32)
        (error "Invalid IPv4 CIDR prefix ~S" cidr))
      (values (parse-ipv4-integer (first parts)) prefix))))

(defun canonical-node-underlay-address (address)
  (unless (and (stringp address) (plusp (length address)))
    (error "node underlay address must be a unicast IPv4 address"))
  (let ((integer (parse-ipv4-integer address)))
    (unless (and (<= #x01000000 integer) (< integer #xe0000000)
                 (/= 127 (ldb (byte 8 24) integer)))
      (error "node underlay address must be a non-loopback unicast IPv4 address"))
    (format-ipv4-integer integer)))

(defun update-node-underlay-address (store node-name address)
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
      (let ((previous (node-record-underlay-address node)))
        (setf (node-record-underlay-address node) address)
        (handler-case (persist-node store node)
          (error (condition)
            (setf (node-record-underlay-address node) previous)
            (error condition))))))
  t)

(defun allocate-node-pod-cidr (store cluster-cidr node-prefix)
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
      (with-store-lock (store)
        (loop for index below block-count
              for candidate = (format nil "~A/~D"
                                      (format-ipv4-integer
                                       (+ base (* index block-size)))
                                      node-prefix)
              unless (loop for node being the hash-values
                             of (pod-store-nodes store)
                           thereis (string= candidate
                                            (node-record-pod-cidr node)))
                return candidate
              finally (error "No free /~D PodCIDR remains in ~A"
                             node-prefix cluster-cidr))))))

(defun terminal-pod-phase-p (phase)
  (member phase '("Succeeded" "Failed") :test #'string=))

(defun assigned-nonterminal-pod-count (store node-name)
  (loop for pod being the hash-values of (pod-store-pods store)
        count (and (equal node-name (pod-node-name pod))
                   (not (terminal-pod-phase-p
                         (gethash (pod-uid pod)
                                  (pod-store-pod-observed-phases store)))))))

(defun persist-pod-assignment (store pod node-name)
  (let* ((object (pod-to-object pod))
         (spec (gethash "spec" object))
         (metadata (gethash "metadata" object))
         (next-version
           (write-to-string (1+ (parse-integer (pod-resource-version pod))))))
    (setf (pod-node-name pod) node-name
          (gethash "nodeName" spec) node-name
          (pod-resource-version pod) next-version
          (gethash "resourceVersion" metadata) next-version)
    (persist-pod store pod)))

(defun schedule-pod (store pod)
  (with-store-lock (store)
    (let ((requested-node (pod-node-name pod)))
      (when requested-node
        (return-from schedule-pod (get-node-unlocked store requested-node)))
      (let ((node
              (first
               (sort
                (loop for candidate being the hash-values
                        of (pod-store-nodes store)
                      when (node-record-ready-p candidate)
                        collect candidate)
                (lambda (left right)
                  (let ((left-count
                          (assigned-nonterminal-pod-count
                           store (node-record-name left)))
                        (right-count
                          (assigned-nonterminal-pod-count
                           store (node-record-name right))))
                    (or (< left-count right-count)
                        (and (= left-count right-count)
                             (string< (node-record-name left)
                                      (node-record-name right))))))))))
        (when node
          (persist-pod-assignment store pod (node-record-name node)))
        node))))

(defun update-pod-observed-phase (store pod phase)
  (with-store-lock (store)
    (setf (gethash (pod-uid pod) (pod-store-pod-observed-phases store)) phase)))

(defun update-pod-observed-status (store pod status)
  (with-store-lock (store)
    (setf (gethash (pod-uid pod) (pod-store-pod-observed-statuses store)) status
          (gethash (pod-uid pod) (pod-store-pod-observed-phases store))
          (gethash "phase" status "Unknown"))))

(defun pod-observed-status (store pod)
  (with-store-lock (store)
    (gethash (pod-uid pod) (pod-store-pod-observed-statuses store))))

(defun pod-scheduling-phase (store pod)
  (with-store-lock (store)
    (let* ((node-name (pod-node-name pod))
           (node (and node-name (get-node-unlocked store node-name))))
      (cond
        ((null node) "Pending")
        ((not (node-record-ready-p node)) "Unknown")
        (t (or (gethash (pod-uid pod) (pod-store-pod-observed-phases store))
               "Pending"))))))
