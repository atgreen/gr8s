;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Provide the control plane's durable, lock-protected Pod and node registry.
;;;; Kubernetes objects are indexed in memory for API operations and persisted
;;;; as atomically replaced JSON files, while optimistic resource versions and
;;;; immutable scheduling decisions preserve the API invariants expected by
;;;; kubectl and the reconciliation loop.

(in-package #:gr8s)

(defstruct (pod-store (:constructor make-pod-store (path)))
  "Hold durable paths, in-memory indexes, observed status, and the store lock."
  path
  (pods (make-hash-table :test #'equal))
  (nodes (make-hash-table :test #'equal))
  (resources (make-hash-table :test #'equal))
  (resource-revision 0)
  template-history
  (template-history-floor 0)
  (resource-history-start 0)
  template-token-key
  (event-expirations (make-hash-table :test #'equal))
  in-cluster-config
  (credential-lock (bt:make-lock "gr8s ServiceAccount credentials"))
  (workload-lock (bt:make-lock "gr8s workload controllers"))
  (workload-deletions (make-hash-table :test #'equal))
  (job-controller-states (make-hash-table :test #'equal))
  (pod-finalization-states (make-hash-table :test #'equal))
  (pod-observed-phases (make-hash-table :test #'equal))
  (pod-observed-statuses (make-hash-table :test #'equal))
  (pod-observed-resource-versions (make-hash-table :test #'equal))
  (pod-condition-histories (make-hash-table :test #'equal))
  (pod-revision 0)
  (pod-revision-ceiling 0)
  (pod-watch-floor 0)
  pod-watch-journal
  (pod-watch-journal-length 0)
  (pod-published-statuses (make-hash-table :test #'equal))
  (lock (bt:make-lock "gr8s store")))

(defmacro with-store-lock ((store) &body body)
  "Evaluate BODY while holding STORE's lock."
  `(bt:with-lock-held ((pod-store-lock ,store))
     ,@body))

(defun pod-key (namespace name)
  "Return the stable in-memory key for NAMESPACE and Pod NAME."
  (format nil "~A/~A" namespace name))

(defun pod-path (store pod)
  "Return the JSON persistence pathname for POD in STORE."
  (merge-pathnames (format nil "~A.json" (pod-uid pod))
                   (pod-store-path store)))

(defun nodes-path (store)
  "Return STORE's directory for durable node records."
  (merge-pathnames "nodes/" (pod-store-path store)))

(defun node-path (store node)
  "Return the JSON persistence pathname for NODE in STORE."
  (merge-pathnames (format nil "~A.json" (node-record-id node))
                   (nodes-path store)))

(defun node-record-to-object (node)
  "Serialize NODE into the JSON object persisted by the control plane."
  (let ((object (make-hash-table :test #'equal)))
    (setf (gethash "id" object) (node-record-id node)
          (gethash "name" object) (node-record-name node)
          (gethash "podCIDR" object) (node-record-pod-cidr node)
          (gethash "underlayAddress" object) (node-record-underlay-address node)
          (gethash "ready" object) (not (null (node-record-ready-p node))))
    (when (node-record-last-heartbeat node)
      (setf (gethash "lastHeartbeat" object) (node-record-last-heartbeat node)))
    (when (node-record-lease-deadline node)
      (setf (gethash "leaseDeadline" object) (node-record-lease-deadline node)))
    object))

(defun parse-node-record (input)
  "Parse JSON text or an object into a NODE-RECORD."
  (let* ((object (if (hash-table-p input)
                    input
                    (com.inuoe.jzon:parse input)))
         (heartbeat (gethash "lastHeartbeat" object))
         (deadline (gethash "leaseDeadline" object)))
    (make-node-record :id (gethash "id" object)
                      :name (gethash "name" object)
                      :pod-cidr (gethash "podCIDR" object)
                      :underlay-address (gethash "underlayAddress" object "")
                      :last-heartbeat (when (integerp heartbeat) heartbeat)
                      :lease-deadline (when (integerp deadline) deadline)
                      :ready-p (and (eq t (gethash "ready" object))
                                    (integerp heartbeat) (integerp deadline)
                                    (<= (get-universal-time) deadline)))))

(defun secure-random-octets (count)
  "Read COUNT cryptographically secure random octets from the operating system."
  (let ((octets (make-array count :element-type '(unsigned-byte 8))))
    (with-open-file (stream #P"/dev/urandom"
                            :direction :input
                            :element-type '(unsigned-byte 8))
      (unless (= count (read-sequence octets stream))
        (error "could not read ~D bytes of operating-system entropy" count)))
    octets))

(defun generate-uid (&optional (entropy (secure-random-octets 16)))
  "Return an RFC 4122 version-4 UUID string derived from 16 ENTROPY octets."
  (unless (= 16 (length entropy))
    (error "a UUID requires exactly 16 bytes of entropy"))
  (let ((octets (copy-seq entropy)))
    (setf (aref octets 6) (logior #x40 (logand #x0f (aref octets 6)))
          (aref octets 8) (logior #x80 (logand #x3f (aref octets 8))))
    (format nil
            "~2,'0X~2,'0X~2,'0X~2,'0X-~2,'0X~2,'0X-~2,'0X~2,'0X-~2,'0X~2,'0X-~2,'0X~2,'0X~2,'0X~2,'0X~2,'0X~2,'0X"
            (aref octets 0) (aref octets 1) (aref octets 2) (aref octets 3)
            (aref octets 4) (aref octets 5) (aref octets 6) (aref octets 7)
            (aref octets 8) (aref octets 9) (aref octets 10) (aref octets 11)
            (aref octets 12) (aref octets 13) (aref octets 14)
            (aref octets 15))))

(defun current-timestamp (&optional (time (get-universal-time)))
  "Return the current UTC time in Kubernetes-compatible RFC 3339 form."
  (multiple-value-bind (second minute hour day month year)
      (decode-universal-time time 0)
    (format nil "~4,'0D-~2,'0D-~2,'0DT~2,'0D:~2,'0D:~2,'0DZ"
            year month day hour minute second)))

(defun persist-pod (store pod)
  "Atomically persist POD's authoritative JSON object in STORE."
  (let* ((target (pod-path store pod))
         (temporary
           (make-pathname
            :name (format nil "~A-~36R"
                          (pathname-name target) (random (expt 36 10)))
            :type "tmp"
            :defaults target)))
    (with-open-file (stream temporary
                            :direction :output
                            :if-exists :supersede
                            :if-does-not-exist :create)
      (com.inuoe.jzon:stringify (pod-to-object pod) :stream stream))
    (uiop:rename-file-overwriting-target temporary target))
  pod)

(defun persist-node (store node)
  "Atomically persist NODE in STORE's node directory."
  (ensure-directories-exist (nodes-path store))
  (let* ((target (node-path store node))
         (temporary
           (make-pathname
            :name (format nil "~A-~36R"
                          (pathname-name target) (random (expt 36 10)))
            :type "tmp"
            :defaults target)))
    (with-open-file (stream temporary
                            :direction :output
                            :if-exists :supersede
                            :if-does-not-exist :create)
      (com.inuoe.jzon:stringify (node-record-to-object node) :stream stream))
    (uiop:rename-file-overwriting-target temporary target))
  node)

(defun index-pod (store pod)
  "Install POD in STORE's namespace/name index and return it."
  (setf (gethash (pod-key (pod-namespace pod) (pod-name pod))
                 (pod-store-pods store))
        pod))

(defun open-store (path)
  "Open or create a durable store at PATH and rebuild its in-memory indexes."
  (let* ((directory (uiop:ensure-directory-pathname path))
         (store (make-pod-store directory)))
    (ensure-directories-exist directory)
    (ensure-directories-exist (nodes-path store))
    (dolist (file (directory (merge-pathnames "*.json" directory)))
      (index-pod store (parse-pod file)))
    (dolist (file (directory (merge-pathnames "*.json" (nodes-path store))))
      (let ((node (parse-node-record file)))
        (setf (gethash (node-record-name node) (pod-store-nodes store)) node)))
    (load-core-resources store)
    (load-pod-status-state store)
    (load-pod-revision store)
    store))

(defun get-pod-unlocked (store namespace name)
  "Return a Pod without locking, or signal a Kubernetes NotFound error."
  (or (gethash (pod-key namespace name) (pod-store-pods store))
      (error 'kubernetes-error
             :status-code 404
             :reason "NotFound"
             :message (format nil "Pod ~A/~A was not found" namespace name))))

(defun get-pod (store namespace name)
  "Return the Pod named NAME in NAMESPACE under STORE's lock."
  (with-store-lock (store)
    (get-pod-unlocked store namespace name)))

(defun list-pods (store &optional namespace)
  "Return a consistent snapshot of Pods, optionally restricted to NAMESPACE."
  (with-store-lock (store)
    (loop for pod being the hash-values of (pod-store-pods store)
          when (or (null namespace) (string= namespace (pod-namespace pod)))
            collect pod)))

(defun generate-pod-name (prefix)
  "Append five random characters to at most 58 prefix characters, matching upstream limits."
  (let ((alphabet "bcdfghjklmnpqrstvwxz2456789"))
    (concatenate 'string (subseq prefix 0 (min 58 (length prefix)))
                 (map 'string (lambda (byte) (char alphabet (mod byte (length alphabet))))
                      (secure-random-octets 5)))))

(defparameter *pod-name-generator* #'generate-pod-name
  "Generate a candidate Pod name; dynamically bound by deterministic collision tests.")

(defun assign-generated-pod-name-unlocked (store pod)
  "Choose an unused name under STORE's lock, retrying up to eight generated collisions."
  (unless (pod-name pod)
    (let* ((metadata (gethash "metadata" (pod-to-object pod)))
           (prefix (pod-generate-name-prefix metadata)))
      (unless (plusp (length prefix)) (invalid-pod "metadata.name or generateName is required"))
      (loop repeat 8
            for name = (require-dns-subdomain (funcall *pod-name-generator* prefix) "metadata.name")
            unless (gethash (pod-key (pod-namespace pod) name) (pod-store-pods store))
              do (setf (pod-name pod) name (gethash "name" metadata) name)
                 (return-from assign-generated-pod-name-unlocked pod))
      (error 'kubernetes-error :status-code 409 :reason "AlreadyExists"
             :message "Could not generate an unused Pod name after eight attempts")))
  pod)

(defun create-pod (store pod)
  "Assign server metadata, persist POD, and reject duplicate names atomically."
  (with-store-lock (store)
    (create-pod-unlocked store pod)))

(defun create-pod-unlocked (store pod)
  "Create POD while the caller holds STORE's lock, including owner-checked controller writes."
    (assign-generated-pod-name-unlocked store pod)
    (when (gethash (pod-key (pod-namespace pod) (pod-name pod))
                   (pod-store-pods store))
      (error 'kubernetes-error
             :status-code 409
             :reason "AlreadyExists"
             :message (format nil "Pod ~A already exists" (pod-name pod))))
    (let ((metadata (gethash "metadata" (pod-to-object pod))))
      (remhash "deletionTimestamp" metadata)
      (remhash "deletionGracePeriodSeconds" metadata)
      (setf (pod-uid pod) (generate-uid)
            (pod-resource-version pod) (write-to-string (next-pod-revision-unlocked store))
            (gethash "namespace" metadata) (pod-namespace pod)
            (gethash "uid" metadata) (pod-uid pod)
            (gethash "resourceVersion" metadata) (pod-resource-version pod)
            (gethash "generation" metadata) 1
            (gethash "creationTimestamp" metadata) (current-timestamp)))
    (persist-pod store pod)
    (index-pod store pod)
    (publish-pod-spec-change-unlocked store nil pod)
    pod)

(defun update-pod (store replacement expected-resource-version)
  "Persist REPLACEMENT when EXPECTED-RESOURCE-VERSION matches the stored Pod."
  (with-store-lock (store)
    (update-pod-unlocked store replacement expected-resource-version)))

(defun update-pod-unlocked (store replacement expected-resource-version)
  "Update a Pod while STORE's lock is already held by an owner/identity transaction."
    (let* ((existing (get-pod-unlocked
                      store (pod-namespace replacement) (pod-name replacement)))
           (actual (pod-resource-version existing)))
      (unless (pod-revision-satisfied-p store expected-resource-version actual)
        (error 'kubernetes-error
               :status-code 409
               :reason "Conflict"
               :message (format nil "expected resourceVersion ~A, found ~A"
                                expected-resource-version actual)))
      (validate-pod-hostname-update existing replacement)
      (validate-pod-dns-update existing replacement)
      (validate-pod-finalizer-update existing replacement)
      (when (pod-node-name existing)
        (when (and (pod-node-name replacement)
                   (not (string= (pod-node-name existing)
                                 (pod-node-name replacement))))
          (error 'kubernetes-error
                 :status-code 409
                 :reason "Conflict"
                 :message "spec.nodeName is immutable after scheduling"))
        (setf (pod-node-name replacement) (pod-node-name existing)
              (gethash "nodeName"
                       (gethash "spec" (pod-to-object replacement)))
              (pod-node-name existing)))
      (let ((metadata (gethash "metadata" (pod-to-object replacement)))
            (existing-metadata (gethash "metadata" (pod-to-object existing))))
        ;; Deletion is irreversible. An ordinary metadata/spec update cannot
        ;; erase or extend a shutdown that an agent is already carrying out.
        (dolist (key '("deletionTimestamp" "deletionGracePeriodSeconds"))
          (remhash key metadata)
          (when (gethash key existing-metadata)
            (setf (gethash key metadata) (gethash key existing-metadata))))
        (setf (gethash "generation" metadata)
              (+ (gethash "generation" existing-metadata 1)
                 (if (equalp (gethash "spec" (pod-to-object existing))
                             (gethash "spec" (pod-to-object replacement))) 0 1)))
        (setf (pod-uid replacement) (pod-uid existing)
              (pod-resource-version replacement)
              (write-to-string (next-pod-revision-unlocked store))
              (gethash "namespace" metadata) (pod-namespace replacement)
              (gethash "uid" metadata) (pod-uid replacement)
              (gethash "resourceVersion" metadata)
              (pod-resource-version replacement)
              (gethash "creationTimestamp" metadata)
              (gethash "creationTimestamp" existing-metadata)))
      (let ((old (pod-published-view store existing)))
        (persist-pod store replacement)
        (index-pod store replacement)
        (publish-pod-spec-change-unlocked store old replacement))
      replacement))

(defun remove-pod (store namespace name &key uid)
  "Remove a Pod and its observed status from STORE, returning the removed Pod."
  (with-store-lock (store)
    (let ((pod (get-pod-unlocked store namespace name)))
      (when (and uid (not (equal uid (pod-uid pod))))
        (error 'kubernetes-error :status-code 409 :reason "Conflict" :message "Pod UID changed before removal"))
      (when (pod-finalizers-present-p pod)
        (error 'kubernetes-error :status-code 409 :reason "Conflict" :message "Pod finalizers still retain this object"))
      (let ((status-path (pod-status-state-path store (pod-uid pod))))
        (when (probe-file status-path) (delete-file status-path)))
      (delete-file (pod-path store pod))
      (remhash (pod-key namespace name) (pod-store-pods store))
      (publish-pod-removal-unlocked store pod)
      (remhash (pod-uid pod) (pod-store-pod-finalization-states store))
      (remhash (pod-uid pod) (pod-store-pod-observed-phases store))
      (remhash (pod-uid pod) (pod-store-pod-observed-statuses store))
      (remhash (pod-uid pod) (pod-store-pod-observed-resource-versions store))
      (remhash (pod-uid pod) (pod-store-pod-condition-histories store))
      pod)))

(defun delete-pod (store namespace name)
  "Delete and return the Pod named NAME in NAMESPACE."
  (remove-pod store namespace name))

(defun mark-pod-deleting (store namespace name &key uid resource-version
                                                (grace-period nil grace-supplied-p)
                                                dry-run)
  "Set a Pod's deletion timestamp, advance its resource version, and persist it."
  (with-store-lock (store)
    (let* ((existing (get-pod-unlocked store namespace name))
           (pod (parse-pod (com.inuoe.jzon:parse
                            (com.inuoe.jzon:stringify (pod-to-object existing)))))
           (metadata (gethash "metadata" (pod-to-object pod))))
      (when (and uid (not (equal uid (pod-uid pod))))
        (error 'kubernetes-error :status-code 409 :reason "Conflict"
               :message "Pod UID no longer matches deletion precondition"))
      (when (and resource-version
                 (not (pod-revision-satisfied-p store resource-version (pod-resource-version pod))))
        (error 'kubernetes-error :status-code 409 :reason "Conflict"
               :message "Pod resourceVersion no longer matches deletion precondition"))
      (unless (prepare-pod-deletion store pod grace-period grace-supplied-p)
        (return-from mark-pod-deleting pod))
      (unless dry-run
        (let ((next-version (write-to-string (next-pod-revision-unlocked store)))
              (old (pod-published-view store existing)))
          (setf (gethash "resourceVersion" metadata) next-version
                (pod-resource-version pod) next-version)
          (persist-pod store pod)
          (index-pod store pod)
          (publish-pod-spec-change-unlocked store old pod)))
      pod)))
