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
  (template-history-recent nil)
  (template-history-maintained-at 0)
  (template-history-floor 0)
  (resource-history-start 0)
  template-token-key
  (event-expirations (make-hash-table :test #'equal))
  in-cluster-config
  (credential-lock (bt:make-lock "gr8s ServiceAccount credentials"))
  service-account-signing-key
  ;; Digest of each verified token to its claims.
  (verified-tokens (make-hash-table :test #'equal))
  ;; (Pod UID, token identity) to the projected token last minted for it.
  (projected-tokens (make-hash-table :test #'equal))
  ;; (Pod UID, PodCertificateRequest name) to the node-generated private key
  ;; material for a podCertificate projected volume. The key never leaves the
  ;; node, so it lives only here and is regenerated if the node restarts.
  (pod-certificates (make-hash-table :test #'equal))
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
  (node-watch-floor 0)
  node-watch-journal
  (node-watch-journal-length 0)
  (pod-published-statuses (make-hash-table :test #'equal))
  (pod-client-statuses (make-hash-table :test #'equal))
  ;; Pod UID to the node reserved for it while its preemption victims terminate.
  (nominated-nodes (make-hash-table :test #'equal))
  ;; Pod UID to the (message . time) of its latest FailedScheduling Event.
  (scheduling-notes (make-hash-table :test #'equal))
  (lock (bt:make-lock "gr8s store"))
  ;; HA (podster-c2d.7.2). When CONSENSUS-COMMIT-FN is set, a durable
  ;; (consensus-plane) write is not published locally under the store lock;
  ;; instead the committed state blob is handed to this function, which
  ;; replicates it through Raft and installs it on every replica (including this
  ;; one) via INSTALL-CORE-STATE-BLOB. CONSENSUS-WRITE-LOCK serializes writers so
  ;; the store lock is never held across the Raft round-trip (no deadlock with
  ;; the apply path). NIL (the default) keeps the single-node path unchanged.
  consensus-commit-fn
  (consensus-write-lock (bt:make-lock "gr8s consensus write")))

(defmacro with-store-lock ((store) &body body)
  "Evaluate BODY while holding STORE's lock. In HA consensus mode (STORE has a
   consensus-commit-fn) a durable write made in BODY is not published under the
   lock; COMMIT-CORE-RESOURCES stashes the committed state, and once the store
   lock is released the state is replicated through Raft and installed on every
   replica. The store lock is therefore never held across the Raft round-trip, so
   there is no deadlock with the apply path, and writers serialize on the
   consensus-write lock. This is sound because WITH-STORE-LOCK is non-reentrant,
   so it is never nested: every acquisition is the outermost one. Without HA this
   is a plain lock hold, identical to the single-node path."
  (let ((s (gensym "STORE")))
    `(let ((,s ,store))
       (if (pod-store-consensus-commit-fn ,s)
           (bt:with-lock-held ((pod-store-consensus-write-lock ,s))
             (let ((*pending-consensus-commit* nil)
                   (*pending-pod-commit* nil)
                   (*pending-node-commit* nil)
                   (*core-write-active* t))
               (multiple-value-prog1
                   (bt:with-lock-held ((pod-store-lock ,s)) ,@body)
                 ;; Replicate whatever the body committed, once the store lock is
                 ;; released: core API resources, Pod desired state, node desired state.
                 (when *pending-consensus-commit*
                   (funcall (pod-store-consensus-commit-fn ,s) :core-state *pending-consensus-commit*))
                 (when *pending-pod-commit*
                   (funcall (pod-store-consensus-commit-fn ,s) :pod-state *pending-pod-commit*))
                 (when *pending-node-commit*
                   (funcall (pod-store-consensus-commit-fn ,s) :node-state *pending-node-commit*)))))
           (bt:with-lock-held ((pod-store-lock ,s)) ,@body)))))

(defvar *pending-consensus-commit* nil
  "Bound by WITH-CORE-WRITE; COMMIT-CORE-RESOURCES stashes the committed state
   blob here (instead of publishing) when STORE is in HA consensus mode, so the
   write can be replicated after the store lock is released.")

(defvar *core-write-active* nil
  "True only within a WITH-CORE-WRITE body, so COMMIT-CORE-RESOURCES knows the
   caller will flush the replicated write after releasing the store lock. A
   durable write made outside WITH-CORE-WRITE (e.g. a not-yet-converted
   controller path) publishes locally as before.")

(defvar *local-plane-write* nil
  "True while writing only local-plane resources (events). COMMIT-CORE-RESOURCES
   then publishes locally and never replicates, so high-churn events stay off the
   Raft log (podster-8ia.3). Each member keeps its own; agents/controllers on the
   new leader regenerate them after failover.")

(defvar *pending-pod-commit* nil
  "Bound by WITH-STORE-LOCK; set to the serialized Pod desired-state index when a
   Pod desired-state write happens on an HA store, so the change replicates to
   the other members after the store lock is released (podster-8ia.2).")

(defvar *pending-node-commit* nil
  "Bound by WITH-STORE-LOCK; set to the serialized node index when a node
   DESIRED-state write (CIDR assignment, taints, labels) happens on an HA store.
   Node heartbeat/lease writes deliberately do NOT set this -- they are observed
   state, re-reported by agents after they reconnect (podster-8ia.4).")

(defmacro with-core-write ((store) &body body)
  "Historical alias: WITH-STORE-LOCK is now itself HA-aware, so a durable write
   needs no special wrapper. Kept so existing call sites read intently."
  `(with-store-lock (,store) ,@body))

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
    (when (node-record-labels node) (setf (gethash "labels" object) (node-record-labels node)))
    (when (node-record-annotations node) (setf (gethash "annotations" object) (node-record-annotations node)))
    (setf (gethash "resourceVersion" object) (node-record-resource-version node))
    (when (node-record-capacity node)
      (setf (gethash "capacity" object) (node-record-capacity node)))
    (when (node-record-extended-resources node)
      (setf (gethash "extendedResources" object) (node-record-extended-resources node)))
    (when (plusp (length (node-record-taints node)))
      (setf (gethash "taints" object) (node-record-taints node)))
    (when (node-record-unschedulable node) (setf (gethash "unschedulable" object) t))
    (when (node-record-api-only node) (setf (gethash "apiOnly" object) t))
    (when (node-record-api-status node) (setf (gethash "apiStatus" object) (node-record-api-status node)))
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
                      :labels (gethash "labels" object)
                      :annotations (gethash "annotations" object)
                      :resource-version (gethash "resourceVersion" object "1")
                      :capacity (gethash "capacity" object)
                      :extended-resources (gethash "extendedResources" object)
                      :taints (gethash "taints" object #())
                      :unschedulable (eq t (gethash "unschedulable" object))
                      :api-only (eq t (gethash "apiOnly" object))
                      :api-status (gethash "apiStatus" object)
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
            "~(~2,'0X~2,'0X~2,'0X~2,'0X-~2,'0X~2,'0X-~2,'0X~2,'0X-~2,'0X~2,'0X-~2,'0X~2,'0X~2,'0X~2,'0X~2,'0X~2,'0X~)"
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
        pod)
  ;; A desired-state Pod write lands here (after persist); flag it for HA
  ;; replication. A no-op off the consensus path. Done after the index update so
  ;; the replicated snapshot includes this Pod (podster-8ia.2).
  (note-pod-desired-change store)
  pod)

;;; ---------------------------------------------------------------------------
;;; HA Pod desired-state replication (podster-8ia.2).
;;;
;;; Pods live outside the core-resource index: each is persisted in its own file,
;;; and the persisted object is the DESIRED state (its observed status is kept
;;; separately and merged on read). To replicate, the leader applies a Pod write
;;; locally as always and then ships the whole Pod desired-state index; followers
;;; reconcile their Pod files and index to match. Observed status is never
;;; replicated -- agents re-report it after they reconnect to the new leader.

(defun pod-desired-state-json (store)
  "Serialize every Pod's authoritative (desired-state) object."
  (com.inuoe.jzon:stringify
   (let ((table (make-hash-table :test #'equal)))
     (setf (gethash "pods" table)
           (coerce (loop for pod being the hash-values of (pod-store-pods store)
                         collect (pod-to-object pod))
                   'vector))
     table)))

(defun note-pod-desired-change (store)
  "On an HA store, stash the Pod desired-state index so WITH-STORE-LOCK replicates
   it after the lock is released. A no-op off the consensus path (e.g. the node
   agent's own store, or a write outside WITH-STORE-LOCK)."
  (when (and *core-write-active* (pod-store-consensus-commit-fn store))
    (setf *pending-pod-commit* (pod-desired-state-json store))))

(defun install-pod-state-blob (store json)
  "Install a replicated Pod desired-state blob on this replica: make the Pod files
   and index match it exactly. Uses the RAW store lock (see INSTALL-CORE-STATE-BLOB)."
  (bt:with-lock-held ((pod-store-lock store))
    (let ((state (com.inuoe.jzon:parse json))
          (seen (make-hash-table :test #'equal)))
      (loop for object across (gethash "pods" state)
            for pod = (parse-pod object)
            for key = (pod-key (pod-namespace pod) (pod-name pod))
            do (setf (gethash key seen) t)
               (persist-pod store pod)
               (index-pod store pod))
      ;; Drop Pods the leader no longer has.
      (loop for key being the hash-keys of (pod-store-pods store)
            for pod = (gethash key (pod-store-pods store))
            unless (gethash key seen)
              do (ignore-errors (delete-file (pod-path store pod)))
                 (remhash key (pod-store-pods store))))))

;;; ---------------------------------------------------------------------------
;;; HA node desired-state replication (podster-8ia.4).
;;;
;;; Node records mix desired state (the control-plane-assigned podCIDR, taints,
;;; labels) with observed state (ready/lastHeartbeat/leaseDeadline, re-reported by
;;; the agent). Only DESIRED writes call NOTE-NODE-DESIRED-CHANGE; heartbeat
;;; writes do not, so a node's lease churn never hits the Raft log. The critical
;;; field is podCIDR: a control-plane allocation that is not re-derivable, so a
;;; new leader must keep it or it could hand the node a different CIDR than the
;;; one its agent is already running.

(defun node-desired-state-json (store)
  "Serialize every node record for replication."
  (com.inuoe.jzon:stringify
   (let ((table (make-hash-table :test #'equal)))
     (setf (gethash "nodes" table)
           (coerce (loop for node being the hash-values of (pod-store-nodes store)
                         collect (node-record-to-object node))
                   'vector))
     table)))

(defun note-node-desired-change (store)
  "Stash the node index so WITH-STORE-LOCK replicates it after the lock is
   released. Call only from node DESIRED-state writes, never heartbeat writes."
  (when (and *core-write-active* (pod-store-consensus-commit-fn store))
    (setf *pending-node-commit* (node-desired-state-json store))))

(defun install-node-state-blob (store json)
  "Install a replicated node desired-state blob on this replica: make the node
   files and index match it. Uses the RAW store lock (see INSTALL-CORE-STATE-BLOB)."
  (bt:with-lock-held ((pod-store-lock store))
    (let ((state (com.inuoe.jzon:parse json))
          (seen (make-hash-table :test #'equal)))
      (loop for object across (gethash "nodes" state)
            for node = (parse-node-record object)
            do (setf (gethash (node-record-name node) seen) t)
               (persist-node store node)
               (setf (gethash (node-record-name node) (pod-store-nodes store)) node))
      (loop for name being the hash-keys of (pod-store-nodes store)
            for node = (gethash name (pod-store-nodes store))
            unless (gethash name seen)
              do (ignore-errors (delete-file (node-path store node)))
                 (remhash name (pod-store-nodes store))))))

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
    (enforce-resource-quotas-unlocked store "pods" (pod-namespace pod) (pod-to-object pod))
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
      (validate-pod-policy-update existing replacement)
      (preserve-pod-ephemeral-containers existing replacement)
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
      (note-pod-desired-change store)
      (publish-pod-removal-unlocked store pod)
      (remhash (pod-uid pod) (pod-store-pod-finalization-states store))
      (remhash (pod-uid pod) (pod-store-pod-observed-phases store))
      (remhash (pod-uid pod) (pod-store-pod-observed-statuses store))
      (remhash (pod-uid pod) (pod-store-pod-observed-resource-versions store))
      (remhash (pod-uid pod) (pod-store-pod-condition-histories store))
      (remhash (pod-uid pod) (pod-store-pod-client-statuses store))
      (remhash (pod-uid pod) (pod-store-nominated-nodes store))
      (remhash (pod-uid pod) (pod-store-scheduling-notes store))
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
