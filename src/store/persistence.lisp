;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Provide the control plane's durable, lock-protected Pod and node registry.
;;;; Kubernetes objects are indexed in memory for API operations and persisted
;;;; as atomically replaced JSON files, while optimistic resource versions and
;;;; immutable scheduling decisions preserve the API invariants expected by
;;;; kubectl and the reconciliation loop.

(in-package #:gr8s.store)

(defvar *apply-update-manager* nil)

(defun store-json-object (&rest pairs)
  "Return an EQUAL hash table populated by alternating key and value PAIRS."
  (let ((object (make-hash-table :test #'equal)))
    (loop for (key value) on pairs by #'cddr
          do (setf (gethash key object) value))
    object))

(defun pending-pod-status ()
  "Return the initial status published for a Pod without an observation."
  (store-json-object "phase" "Pending"))

(defmacro with-store-lock ((store) &body body)
  "Hold STORE's lock; HA Pod writes are staged and published only on commit."
  `(call-with-store-transaction ,store (lambda () ,@body)))

(defvar *pending-consensus-commit* nil
  "Bound by WITH-CORE-WRITE; COMMIT-CORE-RESOURCES stashes the key-level state
   delta here (instead of publishing) when STORE is in HA consensus mode, so the
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
  "Changed Pod keys collected by WITH-STORE-LOCK. The transaction freezes their
   desired objects and checkpoints before restoring the committed local view.")

(defvar *pending-node-commit* nil
  "Bound by WITH-STORE-LOCK; node changes collect their names here so the
   committed command carries only those keys after the store lock is released.")

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
                   (store-data-path store)))

(defun nodes-path (store)
  "Return STORE's directory for durable node records."
  (merge-pathnames "nodes/" (store-data-path store)))

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
          (gethash "podCIDRs" object) (copy-seq (node-record-all-pod-cidrs node))
          (gethash "underlayAddress" object) (node-record-underlay-address node)
          (gethash "kubeletPort" object) (node-record-kubelet-port node)
          (gethash "ready" object) (not (null (node-record-ready-p node))))
    (when (plusp (length (node-record-wireguard-public-key node)))
      (setf (gethash "wireguardPublicKey" object)
            (ag-grpc:base64-encode (node-record-wireguard-public-key node))))
    (when (node-record-wireguard-endpoints node)
      (setf (gethash "wireguardEndpoints" object)
            (coerce
             (mapcar (lambda (endpoint)
                       (let ((object (make-hash-table :test #'equal)))
                         (setf (gethash "name" object) (first endpoint)
                               (gethash "address" object) (second endpoint)
                               (gethash "port" object) (third endpoint))
                         object))
                     (node-record-wireguard-endpoints node))
             'vector)))
    (when (node-record-wireguard-reflexive-observed-at node)
      (setf (gethash "wireguardReflexiveObservedAt" object)
            (node-record-wireguard-reflexive-observed-at node)))
    (when (node-record-last-heartbeat node)
      (setf (gethash "lastHeartbeat" object) (node-record-last-heartbeat node)))
    (when (node-record-lease-deadline node)
      (setf (gethash "leaseDeadline" object) (node-record-lease-deadline node)))
    (when (node-record-ready-since node)
      (setf (gethash "readySince" object) (node-record-ready-since node)))
    (when (node-record-labels node) (setf (gethash "labels" object) (node-record-labels node)))
    (when (node-record-annotations node) (setf (gethash "annotations" object) (node-record-annotations node)))
    ;; Standard kubelet nodeInfo (only non-empty fields persist/replicate).
    (loop for (key . value) in (list (cons "machineID" (node-record-machine-id node))
                                     (cons "systemUUID" (node-record-system-uuid node))
                                     (cons "bootID" (node-record-boot-id node))
                                     (cons "kernelVersion" (node-record-kernel-version node))
                                     (cons "osImage" (node-record-os-image node))
                                     (cons "containerRuntimeVersion" (node-record-runtime-version node)))
          when (and value (plusp (length value)))
            do (setf (gethash key object) value))
    (when (node-record-control-plane-p node)
      (setf (gethash "controlPlane" object) t))
    (when (node-record-certificate-issuer-fingerprint node)
      (setf (gethash "certificateIssuerFingerprint" object)
            (node-record-certificate-issuer-fingerprint node)))
    (setf (gethash "resourceVersion" object) (node-record-resource-version node))
    (when (node-record-capacity node)
      (setf (gethash "capacity" object) (node-record-capacity node)))
    (when (node-record-allocatable node)
      (setf (gethash "allocatable" object) (node-record-allocatable node)))
    (when (node-record-extended-resources node)
      (setf (gethash "extendedResources" object) (node-record-extended-resources node)))
    (when (plusp (length (node-record-taints node)))
      (setf (gethash "taints" object) (node-record-taints node)))
    (when (node-record-unschedulable node) (setf (gethash "unschedulable" object) t))
    (when (node-record-api-only node) (setf (gethash "apiOnly" object) t))
    (when (node-record-api-status node) (setf (gethash "apiStatus" object) (node-record-api-status node)))
    (when (node-record-creation-timestamp node)
      (setf (gethash "creationTimestamp" object) (node-record-creation-timestamp node)))
    object))

(defun parse-node-record (input &key (expire-leases t))
  "Parse JSON text or an object into a NODE-RECORD."
  (let* ((object (if (hash-table-p input)
                    input
                    (com.inuoe.jzon:parse input)))
         (heartbeat (gethash "lastHeartbeat" object))
         (deadline (gethash "leaseDeadline" object))
         (ready-since (gethash "readySince" object)))
    (let* ((persisted-ready-p
             (and (eq t (gethash "ready" object))
                  (integerp heartbeat) (integerp deadline)
                  (or (not expire-leases) (<= (get-universal-time) deadline))))
           (encoded-key (gethash "wireguardPublicKey" object))
           (wireguard-public-key
             (if encoded-key
                 (handler-case
                     (let ((key (ag-grpc:base64-decode encoded-key)))
                       (unless (and (= 32 (length key))
                                    (string= encoded-key (ag-grpc:base64-encode key)))
                         (error "not one canonical 32-byte key"))
                       key)
                   (error (condition)
                     (error "Invalid persisted WireGuard public key: ~A" condition)))
                 #())))
      (let* ((stored-cidrs (gethash "podCIDRs" object))
             (primary (gethash "podCIDR" object))
             (cidrs (if (and (vectorp stored-cidrs) (not (stringp stored-cidrs))
                             (plusp (length stored-cidrs)))
                        stored-cidrs
                        (if (and (stringp primary) (plusp (length primary))) (vector primary) #()))))
       (make-node-record :id (gethash "id" object)
                      :name (gethash "name" object)
                      :pod-cidr (if (plusp (length cidrs)) (aref cidrs 0) primary)
                      :pod-cidrs (copy-seq cidrs)
                      :underlay-address (gethash "underlayAddress" object "")
                      :wireguard-public-key wireguard-public-key
                      :wireguard-endpoints
                      (loop for endpoint across (gethash "wireguardEndpoints" object #())
                            collect (list (gethash "name" endpoint)
                                          (gethash "address" endpoint)
                                          (gethash "port" endpoint)))
                      :wireguard-reflexive-observed-at
                      (let ((time (gethash "wireguardReflexiveObservedAt" object)))
                        (when (integerp time) time))
                      :kubelet-port (let ((port (gethash "kubeletPort" object 0))) (if (integerp port) port 0))
                      :machine-id (gethash "machineID" object "")
                      :system-uuid (gethash "systemUUID" object "")
                      :boot-id (gethash "bootID" object "")
                      :kernel-version (gethash "kernelVersion" object "")
                      :os-image (gethash "osImage" object "")
                      :runtime-version (gethash "containerRuntimeVersion" object "")
                      :control-plane-p (eq t (gethash "controlPlane" object))
                      :last-heartbeat (when (integerp heartbeat) heartbeat)
                      :lease-deadline (when (integerp deadline) deadline)
                      :ready-since (when (and persisted-ready-p
                                              (integerp ready-since))
                                     ready-since)
                      :labels (gethash "labels" object)
                      :annotations (gethash "annotations" object)
                      :certificate-issuer-fingerprint
                      (gethash "certificateIssuerFingerprint" object)
                      :resource-version (gethash "resourceVersion" object "1")
                      :capacity (gethash "capacity" object)
                      :allocatable (gethash "allocatable" object)
                      :extended-resources (gethash "extendedResources" object)
                      :taints (gethash "taints" object #())
                      :unschedulable (eq t (gethash "unschedulable" object))
                      :api-only (eq t (gethash "apiOnly" object))
                      :api-status (gethash "apiStatus" object)
                      :creation-timestamp (let ((time (gethash "creationTimestamp" object)))
                                            (and (stringp time) time))
                      :ready-p persisted-ready-p)))))

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
  (when (pod-stage-active-p store)
    (stage-pod-write store pod :desired t)
    (return-from persist-pod pod))
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
      (com.inuoe.jzon:stringify (pod-to-object pod) :stream stream)
      (finish-output stream)
      (sb-posix:fsync (sb-sys:fd-stream-fd stream)))
    (uiop:rename-file-overwriting-target temporary target)
    ;; Persist the rename itself: without the directory fsync a power cut after
    ;; RENAME can lose it on some filesystems, matching the durable WAL path.
    (sync-store-generation-directory (store-data-path store)))
  pod)

(defun persist-node (store node)
  "Atomically persist NODE in STORE's node directory."
  (when (pod-stage-active-p store)
    (stage-node-write store (node-record-name node))
    (return-from persist-node node))
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
      (com.inuoe.jzon:stringify (node-record-to-object node) :stream stream)
      (finish-output stream)
      (sb-posix:fsync (sb-sys:fd-stream-fd stream)))
    (uiop:rename-file-overwriting-target temporary target)
    (sync-store-generation-directory (nodes-path store)))
  node)

(defun index-pod (store pod)
  "Install POD in STORE's namespace/name index and return it."
  (setf (gethash (pod-key (pod-namespace pod) (pod-name pod))
                 (pod-store-pods store))
        pod)
  ;; The transaction freezes this key after its final state and watch revision
  ;; have been assigned. The committed apply path publishes it on every replica.
  (note-pod-desired-change store pod)
  pod)

;;; ---------------------------------------------------------------------------
;;; HA Pod state replication (podster-8ia.2).
;;;
;;; Pods live outside the core-resource index: each is persisted in its own file,
;;; and the persisted object is desired state while agent observations are kept
;;; separately and merged on read. The replicated blob carries both: followers
;;; reconcile Pod files/indexes and install changed observations, so any member's
;;; local API serves the same phase and container status. Only changed observations
;;; propose a blob; unchanged periodic reports do not churn the Raft log.

(defun pod-state-json (store)
  "Serialize every Pod's authoritative desired state and current observation."
  (com.inuoe.jzon:stringify
   (let ((table (make-hash-table :test #'equal)))
     (setf (gethash "pods" table)
           (coerce (loop for pod being the hash-values of (pod-store-pods store)
                         collect (pod-to-object pod))
                   'vector)
           (gethash "resourceVersion" table)
           (write-to-string (pod-store-pod-revision store))
           (gethash "observations" table)
           (coerce
            (loop for pod being the hash-values of (pod-store-pods store)
                  for uid = (pod-uid pod)
                  for status = (gethash uid (pod-store-pod-observed-statuses store))
                  when status
                    collect (store-json-object
                             "uid" uid
                             "resourceVersion"
                             (or (gethash uid (pod-store-pod-observed-resource-versions store))
                                 (pod-resource-version pod))
                             "status" status))
            'vector)
           ;; API watches consume the derived status, not the raw agent report.
           ;; Carry both it and the revision assigned when it was published so
           ;; every HA member can expose the same resumable transition.
           (gethash "published" table)
           (coerce
            (loop for pod being the hash-values of (pod-store-pods store)
                  for uid = (pod-uid pod)
                  collect (store-json-object
                           "uid" uid
                           "resourceVersion"
                           (write-to-string (or (pod-status-revision pod)
                                               (parse-integer (pod-resource-version pod))))
                           "status"
                           (or (gethash uid (pod-store-pod-published-statuses store))
                               (pending-pod-status))))
            'vector))
     table)))

(defun pod-desired-state-json (store)
  "Compatibility name for the complete replicated Pod state blob."
  (pod-state-json store))

(defun note-pod-state-change (store pod)
  "Mark one Pod for replicated observation/publication after releasing the lock."
  (when (pod-stage-active-p store) (stage-pod-write store pod :status t)))

(defun note-pod-desired-change (store pod)
  "Mark one desired Pod key, never the complete Pod index."
  (when (pod-stage-active-p store) (stage-pod-write store pod :desired t)))

(defun replicated-pod-entry-table (entries)
  "Index replicated ENTRIES by their Pod UID."
  (let ((table (make-hash-table :test #'equal)))
    (loop for entry across entries
          for uid = (and (hash-table-p entry) (gethash "uid" entry))
          when (stringp uid) do (setf (gethash uid table) entry))
    table))

(defun replicated-pod-revision (text &optional (default 0))
  "Parse a replicated Pod revision TEXT, returning DEFAULT when absent or invalid."
  (if (and (stringp text) (plusp (length text)) (every #'digit-char-p text))
      (parse-integer text)
      default))

(defun advance-replicated-pod-revision-unlocked (store revision)
  "Advance STORE to replicated REVISION and durably prevent its reuse after failover."
  (when (> revision (pod-store-pod-revision store))
    (setf (pod-store-pod-revision store) revision))
  (when (> revision (pod-store-pod-revision-ceiling store))
    (let ((ceiling (+ revision *pod-revision-reservation*)))
      (write-text-atomically
       (pod-revision-ceiling-path store) (write-to-string ceiling))
      (setf (pod-store-pod-revision-ceiling store) ceiling))))

(defun local-replicated-pod-event-revision-unlocked (store incoming-revision)
  "Return a local watch revision for an incoming replicated transition.
Members allocate revisions concurrently for the agent sessions they own.  Reuse
the incoming number only when it is newer than every revision this member has
served; otherwise allocate a fresh local number so an existing ListWatch
checkpoint cannot hide the transition."
  (if (> incoming-revision (pod-store-pod-revision store))
      (progn
        (advance-replicated-pod-revision-unlocked store incoming-revision)
        incoming-revision)
      (next-pod-revision-unlocked store)))

(defun clear-replicated-pod-state-unlocked (store pod)
  "Forget every replicated observation belonging to POD's UID."
  (let ((uid (pod-uid pod)))
    (remhash uid (pod-store-pod-observed-statuses store))
    (remhash uid (pod-store-pod-observed-resource-versions store))
    (remhash uid (pod-store-pod-observed-phases store))
    (remhash uid (pod-store-pod-published-statuses store))))

(defun install-pod-state-blob (store json)
  "Install a legacy complete Pod snapshot. New transactions use per-Pod deltas."
  (bt:with-lock-held ((pod-store-lock store))
    (install-pod-state-object-unlocked store (com.inuoe.jzon:parse json))))

(defun install-pod-state-object-unlocked (store state &key partial)
  "Install a replicated Pod state snapshot and publish its exact watch transitions.
The snapshot watermark and published statuses make ListWatch behavior identical on
every HA member, including a member that did not own the reporting agent session."
  (let* ((observations (replicated-pod-entry-table (gethash "observations" state #())))
           (published (replicated-pod-entry-table (gethash "published" state #())))
           (watermark (replicated-pod-revision (gethash "resourceVersion" state)))
           (seen (make-hash-table :test #'equal)))
      (let ((*core-write-active* nil))
        (loop for object across (gethash "pods" state)
              for pod = (store-parse-pod object)
              for key = (pod-key (pod-namespace pod) (pod-name pod))
              for old = (gethash key (pod-store-pods store))
              for old-view = (and old (pod-published-view store old))
              for uid = (pod-uid pod)
              for stale-desired-state-p =
                (and old
                     (equal uid (pod-uid old))
                     (< (replicated-pod-revision (pod-resource-version pod))
                        (replicated-pod-revision (pod-resource-version old))))
              for observation = (gethash uid observations)
              for publication = (gethash uid published)
              for desired-revision = (replicated-pod-revision (pod-resource-version pod))
              for published-revision = (replicated-pod-revision
                                         (and publication (gethash "resourceVersion" publication))
                                         desired-revision)
              for incoming-revision = (max desired-revision published-revision)
              for previous-local-revision = (and old-view
                                                 (replicated-pod-revision
                                                  (gethash "resourceVersion"
                                                           (gethash "metadata" old-view))))
              do (setf (gethash key seen) t)
                 (unless stale-desired-state-p
                   (when publication
                     ;; Compare API contents while retaining the follower's local
                     ;; revision.  Incoming revisions are member-local and may be
                     ;; lower without representing an older object here.
                     (setf (pod-status-revision pod)
                           (or previous-local-revision published-revision)))
                   (persist-pod store pod)
                   (index-pod store pod)
                   (clear-replicated-pod-state-unlocked store pod)
                   (when observation
                     (let ((status (gethash "status" observation))
                           (revision (gethash "resourceVersion" observation)))
                       (when (and (hash-table-p status) (stringp revision))
                         (let ((copy (copy-pod-status-value status)))
                           (persist-pod-status-state
                            store pod :status copy :resource-version revision)
                           (setf (gethash uid (pod-store-pod-observed-statuses store)) copy
                                 (gethash uid (pod-store-pod-observed-resource-versions store)) revision
                                 (gethash uid (pod-store-pod-observed-phases store))
                                 (gethash "phase" copy "Unknown"))))))
                   (when publication
                     (setf (gethash uid (pod-store-pod-published-statuses store))
                           (copy-pod-status-value (gethash "status" publication))))
                   (let ((new-view (pod-published-view store pod)))
                     (when (and old-view (json-value-equal-p old-view new-view))
                       (persist-pod-publication store pod))
                     (unless (and old-view (json-value-equal-p old-view new-view))
                       (let ((event-revision
                               (local-replicated-pod-event-revision-unlocked
                                store incoming-revision)))
                         (persist-pod-publication store pod :revision event-revision)
                         (setf (pod-status-revision pod) event-revision
                               new-view (pod-published-view store pod))
                         (record-pod-watch-event-unlocked
                          store event-revision old-view new-view))))))
        ;; Drop Pods the committed snapshot no longer has, journalling deletion
        ;; at the snapshot watermark so a resumed watch cannot silently miss it.
        (unless partial
         (loop for key being the hash-keys of (pod-store-pods store)
              for pod = (gethash key (pod-store-pods store))
              unless (gethash key seen)
                do (let ((old-view (pod-published-view store pod)))
                     (ignore-errors (delete-file (pod-path store pod)))
                     (ignore-errors (delete-file (pod-publication-path store (pod-uid pod))))
                     (remhash key (pod-store-pods store))
                     (clear-replicated-pod-state-unlocked store pod)
                     (record-pod-watch-event-unlocked
                      store
                      (local-replicated-pod-event-revision-unlocked store watermark)
                      old-view nil))))
      (advance-replicated-pod-revision-unlocked store watermark))))

;;; ---------------------------------------------------------------------------
;;; HA node desired-state replication (podster-8ia.4).
;;;
;;; Node records mix desired state (the control-plane-assigned podCIDR, taints,
;;; labels) with observed state (ready/lastHeartbeat/leaseDeadline, re-reported by
;;; the agent). Desired writes, readiness transitions, and deadline renewals
;;; replicate. Every member runs the expiry monitor, so all must see the deadline
;;; even though only one member owns a particular agent stream.
;;; The critical durable field is podCIDR: a new leader must keep it or it could
;;; hand the node a different CIDR than the one its agent is already running.

(defun node-desired-state-json (store)
  "Serialize every node record for replication."
  (com.inuoe.jzon:stringify
   (let ((table (make-hash-table :test #'equal)))
     (setf (gethash "nodes" table)
           (coerce (loop for node being the hash-values of (pod-store-nodes store)
                         collect (node-record-to-object node))
                   'vector))
     table)))

(defun node-replicated-object (node)
  (when node
    (let ((object (node-record-to-object node)))
      (setf (gethash "runtimeDownMessage" object) (node-record-runtime-down-message node))
      object)))

(defun node-state-delta-json (changes &optional revision)
  "Serialize the Nodes actually changed by one transaction. A missing named
Node is a tombstone. Unrelated stale member state never enters the command."
  (com.inuoe.jzon:stringify
   (store-json-object
    "version" (if *pod-write-context* 2 1)
    "resourceVersion" (write-to-string (or revision 0))
    "changes"
    (coerce
     (loop for (name . object-json) in (reverse changes)
           collect (store-json-object "name" name
                                "expected" (or (and *pod-write-context*
                                                    (node-replicated-object
                                                     (gethash name (pod-write-context-nodes *pod-write-context*))))
                                               'null)
                                "object" (if object-json
                                             (com.inuoe.jzon:parse object-json)
                                             'null)))
     'vector))))

(defun note-node-state-change (store node-or-name)
  "Record the one Node changed by this transaction for replication after the
store lock is released. NODE-OR-NAME may name a just-deleted Node. Heartbeat
renewals use the same compact one-key delta without changing resourceVersion."
  (when (and *core-write-active* (pod-store-consensus-commit-fn store))
    (let* ((name (etypecase node-or-name
                   (node-record (node-record-name node-or-name))
                   (string node-or-name)))
           (node (gethash name (pod-store-nodes store)))
           ;; Freeze the changed value while the store lock is held. Raft apply
           ;; threads do not take the author-side consensus lock, so serializing
           ;; the live hash table after releasing this lock would race them.
           (object-json (and node
                             (com.inuoe.jzon:stringify
                              (node-replicated-object node)))))
      (setf *pending-node-commit*
            (acons name object-json
                   (remove name *pending-node-commit* :key #'car :test #'equal))))))

(defun note-node-desired-change (store node-or-name)
  "Replicate a node desired-state write after STORE's lock is released."
  (note-node-state-change store node-or-name))

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

(defparameter +node-volatile-comparison-fields+
  '("resourceVersion" "lastHeartbeat" "leaseDeadline" "readySince"
    "ready" "runtimeDownMessage"
    ;; Standard kubelet nodeInfo: single-author session state the owning
    ;; member learns from the hello, so it must not drive CAS verdicts on
    ;; other members (same reasoning as readiness; podster-uvs/zu3/k4t).
    "machineID" "systemUUID" "bootID" "kernelVersion" "osImage"
    "containerRuntimeVersion" "controlPlane")
  "Fields the replicated-node CAS comparison ignores: the commit revision, the
lease clock, and the lease-DERIVED session state (ready, runtimeDownMessage).
The clock renews every few seconds on the session-owning member, and every
member's expiry monitor flips readiness locally at its own pace, so including
any of them gives member-dependent conflict verdicts: a replica that once
believed a node NotReady skipped every later heartbeat delta (whose expected
image said Ready) forever -- even a replica freshly rebuilt from the leader's
snapshot re-forked within seconds. These fields are single-author session
state derived from the clock, not CAS-protected content (podster-uvs,
podster-zu3).")

(defun node-object-same-state-p (left right)
  "Compare a retry's desired state independently of its assigned commit revision
and the volatile lease clock. The verdict decides whether a committed delta
installs, so it must come out identical on every member (podster-uvs)."
  (if (and (hash-table-p left) (hash-table-p right))
      (let ((a (copy-pod-status-value left)) (b (copy-pod-status-value right)))
        (dolist (field +node-volatile-comparison-fields+)
          (remhash field a)
          (remhash field b))
        (json-value-equal-p a b))
      (eq left right)))

(defun node-public-change-p (old new)
  (if (and old new)
      (let ((copy (copy-pod-status-value new)))
        (setf (gethash "resourceVersion" (gethash "metadata" copy))
              (gethash "resourceVersion" (gethash "metadata" old)))
        (not (json-value-equal-p old copy)))
      (not (eq old new))))

(defun node-delta-claims-available-p (store changes)
  "Validate the final Node set before publishing any member of a delta."
  (let ((nodes (make-hash-table :test #'equal))
        (identities (make-hash-table :test #'equal))
        (cidrs (make-hash-table :test #'equal))
        (underlays (make-hash-table :test #'equal)))
    (maphash (lambda (name node) (setf (gethash name nodes) node)) (pod-store-nodes store))
    ;; Apply replacements and tombstones to the candidate index first, allowing
    ;; one atomic delta to release a claim and assign it to another Node.
    (loop for change across changes
          for name = (gethash "name" change)
          for object = (gethash "object" change)
          do (if (eq object 'null) (remhash name nodes)
                 (setf (gethash name nodes) (parse-node-record object :expire-leases nil))))
    (block validate
      (labels ((claim (table value name)
                 (when (and (stringp value) (plusp (length value)))
                   (let ((owner (gethash value table)))
                     (when (and owner (not (equal owner name)))
                       (return-from validate nil))
                     (setf (gethash value table) name)))))
        (maphash
         (lambda (name node)
           (unless (equal name (node-record-name node)) (return-from validate nil))
           (claim identities (node-record-id node) name)
           (claim underlays (node-record-underlay-address node) name)
           (loop for cidr across (node-record-all-pod-cidrs node)
                 do (claim cidrs cidr name)))
         nodes)
        t))))

(defun install-node-state-delta (store json)
  "Validate all Node preconditions, then publish in committed revision order."
  (bt:with-lock-held ((pod-store-lock store))
    (let* ((delta (com.inuoe.jzon:parse json))
           (changes (gethash "changes" delta #()))
           (checked (eql 2 (gethash "version" delta)))
           (*core-write-active* nil)
           (results nil))
      (when checked
        (loop for change across changes
              for current = (or (node-replicated-object
                                 (gethash (gethash "name" change) (pod-store-nodes store))) 'null)
              unless (or (node-object-same-state-p current (gethash "expected" change))
                         (node-object-same-state-p current (gethash "object" change)))
                do ;; A skipped committed delta must be visible in the journal:
                   ;; members silently dropping deltas is how replica divergence
                   ;; went unnoticed for hours (podster-uvs).
                   (format *error-output*
                           "~&gr8s: committed node delta for ~A conflicts with this member's state; skipped~%"
                           (gethash "name" change))
                   (return-from install-node-state-delta (list :node-conflict))))
      (when (and checked (not (node-delta-claims-available-p store changes)))
        (format *error-output*
                "~&gr8s: committed node delta refused: it claims an identity, address or CIDR another node holds~%")
        (return-from install-node-state-delta (list :node-conflict)))
      (loop for change across changes
            for name = (gethash "name" change)
            for object = (gethash "object" change)
            for existing = (gethash name (pod-store-nodes store))
            for old = (and existing (funcall (store-policy-node-view *store-policy*) existing))
            do (let ((new nil) (revision nil))
                 (if (eq object 'null)
                     (when existing
                       (setf revision (max (1+ (pod-store-pod-revision store))
                                       (replicated-pod-revision (gethash "resourceVersion" delta))))
                       (let ((path (node-path store existing)))
                         (when (probe-file path) (delete-file path)))
                       (remhash name (pod-store-nodes store)))
                     (let ((node (parse-node-record object :expire-leases nil)))
                       (setf (node-record-runtime-down-message node) (gethash "runtimeDownMessage" object))
                       (let* ((candidate (funcall (store-policy-node-view *store-policy*) node))
                              (changed (node-public-change-p old candidate)))
                         (setf (node-record-resource-version node)
                               (if changed
                                   (write-to-string
                                    (max (1+ (pod-store-pod-revision store))
                                     (replicated-pod-revision (node-record-resource-version node))))
                                   (node-record-resource-version existing))))
                       (persist-node store node)
                       (setf (gethash name (pod-store-nodes store)) node
                             new (funcall (store-policy-node-view *store-policy*) node)
                             revision (replicated-pod-revision (node-record-resource-version node)))
                       (push (list name (node-record-resource-version node)) results)))
                 (when revision
                   (advance-replicated-pod-revision-unlocked store revision)
                   (unless (json-value-equal-p old new)
                     (funcall (store-policy-node-event *store-policy*) store revision old new)))))
      (save-consensus-pod-revision-unlocked store)
      (list :node-ok (nreverse results)))))

(defun load-store-application-files (store)
  "Load the selected application's files into empty indexes; caller owns synchronization."
    (ensure-directories-exist (nodes-path store))
    (dolist (file (directory (merge-pathnames "*.json" (store-data-path store))))
      (index-pod store (store-parse-pod file)))
    (dolist (file (directory (merge-pathnames "*.json" (nodes-path store))))
      (let ((node (parse-node-record file)))
        (setf (gethash (node-record-name node) (pod-store-nodes store)) node)))
    (funcall (store-policy-load-resources *store-policy*) store)
    (load-pod-status-state store)
    (load-pod-revision store)
    (load-consensus-pod-revision store)
    (let ((boundary (merge-pathnames "metadata/snapshot-boundary.json" (store-data-path store))))
      (when (store-generation-stat boundary)
        (let ((floor (gethash "podEpochFloor" (read-private-generation-json boundary) 0)))
          (unless (typep floor `(integer 0 ,(pod-store-pod-revision store)))
            (error "Invalid restored Pod revision epoch"))
          (setf (pod-store-pod-revision-epoch-floor store) floor))))
    (load-pod-publications store)
  store)

(defun open-store (path &key defer-restore-completion)
  "Load the selected application. HA defers intent completion to WAL validation."
  (let* ((directory (uiop:ensure-directory-pathname path))
         (store (make-pod-store directory))
         (restore nil))
    (ensure-directories-exist directory)
    (setf restore (resume-store-restore-selection directory))
    (setf (pod-store-data-root store) (selected-store-generation-root directory))
    (load-store-application-files store)
    (when (and restore (not defer-restore-completion)) (finish-store-restore store restore))
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

(defgeneric list-pods (store &optional namespace)
  (:documentation "A consistent snapshot of Pods, optionally restricted to NAMESPACE.
Part of the desired-state read seam: STORE is the gr8s store, or a foreign
cluster's watch cache."))

(defmethod list-pods ((store pod-store) &optional namespace)
  (with-store-lock (store)
    (loop for pod being the hash-values of (pod-store-pods store)
          when (or (null namespace) (string= namespace (pod-namespace pod)))
            collect pod)))

(defgeneric pod-reported-status (store pod)
  (:documentation "POD's latest reported status object, or NIL.  Part of the
desired-state read seam: the gr8s store keeps agent observations beside the Pod,
while a foreign cluster carries status inside the watched Pod object."))

(defmethod pod-reported-status ((store pod-store) pod)
  (with-store-lock (store)
    (gethash (pod-uid pod) (pod-store-pod-observed-statuses store))))

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
    ;; Controllers create Pods here directly, and the API server applies the
    ;; same admission/defaulting policy to every Pod it creates.
    (funcall (store-policy-prepare-create *store-policy*) store pod)
    (assign-generated-pod-name-unlocked store pod)
    (when (gethash (pod-key (pod-namespace pod) (pod-name pod))
                   (pod-store-pods store))
      (error 'kubernetes-error
             :status-code 409
             :reason "AlreadyExists"
             :message (format nil "Pod ~A already exists" (pod-name pod))))
    ;; The creating manager owns every field it set, the defaults included, as upstream records it.
    (when *apply-update-manager*
      (funcall (store-policy-track-create *store-policy*) pod))
    (let ((metadata (gethash "metadata" (pod-to-object pod))))
      (remhash "deletionTimestamp" metadata)
      (remhash "deletionGracePeriodSeconds" metadata)
      (setf (pod-uid pod) (generate-uid)
            (pod-resource-version pod)
            (write-to-string (next-pod-revision-unlocked store))
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
      (unless (pod-revision-satisfied-p
               store expected-resource-version actual)
        (error 'kubernetes-error
               :status-code 409
               :reason "Conflict"
               :message (format nil "expected resourceVersion ~A, found ~A"
                                expected-resource-version actual)))
      (funcall (store-policy-prepare-update *store-policy*) existing replacement)
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
        ;; A client's write comes to own what it changed, and one that omits managedFields keeps them.
        (when *apply-update-manager*
          (funcall (store-policy-track-update *store-policy*) existing replacement))
        ;; An unchanged Pod keeps its revision and sends no watch event, as upstream.
        (setf (pod-uid replacement) (pod-uid existing)
              (gethash "namespace" metadata) (pod-namespace replacement)
              (gethash "uid" metadata) (pod-uid replacement)
              (gethash "creationTimestamp" metadata) (gethash "creationTimestamp" existing-metadata))
        (when (funcall (store-policy-unchanged-p *store-policy*)
                       (pod-to-object existing) (pod-to-object replacement))
          (return-from update-pod-unlocked existing))
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
  "Remove a Pod through the HA transaction boundary."
  (with-store-lock (store) (remove-pod-unlocked store namespace name :uid uid)))

(defun remove-pod-unlocked (store namespace name &key uid)
  "Remove a Pod and its observed status from STORE, returning the removed Pod."
  (let ((pod (get-pod-unlocked store namespace name)))
      (when (and uid (not (equal uid (pod-uid pod))))
        (error 'kubernetes-error :status-code 409 :reason "Conflict" :message "Pod UID changed before removal"))
      (when (funcall (store-policy-retained-p *store-policy*) pod)
        (error 'kubernetes-error :status-code 409 :reason "Conflict" :message "Pod finalizers still retain this object"))
      (when (pod-stage-active-p store) (stage-pod-write store pod :desired t))
      (unless (pod-stage-active-p store)
       (let ((status-path (pod-status-state-path store (pod-uid pod))))
        (when (probe-file status-path) (delete-file status-path)))
       (delete-file (pod-path store pod))
       (let ((publication (pod-publication-path store (pod-uid pod))))
         (when (store-generation-stat publication) (sb-posix:unlink (namestring publication)))))
      (remhash (pod-key namespace name) (pod-store-pods store))
      (publish-pod-removal-unlocked store pod)
      ;; Serialize only after allocating the deletion's watch revision; followers
      ;; need that watermark to replay the tombstone to a resumed ListWatch.
      (note-pod-desired-change store pod)
      (remhash (pod-uid pod) (pod-store-pod-finalization-states store))
      (remhash (pod-uid pod) (pod-store-pod-observed-phases store))
      (remhash (pod-uid pod) (pod-store-pod-observed-statuses store))
      (remhash (pod-uid pod) (pod-store-pod-observed-resource-versions store))
      (remhash (pod-uid pod) (pod-store-pod-condition-histories store))
      (remhash (pod-uid pod) (pod-store-pod-client-statuses store))
      (remhash (pod-uid pod) (pod-store-nominated-nodes store))
      (remhash (pod-uid pod) (pod-store-scheduling-notes store))
      pod))

(defun delete-pod (store namespace name)
  "Delete and return the Pod named NAME in NAMESPACE."
  (remove-pod store namespace name))

(defun mark-pod-deleting (store namespace name &key uid resource-version
                                                (grace-period nil grace-supplied-p)
                                                dry-run)
  "Set a Pod's deletion timestamp, advance its resource version, and persist it."
  (with-store-lock (store)
    (let* ((existing (get-pod-unlocked store namespace name))
           (pod (store-parse-pod
                 (com.inuoe.jzon:parse
                  (com.inuoe.jzon:stringify (pod-to-object existing)))))
           (metadata (gethash "metadata" (pod-to-object pod))))
      (when (and uid (not (equal uid (pod-uid pod))))
        (error 'kubernetes-error :status-code 409 :reason "Conflict"
               :message "Pod UID no longer matches deletion precondition"))
      (when (and resource-version
                 (not (pod-revision-satisfied-p
                       store resource-version (pod-resource-version pod))))
        (error 'kubernetes-error :status-code 409 :reason "Conflict"
               :message "Pod resourceVersion no longer matches deletion precondition"))
      (unless (funcall (store-policy-prepare-deletion *store-policy*)
                       store pod grace-period grace-supplied-p)
        (return-from mark-pod-deleting pod))
      (unless dry-run
        (let ((next-version
                (write-to-string (next-pod-revision-unlocked store)))
              (old (pod-published-view store existing)))
          (setf (gethash "resourceVersion" metadata) next-version
                (pod-resource-version pod) next-version)
          (persist-pod store pod)
          (index-pod store pod)
          (publish-pod-spec-change-unlocked store old pod)))
      pod)))
