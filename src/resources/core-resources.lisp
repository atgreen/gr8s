;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Durable storage and create/read/update/delete for the Kubernetes core, typed,
;;;; and custom resources the API server serves (the collections in
;;;; *stored-resource-types*: ConfigMaps, Secrets, Namespaces, RBAC, workloads,
;;;; Gateway and cert-manager kinds, and the rest).
;;;;
;;;; State lives in memory as an index keyed by (resource namespace name) and is
;;;; made durable by a checkpoint (objects/state.json) plus an append-only journal
;;;; (objects/journal.jsonl): each commit appends only what it changed, and a new
;;;; checkpoint is rewritten once the journal outgrows its bound, so a commit costs
;;;; a bounded multiple of what it touched whatever the store's total size. Only
;;;; the last journal record can be torn -- by a crash mid-append -- and damage
;;;; anywhere else is an error. On an HA store a commit instead stashes the full
;;;; state blob for the caller to replicate through Raft once the lock is released,
;;;; and every member reinstalls it; high-churn, self-expiring kinds (events) are
;;;; kept off the consensus plane (podster-8ia.3) but still live in the on-disk
;;;; state. Objects are copied at the store boundary so callers cannot mutate
;;;; indexed state; writes run under WITH-CORE-WRITE with optimistic
;;;; resourceVersion concurrency and mirror upstream validation, immutability,
;;;; finalizer, and resource-quota semantics.

(in-package #:gr8s.resources)

(defvar *core-resource-view-version* nil)

(defvar *typed-api-status-write* nil
  "True only while a status subresource write replaces a typed object's or Namespace's status.")

(defvar *resource-quota-admission-exempt* nil
  "True while the server creates its own bootstrap objects, which are counted but never refused.")

(defvar *crd-view-definition* nil)
(defvar *crd-request-version* nil)
(defvar *crd-view-store* nil
  "The store of the current custom resource request, whose Services route conversion webhooks.")
(defvar *crd-conversion-deferred* nil
  "True inside a store transaction, where a conversion webhook must not be called.")
(defvar *crd-conversion-memo* nil
  "Conversions this request has already obtained, keyed by object content and target.")

(define-condition crd-conversion-needed (serious-condition)
  ((definition :initarg :definition :reader crd-conversion-needed-definition)
   (objects :initarg :objects :reader crd-conversion-needed-objects)
   (target :initarg :target :reader crd-conversion-needed-target))
  (:documentation "A store transaction needs a webhook conversion it has not got yet."))

(defparameter +crd-conversion-transaction-attempts+ 16
  "Times a store transaction may restart to obtain conversions before giving up.")

(defmacro with-crd-deferred-conversions (&body body)
  "Run the store transaction BODY, restarting it outside the lock whenever it needs a conversion."
  (let ((run (gensym "RUN")) (done (gensym "DONE")))
    `(flet ((,run () ,@body))
       (if *crd-conversion-deferred*
           (,run)
           (let ((*crd-conversion-memo* *crd-conversion-memo*))
             (block ,done
               (loop repeat +crd-conversion-transaction-attempts+
                     do (handler-case
                            (let ((*crd-conversion-deferred* t)) (return-from ,done (,run)))
                          (crd-conversion-needed (condition) (crd-perform-deferred-conversion condition))))
               (core-resource-error 500 "InternalError" "Custom resource conversion did not settle")))))))

;; Core and bootstrap resources share a durable transaction and revision sequence.
;; Objects are copied at the boundary so clients cannot mutate indexed state.
(defun core-object (&rest pairs)
  "Return an EQUAL hash table holding the flat KEY VALUE PAIRS -- gr8s's JSON-object constructor."
  (let ((object (make-hash-table :test #'equal)))
    (loop for (key value) on pairs by #'cddr do (setf (gethash key object) value))
    object))

(defun copy-core-object (object)
  "Return a deep copy of a parsed-JSON value: hash tables, strings, and vectors are
   copied recursively so nothing is shared with OBJECT; other atoms are returned as is."
  (cond ((hash-table-p object)
         (let ((copy (make-hash-table :test #'equal)))
           (maphash (lambda (key value) (setf (gethash (copy-seq key) copy) (copy-core-object value))) object)
           copy))
        ((stringp object) (copy-seq object))
        ((vectorp object) (map 'vector #'copy-core-object object))
        (t object)))

(defparameter *stored-resource-types*
  '(("configmaps" "ConfigMap" "v1" t)
    ("secrets" "Secret" "v1" t)
    ("namespaces" "Namespace" "v1" nil)
    ("serviceaccounts" "ServiceAccount" "v1" t)
    ("services" "Service" "v1" t)
    ("podtemplates" "PodTemplate" "v1" t)
    ("replicationcontrollers" "ReplicationController" "v1" t)
    ("events" "Event" "v1" t)
    ("deployments" "Deployment" "apps/v1" t)
    ("replicasets" "ReplicaSet" "apps/v1" t)
    ("daemonsets" "DaemonSet" "apps/v1" t)
    ("statefulsets" "StatefulSet" "apps/v1" t)
    ("controllerrevisions" "ControllerRevision" "apps/v1" t)
    ("jobs" "Job" "batch/v1" t)
    ("poddisruptionbudgets" "PodDisruptionBudget" "policy/v1" t)
    ("cronjobs" "CronJob" "batch/v1" t)
    ("mutatingwebhookconfigurations" "MutatingWebhookConfiguration" "admissionregistration.k8s.io/v1" nil)
    ("validatingwebhookconfigurations" "ValidatingWebhookConfiguration" "admissionregistration.k8s.io/v1" nil)
    ("roles" "Role" "rbac.authorization.k8s.io/v1" t)
    ("rolebindings" "RoleBinding" "rbac.authorization.k8s.io/v1" t)
    ("clusterroles" "ClusterRole" "rbac.authorization.k8s.io/v1" nil)
    ("clusterrolebindings" "ClusterRoleBinding" "rbac.authorization.k8s.io/v1" nil)
    ("networkpolicies" "NetworkPolicy" "networking.k8s.io/v1" t)
    ("gatewayclasses" "GatewayClass" "gateway.networking.k8s.io/v1" nil)
    ("gateways" "Gateway" "gateway.networking.k8s.io/v1" t)
    ("httproutes" "HTTPRoute" "gateway.networking.k8s.io/v1" t)
    ("tcproutes" "TCPRoute" "gateway.networking.k8s.io/v1" t)
    ("tlsroutes" "TLSRoute" "gateway.networking.k8s.io/v1" t)
    ("grpcroutes" "GRPCRoute" "gateway.networking.k8s.io/v1" t)
    ("issuers" "Issuer" "cert-manager.io/v1" t)
    ("clusterissuers" "ClusterIssuer" "cert-manager.io/v1" nil)
    ("certificates" "Certificate" "cert-manager.io/v1" t)
    ("certificaterequests" "CertificateRequest" "cert-manager.io/v1" t)
    ;; KEP-3257/4317 trust distribution: cluster-scoped CA trust anchors a
    ;; signer publishes, consumed by the clusterTrustBundle projected volume
    ;; source. GA at certificates.k8s.io/v1 in Kubernetes 1.37, the version
    ;; Agent Substrate's client uses, alongside the v1 CertificateSigningRequest.
    ("clustertrustbundles" "ClusterTrustBundle" "certificates.k8s.io/v1" nil)
    ;; KEP-4317 PodCertificateRequest: the node asks a signer for a short-lived
    ;; pod X.509 (the podCertificate projected volume). Namespaced; the signer
    ;; fills status.certificateChain. Stored and served at certificates.k8s.io/v1
    ;; (GA in Kubernetes 1.37), and also served at v1beta1 for clients that have
    ;; not moved (Agent Substrate's controller).
    ("podcertificaterequests" "PodCertificateRequest" "certificates.k8s.io/v1" t)))

(defun stored-resource-type (resource)
  "Return the descriptor for a durable Kubernetes resource collection."
  (or (assoc resource *stored-resource-types* :test #'equal)
      (assoc resource *internal-stored-resource-types* :test #'equal)
      (error "Unknown stored resource ~S" resource)))

(defun core-resource-kind (resource)
  "Return the Kind string RESOURCE's objects serialize as (e.g. \"ConfigMap\" for
   \"configmaps\"); signals when RESOURCE is not a known stored collection."
  (second (stored-resource-type resource)))

(defun core-resource-api-version (resource)
  "Return the API version serialized for RESOURCE."
  (third (stored-resource-type resource)))

(defun core-resource-namespaced-p (resource)
  "Return whether RESOURCE is scoped to a namespace."
  (fourth (stored-resource-type resource)))

(defun core-resource-error (code reason control &rest arguments)
  "Signal a KUBERNETES-ERROR carrying HTTP status CODE and REASON, with a message
   formatted from CONTROL and ARGUMENTS. Does not return."
  (error 'kubernetes-error :status-code code :reason reason
         :message (apply #'format nil control arguments)))

(defun core-resource-key (resource namespace name)
  "Return the index key identifying one stored object: the list (RESOURCE NAMESPACE NAME)."
  (list resource namespace name))

(defun core-resource-state-path (store)
  "Return the pathname of STORE's core-resource checkpoint (objects/state.json)."
  (merge-pathnames "objects/state.json" (gr8s.store:store-data-path store)))

(defun core-journal-path (store)
  "The journal of commits made after the checkpoint at CORE-RESOURCE-STATE-PATH."
  (merge-pathnames "objects/journal.jsonl" (gr8s.store:store-data-path store)))

(defparameter *core-journal-checkpoint-bytes* (* 8 1024 1024)
  "Journal size past which the next commit writes a checkpoint and starts a new journal.
A journal may also grow to the size of the checkpoint, so writing checkpoints costs
each commit a bounded multiple of what it changed, whatever the size of the store.")

(defun core-resource-key-from-object (resource object)
  "Return the index key for OBJECT in collection RESOURCE, reading its namespace and
   name from OBJECT's metadata."
  (let ((metadata (gethash "metadata" object)))
    (core-resource-key resource (gethash "namespace" metadata) (gethash "name" metadata))))

(defun core-state-index (state)
  "Index a checkpoint's objects by key, as (resource . object) values, refusing duplicates."
  (let ((index (make-hash-table :test #'equal)))
    (flet ((add (resource object)
             (let ((key (core-resource-key-from-object resource object)))
               (when (gethash key index) (error "Duplicate persisted core resource ~S" key))
               (setf (gethash key index) object))))
      (loop for object across (gethash "items" state #())
            do (add (or (first (find (gethash "kind" object) (append *stored-resource-types* *internal-stored-resource-types*) :key #'second :test #'equal))
                        (error "Invalid stored resource kind"))
                    object))
      (loop for entry across (gethash "customResourceItems" state #())
            do (add (gethash "resource" entry) (gethash "object" entry))))
    index))

(defun apply-core-map-delta (map delta)
  "Return a copy of MAP with a journal record's map DELTA applied."
  (let ((result (make-hash-table :test #'equal)))
    (maphash (lambda (key value) (setf (gethash key result) value)) map)
    (maphash (lambda (key value) (setf (gethash key result) value)) (gethash "set" delta (core-object)))
    (loop for key across (gethash "delete" delta #()) do (remhash key result))
    result))

(defun make-core-journal-reader (stream path)
  "Return a record iterator over binary STREAM. Second/third values report a torn
final record and the byte offset after the last complete record. Memory is bounded
by one record, not the journal size. Only newline-terminated records are parsed."
  (let ((buffer (make-array 1024 :element-type '(unsigned-byte 8)
                                 :adjustable t :fill-pointer 0))
        (bytes 0))
    (lambda ()
      (setf (fill-pointer buffer) 0)
      (loop for byte = (read-byte stream nil nil) do
        (cond
          ((null byte) (return (values nil (plusp (length buffer)) bytes)))
          ((= byte 10)
           (let ((record
                   (handler-case
                       (com.inuoe.jzon:parse
                        (trivial-utf-8:utf-8-bytes-to-string buffer)
                        :max-string-length (* 2 1024 1024))
                     (error (condition)
                       (error "Damaged core resource journal record at byte ~D of ~A: ~A"
                              bytes path condition)))))
             (setf bytes (file-position stream))
             (unless (hash-table-p record)
               (error "Invalid core resource journal record at byte ~D of ~A" bytes path))
             (return (values record nil bytes))))
          (t (vector-push-extend byte buffer)))))))

(defun read-core-journal-records (path)
  "Return complete records, torn-tail status, and complete bytes for inspection.
Startup instead passes the streaming iterator directly to REPLAY-CORE-JOURNAL."
  (with-open-file (stream path :element-type '(unsigned-byte 8))
    (let ((next (make-core-journal-reader stream path)) (records nil))
      (loop
        (multiple-value-bind (record torn bytes) (funcall next)
          (unless record (return (values (nreverse records) torn bytes)))
          (push record records))))))

(defun replay-core-journal (store state records)
  "Apply journal RECORDS newer than STATE's revision to STATE, a parsed checkpoint,
rebuilding the history a commit used to write. RECORDS may be a zero-argument
iterator instead of a list; its final values are returned after STATE."
  (let* ((index (core-state-index state))
         (history (coerce (gethash "templateHistory" state #()) 'list))
         (floor (gethash "templateHistoryFloor" state (gethash "revision" state)))
         (expirations (gethash "eventExpirations" state (make-hash-table :test #'equal)))
         (time nil) (torn nil) (bytes 0))
    (loop for record = (if (functionp records)
                          (multiple-value-bind (record tail complete)
                              (progn
                                ;; Large decoded strings can survive young-generation
                                ;; collections and fragment a constrained SBCL heap.
                                ;; Reclaim them before the next record needs space.
                                (when (> (sb-kernel:dynamic-usage)
                                         (* 2/3 (sb-ext:dynamic-space-size)))
                                  (sb-ext:gc :full t))
                                (funcall records))
                            (setf torn tail bytes complete) record)
                          (pop records))
          while record do
      (let ((revision (gethash "revision" record)))
        (when (> revision (gethash "revision" state))
          (setf time (gethash "time" record))
          (loop for change across (gethash "changes" record #())
                for key = (core-resource-key (gethash "resource" change)
                                             (let ((namespace (gethash "namespace" change)))
                                               (unless (eq namespace 'null) namespace))
                                             (gethash "name" change))
                for old = (gethash key index)
                for new = (let ((object (gethash "object" change)))
                            (unless (eq object 'null)
                              (decrypt-secret-object store (first key) object)))
                do (setf history
                         (nconc history
                                (list (core-object "revision" revision "time" time "resource" (first key)
                                                   "namespace" (second key) "name" (third key)
                                                   "old" (or old 'null) "new" (or new 'null)
                                                   "bytes" (template-history-old-bytes old)))))
                   (if new (setf (gethash key index) new) (remhash key index)))
          (maphash (lambda (uid expiry) (setf (gethash uid expirations) expiry))
                   (gethash "eventExpirations" record (core-object)))
          (dolist (field '("workloadDeletions" "jobControllerStates"))
            (let ((delta (gethash field record)))
              (when delta
                (setf (gethash field state)
                      (apply-core-map-delta (gethash field state (make-hash-table :test #'equal)) delta)))))
          (setf (gethash "revision" state) revision
                (gethash "resourceHistoryStart" state)
                (gethash "resourceHistoryStart" record (gethash "resourceHistoryStart" state revision)))
          ;; Bound transient history during replay too, not just after the last
          ;; record. Expired/superseded values must be collectible while reading.
          (multiple-value-bind (durable durable-floor)
              (let ((*podtemplate-clock* (constantly time)))
                (durable-template-history history floor))
            (setf history durable floor durable-floor)))))
    (when time
      ;; Trim as the last replayed commit would have when it wrote everything.
      (multiple-value-bind (durable durable-floor)
          (let ((*podtemplate-clock* (constantly time)))
            (durable-template-history history floor))
        (setf history durable floor durable-floor))
      (let ((events (make-hash-table :test #'equal)))
        (maphash (lambda (key object)
                   (when (equal "events" (first key))
                     (let ((uid (gethash "uid" (gethash "metadata" object))))
                       (when (gethash uid expirations) (setf (gethash uid events) (gethash uid expirations))))))
                 index)
        (setf expirations events))
      (setf (gethash "version" state) 2
            (gethash "templateHistory" state) (coerce history 'vector)
            (gethash "templateHistoryFloor" state) floor
            (gethash "eventExpirations" state) expirations
            (gethash "items" state)
            (coerce (loop for key being the hash-keys of index using (hash-value object)
                          unless (custom-resource-key-p (first key)) collect object) 'vector)
            (gethash "customResourceItems" state)
            (coerce (loop for key being the hash-keys of index using (hash-value object)
                          when (custom-resource-key-p (first key))
                            collect (core-object "resource" (first key) "object" object)) 'vector)))
    (values state torn bytes)))

(defun read-durable-core-state (store)
  "Return STORE's durable core-resource state in checkpoint form, the checkpoint with
its journal replayed, or NIL when nothing was committed. Second and third values:
whether the journal must be rewritten (a torn record) and its complete bytes."
  (let ((path (core-resource-state-path store)) (journal (core-journal-path store)))
    (when (probe-file path)
      (let ((state (com.inuoe.jzon:parse path :max-string-length (* 2 1024 1024))))
        (unless (and (member (gethash "version" state) '(1 2))
                     (typep (gethash "revision" state) '(integer 0 *)))
          (error "Invalid core resource state at ~A" path))
        (when (and (eql 2 (gethash "version" state))
                   (not (typep (gethash "resourceHistoryStart" state) `(integer 0 ,(gethash "revision" state)))))
          (error "Invalid resource history start at ~A" path))
        (setf (pod-store-secret-encryption-config store)
              (gethash "secretsEncryption" state))
        (decrypt-core-state-secrets store state)
        (if (probe-file journal)
            (with-open-file (stream journal :element-type '(unsigned-byte 8))
              (replay-core-journal store state (make-core-journal-reader stream journal)))
            (values state nil 0))))))

(defun load-core-resources (store)
  "Load STORE's durable core-resource state -- the checkpoint with its journal
   replayed -- into memory: set the revision, workload-deletion, job-controller,
   event-expiration, template-history and -floor, resource-history-start, template
   token key, and checkpoint/journal byte-count slots, then rebuild the resource
   index from the persisted items and custom-resource items. Signals on a duplicate
   persisted key, an unknown stored kind, or a persisted custom resource with no
   matching definition. A no-op leaving the store empty when nothing was ever
   committed. Returns STORE."
  (multiple-value-bind (state torn journal-bytes) (read-durable-core-state store)
    (when state
      (setf (pod-store-resource-revision store) (gethash "revision" state)
            (pod-store-workload-deletions store) (gethash "workloadDeletions" state (make-hash-table :test #'equal))
            (pod-store-job-controller-states store) (gethash "jobControllerStates" state (make-hash-table :test #'equal))
            (pod-store-event-expirations store) (gethash "eventExpirations" state (make-hash-table :test #'equal))
            (pod-store-template-history store) (coerce (gethash "templateHistory" state #()) 'list)
            (pod-store-template-history-floor store) (gethash "templateHistoryFloor" state (gethash "revision" state))
            (pod-store-resource-history-start store) (gethash "resourceHistoryStart" state (gethash "revision" state))
            (pod-store-template-token-key store) (when (gethash "templateTokenKey" state)
                                                   (ag-grpc:base64-decode (gethash "templateTokenKey" state)))
            (pod-store-core-checkpoint-bytes store) (with-open-file (stream (core-resource-state-path store))
                                                      (file-length stream))
            (pod-store-core-journal-bytes store) journal-bytes
            ;; A torn record must not end up in the middle of the journal.
            (pod-store-core-checkpoint-needed store) torn)
      (loop for object across (gethash "items" state)
            for resource = (or (first (find (gethash "kind" object) (append *stored-resource-types* *internal-stored-resource-types*)
                                           :key #'second :test #'equal))
                               (error "Invalid stored resource kind"))
            for key = (core-resource-key-from-object resource object)
            do (when (gethash key (pod-store-resources store))
                 (error "Duplicate persisted core resource ~S" key))
               (setf (gethash key (pod-store-resources store)) object))
      (loop for entry across (gethash "customResourceItems" state #())
            for resource = (gethash "resource" entry)
            for object = (gethash "object" entry)
            for key = (core-resource-key-from-object resource object)
            do (unless (and (custom-resource-key-p resource) (crd-definition-unlocked store resource))
                 (error "Persisted custom resource has no matching definition"))
               (when (gethash key (pod-store-resources store)) (error "Duplicate persisted custom resource"))
               (setf (gethash key (pod-store-resources store)) object))))
  store)

(defparameter +template-history-recent-limit+ 512
  "Newest journal entries kept separately, so that an idle watch reads few of them.")

(defparameter *raft-local-plane-resources*
  '("events")
  "Durable resource kinds kept OFF the consensus plane: high-churn and
   self-expiring, so eventual consistency is acceptable. They publish locally on
   each member and are excluded from the HA replication blob (podster-8ia.3); the
   full on-disk state still includes them.")

(defun local-plane-resource-p (resource)
  "Return whether RESOURCE is a local-plane kind (events): kept off the consensus
   plane, published per-member, and excluded from the HA replication blob."
  (member resource *raft-local-plane-resources* :test #'equal))

(defun core-checkpoint-object (store resources revision workload-deletions job-controller-states
                               history floor token-key event-expirations &key omit-local-plane)
  "Return the complete durable core-resource state, as a checkpoint or HA state blob holds it."
  (multiple-value-bind (durable durable-floor) (durable-template-history history floor)
    (progn
     (core-object "version" 2 "revision" revision "workloadDeletions" workload-deletions
                  "jobControllerStates" job-controller-states
                  "templateHistory" (coerce (mapcar (lambda (entry)
                                                       (encrypt-secret-history-entry store entry))
                                                     durable)
                                              'vector)
                  "templateHistoryFloor" durable-floor
                  "templateTokenKey" (ag-grpc:base64-encode token-key)
                  "secretsEncryption" (or (pod-store-secret-encryption-config store) 'null)
                  "resourceHistoryStart" (pod-store-resource-history-start store)
                  "eventExpirations" event-expirations
                  "items" (coerce (loop for key being the hash-keys of resources using (hash-value object)
                                        unless (or (custom-resource-key-p (first key))
                                                   (and omit-local-plane (local-plane-resource-p (first key))))
                                          collect (encrypt-secret-object store (first key) object)) 'vector)
                  "customResourceItems" (coerce (loop for key being the hash-keys of resources using (hash-value object)
                                                      when (custom-resource-key-p (first key))
                                                        collect (core-object "resource" (first key) "object"
                                                                             (encrypt-secret-object store (first key) object))) 'vector)))))

(defun core-state-json (store resources revision workload-deletions job-controller-states
                        &key omit-local-plane)
  "Serialize the complete durable core-resource state, as a checkpoint is written.
   Returns (values json history floor token-key event-expirations added) so the
   direct publish path can also set the derived in-memory slots: HISTORY and FLOOR
   are what watches read, which reaches further back than what is written. With
   OMIT-LOCAL-PLANE, local-plane kinds (events) are left out -- used for the HA
   replication blob so high-churn events never ride the Raft log."
  (multiple-value-bind (history floor added) (next-template-history store resources revision)
    (let* ((token-key (or (pod-store-template-token-key store) (secure-random-octets 32)))
           (event-expirations (next-event-expirations store resources)))
      (values (com.inuoe.jzon:stringify
               (core-checkpoint-object store resources revision workload-deletions job-controller-states
                                       history floor token-key event-expirations
                                       :omit-local-plane omit-local-plane))
              history floor token-key event-expirations added))))

(defun core-state-delta-json (store resources revision workload-deletions job-controller-states)
  "Serialize one HA core transaction as key-level effects against STORE's base.
Effects carry encrypted prior-object conditions and are merged at Raft apply
time. A stale author cannot replace a changed key or erase unrelated commits."
  (let ((changes nil)
        (base (pod-store-resource-revision store))
        (keys (make-hash-table :test #'equal))
        (record (core-object)))
    (dolist (index (list (pod-store-resources store) resources))
      (maphash (lambda (key object)
                 (declare (ignore object))
                 (setf (gethash key keys) t))
               index))
    (maphash
     (lambda (key present)
       (declare (ignore present))
       (let ((old (gethash key (pod-store-resources store)))
             (new (gethash key resources)))
         (unless (or (eq old new) (local-plane-resource-p (first key)))
           (push (core-object "resource" (first key)
                              "namespace" (or (second key) 'null)
                              "name" (third key)
                              "expected" (if old (encrypt-secret-object store (first key) old) 'null)
                              "object" (if new
                                           (encrypt-secret-object store (first key) new)
                                           'null))
                 changes))))
     keys)
    (setf (gethash "version" record) 2
          (gethash "baseRevision" record) base
          ;; Preserve the transaction's revision width (for example a Service
          ;; plus its IPAddress claim), but rebase it on committed apply state.
          (gethash "revisionSpan" record) (max 1 (- revision base))
          (gethash "changes" record) (coerce changes 'vector)
          (gethash "secretsEncryption" record)
          (or (pod-store-secret-encryption-config store) 'null)
          (gethash "templateTokenKey" record)
          (ag-grpc:base64-encode
           (or (pod-store-template-token-key store) (secure-random-octets 32))))
    (let ((delta (core-map-delta (pod-store-workload-deletions store) workload-deletions :preconditions t)))
      (when delta (setf (gethash "workloadDeletions" record) delta)))
    (let ((delta (core-map-delta (pod-store-job-controller-states store) job-controller-states :preconditions t)))
      (when delta (setf (gethash "jobControllerStates" record) delta)))
    (com.inuoe.jzon:stringify record)))

(defun core-map-delta (old new &key preconditions)
  "Describe how the string-keyed JSON map NEW differs from OLD, or NIL when it does not."
  (unless (eq old new)
    (let ((set (core-object)) (deleted nil))
      (maphash (lambda (key value)
                 (multiple-value-bind (previous present) (gethash key old)
                   (unless (and present (core-json-equal-p previous value))
                     (setf (gethash key set) value))))
               new)
      (maphash (lambda (key value)
                 (declare (ignore value))
                 (unless (nth-value 1 (gethash key new)) (push key deleted)))
               old)
      (when (or (plusp (hash-table-count set)) deleted)
        (let ((delta (core-object "set" set "delete" (coerce deleted 'vector))))
          (when preconditions
            (let ((expected (core-object)))
              (labels ((expect (key)
                         (multiple-value-bind (value present) (gethash key old)
                           (setf (gethash key expected)
                                 (core-object "present" (if present t :false)
                                              "value" (if present value 'null))))))
                (maphash (lambda (key value) (declare (ignore value)) (expect key)) set)
                (dolist (key deleted) (expect key)))
              (setf (gethash "expected" delta) expected)))
          delta)))))

(defun core-journal-record-json (store revision added workload-deletions job-controller-states event-expirations)
  "Serialize one commit as a journal line: only what it changed. ADDED are its history entries."
  (let ((changes nil) (expirations (core-object)) (record (core-object "revision" revision)))
    (dolist (entry added)
      (let ((new (gethash "new" entry)))
        (push (core-object "resource" (gethash "resource" entry) "namespace" (or (gethash "namespace" entry) 'null)
                           "name" (gethash "name" entry)
                           "object" (if (hash-table-p new)
                                        (encrypt-secret-object store (gethash "resource" entry) new)
                                        new))
              changes)
        (when (and (equal "events" (gethash "resource" entry)) (hash-table-p new))
          (let ((uid (gethash "uid" (gethash "metadata" new))))
            (setf (gethash uid expirations) (gethash uid event-expirations))))))
    (setf (gethash "time" record) (if added (gethash "time" (first added)) (funcall *podtemplate-clock*))
          ;; ADDED is newest first, so CHANGES is in the order history holds them.
          (gethash "changes" record) (coerce changes 'vector)
          (gethash "resourceHistoryStart" record) (pod-store-resource-history-start store))
    (when (plusp (hash-table-count expirations))
      (setf (gethash "eventExpirations" record) expirations))
    (let ((delta (core-map-delta (pod-store-workload-deletions store) workload-deletions)))
      (when delta (setf (gethash "workloadDeletions" record) delta)))
    (let ((delta (core-map-delta (pod-store-job-controller-states store) job-controller-states)))
      (when delta (setf (gethash "jobControllerStates" record) delta)))
    (com.inuoe.jzon:stringify record)))

(defun append-core-journal-record (store json)
  "Append one commit's JSON line to STORE's journal, removing any part of it on failure,
so that only a crash can leave a torn record, and only at the end."
  (let* ((path (core-journal-path store))
         (octets (trivial-utf-8:string-to-utf-8-bytes (concatenate 'string json (string #\Newline))))
         (start (pod-store-core-journal-bytes store))
         (done nil))
    (unwind-protect
         (progn
           ;; It holds Secrets, like the checkpoint: create it private.
           (unless (probe-file path)
             (sb-posix:close (sb-posix:open (namestring path)
                                            (logior sb-posix:o-wronly sb-posix:o-creat sb-posix:o-excl)
                                            #o600)))
           (with-open-file (stream path :direction :output :element-type '(unsigned-byte 8)
                                        :if-exists :append :if-does-not-exist :error)
             (write-sequence octets stream)
             (finish-output stream))
           (setf done t))
      (unless done
        (ignore-errors (sb-posix:truncate (namestring path) start))))
    (incf (pod-store-core-journal-bytes store) (length octets))))

(defun write-core-checkpoint (store state)
  "Replace STORE's checkpoint with STATE, a JSON string or object, and start an empty journal after it.
An object is streamed to the file, never held as one string as large as the store."
  (write-private-text-atomically (core-resource-state-path store)
                                 (if (stringp state)
                                     state
                                     (lambda (stream) (com.inuoe.jzon:stringify state :stream stream))))
  ;; The checkpoint holds everything the journal did. Should deleting the journal
  ;; fail, replay still skips its records, all at or below the checkpoint's
  ;; revision, and the next commit tries another checkpoint rather than append.
  (let ((deleted (ignore-errors
                  (let ((journal (core-journal-path store)))
                    (when (probe-file journal) (delete-file journal)))
                  t)))
    (setf (pod-store-core-checkpoint-bytes store)
          (sb-posix:stat-size (sb-posix:stat (namestring (core-resource-state-path store))))
          (pod-store-core-journal-bytes store) 0
          (pod-store-core-checkpoint-needed store) (not deleted))))

(defun core-checkpoint-due-p (store)
  "Return whether STORE's next commit must write a full checkpoint rather than
   append to the journal: because a torn record needs rewriting, no template token
   key exists yet, or the journal has outgrown both its size bound and the current
   checkpoint."
  (or (pod-store-core-checkpoint-needed store)
      (null (pod-store-template-token-key store))
      (> (pod-store-core-journal-bytes store)
         (max *core-journal-checkpoint-bytes* (pod-store-core-checkpoint-bytes store)))))

(defun commit-core-resources (store resources revision
                              &key (workload-deletions (pod-store-workload-deletions store))
                                (job-controller-states (pod-store-job-controller-states store)))
  "Commit a durable core-resource transition. Normally (and always without HA)
   appends what changed to the journal, or now and then writes a complete
   checkpoint, and then publishes the new state in memory. Inside a
   WITH-CORE-WRITE on an HA store, instead stashes the committed state blob so the
   caller can replicate it through Raft once the store lock is released; every
   replica then installs it via INSTALL-CORE-STATE-BLOB."
  ;; Write the new state durably before publishing it in memory. A failed write
  ;; leaves both the old disk state and the old index intact.
  (cond
    ;; HA consensus write: defer to the replicated apply path, keeping local-plane
    ;; resources (events) out of the Raft log (podster-8ia.3). A local-plane-only
    ;; write never replicates -- it falls through to the local publish below.
    ((and *core-write-active* (not *local-plane-write*) (pod-store-consensus-commit-fn store))
     (setf *pending-consensus-commit*
           (core-state-delta-json store resources revision workload-deletions job-controller-states)))
    (t
     (multiple-value-bind (history floor added) (next-template-history store resources revision)
       (let ((token-key (or (pod-store-template-token-key store) (secure-random-octets 32)))
             (event-expirations (next-event-expirations store resources)))
         (if (core-checkpoint-due-p store)
             (write-core-checkpoint store (core-checkpoint-object store resources revision workload-deletions
                                                                  job-controller-states history floor
                                                                  token-key event-expirations))
             (append-core-journal-record
              store (core-journal-record-json store revision added workload-deletions
                                              job-controller-states event-expirations)))
         (setf (pod-store-resources store) resources
               (pod-store-workload-deletions store) workload-deletions
               (pod-store-job-controller-states store) job-controller-states
               (pod-store-resource-revision store) revision
               (pod-store-template-history store) history
               (pod-store-template-history-recent store)
               (let ((recent (append added (pod-store-template-history-recent store))))
                 (if (nthcdr +template-history-recent-limit+ recent)
                     (subseq recent 0 +template-history-recent-limit+)
                     recent))
               (pod-store-template-history-floor store) floor
               (pod-store-template-token-key store) token-key
               (pod-store-event-expirations store) event-expirations))))))

(defun install-core-state-blob (store json)
  "Install a replicated core-resource state JSON blob on this replica: write it to
   disk and reload the in-memory index from it. Runs on every member when a
   :core-state entry commits (podster-c2d.7.2). Uses the RAW store lock, never
   WITH-STORE-LOCK: on the leader this runs while the proposing writer still holds
   the consensus-write lock during its flush, so acquiring that lock again here
   would deadlock. Local-plane resources (events) are not in the blob, so this
   member's own ones are carried across the reload rather than dropped (8ia.3)."
  (bt:with-lock-held ((pod-store-lock store))
    (let ((local (loop for key being the hash-keys of (pod-store-resources store)
                         using (hash-value object)
                       when (local-plane-resource-p (first key))
                         collect (cons key object))))
      ;; The blob replaces the checkpoint, so no older journal may be replayed over it.
      (write-core-checkpoint store json)
      (clrhash (pod-store-resources store))
      (load-core-resources store)
      (loop for (key . object) in local
            unless (gethash key (pod-store-resources store))
              do (setf (gethash key (pod-store-resources store)) object))
      ;; The carried objects are only in memory: the next commit writes them all.
      (setf (pod-store-core-checkpoint-needed store) t))))

(defun core-replicated-state-equal-p (left right)
  "Compare committed object identity/content independently of local revision epochs."
  (if (and (hash-table-p left) (hash-table-p right))
      (let ((a (copy-core-object left)) (b (copy-core-object right)))
        (remhash "resourceVersion" (gethash "metadata" a))
        (remhash "resourceVersion" (gethash "metadata" b))
        (gr8s.store::json-value-equal-p a b))
      (eq left right)))

(defun core-map-preconditions-satisfied-p (current delta)
  (let ((expected (gethash "expected" delta)))
    (and (hash-table-p expected)
         (loop for key being the hash-keys of expected using (hash-value condition)
               always (multiple-value-bind (value present) (gethash key current)
                        (and (eq (not (null present)) (eq t (gethash "present" condition)))
                             (or (not present)
                                 (gr8s.store::json-value-equal-p value (gethash "value" condition)))))))))

(defun install-core-state-delta (store json)
  "Apply one committed key-level core transaction to STORE in Raft log order.
The command's revision span is rebased on this replica's committed revision;
unrelated keys are preserved; version 2 conditions reject stale same-key writes
before any state is published."
  (bt:with-lock-held ((pod-store-lock store))
    (let* ((delta (com.inuoe.jzon:parse json))
           (resources (copy-core-resource-index store))
           (revision (+ (pod-store-resource-revision store)
                        (gethash "revisionSpan" delta 1)))
           (workload-deletions (pod-store-workload-deletions store))
           (job-controller-states (pod-store-job-controller-states store)))
      ;; All conditions run before mutation, including policy/key installation
      ;; and clock/history publication. Rejection is a committed no-op, not an
      ;; apply exception that would stall Raft on a normal concurrent writer.
      (when (eql 2 (gethash "version" delta))
        (unless (gr8s.store::json-value-equal-p (or (pod-store-secret-encryption-config store) 'null)
                                   (gethash "secretsEncryption" delta))
          (return-from install-core-state-delta (list :core-conflict)))
        (loop for change across (gethash "changes" delta #())
              for namespace = (gethash "namespace" change)
              for resource = (gethash "resource" change)
              for key = (core-resource-key resource (unless (eq namespace 'null) namespace)
                                          (gethash "name" change))
              for current = (gethash key (pod-store-resources store) 'null)
              for expected = (gethash "expected" change)
              unless (core-replicated-state-equal-p
                      current (if (hash-table-p expected)
                                  (decrypt-secret-object store resource expected) expected))
                do (return-from install-core-state-delta (list :core-conflict)))
        (dolist (entry (list (cons "workloadDeletions" workload-deletions)
                            (cons "jobControllerStates" job-controller-states)))
          (let ((map-delta (gethash (car entry) delta)))
            (when (and map-delta (not (core-map-preconditions-satisfied-p (cdr entry) map-delta)))
              (return-from install-core-state-delta (list :core-conflict))))))
      (let ((config (gethash "secretsEncryption" delta)))
        (unless (eq config 'null)
          (setf (pod-store-secret-encryption-config store) config)))
      (loop for change across (gethash "changes" delta #())
            for namespace = (gethash "namespace" change)
            for key = (core-resource-key
                       (gethash "resource" change)
                       (unless (eq namespace 'null) namespace)
                       (gethash "name" change))
            for object = (gethash "object" change)
            do (if (eq object 'null)
                   (remhash key resources)
                   (let ((object (decrypt-secret-object store (first key) object)))
                     ;; Revisions, including post-restore epochs, are local to
                     ;; this member; the next delta must not move one backwards.
                     (setf (gethash "resourceVersion" (gethash "metadata" object)) (write-to-string revision)
                           (gethash key resources) object))))
      (when (gethash "workloadDeletions" delta)
        (setf workload-deletions
              (apply-core-map-delta workload-deletions
                                    (gethash "workloadDeletions" delta))))
      (when (gethash "jobControllerStates" delta)
        (setf job-controller-states
              (apply-core-map-delta job-controller-states
                                    (gethash "jobControllerStates" delta))))
      ;; The first committed writer chooses the cluster-wide continuation-token
      ;; key; subsequent commands carry the same value from replicated state.
      (unless (pod-store-template-token-key store)
        (setf (pod-store-template-token-key store)
              (ag-grpc:base64-decode (gethash "templateTokenKey" delta))))
      ;; A leader can synchronously run its own Raft apply callback from inside
      ;; the dynamic extent of WITH-STORE-LOCK's author-side write. This is an
      ;; apply, not another transaction to propose: force the durable publish
      ;; path so the leader installs the same committed entry as its followers.
      (let ((*core-write-active* nil)
            (*local-plane-write* nil))
        (commit-core-resources store resources revision
                               :workload-deletions workload-deletions
                               :job-controller-states job-controller-states))
      (list :core-ok))))

(defun copy-core-resource-index (store)
  "Return a shallow copy of STORE's resource index: a fresh EQUAL table that shares
   the stored objects. This is the mutable working set a write prepares and mutates
   before it commits, leaving the live index untouched until then."
  (let ((copy (make-hash-table :test #'equal)))
    (maphash (lambda (key value) (setf (gethash key copy) value))
             (pod-store-resources store))
    copy))

(defun core-data-key-p (key)
  "Return whether KEY is a valid ConfigMap/Secret data key: 1 to 253 characters of
   ASCII letters, digits, '-', '_', or '.'."
  (and (stringp key) (<= 1 (length key) 253)
       (every (lambda (character)
                (or (find character "-_.")
                    (and (char<= #\a character) (char<= character #\z))
                    (and (char<= #\A character) (char<= character #\Z))
                    (digit-char-p character))) key)))

(defun validate-core-string-map (object context &key data-keys)
  "Require OBJECT to be a JSON object whose keys and values are all strings -- and,
   with DATA-KEYS, whose keys are valid data keys -- signalling a 422 under CONTEXT
   otherwise. Returns OBJECT."
  (require-object object context)
  (maphash (lambda (key value)
             (unless (and (stringp key) (stringp value)
                          (or (not data-keys) (core-data-key-p key)))
               (core-resource-error 422 "Invalid" "~A requires valid keys and string values" context)))
           object)
  object)

(defun core-base64-bytes (value context)
  "Decode VALUE, a canonical base64 string (carriage returns and linefeeds removed
   first), to its bytes. Signals a 400 under CONTEXT when VALUE is not a string, is
   not valid base64, or is not canonically encoded."
  (unless (stringp value)
    (core-resource-error 400 "BadRequest" "~A must be a base64 string" context))
  (let ((normalized (remove-if (lambda (character) (find character '(#\Return #\Linefeed))) value)))
    (handler-case
        (let ((bytes (ag-grpc:base64-decode normalized)))
          (unless (string= normalized (ag-grpc:base64-encode bytes))
            (error "noncanonical base64"))
          bytes)
      (error () (core-resource-error 400 "BadRequest" "~A is not valid base64" context)))))

(defun core-label-name-p (value &key empty)
  "Return whether VALUE is a valid label value: at most 63 characters of ASCII
   letters, digits, '-', '_', or '.', beginning and ending alphanumeric. An empty
   VALUE is accepted only when EMPTY."
  (and (stringp value) (<= (length value) 63)
       (if (zerop (length value)) empty
           (and (alphanumericp (char value 0)) (alphanumericp (char value (1- (length value))))))
       (every (lambda (character)
                (or (and (char<= #\a character) (char<= character #\z))
                    (and (char<= #\A character) (char<= character #\Z))
                    (digit-char-p character) (find character "-_."))) value)))

(defun core-qualified-key-p (value)
  "Return whether VALUE is a valid qualified key: a bare label name, or a DNS-
   subdomain prefix and a label name joined by a single '/'."
  (when (stringp value)
    (let ((parts (uiop:split-string value :separator '(#\/))))
      (or (and (= 1 (length parts)) (core-label-name-p (first parts)))
          (and (= 2 (length parts)) (dns-subdomain-p (first parts)) (core-label-name-p (second parts)))))))

(defun path-segment-name-p (name)
  "Accept what upstream's RBAC objects may be named: anything usable as one URL path segment."
  (and (stringp name) (<= 1 (length name) 253) (not (member name '("." "..") :test #'equal))
       (notany (lambda (character) (find character "/%")) name)))

(defun rbac-resource-p (resource)
  "Return whether RESOURCE is an RBAC collection, whose names may contain colons."
  (member resource '("roles" "rolebindings" "clusterroles" "clusterrolebindings") :test #'equal))

(defun validate-core-metadata (metadata namespace name &key allow-finalizers name-test)
  "Validate an object's METADATA in place, returning it, and signal a 4xx core-
   resource-error on any violation: NAMESPACE must be a DNS label and must match
   metadata.namespace when that is set; NAME, when given, must equal metadata.name,
   which must satisfy NAME-TEST (a DNS subdomain by default); labels and
   annotations must be string maps with qualified keys (label values also valid),
   and annotations must stay within 256 KiB; owner references are validated.
   Finalizers are accepted and checked only when ALLOW-FINALIZERS; otherwise only
   the propagation-policy finalizers foregroundDeletion and orphan are tolerated."
  (require-object metadata "metadata")
  (when (and namespace (not (dns-label-p namespace)))
    (core-resource-error 422 "Invalid" "metadata.namespace must be a DNS label"))
  (multiple-value-bind (specified present) (gethash "namespace" metadata)
    (when (and present (not (member specified '(null "") :test #'equal)) (not (equal specified namespace)))
      (core-resource-error 400 "BadRequest" "metadata.namespace does not match the request namespace")))
  (when (and name (not (equal name (gethash "name" metadata))))
    (core-resource-error 400 "BadRequest" "metadata.name does not match the request name"))
  (let ((object-name (gethash "name" metadata)))
    (unless (if name-test (funcall name-test object-name) (dns-subdomain-p object-name))
      (core-resource-error 422 "Invalid" "metadata.name must be a DNS subdomain")))
  (dolist (field '("labels" "annotations"))
    (when (gethash field metadata)
      (let ((values (validate-core-string-map (gethash field metadata) (concatenate 'string "metadata." field)))
            (size 0))
        (maphash (lambda (key value)
                   (unless (and (core-qualified-key-p key)
                                (or (string= field "annotations") (core-label-name-p value :empty t)))
                     (core-resource-error 422 "Invalid" "metadata.~A has an invalid key or value" field))
                   (incf size (+ (length (trivial-utf-8:string-to-utf-8-bytes key))
                                 (length (trivial-utf-8:string-to-utf-8-bytes value))))) values)
        (when (and (string= field "annotations") (> size (* 256 1024)))
          (core-resource-error 422 "Invalid" "metadata.annotations exceeds the 256 KiB limit")))))
  (validate-owner-references metadata)
  (when allow-finalizers
    (when (nth-value 1 (gethash "finalizers" metadata))
      (bootstrap-string-array (gethash "finalizers" metadata) "metadata.finalizers")
      (loop for finalizer across (gethash "finalizers" metadata)
            unless (core-qualified-key-p finalizer)
              do (core-resource-error 422 "Invalid" "Invalid finalizer name"))))
  (dolist (field (unless allow-finalizers '("finalizers")))
    (let ((value (gethash field metadata)))
      ;; A deletion held for its dependents shows a finalizer that clients echo back.
      (when (and value (not (eq value 'null))
                 (or (not (vectorp value))
                     (notevery (lambda (name) (member name '("foregroundDeletion" "orphan") :test #'equal)) value)))
        (core-resource-error 422 "Invalid" "metadata.~A is not supported" field))))
  metadata)

(defun validate-core-secret-type (object)
  "Validate a Secret's type and the data its type demands, defaulting an unset or
   empty type to \"Opaque\" and storing the result back in OBJECT. Signals a 422
   when the type is not a nonempty string, or when a well-known type
   (kubernetes.io/tls, ssh-auth, basic-auth, dockercfg/dockerconfigjson,
   service-account-token) is missing a required data key, a valid JSON dockercfg,
   or the service-account name annotation. Returns the stored type."
  (let* ((specified (gethash "type" object "Opaque"))
         (type (if (member specified '(null "") :test #'equal) "Opaque" specified))
         (data (gethash "data" object)))
    (unless (and (stringp type) (plusp (length type)))
      (core-resource-error 422 "Invalid" "Secret.type must be a nonempty string"))
    (labels ((require-key (key)
               (unless (and data (nth-value 1 (gethash key data)))
                 (core-resource-error 422 "Invalid" "Secret type ~A requires data[~S]" type key))))
      (cond
        ((string= type "kubernetes.io/tls")
         (require-key "tls.crt") (require-key "tls.key"))
        ((string= type "kubernetes.io/ssh-auth") (require-key "ssh-privatekey"))
        ((string= type "kubernetes.io/basic-auth")
         (unless (and data (or (nth-value 1 (gethash "username" data))
                              (nth-value 1 (gethash "password" data))))
           (core-resource-error 422 "Invalid" "basic-auth Secret requires username or password")))
        ((member type '("kubernetes.io/dockerconfigjson" "kubernetes.io/dockercfg") :test #'string=)
         (let ((key (if (string= type "kubernetes.io/dockercfg") ".dockercfg" ".dockerconfigjson")))
           (require-key key)
           (handler-case
               (require-object (com.inuoe.jzon:parse
                                (trivial-utf-8:utf-8-bytes-to-string
                                 (core-base64-bytes (gethash key data) key))) key)
             (error () (core-resource-error 422 "Invalid" "~A must contain a JSON object" key)))))
        ((string= type "kubernetes.io/service-account-token")
         (let ((annotations (gethash "annotations" (gethash "metadata" object))))
           (unless (and annotations
                        (stringp (gethash "kubernetes.io/service-account.name" annotations))
                        (plusp (length (gethash "kubernetes.io/service-account.name" annotations))))
             (core-resource-error 422 "Invalid" "service-account-token Secret requires the service account name annotation"))))))
    (setf (gethash "type" object) type)))

(defun normalize-core-resource (resource input namespace &optional name store)
  "Return the normalized, validated stored form of INPUT for collection RESOURCE in
   NAMESPACE (and NAME on update), never mutating INPUT. Delegates to the per-kind
   normalizer for cronjob, batch, budget, HPA, policy, typed-API, networking,
   admission-config, CSR, endpointslice, CRD, custom, storage, and bootstrap
   resources; handles ConfigMaps and Secrets directly -- copying INPUT, requiring
   apiVersion v1 and the right Kind, rejecting unsupported fields, validating
   metadata, base64-encoding binary data, folding Secret stringData into data, and
   signalling a 422 when the data exceeds 1 MiB."
  (when (cronjob-resource-p resource)
    (return-from normalize-core-resource (normalize-cronjob-resource input namespace name)))
  (when (batch-resource-p resource)
    (return-from normalize-core-resource (normalize-batch-resource input namespace name)))
  (when (budget-resource-p resource)
    (return-from normalize-core-resource (normalize-budget-resource input namespace name)))
  (when (hpa-resource-p resource)
    (return-from normalize-core-resource (normalize-hpa-resource input namespace name store)))
  (when (policy-resource-p resource)
    (return-from normalize-core-resource (normalize-policy-resource resource input namespace name store)))
  (when (typed-api-resource-p resource)
    (return-from normalize-core-resource (normalize-typed-api-resource resource input namespace name store)))
  (when (networking-resource-p resource)
    (return-from normalize-core-resource (normalize-networking-resource resource input namespace name store)))
  (when (admission-config-resource-p resource)
    (return-from normalize-core-resource (normalize-admission-config resource input name)))
  (when (csr-resource-p resource)
    (return-from normalize-core-resource (normalize-csr-resource input name store)))
  (when (endpointslice-resource-p resource)
    (return-from normalize-core-resource (normalize-endpointslice-resource input namespace name)))
  (when (equal resource "customresourcedefinitions")
    (return-from normalize-core-resource (normalize-crd-resource input namespace name store)))
  (when (custom-resource-key-p resource)
    (return-from normalize-core-resource (normalize-custom-resource resource input namespace name store)))
  (when (storage-resource-p resource)
    (return-from normalize-core-resource (normalize-storage-resource resource input namespace name store)))
  (unless (member resource '("configmaps" "secrets") :test #'equal)
    (return-from normalize-core-resource
      (normalize-bootstrap-resource resource input namespace name store)))
  (let* ((object (copy-core-object (require-object input (core-resource-kind resource))))
         (kind (core-resource-kind resource))
         (metadata (require-object (gethash "metadata" object) "metadata"))
         (size 0))
    (unless (and (member (gethash "apiVersion" object "v1") '("v1") :test #'equal)
                 (equal kind (gethash "kind" object kind)))
      (core-resource-error 400 "BadRequest" "Expected v1 ~A" kind))
    (reject-unsupported-fields
     object (if (string= resource "secrets")
                '("apiVersion" "kind" "metadata" "data" "stringData" "type" "immutable")
                '("apiVersion" "kind" "metadata" "data" "binaryData" "immutable")) kind)
    (validate-core-metadata metadata namespace name :allow-finalizers t)
    (setf (gethash "apiVersion" object) "v1" (gethash "kind" object) kind
          (gethash "namespace" metadata) namespace)
    (multiple-value-bind (immutable present) (gethash "immutable" object)
      (when (and present (not (member immutable '(t nil null))))
        (core-resource-error 422 "Invalid" "immutable must be a boolean")))
    (when (eq (gethash "immutable" object) 'null) (remhash "immutable" object))
    (dolist (field (if (string= resource "secrets") '("data" "stringData") '("data" "binaryData")))
      (when (eq (gethash field object) 'null) (remhash field object))
      (multiple-value-bind (data present) (gethash field object)
        (when present
          (validate-core-string-map data field :data-keys t)
          (maphash (lambda (key value)
                     (let* ((binary (or (string= field "binaryData")
                                        (and (string= resource "secrets") (string= field "data"))))
                            (bytes (if binary (core-base64-bytes value field)
                                       (trivial-utf-8:string-to-utf-8-bytes value))))
                       (when binary (setf (gethash key data) (ag-grpc:base64-encode bytes)))
                       (incf size (length bytes)))) data))))
    (if (string= resource "secrets")
        (let ((strings (gethash "stringData" object)))
          (when strings
            (let ((data (or (gethash "data" object) (make-hash-table :test #'equal))))
              (maphash (lambda (key value)
                         (setf (gethash key data)
                               (ag-grpc:base64-encode (trivial-utf-8:string-to-utf-8-bytes value)))) strings)
              (setf (gethash "data" object) data)))
          (remhash "stringData" object)
          ;; Count the final data only: stringData replaces overlapping keys.
          (setf size 0)
          (when (gethash "data" object)
            (maphash (lambda (key value)
                       (declare (ignore key))
                       (incf size (length (core-base64-bytes value "data")))) (gethash "data" object)))
          (validate-core-secret-type object))
        (let ((data (gethash "data" object)) (binary (gethash "binaryData" object)))
          (when (and data binary)
            (maphash (lambda (key value)
                       (declare (ignore value))
                       (when (nth-value 1 (gethash key binary))
                         (core-resource-error 422 "Invalid" "data and binaryData overlap at key ~S" key))) data))))
    (when (> size (* 1024 1024))
      (core-resource-error 422 "Invalid" "~A data exceeds the 1 MiB limit" kind))
    object))

(defun get-core-resource-unlocked (store resource namespace name)
  "Return the live stored object for RESOURCE NAMESPACE NAME, or signal a 404.
   Assumes the caller holds the store lock and returns the indexed object without
   copying, so the caller must not mutate it."
  (or (gethash (core-resource-key resource namespace name) (pod-store-resources store))
      (core-resource-error 404 "NotFound" "~A ~A/~A was not found" (core-resource-kind resource) namespace name)))

(defun get-core-resource (store resource namespace name)
  "Return a private copy of the stored object for RESOURCE NAMESPACE NAME, or signal
   a 404. Takes the store lock, checks the CRD request context, and expires due
   events first."
  (with-store-lock (store)
    (check-crd-resource-context-unlocked store resource)
    (expire-core-events-unlocked store)
    (copy-core-object (get-core-resource-unlocked store resource namespace name))))

(defun list-core-resources (store resource &optional namespace)
  "Return (values OBJECTS RESOURCE-VERSION): private copies of every stored object
   in collection RESOURCE, optionally restricted to NAMESPACE, sorted by
   namespace/name, and the store's current resource revision as a string. Takes the
   store lock and expires due events first."
  (with-store-lock (store)
    (expire-core-events-unlocked store)
    (values
     (sort (loop for key being the hash-keys of (pod-store-resources store) using (hash-value object)
                 when (and (equal resource (first key)) (or (null namespace) (equal namespace (second key))))
                   collect (copy-core-object object))
           #'string< :key (lambda (object)
                           (let ((metadata (gethash "metadata" object)))
                             (format nil "~A/~A" (gethash "namespace" metadata) (gethash "name" metadata)))))
     (write-to-string (pod-store-resource-revision store)))))

(defvar *core-resource-assigned-uid* nil
  "UID a new object must take, because admission webhooks have already seen it.")

(defun prepare-core-resource-metadata (object existing revision)
  "Stamp OBJECT's metadata for a write at REVISION, returning OBJECT: set
   resourceVersion to REVISION; when EXISTING, carry its uid and creationTimestamp;
   otherwise assign a uid (the admission-assigned *core-resource-assigned-uid* when
   bound, else a fresh one) and the current timestamp."
  (let ((metadata (gethash "metadata" object)))
    (setf (gethash "uid" metadata) (if existing
                                       (gethash "uid" (gethash "metadata" existing))
                                       (or *core-resource-assigned-uid* (generate-uid)))
          (gethash "creationTimestamp" metadata)
          (if existing (gethash "creationTimestamp" (gethash "metadata" existing)) (current-timestamp))
          (gethash "resourceVersion" metadata) (write-to-string revision)))
  object)

(defun core-resource-immutable-p (object)
  "Return whether OBJECT is marked immutable (its \"immutable\" field is true)."
  (eq t (gethash "immutable" object)))

(defun core-resource-data-equal-p (left right)
  "Return whether LEFT and RIGHT hold the same \"data\" and \"binaryData\" maps,
   compared by key and value regardless of map order."
  ;; JSON's map order is insignificant.
  (labels ((map-equal (a b)
             (and (= (if a (hash-table-count a) 0) (if b (hash-table-count b) 0))
                  (or (null a) (loop for key being the hash-keys of a using (hash-value value)
                                    always (and b (equal value (gethash key b))))))))
    (and (map-equal (gethash "data" left) (gethash "data" right))
         (map-equal (gethash "binaryData" left) (gethash "binaryData" right)))))

(defun create-core-resource (store resource input namespace &key dry-run)
  "Create a new object in collection RESOURCE under NAMESPACE from INPUT, returning
   a private copy of the stored result. Runs under WITH-CORE-WRITE with deferred
   CRD conversions: expires due events, enforces namespace admission and resource
   quotas, allocates a generated name when generateName is given, rejects a client-
   set resourceVersion, normalizes and validates the object, stamps its metadata at
   the next revision, and commits -- signalling 409 AlreadyExists on a key
   collision. A Service's ClusterIP is claimed by its IPAddress object in the same
   commit. With DRY-RUN, validates and prepares everything but does not commit."
  (let ((*local-plane-write* (local-plane-resource-p resource)))
   (with-crd-deferred-conversions
    (with-core-write (store)
    (expire-core-events-unlocked store)
    (unless (or (equal resource "events") *resource-quota-admission-exempt*)
      (require-namespace-accepts-content store namespace))
    (let* ((input (copy-core-object input))
           (metadata (require-object (gethash "metadata" input) "metadata")))
      (when (csr-resource-p resource)
        (assign-generated-csr-name-unlocked store input)
        (when (member (gethash "resourceVersion" metadata) '(null "") :test #'equal) (remhash "resourceVersion" metadata)))
      (when (or (workload-resource-p resource) (budget-resource-p resource))
        (assign-generated-workload-name-unlocked store resource input namespace))
      (when (endpointslice-resource-p resource) (assign-generated-endpointslice-name-unlocked store input namespace))
      (when (and (not (gethash "name" metadata)) (gethash "generateName" metadata))
        (let ((prefix (gethash "generateName" metadata)))
          (unless (and (stringp prefix) (<= 1 (length prefix) 247)
                       (dns-subdomain-p (concatenate 'string prefix "x")))
            (core-resource-error 422 "Invalid" "metadata.generateName is invalid"))
          (loop repeat 8
                for name = (concatenate 'string prefix (string-downcase (subseq (generate-uid) 0 5)))
                unless (gethash (core-resource-key resource namespace name) (pod-store-resources store))
                  do (setf (gethash "name" metadata) name) (return)
                finally (core-resource-error 409 "AlreadyExists" "Could not allocate a unique generated name"))))
      (multiple-value-bind (version present) (gethash "resourceVersion" metadata)
        (when present
          (unless (or (equal version "") (eq version 'null))
            (core-resource-error 400 "BadRequest" "metadata.resourceVersion must not be set on create"))
          (remhash "resourceVersion" metadata)))
      (let* ((object (normalize-core-resource resource input namespace nil store))
             (name (gethash "name" (gethash "metadata" object)))
             (key (core-resource-key resource namespace name))
             (revision (1+ (pod-store-resource-revision store)))
             (resources (copy-core-resource-index store)))
        (when (gethash key resources)
          (core-resource-error 409 "AlreadyExists" "~A ~A/~A already exists" (core-resource-kind resource) namespace name))
        (prepare-core-resource-metadata object nil revision)
        (apply-track-write nil object resource)
        (prepare-workload-write resource object nil)
        (when (batch-resource-p resource)
          (if (cronjob-resource-p resource) (prepare-cronjob-write object nil) (prepare-batch-write object nil)))
        (when (budget-resource-p resource) (prepare-budget-write object nil))
        (when (csr-resource-p resource) (prepare-csr-write object nil))
        (when (endpointslice-resource-p resource) (prepare-endpointslice-write object nil))
        (when (equal resource "persistentvolumeclaims") (enforce-claim-limit-ranges-unlocked store namespace object))
        (enforce-resource-quotas-unlocked store resource namespace object)
        (when (admission-config-resource-p resource) (prepare-admission-config-write object nil))
        (setf (gethash key resources) object)
        ;; A ClusterIP is claimed by its IPAddress object in the same commit, as upstream's allocator does.
        (when (equal resource "services")
          (setf revision (prepare-service-ip-address-writes resources object nil revision)))
        (unless dry-run (commit-core-resources store resources revision))
        (copy-core-object object)))))))

(defun core-resource-update-view (resource existing)
  "Copy stored object EXISTING into the form the current request's writer sees."
  (cond ((custom-resource-key-p resource) (crd-api-view (copy-core-object existing)))
        ((equal resource "events") (event-api-view (copy-core-object existing) (or *core-resource-view-version* "v1")))
        ((and (hpa-resource-p resource) (equal *core-resource-view-version* "autoscaling/v1")) (hpa-v1-view existing))
        ;; An API writer edits the version it asked for; in-process writers see the stored object.
        ((and (equal resource "podcertificaterequests") *core-resource-view-version*)
         (pod-certificate-request-view existing *core-resource-view-version*))
        (t (copy-core-object existing))))

(defun deletion-held-by-finalizers-p (metadata)
  "Return whether METADATA names finalizers besides the ones a propagation policy adds."
  (find-if-not (lambda (name) (member name '("foregroundDeletion" "orphan") :test #'equal))
               (gethash "finalizers" metadata #())))

(defun core-finalizer-lifecycle-p (resource)
  "Return whether RESOURCE's objects follow the generic finalizer lifecycle: a deleted object
with finalizers stays, deleting, until a client removes the last one. Kinds with a deletion
lifecycle of their own are excluded."
  (not (or (member resource '("namespaces" "customresourcedefinitions" "pods") :test #'equal)
           (custom-resource-key-p resource) (typed-api-resource-p resource)
           (storage-resource-p resource) (csr-resource-p resource))))

(defun core-write-unchanged-p (existing object)
  "Report whether OBJECT, a prepared write, stores exactly what EXISTING holds apart from its
revision. Upstream's storage skips such a write: the object keeps its resourceVersion and no
watch event is sent, so a repeated apply or update shows no drift."
  (let ((candidate (copy-core-object object)))
    (setf (gethash "resourceVersion" (gethash "metadata" candidate))
          (gethash "resourceVersion" (gethash "metadata" existing)))
    (crd-json-equal-p candidate existing)))

(defun update-core-resource (store resource namespace name transform &key dry-run)
  "Apply TRANSFORM to the current object for RESOURCE NAMESPACE NAME and store the
   result, returning a private copy. Runs under WITH-CORE-WRITE with deferred CRD
   conversions: enforces optimistic concurrency on resourceVersion (409 Conflict on
   mismatch; an omitted version is an unconditional update except for custom
   resources), rejects changes to immutable fields (roleRef, Service clusterIP,
   Secret type, immutable resource data, a changed uid), runs per-kind update
   validation and quota enforcement, and preserves a pending deletionTimestamp and
   its finalizers (no new finalizer may be added while deleting). A write that
   stores exactly what already exists is skipped -- no new revision, no watch
   event. When the transform clears the last finalizer of a deleting object (or
   finalizes a CSR), the object is removed instead. With DRY-RUN, prepares
   everything but does not commit."
  (let ((*local-plane-write* (local-plane-resource-p resource)))
   (with-crd-deferred-conversions
    (with-core-write (store)
    (expire-core-events-unlocked store)
    (let* ((existing (get-core-resource-unlocked store resource namespace name))
           (existing-metadata (gethash "metadata" existing))
           (object (normalize-core-resource resource (funcall transform (core-resource-update-view resource existing)) namespace name store))
           (metadata (gethash "metadata" object))
           (expected (gethash "resourceVersion" metadata))
           (revision (1+ (pod-store-resource-revision store))))
      ;; An omitted revision is an unconditional update, except for custom resources.
      (when (and (not (custom-resource-key-p resource)) (member expected '(nil "") :test #'equal))
        (setf expected (gethash "resourceVersion" existing-metadata)))
      (unless expected (core-resource-error 422 "Invalid" "metadata.resourceVersion is required for update"))
      (unless (equal expected (gethash "resourceVersion" existing-metadata))
        (core-resource-error 409 "Conflict" "The resource was modified; apply your changes to the latest version"))
      (when (equal resource "events") (validate-event-update existing object))
      (when (storage-resource-p resource) (validate-storage-update store resource existing object))
      (when (endpointslice-resource-p resource) (validate-endpointslice-update existing object))
      (when (policy-resource-p resource) (validate-policy-update resource existing object))
      (when (typed-api-resource-p resource) (validate-typed-api-update resource existing object))
      (when (member resource '("services" "persistentvolumeclaims") :test #'equal)
        (enforce-resource-quotas-unlocked store resource namespace object existing))
      (when (and (gethash "uid" metadata) (not (equal (gethash "uid" metadata) (gethash "uid" existing-metadata))))
        (core-resource-error 409 "Conflict" "metadata.uid does not match the stored object"))
      (when (and (member resource '("rolebindings" "clusterrolebindings") :test #'equal)
                 (let ((before (gethash "roleRef" existing)) (after (gethash "roleRef" object)))
                   (not (every (lambda (key) (equal (gethash key before) (gethash key after)))
                               '("apiGroup" "kind" "name")))))
        (core-resource-error 422 "Invalid" "roleRef is immutable"))
      (when (and (equal resource "services")
                 (not (or (service-external-name-p existing) (service-external-name-p object)))
                 (not (equal (gethash "clusterIP" (gethash "spec" existing))
                             (gethash "clusterIP" (gethash "spec" object)))))
        (core-resource-error 422 "Invalid" "Service clusterIP is immutable"))
      (when (and (string= resource "secrets") (not (equal (gethash "type" existing) (gethash "type" object))))
        (core-resource-error 422 "Invalid" "Secret.type is immutable"))
      (when (and (core-resource-immutable-p existing)
                 (or (not (core-resource-immutable-p object)) (not (core-resource-data-equal-p existing object))))
        (core-resource-error 422 "Invalid" "Immutable resource data cannot change"))
      (when (core-finalizer-lifecycle-p resource)
        (let ((pending (gethash "deletionTimestamp" existing-metadata)))
          (when pending
            (setf (gethash "deletionTimestamp" metadata) pending)
            (loop for finalizer across (gethash "finalizers" metadata #())
                  unless (find finalizer (gethash "finalizers" existing-metadata #()) :test #'equal)
                    do (core-resource-error 422 "Invalid" "metadata.finalizers: Forbidden: no new finalizers can be added if the object is being deleted")))))
      (prepare-core-resource-metadata object existing revision)
      (apply-track-write existing object resource)
      (prepare-workload-write resource object existing)
      (when (batch-resource-p resource)
        (if (cronjob-resource-p resource) (prepare-cronjob-write object existing) (prepare-batch-write object existing)))
      (when (budget-resource-p resource) (prepare-budget-write object existing))
      (when (csr-resource-p resource) (prepare-csr-write object existing))
      (when (endpointslice-resource-p resource) (prepare-endpointslice-write object existing))
      (when (admission-config-resource-p resource) (prepare-admission-config-write object existing))
      (let ((resources (copy-core-resource-index store))
            (removed (or (and (csr-resource-p resource) (csr-finalized-p object))
                         (and (or (custom-resource-key-p resource) (typed-api-resource-p resource) (core-finalizer-lifecycle-p resource))
                              (gethash "deletionTimestamp" metadata) (zerop (length (gethash "finalizers" metadata #())))))))
        ;; A COND (not RETURN-FROM) so WITH-CORE-WRITE's consensus flush still runs.
        (cond
          ((and (not removed) (core-write-unchanged-p existing object))
           (copy-core-object existing))
          (t
           (if removed
               (progn
                 (remhash (core-resource-key resource namespace name) resources)
                 ;; A selector Service owns the Endpoints of its name, as on any other deletion.
                 (when (and (equal resource "services") (plusp (hash-table-count (gethash "selector" (gethash "spec" existing) (core-object)))))
                   (remhash (core-resource-key "endpoints" namespace name) resources)))
               (setf (gethash (core-resource-key resource namespace name) resources) object))
           (when (equal resource "services")
             (setf revision (prepare-service-ip-address-writes resources object existing revision)))
           (unless dry-run (commit-core-resources store resources revision))
           (copy-core-object object)))))))))

(defun delete-core-resource (store resource namespace name &key uid resource-version dry-run)
  "Delete the object for RESOURCE NAMESPACE NAME, returning a private copy of what
   was removed or, for a finalizer-held deletion, the object now marked deleting.
   Runs under WITH-CORE-WRITE: enforces the optional UID and RESOURCE-VERSION
   preconditions (409 Conflict on mismatch) and delegates CRD, custom, CSR,
   storage, namespace, and typed-API kinds to their own deletion paths. An object
   still holding non-propagation finalizers is stamped with a deletionTimestamp and
   kept until its last finalizer is removed; otherwise it is removed outright, and a
   selector Service's Endpoints go with it. With DRY-RUN, prepares everything but
   does not commit."
  ;; A COND (not RETURN-FROM) so WITH-CORE-WRITE's consensus flush always runs on
  ;; the delegated CRD/CSR/storage delete paths too (they stash via COMMIT-CORE-RESOURCES).
  (let ((*local-plane-write* (local-plane-resource-p resource)))
   (with-core-write (store)
    (expire-core-events-unlocked store)
    (let* ((existing (get-core-resource-unlocked store resource namespace name))
           (metadata (gethash "metadata" existing)))
      (when (or (and uid (not (equal uid (gethash "uid" metadata))))
                (and resource-version (not (equal resource-version (gethash "resourceVersion" metadata)))))
        (core-resource-error 409 "Conflict" "Delete precondition does not match the stored object"))
      ;; A COND (not RETURN-FROM) so WITH-CORE-WRITE's consensus flush always runs
      ;; on the delegated delete paths too (they stash via COMMIT-CORE-RESOURCES).
      (cond
        ((or (equal resource "customresourcedefinitions") (custom-resource-key-p resource))
         (delete-crd-object-unlocked store resource existing dry-run))
        ((csr-resource-p resource)
         (delete-csr-unlocked store existing dry-run))
        ((storage-resource-p resource)
         (delete-storage-resource-unlocked store resource existing dry-run))
        ((equal resource "namespaces")
         (delete-namespace-unlocked store existing dry-run))
        ((typed-api-resource-p resource)
         (delete-typed-api-resource-unlocked store resource existing dry-run))
        ;; A finalizer holds the object, deleting, until a client removes the last one.
        ((deletion-held-by-finalizers-p metadata)
         (when (policy-resource-p resource) (validate-policy-delete resource existing))
         (if (gethash "deletionTimestamp" metadata)
             (copy-core-object existing)
             (let ((copy (copy-core-object existing)) (resources (copy-core-resource-index store))
                   (revision (1+ (pod-store-resource-revision store))))
               (setf (gethash "deletionTimestamp" (gethash "metadata" copy)) (current-timestamp))
               (prepare-core-resource-metadata copy existing revision)
               (setf (gethash (core-resource-key resource namespace name) resources) copy)
               (unless dry-run (commit-core-resources store resources revision))
               (copy-core-object copy))))
        (t
         (when (policy-resource-p resource) (validate-policy-delete resource existing))
         (let ((resources (copy-core-resource-index store)))
           (remhash (core-resource-key resource namespace name) resources)
           ;; A selector Service owns the Endpoints of its name; a manual Endpoints object outlives its Service.
           (when (and (equal resource "services") (plusp (hash-table-count (gethash "selector" (gethash "spec" existing) (core-object)))))
             (remhash (core-resource-key "endpoints" namespace name) resources))
           (unless dry-run (commit-core-resources store resources (1+ (pod-store-resource-revision store)))))
         (copy-core-object existing)))))))
