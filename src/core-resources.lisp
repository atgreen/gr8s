(in-package #:gr8s)

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
  (let ((object (make-hash-table :test #'equal)))
    (loop for (key value) on pairs by #'cddr do (setf (gethash key object) value))
    object))

(defun copy-core-object (object)
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
      (error "Unknown stored resource ~S" resource)))

(defun core-resource-kind (resource)
  (second (stored-resource-type resource)))

(defun core-resource-api-version (resource)
  "Return the API version serialized for RESOURCE."
  (third (stored-resource-type resource)))

(defun core-resource-namespaced-p (resource)
  "Return whether RESOURCE is scoped to a namespace."
  (fourth (stored-resource-type resource)))

(defun core-resource-error (code reason control &rest arguments)
  (error 'kubernetes-error :status-code code :reason reason
         :message (apply #'format nil control arguments)))

(defun core-resource-key (resource namespace name)
  (list resource namespace name))

(defun core-resource-state-path (store)
  (merge-pathnames "objects/state.json" (pod-store-path store)))

(defun core-journal-path (store)
  "The journal of commits made after the checkpoint at CORE-RESOURCE-STATE-PATH."
  (merge-pathnames "objects/journal.jsonl" (pod-store-path store)))

(defparameter *core-journal-checkpoint-bytes* (* 8 1024 1024)
  "Journal size past which the next commit writes a checkpoint and starts a new journal.
A journal may also grow to the size of the checkpoint, so writing checkpoints costs
each commit a bounded multiple of what it changed, whatever the size of the store.")

(defun core-resource-key-from-object (resource object)
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
            do (add (or (first (find (gethash "kind" object) *stored-resource-types* :key #'second :test #'equal))
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

(defun read-core-journal-records (path)
  "Return PATH's complete journal records in order, whether a torn final record was
dropped, and the bytes the complete records occupy. Only the last record can be torn,
by a crash while it was appended; damage anywhere else is an error."
  (let ((records nil) (torn nil) (bytes 0))
    (with-open-file (stream path :element-type '(unsigned-byte 8))
      (let* ((length (file-length stream))
             (octets (make-array length :element-type '(unsigned-byte 8))))
        (read-sequence octets stream)
        (loop with start = 0
              while (< start length)
              do (let ((end (position 10 octets :start start)))
                   (if (null end)
                       (progn (setf torn t) (return))
                       (let ((record (handler-case
                                         (com.inuoe.jzon:parse
                                          (trivial-utf-8:utf-8-bytes-to-string octets :start start :end end)
                                          :max-string-length (* 2 1024 1024))
                                       (error (condition)
                                         (error "Damaged core resource journal record at byte ~D of ~A: ~A"
                                                start path condition)))))
                         (push record records)
                         (setf start (1+ end) bytes start)))))))
    (values (nreverse records) torn bytes)))

(defun replay-core-journal (state records)
  "Apply journal RECORDS newer than STATE's revision to STATE, a parsed checkpoint,
rebuilding the history a commit used to write. Return STATE, now in checkpoint form."
  (let* ((index (core-state-index state))
         (history (coerce (gethash "templateHistory" state #()) 'list))
         (floor (gethash "templateHistoryFloor" state (gethash "revision" state)))
         (expirations (gethash "eventExpirations" state (make-hash-table :test #'equal)))
         (time nil))
    (dolist (record records)
      (let ((revision (gethash "revision" record)))
        (when (> revision (gethash "revision" state))
          (setf time (gethash "time" record))
          (loop for change across (gethash "changes" record #())
                for key = (core-resource-key (gethash "resource" change)
                                             (let ((namespace (gethash "namespace" change)))
                                               (unless (eq namespace 'null) namespace))
                                             (gethash "name" change))
                for old = (gethash key index)
                for new = (let ((object (gethash "object" change))) (unless (eq object 'null) object))
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
                (gethash "resourceHistoryStart" record (gethash "resourceHistoryStart" state revision))))))
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
    state))

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
        (if (probe-file journal)
            (multiple-value-bind (records torn bytes) (read-core-journal-records journal)
              (values (replay-core-journal state records) torn bytes))
            (values state nil 0))))))

(defun load-core-resources (store)
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
            for resource = (or (first (find (gethash "kind" object) *stored-resource-types*
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
  (member resource *raft-local-plane-resources* :test #'equal))

(defun core-checkpoint-object (store resources revision workload-deletions job-controller-states
                               history floor token-key event-expirations &key omit-local-plane)
  "Return the complete durable core-resource state, as a checkpoint or HA state blob holds it."
  (multiple-value-bind (durable durable-floor) (durable-template-history history floor)
    (progn
     (core-object "version" 2 "revision" revision "workloadDeletions" workload-deletions
                  "jobControllerStates" job-controller-states
                  "templateHistory" (coerce durable 'vector) "templateHistoryFloor" durable-floor
                  "templateTokenKey" (ag-grpc:base64-encode token-key)
                  "resourceHistoryStart" (pod-store-resource-history-start store)
                  "eventExpirations" event-expirations
                  "items" (coerce (loop for key being the hash-keys of resources using (hash-value object)
                                        unless (or (custom-resource-key-p (first key))
                                                   (and omit-local-plane (local-plane-resource-p (first key))))
                                          collect object) 'vector)
                  "customResourceItems" (coerce (loop for key being the hash-keys of resources using (hash-value object)
                                                      when (custom-resource-key-p (first key))
                                                        collect (core-object "resource" (first key) "object" object)) 'vector)))))

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

(defun core-map-delta (old new)
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
        (core-object "set" set "delete" (coerce deleted 'vector))))))

(defun core-journal-record-json (store revision added workload-deletions job-controller-states event-expirations)
  "Serialize one commit as a journal line: only what it changed. ADDED are its history entries."
  (let ((changes nil) (expirations (core-object)) (record (core-object "revision" revision)))
    (dolist (entry added)
      (let ((new (gethash "new" entry)))
        (push (core-object "resource" (gethash "resource" entry) "namespace" (or (gethash "namespace" entry) 'null)
                           "name" (gethash "name" entry) "object" new)
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
           (core-state-json store resources revision workload-deletions job-controller-states
                            :omit-local-plane t)))
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

(defun copy-core-resource-index (store)
  (let ((copy (make-hash-table :test #'equal)))
    (maphash (lambda (key value) (setf (gethash key copy) value))
             (pod-store-resources store))
    copy))

(defun core-data-key-p (key)
  (and (stringp key) (<= 1 (length key) 253)
       (every (lambda (character)
                (or (find character "-_.")
                    (and (char<= #\a character) (char<= character #\z))
                    (and (char<= #\A character) (char<= character #\Z))
                    (digit-char-p character))) key)))

(defun validate-core-string-map (object context &key data-keys)
  (require-object object context)
  (maphash (lambda (key value)
             (unless (and (stringp key) (stringp value)
                          (or (not data-keys) (core-data-key-p key)))
               (core-resource-error 422 "Invalid" "~A requires valid keys and string values" context)))
           object)
  object)

(defun core-base64-bytes (value context)
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
  (and (stringp value) (<= (length value) 63)
       (if (zerop (length value)) empty
           (and (alphanumericp (char value 0)) (alphanumericp (char value (1- (length value))))))
       (every (lambda (character)
                (or (and (char<= #\a character) (char<= character #\z))
                    (and (char<= #\A character) (char<= character #\Z))
                    (digit-char-p character) (find character "-_."))) value)))

(defun core-qualified-key-p (value)
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
  (or (gethash (core-resource-key resource namespace name) (pod-store-resources store))
      (core-resource-error 404 "NotFound" "~A ~A/~A was not found" (core-resource-kind resource) namespace name)))

(defun get-core-resource (store resource namespace name)
  (with-store-lock (store)
    (check-crd-resource-context-unlocked store resource)
    (expire-core-events-unlocked store)
    (copy-core-object (get-core-resource-unlocked store resource namespace name))))

(defun list-core-resources (store resource &optional namespace)
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
  (let ((metadata (gethash "metadata" object)))
    (setf (gethash "uid" metadata) (if existing
                                       (gethash "uid" (gethash "metadata" existing))
                                       (or *core-resource-assigned-uid* (generate-uid)))
          (gethash "creationTimestamp" metadata)
          (if existing (gethash "creationTimestamp" (gethash "metadata" existing)) (current-timestamp))
          (gethash "resourceVersion" metadata) (write-to-string revision)))
  object)

(defun core-resource-immutable-p (object)
  (eq t (gethash "immutable" object)))

(defun core-resource-data-equal-p (left right)
  ;; JSON's map order is insignificant.
  (labels ((map-equal (a b)
             (and (= (if a (hash-table-count a) 0) (if b (hash-table-count b) 0))
                  (or (null a) (loop for key being the hash-keys of a using (hash-value value)
                                    always (and b (equal value (gethash key b))))))))
    (and (map-equal (gethash "data" left) (gethash "data" right))
         (map-equal (gethash "binaryData" left) (gethash "binaryData" right)))))

(defun create-core-resource (store resource input namespace &key dry-run)
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
