;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
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
            (gethash (node-record-name node) (pod-store-nodes store)) node)
      (publish-node-change-unlocked store nil node)
      ;; Desired write (the control-plane-assigned podCIDR): replicate (8ia.4).
      (note-node-desired-change store)
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
        (when old (publish-node-change-unlocked store old node)))
      node)))

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
    (setf (node-record-ready-p updated) nil)
    (persist-node store updated)
    (setf (node-record-ready-p node) nil)
    (publish-node-change-unlocked store old node)))

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

(defun allocate-node-pod-cidr (store cluster-cidr node-prefix)
  "Return the first free NODE-PREFIX block within CLUSTER-CIDR."
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
                           thereis (and (plusp (length (node-record-pod-cidr node)))
                                        (ipv4-prefixes-overlap-p candidate (node-record-pod-cidr node))))
                return candidate
              finally (error "No free /~D PodCIDR remains in ~A"
                             node-prefix cluster-cidr))))))

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

(defun persist-pod-assignment (store pod node-name)
  "Assign POD to NODE-NAME, advance its resource version, and persist it."
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
    pod))

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
  "Prefer a node POD's affinity favors, then the fewest Pods, then a stable name."
  (let ((left-score (+ (pod-node-preference-score pod left) (pod-affinity-preference-score-unlocked store pod left)))
        (right-score (+ (pod-node-preference-score pod right) (pod-affinity-preference-score-unlocked store pod right)))
        (left-count (assigned-nonterminal-pod-count store (node-record-name left)))
        (right-count (assigned-nonterminal-pod-count store (node-record-name right))))
    (cond ((/= left-score right-score) (> left-score right-score))
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

(defun schedule-pod (store pod)
  "Return POD's selected node, or preempt lower-priority Pods when no placeable node fits it."
  (let ((node nil) (victims nil))
    (with-store-lock (store)
      (let ((requested-node (pod-node-name pod)))
        (when requested-node
          (return-from schedule-pod (get-node-unlocked store requested-node)))
        ;; As kube-scheduler does, leave a Pod naming another scheduler for that one to bind.
        (unless (pod-for-this-scheduler-p pod)
          (return-from schedule-pod nil)))
      (let* ((placeable (loop for candidate being the hash-values of (pod-store-nodes store)
                              when (pod-node-placeable-p store pod candidate) collect candidate))
             (fitting (remove-if-not (lambda (candidate) (pod-fits-node-unlocked store pod candidate)) placeable)))
        (setf node (first (sort fitting (lambda (left right) (node-placement-better-p store pod left right)))))
        (if node
            (progn
              (remhash (pod-uid pod) (pod-store-nominated-nodes store))
              (persist-pod-assignment store pod (node-record-name node)))
            (let ((plan (choose-preemption-unlocked store pod placeable)))
              (when plan
                (setf victims (cdr plan)
                      (gethash (pod-uid pod) (pod-store-nominated-nodes store)) (node-record-name (car plan))))))))
    ;; Deletion takes the store lock itself and is retried by reconciliation.
    (dolist (victim victims) (preempt-pod store victim))
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
