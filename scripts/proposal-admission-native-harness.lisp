;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;; Actual loopback replication and production store writes; no containers/BPF.
(in-package #:cl-user)

(defun admission-native-await (predicate &optional (seconds 120))
  (let ((deadline (+ (get-internal-real-time) (* seconds internal-time-units-per-second))))
    (loop when (funcall predicate) return t
          when (> (get-internal-real-time) deadline) do (error "Admission acceptance timed out")
          do (sleep 0.02))))

(defun admission-native-input (name value)
  (gr8s::core-object "apiVersion" "v1" "kind" "ConfigMap"
    "metadata" (gr8s::core-object "name" name) "data" (gr8s::core-object "value" value)))

(defun admission-native-main ()
  (gr8s.server::install-memory-hooks)
  (destructuring-bind (root-text rounds-text) (uiop:command-line-arguments)
    (let* ((root (uiop:ensure-directory-pathname root-text)) (rounds (parse-integer rounds-text))
           (ids #("admit-a" "admit-b" "admit-c" "admit-learner"))
           (stores (make-array 4 :initial-element nil)) (planes (make-array 4 :initial-element nil))
           (ports (make-array 4 :initial-element 0)) (leader-index nil)
           (capacity-count 0) (timeout-count 0) (full nil)
           (limit (* 16 1024 1024))
           (report (gr8s::core-object "passed" nil "nativeHarness" t "productionServe" nil
                     "vmAcceptance" nil "mutualTls" nil "processes" 1 "members" 4 "voters" 3
                     "heapLimitMiB" (/ (sb-ext:dynamic-space-size) (* 1024 1024))
                     "rounds" rounds "attemptedPayloadBytes" (* rounds 65536)
                     "admissionBudgetBytes" limit "productionProposalTimeoutSeconds" 10)))
      (labels ((member-at (i) (gr8s::ha-control-plane-member (aref planes i)))
               (start-at (i fresh)
                 (let* ((path (merge-pathnames (format nil "~A/" (aref ids i)) root))
                        (store (gr8s:open-store path :defer-restore-completion (not fresh)))
                        (ha
                          (if (< i 3)
                              (gr8s::start-ha-control-plane store :id (aref ids i) :init (zerop i)
                                :join-host (unless (zerop i) "127.0.0.1") :join-port (aref ports 0)
                                :port (aref ports i))
                              (let ((member (gr8s.resources::start-store-member-from-wal
                                             store (aref ids i) (merge-pathnames "raft/control-plane.log" path)
                                             :bootstrap-role (when fresh :learner) :port (aref ports i))))
                                (bt:with-lock-held ((gr8s::raft-member-lock member))
                                  (setf (gr8s.raft::raft-node-uncommitted-byte-limit
                                         (gr8s::raft-member-node member)) limit)
                                  (gr8s::raft-member-enable-dynamic-membership member))
                                (gr8s::raft-member-start member)
                                (when fresh
                                  (assert (gr8s::raft-cluster-join member "127.0.0.1" (aref ports 0) :role :learner)))
                                (gr8s.ha::make-ha-control-plane :member member :store store)))))
                   (setf (aref stores i) store (aref planes i) ha
                         (aref ports i) (gr8s::raft-member-port (gr8s::ha-control-plane-member ha)))))
               (stop-at (i)
                 (when (aref planes i)
                   (gr8s::stop-ha-control-plane (aref planes i))
                   (setf (aref planes i) nil)))
               (ready ()
                 (and (loop for ha across planes always
                            (and ha (not (gr8s.store::store-access-blocked-p (gr8s.ha::ha-control-plane-store ha)))))
                      (loop for i below 4 always
                        (bt:with-lock-held ((gr8s::raft-member-lock (member-at i)))
                          (let ((node (gr8s::raft-member-node (member-at i))))
                            (and (= 3 (gr8s::raft-cluster-size node))
                                 (eq (if (= i 3) :learner :voter) (gr8s::raft-node-self-role node))))))))
               (value-at (i name)
                 (handler-case
                     (gethash "value" (gethash "data"
                       (gr8s::get-core-resource (aref stores i) "configmaps" "default" name)))
                   (gr8s:kubernetes-error () nil)))
               (all-have (name value) (loop for i below 4 always (equal value (value-at i name))))
               (sample (&optional (require-leader t))
                 (let ((member (member-at leader-index)))
                   (bt:with-lock-held ((gr8s::raft-member-lock member))
                     (let* ((node (gr8s::raft-member-node member))
                            (storage (gr8s.raft.transport::raft-member-owned-storage member)))
                       (when require-leader (assert (eq :leader (gr8s::raft-node-role node))))
                       (gr8s::core-object "lastIndex" (gr8s::raft-last-log-index node)
                         "commitIndex" (gr8s::raft-node-commit-index node)
                         "pendingCallbacks" (hash-table-count (gr8s.raft::raft-node-pending node))
                         "uncommittedWeightBytes"
                         (loop for entry across (gr8s.raft:raft-node-log node)
                               when (> (gr8s.raft:raft-entry-index entry) (gr8s::raft-node-commit-index node))
                                 sum (+ 128 (gr8s.raft::raft-command-wire-weight (gr8s.raft:raft-entry-command entry))))
                         "walBytes" (sb-posix:stat-size
                           (sb-posix:fstat (sb-sys:fd-stream-fd (gr8s.raft::file-raft-storage-stream storage)))))))))
               (pending-resources (i)
                 (loop for key being the hash-keys of (gr8s::pod-store-resources (aref stores i))
                       count (and (equal "configmaps" (first key)) (uiop:string-prefix-p "pending-" (third key))))))
        (unwind-protect
             (handler-case
                 (progn
                   (assert (= 384 (gethash "heapLimitMiB" report)))
                   (assert (>= rounds 2048))
                   (start-at 0 t)
                   (admission-native-await (lambda () (gr8s::ha-control-plane-leader-p (aref planes 0))))
                   (start-at 1 t)
                   (start-at 2 t)
                   (start-at 3 t)
                   (admission-native-await #'ready)
                   (gr8s::create-core-resource (aref stores 0) "namespaces"
                     (gr8s::core-object "apiVersion" "v1" "kind" "Namespace"
                       "metadata" (gr8s::core-object "name" "default")) nil)
                   (gr8s::create-core-resource (aref stores 0) "configmaps"
                     (admission-native-input "sentinel" "preserved") "default")
                   (admission-native-await (lambda () (all-have "sentinel" "preserved")))
                   (setf leader-index (position-if #'gr8s::ha-control-plane-leader-p planes))
                   (assert (and leader-index (< leader-index 3)))
                   ;; Leave one voter and a non-voting forwarder connected. They
                   ;; cannot form quorum; the learner exercises the real RPC path.
                   (dotimes (i 3) (unless (= i leader-index) (stop-at i)))
                   (let ((baseline (sample)))
                     (dotimes (i rounds)
                       (handler-case
                           (progn
                             (gr8s::create-core-resource (aref stores leader-index) "configmaps"
                               (admission-native-input (format nil "pending-~D" i)
                                 (make-string 65536 :initial-element #\x)) "default")
                             (error "A minority write was acknowledged"))
                         (gr8s:kubernetes-error (condition)
                           (assert (= 503 (gr8s::kubernetes-error-status-code condition)))
                           (if (search "capacity" (gr8s::kubernetes-error-message condition))
                               (incf capacity-count) (incf timeout-count))))
                       (let ((current (sample)))
                         (assert (= (gethash "commitIndex" baseline) (gethash "commitIndex" current)))
                         (assert (<= (gethash "uncommittedWeightBytes" current) limit))
                         (when (plusp capacity-count)
                           (if full (assert (equalp full current)) (setf full current))))
                       (when (zerop (mod i 128))
                         (format *error-output* "~&admission progress: ~A~%"
                           (com.inuoe.jzon:stringify
                             (gr8s::core-object "attempts" (1+ i) "capacityRefusals" capacity-count
                               "timeouts" timeout-count "tail" (sample))))
                         (finish-output *error-output*)))
                     (assert (plusp timeout-count))
                     (assert (> capacity-count 1000))
                     (assert (<= (- (gethash "walBytes" full) (gethash "walBytes" baseline)) limit)))
                   ;; A follower's capacity refusal must survive RPC encoding and
                   ;; return without appending or retaining another callback.
                   (handler-case
                       (progn
                         (gr8s::create-core-resource (aref stores 3) "configmaps"
                           (admission-native-input "forwarded-overload" (make-string 65536 :initial-element #\x)) "default")
                         (error "Forwarded minority write was acknowledged"))
                     (gr8s:kubernetes-error (condition)
                       (assert (= 503 (gr8s::kubernetes-error-status-code condition)))
                       (assert (search "capacity" (gr8s::kubernetes-error-message condition)))))
                   (assert (equalp full (sample)))
                   (setf (gethash "fullTail" report) full)
                   (dotimes (i 3) (unless (= i leader-index) (start-at i nil)))
                   (admission-native-await #'ready)
                   (admission-native-await (lambda () (zerop (gethash "uncommittedWeightBytes" (sample nil)))))
                   (assert (zerop (gethash "pendingCallbacks" (sample nil))))
                   (gr8s::create-core-resource (aref stores 3) "configmaps"
                     (admission-native-input "after-recovery" "committed") "default")
                   (admission-native-await (lambda () (and (all-have "sentinel" "preserved")
                                                          (all-have "after-recovery" "committed"))))
                   ;; Full durable reopen, including the member that held the
                   ;; unknown-outcome tail. Unacknowledged writes may commit or
                   ;; be discarded; acknowledged sentinel/new data must survive.
                   (dotimes (i 4) (stop-at i))
                   (dotimes (i 4) (start-at i nil))
                   (admission-native-await #'ready)
                   (admission-native-await (lambda () (and (all-have "sentinel" "preserved")
                                                          (all-have "after-recovery" "committed"))))
                   (let ((pending (pending-resources 0)))
                     (assert (loop for i below 4 always (= pending (pending-resources i))))
                     (setf (gethash "unknownOutcomeWritesPresent" report) pending))
                   (setf (gethash "passed" report) t (gethash "capacityRefusals" report) capacity-count
                         (gethash "timedOutProposals" report) timeout-count
                         (gethash "forwardedCapacityRefusal" report) t
                         (gethash "sentinelRecovered" report) t (gethash "newWritesAfterRecovery" report) t
                         (gethash "durableReopen" report) t))
               (error (condition) (setf (gethash "error" report) (princ-to-string condition))))
          (dotimes (i 4) (stop-at i)))
        (write-line (com.inuoe.jzon:stringify report))
        (uiop:quit (if (gethash "passed" report) 0 1))))))
