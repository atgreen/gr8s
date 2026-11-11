;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
(in-package #:gr8s/tests)
(def-suite store-snapshot-registry :in gr8s)
(in-suite store-snapshot-registry)

(test publication-validates-new-inode-once-and-rechecks-existing-winners
  (with-temporary-store (store root)
    (let ((source (merge-pathnames "transfer.jsonl" root))
          (validate (symbol-function 'gr8s.resources::validate-store-snapshot))
          (scans 0))
      (gr8s.resources::capture-store-snapshot store source 42 7)
      (let ((digest (snapshot-test-digest source)))
        (unwind-protect
             (progn
               (setf (symbol-function 'gr8s.resources::validate-store-snapshot)
                     (lambda (path &rest args)
                       (incf scans)
                       (apply validate path args)))
               (let ((target (gr8s.resources::retain-store-snapshot-artifact root source 42 7 digest)))
                 (is (= 1 scans))
                 (setf scans 0)
                 (is (equal target (gr8s.resources::retain-store-snapshot-artifact root source 42 7 digest)))
                 (is (= 2 scans))
                 (with-open-file (out target :direction :output :if-exists :append)
                   (write-line "corrupt" out))
                 (signals error (gr8s.resources::retain-store-snapshot-artifact root source 42 7 digest))))
          (setf (symbol-function 'gr8s.resources::validate-store-snapshot) validate))))))

(test retained-artifacts-survive-source-cleanup-and-reopen
  (with-temporary-store (store root)
    (let ((source (merge-pathnames "transfer.jsonl" root)))
      (gr8s.resources::capture-store-snapshot store source 42 7)
      (let ((digest (snapshot-test-digest source)))
        (multiple-value-bind (path reference)
            (gr8s.resources::retain-store-snapshot-artifact root source 42 7 digest)
          (is (equal reference (list :gr8s-store-artifact 1 :index 42 :term 7 :sha256 digest)))
          (is (= #o600 (logand #o777 (sb-posix:stat-mode (sb-posix:stat path)))))
          (is (= #o700 (logand #o777 (sb-posix:stat-mode
                                     (sb-posix:stat (uiop:pathname-directory-pathname path))))))
          (is (equal path (gr8s.resources::retain-store-snapshot-artifact root source 42 7 digest)))
          (delete-file source)
          (is (equal path (gr8s.resources::checked-store-snapshot-artifact-path root reference)))
          (multiple-value-bind (generation descriptor)
              (gr8s.resources::materialize-store-snapshot root path digest :expected-index 42 :expected-term 7)
            (declare (ignore generation))
            (is (= 42 (gethash "index" descriptor))))
          (signals error (gr8s.resources::checked-store-snapshot-artifact-path
                          root (gr8s.resources::store-snapshot-artifact-reference 43 7 digest)))
          (with-open-file (out path :direction :output :if-exists :append) (write-line "corrupt" out))
          (signals error (gr8s.resources::checked-store-snapshot-artifact-path root reference)))))))

(test rejected-artifacts-never-get-published
  (with-temporary-store (store root)
    (let ((source (merge-pathnames "transfer.jsonl" root)))
      (gr8s.resources::capture-store-snapshot store source 42 7)
      (let* ((digest (snapshot-test-digest source))
             (directory (gr8s.resources::store-snapshot-registry-directory root)))
        (signals error (gr8s.resources::retain-store-snapshot-artifact root source 43 7 digest))
        (signals error (gr8s.resources::retain-store-snapshot-artifact root source 42 8 digest))
        (signals error (gr8s.resources::retain-store-snapshot-artifact root source 42 7 (make-string 64 :initial-element #\0)))
        (signals error (gr8s.resources::retain-store-snapshot-artifact root source 42 7 "../bad"))
        (is (null (directory (merge-pathnames "*.*" directory))))
        (signals error (gr8s.resources::checked-store-snapshot-artifact-path
                        root (gr8s.resources::store-snapshot-artifact-reference 42 7 digest)))
        (signals error (gr8s.resources::checked-store-snapshot-artifact-path
                        root (list :gr8s-store-artifact 2 :index 42 :term 7 :sha256 digest)))))))

(test retained-artifact-symlinks-and-unsafe-permissions-are-rejected
  (with-temporary-store (store root)
    (let ((source (merge-pathnames "transfer.jsonl" root)))
      (gr8s.resources::capture-store-snapshot store source 42 7)
      (let* ((digest (snapshot-test-digest source))
             (reference (gr8s.resources::store-snapshot-artifact-reference 42 7 digest))
             (directory (gr8s.resources::store-snapshot-registry-directory root))
             (target (merge-pathnames (format nil "~A.jsonl" digest) directory)))
        (sb-posix:symlink (namestring source) (namestring target))
        (signals error (gr8s.resources::retain-store-snapshot-artifact root source 42 7 digest))
        (signals error (gr8s.resources::checked-store-snapshot-artifact-path root reference))
        (sb-posix:unlink (namestring target))
        (gr8s.resources::retain-store-snapshot-artifact root source 42 7 digest)
        (sb-posix:chmod (namestring target) #o644)
        (signals error (gr8s.resources::checked-store-snapshot-artifact-path root reference))))))

(test artifact-directory-sync-failure-requires-a-successful-retry
  (with-temporary-store (store root)
    (let* ((source (merge-pathnames "transfer.jsonl" root))
           (directory (gr8s.resources::store-snapshot-registry-directory root))
           (original (symbol-function 'gr8s.store::sync-store-generation-directory))
           (injected nil))
      (gr8s.resources::capture-store-snapshot store source 42 7)
      (let ((digest (snapshot-test-digest source)))
        (unwind-protect
             (progn
               (setf (symbol-function 'gr8s.store::sync-store-generation-directory)
                     (lambda (path)
                       (when (equal path directory)
                         (setf injected t)
                         (error "Injected registry directory sync failure"))
                       (funcall original path)))
               (signals error (gr8s.resources::retain-store-snapshot-artifact root source 42 7 digest)))
          (setf (symbol-function 'gr8s.store::sync-store-generation-directory) original))
        (is-true injected)
        (multiple-value-bind (path reference)
            (gr8s.resources::retain-store-snapshot-artifact root source 42 7 digest)
          (delete-file source)
          (is (equal path (gr8s.resources::checked-store-snapshot-artifact-path root reference))))))))

(defun artifact-wire-test-message (reference)
  (list :type :install-snapshot :term 9 :from "source" :last-index 42 :last-term 7
        :state (list :gr8s-raft-snapshot 1 :application reference :application-present t
                     :members '(("source" . :voter) ("sink" . :learner)) :addresses nil :api-urls nil)))

(defun send-artifact-wire-test-snapshot (sender receiver message)
  (let ((channel (gr8s::make-raft-channel (gr8s::raft-member-credentials sender)
                                        "127.0.0.1" (gr8s::raft-member-port receiver) 2)))
    (unwind-protect
         (gr8s.raft.transport::raft-link-send-snapshot sender (gr8s.node.v1::make-raft-transport-stub channel) message)
      (ag-grpc:channel-close channel))))

(test artifact-rpc-retains-bytes-before-wal-and-survives-transfer-cleanup
  (with-temporary-store (source source-root)
    (with-temporary-store (sink sink-root)
      (declare (ignore sink))
      (let* ((artifact (merge-pathnames "source.jsonl" source-root))
             (wal (merge-pathnames "raft/transfer.log" sink-root))
             (credentials (gr8s::ensure-raft-founder-credentials (merge-pathnames "tls/" source-root) "source"))
             (sink-credentials (snapshot-test-member-credentials (merge-pathnames "tls/" sink-root) "sink" credentials))
             (sender nil) (receiver nil) (restored nil) (seen-durable nil))
        (gr8s::create-core-resource source "configmaps"
         (gr8s::core-object "apiVersion" "v1" "kind" "ConfigMap"
                           "metadata" (gr8s::core-object "name" "large")
                           "data" (gr8s::core-object "payload" (make-string 200000 :initial-element #\x))) "default")
        (gr8s.resources::capture-store-snapshot source artifact 42 7)
        (multiple-value-bind (retained reference)
            (gr8s.resources::retain-store-snapshot-artifact source-root artifact 42 7 (snapshot-test-digest artifact))
          (declare (ignore retained))
          (delete-file artifact)
          (unwind-protect
               (progn
                 (setf sender (gr8s::start-raft-member "source" :credentials credentials)
                       receiver (gr8s::start-raft-member "sink" :storage-path wal :credentials sink-credentials
                                  :restore-fn
                                  (lambda (ref)
                                    (setf seen-durable
                                          (and (probe-file (gr8s.resources::checked-store-snapshot-artifact-path sink-root ref))
                                               (= 42 (gr8s::raft-recovered-snapshot-index (gr8s::load-raft-log wal))))
                                          restored ref))))
                 (gr8s.resources::configure-store-artifact-transport sender source-root)
                 (gr8s.resources::configure-store-artifact-transport receiver sink-root)
                 (send-artifact-wire-test-snapshot sender receiver (artifact-wire-test-message reference))
                 (is-true seen-durable)
                 (is (equal reference restored))
                 (is (= 42 (gr8s::raft-node-last-applied (gr8s::raft-member-node receiver))))
                 (is (null (gr8s.raft.transport::raft-member-snapshot-receiver receiver)))
                 (let ((path (gr8s.resources::checked-store-snapshot-artifact-path sink-root reference)))
                   (is (> (sb-posix:stat-size (sb-posix:stat path)) 65536))
                   (is (equal (eighth reference) (snapshot-test-digest path))))
                 (gr8s::stop-raft-member receiver)
                 (setf receiver nil)
                 (let ((recovered (gr8s::load-raft-log wal)))
                   (is (equal reference (getf (cddr (gr8s::raft-recovered-snapshot-state recovered)) :application)))
                   (is (probe-file (gr8s.resources::checked-store-snapshot-artifact-path sink-root reference)))))
            (when receiver (gr8s::stop-raft-member receiver))
            (when sender (gr8s::stop-raft-member sender))))))))

(test artifact-retention-failure-cannot-persist-a-wal-reference-and-retry-succeeds
  (with-temporary-store (source source-root)
    (with-temporary-store (sink sink-root)
      (declare (ignore sink))
      (let ((artifact (merge-pathnames "source.jsonl" source-root))
            (wal (merge-pathnames "raft/transfer.log" sink-root)) (sender nil) (receiver nil))
        (gr8s.resources::capture-store-snapshot source artifact 42 7)
        (multiple-value-bind (path reference)
            (gr8s.resources::retain-store-snapshot-artifact source-root artifact 42 7 (snapshot-test-digest artifact))
          (declare (ignore path))
          (unwind-protect
               (progn
                 (setf sender (gr8s::start-raft-member "source")
                       receiver (gr8s::start-raft-member "sink" :storage-path wal))
                 (gr8s.resources::configure-store-artifact-transport sender source-root)
                 (gr8s.resources::configure-store-artifact-transport receiver sink-root)
                 (setf (gr8s.raft.transport::raft-member-artifact-retain-fn receiver)
                       (lambda (&rest args) (declare (ignore args)) nil))
                 (signals error (send-artifact-wire-test-snapshot sender receiver (artifact-wire-test-message reference)))
                 (is (= 0 (gr8s::raft-recovered-snapshot-index (gr8s::load-raft-log wal))))
                 (is (= 0 (gr8s::raft-node-last-applied (gr8s::raft-member-node receiver))))
                 (is (null (gr8s.raft.transport::raft-member-snapshot-receiver receiver)))
                 (gr8s.resources::configure-store-artifact-transport receiver sink-root)
                 (send-artifact-wire-test-snapshot sender receiver (artifact-wire-test-message reference))
                 (is (= 42 (gr8s::raft-recovered-snapshot-index (gr8s::load-raft-log wal))))
                 (is (probe-file (gr8s.resources::checked-store-snapshot-artifact-path sink-root reference))))
            (when receiver (gr8s::stop-raft-member receiver))
            (when sender (gr8s::stop-raft-member sender))))))))

(test artifact-wire-rejects-unbound-headers-and-reference-only-legacy-transfers
  (with-temporary-store (store root)
    (declare (ignore store))
    (let* ((wal (merge-pathnames "raft/transfer.log" root))
           (receiver (gr8s::start-raft-member "sink" :storage-path wal))
           (reference (gr8s.resources::store-snapshot-artifact-reference 42 7 (make-string 64 :initial-element #\0)))
           (message (artifact-wire-test-message reference))
           (header (gr8s.raft.transport::raft-message->octets message))
           (chunk (list :type :snapshot-chunk :term 9 :from "source" :last-index 42 :last-term 7
                        :total 1 :offset 0 :data #(123) :token "bounded" :digest (eighth reference)
                        :done t :format :artifact-v1 :artifact-envelope header))
           (retained 0))
      (labels ((receive (chunk)
                 (bt:with-lock-held ((gr8s::raft-member-lock receiver))
                   (gr8s.raft.transport::raft-member-receive-snapshot-chunk receiver chunk))))
        (unwind-protect
             (progn
               (signals error (receive chunk)) ; no retainer configured
               (setf (gr8s.raft.transport::raft-member-artifact-retain-fn receiver)
                     (lambda (&rest args) (declare (ignore args)) (incf retained) t))
               (signals error (gr8s.raft.transport::raft-link-send-snapshot receiver nil message)) ; no source
               (dolist (entry (list (cons :format :unknown)
                                   (cons :artifact-envelope (make-array 65537 :element-type '(unsigned-byte 8) :initial-element 0))
                                   (cons :digest (make-string 64 :initial-element #\1))))
                 (let ((bad (copy-list chunk)))
                   (setf (getf bad (car entry)) (cdr entry))
                   (signals error (receive bad))))
               (signals error (receive chunk)) ; corrupt raw bytes, before retention/WAL
               (let* ((legacy (copy-list chunk))
                      (bytes (gr8s.raft.transport::raft-message->octets message)))
                 (remf legacy :format)
                 (remf legacy :artifact-envelope)
                 (setf (getf legacy :data) bytes (getf legacy :total) (length bytes)
                       (getf legacy :digest) (ironclad:byte-array-to-hex-string (ironclad:digest-sequence :sha256 bytes)))
                 (signals error (receive legacy)))
               (is (= 0 retained))
               (is (= 0 (gr8s::raft-recovered-snapshot-index (gr8s::load-raft-log wal))))
               (is (= 0 (gr8s::raft-node-last-applied (gr8s::raft-member-node receiver))))
               (is (null (gr8s.raft.transport::raft-member-snapshot-receiver receiver))))
          (gr8s::stop-raft-member receiver))))))

(test retained-artifact-outlives-failed-restore-and-is-found-by-wal-recovery
  (with-temporary-store (source source-root)
    (with-temporary-store (sink sink-root)
      (declare (ignore sink))
      (let ((artifact (merge-pathnames "source.jsonl" source-root))
            (wal (merge-pathnames "raft/transfer.log" sink-root))
            (sender nil) (receiver nil) (restored nil))
        (gr8s.resources::capture-store-snapshot source artifact 42 7)
        (multiple-value-bind (path reference)
            (gr8s.resources::retain-store-snapshot-artifact source-root artifact 42 7 (snapshot-test-digest artifact))
          (declare (ignore path))
          (unwind-protect
               (progn
                 (setf sender (gr8s::start-raft-member "source")
                       receiver (gr8s::start-raft-member "sink" :storage-path wal
                                   :restore-fn (lambda (ref) (declare (ignore ref)) (error "Injected restore failure"))))
                 (gr8s.resources::configure-store-artifact-transport sender source-root)
                 (gr8s.resources::configure-store-artifact-transport receiver sink-root)
                 (signals error (send-artifact-wire-test-snapshot sender receiver (artifact-wire-test-message reference)))
                 (is-true (gr8s.raft:raft-node-snapshot-pending (gr8s::raft-member-node receiver)))
                 (is (= 42 (gr8s::raft-recovered-snapshot-index (gr8s::load-raft-log wal))))
                 (is (null (gr8s.raft.transport::raft-member-snapshot-receiver receiver)))
                 (is (probe-file (gr8s.resources::checked-store-snapshot-artifact-path sink-root reference)))
                 (gr8s::stop-raft-member receiver)
                 (setf receiver nil)
                 (setf receiver (gr8s::start-raft-member "sink" :storage-path wal
                                  :restore-fn (lambda (ref)
                                                (gr8s.resources::checked-store-snapshot-artifact-path sink-root ref)
                                                (setf restored ref))))
                 (is (equal reference restored))
                 (is (= 42 (gr8s::raft-node-last-applied (gr8s::raft-member-node receiver)))))
            (when receiver (gr8s::stop-raft-member receiver))
            (when sender (gr8s::stop-raft-member sender))))))))

(test artifact-chunk-binary-frame-is-bounded-and-roundtrips-arbitrary-bytes
  (let* ((data (make-array 65536 :element-type '(unsigned-byte 8)))
         (message (list :type :snapshot-chunk :format :artifact-v1 :term 9 :from "source"
                        :last-index 42 :last-term 7 :token "binary" :digest (make-string 64 :initial-element #\0)
                        :total 65536 :offset 0 :done t :data data :artifact-envelope #(0 128 255))))
    (dotimes (i (length data)) (setf (aref data i) (mod i 256)))
    (let* ((bytes (gr8s.raft.transport::raft-message->octets message))
           (decoded (gr8s.raft.transport::octets->raft-message bytes)))
      (is (< (length bytes) 70000))
      (is (typep (getf decoded :data) '(vector (unsigned-byte 8))))
      (is (equalp data (getf decoded :data)))
      (is (equalp #(0 128 255) (getf decoded :artifact-envelope)))
      (is (= 42 (getf decoded :last-index)))
      (signals error (gr8s.raft.transport::octets->raft-message (subseq bytes 0 19)))
      (signals error (gr8s.raft.transport::octets->raft-message (subseq bytes 0 (1- (length bytes)))))
      (let ((invalid (copy-seq bytes)))
        (gr8s.raft.transport::raft-wire-put-u32 invalid 16 65537)
        (signals error (gr8s.raft.transport::octets->raft-message invalid)))
      (let ((invalid (copy-list message)))
        (setf (getf invalid :data) (make-array 65537 :element-type '(unsigned-byte 8) :initial-element 0))
        (signals error (gr8s.raft.transport::raft-message->octets invalid))))))

(test store-artifact-witness-catchup-needs-no-retainer-and-preserves-departure-role
  (with-temporary-store (unused root)
    (declare (ignore unused))
    (let* ((sender (gr8s::start-raft-member "source"))
           (wal (merge-pathnames "raft/witness.log" root))
           (receiver nil)
           (reference (gr8s.resources::store-snapshot-artifact-reference 42 7 (make-string 64 :initial-element #\a)))
           (message (artifact-wire-test-message reference)))
      (setf (getf (cddr (getf message :state)) :members) '(("source" . :voter) ("sink" . :witness)))
      (unwind-protect
           (progn
             (setf receiver (gr8s::start-raft-member "sink" :initial-role :witness :storage-path wal))
             (bt:with-lock-held ((gr8s::raft-member-lock sender))
               (gr8s::raft-configure (gr8s::raft-member-node sender) '(("source" . :voter) ("sink" . :witness)))
               (setf (gethash "sink" (gr8s::raft-node-peer-addresses (gr8s::raft-member-node sender)))
                     (list "127.0.0.1" (gr8s::raft-member-port receiver)))
               (gr8s::raft-member-enable-dynamic-membership sender)
               (gr8s::raft-member-reconcile-links sender))
             ;; There is intentionally no source artifact file/callback and no
             ;; receiver retainer. Only the small configuration image can pass.
             (let ((link (gethash "sink" (gr8s::raft-member-links sender))))
               (gr8s.raft.transport::raft-link-enqueue link message)
               (is (poll-until (lambda () (= 42 (gr8s::raft-node-snapshot-index (gr8s::raft-member-node receiver)))) :timeout 10))
               (is (null (getf (cddr (gr8s::raft-node-snapshot-state (gr8s::raft-member-node receiver))) :application)))
               (is (equal reference (getf (cddr (getf message :state)) :application)))
               ;; Departing witnesses still need a metadata snapshot telling them
               ;; they were removed; their role is no longer in the live map.
               (bt:with-lock-held ((gr8s::raft-member-lock sender))
                 (gr8s::raft-configure (gr8s::raft-member-node sender) '(("source" . :voter)))
                 (gr8s::raft-member-reconcile-links sender))
               (is (eq :witness (gr8s.raft.transport::raft-peer-link-role link)))
               (let ((removed (copy-tree message)))
                 (setf (getf removed :last-index) 43
                       (getf (cddr (getf removed :state)) :members) '(("source" . :voter))
                       (getf (cddr (getf removed :state)) :application)
                       (gr8s.resources::store-snapshot-artifact-reference 43 7 (make-string 64 :initial-element #\b)))
                 (gr8s.raft.transport::raft-link-enqueue link removed)
                 (is (poll-until (lambda () (= 43 (gr8s::raft-node-snapshot-index (gr8s::raft-member-node receiver)))) :timeout 10))
                 (is-true (gr8s::raft-node-removed (gr8s::raft-member-node receiver)))))
             (gr8s::stop-raft-member receiver)
             (setf receiver (gr8s::start-raft-member "sink" :initial-role :witness :storage-path wal))
             (is (= 43 (gr8s::raft-node-last-applied (gr8s::raft-member-node receiver))))
             (is-true (gr8s::raft-node-removed (gr8s::raft-member-node receiver)))
             (is (not (probe-file (merge-pathnames "application-generations/" root)))))
        (gr8s::stop-raft-member sender)
        (when receiver (gr8s::stop-raft-member receiver))))))

(in-suite store-snapshot-registry)
(test unpublished-artifact-pins-protect-retention-and-unwind-independently
  (with-temporary-store (store root)
    (let* ((member (gr8s.resources::start-store-member-from-wal
                    store "source" (merge-pathnames "raft/control-plane.log" root)
                    :bootstrap-role :founder :host "127.0.0.1" :port 0))
           (source (merge-pathnames "unpublished.jsonl" root)))
      (unwind-protect
           (progn
             (gr8s.resources::capture-store-snapshot store source 2 1)
             (let* ((digest (snapshot-test-digest source))
                    (reference (gr8s.resources::store-snapshot-artifact-reference 2 1 digest))
                    (target nil))
               (flet ((reap ()
                        (bt:with-lock-held ((gr8s::raft-member-lock member))
                          (length (gr8s.resources::claim-store-snapshot-artifacts-unlocked member root :maximum-artifacts 64)))))
                 (is (null (gr8s.raft.transport::raft-member-artifact-pins member)))
                 (is (eq :done
                         (gr8s.resources::call-with-store-artifact-pin
                          member reference
                          (lambda ()
                            (is (not (sb-thread:holding-mutex-p (gr8s::raft-member-lock member))))
                            ;; The pin is installed before the artifact even exists.
                            (is (= 0 (reap)))
                            (setf target (gr8s.resources::retain-store-snapshot-artifact root source 2 1 digest))
                            (is (= 0 (reap)))
                            (is (probe-file target))
                            (signals error
                              (gr8s.resources::call-with-store-artifact-pin
                               member reference
                               (lambda ()
                                 (is (= 2 (length (gr8s.raft.transport::raft-member-artifact-pins member))))
                                 (is (= 0 (reap)))
                                 (error "abandoned inner capture"))))
                            (is (= 1 (length (gr8s.raft.transport::raft-member-artifact-pins member))))
                            ;; Corrupt roots stop reclamation before any deletion.
                            (let ((before (gr8s.raft.transport::raft-member-artifact-pins member)))
                              (unwind-protect
                                   (progn
                                     (setf (gr8s.raft.transport::raft-member-artifact-pins member) '((:invalid)))
                                     (signals error (reap))
                                     (is (probe-file target)))
                                (setf (gr8s.raft.transport::raft-member-artifact-pins member) before)))
                            (is (= 0 (reap)))
                            ;; Caller-owned strings cannot mutate the private pin.
                            (setf (aref (eighth reference) 0) #\z)
                            (is (= 0 (reap)))
                            :done))))
                 (is (null (gr8s.raft.transport::raft-member-artifact-pins member)))
                 (is (= 1 (reap)))
                 (is (null (probe-file target)))
                 (signals error
                   (gr8s.resources::call-with-store-artifact-pin member reference (lambda () (fail "Invalid pin ran"))))
                 (is (null (gr8s.raft.transport::raft-member-artifact-pins member))))))
        (gr8s::stop-raft-member member)))))

(test artifact-reclamation-preserves-durable-pending-and-outbound-roots
  (with-temporary-store (store root)
    (let* ((member (gr8s.resources::start-store-member-from-wal
                    store "source" (merge-pathnames "raft/control-plane.log" root)
                    :bootstrap-role :founder :host "127.0.0.1" :port 0))
           (link (gr8s.raft.transport::make-raft-peer-link :id "peer"))
           (paths nil) (references nil))
      (unwind-protect
           (progn
             (dotimes (i 4)
               (let ((source (merge-pathnames (format nil "sample-~D.jsonl" i) root)))
                 (gr8s.resources::capture-store-snapshot store source (+ 2 i) 1)
                 (multiple-value-bind (path reference)
                     (gr8s.resources::retain-store-snapshot-artifact root source (+ 2 i) 1 (snapshot-test-digest source))
                   (push path paths) (push reference references))))
             (setf paths (nreverse paths) references (nreverse references))
             (flet ((envelope (reference)
                      (list :gr8s-raft-snapshot 1 :application reference :application-present t
                            :members '(("source" . :voter))))
                    (reap () (bt:with-lock-held ((gr8s::raft-member-lock member))
                               (length (gr8s.resources::claim-store-snapshot-artifacts-unlocked member root :maximum-artifacts 64)))))
               (signals error (length (gr8s.resources::claim-store-snapshot-artifacts-unlocked member root :maximum-artifacts 64)))
               (bt:with-lock-held ((gr8s::raft-member-lock member))
                 (setf (gethash "peer" (gr8s.raft.transport::raft-member-links member)) link
                       (gr8s.raft.transport::raft-peer-link-items link)
                       (list (list :type :install-snapshot :state (envelope (first references))))
                       (gr8s.raft.transport::raft-peer-link-active-items link)
                       (list (list :type :install-snapshot :state (envelope (second references))))
                       (gr8s.raft:raft-node-snapshot-pending (gr8s::raft-member-node member))
                       (list 4 1 (envelope (third references)) #())))
               (let* ((journal (merge-pathnames "raft/bootstrap.json" root))
                      (before (uiop:read-file-string journal)))
                 (unwind-protect
                      (progn
                        (gr8s::write-private-text-atomically journal "{}")
                        (signals error (reap))
                        (is (every #'probe-file paths)))
                   (gr8s::write-private-text-atomically journal before)))
               (is (= 1 (reap)))
               (is (not (probe-file (fourth paths))))
               (is (every #'probe-file (subseq paths 0 3)))
               (bt:with-lock-held ((gr8s::raft-member-lock member))
                 (setf (gr8s.raft.transport::raft-peer-link-items link) nil
                       (gr8s.raft.transport::raft-peer-link-active-items link) nil
                       (gr8s.raft:raft-node-snapshot-pending (gr8s::raft-member-node member)) nil))
               ;; Unsafe/unknown files are preserved even if their basename is a digest.
               (sb-posix:chmod (namestring (first paths)) #o644)
               (sb-posix:link (namestring (second paths)) (namestring (merge-pathnames "other-link" root)))
               (delete-file (third paths))
               (sb-posix:symlink "missing" (namestring (third paths)))
               (is (= 0 (reap)))
               (is (probe-file (first paths)))
               (is (probe-file (second paths)))
               (is (sb-posix:s-islnk (sb-posix:stat-mode (sb-posix:lstat (namestring (third paths))))))
               (delete-file (third paths))
               (delete-file (merge-pathnames "other-link" root))
               (sb-posix:chmod (namestring (first paths)) #o600)
               (is (= 2 (reap)))
               ;; A different current snapshot must not reclaim the journal baseline.
               (let* ((node (gr8s::raft-member-node member))
                      (baseline (gr8s.resources::checked-store-snapshot-artifact-path
                                 root (getf (cddr (gr8s.raft:raft-node-snapshot-state node)) :application)))
                      (source (merge-pathnames "sample-0.jsonl" root)))
                 (gr8s.resources::retain-store-snapshot-artifact root source 2 1 (snapshot-test-digest source))
                 (bt:with-lock-held ((gr8s::raft-member-lock member))
                   (setf (gr8s.raft:raft-node-snapshot-state node) (envelope (first references))))
                 (is (= 0 (reap)))
                 (is (probe-file baseline))
                 (is (probe-file (first paths))))))
        (gr8s::stop-raft-member member)))))

(defun retain-artifact-maintenance-fixture (store root index)
  (let ((source (merge-pathnames (format nil "artifact-maintenance-~D.jsonl" index) root)))
    (gr8s.resources::capture-store-snapshot store source index 1)
    (multiple-value-bind (path reference)
        (gr8s.resources::retain-store-snapshot-artifact root source index 1 (snapshot-test-digest source))
      (values path reference source))))

(defun call-with-artifact-maintenance-member (store root function)
  (let ((member (gr8s.resources::start-store-member-from-wal
                 store "source" (merge-pathnames "raft/control-plane.log" root)
                 :bootstrap-role :founder :host "127.0.0.1" :port 0)))
    (unwind-protect (funcall function member)
      (gr8s::stop-raft-member member))))

(test detached-artifact-cleanup-cannot-unlink-a-new-copy-of-the-same-digest
  (with-temporary-store (store root)
    (call-with-artifact-maintenance-member
     store root
     (lambda (member)
       (multiple-value-bind (target reference source) (retain-artifact-maintenance-fixture store root 2)
         (let ((trash (bt:with-lock-held ((gr8s::raft-member-lock member))
                        (gr8s.resources::claim-store-snapshot-artifacts-unlocked member root))))
           (is (= 1 (length trash)))
           (is-false (probe-file target))
           (is (equal (snapshot-test-digest source) (snapshot-test-digest (first trash))))
           (gr8s.resources::call-with-store-artifact-pin
            member reference
            (lambda ()
              (is (equal target (gr8s.resources::retain-store-snapshot-artifact root source 2 1 (eighth reference))))
              (is (/= (sb-posix:stat-ino (sb-posix:lstat (namestring target)))
                      (sb-posix:stat-ino (sb-posix:lstat (namestring (first trash))))))
              (is (= 1 (gr8s.resources::reap-store-snapshot-artifact-trash root)))
              (is (equal target (gr8s.resources::checked-store-snapshot-artifact-path root reference)))
              (is-false (probe-file (first trash)))))))))))

(test artifact-trash-pruning-is-bounded-and-retains-unsafe-and-unknown-files
  (with-temporary-store (store root)
    (call-with-artifact-maintenance-member
     store root
     (lambda (member)
       (loop for index from 2 to 4 do (retain-artifact-maintenance-fixture store root index))
       (let* ((trash (bt:with-lock-held ((gr8s::raft-member-lock member))
                       (gr8s.resources::claim-store-snapshot-artifacts-unlocked member root :maximum-artifacts 3)))
              (link (merge-pathnames "artifact-hardlink" root))
              (unknown (merge-pathnames ".retired-unknown.jsonl" (gr8s.resources::store-snapshot-registry-directory root))))
         (is (= 3 (length trash)))
         (gr8s.security::write-private-text-exclusively unknown "preserve")
         (sb-posix:link (namestring (first trash)) (namestring link))
         (sb-posix:chmod (namestring (second trash)) #o644)
         (delete-file (third trash))
         (sb-posix:symlink (namestring link) (namestring (third trash)))
         (is (= 0 (gr8s.resources::reap-store-snapshot-artifact-trash root)))
         (is (equal "preserve" (uiop:read-file-string unknown)))
         (delete-file link)
         (sb-posix:chmod (namestring (second trash)) #o600)
         (is (= 1 (gr8s.resources::reap-store-snapshot-artifact-trash root :maximum-artifacts 1)))
         (is (= 1 (count-if #'probe-file (subseq trash 0 2))))
         (is (= 1 (gr8s.resources::reap-store-snapshot-artifact-trash root :maximum-artifacts 1)))
         (is (sb-posix:s-islnk (sb-posix:stat-mode (sb-posix:lstat (namestring (third trash))))))
         (is-true (probe-file unknown)))))))

(test detached-artifact-cleanup-resumes-after-uncertain-directory-sync-and-wal-reopen
  (with-temporary-store (store root)
    (let* ((wal (merge-pathnames "raft/control-plane.log" root))
           (member (gr8s.resources::start-store-member-from-wal
                    store "source" wal :bootstrap-role :founder :host "127.0.0.1" :port 0))
           (sync (symbol-function 'gr8s.store::sync-store-generation-directory)))
      (unwind-protect
           (multiple-value-bind (target reference source) (retain-artifact-maintenance-fixture store root 2)
             (declare (ignore reference source))
             (let ((directory (gr8s.resources::store-snapshot-registry-directory root)))
               (unwind-protect
                    (progn
                      (setf (symbol-function 'gr8s.store::sync-store-generation-directory)
                            (lambda (path)
                              (if (equal path directory) (error "Injected artifact detach sync uncertainty")
                                  (funcall sync path))))
                      (signals error
                        (bt:with-lock-held ((gr8s::raft-member-lock member))
                          (gr8s.resources::claim-store-snapshot-artifacts-unlocked member root))))
                 (setf (symbol-function 'gr8s.store::sync-store-generation-directory) sync)))
             (is-false (probe-file target))
             (gr8s::stop-raft-member member)
             (setf member nil)
             (let ((reopened (gr8s:open-store root)))
               (setf member (gr8s.resources::start-store-member-from-wal reopened "source" wal :host "127.0.0.1" :port 0))
               (let ((hcp (gr8s.ha::make-ha-control-plane :member member :store reopened :compaction-interval nil)))
                 (is (= 1 (gr8s.ha::maintain-ha-artifacts-once hcp)))
                 (is (= 0 (gr8s.ha::ha-control-plane-compaction-count hcp)))
                 (is (= 1 (gr8s.ha::ha-control-plane-artifacts-reaped hcp)))
                 (is-true (gr8s.resources::checked-store-snapshot-artifact-path
                           root (getf (cddr (gr8s.raft:raft-node-snapshot-state (gr8s::raft-member-node member))) :application))))))
        (setf (symbol-function 'gr8s.store::sync-store-generation-directory) sync)
        (when member (gr8s::stop-raft-member member))))))

(test artifact-maintenance-runs-outside-member-lock-and-failures-are-independent
  (with-temporary-store (store root)
    (call-with-artifact-maintenance-member
     store root
     (lambda (member)
       (let ((hcp (gr8s.ha::make-ha-control-plane :member member :store store :compaction-interval nil))
             (generation (symbol-function 'gr8s.store::reap-retired-store-generations))
             (prune (symbol-function 'gr8s.resources::reap-store-snapshot-artifact-trash))
             (called nil))
         (unwind-protect
              (progn
                (retain-artifact-maintenance-fixture store root 2)
                (setf (symbol-function 'gr8s.store::reap-retired-store-generations)
                      (lambda (target &rest args) (declare (ignore target args)) (error "Generation failure"))
                      (symbol-function 'gr8s.resources::reap-store-snapshot-artifact-trash)
                      (lambda (target &rest args)
                        (setf called t)
                        (is-false (sb-thread:holding-mutex-p (gr8s::raft-member-lock member)))
                        (is-false (sb-thread:holding-mutex-p (gr8s::pod-store-lock store)))
                        (apply prune target args)))
                (signals simple-error (gr8s.ha::maintain-ha-store-once hcp))
                (is-true called)
                (is (= 1 (gr8s.ha::ha-control-plane-artifacts-reaped hcp)))
                (setf (symbol-function 'gr8s.resources::reap-store-snapshot-artifact-trash)
                      (lambda (target &rest args) (declare (ignore target args)) (error "Artifact failure too")))
                (handler-case
                    (progn (gr8s.ha::maintain-ha-store-once hcp) (fail "Generation failure was hidden"))
                  (simple-error (condition) (is (search "Generation failure" (princ-to-string condition)))))
                (is-true (gr8s.ha::ha-control-plane-artifact-maintenance-error hcp))
                (setf (symbol-function 'gr8s.store::reap-retired-store-generations) generation)
                (retain-artifact-maintenance-fixture store root 3)
                (setf (symbol-function 'gr8s.resources::reap-store-snapshot-artifact-trash)
                      (lambda (target &rest args) (declare (ignore target args)) (error "PRIVATE artifact cleanup failure")))
                (finishes (gr8s.ha::maintain-ha-store-once hcp))
                (let ((text (gr8s.ha::ha-metrics-text hcp)))
                  (is (search "gr8s_generation_reclamation_error 0" text))
                  (is (search "gr8s_snapshot_artifact_reclamation_error 1" text))
                  (is-false (search "PRIVATE" text)))
                (setf (symbol-function 'gr8s.resources::reap-store-snapshot-artifact-trash) prune)
                (finishes (gr8s.ha::maintain-ha-store-once hcp))
                (is (= 2 (gr8s.ha::ha-control-plane-artifacts-reaped hcp)))
                (is (= 0 (gr8s.ha::ha-control-plane-compaction-count hcp)))
                (is (search "gr8s_snapshot_artifact_reclamation_error 0" (gr8s.ha::ha-metrics-text hcp))))
           (setf (symbol-function 'gr8s.store::reap-retired-store-generations) generation
                 (symbol-function 'gr8s.resources::reap-store-snapshot-artifact-trash) prune)))))))

(test artifact-owner-check-and-cleanup-support-relative-member-roots
  (with-temporary-store (store root)
    (call-with-artifact-maintenance-member
     store root
     (lambda (member)
       (multiple-value-bind (target reference source) (retain-artifact-maintenance-fixture store root 2)
         (declare (ignore reference source))
         (uiop:with-current-directory (root)
           (bt:with-lock-held ((gr8s::raft-member-lock member))
             (is-true (gr8s.resources::store-snapshot-artifact-owner-p member #P"./"))
             (is-false (gr8s.resources::store-snapshot-artifact-owner-p member #P"./different-root/"))
             (is (= 1 (length (gr8s.resources::claim-store-snapshot-artifacts-unlocked member #P"./")))))
           (is (= 1 (gr8s.resources::reap-store-snapshot-artifact-trash #P"./"))))
         (is-false (probe-file target)))))))
