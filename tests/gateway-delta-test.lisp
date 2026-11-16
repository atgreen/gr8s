;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0

(in-package #:gr8s/tests)

(def-suite gateway-delta :in gr8s)
(in-suite gateway-delta)

(test discovery-octet-hash-agrees-across-vector-representations
  (let* ((bytes (make-array 5 :element-type '(unsigned-byte 8)
                             :initial-contents '(0 65 97 128 255)))
         (backing (make-array 7 :element-type '(unsigned-byte 8)
                               :initial-contents '(9 0 65 97 128 255 9)))
         (displaced (make-array 5 :element-type '(unsigned-byte 8)
                                 :displaced-to backing :displaced-index-offset 1))
         (adjustable (make-array 7 :element-type '(unsigned-byte 8) :adjustable t
                                  :fill-pointer 5 :initial-contents '(0 65 97 128 255 9 9))))
    (dolist (copy (list (copy-seq bytes) displaced adjustable))
      (is (equalp bytes copy))
      (is (typep (gr8s.kubelet::discovery-octet-hash copy) '(integer 0 #.most-positive-fixnum)))
      (is (= (gr8s.kubelet::discovery-octet-hash bytes)
             (gr8s.kubelet::discovery-octet-hash copy))))
    (is (/= (gr8s.kubelet::discovery-octet-hash bytes)
            (gr8s.kubelet::discovery-octet-hash
             (make-array 5 :element-type '(unsigned-byte 8) :initial-contents '(0 97 65 128 255)))))))

#+sbcl
(test discovery-cache-hash-collisions-still-compare-complete-octets
  (with-temporary-store (store path)
    (values path)
    (gwc-seed store)
    (let ((hash (symbol-function 'gr8s.kubelet::discovery-octet-hash)))
      (unwind-protect
           (progn
             (setf (symbol-function 'gr8s.kubelet::discovery-octet-hash)
                   (lambda (bytes) (declare (ignore bytes)) 0))
             (multiple-value-bind (before cache)
                 (gr8s.kubelet::decode-service-discovery-projection
                  (gr8s.kubelet::service-discovery-projection store))
               (gr8s.resources::update-core-resource
                store "httproutes" "default" "app"
                (lambda (object)
                  (setf (gethash "hostnames" (gethash "spec" object)) #("Changed.example.com"))
                  object))
               (let* ((after (gr8s.kubelet::decode-service-discovery-projection
                              (gr8s.kubelet::service-discovery-projection store) cache))
                      (key '("httproutes" "default" "app")))
                 (is (= (hash-table-count before) (hash-table-count after)))
                 (is (equalp #("Changed.example.com")
                             (gethash "hostnames" (gethash "spec" (gethash key after))))))))
        (setf (symbol-function 'gr8s.kubelet::discovery-octet-hash) hash)))))

(test gateway-full-baseline-reuses-only-previously-validated-discovery-identities
  (with-temporary-store (store path)
    (values path)
    (gwc-seed store)
    (let* ((session (gr8s.apiserver::make-node-agent-session nil))
           (snapshot (desired-snapshot-for-test))
           (decoder (symbol-function 'gr8s.kubelet::decode-service-discovery-entry))
           (decoded 0))
      (setf (gr8s.apiserver::node-agent-session-gateway-deltas-p session) t
            (slot-value snapshot 'gr8s.node.v1::service-discovery-objects-json)
            (gr8s.kubelet::service-discovery-projection store))
      (unwind-protect
           (progn
             (setf (symbol-function 'gr8s.kubelet::decode-service-discovery-entry)
                   (lambda (bytes) (incf decoded) (funcall decoder bytes)))
             (gr8s.apiserver::install-node-gateway-baseline session snapshot)
             (is (= 5 decoded))
             ;; Equal octets may arrive in fresh vectors after snapshot reconstruction.
             (setf decoded 0
                   (slot-value snapshot 'gr8s.node.v1::service-discovery-objects-json)
                   (mapcar #'copy-seq (slot-value snapshot 'gr8s.node.v1::service-discovery-objects-json)))
             (gr8s.apiserver::install-node-gateway-baseline session snapshot)
             (is (= 0 decoded))
             (gr8s.resources::update-core-resource
              store "httproutes" "default" "app"
              (lambda (object) (setf (gethash "hostnames" (gethash "spec" object)) #("Changed.example.com")) object))
             (setf decoded 0
                   (slot-value snapshot 'gr8s.node.v1::service-discovery-objects-json)
                   (gr8s.kubelet::service-discovery-projection store)
                   (gr8s.apiserver::node-agent-session-gateway-revision session) 5
                   (gr8s.apiserver::node-agent-session-gateway-acknowledged-revision session) 4)
             (gr8s.apiserver::install-node-gateway-baseline session snapshot 23)
             (is (= 1 decoded))
             (is (= 0 (gr8s.apiserver::node-agent-session-gateway-revision session)))
             (is (= 0 (gr8s.apiserver::node-agent-session-gateway-acknowledged-revision session)))
             (is (= 23 (gr8s.apiserver::node-agent-session-gateway-dependency-epoch session)))
             (let ((previous (gr8s.apiserver::node-agent-session-gateway-resources session))
                   (previous-cache (gr8s.apiserver::node-agent-session-gateway-discovery-key-cache session)))
               (push (trivial-utf-8:string-to-utf-8-bytes "{}")
                     (slot-value snapshot 'gr8s.node.v1::service-discovery-objects-json))
               (signals error (gr8s.apiserver::install-node-gateway-baseline session snapshot 24))
               (is (eq previous (gr8s.apiserver::node-agent-session-gateway-resources session)))
               (is (eq previous-cache (gr8s.apiserver::node-agent-session-gateway-discovery-key-cache session)))
               (is (= 23 (gr8s.apiserver::node-agent-session-gateway-dependency-epoch session))))
             (gr8s.resources::delete-core-resource store "httproutes" "default" "app")
             (setf (slot-value snapshot 'gr8s.node.v1::service-discovery-objects-json)
                   (gr8s.kubelet::service-discovery-projection store))
             (gr8s.apiserver::install-node-gateway-baseline session snapshot)
             (is (= 4 (hash-table-count (gr8s.apiserver::node-agent-session-gateway-discovery-key-cache session))))
             (is (not (gethash '("httproutes" "default" "app")
                              (gr8s.apiserver::node-agent-session-gateway-resources session)))))
        (setf (symbol-function 'gr8s.kubelet::decode-service-discovery-entry) decoder)))))

(defun gateway-change-for-test (name &key deleted (resource "httproutes") (namespace "default"))
  (make-instance 'gr8s.node.v1::gateway-resource-change
                 :resource resource :namespace namespace :name name :deleted deleted
                 :object-json (if deleted (make-array 0 :element-type '(unsigned-byte 8))
                                  (trivial-utf-8:string-to-utf-8-bytes "{}"))))

(defun gateway-update-for-test (base revision &rest changes)
  (make-instance 'gr8s.node.v1::gateway-config-update
                 :base-node-revision 7 :base-revision base :revision revision :changes changes))

(test gateway-delta-envelopes-roundtrip-independent-revisions-and-deletions
  (let* ((update (gateway-update-for-test 2 3 (gateway-change-for-test "app" :deleted t)))
         (envelope (gr8s.protocol::make-server-envelope :gateway-config update :sequence 12))
         (restored (roundtrip-node-message envelope 'gr8s.node.v1::server-envelope))
         (payload (slot-value restored 'gr8s.node.v1::gateway-config))
         (change (first (slot-value payload 'gr8s.node.v1::changes))))
    (is (eq :gateway-config (slot-value restored 'gr8s.node.v1::payload-case)))
    (is (= 7 (slot-value payload 'gr8s.node.v1::base-node-revision)))
    (is (= 2 (slot-value payload 'gr8s.node.v1::base-revision)))
    (is (= 3 (slot-value payload 'gr8s.node.v1::revision)))
    (is (slot-value change 'gr8s.node.v1::deleted))
    (is (equal '("httproutes" "default" "app")
               (gr8s.protocol::gateway-resource-change-key change))))
  (let* ((ack (make-instance 'gr8s.node.v1::gateway-config-ack
                             :base-node-revision 7 :revision 3 :applied t))
         (envelope (gr8s.protocol::make-agent-envelope :gateway-config-ack ack))
         (restored (roundtrip-node-message envelope 'gr8s.node.v1::agent-envelope)))
    (is (eq :gateway-config-ack (slot-value restored 'gr8s.node.v1::payload-case)))
    (is (= 7 (slot-value (slot-value restored 'gr8s.node.v1::gateway-config-ack)
                         'gr8s.node.v1::base-node-revision)))))

(test gateway-delta-validation-rejects-gaps-wrong-node-bases-and-ambiguous-keys
  (let ((update (gateway-update-for-test 2 3 (gateway-change-for-test "app"))))
    (is (eq update (gr8s.protocol::validate-gateway-config-update update 7 2)))
    (signals error (gr8s.protocol::validate-gateway-config-update update 8 2))
    (signals error (gr8s.protocol::validate-gateway-config-update update 7 1))
    (setf (slot-value update 'gr8s.node.v1::revision) 2)
    (signals error (gr8s.protocol::validate-gateway-config-update update 7 2)))
  (dolist (changes (list (list (gateway-change-for-test "app") (gateway-change-for-test "app" :deleted t))
                        (list (gateway-change-for-test "app" :resource "pods"))
                        (list (gateway-change-for-test ""))
                        (list (gateway-change-for-test "app" :namespace ""))))
    (signals error
      (gr8s.protocol::validate-gateway-config-update
       (apply #'gateway-update-for-test 0 1 changes) 7 0))))

(test queued-gateway-deltas-coalesce-with-last-change-winning-without-losing-the-base
  (let* ((first (gateway-update-for-test 0 1 (gateway-change-for-test "a") (gateway-change-for-test "b")))
         (second (gateway-update-for-test 1 3 (gateway-change-for-test "a" :deleted t)
                                          (gateway-change-for-test "c")))
         (merged (gr8s.protocol::coalesce-gateway-config-updates first second)))
    (is (= 0 (slot-value merged 'gr8s.node.v1::base-revision)))
    (is (= 3 (slot-value merged 'gr8s.node.v1::revision)))
    (is (= 3 (length (slot-value merged 'gr8s.node.v1::changes))))
    (is (slot-value (find "a" (slot-value merged 'gr8s.node.v1::changes)
                         :test #'equal :key (lambda (change) (slot-value change 'gr8s.node.v1::name)))
                   'gr8s.node.v1::deleted))
    (signals error (gr8s.protocol::coalesce-gateway-config-updates second first))))

(test gateway-work-waits-for-node-application-and-coalesces-adjacent-batches
  (let ((entered nil) (release nil) (applied nil)
        (worker nil) (finished nil))
    (unwind-protect
         (progn
           (setf worker
                 (gr8s.agent::start-agent-snapshot-worker
                  (lambda (snapshot replay)
                    (declare (ignore replay))
                    (setf entered t)
                    (loop until release do (sleep .005))
                    (push (list :node (slot-value snapshot 'gr8s.node.v1::revision)) applied))
                  (lambda () (setf finished t))
                  :gateway-function
                  (lambda (update)
                    (push (list :gateway (slot-value update 'gr8s.node.v1::base-revision)
                                (slot-value update 'gr8s.node.v1::revision)) applied))))
           (gr8s.agent::queue-agent-snapshot-work
            worker (make-instance 'gr8s.node.v1::desired-state-snapshot :revision 7))
           (is (poll-until (lambda () entered)))
           (gr8s.agent::handle-node-server-envelope
            nil (gr8s.protocol::make-server-envelope
                 :gateway-config (gateway-update-for-test 0 1 (gateway-change-for-test "a")))
            nil nil nil nil worker)
           (gr8s.agent::queue-agent-gateway-work worker (gateway-update-for-test 1 2 (gateway-change-for-test "b")))
           (is (= 1 (length (gr8s.agent::agent-snapshot-worker-pending worker))))
           (setf release t)
           (is (poll-until (lambda () (= 2 (length applied)))))
           (is (equal '((:node 7) (:gateway 0 2)) (reverse applied)))
           (is (not finished)))
      (setf release t)
      (gr8s.agent::stop-agent-snapshot-worker worker))))

(test incomplete-node-work-is-retried-before-dependent-gateway-work
  (let ((entered nil) (release nil) (attempts 0) (gateway-applied nil) (worker nil))
    (unwind-protect
         (progn
           (setf worker
                 (gr8s.agent::start-agent-snapshot-worker
                  (lambda (snapshot replay)
                    (declare (ignore snapshot replay))
                    (incf attempts)
                    (when (= attempts 1)
                      (setf entered t)
                      (loop until release do (sleep .005))
                      (error 'gr8s.agent::node-snapshot-incomplete :message "waiting for Service safety")))
                  (lambda () (fail "an incomplete baseline must retry"))
                  :gateway-function (lambda (update) (declare (ignore update)) (setf gateway-applied t))))
           (gr8s.agent::queue-agent-snapshot-work
            worker (make-instance 'gr8s.node.v1::desired-state-snapshot :revision 7))
           (is (poll-until (lambda () entered)))
           (gr8s.agent::queue-agent-gateway-work worker (gateway-update-for-test 0 1 (gateway-change-for-test "a")))
           (setf release t)
           (is (poll-until (lambda () gateway-applied) :timeout 5))
           (is (= 2 attempts)))
      (setf release t)
      (gr8s.agent::stop-agent-snapshot-worker worker))))

(test gateway-acknowledgements-do-not-advance-node-snapshot-acknowledgements
  (with-temporary-store (store path)
    (values path)
    (let* ((server (gr8s.apiserver::%make-node-grpc-server :store store))
           (session (gr8s.apiserver::make-node-agent-session nil))
           (ack (make-instance 'gr8s.node.v1::gateway-config-ack
                               :base-node-revision 7 :revision 2 :applied t)))
      (setf (gethash "worker" (gr8s.apiserver::node-grpc-server-sessions server)) session
            (gethash "worker" (gr8s.apiserver::node-grpc-server-acknowledged-revisions server)) 7
            (gr8s.apiserver::node-agent-session-delivered session)
            (make-instance 'gr8s.node.v1::desired-state-snapshot :revision 7)
            (gr8s.apiserver::node-agent-session-gateway-revision session) 2)
      (gr8s.apiserver::note-node-gateway-config-ack server "worker" ack session)
      (is (= 2 (gr8s.apiserver::node-agent-session-gateway-acknowledged-revision session)))
      (is (= 7 (gr8s.apiserver::node-session-acknowledged-revision server "worker")))
      (setf (slot-value ack 'gr8s.node.v1::revision) 3)
      (gr8s.apiserver::note-node-gateway-config-ack server "worker" ack session)
      (is (= 2 (gr8s.apiserver::node-agent-session-gateway-acknowledged-revision session)))
      (setf (slot-value ack 'gr8s.node.v1::base-node-revision) 6
            (slot-value ack 'gr8s.node.v1::revision) 2)
      (gr8s.apiserver::note-node-gateway-config-ack server "worker" ack session)
      (is (= 2 (gr8s.apiserver::node-agent-session-gateway-acknowledged-revision session))))))

(test a-new-full-snapshot-supersedes-pending-gateway-work-and-resets-its-sequence
  (let ((entered nil) (release nil) (applied nil) (worker nil))
    (unwind-protect
         (progn
           (setf worker
                 (gr8s.agent::start-agent-snapshot-worker
                  (lambda (snapshot replay)
                    (declare (ignore replay))
                    (when (= 7 (slot-value snapshot 'gr8s.node.v1::revision))
                      (setf entered t) (loop until release do (sleep .005)))
                    (push (slot-value snapshot 'gr8s.node.v1::revision) applied))
                  (lambda () (fail "unexpected worker failure"))
                  :gateway-function (lambda (update)
                                      (push (list :gateway (slot-value update 'gr8s.node.v1::base-node-revision)) applied))))
           (gr8s.agent::queue-agent-snapshot-work worker (make-instance 'gr8s.node.v1::desired-state-snapshot :revision 7))
           (is (poll-until (lambda () entered)))
           (gr8s.agent::queue-agent-gateway-work worker (gateway-update-for-test 0 1 (gateway-change-for-test "old")))
           (gr8s.agent::queue-agent-snapshot-work worker (make-instance 'gr8s.node.v1::desired-state-snapshot :revision 8))
           (signals error
             (gr8s.agent::queue-agent-gateway-work worker (gateway-update-for-test 1 2 (gateway-change-for-test "old"))))
           (let ((next (gateway-update-for-test 0 1 (gateway-change-for-test "new"))))
             (setf (slot-value next 'gr8s.node.v1::base-node-revision) 8)
             (gr8s.agent::queue-agent-gateway-work worker next))
           (setf release t)
           (is (poll-until (lambda () (= 3 (length applied)))))
           (is (equal '(7 8 (:gateway 8)) (reverse applied))))
      (setf release t) (gr8s.agent::stop-agent-snapshot-worker worker))))

(test an-incomplete-gateway-batch-is-composed-with-its-pending-successor-before-retry
  (let ((entered nil) (release nil) (applied nil) (worker nil))
    (unwind-protect
         (progn
           (setf worker
                 (gr8s.agent::start-agent-snapshot-worker
                  (lambda (&rest arguments) (declare (ignore arguments)))
                  (lambda () (fail "unexpected Gateway worker failure"))
                  :gateway-function
                  (lambda (update)
                    (unless entered
                      (setf entered t) (loop until release do (sleep .005))
                      (error 'gr8s.agent::node-snapshot-incomplete :message "Gateway not yet converged"))
                    (push update applied))))
           (gr8s.agent::queue-agent-snapshot-work worker (make-instance 'gr8s.node.v1::desired-state-snapshot :revision 7))
           (gr8s.agent::queue-agent-gateway-work worker (gateway-update-for-test 0 1 (gateway-change-for-test "a")))
           (is (poll-until (lambda () entered)))
           (gr8s.agent::queue-agent-gateway-work worker (gateway-update-for-test 1 2 (gateway-change-for-test "b")))
           (setf release t)
           (is (poll-until (lambda () applied) :timeout 5))
           (is (= 0 (slot-value (first applied) 'gr8s.node.v1::base-revision)))
           (is (= 2 (slot-value (first applied) 'gr8s.node.v1::revision)))
           (is (= 2 (length (slot-value (first applied) 'gr8s.node.v1::changes)))))
      (setf release t) (gr8s.agent::stop-agent-snapshot-worker worker))))

(test gateway-delivery-is-negotiated-and-commits-its-base-only-after-send-success
  (with-temporary-store (store path)
    (values path)
    (gwc-seed store)
    (let* ((session (gr8s.apiserver::make-node-agent-session nil))
           (snapshot (make-instance 'gr8s.node.v1::desired-state-snapshot :revision 7
                                    :service-discovery-objects-json (gr8s.kubelet::service-discovery-projection store)))
           (original (symbol-function 'ag-grpc:stream-send))
           (sent nil) (fail nil))
      (unwind-protect
           (progn
             (setf (symbol-function 'ag-grpc:stream-send)
                   (lambda (stream envelope)
                     (declare (ignore stream))
                     (when fail (error "injected send failure"))
                     (push envelope sent)))
             (setf (gr8s.apiserver::node-agent-session-delivered session) snapshot)
             (is (null (gr8s.apiserver::deliver-node-gateway-config session (list (gateway-change-for-test "new")))))
             (is (null sent))
             (setf (gr8s.apiserver::node-agent-session-gateway-deltas-p session) t)
             (gr8s.apiserver::install-node-gateway-baseline session snapshot)
             (gr8s.apiserver::deliver-node-gateway-config session (list (gateway-change-for-test "new")))
             (is (= 1 (gr8s.apiserver::node-agent-session-gateway-revision session)))
             (is (eq :gateway-config (slot-value (first sent) 'gr8s.node.v1::payload-case)))
             (is (= 1 (length (slot-value (slot-value (first sent) 'gr8s.node.v1::gateway-config) 'gr8s.node.v1::changes))))
             (setf fail t)
             (signals error (gr8s.apiserver::deliver-node-gateway-config session (list (gateway-change-for-test "other"))))
             (is (= 1 (gr8s.apiserver::node-agent-session-gateway-revision session)))
             (is (null (gethash '("httproutes" "default" "other")
                               (gr8s.apiserver::node-agent-session-gateway-resources session))))
             (setf (slot-value snapshot 'gr8s.node.v1::revision) 8)
             (gr8s.apiserver::install-node-gateway-baseline session snapshot)
             (is (= 0 (gr8s.apiserver::node-agent-session-gateway-revision session))))
        (setf (symbol-function 'ag-grpc:stream-send) original)))))

(defun call-with-gateway-repair-session (function)
  (with-temporary-store (store path)
    (declare (ignore path))
    (gwc-seed store)
    (gr8s.controllers::register-node
     store (gr8s.model::make-node-record :id "repair-node" :name "worker" :pod-cidr "10.88.0.0/20"))
    (let* ((server (gr8s.apiserver::%make-node-grpc-server :store store))
           (session (gr8s.apiserver::make-node-agent-session nil))
           (runtime (gr8s.controllers::make-control-plane-runtime store server))
           (send (symbol-function 'ag-grpc:stream-send)) (sent nil))
      (setf (gr8s.apiserver::node-agent-session-gateway-deltas-p session) t
            (gethash "worker" (gr8s.apiserver::node-grpc-server-sessions server)) session)
      (unwind-protect
           (progn
             (setf (symbol-function 'ag-grpc:stream-send)
                   (lambda (stream envelope) (declare (ignore stream)) (push envelope sent)))
             (gr8s.controllers::publish-node-snapshot runtime "worker")
             (gr8s.apiserver::note-node-snapshot-ack
              server "worker" (make-instance 'gr8s.node.v1::snapshot-ack :revision 1 :applied t) session)
             (funcall function store runtime server session (lambda () sent)))
        (setf (symbol-function 'ag-grpc:stream-send) send)))))

(defun send-gateway-repair-route-change (runtime server session &key (acknowledge t) (name "app"))
  (multiple-value-bind (changes epoch)
      (gr8s.controllers::capture-gateway-resource-changes runtime (list (list "httproutes" "default" name)))
    (gr8s.apiserver::deliver-node-gateway-config session changes :dependency-epoch epoch))
  (when acknowledge
    (gr8s.apiserver::note-node-gateway-config-ack
     server "worker"
     (make-instance 'gr8s.node.v1::gateway-config-ack :base-node-revision 1
                    :revision (gr8s.apiserver::node-agent-session-gateway-revision session) :applied t)
     session)))

(test periodic-repair-does-not-resend-acknowledged-gateway-state
  (call-with-gateway-repair-session
   (lambda (store runtime server session sent)
     (let ((baseline (gr8s.apiserver::current-node-snapshot server "worker")))
       (change-published-route-host store "repaired.example.com")
       (send-gateway-repair-route-change runtime server session)
       (is (= 2 (length (funcall sent))))
       (is (= 1 (gr8s.controllers::publish-node-snapshot runtime "worker")))
       (is (= 2 (length (funcall sent))))
       (is (eq baseline (gr8s.apiserver::current-node-snapshot server "worker")))
       (is (= 1 (gr8s.apiserver::node-agent-session-gateway-revision session)))))))

(test periodic-repair-sends-missed-gateway-changes-behind-an-in-flight-update
  (call-with-gateway-repair-session
   (lambda (store runtime server session sent)
     (let ((baseline (gr8s.apiserver::current-node-snapshot server "worker")))
       (change-published-route-host store "in-flight.example.com")
       (send-gateway-repair-route-change runtime server session :acknowledge nil)
       ;; Repair must find durable changes even when their event was missed.
       (change-published-route-host store "missed-event.example.com")
       (is (= 1 (gr8s.controllers::publish-node-snapshot runtime "worker")))
       (is (eq baseline (gr8s.apiserver::current-node-snapshot server "worker")))
       (is (= 3 (length (funcall sent))))
       (let ((envelope (first (funcall sent))))
         (is (eq :gateway-config (slot-value envelope 'gr8s.node.v1::payload-case)))
         (when (eq :gateway-config (slot-value envelope 'gr8s.node.v1::payload-case))
           (let ((update (slot-value envelope 'gr8s.node.v1::gateway-config)))
             (is (= 1 (slot-value update 'gr8s.node.v1::base-node-revision)))
             (is (= 1 (slot-value update 'gr8s.node.v1::base-revision)))
             (is (= 2 (slot-value update 'gr8s.node.v1::revision)))
             (is (= 1 (length (slot-value update 'gr8s.node.v1::changes)))))))
       (is (= 0 (gr8s.apiserver::node-agent-session-gateway-acknowledged-revision session)))))))

(test gateway-repair-progress-requires-advancing-authenticated-acks
  (call-with-gateway-repair-session
   (lambda (store runtime server session sent)
     (declare (ignore sent))
     (flet ((ack (revision &key (base 1) (applied t) (peer session))
              (gr8s.apiserver::note-node-gateway-config-ack
               server "worker" (make-instance 'gr8s.node.v1::gateway-config-ack
                                              :base-node-revision base :revision revision :applied applied) peer)))
       (change-published-route-host store "one.example.com")
       (send-gateway-repair-route-change runtime server session :acknowledge nil)
       (is (integerp (gr8s.apiserver::node-agent-session-gateway-pending-since session)))
       ;; A deterministic old timestamp proves sends cannot extend the deadline.
       (setf (gr8s.apiserver::node-agent-session-gateway-pending-since session) -123)
       (change-published-route-host store "two.example.com")
       (send-gateway-repair-route-change runtime server session :acknowledge nil)
       (is (= -123 (gr8s.apiserver::node-agent-session-gateway-pending-since session)))
       (ack 0) (ack 3) (ack 1 :base 999)
       (ack 1 :peer (gr8s.apiserver::make-node-agent-session nil))
       (is (= 0 (gr8s.apiserver::node-agent-session-gateway-acknowledged-revision session)))
       (is (= -123 (gr8s.apiserver::node-agent-session-gateway-pending-since session)))
       (ack 1)
       (is (= 1 (gr8s.apiserver::node-agent-session-gateway-acknowledged-revision session)))
       (is (> (gr8s.apiserver::node-agent-session-gateway-pending-since session) -123))
       (ack 1 :applied nil) (ack 3 :applied nil) (ack 2 :base 999 :applied nil)
       (is (not (gr8s.apiserver::node-agent-session-gateway-repair-required-p session)))
       (ack 2 :applied nil)
       (is (gr8s.apiserver::node-agent-session-gateway-repair-required-p session))
       (ack 2)
       (is (null (gr8s.apiserver::node-agent-session-gateway-pending-since session)))
       (is (gr8s.apiserver::node-agent-session-gateway-repair-required-p session))
       (is (= 2 (gr8s.controllers::publish-node-snapshot runtime "worker")))
       (is (not (gr8s.apiserver::node-agent-session-gateway-repair-required-p session)))
       (is (null (gr8s.apiserver::node-agent-session-gateway-pending-since session)))
       (is (= 0 (gr8s.apiserver::node-agent-session-gateway-revision session)))))))

(test gateway-repair-recovers-missed-deletion-with-pending-acks
  (call-with-gateway-repair-session
   (lambda (store runtime server session sent)
     (change-published-route-host store "pending.example.com")
     (send-gateway-repair-route-change runtime server session :acknowledge nil)
     (gr8s.resources::delete-core-resource store "httproutes" "default" "app")
     (is (= 1 (gr8s.controllers::publish-node-snapshot runtime "worker")))
     (is (= 3 (length (funcall sent))))
     (let* ((envelope (first (funcall sent)))
            (update (slot-value envelope 'gr8s.node.v1::gateway-config)))
       (is (eq :gateway-config (slot-value envelope 'gr8s.node.v1::payload-case)))
       (is (= 1 (length (slot-value update 'gr8s.node.v1::changes))))
       (is (slot-value (first (slot-value update 'gr8s.node.v1::changes)) 'gr8s.node.v1::deleted)))
     (is (not (gethash '("httproutes" "default" "app")
                       (gr8s.apiserver::node-agent-session-gateway-resources session)))))))

(test gateway-repair-send-failure-reconnects-with-fresh-durable-state
  (call-with-gateway-repair-session
   (lambda (store runtime server session sent)
     (declare (ignore sent))
     (change-published-route-host store "pending.example.com")
     (send-gateway-repair-route-change runtime server session :acknowledge nil)
     (change-published-route-host store "repair.example.com")
     (let ((send (symbol-function 'ag-grpc:stream-send)))
       (unwind-protect
            (progn
              (setf (symbol-function 'ag-grpc:stream-send)
                    (lambda (&rest args) (declare (ignore args)) (error "injected repair send failure")))
              (is (= 1 (gr8s.controllers::publish-node-snapshot runtime "worker"))))
         (setf (symbol-function 'ag-grpc:stream-send) send)))
     (is (gr8s.apiserver::node-agent-session-evicted-p session))
     (is (= 1 (gr8s.apiserver::node-agent-session-gateway-revision session)))
     (let* ((snapshot (gr8s.apiserver::prepare-node-connect-snapshot server "worker" 1))
            (rows (gr8s.kubelet::decode-service-discovery-projection
                   (slot-value snapshot 'gr8s.node.v1::service-discovery-objects-json)))
            (route (gethash '("httproutes" "default" "app") rows)))
       (is (= 2 (slot-value snapshot 'gr8s.node.v1::revision)))
       (is (equalp #("repair.example.com") (gethash "hostnames" (gethash "spec" route))))))))

(test unchanged-repair-reuses-validated-row-identities-without-content-hashing
  (let ((hash (symbol-function 'gr8s.kubelet::discovery-octet-hash)) (hashed-bytes 0))
    (unwind-protect
         (progn
           ;; Install before constructing caches so the tables retain this counter.
           (setf (symbol-function 'gr8s.kubelet::discovery-octet-hash)
                 (lambda (bytes) (incf hashed-bytes (length bytes)) (funcall hash bytes)))
           (call-with-gateway-repair-session
            (lambda (store runtime server session sent)
              (declare (ignore runtime sent))
              (let ((candidate (gr8s.controllers::node-desired-state-snapshot store "worker"))
                    (baseline (gr8s.apiserver::current-node-snapshot server "worker")))
                (gr8s.apiserver::attach-node-topology server "worker" candidate)
                (bt:with-lock-held ((gr8s.apiserver::node-agent-session-lock session))
                  (bt:with-lock-held ((gr8s.apiserver::node-grpc-server-lock server))
                    (is (gr8s.apiserver::node-session-gateway-repair server "worker" session baseline candidate))
                    (setf hashed-bytes 0)
                    (multiple-value-bind (eligible changes)
                        (gr8s.apiserver::node-session-gateway-repair server "worker" session baseline candidate)
                      (is (eq t eligible)) (is (null changes)))
                    (is (= 0 hashed-bytes))))))))
      (setf (symbol-function 'gr8s.kubelet::discovery-octet-hash) hash))))

(test covered-repair-caches-validated-identities-without-retaining-old-row-versions
  (call-with-gateway-repair-session
   (lambda (store runtime server session sent)
     (declare (ignore sent))
     (let ((decode (symbol-function 'gr8s.kubelet::decode-service-discovery-entry)) (decoded 0))
       (unwind-protect
            (progn
              (setf (symbol-function 'gr8s.kubelet::decode-service-discovery-entry)
                    (lambda (bytes) (incf decoded) (funcall decode bytes)))
              (dotimes (i 3)
                (change-published-route-host store (format nil "version-~D.example.com" i))
                (send-gateway-repair-route-change runtime server session)
                (setf decoded 0)
                (is (= 1 (gr8s.controllers::publish-node-snapshot runtime "worker")))
                (is (= 1 decoded))
                (setf decoded 0)
                (is (= 1 (gr8s.controllers::publish-node-snapshot runtime "worker")))
                (is (= 0 decoded))
                (is (= (length (gr8s.kubelet::service-discovery-projection store))
                       (hash-table-count (gr8s.apiserver::node-agent-session-gateway-repair-key-cache session))))))
         (setf (symbol-function 'gr8s.kubelet::decode-service-discovery-entry) decode))))))

(test repair-preserves-full-delivery-for-unacknowledged-or-replaced-sessions
  (dolist (reason '(:gateway-stalled :negative-ack :node-unacknowledged :replaced :evicted :unsupported :epoch))
    (call-with-gateway-repair-session
     (lambda (store runtime server session sent)
       (change-published-route-host store "repaired.example.com")
       (send-gateway-repair-route-change runtime server session
                                        :acknowledge (not (member reason '(:gateway-stalled :negative-ack))))
       (case reason
         (:gateway-stalled
          (setf (gr8s.apiserver::node-agent-session-gateway-pending-since session)
                (- (get-internal-real-time) (* 31 internal-time-units-per-second))))
         (:negative-ack
          (gr8s.apiserver::note-node-gateway-config-ack
           server "worker" (make-instance 'gr8s.node.v1::gateway-config-ack
                                           :base-node-revision 1 :revision 1 :applied nil) session))
         (:node-unacknowledged
          (setf (gethash "worker" (gr8s.apiserver::node-grpc-server-acknowledged-revisions server)) 0))
         (:replaced
          (setf (gethash "worker" (gr8s.apiserver::node-grpc-server-sessions server))
                (gr8s.apiserver::make-node-agent-session nil)))
         (:evicted (setf (gr8s.apiserver::node-agent-session-evicted-p session) t))
         (:unsupported (setf (gr8s.apiserver::node-agent-session-gateway-deltas-p session) nil))
         (:epoch (incf (gr8s.apiserver::node-agent-session-gateway-dependency-epoch session))))
       (is (= 2 (gr8s.controllers::publish-node-snapshot runtime "worker")))
       (is (= 3 (length (funcall sent))))))))

(test return-to-canonical-baseline-still-repairs-an-outstanding-gateway-deletion
  (call-with-gateway-repair-session
   (lambda (store runtime server session sent)
     (let ((extra (gr8s.resources::get-core-resource store "httproutes" "default" "app")))
       (setf (gethash "metadata" extra) (gr8s.resources::core-object "name" "extra"))
       (gr8s.resources::create-core-resource store "httproutes" extra "default"))
     (send-gateway-repair-route-change runtime server session :name "extra")
     (gr8s.resources::delete-core-resource store "httproutes" "default" "extra")
     (let ((candidate (gr8s.controllers::node-desired-state-snapshot store "worker")))
       (gr8s.apiserver::attach-node-topology server "worker" candidate)
       (is (gr8s.apiserver::same-node-desired-content-p
            (gr8s.apiserver::current-node-snapshot server "worker") candidate)))
     (is (= 1 (gr8s.controllers::publish-node-snapshot runtime "worker")))
     (is (= 3 (length (funcall sent))))
     (is (eq :gateway-config (slot-value (first (funcall sent)) 'gr8s.node.v1::payload-case)))
     (is (not (gethash '("httproutes" "default" "extra")
                       (gr8s.apiserver::node-agent-session-gateway-resources session)))))))

(test covered-gateway-deletions-still-rebuild-fresh-state-on-reconnect
  (call-with-gateway-repair-session
   (lambda (store runtime server session sent)
     (gr8s.resources::delete-core-resource store "httproutes" "default" "app")
     (send-gateway-repair-route-change runtime server session)
     (is (= 1 (gr8s.controllers::publish-node-snapshot runtime "worker")))
     (is (= 2 (length (funcall sent))))
     (let ((reconnect (gr8s.apiserver::prepare-node-connect-snapshot server "worker" 1)))
       (is (= 2 (slot-value reconnect 'gr8s.node.v1::revision)))
       (is (not (gethash '("httproutes" "default" "app")
                         (gr8s.kubelet::decode-service-discovery-projection
                          (slot-value reconnect 'gr8s.node.v1::service-discovery-objects-json)))))))))

(test repair-requires-exact-discovery-coverage-and-unchanged-safety-state
  (dolist (change '(:extra-row :missing-row :duplicate-row :dependency :pod :token :route :grant :receivers))
    (call-with-gateway-repair-session
     (lambda (store runtime server session sent)
       (declare (ignore sent))
       (change-published-route-host store "repaired.example.com")
       (send-gateway-repair-route-change runtime server session)
       (let ((candidate (gr8s.controllers::node-desired-state-snapshot store "worker"))
             (baseline (gr8s.apiserver::current-node-snapshot server "worker")))
         (gr8s.apiserver::attach-node-topology server "worker" candidate)
         (case change
           (:extra-row
            (push (trivial-utf-8:string-to-utf-8-bytes
                   "{\"apiVersion\":\"v1\",\"kind\":\"NetworkPolicy\",\"spec\":{},\"metadata\":{\"name\":\"extra\",\"namespace\":\"default\"}}")
                  (slot-value candidate 'gr8s.node.v1::service-discovery-objects-json)))
           (:missing-row
            (push (trivial-utf-8:string-to-utf-8-bytes
                   "{\"apiVersion\":\"networking.k8s.io/v1\",\"kind\":\"NetworkPolicy\",\"spec\":{},\"metadata\":{\"name\":\"old\",\"namespace\":\"default\"}}")
                  (slot-value baseline 'gr8s.node.v1::service-discovery-objects-json)))
           (:duplicate-row
            (let ((rows (slot-value candidate 'gr8s.node.v1::service-discovery-objects-json)))
              (setf (second rows) (first rows))))
           (:dependency (incf (slot-value candidate 'gr8s.node.v1::gateway-dependency-revision)))
           (:pod (push (make-instance 'gr8s.node.v1::pod-assignment :uid "new-pod")
                       (slot-value candidate 'gr8s.node.v1::pods)))
           (:token
            (setf (slot-value baseline 'gr8s.node.v1::pods)
                  (list (make-instance 'gr8s.node.v1::pod-assignment :uid "pod"
                                       :resource-objects-json (list (make-array 1 :element-type '(unsigned-byte 8) :initial-element 1))))
                  (slot-value candidate 'gr8s.node.v1::pods)
                  (list (make-instance 'gr8s.node.v1::pod-assignment :uid "pod"
                                       :resource-objects-json (list (make-array 1 :element-type '(unsigned-byte 8) :initial-element 2))))))
           (:receivers
            (setf (slot-value candidate 'gr8s.node.v1::service-receivers)
                  (list (make-instance 'gr8s.node.v1::service-receiver-proof :pod-uid "new"))))
           (:route (setf (slot-value candidate 'gr8s.node.v1::routes) nil))
           (:grant (setf (slot-value candidate 'gr8s.node.v1::service-risk-grant-digest)
                         (make-array 1 :element-type '(unsigned-byte 8) :initial-element 1))))
         ;; Empty route lists can already be the fixture's topology: modify the network instead.
         (when (eq change :route)
           (setf (slot-value candidate 'gr8s.node.v1::network)
                 (make-instance (class-of (slot-value baseline 'gr8s.node.v1::network)))))
         (bt:with-lock-held ((gr8s.apiserver::node-agent-session-lock session))
           (bt:with-lock-held ((gr8s.apiserver::node-grpc-server-lock server))
             (is (not (gr8s.apiserver::node-session-gateway-repair
                       server "worker" session baseline candidate))))))))))

(test applying-a-gateway-update-sends-only-a-gateway-ack-and-does-not-persist-node-identity
  (let ((send (symbol-function 'gr8s.agent::send-agent-session-envelope))
        (persist (symbol-function 'gr8s.agent::persist-agent-identity))
        (applied nil) (sent nil))
    (unwind-protect
         (progn
           (setf (symbol-function 'gr8s.agent::send-agent-session-envelope)
                 (lambda (session variant payload)
                   (declare (ignore session)) (push (cons variant payload) sent))
                 (symbol-function 'gr8s.agent::persist-agent-identity)
                 (lambda (&rest args) (declare (ignore args)) (fail "Gateway update wrote node identity")))
           (gr8s.agent::apply-gateway-config-and-respond
            nil (gateway-update-for-test 0 1 (gateway-change-for-test "a"))
            (lambda (update) (setf applied update)))
           (is (typep applied 'gr8s.node.v1::gateway-config-update))
           (is (equal '(:gateway-config-ack) (mapcar #'car sent)))
           (is (= 7 (slot-value (cdar sent) 'gr8s.node.v1::base-node-revision))))
      (setf (symbol-function 'gr8s.agent::send-agent-session-envelope) send
            (symbol-function 'gr8s.agent::persist-agent-identity) persist))))

(test gateway-capability-is-offered-only-with-an-ordered-gateway-applicator
  (let ((capability gr8s.protocol::+gateway-config-delta-capability+))
    (is (not (member capability (gr8s.agent::node-session-capabilities (list capability) nil nil) :test #'equal)))
    (is (not (member capability (gr8s.agent::node-session-capabilities nil #'identity t) :test #'equal)))
    (let ((capabilities (gr8s.agent::node-session-capabilities '("service-risk-v2") #'identity nil)))
      (is (member capability capabilities :test #'equal))
      (is (member "desired-state-delta" capabilities :test #'equal))
      (is (member "service-risk-v2" capabilities :test #'equal)))))

(defun gateway-node-for-test (path)
  (let ((agent (gr8s.agent::make-node-runtime (merge-pathnames "agent/" path) (make-fake-runtime) nil)))
    (setf (gr8s.agent::node-runtime-state agent) :running
          (gr8s.agent::node-runtime-gateway-controller agent)
          (gr8s.controllers::make-gateway-controller
           (gr8s.agent::node-runtime-store agent)
           :start-fn (lambda (&rest args) (declare (ignore args)) :listener)
           :swap-fn (lambda (&rest args) (declare (ignore args)))
           :stop-fn (lambda (&rest args) (declare (ignore args)))))
    agent))

(defun gateway-snapshot-for-test (source revision)
  (make-instance 'gr8s.node.v1::desired-state-snapshot :revision revision
                 :service-discovery-objects-json (gr8s.kubelet::service-discovery-projection source)))

(defun gateway-object-change-for-test (resource object)
  (let* ((public (gr8s.kubelet::service-discovery-public-object object))
         (metadata (gethash "metadata" public)))
    (make-instance 'gr8s.node.v1::gateway-resource-change
                   :resource resource :namespace (gethash "namespace" metadata "")
                   :name (gethash "name" metadata)
                   :object-json (trivial-utf-8:string-to-utf-8-bytes (com.inuoe.jzon:stringify public)))))

(test gateway-resource-edits-decode-only-changed-rows-and-do-not-journal-node-state
  (with-temporary-store (source path)
    (gwc-seed source)
    (let* ((agent (gateway-node-for-test path))
           (store (gr8s.agent::node-runtime-store agent))
           (decode (symbol-function 'gr8s.kubelet::decode-service-discovery-entry))
           (commit (symbol-function 'gr8s.resources::commit-core-resources))
           (decoded 0))
      (gr8s.agent::reconcile-node-snapshot agent (gateway-snapshot-for-test source 7))
      (is (= 7 (gr8s.agent::node-runtime-gateway-base-revision agent)))
      (gr8s.resources::update-core-resource
       source "httproutes" "default" "app"
       (lambda (object) (setf (gethash "hostnames" (gethash "spec" object)) #("new.example.com")) object))
      (let ((revision (gr8s.store::pod-store-resource-revision store))
            (update (gateway-update-for-test
                     0 1 (gateway-object-change-for-test
                          "httproutes" (gr8s.resources::get-core-resource source "httproutes" "default" "app")))))
        (unwind-protect
             (progn
               (setf (symbol-function 'gr8s.kubelet::decode-service-discovery-entry)
                     (lambda (bytes) (incf decoded) (funcall decode bytes))
                     (symbol-function 'gr8s.resources::commit-core-resources)
                     (lambda (&rest args) (declare (ignore args)) (error "Gateway delta attempted a durable node resource write")))
               (gr8s.agent::reconcile-node-gateway-config agent update)
               (is (= 1 decoded))
               (is (= revision (gr8s.store::pod-store-resource-revision store)))
               (is (= 1 (gr8s.agent::node-runtime-gateway-config-revision agent)))
               (is (equalp #("new.example.com")
                           (gethash "hostnames" (gethash "spec"
                             (gr8s.resources::get-core-resource
                              (gr8s.controllers::gateway-controller-store (gr8s.agent::node-runtime-gateway-controller agent))
                              "httproutes" "default" "app")))))
               (is (equalp #("app.example.com")
                           (gethash "hostnames" (gethash "spec"
                             (gr8s.resources::get-core-resource store "httproutes" "default" "app"))))))
          (setf (symbol-function 'gr8s.kubelet::decode-service-discovery-entry) decode
                (symbol-function 'gr8s.resources::commit-core-resources) commit)))
      (gr8s.agent::reconcile-node-gateway-config
       agent (gateway-update-for-test 1 2 (gateway-change-for-test "app" :deleted t)))
      (signals kubernetes-error
        (gr8s.resources::get-core-resource
         (gr8s.controllers::gateway-controller-store (gr8s.agent::node-runtime-gateway-controller agent))
         "httproutes" "default" "app"))
      (is (null (funcall (cdr (gethash 8080 (gr8s.controllers::gateway-controller-routing-tables
                                           (gr8s.agent::node-runtime-gateway-controller agent))))
                        "new.example.com" "/" "GET" nil))))))

(test gateway-deltas-preserve-old-resource-views-without-copying-the-whole-index
  (with-temporary-store (source path)
    (gwc-seed source)
    (let ((agent (gateway-node-for-test path)))
      (gr8s.agent::reconcile-node-snapshot agent (gateway-snapshot-for-test source 7))
      (let* ((old (gr8s.agent::node-runtime-gateway-view-store agent))
             (old-index (gr8s.store::pod-store-resources old))
             (copy (symbol-function 'alexandria:copy-hash-table)))
        (change-published-route-host source "changed.example.com")
        (sb-ext:with-unlocked-packages (:alexandria)
        (unwind-protect
             (progn
               (setf (symbol-function 'alexandria:copy-hash-table)
                     (lambda (table &rest args)
                       (when (eq table old-index) (error "Copied the entire Gateway resource index"))
                       (apply copy table args)))
               (gr8s.agent::reconcile-node-gateway-config
                agent (gateway-update-for-test
                       0 1 (gateway-object-change-for-test
                            "httproutes" (gr8s.resources::get-core-resource source "httproutes" "default" "app")))))
          (setf (symbol-function 'alexandria:copy-hash-table) copy)))
        (is (equalp #("app.example.com")
                    (gethash "hostnames" (gethash "spec"
                      (gr8s.resources::get-core-resource old "httproutes" "default" "app")))))
        (is (equalp #("changed.example.com")
                    (gethash "hostnames" (gethash "spec"
                      (gr8s.resources::get-core-resource
                       (gr8s.agent::node-runtime-gateway-view-store agent) "httproutes" "default" "app")))))))))

(test invalid-gateway-batches-cannot-partially-change-the-active-view
  (with-temporary-store (source path)
    (gwc-seed source)
    (let* ((agent (gateway-node-for-test path))
           (good (gateway-object-change-for-test
                  "httproutes" (gr8s.resources::get-core-resource source "httproutes" "default" "app")))
           (bad (gateway-object-change-for-test
                 "gateways" (gr8s.resources::get-core-resource source "gateways" "default" "web"))))
      (gr8s.agent::reconcile-node-snapshot agent (gateway-snapshot-for-test source 7))
      (let ((view (gr8s.controllers::gateway-controller-store (gr8s.agent::node-runtime-gateway-controller agent))))
        (setf (slot-value bad 'gr8s.node.v1::resource) "httproutes"
              (slot-value bad 'gr8s.node.v1::name) "forged")
        (signals error (gr8s.agent::reconcile-node-gateway-config agent (gateway-update-for-test 0 1 good bad)))
        (is (eq view (gr8s.controllers::gateway-controller-store (gr8s.agent::node-runtime-gateway-controller agent))))
        (is (= 0 (gr8s.agent::node-runtime-gateway-config-revision agent)))))))

(test gateway-recovery-requires-full-synchronization-before-deltas-or-readiness
  (with-temporary-store (source path)
    (gwc-seed source)
    (let ((agent (gateway-node-for-test path))
          (update (gateway-update-for-test 0 1 (gateway-change-for-test "app" :deleted t))))
      (is (not (gr8s.agent::node-runtime-gateway-synchronized-p agent)))
      (signals error (gr8s.agent::reconcile-node-gateway-config agent update))
      (gr8s.agent::reconcile-node-snapshot agent (gateway-snapshot-for-test source 7))
      (is (gr8s.agent::node-runtime-gateway-synchronized-p agent))
      (gr8s.agent::reset-node-gateway-session agent)
      (is (not (gr8s.agent::node-runtime-gateway-synchronized-p agent)))
      (signals error (gr8s.agent::reconcile-node-gateway-config agent update))
      (is (null (slot-value (gr8s.agent::node-runtime-status agent) 'gr8s.node.v1::gateways)))
      (gr8s.agent::reconcile-node-snapshot agent (gateway-snapshot-for-test source 8))
      (is (= 8 (gr8s.agent::node-runtime-gateway-base-revision agent)))
      (is (gr8s.agent::node-runtime-gateway-synchronized-p agent)))))

(test gateway-deltas-cannot-change-service-selection-outside-the-node-safety-baseline
  (with-temporary-store (source path)
    (gwc-seed source)
    (gr8s.resources::create-core-resource
     source "services"
     (com.inuoe.jzon:parse "{\"apiVersion\":\"v1\",\"kind\":\"Service\",\"metadata\":{\"name\":\"app-svc\"},\"spec\":{\"ports\":[{\"port\":80}]}}") "default")
    (let ((agent (gateway-node-for-test path)))
      (gr8s.agent::reconcile-node-snapshot agent (gateway-snapshot-for-test source 7))
      (let ((service (gr8s.resources::get-core-resource source "services" "default" "app-svc")))
        (setf (gethash "port" (aref (gethash "ports" (gethash "spec" service)) 0)) 81)
        (signals error
          (gr8s.agent::reconcile-node-gateway-config
           agent (gateway-update-for-test 0 1 (gateway-object-change-for-test "services" service)))))
      (is (= 0 (gr8s.agent::node-runtime-gateway-config-revision agent))))))

(test dispatched-routes-retain-their-own-endpoint-view-across-full-updates
  (with-temporary-store (source path)
    (gwc-seed source)
    (gr8s.resources::create-core-resource
     source "services"
     (com.inuoe.jzon:parse "{\"apiVersion\":\"v1\",\"kind\":\"Service\",\"metadata\":{\"name\":\"app-svc\"},\"spec\":{\"ports\":[{\"name\":\"http\",\"port\":80,\"targetPort\":8080}]}}") "default")
    (gr8s.resources::create-core-resource
     source "endpointslices"
     (com.inuoe.jzon:parse "{\"apiVersion\":\"discovery.k8s.io/v1\",\"kind\":\"EndpointSlice\",\"metadata\":{\"name\":\"app\",\"labels\":{\"kubernetes.io/service-name\":\"app-svc\"}},\"addressType\":\"IPv4\",\"ports\":[{\"name\":\"http\",\"port\":8080}],\"endpoints\":[{\"addresses\":[\"10.0.0.1\"],\"conditions\":{\"ready\":true}}]}") "default")
    (let* ((agent (gateway-node-for-test path))
           (controller (gr8s.agent::node-runtime-gateway-controller agent)))
      (gr8s.agent::reconcile-node-snapshot agent (gateway-snapshot-for-test source 7))
      (let* ((acceptor (make-instance 'gr8s.controllers::gateway-acceptor
                                      :resolver (gr8s.controllers::gateway-controller-resolver controller)))
             (old-router (cdr (gethash 8080 (gr8s.controllers::gateway-controller-routing-tables controller))))
             (old-backend (gr8s.controllers::gw-dispatch-backend
                           (funcall old-router "app.example.com" "/" "GET" nil))))
        (is (equal '("10.0.0.1" 8080)
                   (multiple-value-list (gr8s.controllers::gateway-resolve-backend acceptor old-backend))))
        (gr8s.resources::update-core-resource
         source "endpointslices" "default" "app"
         (lambda (object)
           (setf (gethash "addresses" (aref (gethash "endpoints" object) 0)) #("10.0.0.2")) object))
        (gr8s.agent::reconcile-node-snapshot agent (gateway-snapshot-for-test source 8))
        (let* ((new-router (cdr (gethash 8080 (gr8s.controllers::gateway-controller-routing-tables controller))))
               (new-backend (gr8s.controllers::gw-dispatch-backend
                             (funcall new-router "app.example.com" "/" "GET" nil))))
          (is (equal '("10.0.0.2" 8080)
                     (multiple-value-list (gr8s.controllers::gateway-resolve-backend acceptor new-backend))))
          (is (equal '("10.0.0.1" 8080)
                     (multiple-value-list (gr8s.controllers::gateway-resolve-backend acceptor old-backend)))))))))

(test backend-bindings-preserve-l4-view-consistency-without-mutating-route-candidates
  (let* ((backend (gr8s.controllers::make-gw-backend :name "app" :port 80 :weight 3))
         (old (lambda (backend) (declare (ignore backend)) (values "10.0.0.1" 80)))
         (new (lambda (backend) (declare (ignore backend)) (values "10.0.0.2" 80)))
         (dispatcher (gr8s.controllers::bind-gateway-l4-dispatcher
                      (lambda (sni) (declare (ignore sni)) backend) new))
         (bound (funcall dispatcher "app.example.com")))
    (is (not (eq backend bound)))
    (is (null (gr8s.controllers::gw-backend-resolver backend)))
    (is (= 3 (gr8s.controllers::gw-backend-weight bound)))
    (is (equal '("10.0.0.2" 80)
               (multiple-value-list (gr8s.controllers::resolve-gateway-backend bound old))))
    (is (equal '("10.0.0.1" 80)
               (multiple-value-list (gr8s.controllers::resolve-gateway-backend backend old))))))

(test committed-change-context-and-dependency-clock-distinguish-gateway-edits
  (with-temporary-store (store path)
    (values path)
    (gwc-seed store)
    (let ((batches nil)
          (before (gr8s.store::pod-store-gateway-dependency-revision store)))
      (gr8s.resources::add-core-resource-change-observer
       store (lambda () (push gr8s.resources::*core-resource-changes* batches)))
      (gr8s.resources::update-core-resource
       store "httproutes" "default" "app"
       (lambda (object) (setf (gethash "hostnames" (gethash "spec" object)) #("changed.example.com")) object))
      (is (= 1 (length (first batches))))
      (is (equal "httproutes" (gethash "resource" (first (first batches)))))
      (is (= before (gr8s.store::pod-store-gateway-dependency-revision store)))
      (gr8s.resources::create-core-resource
       store "services"
       (com.inuoe.jzon:parse "{\"apiVersion\":\"v1\",\"kind\":\"Service\",\"metadata\":{\"name\":\"dep\"},\"spec\":{\"ports\":[{\"port\":80}]}}") "default")
      (is (= (1+ before) (gr8s.store::pod-store-gateway-dependency-revision store)))
      (let ((count (length batches)))
        (gr8s.resources::update-core-resource
         store "gateways" "default" "web"
         (lambda (object) (setf (gethash "status" object) (gr8s.resources::core-object "test" t)) object))
        (is (= count (length batches)))
        (is (= (1+ before) (gr8s.store::pod-store-gateway-dependency-revision store)))))))

(test discovery-serialization-uses-one-captured-resource-view-and-returns-its-dependency-clock
  (with-temporary-store (source path)
    (values path)
    (gr8s.resources::create-core-resource
     source "services"
     (com.inuoe.jzon:parse "{\"apiVersion\":\"v1\",\"kind\":\"Service\",\"metadata\":{\"name\":\"dep\"},\"spec\":{\"ports\":[{\"port\":80}]}}") "default")
    (let ((original (symbol-function 'gr8s.kubelet::build-service-discovery-projection))
          (mutate t))
      (unwind-protect
           (progn
             (setf (symbol-function 'gr8s.kubelet::build-service-discovery-projection)
                   (lambda (view &optional cache)
                     (when mutate
                       (setf mutate nil)
                       (gr8s.resources::update-core-resource
                        source "services" "default" "dep"
                        (lambda (object) (setf (gethash "port" (aref (gethash "ports" (gethash "spec" object)) 0)) 81) object)))
                     (funcall original view cache)))
             (gr8s.kubelet::call-with-discovery-projection-cache
              (lambda ()
                (multiple-value-bind (projection clock) (gr8s.kubelet::service-discovery-projection source)
                  (let ((object (com.inuoe.jzon:parse (trivial-utf-8:utf-8-bytes-to-string (first projection)))))
                    (is (= 80 (gethash "port" (aref (gethash "ports" (gethash "spec" object)) 0)))))
                  (is (integerp clock))
                  (multiple-value-bind (next next-clock) (gr8s.kubelet::service-discovery-projection source)
                    (let ((object (com.inuoe.jzon:parse (trivial-utf-8:utf-8-bytes-to-string (first next)))))
                      (is (= 81 (gethash "port" (aref (gethash "ports" (gethash "spec" object)) 0)))))
                    (is (integerp next-clock))
                    (when (and (integerp clock) (integerp next-clock)) (is (= (1+ clock) next-clock))))))))
        (setf (symbol-function 'gr8s.kubelet::build-service-discovery-projection) original)))))

(test node-deltas-and-deduplication-preserve-the-gateway-dependency-fence
  (let* ((base (make-instance 'gr8s.node.v1::desired-state-snapshot :revision 7 :gateway-dependency-revision 2))
         (next (make-instance 'gr8s.node.v1::desired-state-snapshot :revision 8 :gateway-dependency-revision 3))
         (session (gr8s.agent::make-agent-node-session nil)))
    (is (not (gr8s.apiserver::same-node-desired-content-p base next)))
    (setf (gr8s.agent::agent-node-session-received session) base)
    (let* ((delta (roundtrip-node-message (gr8s.apiserver::node-snapshot-delta base next)
                                          'gr8s.node.v1::desired-state-snapshot))
           (assembled (gr8s.agent::assemble-node-snapshot session delta)))
      (is (= 3 (slot-value delta 'gr8s.node.v1::gateway-dependency-revision)))
      (is (= 3 (slot-value assembled 'gr8s.node.v1::gateway-dependency-revision)))))
  (with-temporary-store (store path)
    (values path)
    (let ((snapshot (gr8s.controllers::node-desired-state-snapshot store "worker")))
      (is (= (gr8s.store::pod-store-gateway-dependency-revision store)
             (slot-value snapshot 'gr8s.node.v1::gateway-dependency-revision))))))

(test full-and-gateway-publication-share-a-reentrant-per-node-capture-order
  (let ((server (gr8s.apiserver::%make-node-grpc-server))
        (entered nil) (release nil) (gateway-captured nil) (failure nil)
        (full-thread nil) (gateway-thread nil))
    (is (eq :nested
            (gr8s.apiserver::call-with-node-publication
             server "worker" (lambda ()
                               (gr8s.apiserver::call-with-node-publication
                                server "worker" (lambda () :nested))))))
    (unwind-protect
         (progn
           (setf full-thread
                 (bt:make-thread
                  (lambda ()
                    (handler-case
                        (gr8s.apiserver::call-with-node-publication
                         server "worker" (lambda () (setf entered t) (loop until release do (sleep .005))))
                      (error (condition) (setf failure condition))))))
           (is (poll-until (lambda () entered)))
           (setf gateway-thread
                 (bt:make-thread
                  (lambda ()
                    (handler-case
                        (gr8s.apiserver::call-with-node-publication
                         server "worker" (lambda () (setf gateway-captured t)))
                      (error (condition) (setf failure condition))))))
           (is (eq :other (gr8s.apiserver::call-with-node-publication server "other" (lambda () :other))))
           (sleep .03)
           (is (not gateway-captured))
           (setf release t)
           (is (poll-until (lambda () gateway-captured)))
           (is (null failure)))
      (setf release t)
      (when full-thread (bt:join-thread full-thread))
      (when gateway-thread (bt:join-thread gateway-thread)))))

(test route-edits-reuse-untouched-host-buckets-and-leave-old-dispatchers-immutable
  (flet ((route (name host backend)
           (gr8s.controllers::make-gw-route
            :namespace "default" :name name :hostnames (list host)
            :rules (list (gr8s.controllers::make-gw-rule
                          :matches (list (gr8s.controllers::make-gw-match))
                          :backends (list (gr8s.controllers::make-gw-backend :name backend)))))))
    (let* ((old (route "a" "old.example.com" "old"))
           (untouched (route "b" "untouched.example.com" "b"))
           (replacement (route "a" "new.example.com" "new")))
      (multiple-value-bind (dispatcher table) (gr8s.controllers::build-gateway-router (list old untouched))
        (is (typep table 'gr8s.controllers::gw-routing-table))
        (let* ((next (gr8s.controllers::update-gateway-routing-table
                      table (list old) (list replacement)
                      (lambda (a b) (gr8s.controllers::gw-key> (gr8s.controllers::gw-candidate-key a)
                                                             (gr8s.controllers::gw-candidate-key b)))))
               (updated (gr8s.controllers::gateway-router-from-table next)))
          (is (eq (gr8s.controllers::gateway-host-bucket table "untouched.example.com")
                  (gr8s.controllers::gateway-host-bucket next "untouched.example.com")))
          (is (null (funcall updated "old.example.com" "/" "GET" nil)))
          (is (equal "new" (gr8s.controllers::gw-backend-name
                             (gr8s.controllers::gw-dispatch-backend (funcall updated "new.example.com" "/" "GET" nil)))))
          (is (equal "old" (gr8s.controllers::gw-backend-name
                             (gr8s.controllers::gw-dispatch-backend (funcall dispatcher "old.example.com" "/" "GET" nil))))))))))

#+sbcl
(test a-single-route-update-does-not-allocate-a-copy-of-the-hostname-index
  (let* ((routes (loop for i below 10000
                       collect (gr8s.controllers::make-gw-route
                                :namespace "default" :name (format nil "route-~D" i)
                                :hostnames (list (format nil "~D.example.com" i))
                                :rules (list (gr8s.controllers::make-gw-rule
                                              :matches (list (gr8s.controllers::make-gw-match)))))))
         (replacement (gr8s.controllers::make-gw-route
                       :namespace "default" :name "route-0" :hostnames '("changed.example.com")
                       :rules (list (gr8s.controllers::make-gw-rule
                                     :matches (list (gr8s.controllers::make-gw-match)))))))
    (multiple-value-bind (dispatcher table) (gr8s.controllers::build-gateway-router routes)
      (declare (ignore dispatcher))
      (flet ((update ()
               (gr8s.controllers::update-gateway-routing-table
                table (list (first routes)) (list replacement)
                (lambda (a b) (gr8s.controllers::gw-key>
                               (gr8s.controllers::gw-candidate-key a)
                               (gr8s.controllers::gw-candidate-key b))))))
        (update)
        (sb-ext:gc :full t)
        (let ((start (sb-ext:get-bytes-consed)))
          (dotimes (i 100) (update))
          ;; Loose budget tolerates allocator granularity, but not a 10000-key copy.
          (is (< (/ (- (sb-ext:get-bytes-consed) start) 100) 32768)))))))

(test an-agent-route-edit-parses-only-that-route-and-does-not-replan-all-listeners
  (with-temporary-store (source path)
    (gwc-seed source)
    (let ((template (gr8s.resources::get-core-resource source "httproutes" "default" "app")))
      (dotimes (index 100)
        (let* ((name (format nil "other-~D" index)) (route (gr8s.resources::copy-core-object template)))
          (setf (gethash "name" (gethash "metadata" route)) name
                (gethash "uid" (gethash "metadata" route)) name
                (gethash "hostnames" (gethash "spec" route)) (vector (format nil "~A.example.com" name))
                (gethash (list "httproutes" "default" name) (gr8s.store::pod-store-resources source)) route))))
    (let* ((agent (gateway-node-for-test path))
           (parse (symbol-function 'gr8s.controllers::parse-httproute))
           (plan (symbol-function 'gr8s.controllers::gateway-listener-plan))
           (parsed 0))
      (gr8s.agent::reconcile-node-snapshot agent (gateway-snapshot-for-test source 7))
      (change-published-route-host source "incremental.example.com")
      (unwind-protect
           (progn
             (setf (symbol-function 'gr8s.controllers::parse-httproute)
                   (lambda (object) (incf parsed) (funcall parse object))
                   (symbol-function 'gr8s.controllers::gateway-listener-plan)
                   (lambda (&rest args) (declare (ignore args)) (error "Route edit replanned every listener")))
             (gr8s.agent::reconcile-node-gateway-config
              agent (gateway-update-for-test 0 1 (gateway-object-change-for-test
                                                 "httproutes" (gr8s.resources::get-core-resource source "httproutes" "default" "app"))))
             (is (<= parsed 2))
             (let ((router (cdr (gethash 8080 (gr8s.controllers::gateway-controller-routing-tables
                                             (gr8s.agent::node-runtime-gateway-controller agent))))))
               (is (equal "app" (gr8s.controllers::gw-dispatch-route-name
                                 (funcall router "incremental.example.com" "/" "GET" nil))))
               (is (equal "other-50" (gr8s.controllers::gw-dispatch-route-name
                                      (funcall router "other-50.example.com" "/" "GET" nil))))))
        (setf (symbol-function 'gr8s.controllers::parse-httproute) parse
              (symbol-function 'gr8s.controllers::gateway-listener-plan) plan)))))

(test incremental-routing-matches-full-rebuilds-with-parent-ties-wildcards-and-ingress
  (with-temporary-store (source path)
    (gwc-seed source)
    (gr8s.resources::update-core-resource
     source "gateways" "default" "web"
     (lambda (object) (setf (gethash "port" (aref (gethash "listeners" (gethash "spec" object)) 0)) 80) object))
    (gr8s.resources::create-core-resource source "gateways"
      (com.inuoe.jzon:parse "{\"apiVersion\":\"gateway.networking.k8s.io/v1\",\"kind\":\"Gateway\",\"metadata\":{\"name\":\"web2\"},\"spec\":{\"gatewayClassName\":\"gr8s\",\"listeners\":[{\"name\":\"http\",\"port\":80,\"protocol\":\"HTTP\"}]}}") "default")
    (gr8s.resources::create-core-resource source "ingressclasses"
      (com.inuoe.jzon:parse "{\"apiVersion\":\"networking.k8s.io/v1\",\"kind\":\"IngressClass\",\"metadata\":{\"name\":\"gr8s\"},\"spec\":{\"controller\":\"gr8s.io/ingress-controller\"}}") nil)
    (gr8s.resources::create-core-resource source "ingresses"
      (com.inuoe.jzon:parse "{\"apiVersion\":\"networking.k8s.io/v1\",\"kind\":\"Ingress\",\"metadata\":{\"name\":\"zeta\"},\"spec\":{\"ingressClassName\":\"gr8s\",\"defaultBackend\":{\"service\":{\"name\":\"ingress-svc\",\"port\":{\"number\":80}}}}}") "default")
    (labels ((create-route (name parent backend)
               (let ((object (gr8s.resources::get-core-resource source "httproutes" "default" "app")))
                 (setf (gethash "metadata" object) (gr8s.resources::core-object "name" name)
                       (gethash "parentRefs" (gethash "spec" object)) (vector (gr8s.resources::core-object "name" parent))
                       (gethash "hostnames" (gethash "spec" object)) #("shared.example.com")
                       (gethash "name" (aref (gethash "backendRefs" (aref (gethash "rules" (gethash "spec" object)) 0)) 0)) backend)
                 (gr8s.resources::create-core-resource source "httproutes" object "default"))))
      (create-route "alpha" "web2" "alpha-svc")
      (create-route "zeta" "web" "zeta-svc")
      (let ((agent (gateway-node-for-test path)) (revision 0))
        (gr8s.agent::reconcile-node-snapshot agent (gateway-snapshot-for-test source 7))
        (labels ((check-reference ()
                   (let* ((view (gr8s.controllers::gateway-controller-store (gr8s.agent::node-runtime-gateway-controller agent)))
                          (reference (gr8s.controllers::make-gateway-controller
                                      view :start-fn (lambda (&rest args) (declare (ignore args)) :listener)
                                      :swap-fn (lambda (&rest args) (declare (ignore args)))
                                      :stop-fn (lambda (&rest args) (declare (ignore args)))))
                          (actual (cdr (gethash 80 (gr8s.controllers::gateway-controller-routing-tables
                                                  (gr8s.agent::node-runtime-gateway-controller agent))))))
                     (gr8s.controllers::converge-gateway-listeners reference)
                     (let ((expected (cdr (gethash 80 (gr8s.controllers::gateway-controller-routing-tables reference)))))
                       (dolist (host '("shared.example.com" "app.example.com" "something.example.com" "outside.test"))
                         (dolist (path '("/" "/a" "/a/x" "/ab" "/v1/route"))
                           (dolist (method '("GET" "POST"))
                             (let* ((a (funcall actual host path method nil)) (b (funcall expected host path method nil))
                                    (a-backend (and a (gr8s.controllers::gw-dispatch-backend a)))
                                    (b-backend (and b (gr8s.controllers::gw-dispatch-backend b))))
                               (is (equal (and a-backend (gr8s.controllers::gw-backend-name a-backend))
                                          (and b-backend (gr8s.controllers::gw-backend-name b-backend)))))))))))
                 (apply-route (name &optional deleted)
                   (let ((change (if deleted (gateway-change-for-test name :deleted t)
                                     (gateway-object-change-for-test "httproutes"
                                       (gr8s.resources::get-core-resource source "httproutes" "default" name)))))
                     (gr8s.agent::reconcile-node-gateway-config agent (gateway-update-for-test revision (1+ revision) change))
                     (incf revision)
                     (check-reference))))
          (check-reference)
          (gr8s.resources::update-core-resource source "httproutes" "default" "zeta"
            (lambda (object)
              (setf (gethash "parentRefs" (gethash "spec" object))
                    (vector (gr8s.resources::core-object "name" "web") (gr8s.resources::core-object "name" "web2"))) object))
          (apply-route "zeta")
          (gr8s.resources::update-core-resource source "httproutes" "default" "zeta"
            (lambda (object)
              (setf (gethash "hostnames" (gethash "spec" object)) #("*.example.com"))
              (setf (gethash "matches" (aref (gethash "rules" (gethash "spec" object)) 0))
                    (vector (gr8s.resources::core-object "path" (gr8s.resources::core-object "type" "PathPrefix" "value" "/a")))) object))
          (apply-route "zeta")
          (gr8s.resources::delete-core-resource source "httproutes" "default" "alpha")
          (apply-route "alpha" t)
          (gr8s.resources::update-core-resource source "httproutes" "default" "zeta"
            (lambda (object)
              (remhash "hostnames" (gethash "spec" object))
              (setf (gethash "matches" (aref (gethash "rules" (gethash "spec" object)) 0))
                    (vector (gr8s.resources::core-object "path" (gr8s.resources::core-object "type" "PathPrefix" "value" "/")))) object))
          (apply-route "zeta")
          (gr8s.resources::delete-core-resource source "httproutes" "default" "zeta")
          (apply-route "zeta" t))))))

(test gateway-incremental-hostname-restriction-survives-route-update-and-delete
  (with-temporary-store (source path)
    (gwc-seed source)
    (gr8s.resources::update-core-resource
     source "gateways" "default" "web"
     (lambda (object)
       (setf (gethash "hostname" (aref (gethash "listeners" (gethash "spec" object)) 0)) "app.example.com")
       object))
    (let* ((agent (gateway-node-for-test path))
           (controller (gr8s.agent::node-runtime-gateway-controller agent)))
      (gr8s.agent::reconcile-node-snapshot agent (gateway-snapshot-for-test source 7))
      (gr8s.resources::update-core-resource
       source "httproutes" "default" "app"
       (lambda (object) (setf (gethash "hostnames" (gethash "spec" object)) #("*.example.com")) object))
      (gr8s.agent::reconcile-node-gateway-config
       agent (gateway-update-for-test 0 1
               (gateway-object-change-for-test "httproutes"
                 (gr8s.resources::get-core-resource source "httproutes" "default" "app"))))
      (let ((router (gethash 8080 (gr8s.controllers::gateway-controller-routing-bases controller))))
        (is (not (null (funcall router "app.example.com" "/" "GET" nil))))
        (is (null (funcall router "other.example.com" "/" "GET" nil))))
      (gr8s.agent::reconcile-node-gateway-config
       agent (gateway-update-for-test 1 2 (gateway-change-for-test "app" :deleted t)))
      (let ((router (gethash 8080 (gr8s.controllers::gateway-controller-routing-bases controller))))
        (is (null (funcall router "app.example.com" "/" "GET" nil)))))))

(test gateway-node-view-preserves-namespace-selector-labels
  (with-temporary-store (source path)
    (gwc-seed source)
    (gr8s.resources::create-core-resource
     source "namespaces" (com.inuoe.jzon:parse
                          "{\"apiVersion\":\"v1\",\"kind\":\"Namespace\",\"metadata\":{\"name\":\"tenant\",\"labels\":{\"team\":\"blue\"}}}") nil)
    (let ((agent (gateway-node-for-test path)))
      (loop for color in '("blue" "red") for revision from 7 do
        (gr8s.resources::update-core-resource
         source "namespaces" nil "tenant"
         (lambda (object) (setf (gethash "team" (gethash "labels" (gethash "metadata" object))) color) object))
        (gr8s.agent::reconcile-node-snapshot agent (gateway-snapshot-for-test source revision))
        (let* ((view (gr8s.controllers::gateway-controller-store
                      (gr8s.agent::node-runtime-gateway-controller agent)))
               (namespace (ignore-errors (gr8s.resources::get-core-resource view "namespaces" nil "tenant"))))
          (is (not (null namespace)))
          (when namespace
            (is (equal color (gethash "team" (gethash "labels" (gethash "metadata" namespace)))))))))))

(test gateway-node-view-delivers-reference-grants-and-revocation
  (with-temporary-store (source path)
    (gwc-seed source)
    (gr8s.resources::create-core-resource
     source "services" (com.inuoe.jzon:parse
                       "{\"metadata\":{\"name\":\"web\",\"namespace\":\"target\"},\"spec\":{\"ports\":[{\"port\":80}]}}") "target")
    (let ((agent (gateway-node-for-test path))
          (backend (gr8s.controllers::gw-parse-backend
                    (com.inuoe.jzon:parse "{\"name\":\"web\",\"namespace\":\"target\",\"port\":80}") "default"))
          (grant (com.inuoe.jzon:parse
                  "{\"apiVersion\":\"gateway.networking.k8s.io/v1\",\"kind\":\"ReferenceGrant\",\"metadata\":{\"name\":\"allow\",\"namespace\":\"target\"},\"spec\":{\"from\":[{\"group\":\"gateway.networking.k8s.io\",\"kind\":\"HTTPRoute\",\"namespace\":\"default\"}],\"to\":[{\"group\":\"\",\"kind\":\"Service\",\"name\":\"web\"}]}}")))
      ;; Populate the desired-resource seam directly: this test covers projection,
      ;; not registration of the ReferenceGrant API in the native server.
      (loop for allowed in '(nil t nil) for revision from 7 do
        (gr8s.store::with-store-lock (source)
          (if allowed
              (setf (gethash '("referencegrants" "target" "allow") (gr8s.store::pod-store-resources source)) grant)
              (remhash '("referencegrants" "target" "allow") (gr8s.store::pod-store-resources source)))
          (incf (gr8s.store::pod-store-resource-revision source)))
        (gr8s.agent::reconcile-node-snapshot agent (gateway-snapshot-for-test source revision))
        (let ((view (gr8s.controllers::gateway-controller-store
                     (gr8s.agent::node-runtime-gateway-controller agent))))
          (is (equal (unless allowed "RefNotPermitted")
                     (gr8s.controllers::gateway-backend-reference-error view backend))))))))
