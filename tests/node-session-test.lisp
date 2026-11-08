(in-package #:gr8s/tests)

(in-suite gr8s)

(test node-session-packages-own-their-public-entry-points
  (dolist (name '("START-NODE-GRPC-SERVER"
                  "STOP-NODE-GRPC-SERVER"
                  "PUBLISH-NODE-DESIRED-STATE"))
    (multiple-value-bind (facade facade-status) (find-symbol name '#:gr8s)
      (multiple-value-bind (implementation implementation-status)
          (find-symbol name '#:gr8s.apiserver)
        (is (eq implementation-status :external))
        (is (eq facade-status :external))
        (is (eq facade implementation))
        (is (eq (symbol-package implementation) (find-package '#:gr8s.apiserver))))))
  (dolist (name '("RUN-NODE-SESSION"
                  "MAKE-NODE-SESSION-CONTROL"
                  "CANCEL-NODE-SESSION"))
    (multiple-value-bind (facade facade-status) (find-symbol name '#:gr8s)
      (multiple-value-bind (implementation implementation-status)
          (find-symbol name '#:gr8s.agent)
        (is (eq implementation-status :external))
        (is (if (equal name "RUN-NODE-SESSION")
                (eq facade-status :external)
                (member facade-status '(:internal :external))))
        (is (eq facade implementation))
        (is (eq (symbol-package implementation) (find-package '#:gr8s.agent)))))))

(test node-status-merge-preserves-authenticated-additional-pod-addresses
  (let* ((object (gr8s::core-object
                  "phase" "Running" "podIP" "10.88.1.2"
                  "podIPs" (vector (gr8s::core-object "ip" "10.88.1.2")
                                   (gr8s::core-object "ip" "fd88::2"))))
         (message (make-instance 'gr8s.node.v1::pod-observed-status
                                 :phase "Running" :pod-ip "10.88.1.2")))
    (gr8s.apiserver::merge-node-pod-address-status object message)
    (is (equalp #("10.88.1.2" "fd88::2")
                (map 'vector (lambda (item) (gethash "ip" item))
                     (gethash "podIPs" object))))))

(defun wait-until (predicate &key (timeout 3))
  (let ((deadline (+ (get-internal-real-time)
                     (* timeout internal-time-units-per-second))))
    (loop until (funcall predicate)
          when (>= (get-internal-real-time) deadline) return nil
          do (sleep 0.02)
          finally (return t))))

(defun empty-desired-snapshot ()
  (make-instance 'gr8s.node.v1::desired-state-snapshot))

(test credential-token-requests-are-bound-to-the-authenticated-nodes-pod
  (with-temporary-store (store path)
    (declare (ignore path))
    (gr8s:register-node
     store (gr8s:make-node-record :id "token-node" :name "worker-a" :pod-cidr "10.88.7.0/24"))
    (gr8s::create-core-resource
     store "serviceaccounts"
     (gr8s::core-object
      "metadata" (gr8s::core-object "name" "builder" "uid" "builder-uid"
                                     "annotations" (gr8s::core-object "tenant.example/id" "acme"
                                                                      "tenant.example/region" "ca")))
     "default")
    (let* ((pod (create-pod
                 store
                 (parse-pod
                  "{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"name\":\"puller\",\"namespace\":\"default\"},\"spec\":{\"serviceAccountName\":\"builder\",\"containers\":[{\"name\":\"c\",\"image\":\"private.example/a\"}]}}")))
           (version (pod-resource-version pod)))
      (setf (gr8s::pod-node-name pod) "worker-a")
      (setf pod (gr8s:update-pod store pod version))
      (let* ((request
               (make-instance
                'gr8s.node.v1::credential-token-request
                :request-id "request-1" :namespace "default" :pod-name "puller"
                :pod-uid (pod-uid pod) :service-account-name "builder"
                :audience "private.example"
                :required-annotation-keys '("tenant.example/id")
                :optional-annotation-keys '("tenant.example/region" "tenant.example/missing")))
             (response (gr8s::credential-token-response store "worker-a" request)))
        (is (equal "request-1" (slot-value response 'gr8s.node.v1::request-id)))
        (is (plusp (length (slot-value response 'gr8s.node.v1::token))))
        (is (equal (gethash "uid" (gethash "metadata"
                                            (gr8s::get-core-resource store "serviceaccounts"
                                                                      "default" "builder")))
                   (slot-value response 'gr8s.node.v1::service-account-uid)))
        (is (equal "acme" (gethash "tenant.example/id"
                                    (slot-value response 'gr8s.node.v1::service-account-annotations))))
        (is (equal "ca" (gethash "tenant.example/region"
                                  (slot-value response 'gr8s.node.v1::service-account-annotations))))
        (is (null (gr8s::verify-service-account-jwt store
                                                     (slot-value response 'gr8s.node.v1::token)
                                                     '("another-audience"))))
        (is (not (null (gr8s::verify-service-account-jwt
                        store (slot-value response 'gr8s.node.v1::token) '("private.example")))))
        (setf (slot-value request 'gr8s.node.v1::pod-uid) "another-pod")
        (signals error (gr8s::credential-token-response store "worker-a" request))))))

(defun send-stale-node-ack (port node-name revision)
  (let ((channel (ag-grpc:make-channel "127.0.0.1" port :timeout 3)))
    (unwind-protect
         (let* ((stub (gr8s.node.v1::make-node-service-stub channel))
                (stream (gr8s.node.v1::node-service-connect stub :timeout 3)))
           (ag-grpc:stream-send
            stream
            (gr8s:make-agent-envelope
             :hello
             (make-instance 'gr8s.node.v1::node-hello
                            :node-name node-name
                            :boot-id "stale-ack-test"
                            :agent-version "test"
                            :last-applied-revision revision)
             :sequence 1))
           (ag-grpc:stream-read-message stream)
           (ag-grpc:stream-read-message stream)
           (ag-grpc:stream-send
            stream
            (gr8s:make-agent-envelope
             :snapshot-ack
             (make-instance 'gr8s.node.v1::snapshot-ack
                            :revision (max 0 (1- revision))
                            :applied t)
             :sequence 2))
           (ag-grpc:stream-close-send stream)
           (loop while (ag-grpc:stream-read-message stream)))
      (ignore-errors (ag-grpc:channel-close channel)))))

(defun malformed-session-is-rejected (port)
  (let ((channel (ag-grpc:make-channel "127.0.0.1" port :timeout 3)))
    (unwind-protect
         (let* ((stub (gr8s.node.v1::make-node-service-stub channel))
                (stream (gr8s.node.v1::node-service-connect stub :timeout 3)))
           (ag-grpc:stream-send
            stream
            (gr8s:make-agent-envelope
             :heartbeat (make-instance 'gr8s.node.v1::heartbeat) :sequence 1))
           (ag-grpc:stream-close-send stream)
           (let ((response (ag-grpc:stream-read-message stream)))
             (and response
                  (eq :protocol-error
                      (slot-value response 'gr8s.node.v1::payload-case)))))
      (ignore-errors (ag-grpc:channel-close channel)))))

(test revisioned-node-session-reconnects-acknowledges-and-expires-heartbeats
  (with-temporary-store (store path)
    (gr8s:register-node
     store (gr8s:make-node-record :id "node-1" :name "worker-a"
                                  :pod-cidr "10.88.0.0/20"))
    (let* ((identity-path (merge-pathnames "agent/identity.json" path))
           (server (gr8s:start-node-grpc-server
                    store :host "127.0.0.1" :port 0
                    :heartbeat-timeout-seconds 1))
           (applied nil))
      (unwind-protect
           (progn
             (is (= 1 (gr8s:publish-node-desired-state
                       server "worker-a" (empty-desired-snapshot))))
             (gr8s:run-node-session
              "127.0.0.1" (gr8s:node-grpc-server-port server)
              "worker-a" identity-path
              (lambda (snapshot)
                (push (slot-value snapshot 'gr8s.node.v1::revision) applied))
              :max-sessions 1 :reconnect-delay 0.01)
             (is (equal '(1) applied))
             (is (= 1 (gr8s:node-session-acknowledged-revision
                       server "worker-a")))
             (is (probe-file identity-path))
             (is (string= "10.88.0.0/20"
                          (gethash "assignedPodCIDR" (com.inuoe.jzon:parse identity-path))))
             (is (gr8s:node-record-ready-p (gr8s:get-node store "worker-a")))

             (send-stale-node-ack
              (gr8s:node-grpc-server-port server) "worker-a" 1)
             (is (= 1 (gr8s:node-session-acknowledged-revision
                       server "worker-a")))

             (is (= 2 (gr8s:publish-node-desired-state
                       server "worker-a" (empty-desired-snapshot))))
             (gr8s:run-node-session
              "127.0.0.1" (gr8s:node-grpc-server-port server)
              "worker-a" identity-path
              (lambda (snapshot)
                (push (slot-value snapshot 'gr8s.node.v1::revision) applied))
              :max-sessions 1 :reconnect-delay 0.01)
             (is (equal '(2 1) applied))
             (is (= 2 (gr8s:node-session-acknowledged-revision
                       server "worker-a")))

             (is-true (malformed-session-is-rejected
                       (gr8s:node-grpc-server-port server)))
             ;; A bad stream must not poison the listener or a later session.
             (gr8s:run-node-session
              "127.0.0.1" (gr8s:node-grpc-server-port server)
              "worker-a" identity-path (lambda (snapshot) (declare (ignore snapshot)))
              :max-sessions 1 :reconnect-delay 0.01)

             (is-true
              (wait-until
               (lambda ()
                 (not (gr8s:node-record-ready-p
                       (gr8s:get-node store "worker-a"))))
               :timeout 3)))
        (gr8s:stop-node-grpc-server server)))))

(test persistent-node-session-renews-its-heartbeat-lease
  (with-temporary-store (store path)
    (gr8s:register-node
     store (gr8s:make-node-record :id "node-heartbeat" :name "worker-heartbeat"
                                  :pod-cidr "10.88.2.0/24"))
    (let* ((server (gr8s:start-node-grpc-server
                    store :host "127.0.0.1" :port 0
                    :heartbeat-timeout-seconds 2))
           (identity-path (merge-pathnames "agent/identity.json" path))
           (control (gr8s::make-node-session-control))
           (agent-thread nil))
      (unwind-protect
           (progn
             (setf agent-thread
                   (bt:make-thread
                    (lambda ()
                      (gr8s:run-node-session
                       "127.0.0.1" (gr8s:node-grpc-server-port server)
                       "worker-heartbeat" identity-path
                       (lambda (snapshot) (declare (ignore snapshot)))
                       :reconnect-delay 0.01
                       :control control))
                    :name "gr8s persistent heartbeat test agent"))
             (is-true
              (wait-until
               (lambda ()
                 (gr8s:node-record-ready-p
                  (gr8s:get-node store "worker-heartbeat")))
               :timeout 3))
             (sleep 3)
             (is-true
              (gr8s:node-record-ready-p
               (gr8s:get-node store "worker-heartbeat"))))
        (gr8s::cancel-node-session control)
        (when agent-thread
          (ignore-errors (bt:join-thread agent-thread)))
        (gr8s:stop-node-grpc-server server)))))

;; Runs a persistent agent against a real server, and tears both down.
(defun call-with-persistent-node-session (node-name function &key status-provider)
  (with-temporary-store (store path)
    (gr8s:register-node
     store (gr8s:make-node-record :id node-name :name node-name :pod-cidr "10.88.3.0/24"))
    (let* ((server (gr8s:start-node-grpc-server
                    store :host "127.0.0.1" :port 0 :heartbeat-timeout-seconds 2))
           (control (gr8s::make-node-session-control))
           (agent-thread
             (bt:make-thread
              (lambda ()
                (gr8s:run-node-session
                 "127.0.0.1" (gr8s:node-grpc-server-port server)
                 node-name (merge-pathnames "agent/identity.json" path)
                 (lambda (snapshot) (declare (ignore snapshot)))
                 :reconnect-delay 0.01 :control control
                 :status-provider status-provider))
              :name "gr8s watchdog test agent")))
      (unwind-protect
           (flet ((ready-p ()
                    (gr8s:node-record-ready-p (gr8s:get-node store node-name)))
                  (session ()
                    (bt:with-lock-held ((gr8s::node-grpc-server-lock server))
                      (gethash node-name (gr8s::node-grpc-server-sessions server)))))
             (is-true (wait-until #'ready-p :timeout 5))
             (funcall function #'ready-p #'session server))
        (gr8s::cancel-node-session control)
        (ignore-errors (bt:join-thread agent-thread))
        (gr8s:stop-node-grpc-server server)))))

(test blocked-status-provider-does-not-stop-node-heartbeats
  (let ((release (bt:make-semaphore)))
    (call-with-persistent-node-session
     "worker-blocked-status"
     (lambda (ready-p session server)
       (declare (ignore session server))
       (sleep 4)
       (is-true (funcall ready-p))
       (bt:signal-semaphore release :count 100))
     :status-provider (lambda () (bt:wait-on-semaphore release) nil))))

(test blocked-heartbeat-send-reconnects-the-session
  (let ((saved gr8s::*node-session-stall-seconds*)
        (block-next nil))
    (let ((*error-output* (make-broadcast-stream)))
      ;; Other threads see only the global value, so this cannot be a LET.
      (setf gr8s::*node-session-stall-seconds* 1)
      (sb-int:encapsulate
       'gr8s::send-agent-session-envelope 'block-heartbeat
       (lambda (function session variant payload)
         (when (and block-next (eq variant :heartbeat))
           (setf block-next nil)
           (sleep 3600))
         (funcall function session variant payload)))
      (unwind-protect
           (call-with-persistent-node-session
            "worker-blocked-heartbeat"
            (lambda (ready-p session server)
              (declare (ignore server))
              (let ((first (funcall session)))
                (setf block-next t)
                (is-true (wait-until (lambda () (not (eq first (funcall session)))) :timeout 10))
                (is-true (wait-until ready-p :timeout 5)))))
        (sb-int:unencapsulate 'gr8s::send-agent-session-envelope 'block-heartbeat)
        (setf gr8s::*node-session-stall-seconds* saved)))))

;; podster-uqb.121: closing the channel did not reliably wake the thread reading it, and a
;; quiet server had nothing else to wake it with. No Pod started until something did, which
;; took 5 minutes once. Over TLS, as every real agent's session is, and repeatedly, since
;; the first failure can get away with it.
(test failed-snapshots-reconnect-without-waiting-for-the-server-to-speak
  (with-temporary-store (store path)
    (let* ((pki (gr8s:ensure-cluster-pki (merge-pathnames "pki/" path)))
           (token (gr8s:create-join-token pki "worker-failed"))
           (server (gr8s:start-node-grpc-server
                    store :host "127.0.0.1" :port 0 :pki pki
                    :cluster-pod-cidr "10.96.0.0/12" :node-prefix 20))
           (agent-directory (merge-pathnames "worker-failed/" path))
           (private-key (merge-pathnames "node.key" agent-directory))
           (certificate (merge-pathnames "node.crt" agent-directory))
           (ca-certificate (merge-pathnames "ca.crt" agent-directory))
           (control (gr8s::make-node-session-control))
           (lock (bt:make-lock))
           (fail-next nil) (failed nil) (recovered 0) (revision 0)
           (*error-output* (make-broadcast-stream))
           (agent nil))
      (unwind-protect
           (progn
             (gr8s:enroll-node-over-grpc
              "127.0.0.1" (gr8s:node-grpc-server-port server)
              "worker-failed" token (gr8s:cluster-pki-ca-fingerprint pki)
              private-key certificate ca-certificate)
             (setf agent
                   (bt:make-thread
                    (lambda ()
                      (gr8s:run-node-session
                       "127.0.0.1" (gr8s:node-grpc-server-port server)
                       "worker-failed" (merge-pathnames "identity.json" agent-directory)
                       (lambda (snapshot)
                         (declare (ignore snapshot))
                         (bt:with-lock-held (lock)
                           (when failed (setf failed nil) (incf recovered))
                           (when fail-next
                             (setf fail-next nil failed t)
                             (error "Injected snapshot failure")))
                         nil)
                       :ca-certificate-path ca-certificate
                       :certificate-path certificate :private-key-path private-key
                       :status-provider (lambda () (make-instance 'gr8s.node.v1::node-status))
                       :control control :reconnect-delay 0.01))
                    :name "gr8s failed snapshot test agent"))
             (is-true (wait-until (lambda () (gr8s:node-record-ready-p (gr8s:get-node store "worker-failed")))
                                  :timeout 10))
             ;; Once the snapshot fails, the server stays quiet until the agent is back.
             (loop for attempt from 1 to 8
                   do (bt:with-lock-held (lock) (setf fail-next t))
                      (gr8s:publish-node-desired-state
                       server "worker-failed"
                       (make-instance 'gr8s.node.v1::desired-state-snapshot :revision (incf revision)))
                      (is-true (wait-until (lambda () (>= recovered attempt)) :timeout 10)
                               "the agent did not come back after failure ~D" attempt)
                      (unless (>= recovered attempt) (return))))
        (gr8s::cancel-node-session control)
        (when agent (ignore-errors (bt:join-thread agent)))
        (gr8s:stop-node-grpc-server server)))))

;; podster-uqb.104: the reading thread can reach its next read before it is interrupted.
(test closing-a-session-leaves-the-reading-thread-a-closed-connection-to-find
  (with-temporary-store (store path)
    (values path)
    (gr8s:register-node
     store (gr8s:make-node-record :id "worker-closed" :name "worker-closed" :pod-cidr "10.88.3.0/24"))
    (let* ((server (gr8s:start-node-grpc-server store :host "127.0.0.1" :port 0))
           (channel (ag-grpc:make-channel "127.0.0.1" (gr8s:node-grpc-server-port server) :timeout 3)))
      (unwind-protect
           (let* ((stub (gr8s.node.v1::make-node-service-stub channel))
                  (stream (gr8s.node.v1::node-service-connect stub :timeout 3)))
             (gr8s::close-agent-session-connection channel)
             (is-true (ag-grpc:channel-connection channel))
             (is (eq :closed (ag-http2:connection-state (ag-grpc:channel-connection channel))))
             (handler-case (ag-grpc:stream-read-message stream)
               (error (condition)
                 (is-false (search "no applicable method" (string-downcase (princ-to-string condition)))
                           "~A" condition))))
        (ignore-errors (ag-grpc:channel-close channel))
        (gr8s:stop-node-grpc-server server)))))

;; podster-uqb.109: the interrupt found the session thread in %SIGNAL for a stream
;; error. A handler function runs with the clusters rebound to those outside it, as
;; a handler test does, and with none outside an ERROR killed the thread.
(test node-session-interrupt-during-signal-still-unwinds
  (let* ((tag (list :test))
         (signalling (bt:make-semaphore))
         (cleaned-up nil)
         (thread (bt:make-thread
                  (lambda ()
                    (gr8s::with-node-session-interruption (tag)
                      (unwind-protect
                           (handler-bind
                               ((error (lambda (condition)
                                         (declare (ignore condition))
                                         (bt:signal-semaphore signalling)
                                         (sleep 3600))))
                             (error "read failed"))
                        (setf cleaned-up t))))
                  :name "gr8s interrupted session test")))
    (bt:wait-on-semaphore signalling)
    (gr8s::interrupt-node-session-thread thread tag)
    (is (eq :interrupted (bt:join-thread thread)))
    (is-true cleaned-up)))

(test node-session-interrupt-passes-handlers-that-recover-from-errors
  (let* ((tag (list :test))
         (blocked (bt:make-semaphore))
         (swallowed nil)
         (thread (bt:make-thread
                  (lambda ()
                    (gr8s::with-node-session-interruption (tag)
                      (handler-case (progn (bt:signal-semaphore blocked) (sleep 3600))
                        (serious-condition () (setf swallowed t))))))))
    (bt:wait-on-semaphore blocked)
    (gr8s::interrupt-node-session-thread thread tag)
    (is (eq :interrupted (bt:join-thread thread)))
    (is-false swallowed)))

(test node-session-interrupt-outside-its-scope-is-ignored
  (let* ((tag (list :old-session))
         (left (bt:make-semaphore))
         (received (bt:make-semaphore))
         (thread (bt:make-thread
                  (lambda ()
                    (gr8s::with-node-session-interruption (tag) nil)
                    (bt:signal-semaphore left)
                    ;; Cleanup after the scope, then a newer session on the same
                    ;; thread: neither may be unwound by the old session's interrupt.
                    (bt:wait-on-semaphore received)
                    (gr8s::with-node-session-interruption ((list :new-session))
                      (bt:signal-semaphore left)
                      (bt:wait-on-semaphore received)
                      :finished)))))
    (bt:wait-on-semaphore left)
    (gr8s::interrupt-node-session-thread thread tag)
    (bt:signal-semaphore received)
    (bt:wait-on-semaphore left)
    (gr8s::interrupt-node-session-thread thread tag)
    (bt:signal-semaphore received)
    (is (eq :finished (bt:join-thread thread)))))

(test stopping-a-snapshot-worker-passes-handlers-that-recover-from-errors
  (let* ((blocked (bt:make-semaphore))
         (swallowed nil)
         (worker (gr8s::start-agent-snapshot-worker
                  (lambda (snapshot replay)
                    (declare (ignore snapshot replay))
                    (handler-case (progn (bt:signal-semaphore blocked) (sleep 3600))
                      (serious-condition () (setf swallowed t))))
                  (lambda ()))))
    (gr8s::queue-agent-snapshot-work
     worker (make-instance 'gr8s.node.v1::desired-state-snapshot :revision 1))
    (bt:wait-on-semaphore blocked)
    (gr8s::stop-agent-snapshot-worker worker)
    (is-false swallowed)
    (is-false (bt:thread-alive-p (gr8s::agent-snapshot-worker-thread worker)))))

(test silent-node-session-is-evicted-so-the-agent-reconnects
  (let ((*error-output* (make-broadcast-stream)))
    (call-with-persistent-node-session
     "worker-silent"
     (lambda (ready-p session server)
       (let ((first (funcall session)))
         ;; Pass a later clock instead of aging the session: its next heartbeat
         ;; can overwrite any timestamp written here.
         (gr8s::evict-silent-node-sessions server (+ (get-universal-time) 3600))
         (is-true (wait-until (lambda () (not (eq first (funcall session)))) :timeout 10))
         (is-true (wait-until ready-p :timeout 5)))))))

(test cancelling-persistent-node-session-wakes-blocked-read
  (with-temporary-store (store path)
    (gr8s:register-node
     store (gr8s:make-node-record :id "node-cancel" :name "worker-cancel"
                                  :pod-cidr "10.88.3.0/24"))
    (let* ((server (gr8s:start-node-grpc-server
                    store :host "127.0.0.1" :port 0))
           (identity-path (merge-pathnames "agent/identity.json" path))
           (control (gr8s::make-node-session-control))
           (agent-thread nil))
      (unwind-protect
           (progn
             (setf agent-thread
                   (bt:make-thread
                    (lambda ()
                      (gr8s:run-node-session
                       "127.0.0.1" (gr8s:node-grpc-server-port server)
                       "worker-cancel" identity-path
                       (lambda (snapshot) (declare (ignore snapshot)))
                       :control control :reconnect-delay 0.01))
                    :name "gr8s cancellable persistent session test agent"))
             (is-true
              (wait-until
               (lambda ()
                 (gr8s:node-record-ready-p
                  (gr8s:get-node store "worker-cancel")))
               :timeout 3))
             (gr8s::cancel-node-session control)
             (is-true
              (wait-until (lambda () (not (bt:thread-alive-p agent-thread)))
                          :timeout 2)))
        (when (and agent-thread (bt:thread-alive-p agent-thread))
          (ignore-errors (bt:destroy-thread agent-thread)))
        (when agent-thread
          (ignore-errors (bt:join-thread agent-thread)))
        (gr8s:stop-node-grpc-server server)))))

(test standalone-agent-enrolls-registers-and-connects-over-grpc
  (with-temporary-store (store path)
    (let* ((pki (gr8s:ensure-cluster-pki (merge-pathnames "pki/" path)))
           (token (gr8s:create-join-token pki "worker-b"))
           (server (gr8s:start-node-grpc-server
                    store :host "127.0.0.1" :port 0 :pki pki
                    :cluster-pod-cidr "10.96.0.0/12" :node-prefix 20
                    :overlay-backend "wireguard" :wireguard-listen-port 51820))
           (agent-directory (merge-pathnames "worker-b/" path))
           (private-key (merge-pathnames "node.key" agent-directory))
           (certificate (merge-pathnames "node.crt" agent-directory))
           (ca-certificate (merge-pathnames "ca.crt" agent-directory))
           (identity (merge-pathnames "identity.json" agent-directory)))
      (unwind-protect
           (multiple-value-bind (wireguard-private-key wireguard-public-key)
               (gr8s.security::ensure-wireguard-key-pair agent-directory)
             (declare (ignore wireguard-private-key))
             (let ((node-id
                   (gr8s:enroll-node-over-grpc
                    "127.0.0.1" (gr8s:node-grpc-server-port server)
                    "worker-b" token (gr8s:cluster-pki-ca-fingerprint pki)
                    private-key certificate ca-certificate)))
             (is (string= node-id (gr8s:node-record-id
                                   (gr8s:get-node store "worker-b"))))
             (is (string= "10.96.0.0/20"
                          (gr8s:node-record-pod-cidr
                           (gr8s:get-node store "worker-b"))))
             (is (probe-file private-key))
             (is (probe-file certificate))
             (is (probe-file ca-certificate))
             (gr8s:publish-node-desired-state
              server "worker-b" (empty-desired-snapshot))
             (gr8s:run-node-session
              "127.0.0.1" (gr8s:node-grpc-server-port server)
              "worker-b" identity (lambda (snapshot) (declare (ignore snapshot)))
              :ca-certificate-path ca-certificate
              :certificate-path certificate :private-key-path private-key
              :wireguard-public-key wireguard-public-key
              :max-sessions 1 :reconnect-delay 0.01)
             (is (gr8s:node-record-ready-p (gr8s:get-node store "worker-b")))
             (is (equalp wireguard-public-key
                         (gr8s::node-record-wireguard-public-key
                          (gr8s:get-node store "worker-b"))))))
        (gr8s:stop-node-grpc-server server)))))

(test repeated-node-enrollment-preserves-the-committed-identity
  (with-temporary-store (store path)
    (let* ((pki (gr8s:ensure-cluster-pki (merge-pathnames "pki/" path)))
           (server (gr8s:start-node-grpc-server store :host "127.0.0.1" :port 0 :pki pki))
           (directory (merge-pathnames "worker-retry/" path))
           (private-key (merge-pathnames "node.key" directory))
           (certificate (merge-pathnames "node.crt" directory))
           (ca-certificate (merge-pathnames "ca.crt" directory)))
      (unwind-protect
           (let* ((first-id
                    (gr8s:enroll-node-over-grpc
                     "127.0.0.1" (gr8s:node-grpc-server-port server)
                     "worker-retry" (gr8s:create-join-token pki "worker-retry")
                     (gr8s:cluster-pki-ca-fingerprint pki)
                     private-key certificate ca-certificate))
                  ;; A control-plane response can be lost after the replicated
                  ;; node record commits.  A fresh, name-bound token and the
                  ;; same persisted key must recover that committed identity.
                  (retry-id
                    (gr8s:enroll-node-over-grpc
                     "127.0.0.1" (gr8s:node-grpc-server-port server)
                     "worker-retry" (gr8s:create-join-token pki "worker-retry")
                     (gr8s:cluster-pki-ca-fingerprint pki)
                     private-key certificate ca-certificate)))
             (is (string= first-id retry-id))
             (is (string= retry-id
                          (gr8s:node-record-id (gr8s:get-node store "worker-retry")))))
        (gr8s:stop-node-grpc-server server)))))

(test image-tracker-rpc-binds-node-name-to-the-mtls-certificate
  (with-temporary-store (store path)
    (let* ((pki (gr8s:ensure-cluster-pki (merge-pathnames "pki/" path)))
           (server (gr8s:start-node-grpc-server
                    store :host "127.0.0.1" :port 0 :pki pki))
           (directory (merge-pathnames "tracker-node/" path))
           (private-key (merge-pathnames "node.key" directory))
           (certificate (merge-pathnames "node.crt" directory))
           (ca-certificate (merge-pathnames "ca.crt" directory))
           (channel nil))
      (unwind-protect
           (progn
             (gr8s:enroll-node-over-grpc
              "127.0.0.1" (gr8s:node-grpc-server-port server)
              "tracker-node" (gr8s:create-join-token pki "tracker-node")
              (gr8s:cluster-pki-ca-fingerprint pki)
              private-key certificate ca-certificate)
             (setf channel
                   (gr8s::make-node-tls-channel
                    "127.0.0.1" (gr8s:node-grpc-server-port server)
                    :timeout 5 :ca-certificate-path ca-certificate
                    :certificate-path certificate :private-key-path private-key))
             (let ((stub (gr8s.node.v1::make-node-service-stub channel)))
               (multiple-value-bind (response status)
                   (gr8s.node.v1::node-service-track-image
                    stub
                    (make-instance
                     'gr8s.node.v1::image-tracker-request
                     :node-name "tracker-node" :action "acquire"
                     :digest
                     "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                    :timeout 5)
                 (declare (ignore status))
                 (is (string= "granted"
                              (slot-value response 'gr8s.node.v1::status))))
               (signals ag-grpc:grpc-status-error
                   (gr8s.node.v1::node-service-track-image
                  stub
                  (make-instance
                   'gr8s.node.v1::image-tracker-request
                   :node-name "different-node" :action "lookup"
                   :digest
                   "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                  :timeout 5))))
        (when channel (ignore-errors (ag-grpc:channel-close channel)))
        (gr8s:stop-node-grpc-server server)))))

(test ha-enrollment-replicates-an-ordered-node-operation
  (with-temporary-store (store path)
    (gr8s:register-node
     store (gr8s:make-node-record :id "existing-id" :name "existing"
                                  :pod-cidr "10.80.0.0/20"))
    (let* ((pki (gr8s:ensure-cluster-pki (merge-pathnames "pki/" path)))
           (commits nil)
           (server nil)
           (directory (merge-pathnames "worker-ordered/" path)))
      (setf (gr8s::pod-store-consensus-commit-fn store)
            (lambda (tag payload)
              (push tag commits)
              (ecase tag
                (:node-state (gr8s::install-node-state-blob store payload))
                (:node-delta (gr8s::install-node-state-delta store payload))
                (:node-enrollment
                 (apply #'gr8s::install-node-enrollment-command store payload)))))
      (setf server (gr8s:start-node-grpc-server
                    store :host "127.0.0.1" :port 0 :pki pki
                    :cluster-pod-cidr "10.80.0.0/12" :node-prefix 20))
      (unwind-protect
           (progn
             (gr8s:enroll-node-over-grpc
              "127.0.0.1" (gr8s:node-grpc-server-port server)
              "worker-ordered" (gr8s:create-join-token pki "worker-ordered")
              (gr8s:cluster-pki-ca-fingerprint pki)
              (merge-pathnames "node.key" directory)
              (merge-pathnames "node.crt" directory)
              (merge-pathnames "ca.crt" directory))
             (is (equal '(:node-enrollment) commits))
             (is (string= "10.80.16.0/20"
                          (gr8s:node-record-pod-cidr
                           (gr8s:get-node store "worker-ordered"))))
             (is (gr8s:get-node store "existing")))
        (when server (gr8s:stop-node-grpc-server server))))))

(test agent-enrollment-falls-through-to-a-live-control-plane-endpoint
  (with-temporary-store (store path)
    (let* ((pki (gr8s:ensure-cluster-pki (merge-pathnames "pki/" path)))
           (token (gr8s:create-join-token pki "worker-failover"))
           (server (gr8s:start-node-grpc-server store :host "127.0.0.1" :port 0 :pki pki))
           (dead-listener (make-instance 'hunchentoot:easy-acceptor :address "127.0.0.1" :port 0))
           (dead-port (progn (hunchentoot:start dead-listener)
                             (prog1 (hunchentoot:acceptor-port dead-listener)
                               (hunchentoot:stop dead-listener))))
           (directory (merge-pathnames "worker-failover/" path)))
      (unwind-protect
           (let ((node-id
                   (gr8s::enroll-node-over-endpoints
                    (list (list "127.0.0.1" dead-port)
                          (list "127.0.0.1" (gr8s:node-grpc-server-port server)))
                    "worker-failover" token (gr8s:cluster-pki-ca-fingerprint pki)
                    (merge-pathnames "node.key" directory)
                    (merge-pathnames "node.crt" directory)
                    (merge-pathnames "ca.crt" directory))))
             (is (string= node-id
                          (gr8s:node-record-id (gr8s:get-node store "worker-failover")))))
        (gr8s:stop-node-grpc-server server)))))

(test local-agent-starts-through-grpc-and-stops-cleanly
  (with-temporary-store (store path)
    (let* ((pki (gr8s:ensure-cluster-pki (merge-pathnames "pki/" path)))
           (server (gr8s:start-node-grpc-server
                    store :host "127.0.0.1" :port 0 :pki pki))
           (worker nil))
      (unwind-protect
           (progn
             ;; Real RSA key generation can exceed the handshake's five-second
             ;; assertion window. Prepare it before starting that timed work;
             ;; enrollment still builds/verifies the CSR and negotiates mTLS.
             (gr8s:generate-node-key-and-csr "gr8s-local" (merge-pathnames "agent/node.key" path))
             (setf worker
                   (gr8s::start-local-node-agent
                    server pki "gr8s-local" (merge-pathnames "agent/" path)))
             (is-true
              (wait-until
               (lambda ()
                 (handler-case
                     (gr8s:node-record-ready-p
                      (gr8s:get-node store "gr8s-local"))
                   (gr8s:kubernetes-error () nil)))
               :timeout 5))
             (gr8s::stop-local-node-agent worker)
             (is-false
              (bt:thread-alive-p (gr8s::local-node-agent-thread worker))))
        (when (and worker
                   (bt:thread-alive-p (gr8s::local-node-agent-thread worker)))
          (gr8s::stop-local-node-agent worker))
        (gr8s:stop-node-grpc-server server)))))

(test local-agent-executes-control-plane-snapshots-and-reports-status
  (with-temporary-store (store path)
    (let* ((pki (gr8s:ensure-cluster-pki (merge-pathnames "pki/" path)))
           (server (gr8s:start-node-grpc-server
                    store :host "127.0.0.1" :port 0 :pki pki))
           (agent-directory (merge-pathnames "agent/" path))
           (worker nil)
           (runtime (gr8s::make-control-plane-runtime store server))
           (reconciler (make-reconciler store runtime))
           (pod (create-pod store (parse-pod *valid-pod-json*))))
      (unwind-protect
           (progn
             ;; Real RSA key generation can exceed the handshake's five-second
             ;; assertion window. Prepare it before starting that timed work;
             ;; enrollment still builds/verifies the CSR and negotiates mTLS.
             (gr8s:generate-node-key-and-csr "gr8s-local" (merge-pathnames "agent/node.key" path))
             (setf worker
                   (gr8s::start-local-node-agent
                    server pki "gr8s-local" agent-directory
                    (list :runtime "fake")))
             (is-true
              (wait-until
               (lambda ()
                 (handler-case
                     (gr8s:node-record-ready-p
                      (gr8s:get-node store "gr8s-local"))
                   (gr8s:kubernetes-error () nil)))
               :timeout 5))

             (reconcile-pod reconciler "default" "hello")
             (is-true
              (wait-until
               (lambda ()
                 (string= "Running" (gr8s:pod-scheduling-phase store pod)))
               :timeout 5))

             (gr8s::delete-reconciled-pod reconciler "default" "hello")
             (let ((deletion-revision
                     (slot-value (gr8s::current-node-snapshot server "gr8s-local")
                                 'gr8s.node.v1::revision)))
               (is-true
                (wait-until
                 (lambda ()
                   (>= (gr8s:node-session-acknowledged-revision
                        server "gr8s-local")
                       deletion-revision))
                 :timeout 5)))
             (is (null
                  (list-pods
                   (gr8s:open-store
                    (merge-pathnames "runtime/desired/" agent-directory))
                   "default"))))
        (when worker (gr8s::stop-local-node-agent worker))
        (gr8s:stop-node-grpc-server server)))))

(test control-plane-logs-come-from-the-assigned-remote-agent
  (with-temporary-store (store path)
    (gr8s:register-node
     store (gr8s:make-node-record :id "node-remote" :name "worker-a"
                                  :pod-cidr "10.88.1.0/24"))
    (let* ((server (gr8s:start-node-grpc-server
                    store :host "127.0.0.1" :port 0))
           (fake-runtime (make-fake-runtime))
           (node-runtime
             (gr8s::make-node-runtime
              (merge-pathnames "worker-a/runtime/" path) fake-runtime nil))
           (identity-path
             (merge-pathnames "worker-a/identity.json" path))
           (control (gr8s::make-node-session-control))
           (agent-thread nil)
           (control-runtime
             (gr8s::make-control-plane-runtime store server))
           (reconciler (make-reconciler store control-runtime))
           (pod (create-pod store (parse-pod *valid-pod-json*))))
      (unwind-protect
           (progn
             (gr8s::start-node-runtime node-runtime)
             (setf agent-thread
                   (bt:make-thread
                    (lambda ()
                      (gr8s:run-node-session
                       "127.0.0.1" (gr8s:node-grpc-server-port server)
                       "worker-a" identity-path
                       (lambda (snapshot)
                         (gr8s::reconcile-node-snapshot
                          node-runtime snapshot))
                       :operation-handler
                       (lambda (variant payload emit)
                         (unless (eq variant :operation-request)
                           (error "Unexpected operation payload ~S" variant))
                         (dolist (reply
                                  (gr8s::handle-node-operation
                                   node-runtime payload))
                           (funcall emit (car reply) (cdr reply))))
                       :reconnect-delay 0.01
                       :control control))
                    :name "gr8s remote log test agent"))
             (is-true
              (wait-until
               (lambda ()
                 (gr8s:node-record-ready-p
                  (gr8s:get-node store "worker-a")))
               :timeout 5))
             (reconcile-pod reconciler "default" "hello")
             (is-true
              (wait-until
               (lambda ()
                 (runtime-observe fake-runtime (pod-uid pod)))
               :timeout 5))
             (setf (gethash "web"
                            (gr8s::runtime-pod-logs
                             (runtime-observe fake-runtime (pod-uid pod))))
                   "hello from worker-a\n")
             (is (string= "hello from worker-a\n"
                          (runtime-logs control-runtime (pod-uid pod) "web")))
             (gr8s::set-fake-runtime-exec-result
              fake-runtime
              (gr8s::make-runtime-exec-result
               :stdout (trivial-utf-8:string-to-utf-8-bytes "remote stdout\n")
               :stderr (trivial-utf-8:string-to-utf-8-bytes "remote stderr\n")
               :exit-code 7))
             (let ((result
                     (gr8s::runtime-exec-sync
                      control-runtime (pod-uid pod) "web"
                      '("sh" "-c" "printf remote") :timeout 4)))
               (is (equalp
                    (trivial-utf-8:string-to-utf-8-bytes "remote stdout\n")
                    (gr8s::runtime-exec-result-stdout result)))
               (is (equalp
                    (trivial-utf-8:string-to-utf-8-bytes "remote stderr\n")
                    (gr8s::runtime-exec-result-stderr result)))
               (is (= 7 (gr8s::runtime-exec-result-exit-code result)))))
        (gr8s::cancel-node-session control)
        (when agent-thread
          (ignore-errors (bt:join-thread agent-thread)))
        (gr8s::stop-node-runtime node-runtime)
        (gr8s:stop-node-grpc-server server)))))

(test node-operation-crosses-the-control-plane-member-owning-the-agent-session
  (with-temporary-store (origin-store origin-path)
    (with-temporary-store (owner-store owner-path)
      (declare (ignore origin-path))
      (dolist (store (list origin-store owner-store))
        (gr8s:register-node
         store (gr8s:make-node-record :id "node-relayed" :name "worker-relayed"
                                      :pod-cidr "10.88.9.0/24")))
      (let* ((origin (gr8s:start-node-grpc-server origin-store :host "127.0.0.1" :port 0))
             (owner (gr8s:start-node-grpc-server owner-store :host "127.0.0.1" :port 0))
             (origin-member (gr8s::start-raft-member "origin" :port 0))
             (owner-member (gr8s::start-raft-member "owner" :port 0))
             (control (gr8s::make-node-session-control))
             (agent nil))
        (unwind-protect
             (progn
               (gr8s::raft-member-set-peers
                origin-member
                (list (list "owner" "127.0.0.1"
                            (gr8s::raft-member-port owner-member))))
               (gr8s::raft-member-set-peers
                owner-member
                (list (list "origin" "127.0.0.1"
                            (gr8s::raft-member-port origin-member))))
               (gr8s::configure-raft-node-operation-routing origin-member origin)
               (gr8s::configure-raft-node-operation-routing owner-member owner)
               (setf agent
                     (bt:make-thread
                      (lambda ()
                        (gr8s:run-node-session
                         "127.0.0.1" (gr8s:node-grpc-server-port owner)
                         "worker-relayed"
                         (merge-pathnames "worker-relayed/identity.json" owner-path)
                         (lambda (snapshot) (declare (ignore snapshot)))
                         :operation-handler
                         (lambda (variant payload emit)
                           (when (eq variant :operation-request)
                             (let ((id (slot-value payload 'gr8s.node.v1::operation-id)))
                               (funcall emit :operation-stream
                                        (make-instance 'gr8s.node.v1::operation-stream
                                                       :operation-id id :sequence 1
                                                       :channel gr8s.node.v1::+streamchannel-stream_channel_stdout+
                                                       :data (gr8s::ascii-octets "relayed")))
                               (funcall emit :operation-response
                                        (make-instance 'gr8s.node.v1::operation-response
                                                       :operation-id id
                                                       :status gr8s.node.v1::+operationstatus-operation_status_complete+
                                                       :exit-code 0)))))
                         :control control :reconnect-delay 0.01))
                      :name "gr8s relayed operation agent"))
               (is-true
                (wait-until
                 (lambda ()
                   (bt:with-lock-held ((gr8s::node-grpc-server-lock owner))
                     (gethash "worker-relayed"
                              (gr8s::node-grpc-server-sessions owner))))
                 :timeout 5))
               (let* ((request
                        (make-instance 'gr8s.node.v1::operation-request
                                       :operation-id "relayed-operation"
                                       :kind gr8s.node.v1::+operationkind-operation_kind_exec+))
                      (operation
                        (gr8s::request-node-operation
                         origin "worker-relayed" request :timeout 3)))
                 (is (string= "owner"
                              (gr8s::pending-node-operation-remote-member operation)))
                 (is (equalp (gr8s::ascii-octets "relayed")
                             (gr8s::node-operation-channel-data
                              operation gr8s.node.v1::+streamchannel-stream_channel_stdout+)))
                 (is (= 0 (slot-value (gr8s::pending-node-operation-response operation)
                                      'gr8s.node.v1::exit-code)))))
          (gr8s::cancel-node-session control)
          (when agent (ignore-errors (bt:join-thread agent)))
          (gr8s::stop-raft-member owner-member)
          (gr8s::stop-raft-member origin-member)
          (gr8s:stop-node-grpc-server owner)
          (gr8s:stop-node-grpc-server origin))))))

(test a-transient-peer-routing-miss-does-not-strand-a-node-operation-locally
  (with-temporary-store (store path)
    (declare (ignore path))
    (gr8s:register-node
     store (gr8s:make-node-record :id "node-rerouted" :name "worker-rerouted"
                                  :pod-cidr "10.88.10.0/24"))
    (let* ((server (gr8s::%make-node-grpc-server :store store))
           (attempts 0)
           (seen-variants nil)
           (seen-node-names nil)
           (request
             (make-instance 'gr8s.node.v1::operation-request
                            :operation-id "reroute-after-miss"
                            :kind gr8s.node.v1::+operationkind-operation_kind_exec+))
           (operation nil))
      (setf (gr8s::node-grpc-server-operation-router server)
            (lambda (variant target-member node-name payload)
              (declare (ignore target-member payload))
              (push variant seen-variants)
              (push node-name seen-node-names)
              (when (> (incf attempts) 1) "owner")))
      (unwind-protect
           (progn
             (setf operation
                   (gr8s::queue-node-operation server "worker-rerouted" request))
             (is-true
              (wait-until
               (lambda ()
                 (equal "owner"
                        (gr8s::pending-node-operation-remote-member operation)))
               :timeout 1))
             (is (>= attempts 2))
             (is (every (lambda (variant) (eq :operation-request variant))
                        seen-variants))
             (is (every (lambda (node-name)
                          (string= "worker-rerouted" node-name))
                        seen-node-names))
             (bt:with-lock-held ((gr8s::node-grpc-server-lock server))
               (is (null (gethash "worker-rerouted"
                                  (gr8s::node-grpc-server-operation-queues server))))))
        (setf (gr8s::node-grpc-server-stopping-p server) t)
        (when operation
          (gr8s::finish-node-operation operation :error "test cleanup")
          (gr8s::release-node-operation server operation))))))

(test a-transient-directed-peer-miss-does-not-fail-an-active-node-operation
  (with-temporary-store (store path)
    (declare (ignore path))
    (let* ((server (gr8s::%make-node-grpc-server :store store))
           (request
             (make-instance 'gr8s.node.v1::operation-request
                            :operation-id "directed-retry"
                            :kind gr8s.node.v1::+operationkind-operation_kind_exec+))
           (operation (gr8s::make-pending-node-operation "worker" request))
           (attempts 0))
      (setf (gr8s::pending-node-operation-remote-member operation) "owner"
            (gethash "directed-retry" (gr8s::node-grpc-server-operations server)) operation
            (gr8s::node-grpc-server-operation-router server)
            (lambda (variant target-member node-name payload)
              (declare (ignore payload))
              (is (eq :operation-input variant))
              (is (string= "owner" target-member))
              (is (string= "worker" node-name))
              (when (> (incf attempts) 1) "owner")))
      (unwind-protect
           (progn
             (gr8s::send-node-operation-input
              server operation
              (make-instance 'gr8s.node.v1::operation-input
                             :operation-id "directed-retry" :sequence 1
                             :channel gr8s.node.v1::+streamchannel-stream_channel_stdin+
                             :data (gr8s::ascii-octets "input")))
             (is (= 2 attempts))
             (is-false (gr8s::pending-node-operation-done-p operation)))
        (gr8s::release-node-operation server operation)))))

(test operation-input-and-cancel-follow-the-correlated-node-session
  (with-temporary-store (store path)
    (gr8s:register-node
     store (gr8s:make-node-record :id "node-interactive" :name "worker-interactive"
                                  :pod-cidr "10.88.4.0/24"))
    (let* ((server (gr8s:start-node-grpc-server
                    store :host "127.0.0.1" :port 0))
           (identity-path (merge-pathnames "interactive/identity.json" path))
           (control (gr8s::make-node-session-control))
           (agent-thread nil)
           (seen nil)
           (seen-lock (bt:make-lock "gr8s interactive operation test"))
           (request
             (make-instance
              'gr8s.node.v1::operation-request
              :operation-id "interactive-1"
              :kind gr8s.node.v1::+operationkind-operation_kind_exec+
              :namespace "default" :pod "shell" :pod-uid "pod-1"
              :container "main" :command '("sh")
              :stdin t :stdout t :stderr t :tty t))
           (operation nil))
      (labels ((remember (variant payload)
                 (bt:with-lock-held (seen-lock)
                   (setf seen (nconc seen (list (cons variant payload))))))
               (seen-variant-p (variant)
                 (bt:with-lock-held (seen-lock)
                   (find variant seen :key #'car))))
        (unwind-protect
             (progn
               (setf agent-thread
                     (bt:make-thread
                      (lambda ()
                        (gr8s:run-node-session
                         "127.0.0.1" (gr8s:node-grpc-server-port server)
                         "worker-interactive" identity-path
                         (lambda (snapshot) (declare (ignore snapshot)))
                         :operation-handler
                         (lambda (variant payload emit)
                           (remember variant payload)
                           (case variant
                             (:operation-request
                              (funcall
                               emit :operation-response
                               (make-instance
                                'gr8s.node.v1::operation-response
                                :operation-id "interactive-1"
                                :status
                                gr8s.node.v1::+operationstatus-operation_status_accepted+)))
                             (:operation-cancel
                              (funcall
                               emit :operation-response
                               (make-instance
                                'gr8s.node.v1::operation-response
                                :operation-id "interactive-1"
                                :status
                                gr8s.node.v1::+operationstatus-operation_status_complete+)))))
                         :reconnect-delay 0.01 :control control))
                      :name "gr8s interactive operation test agent"))
               (is-true
                (wait-until
                 (lambda ()
                   (gr8s:node-record-ready-p
                    (gr8s:get-node store "worker-interactive")))
                 :timeout 5))
               (setf operation
                     (gr8s::queue-node-operation
                      server "worker-interactive" request))
               (is-true
                (wait-until (lambda () (seen-variant-p :operation-request))
                            :timeout 3))
               (gr8s::send-node-operation-input
                server operation
                (make-instance
                 'gr8s.node.v1::operation-input
                 :operation-id "interactive-1" :sequence 1
                 :channel gr8s.node.v1::+streamchannel-stream_channel_stdin+
                 :data (trivial-utf-8:string-to-utf-8-bytes "echo hi\n")))
               (gr8s::cancel-node-operation server operation "client closed")
               (gr8s::wait-for-node-operation server operation :timeout 3)
               (is-true (seen-variant-p :operation-input))
               (let ((cancel (cdr (seen-variant-p :operation-cancel))))
                 (is (string= "client closed"
                              (slot-value cancel 'gr8s.node.v1::reason)))))
          (gr8s::cancel-node-session control)
          (when agent-thread
            (ignore-errors (bt:join-thread agent-thread)))
          (gr8s:stop-node-grpc-server server))))))

(test ending-node-session-notifies-its-operation-handler
  (with-temporary-store (store path)
    (gr8s:register-node
     store (gr8s:make-node-record :id "node-session-close"
                                  :name "worker-session-close"
                                  :pod-cidr "10.88.6.0/24"))
    (let* ((server (gr8s:start-node-grpc-server
                    store :host "127.0.0.1" :port 0))
           (identity-path (merge-pathnames "session-close/identity.json" path))
           (control (gr8s::make-node-session-control))
           (events nil)
           (events-lock (bt:make-lock "gr8s session close events"))
           (agent-thread nil)
           (operation nil)
           (waiter nil)
           (waiter-error nil))
      (unwind-protect
           (progn
             (setf agent-thread
                   (bt:make-thread
                    (lambda ()
                      (gr8s:run-node-session
                       "127.0.0.1" (gr8s:node-grpc-server-port server)
                       "worker-session-close" identity-path
                       (lambda (snapshot) (declare (ignore snapshot)))
                       :operation-handler
                       (lambda (variant payload emit)
                         (bt:with-lock-held (events-lock)
                           (push variant events))
                         (when (eq variant :operation-request)
                           (funcall
                            emit :operation-response
                            (make-instance
                             'gr8s.node.v1::operation-response
                             :operation-id
                             (slot-value payload 'gr8s.node.v1::operation-id)
                             :status
                             gr8s.node.v1::+operationstatus-operation_status_accepted+))))
                       :reconnect-delay 0.01 :control control))
                    :name "gr8s session close notification test agent"))
             (is-true
              (wait-until
               (lambda ()
                 (gr8s:node-record-ready-p
                  (gr8s:get-node store "worker-session-close")))
               :timeout 5))
             (setf operation
                   (gr8s::queue-node-operation
                    server "worker-session-close"
                    (make-instance
                     'gr8s.node.v1::operation-request
                     :operation-id "disconnect-wakes-caller"
                     :kind gr8s.node.v1::+operationkind-operation_kind_exec+)))
             (is-true
              (wait-until
               (lambda ()
                 (bt:with-lock-held (events-lock)
                   (member :operation-request events)))
               :timeout 3))
             (setf waiter
                   (bt:make-thread
                    (lambda ()
                      (handler-case
                          (gr8s::wait-for-node-operation
                           server operation :timeout 5)
                        (runtime-error (condition)
                          (setf waiter-error
                                (runtime-error-message condition)))))
                    :name "gr8s disconnected operation waiter"))
             (gr8s::cancel-node-session control)
             (is-true
              (wait-until
               (lambda ()
                 (bt:with-lock-held (events-lock)
                   (member :session-closed events)))
               :timeout 3))
             (bt:join-thread waiter)
             (setf waiter nil)
             (is (string= "Node disconnected" waiter-error))
             (bt:join-thread agent-thread)
             (setf agent-thread nil)
             (bt:with-lock-held (events-lock)
               (is (= 1 (count :session-closed events)))))
        (gr8s::cancel-node-session control)
        (when waiter
          (ignore-errors (bt:join-thread waiter)))
        (when agent-thread
          (ignore-errors (bt:join-thread agent-thread)))
        (gr8s:stop-node-grpc-server server)))))

(test pending-node-operation-wakes-for-stream-data-before-completion
  (with-temporary-store (store path)
    (values path)
    (gr8s:register-node
     store (gr8s:make-node-record :id "node-stream" :name "worker-stream"
                                  :pod-cidr "10.88.5.0/24"))
    (let* ((server (gr8s::%make-node-grpc-server :store store))
           (request
             (make-instance
              'gr8s.node.v1::operation-request
              :operation-id "stream-before-complete"
              :kind gr8s.node.v1::+operationkind-operation_kind_exec+))
           (operation
             (gr8s::queue-node-operation server "worker-stream" request))
           (message
             (make-instance
              'gr8s.node.v1::operation-stream
              :operation-id "stream-before-complete" :sequence 1
              :channel gr8s.node.v1::+streamchannel-stream_channel_stdout+
              :data (trivial-utf-8:string-to-utf-8-bytes "first")))
           (result nil)
           (waiter
             (bt:make-thread
              (lambda ()
                (setf result
                      (multiple-value-list
                       (gr8s::wait-for-next-node-operation-message
                        operation 0 :timeout 2))))
              :name "gr8s pending stream waiter")))
      (sleep 0.05)
      (gr8s::note-node-operation-stream server message)
      (bt:join-thread waiter)
      (is (eq message (first result)))
      (is (= 1 (second result)))
      (is-false (third result))
      (gr8s::finish-node-operation
       operation
       :response
       (make-instance
        'gr8s.node.v1::operation-response
        :operation-id "stream-before-complete"
        :status gr8s.node.v1::+operationstatus-operation_status_complete+))
      (multiple-value-bind (next cursor done-p)
          (gr8s::wait-for-next-node-operation-message
           operation 1 :timeout 1)
        (is (null next))
        (is (= 1 cursor))
        (is-true done-p))
      (gr8s::release-node-operation server operation)
      (is (null
           (gr8s::find-node-operation server "stream-before-complete"))))))

(test restarted-control-plane-rebuilds-snapshot-above-agent-revision
  (with-temporary-store (store path)
    (gr8s:register-node
     store (gr8s:make-node-record :id "node-recovery" :name "worker-a"
                                  :pod-cidr "10.88.7.0/24"))
    (let* ((pod (create-pod store (parse-pod *valid-pod-json*)))
           (server (gr8s::%make-node-grpc-server
                    :store store :port 0
                    :heartbeat-timeout-seconds 5
                    :cluster-pod-cidr "10.88.0.0/16" :node-prefix 24)))
      (gr8s:mark-node-ready store "worker-a" (get-universal-time))
      (gr8s:schedule-pod store pod)
      (let* ((snapshot (gr8s::prepare-node-connect-snapshot server "worker-a" 42))
             (network (slot-value snapshot 'gr8s.node.v1::network)))
        (is (= 43 (slot-value snapshot 'gr8s.node.v1::revision)))
        (is (= 1 (length (slot-value snapshot 'gr8s.node.v1::pods))))
        (is (string= "10.88.7.0/24"
                     (slot-value network 'gr8s.node.v1::node-pod-cidr)))
        (is (string= "169.254.1.1"
                     (slot-value network 'gr8s.node.v1::dns-address)))
        (is (eq snapshot (gr8s::prepare-node-connect-snapshot server "worker-a" 43)))))))

(test cancelling-agent-during-server-hello-wait-unwinds-the-session
  (with-temporary-store (store path)
    (let* ((server (gr8s:start-node-grpc-server store :host "127.0.0.1" :port 0))
           (control (gr8s::make-node-session-control))
           (received-hello nil)
           (agent nil))
      (unwind-protect
           (progn
             ;; A live peer accepts the RPC and reads requests but never sends
             ;; ServerHello. Cancellation must cover this handshake phase.
             (gr8s.node.v1::register-node-service-service
              (gr8s::node-grpc-server-grpc-server server)
              :connect-handler
              (lambda (context stream)
                (declare (ignore context))
                (setf received-hello (not (null (ag-grpc:stream-recv stream))))
                (loop while (ag-grpc:stream-recv stream))))
             (setf agent
                   (bt:make-thread
                    (lambda ()
                      (gr8s:run-node-session
                       "127.0.0.1" (gr8s:node-grpc-server-port server)
                       "stalled-worker" (merge-pathnames "stalled/identity.json" path)
                       (lambda (snapshot) (declare (ignore snapshot)))
                       :control control :reconnect-delay 0.01))))
             (is-true (wait-until (lambda () received-hello) :timeout 3))
             (gr8s::cancel-node-session control)
             (is-true (wait-until (lambda () (not (bt:thread-alive-p agent)))
                                 :timeout 3)))
        (gr8s::cancel-node-session control)
        (when agent
          (when (bt:thread-alive-p agent) (bt:destroy-thread agent))
          (ignore-errors (bt:join-thread agent)))
        (gr8s:stop-node-grpc-server server)))))

(test node-underlay-identity-is-durable-and-cannot-overlap-another-node
  (with-temporary-store (store path)
    (dolist (entry '(("node-a" "worker-a" "10.88.1.0/24")
                     ("node-b" "worker-b" "10.88.2.0/24")))
      (gr8s:register-node store (gr8s:make-node-record
                                :id (first entry) :name (second entry)
                                :pod-cidr (third entry))))
    (is-true (gr8s::update-node-underlay-address store "worker-a" "192.0.2.10"))
    (is-false (gr8s::update-node-underlay-address store "worker-a" "192.0.2.10"))
    (signals gr8s:kubernetes-error
      (gr8s::update-node-underlay-address store "worker-b" "192.0.2.10"))
    (is (string= "192.0.2.10"
                 (gr8s::node-record-underlay-address
                  (gr8s:get-node (gr8s:open-store path) "worker-a"))))))

(test wireguard-peer-keys-are-durable-and-projected-only-into-peer-routes
  (with-temporary-store (store path)
    (let ((key-a (make-array 32 :element-type '(unsigned-byte 8) :initial-element 10))
          (key-b (make-array 32 :element-type '(unsigned-byte 8) :initial-element 11)))
      (gr8s:register-node
       store (gr8s:make-node-record :id "node-a" :name "worker-a"
                                    :pod-cidr "10.88.1.0/24"
                                    :underlay-address "192.0.2.10"
                                    :wireguard-public-key key-a))
      (gr8s:register-node
       store (gr8s:make-node-record :id "node-b" :name "worker-b"
                                    :pod-cidr "10.88.2.0/24"
                                    :underlay-address "192.0.2.11"
                                    :wireguard-public-key key-b))
      (let* ((reopened (gr8s:open-store path))
             (server (gr8s::%make-node-grpc-server
                      :store reopened :port 0 :heartbeat-timeout-seconds 5
                      :cluster-pod-cidr "10.88.0.0/16" :node-prefix 24
                      :overlay-backend "wireguard" :wireguard-listen-port 51820))
             (network (gr8s::assigned-node-network server "worker-a"))
             (routes (gr8s::assigned-node-routes server "worker-a")))
        (is (equalp key-a
                    (gr8s::node-record-wireguard-public-key
                     (gr8s:get-node reopened "worker-a"))))
        (is (string= "wireguard"
                     (slot-value network 'gr8s.node.v1::overlay-backend)))
        (is (= 51820
               (slot-value network 'gr8s.node.v1::wireguard-listen-port)))
        (is (= 1 (length routes)))
        (is (equalp key-b
                    (slot-value (first routes)
                                'gr8s.node.v1::wireguard-public-key)))
        (is (= 51820
               (slot-value (first routes)
                           'gr8s.node.v1::wireguard-listen-port)))))))

(test live-node-sessions-publish-peer-address-and-key-changes-and-withdrawals
  (with-temporary-store (store path)
    (dolist (entry '(("node-a" "worker-a" "10.88.1.0/24")
                     ("node-b" "worker-b" "10.88.2.0/24")))
      (gr8s:register-node store (gr8s:make-node-record
                                :id (first entry) :name (second entry)
                                :pod-cidr (third entry))))
    (let* ((key-a (make-array 32 :element-type '(unsigned-byte 8) :initial-element 10))
           (key-b (make-array 32 :element-type '(unsigned-byte 8) :initial-element 11))
           (key-c (make-array 32 :element-type '(unsigned-byte 8) :initial-element 12))
           (server (gr8s:start-node-grpc-server
                    store :host "127.0.0.1" :port 0
                    :overlay-backend "wireguard" :wireguard-listen-port 51820))
           (control (gr8s::make-node-session-control))
           (agent nil) (snapshots nil)
           (lock (bt:make-lock "peer snapshot observations")))
      (labels ((latest-peer-address ()
                 (bt:with-lock-held (lock)
                   (let* ((snapshot (first snapshots))
                          (peer (and snapshot (first (slot-value snapshot 'gr8s.node.v1::routes)))))
                     (and peer (slot-value peer 'gr8s.node.v1::underlay-address)))))
               (latest-peer-key ()
                 (bt:with-lock-held (lock)
                   (let* ((snapshot (first snapshots))
                          (peer (and snapshot (first (slot-value snapshot 'gr8s.node.v1::routes)))))
                     (and peer (slot-value peer 'gr8s.node.v1::wireguard-public-key)))))
               (connect-peer (address key)
                 (gr8s:run-node-session
                  "127.0.0.1" (gr8s:node-grpc-server-port server) "worker-b"
                  (merge-pathnames "peer-b/identity.json" path)
                  (lambda (snapshot)
                    (is (string= address (slot-value (slot-value snapshot 'gr8s.node.v1::network)
                                                     'gr8s.node.v1::underlay-address))))
                  :underlay-address address :wireguard-public-key key
                  :max-sessions 1)))
        (unwind-protect
             (progn
               (setf agent
                     (bt:make-thread
                      (lambda ()
                        (gr8s:run-node-session
                         "127.0.0.1" (gr8s:node-grpc-server-port server) "worker-a"
                         (merge-pathnames "peer-a/identity.json" path)
                         (lambda (snapshot)
                           (bt:with-lock-held (lock) (push snapshot snapshots)) nil)
                         :underlay-address "192.0.2.10"
                         :wireguard-public-key key-a :control control
                         :reconnect-delay 0.01))))
               (is-true (wait-until (lambda () (bt:with-lock-held (lock) snapshots)) :timeout 5))
               (connect-peer "192.0.2.11" key-b)
               (is-true (wait-until (lambda () (equal "192.0.2.11" (latest-peer-address))) :timeout 5))
               (is-true (equalp key-b (latest-peer-key)))
               (connect-peer "192.0.2.12" key-b)
               (is-true (wait-until (lambda () (equal "192.0.2.12" (latest-peer-address))) :timeout 5))
               (connect-peer "192.0.2.12" key-c)
               (is-true (wait-until (lambda () (equalp key-c (latest-peer-key))) :timeout 5))
               (is (equalp key-c
                           (gr8s::node-record-wireguard-public-key
                            (gr8s:get-node store "worker-b"))))
               (connect-peer "" key-c)
               (is-true (wait-until (lambda () (null (latest-peer-address))) :timeout 5)))
          (gr8s::cancel-node-session control)
          (when agent
            (unless (wait-until (lambda () (not (bt:thread-alive-p agent))) :timeout 3)
              (bt:destroy-thread agent))
            (ignore-errors (bt:join-thread agent)))
          (gr8s:stop-node-grpc-server server))))))

(test server-hello-cannot-reassign-a-durable-node-cidr
  (with-temporary-store (store path)
    (values store)
    (let* ((identity-path (merge-pathnames "agent/identity.json" path))
           (identity (gr8s::make-agent-identity "worker-a" :node-id "node-1"))
           (hello (make-instance 'gr8s.node.v1::server-hello
                                :node-id "node-1" :assigned-pod-cidr "10.88.0.0/20")))
      (gr8s::accept-agent-server-hello identity identity-path hello)
      (let ((original (uiop:read-file-string identity-path)))
        (setf (slot-value hello 'gr8s.node.v1::assigned-pod-cidr) "10.88.16.0/20")
        (signals error (gr8s::accept-agent-server-hello identity identity-path hello))
        (is (string= "10.88.0.0/20" (gethash "assignedPodCIDR" identity)))
        (is (string= original (uiop:read-file-string identity-path)))
        (setf (slot-value hello 'gr8s.node.v1::assigned-pod-cidr) "10.88.0.1/20")
        (signals error (gr8s::accept-agent-server-hello identity identity-path hello))
        (is (string= original (uiop:read-file-string identity-path)))))))

(test server-hello-persists-and-protects-the-complete-dual-stack-allocation
  (with-temporary-store (store path)
    (values store)
    (let* ((identity-path (merge-pathnames "agent/identity.json" path))
           (identity (gr8s::make-agent-identity "worker-a" :node-id "node-1"))
           (hello (make-instance
                   'gr8s.node.v1::server-hello
                   :node-id "node-1" :assigned-pod-cidr "10.88.0.0/20"
                   :assigned-pod-cidrs '("10.88.0.0/20" "fd88::/64"))))
      (gr8s::accept-agent-server-hello identity identity-path hello)
      (is (equalp #("10.88.0.0/20" "fd88::/64")
                  (gethash "assignedPodCIDRs" identity)))
      (let ((original (uiop:read-file-string identity-path)))
        (setf (slot-value hello 'gr8s.node.v1::assigned-pod-cidrs)
              '("10.88.0.0/20" "fd88:0:0:1::/64"))
        (signals error (gr8s::accept-agent-server-hello identity identity-path hello))
        (is (string= original (uiop:read-file-string identity-path)))))))

(test dual-stack-enrollment-allocates-both-families-from-committed-node-state
  (with-temporary-store (store path)
    (values path)
    (let ((first (gr8s::install-node-enrollment-command
                  store "id-a" "worker-a" '("10.88.0.0/16" "fd88::/48")
                  '(24 64) "2026-11-08T00:00:00Z"))
          (second nil))
      (setf second (gr8s::install-node-enrollment-command
                    store "id-b" "worker-b" '("10.88.0.0/16" "fd88::/48")
                    '(24 64) "2026-11-08T00:00:01Z"))
      (is (equalp #("10.88.0.0/24" "fd88::/64")
                  (gr8s:node-record-all-pod-cidrs first)))
      (is (equalp #("10.88.1.0/24" "fd88:0:0:1::/64")
                  (gr8s:node-record-all-pod-cidrs second))))))

(test snapshot-cidr-is-checked-before-runtime-application-or-acknowledgement
  (let ((identity (gr8s::make-agent-identity "worker-a"))
        (snapshot (empty-desired-snapshot)))
    (setf (gethash "assignedPodCIDR" identity) "10.88.0.0/20"
          (slot-value snapshot 'gr8s.node.v1::revision) 1
          (slot-value snapshot 'gr8s.node.v1::network)
          (make-instance 'gr8s.node.v1::node-network-config :node-pod-cidr "10.88.16.0/20"))
    (signals error
      (gr8s::apply-node-snapshot-and-respond
       nil identity #P"/must-not-write-node-identity" snapshot
       (lambda (snapshot) (declare (ignore snapshot))
         (fail "mismatched snapshot reached the runtime"))))
    (is (= 0 (gethash "lastAppliedRevision" identity)))))

(test legacy-snapshot-singular-cidr-matches-a-new-vector-identity
  (let ((identity (gr8s::make-agent-identity "worker-a"))
        (snapshot (empty-desired-snapshot)))
    (setf (gethash "assignedPodCIDR" identity) "10.88.0.0/20"
          (gethash "assignedPodCIDRs" identity) #("10.88.0.0/20")
          (slot-value snapshot 'gr8s.node.v1::network)
          (make-instance 'gr8s.node.v1::node-network-config
                         :node-pod-cidr "10.88.0.0/20"))
    (finishes (gr8s::validate-node-snapshot-identity identity snapshot))))

(test tls-enrollment-verifies-the-server-before-consuming-its-token
  (with-temporary-store (store path)
    (let* ((pki (gr8s:ensure-cluster-pki path))
           (token (gr8s:create-join-token pki "tls-worker"))
           (server (gr8s:start-node-grpc-server store :pki pki :port 0))
           (key (merge-pathnames "worker/node.key" path))
           (cert (merge-pathnames "worker/node.crt" path))
           (ca (merge-pathnames "worker/ca.crt" path)))
      (unwind-protect
           (progn
             (signals error
               (gr8s:enroll-node-over-grpc
                "127.0.0.1" (gr8s:node-grpc-server-port server) "tls-worker" token
                (make-string 64 :initial-element #\0) key cert ca))
             (signals gr8s:kubernetes-error (gr8s:get-node store "tls-worker"))
             ;; The same token still works: it never crossed the rejected TLS connection.
             (gr8s:enroll-node-over-grpc
              "127.0.0.1" (gr8s:node-grpc-server-port server) "tls-worker" token
              (gr8s:cluster-pki-ca-fingerprint pki) key cert ca)
             (is (probe-file cert))
             (let ((port (gr8s:node-grpc-server-port server)))
               (signals error
                 (gr8s:run-node-session
                  "127.0.0.1" port "tls-worker" (merge-pathnames "no-cert.json" path)
                  (lambda (snapshot) (declare (ignore snapshot)) (fail "Unauthenticated snapshot"))
                  :ca-certificate-path ca :max-sessions 1))
               (is-false (gr8s:node-record-ready-p (gr8s:get-node store "tls-worker")))
               (signals error
                 (gr8s:run-node-session
                  "127.0.0.1" port "other-worker" (merge-pathnames "wrong-name.json" path)
                  (lambda (snapshot) (declare (ignore snapshot)) (fail "Mismatched certificate snapshot"))
                  :ca-certificate-path ca :certificate-path cert :private-key-path key :max-sessions 1))
               (is-false (gr8s:node-record-ready-p (gr8s:get-node store "tls-worker")))
               (gr8s:publish-node-desired-state server "tls-worker" (empty-desired-snapshot))
               (gr8s:run-node-session
                "127.0.0.1" port "tls-worker" (merge-pathnames "good-identity.json" path)
                (lambda (snapshot) (declare (ignore snapshot)))
                :ca-certificate-path ca :certificate-path cert :private-key-path key :max-sessions 1)
               (is (gr8s:node-record-ready-p (gr8s:get-node store "tls-worker")))))
        (gr8s:stop-node-grpc-server server)))))

(test node-runtime-outage-makes-the-node-not-ready-without-dropping-its-lease
  (with-temporary-store (store path)
    (gr8s:register-node
     store (gr8s:make-node-record :id "node-runtime" :name "worker-a"
                                  :pod-cidr "10.88.7.0/24"))
    (let ((server (gr8s::%make-node-grpc-server
                   :store store :port 0 :heartbeat-timeout-seconds 5
                   :cluster-pod-cidr "10.88.0.0/16" :node-prefix 24)))
      (flet ((heartbeat (message)
               (let ((envelope (make-instance 'gr8s.node.v1::agent-envelope
                                              :protocol-version gr8s::+node-protocol-version+
                                              :heartbeat (make-instance 'gr8s.node.v1::heartbeat
                                                                        :runtime-down-message message))))
                 (setf (gr8s.node.v1::payload-case envelope) :heartbeat)
                 ;; Through the wire, as the agent sends it.
                 (gr8s::handle-node-agent-envelope
                  server "worker-a"
                  (ag-proto:deserialize-from-bytes 'gr8s.node.v1::agent-envelope
                                                   (ag-proto:serialize-to-bytes envelope)))))
             (ready-condition ()
               (aref (gethash "conditions" (gethash "status" (gr8s::node-api-object (gr8s:get-node store "worker-a")))) 0)))
        (heartbeat "")
        (is (string= "True" (gethash "status" (ready-condition))))
        (heartbeat "container runtime is down: managed containerd exited (exit status 2)")
        (let ((node (gr8s:get-node store "worker-a")))
          (is (gr8s:node-record-ready-p node))
          (is (not (gr8s::node-record-runtime-ready-p node))))
        (is (string= "False" (gethash "status" (ready-condition))))
        (is (string= "KubeletNotReady" (gethash "reason" (ready-condition))))
        (is (search "container runtime is down" (gethash "message" (ready-condition))))
        (heartbeat "")
        (is (string= "True" (gethash "status" (ready-condition))))
        (is (gr8s::node-record-runtime-ready-p (gr8s:get-node store "worker-a")))))))
(defun delta-test-assignment (name &key (version "1") (body "a") deleting objects)
  (make-instance 'gr8s.node.v1::pod-assignment
                 :namespace "default" :name name :uid (format nil "uid-~A" name)
                 :resource-version version :deleting deleting
                 :pod-json (trivial-utf-8:string-to-utf-8-bytes (format nil "{\"name\":\"~A\",\"body\":\"~A\"}" name body))
                 :resource-objects-json (mapcar #'trivial-utf-8:string-to-utf-8-bytes objects)))

(defun delta-test-snapshot (revision pods &optional (discovery '("svc-a")))
  (make-instance 'gr8s.node.v1::desired-state-snapshot
                 :revision revision
                 :network (make-instance 'gr8s.node.v1::node-network-config :node-pod-cidr "10.88.3.0/24")
                 :service-discovery-objects-json (mapcar #'trivial-utf-8:string-to-utf-8-bytes discovery)
                 :pods (sort (copy-list pods) #'string< :key #'gr8s::pod-assignment-sort-key)))

;; podster-uqb.139: a change sends what changed, and the agent rebuilds exactly
;; the snapshot the server holds.
(test desired-state-deltas-rebuild-the-servers-snapshot
  (let* ((base (delta-test-snapshot 4 (list (delta-test-assignment "kept")
                                            (delta-test-assignment "changed")
                                            (delta-test-assignment "objects" :objects '("{\"cm\":1}"))
                                            (delta-test-assignment "removed"))))
         (next (delta-test-snapshot 5 (list (delta-test-assignment "kept")
                                            (delta-test-assignment "changed" :version "2" :body "b")
                                            (delta-test-assignment "objects" :objects '("{\"cm\":2}"))
                                            (delta-test-assignment "added")
                                            (delta-test-assignment "aardvark" :deleting t))))
         (later (delta-test-snapshot 6 (slot-value next 'gr8s.node.v1::pods) '("svc-a" "svc-b")))
         (delta (gr8s::node-snapshot-delta base next))
         (agent (gr8s::make-agent-node-session nil)))
    (is (= 4 (slot-value delta 'gr8s.node.v1::base-revision)))
    (is (equal '("uid-aardvark" "uid-added" "uid-changed" "uid-objects")
               (sort (mapcar (lambda (pod) (slot-value pod 'gr8s.node.v1::uid)) (slot-value delta 'gr8s.node.v1::pods))
                     #'string<)))
    (is (equal '("uid-removed") (slot-value delta 'gr8s.node.v1::removed-pod-uids)))
    (is-false (slot-value delta 'gr8s.node.v1::service-discovery-changed))
    (is (null (slot-value delta 'gr8s.node.v1::service-discovery-objects-json)))
    ;; Over the wire, as the agent receives them.
    (flet ((wire (snapshot)
             (ag-proto:deserialize-from-bytes 'gr8s.node.v1::desired-state-snapshot
                                              (ag-proto:serialize-to-bytes snapshot))))
      (is (eq (gr8s::assemble-node-snapshot agent (wire base)) (gr8s::agent-node-session-received agent)))
      (is (equalp (ag-proto:serialize-to-bytes next)
                  (ag-proto:serialize-to-bytes (gr8s::assemble-node-snapshot agent (wire delta)))))
      (let ((discovery (gr8s::node-snapshot-delta next later)))
        (is (null (slot-value discovery 'gr8s.node.v1::pods)))
        (is-true (slot-value discovery 'gr8s.node.v1::service-discovery-changed))
        (is (equalp (ag-proto:serialize-to-bytes later)
                    (ag-proto:serialize-to-bytes (gr8s::assemble-node-snapshot agent (wire discovery))))))
      ;; A delta that does not follow what this session received is refused.
      (signals error (gr8s::assemble-node-snapshot agent (wire delta)))
      (signals error (gr8s::assemble-node-snapshot (gr8s::make-agent-node-session nil) (wire delta))))))

(test persistent-agent-applies-deltas-and-resyncs-after-reconnecting
  (with-temporary-store (store path)
    (gr8s:register-node
     store (gr8s:make-node-record :id "node-delta" :name "worker-delta" :pod-cidr "10.88.3.0/24"))
    (let* ((server (gr8s:start-node-grpc-server
                    store :host "127.0.0.1" :port 0 :heartbeat-timeout-seconds 2))
           (identity (merge-pathnames "agent/identity.json" path))
           (applied nil) (lock (bt:make-lock)) (control nil) (agent-thread nil)
           (deltas 0) (delta-function (symbol-function 'gr8s::node-snapshot-delta)))
      (labels ((start-agent ()
                 (setf control (gr8s::make-node-session-control)
                       agent-thread
                       (bt:make-thread
                        (lambda ()
                          (gr8s:run-node-session
                           "127.0.0.1" (gr8s:node-grpc-server-port server) "worker-delta" identity
                           (lambda (snapshot) (bt:with-lock-held (lock) (setf applied snapshot)))
                           :reconnect-delay 0.01 :control control))
                        :name "gr8s delta test agent")))
               (stop-agent ()
                 (gr8s::cancel-node-session control)
                 (bt:join-thread agent-thread))
               (session ()
                 (bt:with-lock-held ((gr8s::node-grpc-server-lock server))
                   (gethash "worker-delta" (gr8s::node-grpc-server-sessions server))))
               (publish (revision pods)
                 (declare (ignore revision))
                 (gr8s:publish-node-desired-state server "worker-delta" (delta-test-snapshot 0 pods)))
               (converged-p ()
                 (let ((current (gr8s::current-node-snapshot server "worker-delta")))
                   (bt:with-lock-held (lock)
                     (and applied (= (slot-value applied 'gr8s.node.v1::revision)
                                     (slot-value current 'gr8s.node.v1::revision))
                          (equalp (mapcar #'ag-proto:serialize-to-bytes (slot-value applied 'gr8s.node.v1::pods))
                                  (mapcar #'ag-proto:serialize-to-bytes (slot-value current 'gr8s.node.v1::pods)))
                          (equalp (slot-value applied 'gr8s.node.v1::service-discovery-objects-json)
                                  (slot-value current 'gr8s.node.v1::service-discovery-objects-json)))))))
        ;; Count the deltas the server actually sends.
        (setf (symbol-function 'gr8s::node-snapshot-delta)
              (lambda (base snapshot) (incf deltas) (funcall delta-function base snapshot)))
        (unwind-protect
             (progn
               (publish 1 (list (delta-test-assignment "a") (delta-test-assignment "b")))
               (start-agent)
               (is-true (wait-until #'converged-p :timeout 5))
               (is-true (gr8s::node-agent-session-deltas-p (session)))
               (publish 2 (list (delta-test-assignment "a" :version "2") (delta-test-assignment "c")))
               (is-true (wait-until #'converged-p :timeout 5))
               (publish 3 (list (delta-test-assignment "c")))
               (is-true (wait-until #'converged-p :timeout 5))
               ;; Changes made while no session is open arrive as a complete snapshot.
               (stop-agent)
               (publish 4 (list (delta-test-assignment "c" :version "2") (delta-test-assignment "d")))
               (start-agent)
               (is-true (wait-until #'converged-p :timeout 5))
               (publish 5 (list (delta-test-assignment "d")))
               (is-true (wait-until #'converged-p :timeout 5))
               ;; Revisions 2, 3 and 5 followed one the session had delivered.
               (is (= 3 deltas)))
          (setf (symbol-function 'gr8s::node-snapshot-delta) delta-function)
          (ignore-errors (stop-agent))
          (gr8s:stop-node-grpc-server server))))))
