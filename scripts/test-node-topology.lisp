(load (merge-pathnames "network-test-support.lisp" *load-truename*))
(in-package #:gr8s.network)
;; Import the sibling-module symbols the removed #:gr8s facade used to expose
;; (podster-yjf / podster-oed).
(import '(gr8s.store::open-store
          gr8s.model::make-node-record
          gr8s.controllers::register-node
          gr8s.apiserver::start-node-grpc-server
          gr8s.apiserver::stop-node-grpc-server
          gr8s.apiserver::node-grpc-server-port
          gr8s.agent::make-node-session-control
          gr8s.agent::run-node-session
          gr8s.agent::cancel-node-session
          gr8s.agent::make-node-runtime
          gr8s.agent::node-runtime-network
          gr8s.agent::apply-node-runtime-network
          gr8s.runtime::make-fake-runtime))

(defun topology-test-wait (predicate)
  (loop repeat 400
        when (funcall predicate) return t
        do (sleep 0.05)
        finally (error "node topology did not converge")))

(let* ((directory (merge-pathnames
                   (format nil "gr8s-topology-~36R/" (random (expt 36 8)))
                   (uiop:temporary-directory)))
       (store (open-store (merge-pathnames "control/" directory)))
       (server nil)
       (nodes (make-array 2 :initial-element nil))
       (pods (make-array 2 :initial-element nil))
       (agents (make-array 2 :initial-element nil))
       (controls (make-array 2 :initial-element nil))
       (observed (make-array 2 :initial-element nil))
       (failures (make-array 2 :initial-element nil))
       (lock (bt:make-lock "gr8s topology test observations")))
  (labels ((node-path (index) (format nil "/proc/self/fd/~D" (aref nodes index)))
           (in-node (index function)
             (call-with-cni-network-namespace (node-path index) function))
           (agent-state (index)
             (merge-pathnames (format nil "node-~D/" index) directory))
           (stop-agent (index)
             (when (aref controls index) (cancel-node-session (aref controls index)))
             (when (aref agents index)
               (topology-test-wait (lambda () (not (bt:thread-alive-p (aref agents index)))))
               (ignore-errors (bt:join-thread (aref agents index)))
               (setf (aref agents index) nil)))
           (start-agent (index &optional underlay)
             (let ((control (make-node-session-control))
                   (node-name (format nil "worker-~D" index))
                   (host (format nil "192.0.~D.1" (+ index 2)))
                   (state (agent-state index)))
               (setf (aref controls index) control)
               (bt:with-lock-held (lock)
                 (setf (aref observed index) nil (aref failures index) nil))
               (in-node
                index
                (lambda ()
                  (setf (aref agents index)
                        (bt:make-thread
                         (lambda ()
                           (handler-case
                               (let ((runtime
                                       (make-node-runtime
                                        (merge-pathnames "runtime/" state)
                                        (make-fake-runtime) nil
                                        :network-reconciler #'reconcile-node-vxlan-network)))
                                 (bt:with-lock-held (lock)
                                   (setf (aref observed index) (node-runtime-network runtime)))
                                 (run-node-session
                                  host (node-grpc-server-port server) node-name
                                  (merge-pathnames "identity.json" state)
                                  (lambda (snapshot)
                                    (handler-case (apply-node-runtime-network runtime snapshot)
                                      (error (condition)
                                        (bt:with-lock-held (lock)
                                          (setf (aref failures index) condition))
                                        (error condition)))
                                    (bt:with-lock-held (lock)
                                      (setf (aref observed index) (node-runtime-network runtime)))
                                    nil)
                                  :underlay-address underlay :control control
                                  :reconnect-delay 0.05))
                             (error (condition)
                               (bt:with-lock-held (lock)
                                 (setf (aref failures index) condition)))))
                         :name (format nil "gr8s topology node ~D" index)))))))
           (wait-network (index underlay peer-address)
             (topology-test-wait
              (lambda ()
                (bt:with-lock-held (lock)
                  (when (aref failures index) (error (aref failures index)))
                  (let ((network (aref observed index)))
                    (and network
                         (equal underlay (gethash "underlayAddress" network))
                         (if peer-address
                             (let ((routes (gethash "routes" network)))
                               (and (= 1 (length routes))
                                    (equal peer-address
                                           (gethash "underlayAddress" (aref routes 0)))))
                             (zerop (length (gethash "routes" network))))))))))
           (ping-pods ()
             (dotimes (index 2)
               (call-with-cni-network-namespace
                (format nil "/proc/self/fd/~D" (aref pods index))
                (lambda ()
                  (uiop:run-program
                   (list "ping" "-n" "-c" "1" "-W" "2" "-M" "do" "-s" "1422"
                         (format nil "10.88.~D.1" (- 2 index)))
                   :output *standard-output* :error-output *error-output*))))))
    (unwind-protect
         (progn
           (enable-node-ipv4-forwarding)
           (dotimes (index 2)
             (register-node store (make-node-record
                                   :id (format nil "topology-node-~D" index)
                                   :name (format nil "worker-~D" index)
                                   :pod-cidr (format nil "10.88.~D.0/24" (1+ index))))
             (setf (aref nodes index) (test-network-namespace)
                   (aref pods index) (test-network-namespace))
             (let ((host (format nil "topology-u-~D" index))
                   (gateway (format nil "192.0.~D.1" (+ index 2)))
                   (local (format nil "192.0.~D.2" (+ index 2))))
               (create-routed-veth host "underlay0" (node-path index) :mtu 1500)
               (add-network-address host gateway 24)
               (set-network-link-up host)
               (in-node
                index
                (lambda ()
                  (set-network-link-up "lo")
                  (add-network-address "underlay0" local 24)
                  (set-network-link-up "underlay0")
                  (replace-network-route "0.0.0.0" 0 "underlay0" :gateway gateway)
                  (configure-routed-veth
                   (make-cni-context
                    :container-id (format nil "topology-pod-~D" index)
                    :interface-name "eth0"
                    :netns (format nil "/proc/self/fd/~D" (aref pods index)))
                   (format nil "10.88.~D.1" (1+ index)))))))
           (setf server (start-node-grpc-server store :host "0.0.0.0" :port 0))
           ;; No explicit underlay: agents advertise their actual gRPC source IP.
           (start-agent 0) (start-agent 1)
           (wait-network 0 "192.0.2.2" "192.0.3.2")
           (wait-network 1 "192.0.3.2" "192.0.2.2")
           (ping-pods)
           ;; Recover a crash after NEWLINK but before its ownership alias.
           (stop-agent 0)
           (in-node 0 (lambda () (set-network-link-owner +node-vxlan-interface+ "")))
           (start-agent 0)
           (wait-network 0 "192.0.2.2" "192.0.3.2")
           (ping-pods)
           ;; Recover a lost tunnel from persisted topology before reconnecting.
           (stop-agent 0)
           (in-node 0 (lambda () (delete-network-link +node-vxlan-interface+)))
           (start-agent 0)
           (wait-network 0 "192.0.2.2" "192.0.3.2")
           (ping-pods)
           ;; Changing a peer's underlay address replaces its owned tunnel and
           ;; updates the other node's FDB through a new authoritative snapshot.
           (stop-agent 1)
           (in-node 1 (lambda () (add-network-address "underlay0" "192.0.3.3" 24)))
           (start-agent 1 "192.0.3.3")
           (wait-network 0 "192.0.2.2" "192.0.3.3")
           (wait-network 1 "192.0.3.3" "192.0.2.2")
           (ping-pods)
           ;; Explicitly withdrawing the address removes peer routes and the
           ;; withdrawing node's tunnel without releasing any Pod endpoint.
           (stop-agent 1)
           (start-agent 1 "")
           (wait-network 0 "192.0.2.2" nil)
           (wait-network 1 "" nil)
           (in-node 0 (lambda ()
                        (let ((routes (uiop:run-program
                                       '("ip" "-4" "route" "show" "dev" "gr8s-vxlan")
                                       :output :string)))
                          (assert (not (search "10.88.2." routes))))))
           (in-node 1 (lambda () (assert (zerop (native-interface-index +node-vxlan-interface+)))))
           (format t "gr8s live two-node snapshot/VXLAN recovery test passed~%"))
      (dotimes (index 2)
        (ignore-errors (stop-agent index))
        (when (and (aref agents index) (bt:thread-alive-p (aref agents index)))
          (ignore-errors (bt:destroy-thread (aref agents index)))))
      (when server (stop-node-grpc-server server))
      (dotimes (index 2)
        (when (aref pods index) (ignore-errors (sb-posix:close (aref pods index))))
        (when (aref nodes index) (ignore-errors (sb-posix:close (aref nodes index)))))
      (uiop:delete-directory-tree directory :validate t))))
