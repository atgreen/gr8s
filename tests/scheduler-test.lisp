(in-package #:gr8s/tests)

(in-suite gr8s)

(defun make-test-node (name id cidr)
  (gr8s:make-node-record :name name :id id :pod-cidr cidr))

(test node-identity-and-pod-cidr-survive-a-store-restart
  (with-temporary-store (store path)
    (gr8s:register-node store
                        (make-test-node "worker-a" "node-a" "10.64.0.0/20"))
    (gr8s:mark-node-ready store "worker-a" 100)
    (let* ((pod (create-pod store (parse-pod *valid-pod-json*)))
           (assigned (gr8s:schedule-pod store pod))
           (reopened (open-store path))
           (node (gr8s:get-node reopened "worker-a"))
           (restored-pod (get-pod reopened "default" "hello")))
      (is (string= "worker-a" (gr8s:node-record-name assigned)))
      (is (string= "node-a" (gr8s:node-record-id node)))
      (is (string= "10.64.0.0/20" (gr8s:node-record-pod-cidr node)))
      (is-false (gr8s:node-record-ready-p node))
      (is (string= "worker-a" (gr8s:pod-node-name restored-pod))))))

(test duplicate-node-identities-and-pod-cidrs-are-rejected
  (with-temporary-store (store path)
    (gr8s:register-node store
                        (make-test-node "worker-a" "node-a" "10.64.0.0/20"))
    (dolist (duplicate
             (list (make-test-node "worker-a" "node-b" "10.64.16.0/20")
                   (make-test-node "worker-b" "node-a" "10.64.16.0/20")
                   (make-test-node "worker-b" "node-b" "10.64.0.0/20")))
      (handler-case
          (progn
            (gr8s:register-node store duplicate)
            (fail "duplicate node claim must fail"))
        (kubernetes-error (condition)
          (is (string= "Conflict" (kubernetes-error-reason condition))))))))

(test pod-cidr-allocation-is-deterministic-and-skips-claimed-blocks
  (with-temporary-store (store path)
    (is (string= "10.64.0.0/20"
                 (gr8s:allocate-node-pod-cidr store "10.64.0.0/12" 20)))
    (gr8s:register-node store
                        (make-test-node "worker-a" "node-a" "10.64.0.0/20"))
    (is (string= "10.64.16.0/20"
                 (gr8s:allocate-node-pod-cidr store "10.64.0.0/12" 20)))))

(test scheduler-leaves-pods-pending-until-a-node-is-ready
  (with-temporary-store (store path)
    (let ((pod (create-pod store (parse-pod *valid-pod-json*))))
      (is (null (gr8s:schedule-pod store pod)))
      (is (null (gr8s:pod-node-name pod)))
      (is (string= "Pending" (gr8s:pod-scheduling-phase store pod))))))

(test scheduler-uses-fewest-nonterminal-assignments-and-breaks-ties-by-name
  (with-temporary-store (store path)
    (dolist (node (list (make-test-node "worker-b" "node-b" "10.64.16.0/20")
                        (make-test-node "worker-a" "node-a" "10.64.0.0/20")))
      (gr8s:register-node store node)
      (gr8s:mark-node-ready store (gr8s:node-record-name node) 100))
    (let ((first (create-pod store (parse-pod *valid-pod-json*))))
      (is (string= "worker-a"
                   (gr8s:node-record-name (gr8s:schedule-pod store first))))
      (let* ((object (com.inuoe.jzon:parse *valid-pod-json*))
             (metadata (gethash "metadata" object)))
        (setf (gethash "name" metadata) "second")
        (let ((second (create-pod store (parse-pod object))))
          (is (string= "worker-b"
                       (gr8s:node-record-name
                        (gr8s:schedule-pod store second))))
          (gr8s:update-pod-observed-phase store first "Succeeded")
          (let* ((third-object (com.inuoe.jzon:parse *valid-pod-json*))
                 (third-metadata (gethash "metadata" third-object)))
            (setf (gethash "name" third-metadata) "third")
            (is (string= "worker-a"
                         (gr8s:node-record-name
                          (gr8s:schedule-pod
                           store (create-pod store (parse-pod third-object))))))))))))

(test scheduler-respects-an-explicit-existing-node-name
  (with-temporary-store (store path)
    (gr8s:register-node store
                        (make-test-node "worker-a" "node-a" "10.64.0.0/20"))
    (let* ((object (com.inuoe.jzon:parse *valid-pod-json*))
           (spec (gethash "spec" object)))
      (setf (gethash "nodeName" spec) "worker-a")
      (let ((pod (create-pod store (parse-pod object))))
        (is (string= "worker-a"
                     (gr8s:node-record-name (gr8s:schedule-pod store pod))))
        (is (string= "Unknown" (gr8s:pod-scheduling-phase store pod)))))))

(test losing-node-readiness-marks-its-assigned-pods-unknown-without-moving-them
  (with-temporary-store (store path)
    (gr8s:register-node store
                        (make-test-node "worker-a" "node-a" "10.64.0.0/20"))
    (gr8s:mark-node-ready store "worker-a" 100)
    (let ((pod (create-pod store (parse-pod *valid-pod-json*))))
      (gr8s:schedule-pod store pod)
      (gr8s:update-pod-observed-phase store pod "Running")
      (is (string= "Running" (gr8s:pod-scheduling-phase store pod)))
      (gr8s:mark-node-not-ready store "worker-a")
      (is (string= "Unknown" (gr8s:pod-scheduling-phase store pod)))
      (is (string= "worker-a" (gr8s:pod-node-name pod))))))

(test heartbeat-expiry-makes-only-stale-nodes-not-ready
  (with-temporary-store (store path)
    (gr8s:register-node store
                        (make-test-node "worker-a" "node-a" "10.64.0.0/20"))
    (gr8s:register-node store
                        (make-test-node "worker-b" "node-b" "10.64.16.0/20"))
    (gr8s:mark-node-ready store "worker-a" 100)
    (gr8s:mark-node-ready store "worker-b" 200)
    (let ((expired (gr8s:expire-node-heartbeats store 150)))
      (is (= 1 (length expired)))
      (is (string= "worker-a" (gr8s:node-record-name (first expired))))
      (is-false (gr8s:node-record-ready-p (gr8s:get-node store "worker-a")))
      (is-true (gr8s:node-record-ready-p (gr8s:get-node store "worker-b"))))))

(test pod-updates-preserve-and-cannot-move-a-scheduled-assignment
  (with-temporary-store (store path)
    (gr8s:register-node store
                        (make-test-node "worker-a" "node-a" "10.64.0.0/20"))
    (gr8s:mark-node-ready store "worker-a" 100)
    (let ((pod (create-pod store (parse-pod *valid-pod-json*))))
      (gr8s:schedule-pod store pod)
      (let ((updated (update-pod store (parse-pod *valid-pod-json*) "2")))
        (is (string= "worker-a" (gr8s:pod-node-name updated)))
        (is (string= "worker-a"
                     (gethash "nodeName"
                              (gethash "spec" (gr8s:pod-to-object updated))))))
      (let* ((object (com.inuoe.jzon:parse *valid-pod-json*))
             (spec (gethash "spec" object)))
        (setf (gethash "nodeName" spec) "worker-b")
        (handler-case
            (progn
              (update-pod store (parse-pod object) "3")
              (fail "a scheduled Pod must not move through an update"))
          (kubernetes-error (condition)
            (is (string= "Conflict" (kubernetes-error-reason condition)))))))))

(defun capacity-test-pod (name &key cpu memory node init-cpu)
  "Build a Pod requesting CPU and MEMORY, optionally pinned to NODE or with an init container."
  (let* ((requests (gr8s::core-object)) (spec (gr8s::core-object
                                               "containers"
                                               (vector (gr8s::core-object "name" "c" "image" "busybox"
                                                                          "resources" (gr8s::core-object "requests" requests))))))
    (when cpu (setf (gethash "cpu" requests) cpu))
    (when memory (setf (gethash "memory" requests) memory))
    (when node (setf (gethash "nodeName" spec) node))
    (when init-cpu
      (setf (gethash "initContainers" spec)
            (vector (gr8s::core-object "name" "i" "image" "busybox"
                                       "resources" (gr8s::core-object "requests" (gr8s::core-object "cpu" init-cpu))))))
    (parse-pod (gr8s::core-object "apiVersion" "v1" "kind" "Pod" "spec" spec
                                  "metadata" (gr8s::core-object "name" name "namespace" "default")))))

(defun register-capacity-node (store name id cidr cpu memory &optional (pods "110"))
  "Register a ready node whose agent reported CPU, MEMORY and PODS capacity."
  (gr8s:register-node store (make-test-node name id cidr))
  (gr8s::update-node-capacity store name (gr8s::core-object "cpu" cpu "memory" memory "pods" pods))
  (gr8s:mark-node-ready store name 100))

(test requests-keep-pods-within-a-nodes-capacity
  (with-temporary-store (store path)
    (register-capacity-node store "worker-a" "node-a" "10.64.0.0/20" "2" "1Gi")
    (let ((first (create-pod store (capacity-test-pod "first" :cpu "1500m")))
          (second (create-pod store (capacity-test-pod "second" :cpu "1")))
          (third (create-pod store (capacity-test-pod "third" :memory "2Gi")))
          (free (create-pod store (capacity-test-pod "free"))))
      (is (gr8s:schedule-pod store first))
      (is-false (gr8s:schedule-pod store second))
      (is-false (gr8s:pod-node-name second))
      (is-false (gr8s:schedule-pod store third))
      (is (search "1 Insufficient cpu"
                  (gr8s::with-store-lock (store) (gr8s::pod-unschedulable-message store second))))
      (is (search "1 Insufficient memory"
                  (gr8s::with-store-lock (store) (gr8s::pod-unschedulable-message store third))))
      ;; A Pod that requests nothing fits however full the node is.
      (is (gr8s:schedule-pod store free))
      ;; A finished Pod no longer holds what it requested.
      (gr8s::update-pod-observed-phase store first "Succeeded")
      (is (gr8s:schedule-pod store second)))))

(test the-largest-init-container-request-counts-against-capacity
  (with-temporary-store (store path)
    (register-capacity-node store "worker-a" "node-a" "10.64.0.0/20" "2" "1Gi")
    (let ((large (create-pod store (capacity-test-pod "large" :cpu "100m" :init-cpu "3")))
          (small (create-pod store (capacity-test-pod "small" :cpu "1" :init-cpu "500m"))))
      (is-false (gr8s:schedule-pod store large))
      (is (gr8s:schedule-pod store small)))))

(test a-node-accepts-only-as-many-pods-as-it-reports
  (with-temporary-store (store path)
    (register-capacity-node store "worker-a" "node-a" "10.64.0.0/20" "2" "1Gi" "1")
    (let ((first (create-pod store (capacity-test-pod "first")))
          (second (create-pod store (capacity-test-pod "second"))))
      (is (gr8s:schedule-pod store first))
      (is-false (gr8s:schedule-pod store second))
      (is (search "1 Too many pods"
                  (gr8s::with-store-lock (store) (gr8s::pod-unschedulable-message store second)))))))

(test a-second-node-takes-a-pod-the-first-has-no-room-for
  (with-temporary-store (store path)
    (register-capacity-node store "worker-a" "node-a" "10.64.0.0/20" "1" "1Gi")
    (register-capacity-node store "worker-b" "node-b" "10.64.16.0/20" "4" "1Gi")
    (let ((pod (create-pod store (capacity-test-pod "wide" :cpu "2"))))
      (is (string= "worker-b" (gr8s:node-record-name (gr8s:schedule-pod store pod)))))))

(defun host-port-test-pod (name port &key ip node)
  "Build a Pod claiming host PORT, optionally on one address IP or pinned to NODE."
  (let ((declared (gr8s::core-object "containerPort" 80 "hostPort" port))
        (spec (gr8s::core-object)))
    (when ip (setf (gethash "hostIP" declared) ip))
    (when node (setf (gethash "nodeName" spec) node))
    (setf (gethash "containers" spec)
          (vector (gr8s::core-object "name" "c" "image" "busybox" "ports" (vector declared))))
    (parse-pod (gr8s::core-object "apiVersion" "v1" "kind" "Pod" "spec" spec
                                  "metadata" (gr8s::core-object "name" name "namespace" "default")))))

(test host-ports-are-validated-and-only-tcp-is-accepted
  (is (equal '(("TCP" "" . 8080)) (gr8s::pod-host-ports (host-port-test-pod "a" 8080))))
  (is (equal '(("TCP" "" . 8080)) (gr8s::pod-host-ports (host-port-test-pod "a" 8080 :ip "0.0.0.0"))))
  (is (equal '(("TCP" "10.0.0.1" . 8080)) (gr8s::pod-host-ports (host-port-test-pod "a" 8080 :ip "10.0.0.1"))))
  (signals gr8s::kubernetes-error (host-port-test-pod "a" 70000))
  (signals gr8s::kubernetes-error (host-port-test-pod "a" 8080 :ip "not-an-address"))
  (is (gr8s::host-ports-conflict-p '("TCP" "" . 1) '("TCP" "10.0.0.1" . 1)))
  (is-false (gr8s::host-ports-conflict-p '("TCP" "10.0.0.2" . 1) '("TCP" "10.0.0.1" . 1)))
  (is-false (gr8s::host-ports-conflict-p '("TCP" "" . 1) '("TCP" "" . 2)))
  (is-false (gr8s::host-ports-conflict-p '("TCP" "" . 1) '("UDP" "" . 1))))

(test the-scheduler-will-not-place-two-pods-on-one-host-port
  (with-temporary-store (store path)
    (register-capacity-node store "worker-a" "node-a" "10.64.0.0/20" "2" "1Gi")
    (let ((first (create-pod store (host-port-test-pod "first" 8080)))
          (second (create-pod store (host-port-test-pod "second" 8080)))
          (other (create-pod store (host-port-test-pod "other" 8081))))
      (is (gr8s:schedule-pod store first))
      (is (gr8s:schedule-pod store other))
      (is-false (gr8s:schedule-pod store second))
      (is (search "didn't have free ports"
                  (gr8s::with-store-lock (store) (gr8s::pod-unschedulable-message store second)))))))

(test a-node-refuses-a-pod-that-named-it-when-a-host-port-is-taken
  (with-temporary-store (store path)
    (register-capacity-node store "worker-a" "node-a" "10.64.0.0/20" "2" "1Gi")
    (let ((holder (create-pod store (host-port-test-pod "a-holder" 8080 :node "worker-a")))
          (refused (create-pod store (host-port-test-pod "refused" 8080 :node "worker-a"))))
      (is-false (gr8s::admit-assigned-pod store refused))
      (is-true (gr8s::admit-assigned-pod store holder))
      (gr8s::update-pod-observed-phase store holder "Running")
      (let ((status (gr8s::pod-observed-status store refused)))
        (is (equal "Failed" (gethash "phase" status)))
        (is (equal "NodePorts" (gethash "reason" status)))
        (is (search "free ports" (gethash "message" status))))
      ;; Admission does not depend on the order it is asked in: the holder is older.
      (is-true (gr8s::admit-assigned-pod store holder))
      ;; Refusal is final even once the port frees up, and the Pod is never published.
      (gr8s::update-pod-observed-phase store holder "Succeeded")
      (is-false (gr8s::admit-assigned-pod store refused))
      (let ((snapshot (gr8s::node-desired-state-snapshot store "worker-a")))
        (is (equal '("a-holder") (mapcar (lambda (assignment) (slot-value assignment 'gr8s.node.v1::name))
                                       (slot-value snapshot 'gr8s.node.v1::pods)))))
      ;; A replacement admitted after the holder finished may start.
      (let ((replacement (create-pod store (host-port-test-pod "replacement" 8080 :node "worker-a"))))
        (is-true (gr8s::admit-assigned-pod store replacement))))))

(test a-node-refuses-a-pod-that-named-it-when-it-is-full
  (with-temporary-store (store path)
    (register-capacity-node store "worker-a" "node-a" "10.64.0.0/20" "1" "1Gi")
    (let ((refused (create-pod store (capacity-test-pod "big" :cpu "2" :node "worker-a"))))
      (is-false (gr8s::admit-assigned-pod store refused))
      (is (equal "OutOfcpu" (gethash "reason" (gr8s::pod-observed-status store refused))))
      (is (equal "Failed" (gr8s::pod-scheduling-phase store refused))))))

(test a-refused-pod-can-be-deleted-without-its-agent
  (with-temporary-store (store path)
    (register-capacity-node store "worker-a" "node-a" "10.64.0.0/20" "1" "1Gi")
    (let* ((runtime (gr8s::make-control-plane-runtime store nil))
           (pod (create-pod store (capacity-test-pod "big" :cpu "2" :node "worker-a"))))
      (is-false (gr8s::admit-assigned-pod store pod))
      (is-true (gr8s::with-store-lock (store) (gr8s::pod-admission-rejected-p store pod)))
      (let ((deleted (gr8s::mark-pod-deleting store "default" "big" :uid (pod-uid pod))))
        (is-false (gr8s::admit-assigned-pod store deleted))
        (handler-case (is-true (gr8s::runtime-delete-pod runtime deleted))
          ;; This test has no node server to tell, and the Pod's refusal must not need one.
          (error (condition) (fail "A refused Pod needed its agent: ~A" condition)))))))

(test a-host-port-relays-a-tcp-connection-both-ways
  (let ((upstream (make-instance 'sb-bsd-sockets:inet-socket :type :stream :protocol :tcp))
        (forwarder nil))
    (unwind-protect
         (progn
           (setf (sb-bsd-sockets:sockopt-reuse-address upstream) t)
           (sb-bsd-sockets:socket-bind upstream #(127 0 0 1) 0)
           (sb-bsd-sockets:socket-listen upstream 5)
           (let* ((upstream-port (nth-value 1 (sb-bsd-sockets:socket-name upstream)))
                  (echo (bt:make-thread
                         (lambda ()
                           (let ((connection (sb-bsd-sockets:socket-accept upstream))
                                 (buffer (make-array 16 :element-type '(unsigned-byte 8))))
                             (multiple-value-bind (data length) (sb-bsd-sockets:socket-receive connection buffer nil)
                               (declare (ignore data))
                               (sb-bsd-sockets:socket-send connection (subseq buffer 0 length) length))
                             (sb-bsd-sockets:socket-shutdown connection :direction :output)
                             (sb-bsd-sockets:socket-close connection)))))
                  (client (make-instance 'sb-bsd-sockets:inet-socket :type :stream :protocol :tcp)))
             (setf forwarder (gr8s::start-host-port-forwarder "127.0.0.1" 0 (cons "127.0.0.1" upstream-port)))
             (sb-bsd-sockets:socket-connect client #(127 0 0 1)
                                            (nth-value 1 (sb-bsd-sockets:socket-name (gr8s::host-port-forwarder-listener forwarder))))
             (let ((message (coerce #(1 2 3) '(vector (unsigned-byte 8))))
                   (buffer (make-array 16 :element-type '(unsigned-byte 8))))
               (sb-bsd-sockets:socket-send client message 3)
               (multiple-value-bind (data length) (sb-bsd-sockets:socket-receive client buffer nil)
                 (declare (ignore data))
                 (is (= 3 length))
                 (is (equalp #(1 2 3) (subseq buffer 0 3)))))
             (bt:join-thread echo)
             (sb-bsd-sockets:socket-close client)))
      (when forwarder (gr8s::stop-host-port-forwarder forwarder))
      (sb-bsd-sockets:socket-close upstream))))

(test the-host-port-table-follows-the-pods
  (with-temporary-store (store path)
    (let* ((forwarders (make-hash-table :test #'equal))
           (pod (create-pod store (host-port-test-pod "web" 0))))
      (declare (ignorable pod))
      (let* ((declared (gr8s::core-object "containerPort" 80 "hostPort" 28431 "hostIP" "127.0.0.1"))
             (input (gr8s::core-object "apiVersion" "v1" "kind" "Pod"
                                       "metadata" (gr8s::core-object "name" "served" "namespace" "default")
                                       "spec" (gr8s::core-object "containers"
                                                                 (vector (gr8s::core-object "name" "c" "image" "busybox"
                                                                                            "ports" (vector declared))))))
             (served (create-pod store (parse-pod input))))
        (unwind-protect
             (progn
               (gr8s::converge-host-port-forwarders forwarders store)
               (is (zerop (hash-table-count forwarders)) "A Pod with no address has nothing to relay to")
               (gr8s::update-pod-observed-status store served (gr8s::core-object "phase" "Running" "podIP" "10.1.2.3"))
               (gr8s::converge-host-port-forwarders forwarders store)
               (let ((forwarder (gethash (list* "TCP" "127.0.0.1" 28431) forwarders)))
                 (is (equal '("10.1.2.3" . 80) (gr8s::host-port-forwarder-target forwarder))))
               (gr8s::update-pod-observed-status store served (gr8s::core-object "phase" "Failed" "podIP" "10.1.2.3"))
               (gr8s::converge-host-port-forwarders forwarders store)
               (is (zerop (hash-table-count forwarders))))
          (gr8s::stop-host-port-forwarders forwarders))))))
