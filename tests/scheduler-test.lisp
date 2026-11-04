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
  (gr8s::update-node-capacity store name (list (cons "cpu" cpu) (cons "memory" memory) (cons "pods" pods)))
  (gr8s:mark-node-ready store name 100))

(test node-api-reports-the-capacity-its-agent-reported
  (with-temporary-store (store path)
    (gr8s:register-node store (make-test-node "worker-a" "node-a" "10.64.0.0/20"))
    (is-false (gethash "capacity" (gethash "status" (gr8s::node-api-object (gr8s:get-node store "worker-a")))))
    (gr8s::update-node-capacity store "worker-a" (list (cons "cpu" "4") (cons "memory" "8192Ki") (cons "pods" "110")))
    (let* ((reopened (open-store path))
           (status (gethash "status" (gr8s::node-api-object (gr8s:get-node reopened "worker-a")))))
      (is (equal "4" (gethash "cpu" (gethash "capacity" status))))
      (is (equal "8192Ki" (gethash "memory" (gethash "allocatable" status))))
      (is (equal "110" (gethash "pods" (gethash "allocatable" status)))))
    (signals gr8s::kubernetes-error
      (gr8s::update-node-capacity store "worker-a" (list (cons "cpu" "many"))))))

(test local-node-capacity-matches-what-the-downward-api-reports
  (let ((capacity (gr8s::local-node-capacity)))
    (is (equal (write-to-string (gr8s::node-allocatable-cpu)) (cdr (assoc "cpu" capacity :test #'equal))))
    (is (= (* 1024 (floor (gr8s::node-allocatable-memory) 1024))
           (gr8s::container-quantity-integer (gr8s::parse-container-quantity (cdr (assoc "memory" capacity :test #'equal))))))))

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
      (is (equal '(3000 0) (multiple-value-list (gr8s::pod-effective-requests large))))
      (is (equal '(1000 0) (multiple-value-list (gr8s::pod-effective-requests small))))
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
