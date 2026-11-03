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
