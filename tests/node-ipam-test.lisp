(in-package #:gr8s/tests)

(in-suite gr8s)

(test node-ipam-allocations-are-idempotent-and-survive-restart
  (let ((directory
          (merge-pathnames
           (format nil "gr8s-node-ipam-~36R/" (random (expt 36 8)))
           (uiop:temporary-directory))))
    (unwind-protect
         (let* ((ipam (gr8s::open-node-ipam directory "10.42.0.0/29"))
                (first
                  (gr8s::allocate-pod-address ipam "sandbox-a" "eth0"))
                (second
                  (gr8s::allocate-pod-address ipam "sandbox-b" "eth0")))
           (is (string= "10.42.0.1" first))
           (is (string= "10.42.0.2" second))
           (is (string= first
                        (gr8s::allocate-pod-address
                         ipam "sandbox-a" "eth0")))
           (let ((reopened
                   (gr8s::open-node-ipam directory "10.42.0.0/29")))
             (is (string= first
                          (gr8s::check-pod-address
                           reopened "sandbox-a" "eth0")))
             (is (string= second
                          (gr8s::check-pod-address
                           reopened "sandbox-b" "eth0")))))
      (when (probe-file directory)
        (uiop:delete-directory-tree directory :validate t)))))

(test node-ipam-release-is-persistent-and-unknown-release-succeeds
  (let ((directory
          (merge-pathnames
           (format nil "gr8s-node-ipam-release-~36R/"
                   (random (expt 36 8)))
           (uiop:temporary-directory))))
    (unwind-protect
         (let ((ipam (gr8s::open-node-ipam directory "10.42.1.0/29")))
           (is (null (gr8s::release-pod-address
                      ipam "unknown" "eth0")))
           (is (string= "10.42.1.1"
                        (gr8s::allocate-pod-address
                         ipam "sandbox-a" "eth0")))
           (is (null (gr8s::release-pod-address
                      ipam "sandbox-a" "eth0")))
           (signals gr8s::cni-error
             (gr8s::check-pod-address ipam "sandbox-a" "eth0"))
           (let ((reopened
                   (gr8s::open-node-ipam directory "10.42.1.0/29")))
             (signals gr8s::cni-error
               (gr8s::check-pod-address reopened "sandbox-a" "eth0"))
             (is (string= "10.42.1.1"
                          (gr8s::allocate-pod-address
                           reopened "sandbox-b" "eth0")))))
      (when (probe-file directory)
        (uiop:delete-directory-tree directory :validate t)))))

(defun write-node-ipam-state-for-test (directory cidr allocations)
  (ensure-directories-exist directory)
  (with-open-file (stream (merge-pathnames "allocations.json" directory)
                          :direction :output
                          :if-exists :supersede
                          :if-does-not-exist :create)
    (com.inuoe.jzon:stringify
     (gr8s::json-object
      "version" 1 "cidr" cidr
      "allocations"
      (coerce
       (mapcar (lambda (allocation)
                 (gr8s::json-object
                  "sandboxID" (first allocation)
                  "interfaceName" (second allocation)
                  "address" (third allocation)))
               allocations)
       'vector))
     :stream stream)))

(test node-ipam-rejects-conflicting-or-out-of-range-restored-state
  (let ((directory
          (merge-pathnames
           (format nil "gr8s-node-ipam-invalid-~36R/"
                   (random (expt 36 8)))
           (uiop:temporary-directory))))
    (unwind-protect
         (progn
           (write-node-ipam-state-for-test
            directory "10.42.2.0/29"
            '(("sandbox-a" "eth0" "10.42.2.1")
              ("sandbox-b" "eth0" "10.42.2.1")))
           (signals gr8s::cni-error
             (gr8s::open-node-ipam directory "10.42.2.0/29"))
           (write-node-ipam-state-for-test
            directory "10.42.2.0/29"
            '(("sandbox-a" "eth0" "10.42.3.1")))
           (signals gr8s::cni-error
             (gr8s::open-node-ipam directory "10.42.2.0/29"))
           (delete-file (merge-pathnames "allocations.json" directory))
           (signals gr8s::cni-error
             (gr8s::open-node-ipam directory "10.42.2.1/29")))
      (when (probe-file directory)
        (uiop:delete-directory-tree directory :validate t)))))

(test node-ipam-supports-more-than-250-pods-and-types-exhaustion
  (let ((directory
          (merge-pathnames
           (format nil "gr8s-node-ipam-capacity-~36R/"
                   (random (expt 36 8)))
           (uiop:temporary-directory))))
    (unwind-protect
         (let* ((ipam (gr8s::open-node-ipam directory "10.42.16.0/20"))
                (addresses
                  (loop for index from 1 to 300
                        collect
                        (gr8s::allocate-pod-address
                         ipam (format nil "sandbox-~D" index) "eth0"))))
           (is (= 300 (length (remove-duplicates addresses :test #'string=))))
           (is (string= "10.42.16.1" (first addresses)))
           (is (string= "10.42.17.44" (car (last addresses))))
           (let ((reopened
                   (gr8s::open-node-ipam directory "10.42.16.0/20")))
             (is (string= "10.42.17.44"
                          (gr8s::check-pod-address
                           reopened "sandbox-300" "eth0")))))
      (when (probe-file directory)
        (uiop:delete-directory-tree directory :validate t))))
  (let ((directory
          (merge-pathnames
           (format nil "gr8s-node-ipam-exhausted-~36R/"
                   (random (expt 36 8)))
           (uiop:temporary-directory))))
    (unwind-protect
         (let ((ipam (gr8s::open-node-ipam directory "192.0.2.0/30")))
           (is (string= "192.0.2.1"
                        (gr8s::allocate-pod-address ipam "one" "eth0")))
           (is (string= "192.0.2.2"
                        (gr8s::allocate-pod-address ipam "two" "eth0")))
           (signals gr8s::cni-error
             (gr8s::allocate-pod-address ipam "three" "eth0")))
      (when (probe-file directory)
        (uiop:delete-directory-tree directory :validate t)))))

(test node-ipam-rolls-back-memory-when-persistence-fails
  (let ((directory
          (merge-pathnames
           (format nil "gr8s-node-ipam-rollback-~36R/"
                   (random (expt 36 8)))
           (uiop:temporary-directory)))
        (fail-p t))
    (unwind-protect
         (let ((ipam
                 (gr8s::open-node-ipam
                  directory "10.42.32.0/29"
                  :persister
                  (lambda (candidate)
                    (if fail-p
                        (error "injected persistence failure")
                        (gr8s::persist-node-ipam-state candidate))))))
           (signals error
             (gr8s::allocate-pod-address ipam "sandbox-a" "eth0"))
           (setf fail-p nil)
           (is (string= "10.42.32.1"
                        (gr8s::allocate-pod-address
                         ipam "sandbox-b" "eth0")))
           (setf fail-p t)
           (signals error
             (gr8s::release-pod-address ipam "sandbox-b" "eth0"))
           (is (string= "10.42.32.1"
                        (gr8s::check-pod-address
                         ipam "sandbox-b" "eth0"))))
      (when (probe-file directory)
        (uiop:delete-directory-tree directory :validate t)))))
