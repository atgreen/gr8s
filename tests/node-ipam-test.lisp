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

(test node-ipam-dual-family-allocations-are-atomic-and-survive-restart
  (let ((directory
          (merge-pathnames
           (format nil "gr8s-node-ipam-dual-~36R/" (random (expt 36 8)))
           (uiop:temporary-directory)))
        (cidrs '("10.42.0.0/29" "fd42::/125")))
    (unwind-protect
         (let* ((ipam (gr8s::open-node-ipam directory cidrs))
                (first (gr8s::allocate-pod-addresses ipam "sandbox-a" "eth0"))
                (second (gr8s::allocate-pod-addresses ipam "sandbox-b" "eth0")))
           (is (equal '("10.42.0.1" "fd42::1") first))
           (is (equal '("10.42.0.2" "fd42::2") second))
           (is (equal first
                      (gr8s::allocate-pod-addresses
                       ipam "sandbox-a" "eth0")))
           (let ((reopened (gr8s::open-node-ipam directory cidrs)))
             (is (equal first
                        (gr8s::check-pod-addresses
                         reopened "sandbox-a" "eth0")))
             (is (equal second
                        (gr8s::check-pod-addresses
                         reopened "sandbox-b" "eth0")))
             ;; Singular callers retain the primary-family compatibility view.
             (is (string= "10.42.0.1"
                          (gr8s::check-pod-address
                           reopened "sandbox-a" "eth0")))
             (is (null (gr8s::release-pod-address
                        reopened "sandbox-a" "eth0"))))
           (let ((reopened (gr8s::open-node-ipam directory cidrs)))
             (signals gr8s::cni-error
               (gr8s::check-pod-addresses reopened "sandbox-a" "eth0"))
             (is (equal '("10.42.0.1" "fd42::1")
                        (gr8s::allocate-pod-addresses
                         reopened "sandbox-c" "eth0")))))
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

(test service-snat-ipam-leases-survive-restart-without-changing-pod-addresses
  (let* ((directory (merge-pathnames (format nil "gr8s-snat-ipam-~36R/" (random (expt 36 8)))
                                    (uiop:temporary-directory)))
         (cidrs '("fd42::/125" "10.42.0.0/29")))
    (unwind-protect
         (let* ((ipam (gr8s::open-node-ipam directory cidrs))
                (addresses (gr8s::allocate-pod-addresses ipam "a" "eth0")))
           (is (= 2 (gethash "version" (gr8s::node-ipam-state-object ipam))))
           (is (equal '("fd42::1" "10.42.0.1") addresses))
           (is (equal "10.42.0.2" (gr8s.network::allocate-service-snat-address ipam "a" "eth0")))
           (is (equal "10.42.0.2" (gr8s.network::allocate-service-snat-address ipam "a" "eth0")))
           (is (equal addresses (gr8s::check-pod-addresses ipam "a" "eth0")))
           (is (= 1 (hash-table-count (gr8s::node-ipam-allocations ipam))))
           (is (equal '("fd42::2" "10.42.0.3") (gr8s::allocate-pod-addresses ipam "b" "eth0")))
           (let* ((state (gr8s::node-ipam-state-object ipam))
                  (restored (gr8s::open-node-ipam directory cidrs)))
             (is (= 3 (gethash "version" state)))
             (is (equal cidrs (coerce (gethash "cidrs" state) 'list)))
             (is (= 1 (length (gethash "serviceSNATAllocations" state))))
             (is (equal addresses (gr8s::check-pod-addresses restored "a" "eth0")))
             (is (equal "10.42.0.2" (gr8s.network::allocate-service-snat-address restored "a" "eth0")))
             (gr8s::release-pod-address restored "a" "eth0")
             (gr8s::reload-node-ipam-allocations ipam)
             (is (zerop (hash-table-count (gr8s.network::node-ipam-service-snat-allocations ipam))))
             (is (= 2 (gethash "version" (gr8s::node-ipam-state-object ipam))))
             (is (equal addresses (gr8s::allocate-pod-addresses ipam "c" "eth0")))
             (is (equal "10.42.0.2" (gr8s.network::allocate-service-snat-address ipam "c" "eth0")))))
      (uiop:delete-directory-tree directory :validate t :if-does-not-exist :ignore))))

(test service-snat-ipam-allocation-and-release-roll-back-together
  (let ((directory (merge-pathnames (format nil "gr8s-snat-rollback-~36R/" (random (expt 36 8)))
                                   (uiop:temporary-directory)))
        (fail nil))
    (unwind-protect
         (let ((ipam (gr8s::open-node-ipam directory "10.42.0.0/29"
                       :persister (lambda (candidate)
                                    (when fail (error "injected SNAT persist failure"))
                                    (gr8s::persist-node-ipam-state candidate)))))
           (gr8s::allocate-pod-address ipam "a" "eth0")
           (setf fail t)
           (signals error (gr8s.network::allocate-service-snat-address ipam "a" "eth0"))
           (is (zerop (hash-table-count (gr8s.network::node-ipam-service-snat-allocations ipam))))
           (is (= 1 (gethash "version" (gr8s::node-ipam-state-object ipam))))
           (setf fail nil)
           (is (equal "10.42.0.2" (gr8s.network::allocate-service-snat-address ipam "a" "eth0")))
           (setf fail t)
           ;; Idempotent lease reads do not need a write and still succeed.
           (is (equal "10.42.0.2" (gr8s.network::allocate-service-snat-address ipam "a" "eth0")))
           (signals error (gr8s::release-pod-address ipam "a" "eth0"))
           (is (equal "10.42.0.1" (gr8s::check-pod-address ipam "a" "eth0")))
           (is (equal "10.42.0.2" (gr8s.network::allocate-service-snat-address ipam "a" "eth0")))
           (let ((restored (gr8s::open-node-ipam directory "10.42.0.0/29")))
             (is (equal "10.42.0.2" (gr8s.network::allocate-service-snat-address restored "a" "eth0")))))
      (uiop:delete-directory-tree directory :validate t :if-does-not-exist :ignore))))

(test service-snat-ipam-exhaustion-does-not-consume-a-pod-lease
  (let ((directory (merge-pathnames (format nil "gr8s-snat-capacity-~36R/" (random (expt 36 8)))
                                   (uiop:temporary-directory))))
    (unwind-protect
         (let ((ipam (gr8s::open-node-ipam directory "192.0.2.0/30")))
           (signals gr8s::cni-error (gr8s.network::allocate-service-snat-address ipam "missing" "eth0"))
           (is (= 1 (gethash "version" (gr8s::node-ipam-state-object ipam))))
           (gr8s::allocate-pod-address ipam "a" "eth0")
           (gr8s::allocate-pod-address ipam "b" "eth0")
           (signals gr8s::cni-error (gr8s.network::allocate-service-snat-address ipam "a" "eth0"))
           (is (equal "192.0.2.1" (gr8s::check-pod-address ipam "a" "eth0")))
           (is (zerop (hash-table-count (gr8s.network::node-ipam-service-snat-allocations ipam))))
           (gr8s::release-pod-address ipam "b" "eth0")
           (is (equal "192.0.2.2" (gr8s.network::allocate-service-snat-address ipam "a" "eth0")))
           (signals gr8s::cni-error (gr8s::allocate-pod-address ipam "b" "eth0"))
           (gr8s::release-pod-address ipam "a" "eth0")
           (is (equal "192.0.2.1" (gr8s::allocate-pod-address ipam "b" "eth0"))))
      (uiop:delete-directory-tree directory :validate t :if-does-not-exist :ignore))))

(test service-snat-ipam-rejects-orphans-conflicts-and-malformed-state-atomically
  (let ((directory (merge-pathnames (format nil "gr8s-snat-invalid-~36R/" (random (expt 36 8)))
                                   (uiop:temporary-directory))))
    (unwind-protect
         (let ((ipam (gr8s::open-node-ipam directory "10.42.0.0/29")))
           (gr8s::allocate-pod-address ipam "a" "eth0")
           (gr8s.network::allocate-service-snat-address ipam "a" "eth0")
           (gr8s::allocate-pod-address ipam "b" "eth0")
           (let ((valid (gr8s::node-ipam-state-object ipam)))
             (dolist (invalid (list nil "bad"
                                   (vector (gr8s::json-object "sandboxID" "missing" "interfaceName" "eth0" "address" "10.42.0.2"))
                                   (vector (gr8s::json-object "sandboxID" "a" "interfaceName" "eth0" "address" "10.42.0.1"))
                                   (vector (gr8s::json-object "sandboxID" "a" "interfaceName" "eth0" "address" "10.42.1.2"))
                                   (vector (gr8s::json-object "sandboxID" "a" "interfaceName" "eth0" "address" "10.42.0.0"))
                                   (vector (gr8s::json-object "sandboxID" "a" "interfaceName" "eth0" "address" "10.42.0.7"))
                                   (vector (gr8s::json-object "sandboxID" "a" "interfaceName" "eth0" "address" "10.42.0.02"))
                                   (concatenate 'vector (gethash "serviceSNATAllocations" valid)
                                                        (gethash "serviceSNATAllocations" valid))
                                   (concatenate 'vector (gethash "serviceSNATAllocations" valid)
                                     (vector (gr8s::json-object "sandboxID" "b" "interfaceName" "eth0"
                                                               "address" "10.42.0.2")))))
               (let ((state (gr8s::copy-core-object valid)))
                 (setf (gethash "serviceSNATAllocations" state) invalid)
                 (with-open-file (s (gr8s::node-ipam-state-path ipam) :direction :output :if-exists :supersede)
                   (com.inuoe.jzon:stringify state :stream s)))
               (signals gr8s::cni-error (gr8s::reload-node-ipam-allocations ipam))
               (is (equal "10.42.0.1" (gr8s::check-pod-address ipam "a" "eth0")))
               (is (equal "10.42.0.2" (gr8s.network::allocate-service-snat-address ipam "a" "eth0")))))
           (let ((state (gr8s::node-ipam-state-object ipam)))
             (setf (gethash "version" state) 2)
             (with-open-file (s (gr8s::node-ipam-state-path ipam) :direction :output :if-exists :supersede)
               (com.inuoe.jzon:stringify state :stream s))
             (signals gr8s::cni-error (gr8s::reload-node-ipam-allocations ipam))))
      (uiop:delete-directory-tree directory :validate t :if-does-not-exist :ignore))))

(test service-snat-ipam-preserves-old-ipv4-spellings-and-rejects-ipv6-only-pools
  (let ((directory (merge-pathnames (format nil "gr8s-snat-legacy-~36R/" (random (expt 36 8)))
                                   (uiop:temporary-directory))))
    (unwind-protect
         (progn
           (write-node-ipam-state-for-test directory "10.42.0.0/29"
                                          '(("a" "eth0" "10.42.0.01")))
           (let ((ipam (gr8s::open-node-ipam directory "10.42.0.0/29")))
             (is (equal "10.42.0.2" (gr8s::allocate-pod-address ipam "b" "eth0")))
             (is (equal "10.42.0.3" (gr8s.network::allocate-service-snat-address ipam "a" "eth0")))
             (is (equal "10.42.0.01" (gr8s::check-pod-address ipam "a" "eth0")))))
      (uiop:delete-directory-tree directory :validate t :if-does-not-exist :ignore)))
  (let ((directory (merge-pathnames (format nil "gr8s-snat-v6-~36R/" (random (expt 36 8)))
                                   (uiop:temporary-directory))))
    (unwind-protect
         (let ((ipam (gr8s::open-node-ipam directory "fd42::/125")))
           (gr8s::allocate-pod-address ipam "a" "eth0")
           (signals gr8s::cni-error (gr8s.network::allocate-service-snat-address ipam "a" "eth0"))
           (is (equal '("fd42::1") (gr8s::check-pod-addresses ipam "a" "eth0")))
           (is (zerop (hash-table-count (gr8s.network::node-ipam-service-snat-allocations ipam)))))
      (uiop:delete-directory-tree directory :validate t :if-does-not-exist :ignore))))
