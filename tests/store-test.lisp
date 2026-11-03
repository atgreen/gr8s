(in-package #:gr8s/tests)

(in-suite gr8s)

(test generated-uids-have-rfc-4122-version-and-variant-bits
  (is (string=
       "00010203-0405-4607-8809-0A0B0C0D0E0F"
       (gr8s::generate-uid
        #(0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15)))))

(defmacro with-temporary-store ((store path) &body body)
  `(let* ((,path (merge-pathnames
                  (format nil "gr8s-test-~36R/" (random (expt 36 8)))
                  (uiop:temporary-directory)))
          (,store (open-store ,path)))
     (unwind-protect (progn ,@body)
       (uiop:delete-directory-tree ,path :validate t :if-does-not-exist :ignore))))

(test store-persists-pods-across-instances
  (with-temporary-store (store path)
    (let ((created (create-pod store (parse-pod *valid-pod-json*))))
      (is (plusp (length (pod-uid created))))
      (is (string= "1" (pod-resource-version created)))
      (is (string= "hello" (pod-name (get-pod store "default" "hello"))))
      (is (= 1 (length (list-pods store "default"))))
      (let ((reopened (open-store path)))
        (is (string= (pod-uid created)
                     (pod-uid (get-pod reopened "default" "hello"))))))))

(test store-updates-with-optimistic-concurrency
  (with-temporary-store (store path)
    (create-pod store (parse-pod *valid-pod-json*))
    (let ((updated (update-pod store (parse-pod *valid-pod-json*) "1")))
      (is (string= "2" (pod-resource-version updated))))
    (handler-case
        (progn
          (update-pod store (parse-pod *valid-pod-json*) "1")
          (fail "Expected a resource version conflict"))
      (kubernetes-error (error)
        (is (string= "Conflict" (kubernetes-error-reason error)))))))

(test store-deletes-the-record-and-its-file
  (with-temporary-store (store path)
    (create-pod store (parse-pod *valid-pod-json*))
    (delete-pod store "default" "hello")
    (is (null (list-pods store "default")))
    (is (null (directory (merge-pathnames "*.json" path))))))

(test concurrent-creates-produce-one-pod-and-one-record
  (with-temporary-store (store path)
    (let ((outcomes (make-array 2))
          (start-lock (bt:make-lock))
          (start-condition (bt:make-condition-variable))
          (ready 0))
      (labels ((create-at-once (index)
                 (bt:with-lock-held (start-lock)
                   (incf ready)
                   (if (= ready 2)
                       (bt:condition-notify start-condition)
                       (loop while (< ready 2)
                             do (bt:condition-wait start-condition start-lock))))
                 (setf (aref outcomes index)
                       (handler-case
                           (progn
                             (create-pod store (parse-pod *valid-pod-json*))
                             :created)
                         (kubernetes-error (error)
                           (if (string= "AlreadyExists"
                                        (kubernetes-error-reason error))
                               :conflict
                               (error error)))))))
        (let ((threads
                (loop for index below 2
                      collect (let ((thread-index index))
                                (bt:make-thread
                                 (lambda () (create-at-once thread-index)))))))
          (mapc #'bt:join-thread threads)))
      (is (= 1 (count :created outcomes)))
      (is (= 1 (count :conflict outcomes)))
      (is (= 1 (length (list-pods store "default"))))
      (is (= 1 (length (directory (merge-pathnames "*.json" path)))))
      (is (null (directory (merge-pathnames "*.tmp" path)))))))
