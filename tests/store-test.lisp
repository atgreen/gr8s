(in-package #:gr8s/tests)

(in-suite gr8s)

(test generated-uids-have-rfc-4122-version-and-variant-bits
  (is (string=
       "00010203-0405-4607-8809-0a0b0c0d0e0f"
       (gr8s::generate-uid
        #(0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15)))))

(defmacro with-temporary-store ((store path) &body body)
  "Reserve an independent store directory atomically, including across test processes."
  `(let ((,path (uiop:ensure-directory-pathname
                (sb-posix:mkdtemp
                 (namestring (merge-pathnames "gr8s-test-XXXXXX" (uiop:temporary-directory)))))))
     (unwind-protect (let ((,store (open-store ,path))) ,@body)
       (uiop:delete-directory-tree ,path :validate t :if-does-not-exist :ignore))))

;; Order is the point: data before the rename, and the directory entry after it.
(test pod-writes-flush-data-before-the-rename-and-the-directory-after
  (with-temporary-store (store path)
    (let* ((synced nil)
           (gr8s::*durable-sync*
             (lambda (target)
               (push (list (namestring target)
                           (not (null (directory (merge-pathnames "*.json" path)))))
                     synced)))
           (pod (create-pod store (parse-pod *valid-pod-json*))))
      ;; The Pod's own file comes last, after the revision high-water mark it depends on.
      (destructuring-bind ((file before-rename) (directory after-rename)) (last (reverse synced) 2)
        (is (search ".tmp" file))
        (is (not before-rename) "the temporary is flushed while the target does not exist yet")
        (is (equal (namestring path) directory))
        (is-true after-rename "the directory is flushed once the entry is in place"))
      (is (probe-file (gr8s::pod-path store pod))))))

(test a-failed-flush-publishes-nothing
  (with-temporary-store (store path)
    (let ((gr8s::*durable-sync* (lambda (target) (declare (ignore target)) (error "disk failure"))))
      (signals error (create-pod store (parse-pod *valid-pod-json*))))
    (signals kubernetes-error (get-pod store "default" "hello"))
    (is (null (directory (merge-pathnames "*.json" path))))
    (is (null (list-pods (open-store path))))))

(test removing-a-pod-flushes-its-directory
  (with-temporary-store (store path)
    (create-pod store (parse-pod *valid-pod-json*))
    (let* ((synced nil)
           (gr8s::*durable-sync* (lambda (target) (push (namestring target) synced))))
      (gr8s::remove-pod store "default" "hello")
      (is (member (namestring path) synced :test #'equal)))))

(test sync-path-flushes-real-files-and-directories
  (with-temporary-store (store path)
    (values store)
    (let ((file (merge-pathnames "probe" path)))
      (with-open-file (out file :direction :output) (write-string "x" out))
      (finishes (gr8s::sync-path file))
      (finishes (gr8s::sync-path path))
      (signals error (gr8s::sync-path (merge-pathnames "missing" path))))))

(test temporary-stores-remain-isolated-with-identical-random-states
  (let ((seed (make-random-state nil)) (first-path nil))
    (let ((*random-state* (make-random-state seed)))
      (with-temporary-store (first-store path)
        (setf first-path path)
        (create-pod first-store (parse-pod *valid-pod-json*))
        (let ((*random-state* (make-random-state seed)))
          (with-temporary-store (second-store other-path)
            (is (not (equal path other-path)))
            (is (null (list-pods second-store "default")))
            (create-pod second-store (parse-pod *valid-pod-json*))
            (is (= 1 (length (list-pods first-store "default"))))))))
    (is (not (probe-file first-path)))))

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
