(in-package #:gr8s/tests)

(in-suite gr8s)

(test durable-store-has-an-explicit-package-boundary
  (let ((package (find-package "GR8S.STORE")))
    (is (not (null package)))
    (dolist (name '("MAKE-POD-STORE" "POD-STORE-PATH" "POD-STORE-PODS"
                    "POD-STORE-NODES" "POD-STORE-CONSENSUS-COMMIT-FN"))
      (multiple-value-bind (symbol status) (and package (find-symbol name package))
        (is (not (null symbol)) "~A is present in GR8S.STORE" name)
        (is (eq :external status) "~A is exported from GR8S.STORE" name)))))

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

(defmacro with-failing-core-writes ((message) &body body)
  "Run BODY while every durable core-resource write fails with MESSAGE: a checkpoint,
which goes through WRITE-PRIVATE-TEXT-ATOMICALLY, and a journal append."
  (let ((checkpoint (gensym "CHECKPOINT")) (journal (gensym "JOURNAL")))
    `(let ((,checkpoint (symbol-function 'gr8s::write-private-text-atomically))
           (,journal (symbol-function 'gr8s::append-core-journal-record)))
       (unwind-protect
            (progn
              (setf (symbol-function 'gr8s::write-private-text-atomically)
                    (lambda (&rest arguments) (declare (ignore arguments)) (error ,message))
                    (symbol-function 'gr8s::append-core-journal-record)
                    (lambda (&rest arguments) (declare (ignore arguments)) (error ,message)))
              ,@body)
         (setf (symbol-function 'gr8s::write-private-text-atomically) ,checkpoint
               (symbol-function 'gr8s::append-core-journal-record) ,journal)))))

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

(defun labelled-pod-json (json)
  "Return the Pod JSON text with a label added, so that writing it changes the Pod."
  (let ((object (com.inuoe.jzon:parse json)))
    (setf (gethash "labels" (gethash "metadata" object)) (gr8s::core-object "changed" "yes"))
    (com.inuoe.jzon:stringify object)))

(test store-updates-with-optimistic-concurrency
  (with-temporary-store (store path)
    (create-pod store (parse-pod *valid-pod-json*))
    ;; An unchanged update keeps the revision, as upstream's GuaranteedUpdate
    ;; (k8s.io/apiserver pkg/storage/etcd3/store.go) skips a write that changes nothing.
    (is (string= "1" (pod-resource-version (update-pod store (parse-pod *valid-pod-json*) "1"))))
    (let ((updated (update-pod store (parse-pod (labelled-pod-json *valid-pod-json*)) "1")))
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
