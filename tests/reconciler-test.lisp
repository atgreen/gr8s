(in-package #:gr8s/tests)

(in-suite gr8s)

(test reconciliation-is-idempotent-and-replaces-changed-pods
  (with-temporary-store (store path)
    (let* ((pod (create-pod store (parse-pod *valid-pod-json*)))
           (runtime (make-fake-runtime))
           (reconciler (make-reconciler store runtime)))
      (is (string= "Running"
                   (gethash "phase" (reconcile-pod reconciler "default" "hello"))))
      (is (= 1 (fake-runtime-ensure-count runtime)))
      (reconcile-pod reconciler "default" "hello")
      (is (= 1 (fake-runtime-ensure-count runtime)))
      (update-pod store (parse-pod *valid-pod-json*) "1")
      (reconcile-pod reconciler "default" "hello")
      (is (= 2 (fake-runtime-ensure-count runtime)))
      (is (string= "2"
                   (runtime-pod-resource-version
                    (runtime-observe runtime (pod-uid pod))))))))

(test deletion-converges-before-removing-desired-state
  (with-temporary-store (store path)
    (let* ((pod (create-pod store (parse-pod *valid-pod-json*)))
           (runtime (make-fake-runtime))
           (reconciler (make-reconciler store runtime)))
      (reconcile-pod reconciler "default" "hello")
      (let ((foreign (create-pod store
                                 (parse-pod
                                  "{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"name\":\"foreign\"},\"spec\":{\"containers\":[{\"name\":\"main\",\"image\":\"busybox\"}]}}"))))
        (reconcile-pod reconciler "default" "foreign")
        (mark-pod-deleting store "default" "hello")
        (reconcile-pod reconciler "default" "hello")
        (is (null (runtime-observe runtime (pod-uid pod))))
        (is (runtime-observe runtime (pod-uid foreign)))
        (signals kubernetes-error (get-pod store "default" "hello"))))))

(test deletion-request-is-serialized-with-background-reconciliation
  (with-temporary-store (store path)
    (create-pod store (parse-pod *valid-pod-json*))
    (let* ((runtime (make-fake-runtime))
           (reconciler (make-reconciler store runtime))
           (finished nil)
           (thread nil))
      (reconcile-pod reconciler "default" "hello")
      (bt:with-lock-held ((gr8s::reconciler-lock reconciler))
        (setf thread
              (bt:make-thread
               (lambda ()
                 (gr8s::delete-reconciled-pod
                  reconciler "default" "hello")
                 (setf finished t))))
        (sleep 0.02)
        (is (not finished)))
      (bt:join-thread thread)
      (is (eq t finished))
      (signals kubernetes-error
        (get-pod store "default" "hello")))))

(test retryable-runtime-failures-become-pending-status
  (with-temporary-store (store path)
    (create-pod store (parse-pod *valid-pod-json*))
    (let* ((runtime (make-fake-runtime))
           (reconciler (make-reconciler store runtime)))
      (set-fake-runtime-failure runtime "temporary runtime failure")
      (let ((status (reconcile-pod reconciler "default" "hello")))
        (is (string= "Pending" (gethash "phase" status)))
        (is (string= "RuntimeError" (gethash "reason" status))))
      (is (string= "Running"
                   (gethash "phase"
                            (reconcile-pod reconciler "default" "hello")))))))

(test reconcile-all-visits-every-desired-pod
  (with-temporary-store (store path)
    (create-pod store (parse-pod *valid-pod-json*))
    (let* ((runtime (make-fake-runtime))
           (reconciler (make-reconciler store runtime)))
      (is (= 1 (length (reconcile-all reconciler))))
      (is (= 1 (fake-runtime-ensure-count runtime))))))

(test always-restart-policy-reconverges-an-exited-runtime-pod
  (with-temporary-store (store path)
    (let* ((pod (create-pod store (parse-pod *valid-pod-json*)))
           (runtime (make-fake-runtime))
           (reconciler (make-reconciler store runtime)))
      (reconcile-pod reconciler "default" "hello")
      (setf (runtime-pod-phase (runtime-observe runtime (pod-uid pod)))
            "Succeeded")
      (reconcile-pod reconciler "default" "hello")
      (is (= 2 (fake-runtime-ensure-count runtime))))))

(test log-reads-are-serialized-with-reconciliation
  (let* ((runtime (make-fake-runtime))
         (reconciler (make-reconciler nil runtime))
         (finished nil)
         (thread nil))
    (bt:with-lock-held ((gr8s::reconciler-lock reconciler))
      (setf thread
            (bt:make-thread
             (lambda ()
               (reconciler-logs reconciler "uid" "main")
               (setf finished t))))
      (sleep 0.02)
      (is (not finished)))
    (bt:join-thread thread)
    (is (eq t finished))))

(test fake-runtime-exec-records-the-complete-stream-request
  (let ((runtime (make-fake-runtime)))
    (gr8s::set-fake-runtime-exec-url
     runtime "http://127.0.0.1:1234/exec/token")
    (is (string= "http://127.0.0.1:1234/exec/token"
                 (gr8s::runtime-exec-url
                  runtime "pod-uid" "main" '("sh" "-i")
                  :stdin t :stdout t :stderr nil :tty t)))
    (is (equal '("pod-uid" "main" ("sh" "-i") t t nil t)
               (gr8s::fake-runtime-last-exec runtime)))))
