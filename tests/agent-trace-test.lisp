(in-package #:gr8s/tests)

(in-suite gr8s)

(test trace-compiler-ands-exact-cgroup-scope-with-user-predicate
  "Every probe retains its predicate and is restricted to the requested cgroups."
  (let* ((generated
           (gr8s.agent::compile-cgroup-scoped-trace
            "kprobe:tcp_sendmsg /pid == 42/ { @[comm] = count(); }"
            '(101 202)))
         (program (first (getf generated :progs)))
         (text (prin1-to-string program)))
    (is (= 1 (length (getf generated :progs))))
    (is (search "GET-CURRENT-CGROUP-ID" text))
    (is (search "101" text))
    (is (search "202" text))
    (is (search "GET-CURRENT-PID-TGID" text))))

(test trace-compiler-rejects-an-empty-cgroup-scope
  (signals gr8s.runtime:runtime-error
    (gr8s.agent::compile-cgroup-scoped-trace
     "kprobe:tcp_sendmsg { @ = count(); }" nil)))

(test trace-compiler-enforces-request-limits
  (signals gr8s.runtime:runtime-error
    (gr8s.agent::compile-cgroup-scoped-trace
     (make-string (1+ gr8s.agent::+trace-max-source-bytes+)
                  :initial-element #\Space)
     '(101)))
  (signals gr8s.runtime:runtime-error
    (gr8s.agent::compile-cgroup-scoped-trace
     "kprobe:tcp_sendmsg { @ = count(); }"
     '(101)
     :duration-milliseconds
     (1+ gr8s.agent::+trace-max-duration-milliseconds+)))
  (signals gr8s.runtime:runtime-error
    (gr8s.agent::compile-cgroup-scoped-trace
     "kprobe:tcp_sendmsg { @ = count(); }"
     '(101)
     :duration-milliseconds 0)))

(test trace-compiler-rejects-userspace-probes
  (signals gr8s.runtime:runtime-error
    (gr8s.agent::compile-cgroup-scoped-trace
     "uprobe:/usr/lib64/libc.so.6:malloc { @[comm] = count(); }"
     '(101)))
  (signals gr8s.runtime:runtime-error
    (gr8s.agent::compile-cgroup-scoped-trace
     "uretprobe:/usr/lib64/libc.so.6:malloc { @[comm] = count(); }"
     '(101))))

(test trace-compiler-enforces-generated-program-limit
  (signals gr8s.runtime:runtime-error
    (gr8s.agent::enforce-trace-program-limit
     (list :progs
           (make-list (1+ gr8s.agent::+trace-max-programs+))))))

(test trace-cgroup-resolution-selects-every-container-in-exact-pods
  (let* ((pods (list (gr8s.model::make-pod :uid "uid-a" :name "web-a"
                                     :namespace "alpha" :containers #())
                     (gr8s.model::make-pod :uid "uid-b" :name "web-b"
                                     :namespace "alpha" :containers #())))
         (entries
           (list (gr8s.kubelet::make-cadvisor-entry
                  :pod "web-a" :namespace "alpha" :container ""
                  :directory "/cg/sandbox-a/")
                 (gr8s.kubelet::make-cadvisor-entry
                  :pod "web-a" :namespace "alpha" :container "main"
                  :directory "/cg/container-a/")
                 (gr8s.kubelet::make-cadvisor-entry
                  :pod "web-b" :namespace "alpha" :container "main"
                  :directory "/cg/container-b/"))))
    (is (equal '(11 12)
               (gr8s.agent::resolve-trace-cgroup-ids
                pods '("uid-a") entries
                :inode-function
                (lambda (directory)
                  (cdr (assoc directory
                              '(("/cg/sandbox-a/" . 11)
                                ("/cg/container-a/" . 12)
                                ("/cg/container-b/" . 21))
                              :test #'equal))))))
    (signals gr8s.runtime:runtime-error
      (gr8s.agent::resolve-trace-cgroup-ids pods '("missing") entries
                                             :inode-function (constantly 1)))))

(defun trace-request-for-test (&key (id "trace-1") (source "kprobe:do_sys_open { printf(\"hit\\n\"); }")
                                    (duration 1000))
  (make-instance 'gr8s.node.v1::operation-request
                 :operation-id id
                 :kind gr8s.node.v1::+operationkind-operation_kind_trace+
                 :trace-source source
                 :trace-pod-uids '("pod-a")
                 :trace-duration-milliseconds duration
                 :acknowledges-output t))

(test trace-operation-accepts-after-attach-streams-output-and-completes
  (let* ((runtime (gr8s.agent::%make-node-runtime :runtime t))
         (events nil)
         (compiled-cgroups nil)
         (gr8s.agent::*trace-cgroup-id-function* (lambda (node request)
                                                    (declare (ignore node request))
                                                    '(101 202)))
         (gr8s.agent::*trace-compile-function*
           (lambda (source ids &key duration-milliseconds)
             (declare (ignore source duration-milliseconds))
             (setf compiled-cgroups ids)
             '(:progs (:fake))))
         (gr8s.agent::*trace-run-function*
           (lambda (generated attached cancelled-p)
             (declare (ignore generated cancelled-p))
             (funcall attached)
             (format t "hit~%"))))
    (gr8s.agent::dispatch-node-operation
     runtime :operation-request (trace-request-for-test)
     (lambda (variant payload) (push (cons variant payload) events)))
    (is-true (wait-until (lambda ()
                           (find :operation-response events :key #'car))
                         :timeout 2))
    (is (equal '(101 202) compiled-cgroups))
    (let ((ordered (reverse events)))
      (is (equal '(:operation-response :operation-stream :operation-response)
                 (mapcar #'car ordered)))
      (is (= gr8s.node.v1::+operationstatus-operation_status_accepted+
             (slot-value (cdr (first ordered)) 'gr8s.node.v1::status)))
      (is (string= (format nil "hit~%")
                   (trivial-utf-8:utf-8-bytes-to-string
                    (slot-value (cdr (second ordered)) 'gr8s.node.v1::data))))
      (is (= gr8s.node.v1::+operationstatus-operation_status_complete+
             (slot-value (cdr (third ordered)) 'gr8s.node.v1::status))))))

(test trace-operation-cancel-waits-for-runner-cleanup-before-terminal-response
  (let* ((runtime (gr8s.agent::%make-node-runtime :runtime t))
         (events nil)
         (cleaned nil)
         (gr8s.agent::*trace-cgroup-id-function* (lambda (&rest ignored)
                                                    (declare (ignore ignored)) '(101)))
         (gr8s.agent::*trace-compile-function* (lambda (&rest ignored)
                                                  (declare (ignore ignored)) '(:progs (:fake))))
         (gr8s.agent::*trace-run-function*
           (lambda (generated attached cancelled-p)
             (declare (ignore generated))
             (unwind-protect
                  (progn
                    (funcall attached)
                    (loop until (funcall cancelled-p) do (sleep 0.01)))
               (setf cleaned t)))))
    (gr8s.agent::dispatch-node-operation
     runtime :operation-request (trace-request-for-test :id "cancel-me")
     (lambda (variant payload) (push (cons variant payload) events)))
    (is-true (wait-until (lambda () (plusp (length events))) :timeout 2))
    (gr8s.agent::dispatch-node-operation
     runtime :operation-cancel
     (make-instance 'gr8s.node.v1::operation-cancel
                    :operation-id "cancel-me" :reason "client left")
     (lambda (variant payload) (push (cons variant payload) events)))
    (is-true (wait-until (lambda () cleaned) :timeout 2))
    (is-true (wait-until (lambda () (= 2 (length events))) :timeout 2))
    (let ((terminal (cdar events)))
      (is (= gr8s.node.v1::+operationstatus-operation_status_failed+
             (slot-value terminal 'gr8s.node.v1::status)))
      (is (string= "client left"
                   (slot-value terminal 'gr8s.node.v1::error-message))))))

(test trace-operation-deadline-cleans-up-and-completes-successfully
  (let* ((runtime (gr8s.agent::%make-node-runtime :runtime t))
         (events nil)
         (cleaned nil)
         (gr8s.agent::*trace-cgroup-id-function* (lambda (&rest ignored)
                                                    (declare (ignore ignored)) '(101)))
         (gr8s.agent::*trace-compile-function* (lambda (&rest ignored)
                                                  (declare (ignore ignored)) '(:progs (:fake))))
         (gr8s.agent::*trace-run-function*
           (lambda (generated attached cancelled-p)
             (declare (ignore generated))
             (unwind-protect
                  (progn (funcall attached)
                         (loop until (funcall cancelled-p) do (sleep 0.001)))
               (setf cleaned t)))))
    (gr8s.agent::dispatch-node-operation
     runtime :operation-request (trace-request-for-test :id "deadline" :duration 10)
     (lambda (variant payload) (push (cons variant payload) events)))
    (is-true (wait-until (lambda () (= 2 (length events))) :timeout 2))
    (is-true cleaned)
    (is (= gr8s.node.v1::+operationstatus-operation_status_complete+
           (slot-value (cdar events) 'gr8s.node.v1::status)))))

(test trace-operation-enforces-node-concurrency-and-output-limit
  (let* ((runtime (gr8s.agent::%make-node-runtime :runtime t))
         (events nil)
         (release nil)
         (gr8s.agent::*trace-cgroup-id-function* (lambda (&rest ignored)
                                                    (declare (ignore ignored)) '(101)))
         (gr8s.agent::*trace-compile-function* (lambda (&rest ignored)
                                                  (declare (ignore ignored)) '(:progs (:fake))))
         (gr8s.agent::*trace-run-function*
           (lambda (generated attached cancelled-p)
             (declare (ignore generated))
             (funcall attached)
             (loop until (or release (funcall cancelled-p)) do (sleep 0.01)))))
    (flet ((emit (variant payload) (push (cons variant payload) events)))
      (gr8s.agent::dispatch-node-operation
       runtime :operation-request (trace-request-for-test :id "first") #'emit)
      (is-true (wait-until (lambda () (plusp (length events))) :timeout 2))
      (gr8s.agent::dispatch-node-operation
       runtime :operation-request (trace-request-for-test :id "second") #'emit)
      (is-true (wait-until (lambda () (= 2 (length events))) :timeout 2))
      (is (= gr8s.node.v1::+operationstatus-operation_status_failed+
             (slot-value (cdar events) 'gr8s.node.v1::status)))
      (setf release t)
      (is-true (wait-until (lambda () (= 3 (length events))) :timeout 2))))
  (let* ((runtime (gr8s.agent::%make-node-runtime :runtime t))
         (events nil)
         (gr8s.agent::*trace-max-output-bytes* 4)
         (gr8s.agent::*trace-cgroup-id-function* (lambda (&rest ignored)
                                                    (declare (ignore ignored)) '(101)))
         (gr8s.agent::*trace-compile-function* (lambda (&rest ignored)
                                                  (declare (ignore ignored)) '(:progs (:fake))))
         (gr8s.agent::*trace-run-function*
           (lambda (generated attached cancelled-p)
             (declare (ignore generated cancelled-p))
             (funcall attached)
             (write-string "too much"))))
    (gr8s.agent::dispatch-node-operation
     runtime :operation-request (trace-request-for-test :id "overflow")
     (lambda (variant payload) (push (cons variant payload) events)))
    (is-true (wait-until (lambda ()
                           (find gr8s.node.v1::+operationstatus-operation_status_failed+
                                 events :key (lambda (event)
                                               (and (eq (car event) :operation-response)
                                                    (slot-value (cdr event)
                                                                'gr8s.node.v1::status)))))
                         :timeout 2))))

(test trace-operation-input-acknowledges-output-without-ending-the-trace
  (let* ((runtime (gr8s.agent::%make-node-runtime :runtime t))
         (events nil)
         (release nil)
         (gr8s.agent::*trace-cgroup-id-function* (lambda (&rest ignored)
                                                    (declare (ignore ignored)) '(101)))
         (gr8s.agent::*trace-compile-function* (lambda (&rest ignored)
                                                  (declare (ignore ignored)) '(:progs (:fake))))
         (gr8s.agent::*trace-run-function*
           (lambda (generated attached cancelled-p)
             (declare (ignore generated))
             (funcall attached)
             (loop until (or release (funcall cancelled-p)) do (sleep 0.01)))))
    (gr8s.agent::dispatch-node-operation
     runtime :operation-request (trace-request-for-test :id "ack-trace")
     (lambda (variant payload) (push (cons variant payload) events)))
    (is-true (wait-until (lambda () (plusp (length events))) :timeout 2))
    (let ((operation (gr8s.agent::find-node-exec-operation runtime "ack-trace")))
      (setf (gr8s.agent::node-exec-operation-unacknowledged-output operation) 100)
      (gr8s.agent::dispatch-node-operation
       runtime :operation-input
       (make-instance 'gr8s.node.v1::operation-input
                      :operation-id "ack-trace" :sequence 1
                      :channel gr8s.node.v1::+streamchannel-stream_channel_stdout+
                      :acknowledged-bytes 100)
       (lambda (variant payload) (push (cons variant payload) events)))
      (is (= 0 (gr8s.agent::node-exec-operation-unacknowledged-output operation)))
      (is-false (gr8s.agent::node-exec-operation-finished-p operation)))
    (setf release t)
    (is-true (wait-until (lambda () (= 2 (length events))) :timeout 2))))
