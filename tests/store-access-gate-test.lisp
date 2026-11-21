;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
(in-package #:gr8s/tests)
(def-suite store-access-gate :in gr8s)
(in-suite store-access-gate)

(defun assert-store-access-503 (function)
  (handler-case (progn (funcall function) (fail "Expected store access to be unavailable"))
    (gr8s.model::kubernetes-error (condition)
      (is (= 503 (gr8s.model::kubernetes-error-status-code condition))))))

(defun wait-for-store-access-block (store)
  (let ((deadline (+ (get-internal-real-time) (* 3 internal-time-units-per-second))))
    (loop
      (when (bt:with-lock-held ((gr8s.store::pod-store-lock store))
              (gr8s.store::pod-store-access-blocked store)) (return t))
      (when (> (get-internal-real-time) deadline) (error "Store never entered quiescence"))
      (sleep 0.005))))

(test quiescence-blocks-new-readers-and-writers-while-existing-request-drains
  (with-temporary-store (store root)
    (declare (ignore root))
    (ha-make-pod store "before")
    (let* ((entered (bt:make-semaphore)) (release (bt:make-semaphore))
           (request-result nil) (drain-result nil)
           (request (bt:make-thread
                     (lambda ()
                       (setf request-result
                             (handler-case
                                 (gr8s.store::call-with-store-request
                                  store (lambda ()
                                          (bt:signal-semaphore entered)
                                          (unless (bt:wait-on-semaphore release :timeout 5) (error "Lease release timeout"))
                                          (ha-make-pod store "inflight-write")))
                               (error (condition) condition))))))
           (drain nil))
      (unwind-protect
           (progn
             (is-true (bt:wait-on-semaphore entered :timeout 5))
             (setf drain (bt:make-thread
                          (lambda () (setf drain-result
                                           (handler-case (gr8s.store::quiesce-store-access store :timeout 5)
                                             (error (condition) condition))))))
             (wait-for-store-access-block store)
             (assert-store-access-503 (lambda () (gr8s.store::resume-store-access store)))
             (assert-store-access-503 (lambda () (gr8s.store::get-pod store "default" "before")))
             (assert-store-access-503 (lambda () (ha-make-pod store "rejected")))
             (assert-store-access-503 (lambda () (gr8s.store::call-with-store-request store (lambda () t))))
             (bt:signal-semaphore release)
             (bt:join-thread request)
             (bt:join-thread drain)
             (is (typep request-result 'gr8s.model::pod))
             (is (eq store drain-result))
             (assert-store-access-503 (lambda () (gr8s.store::get-pod store "default" "inflight-write")))
             (gr8s.store::resume-store-access store)
             (is (gr8s.store::get-pod store "default" "inflight-write"))
             (signals gr8s.model::kubernetes-error (gr8s.store::get-pod store "default" "rejected")))
        (bt:signal-semaphore release)
        (when (bt:thread-alive-p request) (bt:join-thread request))
        (when (and drain (bt:thread-alive-p drain)) (bt:join-thread drain))))))

(test request-errors-and-nested-routing-do-not-leak-access-leases
  (with-temporary-store (store root)
    (declare (ignore root))
    (signals error
      (gr8s.store::call-with-store-request
       store (lambda () (gr8s.store::call-with-store-request store (lambda () (error "Handler failed"))))))
    (is (gr8s.store::quiesce-store-access store :timeout 0))
    (assert-store-access-503 (lambda () (gr8s.store::quiesce-store-access store :timeout 0)))
    (gr8s.store::resume-store-access store)
    (is (gr8s.store::call-with-store-request store (lambda () t)))))

(test drain-timeout-reopens-unchanged-store-and-request-can-finish
  (with-temporary-store (store root)
    (declare (ignore root))
    (ha-make-pod store "unchanged")
    (let* ((entered (bt:make-semaphore)) (release (bt:make-semaphore))
           (thread (bt:make-thread
                    (lambda ()
                      (gr8s.store::call-with-store-request
                       store (lambda () (bt:signal-semaphore entered)
                               (bt:wait-on-semaphore release :timeout 5)))))))
      (unwind-protect
           (progn
             (is-true (bt:wait-on-semaphore entered :timeout 5))
             (assert-store-access-503 (lambda () (gr8s.store::quiesce-store-access store :timeout 0.02)))
             (is (gr8s.store::get-pod store "default" "unchanged")))
        (bt:signal-semaphore release)
        (bt:join-thread thread))
      (is (gr8s.store::quiesce-store-access store :timeout 0))
      (gr8s.store::resume-store-access store))))

(test pending-restore-intent-prevents-reopening-access
  (with-temporary-store (store root)
    (let* ((descriptor (make-restore-intent-fixture store root))
           (id (gethash "generation" descriptor)))
      (gr8s.store::quiesce-store-access store :timeout 0)
      (gr8s.store::begin-store-restore root id)
      (assert-store-access-503 (lambda () (gr8s.store::resume-store-access store)))
      (assert-store-access-503 (lambda () (gr8s.store::get-pod store "default" "snapshot-pod")))
      (is (gr8s.store::open-store root))
      (assert-store-access-503 (lambda () (gr8s.store::resume-store-access store)))
      (assert-store-access-503 (lambda () (gr8s.store::get-pod store "default" "snapshot-pod"))))))

(test blocked-store-http-request-returns-kubernetes-service-unavailable
  (with-temporary-store (store root)
    (declare (ignore root))
    (let ((server (start-http-test-server :store store :runtime (make-fake-runtime))))
      (unwind-protect
           (progn
             (gr8s.store::quiesce-store-access store :timeout 0)
             (multiple-value-bind (body status) (request "/api/v1/namespaces/default/pods")
               (is (= 503 status))
               (is (equal "ServiceUnavailable" (gethash "reason" (response-object body)))))
             (multiple-value-bind (body status) (request "/readyz")
               (declare (ignore body))
               (is (= 503 status)))
             (multiple-value-bind (body status) (request "/livez")
               (declare (ignore body))
               (is (= 200 status)))
             (gr8s.store::resume-store-access store)
             (multiple-value-bind (body status) (request "/api/v1/namespaces/default/pods")
               (declare (ignore body))
               (is (= 200 status))))
        (stop-server server)))))

(test blocked-ha-writes-never-propose-consensus-commands
  (with-temporary-store (store root)
    (declare (ignore root))
    (let ((proposals 0))
      (setf (gr8s.store::pod-store-consensus-commit-fn store)
            (lambda (&rest args) (declare (ignore args)) (incf proposals)))
      (gr8s.store::quiesce-store-access store :timeout 0)
      (assert-store-access-503 (lambda () (ha-make-pod store "blocked-ha")))
      (assert-store-access-503
       (lambda () (gr8s.resources::create-core-resource store "configmaps" (core-fixture "ConfigMap" "blocked-ha") "default")))
      (assert-store-access-503
       (lambda () (gr8s.controllers::register-node store (gr8s.model::make-node-record :id "blocked-ha" :name "blocked-ha" :pod-cidr "10.89.0.0/20"))))
      (is (= 0 proposals))
      (gr8s.store::resume-store-access store))))

(test established-watches-expire-and-release-leases-when-restore-drains
  (with-temporary-store (store root)
    (declare (ignore root))
    (ha-make-pod store "watched")
    (gr8s.controllers::register-node store (gr8s.model::make-node-record :id "watched-node" :name "watched-node" :pod-cidr "10.89.0.0/20"))
    (gr8s.resources::create-core-resource store "configmaps" (core-fixture "ConfigMap" "watched") "default")
    (let ((server (start-http-test-server :store store :runtime (make-fake-runtime))))
      (unwind-protect
           (dolist (path '("/api/v1/pods" "/api/v1/nodes" "/api/v1/configmaps"))
             (sb-sys:with-deadline (:seconds 15)
               (multiple-value-bind (stream code)
                   (drakma:http-request
                    (format nil "http://127.0.0.1:~D~A" *http-test-port* path) :want-stream t
                    :parameters '(("watch" . "true") ("resourceVersion" . "0") ("timeoutSeconds" . "300")))
                 (unwind-protect
                      (progn
                        (is (= 200 code))
                        (is (equal "ADDED" (gethash "type" (read-template-watch-event stream))))
                        ;; A five-minute watch must release its request lease within
                        ;; this short drain, rather than make restore time out.
                        (is (eq store (gr8s.store::quiesce-store-access store :timeout 3)))
                        (let* ((event (read-template-watch-event stream)) (status (gethash "object" event)))
                          (is (equal "ERROR" (gethash "type" event)))
                          (is (= 410 (gethash "code" status)))
                          (is (equal "Expired" (gethash "reason" status))))
                        (is (zerop (gr8s.store::pod-store-active-requests store)))
                        (is (null (handler-case (read-template-watch-event stream) (end-of-file () nil))))
                        (gr8s.store::resume-store-access store))
                   (close stream)))))
        (stop-server server)))))

(defun store-request-outcome (store)
  "Run one leased request against STORE; return :SERVED or the status code it was refused with."
  (handler-case (gr8s.store::call-with-store-request store (lambda () :served))
    (gr8s.model::kubernetes-error (condition)
      (gr8s.model::kubernetes-error-status-code condition))))

(test a-request-waits-out-a-checkpoint-quiesce-and-is-served
  ;; Helm does not retry a 503, so a write that lands in a checkpoint must not get one.
  (with-temporary-store (store root)
    (declare (ignore root))
    (gr8s.store::quiesce-store-access store :timeout 0 :brief t)
    (let* ((outcome nil)
           (request (bt:make-thread (lambda () (setf outcome (store-request-outcome store))))))
      (sleep 0.2)
      (is (null outcome) "the request is held while the checkpoint has the store")
      (gr8s.store::resume-store-access store)
      (bt:join-thread request)
      (is (eq :served outcome)))))

(test a-request-is-not-held-for-a-restore
  (with-temporary-store (store root)
    (declare (ignore root))
    (gr8s.store::quiesce-store-access store :timeout 0)
    (let ((start (get-internal-real-time)))
      (is (eql 503 (store-request-outcome store)) "a store closed for a restore fails closed")
      (is (< (- (get-internal-real-time) start) internal-time-units-per-second)))
    ;; A checkpoint that hands its gate to a restore stops holding requests too.
    (bt:with-lock-held ((gr8s.store::pod-store-lock store))
      (setf (gr8s.store::pod-store-access-block-brief-p store) t))
    (let* ((outcome nil)
           (request (bt:make-thread (lambda () (setf outcome (store-request-outcome store))))))
      (sleep 0.2)
      (is (null outcome))
      (gr8s.store::end-brief-store-quiesce store)
      (bt:join-thread request)
      (is (eql 503 outcome)))
    (gr8s.store::resume-store-access store)))

(test a-checkpoint-quiesce-that-outlasts-patience-asks-the-client-to-retry
  (with-temporary-store (store root)
    (declare (ignore root))
    (gr8s.store::quiesce-store-access store :timeout 0 :brief t)
    (let ((gr8s.store::*store-quiesce-patience-seconds* 0.2))
      (is (eql 429 (store-request-outcome store))))
    (gr8s.store::resume-store-access store)))

(test an-http-request-waits-out-a-checkpoint-from-its-first-store-read
  ;; A request reads the store to be classified for flow control before it is
  ;; routed. That read was unleased and was refused while a checkpoint had the
  ;; store: four GETs in a row on the lab, during one two-second quiesce.
  (with-temporary-store (store root)
    (declare (ignore root))
    (let ((server (start-http-test-server :store store :runtime (make-fake-runtime))))
      (unwind-protect
           (progn
             (gr8s.store::quiesce-store-access store :timeout 0 :brief t)
             (let* ((status nil)
                    (client (bt:make-thread
                             (lambda ()
                               (setf status (nth-value 1 (request "/api/v1/namespaces/default/pods")))))))
               (sleep 0.3)
               (is (null status) "the request is held, not refused, while the checkpoint has the store")
               (gr8s.store::resume-store-access store)
               (bt:join-thread client)
               (is (eql 200 status))))
        (stop-server server)))))
(test a-request-that-released-its-lease-does-not-hold-up-a-checkpoint
  ;; A followed log or an exec session stays open as long as its client likes.
  (with-temporary-store (store root)
    (declare (ignore root))
    (let* ((released (bt:make-semaphore)) (finish (bt:make-semaphore))
           (after-release nil) (first-release nil) (second-release nil)
           (request (bt:make-thread
                     (lambda ()
                       (gr8s.store::call-with-store-request
                        store (lambda ()
                                (setf first-release (gr8s.store::release-store-request)
                                      second-release (gr8s.store::release-store-request))
                                (bt:signal-semaphore released)
                                (bt:wait-on-semaphore finish :timeout 10)
                                ;; Reads after the release are refused like any unleased caller's.
                                (setf after-release
                                      (handler-case (progn (list-pods store nil) :served)
                                        (gr8s.model::kubernetes-error (condition)
                                          (gr8s.model::kubernetes-error-status-code condition))))))))))
      (is-true (bt:wait-on-semaphore released :timeout 5))
      (is-true first-release)
      (is-true second-release "releasing twice is harmless")
      (is (zerop (gr8s.store::pod-store-active-requests store)))
      ;; The request is still running, and the store quiesces without waiting for it.
      (is (eq store (gr8s.store::quiesce-store-access store :timeout 0)))
      (bt:signal-semaphore finish)
      (bt:join-thread request)
      (is (eql 503 after-release))
      (is (zerop (gr8s.store::pod-store-active-requests store)) "the lease is given back once, not twice")
      (gr8s.store::resume-store-access store)))
  (is (null (gr8s.store::release-store-request)) "outside a request there is nothing to release"))

(test a-slow-drain-names-the-requests-it-waits-on
  ;; The store is closed to everyone while a checkpoint drains, so a drain that
  ;; takes seconds has to say whose request it was waiting for.
  (with-temporary-store (store root)
    (declare (ignore root))
    (let* ((entered (bt:make-semaphore))
           (request (bt:make-thread
                     (lambda ()
                       (let ((gr8s.store::*store-request-description* "PATCH /apis/example/slow"))
                         (gr8s.store::call-with-store-request
                          store (lambda () (bt:signal-semaphore entered) (sleep 0.6)))))))
           (report (make-string-output-stream)))
      (is-true (bt:wait-on-semaphore entered :timeout 5))
      (let ((gr8s.store::*store-drain-report-seconds* 0.2)
            (*error-output* report))
        (is (eq store (gr8s.store::quiesce-store-access store :timeout 5 :brief t))))
      (bt:join-thread request)
      (gr8s.store::resume-store-access store)
      (let ((text (get-output-stream-string report)))
        (is (search "drain still waiting" text))
        (is (search "1 request active: PATCH /apis/example/slow" text) "the holder is named")
        (is (= 1 (count-if (lambda (line) (search "still waiting" line))
                           (uiop:split-string text :separator '(#\Newline))))
            "it is said once, not on every wake-up")))
    ;; A drain that finishes promptly says nothing extra.
    (let ((report (make-string-output-stream)))
      (let ((*error-output* report))
        (gr8s.store::quiesce-store-access store :timeout 5 :brief t)
        (gr8s.store::resume-store-access store))
      (is (null (search "still waiting" (get-output-stream-string report)))))))

(test a-request-sending-its-response-does-not-hold-up-a-checkpoint
  ;; Sending a response reads nothing from the store and lasts as long as the
  ;; client takes to read it.
  (with-temporary-store (store root)
    (declare (ignore root))
    (flet ((sending-request (sending finish)
             "Start a request that suspends its lease to send; return (thread . results)."
             (let ((results (list nil)))
               (cons (bt:make-thread
                      (lambda ()
                        (setf (car results)
                              (handler-case
                                  (gr8s.store::call-with-store-request
                                   store (lambda ()
                                           (gr8s.store::call-with-store-request-suspended
                                            (lambda ()
                                              (bt:signal-semaphore sending)
                                              (bt:wait-on-semaphore finish :timeout 10)))
                                           ;; Back under the lease: the store can be read again.
                                           (list-pods store nil)
                                           (gr8s.store::pod-store-active-requests store)))
                                (gr8s.model::kubernetes-error (condition)
                                  (gr8s.model::kubernetes-error-status-code condition))))))
                     results))))
      ;; A checkpoint runs to completion while the request is sending.
      (let* ((sending (bt:make-semaphore)) (finish (bt:make-semaphore))
             (request (sending-request sending finish)))
        (is-true (bt:wait-on-semaphore sending :timeout 5))
        (is (zerop (gr8s.store::pod-store-active-requests store)))
        (is (eq store (gr8s.store::quiesce-store-access store :timeout 0 :brief t)))
        (gr8s.store::resume-store-access store)
        (bt:signal-semaphore finish)
        (bt:join-thread (car request))
        (is (eql 1 (cadr request)) "the request holds its lease again once it has sent")
        (is (zerop (gr8s.store::pod-store-active-requests store))))
      ;; A restore that began meanwhile ends the request instead of readmitting it.
      (let* ((sending (bt:make-semaphore)) (finish (bt:make-semaphore))
             (request (sending-request sending finish)))
        (is-true (bt:wait-on-semaphore sending :timeout 5))
        (is (eq store (gr8s.store::quiesce-store-access store :timeout 0)))
        (bt:signal-semaphore finish)
        (bt:join-thread (car request))
        (is (eql 503 (cadr request)))
        (is (zerop (gr8s.store::pod-store-active-requests store)))
        (gr8s.store::resume-store-access store))
      ;; A request that gave its lease up for good is not handed one back.
      (is (zerop (gr8s.store::call-with-store-request
                  store (lambda ()
                          (gr8s.store::release-store-request)
                          (gr8s.store::call-with-store-request-suspended (lambda () nil))
                          (gr8s.store::pod-store-active-requests store)))))))
  (is (eq :sent (gr8s.store::call-with-store-request-suspended (lambda () :sent)))
      "outside a request the function is simply called"))

(test a-checkpoint-does-not-end-a-watch-that-is-between-two-sends
  ;; The watch has sent what there is and waits for more, holding its lease. It
  ;; must give the lease up for the checkpoint and go on afterwards. It used to
  ;; end with 410 Expired, and whether a watch was between two sends or in one
  ;; when a checkpoint began was chance (podster-0o5).
  (with-temporary-store (store root)
    (declare (ignore root))
    (ha-make-pod store "watched")
    (gr8s.controllers::register-node store (gr8s.model::make-node-record :id "watched-node" :name "watched-node" :pod-cidr "10.89.0.0/20"))
    (gr8s.resources::create-core-resource store "configmaps" (core-fixture "ConfigMap" "watched") "default")
    (let ((server (start-http-test-server :store store :runtime (make-fake-runtime)))
          (changes
            (list (cons "/api/v1/pods" (lambda () (ha-make-pod store "another")))
                  (cons "/api/v1/nodes"
                        (lambda ()
                          (gr8s.controllers::register-node
                           store (gr8s.model::make-node-record :id "another-node" :name "another-node"
                                                               :pod-cidr "10.89.16.0/20"))))
                  (cons "/api/v1/configmaps"
                        (lambda ()
                          (gr8s.resources::create-core-resource store "configmaps" (core-fixture "ConfigMap" "another")
                                                                "default"))))))
      (unwind-protect
           (loop for (path . change) in changes do
             (sb-sys:with-deadline (:seconds 30)
               (multiple-value-bind (stream code)
                   (drakma:http-request
                    (format nil "http://127.0.0.1:~D~A" *http-test-port* path) :want-stream t
                    :parameters '(("watch" . "true") ("resourceVersion" . "0") ("timeoutSeconds" . "300")))
                 (unwind-protect
                      (progn
                        (is (= 200 code))
                        (is (equal "ADDED" (gethash "type" (read-template-watch-event stream))))
                        ;; Let the watch come to rest between two sends.
                        (sleep .3)
                        (dotimes (checkpoint 3)
                          (is (eq store (gr8s.store::quiesce-store-access store :timeout 3 :brief t))
                              "the watch gives its lease up for the checkpoint")
                          (is (zerop (gr8s.store::pod-store-active-requests store)))
                          (sleep .2)
                          (gr8s.store::resume-store-access store))
                        (funcall change)
                        (let ((event (read-template-watch-event stream)))
                          (is (equal "ADDED" (gethash "type" event))
                              "the watch on ~A goes on after the checkpoints: ~A" path
                              (gethash "message" (gethash "object" event)))
                          (is (equal "another" (subseq (gethash "name" (gethash "metadata" (gethash "object" event) (gr8s.resources::core-object)) "-------") 0 7)))))
                   (close stream)))))
        (stop-server server)))))

(test a-watch-never-holds-its-lease-against-a-checkpoint
  ;; One checkpoint may follow another at once. A watch that has just taken its
  ;; lease back from the first must give it up for the second, and not wait,
  ;; holding it, for the store to open: the checkpoint is waiting for the lease.
  (with-temporary-store (store root)
    (declare (ignore root))
    (let* ((stop nil) (passes 0) (ended nil)
           (watch (bt:make-thread
                   (lambda ()
                     (handler-case
                         (gr8s.store::call-with-store-request
                          store
                          (lambda ()
                            (loop until stop
                                  do (gr8s.apiserver::check-watch-store-access store)
                                     (incf passes))))
                       (error (condition) (setf ended condition))))
                   :name "test watch pass"))
           (timed-out 0))
      (unwind-protect
           (progn
             (is (poll-until (lambda () (plusp passes)) :timeout 10) "the watch is running")
             (dotimes (checkpoint 400)
               (handler-case
                   (progn (gr8s.store::quiesce-store-access store :timeout 2 :brief t)
                          (gr8s.store::resume-store-access store)
                          ;; Now and then the watch takes its lease back before the next.
                          (when (zerop (mod checkpoint 3)) (sleep .001)))
                 (error ()
                   (incf timed-out)
                   (return)))))
        (setf stop t)
        (ignore-errors (gr8s.store::resume-store-access store))
        (bt:join-thread watch))
      (is (zerop timed-out) "no checkpoint waited for the watch's lease")
      (is (null ended) "and the watch went on: ~A" ended)
      (is (plusp passes)))))

(test a-watch-writing-to-a-slow-client-does-not-hold-up-a-checkpoint
  ;; Lab, 2026-11-19: kube-state-metrics watched all Secrets over a 2 MB/s link.
  ;; Six megabytes of Helm releases took three seconds to send, and a checkpoint
  ;; waited for all of it.
  (with-temporary-store (store root)
    (declare (ignore root))
    (let ((count 16))
      (dotimes (index count)
        (gr8s.resources::create-core-resource
         store "configmaps"
         (configmap-input (format nil "large-~D" index) "k" (make-string 900000 :initial-element #\x))
         "default"))
      (let ((server (start-http-test-server :store store :runtime (make-fake-runtime))))
        (unwind-protect
             (sb-sys:with-deadline (:seconds 60)
               (multiple-value-bind (stream code)
                   (drakma:http-request
                    (format nil "http://127.0.0.1:~D/api/v1/namespaces/default/configmaps" *http-test-port*)
                    :want-stream t
                    :parameters '(("watch" . "true") ("resourceVersion" . "0") ("timeoutSeconds" . "300")))
                 (unwind-protect
                      (progn
                        (is (= 200 code))
                        ;; The client has read nothing; the server is mid-send.
                        (is (eq store (gr8s.store::quiesce-store-access store :timeout 2 :brief t))
                            "the checkpoint does not wait for the client to read")
                        (gr8s.store::resume-store-access store)
                        (dotimes (index count)
                          (is (equal "ADDED" (gethash "type" (read-template-watch-event stream)))))
                        ;; The same holds for what the watch reports later. On the lab a
                        ;; rewritten half-megabyte Helm release, sent at 100 kB/s, held a
                        ;; checkpoint for nine seconds.
                        (dotimes (index count)
                          (gr8s.resources::update-core-resource
                           store "configmaps" "default" (format nil "large-~D" index)
                           (lambda (object)
                             (setf (gethash "k" (gethash "data" object)) (make-string 900000 :initial-element #\y))
                             object)))
                        (sleep 1)
                        (is (eq store (gr8s.store::quiesce-store-access store :timeout 2 :brief t))
                            "nor for the client to read later events")
                        (gr8s.store::resume-store-access store)
                        (dotimes (index count)
                          (is (equal "MODIFIED" (gethash "type" (read-template-watch-event stream)))))
                        ;; The watch took its lease back and goes on reporting changes.
                        (gr8s.resources::create-core-resource
                         store "configmaps" (configmap-input "afterwards" "k" "v") "default")
                        (let ((event (read-template-watch-event stream)))
                          (is (equal "ADDED" (gethash "type" event)))
                          (is (equal "afterwards"
                                     (gethash "name" (gethash "metadata" (gethash "object" event)))))))
                   (close stream))))
          (stop-server server))))))
