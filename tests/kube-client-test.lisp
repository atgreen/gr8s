;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Exercise the foreign-cluster Kubernetes client (gr8s.kube-client) against
;;;; gr8s's own API server: one-shot requests, a real streaming watch with
;;;; resourceVersion resume, the informer cache through creates, updates,
;;;; deletes and relists, kubeconfig parsing, and Lease leader contention.

(in-package #:gr8s/tests)
(def-suite kube-client :in gr8s)
(in-suite kube-client)

(defun kube-test-cluster ()
  "The running with-core-api fixture as a kube-client cluster (plain HTTP)."
  (gr8s.kube-client:make-kube-cluster
   :host "127.0.0.1" :port *core-api-port* :plain t :namespace "default"))

(defun kube-test-configmap (name &rest data)
  (gr8s.resources::core-object
   "apiVersion" "v1" "kind" "ConfigMap"
   "metadata" (gr8s.resources::core-object "name" name)
   "data" (apply #'gr8s.resources::core-object data)))

(defparameter +kube-test-configmaps+
  (gr8s.kube-client:resource-path nil "v1" "configmaps" :namespace "default"))

(test kube-client-requests-round-trip-create-get-list-delete
  (with-core-api (store path)
    (values store path)
    (let ((cluster (kube-test-cluster)))
      (multiple-value-bind (created code)
          (gr8s.kube-client:kube-create cluster +kube-test-configmaps+
                                        (kube-test-configmap "alpha" "k" "v"))
        (is (= 201 code))
        (is (equal "alpha" (gethash "name" (gethash "metadata" created)))))
      (let ((fetched (gr8s.kube-client:kube-get
                      cluster (gr8s.kube-client:resource-path
                               nil "v1" "configmaps" :namespace "default" :name "alpha"))))
        (is (equal "v" (gethash "k" (gethash "data" fetched))))
        ;; Replace through the client, proving optimistic concurrency fields pass.
        (setf (gethash "k" (gethash "data" fetched)) "v2")
        (is (equal "v2" (gethash "k" (gethash "data"
                          (gr8s.kube-client:kube-replace
                           cluster (gr8s.kube-client:resource-path
                                    nil "v1" "configmaps" :namespace "default" :name "alpha")
                           fetched))))))
      (let ((page (gr8s.kube-client:kube-list cluster +kube-test-configmaps+)))
        (is (find "alpha" (gethash "items" page) :test #'equal
                  :key (lambda (item) (gethash "name" (gethash "metadata" item)))))
        (is (stringp (gethash "resourceVersion" (gethash "metadata" page)))))
      (gr8s.kube-client:kube-delete
       cluster (gr8s.kube-client:resource-path
                nil "v1" "configmaps" :namespace "default" :name "alpha"))
      (handler-case
          (progn (gr8s.kube-client:kube-get
                  cluster (gr8s.kube-client:resource-path
                           nil "v1" "configmaps" :namespace "default" :name "alpha"))
                 (fail "a deleted object must 404"))
        (gr8s.kube-client:kube-error (condition)
          (is (= 404 (gr8s.kube-client:kube-error-status condition))))))))

(test kube-client-watch-streams-events-and-resumes-from-a-revision
  (with-core-api (store path)
    (values store path)
    (let* ((cluster (kube-test-cluster))
           (events nil) (events-lock (bt:make-lock)) (closer nil)
           (page (gr8s.kube-client:kube-list cluster +kube-test-configmaps+))
           (revision (gethash "resourceVersion" (gethash "metadata" page)))
           (watcher (bt:make-thread
                     (lambda ()
                       (gr8s.kube-client:kube-watch
                        cluster +kube-test-configmaps+
                        (lambda (type object)
                          (bt:with-lock-held (events-lock)
                            (push (list type (gethash "name" (gethash "metadata" object)))
                                  events)))
                        :resource-version revision
                        :on-connect (lambda (close) (setf closer close))))
                     :name "kube client watch test")))
      (flet ((event-count () (bt:with-lock-held (events-lock) (length events))))
        (unwind-protect
             (progn
               (gr8s.kube-client:kube-create cluster +kube-test-configmaps+
                                             (kube-test-configmap "watched" "k" "1"))
               (is (poll-until (lambda () (>= (event-count) 1))))
               (gr8s.kube-client:kube-delete
                cluster (gr8s.kube-client:resource-path
                         nil "v1" "configmaps" :namespace "default" :name "watched"))
               (is (poll-until (lambda () (>= (event-count) 2))))
               (let ((seen (bt:with-lock-held (events-lock) (reverse events))))
                 (is (equal '("ADDED" "watched") (first seen)))
                 (is (equal '("DELETED" "watched") (second seen)))))
          (when closer (funcall closer))
          (ignore-errors (bt:join-thread watcher)))))))

(test kube-client-informer-converges-and-survives-reconnection
  (with-core-api (store path)
    (values store path)
    (let* ((cluster (kube-test-cluster))
           (changes nil) (changes-lock (bt:make-lock))
           (informer (gr8s.kube-client:start-informer
                      cluster +kube-test-configmaps+
                      :on-change (lambda (change key object)
                                   (declare (ignore object))
                                   (bt:with-lock-held (changes-lock)
                                     (push (list change key) changes))))))
      (unwind-protect
           (progn
             (is (poll-until (lambda () (gr8s.kube-client:informer-synced-p informer))))
             (gr8s.kube-client:kube-create cluster +kube-test-configmaps+
                                           (kube-test-configmap "one" "k" "1"))
             (gr8s.kube-client:kube-create cluster +kube-test-configmaps+
                                           (kube-test-configmap "two" "k" "2"))
             (is (poll-until (lambda ()
                               (and (gr8s.kube-client:informer-object informer "default/one")
                                    (gr8s.kube-client:informer-object informer "default/two")))))
             (is (= 2 (length (gr8s.kube-client:informer-objects informer))))
             (let ((current (gr8s.kube-client:kube-get
                             cluster (gr8s.kube-client:resource-path
                                      nil "v1" "configmaps" :namespace "default" :name "one"))))
               (setf (gethash "k" (gethash "data" current)) "updated")
               (gr8s.kube-client:kube-replace
                cluster (gr8s.kube-client:resource-path
                         nil "v1" "configmaps" :namespace "default" :name "one")
                current))
             (is (poll-until
                  (lambda ()
                    (equal "updated"
                           (gethash "k" (gethash "data"
                             (gr8s.kube-client:informer-object informer "default/one")))))))
             (gr8s.kube-client:kube-delete
              cluster (gr8s.kube-client:resource-path
                       nil "v1" "configmaps" :namespace "default" :name "two"))
             (is (poll-until
                  (lambda ()
                    (null (gr8s.kube-client:informer-object informer "default/two")))))
             (let ((seen (bt:with-lock-held (changes-lock) (reverse changes))))
               (is (member '(:added "default/one") seen :test #'equal))
               (is (member '(:added "default/two") seen :test #'equal))
               (is (member '(:modified "default/one") seen :test #'equal))
               (is (member '(:deleted "default/two") seen :test #'equal))))
        (gr8s.kube-client:stop-informer informer)))))

(test kube-client-kubeconfig-parses-context-cluster-and-user
  (with-temporary-store (store directory)
    (declare (ignorable store))
    (let ((path (merge-pathnames "kubeconfig" directory))
          (ca (merge-pathnames "test-ca.crt" directory)))
      (with-open-file (out ca :direction :output)
        (write-string "unused" out))
      (with-open-file (out path :direction :output)
        (format out "apiVersion: v1~%kind: Config~%current-context: main~%~
contexts:~%- name: main~%  context:~%    cluster: test~%    user: admin~%    namespace: web~%~
clusters:~%- name: test~%  cluster:~%    server: https://cluster.example:6443~%    insecure-skip-tls-verify: true~%~
users:~%- name: admin~%  user:~%    token: sekrit~%    client-certificate-data: ~A~%    client-key-data: ~A~%"
                (ag-grpc:base64-encode (trivial-utf-8:string-to-utf-8-bytes "CERT-PEM"))
                (ag-grpc:base64-encode (trivial-utf-8:string-to-utf-8-bytes "KEY-PEM"))))
      (let ((cluster (gr8s.kube-client:cluster-from-kubeconfig path)))
        (is (equal "cluster.example" (gr8s.kube-client:kube-cluster-host cluster)))
        (is (= 6443 (gr8s.kube-client:kube-cluster-port cluster)))
        (is (equal "web" (gr8s.kube-client:kube-cluster-namespace cluster)))
        (is (equal "sekrit" (funcall (gr8s.kube-client::kube-cluster-token-function cluster))))
        (is (gr8s.kube-client::kube-cluster-insecure cluster))
        (is (not (gr8s.kube-client::kube-cluster-plain cluster)))
        ;; Inline credentials (the k3s style) materialize to private files.
        (let ((certificate (gr8s.kube-client::kube-cluster-client-certificate-path cluster))
              (key (gr8s.kube-client::kube-cluster-client-key-path cluster)))
          (is (equal "CERT-PEM" (uiop:read-file-string certificate)))
          (is (equal "KEY-PEM" (uiop:read-file-string key)))
          (ignore-errors (delete-file certificate))
          (ignore-errors (delete-file key)))))))

(test kube-client-lease-leadership-is-exclusive-and-taken-over-after-expiry
  (with-core-api (store path)
    (values store path)
    (let* ((cluster (kube-test-cluster))
           (first-held nil) (second-held nil)
           (stop-first nil) (stop-second nil)
           (first-thread
             (bt:make-thread
              (lambda ()
                (gr8s.kube-client:run-lease-leader
                 cluster "gr8s-test" "agent-1"
                 :namespace "default" :lease-seconds 2 :renew-seconds 1/4
                 :on-gained (lambda () (setf first-held t))
                 :on-lost (lambda () (setf first-held nil))
                 :stop-predicate (lambda () stop-first)))
              :name "lease agent-1")))
      (unwind-protect
           (progn
             (is (poll-until (lambda () first-held)))
             ;; A contender cannot take a held, renewed lease.
             (let ((second-thread
                     (bt:make-thread
                      (lambda ()
                        (gr8s.kube-client:run-lease-leader
                         cluster "gr8s-test" "agent-2"
                         :namespace "default" :lease-seconds 2 :renew-seconds 1/4
                         :on-gained (lambda () (setf second-held t))
                         :on-lost (lambda () (setf second-held nil))
                         :stop-predicate (lambda () stop-second)))
                      :name "lease agent-2")))
               (unwind-protect
                    (progn
                      (sleep 3)
                      (is-true first-held)
                      (is-false second-held)
                      ;; The holder stops renewing; the contender takes over.
                      (setf stop-first t)
                      (ignore-errors (bt:join-thread first-thread))
                      (is (poll-until (lambda () second-held) :timeout 15))
                      (let ((lease (gr8s.kube-client:kube-get
                                    cluster (gr8s.kube-client:resource-path
                                             "coordination.k8s.io" "v1" "leases"
                                             :namespace "default" :name "gr8s-test"))))
                        (is (equal "agent-2"
                                   (gethash "holderIdentity" (gethash "spec" lease))))
                        (is (plusp (floor (gethash "leaseTransitions" (gethash "spec" lease)))))))
                 (setf stop-second t)
                 (ignore-errors (bt:join-thread second-thread)))))
        (setf stop-first t stop-second t)
        (ignore-errors (bt:join-thread first-thread))))))

(test foreign-resource-view-serves-the-desired-state-read-seam
  (with-core-api (store path)
    (values path)
    (let* ((cluster (kube-test-cluster))
           (changes nil) (changes-lock (bt:make-lock))
           (view (gr8s.resources::make-foreign-resource-view
                  cluster
                  :on-change (lambda (resource change key object)
                               (declare (ignore object))
                               (bt:with-lock-held (changes-lock)
                                 (push (list resource change key) changes))))))
      (unwind-protect
           (progn
             (gr8s.kube-client:kube-create cluster +kube-test-configmaps+
                                           (kube-test-configmap "seam" "k" "v"))
             ;; The same calls the gateway and service-lb planners make.
             (is (poll-until
                  (lambda ()
                    (ignore-errors
                      (equal "v" (gethash "k" (gethash "data"
                        (gr8s.resources::get-core-resource view "configmaps" "default" "seam"))))))))
             (multiple-value-bind (objects revision)
                 (gr8s.resources::list-core-resources view "configmaps" "default")
               (is (= 1 (length objects)))
               (is (stringp revision)))
             (is (null (gr8s.resources::list-core-resources view "configmaps" "elsewhere")))
             (handler-case
                 (progn (gr8s.resources::get-core-resource view "configmaps" "default" "absent")
                        (fail "a missing object must 404 through the seam"))
               (kubernetes-error (condition)
                 (is (= 404 (gr8s.model::kubernetes-error-status-code condition)))))
             ;; Mutating a returned copy must not poison the cache.
             (let ((copy (gr8s.resources::get-core-resource view "configmaps" "default" "seam")))
               (setf (gethash "k" (gethash "data" copy)) "mutated")
               (is (equal "v" (gethash "k" (gethash "data"
                 (gr8s.resources::get-core-resource view "configmaps" "default" "seam"))))))
             ;; Pods arrive as gr8s model Pods, as LIST-PODS promises.
             (create-pod store (parse-pod *valid-pod-json*))
             (is (poll-until
                  (lambda () (= 1 (length (gr8s.store:list-pods view))))))
             (is (typep (first (gr8s.store:list-pods view)) 'gr8s.model:pod))
             (is (member '("configmaps" :added "default/seam")
                         (bt:with-lock-held (changes-lock) changes)
                         :test #'equal)))
        (gr8s.resources::stop-foreign-resource-view view)))))

(test informer-treats-an-absent-collection-as-synced-and-empty
  (with-core-api (store path)
    (values store path)
    ;; A resource whose CRD is not installed must not stall consumers: the
    ;; correct cache for an absent collection is empty, immediately.
    (let ((informer (gr8s.kube-client:start-informer
                     (kube-test-cluster) "/apis/absent.example.com/v1/widgets")))
      (unwind-protect
           (progn
             (is (poll-until (lambda () (gr8s.kube-client:informer-synced-p informer))))
             (is (null (gr8s.kube-client:informer-objects informer))))
        (gr8s.kube-client:stop-informer informer)))))

(test kube-client-normalizes-json-null-to-nil-throughout
  ;; A foreign cluster sends array fields as explicit null where gr8s omits
  ;; them; CL:NULL is truthy and breaks sequence ops and OR-defaults, so the
  ;; client normalizes it to NIL everywhere.
  (let ((object (gr8s.kube-client::parse-kube-json
                 "{\"a\":null,\"b\":[1,null,3],\"c\":{\"d\":null},\"e\":\"x\"}")))
    (is (null (gethash "a" object)))
    (is (equalp #(1 nil 3) (gethash "b" object)))
    (is (null (gethash "d" (gethash "c" object))))
    (is (equal "x" (gethash "e" object)))
    ;; The whole point: a null-valued array field is a usable empty sequence.
    (is (null (loop for x across (coerce '() 'vector) collect x)))
    (is (zerop (length (or (gethash "a" object) #()))))))
