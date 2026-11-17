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

(test foreign-snapshot-listenerset-index-follows-parent-and-gateway-identity
  (let* ((view (gr8s.resources::make-foreign-resource-view nil))
         (gateway (gw-parse "{\"metadata\":{\"namespace\":\"apps\",\"name\":\"edge\",\"uid\":\"gw1\"},\"spec\":{}}"))
         (owner (gw-parse "{\"metadata\":{\"namespace\":\"apps\",\"name\":\"child\",\"uid\":\"set1\"},\"spec\":{\"parentRef\":{\"name\":\"edge\"}}}")))
    (gr8s.resources::foreign-view-note view "gateways" :added "apps/edge" gateway)
    (gr8s.resources::foreign-view-note view "listenersets" :added "apps/child" owner)
    (let ((old (gr8s.resources::foreign-view-snapshot view)))
      (flet ((children (snapshot uid)
               (gr8s.resources::list-core-resources
                (gr8s.controllers::make-foreign-gateway-view
                 :source snapshot :gateway-key (list "apps" "edge" uid)) "listenersets")))
        (is (= 1 (length (children old "gw1"))))
        (is (null (children old "wrong")))
        (setf (gethash "uid" (gethash "metadata" gateway)) "gw2")
        (gr8s.resources::foreign-view-note view "gateways" :modified "apps/edge" gateway)
        (let ((new (gr8s.resources::foreign-view-snapshot view)))
          (is (null (children new "gw1")))
          (is (= 1 (length (children new "gw2"))))
          (setf (gethash "namespace" (gethash "parentRef" (gethash "spec" owner))) "other")
          (gr8s.resources::foreign-view-note view "listenersets" :modified "apps/child" owner)
          (is (null (children (gr8s.resources::foreign-view-snapshot view) "gw2")))
          (is (= 1 (length (children new "gw2"))))
          (remhash "namespace" (gethash "parentRef" (gethash "spec" owner)))
          (gr8s.resources::foreign-view-note view "listenersets" :modified "apps/child" owner)
          (gr8s.resources::foreign-view-note view "listenersets" :deleted "apps/child" owner)
          (is (null (children (gr8s.resources::foreign-view-snapshot view) "gw2")))
          (is (= 1 (length (children old "gw1")))))))))

(test informer-initial-sync-waits-for-change-callbacks
  (let ((original (symbol-function 'gr8s.kube-client:kube-list))
        (informer nil) (observed :not-called))
    (unwind-protect
         (progn
           (setf informer (gr8s.kube-client::%make-informer
                           :on-change (lambda (&rest args)
                                        (declare (ignore args))
                                        (setf observed (gr8s.kube-client:informer-synced-p informer))))
                 (symbol-function 'gr8s.kube-client:kube-list)
                 (lambda (&rest args)
                   (declare (ignore args))
                   (gw-parse "{\"metadata\":{\"resourceVersion\":\"1\"},\"items\":[{\"metadata\":{\"name\":\"a\",\"resourceVersion\":\"1\"}}]}")))
           (gr8s.kube-client::informer-relist informer)
           (is (null observed))
           (is (gr8s.kube-client:informer-synced-p informer)))
      (setf (symbol-function 'gr8s.kube-client:kube-list) original))))

(test foreign-snapshot-parent-index-retains-identity-and-reparenting
  (let* ((view (gr8s.resources::make-foreign-resource-view nil))
         (route (gw-parse "{\"metadata\":{\"namespace\":\"apps\",\"name\":\"r\"},\"spec\":{\"parentRefs\":[{\"kind\":\"ListenerSet\",\"name\":\"shared\"},{\"kind\":\"ListenerSet\",\"name\":\"shared\",\"sectionName\":\"two\"},{\"group\":\"gateway.networking.x-k8s.io\",\"kind\":\"XListenerSet\",\"name\":\"shared\"}]}}"))
         (stable '("gateway.networking.k8s.io" "ListenerSet" "apps" "shared"))
         (experimental '("gateway.networking.x-k8s.io" "XListenerSet" "apps" "shared"))
         (gateway '("gateway.networking.k8s.io" "Gateway" "edge" "shared")))
    (gr8s.resources::foreign-view-note view "httproutes" :added "apps/r" route)
    (let ((old (gr8s.resources::foreign-view-snapshot view)))
      (is (= 1 (length (gr8s.resources::foreign-snapshot-parent-routes old stable))))
      (is (= 1 (length (gr8s.resources::foreign-snapshot-parent-routes old experimental))))
      (is (null (gr8s.resources::foreign-snapshot-parent-routes old gateway)))
      (setf (gethash "parentRefs" (gethash "spec" route))
            (vector (gr8s.resources::core-object "name" "shared" "namespace" "edge")))
      (gr8s.resources::foreign-view-note view "httproutes" :modified "apps/r" route)
      (let ((new (gr8s.resources::foreign-view-snapshot view)))
        (is (null (gr8s.resources::foreign-snapshot-parent-routes new stable)))
        (is (null (gr8s.resources::foreign-snapshot-parent-routes new experimental)))
        (is (= 1 (length (gr8s.resources::foreign-snapshot-parent-routes new gateway))))
        (is (= 1 (length (gr8s.resources::foreign-snapshot-parent-routes old stable))))
        (gr8s.resources::foreign-view-note view "httproutes" :deleted "apps/r" route)
        (is (null (gr8s.resources::foreign-snapshot-parent-routes
                   (gr8s.resources::foreign-view-snapshot view) gateway)))
        (is (= 1 (length (gr8s.resources::foreign-snapshot-parent-routes new gateway))))))))

(test foreign-view-snapshots-retain-old-state-and-coalesce-changes
  (let* ((view (gr8s.resources::make-foreign-resource-view nil))
         (object (gw-parse "{\"metadata\":{\"namespace\":\"apps\",\"name\":\"r\",\"uid\":\"old\"},\"spec\":{\"value\":1}}")))
    (gr8s.resources::foreign-view-note view "httproutes" :added "apps/r" object)
    (multiple-value-bind (before revision changes full)
        (gr8s.resources::foreign-view-snapshot view)
      (declare (ignore changes))
      (is (not (null full)))
      (setf (gethash "value" (gethash "spec" object)) 2)
      (gr8s.resources::foreign-view-note view "httproutes" :modified "apps/r" object)
      (gr8s.resources::foreign-view-note view "httproutes" :deleted "apps/r" object)
      (setf (gethash "uid" (gethash "metadata" object)) "replacement")
      (gr8s.resources::foreign-view-note view "httproutes" :added "apps/r" object)
      (multiple-value-bind (after next deltas rebuild)
          (gr8s.resources::foreign-view-snapshot view revision)
        (is (not rebuild))
        (is (= 1 (length deltas)))
        (is (equal '("httproutes" "apps" "r") (caar deltas)))
        (is (equal "replacement" (gethash "uid" (gethash "metadata" (cdar deltas)))))
        (is (= 1 (gethash "value" (gethash "spec"
                              (gr8s.resources::get-core-resource before "httproutes" "apps" "r")))))
        (is (= 2 (gethash "value" (gethash "spec"
                              (gr8s.resources::get-core-resource after "httproutes" "apps" "r")))))
        ;; Returned deltas and reads must not mutate the retained snapshot.
        (setf (gethash "value" (gethash "spec" (cdar deltas))) 99)
        (is (= 2 (gethash "value" (gethash "spec"
                              (gr8s.resources::get-core-resource after "httproutes" "apps" "r")))))
        (gr8s.resources::foreign-view-note view "httproutes" :deleted "apps/r" object)
        (multiple-value-bind (deleted ignored removals full)
            (gr8s.resources::foreign-view-snapshot view next)
          (declare (ignore ignored))
          (is (not full))
          (is (equal '((("httproutes" "apps" "r"))) removals))
          (is (null (gr8s.resources::list-core-resources deleted "httproutes"))))))))

(test foreign-view-snapshot-history-overflow-requires-rebuild
  (let ((view (gr8s.resources::make-foreign-resource-view nil :history-limit 2)))
    (dotimes (i 3)
      (gr8s.resources::foreign-view-note
       view "namespaces" :added (format nil "ns-~D" i)
       (gr8s.resources::core-object "metadata" (gr8s.resources::core-object "name" (format nil "ns-~D" i)))))
    (multiple-value-bind (snapshot revision changes full)
        (gr8s.resources::foreign-view-snapshot view 0)
      (is (not (null full)))
      (is (null changes))
      (is (= 3 (length (gr8s.resources::list-core-resources snapshot "namespaces"))))
      (multiple-value-bind (same next changes full)
          (gr8s.resources::foreign-view-snapshot view revision)
        (declare (ignore same))
        (is (= revision next))
        (is (null changes))
        (is (not full))))))

(defun listenerset-test-api-resources (group-version &key (namespaced t)
                                                       (verbs #("get" "list" "watch")))
  (let ((experimental (equal group-version "gateway.networking.x-k8s.io/v1alpha1")))
   (gr8s.resources::core-object
   "groupVersion" group-version
   "resources" (vector (gr8s.resources::core-object
                         "name" (if experimental "xlistenersets" "listenersets")
                         "kind" (if experimental "XListenerSet" "ListenerSet")
                         "namespaced" namespaced "verbs" verbs)))))

(test listenerset-discovery-selects-one-served-version-and-preserves-group
  (let ((advertised
          (list (listenerset-test-api-resources "gateway.networking.k8s.io/v1beta1")
                (listenerset-test-api-resources "gateway.networking.x-k8s.io/v1alpha1")
                (listenerset-test-api-resources "gateway.networking.k8s.io/v1"))))
    (is (equal '("listenersets" "gateway.networking.k8s.io" "v1" t)
               (gr8s.resources::foreign-listenerset-location advertised)))
    (is (equal '("xlistenersets" "gateway.networking.x-k8s.io" "v1alpha1" t)
               (gr8s.resources::foreign-listenerset-location
                advertised :group "gateway.networking.x-k8s.io")))
    (is (null (gr8s.resources::foreign-listenerset-location nil)))
    (is (null (gr8s.resources::foreign-listenerset-location
               (list (first advertised)) :group "gateway.networking.x-k8s.io")))))

(test listenerset-discovery-requires-a-namespaced-watchable-resource
  (dolist (advertised
            (list (listenerset-test-api-resources "gateway.networking.k8s.io/v1"
                                                 :namespaced nil)
                  (listenerset-test-api-resources "gateway.networking.k8s.io/v1"
                                                 :verbs #("get" "list"))
                  (listenerset-test-api-resources "unrelated.example/v1")))
    (is (null (gr8s.resources::foreign-listenerset-location (list advertised))))))

(test listenerset-discovery-retries-absence-and-propagates-forbidden
  (let ((original (symbol-function 'gr8s.kube-client:kube-get))
        (mode :absent) (calls nil))
    (unwind-protect
         (progn
           (setf (symbol-function 'gr8s.kube-client:kube-get)
                 (lambda (cluster path &key &allow-other-keys)
                   (declare (ignore cluster))
                   (push path calls)
                   (ecase mode
                     (:absent (error 'gr8s.kube-client:kube-error :status 404 :body nil))
                     (:forbidden (error 'gr8s.kube-client:kube-error :status 403 :body nil))
                     (:present (listenerset-test-api-resources "gateway.networking.k8s.io/v1")))))
           (is (null (gr8s.resources::discover-foreign-listenerset-location nil)))
           (setf mode :present calls nil)
           (is (equal '("listenersets" "gateway.networking.k8s.io" "v1" t)
                      (gr8s.resources::discover-foreign-listenerset-location nil)))
           (is (equal '("/apis/gateway.networking.k8s.io/v1") calls))
           (setf mode :forbidden)
           (signals gr8s.kube-client:kube-error
             (gr8s.resources::discover-foreign-listenerset-location nil)))
      (setf (symbol-function 'gr8s.kube-client:kube-get) original))))

(test informer-withdraws-objects-when-the-api-disappears
  (let* ((changes nil)
         (informer (gr8s.kube-client::%make-informer
                    :path "/apis/gateway.networking.k8s.io/v1/listenersets"
                    :on-change (lambda (change key object)
                                 (declare (ignore object))
                                 (push (list change key) changes)))))
    (let ((object (kube-test-configmap "old" "k" "v")))
      (setf (gethash "namespace" (gethash "metadata" object)) "default")
      (gr8s.kube-client::informer-apply informer "ADDED" object))
    (gr8s.kube-client::informer-record-error
     informer (make-condition 'gr8s.kube-client:kube-error :status 404 :body nil))
    (is (null (gr8s.kube-client:informer-objects informer)))
    (is (gr8s.kube-client:informer-synced-p informer))
    (is (member '(:deleted "default/old") changes :test #'equal))))

(test informer-surfaces-forbidden-and-clears-the-error-after-a-successful-relist
  (let* ((informer (gr8s.kube-client::%make-informer :path "/test"))
         (denied (make-condition 'gr8s.kube-client:kube-error :status 403 :body nil))
         (original (symbol-function 'gr8s.kube-client:kube-list)))
    (gr8s.kube-client::informer-record-error informer denied)
    (is (eq denied (gr8s.kube-client::informer-last-error informer)))
    (is (not (gr8s.kube-client:informer-synced-p informer)))
    (unwind-protect
         (progn
           (setf (symbol-function 'gr8s.kube-client:kube-list)
                 (lambda (&rest arguments)
                   (declare (ignore arguments))
                   (gr8s.resources::core-object
                    "metadata" (gr8s.resources::core-object "resourceVersion" "12")
                    "items" #())))
           (gr8s.kube-client::informer-relist informer)
           (is (null (gr8s.kube-client::informer-last-error informer)))
           (is (gr8s.kube-client:informer-synced-p informer)))
      (setf (symbol-function 'gr8s.kube-client:kube-list) original))))

(test foreign-listenerset-view-discovers-late-crds-and-keeps-groups-distinct
  (with-core-api (store path)
    (values store path)
    (let* ((cluster (kube-test-cluster))
           (view (gr8s.resources::make-foreign-resource-view
                  cluster :discovery-retry-seconds 0))
           (experimental (gr8s.resources::make-foreign-resource-view
                          cluster :listenerset-group "gateway.networking.x-k8s.io"
                                  :discovery-retry-seconds 0)))
      (unwind-protect
           (progn
             (is (null (gr8s.resources::list-core-resources view "listenersets")))
             (is (zerop (hash-table-count (gr8s.resources::foreign-resource-view-informers view))))
             (loop for group in '("gateway.networking.k8s.io" "gateway.networking.x-k8s.io")
                   ;; The native test server reserves Gateway v1 discovery for
                   ;; built-ins; use its CRD-served stable-group alias here.
                   for version in '("v1beta1" "v1alpha1")
                   for resource in '("listenersets" "xlistenersets")
                   for kind in '("ListenerSet" "XListenerSet")
                   do (gr8s.kube-client:kube-create
                       cluster "/apis/apiextensions.k8s.io/v1/customresourcedefinitions"
                       (crd-fixture :group group :plural resource :kind kind
                                    :versions (list version)))
                      (gr8s.kube-client:kube-create
                       cluster (gr8s.kube-client:resource-path group version resource
                                                             :namespace "default")
                       (crd-instance "shared-name" group kind version)))
             (is (equal "gateway.networking.k8s.io/v1beta1"
                        (gethash "apiVersion"
                                 (first (gr8s.resources::list-core-resources view "listenersets")))))
             (is (equal "gateway.networking.x-k8s.io/v1alpha1"
                        (gethash "apiVersion"
                                 (first (gr8s.resources::list-core-resources experimental "listenersets")))))
             (is (= 1 (hash-table-count (gr8s.resources::foreign-resource-view-informers view))))
             (gr8s.kube-client:kube-delete
              cluster "/apis/gateway.networking.k8s.io/v1beta1/namespaces/default/listenersets/shared-name")
             (is (poll-until
                  (lambda () (null (gr8s.resources::list-core-resources view "listenersets")))))
             (is (= 1 (length (gr8s.resources::list-core-resources experimental "listenersets")))))
        (gr8s.resources::stop-foreign-resource-view view)
        (gr8s.resources::stop-foreign-resource-view experimental)))))

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
