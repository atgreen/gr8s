;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Exercise durable watches across resource kinds, including HTTP streams,
;;;; historical lists, resource-bound tokens and pre-journal database upgrades.

(in-package #:gr8s/tests)
(def-suite durable-resource-watches :in gr8s)
(in-suite durable-resource-watches)

(defvar *durable-watch-csr-request* nil)

(defun durable-watch-csr-request ()
  "Cache only public signed CSR bytes after deleting the private fixture key."
  (or *durable-watch-csr-request*
      (setf *durable-watch-csr-request*
            (with-temporary-store (store directory)
              (declare (ignore store))
              (csr-crypto-fixture directory "ec")))))

(defun typed-api-watch-fixture (resource object)
  "Give OBJECT the minimum content a typed RESOURCE requires."
  (flet ((spec (&rest fields) (setf (gethash "spec" object) (apply #'gr8s.resources::core-object fields))))
    (let ((claim (gr8s.resources::core-object "devices" (gr8s.resources::core-object "requests" #())))
          (match (gr8s.resources::core-object "resourceRules"
                   (vector (gr8s.resources::core-object "operations" #("CREATE") "apiGroups" #("") "apiVersions" #("v1")
                                              "resources" #("watched-kind"))))))
      (cond
        ((equal resource "leases") (spec))
        ((equal resource "apiservices")
         (spec "group" "watched.example.test" "version" "v1" "groupPriorityMinimum" 1000 "versionPriority" 100))
        ((equal resource "prioritylevelconfigurations") (spec "type" "Exempt"))
        ((equal resource "flowschemas") (spec "priorityLevelConfiguration" (gr8s.resources::core-object "name" "exempt")))
        ((equal resource "deviceclasses") (spec))
        ((equal resource "resourceclaims") (setf (gethash "spec" object) claim))
        ((equal resource "resourceclaimtemplates") (spec "spec" claim))
        ((equal resource "devicetaintrules") (spec "taint" (gr8s.resources::core-object "key" "testing" "effect" "None")))
        ((equal resource "storageversionmigrations") (spec "resource" (gr8s.resources::core-object "group" "" "resource" "foo")))
        ((equal resource "resourceslices")
         (spec "driver" "example.com" "allNodes" t
               "pool" (gr8s.resources::core-object "name" "pool" "generation" 1 "resourceSliceCount" 1)))
        ((equal resource "validatingadmissionpolicies")
         (spec "matchConstraints" match "validations" (vector (gr8s.resources::core-object "expression" "true"))))
        ((equal resource "validatingadmissionpolicybindings")
         (spec "policyName" "absent" "validationActions" #("Deny")))
        ((equal resource "mutatingadmissionpolicies")
         (spec "matchConstraints" match
               "mutations" (vector (gr8s.resources::core-object "patchType" "ApplyConfiguration"
                                     "applyConfiguration" (gr8s.resources::core-object "expression" "Object{}")))))
        ((equal resource "mutatingadmissionpolicybindings") (spec "policyName" "absent")))))
  object)

(defun durable-watch-fixture (resource name)
  "Build a valid stored resource with labels for cross-kind watch checks."
  (let ((object (gr8s.resources::core-object "apiVersion" (gr8s.resources::core-resource-api-version resource)
                                 "kind" (gr8s.resources::core-resource-kind resource)
                                 "metadata" (gr8s.resources::core-object "name" name "labels" (gr8s.resources::core-object "app" "watched")))))
    (cond ((gr8s.resources::typed-api-resource-p resource)
           (typed-api-watch-fixture resource object))
          ((equal resource "jobs")
           (setf (gethash "spec" object) (gethash "spec" (batch-test-job))))
          ((equal resource "cronjobs")
           (setf (gethash "spec" object)
                 (gr8s.resources::core-object "schedule" "0 0 1 1 *"
                                    "jobTemplate" (gr8s.resources::core-object "spec" (gethash "spec" (batch-test-job))))))
          ((equal resource "certificatesigningrequests")
           (setf (gethash "spec" object) (gethash "spec" (csr-fixture (durable-watch-csr-request) :name name))))
          ((equal resource "ingresses")
           (setf (gethash "spec" object)
                 (gr8s.resources::core-object "defaultBackend" (gr8s.resources::core-object "service" (gr8s.resources::core-object "name" "svc" "port" (gr8s.resources::core-object "number" 80))))))
          ((equal resource "ingressclasses")
           (setf (gethash "spec" object) (gr8s.resources::core-object "controller" "example.com/controller")))
          ((equal resource "servicecidrs")
           (setf (gethash "spec" object) (gr8s.resources::core-object "cidrs" (vector "203.0.113.0/24"))))
          ((equal resource "ipaddresses")
           (setf (gethash "spec" object) (gr8s.resources::core-object "parentRef" (gr8s.resources::core-object "resource" "services" "name" "svc"))))
          ((equal resource "endpointslices")
           (setf (gethash "addressType" object) "IPv4" (gethash "endpoints" object) #() (gethash "ports" object) #()))
          ((equal resource "customresourcedefinitions")
           (setf object (crd-fixture :group "watch.example.test" :plural "watched"))
           (setf (gethash "labels" (gethash "metadata" object)) (gr8s.resources::core-object "app" "watched")))
          ((equal resource "csidrivers")
           (setf (gethash "spec" object) (gr8s.resources::core-object)))
          ((equal resource "csinodes")
           (setf (gethash "spec" object) (gr8s.resources::core-object "drivers" #())))
          ((equal resource "volumeattachments")
           (setf (gethash "spec" object)
                 (gr8s.resources::core-object "attacher" "watched.example.test" "nodeName" "node"
                                    "source" (gr8s.resources::core-object "persistentVolumeName" "pv"))))
          ((equal resource "csistoragecapacities")
           (setf (gethash "storageClassName" object) "fast"))
          ((equal resource "horizontalpodautoscalers")
           (setf (gethash "spec" object)
                 (gr8s.resources::core-object "maxReplicas" 2 "scaleTargetRef"
                                    (gr8s.resources::core-object "apiVersion" "apps/v1" "kind" "Deployment" "name" "web"))))
          ((equal resource "persistentvolumes")
           (setf (gethash "spec" object)
                 (gr8s.resources::core-object "capacity" (gr8s.resources::core-object "storage" "1Gi") "accessModes" #("ReadWriteOnce")
                                    "hostPath" (gr8s.resources::core-object "path" "/tmp/gr8s-watch-volume" "type" "DirectoryOrCreate"))))
          ((equal resource "persistentvolumeclaims")
           (setf (gethash "spec" object)
                 (gr8s.resources::core-object "resources" (gr8s.resources::core-object "requests" (gr8s.resources::core-object "storage" "1Gi"))
                                    "accessModes" #("ReadWriteOnce") "storageClassName" "")))
          ((equal resource "storageclasses") (setf (gethash "provisioner" object) "kubernetes.io/no-provisioner"))
          ((equal resource "volumeattributesclasses")
           (setf (gethash "driverName" object) "watched.example.test"
                 (gethash "parameters" object) (gr8s.resources::core-object "iops" "100")))
          ((equal resource "events") (setf (gethash "involvedObject" object) (gr8s.resources::core-object)))
          ((equal resource "resourcequotas")
           (setf (gethash "spec" object) (gr8s.resources::core-object "hard" (gr8s.resources::core-object "pods" "1"))))
          ((equal resource "limitranges")
           (setf (gethash "spec" object)
                 (gr8s.resources::core-object "limits" (vector (gr8s.resources::core-object "type" "Container" "max" (gr8s.resources::core-object "cpu" "1"))))))
          ((equal resource "runtimeclasses") (setf (gethash "handler" object) "runc"))
          ((equal resource "priorityclasses") (setf (gethash "value" object) 10))
          ((member resource '("deployments" "replicasets") :test #'equal)
           (setf (gethash "spec" object) (gethash "spec" (workload-fixture (gr8s.resources::core-resource-kind resource) name))))
          ((equal resource "replicationcontrollers")
           (setf (gethash "spec" object) (gethash "spec" (rc-fixture name))))
          ((equal resource "statefulsets")
           (setf (gethash "spec" object) (gethash "spec" (stateful-fixture name))))
          ((equal resource "daemonsets")
           (setf (gethash "spec" object) (gethash "spec" (daemonset-fixture name))))
          ((equal resource "controllerrevisions")
           (setf (gethash "data" object) (gr8s.resources::core-object) (gethash "revision" object) 1))
          ((equal resource "poddisruptionbudgets")
           (setf (gethash "spec" object) (gr8s.resources::core-object "minAvailable" 1)))
          ((equal resource "podtemplates")
           (setf (gethash "template" object) (gethash "template" (podtemplate-fixture name))))
          ((equal resource "services")
           (setf (gethash "spec" object) (gr8s.resources::core-object "ports" (vector (gr8s.resources::core-object "port" 8080)))))
          ((member resource '("roles" "clusterroles") :test #'equal) (setf (gethash "rules" object) #()))
          ((member resource '("rolebindings" "clusterrolebindings") :test #'equal)
           (setf (gethash "roleRef" object) (gr8s.resources::core-object "apiGroup" "rbac.authorization.k8s.io" "kind" "ClusterRole" "name" "reader")))
          ((equal resource "clustertrustbundles")
           (setf (gethash "spec" object)
                 (gr8s.resources::core-object "trustBundle" (ctb-test-ca-pem "watched"))))
          ((equal resource "podcertificaterequests")
           (setf (gethash "spec" object)
                 (gr8s.resources::core-object "signerName" "podidentity.podcert.ate.dev/identity"
                                    "podName" "demo" "podUID" "11111111-1111-1111-1111-111111111111"
                                    "serviceAccountName" "default" "nodeName" "node" "pkixPublicKey" "QUJD")))
          ((equal resource "gatewayclasses")
           (setf (gethash "spec" object) (gr8s.resources::core-object "controllerName" "gr8s.io/gateway-controller")))
          ((equal resource "gateways")
           (setf (gethash "spec" object)
                 (gr8s.resources::core-object "gatewayClassName" "gr8s"
                                    "listeners" (vector (gr8s.resources::core-object "name" "http" "port" 80 "protocol" "HTTP")))))
          ((equal resource "httproutes")
           (setf (gethash "spec" object)
                 (gr8s.resources::core-object "rules" (vector (gr8s.resources::core-object "backendRefs"
                                                                       (vector (gr8s.resources::core-object "name" "svc" "port" 8080)))))))
          ((equal resource "tcproutes")
           (setf (gethash "spec" object)
                 (gr8s.resources::core-object "rules" (vector (gr8s.resources::core-object "backendRefs"
                                                                       (vector (gr8s.resources::core-object "name" "svc" "port" 3306)))))))
          ((member resource '("tlsroutes" "grpcroutes") :test #'equal)
           (setf (gethash "spec" object)
                 (gr8s.resources::core-object "hostnames" (vector "watched.example.com")
                                    "rules" (vector (gr8s.resources::core-object "backendRefs"
                                                                       (vector (gr8s.resources::core-object "name" "svc" "port" 8443)))))))
          ((member resource '("issuers" "clusterissuers") :test #'equal)
           (setf (gethash "spec" object) (gr8s.resources::core-object "selfSigned" (gr8s.resources::core-object))))
          ((equal resource "certificates")
           (setf (gethash "spec" object)
                 (gr8s.resources::core-object "secretName" "watched-tls"
                                    "issuerRef" (gr8s.resources::core-object "name" "watched" "kind" "ClusterIssuer")
                                    "dnsNames" (vector "watched.example.com"))))
          ((equal resource "certificaterequests")
           (setf (gethash "spec" object)
                 (gr8s.resources::core-object "issuerRef" (gr8s.resources::core-object "name" "watched")
                                    "request" "Zm9v")))
          ((equal resource "challenges")
           (setf (gethash "spec" object)
                 (gr8s.resources::core-object "url" "https://acme.test/chall/1" "authorizationURL" "https://acme.test/authz/1"
                                    "dnsName" "watched.example.com" "type" "HTTP-01"
                                    "token" "watched" "key" "watched.thumb")))
          ((equal resource "clusternetworkpolicies")
           (setf (gethash "spec" object)
                 (gr8s.resources::core-object "tier" "Baseline" "priority" 10
                                              "subject" (gr8s.resources::core-object
                                                         "namespaces" (gr8s.resources::core-object)))))
          ((equal resource "sandboxprofiles")
           (setf (gethash "spec" object)
                 (gr8s.resources::core-object "commands" (vector "claude"))))
          ((equal resource "securityprofiles")
           (setf (gethash "spec" object)
                 (com.inuoe.jzon:parse
                  "{\"selector\":{},\"rules\":[{\"name\":\"r\",\"match\":[{\"domains\":[\"api.example.com\"]}],
                    \"actions\":{\"tokenTransformation\":{\"type\":\"ApiKey\",
                      \"credentialRef\":{\"secret\":{\"name\":\"s\"}},
                      \"apiKey\":{\"targetHeaders\":{\"names\":[\"x-api-key\"]},
                                  \"value\":{\"template\":\"{{ .Token }}\"}}}}}]}"))))
    object))

(test durable-resources-stream-real-http-selector-transitions
  (with-core-api (store path)
    (values path)
    (dolist (descriptor gr8s.resources::*stored-resource-types*)
      (destructuring-bind (resource kind version namespaced) descriptor
        (let* ((name (cond ((equal resource "customresourcedefinitions") "watched.watch.example.test")
                           ((equal resource "ipaddresses") "192.0.2.77")
                           ((equal resource "apiservices") "v1.watched.example.test")
                           (t "watched")))
               (namespace (and namespaced "alpha"))
               (collection (if (equal version "v1") "/api/v1" (concatenate 'string "/apis/" version)))
               (url (format nil "http://127.0.0.1:~D~A~A/~A" *core-api-port* collection
                            (if namespace (concatenate 'string "/namespaces/" namespace) "") resource)))
          (gr8s.resources::create-core-resource store resource (durable-watch-fixture resource name) namespace)
          (sb-sys:with-deadline (:seconds 10)
            (multiple-value-bind (stream code)
                (drakma:http-request url :want-stream t
                  :parameters '(("watch" . "true") ("resourceVersion" . "0") ("labelSelector" . "app=watched") ("timeoutSeconds" . "2")))
              (unwind-protect
                   (progn
                     (is (= 200 code))
                     (let* ((event (read-template-watch-event stream)) (object (gethash "object" event)))
                       (is (equal "ADDED" (gethash "type" event)))
                       (is (equal kind (gethash "kind" object)))
                       (is (equal version (gethash "apiVersion" object))))
                     (gr8s.resources::update-core-resource store resource namespace name
                       (lambda (object)
                         (setf (gethash "app" (gethash "labels" (gethash "metadata" object))) "other") object))
                     (is (equal "DELETED" (gethash "type" (read-template-watch-event stream))))
                     (gr8s.resources::update-core-resource store resource namespace name
                       (lambda (object)
                         (setf (gethash "app" (gethash "labels" (gethash "metadata" object))) "watched") object))
                     (is (equal "ADDED" (gethash "type" (read-template-watch-event stream))))
                     (gr8s.resources::delete-core-resource store resource namespace name)
                     ;; A Namespace first turns Terminating, until its controller releases it.
                     (when (equal resource "namespaces")
                       (is (equal "MODIFIED" (gethash "type" (read-template-watch-event stream))))
                       (gr8s.resources::reconcile-namespace-deletions (gr8s.kubelet::make-reconciler store (make-fake-runtime)))
                       ;; The controller reports its conditions and releases its finalizer on the way out.
                       (loop repeat 2 do (is (equal "MODIFIED" (gethash "type" (read-template-watch-event stream))))))
                     (is (equal "DELETED" (gethash "type" (read-template-watch-event stream)))))
                (close stream)))))))))

(test durable-list-pages-survive-mixed-resource-mutations-and-restart
  (with-temporary-store (store path)
    (dolist (resource '("configmaps" "secrets"))
      (dolist (name '("a" "b" "c"))
        (gr8s.resources::create-core-resource store resource (durable-watch-fixture resource name) "alpha")))
    (let* ((page (gr8s.resources::template-list-page store "alpha" "" "" :resource "configmaps" :limit 1))
           (metadata (gethash "metadata" page))
           (token (gethash "continue" metadata)))
      (gr8s.resources::delete-core-resource store "configmaps" "alpha" "b")
      (gr8s.resources::update-core-resource store "configmaps" "alpha" "c"
        (lambda (object) (setf (gethash "data" object) (gr8s.resources::core-object "mode" "updated")) object))
      (gr8s.resources::create-core-resource store "configmaps" (durable-watch-fixture "configmaps" "aa") "alpha")
      (gr8s.resources::delete-core-resource store "secrets" "alpha" "b")
      (is (= 2 (gethash "version" (gr8s.resources::read-durable-core-state store))))
      (let* ((reopened (open-store path))
             (next (gr8s.resources::template-list-page reopened "alpha" "" "" :resource "configmaps" :limit 10 :continuation token))
             (items (gethash "items" next)))
        (is (equal "ConfigMapList" (gethash "kind" next)))
        (is (equal '("b" "c") (map 'list (lambda (object) (gethash "name" (gethash "metadata" object))) items)))
        (is (null (gethash "data" (aref items 1))))
        (is (equal (gethash "resourceVersion" metadata) (gethash "resourceVersion" (gethash "metadata" next))))
        (is (= 400 (core-resource-status (lambda () (gr8s.resources::template-list-page reopened "alpha" "" "" :resource "secrets" :continuation token)))))
        (multiple-value-bind (events watermark) (gr8s.apiserver::template-watch-events reopened "alpha" "" ""
                                                 (parse-integer (gethash "resourceVersion" metadata)) :resource "configmaps")
          (declare (ignore watermark))
          (is (equal '("DELETED" "MODIFIED" "ADDED") (mapcar (lambda (event) (gethash "type" event)) events)))
          (is (every (lambda (event) (equal "ConfigMap" (gethash "kind" (gethash "object" event)))) events)))))))

(test durable-resource-history-expires-with-a-replacement-token
  (with-temporary-store (store path)
    (values path)
    (let* ((now 1000) (gr8s.store::*podtemplate-clock* (lambda () now)))
      (dolist (name '("a" "b"))
        (gr8s.resources::create-core-resource store "secrets" (durable-watch-fixture "secrets" name) "alpha"))
      (let* ((page (gr8s.resources::template-list-page store "alpha" "" "" :resource "secrets" :limit 1))
             (token (gethash "continue" (gethash "metadata" page))))
        (setf now 1400)
        (multiple-value-bind (error code) (gr8s.resources::template-list-page store "alpha" "" "" :resource "secrets" :continuation token)
          (is (= 410 code))
          (let* ((replacement (gethash "continue" (gethash "metadata" error)))
                 (resumed (gr8s.resources::template-list-page store "alpha" "" "" :resource "secrets" :continuation replacement)))
            (is (equal "b" (gethash "name" (gethash "metadata" (aref (gethash "items" resumed) 0)))))))))))

;; podster-uqb.122: ReplicaSet Replace and Patch watched from a revision 305 seconds old.
(test watch-history-reaches-further-back-than-a-commit-writes
  (with-temporary-store (store path)
    (let* ((now 1000) (gr8s.store::*podtemplate-clock* (lambda () now)))
      (flet ((create (name)
               (gr8s.resources::create-core-resource store "configmaps" (durable-watch-fixture "configmaps" name) "alpha")
               (gr8s.store::pod-store-resource-revision store))
             (names (store revision)
               (mapcar (lambda (event) (gethash "name" (gethash "metadata" (gethash "object" event))))
                       (gr8s.apiserver::template-watch-events store "alpha" "" "" revision :resource "configmaps"))))
        (let ((created (create "first")))
          (setf now 1305)
          (create "second")
          (is (equal '("first" "second") (names store (1- created))))
          (is (equal '("second") (names store created)))
          ;; A commit writes only what it always wrote, and a restart resumes from that.
          (let ((state (gr8s.resources::read-durable-core-state store)))
            (is (= 1 (length (gethash "templateHistory" state))))
            (is (= created (gethash "templateHistoryFloor" state))))
          (let ((reopened (open-store path)))
            (is (equal '("second") (names reopened created)))
            (signals gr8s.model::kubernetes-error (names reopened (1- created))))
          ;; Past the window, the journal lets go of it here as well.
          (setf now 1601)
          (create "third")
          (is (= created (gr8s.store::pod-store-template-history-floor store)))
          (is (equal '("second" "third") (names store created)))
          (signals gr8s.model::kubernetes-error (names store (1- created))))))))

(test watch-history-holds-more-than-a-commit-writes-up-to-its-own-limit
  (with-temporary-store (store path)
    (values path)
    (flet ((create-all (names)
             (dolist (name names)
               (gr8s.resources::create-core-resource store "configmaps" (durable-watch-fixture "configmaps" name) "alpha"))))
      (let ((gr8s.resources::*podtemplate-history-limit* 2) (start (gr8s.store::pod-store-resource-revision store)))
        (create-all '("a" "b" "c" "d" "e"))
        (is (= 5 (length (gr8s.store::pod-store-template-history store))))
        (is (= start (gr8s.store::pod-store-template-history-floor store)))
        (is (= 2 (length (gethash "templateHistory"
                                  (gr8s.resources::read-durable-core-state store))))))
      (let ((gr8s.resources::*resource-watch-history-limit* 3))
        (create-all '("f"))
        (is (= 3 (length (gr8s.store::pod-store-template-history store))))
        (is (= (- (gr8s.store::pod-store-resource-revision store) 3)
               (gr8s.store::pod-store-template-history-floor store)))))))

(test watch-history-stops-at-its-memory-limit-and-expires-what-it-dropped
  (with-temporary-store (store path)
    (values path)
    (flet ((update (count)
             (flet ((fill-data (object index)
                      (setf (gethash "data" object) (gr8s.resources::core-object "value" (make-string 10000 :initial-element #\x)
                                                                      "index" (write-to-string index)))
                      object))
               (gr8s.resources::create-core-resource store "configmaps" (fill-data (durable-watch-fixture "configmaps" "big") 0) "alpha")
               (loop for index from 1 below count
                     do (gr8s.resources::update-core-resource store "configmaps" "alpha" "big"
                                                    (lambda (object) (fill-data object index)))))))
      ;; Each change keeps the version it replaced, about 40 KB here.
      (let ((gr8s.resources::*resource-watch-history-bytes* (* 400 1024)))
        (update 30)
        (let ((history (gr8s.store::pod-store-template-history store)))
          (is (< 3 (length history) 12))
          (is (<= (reduce #'+ history :key #'gr8s.resources::template-history-entry-bytes) (* 400 1024)))
          (is (< (gr8s.store::pod-store-template-history-floor store) (gethash "revision" (first history)))))
        (is (= 410 (core-resource-status
                    (lambda () (gr8s.resources::template-list-page store "alpha" "" "" :resource "configmaps"
                                                          :resource-version (write-to-string (1- (gr8s.store::pod-store-template-history-floor store)))))))))))
  ;; Small objects keep the whole count however many there are.
  (with-temporary-store (store path)
    (values path)
    (dolist (name '("a" "b" "c" "d" "e"))
      (gr8s.resources::create-core-resource store "configmaps" (durable-watch-fixture "configmaps" name) "alpha"))
    (is (= 5 (length (gr8s.store::pod-store-template-history store))))))

(test legacy-template-history-upgrade-does-not-invent-other-resource-history
  (with-temporary-store (store path)
    (gr8s.resources::create-core-resource store "configmaps" (durable-watch-fixture "configmaps" "settings") "alpha")
    (dolist (name '("a" "b"))
      (gr8s.resources::create-core-resource store "podtemplates" (podtemplate-fixture name) "alpha"))
    (let* ((state-path (gr8s.resources::core-resource-state-path store))
           (state (gr8s.resources::read-durable-core-state store))
           (revision (gethash "revision" state))
           (token-object (gr8s.resources::core-object "namespace" "alpha" "labels" "" "fields" "" "revision" revision
                                           "lastKey" "alpha/a" "issuedAt" (get-universal-time)))
           (payload (ag-grpc:base64-encode (trivial-utf-8:string-to-utf-8-bytes (com.inuoe.jzon:stringify token-object))))
           (token (concatenate 'string payload "." (gr8s.resources::template-token-signature store payload))))
      ;; Exact shape written by versions that only tracked PodTemplates.
      (setf (gethash "version" state) 1)
      (remhash "resourceHistoryStart" state)
      (setf (gethash "templateHistory" state)
            (coerce (loop for entry across (gethash "templateHistory" state)
                          when (equal "podtemplates" (gethash "resource" entry))
                            collect (progn (remhash "resource" entry) entry)) 'vector))
      ;; Those versions wrote everything to the one file and kept no journal.
      (gr8s.security::write-private-text-atomically state-path (com.inuoe.jzon:stringify state))
      (uiop:delete-file-if-exists (gr8s.resources::core-journal-path store))
      (let* ((reopened (open-store path))
             (page (gr8s.resources::template-list-page reopened "alpha" "" "" :continuation token)))
        (is (equal "b" (gethash "name" (gethash "metadata" (aref (gethash "items" page) 0)))))
        (is (= 410 (core-resource-status (lambda () (gr8s.resources::template-list-page reopened "alpha" "" "" :resource "configmaps" :resource-version "1")))))
        (is (= 400 (core-resource-status (lambda () (gr8s.resources::template-list-page reopened "alpha" "" "" :resource "configmaps" :continuation token)))))
        (gr8s.resources::update-core-resource reopened "configmaps" "alpha" "settings"
          (lambda (object) (setf (gethash "data" object) (gr8s.resources::core-object "key" "new")) object))
        (multiple-value-bind (events watermark) (gr8s.apiserver::template-watch-events (open-store path) "alpha" "" "" revision :resource "configmaps")
          (declare (ignore watermark))
          (is (equal '("MODIFIED") (mapcar (lambda (event) (gethash "type" event)) events))))))))

(in-suite gr8s)

;; podster-uqb.140: a commit appends what it changed; the store is rebuilt from
;; the last checkpoint and the journal of later commits.
(test core-commits-journal-their-changes-and-replay-on-reopen
  (with-temporary-store (store path)
    (gr8s.resources::create-core-resource store "configmaps" (durable-watch-fixture "configmaps" "kept") "alpha")
    (let ((checkpoint (uiop:read-file-string (gr8s.resources::core-resource-state-path store))))
      (dotimes (index 5)
        (gr8s.resources::create-core-resource store "configmaps" (durable-watch-fixture "configmaps" (format nil "c~D" index)) "alpha"))
      (gr8s.resources::update-core-resource store "configmaps" "alpha" "kept"
        (lambda (object) (setf (gethash "data" object) (gr8s.resources::core-object "mode" "journaled")) object))
      (gr8s.resources::delete-core-resource store "configmaps" "alpha" "c0")
      ;; The checkpoint was not rewritten; each commit added one journal line.
      (is (equal checkpoint (uiop:read-file-string (gr8s.resources::core-resource-state-path store))))
      (is (= 7 (length (uiop:read-file-lines (gr8s.resources::core-journal-path store)))))
      (let ((reopened (open-store path)))
        (is (= (gr8s.store::pod-store-resource-revision store) (gr8s.store::pod-store-resource-revision reopened)))
        (is (equal (sort (mapcar (lambda (object) (gethash "name" (gethash "metadata" object)))
                                 (gr8s.resources::list-core-resources reopened "configmaps" "alpha")) #'string<)
                   '("c1" "c2" "c3" "c4" "kept")))
        (is (equal "journaled" (gethash "mode" (gethash "data" (gr8s.resources::get-core-resource reopened "configmaps" "alpha" "kept")))))
        ;; The history a watch resumes from was rebuilt too.
        (flet ((entries (store)
                 (mapcar (lambda (entry)
                           (list (gethash "revision" entry) (gethash "resource" entry) (gethash "name" entry)
                                 (hash-table-p (gethash "old" entry)) (hash-table-p (gethash "new" entry))))
                         (gr8s.store::pod-store-template-history store))))
          (is (equal (entries store) (entries reopened))))
        (is (= (gr8s.store::pod-store-template-history-floor store) (gr8s.store::pod-store-template-history-floor reopened)))))))

(test core-journal-checkpoints-when-it-outgrows-the-checkpoint
  (with-temporary-store (store path)
    (let ((gr8s.resources::*core-journal-checkpoint-bytes* 2000))
      (dotimes (index 40)
        (gr8s.resources::create-core-resource store "configmaps" (durable-watch-fixture "configmaps" (format nil "c~D" index)) "alpha"))
      ;; The journal never grows far past the larger of the limit and the checkpoint.
      (is (<= (gr8s.store::pod-store-core-journal-bytes store)
              (+ 2000 (gr8s.store::pod-store-core-checkpoint-bytes store) 2000)))
      (is (= 40 (length (gr8s.resources::list-core-resources (open-store path) "configmaps" "alpha")))))))

(test torn-core-journal-record-is-dropped-and-never-followed
  (with-temporary-store (store path)
    (dolist (name '("a" "b"))
      (gr8s.resources::create-core-resource store "configmaps" (durable-watch-fixture "configmaps" name) "alpha"))
    (let ((revision (gr8s.store::pod-store-resource-revision store)))
      ;; A crash while appending leaves part of a record at the end.
      (with-open-file (stream (gr8s.resources::core-journal-path store) :direction :output :if-exists :append)
        (write-string "{\"revision\":99,\"changes\":[{\"resou" stream))
      (let ((reopened (open-store path)))
        (is (= revision (gr8s.store::pod-store-resource-revision reopened)))
        (is (gr8s.store::pod-store-core-checkpoint-needed reopened))
        ;; The next commit writes a checkpoint, so nothing follows the torn record.
        (gr8s.resources::create-core-resource reopened "configmaps" (durable-watch-fixture "configmaps" "c") "alpha")
        (is (null (probe-file (gr8s.resources::core-journal-path reopened))))
        (gr8s.resources::create-core-resource reopened "configmaps" (durable-watch-fixture "configmaps" "d") "alpha")
        (is (equal '("a" "b" "c" "d")
                   (sort (mapcar (lambda (object) (gethash "name" (gethash "metadata" object)))
                                 (gr8s.resources::list-core-resources (open-store path) "configmaps" "alpha"))
                         #'string<))))))
  ;; Damage before the end is not a crash and is refused.
  (with-temporary-store (store path)
    (dolist (name '("a" "b" "c"))
      (gr8s.resources::create-core-resource store "configmaps" (durable-watch-fixture "configmaps" name) "alpha"))
    (let ((lines (uiop:read-file-lines (gr8s.resources::core-journal-path store))))
      (with-open-file (stream (gr8s.resources::core-journal-path store) :direction :output :if-exists :supersede)
        (format stream "~A~%{damaged~%" (first lines))))
    (signals error (open-store path))))
