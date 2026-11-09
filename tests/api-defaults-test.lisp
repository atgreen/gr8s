(in-package #:gr8s/tests)
(def-suite api-defaults :in gr8s)
(in-suite api-defaults)

;;; Expected values follow upstream v1.37.2's pkg/apis/core/v1/defaults.go and
;;; zz_generated.defaults.go (SetDefaults_PodSpec, SetDefaults_Pod, SetDefaults_Container and
;;; the nested volume, probe and field-selector defaults), and networking/v1's SetDefaults_IngressClass.

(defparameter *minimal-defaults-pod*
  "{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"name\":\"minimal\"},\"spec\":{
    \"containers\":[{\"name\":\"c\",\"image\":\"busybox:1.36\",\"ports\":[{\"containerPort\":80}],
                     \"env\":[{\"name\":\"N\",\"valueFrom\":{\"fieldRef\":{\"fieldPath\":\"metadata.name\"}}}],
                     \"readinessProbe\":{\"grpc\":{\"port\":9000}},
                     \"lifecycle\":{\"preStop\":{\"httpGet\":{\"port\":80}}}},
                    {\"name\":\"d\",\"image\":\"busybox\"}],
    \"initContainers\":[{\"name\":\"i\",\"image\":\"registry:5000/tool:latest@sha256:0123\"}],
    \"volumes\":[{\"name\":\"s\",\"secret\":{\"secretName\":\"x\"}},
                 {\"name\":\"m\",\"configMap\":{\"name\":\"x\"}},
                 {\"name\":\"a\",\"downwardAPI\":{\"items\":[{\"path\":\"n\",\"fieldRef\":{\"fieldPath\":\"metadata.name\"}}]}},
                 {\"name\":\"p\",\"projected\":{\"sources\":[{\"serviceAccountToken\":{\"path\":\"t\"}}]}},
                 {\"name\":\"h\",\"hostPath\":{\"path\":\"/tmp\"}},
                 {\"name\":\"e\"}]}}")

(defun json-path (object &rest keys)
  "Follow KEYS (strings for fields, integers for array indices) through OBJECT."
  (dolist (key keys object)
    (setf object (if (integerp key) (aref object key) (gethash key object)))))

(test created-pods-carry-the-api-server-defaults
  (with-core-api (store path)
    (values store path)
    (check-core-status 201 "/api/v1/namespaces/default/pods" :method :post
                                                             :octets (trivial-utf-8:string-to-utf-8-bytes *minimal-defaults-pod*))
    (let ((spec (gethash "spec" (check-core-status 200 "/api/v1/namespaces/default/pods/minimal"))))
      (is (equal "Always" (gethash "restartPolicy" spec)))
      (is (equal "ClusterFirst" (gethash "dnsPolicy" spec)))
      (is (eq t (gethash "enableServiceLinks" spec)))
      (is (equal "default-scheduler" (gethash "schedulerName" spec)))
      (is (hash-table-p (gethash "securityContext" spec)))
      (is (equal "IfNotPresent" (json-path spec "containers" 0 "imagePullPolicy")))
      (is (equal "Always" (json-path spec "containers" 1 "imagePullPolicy")))
      ;; A latest tag pinned by digest is still the latest tag to parsers.ParseImageName.
      (is (equal "Always" (json-path spec "initContainers" 0 "imagePullPolicy")))
      (is (equal "TCP" (json-path spec "containers" 0 "ports" 0 "protocol")))
      (is (equal "v1" (json-path spec "containers" 0 "env" 0 "valueFrom" "fieldRef" "apiVersion")))
      (is (equal "" (json-path spec "containers" 0 "readinessProbe" "grpc" "service")))
      (is (equal "/" (json-path spec "containers" 0 "lifecycle" "preStop" "httpGet" "path")))
      (is (equal "HTTP" (json-path spec "containers" 0 "lifecycle" "preStop" "httpGet" "scheme")))
      (is (equal "/dev/termination-log" (json-path spec "initContainers" 0 "terminationMessagePath")))
      (dolist (index '(0 1 2 3))
        (let ((volume (json-path spec "volumes" index)))
          (is (eql 420 (gethash "defaultMode" (gethash (find-if (lambda (key) (gethash key volume))
                                                                 '("secret" "configMap" "downwardAPI" "projected"))
                                                        volume)))
              "~A" (gethash "name" volume))))
      (is (equal "v1" (json-path spec "volumes" 2 "downwardAPI" "items" 0 "fieldRef" "apiVersion")))
      (is (eql 3600 (json-path spec "volumes" 3 "projected" "sources" 0 "serviceAccountToken" "expirationSeconds")))
      (is (equal "" (json-path spec "volumes" 4 "hostPath" "type")))
      ;; SetDefaults_Volume gives a volume without a source an emptyDir.
      (is (hash-table-p (json-path spec "volumes" 5 "emptyDir"))))))

(test explicit-values-survive-defaulting
  (let ((spec (com.inuoe.jzon:parse
               "{\"restartPolicy\":\"Never\",\"enableServiceLinks\":false,\"terminationGracePeriodSeconds\":0,
                 \"containers\":[{\"name\":\"c\",\"image\":\"a\",\"imagePullPolicy\":\"Never\",
                                  \"ports\":[{\"containerPort\":53,\"protocol\":\"UDP\"}]}],
                 \"volumes\":[{\"name\":\"s\",\"secret\":{\"secretName\":\"x\",\"defaultMode\":256}}]}")))
    (gr8s::default-pod-spec-object spec)
    (is (equal "Never" (gethash "restartPolicy" spec)))
    (is (eq nil (gethash "enableServiceLinks" spec)))
    (is (eql 0 (gethash "terminationGracePeriodSeconds" spec)))
    (is (equal "Never" (json-path spec "containers" 0 "imagePullPolicy")))
    (is (equal "UDP" (json-path spec "containers" 0 "ports" 0 "protocol")))
    (is (eql 256 (json-path spec "volumes" 0 "secret" "defaultMode")))
    (is-true (gr8s::pod-spec-defaulted-p spec))))

(test a-pod-template-gets-podspec-defaults-but-not-the-pod-only-ones
  (let ((spec (com.inuoe.jzon:parse "{\"containers\":[{\"name\":\"c\",\"image\":\"a:1\"}]}")))
    (gr8s::default-pod-template-spec-object spec)
    (is (equal "IfNotPresent" (json-path spec "containers" 0 "imagePullPolicy")))
    (is (equal "Always" (gethash "restartPolicy" spec)))
    ;; "For historical reasons, PodTemplate is not defaulted this way" (SetDefaults_Pod).
    (is (null (nth-value 1 (gethash "enableServiceLinks" spec))))))

(test updating-a-pod-stored-without-defaults-keeps-its-representation
  (with-temporary-store (store path)
    (values path)
    (let* ((pod (create-pod store (parse-pod *valid-pod-json*)))
           (legacy (gethash "spec" (pod-to-object pod))))
      ;; As an older gr8s stored it.
      (dolist (field '("dnsPolicy" "enableServiceLinks" "restartPolicy"))
        (remhash field legacy))
      (remhash "imagePullPolicy" (aref (gethash "containers" legacy) 0))
      (remhash "protocol" (aref (gethash "ports" (aref (gethash "containers" legacy) 0)) 0))
      (let* ((fingerprint (gr8s::pod-runtime-spec-fingerprint pod))
             (replacement (parse-pod (com.inuoe.jzon:stringify (pod-to-object pod))))
             (labels (gr8s::core-object "edited" "yes")))
        (setf (gethash "labels" (gethash "metadata" (pod-to-object replacement))) labels)
        (let ((updated (update-pod store replacement (pod-resource-version pod))))
          (is (equal fingerprint (gr8s::pod-runtime-spec-fingerprint updated)))
          (is (null (nth-value 1 (gethash "enableServiceLinks" (gethash "spec" (pod-to-object updated))))))
          (is (eql 1 (gethash "generation" (gethash "metadata" (pod-to-object updated))))))))))

(test updating-a-defaulted-pod-restores-an-omitted-default
  (with-temporary-store (store path)
    (values path)
    (let* ((pod (create-pod store (parse-pod *valid-pod-json*)))
           (fingerprint (gr8s::pod-runtime-spec-fingerprint pod))
           (replacement (parse-pod (com.inuoe.jzon:stringify (pod-to-object pod)))))
      (is (equal "Always" (json-path (pod-to-object pod) "spec" "containers" 0 "imagePullPolicy")))
      ;; A client's PUT that leaves defaults out still means them.
      (remhash "imagePullPolicy" (aref (gethash "containers" (gethash "spec" (pod-to-object replacement))) 0))
      (remhash "enableServiceLinks" (gethash "spec" (pod-to-object replacement)))
      (let ((updated (update-pod store replacement (pod-resource-version pod))))
        (is (equal fingerprint (gr8s::pod-runtime-spec-fingerprint updated)))
        (is (equal "Always" (json-path (pod-to-object updated) "spec" "containers" 0 "imagePullPolicy")))
        (is (eql 1 (gethash "generation" (gethash "metadata" (pod-to-object updated)))))))))

(defun pod-tolerations-of (object)
  "Return (key effect seconds) for each toleration of a Pod OBJECT."
  (map 'list (lambda (toleration)
               (list (gethash "key" toleration) (gethash "effect" toleration) (gethash "tolerationSeconds" toleration)))
       (gethash "tolerations" (gethash "spec" object) #())))

(defparameter *default-tolerations*
  '(("node.kubernetes.io/not-ready" "NoExecute" 300) ("node.kubernetes.io/unreachable" "NoExecute" 300))
  "What upstream's DefaultTolerationSeconds admission (plugin/pkg/admission/defaulttolerationseconds)
appends to a Pod that does not already tolerate those taints.")

(test created-pods-tolerate-not-ready-and-unreachable-nodes-for-five-minutes
  (with-core-api (store path)
    (values store path)
    (flet ((create (name tolerations)
             (let ((object (com.inuoe.jzon:parse *valid-pod-json*)))
               (setf (gethash "name" (gethash "metadata" object)) name)
               (when tolerations (setf (gethash "tolerations" (gethash "spec" object)) (com.inuoe.jzon:parse tolerations)))
               (check-core-status 201 "/api/v1/namespaces/default/pods" :method :post :object object)
               (check-core-status 200 (format nil "/api/v1/namespaces/default/pods/~A" name)))))
      (let ((plain (create "plain" nil)))
        (is (equal *default-tolerations* (pod-tolerations-of plain)))
        (is (equal "Exists" (json-path plain "spec" "tolerations" 0 "operator"))))
      ;; A toleration of the not-ready taint, or of every NoExecute taint, is left alone.
      (is (equal '(("node.kubernetes.io/not-ready" "NoExecute" 60) ("node.kubernetes.io/unreachable" "NoExecute" 300))
                 (pod-tolerations-of (create "own" "[{\"key\":\"node.kubernetes.io/not-ready\",\"operator\":\"Exists\",\"effect\":\"NoExecute\",\"tolerationSeconds\":60}]"))))
      (is (equal '((nil "NoExecute" nil))
                 (pod-tolerations-of (create "every" "[{\"operator\":\"Exists\",\"effect\":\"NoExecute\"}]"))))
      (is (equal '(("dedicated" "NoSchedule" nil) ("node.kubernetes.io/not-ready" "NoExecute" 300)
                   ("node.kubernetes.io/unreachable" "NoExecute" 300))
                 (pod-tolerations-of (create "other" "[{\"key\":\"dedicated\",\"operator\":\"Exists\",\"effect\":\"NoSchedule\"}]"))))
      ;; Upstream admits updates too: a PUT that leaves them out keeps them.
      (let ((current (check-core-status 200 "/api/v1/namespaces/default/pods/plain")))
        (remhash "tolerations" (gethash "spec" current))
        (is (equal *default-tolerations*
                   (pod-tolerations-of (check-core-status 200 "/api/v1/namespaces/default/pods/plain" :method :put :object current))))))))

(test controller-and-template-pods-follow-the-toleration-admission
  (with-temporary-store (store path)
    (values path)
    ;; Pods created in process, as controllers do, are admitted the same way.
    (is (equal *default-tolerations* (pod-tolerations-of (pod-to-object (create-pod store (parse-pod *valid-pod-json*))))))
    ;; The plugin admits Pods, not the templates of the workloads that make them.
    (is (null (pod-tolerations-of (gr8s::defaulted-pod-template (com.inuoe.jzon:parse *valid-pod-json*)))))))

(test updating-a-pod-stored-without-default-tolerations-keeps-its-spec
  (with-temporary-store (store path)
    (values path)
    (let* ((pod (create-pod store (parse-pod *valid-pod-json*))))
      ;; As an older gr8s stored it, with no admitted tolerations.
      (remhash "tolerations" (gethash "spec" (pod-to-object pod)))
      (let* ((fingerprint (gr8s::pod-runtime-spec-fingerprint pod))
             (replacement (parse-pod (com.inuoe.jzon:stringify (pod-to-object pod)))))
        (setf (gethash "labels" (gethash "metadata" (pod-to-object replacement))) (gr8s::core-object "edited" "yes"))
        (let ((updated (update-pod store replacement (pod-resource-version pod))))
          (is (equal fingerprint (gr8s::pod-runtime-spec-fingerprint updated)))
          (is (null (pod-tolerations-of (pod-to-object updated)))))))))

(test nodes-carry-a-durable-creation-timestamp
  (with-temporary-store (store path)
    (gr8s:register-node store (gr8s:make-node-record :id "created-node" :name "worker-created" :pod-cidr "10.88.9.0/24"))
    (let* ((node (gr8s:get-node store "worker-created"))
           (created (gethash "creationTimestamp" (gethash "metadata" (gr8s::node-api-object node)))))
      (is (stringp created))
      (is (equal created (gr8s::node-record-creation-timestamp
                          (gr8s::parse-node-record (gr8s::node-record-to-object node)))))
      ;; A node an older gr8s registered gets one when its agent's lease begins again.
      (setf (gr8s::node-record-creation-timestamp node) nil)
      (gr8s::mark-node-ready store "worker-created" (get-universal-time))
      (is (stringp (gethash "creationTimestamp"
                            (gethash "metadata" (gr8s::node-api-object (gr8s:get-node store "worker-created"))))))
      (let ((reopened (gr8s:open-store path)))
        (is (stringp (gr8s::node-record-creation-timestamp (gr8s:get-node reopened "worker-created"))))))))

(test api-created-nodes-have-a-creation-timestamp
  (with-core-api (store path)
    (values store path)
    (check-core-status 201 "/api/v1/nodes" :method :post
                                           :object (gr8s::core-object "apiVersion" "v1" "kind" "Node"
                                                                      "metadata" (gr8s::core-object "name" "api-node")))
    (is (stringp (json-path (check-core-status 200 "/api/v1/nodes/api-node") "metadata" "creationTimestamp")))))

(test ingress-class-parameters-default-to-cluster-scope
  (with-core-api (store path)
    (values store path)
    (check-core-status 201 "/apis/networking.k8s.io/v1/ingressclasses" :method :post
                       :object (com.inuoe.jzon:parse "{\"apiVersion\":\"networking.k8s.io/v1\",\"kind\":\"IngressClass\",\"metadata\":{\"name\":\"scoped\"},\"spec\":{\"controller\":\"example.com/x\",\"parameters\":{\"kind\":\"K\",\"name\":\"p\"}}}"))
    (is (equal "Cluster" (json-path (check-core-status 200 "/apis/networking.k8s.io/v1/ingressclasses/scoped")
                                    "spec" "parameters" "scope")))))

;;; Defaults of other kinds: core/v1 SetObjectDefaults_PersistentVolume, apps/v1
;;; SetObjectDefaults_StatefulSet and networking/v1 SetObjectDefaults_NetworkPolicy (v1.37.2).

(test network-policies-carry-their-policy-types-and-port-protocols
  (with-temporary-store (store path)
    (values path)
    (flet ((create (name spec)
             (gethash "spec" (gr8s::create-core-resource
                              store "networkpolicies"
                              (gr8s::core-object "metadata" (gr8s::core-object "name" name) "spec" (com.inuoe.jzon:parse spec))
                              "default"))))
      (let ((ingress (create "ingress" "{\"podSelector\":{},\"ingress\":[{\"ports\":[{\"port\":80},{\"port\":53,\"protocol\":\"UDP\"}]}]}")))
        (is (equalp #("Ingress") (gethash "policyTypes" ingress)))
        (is (equal "TCP" (json-path ingress "ingress" 0 "ports" 0 "protocol")))
        (is (equal "UDP" (json-path ingress "ingress" 0 "ports" 1 "protocol"))))
      (let ((both (create "both" "{\"podSelector\":{},\"egress\":[{\"ports\":[{\"port\":443}]}]}")))
        (is (equalp #("Ingress" "Egress") (gethash "policyTypes" both)))
        (is (equal "TCP" (json-path both "egress" 0 "ports" 0 "protocol"))))
      ;; Named types are kept, whatever rules there are.
      (is (equalp #("Egress") (gethash "policyTypes" (create "named" "{\"podSelector\":{},\"policyTypes\":[\"Egress\"]}")))))))

(test persistent-volumes-default-their-source-and-get-no-class
  (with-temporary-store (store path)
    (let ((volume (gr8s::create-core-resource
                   store "persistentvolumes"
                   (gr8s::core-object "metadata" (gr8s::core-object "name" "plain")
                                      "spec" (gr8s::core-object "capacity" (gr8s::core-object "storage" "1Gi")
                                                                "accessModes" #("ReadWriteOnce")
                                                                "hostPath" (gr8s::core-object "path" (namestring path))))
                   nil)))
      (is (equal "" (json-path volume "spec" "hostPath" "type")))
      ;; DefaultStorageClass admission defaults only claims.
      (is (not (nth-value 1 (gethash "storageClassName" (gethash "spec" volume)))))
      (is (equal "Filesystem" (json-path volume "spec" "volumeMode")))
      (is (equal "Retain" (json-path volume "spec" "persistentVolumeReclaimPolicy"))))
    ;; A volume stored before these defaults can still be updated, and gains them.
    (let ((volume (gr8s::create-core-resource
                   store "persistentvolumes"
                   (gr8s::core-object "metadata" (gr8s::core-object "name" "legacy")
                                      "spec" (gr8s::core-object "capacity" (gr8s::core-object "storage" "1Gi")
                                                                "accessModes" #("ReadWriteOnce") "storageClassName" ""
                                                                "hostPath" (gr8s::core-object "path" (namestring path))))
                   nil)))
      (remhash "type" (json-path volume "spec" "hostPath"))
      (setf (gethash (gr8s::core-resource-key "persistentvolumes" nil "legacy") (gr8s::pod-store-resources store)) volume)
      (let ((updated (gr8s::update-core-resource store "persistentvolumes" nil "legacy"
                                                 (lambda (object)
                                                   (setf (gethash "labels" (gethash "metadata" object)) (gr8s::core-object "edited" "yes"))
                                                   object))))
        (is (equal "" (json-path updated "spec" "hostPath" "type")))
        (is (equal "" (json-path updated "spec" "storageClassName")))))))

(test stateful-sets-default-their-claim-templates
  (with-temporary-store (store path)
    (values path)
    (gr8s::create-core-resource store "namespaces" (gr8s::core-object "metadata" (gr8s::core-object "name" "alpha")) nil)
    ;; A set without templates stores none, not an empty list.
    (is (not (nth-value 1 (gethash "volumeClaimTemplates"
                                   (gethash "spec" (gr8s::create-core-resource store "statefulsets" (stateful-fixture "plain") "alpha"))))))
    (let* ((template (stateful-claim-template "data"))
           (created (gr8s::create-core-resource store "statefulsets" (stateful-fixture "web" :claims (vector template)) "alpha")))
      (is (equal "Filesystem" (json-path created "spec" "volumeClaimTemplates" 0 "spec" "volumeMode")))
      (is (equal "Pending" (json-path created "spec" "volumeClaimTemplates" 0 "status" "phase")))
      ;; A set stored before the defaults, with templates lacking them, can still be scaled.
      (let ((stored (gr8s::copy-core-object created)))
        (remhash "status" (json-path stored "spec" "volumeClaimTemplates" 0))
        (remhash "volumeMode" (json-path stored "spec" "volumeClaimTemplates" 0 "spec"))
        (setf (gethash (gr8s::core-resource-key "statefulsets" "alpha" "web") (gr8s::pod-store-resources store)) stored))
      (let ((scaled (gr8s::update-core-resource store "statefulsets" "alpha" "web"
                                                (lambda (object) (setf (gethash "replicas" (gethash "spec" object)) 1) object))))
        (is (= 1 (json-path scaled "spec" "replicas")))
        (is (equal "Pending" (json-path scaled "spec" "volumeClaimTemplates" 0 "status" "phase")))))
    ;; So can one stored with an empty list.
    (let ((stored (gr8s::copy-core-object (gr8s::get-core-resource store "statefulsets" "alpha" "plain"))))
      (setf (gethash "volumeClaimTemplates" (gethash "spec" stored)) #())
      (setf (gethash (gr8s::core-resource-key "statefulsets" "alpha" "plain") (gr8s::pod-store-resources store)) stored)
      (is (= 1 (json-path (gr8s::update-core-resource store "statefulsets" "alpha" "plain"
                                                      (lambda (object) (setf (gethash "replicas" (gethash "spec" object)) 1) object))
                          "spec" "replicas"))))))

(test node-api-responses-use-the-committed-revision
  (with-core-api (store path)
    (values store path)
    (setf (gr8s::pod-store-consensus-commit-fn store)
          (lambda (tag json)
            (unless (eq tag :node-delta) (error "Unexpected command"))
            (incf (gr8s::pod-store-pod-revision store) 5)
            (gr8s::install-node-state-delta store json)))
    (let ((created (check-core-status
                    201 "/api/v1/nodes" :method :post
                    :object (gr8s::core-object "apiVersion" "v1" "kind" "Node"
                                              "metadata" (gr8s::core-object "name" "commit-version")))))
      (is (equal (json-path created "metadata" "resourceVersion")
                 (gr8s::node-record-resource-version (gr8s:get-node store "commit-version"))))
      (setf (gethash "changed" (gethash "labels" (gethash "metadata" created))) "true")
      (let ((updated (check-core-status 200 "/api/v1/nodes/commit-version" :method :put :object created)))
        (is (equal (json-path updated "metadata" "resourceVersion")
                   (gr8s::node-record-resource-version (gr8s:get-node store "commit-version"))))))))
