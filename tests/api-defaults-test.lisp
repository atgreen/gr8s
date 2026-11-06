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
