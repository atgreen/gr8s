(in-package #:gr8s/tests)

(in-suite gr8s)

(test domain-types-have-an-explicit-package-boundary
  (let ((package (find-package "GR8S.MODEL")))
    (is (not (null package)))
    (dolist (name '("MAKE-POD" "POD-NAME" "MAKE-NODE-RECORD"
                    "NODE-RECORD-NAME" "MAKE-CONTAINER-SPEC"))
      (multiple-value-bind (symbol status) (and package (find-symbol name package))
        (is (not (null symbol)) "~A is present in GR8S.MODEL" name)
        (is (eq :external status) "~A is exported from GR8S.MODEL" name)))))

(defparameter *valid-pod-json*
  "{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"name\":\"hello\"},\"spec\":{\"containers\":[{\"name\":\"web\",\"image\":\"docker.io/library/busybox:latest\",\"command\":[\"sh\",\"-c\"],\"args\":[\"echo hello\"],\"env\":[{\"name\":\"GREETING\",\"value\":\"hello\"}],\"ports\":[{\"containerPort\":8080}]}]}}")

(test supported-pod-json-becomes-a-domain-pod
  (let* ((pod (parse-pod *valid-pod-json*))
         (container (aref (pod-containers pod) 0)))
    (is (string= "hello" (pod-name pod)))
    (is (string= "default" (pod-namespace pod)))
    (is (string= "Always" (pod-restart-policy pod)))
    (is (string= "web" (container-spec-name container)))
    (is (string= "docker.io/library/busybox:latest"
                 (container-spec-image container)))
    (is (equalp #( "sh" "-c") (container-spec-command container)))
    (is (equalp #( "echo hello") (container-spec-args container)))
    (is (equal '(("GREETING" . "hello")) (container-spec-env container)))
    (is (equal '(8080) (container-spec-ports container)))
    (let ((expected (com.inuoe.jzon:parse *valid-pod-json*)))
      ;; The API server's defaults (SetDefaults_PodSpec in pkg/apis/core/v1/defaults.go
      ;; gives an absent securityContext an empty one).
      (setf (gethash "terminationGracePeriodSeconds" (gethash "spec" expected)) 30
            (gethash "schedulerName" (gethash "spec" expected)) "default-scheduler"
            (gethash "securityContext" (gethash "spec" expected)) (gr8s.resources::core-object))
      (let ((expected-container (aref (gethash "containers" (gethash "spec" expected)) 0)))
        (setf (gethash "terminationMessagePath" expected-container) "/dev/termination-log"
              (gethash "terminationMessagePolicy" expected-container) "File"))
      (is (equalp expected (pod-to-object pod))))))

(test pods-accept-valid-namespaces
  (let ((object (com.inuoe.jzon:parse *valid-pod-json*)))
    (setf (gethash "namespace" (gethash "metadata" object)) "sonobuoy")
    (is (string= "sonobuoy" (pod-namespace (parse-pod object))))
    (setf (gethash "namespace" (gethash "metadata" object)) "Invalid/namespace")
    (signals kubernetes-error (parse-pod object))))

(test pod-resource-claims-use-the-kubernetes-v1-shape
  (let* ((pod (parse-pod
               "{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"name\":\"hello\"},\"spec\":{\"resourceClaims\":[{\"name\":\"gpu\",\"resourceClaimName\":\"claim\"}],\"containers\":[{\"name\":\"web\",\"image\":\"busybox\",\"resources\":{\"claims\":[{\"name\":\"gpu\",\"request\":\"device\"}]}}]}}"))
         (spec (gethash "spec" (pod-to-object pod))))
    (is (equal "claim" (gethash "resourceClaimName" (aref (gethash "resourceClaims" spec) 0))))
    (is (equal "device" (gethash "request" (aref (gethash "claims" (gethash "resources" (aref (gethash "containers" spec) 0))) 0)))))
  (dolist (claim '(("missing source" . "{\"name\":\"gpu\"}")
                   ("two sources" . "{\"name\":\"gpu\",\"resourceClaimName\":\"claim\",\"resourceClaimTemplateName\":\"template\"}")
                   ("bad name" . "{\"name\":\"Bad_Name\",\"resourceClaimName\":\"claim\"}")))
    (signals kubernetes-error
      (parse-pod
       (format nil "{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"name\":\"hello\"},\"spec\":{\"resourceClaims\":[~A],\"containers\":[{\"name\":\"web\",\"image\":\"busybox\"}]}}"
               (cdr claim)))
      (car claim))))

(test kubectl-generated-default-pod-fields-are-accepted
  (let ((pod
          (parse-pod
           "{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"name\":\"kubectl-pod\"},\"spec\":{\"containers\":[{\"name\":\"main\",\"image\":\"busybox\",\"resources\":{}}],\"restartPolicy\":\"Always\",\"dnsPolicy\":\"ClusterFirst\"},\"status\":{}}")))
    (is (string= "kubectl-pod" (pod-name pod)))))

(test client-cannot-set-pod-status-or-unsupported-default-values
  (signals kubernetes-error
    (parse-pod
     "{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"name\":\"hello\"},\"spec\":{\"containers\":[{\"name\":\"web\",\"image\":\"busybox\"}]},\"status\":{\"phase\":\"Running\"}}"))
  (signals kubernetes-error
    (parse-pod
     "{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"name\":\"hello\"},\"spec\":{\"dnsPolicy\":\"None\",\"containers\":[{\"name\":\"web\",\"image\":\"busybox\"}]}}"))
  (signals kubernetes-error
    (parse-pod
     "{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"name\":\"hello\"},\"spec\":{\"containers\":[{\"name\":\"web\",\"image\":\"busybox\",\"resources\":{\"limits\":{\"hugepages-2Mi\":\"1Gi\"}}}]}}")))

(test malformed-pod-shapes-are-kubernetes-errors
  (dolist (input
           '("[]"
             "{\"apiVersion\":1,\"kind\":\"Pod\",\"metadata\":{},\"spec\":{}}"
             "{\"apiVersion\":\"v1\",\"kind\":2,\"metadata\":{},\"spec\":{}}"
             "{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":[],\"spec\":{}}"
             "{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"name\":\"hello\"},\"spec\":[]}"
             "{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"name\":\"hello\"},\"spec\":{\"containers\":[1]}}"
             "{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"name\":\"hello\",\"namespace\":7},\"spec\":{\"containers\":[{\"name\":\"web\",\"image\":\"busybox\"}]}}"
             "{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"name\":\"hello\"},\"spec\":{\"restartPolicy\":7,\"containers\":[{\"name\":\"web\",\"image\":\"busybox\"}]}}"
             "{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"name\":\"hello\"},\"spec\":{\"containers\":[{\"name\":\"web\",\"image\":\"busybox\",\"command\":[1]}]}}"
             "{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"name\":\"hello\"},\"spec\":{\"containers\":[{\"name\":\"web\",\"image\":\"busybox\",\"env\":[1]}]}}"
             "{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"name\":\"hello\"},\"spec\":{\"containers\":[{\"name\":\"web\",\"image\":\"busybox\",\"ports\":[1]}]}}"))
    (signals kubernetes-error (parse-pod input))))

(test pod-and-container-names-use-supported-dns-syntax
  (dolist (input
           '("{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"name\":\"Bad_Name\"},\"spec\":{\"containers\":[{\"name\":\"web\",\"image\":\"busybox\"}]}}"
             "{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"name\":\"hello\"},\"spec\":{\"containers\":[{\"name\":\"Bad_Name\",\"image\":\"busybox\"}]}}"
             "{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"name\":\"hello\"},\"spec\":{\"containers\":[{\"name\":\"web\",\"image\":\"busybox\"},{\"name\":\"web\",\"image\":\"busybox\"}]}}"))
    (signals kubernetes-error (parse-pod input))))

(test restart-policy-and-port-protocol-are-validated
  (signals kubernetes-error
    (parse-pod
     "{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"name\":\"hello\"},\"spec\":{\"restartPolicy\":\"Sometimes\",\"containers\":[{\"name\":\"web\",\"image\":\"busybox\"}]}}"))
  (signals kubernetes-error
    (parse-pod
     "{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"name\":\"hello\"},\"spec\":{\"containers\":[{\"name\":\"web\",\"image\":\"busybox\",\"ports\":[{\"containerPort\":53,\"protocol\":\"QUIC\"}]}]}}"))
  (is (parse-pod
       "{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"name\":\"hello\"},\"spec\":{\"containers\":[{\"name\":\"web\",\"image\":\"busybox\",\"ports\":[{\"containerPort\":53,\"protocol\":\"UDP\"}]}]}}")))

(test a-null-list-field-is-an-omitted-one
  ;; Helm renders an empty list as null (kube-prometheus-stack's operator has
  ;; `volumes: null` and `volumeMounts: null`), and Kubernetes reads it as absent.
  (let* ((pod (parse-pod
               "{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"name\":\"hello\"},\"spec\":{\"volumes\":null,\"containers\":[{\"name\":\"web\",\"image\":\"busybox\",\"volumeMounts\":null,\"env\":null}]}}"))
         (spec (gethash "spec" (pod-to-object pod))))
    (is (string= "hello" (pod-name pod)))
    (is (not (eq 'null (gethash "volumes" spec))))
    (is (not (eq 'null (gethash "volumeMounts" (aref (gethash "containers" spec) 0))))))
  (let ((template (com.inuoe.jzon:parse
                   "{\"volumes\":null,\"containers\":[{\"name\":\"web\",\"volumeMounts\":null,\"args\":[\"a\"]}],\"nodeSelector\":{\"a\":\"b\"}}")))
    (gr8s.model::omit-null-fields template)
    (is (null (nth-value 1 (gethash "volumes" template))))
    (is (null (nth-value 1 (gethash "volumeMounts" (aref (gethash "containers" template) 0)))))
    (is (equalp #("a") (gethash "args" (aref (gethash "containers" template) 0))))
    (is (equal "b" (gethash "a" (gethash "nodeSelector" template))))))
