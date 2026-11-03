(in-package #:gr8s/tests)

(in-suite gr8s)

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
      (setf (gethash "terminationGracePeriodSeconds" (gethash "spec" expected)) 30)
      (is (equalp expected (pod-to-object pod))))))

(test pods-accept-valid-namespaces
  (let ((object (com.inuoe.jzon:parse *valid-pod-json*)))
    (setf (gethash "namespace" (gethash "metadata" object)) "sonobuoy")
    (is (string= "sonobuoy" (pod-namespace (parse-pod object))))
    (setf (gethash "namespace" (gethash "metadata" object)) "Invalid/namespace")
    (signals kubernetes-error (parse-pod object))))

(test unsupported-pod-spec-fields-are-rejected
  (signals kubernetes-error
    (parse-pod
     "{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"name\":\"hello\"},\"spec\":{\"nodeSelector\":{\"disk\":\"ssd\"},\"containers\":[{\"name\":\"web\",\"image\":\"busybox\"}]}}")))

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
     "{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"name\":\"hello\"},\"spec\":{\"containers\":[{\"name\":\"web\",\"image\":\"busybox\",\"resources\":{\"limits\":{\"cpu\":\"1\"}}}]}}")))

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
     "{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"name\":\"hello\"},\"spec\":{\"containers\":[{\"name\":\"web\",\"image\":\"busybox\",\"ports\":[{\"containerPort\":53,\"protocol\":\"UDP\"}]}]}}")))
