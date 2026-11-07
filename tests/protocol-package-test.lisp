(in-package #:gr8s/tests)

(in-suite gr8s)

(test protocol-has-an-explicit-package-boundary
  (let ((protocol (find-package '#:gr8s.protocol))
        (composition (find-package '#:gr8s)))
    (is-true protocol)
    (dolist (name '("MAKE-AGENT-ENVELOPE"
                    "MAKE-UNIX-GRPC-CHANNEL"
                    "READ-WEBSOCKET-FRAME"
                    "CONNECT-RUNTIME-STREAM"
                    "MAKE-SPDY-SERVER"))
      (multiple-value-bind (implementation status)
          (find-symbol name protocol)
        (is (eq :external status))
        (is (eq protocol (symbol-package implementation)))
        (is (eq implementation (find-symbol name composition)))))
    (is (not (eq :external
                 (nth-value 1 (find-symbol "FOR" protocol)))))))

(test security-has-an-explicit-package-boundary
  (let ((security (find-package '#:gr8s.security))
        (composition (find-package '#:gr8s)))
    (is-true security)
    (dolist (name '("API-CSR-PROFILE-CERTIFICATE-P"
                    "ENSURE-CLUSTER-PKI"
                    "MAKE-NODE-TLS-CHANNEL"
                    "ENSURE-RAFT-FOUNDER-CREDENTIALS"
                    "PARSE-AND-VERIFY-CERTIFICATE-REQUEST"))
      (multiple-value-bind (implementation status)
          (find-symbol name security)
        (is (eq :external status))
        (is (eq security (symbol-package implementation)))
        (is (eq implementation (find-symbol name composition)))))
    (is (not (eq :external
                 (nth-value 1 (find-symbol "FOR" security)))))))

(test kubelet-has-an-explicit-package-boundary
  (let ((kubelet (find-package '#:gr8s.kubelet))
        (composition (find-package '#:gr8s)))
    (is-true kubelet)
    (dolist (name '("ENSURE-CONTAINER-PROBE-MANAGER"
                    "CLEANUP-POD-VOLUMES"
                    "KUBELET-INSTRUMENTATION-TEXT"
                    "MAKE-RECONCILER"
                    "RECONCILE-POD"))
      (multiple-value-bind (implementation status)
          (find-symbol name kubelet)
        (is (eq :external status))
        (is (eq kubelet (symbol-package implementation)))
        (is (eq implementation (find-symbol name composition)))))
    (is (not (eq :external
                 (nth-value 1 (find-symbol "FOR" kubelet)))))))

(test controller-orchestration-has-an-explicit-package-boundary
  (let ((controllers (find-package '#:gr8s.controllers))
        (composition (find-package '#:gr8s)))
    (dolist (name '("SCHEDULE-POD"
                    "MAKE-CONTROL-PLANE-RUNTIME"
                    "SCHEDULER-METRICS-TEXT"
                    "RECONCILE-POD-CERTIFICATE-REQUESTS"))
      (multiple-value-bind (implementation status)
          (find-symbol name controllers)
        (is (eq :external status))
        (is (eq controllers (symbol-package implementation)))
        (is (eq implementation (find-symbol name composition)))))))
(test server-assembly-has-an-explicit-package-boundary
  (let ((server (find-package '#:gr8s.server))
        (composition (find-package '#:gr8s)))
    (dolist (name '("MAIN" "PARSE-CLI-OPTIONS" "RUN-DOCTOR"))
      (multiple-value-bind (implementation status)
          (find-symbol name server)
        (is (eq :external status))
        (is (eq server (symbol-package implementation)))
        (is (eq implementation (find-symbol name composition)))))))
