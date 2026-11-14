;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Prevent false-positive DNS shell probes by proving Kubernetes dollar escaping
;;;; executes actual shell substitutions and handles failed real DNS answers truthfully.

(in-package #:gr8s/tests)
(def-suite container-expansion :in gr8s)
(in-suite container-expansion)

(test container-command-expansion-preserves-kubernetes-escaping
  (let ((environment '(("A" . "resolved") ("EMPTY" . "") ("NESTED" . "$(A)"))))
    (is (equal '("resolved" "$(UNKNOWN)" "$(A)" "$resolved" "$(A)" "" "$" "$A" "$(A" "xresolvedy")
               (gr8s.kubelet::expand-container-command
                #("$(A)" "$(UNKNOWN)" "$$(A)" "$$$(A)" "$(NESTED)" "$(EMPTY)" "$" "$A" "$(A" "x$(A)y")
                environment)))))

(test container-command-expansion-executes-real-shell-substitution-once
  (let* ((encoded "check=\"$$(printf actual-command-ran)\"; test \"$$check\" = actual-command-ran && printf confirmed")
         (expanded (gr8s.kubelet::expand-container-command-argument encoded nil)))
    (is (equal "check=\"$(printf actual-command-ran)\"; test \"$check\" = actual-command-ran && printf confirmed" expanded))
    (is (equal "confirmed" (uiop:run-program (list "/bin/sh" "-c" expanded) :output :string)))
    (is (not (equal "confirmed" (uiop:run-program (list "/bin/sh" "-c" encoded) :output :string :ignore-error-status t))))))

(test container-command-expansion-does-not-fake-success-for-real-failed-dns
  (let ((dig (string-trim '(#\Newline #\Return #\Space)
                          (uiop:run-program '("/bin/sh" "-c" "command -v dig") :output :string :ignore-error-status t))))
    (if (zerop (length dig))
        (skip "dig is required for actual DNS shell probe")
        (with-temporary-store (store directory)
      (let ((server (cl-dns-proxy::start-dns-server :address "127.0.0.1" :port 0 :upstreams nil
                                          :resolver (gr8s.kubelet::make-cluster-dns-resolver store))))
        (unwind-protect
             (let* ((port (cl-dns-proxy::dns-server-port server))
                    (missing (format nil "check=\"$$(~A @127.0.0.1 -p ~D +time=1 +tries=1 +notcp +noall +answer missing.alpha.svc.cluster.local A)\"; test -n \"$$check\" && printf OK" dig port))
                    (known (format nil "check=\"$$(~A @127.0.0.1 -p ~D +time=1 +tries=1 +tcp +noall +answer kubernetes.default.svc.cluster.local A)\"; test -n \"$$check\" && printf OK" dig port)))
               (is (equal "OK" (uiop:run-program (list "/bin/sh" "-c" missing) :output :string)))
               (is (equal "" (uiop:run-program
                               (list "/bin/sh" "-c" (gr8s.kubelet::expand-container-command-argument missing nil))
                               :output :string :ignore-error-status t)))
               (is (equal "OK" (uiop:run-program
                                 (list "/bin/sh" "-c" (gr8s.kubelet::expand-container-command-argument known nil)) :output :string))))
          (cl-dns-proxy::stop-dns-server server)))))))

(test container-command-expansion-uses-actual-resolved-valuefrom-environment
  (with-temporary-store (store directory)
    (gr8s.resources::create-core-resource store "configmaps"
      (gr8s.resources::core-object "metadata" (gr8s.resources::core-object "name" "commands")
                        "data" (gr8s.resources::core-object "script" "resolved-config")) "sonobuoy")
    (gr8s.resources::create-core-resource store "secrets"
      (gr8s.resources::core-object "metadata" (gr8s.resources::core-object "name" "command-secret")
                        "data" (gr8s.resources::core-object "value" "cmVzb2x2ZWQtc2VjcmV0")) "sonobuoy")
    (let* ((object (com.inuoe.jzon:parse *valid-pod-json*))
           (container (aref (gethash "containers" (gethash "spec" object)) 0))
           (runtime (gr8s.runtime.containerd::%make-containerd-runtime :resource-store store)))
      (setf (gethash "namespace" (gethash "metadata" object)) "sonobuoy"
            (gethash "env" container)
            (vector (gr8s.resources::core-object "name" "CONFIG" "valueFrom"
                                      (gr8s.resources::core-object "configMapKeyRef" (gr8s.resources::core-object "name" "commands" "key" "script")))
                    (gr8s.resources::core-object "name" "SECRET" "valueFrom"
                                      (gr8s.resources::core-object "secretKeyRef" (gr8s.resources::core-object "name" "command-secret" "key" "value")))
                    (gr8s.resources::core-object "name" "NS" "valueFrom"
                                      (gr8s.resources::core-object "fieldRef" (gr8s.resources::core-object "fieldPath" "metadata.namespace")))
                    (gr8s.resources::core-object "name" "KUBERNETES_SERVICE_HOST" "value" "10.96.0.1")))
      (let* ((pod (parse-pod object))
             (environment (gr8s.kubelet::containerd-pod-environment runtime pod (aref (pod-containers pod) 0) "sandbox")))
        (is (equal '("resolved-config" "resolved-secret" "sonobuoy" "10.96.0.1" "$(MISSING)")
                   (gr8s.kubelet::expand-container-command
                    #("$(CONFIG)" "$(SECRET)" "$(NS)" "$(KUBERNETES_SERVICE_HOST)" "$(MISSING)") environment))))
      (is (equal "last" (gr8s.kubelet::expand-container-command-argument "$(DUP)" '(("DUP" . "first") ("DUP" . "last"))))))))
