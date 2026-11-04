;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Verify real per-Pod resolver policies, inherited node configuration, ordered
;;;; overrides and CRI sandbox settings with strict validation and immutable updates.

(in-package #:gr8s/tests)
(def-suite pod-dns-config :in gr8s)
(in-suite pod-dns-config)

(defun dns-config-test-object (&optional (policy "None"))
  "Build a Pod requesting explicit resolver servers, searches and an ndots override."
  (let ((object (com.inuoe.jzon:parse *valid-pod-json*)))
    (setf (gethash "dnsPolicy" (gethash "spec" object)) policy
          (gethash "dnsConfig" (gethash "spec" object))
          (gr8s::core-object "nameservers" #("1.1.1.1") "searches" #("resolv.conf.local")
                            "options" (vector (gr8s::core-object "name" "ndots" "value" "2"))))
    object))

(test pod-dns-none-actually-overrides-all-node-defaults-in-cri
  (let* ((pod (parse-pod (dns-config-test-object)))
         (runtime (gr8s::make-containerd-runtime :host-network nil :dns-servers '("169.254.1.1")
                   :dns-searches '("default.svc.cluster.local" "svc.cluster.local" "cluster.local") :dns-options '("ndots:5")))
         (gr8s::*pod-dns-host-resolv-conf* #P"/nonexistent-host-resolver-must-not-be-read")
         (config (slot-value (gr8s::containerd-sandbox-config runtime pod) 'gr8s.cri.v1::dns-config)))
    (is (equal '("1.1.1.1") (slot-value config 'gr8s.cri.v1::servers)))
    (is (equal '("resolv.conf.local") (slot-value config 'gr8s.cri.v1::searches)))
    (is (equal '("ndots:2") (slot-value config 'gr8s.cri.v1::options)))))

(test pod-dns-policies-merge-real-host-searches-and-pod-overrides
  (with-temporary-store (store directory)
    (let* ((file (merge-pathnames "resolv.conf" directory))
           (gr8s::*pod-dns-host-resolv-conf* file)
           (runtime (gr8s::make-containerd-runtime :host-network nil :dns-servers '("169.254.1.1")
                      :dns-searches '("default.svc.cluster.local" "svc.cluster.local" "cluster.local") :dns-options '("ndots:5")))
           (object (dns-config-test-object "ClusterFirst")))
      (with-open-file (out file :direction :output :if-exists :supersede)
        (format out "nameserver 9.9.9.9~%search superseded.example~%search host.example.~%options ndots:3 rotate~%"))
      (setf (gethash "namespace" (gethash "metadata" object)) "alpha"
            (gethash "nameservers" (gethash "dnsConfig" (gethash "spec" object))) #("169.254.1.1" "8.8.8.8")
            (gethash "searches" (gethash "dnsConfig" (gethash "spec" object))) #("custom.test" "host.example"))
      (multiple-value-bind (servers searches options) (gr8s::containerd-pod-dns-configuration runtime (parse-pod object))
        (is (equal '("169.254.1.1" "8.8.8.8") servers))
        (is (equal '("alpha.svc.cluster.local" "svc.cluster.local" "cluster.local" "host.example" "custom.test") searches))
        (is (equal '("ndots:2") options)))
      (setf (gethash "dnsPolicy" (gethash "spec" object)) "Default")
      (multiple-value-bind (servers searches options) (gr8s::containerd-pod-dns-configuration runtime (parse-pod object))
        (is (equal '("9.9.9.9" "169.254.1.1" "8.8.8.8") servers))
        (is (equal '("host.example" "custom.test") searches))
        (is (equal '("ndots:2" "rotate") options)))
      (remhash "dnsConfig" (gethash "spec" object))
      (setf (gethash "dnsPolicy" (gethash "spec" object)) "ClusterFirst"
            (gr8s::containerd-runtime-host-network runtime) t)
      (is (equal '("9.9.9.9") (gr8s::containerd-pod-dns-configuration runtime (parse-pod object))))
      (setf (gethash "dnsPolicy" (gethash "spec" object)) "ClusterFirstWithHostNet")
      (is (equal '("169.254.1.1") (gr8s::containerd-pod-dns-configuration runtime (parse-pod object)))))))

(test pod-dns-config-validates-literal-addresses-searches-and-required-none-servers
  (let ((object (dns-config-test-object)))
    (setf (gethash "nameservers" (gethash "dnsConfig" (gethash "spec" object))) #())
    (signals gr8s:kubernetes-error (parse-pod object)))
  (dolist (servers '(#("resolver.example") #("10.0.0.1/24") #("bad") #("1.1.1.1" "2.2.2.2" "3.3.3.3" "4.4.4.4")))
    (let ((object (dns-config-test-object)))
      (setf (gethash "nameservers" (gethash "dnsConfig" (gethash "spec" object))) servers)
      (signals gr8s:kubernetes-error (parse-pod object))))
  (let ((object (dns-config-test-object)))
    (setf (gethash "nameservers" (gethash "dnsConfig" (gethash "spec" object))) #("::1" "2001:db8::53")
          (gethash "searches" (gethash "dnsConfig" (gethash "spec" object))) #("." "_service.example."))
    (is (typep (parse-pod object) 'gr8s::pod)))
  (let ((object (dns-config-test-object)))
    (setf (gethash "searches" (gethash "dnsConfig" (gethash "spec" object))) (make-array 33 :initial-element "example.org"))
    (signals gr8s:kubernetes-error (parse-pod object)))
  (let ((object (dns-config-test-object)))
    (setf (gethash "name" (aref (gethash "options" (gethash "dnsConfig" (gethash "spec" object))) 0)) "")
    (signals gr8s:kubernetes-error (parse-pod object))))

(test pod-dns-config-is-immutable-after-create
  (with-temporary-store (store directory)
    (let* ((pod (create-pod store (parse-pod (dns-config-test-object))))
           (object (gr8s::copy-core-object (pod-to-object pod))))
      (setf (gethash "nameservers" (gethash "dnsConfig" (gethash "spec" object))) #("8.8.8.8"))
      (signals gr8s:kubernetes-error (gr8s::update-pod store (parse-pod object) (pod-resource-version pod)))
      (setf (gethash "dnsPolicy" (gethash "spec" object)) "ClusterFirst")
      (signals gr8s:kubernetes-error (gr8s::update-pod store (parse-pod object) (pod-resource-version pod))))))
