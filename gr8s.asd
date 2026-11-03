;;;; SPDX-FileCopyrightText: 2026 gr8s contributors
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Describe the serial load order and dependencies of the gr8s control plane,
;;;; node agent, networking dataplane, and their FiveAM test system.  The order
;;;; mirrors architectural dependencies so later modules can rely on the public
;;;; abstractions established by earlier files.

(asdf:defsystem "gr8s"
  :description "A small Kubernetes-compatible control plane in Common Lisp"
  :author "gr8s contributors"
  :license "MIT"
  :version "0.1.0"
  :depends-on ("0conf/dns-wire" "ag-grpc" "bordeaux-threads" "cl-cancel"
               "com.inuoe.jzon" "hunchentoot"
               "pure-tls/acme"
               "sb-posix" "trivial-utf-8" "usocket" "whistler/loader")
  :serial t
  :components ((:module "src"
                :serial t
                :components ((:file "package")
                             (:file "cri-v1-generated")
                             (:file "node-v1-generated")
                             (:file "node-protocol")
                             (:file "grpc-unix")
                             (:file "websocket")
                             (:file "dns")
                             (:file "model")
                             (:file "store")
                             (:file "scheduler")
                             (:file "pki")
                             (:file "node-tls")
                             (:file "node-session")
                             (:file "runtime")
                             (:file "runtime-assets")
                             (:file "cni")
                             (:file "node-ipam")
                             (:file "rtnetlink")
                             (:file "endpoint-policy")
                             (:file "vxlan")
                             (:file "agent-cni")
                             (:file "routed-cni")
                             (:file "managed-containerd")
                             (:file "cri")
                             (:file "containerd")
                             (:file "podman")
                             (:file "reconciler")
                             (:file "control-plane-runtime")
                             (:file "telemetry")
                             (:file "agent-runtime")
                             (:file "http")
                             (:file "server")
                             (:file "main"))))
  :in-order-to ((test-op (test-op "gr8s/tests"))))

(asdf:defsystem "gr8s/tests"
  :depends-on ("gr8s" "drakma" "fiveam")
  :serial t
  :components ((:module "tests"
                :serial t
                :components ((:file "package")
                             (:file "websocket-test")
                             (:file "node-protocol-test")
                             (:file "dns-test")
                             (:file "model-test")
                             (:file "store-test")
                             (:file "scheduler-test")
                             (:file "pki-test")
                             (:file "node-session-test")
                             (:file "reconciler-test")
                             (:file "agent-runtime-test")
                             (:file "grpc-unix-test")
                             (:file "cri-test")
                             (:file "runtime-assets-test")
                             (:file "cni-test")
                             (:file "node-ipam-test")
                             (:file "rtnetlink-test")
                             (:file "managed-containerd-test")
                             (:file "containerd-test")
                             (:file "podman-test")
                             (:file "main-test")
                             (:file "http-test")
                             (:file "telemetry-test"))))
  :perform (test-op (operation component)
             (declare (ignore operation component))
             (unless (uiop:symbol-call
                      :fiveam :run!
                      (find-symbol "GR8S" "GR8S/TESTS"))
               (error "gr8s tests failed"))))
