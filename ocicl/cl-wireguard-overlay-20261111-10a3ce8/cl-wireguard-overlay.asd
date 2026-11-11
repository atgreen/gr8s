;;;; SPDX-FileCopyrightText: 2026 Anthony Green <green@moxielogic.com>
;;;; SPDX-License-Identifier: MIT

(asdf:defsystem "cl-wireguard-overlay"
  :description "Deterministic topology and adaptive path planning for WireGuard overlays"
  :author "Anthony Green <green@moxielogic.com>"
  :license "MIT"
  :version "0.1.0"
  :serial t
  :components ((:module "src" :components ((:file "package") (:file "topology")
                                             (:file "path") (:file "controller"))))
  :in-order-to ((test-op (test-op "cl-wireguard-overlay/tests"))))

(asdf:defsystem "cl-wireguard-overlay/tests"
  :depends-on ("cl-wireguard-overlay" "fiveam")
  :serial t
  :components ((:module "tests" :components ((:file "package") (:file "topology-test")
                                               (:file "path-test") (:file "controller-test"))))
  :perform (test-op (operation component)
             (declare (ignore operation component))
             (unless (uiop:symbol-call :fiveam :run!
                                       (find-symbol "CL-WIREGUARD-OVERLAY"
                                                    "CL-WIREGUARD-OVERLAY/TESTS"))
               (error "cl-wireguard-overlay tests failed"))))
