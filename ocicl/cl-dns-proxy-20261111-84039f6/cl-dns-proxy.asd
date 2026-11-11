;;;; SPDX-FileCopyrightText: 2026 Anthony Green <green@moxielogic.com>
;;;; SPDX-License-Identifier: MIT

(asdf:defsystem "cl-dns-proxy"
  :description "A bounded caching DNS proxy with UDP and TCP listeners"
  :author "Anthony Green <green@moxielogic.com>"
  :license "MIT"
  :version "0.1.0"
  :depends-on ("0conf" "bordeaux-threads" "sb-bsd-sockets")
  :serial t
  :components ((:module "src" :components ((:file "package") (:file "proxy"))))
  :in-order-to ((test-op (test-op "cl-dns-proxy/tests"))))

(asdf:defsystem "cl-dns-proxy/tests"
  :depends-on ("cl-dns-proxy" "fiveam")
  :serial t
  :components ((:module "tests" :components ((:file "package") (:file "proxy-test"))))
  :perform (test-op (operation component)
             (declare (ignore operation component))
             (unless (uiop:symbol-call :fiveam :run!
                                       (find-symbol "CL-DNS-PROXY" "CL-DNS-PROXY/TESTS"))
               (error "cl-dns-proxy tests failed"))))
