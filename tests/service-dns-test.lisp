;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Exercise actual Service and ready EndpointSlice DNS answers, authenticated
;;;; public projection boundaries, snapshot deduplication, and durable withdrawal.

(in-package #:gr8s/tests)
(def-suite service-dns :in gr8s)
(in-suite service-dns)

(defun service-dns-test-message (store name &optional (type 0conf:+type-a+))
  "Ask the production authority path without allowing unknown cluster names upstream."
  (0conf:decode-message
   (gr8s::answer-dns-query
    (0conf:encode-message (0conf:make-dns-message :id 42 :flags #x0100
                           :questions (list (0conf:make-question :name name :qtype type :qclass 1))))
    (lambda (packet) (declare (ignore packet)) (error "cluster query leaked upstream"))
    (gr8s::store-service-dns-resolver store))))

(test service-dns-public-projection-and-durable-withdrawal
  (with-temporary-store (store directory)
    (let* ((object (service-test-object "web" "http"))
           (service (gr8s::create-core-resource store "services" object "alpha"))
           (address (gethash "clusterIP" (gethash "spec" service))))
      (let ((message (service-dns-test-message store "WEB.alpha.svc.cluster.local.")))
        (is (= 1 (length (0conf:dns-message-answers message))))
        (is (equalp (0conf:parse-ipv4 address)
                    (0conf:a-address (first (0conf:dns-message-answers message))))))
      (is (null (0conf:dns-message-answers
                 (service-dns-test-message store "web.alpha.svc.cluster.local" 0conf:+type-aaaa+))))
      (is (= 0 (logand 15 (0conf:dns-message-flags
                           (service-dns-test-message store "web.alpha.svc.cluster.local" 0conf:+type-aaaa+)))))
      (is (= 3 (logand 15 (0conf:dns-message-flags
                           (service-dns-test-message store "web.other.svc.cluster.local")))))
      (let* ((snapshot (gr8s::node-desired-state-snapshot store "worker-a"))
             (projection (slot-value snapshot 'gr8s.node.v1::service-discovery-objects-json))
             (resources (make-hash-table :test #'equal)))
        (is (= 1 (length projection)))
        (gr8s::install-service-discovery-projection resources projection)
        (is (= 1 (hash-table-count resources)))
        (is (equalp projection (slot-value (gr8s::node-desired-state-snapshot store "worker-a") 'gr8s.node.v1::service-discovery-objects-json)))
        (gr8s::delete-core-resource store "services" "alpha" "web")
        (is (not (equalp projection (slot-value (gr8s::node-desired-state-snapshot store "worker-a") 'gr8s.node.v1::service-discovery-objects-json))))
        (is (= 3 (logand 15 (0conf:dns-message-flags
                             (service-dns-test-message store "web.alpha.svc.cluster.local")))))))))

(test service-dns-headless-readiness-hostname-and-family
  (with-temporary-store (store directory)
    (let ((service (service-test-object "web" "http"))
          (slice (endpointslice-test-object "manual" "192.0.2.11")))
      (setf (gethash "clusterIP" (gethash "spec" service)) "None")
      (gr8s::create-core-resource store "services" service "alpha")
      (setf (gethash "endpoints" slice)
            (vector (gr8s::core-object "addresses" #("192.0.2.11") "hostname" "one")
                    (gr8s::core-object "addresses" #("192.0.2.12") "hostname" "two"
                                      "conditions" (gr8s::core-object "ready" nil))))
      (gr8s::create-core-resource store "endpointslices" slice "alpha")
      (is (= 1 (length (0conf:dns-message-answers (service-dns-test-message store "web.alpha.svc.cluster.local")))))
      (is (= 1 (length (0conf:dns-message-answers (service-dns-test-message store "one.web.alpha.svc.cluster.local")))))
      (is (= 3 (logand 15 (0conf:dns-message-flags
                           (service-dns-test-message store "two.web.alpha.svc.cluster.local")))))
      (let ((v6 (endpointslice-test-object "manual6" "2001:db8::1")))
        (setf (gethash "addressType" v6) "IPv6")
        (gr8s::create-core-resource store "endpointslices" v6 "alpha"))
      (let ((answers (0conf:dns-message-answers
                      (service-dns-test-message store "web.alpha.svc.cluster.local" 0conf:+type-aaaa+))))
        (is (= 1 (length answers)))
        (is (equalp (0conf:parse-ipv6 "2001:db8::1") (0conf:aaaa-address (first answers))))))))

(test service-dns-projection-excludes-private-metadata-and-rejects-secrets
  (let* ((object (service-test-object "web" "http"))
         (metadata (gethash "metadata" object)))
    (setf (gethash "annotations" metadata) (gr8s::core-object "private" "excluded")
          (gethash "namespace" metadata) "alpha")
    (is (null (gethash "annotations" (gethash "metadata" (gr8s::service-discovery-public-object object)))))
    (setf (gethash "kind" object) "Secret")
    (signals gr8s:kubernetes-error (gr8s::service-discovery-public-object object))))

(test service-dns-actual-udp-tcp-reads-live-store-and-survives-recovery
  (with-temporary-store (store directory)
    (gr8s::create-core-resource store "services" (service-test-object "web") "alpha")
    (let ((server (gr8s::start-dns-server :address "127.0.0.1" :port 0 :upstreams nil
                                        :service-resolver (gr8s::store-service-dns-resolver store))))
      (unwind-protect
           (progn
             (is (equalp #(10 96 0 10) (dns-first-a-address
                                       (test-udp-dns-query (gr8s::dns-server-port server) "web.alpha.svc.cluster.local"))))
             (is (equalp #(10 96 0 10) (dns-first-a-address
                                       (test-tcp-dns-query (gr8s::dns-server-port server) "web.alpha.svc.cluster.local"))))
             (gr8s::delete-core-resource store "services" "alpha" "web")
             (is (= 3 (gr8s::dns-response-code
                        (test-udp-dns-query (gr8s::dns-server-port server) "web.alpha.svc.cluster.local"))))
             (is (equalp #(10 96 0 1) (dns-first-a-address
                                      (test-tcp-dns-query (gr8s::dns-server-port server) +kubernetes-service-name+)))))
        (gr8s::stop-dns-server server)))
    (is (= 3 (logand 15 (0conf:dns-message-flags
                         (service-dns-test-message (open-store directory) "web.alpha.svc.cluster.local")))))))

(test service-dns-node-projection-wire-install-and-recovery
  (with-temporary-store (control directory)
    (declare (ignore directory))
    (gr8s::create-core-resource control "services" (service-test-object "web") "alpha")
    (let* ((snapshot (gr8s::node-desired-state-snapshot control "worker-a"))
           (wire (ag-proto:serialize-to-bytes snapshot))
           (decoded (ag-proto:deserialize-from-bytes 'gr8s.node.v1::desired-state-snapshot wire))
           (projection (slot-value decoded 'gr8s.node.v1::service-discovery-objects-json)))
      (is (= 1 (length projection)))
      (is (null (slot-value decoded 'gr8s.node.v1::pods)))
      (with-temporary-store (agent agent-directory)
        (gr8s::install-assigned-resource-objects agent nil projection)
        (is (equalp #(10 96 0 10)
                    (0conf:a-address (first (0conf:dns-message-answers
                                            (service-dns-test-message agent "web.alpha.svc.cluster.local"))))))
        (let ((reopened (open-store agent-directory)))
          (is (equalp #(10 96 0 10)
                      (0conf:a-address (first (0conf:dns-message-answers
                                              (service-dns-test-message reopened "web.alpha.svc.cluster.local"))))))
          (let ((revision (gr8s::pod-store-resource-revision reopened)))
            (gr8s::install-assigned-resource-objects reopened nil projection)
            (is (= revision (gr8s::pod-store-resource-revision reopened))))
          (gr8s::install-assigned-resource-objects reopened nil nil)
          (is (= 3 (logand 15 (0conf:dns-message-flags
                               (service-dns-test-message reopened "web.alpha.svc.cluster.local"))))))))))
