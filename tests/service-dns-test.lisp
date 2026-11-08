;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
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

(test service-dns-rotates-headless-multi-address-answers
  (with-temporary-store (store directory)
    (declare (ignore directory))
    (let ((service (service-test-object "web" "http"))
          (slice (endpointslice-test-object "manual" "192.0.2.11")))
      (setf (gethash "clusterIP" (gethash "spec" service)) "None"
            (gethash "endpoints" slice)
            (vector (gr8s::core-object "addresses" #("192.0.2.11"))
                    (gr8s::core-object "addresses" #("192.0.2.12"))
                    (gr8s::core-object "addresses" #("192.0.2.13"))))
      (gr8s::create-core-resource store "services" service "alpha")
      (gr8s::create-core-resource store "endpointslices" slice "alpha")
      (let ((resolver (gr8s::store-service-dns-resolver store)))
        (labels ((addresses ()
                   (mapcar #'0conf:format-ipv4
                           (mapcar #'0conf:a-address
                                   (0conf:dns-message-answers
                                    (0conf:decode-message
                                     (gr8s::answer-dns-query
                                      (dns-a-query "web.alpha.svc.cluster.local")
                                      (lambda (packet) (declare (ignore packet)) (error "forwarded"))
                                      resolver)))))))
          (let ((first (addresses)) (second (addresses)) (third (addresses)))
            (is (equal (sort (copy-list first) #'string<)
                       (sort (copy-list second) #'string<)))
            (is (equal (rest first) (butlast second)))
            (is (equal (rest second) (butlast third)))))))))

(test service-dns-serves-default-coredns-insecure-pod-records
  (with-temporary-store (store directory)
    (declare (ignore directory))
    (let* ((name "10-42-7-19.alpha.pod.cluster.local")
           (a (service-dns-test-message store name))
           (aaaa (service-dns-test-message store name 0conf:+type-aaaa+))
           (invalid (service-dns-test-message store "10-42-999-19.alpha.pod.cluster.local")))
      (is (equalp #(10 42 7 19)
                  (0conf:a-address (first (0conf:dns-message-answers a)))))
      (is (= 0 (logand 15 (0conf:dns-message-flags aaaa))))
      (is (null (0conf:dns-message-answers aaaa)))
      (is (= 3 (logand 15 (0conf:dns-message-flags invalid)))))))

(test service-dns-projection-excludes-private-metadata-and-rejects-secrets
  (let* ((object (service-test-object "web" "http"))
         (metadata (gethash "metadata" object)))
    (setf (gethash "annotations" metadata) (gr8s::core-object "private" "excluded")
          (gethash "namespace" metadata) "alpha")
    (is (null (gethash "annotations" (gethash "metadata" (gr8s::service-discovery-public-object object)))))
    (setf (gethash "kind" object) "Secret")
    (signals gr8s:kubernetes-error (gr8s::service-discovery-public-object object))))

(test service-dns-projects-gateway-referenced-tls-secret
  ;; podster-045.6: a Gateway HTTPS listener's certificateRefs Secret must reach
  ;; the node (via the service-discovery projection) so the TLS acceptor can load
  ;; it; unreferenced Secrets must not.
  (with-temporary-store (store directory)
    (flet ((create (resource namespace json)
             (gr8s::create-core-resource store resource (com.inuoe.jzon:parse json) namespace)))
      (create "secrets" "default"
              "{\"apiVersion\":\"v1\",\"kind\":\"Secret\",\"metadata\":{\"name\":\"web-tls\",\"namespace\":\"default\"},\"type\":\"kubernetes.io/tls\",\"data\":{\"tls.crt\":\"Zm9v\",\"tls.key\":\"YmFy\"}}")
      (create "secrets" "default"
              "{\"apiVersion\":\"v1\",\"kind\":\"Secret\",\"metadata\":{\"name\":\"unused\",\"namespace\":\"default\"},\"type\":\"kubernetes.io/tls\",\"data\":{\"tls.crt\":\"Zm9v\",\"tls.key\":\"YmFy\"}}")
      (create "gateways" "default"
              "{\"apiVersion\":\"gateway.networking.k8s.io/v1\",\"kind\":\"Gateway\",\"metadata\":{\"name\":\"tls-gw\",\"namespace\":\"default\"},\"spec\":{\"gatewayClassName\":\"gr8s\",\"listeners\":[{\"name\":\"https\",\"port\":18443,\"protocol\":\"HTTPS\",\"tls\":{\"mode\":\"Terminate\",\"certificateRefs\":[{\"kind\":\"Secret\",\"name\":\"web-tls\"}]}}]}}"))
    ;; Only the referenced Secret is collected.
    (let ((collected (mapcar (lambda (s) (gethash "name" (gethash "metadata" s)))
                             (gr8s::gateway-referenced-tls-secrets store))))
      (is (equal '("web-tls") collected)))
    ;; It survives projection + install, carrying its cert and key; the
    ;; unreferenced Secret never crosses.
    (let* ((snapshot (gr8s::node-desired-state-snapshot store "worker-a"))
           (projection (slot-value snapshot 'gr8s.node.v1::service-discovery-objects-json))
           (resources (make-hash-table :test #'equal)))
      (gr8s::install-service-discovery-projection resources projection)
      (let ((projected (gethash (gr8s::core-resource-key "secrets" "default" "web-tls") resources)))
        (is (not (null projected)))
        (is (equal "kubernetes.io/tls" (gethash "type" projected)))
        (is (equal "Zm9v" (gethash "tls.crt" (gethash "data" projected))))
        (is (equal "YmFy" (gethash "tls.key" (gethash "data" projected)))))
      (is (null (gethash (gr8s::core-resource-key "secrets" "default" "unused") resources))))))

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

(test service-dns-updates-publish-without-pod-version-changes-and-deduplicate
  (with-temporary-store (store directory)
    (gr8s:register-node store (gr8s:make-node-record :id "dns-node" :name "worker-a"
                                                  :pod-cidr "10.88.0.0/24"))
    (let* ((server (gr8s::%make-node-grpc-server :store store :cluster-pod-cidr "10.88.0.0/16"))
           (runtime (gr8s::make-control-plane-runtime store server)))
      (gr8s::publish-service-discovery-snapshots runtime)
      (is (= 1 (slot-value (gr8s::current-node-snapshot server "worker-a") 'gr8s.node.v1::revision)))
      (gr8s::publish-service-discovery-snapshots runtime)
      (is (= 1 (slot-value (gr8s::current-node-snapshot server "worker-a") 'gr8s.node.v1::revision)))
      (gr8s::create-core-resource store "services" (service-test-object "web") "alpha")
      (gr8s::publish-service-discovery-snapshots runtime)
      (is (= 2 (slot-value (gr8s::current-node-snapshot server "worker-a") 'gr8s.node.v1::revision)))
      (gr8s::publish-service-discovery-snapshots runtime)
      (is (= 2 (slot-value (gr8s::current-node-snapshot server "worker-a") 'gr8s.node.v1::revision)))
      (gr8s::delete-core-resource store "services" "alpha" "web")
      (gr8s::publish-service-discovery-snapshots runtime)
      (is (= 3 (slot-value (gr8s::current-node-snapshot server "worker-a") 'gr8s.node.v1::revision)))
      (is (null (slot-value (gr8s::current-node-snapshot server "worker-a") 'gr8s.node.v1::service-discovery-objects-json))))))

(test service-dns-empty-headless-service-is-nxdomain
  (with-temporary-store (store directory)
    (let ((service (service-test-object "web")))
      (setf (gethash "clusterIP" (gethash "spec" service)) "None")
      (gr8s::create-core-resource store "services" service "alpha"))
    (is (= 3 (logand 15 (0conf:dns-message-flags
                         (service-dns-test-message store "web.alpha.svc.cluster.local")))))
    (is (= 3 (logand 15 (0conf:dns-message-flags
                         (service-dns-test-message store "web.alpha.svc.cluster.local" 0conf:+type-aaaa+)))))))

(def-suite service-dns-records :in gr8s)
(in-suite service-dns-records)

(defun dns-srv-tuples (message)
  "Inspect the decoded endpoint targets and ports instead of only counting records."
  (sort (mapcar (lambda (record) (list (0conf:srv-port record)
                                      (gr8s::canonical-dns-name (0conf:srv-target record))))
                (0conf:dns-message-answers message))
        #'string< :key (lambda (entry) (format nil "~A/~A" (second entry) (first entry)))))

(test service-dns-srv-normal-port-is-service-port
  (with-temporary-store (store directory)
    (let* ((object (service-test-object "web" 7777))
           (port (aref (gethash "ports" (gethash "spec" object)) 0)))
      (setf (gethash "name" port) "http")
      (gr8s::create-core-resource store "services" object "alpha")
      (is (equal '((8080 "web.alpha.svc.cluster.local"))
                 (dns-srv-tuples (service-dns-test-message store "_HTTP._TCP.web.alpha.svc.cluster.local" 0conf:+type-srv+))))
      (is (= 3 (logand 15 (0conf:dns-message-flags
                           (service-dns-test-message store "_other._tcp.web.alpha.svc.cluster.local" 0conf:+type-srv+)))))
      (is (= 3 (logand 15 (0conf:dns-message-flags
                           (service-dns-test-message store "_http._udp.web.alpha.svc.cluster.local" 0conf:+type-srv+)))))
      (is (= 3 (logand 15 (0conf:dns-message-flags
                           (service-dns-test-message store "_http._tcp.web.other.svc.cluster.local" 0conf:+type-srv+))))))))

(test service-dns-srv-headless-uses-ready-actual-endpoint-targets
  (with-temporary-store (store directory)
    (let* ((object (service-test-object "web" "http"))
           (port (aref (gethash "ports" (gethash "spec" object)) 0))
           (slice (endpointslice-test-object "one" "192.0.2.11" 7777)))
      (setf (gethash "clusterIP" (gethash "spec" object)) "None" (gethash "name" port) "http")
      (gr8s::create-core-resource store "services" object "alpha")
      (is (= 3 (logand 15 (0conf:dns-message-flags
                           (service-dns-test-message store "_http._tcp.web.alpha.svc.cluster.local" 0conf:+type-srv+)))))
      (setf (gethash "name" (aref (gethash "ports" slice) 0)) "http"
            (gethash "endpoints" slice)
            (vector (gr8s::core-object "hostname" "first" "addresses" #("192.0.2.11"))
                    (gr8s::core-object "addresses" #("192.0.2.12"))
                    (gr8s::core-object "hostname" "notready" "addresses" #("192.0.2.13")
                                      "conditions" (gr8s::core-object "ready" nil))))
      (gr8s::create-core-resource store "endpointslices" slice "alpha")
      (let ((other (endpointslice-test-object "two" "192.0.2.14" 8888)))
        (setf (gethash "name" (aref (gethash "ports" other) 0)) "http")
        (gr8s::create-core-resource store "endpointslices" other "alpha"))
      (is (equal '((7777 "192-0-2-12.web.alpha.svc.cluster.local")
                   (8888 "192-0-2-14.web.alpha.svc.cluster.local")
                   (7777 "first.web.alpha.svc.cluster.local"))
                 (dns-srv-tuples (service-dns-test-message store "_http._tcp.web.alpha.svc.cluster.local" 0conf:+type-srv+))))
      (is (equalp #(192 0 2 12)
                  (0conf:a-address (first (0conf:dns-message-answers
                                          (service-dns-test-message store "192-0-2-12.web.alpha.svc.cluster.local"))))))
      (is (= 3 (logand 15 (0conf:dns-message-flags
                           (service-dns-test-message store "notready.web.alpha.svc.cluster.local")))))
      (gr8s::delete-core-resource store "services" "alpha" "web")
      (is (= 3 (logand 15 (0conf:dns-message-flags
                           (service-dns-test-message store "_http._tcp.web.alpha.svc.cluster.local" 0conf:+type-srv+))))))))

(test service-dns-reverse-records-use-real-service-and-ready-headless-targets
  (with-temporary-store (store directory)
    (gr8s::create-core-resource store "services" (service-test-object "normal") "alpha")
    (let ((message (service-dns-test-message store "10.0.96.10.in-addr.arpa" 0conf:+type-ptr+)))
      (is (equal "normal.alpha.svc.cluster.local"
                 (gr8s::canonical-dns-name (0conf:ptr-target (first (0conf:dns-message-answers message)))))))
    (let ((object (service-test-object "web")))
      (setf (gethash "clusterIP" (gethash "spec" object)) "None")
      (gr8s::create-core-resource store "services" object "alpha"))
    (let ((slice (endpointslice-test-object "reverse" "192.0.2.22")))
      (setf (gethash "hostname" (aref (gethash "endpoints" slice) 0)) "target")
      (gr8s::create-core-resource store "endpointslices" slice "alpha"))
    (let ((message (service-dns-test-message store "22.2.0.192.in-addr.arpa" 0conf:+type-ptr+)))
      (is (equal "target.web.alpha.svc.cluster.local"
                 (gr8s::canonical-dns-name (0conf:ptr-target (first (0conf:dns-message-answers message)))))))
    (let* ((v6 (endpointslice-test-object "reverse6" "2001:db8::1"))
           (reverse "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"))
      (setf (gethash "addressType" v6) "IPv6")
      (gr8s::create-core-resource store "endpointslices" v6 "alpha")
      (is (equalp (0conf:parse-ipv6 "2001:db8::1") (gr8s::service-dns-reverse-address reverse)))
      (is (equal "2001-db8--1.web.alpha.svc.cluster.local"
                 (gr8s::canonical-dns-name (0conf:ptr-target (first (0conf:dns-message-answers
                                                                  (service-dns-test-message store reverse 0conf:+type-ptr+))))))))
    (is (null (gr8s::service-dns-reverse-address "256.0.0.10.in-addr.arpa")))
    (is (null (gr8s::service-dns-reverse-address "garbage.ip6.arpa")))))

(test service-dns-reverse-unready-headless-address-is-authoritative-nxdomain
  (with-temporary-store (store directory)
    (let ((service (service-test-object "web")) (slice (endpointslice-test-object "unready" "192.0.2.22")))
      (setf (gethash "clusterIP" (gethash "spec" service)) "None"
            (gethash "conditions" (aref (gethash "endpoints" slice) 0)) (gr8s::core-object "ready" nil))
      (gr8s::create-core-resource store "services" service "alpha")
      (gr8s::create-core-resource store "endpointslices" slice "alpha")
      (let ((message (service-dns-test-message store "22.2.0.192.in-addr.arpa" 0conf:+type-ptr+)))
        (is (= 3 (logand 15 (0conf:dns-message-flags message))))
        (is (null (0conf:dns-message-answers message)))))))

(defun external-name-test-object (name target)
  "Build a DNS-only Service without an allocated address or artificial backend."
  (gr8s::core-object "apiVersion" "v1" "kind" "Service"
                    "metadata" (gr8s::core-object "name" name)
                    "spec" (gr8s::core-object "type" "ExternalName" "externalName" target)))

(defun dns-test-cname-target (message)
  "Decode the actual CNAME RDATA written on the wire, rather than checking a local target slot."
  (let ((answer (first (0conf:dns-message-answers message))))
    (is (= 0conf:+type-cname+ (0conf:rr-type answer)))
    (gr8s::canonical-dns-name (0conf:read-name (0conf:make-reader (0conf:rr-rdata answer))))))

(test service-dns-externalname-mutates-real-cname-and-transitions-type
  (with-temporary-store (store directory)
    (let* ((created (gr8s::create-core-resource store "services" (external-name-test-object "alias" "foo.example.com") "alpha"))
           (uid (gethash "uid" (gethash "metadata" created))))
      (is (null (gethash "clusterIP" (gethash "spec" created))))
      (is (null (gethash "clusterIPs" (gethash "spec" created))))
      (is (equal "foo.example.com" (dns-test-cname-target
                                    (service-dns-test-message store "alias.alpha.svc.cluster.local" 0conf:+type-cname+))))
      (gr8s::update-core-resource store "services" "alpha" "alias"
        (lambda (old) (setf (gethash "externalName" (gethash "spec" old)) "bar.example.com.") old))
      (is (equal "bar.example.com" (dns-test-cname-target
                                    (service-dns-test-message store "alias.alpha.svc.cluster.local"))))
      (with-temporary-store (agent agent-directory)
        (gr8s::install-assigned-resource-objects agent nil (gr8s::service-discovery-projection store))
        (is (equal "bar.example.com" (dns-test-cname-target
                                      (service-dns-test-message (open-store agent-directory) "alias.alpha.svc.cluster.local" 0conf:+type-cname+)))))
      (let ((cluster (gr8s::update-core-resource store "services" "alpha" "alias"
                       (lambda (old)
                         (setf (gethash "type" (gethash "spec" old)) "ClusterIP"
                               (gethash "ports" (gethash "spec" old)) (vector (gr8s::core-object "name" "http" "port" 80))) old))))
        (is (equal "10.96.0.10" (gethash "clusterIP" (gethash "spec" cluster))))
        (is (equal uid (gethash "uid" (gethash "metadata" cluster))))
        (is (null (gethash "externalName" (gethash "spec" cluster))))
        (is (equalp #(10 96 0 10) (0conf:a-address (first (0conf:dns-message-answers
                                                        (service-dns-test-message store "alias.alpha.svc.cluster.local")))))))
      (let ((external (gr8s::update-core-resource store "services" "alpha" "alias"
                        (lambda (old) (setf (gethash "type" (gethash "spec" old)) "ExternalName"
                                            (gethash "externalName" (gethash "spec" old)) "again.example.com") old))))
        (is (null (gethash "clusterIP" (gethash "spec" external))))
        (is (equal "again.example.com" (dns-test-cname-target
                                        (service-dns-test-message store "alias.alpha.svc.cluster.local" 0conf:+type-cname+))))))))

(test service-dns-externalname-validation-and-typed-creation
  (with-temporary-store (store directory)
    (dolist (target '("" "bad name" "bad..example" "Upper.example" "https://example.org"))
      (signals gr8s:kubernetes-error (gr8s::create-core-resource store "services" (external-name-test-object "invalid" target) "alpha")))
    (signals gr8s:kubernetes-error (gr8s::create-core-resource store "services" (external-name-test-object "kubernetes" "example.org") "default"))
    (let ((object (external-name-test-object "allocated" "example.org")))
      (setf (gethash "clusterIP" (gethash "spec" object)) "10.96.0.20")
      (signals gr8s:kubernetes-error (gr8s::create-core-resource store "services" object "alpha")))
    (let* ((metadata (core-test-protobuf '((1 "typed-alias") (6 ""))))
           (spec (core-test-protobuf '((3 "") (4 "ExternalName") (7 "") (8 "") (10 "typed.example.org") (11 "") (12 0) (13 0))))
           (wire (core-test-protobuf-envelope "Service" (list (list 1 metadata) (list 2 spec) (list 3 #()))))
           (created (gr8s::create-core-resource store "services" (gr8s::decode-core-resource-protobuf wire "Service") "alpha")))
      (is (equal "typed.example.org" (gethash "externalName" (gethash "spec" created))))
      (is (null (gethash "clusterIP" (gethash "spec" created)))))))

(test service-dns-schema-version-record-is-actual-txt
  (with-temporary-store (store directory)
    (let ((answers (0conf:dns-message-answers (service-dns-test-message store "dns-version.cluster.local" 0conf:+type-txt+))))
      (is (= 1 (length answers)))
      (is (equal '("1.1.0") (0conf:txt-strings (first answers)))))))

(test service-dns-externalname-transition-releases-generated-slices-without-adopting-manual
  (with-temporary-store (store directory)
    (let ((service (gr8s::create-core-resource store "services" (service-test-object "web" "http") "alpha")))
      (declare (ignorable service))
      (create-endpointslice-test-pod store "backend" "alpha" "192.0.2.55")
      (gr8s::reconcile-endpointslices store)
      (is (= 1 (length (gr8s::list-core-resources store "endpointslices" "alpha"))))
      (let ((manual (gr8s::create-core-resource store "endpointslices" (endpointslice-test-object "manual") "alpha")))
        (gr8s::update-core-resource store "services" "alpha" "web"
          (lambda (old) (setf (gethash "type" (gethash "spec" old)) "ExternalName"
                              (gethash "externalName" (gethash "spec" old)) "outside.example.org") old))
        (gr8s::reconcile-endpointslices store)
        (let ((remaining (gr8s::list-core-resources store "endpointslices" "alpha")))
          (is (= 1 (length remaining)))
          (is (equal (gethash "uid" (gethash "metadata" manual))
                     (gethash "uid" (gethash "metadata" (first remaining))))))))))

(test service-dns-srv-headless-reads-ports-from-slices-not-the-spec
  ;; A selectorless headless Service's slices may name ports its spec lacks; CoreDNS answers them.
  (with-temporary-store (store directory)
    (let* ((object (service-test-object "web" "http"))
           (slice (endpointslice-test-object "two" "192.0.2.21" 443)))
      (setf (gethash "clusterIP" (gethash "spec" object)) "None"
            (gethash "name" (aref (gethash "ports" (gethash "spec" object)) 0)) "http")
      (gr8s::create-core-resource store "services" object "alpha")
      (setf (gethash "name" (aref (gethash "ports" slice) 0)) "https")
      (gr8s::create-core-resource store "endpointslices" slice "alpha")
      (is (equal '((443 "192-0-2-21.web.alpha.svc.cluster.local"))
                 (dns-srv-tuples (service-dns-test-message store "_https._tcp.web.alpha.svc.cluster.local" 0conf:+type-srv+)))))))
