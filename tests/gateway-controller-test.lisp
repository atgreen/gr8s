;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Exercise the Gateway controller: GatewayClass ownership, parentRef-based
;;;; HTTPRoute attachment, the pure port->routes planner, and the start/hot-swap
;;;; /stop convergence of L7 proxy listeners (with injected lifecycle to avoid
;;;; binding real ports).

(in-package #:gr8s/tests)
(def-suite gateway-controller :in gr8s)
(in-suite gateway-controller)

(defun gwc-seed (store)
  "Seed a store with an owned and an unowned GatewayClass, two Gateways and one
   attached HTTPRoute."
  (flet ((create (resource namespace json)
           (gr8s::create-core-resource store resource (com.inuoe.jzon:parse json) namespace)))
    (create "gatewayclasses" nil
            "{\"apiVersion\":\"gateway.networking.k8s.io/v1\",\"kind\":\"GatewayClass\",\"metadata\":{\"name\":\"gr8s\"},\"spec\":{\"controllerName\":\"gr8s.io/gateway-controller\"}}")
    (create "gatewayclasses" nil
            "{\"apiVersion\":\"gateway.networking.k8s.io/v1\",\"kind\":\"GatewayClass\",\"metadata\":{\"name\":\"other\"},\"spec\":{\"controllerName\":\"someone.else/controller\"}}")
    (create "gateways" "default"
            "{\"apiVersion\":\"gateway.networking.k8s.io/v1\",\"kind\":\"Gateway\",\"metadata\":{\"name\":\"web\",\"namespace\":\"default\"},\"spec\":{\"gatewayClassName\":\"gr8s\",\"listeners\":[{\"name\":\"http\",\"port\":8080,\"protocol\":\"HTTP\"}]}}")
    (create "gateways" "default"
            "{\"apiVersion\":\"gateway.networking.k8s.io/v1\",\"kind\":\"Gateway\",\"metadata\":{\"name\":\"unmanaged\",\"namespace\":\"default\"},\"spec\":{\"gatewayClassName\":\"other\",\"listeners\":[{\"name\":\"http\",\"port\":9090,\"protocol\":\"HTTP\"}]}}")
    (create "httproutes" "default"
            "{\"apiVersion\":\"gateway.networking.k8s.io/v1\",\"kind\":\"HTTPRoute\",\"metadata\":{\"name\":\"app\",\"namespace\":\"default\"},\"spec\":{\"parentRefs\":[{\"name\":\"web\"}],\"hostnames\":[\"app.example.com\"],\"rules\":[{\"backendRefs\":[{\"name\":\"app-svc\",\"port\":80}]}]}}")))

(test gateway-controller-ownership-and-attachment
  (with-temporary-store (store directory)
    (values directory)
    (gwc-seed store)
    (is (gr8s::gateway-controlled-p store (gr8s::get-core-resource store "gateways" "default" "web")))
    (is (not (gr8s::gateway-controlled-p store (gr8s::get-core-resource store "gateways" "default" "unmanaged"))))
    ;; A parentRef naming a different Gateway does not attach.
    (let ((route (gr8s::get-core-resource store "httproutes" "default" "app")))
      (is (gr8s::gateway-route-attaches-p route "default" "web" "http" 8080))
      (is (not (gr8s::gateway-route-attaches-p route "default" "other-gw" "http" 8080)))
      ;; No sectionName -> attaches to every listener on the Gateway.
      (is (gr8s::gateway-route-attaches-p route "default" "web" "any-listener" 8080)))
    ;; An explicit sectionName/port must equal the listener's.
    (let ((pinned (com.inuoe.jzon:parse
                   "{\"metadata\":{\"namespace\":\"default\"},\"spec\":{\"parentRefs\":[{\"name\":\"web\",\"sectionName\":\"https\",\"port\":8443}],\"rules\":[]}}")))
      (is (gr8s::gateway-route-attaches-p pinned "default" "web" "https" 8443))
      (is (not (gr8s::gateway-route-attaches-p pinned "default" "web" "http" 8080))))))

(test gateway-controller-plans-port-to-routes
  (with-temporary-store (store directory)
    (values directory)
    (gwc-seed store)
    (let ((plan (gr8s::gateway-listener-plan
                 (gr8s::list-core-resources store "gateways")
                 (gr8s::list-core-resources store "httproutes")
                 (lambda (gw) (gr8s::gateway-controlled-p store gw)))))
      ;; Only the owned Gateway's HTTP port is planned.
      (is (= 1 (length plan)))
      (is (equal 8080 (getf (first plan) :port)))
      (is (equal "HTTP" (getf (first plan) :protocol)))
      (is (null (getf (first plan) :tls)))
      (is (= 1 (length (getf (first plan) :routes))))
      (is (equal '("app.example.com") (gr8s::gw-route-hostnames (first (getf (first plan) :routes))))))))

(test gateway-controller-converges-start-swap-stop
  (with-temporary-store (store directory)
    (values directory)
    (gwc-seed store)
    (let* ((actions '())
           (controller (gr8s::make-gateway-controller
                        store
                        :resolver (lambda (b) (declare (ignore b)) nil)
                        :start-fn (lambda (port router resolver tls)
                                    (declare (ignore router resolver tls))
                                    (push (list :start port) actions)
                                    (list :handle port))
                        :stop-fn (lambda (handle) (push (list :stop handle) actions))
                        :swap-fn (lambda (handle router)
                                   (declare (ignore router))
                                   (push (list :swap handle) actions)))))
      ;; First convergence starts the listener on 8080.
      (gr8s::converge-gateway-listeners controller)
      (is (equal '((:start 8080)) actions))
      ;; Second convergence hot-swaps the router (no new start).
      (setf actions '())
      (gr8s::converge-gateway-listeners controller)
      (is (equal '((:swap (:handle 8080))) actions))
      ;; Removing the Gateway stops the listener.
      (setf actions '())
      (gr8s::delete-core-resource store "gateways" "default" "web")
      (gr8s::converge-gateway-listeners controller)
      (is (equal '((:stop (:handle 8080))) actions))
      (is (zerop (hash-table-count (gr8s::gateway-controller-listeners controller)))))))

(test gateway-controller-starts-https-listener-with-secret-cert
  (with-temporary-store (store directory)
    (flet ((create (resource namespace json)
             (gr8s::create-core-resource store resource (com.inuoe.jzon:parse json) namespace)))
      (create "gatewayclasses" nil
              "{\"apiVersion\":\"gateway.networking.k8s.io/v1\",\"kind\":\"GatewayClass\",\"metadata\":{\"name\":\"gr8s\"},\"spec\":{\"controllerName\":\"gr8s.io/gateway-controller\"}}")
      ;; A kubernetes.io/tls Secret (dGxz... are arbitrary base64 payloads).
      (create "secrets" "default"
              "{\"apiVersion\":\"v1\",\"kind\":\"Secret\",\"metadata\":{\"name\":\"web-cert\",\"namespace\":\"default\"},\"type\":\"kubernetes.io/tls\",\"data\":{\"tls.crt\":\"dGxzLWNlcnQtcGVt\",\"tls.key\":\"dGxzLWtleS1wZW0=\"}}")
      (create "gateways" "default"
              "{\"apiVersion\":\"gateway.networking.k8s.io/v1\",\"kind\":\"Gateway\",\"metadata\":{\"name\":\"tls-gw\",\"namespace\":\"default\"},\"spec\":{\"gatewayClassName\":\"gr8s\",\"listeners\":[{\"name\":\"https\",\"port\":8443,\"protocol\":\"HTTPS\",\"tls\":{\"certificateRefs\":[{\"kind\":\"Secret\",\"name\":\"web-cert\"}]}}]}}")
      (create "httproutes" "default"
              "{\"apiVersion\":\"gateway.networking.k8s.io/v1\",\"kind\":\"HTTPRoute\",\"metadata\":{\"name\":\"secure\",\"namespace\":\"default\"},\"spec\":{\"parentRefs\":[{\"name\":\"tls-gw\"}],\"hostnames\":[\"secure.example.com\"],\"rules\":[{\"backendRefs\":[{\"name\":\"app-svc\",\"port\":443}]}]}}"))
    (let ((plan (gr8s::gateway-listener-plan
                 (gr8s::list-core-resources store "gateways")
                 (gr8s::list-core-resources store "httproutes")
                 (lambda (gw) (gr8s::gateway-controlled-p store gw)))))
      (is (equal 8443 (getf (first plan) :port)))
      (is (equal "HTTPS" (getf (first plan) :protocol)))
      (is (equal '("default" . "web-cert") (getf (first plan) :tls))))
    (let* ((started '())
           (cert-dir (merge-pathnames "certs/" directory))
           (controller (gr8s::make-gateway-controller
                        store :cert-dir cert-dir
                        :start-fn (lambda (port router resolver tls)
                                    (declare (ignore router resolver))
                                    (push (cons port tls) started) (list :handle port))
                        :stop-fn (lambda (handle) (declare (ignore handle)))
                        :swap-fn (lambda (handle router) (declare (ignore handle router))))))
      (gr8s::converge-gateway-listeners controller)
      (is (= 1 (length started)))
      (is (equal 8443 (car (first started))))
      (let ((tls (cdr (first started))))
        (is (stringp (getf tls :certificate)))
        (is (probe-file (getf tls :certificate)))        ; cert materialized on disk
        (is (probe-file (getf tls :key)))))))
