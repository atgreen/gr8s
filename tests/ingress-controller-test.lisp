;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Verify that ordinary networking.k8s.io/v1 Ingress objects become native
;;;; Gateway proxy listeners without synthesizing Gateway API resources.

(in-package #:gr8s/tests)

(def-suite ingress-controller :in gr8s)
(in-suite ingress-controller)

(defun seed-ingress-controller-test (store)
  "Create owned and foreign Ingress classes plus one HTTP/TLS Ingress."
  (flet ((create (resource namespace json)
           (gr8s::create-core-resource store resource (com.inuoe.jzon:parse json) namespace)))
    (create "ingressclasses" nil
            "{\"apiVersion\":\"networking.k8s.io/v1\",\"kind\":\"IngressClass\",\"metadata\":{\"name\":\"gr8s\"},\"spec\":{\"controller\":\"gr8s.io/ingress-controller\"}}")
    (create "ingressclasses" nil
            "{\"apiVersion\":\"networking.k8s.io/v1\",\"kind\":\"IngressClass\",\"metadata\":{\"name\":\"foreign\"},\"spec\":{\"controller\":\"example.com/foreign\"}}")
    (create "secrets" "default"
            "{\"apiVersion\":\"v1\",\"kind\":\"Secret\",\"metadata\":{\"name\":\"web-tls\"},\"type\":\"kubernetes.io/tls\",\"data\":{\"tls.crt\":\"Y2VydA==\",\"tls.key\":\"a2V5\"}}")
    (create "ingresses" "default"
            "{\"apiVersion\":\"networking.k8s.io/v1\",\"kind\":\"Ingress\",\"metadata\":{\"name\":\"web\"},\"spec\":{\"ingressClassName\":\"gr8s\",\"defaultBackend\":{\"service\":{\"name\":\"fallback\",\"port\":{\"number\":9000}}},\"tls\":[{\"hosts\":[\"web.example\"],\"secretName\":\"web-tls\"}],\"rules\":[{\"host\":\"web.example\",\"http\":{\"paths\":[{\"path\":\"/exact\",\"pathType\":\"Exact\",\"backend\":{\"service\":{\"name\":\"web\",\"port\":{\"number\":80}}}},{\"path\":\"/api\",\"pathType\":\"Prefix\",\"backend\":{\"service\":{\"name\":\"web\",\"port\":{\"name\":\"http\"}}}}]}}]}}")
    (create "ingresses" "default"
            "{\"apiVersion\":\"networking.k8s.io/v1\",\"kind\":\"Ingress\",\"metadata\":{\"name\":\"ignored\"},\"spec\":{\"ingressClassName\":\"foreign\",\"defaultBackend\":{\"service\":{\"name\":\"other\",\"port\":{\"number\":80}}}}}")))

(test ingress-class-ownership-and-route-normalization
  (with-temporary-store (store directory)
    (values directory)
    (seed-ingress-controller-test store)
    (let ((owned (gr8s::get-core-resource store "ingresses" "default" "web"))
          (foreign (gr8s::get-core-resource store "ingresses" "default" "ignored")))
      (is (gr8s::ingress-controlled-p store owned))
      (is (not (gr8s::ingress-controlled-p store foreign)))
      (let* ((routes (gr8s::parse-ingress-routes owned))
             (fallback (find-if #'null routes :key #'gr8s::gw-route-hostnames))
             (hosted (find-if #'gr8s::gw-route-hostnames routes)))
        (is (= 2 (length routes)))
        (is (equal '("web.example") (gr8s::gw-route-hostnames hosted)))
        (is (equal '(:exact :prefix)
                   (mapcar (lambda (rule)
                             (gr8s::gw-match-path-type (first (gr8s::gw-rule-matches rule))))
                           (gr8s::gw-route-rules hosted))))
        (is (equal '(80 "http")
                   (mapcar (lambda (rule)
                             (gr8s::gw-backend-port (first (gr8s::gw-rule-backends rule))))
                           (gr8s::gw-route-rules hosted))))
        (is (= 9000 (gr8s::gw-backend-port
                     (first (gr8s::gw-rule-backends (first (gr8s::gw-route-rules fallback)))))))))))

(test ingress-plans-standard-http-and-https-listeners
  (with-temporary-store (store directory)
    (values directory)
    (seed-ingress-controller-test store)
    (let* ((plan (gr8s::ingress-listener-plan store))
           (http (find 80 plan :key (lambda (entry) (getf entry :port))))
           (https (find 443 plan :key (lambda (entry) (getf entry :port)))))
      (is (= 2 (length plan)))
      (is (equal "HTTP" (getf http :protocol)))
      (is (= 2 (length (getf http :routes))))
      (is (equal "HTTPS" (getf https :protocol)))
      (is (equal '("default" . "web-tls") (getf https :tls)))
      (is (= 2 (length (getf https :routes)))))))

(test gateway-controller-converges-and-removes-ingress-listeners
  (with-temporary-store (store directory)
    (seed-ingress-controller-test store)
    (let* ((actions nil)
           (controller
             (gr8s::make-gateway-controller
              store :cert-dir (merge-pathnames "certs/" directory)
              :resolver (lambda (backend) (declare (ignore backend)) nil)
              :start-fn (lambda (port router resolver tls)
                          (declare (ignore router resolver tls))
                          (push (list :start port) actions)
                          (list :listener port))
              :stop-fn (lambda (handle) (push (list :stop handle) actions))
              :swap-fn (lambda (handle router) (declare (ignore handle router))))))
      (gr8s::converge-gateway-listeners controller)
      (is (= 2 (count :start actions :key #'first)))
      (is (find '(:start 80) actions :test #'equal))
      (is (find '(:start 443) actions :test #'equal))
      (setf actions nil)
      (gr8s::delete-core-resource store "ingresses" "default" "web")
      (gr8s::converge-gateway-listeners controller)
      (is (= 2 (count :stop actions :key #'first)))
      (is (zerop (hash-table-count (gr8s::gateway-controller-listeners controller)))))))

(test ingress-classes-routes-and-tls-secrets-cross-the-node-snapshot
  (with-temporary-store (store directory)
    (values directory)
    (seed-ingress-controller-test store)
    (let* ((projection (gr8s::service-discovery-projection store))
           (objects (mapcar (lambda (bytes)
                              (com.inuoe.jzon:parse
                               (trivial-utf-8:utf-8-bytes-to-string bytes)))
                            projection))
           (resources (make-hash-table :test #'equal)))
      (is (= 2 (count "IngressClass" objects :test #'equal
                      :key (lambda (object) (gethash "kind" object)))))
      (is (= 2 (count "Ingress" objects :test #'equal
                      :key (lambda (object) (gethash "kind" object)))))
      (is (= 1 (count "Secret" objects :test #'equal
                      :key (lambda (object) (gethash "kind" object)))))
      (gr8s::install-service-discovery-projection resources projection)
      (is (gethash (gr8s::core-resource-key "ingressclasses" nil "gr8s") resources))
      (is (gethash (gr8s::core-resource-key "ingresses" "default" "web") resources))
      (is (gethash (gr8s::core-resource-key "secrets" "default" "web-tls") resources)))))
