;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Adapt networking.k8s.io/v1 Ingress objects into the normalized routes and
;;;; listeners of the embedded Gateway proxy. No Gateway API objects are
;;;; synthesized or persisted; Ingress remains the source of truth.

(in-package #:gr8s.controllers)

(defparameter *ingress-controller-name* "gr8s.io/ingress-controller"
  "The IngressClass spec.controller value reconciled by gr8s.")

(defun ingress-class-name (ingress)
  "Return INGRESS's field or legacy-annotation class name."
  (let* ((metadata (gethash "metadata" ingress))
         (spec (gethash "spec" ingress))
         (annotations (and metadata (gethash "annotations" metadata))))
    (or (and spec (gethash "ingressClassName" spec))
        (and (hash-table-p annotations)
             (gethash "kubernetes.io/ingress.class" annotations)))))

(defun ingress-controlled-p (store ingress)
  "True when INGRESS selects an IngressClass owned by this controller."
  (let* ((name (ingress-class-name ingress))
         (class (and name
                     (ignore-errors (get-core-resource store "ingressclasses" nil name)))))
    (and class
         (equal *ingress-controller-name*
                (gethash "controller" (gethash "spec" class))))))

(defun ingress-service-backend (backend namespace)
  "Normalize one Ingress service BACKEND in NAMESPACE into a GW-BACKEND."
  (let* ((service (and backend (gethash "service" backend)))
         (port (and service (gethash "port" service)))
         (reference (and port (or (gethash "number" port) (gethash "name" port)))))
    (unless (and (hash-table-p service) (stringp (gethash "name" service)) reference)
      (gw-route-error "Ingress backend must name a Service and port"))
    (make-gw-backend :name (gethash "name" service)
                     :namespace namespace :port reference)))

(defun ingress-path-match (path)
  "Normalize one Ingress HTTP path into the Gateway proxy match model."
  (let ((type (gethash "pathType" path))
        (value (or (gethash "path" path) "/")))
    (make-gw-match :path-type (if (equal type "Exact") :exact :prefix)
                   :path value)))

(defun ingress-rule-route (ingress namespace rule)
  "Normalize one host RULE of INGRESS into a GW-ROUTE."
  (let* ((http (gethash "http" rule))
         (paths (and http (gethash "paths" http))))
    (make-gw-route
     :kind :ingress
     :namespace namespace
     :name (gethash "name" (gethash "metadata" ingress))
     :rate-limit (gw-parse-rate-limit (gethash "annotations" (gethash "metadata" ingress)))
     :hostnames (let ((host (gethash "host" rule))) (and host (list host)))
     :rules (loop for path across (or paths #())
                  collect (make-gw-rule
                           :matches (list (ingress-path-match path))
                           :backends (list (ingress-service-backend
                                           (gethash "backend" path) namespace)))))))

(defun ingress-default-route (ingress namespace backend)
  "Normalize INGRESS's default BACKEND into a hostless catch-all route."
  (make-gw-route
   :kind :ingress
   :namespace namespace
   :name (gethash "name" (gethash "metadata" ingress))
   :rate-limit (gw-parse-rate-limit (gethash "annotations" (gethash "metadata" ingress)))
   :rules (list (make-gw-rule
                 :matches (list (make-gw-match :path-type :prefix :path "/"))
                 :backends (list (ingress-service-backend backend namespace))))))

(defun parse-ingress-routes (ingress)
  "Normalize INGRESS into host routes plus its optional default route."
  (let* ((metadata (gethash "metadata" ingress))
         (namespace (gethash "namespace" metadata))
         (spec (gethash "spec" ingress))
         (routes (loop for rule across (gethash "rules" spec #())
                       collect (ingress-rule-route ingress namespace rule)))
         (backend (gethash "defaultBackend" spec)))
    (if (hash-table-p backend)
        (append routes (list (ingress-default-route ingress namespace backend)))
        routes)))

(defun ingress-tls-ref (ingress)
  "Return the first (namespace . Secret) TLS reference of INGRESS, or NIL."
  (let* ((metadata (gethash "metadata" ingress))
         (spec (gethash "spec" ingress))
         (tls (gethash "tls" spec)))
    (when (and tls (plusp (length tls)))
      (let ((name (gethash "secretName" (aref tls 0))))
        (and name (cons (gethash "namespace" metadata) name))))))

(defun ingress-listener-plan (store)
  "Plan standard port 80/443 listeners for every owned Ingress in STORE."
  (let* ((ingresses (remove-if-not
                     (lambda (ingress) (ingress-controlled-p store ingress))
                     (sort (list-core-resources store "ingresses") #'string<
                           :key (lambda (ingress)
                                  (let ((metadata (gethash "metadata" ingress)))
                                    (format nil "~A/~A" (gethash "namespace" metadata)
                                            (gethash "name" metadata)))))))
         (routes (loop for ingress in ingresses append (parse-ingress-routes ingress)))
         (tls (loop for ingress in ingresses thereis (ingress-tls-ref ingress))))
    (append (when routes
              (list (list :port 80 :protocol "HTTP" :tls nil :routes routes)))
            (when (and routes tls)
              (list (list :port 443 :protocol "HTTPS" :tls tls :routes routes))))))

(defun ingress-serving-addresses (store)
  "Return ready node addresses in Ingress load-balancer status form."
  (coerce
   (sort
    (loop for node in (list-nodes store)
          for address = (node-reported-address node)
          when (and (node-record-runtime-ready-p node)
                    (stringp address) (plusp (length address)))
            collect (core-object "ip" address))
    #'string< :key (lambda (entry) (gethash "ip" entry)))
   'vector))

(defun reconcile-ingress-status (store)
  "Publish ready node addresses on every Ingress this controller owns."
  (let ((addresses (ingress-serving-addresses store)))
    (dolist (ingress (list-core-resources store "ingresses"))
      (when (ingress-controlled-p store ingress)
        (let* ((metadata (gethash "metadata" ingress))
               (namespace (gethash "namespace" metadata))
               (name (gethash "name" metadata))
               (desired (core-object
                         "loadBalancer"
                         (if (plusp (length addresses))
                             (core-object "ingress" addresses)
                             (core-object)))))
          (unless (core-json-equal-p desired (gethash "status" ingress (core-object)))
            (let ((*networking-status-write* t))
              (update-core-resource
               store "ingresses" namespace name
               (lambda (current)
                 (when (equal (gethash "uid" metadata)
                              (gethash "uid" (gethash "metadata" current)))
                   (setf (gethash "status" current) (copy-core-object desired)))
                 current))))))))
  nil)
