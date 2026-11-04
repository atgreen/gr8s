;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Converge desired ClusterIP Service state into the socket load balancer's
;;;; BPF maps.  Each reconcile computes the full desired table from the live
;;;; Services and their ready backends (service-pod-endpoints, which already
;;;; prefers EndpointSlices), diffs it against what was last applied, and writes
;;;; only when something changed.  Backends are packed into consecutive slots in
;;;; a deterministic order so the plan is stable across ticks.
;;;;
;;;; The plan computation is pure (no kernel, no store coupling), and every map
;;;; operation is injected, so convergence is tested without privileges.

(in-package #:gr8s)

(defun service-lb-eligible-p (service)
  "True for a Service the socket LB should load-balance: a selector/endpoint
ClusterIP Service with a real virtual address.  ExternalName, headless (None),
and the API Service (10.96.0.1, served by the real HTTPS listener) are excluded."
  (let ((address (gethash "clusterIP" (gethash "spec" service))))
    (and (not (service-external-name-p service))
         (stringp address)
         (not (equal address "None"))
         (not (equal address "10.96.0.1")))))

(defun service-lb-plan (services endpoints-of)
  "Pack SERVICES into load-balancer map entries.
ENDPOINTS-OF is a function of (service port-object) returning a list of
(address target-port) pairs for the Service's ready backends.  Returns three
values: the service entries (VIP key . value conses), the backend entries
(slot key . value conses), and the total slot count.  Backends occupy
consecutive slots from 0, assigned in a deterministic Service/port order."
  (let ((service-entries nil) (backend-entries nil) (slot 0))
    (dolist (service (stable-sort (remove-if-not #'service-lb-eligible-p (copy-list services))
                                  #'string< :key (lambda (s) (gethash "clusterIP" (gethash "spec" s)))))
      (let ((address (gethash "clusterIP" (gethash "spec" service))))
        (loop for port across (gethash "ports" (gethash "spec" service))
              for number = (gethash "port" port)
              for backends = (mapcar (lambda (endpoint) (cons (first endpoint) (second endpoint)))
                                     (funcall endpoints-of service port))
              do (multiple-value-bind (vip-key service-value packed)
                     (service-lb-entries address number slot backends)
                   (push (cons vip-key service-value) service-entries)
                   (dolist (entry packed) (push entry backend-entries))
                   (incf slot (length backends))))))
    (values (nreverse service-entries) (nreverse backend-entries) slot)))

(defstruct (service-lb-controller (:constructor %make-service-lb-controller (store dataplane)))
  "Drives the socket LB maps from the durable store's Service/endpoint state."
  store
  dataplane
  (applied-service-keys nil)   ; VIP key byte-vectors currently in the service map
  (applied-slot-count 0)       ; highest backend slot currently populated
  (applied-signature nil))     ; last applied plan, for no-op skipping

(defun make-service-lb-controller (store dataplane)
  (%make-service-lb-controller store dataplane))

(defun converge-service-lb-controller
    (controller
     &key (update #'whistler/loader:map-update)
          (delete #'whistler/loader:map-delete)
          (list-services
           (lambda () (list-core-resources (service-lb-controller-store controller) "services")))
          (endpoints-of
           (lambda (service port)
             (service-pod-endpoints (service-lb-controller-store controller) service port))))
  "Recompute the desired LB table and apply the difference to the maps.
Writes every backend before the service that references it (so the program never
reads a VIP whose slots are missing), then removes freed backend slots and
withdrawn VIPs.  A plan identical to the last applied one writes nothing."
  (multiple-value-bind (service-entries backend-entries slot-count)
      (service-lb-plan (funcall list-services) endpoints-of)
    (let ((signature (cons service-entries backend-entries)))
      (unless (equalp signature (service-lb-controller-applied-signature controller))
        (let ((service-map (service-lb-service-table (service-lb-controller-dataplane controller)))
              (backend-map (service-lb-backend-table (service-lb-controller-dataplane controller)))
              (new-keys (mapcar #'car service-entries)))
          ;; Add/update first: backends, then the services that point at them.
          (dolist (entry backend-entries) (funcall update backend-map (car entry) (cdr entry)))
          (dolist (entry service-entries) (funcall update service-map (car entry) (cdr entry)))
          ;; Remove withdrawn VIPs and freed backend slots.
          (dolist (old (service-lb-controller-applied-service-keys controller))
            (unless (member old new-keys :test #'equalp)
              (funcall delete service-map old)))
          (loop for slot from slot-count below (service-lb-controller-applied-slot-count controller)
                do (funcall delete backend-map (service-lb-backend-key slot)))
          (setf (service-lb-controller-applied-service-keys controller) new-keys
                (service-lb-controller-applied-slot-count controller) slot-count
                (service-lb-controller-applied-signature controller) signature)))))
  nil)
