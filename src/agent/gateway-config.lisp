;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0

(in-package #:gr8s.agent)

(defun reset-node-gateway-session (node-runtime)
  "Require authoritative synchronization after every session boundary."
  (bt:with-lock-held ((node-runtime-apply-lock node-runtime))
    (setf (node-runtime-gateway-base-revision node-runtime) nil
          (node-runtime-gateway-config-revision node-runtime) 0
          (node-runtime-gateway-synchronized-p node-runtime) nil)))

(defun record-node-gateway-baseline (node-runtime snapshot ready)
  "A complete successful node apply authorizes this session's derived Gateway view."
  (setf (node-runtime-gateway-base-revision node-runtime)
        (when ready (slot-value snapshot 'gr8s.node.v1::revision))
        (node-runtime-gateway-config-revision node-runtime) 0
        (node-runtime-gateway-synchronized-p node-runtime) (and ready t)))

(defun node-gateway-projection-store (node-runtime resources)
  "A derived read-only store: resources are immutable and never enter its journal."
  (let ((view (gr8s.store::make-pod-store nil))
        (source (node-runtime-store node-runtime)))
    (gr8s.store::with-store-lock (source)
      (setf (gr8s.store::pod-store-resources view) resources
            (gr8s.store::pod-store-resource-revision view) (gr8s.store::pod-store-resource-revision source)
            (gr8s.store::pod-store-pods view) (alexandria:copy-hash-table (gr8s.store::pod-store-pods source))
            (gr8s.store::pod-store-pod-observed-statuses view)
            (alexandria:copy-hash-table (gr8s.store::pod-store-pod-observed-statuses source))
            (gr8s.store::pod-store-pod-observed-phases view)
            (alexandria:copy-hash-table (gr8s.store::pod-store-pod-observed-phases source))))
    view))

(defun ensure-node-gateway-controller (node-runtime view)
  (or (node-runtime-gateway-controller node-runtime)
      (setf (node-runtime-gateway-controller node-runtime)
            (let ((steering (node-runtime-gateway-steering node-runtime)))
              (make-gateway-controller
               view
               :cert-dir (merge-pathnames "gateway-certs/" (node-runtime-state-directory node-runtime))
               :register-fn (lambda (port listener)
                              (when steering
                                (gateway-steering-register steering port (gateway-listener-socket-fd listener)))
                              (ensure-gateway-listener-firewall port))
               :unregister-fn (lambda (port)
                                (remove-gateway-listener-firewall port)
                                (when steering (gateway-steering-unregister steering port))))))))

(defun install-node-gateway-view (node-runtime resources &key changes)
  "Publish a complete derived view, failing closed if listener publication fails.
The caller holds the node apply lock; no durable resource index is modified."
  (let* ((view (node-gateway-projection-store node-runtime resources))
         (controller (ensure-node-gateway-controller node-runtime view))
         (old-store (gr8s.controllers::gateway-controller-store controller))
         (old-resolver (gr8s.controllers::gateway-controller-resolver controller))
         (published nil))
    (unwind-protect
         (progn
           (setf (gr8s.controllers::gateway-controller-store controller) view
                 (gr8s.controllers::gateway-controller-snapshot-resolvers-p controller) t
                 (gr8s.controllers::gateway-controller-resolver controller)
                 (gr8s.controllers::make-service-backend-resolver view))
           (cond ((and changes (gr8s.controllers::gateway-controller-parent-listeners controller)
                       (every (lambda (entry) (equal "httproutes" (first (car entry)))) changes))
                  (gr8s.controllers::converge-gateway-http-route-changes controller old-store changes))
                 ((and changes (every (lambda (entry) (member (first (car entry))
                                                            '("tcproutes" "tlsroutes" "grpcroutes") :test #'equal)) changes))
                  (converge-gateway-l4-listeners controller))
                 (t (converge-gateway-listeners controller) (converge-gateway-l4-listeners controller)))
           (setf (node-runtime-gateway-view-store node-runtime) view
                 published t)
           view)
      (unless published
        (setf (node-runtime-gateway-synchronized-p node-runtime) nil
              (gr8s.controllers::gateway-controller-store controller) old-store
              (gr8s.controllers::gateway-controller-resolver controller) old-resolver)
        ;; No partially published mix of old and new listeners may remain ready.
        (ignore-errors (stop-gateway-controller controller))))))

(defun ensure-node-gateway-baseline-current (node-runtime update)
  (unless (and (node-runtime-gateway-synchronized-p node-runtime)
               (node-runtime-gateway-base-revision node-runtime)
               (node-runtime-gateway-view-store node-runtime))
    (error 'node-snapshot-incomplete :message "Gateway configuration needs a successful full node synchronization"))
  (gr8s.protocol::validate-gateway-config-update
   update (node-runtime-gateway-base-revision node-runtime)
   (node-runtime-gateway-config-revision node-runtime))
  (when (bt:with-lock-held ((node-runtime-arrival-lock node-runtime))
          (< (slot-value update 'gr8s.node.v1::base-node-revision)
             (node-runtime-received-revision node-runtime)))
    (error 'pod-reconciliation-superseded))
  (let ((snapshot (node-runtime-applied-snapshot node-runtime)))
    (unless snapshot
      (error 'node-snapshot-incomplete :message "Gateway baseline lost node convergence"))
    (ensure-node-snapshot-service-risk-ready node-runtime)
    (ensure-node-snapshot-service-receivers-ready node-runtime snapshot)
    (ensure-node-snapshot-service-selection-ready node-runtime snapshot)))

(defun decode-node-gateway-changes (node-runtime update)
  "Validate every row before publishing; dependent Service state must be fenced by a full apply."
  (loop for change in (slot-value update 'gr8s.node.v1::changes)
        for key = (gr8s.protocol::gateway-resource-change-key change)
        for entry = (unless (slot-value change 'gr8s.node.v1::deleted)
                      (gr8s.kubelet::decode-service-discovery-entry
                       (slot-value change 'gr8s.node.v1::object-json)))
        do (when (and entry (not (equal key (car entry))))
             (error "Gateway resource identity disagrees with its object: ~S" key))
           (when (and (member (first key) '("services" "endpointslices") :test #'equal)
                      (not (gr8s.store::json-value-equal-p
                            (cdr entry) (gethash key (node-runtime-discovery-resources node-runtime)))))
             (error "Gateway dependency ~S has no matching full node safety baseline" key))
        collect (cons key (cdr entry))))

(defun reconcile-node-gateway-config (node-runtime update)
  "Apply changed Gateway rows against the current node baseline without journaling them."
  (bt:with-lock-held ((node-runtime-apply-lock node-runtime))
    (unless (eq :running (node-runtime-state node-runtime))
      (error 'runtime-error :message "node runtime is not running"))
    (ensure-node-gateway-baseline-current node-runtime update)
    (let* ((changes (decode-node-gateway-changes node-runtime update))
           (resources (alexandria:copy-hash-table
                       (gr8s.store::pod-store-resources (node-runtime-gateway-view-store node-runtime)))))
      (dolist (entry changes)
        (if (cdr entry) (setf (gethash (car entry) resources) (cdr entry)) (remhash (car entry) resources)))
      (ensure-node-gateway-baseline-current node-runtime update)
      (install-node-gateway-view node-runtime resources :changes changes)
      (ensure-node-gateway-baseline-current node-runtime update)
      (setf (node-runtime-gateway-config-revision node-runtime) (slot-value update 'gr8s.node.v1::revision))
      t)))
