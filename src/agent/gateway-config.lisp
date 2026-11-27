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

(defstruct (gateway-projection-store (:include gr8s.store:pod-store)
                                    (:constructor make-gateway-projection-store (index)))
  ;; This derived store is never journaled. Each collection has its own persistent
  ;; index, so backend discovery does not traverse unrelated routes.
  index)

(defun gateway-resource-index-with (index key object)
  (let* ((resource (first key))
         (collection (or (fset:lookup index resource)
                         (fset:empty-ch-map nil 'fset:compare 'fset:eql-compare)))
         (next (if object (fset:with collection (rest key) object)
                   (fset:less collection (rest key)))))
    (if (fset:empty? next) (fset:less index resource)
        (fset:with index resource next))))

(defun gateway-resource-index (resources)
  (if (hash-table-p resources)
      (let ((index (fset:empty-ch-map nil 'fset:compare 'fset:eql-compare)))
        (maphash (lambda (key object)
                   (setf index (gateway-resource-index-with index key object))) resources)
        index)
      resources))

(defmethod gr8s.resources::get-core-resource ((store gateway-projection-store) resource namespace name)
  (let* ((collection (fset:lookup (gateway-projection-store-index store) resource))
         (object (and collection (fset:lookup collection (list namespace name)))))
    (unless object
      (gr8s.resources::core-resource-error 404 "NotFound" "~A ~A/~A was not found" resource namespace name))
    (gr8s.resources::copy-core-object object)))

(defmethod gr8s.resources::list-core-resources ((store gateway-projection-store) resource &optional namespace)
  (let ((collection (fset:lookup (gateway-projection-store-index store) resource)) (objects nil))
    (when collection
      (fset:do-map (key object collection)
        (when (or (null namespace) (equal namespace (first key)))
          (push (gr8s.resources::copy-core-object object) objects))))
    (values (sort objects #'string< :key
                  (lambda (object)
                    (let ((metadata (gethash "metadata" object)))
                      (format nil "~A/~A" (gethash "namespace" metadata) (gethash "name" metadata)))))
            (write-to-string (gr8s.store::pod-store-resource-revision store)))))

(defun node-gateway-projection-store (node-runtime resources)
  "A derived read-only store: resources are immutable and never enter its journal."
  (let ((view (make-gateway-projection-store (gateway-resource-index resources)))
        (source (node-runtime-store node-runtime)))
    (gr8s.store::with-store-lock (source)
      (setf (gr8s.store::pod-store-resource-revision view) (gr8s.store::pod-store-resource-revision source)
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
           ;; Challenges change no listener, so a batch of only them skips convergence.
           (setf gr8s.controllers::*gateway-acme-challenges*
                 (gr8s.controllers::gateway-acme-challenge-table view))
           (cond ((and changes (every (lambda (entry) (equal "challenges" (first (car entry)))) changes)))
                 ((and changes (gr8s.controllers::gateway-controller-parent-listeners controller)
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
           (resources (gateway-projection-store-index (node-runtime-gateway-view-store node-runtime))))
      (dolist (entry changes)
        (setf resources (gateway-resource-index-with resources (car entry) (cdr entry))))
      (ensure-node-gateway-baseline-current node-runtime update)
      (install-node-gateway-view node-runtime resources :changes changes)
      (ensure-node-gateway-baseline-current node-runtime update)
      (setf (node-runtime-gateway-config-revision node-runtime) (slot-value update 'gr8s.node.v1::revision))
      t)))
