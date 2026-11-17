;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0

(in-package #:gr8s.controllers)

(defun gateway-dirty-watermark (runtime)
  (bt:with-lock-held ((control-plane-runtime-gateway-dirty-lock runtime))
    (control-plane-runtime-gateway-change-sequence runtime)))

(defun note-gateway-resource-changes (runtime changes)
  "Record keys only; this callback runs inside the committed store transaction."
  (bt:with-lock-held ((control-plane-runtime-gateway-dirty-lock runtime))
    (let ((sequence (incf (control-plane-runtime-gateway-change-sequence runtime))))
      (dolist (change changes)
        (let ((resource (gethash "resource" change)))
          (when (member resource '("gatewayclasses" "gateways" "httproutes" "tcproutes" "tlsroutes" "grpcroutes")
                        :test #'equal)
            (let* ((new (gethash "new" change))
                   (object (if (hash-table-p new) new (gethash "old" change)))
                   (metadata (gethash "metadata" object))
                   (key (list resource (gethash "namespace" metadata) (gethash "name" metadata))))
              (setf (gethash key (control-plane-runtime-gateway-dirty runtime)) sequence))))))))

(defun clear-gateway-dirty-through (runtime watermark)
  "A full repair covers preceding changes; concurrent later writes stay pending."
  (bt:with-lock-held ((control-plane-runtime-gateway-dirty-lock runtime))
    (let ((dirty (control-plane-runtime-gateway-dirty runtime)))
      (dolist (key (loop for key being the hash-keys of dirty using (hash-value sequence)
                        when (<= sequence watermark) collect key))
        (remhash key dirty)))))

(defun take-gateway-dirty-keys (runtime)
  (bt:with-lock-held ((control-plane-runtime-gateway-dirty-lock runtime))
    (prog1 (loop for key being the hash-keys of (control-plane-runtime-gateway-dirty runtime) collect key)
      (clrhash (control-plane-runtime-gateway-dirty runtime)))))

(defun requeue-gateway-dirty-keys (runtime keys)
  (bt:with-lock-held ((control-plane-runtime-gateway-dirty-lock runtime))
    (let ((sequence (incf (control-plane-runtime-gateway-change-sequence runtime)))
          (dirty (control-plane-runtime-gateway-dirty runtime)))
      (dolist (key keys)
        (unless (gethash key dirty) (setf (gethash key dirty) sequence))))))

(defun capture-gateway-resource-changes (runtime keys)
  "Capture selected committed rows and newly referenced certificates atomically.
Route edits never enumerate or serialize the complete discovery projection."
  (let ((store (control-plane-runtime-store runtime))
        (rows (make-hash-table :test #'equal))
        (dependency-revision nil))
    (gr8s.store::with-store-lock (store)
      (let ((resources (gr8s.store::pod-store-resources store)))
        (dolist (key keys)
          (let ((object (gethash key resources)))
            (setf (gethash key rows) object)
            (when (and object (equal "gateways" (first key)))
              (loop for listener across (gethash "listeners" (gethash "spec" object) #())
                    for reference = (and (equal "HTTPS" (gethash "protocol" listener))
                                         (gateway-listener-tls-ref (second key) listener store))
                    when reference
                      do (let* ((secret-key (list "secrets" (car reference) (cdr reference)))
                                (secret (gethash secret-key resources)))
                           (setf (gethash secret-key rows)
                                 (when (and secret (equal "kubernetes.io/tls" (gethash "type" secret))) secret))))))))
      (setf dependency-revision (gr8s.store::pod-store-gateway-dependency-revision store)))
    (values
     (loop for key in (sort (loop for key being the hash-keys of rows collect key)
                            #'string< :key (lambda (key) (format nil "~{~A~^/~}" key)))
           for object = (gethash key rows)
           collect (make-instance 'gr8s.node.v1::gateway-resource-change
                                   :resource (first key) :namespace (or (second key) "") :name (third key)
                                   :deleted (null object)
                                   :object-json
                                   (if object
                                       (trivial-utf-8:string-to-utf-8-bytes
                                        (endpointslice-canonical-json
                                         (gr8s.kubelet::service-discovery-public-object object)))
                                       (make-array 0 :element-type '(unsigned-byte 8)))))
     dependency-revision)))

(defun publish-gateway-resource-changes (runtime)
  "Publish small Gateway batches, retaining full node safety and legacy delivery."
  (let* ((keys (take-gateway-dirty-keys runtime))
         (server (control-plane-runtime-node-server runtime))
         (sent 0) (full 0) (failed nil))
    (unless keys (return-from publish-gateway-resource-changes (values 0 0)))
    (dolist (name (bt:with-lock-held ((gr8s.apiserver::node-grpc-server-lock server))
                    (loop for name being the hash-keys of (gr8s.apiserver::node-grpc-server-sessions server) collect name)))
      (gr8s.apiserver::call-with-node-publication
       server name
       (lambda ()
         (let ((session (bt:with-lock-held ((gr8s.apiserver::node-grpc-server-lock server))
                          (gethash name (gr8s.apiserver::node-grpc-server-sessions server)))))
           (when (and session (not (gr8s.apiserver::node-agent-session-evicted-p session)))
             (handler-case
                 (let ((reason :unsupported))
                   (when (gr8s.apiserver::node-agent-session-gateway-deltas-p session)
                     (multiple-value-bind (changes dependency-revision) (capture-gateway-resource-changes runtime keys)
                       (multiple-value-bind (update outcome)
                           (gr8s.apiserver::deliver-node-gateway-config session changes :dependency-epoch dependency-revision)
                         (when update (incf sent))
                         (setf reason outcome))))
                   (when (member reason '(:unsupported :baseline-required))
                     (gr8s.apiserver::refresh-cluster-service-risk-grant server)
                     (publish-node-snapshot runtime name)
                     (incf full)))
               (error (condition)
                 (setf failed t)
                 (format *error-output* "gr8s Gateway publication for ~A failed: ~A~%" name condition)
                 (ignore-errors (gr8s.apiserver::close-node-agent-session session)))))))))
    (when failed (requeue-gateway-dirty-keys runtime keys))
    (values sent full)))
