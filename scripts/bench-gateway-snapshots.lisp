;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;; Run alone: sbcl --noinform --non-interactive --load scripts/bench-gateway-snapshots.lisp
;;;; Measures read-only attached-route counting and cold, unchanged and one-row repair projections.
;;;; Synthetic fixture construction is excluded; real managed-fields metadata may be larger.
;;;; Run separately from the test server suites: allocation counters are process-wide.
(require :asdf)
(asdf:load-asd (truename "gr8s.asd"))
(asdf:load-system "gr8s")
(in-package #:gr8s.kubelet)

(let* ((store (gr8s.store::make-pod-store nil))
       (template (com.inuoe.jzon:parse
                  "{\"apiVersion\":\"gateway.networking.k8s.io/v1\",\"kind\":\"HTTPRoute\",\"metadata\":{\"name\":\"route\",\"namespace\":\"default\",\"uid\":\"benchmark-route\",\"resourceVersion\":\"1\"},\"spec\":{\"parentRefs\":[{\"name\":\"web\"}],\"hostnames\":[\"app.example.com\"],\"rules\":[{\"backendRefs\":[{\"name\":\"backend\",\"port\":80}]}]}}")))
  (dotimes (index 3000)
    (let* ((name (format nil "route-~D" index))
           (object (copy-core-object template)) (metadata (gethash "metadata" object)))
      (setf (gethash "name" metadata) name (gethash "uid" metadata) name
            (gethash (list "httproutes" "default" name) (pod-store-resources store)) object)))
  (let* ((gateway (com.inuoe.jzon:parse "{\"metadata\":{\"name\":\"web\",\"namespace\":\"default\"}}"))
         (listener (com.inuoe.jzon:parse "{\"name\":\"http\",\"port\":80,\"protocol\":\"HTTP\"}"))
         (kinds (vector (core-object "kind" "HTTPRoute"))))
    #+sbcl (sb-ext:gc :full t)
    (let* (#+sbcl (before (sb-ext:get-bytes-consed))
           (count (gr8s.apiserver::gateway-listener-attached-routes store gateway listener kinds))
           #+sbcl (allocated (- (sb-ext:get-bytes-consed) before)))
      (assert (= 3000 count))
      (format t "~&ATTACHED routes=~D bytes=~D~%" count #+sbcl allocated #-sbcl 0)
      #+sbcl (assert (< allocated 4000000) () "Read-only route count allocated ~D bytes; budget is 4 MB" allocated)))
  ;; Warm generic dispatch and JSON machinery, then discard the row cache so
  ;; "cold" measures encoding rather than one-time runtime initialization.
  (service-discovery-projection store)
  (setf (gr8s.store::pod-store-discovery-encoding-cache store) nil)
  (labels ((measure (label function budget)
             #+sbcl (sb-ext:gc :full t)
             (let* ((started (get-internal-real-time))
                    #+sbcl (before (sb-ext:get-bytes-consed))
                    (projection (funcall function))
                    #+sbcl (allocated (- (sb-ext:get-bytes-consed) before)))
               (assert (= 3000 (length projection)))
               (format t "~&SNAPSHOT mode=~A routes=3000 milliseconds=~,3F~@[ bytes=~D~]~%"
                       label (* 1000.0 (/ (- (get-internal-real-time) started) internal-time-units-per-second))
                       #+sbcl allocated #-sbcl nil)
               #+sbcl (when budget
                        (assert (< allocated budget) () "~A allocated ~D bytes; budget is ~D" label allocated budget))
               projection)))
    (let* ((cold (measure "cold" (lambda () (service-discovery-projection store)) 34000000))
           (warm (measure "unchanged" (lambda () (service-discovery-projection store)) 2000000)))
      (assert (every #'eq cold warm))
      ;; Publish a replacement row and index, preserving the immutable-store contract.
      (let* ((key '("httproutes" "default" "route-1500"))
             (object (copy-core-object (gethash key (pod-store-resources store))))
             (resources (alexandria:copy-hash-table (pod-store-resources store))))
        (setf (gethash "hostnames" (gethash "spec" object)) #("changed.example.com")
              (gethash key resources) object
              (pod-store-resources store) resources)
        (let ((changed (measure "one-row" (lambda () (service-discovery-projection store)) 2000000)))
          (assert (= 1 (count nil (mapcar #'eq warm changed))))
          (assert (equalp changed (build-service-discovery-projection (capture-service-discovery-store store)))))))
    (let* ((projection (service-discovery-projection store))
           (session (gr8s.apiserver::make-node-agent-session nil))
           (snapshot (make-instance 'gr8s.node.v1::desired-state-snapshot
                                    :service-discovery-objects-json projection)))
      (setf (gr8s.apiserver::node-agent-session-gateway-deltas-p session) t)
      (gr8s.apiserver::install-node-gateway-baseline session snapshot)
      (setf (gr8s.apiserver::node-agent-session-gateway-discovery-key-cache session) nil)
      (flet ((publish ()
               (gr8s.apiserver::install-node-gateway-baseline session snapshot)
               projection))
        (measure "publisher-cold" #'publish nil)
        (measure "publisher-unchanged" #'publish 2000000)))
    (let ((reconciler (make-reconciler store nil))
          (projection (service-discovery-projection store)))
      (gr8s.controllers::collect-orphaned-api-objects reconciler)
      (measure "collector-inspection"
               (lambda () (gr8s.controllers::collect-orphaned-api-objects reconciler) projection)
               2000000))))
