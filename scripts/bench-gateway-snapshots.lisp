;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;; Run alone: sbcl --noinform --non-interactive --load scripts/bench-gateway-snapshots.lisp
;;;; Measures read-only attached-route counting and a 3000-route projection.
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
  (service-discovery-projection store)
  #+sbcl (sb-ext:gc :full t)
  (let* ((started (get-internal-real-time))
         #+sbcl (before (sb-ext:get-bytes-consed))
         (projection (service-discovery-projection store))
         #+sbcl (allocated (- (sb-ext:get-bytes-consed) before)))
    (assert (= 3000 (length projection)))
    (format t "~&SNAPSHOT routes=3000 milliseconds=~,3F~@[ bytes=~D~]~%"
            (* 1000.0 (/ (- (get-internal-real-time) started) internal-time-units-per-second))
            #+sbcl allocated #-sbcl nil)
    ;; A generous isolated-process budget, below the previous ~43 MB per pass, allowing measurement noise.
    #+sbcl (assert (< allocated 34000000) () "3000-route projection allocated ~D bytes; budget is 34 MB" allocated)))
