;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;; Run alone: sbcl --noinform --non-interactive --load scripts/bench-gateway-deltas.lisp
;;;; Synthetic unique-host route updates. Fixture construction is outside measurements.
;;;; Allocation counters are process-wide; do not run server threads in this process.
(require :asdf)
(asdf:load-asd (truename "gr8s.asd"))
(asdf:load-system "gr8s")
(in-package #:gr8s.controllers)

(defun benchmark-delta-route (index &optional replacement)
  (make-gw-route
   :namespace "default" :name (format nil "route-~D" index)
   :hostnames (list (format nil "~D.example.com" index))
   :rules (list (make-gw-rule
                 :matches (list (make-gw-match))
                 :backends (list (make-gw-backend :name (if replacement "new" "old")))))))

(defun measure-gateway-delta-operation (label count iterations function)
  (dotimes (i 10) (funcall function))
  (sb-ext:gc :full t)
  (let ((bytes (sb-ext:get-bytes-consed))
        (cpu (get-internal-run-time))
        (wall (get-internal-real-time)))
    (dotimes (i iterations) (funcall function))
    (format t "~&DELTA operation=~A routes=~D iterations=~D bytes/op=~,1F cpu-us/op=~,3F wall-us/op=~,3F~%"
            label count iterations (/ (- (sb-ext:get-bytes-consed) bytes) iterations)
            (/ (* 1000000.0 (- (get-internal-run-time) cpu)) internal-time-units-per-second iterations)
            (/ (* 1000000.0 (- (get-internal-real-time) wall)) internal-time-units-per-second iterations))))

(dolist (count '(100 1000 3000 10000))
  (let* ((routes (loop for i below count collect (benchmark-delta-route i)))
         (replacement (benchmark-delta-route 0 t))
         (resources (make-hash-table :test #'equal)))
    (dolist (route routes)
      (setf (gethash (list "httproutes" "default" (gw-route-name route)) resources) route))
    (let ((index (gr8s.agent::gateway-resource-index resources)))
      (measure-gateway-delta-operation
       "resource-index-update" count 500
       (lambda () (gr8s.agent::gateway-resource-index-with
                   index '("httproutes" "default" "route-0") replacement))))
    (multiple-value-bind (dispatcher table) (build-gateway-router routes)
      (measure-gateway-delta-operation
       "dispatch" count 100000
       (lambda () (funcall dispatcher "0.example.com" "/" "GET" nil)))
      (measure-gateway-delta-operation
       "resource-map-copy" count 500 (lambda () (alexandria:copy-hash-table resources)))
      (measure-gateway-delta-operation
       "routing-update" count 500
       (lambda ()
         (update-gateway-routing-table
          table (list (first routes)) (list replacement)
          (lambda (a b) (gw-key> (gw-candidate-key a) (gw-candidate-key b)))))))))
