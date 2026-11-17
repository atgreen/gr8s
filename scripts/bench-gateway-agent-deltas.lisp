;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;; Run alone: sbcl --noinform --non-interactive --load scripts/bench-gateway-agent-deltas.lisp
;;;; Exercises the complete agent delta apply using fake listeners/runtime.
;;;; Fixture setup, full synchronization and encoding of input rows are excluded.
;;;; SBCL allocation counters are process-wide; do not run server threads here.
(require :asdf)
(asdf:load-asd (truename "gr8s.asd"))
(asdf:load-system "gr8s/tests")
(in-package #:gr8s/tests)

(dolist (count '(100 1000 3000 10000))
  (with-temporary-store (source path)
    (gwc-seed source)
    (let ((template (gr8s.resources::get-core-resource source "httproutes" "default" "app")))
      (loop for i from 1 below count
            do (let* ((name (format nil "route-~D" i))
                      (object (gr8s.resources::copy-core-object template)))
                 (setf (gethash "name" (gethash "metadata" object)) name
                       (gethash "uid" (gethash "metadata" object)) name
                       (gethash "hostnames" (gethash "spec" object)) (vector (format nil "~D.example.com" i))
                       (gethash (list "httproutes" "default" name)
                                (gr8s.store::pod-store-resources source)) object))))
    (let* ((agent (gateway-node-for-test path))
           (revision 0)
           (iterations 100)
           (changes (loop for host in '("first.example.com" "second.example.com")
                          collect (let ((object (gr8s.resources::get-core-resource
                                                 source "httproutes" "default" "app")))
                                    (setf (gethash "hostnames" (gethash "spec" object)) (vector host))
                                    (gateway-object-change-for-test "httproutes" object)))))
      (gr8s.agent::reconcile-node-snapshot agent (gateway-snapshot-for-test source 7))
      (flet ((apply-change ()
               (let ((update (gateway-update-for-test revision (1+ revision)
                                                      (nth (mod revision 2) changes))))
                 (gr8s.agent::reconcile-node-gateway-config agent update)
                 (incf revision))))
        (dotimes (i 10) (apply-change))
        (sb-ext:gc :full t)
        (let ((bytes (sb-ext:get-bytes-consed)) (cpu (get-internal-run-time)))
          (dotimes (i iterations) (apply-change))
          (format t "~&AGENT-DELTA routes=~D iterations=~D bytes/op=~,1F cpu-us/op=~,3F~%"
                  count iterations (/ (- (sb-ext:get-bytes-consed) bytes) iterations)
                  (/ (* 1000000.0 (- (get-internal-run-time) cpu))
                     internal-time-units-per-second iterations)))))))
