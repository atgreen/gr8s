;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;; Run: sbcl --dynamic-space-size 4096 --non-interactive --load scripts/bench-gateway-router.lisp
;;;; Optional GR8S_ROUTER_BASELINE points to the old gateway-router.lisp to compare
;;;; construction/dispatch and check identical results in this benchmark process.
;;;; BENCH CSV columns: layout,routes,implementation,build-ms,build-bytes,
;;;; dispatch-ns/request,dispatch-bytes/request. Build figures average 100 indexed
;;;; or 3 JIT builds, with compiler notes suppressed. Excludes HTTP/network costs.
(require :asdf)
(asdf:load-asd (truename "gr8s.asd"))
(asdf:load-system "gr8s")
(in-package #:gr8s.controllers)

(let ((baseline (uiop:getenv "GR8S_ROUTER_BASELINE")))
  (when baseline
    (with-open-file (stream baseline)
      (loop for form = (read stream nil :eof) until (eq form :eof)
            when (and (consp form) (eq (first form) 'defun)
                      (member (second form) '(gw-host-test-form gw-match-test-form
                                             gw-candidate-clause compile-gateway-router)))
              do (when (eq (second form) 'compile-gateway-router)
                   (setf (second form) 'benchmark-jit-gateway-router))
                 (eval form)))))

(defun bench-router-workload (layout count)
  (loop for i below count
        for id = (format nil "~6,'0D" i)
        for host = (ecase layout
                     (:hosts (format nil "r~A.example.com" id))
                     (:wildcards (format nil "*.r~A.example.com" id))
                     ((:paths :headers) "shared.example.com"))
        for path = (if (eq layout :paths) (format nil "/r~A" id) "/")
        for headers = (when (eq layout :headers) (list (cons "x-route" id)))
        collect (make-gw-route
                 :namespace "bench" :name id :hostnames (list host)
                 :rules (list (make-gw-rule
                               :matches (list (make-gw-match :path-type :exact :path path :headers headers))
                               :backends (list (make-gw-backend :name id :port 80))))) into routes
        collect (list (if (eq layout :wildcards) (format nil "x.r~A.example.com" id) host)
                      path "GET" headers) into requests
        finally (return (values routes (coerce requests 'vector)))))

(defun bench-router-sample (builder routes requests build-iterations iterations)
  (sb-ext:gc :full t)
  (let* ((bytes (sb-ext:get-bytes-consed))
         (start (get-internal-real-time))
         (router (handler-bind ((sb-ext:compiler-note #'muffle-warning))
                   (loop repeat build-iterations for result = (funcall builder routes)
                         finally (return result))))
         (build-ms (* 1000d0 (/ (- (get-internal-real-time) start) (* build-iterations internal-time-units-per-second))))
         (build-bytes (/ (- (sb-ext:get-bytes-consed) bytes) build-iterations))
         (hits 0))
    ;; Warm code and caches; time request matching separately from construction.
    (loop for request across requests do (apply router request))
    (setf bytes (sb-ext:get-bytes-consed) start (get-internal-real-time))
    (dotimes (i iterations)
      (let ((result (apply router (aref requests (mod i (length requests))))))
        (when result (incf hits))))
    (assert (= hits iterations))
    (values router build-ms build-bytes
            (* 1d9 (/ (- (get-internal-real-time) start)
                       (* iterations internal-time-units-per-second)))
            (/ (- (sb-ext:get-bytes-consed) bytes) (float iterations 1d0)))))

(dolist (layout '(:hosts :paths :wildcards :headers))
  (dolist (count '(100 1000 3000))
    (multiple-value-bind (routes requests) (bench-router-workload layout count)
      (let ((indexed nil))
        (dolist (implementation (if (fboundp 'benchmark-jit-gateway-router) '(indexed jit) '(indexed)))
          (multiple-value-bind (router ms bytes ns request-bytes)
              (bench-router-sample (if (eq implementation 'indexed) #'build-gateway-router
                                      #'benchmark-jit-gateway-router) routes requests
                                   (if (eq implementation 'indexed) 100 3)
                                   (if (and (eq implementation 'indexed) (member layout '(:hosts :wildcards)))
                                       1000000 30000))
            (if (eq implementation 'indexed)
                (setf indexed router)
                (loop for request across requests do
                  (assert (equalp (apply indexed request) (apply router request)))
                  (destructuring-bind (host path method headers) request
                    (assert (equalp (funcall indexed host "/miss" method headers)
                                    (funcall router host "/miss" method headers)))
                    (assert (equalp (funcall indexed "unmatched.invalid" path method headers)
                                    (funcall router "unmatched.invalid" path method headers))))))
            (format t "~&BENCH,~(~A~),~D,~(~A~),~,3F,~,0F,~,1F,~,1F~%"
                    layout count implementation ms bytes ns request-bytes)
            (finish-output)))))))
