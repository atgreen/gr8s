;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Leader-aware HTTP wired into the real server (podster-c2d.7.3): a follower
;;;; 307-redirects a mutating API request to the leader's URL (preserving path +
;;;; query), answers 503 when no leader is known, and serves reads locally.

(in-package #:gr8s/tests)
(def-suite ha-redirect-http :in gr8s)
(in-suite ha-redirect-http)

(test ha-http-redirects-writes-and-serves-reads
  (let ((server (gr8s::start-server
                 :address "127.0.0.1" :port 18091
                 :leader-status-fn (lambda () (values nil "http://10.0.0.9:6443")))))
    (unwind-protect
         (progn
           ;; A write on the follower is redirected to the leader, path+query kept.
           (multiple-value-bind (body status headers)
               (drakma:http-request
                "http://127.0.0.1:18091/api/v1/namespaces/default/configmaps?x=1"
                :method :post :content "{}" :redirect nil)
             (declare (ignore body))
             (is (= 307 status) "a write on a follower is 307-redirected")
             (is (equal "http://10.0.0.9:6443/api/v1/namespaces/default/configmaps?x=1"
                        (cdr (assoc :location headers)))
                 "the redirect preserves the path and query"))
           ;; Reads are served locally (health endpoint answers 200).
           (multiple-value-bind (body status)
               (drakma:http-request "http://127.0.0.1:18091/livez" :redirect nil)
             (is (= 200 status) "reads are served locally on a follower")
             (is (string= "ok" body))))
      (gr8s::stop-server server))))

(test ha-http-503-when-no-leader-known
  (let ((server (gr8s::start-server
                 :address "127.0.0.1" :port 18092
                 :leader-status-fn (lambda () (values nil nil)))))
    (unwind-protect
         (multiple-value-bind (body status)
             (drakma:http-request "http://127.0.0.1:18092/api/v1/configmaps"
                                  :method :post :content "{}" :redirect nil)
           (declare (ignore body))
           (is (= 503 status) "a write with no known leader is 503"))
      (gr8s::stop-server server))))
