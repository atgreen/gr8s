;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Verify apiserver_request_total and apiserver_request_duration_seconds through
;;;; the real HTTP listener: upstream's verb, scope and label rules, which requests
;;;; are left out, the histogram's buckets, and the bound on label sets.

(in-package #:gr8s/tests)

(def-suite apiserver-metrics :in gr8s)
(in-suite apiserver-metrics)

(defun apiserver-metrics-request (path &rest options)
  "Call the real listener on 18080, returning the body as text and the status."
  (multiple-value-bind (body code)
      (apply #'drakma:http-request (concatenate 'string "http://127.0.0.1:18080" path) :proxy nil :redirect nil options)
    (values (if (stringp body) body (trivial-utf-8:utf-8-bytes-to-string body)) code)))

(test apiserver-requests-are-counted-as-upstream-labels-them
  (with-temporary-store (store path)
    (values path)
    (let ((previous gr8s::*apiserver-request-metrics*) (server nil))
      (setf gr8s::*apiserver-request-metrics* (gr8s::make-apiserver-request-metrics))
      (unwind-protect
           (progn
             (setf server (start-server :address "127.0.0.1" :port 18080 :store store :runtime (make-fake-runtime)))
             (gr8s::create-core-resource store "namespaces" (gr8s::core-object "metadata" (gr8s::core-object "name" "alpha")) nil)
             (apiserver-metrics-request "/api/v1/namespaces/alpha/configmaps")
             (apiserver-metrics-request "/api/v1/namespaces/alpha/configmaps" :method :post :content-type "application/json"
                                        :content "{\"apiVersion\":\"v1\",\"kind\":\"ConfigMap\",\"metadata\":{\"name\":\"one\"}}")
             (apiserver-metrics-request "/api/v1/namespaces/alpha/configmaps/one")
             (apiserver-metrics-request "/api/v1/namespaces/alpha/configmaps/two")
             (apiserver-metrics-request "/api/v1/namespaces/alpha/configmaps/one?dryRun=All" :method :delete)
             (apiserver-metrics-request "/api/v1/namespaces/alpha/configmaps/one?fieldManager=t" :method :patch
                                        :content-type "application/apply-patch+yaml"
                                        :content "{\"apiVersion\":\"v1\",\"kind\":\"ConfigMap\",\"metadata\":{\"name\":\"one\"},\"data\":{\"a\":\"b\"}}")
             (apiserver-metrics-request "/api/v1/configmaps")
             (apiserver-metrics-request "/api/v1/namespaces/alpha/configmaps?watch=true&timeoutSeconds=1")
             ;; None of these reach a resource handler.
             (apiserver-metrics-request "/version")
             (apiserver-metrics-request "/api/v1")
             (apiserver-metrics-request "/no/such/route")
             (let ((text (apiserver-metrics-request "/metrics")))
               (flet ((counted (labels) (search (format nil "apiserver_request_total{~A" labels) text)))
                 (is (counted "code=\"200\",component=\"apiserver\",dry_run=\"\",group=\"\",resource=\"configmaps\",scope=\"namespace\",subresource=\"\",verb=\"LIST\",version=\"v1\"} 1"))
                 (is (counted "code=\"201\",component=\"apiserver\",dry_run=\"\",group=\"\",resource=\"configmaps\",scope=\"resource\",subresource=\"\",verb=\"POST\",version=\"v1\"} 1"))
                 (is (counted "code=\"200\",component=\"apiserver\",dry_run=\"\",group=\"\",resource=\"configmaps\",scope=\"resource\",subresource=\"\",verb=\"GET\",version=\"v1\"} 1"))
                 (is (counted "code=\"404\",component=\"apiserver\",dry_run=\"\",group=\"\",resource=\"configmaps\",scope=\"resource\",subresource=\"\",verb=\"GET\",version=\"v1\"} 1"))
                 (is (counted "code=\"200\",component=\"apiserver\",dry_run=\"All\",group=\"\",resource=\"configmaps\",scope=\"resource\",subresource=\"\",verb=\"DELETE\",version=\"v1\"} 1"))
                 (is (search ",component=\"apiserver\",dry_run=\"\",group=\"\",resource=\"configmaps\",scope=\"resource\",subresource=\"\",verb=\"APPLY\",version=\"v1\"} 1" text))
                 (is (counted "code=\"200\",component=\"apiserver\",dry_run=\"\",group=\"\",resource=\"configmaps\",scope=\"cluster\",subresource=\"\",verb=\"LIST\",version=\"v1\"} 1"))
                 (is (counted "code=\"200\",component=\"apiserver\",dry_run=\"\",group=\"\",resource=\"configmaps\",scope=\"namespace\",subresource=\"\",verb=\"WATCH\",version=\"v1\"} 1")))
               (is (= 8 (count-matches "^apiserver_request_total\\{" text)))
               (is (search "# TYPE apiserver_request_duration_seconds histogram" text))
               (is (search "apiserver_request_duration_seconds_bucket{component=\"apiserver\",dry_run=\"\",group=\"\",resource=\"configmaps\",scope=\"namespace\",subresource=\"\",verb=\"LIST\",version=\"v1\",le=\"+Inf\"} 1" text))
               (is (search "le=\"0.005\"" text))
               (is (search "le=\"60\"" text))
               (is (search "apiserver_request_sli_duration_seconds_bucket{component=\"apiserver\",group=\"\",resource=\"configmaps\",scope=\"namespace\",subresource=\"\",verb=\"LIST\",version=\"v1\",le=\"0.05\"}" text))
               ;; The finished watch was long-running while it lasted.
               (is (search "apiserver_longrunning_requests{component=\"apiserver\",group=\"\",resource=\"configmaps\",scope=\"namespace\",subresource=\"\",verb=\"WATCH\",version=\"v1\"} 0" text))
               (is (search "apiserver_current_inflight_requests{request_kind=\"mutating\"}" text))
               (is (search "# TYPE process_resident_memory_bytes gauge" text))
               ;; The GET and its 404 share one latency series.
               (is (search "apiserver_request_duration_seconds_count{component=\"apiserver\",dry_run=\"\",group=\"\",resource=\"configmaps\",scope=\"resource\",subresource=\"\",verb=\"GET\",version=\"v1\"} 2" text))))
        (setf gr8s::*apiserver-request-metrics* previous)
        (when server (stop-server server))))))

(defun count-matches (regex text)
  "Count the lines of TEXT matching REGEX."
  (count-if (lambda (line) (cl-ppcre:scan regex line)) (uiop:split-string text :separator '(#\Newline))))

(test apiserver-request-series-are-bounded
  (let ((metrics (gr8s::make-apiserver-request-metrics))
        (gr8s::+apiserver-request-series-limit+ 3))
    (loop for index below 10
          do (gr8s::record-apiserver-request (list "GET" "" "" "v1" (format nil "r~D" index) "" "resource") 200 0.01
                                             :metrics metrics))
    (is (= 3 (hash-table-count (gr8s::apiserver-request-metrics-counts metrics))))
    (is (= 3 (hash-table-count (gr8s::apiserver-request-metrics-durations metrics))))
    ;; A known series keeps counting, and a 429 has no latency.
    (gr8s::record-apiserver-request (list "GET" "" "" "v1" "r0" "" "resource") 200 nil :metrics metrics)
    (is (= 2 (gethash (list "GET" "" "" "v1" "r0" "" "resource" "200") (gr8s::apiserver-request-metrics-counts metrics))))
    (is (= 1 (gr8s::histogram-count
              (gethash (list "GET" "" "" "v1" "r0" "" "resource") (gr8s::apiserver-request-metrics-durations metrics)))))
    ;; A dry run has no SLI series.
    (gr8s::record-apiserver-request (list "DELETE" "All" "" "v1" "r0" "" "resource") 200 0.01 :metrics metrics)
    (is (null (gethash (list "DELETE" "" "v1" "r0" "" "resource") (gr8s::apiserver-request-metrics-sli metrics))))))

(test inflight-watermark-is-the-last-seconds-maximum
  (let ((metrics (gr8s::make-apiserver-request-metrics)))
    (gr8s::note-inflight-change :mutating 1 :metrics metrics :now 100)
    (gr8s::note-inflight-change :mutating 1 :metrics metrics :now 100)
    (gr8s::note-inflight-change :mutating -1 :metrics metrics :now 100)
    (gr8s::note-inflight-change :mutating -1 :metrics metrics :now 101)
    (is (= 2 (getf (gr8s::apiserver-request-metrics-published metrics) :mutating)))
    (is (= 0 (getf (gr8s::apiserver-request-metrics-inflight metrics) :mutating)))))
