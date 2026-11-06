;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Measure API requests as kube-apiserver v1.37's route instrumentation and
;;;; in-flight filter do: apiserver_request_total, apiserver_request_duration_seconds,
;;;; apiserver_request_sli_duration_seconds, apiserver_longrunning_requests and
;;;; apiserver_current_inflight_requests. Only requests that reach a resource handler
;;;; are counted, once each when the handler returns, so a watch counts at its end with
;;;; its whole duration, and is a long-running request meanwhile. Non-resource URLs,
;;;; unrouted paths and aggregated proxies are not counted, and a flow-control 429
;;;; counts with no latency. The in-flight watermark covers every request that isn't
;;;; long-running. Label sets are bounded, so unusual URLs cannot grow memory.

(in-package #:gr8s)

(defparameter +apiserver-request-duration-buckets+
  '(0.005d0 0.025d0 0.05d0 0.1d0 0.2d0 0.4d0 0.6d0 0.8d0 1 1.25d0 1.5d0 2 3 4 5 6 8 10 15 20 30 45 60)
  "Upper bounds of apiserver_request_duration_seconds, as upstream defines them.")

(defparameter +apiserver-request-sli-buckets+
  '(0.05d0 0.1d0 0.2d0 0.4d0 0.6d0 0.8d0 1 1.25d0 1.5d0 2 3 4 5 6 8 10 15 20 30 45 60)
  "Upper bounds of apiserver_request_sli_duration_seconds, as upstream defines them.")

(defparameter +apiserver-request-series-limit+ 4096
  "Label sets kept per metric; later ones are not recorded.")

(defstruct (apiserver-request-metrics (:constructor make-apiserver-request-metrics))
  "Request counts by labels and code, latency histograms by labels, open long-running requests by
labels, and the in-flight counts with their per-second watermarks by request kind."
  (counts (make-hash-table :test #'equal))
  (durations (make-hash-table :test #'equal))
  (sli (make-hash-table :test #'equal))
  (longrunning (make-hash-table :test #'equal))
  (inflight (list :read-only 0 :mutating 0))
  (watermark (list :read-only 0 :mutating 0))
  (published (list :read-only 0 :mutating 0))
  (second 0)
  (lock (bt:make-lock "gr8s apiserver request metrics")))

(defvar *apiserver-request-metrics* (make-apiserver-request-metrics)
  "This process's API request measurements.")

(defvar *apiserver-request-routed* nil
  "True while the current request is answered by a handler, false once it falls through unrouted.")

(defun apiserver-watch-request-p (path)
  "Report whether the current GET is a watch, by ?watch= or the legacy /watch/ path, as upstream decides."
  (let ((watch (hunchentoot:get-parameter "watch")))
    (or (and watch (not (member (string-downcase watch) '("0" "false") :test #'equal)))
        (and (search "/watch/" path) t))))

(defun remove-watch-segment (path)
  "Drop the legacy /watch/ segment, which names no resource."
  (cl-ppcre:regex-replace "^(/api/v1|/apis/[^/]+/[^/]+)/watch(/|$)" path "\\1\\2"))

(defun apiserver-request-labels (path method)
  "Return verb, dry_run, group, version, resource, subresource and scope for a resource request
at PATH, or NIL for anything else."
  (let* ((parts (remove "" (uiop:split-string path :separator '(#\/)) :test #'equal))
         (version (cond ((and (equal "api" (first parts)) (second parts)) (second parts))
                        ((and (equal "apis" (first parts)) (third parts)) (third parts)))))
    (multiple-value-bind (verb group resource name namespace)
        (kubernetes-authorization-target (remove-watch-segment path) method)
      (declare (ignore verb))
      (when (and version resource (plusp (length resource)))
        (let* ((slash (position #\/ resource))
               (base (subseq resource 0 slash))
               (subresource (if slash (subseq resource (1+ slash)) ""))
               (scope (cond ((or name (eq method :post)) "resource")
                            (namespace "namespace")
                            (t "cluster")))
               (dry-run (let ((values (loop for (key . value) in (hunchentoot:get-parameters*)
                                            when (equal key "dryRun") collect value)))
                          (format nil "~{~A~^,~}" (sort (remove-duplicates values :test #'equal) #'string<))))
               (reported
                 (cond
                   ((member subresource '("log" "exec" "portforward" "attach" "proxy") :test #'equal) "CONNECT")
                   ((member method '(:get :head))
                    (cond ((apiserver-watch-request-p path) "WATCH")
                          ((equal scope "resource") "GET")
                          (t "LIST")))
                   ((and (eq method :patch) (equal (request-media-type) "application/apply-patch+yaml")) "APPLY")
                   ((member method '(:post :put :patch :delete)) (string-upcase (symbol-name method)))
                   (t "other"))))
          (values reported dry-run group version base subresource scope))))))

(defun bounded-entry (table key make)
  "Return KEY's entry in TABLE, making it with MAKE unless the table is full."
  (or (gethash key table)
      (and (< (hash-table-count table) +apiserver-request-series-limit+)
           (setf (gethash key table) (funcall make)))))

(defun record-apiserver-request (labels code seconds &key (metrics *apiserver-request-metrics*))
  "Count one request with LABELS and status CODE, and its latency SECONDS unless NIL."
  (bt:with-lock-held ((apiserver-request-metrics-lock metrics))
    (let ((counts (apiserver-request-metrics-counts metrics))
          (count-key (append labels (list (princ-to-string code)))))
      (when (or (gethash count-key counts) (< (hash-table-count counts) +apiserver-request-series-limit+))
        (incf (gethash count-key counts 0))))
    (when seconds
      (let ((histogram (bounded-entry (apiserver-request-metrics-durations metrics) labels
                                      (lambda () (make-bucketed-histogram +apiserver-request-duration-buckets+)))))
        (when histogram (observe-histogram histogram seconds)))
      ;; The SLI histogram leaves out dry runs and the dry_run label.
      (when (equal "" (second labels))
        (let ((histogram (bounded-entry (apiserver-request-metrics-sli metrics) (cons (first labels) (cddr labels))
                                        (lambda () (make-bucketed-histogram +apiserver-request-sli-buckets+)))))
          (when histogram (observe-histogram histogram seconds)))))))

(defun note-inflight-change (kind delta &key (metrics *apiserver-request-metrics*) (now (get-universal-time)))
  "Change KIND's in-flight count by DELTA, keeping this second's watermark; call with the lock held."
  (unless (= now (apiserver-request-metrics-second metrics))
    (setf (apiserver-request-metrics-published metrics) (copy-list (apiserver-request-metrics-watermark metrics))
          (apiserver-request-metrics-watermark metrics) (copy-list (apiserver-request-metrics-inflight metrics))
          (apiserver-request-metrics-second metrics) now))
  (let ((current (incf (getf (apiserver-request-metrics-inflight metrics) kind) delta)))
    (setf (getf (apiserver-request-metrics-watermark metrics) kind)
          (max current (getf (apiserver-request-metrics-watermark metrics) kind)))))

(defun call-recording-apiserver-request (path method function)
  "Call FUNCTION to answer the current request and record it if a resource handler answered."
  (let* ((labels (ignore-errors (multiple-value-list (apiserver-request-labels path method))))
         (long-running (member (first labels) '("WATCH" "CONNECT") :test #'equal))
         (kind (if (member method '(:post :put :patch :delete)) :mutating :read-only))
         (long-key (and long-running (cons (first labels) (cddr labels))))
         (metrics *apiserver-request-metrics*)
         (started (get-internal-real-time))
         (*apiserver-request-routed* t))
    (bt:with-lock-held ((apiserver-request-metrics-lock metrics))
      (if long-running
          (let ((table (apiserver-request-metrics-longrunning metrics)))
            (when (or (gethash long-key table) (< (hash-table-count table) +apiserver-request-series-limit+))
              (incf (gethash long-key table 0))))
          (note-inflight-change kind 1)))
    (unwind-protect (funcall function)
      (bt:with-lock-held ((apiserver-request-metrics-lock metrics))
        (if long-running
            (let ((table (apiserver-request-metrics-longrunning metrics)))
              (when (gethash long-key table) (decf (gethash long-key table))))
            (note-inflight-change kind -1)))
      (when (and (first labels) *apiserver-request-routed*)
        (let ((code (hunchentoot:return-code*)))
          (ignore-errors
           (record-apiserver-request
            labels code
            (unless (eql code 429)
              (/ (- (get-internal-real-time) started) internal-time-units-per-second)))))))))

(defun apiserver-label-text (labels &optional dry-run-p)
  "Render a label set: verb, then dry_run when DRY-RUN-P, group, version, resource, subresource and scope."
  (destructuring-bind (verb &rest rest) labels
    (let ((rest (if dry-run-p rest (cons nil rest))))
      (destructuring-bind (dry-run group version resource subresource scope) rest
        (sorted-labels (append (list (cons "component" "apiserver") (cons "group" group) (cons "resource" resource)
                                     (cons "scope" scope) (cons "subresource" subresource) (cons "verb" verb)
                                     (cons "version" version))
                               (and dry-run-p (list (cons "dry_run" dry-run)))))))))

(defun apiserver-request-metrics-text (&optional (metrics *apiserver-request-metrics*))
  "Render the request families in Prometheus text, families in name order."
  (bt:with-lock-held ((apiserver-request-metrics-lock metrics))
    (note-inflight-change :read-only 0 :metrics metrics)
    (with-output-to-string (out)
      (write-prometheus-family
       out "apiserver_current_inflight_requests"
       "[STABLE] Maximal number of currently used inflight request limit of this apiserver per request kind in last second."
       "gauge" (list (list (list (cons "request_kind" "mutating")) (getf (apiserver-request-metrics-published metrics) :mutating))
                     (list (list (cons "request_kind" "readOnly")) (getf (apiserver-request-metrics-published metrics) :read-only))))
      (write-prometheus-family
       out "apiserver_longrunning_requests"
       "[STABLE] Gauge of all active long-running apiserver requests broken out by verb, group, version, resource, scope and component. Not all requests are tracked this way."
       "gauge" (loop for key being the hash-keys of (apiserver-request-metrics-longrunning metrics) using (hash-value count)
                     collect (list (apiserver-label-text key) count)))
      (write-prometheus-histograms
       out "apiserver_request_duration_seconds"
       "[STABLE] Response latency distribution in seconds for each verb, dry run value, group, version, resource, subresource, scope and component."
       (loop for key being the hash-keys of (apiserver-request-metrics-durations metrics) using (hash-value histogram)
             collect (cons (apiserver-label-text key t) histogram)))
      (write-prometheus-histograms
       out "apiserver_request_sli_duration_seconds"
       "[ALPHA] Response latency distribution (not counting webhook duration and priority & fairness queue wait times) in seconds for each verb, group, version, resource, subresource, scope and component."
       (loop for key being the hash-keys of (apiserver-request-metrics-sli metrics) using (hash-value histogram)
             collect (cons (apiserver-label-text key) histogram)))
      (write-prometheus-family
       out "apiserver_request_total"
       "[STABLE] Counter of apiserver requests broken out for each verb, dry run value, group, version, resource, scope, component, and HTTP response code."
       "counter" (loop for key being the hash-keys of (apiserver-request-metrics-counts metrics) using (hash-value count)
                       collect (list (sorted-labels (cons (cons "code" (car (last key))) (apiserver-label-text (butlast key) t)))
                                     count))))))
