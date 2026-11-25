;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Flow events as OpenTelemetry log records (podster-krg.2). Each event a node's agent
;;;; collects -- a Pod's new connection, a drop and why, a Gateway's request -- becomes one
;;;; log record with OTel's network attributes, sent over OTLP/HTTP to the logs endpoint.
;;;; A Gateway request's record carries the trace it was recorded in, so a logs backend can
;;;; jump to the trace. Off unless OTEL_LOGS_EXPORTER=otlp.

(in-package #:gr8s.otel)

(defvar *log-queue* (make-otel-queue "logs" (lambda (records) (export-log-records (otel-configuration) records)))
  "Flow log records on their way to the collector.")

(defun logs-enabled-p ()
  "True when flow events are exported as log records."
  (and (otel-logs-endpoint (otel-configuration)) t))

(defun flow-time-ns (text)
  "Unix nanoseconds of an RFC 3339 TEXT such as 2026-11-25T19:51:59.070606Z, or now."
  (or (ignore-errors
       (let* ((dot (position #\. text))
              (seconds (- (gr8s.kube-client::parse-rfc3339 text) 2208988800))
              (fraction (if dot
                            (let ((digits (string-right-trim "Z" (subseq text (1+ dot)))))
                              (round (* (parse-integer digits) (expt 10 (- 9 (length digits))))))
                            0)))
         (+ (* seconds 1000000000) fraction)))
      (otel-now-ns)))

(defun flow-log-record (flow)
  "The OTLP LogRecord for FLOW, a flow event object: its attributes in OTel's network
terms, a one-line body, and the trace a Gateway request was recorded in."
  (let* ((egress (equal "egress" (gethash "direction" flow)))
         (dropped (equal "DROPPED" (gethash "verdict" flow)))
         (l7 (gethash "l7" flow))
         (pod (and (gethash "pod" flow) (format nil "~@[~A/~]~A" (gethash "namespace" flow) (gethash "pod" flow))))
         (peer (or (gethash "peerName" flow) (gethash "peerAddress" flow)))
         (attributes '()))
    (flet ((put (key value) (when (and value (not (eq value 'null)) (not (equal value "")))
                              (push (cons key value) attributes))))
      (put "gr8s.flow.verdict" (gethash "verdict" flow))
      (put "gr8s.flow.reason" (gethash "reason" flow))
      (put "gr8s.flow.direction" (gethash "direction" flow))
      (put "k8s.node.name" (gethash "node" flow))
      (put "k8s.namespace.name" (gethash "namespace" flow))
      (put "k8s.pod.name" (gethash "pod" flow))
      (put "network.transport" (let ((protocol (gethash "protocol" flow)))
                                 (and (stringp protocol) (string-downcase protocol))))
      ;; The Pod is the source of what it sends and the destination of what it receives.
      (put (if egress "source.address" "destination.address") (gethash "podAddress" flow))
      (put (if egress "source.port" "destination.port") (gethash "podPort" flow))
      (put (if egress "destination.address" "source.address") (gethash "peerAddress" flow))
      (put (if egress "destination.port" "source.port") (gethash "peerPort" flow))
      (put "gr8s.flow.peer.name" (gethash "peerName" flow))
      (put "gr8s.flow.peer.pod" (and (gethash "peerPod" flow)
                                     (format nil "~@[~A/~]~A" (gethash "peerNamespace" flow) (gethash "peerPod" flow))))
      (let ((policies (gethash "policies" flow)))
        (when (and (vectorp policies) (plusp (length policies)))
          (put "gr8s.flow.policies" (format nil "~{~A~^,~}" (coerce policies 'list)))))
      (when (hash-table-p l7)
        (put "http.request.method" (gethash "method" l7))
        (put "url.path" (gethash "path" l7))
        (put "server.address" (gethash "host" l7))
        (put "http.response.status_code" (gethash "code" l7))
        (put "http.route" (gethash "route" l7))
        (put "gr8s.gateway.latency_ms" (let ((ns (gethash "latencyNs" l7))) (and (integerp ns) (round ns 1000000))))))
    (let ((record (gr8s.resources::core-object
                   "timeUnixNano" (princ-to-string (flow-time-ns (gethash "time" flow "")))
                   "observedTimeUnixNano" (princ-to-string (otel-now-ns))
                   ;; WARN for a drop, INFO otherwise (OTel severity numbers 13 and 9).
                   "severityNumber" (if dropped 13 9)
                   "severityText" (if dropped "WARN" "INFO")
                   "body" (gr8s.resources::core-object
                           "stringValue"
                           (if (hash-table-p l7)
                               (format nil "~A ~A~A -> ~A ~A ~@[(~Ams)~]"
                                       (gethash "method" l7 "") (gethash "host" l7 "") (gethash "path" l7 "")
                                       (gethash "code" l7 "") (or pod "")
                                       (let ((ns (gethash "latencyNs" l7))) (and (integerp ns) (round ns 1000000))))
                               (format nil "~A ~A ~:[<-~;->~] ~A~@[:~A~] ~A~@[ (~A)~]"
                                       (gethash "verdict" flow "") (or pod "?") egress (or peer "?")
                                       (if egress (gethash "peerPort" flow) (gethash "podPort" flow))
                                       (gethash "protocol" flow "") (and dropped (gethash "reason" flow)))))
                   "attributes" (otel-attributes (nreverse attributes)))))
      (let ((trace (and (hash-table-p l7) (gethash "traceId" l7))))
        (when (and (stringp trace) (= 32 (length trace)))
          (setf (gethash "traceId" record) trace)))
      record)))

(defun emit-flow-log (flow)
  "Queue FLOW, a flow event object, as a log record, when flow logs are on."
  (when (logs-enabled-p)
    (otel-enqueue *log-queue* (flow-log-record flow))))

(defun logs-request-object (configuration records)
  "The ExportLogsServiceRequest, as OTLP's JSON encoding writes it, for RECORDS."
  (gr8s.resources::core-object
   "resourceLogs"
   (vector (gr8s.resources::core-object
            "resource" (gr8s.resources::core-object
                        "attributes" (otel-attributes
                                      ;; Flow logs are the node's, not the Gateway's, service.
                                      (cons (cons "service.name" "gr8s-flows")
                                            (remove "service.name" (otel-resource configuration)
                                                    :key #'car :test #'equal))))
            "scopeLogs" (vector (gr8s.resources::core-object
                                 "scope" (gr8s.resources::core-object
                                          "name" "gr8s.flows" "version" (gr8s.foundation::kubernetes-git-version))
                                 "logRecords" (coerce records 'vector)))))))

(defun export-log-records (configuration records)
  "Send RECORDS to the configured logs endpoint; true when the collector took them."
  (otel-post (otel-logs-endpoint configuration) (otel-logs-headers configuration)
             (logs-request-object configuration records)))

(defun otel-metrics-text ()
  "Prometheus text for the OTLP exporters' counters."
  (with-output-to-string (out)
    (loop for (queue metric help) in `((,*span-queue* "gr8s_otel_spans_total" "Spans")
                                       (,*log-queue* "gr8s_otel_log_records_total" "Flow log records"))
          do (bt:with-lock-held ((otel-queue-lock queue))
               (format out "# HELP ~A ~A the OTLP exporter sent, dropped from a full queue, or lost to a failed export.~%# TYPE ~A counter~%~{~A{result=\"~(~A~)\"} ~D~%~}"
                       metric help metric
                       (loop for (key count) on (otel-queue-counts queue) by #'cddr
                             append (list metric key count)))))))
