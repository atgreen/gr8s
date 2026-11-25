;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; OpenTelemetry for gr8s (podster-krg): W3C trace context, spans, and their export
;;;; over OTLP/HTTP, configured by OTel's standard environment variables.

(defpackage #:gr8s.otel
  (:use #:cl)
  (:export
   #:tracing-enabled-p
   #:start-server-span
   #:span-trace-id
   #:span-sampled-p
   #:span-traceparent
   #:span-tracestate
   #:span-set-attribute
   #:end-span
   #:emit-flow-log
   #:logs-enabled-p
   #:otel-metrics-text))
