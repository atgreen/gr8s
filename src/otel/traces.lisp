;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Traces (podster-krg.1). A span joins the trace its request's W3C traceparent names,
;;;; or starts one, sampled as OTEL_TRACES_SAMPLER says (parent-based, always on, by
;;;; default). A finished, sampled span waits in a bounded queue that one thread sends
;;;; in batches over OTLP/HTTP, JSON-encoded, to OTEL_EXPORTER_OTLP_TRACES_ENDPOINT, or
;;;; OTEL_EXPORTER_OTLP_ENDPOINT's /v1/traces. Tracing is off unless one of those is set.
;;;; Telemetry never holds up the work it describes: a full queue drops spans, a failed
;;;; send drops its batch, and both are counted.

(in-package #:gr8s.otel)

;;; ---------------------------------------------------------------------------
;;; Configuration, from OTel's environment variables

(defstruct (otel-configuration (:conc-name otel-))
  endpoint                      ; the traces URL, or NIL: tracing is off
  (headers '())                 ; ((name . value) ...) sent with each export
  (sampler "parentbased_always_on")
  (ratio 1d0)                   ; for the traceidratio samplers
  (resource '()))               ; ((key . value) ...)

(defun otel-environment (name)
  (let ((value (uiop:getenv name)))
    (and value (plusp (length (string-trim " " value))) (string-trim " " value))))

(defun otel-percent-decode (text)
  "TEXT with %XX escapes decoded, as OTEL_EXPORTER_OTLP_HEADERS values are written."
  (with-output-to-string (out)
    (loop with i = 0 while (< i (length text))
          do (let ((char (char text i)))
               (if (and (char= char #\%) (<= (+ i 3) (length text))
                        (digit-char-p (char text (+ i 1)) 16) (digit-char-p (char text (+ i 2)) 16))
                   (progn (write-char (code-char (parse-integer text :start (1+ i) :end (+ i 3) :radix 16)) out)
                          (incf i 3))
                   (progn (write-char char out) (incf i)))))))

(defun otel-key-values (text)
  "The key=value pairs of a comma-separated TEXT, as OTel's list variables are written."
  (loop for item in (uiop:split-string (or text "") :separator ",")
        for equals = (position #\= item)
        when (and equals (plusp equals))
          collect (cons (string-trim " " (subseq item 0 equals))
                        (otel-percent-decode (string-trim " " (subseq item (1+ equals)))))))

(defun otel-traces-endpoint ()
  "The URL spans are sent to: the traces endpoint as given, else the general endpoint's
/v1/traces; NIL when neither is set or the SDK is disabled."
  (unless (equalp "true" (otel-environment "OTEL_SDK_DISABLED"))
    (or (otel-environment "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")
        (let ((base (otel-environment "OTEL_EXPORTER_OTLP_ENDPOINT")))
          (and base (concatenate 'string (string-right-trim "/" base) "/v1/traces"))))))

(defun read-otel-configuration ()
  (let ((resource (otel-key-values (otel-environment "OTEL_RESOURCE_ATTRIBUTES"))))
    (flet ((default (key value) (unless (assoc key resource :test #'equal) (push (cons key value) resource))))
      (default "service.name" (or (otel-environment "OTEL_SERVICE_NAME") "gr8s-gateway"))
      (default "service.version" (gr8s.foundation::kubernetes-git-version))
      (default "host.name" (or (ignore-errors (machine-instance)) "unknown")))
    (make-otel-configuration
     :endpoint (otel-traces-endpoint)
     :headers (otel-key-values (or (otel-environment "OTEL_EXPORTER_OTLP_TRACES_HEADERS")
                                   (otel-environment "OTEL_EXPORTER_OTLP_HEADERS")))
     :sampler (string-downcase (or (otel-environment "OTEL_TRACES_SAMPLER") "parentbased_always_on"))
     :ratio (let ((ratio (ignore-errors (with-standard-io-syntax
                                          (let ((*read-eval* nil) (*read-default-float-format* 'double-float))
                                            (read-from-string (otel-environment "OTEL_TRACES_SAMPLER_ARG")))))))
              (if (realp ratio) (max 0d0 (min 1d0 (float ratio 1d0))) 1d0))
     :resource (reverse resource))))

(defvar *otel-configuration* nil "The configuration, read from the environment when first needed.")

(defun otel-configuration ()
  (or *otel-configuration* (setf *otel-configuration* (read-otel-configuration))))

(defun tracing-enabled-p ()
  "True when spans have somewhere to go."
  (and (otel-endpoint (otel-configuration)) t))

;;; ---------------------------------------------------------------------------
;;; W3C trace context

(defun otel-hex-p (text start end)
  (loop for i from start below end always (find (char text i) "0123456789abcdef")))

(defun otel-zero-p (text) (every (lambda (char) (char= char #\0)) text))

(defun parse-traceparent (header)
  "(values trace-id parent-span-id sampled-p) from a W3C traceparent HEADER, or NIL when
it is absent or malformed. A later version is read by its version-00 prefix."
  (when (and (stringp header) (>= (length header) 55))
    (let ((text (string-trim " " header)))
      (when (and (>= (length text) 55)
                 (otel-hex-p text 0 2) (not (string= (subseq text 0 2) "ff"))
                 (char= (char text 2) #\-) (otel-hex-p text 3 35)
                 (char= (char text 35) #\-) (otel-hex-p text 36 52)
                 (char= (char text 52) #\-) (otel-hex-p text 53 55)
                 (or (= (length text) 55)
                     (and (not (string= (subseq text 0 2) "00")) (char= (char text 55) #\-))))
        (let ((trace-id (subseq text 3 35)) (parent (subseq text 36 52)))
          (unless (or (otel-zero-p trace-id) (otel-zero-p parent))
            (values trace-id parent (logbitp 0 (parse-integer text :start 53 :end 55 :radix 16)))))))))

(defun otel-random-id (bytes)
  "A random id of BYTES bytes, as lowercase hex, never all zeros."
  (loop for id = (ironclad:byte-array-to-hex-string (ironclad:random-data bytes))
        unless (otel-zero-p id) return id))

(defun otel-sample-p (configuration trace-id parent-sampled)
  "Whether a span of TRACE-ID is recorded. PARENT-SAMPLED is :none for a new trace, else
whether the caller recorded its span."
  (let ((sampler (otel-sampler configuration)))
    (flet ((ratio-p () (< (parse-integer trace-id :start 16 :radix 16)
                          (* (otel-ratio configuration) (expt 2 64)))))
      (cond ((and (uiop:string-prefix-p "parentbased_" sampler) (not (eq parent-sampled :none)))
             parent-sampled)
            ((member sampler '("always_off" "parentbased_always_off") :test #'equal) nil)
            ((member sampler '("traceidratio" "parentbased_traceidratio") :test #'equal) (ratio-p))
            (t t)))))

;;; ---------------------------------------------------------------------------
;;; Spans

(defstruct (span (:constructor %make-span))
  trace-id span-id parent-span-id tracestate sampled-p name (kind 2)
  start-ns end-ns (attributes '()) (status-code 0) status-message)

(defun otel-now-ns ()
  (multiple-value-bind (seconds microseconds) (sb-ext:get-time-of-day)
    (+ (* seconds 1000000000) (* microseconds 1000))))

(defun start-server-span (name &key traceparent tracestate attributes)
  "A SERVER span named NAME for a request that carried TRACEPARENT and TRACESTATE (its
headers' values, or NIL), joining that trace or starting one; NIL when tracing is off."
  (let ((configuration (otel-configuration)))
    (when (otel-endpoint configuration)
      (multiple-value-bind (trace-id parent sampled) (parse-traceparent traceparent)
        (let ((trace-id (or trace-id (otel-random-id 16))))
          (%make-span :trace-id trace-id :span-id (otel-random-id 8) :parent-span-id parent
                      :tracestate (and parent (stringp tracestate) (plusp (length tracestate)) tracestate)
                      :sampled-p (otel-sample-p configuration trace-id (if parent sampled :none))
                      :name name :start-ns (otel-now-ns) :attributes (copy-alist attributes)))))))

(defun span-traceparent (span)
  "The traceparent to send downstream: SPAN's trace, with SPAN as the parent."
  (format nil "00-~A-~A-~:[00~;01~]" (span-trace-id span) (span-span-id span) (span-sampled-p span)))

(defun span-set-attribute (span key value)
  "Set SPAN's attribute KEY to VALUE (a string, integer or boolean); NIL VALUE leaves it unset."
  (when (and span value)
    (let ((cell (assoc key (span-attributes span) :test #'equal)))
      (if cell (setf (cdr cell) value) (push (cons key value) (span-attributes span))))))

(defun end-span (span &key error message)
  "Finish SPAN, an error when ERROR, and queue it for export when it was sampled."
  (when span
    (setf (span-end-ns span) (otel-now-ns))
    (when error (setf (span-status-code span) 2 (span-status-message span) message))
    (when (span-sampled-p span) (enqueue-span span))
    span))

;;; ---------------------------------------------------------------------------
;;; OTLP/HTTP export, JSON-encoded

(defparameter +otel-queue-limit+ 2048 "The most finished spans waiting to be sent.")
(defparameter +otel-batch-size+ 512 "The most spans in one export request.")
(defparameter +otel-flush-seconds+ 2 "How long a span waits for others to batch with.")
(defparameter +otel-export-seconds+ 5 "How long one export request may take.")

(defvar *otel-lock* (bt:make-lock "gr8s otel"))
(defvar *otel-ready* (bt:make-condition-variable :name "gr8s otel spans"))
(defvar *otel-queue* '() "Finished spans, newest first.")
(defvar *otel-queued* 0)
(defvar *otel-exporter* nil "The thread that sends spans, started with the first one.")
(defvar *otel-counts* (list :exported 0 :dropped 0 :failed 0)
  "Spans sent, dropped from a full queue, and lost with a failed export.")

(defun otel-count (key &optional (by 1))
  (incf (getf *otel-counts* key) by))

(defun enqueue-span (span)
  (bt:with-lock-held (*otel-lock*)
    (if (>= *otel-queued* +otel-queue-limit+)
        (otel-count :dropped)
        (progn (push span *otel-queue*) (incf *otel-queued*)
               (unless (and *otel-exporter* (bt:thread-alive-p *otel-exporter*))
                 (setf *otel-exporter* (bt:make-thread #'otel-export-loop :name "gr8s otel exporter")))
               (when (>= *otel-queued* +otel-batch-size+) (bt:condition-notify *otel-ready*))))))

(defun take-span-batch ()
  "Wait up to +OTEL-FLUSH-SECONDS+ for a full batch; take the oldest spans, at most a batch."
  (bt:with-lock-held (*otel-lock*)
    (when (< *otel-queued* +otel-batch-size+)
      (bt:condition-wait *otel-ready* *otel-lock* :timeout +otel-flush-seconds+))
    (let* ((oldest (reverse *otel-queue*))
           (batch (subseq oldest 0 (min +otel-batch-size+ (length oldest)))))
      (setf *otel-queue* (reverse (nthcdr (length batch) oldest))
            *otel-queued* (length *otel-queue*))
      batch)))

(defun otel-attribute (key value)
  (gr8s.resources::core-object
   "key" key
   "value" (etypecase value
             (string (gr8s.resources::core-object "stringValue" value))
             (integer (gr8s.resources::core-object "intValue" (princ-to-string value)))
             ((member t) (gr8s.resources::core-object "boolValue" t))
             (real (gr8s.resources::core-object "doubleValue" (float value 1d0))))))

(defun otel-attributes (alist)
  (coerce (loop for (key . value) in alist collect (otel-attribute key value)) 'vector))

(defun span-object (span)
  (let ((object (gr8s.resources::core-object
                 "traceId" (span-trace-id span) "spanId" (span-span-id span)
                 "name" (span-name span) "kind" (span-kind span) "flags" 1
                 "startTimeUnixNano" (princ-to-string (span-start-ns span))
                 "endTimeUnixNano" (princ-to-string (span-end-ns span))
                 "attributes" (otel-attributes (reverse (span-attributes span)))
                 "status" (if (span-status-message span)
                              (gr8s.resources::core-object "code" (span-status-code span)
                                                          "message" (span-status-message span))
                              (gr8s.resources::core-object "code" (span-status-code span))))))
    (when (span-parent-span-id span) (setf (gethash "parentSpanId" object) (span-parent-span-id span)))
    (when (span-tracestate span) (setf (gethash "traceState" object) (span-tracestate span)))
    object))

(defun spans-request-object (configuration spans)
  "The ExportTraceServiceRequest, as OTLP's JSON encoding writes it, for SPANS."
  (gr8s.resources::core-object
   "resourceSpans"
   (vector (gr8s.resources::core-object
            "resource" (gr8s.resources::core-object "attributes" (otel-attributes (otel-resource configuration)))
            "scopeSpans" (vector (gr8s.resources::core-object
                                  "scope" (gr8s.resources::core-object
                                           "name" "gr8s" "version" (gr8s.foundation::kubernetes-git-version))
                                  "spans" (map 'vector #'span-object spans)))))))

(defun export-spans (configuration spans)
  "Send SPANS to the configured endpoint; true when the collector took them."
  (multiple-value-bind (body status)
      (drakma:http-request (otel-endpoint configuration)
                           :method :post :content-type "application/json"
                           :content (gr8s.resources::stringify-to-utf-8-bytes
                                     (spans-request-object configuration spans))
                           :additional-headers (otel-headers configuration)
                           :connection-timeout +otel-export-seconds+ :want-stream nil
                           :force-binary t :redirect nil :user-agent "gr8s-otel")
    (declare (ignore body))
    (and (integerp status) (<= 200 status 299))))

(defun otel-export-loop ()
  (loop
    (let ((batch (take-span-batch)))
      (when batch
        (let ((sent (ignore-errors
                     (handler-case
                         (sb-ext:with-timeout (* 2 +otel-export-seconds+)
                           (export-spans (otel-configuration) batch))
                       (sb-ext:timeout () nil)))))
          (bt:with-lock-held (*otel-lock*)
            (otel-count (if sent :exported :failed) (length batch))))))))

(defun otel-metrics-text ()
  "Prometheus text for the span exporter's counters."
  (bt:with-lock-held (*otel-lock*)
    (format nil "# HELP gr8s_otel_spans_total Spans the OTLP exporter sent, dropped from a full queue, or lost to a failed export.~%# TYPE gr8s_otel_spans_total counter~%~{gr8s_otel_spans_total{result=\"~(~A~)\"} ~D~%~}"
            *otel-counts*)))
