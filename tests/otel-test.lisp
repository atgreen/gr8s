;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Prove OpenTelemetry tracing (podster-krg.1): W3C traceparent parsing and sampling,
;;;; configuration from OTel's environment variables, the OTLP/HTTP JSON a collector is
;;;; sent, and a Gateway that joins a client's trace, hands the backend its own span as
;;;; the parent, and exports that span -- or, with tracing off, passes the client's
;;;; trace context through untouched.

(in-package #:gr8s/tests)
(def-suite otel :in gr8s)
(in-suite otel)

(defparameter +otel-test-traceparent+ "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
(defparameter +otel-test-gateway-traceparent+ "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01")

(test otel-reads-w3c-traceparents
  (multiple-value-bind (trace parent sampled) (gr8s.otel::parse-traceparent +otel-test-traceparent+)
    (is (equal "4bf92f3577b34da6a3ce929d0e0e4736" trace))
    (is (equal "00f067aa0ba902b7" parent))
    (is (eq t sampled)))
  (is (null (nth-value 2 (gr8s.otel::parse-traceparent "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00"))))
  ;; A later version is read by its version-00 prefix, and may carry more after a dash.
  (is (equal "4bf92f3577b34da6a3ce929d0e0e4736"
             (gr8s.otel::parse-traceparent "01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-extra")))
  (dolist (bad (list nil "" "garbage"
                     "ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"   ; version ff is invalid
                     "00-00000000000000000000000000000000-00f067aa0ba902b7-01"   ; zero trace id
                     "00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01"   ; zero parent
                     "00-4BF92F3577B34DA6A3CE929D0E0E4736-00f067aa0ba902b7-01"   ; uppercase
                     "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-x")) ; v00 has no more
    (is (null (gr8s.otel::parse-traceparent bad)) "~S is refused" bad)))

(test otel-samples-as-configured
  (flet ((sample (sampler ratio trace parent)
           (gr8s.otel::otel-sample-p (gr8s.otel::make-otel-configuration :sampler sampler :ratio ratio) trace parent)))
    (let ((low "00000000000000000000000000000001") (high "0000000000000000ffffffffffffffff"))
      (is (eq t (sample "parentbased_always_on" 1d0 low :none)))
      (is (null (sample "parentbased_always_on" 1d0 low nil)) "a caller's decision not to record is kept")
      (is (eq t (sample "parentbased_always_off" 0d0 low t)) "and so is a decision to record")
      (is (null (sample "parentbased_always_off" 0d0 low :none)))
      (is (eq t (sample "traceidratio" 0.5d0 low :none)))
      (is (null (sample "traceidratio" 0.5d0 high :none)))
      (is (null (sample "always_off" 1d0 low t)) "a non-parent-based sampler ignores the caller"))))

(defmacro with-otel-environment ((&rest pairs) &body body)
  "Run BODY with the environment variables of PAIRS set (others of OTel's unset)."
  `(let ((saved (mapcar (lambda (name) (cons name (uiop:getenv name)))
                        '("OTEL_EXPORTER_OTLP_ENDPOINT" "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT" "OTEL_EXPORTER_OTLP_HEADERS"
                          "OTEL_EXPORTER_OTLP_TRACES_HEADERS" "OTEL_TRACES_SAMPLER" "OTEL_TRACES_SAMPLER_ARG"
                          "OTEL_SERVICE_NAME" "OTEL_RESOURCE_ATTRIBUTES" "OTEL_SDK_DISABLED"))))
     (unwind-protect
          (progn (dolist (entry saved) (sb-posix:unsetenv (car entry)))
                 (loop for (name value) on (list ,@pairs) by #'cddr do (sb-posix:setenv name value 1))
                 ,@body)
       (dolist (entry saved)
         (if (cdr entry) (sb-posix:setenv (car entry) (cdr entry) 1) (sb-posix:unsetenv (car entry)))))))

(test otel-reads-its-configuration-from-the-environment
  (with-otel-environment ()
    (is (null (gr8s.otel::otel-endpoint (gr8s.otel::read-otel-configuration))) "off unless an endpoint is set"))
  (with-otel-environment ("OTEL_EXPORTER_OTLP_ENDPOINT" "http://collector:4318/"
                          "OTEL_EXPORTER_OTLP_HEADERS" "x-api-key=a%20b, tenant=lab"
                          "OTEL_TRACES_SAMPLER" "ParentBased_TraceIdRatio" "OTEL_TRACES_SAMPLER_ARG" "0.25"
                          "OTEL_RESOURCE_ATTRIBUTES" "deployment.environment=lab,service.name=edge")
    (let ((configuration (gr8s.otel::read-otel-configuration)))
      (is (equal "http://collector:4318/v1/traces" (gr8s.otel::otel-endpoint configuration)))
      (is (equal '(("x-api-key" . "a b") ("tenant" . "lab")) (gr8s.otel::otel-headers configuration)))
      (is (equal "parentbased_traceidratio" (gr8s.otel::otel-sampler configuration)))
      (is (= 0.25d0 (gr8s.otel::otel-ratio configuration)))
      (is (equal "edge" (cdr (assoc "service.name" (gr8s.otel::otel-resource configuration) :test #'equal)))
          "a resource attribute given wins over the default")
      (is (equal "lab" (cdr (assoc "deployment.environment" (gr8s.otel::otel-resource configuration) :test #'equal))))))
  (with-otel-environment ("OTEL_EXPORTER_OTLP_ENDPOINT" "http://collector:4318"
                          "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT" "http://traces:9999/in")
    (is (equal "http://traces:9999/in" (gr8s.otel::otel-endpoint (gr8s.otel::read-otel-configuration)))))
  (with-otel-environment ("OTEL_EXPORTER_OTLP_ENDPOINT" "http://collector:4318" "OTEL_SDK_DISABLED" "true")
    (is (null (gr8s.otel::otel-endpoint (gr8s.otel::read-otel-configuration))))))

;;; A collector that keeps what it is sent

(defvar *otel-test-received* '() "Parsed OTLP requests the test collector took, newest first.")
(defvar *otel-test-received-lock* (bt:make-lock))

(defclass otel-test-collector (hunchentoot:acceptor) ())

(defmethod hunchentoot:acceptor-dispatch-request ((acceptor otel-test-collector) request)
  (let ((body (hunchentoot:raw-post-data :force-binary t)))
    (bt:with-lock-held (*otel-test-received-lock*)
      (push (list (hunchentoot:script-name request) (hunchentoot:header-in* :content-type request)
                  (hunchentoot:header-in* :x-api-key request) (com.inuoe.jzon:parse body))
            *otel-test-received*))
    (setf (hunchentoot:content-type*) "application/json")
    "{}"))

(defun otel-test-spans ()
  "Every span the test collector has been sent."
  (bt:with-lock-held (*otel-test-received-lock*)
    (loop for (nil nil nil request) in *otel-test-received*
          append (loop for resource across (gethash "resourceSpans" request)
                       append (loop for scope across (gethash "scopeSpans" resource)
                                    append (coerce (gethash "spans" scope) 'list))))))

(defun otel-test-attribute (span key)
  (let ((attribute (find key (gethash "attributes" span) :key (lambda (a) (gethash "key" a)) :test #'equal)))
    (and attribute (let ((value (gethash "value" attribute)))
                     (or (gethash "stringValue" value) (gethash "intValue" value))))))

(defmacro with-otel-collector ((endpoint &key headers) &body body)
  "Run BODY with tracing on, sending spans to a test collector whose URL binds ENDPOINT."
  `(let* ((collector (hunchentoot:start (make-instance 'otel-test-collector :address "127.0.0.1" :port 0)))
          (,endpoint (format nil "http://127.0.0.1:~D/v1/traces" (hunchentoot:acceptor-port collector)))
          (previous gr8s.otel::*otel-configuration*))
     (declare (ignorable ,endpoint))
     ;; Spans an earlier test queued are not this collector's.
     (bt:with-lock-held (gr8s.otel::*otel-lock*)
       (setf gr8s.otel::*otel-queue* '() gr8s.otel::*otel-queued* 0))
     (setf *otel-test-received* '()
           gr8s.otel::*otel-configuration*
           (gr8s.otel::make-otel-configuration :endpoint ,endpoint :headers ,headers
                                               :resource '(("service.name" . "gr8s-gateway"))))
     (unwind-protect (progn ,@body)
       (setf gr8s.otel::*otel-configuration* previous)
       (hunchentoot:stop collector))))

(defun otel-test-wait-for-spans (count)
  "The collector's spans once it has COUNT of them, waiting up to ten seconds."
  (loop repeat 100
        for spans = (otel-test-spans)
        until (>= (length spans) count)
        do (sleep 0.1)
        finally (return spans)))

(test otel-sends-spans-as-otlp-json
  (with-otel-collector (endpoint :headers '(("x-api-key" . "secret")))
    (let ((span (gr8s.otel:start-server-span "GET shop/web" :traceparent +otel-test-traceparent+ :tracestate "vendor=1"
                                                            :attributes '(("http.request.method" . "GET")))))
      (gr8s.otel:span-set-attribute span "http.response.status_code" 503)
      ;; Finished by hand: END-SPAN would also queue it for the exporter thread.
      (setf (gr8s.otel::span-end-ns span) (1+ (gr8s.otel::otel-now-ns))
            (gr8s.otel::span-status-code span) 2 (gr8s.otel::span-status-message span) "HTTP 503")
      (is (gr8s.otel::export-spans (gr8s.otel::otel-configuration) (list span)))
      (destructuring-bind (path content-type key request) (first *otel-test-received*)
        (is (equal "/v1/traces" path))
        (is (equal "application/json" content-type))
        (is (equal "secret" key) "OTEL_EXPORTER_OTLP_HEADERS go with each export")
        (let* ((resource (aref (gethash "resourceSpans" request) 0))
               (sent (aref (gethash "spans" (aref (gethash "scopeSpans" resource) 0)) 0)))
          (is (equal "gr8s-gateway" (gethash "stringValue" (gethash "value" (aref (gethash "attributes" (gethash "resource" resource)) 0)))))
          (is (equal "4bf92f3577b34da6a3ce929d0e0e4736" (gethash "traceId" sent)) "ids are hex, as OTLP's JSON writes them")
          (is (equal "00f067aa0ba902b7" (gethash "parentSpanId" sent)))
          (is (equal "vendor=1" (gethash "traceState" sent)))
          (is (= 16 (length (gethash "spanId" sent))))
          (is (= 2 (gethash "kind" sent)) "a SERVER span")
          (is (stringp (gethash "startTimeUnixNano" sent)) "64-bit times are strings")
          (is (< (parse-integer (gethash "startTimeUnixNano" sent)) (parse-integer (gethash "endTimeUnixNano" sent))))
          (is (equal "503" (otel-test-attribute sent "http.response.status_code")) "integers are strings too")
          (is (= 2 (gethash "code" (gethash "status" sent))))
          (is (equal "HTTP 503" (gethash "message" (gethash "status" sent)))))))))

(defun otel-test-gateway (function)
  "Call FUNCTION with a Gateway listener's port, its echo backend proxied for app.example.com."
  (let* ((backend (hunchentoot:start (make-instance 'gw-echo-acceptor :address "127.0.0.1" :port 0)))
         (backend-port (hunchentoot:acceptor-port backend))
         (routes (list (gr8s.controllers::make-gw-route
                        :namespace "shop" :name "web" :hostnames '("app.example.com")
                        :rules (list (gr8s.controllers::make-gw-rule
                                      :matches (list (gr8s.controllers::make-gw-match :path-type :prefix :path "/"))
                                      :backends (list (gr8s.controllers::make-gw-backend :name "web" :port backend-port)))))))
         (gateway (gr8s.controllers::start-gateway-listener
                   :port 0 :router (gr8s.controllers::build-gateway-router routes)
                   :resolver (lambda (b) (declare (ignore b)) (values "127.0.0.1" backend-port)) :name "test")))
    (unwind-protect (funcall function (hunchentoot:acceptor-port gateway))
      (gr8s.controllers::stop-gateway-listener gateway)
      (hunchentoot:stop backend))))

(test otel-gateway-continues-the-clients-trace-and-exports-its-span
  (with-otel-collector (endpoint)
    (otel-test-gateway
     (lambda (port)
       (setf *gw-backend-last* nil)
       (is (= 200 (gw-raw-request port "app.example.com" "/cart"
                                  :extra-headers `(("traceparent" . ,+otel-test-gateway-traceparent+)
                                                   ("tracestate" . "vendor=1")))))
       ;; The backend continues the client's trace, with the Gateway's span as its parent.
       (let ((sent (gw-request-header-seen "traceparent")))
         (multiple-value-bind (trace parent sampled) (gr8s.otel::parse-traceparent sent)
           (is (equal "0af7651916cd43dd8448eb211c80319c" trace))
           (is (not (equal "b7ad6b7169203331" parent)))
           (is (eq t sampled))
           (is (equal "vendor=1" (gw-request-header-seen "tracestate")))
           (let ((span (find trace (otel-test-wait-for-spans 1) :key (lambda (s) (gethash "traceId" s)) :test #'equal)))
             (is (not (null span)))
             (when span
               (is (equal parent (gethash "spanId" span)) "the backend's parent is the exported span")
               (is (equal "b7ad6b7169203331" (gethash "parentSpanId" span)))
               (is (equal "GET shop/web" (gethash "name" span)))
               (is (equal "200" (otel-test-attribute span "http.response.status_code")))
               (is (equal "/cart" (otel-test-attribute span "url.path")))
               (is (equal "shop/web" (otel-test-attribute span "http.route")))
               (is (equal "127.0.0.1" (otel-test-attribute span "network.peer.address")))
               (is (= 0 (gethash "code" (gethash "status" span) 0)))))))
       ;; A request with no trace context starts a trace of its own.
       (setf *gw-backend-last* nil)
       (gw-raw-request port "app.example.com" "/fresh")
       (is (gr8s.otel::parse-traceparent (gw-request-header-seen "traceparent")))
       ;; A 404 is traced as well, by its method alone.
       (gw-raw-request port "nowhere.example.com" "/")
       (is (find "GET" (otel-test-wait-for-spans 3) :key (lambda (s) (gethash "name" s)) :test #'equal))))))

(test otel-gateway-passes-trace-context-through-when-tracing-is-off
  (let ((previous gr8s.otel::*otel-configuration*))
    (setf gr8s.otel::*otel-configuration* (gr8s.otel::make-otel-configuration :endpoint nil))
    (unwind-protect
         (otel-test-gateway
          (lambda (port)
            (setf *gw-backend-last* nil)
            (gw-raw-request port "app.example.com" "/" :extra-headers `(("traceparent" . ,+otel-test-traceparent+)))
            (is (equal +otel-test-traceparent+ (gw-request-header-seen "traceparent")))
            (setf *gw-backend-last* nil)
            (gw-raw-request port "app.example.com" "/")
            (is (null (gw-request-header-seen "traceparent")) "and starts none")))
      (setf gr8s.otel::*otel-configuration* previous))))
