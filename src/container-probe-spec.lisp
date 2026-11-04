;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Validate Kubernetes startup/readiness/liveness probe declarations and apply
;;;; their API defaults. Resolve named ports and static command substitutions
;;;; using the target container declaration, never a different running attempt.

(in-package #:gr8s)

(defun probe-port-name-p (value)
  "Recognize an IANA service name suitable for a named container probe port."
  (and (stringp value) (<= 1 (length value) 15)
       (cl-ppcre:scan "^[a-z0-9]([-a-z0-9]*[a-z0-9])?$" value)
       (not (search "--" value))
       (find-if (lambda (char) (find char "abcdefghijklmnopqrstuvwxyz")) value)))

(defun validate-probe-port (value &key numeric)
  "Accept a real TCP port or a Kubernetes named port, unless NUMERIC is required."
  (unless (or (typep value '(integer 1 65535)) (and (not numeric) (probe-port-name-p value)))
    (invalid-pod "probe port must be ~A" (if numeric "an integer in 1..65535" "a TCP port or valid named port"))))

(defun probe-single-line-p (value)
  "Reject HTTP delimiter injection while retaining ordinary field values."
  (and (stringp value) (not (find-if (lambda (char) (find char '(#\Return #\Newline #\Null))) value))))

(defun validate-container-probe (probe kind)
  "Validate one executable probe and default zero-valued scalar API fields."
  (require-object probe kind)
  (reject-unsupported-fields probe '("exec" "httpGet" "tcpSocket" "grpc" "initialDelaySeconds" "timeoutSeconds"
                                      "periodSeconds" "successThreshold" "failureThreshold" "terminationGracePeriodSeconds") kind)
  (let ((handlers (loop for key in '("exec" "httpGet" "tcpSocket" "grpc") when (gethash key probe) collect key)))
    (unless (= 1 (length handlers)) (invalid-pod "~A requires exactly one probe handler" kind))
    (let* ((handler (first handlers)) (action (require-object (gethash handler probe) handler)))
      (cond
        ((equal handler "exec")
         (reject-unsupported-fields action '("command") "probe.exec")
         (let ((command (require-string-vector (optional-vector action "command" "probe.exec") "probe.exec.command")))
           (when (zerop (length command)) (invalid-pod "probe.exec.command must not be empty"))))
        ((equal handler "grpc")
         (reject-unsupported-fields action '("port" "service") "probe.grpc")
         (validate-probe-port (gethash "port" action) :numeric t)
         (when (gethash "service" action) (unless (stringp (gethash "service" action)) (invalid-pod "probe.grpc.service must be a string"))))
        (t
         (reject-unsupported-fields action (if (equal handler "httpGet") '("port" "host" "path" "scheme" "httpHeaders") '("port" "host")) handler)
         (validate-probe-port (gethash "port" action))
         (when (gethash "host" action) (unless (probe-single-line-p (gethash "host" action)) (invalid-pod "Invalid probe host")))
         (when (equal handler "httpGet")
           (when (gethash "path" action) (unless (probe-single-line-p (gethash "path" action)) (invalid-pod "Invalid probe path")))
           (when (member (gethash "path" action) '(nil "") :test #'equal) (setf (gethash "path" action) "/"))
           (when (member (gethash "scheme" action) '(nil "") :test #'equal) (setf (gethash "scheme" action) "HTTP"))
           (unless (member (gethash "scheme" action) '("HTTP" "HTTPS") :test #'equal) (invalid-pod "Invalid HTTP probe scheme"))
           (loop for header across (optional-vector action "httpHeaders" "probe.httpGet")
                 do (require-object header "httpHeader") (reject-unsupported-fields header '("name" "value") "httpHeader")
                    (unless (and (stringp (gethash "name" header))
                                 (cl-ppcre:scan "^[-0-9A-Za-z]+$" (gethash "name" header))
                                 (probe-single-line-p (gethash "value" header)))
                      (invalid-pod "Invalid probe HTTP header"))))))))
  (dolist (field '("initialDelaySeconds" "timeoutSeconds" "periodSeconds" "successThreshold" "failureThreshold"))
    (let* ((default (cond ((equal field "periodSeconds") 10) ((equal field "failureThreshold") 3)
                          ((equal field "initialDelaySeconds") 0) (t 1)))
           (value (gethash field probe 0)))
      (unless (typep value '(integer 0 2147483647)) (invalid-pod "~A must be a nonnegative int32" field))
      (setf (gethash field probe) (if (zerop value) default value))))
  (unless (or (equal kind "readinessProbe") (= 1 (gethash "successThreshold" probe)))
    (invalid-pod "~A successThreshold must be 1" kind))
  (when (gethash "terminationGracePeriodSeconds" probe)
    (when (equal kind "readinessProbe") (invalid-pod "readinessProbe cannot set terminationGracePeriodSeconds"))
    (unless (typep (gethash "terminationGracePeriodSeconds" probe) '(integer 1 9223372036854775807))
      (invalid-pod "probe terminationGracePeriodSeconds must be positive")))
  probe)

(defun resolve-container-probe-port (container value)
  "Resolve VALUE only against the declared target container's named ports."
  (if (integerp value) value
      (or (loop for port across (gethash "ports" container #())
                when (equal value (gethash "name" port))
                  return (gethash "containerPort" port))
          (error 'runtime-error :message (format nil "Probe port ~S is not declared in container ~A" value (gethash "name" container))))))

(defun expand-static-probe-command (container command)
  "Expand only literal env values; retain unknown references and honor doubled dollars."
  (let ((values (make-hash-table :test #'equal)))
    (loop for variable across (gethash "env" container #())
          do (setf (gethash (gethash "name" variable) values) (or (gethash "value" variable) "")))
    (map 'list
         (lambda (argument)
           (with-output-to-string (out)
             (loop with index = 0 while (< index (length argument))
                   do (cond
                        ((and (char= #\$ (char argument index)) (< (1+ index) (length argument)) (char= #\$ (char argument (1+ index))))
                         (write-char #\$ out) (incf index 2))
                        ((and (char= #\$ (char argument index)) (< (1+ index) (length argument)) (char= #\( (char argument (1+ index)))
                              (position #\) argument :start (+ index 2)))
                         (let* ((end (position #\) argument :start (+ index 2)))
                                (name (subseq argument (+ index 2) end)))
                           (write-string (gethash name values (subseq argument index (1+ end))) out)
                           (setf index (1+ end))))
                        (t (write-char (char argument index) out) (incf index))))))
         command)))
