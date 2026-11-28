;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; `gr8s doctor' reads the cluster through gr8s's own API client rather than
;;;; kubectl (podster-71m), so a host without kubectl -- a control-plane member --
;;;; can be diagnosed, and a failed read says why. The getter keeps the doctor's
;;;; contract with kubectl-getter: (values object state), state :present, :absent
;;;; or :unknown. The doctor on its own (gr8s-doctor.asd) still reads through kubectl.

(in-package #:gr8s.server)

(defparameter +doctor-api-response-limit+ (* 8 1024 1024)
  "The most a doctor read accepts, as kubectl-getter does.")

(defparameter +doctor-api-request-seconds+ 10
  "How long one doctor read may take, as kubectl's --request-timeout=10s.")

(defun default-doctor-kubeconfig ()
  "The kubeconfig a doctor run without --kubeconfig reads: kubectl's own choice ($KUBECONFIG's
first file that exists, then ~/.kube/config), else, on a control-plane member, the server's."
  (or (find-if #'probe-file
               (append (remove "" (uiop:split-string (or (uiop:getenv "KUBECONFIG") "") :separator ":")
                               :test #'equal)
                       (list (namestring (merge-pathnames ".kube/config" (user-homedir-pathname)))
                             "/var/lib/gr8s/server/kubeconfig")))
      (error "No kubeconfig found: pass --kubeconfig FILE")))

(defun doctor-api-get (config target &key (limit +doctor-api-response-limit+) (seconds +doctor-api-request-seconds+))
  "GET TARGET on CONFIG's server. Return (values body-octets status headers), bounded in time
by SECONDS and in size by LIMIT octets. Running out of time is an ERROR, which callers'
IGNORE-ERRORS handles: SBCL's own timeout is a serious condition no IGNORE-ERRORS catches, and
one left unhandled in a dashboard thread ended the dashboard."
  (handler-case (doctor-api-get-within config target limit seconds)
    (sb-ext:timeout ()
      (error "no answer from ~A within ~D seconds" (getf config :server) seconds))))

(defun doctor-api-get-within (config target limit seconds)
  "DOCTOR-API-GET's request, abandoned with SB-EXT:TIMEOUT after SECONDS."
  (sb-ext:with-timeout seconds
    (multiple-value-bind (stream socket host port base-path) (open-debug-api-stream config)
      (unwind-protect
           (progn
             (write-debug-http-request stream "GET" host port (concatenate 'string base-path target)
                                       (getf config :token))
             (multiple-value-bind (status headers)
                 (gr8s.protocol::parse-http-response-head (gr8s.protocol::read-http-response-head stream))
               (values (gr8s.http-client::read-response-body
                        stream (mapcar (lambda (header) (cons (string-downcase (string (car header))) (cdr header)))
                                       headers)
                        :limit limit)
                       status headers)))
        (ignore-errors (close stream))
        (ignore-errors (usocket:socket-close socket))))))

(defun doctor-api-status-message (body)
  "The message of the Kubernetes Status BODY holds, or NIL."
  (let ((status (ignore-errors (com.inuoe.jzon:parse body))))
    (and (hash-table-p status) (stringp (gethash "message" status)) (gethash "message" status))))

(defun doctor-api-discover (config)
  "Map each Kind the API serves to (prefix plural namespaced-p api-version), from discovery as
kubectl does: the core API first, then each group's preferred version."
  (let ((kinds (make-hash-table :test #'equal)))
    (flet ((add (prefix api-version)
             (multiple-value-bind (body status) (doctor-api-get config prefix)
               (when (= status 200)
                 (loop for resource across (gethash "resources" (com.inuoe.jzon:parse body) #())
                       for plural = (gethash "name" resource)
                       unless (or (find #\/ plural) (gethash (gethash "kind" resource) kinds))
                         do (setf (gethash (gethash "kind" resource) kinds)
                                  (list prefix plural (eq t (gethash "namespaced" resource)) api-version)))))))
      (add "/api/v1" "v1")
      (multiple-value-bind (body status) (doctor-api-get config "/apis")
        (when (= status 200)
          (loop for group across (gethash "groups" (com.inuoe.jzon:parse body) #())
                for version = (gethash "groupVersion" (gethash "preferredVersion" group))
                when version do (ignore-errors (add (format nil "/apis/~A" version) version))))))
    kinds))

(defun doctor-api-getter (config)
  "A doctor getter reading through CONFIG's API server: kinds, a container's previous log
(PreviousLog, named POD/CONTAINER), one member's view (MemberView, named HOST:PORT) and the
cluster's flow events (Flows)."
  (let ((kinds nil))
    (labels ((failed (control &rest arguments)
               (apply #'gr8s-diagnose::note-read-failure control arguments)
               (values nil :unknown))
             (resource (kind namespace name)
               (unless kinds (setf kinds (doctor-api-discover config)))
               (destructuring-bind (&optional prefix plural namespaced api-version) (gethash kind kinds)
                 (unless prefix
                   ;; A kind this cluster doesn't serve, as kubectl can't get it either.
                   (return-from resource (values nil :unknown)))
                 (let ((target (format nil "~A~@[/namespaces/~A~]/~A~@[/~A~]" prefix
                                       (and namespaced namespace) plural
                                       (and name (hunchentoot:url-encode name)))))
                   (multiple-value-bind (body status) (doctor-api-get config target)
                     (cond
                       ((and name (= status 404)) (values nil :absent))
                       ((/= status 200)
                        (failed "HTTP ~D reading ~A~@[: ~A~]" status target (doctor-api-status-message body)))
                       (t
                        (let ((object (com.inuoe.jzon:parse body)))
                          ;; kubectl names each listed item's kind, which a list from the API leaves out.
                          (unless name
                            (loop for item across (gethash "items" object #())
                                  do (setf (gethash "kind" item) kind
                                           (gethash "apiVersion" item) api-version)))
                          (values object :present))))))))
             (previous-log (namespace name)
               (let* ((slash (position #\/ name))
                      (target (format nil "/api/v1/namespaces/~A/pods/~A/log?container=~A&previous=true&tailLines=40"
                                      namespace (hunchentoot:url-encode (subseq name 0 slash))
                                      (hunchentoot:url-encode (subseq name (1+ slash))))))
                 (multiple-value-bind (body status) (doctor-api-get config target)
                   (if (= status 200)
                       (values (gr8s-diagnose::object "text" (trivial-utf-8:utf-8-bytes-to-string body)) :present)
                       (values nil :unknown)))))
             (member-view (address)
               (multiple-value-bind (body status)
                   (doctor-api-get (list* :server (format nil "https://~A" address) config)
                                   "/api/v1/namespaces/default")
                 (if (= status 200) (values (com.inuoe.jzon:parse body) :present) (values nil :unknown))))
             (flows (namespace)
               (multiple-value-bind (body status) (doctor-api-get config (gr8s-diagnose::flows-raw-path namespace))
                 (if (= status 200)
                     (values (gr8s-diagnose::flows-list-from-text (trivial-utf-8:utf-8-bytes-to-string body)) :present)
                     (values nil :unknown)))))
      (lambda (kind namespace name)
        (cond ((equal kind "PreviousLog")
               (gr8s-diagnose::progress "Reading the last log of Pod ~A" (subseq name 0 (position #\/ name))))
              ((equal kind "MemberView") (gr8s-diagnose::progress "Asking control-plane member ~A" name))
              ((null name) (gr8s-diagnose::progress "Listing ~A resources" kind)))
        (handler-case
            (cond ((equal kind "PreviousLog") (previous-log namespace name))
                  ((equal kind "MemberView") (member-view name))
                  ((equal kind "Flows") (flows namespace))
                  (t (resource kind namespace name)))
          (sb-ext:timeout ()
            (if (member kind '("PreviousLog" "MemberView" "Flows") :test #'equal)
                (values nil :unknown)
                (failed "no answer from ~A within ~D seconds" (getf config :server) +doctor-api-request-seconds+)))
          (error (condition)
            (if (member kind '("PreviousLog" "MemberView" "Flows") :test #'equal)
                (values nil :unknown)
                (failed "~A: ~A" (getf config :server) (remove #\Newline (princ-to-string condition))))))))))

(defun call-with-doctor-api-getter (kubeconfig context function)
  "Call FUNCTION with a doctor getter on KUBECONFIG's CONTEXT, by default the one kubectl would use."
  (call-with-debug-kubeconfig (or kubeconfig (default-doctor-kubeconfig))
                              (lambda (config) (funcall function (doctor-api-getter config)))
                              :context context))
