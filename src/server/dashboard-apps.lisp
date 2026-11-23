;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Tabs for the cluster's own apps in `gr8s dashboard' (podster-ckt). A
;;;; cluster-scoped DashboardTab (dashboard.gr8s.io/v1) names a Service; whoever may
;;;; create one decides what every dashboard shows. Each app is reverse-proxied
;;;; through the cluster API's services/proxy, so the reader needs no route to Pods.
;;;;
;;;; An app is someone else's code, so it never shares the dashboard's origin: the
;;;; Headlamp proxy there acts with the reader's credentials. Each app gets its own
;;;; loopback port, which is its own origin. A port is reachable by any local process,
;;;; so the frame first loads a one-time bootstrap path holding a per-app secret,
;;;; which sets it as an HttpOnly, SameSite=Strict cookie; every other request must
;;;; carry it, and it is taken off before the request goes on.

(in-package #:gr8s.server)

(defparameter +dashboard-tab-resource+ "/apis/dashboard.gr8s.io/v1/dashboardtabs"
  "Where the cluster lists its DashboardTabs.")

(defparameter +dashboard-app-bootstrap+ "/.gr8s-tab/"
  "The path prefix whose next segment is an app tab's secret, setting its cookie.")

(defstruct (dashboard-app (:constructor make-dashboard-app (name title namespace service port path)))
  name title namespace service port path acceptor secret)

(defun dashboard-tab-object-app (object)
  "The app a DashboardTab OBJECT describes, or NIL when it names no Service."
  (let* ((spec (gethash "spec" object (core-object)))
         (service (gethash "service" spec (core-object)))
         (name (gethash "name" (gethash "metadata" object (core-object))))
         (port (gethash "port" service)))
    (when (and name (gethash "namespace" service) (gethash "name" service) port)
      (make-dashboard-app name (gethash "title" spec name) (gethash "namespace" service)
                          (gethash "name" service) port (gethash "path" spec "/")))))

(defun dashboard-app-proxy-prefix (app)
  "The cluster API path that proxies to APP's Service."
  (format nil "/api/v1/namespaces/~A/services/~A:~A/proxy"
          (dashboard-app-namespace app) (dashboard-app-service app) (dashboard-app-port app)))

(defun dashboard-app-cookie (app)
  "The name of APP's secret cookie. Cookies aren't kept apart by port, so it's per app."
  (format nil "gr8s-tab-~A" (hunchentoot:acceptor-port (dashboard-app-acceptor app))))

(defun dashboard-app-target (app request-uri)
  "The API path REQUEST-URI asks of APP. The proxy points the app's links and redirects
through its prefix, so a path already under it goes as is."
  (let ((prefix (dashboard-app-proxy-prefix app)))
    (if (uiop:string-prefix-p prefix request-uri)
        request-uri
        (concatenate 'string prefix request-uri))))

(defun dashboard-app-request-headers (app headers)
  "HEADERS to send on to APP: not those the connection or the API proxy owns, not
Authorization, which the API server would take as the reader's, and not the tabs'
own secret cookies."
  (declare (ignore app))
  (loop for (name . value) in (gr8s.apiserver::pod-proxy-end-to-end-headers
                               (mapcar (lambda (header) (cons (string-downcase (string (car header))) (cdr header)))
                                       headers)
                               :request t)
        unless (or (string-equal name "authorization") (string-equal name "referer"))
          collect (cons name
                        (if (string-equal name "cookie")
                            (format nil "~{~A~^; ~}"
                                    (remove-if (lambda (cookie)
                                                 (uiop:string-prefix-p "gr8s-tab-" (string-trim " " cookie)))
                                               (uiop:split-string value :separator ";")))
                            value))))

(defun dashboard-app-location (app location)
  "LOCATION, a redirect APP's proxy sent, as the app's own path. The proxy points it
through its prefix; an app that routes in the browser (Grafana) must see its own
paths there, so the prefix comes off. Its pages' base still loads assets through it."
  (let ((prefix (dashboard-app-proxy-prefix app)))
    (if (uiop:string-prefix-p prefix location)
        (let ((rest (subseq location (length prefix))))
          (if (or (zerop (length rest)) (char/= #\/ (char rest 0)))
              (concatenate 'string "/" rest)
              rest))
        location)))

(defun dashboard-app-response-header-p (name)
  "Whether a response header NAME goes back to the browser. An app that refuses to be
framed can't be a tab, so the framing guards are dropped; the dashboard frames it on
loopback for the one reader who opened it."
  (not (member name '("connection" "keep-alive" "transfer-encoding" "x-frame-options"
                      "content-length" "content-type")
               :test #'string-equal)))

(defun dashboard-app-csp (value)
  "VALUE, a Content-Security-Policy, without its frame-ancestors directive."
  (format nil "~{~A~^;~}"
          (remove-if (lambda (directive) (uiop:string-prefix-p "frame-ancestors" (string-trim " " directive)))
                     (uiop:split-string value :separator ";"))))

(defun write-dashboard-app-request (stream method host port target token headers body)
  "Write one proxied app request to the cluster-API STREAM."
  (write-sequence
   (gr8s.protocol::ascii-octets
    (with-output-to-string (request)
      (flet ((line (control &rest args)
               (apply #'format request control args)
               (write-string (format nil "~C~C" #\Return #\Linefeed) request)))
        (line "~A ~A HTTP/1.1" method target)
        (line "Host: ~A:~D" host port)
        (line "Connection: close")
        (when token (line "Authorization: Bearer ~A" token))
        (loop for (name . value) in headers
              unless (equal value "") do (line "~A: ~A" name value))
        (line "Content-Length: ~D" (if body (length body) 0))
        (line ""))))
   stream)
  (when (and body (plusp (length body))) (write-sequence body stream))
  (finish-output stream))

(defun dashboard-app-redirect-member (config status headers)
  "The config for the member a 307 or 308 in STATUS and HEADERS sends an app request to,
and its target, or NIL. A follower sends proxy requests that aren't reads to the
leader; the browser can't follow that to the API server, so the dashboard does."
  (let ((location (cdr (assoc :location headers))))
    (when (and (member status '(307 308)) location
               (or (uiop:string-prefix-p "https://" location) (uiop:string-prefix-p "http://" location)))
      (multiple-value-bind (secure-p host port path) (debug-api-url-parts location)
        (declare (ignore path))
        (let* ((authority-end (position #\/ location :start (+ 3 (search "://" location))))
               (target (if authority-end (subseq location authority-end) "/")))
          (values (list* :server (format nil "~:[http~;https~]://~A:~D" secure-p host port) config)
                  target))))))

(defun dashboard-app-forward (config app request &key (target (dashboard-app-target app (hunchentoot:request-uri request)))
                                                       (redirects 1))
  "Answer REQUEST for APP through the cluster API's services/proxy at TARGET."
  (let ((body (ignore-errors (hunchentoot:raw-post-data :force-binary t :request request)))
        (stream nil) (socket nil))
    (unwind-protect
         (handler-case
             (multiple-value-bind (opened opened-socket host port base-path) (open-debug-api-stream config)
               (setf stream opened socket opened-socket)
               (let ((headers (dashboard-app-request-headers app (hunchentoot:headers-in request)))
                     (content-type (hunchentoot:header-in :content-type request)))
                 (write-dashboard-app-request
                  stream (symbol-name (hunchentoot:request-method request)) host port
                  (concatenate 'string base-path target)
                  (getf config :token)
                  (if content-type (acons "Content-Type" content-type headers) headers)
                  body))
               (multiple-value-bind (status headers)
                   (gr8s.protocol::parse-http-response-head (gr8s.protocol::read-http-response-head stream))
                 (multiple-value-bind (member member-target) (dashboard-app-redirect-member config status headers)
                   (when (and member (plusp redirects))
                     (close stream) (usocket:socket-close socket) (setf stream nil socket nil)
                     (return-from dashboard-app-forward
                       (dashboard-app-forward member app request :target member-target
                                                                 :redirects (1- redirects)))))
                 (setf (hunchentoot:return-code*) status
                       (hunchentoot:content-type*) (cdr (assoc :content-type headers)))
                 (loop for (name . value) in headers
                       for text = (string-downcase (symbol-name name))
                       when (dashboard-app-response-header-p text)
                         do (push (cons name (case name
                                               (:content-security-policy (dashboard-app-csp value))
                                               (:location (dashboard-app-location app value))
                                               (t value)))
                                  (slot-value hunchentoot:*reply* 'hunchentoot::headers-out)))
                 (read-dashboard-proxy-body stream headers)))
           (error (condition)
             (setf (hunchentoot:return-code*) hunchentoot:+http-bad-gateway+
                   (hunchentoot:content-type*) "text/plain")
             (format nil "gr8s dashboard: ~A is unreachable through the cluster API: ~A"
                     (dashboard-app-title app) condition)))
      (when stream (ignore-errors (close stream)))
      (when socket (ignore-errors (usocket:socket-close socket))))))

(defclass dashboard-app-acceptor (hunchentoot:acceptor)
  ((app :initarg :app :accessor dashboard-app-acceptor-app)
   (config :initarg :config :reader dashboard-app-acceptor-config))
  (:default-initargs :access-log-destination nil :message-log-destination nil)
  (:documentation "One app tab's own loopback origin."))

(defmethod hunchentoot:acceptor-dispatch-request ((acceptor dashboard-app-acceptor) request)
  (let* ((app (dashboard-app-acceptor-app acceptor))
         (path (hunchentoot:script-name request))
         (bootstrap (concatenate 'string +dashboard-app-bootstrap+ (dashboard-app-secret app))))
    (cond
      ((string= path bootstrap)
       ;; The frame's first load: keep the secret as a cookie, then show the app.
       (hunchentoot:set-cookie (dashboard-app-cookie app) :value (dashboard-app-secret app)
                               :path "/" :http-only t :same-site "Strict")
       (hunchentoot:redirect (dashboard-app-path app) :code hunchentoot:+http-moved-temporarily+))
      ((not (equal (hunchentoot:cookie-in (dashboard-app-cookie app) request) (dashboard-app-secret app)))
       (setf (hunchentoot:return-code*) hunchentoot:+http-forbidden+
             (hunchentoot:content-type*) "text/plain")
       "gr8s dashboard: open this app from its dashboard tab")
      (t (dashboard-app-forward (dashboard-app-acceptor-config acceptor) app request)))))

(defstruct (dashboard-apps (:constructor make-dashboard-apps (config)))
  "The app tabs of one dashboard session, by DashboardTab name."
  config (table (make-hash-table :test #'equal)) (lock (bt:make-lock "gr8s dashboard apps")))

(defun dashboard-apps-tabs (apps &key (list-tabs (lambda (config)
                                                   (multiple-value-bind (body status)
                                                       (debug-api-request-json config "GET" +dashboard-tab-resource+)
                                                     (and (= status 200) body)))))
  "The (name src title) tabs of the cluster's DashboardTabs now, starting a server for
each new one and stopping those whose DashboardTab is gone."
  (let* ((list (ignore-errors (funcall list-tabs (dashboard-apps-config apps))))
         (wanted (remove nil (map 'list #'dashboard-tab-object-app (and list (gethash "items" list #()))))))
    (bt:with-lock-held ((dashboard-apps-lock apps))
      (let ((table (dashboard-apps-table apps)))
        (loop for name being the hash-keys of table using (hash-value app)
              unless (find name wanted :key #'dashboard-app-name :test #'equal)
                do (ignore-errors (hunchentoot:stop (dashboard-app-acceptor app)))
                   (remhash name table))
        (loop for app in (sort wanted #'string< :key #'dashboard-app-title)
              for running = (gethash (dashboard-app-name app) table)
              collect (let ((app (cond ((null running)
                                        (start-dashboard-app (dashboard-apps-config apps) app))
                                       (t
                                        ;; An edited DashboardTab changes where the same server goes.
                                        (setf (dashboard-app-acceptor app) (dashboard-app-acceptor running)
                                              (dashboard-app-secret app) (dashboard-app-secret running)
                                              (dashboard-app-acceptor-app (dashboard-app-acceptor running)) app)
                                        app))))
                        (setf (gethash (dashboard-app-name app) table) app)
                        (list (concatenate 'string "app-" (dashboard-app-name app))
                              (format nil "http://127.0.0.1:~D~A~A"
                                      (hunchentoot:acceptor-port (dashboard-app-acceptor app))
                                      +dashboard-app-bootstrap+ (dashboard-app-secret app))
                              (dashboard-app-title app))))))))

(defun start-dashboard-app (config app)
  "Serve APP on a loopback port of its own, with a fresh secret."
  (setf (dashboard-app-secret app) (dashboard-session-token)
        (dashboard-app-acceptor app)
        (hunchentoot:start (make-instance 'dashboard-app-acceptor :address "127.0.0.1" :port 0
                                                                   :app app :config config)))
  app)

(defun stop-dashboard-apps (apps)
  "Stop every app server of APPS."
  (bt:with-lock-held ((dashboard-apps-lock apps))
    (maphash (lambda (name app) (declare (ignore name))
               (ignore-errors (hunchentoot:stop (dashboard-app-acceptor app))))
             (dashboard-apps-table apps))
    (clrhash (dashboard-apps-table apps))))
