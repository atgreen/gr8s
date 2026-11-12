;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Exercise the kubelet listener over real TLS: the credentials the cluster CA issues
;;;; it, authentication by client certificate and by reviewed bearer token, the
;;;; nodes subresource each path is authorized against, the endpoints it serves, the
;;;; port the Node advertises, and the API server's Node proxy forwarding to it.

(in-package #:gr8s/tests)

(def-suite kubelet-server :in gr8s)
(in-suite kubelet-server)

(defmacro with-kubelet-test-pki ((pki directory) &body body)
  "Run BODY with a fresh cluster PKI and a directory for kubelet credentials."
  `(let ((,directory (uiop:ensure-directory-pathname
                      (sb-posix:mkdtemp (namestring (merge-pathnames "gr8s-kubelet-XXXXXX" (uiop:temporary-directory)))))))
     (unwind-protect (let ((,pki (gr8s.security::ensure-cluster-pki (merge-pathnames "pki/" ,directory)))) ,@body)
       (uiop:delete-directory-tree ,directory :validate t :if-does-not-exist :ignore))))

(test kubelet-paths-map-to-the-kubelet-subresources
  (loop for (path subresources) in '(("/metrics/resource" ("metrics")) ("/metrics" ("metrics"))
                                     ("/metrics/cadvisor" ("metrics")) ("/stats/summary" ("stats"))
                                     ("/stats" ("stats")) ("/logs/messages" ("log"))
                                     ("/pods" ("pods" "proxy")) ("/healthz" ("healthz" "proxy"))
                                     ("/configz" ("configz" "proxy")) ("/checkpoint/ns/pod/c" ("checkpoint"))
                                     ("/spec/" ("proxy")) ("/run/ns/pod/c" ("proxy")) ("/metricsx" ("proxy")))
        do (is (equal subresources (gr8s.apiserver::kubelet-request-subresources path)) "~A" path))
  (is (equal '("get" "create" "update" "patch" "delete" "")
             (mapcar #'gr8s.apiserver::kubelet-request-verb '(:get :post :put :patch :delete :head)))))

(test kubelet-credentials-come-from-the-cluster-ca
  (with-kubelet-test-pki (pki directory)
    (gr8s.apiserver::issue-kubelet-credentials pki directory "node-a" '("127.0.0.1" "10.0.2.15"))
    (multiple-value-bind (certificate key client-certificate) (gr8s.apiserver::kubelet-credential-paths directory)
      (is (probe-file key))
      (let ((leaf (first (pure-tls:load-certificate-chain certificate))))
        (pure-tls::verify-certificate-chain (list leaf) (list (gr8s.security::cluster-pki-ca-certificate pki))
                                            :purpose :server-auth :trust-anchor-mode :replace)
        (is (pure-tls::verify-hostname leaf "10.0.2.15"))
        (is (pure-tls::verify-hostname leaf "node-a"))
        (signals error (pure-tls::verify-hostname leaf "10.0.2.16")))
      ;; The client certificate speaks for the node, as a bootstrapped kubelet's does.
      (let ((identity (gr8s.resources::certificate-api-identity (pure-tls:load-certificate-chain client-certificate)
                                                      (gr8s.security::cluster-pki-ca-certificate pki))))
        (is (equal "system:node:node-a" (gr8s.resources::api-identity-username identity)))
        (is (find "system:nodes" (gr8s.resources::api-identity-groups identity) :test #'equal))))
    (multiple-value-bind (certificate) (gr8s.apiserver::ensure-apiserver-kubelet-client-credentials pki)
      (let ((identity (gr8s.resources::certificate-api-identity (pure-tls:load-certificate-chain certificate)
                                                      (gr8s.security::cluster-pki-ca-certificate pki))))
        (is (equal "kube-apiserver-kubelet-client" (gr8s.resources::api-identity-username identity)))
        (is (find "system:masters" (gr8s.resources::api-identity-groups identity) :test #'equal))))))

(test nodes-may-review-tokens-and-access-for-their-kubelets
  (with-temporary-store (store path)
    (let ((node (gr8s.resources::make-api-user-identity :username "system:node:a" :groups #("system:nodes" "system:authenticated")))
          (other (gr8s.resources::make-api-user-identity :username "someone" :groups #("system:authenticated"))))
      (is (gr8s.resources::service-account-authorized-p store node "create" "authentication.k8s.io" "tokenreviews" nil nil))
      (is (gr8s.resources::service-account-authorized-p store node "create" "authorization.k8s.io" "subjectaccessreviews" nil nil))
      (is (not (gr8s.resources::service-account-authorized-p store node "list" "authentication.k8s.io" "tokenreviews" nil nil)))
      (is (not (gr8s.resources::service-account-authorized-p store other "create" "authentication.k8s.io" "tokenreviews" nil nil))))))

(defun kubelet-test-review (calls)
  "Answer reviews as an API server would, recording each in the CALLS cons: the token \"good\"
is user alice, and only alice may get nodes/metrics, and system:masters anything."
  (lambda (review)
    (push review (car calls))
    (let ((spec (gethash "spec" review)))
      (if (equal "TokenReview" (gethash "kind" review))
          (gr8s.resources::core-object "status" (if (equal "good" (gethash "token" spec))
                                          (gr8s.resources::core-object "authenticated" t
                                                             "user" (gr8s.resources::core-object "username" "alice" "uid" "u-1"
                                                                                       "groups" #("system:authenticated")))
                                          (gr8s.resources::core-object "authenticated" nil)))
          (let ((attributes (gethash "resourceAttributes" spec)))
            (gr8s.resources::core-object
             "status" (gr8s.resources::core-object
                       "allowed" (or (and (find "system:masters" (gethash "groups" spec) :test #'equal) t)
                                     (and (equal "alice" (gethash "user" spec))
                                          (equal "nodes" (gethash "resource" attributes))
                                          (equal "metrics" (gethash "subresource" attributes))
                                          (equal "node-a" (gethash "name" attributes))
                                          (equal "get" (gethash "verb" attributes)))))))))))

(defun kubelet-test-get (pki port path &key token client)
  "GET PATH from the kubelet listener on PORT, verifying it by PKI's CA, returning status and text."
  (multiple-value-bind (code headers body)
      (gr8s.apiserver::tls-http-request :address "127.0.0.1" :port port :server-name "127.0.0.1" :target path
                              :headers (when token (list (cons "Authorization" (format nil "Bearer ~A" token))))
                              :trust-certificates (list (gr8s.security::cluster-pki-ca-certificate pki))
                              :client-certificate (first client) :client-key (second client))
    (values code (trivial-utf-8:utf-8-bytes-to-string body) (cdr (assoc "content-type" headers :test #'string=)))))

(test kubelet-listener-authenticates-authorizes-and-serves
  (with-kubelet-test-pki (pki directory)
    (gr8s.apiserver::issue-kubelet-credentials pki directory "node-a" '("127.0.0.1"))
    (multiple-value-bind (certificate key client-certificate client-key) (gr8s.apiserver::kubelet-credential-paths directory)
      (declare (ignore client-certificate client-key))
      (let* ((calls (list nil))
             (server (gr8s.apiserver::start-kubelet-server
                      :address "127.0.0.1" :port 0 :certificate certificate :key key :node-name "node-a"
                      :auth (gr8s.apiserver::make-kubelet-auth :client-ca (gr8s.security::cluster-pki-ca-certificate pki)
                                                     :review (kubelet-test-review calls))
                      :stats-function #'kubelet-test-node-stats
                      :network-metrics-function
                      (constantly "gr8s_wireguard_telemetry_available{node=\"node-a\"} 1\n")
                      :states-function (lambda () (values 1 '(("running" . 2) ("exited" . 1))))))
             (port (hunchentoot:acceptor-port server)))
        (unwind-protect
             (progn
               (is (= 401 (kubelet-test-get pki port "/metrics/resource")))
               (is (= 401 (kubelet-test-get pki port "/metrics/resource" :token "bad")))
               (multiple-value-bind (code text type) (kubelet-test-get pki port "/metrics/resource" :token "good")
                 (is (= 200 code))
                 (is (equal "text/plain; version=0.0.4; charset=utf-8" type))
                 (is (equal (gr8s.kubelet::kubelet-resource-metrics-text (kubelet-test-node-stats)) text)))
               ;; alice may read metrics but not stats, and the kubelet says what it checked.
               (multiple-value-bind (code text) (kubelet-test-get pki port "/stats/summary" :token "good")
                 (is (= 403 code))
                 (is (equal (format nil "Forbidden (user=alice, verb=get, resource=nodes, subresource(s)=[stats])~%") text)))
               ;; Reviews are cached: a repeat asks the API server nothing more.
               (let ((before (length (car calls))))
                 (kubelet-test-get pki port "/metrics/resource" :token "good")
                 (is (= before (length (car calls)))))
               (let ((access (find "SubjectAccessReview" (car calls) :key (lambda (review) (gethash "kind" review)) :test #'equal)))
                 (is (equal "u-1" (gr8s.apiserver::table-get access "spec" "uid")))
                 (is (equal "v1" (gr8s.apiserver::table-get access "spec" "resourceAttributes" "version"))))
               ;; A cluster-CA client certificate authenticates without a token review.
               (multiple-value-bind (client client-key) (gr8s.apiserver::ensure-apiserver-kubelet-client-credentials pki)
                 (let ((reviews (count "TokenReview" (car calls) :key (lambda (review) (gethash "kind" review)) :test #'equal)))
                   (multiple-value-bind (code text type) (kubelet-test-get pki port "/stats/summary?only_cpu_and_memory=true"
                                                                           :client (list client client-key))
                     (is (= 200 code))
                     (is (equal "application/json" type))
                     (is (equal "node-a" (gr8s.apiserver::table-get (com.inuoe.jzon:parse text) "node" "nodeName"))))
                   (is (= reviews (count "TokenReview" (car calls) :key (lambda (review) (gethash "kind" review)) :test #'equal))))
                 (is (equal '(200 "ok") (multiple-value-list
                                         (values (kubelet-test-get pki port "/healthz" :client (list client client-key))
                                                 (nth-value 1 (kubelet-test-get pki port "/healthz" :client (list client client-key)))))))
                 (is (= 404 (kubelet-test-get pki port "/nothing" :client (list client client-key))))
                 (multiple-value-bind (code text) (kubelet-test-get pki port "/metrics" :client (list client client-key))
                   (is (= 200 code))
                   (is (search "kubelet_node_name{node=\"node-a\"} 1" text))
                   (is (search (format nil "kubelet_running_containers{container_state=\"running\"} 2~%") text))
                   (is (search (format nil "kubelet_running_containers{container_state=\"exited\"} 1~%") text))
                   (is (search "kubelet_running_pods 1" text))
                   (is (search "gr8s_wireguard_telemetry_available{node=\"node-a\"} 1" text))
                   (is (search "# TYPE process_resident_memory_bytes gauge" text))
                   (is (search "# TYPE process_start_time_seconds gauge" text)))))
          (gr8s.apiserver::stop-kubelet-server server))))))

(test kubelet-scrape-failure-reports-the-error-metric
  (with-kubelet-test-pki (pki directory)
    (gr8s.apiserver::issue-kubelet-credentials pki directory "node-a" '("127.0.0.1"))
    (multiple-value-bind (certificate key) (gr8s.apiserver::kubelet-credential-paths directory)
      (let* ((server (gr8s.apiserver::start-kubelet-server
                      :address "127.0.0.1" :port 0 :certificate certificate :key key :node-name "node-a"
                      :auth (gr8s.apiserver::make-kubelet-auth :client-ca (gr8s.security::cluster-pki-ca-certificate pki)
                                                     :review (kubelet-test-review (list nil)))
                      :stats-function (lambda () (error "runtime unavailable"))))
             (port (hunchentoot:acceptor-port server)))
        (unwind-protect
             (multiple-value-bind (code text) (kubelet-test-get pki port "/metrics/resource" :token "good")
               (is (= 200 code))
               (is (search "resource_scrape_error 1" text))
               (is (not (search "node_cpu" text))))
          (gr8s.apiserver::stop-kubelet-server server))))))

(test node-advertises-and-proxies-to-its-kubelet
  (with-kubelet-test-pki (pki directory)
    (with-temporary-store (store path)
      (gr8s.apiserver::issue-kubelet-credentials pki directory "node-a" '("127.0.0.1"))
      (gr8s.controllers::register-node store (gr8s.model::make-node-record :id "kubelet-node-id" :name "node-a" :pod-cidr "10.88.51.0/24"
                                                       :underlay-address "127.0.0.1"))
      (is (= 0 (gr8s.apiserver::table-get (gr8s.resources::node-api-object (gr8s.controllers::get-node store "node-a"))
                                "status" "daemonEndpoints" "kubeletEndpoint" "Port")))
      (multiple-value-bind (certificate key) (gr8s.apiserver::kubelet-credential-paths directory)
        (let* ((calls (list nil))
               (kubelet (gr8s.apiserver::start-kubelet-server
                         :address "127.0.0.1" :port 0 :certificate certificate :key key :node-name "node-a"
                         :auth (gr8s.apiserver::make-kubelet-auth :client-ca (gr8s.security::cluster-pki-ca-certificate pki)
                                                        :review (kubelet-test-review calls))
                         :stats-function #'kubelet-test-node-stats))
               (kubelet-port (hunchentoot:acceptor-port kubelet))
               (frontend nil)
               (previous gr8s.apiserver::*kubelet-proxy-credentials*))
          (gr8s.controllers::update-node-kubelet-port store "node-a" kubelet-port)
          (is (= kubelet-port (gr8s.apiserver::table-get (gr8s.resources::node-api-object (gr8s.controllers::get-node store "node-a"))
                                               "status" "daemonEndpoints" "kubeletEndpoint" "Port")))
          ;; The port survives a restart of the control plane.
          (is (= kubelet-port (gr8s.model::node-record-kubelet-port
                               (gr8s.store::parse-node-record (gr8s.store::node-record-to-object (gr8s.controllers::get-node store "node-a"))))))
          ;; Request threads see only the global value.
          (setf gr8s.apiserver::*kubelet-proxy-credentials*
                (multiple-value-bind (client client-key) (gr8s.apiserver::ensure-apiserver-kubelet-client-credentials pki)
                  (list (gr8s.security::cluster-pki-ca-certificate pki) client client-key)))
          (unwind-protect
               (progn
                 (setf frontend (start-http-test-server :store store :runtime (make-fake-runtime)))
                 (flet ((fetch (suffix)
                          (multiple-value-bind (body code headers)
                              (drakma:http-request (format nil "http://127.0.0.1:~D/api/v1/nodes/~A" *http-test-port* suffix)
                                                   :proxy nil :redirect nil)
                            (values code body (cdr (assoc :content-type headers))))))
                   (multiple-value-bind (code body type) (fetch "node-a/proxy/metrics/resource")
                     (is (= 200 code))
                     (is (equal "text/plain; version=0.0.4; charset=utf-8" type))
                     (is (search "node_cpu_usage_seconds_total 357.35" body)))
                   ;; An explicit port, as the e2e framework names it, reaches the same listener.
                   (multiple-value-bind (code body) (fetch (format nil "node-a:~D/proxy/stats/summary" kubelet-port))
                     (is (= 200 code))
                     (is (equal "node-a" (gr8s.apiserver::table-get (com.inuoe.jzon:parse body) "node" "nodeName"))))
                   ;; The kubelet saw the API server's own identity.
                   (is (some (lambda (review)
                               (equal "kube-apiserver-kubelet-client" (gr8s.apiserver::table-get review "spec" "user")))
                             (car calls)))
                   ;; The node's log directory, with its trailing slash kept on the way through.
                   (multiple-value-bind (code body type) (fetch "node-a/proxy/logs/")
                     (is (= 200 code))
                     (is (equal "text/html; charset=utf-8" type))
                     (is (search "<pre>" body)))
                   ;; The Pod list is still the control plane's own answer.
                   (is (= 200 (fetch "node-a/proxy/pods")))
                   (is (= 404 (fetch "node-b/proxy/metrics")))
                   (gr8s.apiserver::stop-kubelet-server kubelet)
                   (setf kubelet nil)
                   (is (= 503 (fetch "node-a/proxy/metrics/resource")))))
            (setf gr8s.apiserver::*kubelet-proxy-credentials* previous)
            (when frontend (stop-server frontend))
            (when kubelet (gr8s.apiserver::stop-kubelet-server kubelet))))))))

(test a-stalled-tls-handshake-drops-its-connection-not-the-server
  ;; A focused run of 117b50c ended when one client left the in-cluster API's
  ;; handshake unfinished for ten seconds: the bare SB-SYS:DEADLINE-TIMEOUT, a
  ;; SERIOUS-CONDITION, passed Hunchentoot's error handling and quit the process.
  (with-kubelet-test-pki (pki directory)
    (gr8s.apiserver::issue-kubelet-credentials pki directory "node-a" '("127.0.0.1"))
    (multiple-value-bind (certificate key) (gr8s.apiserver::kubelet-credential-paths directory)
      (let* ((limit gr8s.security::*tls-handshake-seconds*)
             (server (gr8s.apiserver::start-kubelet-server
                      :address "127.0.0.1" :port 0 :certificate certificate :key key :node-name "node-a"
                      :auth (gr8s.apiserver::make-kubelet-auth :client-ca (gr8s.security::cluster-pki-ca-certificate pki)
                                                     :review (kubelet-test-review (list nil)))
                      :stats-function #'kubelet-test-node-stats))
             (port (hunchentoot:acceptor-port server))
             (stalled nil))
        ;; Worker threads read the global value.
        (setf gr8s.security::*tls-handshake-seconds* 1)
        (unwind-protect
             (progn
               ;; Connect and never send a ClientHello.
               (setf stalled (usocket:socket-connect "127.0.0.1" port :element-type '(unsigned-byte 8)))
               (sleep 2.5)
               ;; The server dropped that connection and still answers others.
               (is (null (sb-sys:with-deadline (:seconds 5)
                           (read-byte (usocket:socket-stream stalled) nil nil))))
               (is (= 401 (kubelet-test-get pki port "/metrics/resource"))))
          (setf gr8s.security::*tls-handshake-seconds* limit)
          (when stalled (ignore-errors (usocket:socket-close stalled)))
          (gr8s.apiserver::stop-kubelet-server server))))))

(test probe-metrics-follow-the-kubelet-prober
  (let* ((manager (gr8s.kubelet::make-container-probe-manager))
         (ready (gr8s.kubelet::make-container-probe-worker :kind "readinessProbe" :successes 2 :failures 0
                                                   :latencies (let ((histogram (gr8s.kubelet::make-bucketed-histogram
                                                                                gr8s.kubelet::+prometheus-default-buckets+)))
                                                                (gr8s.kubelet::observe-histogram histogram 0.003)
                                                                (gr8s.kubelet::observe-histogram histogram 0.2))))
         (live (gr8s.kubelet::make-container-probe-worker :kind "livenessProbe" :failures 1))
         (target (gr8s.kubelet::make-container-probe-target :uid "u-1" :name "app" :pod-name "web" :namespace "default"
                                                    :workers (list ready live))))
    (setf (gethash '("u-1" "app") (gr8s.kubelet::container-probe-manager-targets manager)) target)
    (let ((text (gr8s.apiserver::kubelet-probe-metrics-text manager)))
      (is (search "prober_probe_total{container=\"app\",namespace=\"default\",pod=\"web\",pod_uid=\"u-1\",probe_type=\"Readiness\",result=\"successful\"} 2" text))
      (is (search "prober_probe_total{container=\"app\",namespace=\"default\",pod=\"web\",pod_uid=\"u-1\",probe_type=\"Liveness\",result=\"failed\"} 1" text))
      ;; A result that never happened has no series.
      (is (not (search "result=\"failed\"} 0" text)))
      (is (search "# HELP prober_probe_total [BETA] Cumulative number of a liveness, readiness or startup probe for a container by result." text))
      (is (search "prober_probe_duration_seconds_bucket{container=\"app\",namespace=\"default\",pod=\"web\",probe_type=\"Readiness\",le=\"0.005\"} 1" text))
      (is (search "prober_probe_duration_seconds_bucket{container=\"app\",namespace=\"default\",pod=\"web\",probe_type=\"Readiness\",le=\"0.25\"} 2" text))
      (is (search "prober_probe_duration_seconds_count{container=\"app\",namespace=\"default\",pod=\"web\",probe_type=\"Readiness\"} 2" text))
      (is (not (search "probe_type=\"Liveness\",le=" text)))
      (is (search "# TYPE process_start_time_seconds gauge" text)))
    (is (search "process_start_time_seconds" (gr8s.apiserver::kubelet-probe-metrics-text nil)))
    (is (not (search "prober_probe_total" (gr8s.apiserver::kubelet-probe-metrics-text nil))))))

(test kubelet-serves-the-node-log-directory
  ;; The Node proxy's /logs/ reaches this file server, as upstream's kubelet serves /var/log.
  (with-kubelet-test-pki (pki directory)
    (gr8s.apiserver::issue-kubelet-credentials pki directory "node-a" '("127.0.0.1"))
    (let ((logs (uiop:ensure-directory-pathname (merge-pathnames "var-log/" directory))))
      (ensure-directories-exist (merge-pathnames "journal/.keep" logs))
      (with-open-file (out (merge-pathnames "messages" logs) :direction :output) (write-string "booted<ok>" out))
      (multiple-value-bind (certificate key) (gr8s.apiserver::kubelet-credential-paths directory)
        ;; Set, not bound: the listener's threads read the global value.
        (let* ((saved (shiftf gr8s.apiserver::*kubelet-log-directory* logs))
               (server (gr8s.apiserver::start-kubelet-server
                        :address "127.0.0.1" :port 0 :certificate certificate :key key :node-name "node-a"
                        :auth (gr8s.apiserver::make-kubelet-auth :client-ca (gr8s.security::cluster-pki-ca-certificate pki)
                                                       :review (kubelet-test-review (list nil)))
                        :stats-function #'kubelet-test-node-stats))
               (port (hunchentoot:acceptor-port server)))
          (unwind-protect
               (multiple-value-bind (client client-key) (gr8s.apiserver::ensure-apiserver-kubelet-client-credentials pki)
                 (let ((credentials (list client client-key)))
                   (multiple-value-bind (code text type) (kubelet-test-get pki port "/logs/" :client credentials)
                     (is (= 200 code))
                     (is (equal "text/html; charset=utf-8" type))
                     (is (search "<a href=\"journal/\">journal/</a>" text))
                     (is (search "<a href=\"messages\">messages</a>" text)))
                   (multiple-value-bind (code text) (kubelet-test-get pki port "/logs/messages" :client credentials)
                     (is (= 200 code))
                     (is (equal "booted<ok>" text)))
                   (is (= 404 (kubelet-test-get pki port "/logs/missing" :client credentials)))
                   (is (= 404 (kubelet-test-get pki port "/logs/../etc/passwd" :client credentials)))))
            (gr8s.apiserver::stop-kubelet-server server)
            (setf gr8s.apiserver::*kubelet-log-directory* saved)))))))
