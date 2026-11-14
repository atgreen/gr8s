;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Pin the pure routing/boot-config logic of the embedded dashboard backend
;;;; (the headlamp-server-compatible contract gr8s serves under /dashboard/).

(in-package #:gr8s/tests)
(def-suite dashboard :in gr8s)
(in-suite dashboard)

(test dashboard-request-p-matches-only-the-mount
  (is-true (gr8s.apiserver::dashboard-request-p "/dashboard"))
  (is-true (gr8s.apiserver::dashboard-request-p "/dashboard/config"))
  (is-true (gr8s.apiserver::dashboard-request-p "/dashboard/clusters/gr8s/api/v1/pods"))
  ;; A sibling path that merely starts with the word must not match.
  (is-false (gr8s.apiserver::dashboard-request-p "/dashboards"))
  (is-false (gr8s.apiserver::dashboard-request-p "/api/v1/pods"))
  (is-false (gr8s.apiserver::dashboard-request-p "/")))

(test dashboard-cluster-proxy-strips-the-cluster-prefix
  ;; /dashboard/clusters/<name>/<api...> -> /<api...>, discarding <name>.
  (is (equal "/api/v1/pods"
             (gr8s.apiserver::dashboard-cluster-proxy-target-path
              "/dashboard/clusters/gr8s/api/v1/pods")))
  (is (equal "/apis/apps/v1/namespaces/default/deployments"
             (gr8s.apiserver::dashboard-cluster-proxy-target-path
              "/dashboard/clusters/anything/apis/apps/v1/namespaces/default/deployments")))
  ;; A bare cluster path has no api part.
  (is (equal "/" (gr8s.apiserver::dashboard-cluster-proxy-target-path "/dashboard/clusters/gr8s")))
  (is (equal "/" (gr8s.apiserver::dashboard-cluster-proxy-target-path "/dashboard/clusters/gr8s/")))
  ;; Non cluster-scoped dashboard paths are not proxied.
  (is (null (gr8s.apiserver::dashboard-cluster-proxy-target-path "/dashboard/config")))
  (is (null (gr8s.apiserver::dashboard-cluster-proxy-target-path "/api/v1/pods"))))

(test dashboard-config-has-the-fields-the-frontend-requires
  (let* ((json (gr8s.apiserver::dashboard-config-json))
         (config (com.inuoe.jzon:parse json))
         (clusters (gethash "clusters" config)))
    ;; Boot config exposes exactly one cluster with the load-bearing snake_case keys.
    (is (vectorp clusters))
    (is (= 1 (length clusters)))
    (let ((cluster (aref clusters 0)))
      (is (equal "gr8s" (gethash "name" cluster)))
      ;; auth_type and meta_data must be spelled snake_case for the frontend.
      (is-true (nth-value 1 (gethash "auth_type" cluster)))
      (is (equal "kubeconfig" (gethash "source" (gethash "meta_data" cluster)))))
    ;; The boolean toggles the frontend checks at boot are present and false
    ;; (jzon parses JSON false to NIL).
    (dolist (key '("isDynamicClusterEnabled" "allowKubeconfigChanges" "oidcAutoLogin"))
      (is-true (nth-value 1 (gethash key config)) "~A present" key)
      (is-false (gethash key config) "~A is false" key))))

(test dashboard-content-type-maps-extensions
  (is (equal "text/javascript; charset=utf-8" (gr8s.apiserver::dashboard-content-type "main.js")))
  (is (equal "text/html; charset=utf-8" (gr8s.apiserver::dashboard-content-type "index.html")))
  (is (equal "text/css; charset=utf-8" (gr8s.apiserver::dashboard-content-type "static/css/a.b.css")))
  (is (equal "font/woff2" (gr8s.apiserver::dashboard-content-type "x.woff2")))
  (is (equal "application/octet-stream" (gr8s.apiserver::dashboard-content-type "noext"))))

(test dashboard-index-rewrite-applies-the-base-url
  ;; Mirrors headlamp-server's makeBaseURLReplacements for base /dashboard.
  ;; Headlamp's own replacements assume url() imports have no "./" in them (its
  ;; comment says so), so the test mirrors that: "./" on script refs, bare url().
  (let* ((in (trivial-utf-8:string-to-utf-8-bytes
              "headlampBaseUrl = __baseUrl__; <script src=\"./static/x.js\"></script> url(fonts/f.woff2)"))
         (out (trivial-utf-8:utf-8-bytes-to-string (gr8s.apiserver::dashboard-rewrite-index in))))
    (is-true (search "headlampBaseUrl = '/dashboard'" out))
    (is-false (search "__baseUrl__" out))
    (is-true (search "\"/dashboard/static/x.js\"" out))
    (is-true (search "url(/dashboard/fonts/f.woff2)" out))))

(test dashboard-browse-url-targets-the-mount
  (is (equal "http://127.0.0.1:8080/dashboard/"
             (gr8s.server::dashboard-browse-url "http://127.0.0.1:8080")))
  ;; A trailing slash on the server is not doubled.
  (is (equal "https://host:6443/dashboard/"
             (gr8s.server::dashboard-browse-url "https://host:6443/"))))
