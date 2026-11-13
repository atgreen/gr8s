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
