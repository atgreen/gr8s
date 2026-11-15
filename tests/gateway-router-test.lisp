;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Exercise the hostname-indexed Gateway API router: parsing stored HTTPRoute
;;;; objects into the normalized model, Gateway-API match precedence in the
;;;; table dispatch, weighted backend selection, and fail-closed rejection of
;;;; unsupported match constructs.

(in-package #:gr8s/tests)
(def-suite gateway-router :in gr8s)
(in-suite gateway-router)

(defun gwr-route (namespace hostnames &rest rules)
  (gr8s.controllers::make-gw-route :namespace namespace :hostnames hostnames :rules rules))

(defun gwr-rule (matches backends)
  (gr8s.controllers::make-gw-rule :matches matches :backends backends))

(defun gwr-backend (name &key (port 80) (weight 1) namespace)
  (gr8s.controllers::make-gw-backend :name name :port port :weight weight :namespace namespace))

(defun gwr-dispatch-name (dispatch)
  "The chosen backend name of a router dispatch result, or NIL."
  (and dispatch
       (let ((backend (gr8s.controllers::gw-dispatch-backend dispatch)))
         (and backend (gr8s.controllers::gw-backend-name backend)))))

(test gateway-router-honors-match-precedence
  (let* ((routes
           (list
            (gwr-route "default" '("api.example.com")
                       (gwr-rule (list (gr8s.controllers::make-gw-match :path-type :exact :path "/health" :method "GET"))
                                 (list (gwr-backend "health-svc")))
                       (gwr-rule (list (gr8s.controllers::make-gw-match :path-type :prefix :path "/v1"))
                                 (list (gwr-backend "api-v1-svc")))
                       (gwr-rule (list (gr8s.controllers::make-gw-match :path-type :prefix :path "/"))
                                 (list (gwr-backend "api-default-svc"))))
            (gwr-route "default" '("*.example.com")
                       (gwr-rule (list (gr8s.controllers::make-gw-match :path-type :prefix :path "/"))
                                 (list (gwr-backend "wildcard-svc"))))))
         (router (gr8s.controllers::build-gateway-router routes)))
    (flet ((route (host path method) (gwr-dispatch-name (funcall router host path method '()))))
      (is (equal "health-svc"      (route "api.example.com" "/health" "GET")))
      (is (equal "api-default-svc" (route "api.example.com" "/health" "POST"))) ; non-GET falls through
      (is (equal "api-v1-svc"      (route "api.example.com" "/v1/users" "GET"))) ; longer prefix wins
      (is (equal "api-default-svc" (route "api.example.com" "/v1x" "GET")))      ; segment boundary
      (is (equal "api-default-svc" (route "api.example.com" "/status" "GET")))
      (is (equal "api-default-svc" (route "api.example.com" "/" "GET")))         ; exact host beats wildcard
      (is (equal "wildcard-svc"    (route "foo.example.com" "/x" "GET")))
      (is (null                    (route "nope.org" "/x" "GET"))))))            ; unmatched -> 404

(test gateway-router-selects-weighted-backends
  (let* ((routes (list (gwr-route "default" '("split.example.com")
                                  (gwr-rule (list (gr8s.controllers::make-gw-match :path-type :prefix :path "/"))
                                            (list (gwr-backend "v2" :weight 3)
                                                  (gwr-backend "v1" :weight 1))))))
         (router (gr8s.controllers::build-gateway-router routes)))
    (let ((gr8s.controllers::*gw-weighted-pick* (lambda (total) (declare (ignore total)) 0)))
      (is (equal "v2" (gwr-dispatch-name (funcall router "split.example.com" "/a" "GET" '())))))
    (let ((gr8s.controllers::*gw-weighted-pick* (lambda (total) (declare (ignore total)) 3)))
      (is (equal "v1" (gwr-dispatch-name (funcall router "split.example.com" "/a" "GET" '())))))))

(test gateway-router-matches-exact-headers
  (let* ((routes (list (gwr-route "default" '("h.example.com")
                                  (gwr-rule (list (gr8s.controllers::make-gw-match
                                                   :path-type :prefix :path "/"
                                                   :headers '(("x-canary" . "yes"))))
                                            (list (gwr-backend "canary-svc"))))))
         (router (gr8s.controllers::build-gateway-router routes)))
    (is (equal "canary-svc"
               (gwr-dispatch-name (funcall router "h.example.com" "/x" "GET" '(("X-Canary" . "yes"))))))
    (is (null (funcall router "h.example.com" "/x" "GET" '(("x-canary" . "no")))))
    (is (null (funcall router "h.example.com" "/x" "GET" '())))))

(test gateway-router-parses-stored-httproute
  (let* ((object (com.inuoe.jzon:parse
                  "{\"apiVersion\":\"gateway.networking.k8s.io/v1\",\"kind\":\"HTTPRoute\",
                    \"metadata\":{\"name\":\"app\",\"namespace\":\"shop\"},
                    \"spec\":{\"hostnames\":[\"shop.example.com\"],
                             \"rules\":[{\"matches\":[{\"path\":{\"type\":\"PathPrefix\",\"value\":\"/cart\"},\"method\":\"POST\"}],
                                         \"backendRefs\":[{\"name\":\"cart\",\"port\":8080,\"weight\":2},
                                                          {\"name\":\"cart-canary\",\"port\":8080,\"weight\":1}]},
                                        {\"backendRefs\":[{\"name\":\"web\",\"port\":80}]}]}}"))
         (route (gr8s.controllers::parse-httproute object)))
    (is (equal "shop" (gr8s.controllers::gw-route-namespace route)))
    (is (equal '("shop.example.com") (gr8s.controllers::gw-route-hostnames route)))
    (is (= 2 (length (gr8s.controllers::gw-route-rules route))))
    (let* ((rule1 (first (gr8s.controllers::gw-route-rules route)))
           (match (first (gr8s.controllers::gw-rule-matches rule1)))
           (b1 (first (gr8s.controllers::gw-rule-backends rule1))))
      (is (eq :prefix (gr8s.controllers::gw-match-path-type match)))
      (is (equal "/cart" (gr8s.controllers::gw-match-path match)))
      (is (equal "POST" (gr8s.controllers::gw-match-method match)))
      (is (= 2 (length (gr8s.controllers::gw-rule-backends rule1))))
      (is (equal "cart" (gr8s.controllers::gw-backend-name b1)))
      (is (= 8080 (gr8s.controllers::gw-backend-port b1)))
      (is (= 2 (gr8s.controllers::gw-backend-weight b1)))
      (is (equal "shop" (gr8s.controllers::gw-backend-namespace b1))))   ; default to the route's namespace
    (let* ((rule2 (second (gr8s.controllers::gw-route-rules route)))
           (match (first (gr8s.controllers::gw-rule-matches rule2))))
      ;; A rule with no matches defaults to PathPrefix "/".
      (is (eq :prefix (gr8s.controllers::gw-match-path-type match)))
      (is (equal "/" (gr8s.controllers::gw-match-path match)))
      (is (equal 1 (gr8s.controllers::gw-backend-weight (first (gr8s.controllers::gw-rule-backends rule2))))))))

(test gateway-router-prefix-trailing-slash-matches-segments
  ;; Mirrors the Gateway-API HTTPRoutePathMatchOrder conformance route, whose
  ;; PathPrefix values carry a trailing slash ("/match/", "/match/prefix/").
  ;; Per spec the trailing slash is not significant and matching is on segment
  ;; boundaries, so "/match/any" must reach the "/match/" prefix backend.
  (let* ((object (com.inuoe.jzon:parse
                  "{\"metadata\":{\"name\":\"path-matching-order\",\"namespace\":\"infra\"},
                    \"spec\":{\"rules\":[
                      {\"matches\":[{\"path\":{\"type\":\"Exact\",\"value\":\"/match\"}}],\"backendRefs\":[{\"name\":\"v1\",\"port\":80}]},
                      {\"matches\":[{\"path\":{\"type\":\"Exact\",\"value\":\"/match/exact\"}}],\"backendRefs\":[{\"name\":\"v2\",\"port\":80}]},
                      {\"matches\":[{\"path\":{\"type\":\"Exact\",\"value\":\"/match/exact/one\"}}],\"backendRefs\":[{\"name\":\"v3\",\"port\":80}]},
                      {\"matches\":[{\"path\":{\"type\":\"PathPrefix\",\"value\":\"/match/\"}}],\"backendRefs\":[{\"name\":\"v3\",\"port\":80}]},
                      {\"matches\":[{\"path\":{\"type\":\"PathPrefix\",\"value\":\"/match/prefix/\"}}],\"backendRefs\":[{\"name\":\"v1\",\"port\":80}]},
                      {\"matches\":[{\"path\":{\"type\":\"PathPrefix\",\"value\":\"/match/prefix/one\"}}],\"backendRefs\":[{\"name\":\"v2\",\"port\":80}]}]}}"))
         (router (gr8s.controllers::build-gateway-router (list (gr8s.controllers::parse-httproute object)))))
    (flet ((route (path) (let ((d (funcall router "any" path "GET" '()))) (and d (gwr-dispatch-name d)))))
      (is (equal "v1" (route "/match")))            ; exact
      (is (equal "v2" (route "/match/exact")))       ; exact beats prefix
      (is (equal "v3" (route "/match/exact/one")))   ; most specific exact
      (is (equal "v3" (route "/match/any")))         ; trailing-slash prefix "/match/" on a deeper path
      (is (equal "v3" (route "/match/exact/two")))   ; falls to "/match/" prefix, not the exact
      (is (equal "v1" (route "/match/prefix/any")))  ; longer prefix "/match/prefix/" wins
      (is (equal "v2" (route "/match/prefix/one")))  ; longest prefix "/match/prefix/one"
      (is (equal "v2" (route "/match/prefix/one/x"))))))

(test gateway-router-parse-and-build-end-to-end
  (let* ((object (com.inuoe.jzon:parse
                  "{\"metadata\":{\"name\":\"app\",\"namespace\":\"shop\"},
                    \"spec\":{\"hostnames\":[\"shop.example.com\"],
                             \"rules\":[{\"matches\":[{\"path\":{\"type\":\"Exact\",\"value\":\"/health\"}}],
                                         \"backendRefs\":[{\"name\":\"health\",\"port\":80}]},
                                        {\"backendRefs\":[{\"name\":\"web\",\"port\":80}]}]}}"))
         (router (gr8s.controllers::build-gateway-router (list (gr8s.controllers::parse-httproute object)))))
    (is (equal "health" (gwr-dispatch-name (funcall router "shop.example.com" "/health" "GET" '()))))
    (is (equal "web"    (gwr-dispatch-name (funcall router "shop.example.com" "/other" "GET" '()))))
    (is (null (funcall router "nope.example.com" "/health" "GET" '())))))

(test gateway-router-parses-rule-filters
  (let* ((object (com.inuoe.jzon:parse
                  "{\"metadata\":{\"name\":\"f\",\"namespace\":\"d\"},
                    \"spec\":{\"rules\":[{\"filters\":[
                                {\"type\":\"RequestHeaderModifier\",\"requestHeaderModifier\":{\"set\":[{\"name\":\"X-A\",\"value\":\"1\"}],\"remove\":[\"X-B\"]}},
                                {\"type\":\"URLRewrite\",\"urlRewrite\":{\"path\":{\"type\":\"ReplacePrefixMatch\",\"replacePrefixMatch\":\"/v2\"}}},
                                {\"type\":\"RequestRedirect\",\"requestRedirect\":{\"scheme\":\"https\",\"statusCode\":301}}],
                              \"backendRefs\":[{\"name\":\"svc\",\"port\":80}]}]}}"))
         (route (gr8s.controllers::parse-httproute object))
         (filters (gr8s.controllers::gw-rule-filters (first (gr8s.controllers::gw-route-rules route)))))
    (is (= 3 (length filters)))
    (let ((hdr (find :request-headers filters :key #'gr8s.controllers::gw-filter-type)))
      (is (equal '(("X-A" . "1")) (getf (gr8s.controllers::gw-filter-data hdr) :set)))
      (is (equal '("X-B") (getf (gr8s.controllers::gw-filter-data hdr) :remove))))
    (let ((rw (find :rewrite filters :key #'gr8s.controllers::gw-filter-type)))
      (is (eq :prefix (getf (getf (gr8s.controllers::gw-filter-data rw) :path) :type)))
      (is (equal "/v2" (getf (getf (gr8s.controllers::gw-filter-data rw) :path) :value))))
    (let ((rd (find :redirect filters :key #'gr8s.controllers::gw-filter-type)))
      (is (equal "https" (getf (gr8s.controllers::gw-filter-data rd) :scheme)))
      (is (= 301 (getf (gr8s.controllers::gw-filter-data rd) :status-code))))))

(test gateway-router-parses-name-and-rate-limit
  (let* ((object (com.inuoe.jzon:parse
                  "{\"metadata\":{\"name\":\"shop\",\"namespace\":\"store\",
                     \"annotations\":{\"gr8s.io/rate-limit-rps\":\"50\"}},
                    \"spec\":{\"rules\":[{\"backendRefs\":[{\"name\":\"svc\",\"port\":80}]}]}}"))
         (route (gr8s.controllers::parse-httproute object)))
    (is (equal "shop" (gr8s.controllers::gw-route-name route)))
    (is (equal 50 (gr8s.controllers::gw-route-rate-limit route)))
    (let ((dispatch (funcall (gr8s.controllers::build-gateway-router (list route)) "any" "/x" "GET" '())))
      (is (equal "shop" (gr8s.controllers::gw-dispatch-route-name dispatch)))
      (is (equal "store/shop" (gr8s.controllers::gw-dispatch-route-key dispatch)))
      (is (equal 50 (gr8s.controllers::gw-dispatch-rate-limit dispatch))))))

(test gateway-router-rejects-unsupported-matches
  (signals gr8s.controllers::gateway-route-error
    (gr8s.controllers::parse-httproute
     (com.inuoe.jzon:parse
      "{\"metadata\":{\"name\":\"r\",\"namespace\":\"d\"},
        \"spec\":{\"rules\":[{\"matches\":[{\"path\":{\"type\":\"RegularExpression\",\"value\":\"/x.*\"}}],
                              \"backendRefs\":[{\"name\":\"s\",\"port\":80}]}]}}")))
  (signals gr8s.controllers::gateway-route-error
    (gr8s.controllers::parse-httproute
     (com.inuoe.jzon:parse
      "{\"metadata\":{\"name\":\"r\",\"namespace\":\"d\"},
        \"spec\":{\"rules\":[{\"backendRefs\":[{\"name\":\"s\"}]}]}}"))))  ; backendRef without a port

(test gateway-router-falls-through-host-buckets
  (let* ((routes
           (loop for (hosts path method headers backend) in
                 '((("api.team.example.com") "/exact" "POST" (("x-mode" . "on")) "exact")
                   (("*.team.example.com") "/team" nil nil "team")
                   (("*.example.com") "/wide" nil nil "wide")
                   (nil "/" nil nil "default"))
                 collect (gwr-route "default" hosts
                           (gwr-rule (list (gr8s.controllers::make-gw-match
                                            :path path :method method :headers headers))
                                     (list (gwr-backend backend))))))
         (router (gr8s.controllers::build-gateway-router routes)))
    (flet ((pick (host path &optional (method "GET") headers)
             (gwr-dispatch-name (funcall router host path method headers))))
      (is (equal "exact" (pick "api.team.example.com" "/exact" "post" '(("X-Mode" . "on")))))
      (is (equal "default" (pick "api.team.example.com" "/exact" "POST" '(("x-mode" . "ON")))))
      (is (equal "team" (pick "api.team.example.com" "/team")))
      (is (equal "wide" (pick "api.team.example.com" "/wide")))
      (is (equal "wide" (pick "team.example.com" "/wide")))
      (is (equal "default" (pick "example.com" "/wide")))
      (is (equal "default" (pick "team.example.com" "/team")))
      (is (equal "default" (pick "api.team.example.com" "/teamwork")))
      (is (equal "default" (pick "unrelated.org" "/anything"))))))

(test gateway-router-preserves-ties-and-independent-tables
  (let* ((first (gwr-route "d" '("a.example.com" "b.example.com")
                 (gwr-rule (list (gr8s.controllers::make-gw-match)) (list (gwr-backend "first")))))
         (second (gwr-route "d" '("a.example.com")
                  (gwr-rule (list (gr8s.controllers::make-gw-match)) (list (gwr-backend "second")))))
         (old (gr8s.controllers::build-gateway-router (list first second)))
         (new (gr8s.controllers::build-gateway-router (list second)))
         (empty (gr8s.controllers::build-gateway-router nil)))
    (is (equal "first" (gwr-dispatch-name (funcall old "a.example.com" "/" "GET" nil))))
    (is (equal "first" (gwr-dispatch-name (funcall old "b.example.com" "/" "GET" nil))))
    (is (equal "second" (gwr-dispatch-name (funcall new "a.example.com" "/" "GET" nil))))
    (is (null (funcall new "b.example.com" "/" "GET" nil)))
    (is (null (funcall empty "a.example.com" "/" "GET" nil)))))
