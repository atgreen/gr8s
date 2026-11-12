;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Exercise the JIT-compiled Gateway API router: parsing stored HTTPRoute
;;;; objects into the normalized model, Gateway-API match precedence in the
;;;; compiled dispatch, weighted backend selection, and fail-closed rejection of
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
         (router (gr8s.controllers::compile-gateway-router routes)))
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
         (router (gr8s.controllers::compile-gateway-router routes)))
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
         (router (gr8s.controllers::compile-gateway-router routes)))
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

(test gateway-router-parse-and-compile-end-to-end
  (let* ((object (com.inuoe.jzon:parse
                  "{\"metadata\":{\"name\":\"app\",\"namespace\":\"shop\"},
                    \"spec\":{\"hostnames\":[\"shop.example.com\"],
                             \"rules\":[{\"matches\":[{\"path\":{\"type\":\"Exact\",\"value\":\"/health\"}}],
                                         \"backendRefs\":[{\"name\":\"health\",\"port\":80}]},
                                        {\"backendRefs\":[{\"name\":\"web\",\"port\":80}]}]}}"))
         (router (gr8s.controllers::compile-gateway-router (list (gr8s.controllers::parse-httproute object)))))
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
    (let ((dispatch (funcall (gr8s.controllers::compile-gateway-router (list route)) "any" "/x" "GET" '())))
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
