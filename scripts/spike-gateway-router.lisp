;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Spike (podster-43k.1): JIT-compile a Gateway API HTTPRoute set into a NATIVE
;;;; Lisp dispatch function. This proves the thesis behind gr8s's Gateway API: the
;;;; routing table is not interpreted per request -- it is compiled, with the
;;;; route constants inlined and Gateway-API precedence baked into branch order,
;;;; via SBCL's (compile nil form). Routes change -> recompile (microseconds, no
;;;; restart, no eBPF verifier). Self-contained; run:
;;;;
;;;;   sbcl --noinform --script scripts/spike-gateway-router.lisp
;;;;
;;;; Scope: hostnames (exact + "*.suffix" wildcard), path Exact/PathPrefix,
;;;; method, exact header matches, and weighted backends -- enough to exercise
;;;; Gateway-API match precedence and the compile/recompile loop. TLS, filters,
;;;; and the eBPF fast path are separate epic children.

(defpackage #:gw-router-spike (:use #:cl))
(in-package #:gw-router-spike)

;;; ---------------------------------------------------------------------------
;;; Normalized model (a subset of Gateway API HTTPRoute).

(defstruct backend (name "" :type string) (weight 1 :type integer))

(defstruct match
  (path-type :prefix)                 ; :prefix | :exact
  (path "/" :type string)
  (method nil)                        ; nil | "GET" ...
  (headers '() :type list))           ; alist (header-name . value), exact

(defstruct rule
  (matches '() :type list)            ; list of MATCH (any match -> rule applies)
  (backends '() :type list))          ; list of BACKEND (weighted)

(defstruct httproute
  (hostnames '() :type list)          ; "api.example.com" or "*.example.com"; () = all
  (rules '() :type list))             ; list of RULE

;;; ---------------------------------------------------------------------------
;;; Runtime helpers (compiled once; the generated dispatch calls these with the
;;; route constants inlined at the call sites).

(declaim (inline path-prefix-match-p))
(defun path-prefix-match-p (path prefix)
  "Gateway-API PathPrefix: match only at a path-segment boundary."
  (let ((pl (length prefix)) (xl (length path)))
    (and (>= xl pl)
         (string= path prefix :end1 pl)
         (or (= xl pl) (string= prefix "/") (char= (char path pl) #\/)))))

(defun header-match-p (headers name value)
  (let ((cell (assoc name headers :test #'string-equal)))
    (and cell (string= (cdr cell) value))))

(defvar *weighted-pick* nil
  "Optional (lambda (total) -> [0,total)) override for deterministic tests;
NIL uses cl:random.")

(defun pick-weighted (backends)
  "Choose a backend name by weight. Single-backend rules are deterministic."
  (if (null (cdr backends))
      (backend-name (first backends))
      (let* ((total (reduce #'+ backends :key #'backend-weight))
             (r (if (plusp total)
                    (if *weighted-pick* (funcall *weighted-pick* total) (random total))
                    0)))
        (loop with acc = 0 for b in backends
              do (incf acc (backend-weight b))
              when (< r acc) return (backend-name b)
              finally (return (backend-name (first backends)))))))

;;; ---------------------------------------------------------------------------
;;; Precedence. Each (route, rule, match) becomes a candidate; candidates are
;;; ordered by Gateway-API precedence so the generated COND tries them in order
;;; and the first hit wins.

(defun host-tier (hostname)            ; higher = more specific
  (cond ((null hostname) 0)
        ((and (> (length hostname) 2) (string= hostname "*." :end1 2)) 1) ; wildcard
        (t 2)))                        ; exact

(defun host-nonwild-length (hostname)
  (cond ((null hostname) 0)
        ((= 1 (host-tier hostname)) (- (length hostname) 2)) ; drop "*."
        (t (length hostname))))

(defstruct candidate hostname match backends key)

(defun candidate-precedence (hostname match)
  "Descending-sort key per Gateway-API precedence: hostname specificity, then
path (Exact > longer PathPrefix), then method present, then #headers."
  (list (host-tier hostname)
        (host-nonwild-length hostname)
        (if (eq (match-path-type match) :exact) 2 1)
        (length (match-path match))
        (if (match-method match) 1 0)
        (length (match-headers match))))

(defun key> (a b)
  (loop for x in a for y in b
        when (> x y) return t
        when (< x y) return nil
        finally (return nil)))

(defun route-candidates (routes)
  (let ((cands '()))
    (dolist (r routes)
      (dolist (rule (httproute-rules r))
        (dolist (m (rule-matches rule))
          (dolist (host (or (httproute-hostnames r) (list nil)))
            (push (make-candidate :hostname host :match m
                                  :backends (rule-backends rule)
                                  :key (candidate-precedence host m))
                  cands)))))
    (stable-sort (nreverse cands) #'key> :key #'candidate-key)))

;;; ---------------------------------------------------------------------------
;;; The compiler: candidates -> a Lisp form -> a NATIVE function via (compile).

(defun host-test-form (hostname)
  (cond ((null hostname) t)
        ((= 1 (host-tier hostname))
         (let ((suffix (subseq hostname 1)))   ; "*.example.com" -> ".example.com"
           `(let ((h host))
              (and (> (length h) ,(length suffix))
                   (string= h ,suffix :start1 (- (length h) ,(length suffix)))))))
        (t `(string= host ,hostname))))

(defun match-test-form (match)
  `(and ,(ecase (match-path-type match)
           (:exact `(string= path ,(match-path match)))
           (:prefix `(path-prefix-match-p path ,(match-path match))))
        ,@(when (match-method match) `((string-equal method ,(match-method match))))
        ,@(loop for (name . value) in (match-headers match)
                collect `(header-match-p headers ,name ,value))))

(defun candidate-clause (candidate)
  ;; The backends vector is captured as a literal; pick-weighted selects at call
  ;; time (deterministic for single-backend rules).
  `((and ,(host-test-form (candidate-hostname candidate))
         ,(match-test-form (candidate-match candidate)))
    (pick-weighted ',(candidate-backends candidate))))

(defun compile-gateway-router (routes)
  "Compile ROUTES into a native function (host path method headers) -> backend
name string, or NIL when nothing matches (the caller serves 404)."
  (let ((form `(lambda (host path method headers)
                 (declare (ignorable host path method headers)
                          (optimize (speed 2) (safety 1)))
                 (cond ,@(mapcar #'candidate-clause (route-candidates routes))
                       (t nil)))))
    (values (compile nil form) form)))

;;; ---------------------------------------------------------------------------
;;; Demo + assertions.

(defvar *failures* 0)
(defun check (label got expected)
  (if (equal got expected)
      (format t "  ok   ~A -> ~S~%" label got)
      (progn (incf *failures*)
             (format t "  FAIL ~A -> got ~S, expected ~S~%" label got expected))))

(defun run ()
  (let* ((routes
           (list
            (make-httproute
             :hostnames '("api.example.com")
             :rules (list
                     ;; Exact /health GET -> health-svc (most specific).
                     (make-rule :matches (list (make-match :path-type :exact :path "/health" :method "GET"))
                                :backends (list (make-backend :name "health-svc")))
                     ;; PathPrefix /v1 -> api-v1-svc.
                     (make-rule :matches (list (make-match :path-type :prefix :path "/v1"))
                                :backends (list (make-backend :name "api-v1-svc")))
                     ;; PathPrefix / -> api-default-svc.
                     (make-rule :matches (list (make-match :path-type :prefix :path "/"))
                                :backends (list (make-backend :name "api-default-svc")))))
            ;; Wildcard host, catch-all.
            (make-httproute
             :hostnames '("*.example.com")
             :rules (list (make-rule :matches (list (make-match :path-type :prefix :path "/"))
                                     :backends (list (make-backend :name "wildcard-svc")))))
            ;; Weighted split on a specific host+path.
            (make-httproute
             :hostnames '("split.example.com")
             :rules (list (make-rule :matches (list (make-match :path-type :prefix :path "/"))
                                     :backends (list (make-backend :name "v2" :weight 3)
                                                     (make-backend :name "v1" :weight 1))))))))
    (multiple-value-bind (router form) (compile-gateway-router routes)
      (declare (ignore form))
      (format t "~%=== JIT-compiled Gateway router ===~%")
      (format t "compiled-function-p: ~A~%" (compiled-function-p router))
      (format t "--- routing (precedence) ---~%")
      (check "exact /health beats prefixes"
             (funcall router "api.example.com" "/health" "GET" '()) "health-svc")
      (check "/health non-GET falls through to /v1? no -> default"
             (funcall router "api.example.com" "/health" "POST" '()) "api-default-svc")
      (check "longer prefix /v1 beats /"
             (funcall router "api.example.com" "/v1/users" "GET" '()) "api-v1-svc")
      (check "prefix boundary: /v1x is NOT under /v1"
             (funcall router "api.example.com" "/v1x" "GET" '()) "api-default-svc")
      (check "other path -> default"
             (funcall router "api.example.com" "/status" "GET" '()) "api-default-svc")
      (check "exact host beats wildcard"
             (funcall router "api.example.com" "/" "GET" '()) "api-default-svc")
      (check "wildcard host matches other subdomain"
             (funcall router "foo.example.com" "/x" "GET" '()) "wildcard-svc")
      (check "unmatched host -> nil (404)"
             (funcall router "nope.org" "/x" "GET" '()) nil)
      (format t "--- weighted split (deterministic via *weighted-pick*) ---~%")
      (let ((*weighted-pick* (lambda (total) (declare (ignore total)) 0))) ; r=0 -> first bucket
        (check "weight pick r=0 -> v2" (funcall router "split.example.com" "/a" "GET" '()) "v2"))
      (let ((*weighted-pick* (lambda (total) (declare (ignore total)) 3))) ; r=3 -> last bucket
        (check "weight pick r=3 -> v1" (funcall router "split.example.com" "/a" "GET" '()) "v1"))
      (format t "--- recompile on route change (drop the /v1 rule) ---~%")
      (let* ((changed (list (make-httproute
                             :hostnames '("api.example.com")
                             :rules (list (make-rule :matches (list (make-match :path-type :prefix :path "/"))
                                                     :backends (list (make-backend :name "api-default-svc")))))))
             (router2 (compile-gateway-router changed)))
        (check "after recompile, /v1/users -> default"
               (funcall router2 "api.example.com" "/v1/users" "GET" '()) "api-default-svc"))
      (format t "~%RESULT: ~:[ALL CHECKS PASSED~;~:*~D CHECK(S) FAILED~]~%" (when (plusp *failures*) *failures*))
      (unless (compiled-function-p router)
        (incf *failures*) (format t "RESULT: router is not a compiled function!~%")))
    (sb-ext:exit :code (if (plusp *failures*) 1 0))))

(run)
