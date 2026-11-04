;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; The Gateway API routing table, JIT-compiled into a native dispatch function.
;;;; A set of HTTPRoutes (normalized from their stored gateway.networking.k8s.io
;;;; /v1 objects) becomes a Lisp COND whose clauses are ordered by Gateway-API
;;;; match precedence and whose route constants are inlined, then handed to
;;;; (compile nil form) -- so the per-request hot path is native code, not an
;;;; interpreted walk of the table. Routes change -> recompile (microseconds, no
;;;; restart). Proven in scripts/spike-gateway-router.lisp (podster-43k.1); this
;;;; is the production module it became.
;;;;
;;;; Scope here (podster-43k.4): hostnames (exact + "*.suffix" wildcard), path
;;;; Exact/PathPrefix, method, exact header matches, and weighted backends. TLS,
;;;; HTTP filters (header/redirect/rewrite/mirror) and the eBPF fast path are
;;;; separate epic children.

(in-package #:gr8s)

;;; ---------------------------------------------------------------------------
;;; Normalized model (a subset of HTTPRoute, independent of the stored JSON).

(defstruct gw-backend
  (name "" :type string)
  (namespace nil)                       ; nil = the route's own namespace
  (port 0 :type integer)
  (weight 1 :type integer))

(defstruct gw-match
  (path-type :prefix)                   ; :prefix | :exact
  (path "/" :type string)
  (method nil)                          ; nil | "GET" ...
  (headers '() :type list))             ; alist (name . value), exact

(defstruct gw-rule
  (matches '() :type list)              ; list of GW-MATCH (any match -> rule applies)
  (backends '() :type list))            ; list of GW-BACKEND (weighted)

(defstruct gw-route
  (namespace nil)                       ; the HTTPRoute's namespace (backendRef default)
  (hostnames '() :type list)            ; "api.example.com" / "*.example.com"; () = all
  (rules '() :type list))               ; list of GW-RULE

;;; ---------------------------------------------------------------------------
;;; Parse a stored HTTPRoute object (jzon hash-table) into a GW-ROUTE.

(define-condition gateway-route-error (error)
  ((message :initarg :message :reader gateway-route-error-message))
  (:report (lambda (c s) (format s "~A" (gateway-route-error-message c)))))

(defun gw-route-error (fmt &rest args)
  (error 'gateway-route-error :message (apply #'format nil fmt args)))

(defun gw-string-list (value)
  "Coerce a JSON string array (or nil) into a list of strings."
  (when value
    (unless (and (vectorp value) (not (stringp value)))
      (gw-route-error "expected a string array"))
    (coerce value 'list)))

(defun gw-parse-path (match-object)
  "Return (values path-type path) from an HTTPRoute match's path object.
   Defaults to PathPrefix \"/\" when absent (Gateway-API default)."
  (let ((path (gethash "path" match-object)))
    (if (null path)
        (values :prefix "/")
        (let ((type (or (gethash "type" path) "PathPrefix"))
              (value (or (gethash "value" path) "/")))
          (cond ((equal type "Exact") (values :exact value))
                ((equal type "PathPrefix") (values :prefix value))
                (t (gw-route-error "unsupported HTTPRoute path match type ~S" type)))))))

(defun gw-parse-headers (match-object)
  "Return an alist of (name . value) from a match's exact header matches."
  (let ((headers (gethash "headers" match-object)))
    (when headers
      (loop for h across headers
            for type = (or (gethash "type" h) "Exact")
            unless (equal type "Exact")
              do (gw-route-error "unsupported HTTPRoute header match type ~S" type)
            collect (cons (or (gethash "name" h) (gw-route-error "header match needs a name"))
                          (or (gethash "value" h) ""))))))

(defun gw-parse-match (match-object)
  (multiple-value-bind (path-type path) (gw-parse-path match-object)
    (make-gw-match :path-type path-type :path path
                   :method (gethash "method" match-object)
                   :headers (gw-parse-headers match-object))))

(defun gw-parse-backend (ref route-namespace)
  (make-gw-backend
   :name (or (gethash "name" ref) (gw-route-error "backendRef needs a name"))
   :namespace (or (gethash "namespace" ref) route-namespace)
   :port (or (gethash "port" ref) (gw-route-error "backendRef ~S needs a port" (gethash "name" ref)))
   :weight (let ((w (gethash "weight" ref))) (if w w 1))))

(defun gw-parse-rule (rule-object route-namespace)
  (let* ((matches (gethash "matches" rule-object))
         (backend-refs (gethash "backendRefs" rule-object)))
    (make-gw-rule
     ;; No matches -> the Gateway-API default of PathPrefix "/".
     :matches (if (and matches (plusp (length matches)))
                  (map 'list #'gw-parse-match matches)
                  (list (make-gw-match :path-type :prefix :path "/")))
     :backends (when backend-refs
                 (map 'list (lambda (r) (gw-parse-backend r route-namespace)) backend-refs)))))

(defun parse-httproute (object)
  "Normalize a stored HTTPRoute (gateway.networking.k8s.io/v1) into a GW-ROUTE.
   Signals GATEWAY-ROUTE-ERROR on unsupported constructs (fail closed)."
  (let* ((metadata (gethash "metadata" object))
         (namespace (and metadata (gethash "namespace" metadata)))
         (spec (gethash "spec" object))
         (rules (and spec (gethash "rules" spec))))
    (make-gw-route
     :namespace namespace
     :hostnames (gw-string-list (and spec (gethash "hostnames" spec)))
     :rules (when rules (map 'list (lambda (r) (gw-parse-rule r namespace)) rules)))))

;;; ---------------------------------------------------------------------------
;;; Runtime helpers (compiled once; the generated dispatch inlines the route
;;; constants at the call sites and calls these).

(declaim (inline gw-path-prefix-match-p))
(defun gw-path-prefix-match-p (path prefix)
  "Gateway-API PathPrefix: match only at a path-segment boundary."
  (let ((pl (length prefix)) (xl (length path)))
    (and (>= xl pl)
         (string= path prefix :end1 pl)
         (or (= xl pl) (string= prefix "/") (char= (char path pl) #\/)))))

(defun gw-header-match-p (headers name value)
  "HEADERS is an alist of (name . value) from the request (case-insensitive name)."
  (let ((cell (assoc name headers :test #'string-equal)))
    (and cell (string= (cdr cell) value))))

(defvar *gw-weighted-pick* nil
  "Optional (lambda (total) -> [0,total)) override for deterministic tests;
NIL uses cl:random.")

(defun gw-pick-weighted (backends)
  "Choose a GW-BACKEND by weight. Single-backend rules are deterministic.
   Returns NIL when there are no backends (the caller serves 5xx)."
  (cond ((null backends) nil)
        ((null (cdr backends)) (first backends))
        (t (let* ((total (reduce #'+ backends :key #'gw-backend-weight))
                  (r (if (plusp total)
                         (if *gw-weighted-pick* (funcall *gw-weighted-pick* total) (random total))
                         0)))
             (loop with acc = 0 for b in backends
                   do (incf acc (gw-backend-weight b))
                   when (< r acc) return b
                   finally (return (first backends)))))))

;;; ---------------------------------------------------------------------------
;;; Precedence. Each (route, rule, match, host) is a candidate; candidates are
;;; ordered by Gateway-API precedence so the generated COND tries them in order
;;; and the first hit wins.

(defun gw-host-tier (hostname)          ; higher = more specific
  (cond ((null hostname) 0)
        ((and (> (length hostname) 2) (string= hostname "*." :end1 2)) 1) ; wildcard
        (t 2)))                         ; exact

(defun gw-host-nonwild-length (hostname)
  (cond ((null hostname) 0)
        ((= 1 (gw-host-tier hostname)) (- (length hostname) 2)) ; drop "*."
        (t (length hostname))))

(defstruct gw-candidate hostname match backends key)

(defun gw-candidate-precedence (hostname match)
  "Descending-sort key per Gateway-API precedence: hostname specificity, then
path (Exact > longer PathPrefix), then method present, then #headers."
  (list (gw-host-tier hostname)
        (gw-host-nonwild-length hostname)
        (if (eq (gw-match-path-type match) :exact) 2 1)
        (length (gw-match-path match))
        (if (gw-match-method match) 1 0)
        (length (gw-match-headers match))))

(defun gw-key> (a b)
  (loop for x in a for y in b
        when (> x y) return t
        when (< x y) return nil
        finally (return nil)))

(defun gw-route-candidates (routes)
  (let ((cands '()))
    (dolist (route routes)
      (dolist (rule (gw-route-rules route))
        (dolist (m (gw-rule-matches rule))
          (dolist (host (or (gw-route-hostnames route) (list nil)))
            (push (make-gw-candidate :hostname host :match m
                                     :backends (gw-rule-backends rule)
                                     :key (gw-candidate-precedence host m))
                  cands)))))
    (stable-sort (nreverse cands) #'gw-key> :key #'gw-candidate-key)))

;;; ---------------------------------------------------------------------------
;;; The compiler: candidates -> a Lisp form -> a NATIVE function via (compile).

(defun gw-host-test-form (hostname)
  (cond ((null hostname) t)
        ((= 1 (gw-host-tier hostname))
         (let ((suffix (subseq hostname 1)))  ; "*.example.com" -> ".example.com"
           `(let ((h host))
              (and (> (length h) ,(length suffix))
                   (string= h ,suffix :start1 (- (length h) ,(length suffix)))))))
        (t `(string= host ,hostname))))

(defun gw-match-test-form (match)
  `(and ,(ecase (gw-match-path-type match)
           (:exact `(string= path ,(gw-match-path match)))
           (:prefix `(gw-path-prefix-match-p path ,(gw-match-path match))))
        ,@(when (gw-match-method match) `((string-equal method ,(gw-match-method match))))
        ,@(loop for (name . value) in (gw-match-headers match)
                collect `(gw-header-match-p headers ,name ,value))))

(defun gw-candidate-clause (candidate)
  `((and ,(gw-host-test-form (gw-candidate-hostname candidate))
         ,(gw-match-test-form (gw-candidate-match candidate)))
    (gw-pick-weighted ',(gw-candidate-backends candidate))))

(defun compile-gateway-router (routes)
  "Compile ROUTES (a list of GW-ROUTE) into a native function
   (host path method headers) -> a GW-BACKEND, or NIL when nothing matches
   (the caller serves 404). HEADERS is an alist of (name . value)."
  (let ((form `(lambda (host path method headers)
                 (declare (ignorable host path method headers)
                          (optimize (speed 2) (safety 1)))
                 (cond ,@(mapcar #'gw-candidate-clause (gw-route-candidates routes))
                       (t nil)))))
    (values (compile nil form) form)))
