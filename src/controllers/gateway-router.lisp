;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; The Gateway API routing table: immutable hostname indexes and ordered match
;;;; records, dispatched by code compiled once with gr8s. Route updates build a
;;;; replacement table without invoking the Lisp compiler. Exact hosts, matching
;;;; wildcard suffixes and catch-all candidates retain Gateway API precedence.
;;;;
;;;; Scope here (podster-43k.4): hostnames (exact + "*.suffix" wildcard), path
;;;; Exact/PathPrefix, method, exact header matches, and weighted backends. TLS,
;;;; HTTP filters (header/redirect/rewrite/mirror) and the eBPF fast path are
;;;; separate epic children.

(in-package #:gr8s.controllers)

;;; ---------------------------------------------------------------------------
;;; Normalized model (a subset of HTTPRoute, independent of the stored JSON).

(defstruct gw-backend
  (name "" :type string)
  (namespace nil)                       ; nil = the route's own namespace
  (port 0 :type (or integer string))
  (weight 1 :type integer)
  resolver)                            ; per-dispatch immutable dependency view, or NIL

(defstruct gw-match
  (path-type :prefix)                   ; :prefix | :exact
  (path "/" :type string)
  (method nil)                          ; nil | "GET" ...
  (headers '() :type list))             ; alist (name . value), exact

(defstruct gw-filter
  (type nil)                            ; :request-headers :response-headers :redirect :rewrite
  (data nil))                           ; a plist of parsed fields (see gw-parse-filter)

(defstruct gw-rule
  (matches '() :type list)              ; list of GW-MATCH (any match -> rule applies)
  (filters '() :type list)              ; list of GW-FILTER applied to the matched exchange
  (backends '() :type list))            ; list of GW-BACKEND (weighted)

(defstruct gw-dispatch
  (backend nil)                         ; chosen GW-BACKEND, or NIL (filter-only rule)
  (filters '() :type list)              ; the matched rule's GW-FILTERs
  (match nil)                           ; the matched GW-MATCH (for prefix rewrite)
  (route-name nil)                      ; matched HTTPRoute name (metrics)
  (route-key nil)                       ; "namespace/name" identity (rate-limit bucket + metrics)
  (rate-limit nil))                     ; requests/sec cap for this route, or NIL

(defstruct gw-route
  (namespace nil)                       ; the HTTPRoute's namespace (backendRef default)
  (name nil)                            ; the HTTPRoute's name (metrics label)
  (rate-limit nil)                      ; requests/sec cap from gr8s.io/rate-limit-rps, or NIL
  (hostnames '() :type list)            ; "api.example.com" / "*.example.com"; () = all
  (rules '() :type list)                ; list of GW-RULE
  (kind :httproute))

(defun bind-gateway-backend (backend resolver)
  "Bind a request's backend to its configuration view without changing candidates."
  (when backend
    (let ((bound (copy-gw-backend backend)))
      (setf (gw-backend-resolver bound) resolver)
      bound)))

(defun resolve-gateway-backend (backend fallback-resolver)
  (let ((resolver (or (gw-backend-resolver backend) fallback-resolver)))
    (when resolver (funcall resolver backend))))

(defun bind-gateway-http-dispatcher (dispatcher resolver)
  (lambda (host path method headers)
    (let ((dispatch (funcall dispatcher host path method headers)))
      (when dispatch
        (setf (gw-dispatch-backend dispatch) (bind-gateway-backend (gw-dispatch-backend dispatch) resolver))
        dispatch))))

(defun bind-gateway-l4-dispatcher (dispatcher resolver)
  (lambda (sni) (bind-gateway-backend (funcall dispatcher sni) resolver)))

;;; ---------------------------------------------------------------------------
;;; Parse a stored HTTPRoute object (jzon hash-table) into a GW-ROUTE.

(define-condition gateway-route-error (error)
  ((message :initarg :message :reader gateway-route-error-message))
  (:report (lambda (c s) (format s "~A" (gateway-route-error-message c)))))

(defun gw-route-error (fmt &rest args)
  "Signal a GATEWAY-ROUTE-ERROR whose message is (format nil FMT ARGS). Never
   returns."
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
                ((equal type "PathPrefix") (values :prefix (gw-canonical-prefix value)))
                (t (gw-route-error "unsupported HTTPRoute path match type ~S" type)))))))

(defun gw-canonical-prefix (value)
  "Gateway-API PathPrefix matching is on path-segment boundaries, and a trailing
   slash in the prefix is not significant: \"/match/\" is equivalent to \"/match\".
   Strip a single trailing slash so segment-boundary matching behaves identically
   for both spellings; the root prefix \"/\" is left intact."
  (let ((len (length value)))
    (if (and (> len 1) (char= (char value (1- len)) #\/))
        (subseq value 0 (1- len))
        value)))

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
  "Normalize one HTTPRoute match object into a GW-MATCH (its path type and value,
   method, and exact header matches)."
  (multiple-value-bind (path-type path) (gw-parse-path match-object)
    (make-gw-match :path-type path-type :path path
                   :method (gethash "method" match-object)
                   :headers (gw-parse-headers match-object))))

(defun gw-parse-backend (ref route-namespace)
  "Normalize a backendRef into a GW-BACKEND, defaulting its namespace to
   ROUTE-NAMESPACE and its weight to 1. Signals a GATEWAY-ROUTE-ERROR when the
   ref has no name or no port."
  (make-gw-backend
   :name (or (gethash "name" ref) (gw-route-error "backendRef needs a name"))
   :namespace (or (gethash "namespace" ref) route-namespace)
   :port (or (gethash "port" ref) (gw-route-error "backendRef ~S needs a port" (gethash "name" ref)))
   :weight (let ((w (gethash "weight" ref))) (if w w 1))))

(defun gw-name-value-alist (value)
  "Convert a JSON array of {name,value} into an alist of (name . value)."
  (when value
    (loop for h across value
          collect (cons (or (gethash "name" h) (gw-route-error "header filter needs a name"))
                        (or (gethash "value" h) "")))))

(defun gw-parse-header-ops (object)
  "Normalize a {set,add,remove} header modifier into a plist."
  (let ((object (or object (make-hash-table :test 'equal))))
    (list :set (gw-name-value-alist (gethash "set" object))
          :add (gw-name-value-alist (gethash "add" object))
          :remove (gw-string-list (gethash "remove" object)))))

(defun gw-parse-path-modifier (path)
  "Normalize a filter path modifier ({type, replaceFullPath|replacePrefixMatch})."
  (when path
    (let ((type (gethash "type" path)))
      (cond ((equal type "ReplaceFullPath") (list :type :full :value (gethash "replaceFullPath" path)))
            ((equal type "ReplacePrefixMatch") (list :type :prefix :value (gethash "replacePrefixMatch" path)))
            (t (gw-route-error "unsupported HTTPRoute path modifier type ~S" type))))))

(defun gw-parse-filter (object)
  "Normalize an HTTPRouteFilter. Fail closed on unimplemented filter types."
  (let ((type (gethash "type" object)))
    (cond
      ((equal type "RequestHeaderModifier")
       (make-gw-filter :type :request-headers
                       :data (gw-parse-header-ops (gethash "requestHeaderModifier" object))))
      ((equal type "ResponseHeaderModifier")
       (make-gw-filter :type :response-headers
                       :data (gw-parse-header-ops (gethash "responseHeaderModifier" object))))
      ((equal type "RequestRedirect")
       (let ((r (or (gethash "requestRedirect" object) (make-hash-table :test 'equal))))
         (make-gw-filter :type :redirect
                         :data (list :scheme (gethash "scheme" r)
                                     :hostname (gethash "hostname" r)
                                     :port (gethash "port" r)
                                     :status-code (or (gethash "statusCode" r) 302)
                                     :path (gw-parse-path-modifier (gethash "path" r))))))
      ((equal type "URLRewrite")
       (let ((r (or (gethash "urlRewrite" object) (make-hash-table :test 'equal))))
         (make-gw-filter :type :rewrite
                         :data (list :hostname (gethash "hostname" r)
                                     :path (gw-parse-path-modifier (gethash "path" r))))))
      (t (gw-route-error "unsupported HTTPRoute filter type ~S" type)))))

(defun gw-parse-rule (rule-object route-namespace)
  "Normalize one HTTPRoute rule into a GW-RULE (its matches, filters and
   backends). An empty match list becomes the Gateway-API default of PathPrefix
   \"/\"."
  (let* ((matches (gethash "matches" rule-object))
         (filters (gethash "filters" rule-object))
         (backend-refs (gethash "backendRefs" rule-object)))
    (make-gw-rule
     ;; No matches -> the Gateway-API default of PathPrefix "/".
     :matches (if (and matches (plusp (length matches)))
                  (map 'list #'gw-parse-match matches)
                  (list (make-gw-match :path-type :prefix :path "/")))
     :filters (when filters (map 'list #'gw-parse-filter filters))
     :backends (when backend-refs
                 (map 'list (lambda (r) (gw-parse-backend r route-namespace)) backend-refs)))))

(defun gw-parse-rate-limit (annotations)
  "Read the gr8s.io/rate-limit-rps annotation (a positive integer rps) or NIL."
  (let ((value (and (hash-table-p annotations) (gethash "gr8s.io/rate-limit-rps" annotations))))
    (when value
      (let ((rps (handler-case (if (stringp value) (parse-integer value) value) (error () nil))))
        (when (and (integerp rps) (plusp rps)) rps)))))

(defun parse-httproute (object)
  "Normalize a stored HTTPRoute (gateway.networking.k8s.io/v1) into a GW-ROUTE.
   Signals GATEWAY-ROUTE-ERROR on unsupported constructs (fail closed)."
  (let* ((metadata (gethash "metadata" object))
         (namespace (and metadata (gethash "namespace" metadata)))
         (spec (gethash "spec" object))
         (rules (and spec (gethash "rules" spec))))
    (make-gw-route
     :namespace namespace
     :name (and metadata (gethash "name" metadata))
     :rate-limit (gw-parse-rate-limit (and metadata (gethash "annotations" metadata)))
     :hostnames (gw-string-list (and spec (gethash "hostnames" spec)))
     :rules (when rules (map 'list (lambda (r) (gw-parse-rule r namespace)) rules)))))

;;; ---------------------------------------------------------------------------
;;; Runtime matching and backend selection, compiled once with gr8s.

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
;;; ordered by Gateway-API precedence so the dispatcher tries them in order
;;; and the first hit wins.

(defun gw-host-tier (hostname)          ; higher = more specific
  "Hostname specificity tier for precedence: 0 for no host, 1 for a \"*.\"
   wildcard, 2 for an exact host."
  (cond ((null hostname) 0)
        ((and (> (length hostname) 2) (string= hostname "*." :end1 2)) 1) ; wildcard
        (t 2)))                         ; exact

(defun gw-host-nonwild-length (hostname)
  "The hostname length used as a precedence tiebreak: the suffix length (less the
   leading \"*.\") for a wildcard, the full length for an exact host, 0 for none."
  (cond ((null hostname) 0)
        ((= 1 (gw-host-tier hostname)) (- (length hostname) 2)) ; drop "*."
        (t (length hostname))))

(defstruct gw-candidate hostname match filters backends key
  route-name route-key rate-limit source-key)

(defun gateway-route-source-key (route)
  (list (gw-route-kind route) (gw-route-namespace route) (gw-route-name route)))

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
  "Lexicographic greater-than over two precedence key lists, compared element by
   element; NIL when A is not greater (including equal)."
  (loop for x in a for y in b
        when (> x y) return t
        when (< x y) return nil
        finally (return nil)))

(defun gw-route-candidates (routes)
  "Expand ROUTES into one GW-CANDIDATE per (route, rule, match, hostname) and
   return them sorted by descending Gateway-API precedence, so the first match
   in the dispatcher wins. The sort is stable, preserving source order
   among equal-precedence candidates."
  (let ((cands '()))
    (dolist (route routes)
      (let ((route-key (format nil "~A/~A" (or (gw-route-namespace route) "")
                               (or (gw-route-name route) ""))))
        (dolist (rule (gw-route-rules route))
          (dolist (m (gw-rule-matches rule))
            (dolist (host (or (gw-route-hostnames route) (list nil)))
              (push (make-gw-candidate :hostname host :match m
                                       :filters (gw-rule-filters rule)
                                       :backends (gw-rule-backends rule)
                                       :route-name (gw-route-name route)
                                       :route-key route-key
                                       :source-key (gateway-route-source-key route)
                                       :rate-limit (gw-route-rate-limit route)
                                       :key (gw-candidate-precedence host m))
                    cands))))))
    (stable-sort (nreverse cands) #'gw-key> :key #'gw-candidate-key)))

;;; ---------------------------------------------------------------------------
;;; Immutable hostname indexes. Candidate vectors retain the global precedence
;;; order; matching host buckets are visited from most specific to catch-all.

(defstruct gw-routing-table
  (exact (make-hash-table :test 'equal))
  (wildcard (make-hash-table :test 'equal))
  (fallback #()))

(defun gateway-host-bucket (table host)
  (cond ((null host) (gw-routing-table-fallback table))
        ((= 1 (gw-host-tier host)) (gethash (subseq host 1) (gw-routing-table-wildcard table) #()))
        (t (gethash host (gw-routing-table-exact table) #()))))

(defun (setf gateway-host-bucket) (candidates table host)
  (if (null host)
      (setf (gw-routing-table-fallback table) candidates)
      (let ((index (if (= 1 (gw-host-tier host)) (gw-routing-table-wildcard table)
                       (gw-routing-table-exact table)))
            (key (if (= 1 (gw-host-tier host)) (subseq host 1) host)))
        (if (zerop (length candidates)) (remhash key index) (setf (gethash key index) candidates))))
  candidates)

(defun update-gateway-routing-table (table removed added candidate-before)
  "Replace changed routes, sharing untouched candidate vectors with the old table."
  (let ((next (copy-gw-routing-table table))
        (new-by-host (make-hash-table :test #'equal)))
    (setf (gw-routing-table-exact next) (alexandria:copy-hash-table (gw-routing-table-exact table))
          (gw-routing-table-wildcard next) (alexandria:copy-hash-table (gw-routing-table-wildcard table)))
    (dolist (route removed)
      (let ((key (gateway-route-source-key route)))
        (dolist (host (or (gw-route-hostnames route) (list nil)))
          (setf (gateway-host-bucket next host)
                (remove-if (lambda (candidate) (equal key (gw-candidate-source-key candidate)))
                           (gateway-host-bucket next host))))))
    (dolist (candidate (gw-route-candidates added))
      (push candidate (gethash (gw-candidate-hostname candidate) new-by-host)))
    (maphash (lambda (host candidates)
               (setf (gateway-host-bucket next host)
                     (coerce (stable-sort (append (coerce (gateway-host-bucket next host) 'list)
                                                 (nreverse candidates)) candidate-before) 'vector)))
             new-by-host)
    next))

(defun gw-match-request-p (match path method headers)
  (and (ecase (gw-match-path-type match)
         (:exact (string= path (gw-match-path match)))
         (:prefix (gw-path-prefix-match-p path (gw-match-path match))))
       (or (null (gw-match-method match))
           (string-equal method (gw-match-method match)))
       (loop for (name . value) in (gw-match-headers match)
             always (gw-header-match-p headers name value))))

(defun gw-dispatch-candidates (candidates path method headers)
  (loop for candidate across candidates
        when (gw-match-request-p (gw-candidate-match candidate) path method headers)
          return (make-gw-dispatch
                  :backend (gw-pick-weighted (gw-candidate-backends candidate))
                  :filters (gw-candidate-filters candidate)
                  :match (gw-candidate-match candidate)
                  :route-name (gw-candidate-route-name candidate)
                  :route-key (gw-candidate-route-key candidate)
                  :rate-limit (gw-candidate-rate-limit candidate))))

(defun gw-dispatch-request (table host path method headers)
  (or (gw-dispatch-candidates (gethash host (gw-routing-table-exact table) #())
                              path method headers)
      ;; A wildcard requires a nonempty prefix before its dot. Visit suffixes
      ;; longest first, allowing a less specific bucket when no rule matches.
      (when (plusp (hash-table-count (gw-routing-table-wildcard table)))
        (loop for dot = (position #\. host :start 1)
                then (position #\. host :start (1+ dot))
              while dot
              thereis (gw-dispatch-candidates
                       (gethash (subseq host dot) (gw-routing-table-wildcard table) #())
                       path method headers)))
      (gw-dispatch-candidates (gw-routing-table-fallback table) path method headers)))

(defun gateway-router-from-table (table)
  (lambda (host path method headers) (gw-dispatch-request table host path method headers)))

(defun build-gateway-router (routes)
  "Build a request dispatcher over an immutable hostname-indexed routing table.
Matching code is compiled with gr8s; changing ROUTES never invokes the compiler.
The returned function owns its indexes; later builds do not mutate them."
  (let ((table (make-gw-routing-table)) (fallback nil))
    (dolist (candidate (gw-route-candidates routes))
      (let ((host (gw-candidate-hostname candidate)))
        (cond ((null host) (push candidate fallback))
              ((= 1 (gw-host-tier host))
               (push candidate (gethash (subseq host 1) (gw-routing-table-wildcard table))))
              (t (push candidate (gethash host (gw-routing-table-exact table)))))))
    (dolist (index (list (gw-routing-table-exact table) (gw-routing-table-wildcard table)))
      (maphash (lambda (host candidates)
                 (setf (gethash host index) (coerce (nreverse candidates) 'vector)))
               index))
    (setf (gw-routing-table-fallback table) (coerce (nreverse fallback) 'vector))
    (values (gateway-router-from-table table) table)))
