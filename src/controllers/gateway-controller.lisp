;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; The Gateway controller (podster-43k.3). It reconciles the durable Gateway
;;;; and HTTPRoute objects into the per-node data-plane desired state: for each
;;;; HTTP listener on a Gateway this controller owns, which listener port runs
;;;; and which HTTPRoutes (parentRef-attached) populate its router. The pure
;;;; planner (gateway-listener-plan) maps the stored objects to port -> routes;
;;;; convergence starts, hot-swaps and stops L7 proxy listeners (gateway-proxy)
;;;; to match, replacing each port's immutable table when its routing content changes.

(in-package #:gr8s.controllers)

(defparameter *gateway-controller-name* "gr8s.io/gateway-controller"
  "The controllerName value of GatewayClasses this agent reconciles.")

(defun gateway-controlled-p (store gateway)
  "True when GATEWAY's gatewayClassName resolves to a GatewayClass whose
   controllerName is ours."
  (let* ((spec (gethash "spec" gateway))
         (class-name (and spec (gethash "gatewayClassName" spec)))
         (class (and class-name
                     (ignore-errors (get-core-resource store "gatewayclasses" nil class-name)))))
    (and class
         (equal *gateway-controller-name*
                (gethash "controllerName" (gethash "spec" class))))))

(defun gateway-parent-matches-p (parent-ref route-namespace
                                 gateway-namespace gateway-name listener-name listener-port
                                 &optional (owner-kind "Gateway")
                                           (owner-group "gateway.networking.k8s.io"))
  "True when an HTTPRoute PARENT-REF attaches to the given Gateway listener.
   kind/group default to Gateway/gateway.networking.k8s.io, namespace to the
   route's own; sectionName and port, when present, must equal the listener's."
  (let ((kind (or (gethash "kind" parent-ref) "Gateway"))
        (group (or (gethash "group" parent-ref) "gateway.networking.k8s.io"))
        (name (gethash "name" parent-ref))
        (namespace (or (gethash "namespace" parent-ref) route-namespace))
        (section (gethash "sectionName" parent-ref))
        (port (gethash "port" parent-ref)))
    (and (equal kind owner-kind)
         (equal group owner-group)
         (equal name gateway-name)
         (equal namespace gateway-namespace)
         (or (null section) (equal section listener-name))
         (or (null port) (eql port listener-port)))))

(defun gateway-route-attaches-p (httproute gateway-namespace gateway-name listener-name listener-port)
  "True when HTTPROUTE has at least one parentRef attaching it to the given Gateway
   listener (GATEWAY-NAMESPACE, GATEWAY-NAME, LISTENER-NAME, LISTENER-PORT); false
   when it has no parentRefs."
  (let* ((metadata (gethash "metadata" httproute))
         (route-namespace (gethash "namespace" metadata))
         (spec (gethash "spec" httproute))
         (parent-refs (and spec (gethash "parentRefs" spec))))
    (and parent-refs
         (some (lambda (ref)
                 (gateway-parent-matches-p ref route-namespace
                                           gateway-namespace gateway-name listener-name listener-port))
               (coerce parent-refs 'list)))))

(defun gateway-listener-allows-route-p (view route gateway-namespace listener)
  "Apply allowedRoutes kind/group and namespace policy before attachment."
  (let* ((allowed (gethash "allowedRoutes" listener))
         (kinds (and allowed (gethash "kinds" allowed)))
         (namespaces (and allowed (gethash "namespaces" allowed)))
         (from (or (and namespaces (gethash "from" namespaces)) "Same"))
         (namespace (gethash "namespace" (gethash "metadata" route)))
         (kind (or (gethash "kind" route) "HTTPRoute")))
    (and (or (null kinds)
             (some (lambda (entry)
                     (and (equal kind (gethash "kind" entry))
                          (equal "gateway.networking.k8s.io"
                                 (or (gethash "group" entry) "gateway.networking.k8s.io")))) kinds))
         (cond ((equal from "All") t)
               ((equal from "Same") (equal namespace gateway-namespace))
               ((equal from "Selector")
                (let ((object (and view (ignore-errors (get-core-resource view "namespaces" nil namespace))))
                      (selector (gethash "selector" namespaces)))
                  (and object selector
                       (gr8s.resources::workload-selector-matches-p
                        selector (gethash "labels" (gethash "metadata" object))))))
               (t nil)))))

(defun gateway-hostname-intersection (left right)
  "Return the narrower overlapping hostname pattern, plus whether they overlap."
  (labels ((covers (pattern host)
             (and (= 1 (gw-host-tier pattern))
                  (> (length host) (1- (length pattern)))
                  (string-equal pattern host :start1 1
                                :start2 (- (length host) (1- (length pattern)))))))
    (cond ((null left) (values right t))
          ((null right) (values left t))
          ((string-equal left right) (values left t))
          ((covers left right) (values right t))
          ((covers right left) (values left t))
          (t (values nil nil)))))

(defun gateway-listener-route-hostnames (route listener)
  "Intersect listener and route hostnames. NIL list means no attachment;
(NIL) means an unrestricted hostname."
  (let ((hosts (gethash "hostnames" (gethash "spec" route))))
    (loop for host in (if (and hosts (plusp (length hosts))) (coerce hosts 'list) (list nil))
          append (multiple-value-bind (intersection overlaps)
                     (gateway-hostname-intersection (gethash "hostname" listener) host)
                   (when overlaps (list intersection))))))

(defun gateway-route-with-hostnames (route hosts parsed-routes)
  "Reuse this pass's parsed rules, copying each attachment's hostname restrictions."
  (when hosts
    (multiple-value-bind (base present) (gethash route parsed-routes)
      (unless present
        (setf base (ignore-errors (parse-httproute route))
              (gethash route parsed-routes) base))
      (when base
        (let ((parsed (copy-gw-route base)))
          (setf (gw-route-hostnames parsed)
                (unless (member nil hosts) (remove-duplicates hosts :test #'equal)))
          parsed)))))

(defun gateway-listener-tls-ref (gateway-namespace listener &optional view
                                                                       (source-kind "Gateway")
                                                                       (source-group "gateway.networking.k8s.io"))
  "Return an authorized Secret reference, or NIL and a listener error reason."
  (let* ((tls (gethash "tls" listener))
         (refs (and tls (gethash "certificateRefs" tls)))
         (ref (and refs (plusp (length refs)) (aref refs 0)))
         (name (and ref (gethash "name" ref)))
         (namespace (or (and ref (gethash "namespace" ref)) gateway-namespace)))
    (cond ((not (and ref name
                     (equal (or (gethash "kind" ref) "Secret") "Secret")
                     (equal (or (gethash "group" ref) "") "")))
           (values nil "InvalidCertificateRef"))
          ((not (gateway-reference-permitted-p view gateway-namespace source-kind namespace "Secret" name
                                               source-group))
           (values nil "RefNotPermitted"))
          (t (cons namespace name)))))

(defgeneric gateway-parent-route-reader (view)
  (:documentation "Return an indexed owner-to-HTTPRoutes reader, or NIL for full-list fallback."))

(defmethod gateway-parent-route-reader ((view t))
  nil)

(defmethod gateway-parent-route-reader ((view gr8s.resources::foreign-resource-snapshot))
  (let ((parents (make-hash-table :test #'equal))
        (objects (make-hash-table :test #'equal)))
    (lambda (parent)
      (multiple-value-bind (routes present) (gethash parent parents)
        (if present routes
            (setf (gethash parent parents)
                  (mapcar
                   (lambda (object)
                     ;; A multi-parent route remains EQ across owner buckets so
                     ;; the planner's parse-once cache also covers intersections.
                     (let* ((metadata (gethash "metadata" object))
                            (key (list (gethash "namespace" metadata) (gethash "name" metadata))))
                       (or (gethash key objects) (setf (gethash key objects) object))))
                   (gr8s.resources::foreign-snapshot-parent-routes view parent))))))))

(defun gateway-listener-plan
    (gateways httproutes controlled-p &optional view listener-sets reuse-routes-p parent-routes)
  "Plan admitted logical listeners, retaining owner-relative route permissions.
REUSE-ROUTES-P may omit route expansion for a published shared-TLS binding that
the caller will retain. It is used only for ListenerSet-only changes."
  (let ((objects-by-port (make-hash-table))
        (logical-by-port (make-hash-table))
        (listener-by-port (make-hash-table))
        (hosts-by-port (make-hash-table))
        (parsed-routes (make-hash-table :test #'eq))
        (routes-by-parent (unless parent-routes (gateway-route-parent-index httproutes))))
    (dolist (gateway gateways)
      (when (funcall controlled-p gateway)
        (dolist (entry (gateway-listener-entries view gateway listener-sets))
          (let* ((owner (gateway-listener-entry-owner entry))
                 (listener (gateway-listener-entry-listener entry))
                 (metadata (gethash "metadata" owner))
                 (namespace (gethash "namespace" metadata))
                 (name (gethash "name" metadata))
                 (kind (or (gethash "kind" owner) "Gateway"))
                 (group (gateway-listener-owner-group owner))
                 (protocol (gethash "protocol" listener))
                 (port (gethash "port" listener)))
            (when (and (null (gateway-listener-entry-error entry))
                       (member protocol '("HTTP" "HTTPS") :test #'equal))
              (push entry (gethash port logical-by-port))
              (unless (gethash port listener-by-port)
                (setf (gethash port listener-by-port)
                      (cons protocol (and (equal protocol "HTTPS")
                                          (gateway-listener-entry-tls-ref view entry)))))
              (dolist (route (unless (and reuse-routes-p (funcall reuse-routes-p entry))
                               (if parent-routes
                                   (funcall parent-routes (list group kind namespace name))
                                   (gethash (list group kind namespace name) routes-by-parent))))
                (when (and (some (lambda (ref)
                                   (gateway-parent-matches-p
                                    ref (gethash "namespace" (gethash "metadata" route))
                                    namespace name (gethash "name" listener) port kind group))
                                 (gethash "parentRefs" (gethash "spec" route) #()))
                           (gateway-listener-allows-route-p view route namespace listener))
                  (let ((hosts (gateway-listener-route-hostnames route listener)))
                    (when hosts
                      (let ((parsed (ignore-errors (gateway-route-with-hostnames route hosts parsed-routes))))
                        (when parsed
                          (push parsed (gateway-listener-entry-routes entry))))
                      (let ((by-route (or (gethash port hosts-by-port)
                                          (setf (gethash port hosts-by-port)
                                                (make-hash-table :test #'eq)))))
                        (setf (gethash route by-route) (append hosts (gethash route by-route)))
                        (push route (gethash port objects-by-port))))))))))))
    (loop for port being the hash-keys of listener-by-port using (hash-value listener)
          collect (list :port port :protocol (car listener) :tls (cdr listener)
                        :logical-listeners
                        (loop for entry in (nreverse (gethash port logical-by-port))
                              do (setf (gateway-listener-entry-routes entry)
                                       (nreverse (gateway-listener-entry-routes entry)))
                              collect entry)
                        :routes (loop for object in (gateway-distinct-route-objects (gethash port objects-by-port))
                                      for hosts = (gethash object (gethash port hosts-by-port))
                                      for route = (ignore-errors (gateway-route-with-hostnames object hosts parsed-routes))
                                      when route collect route)))))

;;; ---------------------------------------------------------------------------
;;; Convergence. Side effects (start/stop/swap) are injectable for testing.

(defstruct (gateway-controller (:constructor %make-gateway-controller))
  store resolver cert-dir
  (listeners (make-hash-table))         ; HTTP/HTTPS port -> (handle . tls-signature)
  (routing-tables (make-hash-table))    ; HTTP/HTTPS port -> (routing-content . dispatcher)
  (routing-bases (make-hash-table))     ; same dispatchers without a dependency-view binding
  (routing-indices (make-hash-table))
  (tls-materials (make-hash-table :test 'equal))
  (tls-material-users (make-hash-table :test 'equal))
  (tls-snapshots (make-hash-table))
  (http-snapshots (make-hash-table))
  (installed-listeners (make-hash-table))
  (secret-ports (make-hash-table :test 'equal))
  parent-listeners
  snapshot-resolvers-p
  start-fn stop-fn swap-fn tls-swap-fn register-fn unregister-fn
  (l4-listeners (make-hash-table))      ; TCP/TLS port -> (mode . handle)
  (l4-installed-listeners (fset:empty-ch-map nil))
  l4-start-fn l4-stop-fn l4-swap-fn)

(defun gateway-write-octets (path octets)
  "Write OCTETS to PATH as a binary file, creating it or truncating any existing one."
  (with-open-file (stream path :direction :output :element-type '(unsigned-byte 8)
                               :if-exists :supersede :if-does-not-exist :create)
    (write-sequence octets stream)))

(defvar *gateway-tls-material-cache* (make-hash-table :test 'equal))
(defvar *gateway-tls-material-cache-lock* (bt:make-lock "Gateway TLS material"))

(defun gateway-check-tls-material (certificate-bytes key-bytes)
  "Parse every PEM certificate and prove the leaf's key can sign a TLS handshake.
This checks configured server material, not trust, hostname, or chain validity."
  (let ((text (babel:octets-to-string certificate-bytes :encoding :utf-8))
        (certificates nil)
        (position 0))
    (loop for begin = (search "-----BEGIN CERTIFICATE-----" text :start2 position)
          while begin do
            (let ((end (search "-----END CERTIFICATE-----" text :start2 begin)))
              (unless end (error "Truncated Gateway certificate PEM"))
              (setf position (+ end (length "-----END CERTIFICATE-----")))
              (push (pure-tls:parse-certificate
                     (pure-tls::pem-decode
                      (babel:string-to-octets (subseq text begin position) :encoding :utf-8)
                      "CERTIFICATE")) certificates)))
    (unless certificates (error "Gateway certificate PEM is empty"))
    (let* ((key-text (babel:octets-to-string key-bytes :encoding :utf-8))
           (key (cond ((search "-----BEGIN PRIVATE KEY-----" key-text)
                       (pure-tls::parse-pkcs8-private-key (pure-tls::pem-decode key-bytes "PRIVATE KEY")))
                      ((search "-----BEGIN RSA PRIVATE KEY-----" key-text)
                       (pure-tls::parse-rsa-private-key (pure-tls::pem-decode key-bytes "RSA PRIVATE KEY")))
                      ((search "-----BEGIN EC PRIVATE KEY-----" key-text)
                       (pure-tls::parse-ec-private-key (pure-tls::pem-decode key-bytes "EC PRIVATE KEY")))
                      (t (error "Unsupported Gateway private key PEM"))))
           (algorithm (pure-tls::signature-algorithm-for-key key))
           (challenge (babel:string-to-octets "gr8s Gateway TLS key check" :encoding :utf-8))
           (signature (pure-tls::sign-data-with-algorithm challenge key algorithm)))
      (pure-tls::verify-certificate-verify-signature
       (car (last certificates)) algorithm signature challenge)
      ;; The verifier signals on failure; some algorithms return NIL on success.
      (values t (nreverse certificates) key))))

(defun gateway-tls-material-valid-p (certificate key)
  "Cache immutable material checks, retaining digests and verdicts only.
ReferenceGrant authorization must be checked separately on every reconciliation."
  (handler-case
      (let* ((certificate-bytes (ag-grpc:base64-decode certificate))
             (key-bytes (ag-grpc:base64-decode key))
             (identity (concatenate 'string
                                    (ironclad:byte-array-to-hex-string (ironclad:digest-sequence :sha256 certificate-bytes))
                                    (ironclad:byte-array-to-hex-string (ironclad:digest-sequence :sha256 key-bytes)))))
        (multiple-value-bind (valid present)
            (bt:with-lock-held (*gateway-tls-material-cache-lock*)
              (gethash identity *gateway-tls-material-cache*))
          (if present valid
              (let ((result (handler-case (not (null (gateway-check-tls-material certificate-bytes key-bytes)))
                              (error () nil))))
                (bt:with-lock-held (*gateway-tls-material-cache-lock*)
                  (when (>= (hash-table-count *gateway-tls-material-cache*) 4096)
                    (clrhash *gateway-tls-material-cache*))
                  (setf (gethash identity *gateway-tls-material-cache*) result))
                result))))
    (error () nil)))

(defun gateway-resolve-listener-tls (store tls-ref cert-dir &key (materialize t))
  "Materialize an HTTPS listener's certificate. TLS-REF is (namespace . secret);
   write the kubernetes.io/tls Secret's cert/key under CERT-DIR and return a
   certificate/key paths plus Secret identity, or NIL when unresolvable.
   With MATERIALIZE false, inspect the desired identity without writing files."
  (when (and tls-ref cert-dir)
    (let* ((namespace (car tls-ref))
           (name (cdr tls-ref))
           (secret (ignore-errors (get-core-resource store "secrets" namespace name)))
           (data (and secret (gethash "data" secret)))
           (crt (and data (gethash "tls.crt" data)))
           (key (and data (gethash "tls.key" data))))
      (when (and crt key (gateway-tls-material-valid-p crt key))
        (let* ((dir (uiop:ensure-directory-pathname cert-dir))
               (cert-path (merge-pathnames (format nil "~A-~A.crt" namespace name) dir))
               (key-path (merge-pathnames (format nil "~A-~A.key" namespace name) dir)))
          (when materialize
            (ensure-directories-exist dir)
            (gateway-write-octets cert-path (ag-grpc:base64-decode crt))
            (gateway-write-octets key-path (ag-grpc:base64-decode key)))
          (list :certificate (namestring cert-path) :key (namestring key-path)
                :secret-uid (gethash "uid" (gethash "metadata" secret))
                :secret-version (gethash "resourceVersion" (gethash "metadata" secret))))))))

(defun make-gateway-controller (store &key resolver cert-dir start-fn stop-fn swap-fn tls-swap-fn
                                           register-fn unregister-fn
                                           l4-start-fn l4-stop-fn l4-swap-fn)
  "A controller over STORE. RESOLVER maps a GW-BACKEND to an address (defaults to
   the ClusterIP service resolver). CERT-DIR is where HTTPS listener certs are
   materialized. START-FN/STOP-FN/SWAP-FN manage listener lifecycle and default
   to the real Hunchentoot gateway acceptors."
  (%make-gateway-controller
   :store store
   :resolver (or resolver (make-service-backend-resolver store))
   :cert-dir cert-dir
   :start-fn (or start-fn
                 (lambda (port router resolver tls)
                   (start-gateway-listener :port port :router router :resolver resolver :tls tls)))
   :stop-fn (or stop-fn #'stop-gateway-listener)
   :swap-fn (or swap-fn
                (lambda (handle router) (setf (gateway-acceptor-router handle) router)))
   :tls-swap-fn (or tls-swap-fn
                    (lambda (handle snapshot) (setf (gateway-acceptor-tls-snapshot handle) snapshot)))
   :register-fn (or register-fn (lambda (port handle) (declare (ignore port handle))))
   :unregister-fn (or unregister-fn (lambda (port) (declare (ignore port))))
   :l4-start-fn (or l4-start-fn
                    (lambda (port mode dispatcher resolver)
                      (start-l4-listener :port port :mode mode :dispatcher dispatcher :resolver resolver)))
   :l4-stop-fn (or l4-stop-fn #'stop-l4-listener)
   :l4-swap-fn (or l4-swap-fn #'l4-listener-swap-dispatcher)))

(defun gateway-listener-signature (protocol tls-paths)
  "Transport identity of a listener; a change forces a restart (a router change
   alone only hot-swaps)."
  (list protocol (if (getf tls-paths :snapshot) :sni tls-paths)))

(defun register-gateway-listener (controller port handle stop-fn)
  "Publish HANDLE only after registration succeeds; close it on failure."
  (handler-case
      (progn (funcall (gateway-controller-register-fn controller) port handle) handle)
    (error (condition)
      (ignore-errors (funcall stop-fn handle))
      (error condition))))

(defun gateway-controller-observations (controller)
  "Report actual listener state for the installed Gateway UID and generation."
  (let ((store (gateway-controller-store controller)))
    (loop for gateway in (list-core-resources store "gateways")
          when (gateway-controlled-p store gateway)
            collect
            (let ((metadata (gethash "metadata" gateway)))
              (make-instance
               'gr8s.node.v1::gateway-observation
               :namespace (gethash "namespace" metadata) :name (gethash "name" metadata)
               :uid (gethash "uid" metadata) :generation (gethash "generation" metadata 1)
               :listeners
               (loop for listener across (gethash "listeners" (gethash "spec" gateway))
                     for protocol = (gethash "protocol" listener)
                     for port = (gethash "port" listener)
                     for running = (gethash port (gateway-controller-listeners controller))
                     for l4 = (gethash port (gateway-controller-l4-listeners controller))
                     for tls = (when (equal protocol "HTTPS")
                                 (gateway-resolve-listener-tls
                                  store (gateway-listener-tls-ref (gethash "namespace" metadata) listener store)
                                  (gateway-controller-cert-dir controller) :materialize nil))
                     for programmed =
                     (cond ((member protocol '("HTTP" "HTTPS") :test #'equal)
                            (and running (or (equal protocol "HTTP") tls)
                                 (equal (cdr running) (gateway-listener-signature protocol tls))))
                           ((equal protocol "TCP") (and l4 (eq (car l4) :tcp)))
                           ((equal protocol "TLS") (and l4 (eq (car l4) :tls))))
                     collect (make-instance
                              'gr8s.node.v1::gateway-listener-observation
                              :name (gethash "name" listener) :programmed (not (null programmed))
                              :reason (cond (programmed "Programmed")
                                            ((and (equal protocol "HTTPS") (null tls)) "InvalidCertificateRef")
                                            ((not (member protocol '("HTTP" "HTTPS" "TCP" "TLS") :test #'equal))
                                             "UnsupportedProtocol")
                                            (t "Pending"))
                              :message (if programmed "Listener is running" "Listener is not running"))))))))

(defun merge-gateway-listener-plans (&rest plans)
  "Merge compatible listener PLANS by port, appending their routes.

The first transport definition for a port owns it; later plans with a different
protocol or TLS reference cannot share that socket and are ignored."
  (let ((by-port (make-hash-table)) (ports nil))
    (dolist (plan plans)
      (dolist (entry plan)
        (let* ((port (getf entry :port))
               (existing (gethash port by-port)))
          (cond
            ((null existing)
             (push port ports)
             (setf (gethash port by-port) (copy-list entry)))
            ((and (equal (getf existing :protocol) (getf entry :protocol))
                  (equal (getf existing :tls) (getf entry :tls)))
             (setf (getf existing :routes)
                   (append (getf existing :routes) (getf entry :routes))))))))
    (mapcar (lambda (port) (gethash port by-port)) (nreverse ports))))

(defun gateway-routing-content (routes)
  "Case-sensitive value identity of normalized routing configuration.
Ignore storage metadata while retaining every field used by dispatch and filters."
  (loop for route in routes collect
    (list (gw-route-kind route) (gw-route-namespace route) (gw-route-name route) (gw-route-rate-limit route)
          (gw-route-hostnames route)
          (loop for rule in (gw-route-rules route) collect
            (list (loop for match in (gw-rule-matches rule) collect
                    (list (gw-match-path-type match) (gw-match-path match)
                          (gw-match-method match) (gw-match-headers match)))
                  (loop for filter in (gw-rule-filters rule) collect
                    (list (gw-filter-type filter) (gw-filter-data filter)))
                  (loop for backend in (gw-rule-backends rule) collect
                    (list (gw-backend-name backend) (gw-backend-namespace backend)
                          (gw-backend-port backend) (gw-backend-weight backend)
                          (gw-backend-source-namespace backend) (gw-backend-source-kind backend)
                          (gw-backend-invalid-reason backend))))))))

(defun gateway-router-for-port (controller port routes)
  "Return dispatcher and content identity, without publishing either in the cache."
  (let* ((content (gateway-routing-content routes))
         (cached (gethash port (gateway-controller-routing-tables controller))))
    (multiple-value-bind (base index)
        (if (and cached (equal content (car cached)))
            (values (or (gethash port (gateway-controller-routing-bases controller)) (cdr cached))
                    (gethash port (gateway-controller-routing-indices controller)))
            (build-gateway-router routes))
      (values (if (gateway-controller-snapshot-resolvers-p controller)
                  (bind-gateway-http-dispatcher base (gateway-controller-resolver controller)) base)
              content base index))))

(defun converge-gateway-listeners (controller &key reuse-tls-bindings-p)
  "Start, update and stop listeners to match the current Gateway/Ingress plan.
Unchanged routing content reuses the published table. Transport identity changes
restart the listener. HTTPS with an unresolved certificate is never plaintext."
  (let* ((store (gateway-controller-store controller))
         (resolver (gateway-controller-resolver controller))
         (cert-dir (gateway-controller-cert-dir controller))
         (start-fn (gateway-controller-start-fn controller))
         (stop-fn (gateway-controller-stop-fn controller))
         (swap-fn (gateway-controller-swap-fn controller))
         (unregister-fn (gateway-controller-unregister-fn controller))
         (gateways (list-core-resources store "gateways"))
         (listener-sets (list-core-resources store "listenersets"))
         (parent-routes (and reuse-tls-bindings-p (gateway-parent-route-reader store)))
         (plan (merge-gateway-listener-plans
                (gateway-listener-plan gateways
                                       (unless parent-routes (list-core-resources store "httproutes"))
                                       (lambda (gateway) (gateway-controlled-p store gateway)) store listener-sets
                                       (when reuse-tls-bindings-p
                                         (lambda (entry)
                                           (gateway-reusable-tls-binding
                                            controller entry
                                            (when (equal "HTTPS" (gethash "protocol" (gateway-listener-entry-listener entry)))
                                              (gateway-current-secret-identity store entry)))))
                                       parent-routes)
                (ingress-listener-plan store)))
         (running (gateway-controller-listeners controller))
         (tables (gateway-controller-routing-tables controller))
         (live-materials (make-hash-table :test 'equal))
         (secret-ports (make-hash-table :test 'equal))
         (desired-ports '()))
    (dolist (entry plan)
      (destructuring-bind (&key port protocol tls routes logical-listeners) entry
        (when (equal protocol "HTTPS")
          ;; Keep missing/invalid material dependencies so a later Secret can
          ;; activate the listener without requiring a parent edit.
          (dolist (reference (if logical-listeners
                                 (mapcar (lambda (logical) (gateway-listener-entry-tls-ref store logical))
                                         logical-listeners)
                                 (list tls)))
            (when reference
              (pushnew port (gethash (list (car reference) (cdr reference)) secret-ports)))))
        (let* ((existing (gethash port running))
               (isolated-http-p (and (equal protocol "HTTP") logical-listeners
                                     (or (gethash port (gateway-controller-http-snapshots controller))
                                         (some (lambda (entry)
                                                 (member (gethash "kind" (gateway-listener-entry-owner entry))
                                                         '("ListenerSet" "XListenerSet") :test #'equal))
                                               logical-listeners))))
               (http-snapshot (when isolated-http-p
                                (gateway-build-http-snapshot controller logical-listeners reuse-tls-bindings-p)))
               (shared-tls-p (and (equal protocol "HTTPS")
                                  (or (equal (cdr existing) '("HTTPS" :sni))
                                      (some (lambda (listener)
                                              (member (gethash "kind" (gateway-listener-entry-owner listener))
                                                      '("ListenerSet" "XListenerSet") :test #'equal))
                                            logical-listeners))))
               (snapshot (when shared-tls-p
                           (gateway-build-tls-snapshot controller logical-listeners live-materials
                                                       reuse-tls-bindings-p)))
               (tls-paths (when (equal protocol "HTTPS")
                            (if shared-tls-p
                                (when snapshot (list :snapshot snapshot))
                                (gateway-resolve-listener-tls store tls cert-dir)))))
          (unless (and (equal protocol "HTTPS") (null tls-paths))
            (push port desired-ports)
            (multiple-value-bind (router content base index)
                (cond (http-snapshot
                       (let ((base (if (eq http-snapshot (gethash port (gateway-controller-http-snapshots controller)))
                                       (gethash port (gateway-controller-routing-bases controller))
                                       (gateway-http-snapshot-router http-snapshot))))
                         (values base :logical-listeners base nil)))
                      ((not shared-tls-p) (gateway-router-for-port controller port routes)))
              (let ((signature (gateway-listener-signature protocol tls-paths)))
                (if (and existing (equal (cdr existing) signature))
                    (progn
                      (unless (or shared-tls-p (eq router (cdr (gethash port tables))))
                        (funcall swap-fn (car existing) router))
                      (when snapshot
                        (funcall (gateway-controller-tls-swap-fn controller) (car existing) snapshot)))
                    (progn
                      (when existing
                        (funcall unregister-fn port)
                        (funcall stop-fn (car existing))
                        (remhash port running))
                      (setf (gethash port running)
                            (cons (register-gateway-listener
                                   controller port (funcall start-fn port router resolver tls-paths) stop-fn)
                                  signature))))
                ;; Commit only after publication succeeds, so a failed swap retries.
                (if snapshot
                    (setf (gethash port (gateway-controller-tls-snapshots controller)) snapshot)
                    (remhash port (gateway-controller-tls-snapshots controller)))
                (if http-snapshot
                    (setf (gethash port (gateway-controller-http-snapshots controller)) http-snapshot)
                    (remhash port (gateway-controller-http-snapshots controller)))
                (setf (gethash port (gateway-controller-installed-listeners controller))
                      (gateway-installed-listener-records logical-listeners snapshot store
                                                          (unless shared-tls-p tls)))
                (if shared-tls-p
                    (progn
                      (remhash port tables)
                      (remhash port (gateway-controller-routing-bases controller))
                      (remhash port (gateway-controller-routing-indices controller)))
                    (setf (gethash port tables) (cons content router)
                          (gethash port (gateway-controller-routing-bases controller)) base
                          (gethash port (gateway-controller-routing-indices controller)) index))))))))
    (dolist (port (loop for p being the hash-keys of running collect p))
      (unless (member port desired-ports)
        (funcall unregister-fn port)
        (funcall stop-fn (car (gethash port running)))
        (remhash port running)
        (remhash port tables)
        (remhash port (gateway-controller-tls-snapshots controller))
        (remhash port (gateway-controller-http-snapshots controller))
        (remhash port (gateway-controller-installed-listeners controller))
        (remhash port (gateway-controller-routing-bases controller))
        (remhash port (gateway-controller-routing-indices controller))))
    (setf (gateway-controller-tls-materials controller) live-materials
          (gateway-controller-tls-material-users controller) (gateway-tls-material-use-counts controller)
          (gateway-controller-secret-ports controller) secret-ports
          (gateway-controller-parent-listeners controller)
          (gateway-parent-listener-index store gateways listener-sets))
    (gateway-controller-listeners controller)))

(defun gateway-parent-listener-index (store gateways &optional listener-sets)
  "Index controlled HTTP listener attachments in the full planner's source order."
  (let ((index (make-hash-table :test #'equal)) (rank 0))
    (dolist (gateway gateways)
      (when (gateway-controlled-p store gateway)
        (dolist (entry (gateway-listener-entries store gateway listener-sets))
          (let* ((owner (gateway-listener-entry-owner entry))
                 (metadata (gethash "metadata" owner))
                 (listener (gateway-listener-entry-listener entry))
                 (key (list (gateway-listener-owner-group owner) (or (gethash "kind" owner) "Gateway")
                            (gethash "namespace" metadata) (gethash "name" metadata))))
            (when (and (null (gateway-listener-entry-error entry))
                       (member (gethash "protocol" listener) '("HTTP" "HTTPS") :test #'equal))
              (push (list (gethash "name" listener) (gethash "port" listener) (incf rank) listener)
                    (gethash key index)))))))
    index))

(defun gateway-route-port-ranks (controller object)
  (let ((ports (make-hash-table)))
    (when object
      (let ((namespace (gethash "namespace" (gethash "metadata" object))))
        (loop for reference across (gethash "parentRefs" (gethash "spec" object) #())
              for parent-namespace = (or (gethash "namespace" reference) namespace)
              for parent-name = (gethash "name" reference)
              for parent-kind = (or (gethash "kind" reference) "Gateway")
              for parent-group = (or (gethash "group" reference) "gateway.networking.k8s.io")
              do (dolist (listener (gethash (list parent-group parent-kind parent-namespace parent-name)
                                           (gateway-controller-parent-listeners controller)))
                   (destructuring-bind (name port rank definition) listener
                     (when (and (gateway-parent-matches-p reference namespace parent-namespace parent-name name port
                                                         parent-kind parent-group)
                                (gateway-listener-route-hostnames object definition)
                                (gateway-listener-allows-route-p (gateway-controller-store controller) object parent-namespace definition))
                       (setf (gethash port ports) (max rank (gethash port ports 0)))))))))
    ports))

(defun gateway-route-at-port (controller object parsed port)
  "Restrict a parsed delta route to the hostnames admitted on PORT."
  (let ((namespace (gethash "namespace" (gethash "metadata" object)))
        (hosts nil))
    (loop for reference across (gethash "parentRefs" (gethash "spec" object) #())
          for parent-namespace = (or (gethash "namespace" reference) namespace)
          for parent-name = (gethash "name" reference)
          for parent-kind = (or (gethash "kind" reference) "Gateway")
          for parent-group = (or (gethash "group" reference) "gateway.networking.k8s.io")
          do (dolist (entry (gethash (list parent-group parent-kind parent-namespace parent-name)
                                     (gateway-controller-parent-listeners controller)))
               (destructuring-bind (name listener-port rank definition) entry
                 (declare (ignore rank))
                 (when (and (= port listener-port)
                            (gateway-parent-matches-p reference namespace parent-namespace parent-name name port
                                                      parent-kind parent-group)
                            (gateway-listener-allows-route-p (gateway-controller-store controller) object parent-namespace definition))
                   (setf hosts (append (gateway-listener-route-hostnames object definition) hosts))))))
    (when hosts
      (let ((route (copy-gw-route parsed)))
        (setf (gw-route-hostnames route)
              (unless (member nil hosts) (remove-duplicates hosts :test #'equal)))
        route))))

(defun gateway-incremental-candidate-order (controller port store)
  "Preserve full-plan ties: last matching listener, then namespace/name; Ingress follows."
  (let ((ranks (make-hash-table :test #'equal)))
    (labels ((rank (candidate)
               (let ((key (gw-candidate-source-key candidate)))
                 (or (gethash key ranks)
                     (setf (gethash key ranks)
                           (gethash port (gateway-route-port-ranks
                                          controller (get-core-resource store "httproutes" (second key) (third key))) 0))))))
      (lambda (a b)
        (cond ((gw-key> (gw-candidate-key a) (gw-candidate-key b)) t)
              ((gw-key> (gw-candidate-key b) (gw-candidate-key a)) nil)
              ((equal (gw-candidate-source-key a) (gw-candidate-source-key b)) nil)
              ((eq :ingress (first (gw-candidate-source-key a))) nil)
              ((eq :ingress (first (gw-candidate-source-key b))) t)
              ((/= (rank a) (rank b)) (< (rank a) (rank b)))
              (t (string< (gw-candidate-route-key a) (gw-candidate-route-key b))))))))

(defun converge-gateway-http-route-changes (controller old-store changes)
  "Parse changed routes only and publish replacement buckets on affected ports."
  (let ((store (gateway-controller-store controller))
        (by-port (make-hash-table)) (publications nil) (parsed-changes nil))
    (dolist (change changes)
      (let* ((key (car change))
             (old (ignore-errors (apply #'get-core-resource old-store key))) (new (cdr change))
             (old-route (and old (ignore-errors (parse-httproute old))))
             (new-route (and new (ignore-errors (parse-httproute new)))))
        (push (list old old-route new new-route) parsed-changes)
        (when old-route
          (maphash (lambda (port rank) (declare (ignore rank))
                     (let ((delta (or (gethash port by-port)
                                      (setf (gethash port by-port) (cons nil nil)))))
                       (push (gateway-route-at-port controller old old-route port) (car delta))))
                   (gateway-route-port-ranks controller old)))
        (when new-route
          (maphash (lambda (port rank) (declare (ignore rank))
                     (let ((delta (or (gethash port by-port)
                                      (setf (gethash port by-port) (cons nil nil)))))
                       (push (gateway-route-at-port controller new new-route port) (cdr delta))))
                   (gateway-route-port-ranks controller new)))))
    (maphash
     (lambda (port delta)
       (when (gethash port (gateway-controller-listeners controller))
         (let* ((tls (gethash port (gateway-controller-tls-snapshots controller)))
                (http (gethash port (gateway-controller-http-snapshots controller)))
                (table (gethash port (gateway-controller-routing-indices controller)))
                (next (unless (or tls http)
                        (update-gateway-routing-table
                         table (car delta) (cdr delta)
                         (gateway-incremental-candidate-order controller port store))))
                (snapshot (when (or tls http)
                            (gateway-update-tls-routes controller (or tls http) old-store parsed-changes)))
                (base (cond (http (gateway-http-snapshot-router snapshot))
                            ((not tls) (gateway-router-from-table next))))
                (router (cond (http base)
                              ((not tls) (bind-gateway-http-dispatcher base (gateway-controller-resolver controller))))))
           (push (list port next base router snapshot http) publications)))) by-port)
    (dolist (publication publications)
      (destructuring-bind (port index base router snapshot http) publication
        (if (and snapshot (not http))
            (progn
              (funcall (gateway-controller-tls-swap-fn controller)
                       (car (gethash port (gateway-controller-listeners controller))) snapshot)
              (setf (gethash port (gateway-controller-tls-snapshots controller)) snapshot))
            (progn
              (funcall (gateway-controller-swap-fn controller)
                       (car (gethash port (gateway-controller-listeners controller))) router)
              (when http
                (setf (gethash port (gateway-controller-http-snapshots controller)) snapshot))
              (setf (gethash port (gateway-controller-routing-tables controller)) (cons :incremental router)
                    (gethash port (gateway-controller-routing-bases controller)) base
                    (gethash port (gateway-controller-routing-indices controller)) index)))))))

;;; ---------------------------------------------------------------------------
;;; L4 (TCPRoute / TLSRoute / GRPCRoute) planning and convergence.

(defun gateway-l4-plan (gateways tcproutes tlsroutes grpcroutes controlled-p &optional view)
  "Pure planner for L4 listeners: a list of per-port plists
   (:port P :mode :tcp|:tls :tcp-routes (...) :sni-routes (...)) for TCP and TLS
   listeners on controlled Gateways. TCP uses attached TCPRoutes; TLS routes by
   SNI using attached TLSRoutes and GRPCRoutes."
  (let ((tcp-by-port (make-hash-table)) (sni-by-port (make-hash-table))
        (tcp-listeners (make-hash-table)) (ports '()))
    (dolist (gateway gateways)
      (when (funcall controlled-p gateway)
        (let* ((metadata (gethash "metadata" gateway))
               (gns (gethash "namespace" metadata))
               (gname (gethash "name" metadata))
               (spec (gethash "spec" gateway))
               (listeners (and spec (gethash "listeners" spec))))
          (when listeners
            (loop for listener across listeners
                  for protocol = (gethash "protocol" listener)
                  for port = (gethash "port" listener)
                  for lname = (gethash "name" listener)
                  do (cond
                       ((equal protocol "TCP")
                        (pushnew port ports)
                        (setf (gethash port tcp-listeners) t)
                        (dolist (route tcproutes)
                          (when (and (gateway-route-attaches-p route gns gname lname port)
                                     (gateway-listener-allows-route-p view route gns listener))
                            (push route (gethash port tcp-by-port)))))
                       ((equal protocol "TLS")
                        (pushnew port ports)
                        (dolist (route (append tlsroutes grpcroutes))
                          (when (and (gateway-route-attaches-p route gns gname lname port)
                                     (gateway-listener-allows-route-p view route gns listener))
                            (push route (gethash port sni-by-port)))))))))))
    (loop for port in (nreverse ports)
          for tcp = (gethash port tcp-by-port)
          for sni = (gethash port sni-by-port)
          collect (if (gethash port tcp-listeners)
                      (list :port port :mode :tcp
                            :tcp-routes (loop for o in (remove-duplicates (nreverse tcp))
                                              for r = (ignore-errors (parse-tcproute o)) when r collect r)
                            :sni-routes nil)
                      (list :port port :mode :tls :tcp-routes nil
                            :sni-routes (loop for o in (remove-duplicates (nreverse sni))
                                              for r = (ignore-errors (parse-sni-route o)) when r collect r))))))

(defun gateway-l4-dispatcher (mode tcp-routes sni-routes)
  "Build the dispatcher closure for an L4 listener."
  (if (eq mode :tcp)
      (let ((routes tcp-routes)) (lambda (sni) (declare (ignore sni)) (l4-tcp-dispatch routes)))
      (let ((routes sni-routes)) (lambda (sni) (l4-sni-dispatch routes sni)))))

(defun converge-gateway-l4-listeners (controller)
  "Reconcile L4 (TCP/TLS) proxy listeners to the plan: start new ports, hot-swap
   the dispatcher when routes change, restart on a mode change, and stop ports no
   longer desired."
  (let* ((store (gateway-controller-store controller))
         (resolver (gateway-controller-resolver controller))
         (gateways (list-core-resources store "gateways"))
         (plan (gateway-l4-plan gateways
                                (list-core-resources store "tcproutes")
                                (list-core-resources store "tlsroutes")
                                (list-core-resources store "grpcroutes")
                                (lambda (gateway) (gateway-controlled-p store gateway)) store))
         (running (gateway-controller-l4-listeners controller))
         (desired '()))
    (dolist (entry plan)
      (destructuring-bind (&key port mode tcp-routes sni-routes) entry
        (push port desired)
        (let ((dispatcher (let ((base (gateway-l4-dispatcher mode tcp-routes sni-routes)))
                            (if (gateway-controller-snapshot-resolvers-p controller)
                                (bind-gateway-l4-dispatcher base resolver) base)))
              (existing (gethash port running)))
          (if (and existing (eq (car existing) mode))
              (funcall (gateway-controller-l4-swap-fn controller) (cdr existing) dispatcher)
              (progn
                (when existing
                  (funcall (gateway-controller-unregister-fn controller) port)
                  (funcall (gateway-controller-l4-stop-fn controller) (cdr existing))
                  (remhash port running))
                (setf (gethash port running)
                      (cons mode
                            (register-gateway-listener
                             controller port
                             (funcall (gateway-controller-l4-start-fn controller) port mode dispatcher resolver)
                             (gateway-controller-l4-stop-fn controller)))))))))
    (dolist (port (loop for p being the hash-keys of running collect p))
      (unless (member port desired)
        (funcall (gateway-controller-unregister-fn controller) port)
        (funcall (gateway-controller-l4-stop-fn controller) (cdr (gethash port running)))
        (remhash port running)))
    (let ((records (fset:empty-ch-map nil)))
      (dolist (gateway gateways)
        (when (gateway-controlled-p store gateway)
          (loop for listener across (gethash "listeners" (gethash "spec" gateway) #())
                for mode = (cond ((equal "TCP" (gethash "protocol" listener)) :tcp)
                                 ((equal "TLS" (gethash "protocol" listener)) :tls))
                when (and mode (eql mode (car (gethash (gethash "port" listener) running))))
                  do (let ((entry (make-gateway-listener-entry :gateway gateway :owner gateway :listener listener)))
                       (setf records (fset:with records (gateway-listener-installation-key entry)
                                               (gateway-listener-installation-value entry nil)))))))
      ;; Publish generation evidence only after every lifecycle operation succeeds.
      (setf (gateway-controller-l4-installed-listeners controller) records))
    running))

(defun stop-gateway-controller (controller)
  "Stop every running listener this controller owns (node shutdown)."
  (let ((running (gateway-controller-listeners controller)))
    (maphash (lambda (port entry)
               (ignore-errors (funcall (gateway-controller-unregister-fn controller) port))
               (ignore-errors (funcall (gateway-controller-stop-fn controller) (car entry))))
             running)
    (clrhash running))
  (let ((l4 (gateway-controller-l4-listeners controller)))
    (maphash (lambda (port entry)
               (ignore-errors (funcall (gateway-controller-unregister-fn controller) port))
               (ignore-errors (funcall (gateway-controller-l4-stop-fn controller) (cdr entry))))
             l4)
    (clrhash l4))
  (clrhash (gateway-controller-tls-snapshots controller))
  (clrhash (gateway-controller-http-snapshots controller))
  (clrhash (gateway-controller-installed-listeners controller))
  (setf (gateway-controller-l4-installed-listeners controller) (fset:empty-ch-map nil))
  (clrhash (gateway-controller-secret-ports controller))
  (clrhash (gateway-controller-tls-materials controller))
  (clrhash (gateway-controller-tls-material-users controller)))
