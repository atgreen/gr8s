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
                                 gateway-namespace gateway-name listener-name listener-port)
  "True when an HTTPRoute PARENT-REF attaches to the given Gateway listener.
   kind/group default to Gateway/gateway.networking.k8s.io, namespace to the
   route's own; sectionName and port, when present, must equal the listener's."
  (let ((kind (or (gethash "kind" parent-ref) "Gateway"))
        (group (or (gethash "group" parent-ref) "gateway.networking.k8s.io"))
        (name (gethash "name" parent-ref))
        (namespace (or (gethash "namespace" parent-ref) route-namespace))
        (section (gethash "sectionName" parent-ref))
        (port (gethash "port" parent-ref)))
    (and (equal kind "Gateway")
         (equal group "gateway.networking.k8s.io")
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

(defun gateway-route-with-hostnames (route hosts)
  "Parse ROUTE using the effective listener hostname restrictions."
  (when hosts
    (let ((parsed (parse-httproute route)))
      (setf (gw-route-hostnames parsed)
            (unless (member nil hosts) (remove-duplicates hosts :test #'equal)))
      parsed)))

(defun gateway-listener-tls-ref (gateway-namespace listener &optional view)
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
          ((not (gateway-reference-permitted-p view gateway-namespace "Gateway" namespace "Secret" name))
           (values nil "RefNotPermitted"))
          (t (cons namespace name)))))

(defun gateway-listener-plan (gateways httproutes controlled-p &optional view)
  "Pure planner: return a list of per-port plists
   (:port P :protocol \"HTTP\"|\"HTTPS\" :tls (ns . secret)|NIL :routes (GW-ROUTE...))
   for every HTTP/HTTPS listener on a controlled Gateway, with each parentRef-
   attached HTTPRoute parsed into a GW-ROUTE. Unparseable HTTPRoutes are dropped
   (fail closed); routes attached via several listeners on one port are
   de-duplicated. The first listener seen on a port fixes its protocol/TLS."
  (let ((objects-by-port (make-hash-table))        ; port -> list of stored HTTPRoute objects
        (listener-by-port (make-hash-table))       ; port -> (protocol . tls-ref)
        (hosts-by-port (make-hash-table)))
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
                  when (member protocol '("HTTP" "HTTPS") :test #'equal)
                    do (let ((port (gethash "port" listener))
                             (lname (gethash "name" listener)))
                         (unless (gethash port listener-by-port)
                           (setf (gethash port listener-by-port)
                                 (cons protocol (and (equal protocol "HTTPS")
                                                     (gateway-listener-tls-ref gns listener view)))))
                         (dolist (route httproutes)
                           (when (and (gateway-route-attaches-p route gns gname lname port)
                                      (gateway-listener-allows-route-p view route gns listener))
                             (let ((hosts (gateway-listener-route-hostnames route listener)))
                               (when hosts
                                 (let ((by-route (or (gethash port hosts-by-port)
                                                     (setf (gethash port hosts-by-port)
                                                           (make-hash-table :test #'eq)))))
                                   (setf (gethash route by-route) (append hosts (gethash route by-route)))
                                   (push route (gethash port objects-by-port)))))))))))))
    (loop for port being the hash-keys of listener-by-port using (hash-value listener)
          for objects = (gethash port objects-by-port)
          collect (list :port port
                        :protocol (car listener)
                        :tls (cdr listener)
                        :routes (loop for object in (remove-duplicates (nreverse objects))
                                      for hosts = (gethash object (gethash port hosts-by-port))
                                      for route = (ignore-errors (gateway-route-with-hostnames object hosts))
                                      when route collect route)))))

;;; ---------------------------------------------------------------------------
;;; Convergence. Side effects (start/stop/swap) are injectable for testing.

(defstruct (gateway-controller (:constructor %make-gateway-controller))
  store resolver cert-dir
  (listeners (make-hash-table))         ; HTTP/HTTPS port -> (handle . tls-signature)
  (routing-tables (make-hash-table))    ; HTTP/HTTPS port -> (routing-content . dispatcher)
  (routing-bases (make-hash-table))     ; same dispatchers without a dependency-view binding
  (routing-indices (make-hash-table))
  parent-listeners
  snapshot-resolvers-p
  start-fn stop-fn swap-fn register-fn unregister-fn
  (l4-listeners (make-hash-table))      ; TCP/TLS port -> (mode . handle)
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
      t)))

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

(defun make-gateway-controller (store &key resolver cert-dir start-fn stop-fn swap-fn
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
  (list protocol tls-paths))

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

(defun converge-gateway-listeners (controller)
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
         (plan (merge-gateway-listener-plans
                (gateway-listener-plan gateways
                                       (list-core-resources store "httproutes")
                                       (lambda (gateway) (gateway-controlled-p store gateway)) store)
                (ingress-listener-plan store)))
         (running (gateway-controller-listeners controller))
         (tables (gateway-controller-routing-tables controller))
         (desired-ports '()))
    (dolist (entry plan)
      (destructuring-bind (&key port protocol tls routes) entry
        (let ((tls-paths (when (equal protocol "HTTPS")
                           (gateway-resolve-listener-tls store tls cert-dir)))
              (existing (gethash port running)))
          (unless (and (equal protocol "HTTPS") (null tls-paths))
            (push port desired-ports)
            (multiple-value-bind (router content base index) (gateway-router-for-port controller port routes)
              (let ((signature (gateway-listener-signature protocol tls-paths)))
                (if (and existing (equal (cdr existing) signature))
                    (unless (eq router (cdr (gethash port tables)))
                      (funcall swap-fn (car existing) router))
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
                (setf (gethash port tables) (cons content router)
                      (gethash port (gateway-controller-routing-bases controller)) base
                      (gethash port (gateway-controller-routing-indices controller)) index)))))))
    (dolist (port (loop for p being the hash-keys of running collect p))
      (unless (member port desired-ports)
        (funcall unregister-fn port)
        (funcall stop-fn (car (gethash port running)))
        (remhash port running)
        (remhash port tables)
        (remhash port (gateway-controller-routing-bases controller))
        (remhash port (gateway-controller-routing-indices controller))))
    (setf (gateway-controller-parent-listeners controller) (gateway-parent-listener-index store gateways))
    (gateway-controller-listeners controller)))

(defun gateway-parent-listener-index (store gateways)
  "Index controlled HTTP listener attachments in the full planner's source order."
  (let ((index (make-hash-table :test #'equal)) (rank 0))
    (dolist (gateway gateways)
      (when (gateway-controlled-p store gateway)
        (let* ((metadata (gethash "metadata" gateway))
               (key (list (gethash "namespace" metadata) (gethash "name" metadata))))
          (loop for listener across (gethash "listeners" (gethash "spec" gateway) #())
                when (member (gethash "protocol" listener) '("HTTP" "HTTPS") :test #'equal)
                  do (push (list (gethash "name" listener) (gethash "port" listener) (incf rank) listener)
                           (gethash key index))))))
    index))

(defun gateway-route-port-ranks (controller object)
  (let ((ports (make-hash-table)))
    (when object
      (let ((namespace (gethash "namespace" (gethash "metadata" object))))
        (loop for reference across (gethash "parentRefs" (gethash "spec" object) #())
              for parent-namespace = (or (gethash "namespace" reference) namespace)
              for parent-name = (gethash "name" reference)
              do (dolist (listener (gethash (list parent-namespace parent-name)
                                           (gateway-controller-parent-listeners controller)))
                   (destructuring-bind (name port rank definition) listener
                     (when (and (gateway-parent-matches-p reference namespace parent-namespace parent-name name port)
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
          do (dolist (entry (gethash (list parent-namespace parent-name)
                                     (gateway-controller-parent-listeners controller)))
               (destructuring-bind (name listener-port rank definition) entry
                 (declare (ignore rank))
                 (when (and (= port listener-port)
                            (gateway-parent-matches-p reference namespace parent-namespace parent-name name port)
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
        (by-port (make-hash-table)) (publications nil))
    (dolist (change changes)
      (let* ((key (car change))
             (old (ignore-errors (apply #'get-core-resource old-store key))) (new (cdr change))
             (old-route (and old (ignore-errors (parse-httproute old))))
             (new-route (and new (ignore-errors (parse-httproute new)))))
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
         (let* ((table (gethash port (gateway-controller-routing-indices controller)))
                (next (update-gateway-routing-table table (car delta) (cdr delta)
                                                   (gateway-incremental-candidate-order controller port store)))
                (base (gateway-router-from-table next))
                (router (bind-gateway-http-dispatcher base (gateway-controller-resolver controller))))
           (push (list port next base router) publications)))) by-port)
    (dolist (publication publications)
      (destructuring-bind (port index base router) publication
        (funcall (gateway-controller-swap-fn controller)
                 (car (gethash port (gateway-controller-listeners controller))) router)
        (setf (gethash port (gateway-controller-routing-tables controller)) (cons :incremental router)
              (gethash port (gateway-controller-routing-bases controller)) base
              (gethash port (gateway-controller-routing-indices controller)) index)))))

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
         (plan (gateway-l4-plan (list-core-resources store "gateways")
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
    (clrhash l4)))
