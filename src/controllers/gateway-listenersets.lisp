;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; ListenerSet ownership and admission. A ListenerSet retains its own API
;;;; identity and namespace while sharing its parent Gateway's sockets.

(in-package #:gr8s.controllers)

(defstruct gateway-listener-entry
  "A logical listener retains its owning resource and physical Gateway."
  gateway owner listener conflict routes)

(defun gateway-listener-port-supported-p (listener)
  (typep (gethash "port" listener) '(integer 1 65535)))

(defun gateway-listener-entry-error (entry)
  (or (unless (gateway-listener-port-supported-p (gateway-listener-entry-listener entry))
        "UnsupportedPort")
      (gateway-listener-entry-conflict entry)))

(defun gateway-listener-owner-group (owner)
  (let ((version (or (gethash "apiVersion" owner) "gateway.networking.k8s.io/v1")))
    (subseq version 0 (position #\/ version))))

(defun gateway-listener-owner-key (entry)
  (let* ((owner (gateway-listener-entry-owner entry))
         (metadata (gethash "metadata" owner)))
    (list (gateway-listener-owner-group owner) (or (gethash "kind" owner) "Gateway")
          (gethash "namespace" metadata) (gethash "name" metadata))))

(defun gateway-listener-installation-key (entry)
  (append (gateway-listener-owner-key entry)
          (list (gethash "uid" (gethash "metadata" (gateway-listener-entry-owner entry)))
                (gethash "name" (gateway-listener-entry-listener entry)))))

(defun gateway-listener-installation-value (entry secret-identity)
  (list (gethash "uid" (gethash "metadata" (gateway-listener-entry-gateway entry)))
        (gethash "generation" (gethash "metadata" (gateway-listener-entry-owner entry)) 1)
        (gr8s.resources::copy-core-object (gateway-listener-entry-listener entry))
        secret-identity))

(defun gateway-installed-listener-records (entries snapshot &optional view legacy-reference)
  "Capture identity only for logical listeners included in a published socket."
  (let ((records (make-hash-table :test 'equal)))
    (dolist (entry entries (fset:convert 'fset:ch-map records :default nil))
      (let* ((listener (gateway-listener-entry-listener entry))
             (key (gateway-listener-installation-key entry))
             (binding (when snapshot
                        (gateway-certificate-for-host (gateway-tls-snapshot-index snapshot)
                                                      (gethash "hostname" listener))))
             (legacy-identity
               (when (and legacy-reference (equal "HTTPS" (gethash "protocol" listener))
                          (equal legacy-reference (gateway-listener-entry-tls-ref view entry)))
                 (gateway-current-secret-identity view entry))))
        (when (or (equal "HTTP" (gethash "protocol" listener))
                  legacy-identity
                  (and binding (equal key (gateway-listener-installation-key
                                           (gateway-tls-binding-entry binding)))))
          (setf (gethash key records)
                (gateway-listener-installation-value entry
                                                     (or legacy-identity
                                                         (and binding (gateway-tls-binding-secret-identity binding))))))))))

(defun gateway-listener-installation-matches-p (installed entry secret-identity)
  "Compare immutable installation evidence without folding case in JSON strings."
  (and installed
       (equal (first installed)
              (gethash "uid" (gethash "metadata" (gateway-listener-entry-gateway entry))))
       (eql (second installed)
            (gethash "generation" (gethash "metadata" (gateway-listener-entry-owner entry)) 1))
       (gr8s.resources::core-json-equal-p (third installed) (gateway-listener-entry-listener entry))
       (equal (fourth installed) secret-identity)))

(defun gateway-current-secret-identity (view entry)
  "Identity for readiness comparison, without retaining Secret plaintext."
  (handler-case
      (let* ((reference (gateway-listener-entry-tls-ref view entry))
             (secret (and reference (get-core-resource view "secrets" (car reference) (cdr reference))))
             (metadata (gethash "metadata" secret))
             (data (gethash "data" secret)))
        (list (gethash "uid" metadata) (gethash "resourceVersion" metadata)
              (loop for key in '("tls.crt" "tls.key")
                    collect (ironclad:byte-array-to-hex-string
                             (ironclad:digest-sequence :sha256 (ag-grpc:base64-decode (gethash key data)))))))
    (error () nil)))

(defun gateway-listener-entry-programmed-p (controller entry &optional (view (gateway-controller-store controller)))
  "Require the current UID, generation, listener and Secret to match installed state."
  (let* ((listener (gateway-listener-entry-listener entry))
         (port (gethash "port" listener))
         (l4 (member (gethash "protocol" listener) '("TCP" "TLS") :test #'equal))
         (records (if l4 (gateway-controller-l4-installed-listeners controller)
                      (gethash port (gateway-controller-installed-listeners controller))))
         (installed (and records (fset:lookup records (gateway-listener-installation-key entry))))
         (owner (gateway-listener-entry-owner entry))
         (https (equal "HTTPS" (gethash "protocol" listener)))
         (secret (when https (gateway-current-secret-identity view entry))))
    (and installed (gethash port (if l4 (gateway-controller-l4-listeners controller)
                                   (gateway-controller-listeners controller)))
         (null (gateway-listener-entry-error entry))
         (or (equal "Gateway" (gethash "kind" owner "Gateway"))
             (gateway-listenerset-admitted-p view (gateway-listener-entry-gateway entry) owner))
         (or (not https) secret)
         (gateway-listener-installation-matches-p installed entry secret))))

(defun gateway-route-parent-index (routes)
  "Index route owners once; never scan every route for each ListenerSet."
  (let ((index (make-hash-table :test 'equal)))
    (dolist (route routes)
      (let ((namespace (gethash "namespace" (gethash "metadata" route)))
            (seen (make-hash-table :test 'equal)))
        (loop for reference across (gethash "parentRefs" (gethash "spec" route) #())
              for key = (list (or (gethash "group" reference) "gateway.networking.k8s.io")
                              (or (gethash "kind" reference) "Gateway")
                              (or (gethash "namespace" reference) namespace)
                              (gethash "name" reference))
              unless (gethash key seen)
                do (setf (gethash key seen) t)
                   (push route (gethash key index)))))
    (maphash (lambda (key routes) (setf (gethash key index) (nreverse routes))) index)
    index))

(defun gateway-distinct-route-objects (reverse-objects)
  "Preserve the last attachment's order while deduplicating routes in linear time."
  (let ((seen (make-hash-table :test 'eq)) (result nil))
    (dolist (object reverse-objects result)
      (unless (gethash object seen)
        (setf (gethash object seen) t)
        (push object result)))))

(defun gateway-listener-entry-tls-ref (view entry)
  "Authorize a certificate in the logical owner's namespace and API identity."
  (let* ((owner (gateway-listener-entry-owner entry))
         (kind (or (gethash "kind" owner) "Gateway"))
         (api-version (or (gethash "apiVersion" owner) "gateway.networking.k8s.io/v1"))
         (group (subseq api-version 0 (position #\/ api-version))))
    (gateway-listener-tls-ref
     (gethash "namespace" (gethash "metadata" owner))
     (gateway-listener-entry-listener entry) view kind group)))

(defun listenerset-precedes-p (left right)
  (let ((a (gethash "metadata" left)) (b (gethash "metadata" right)))
    ;; Kubernetes creationTimestamp is an RFC3339 UTC metav1.Time.
    (loop for field in '("creationTimestamp" "namespace" "name")
          for av = (gethash field a "")
          for bv = (gethash field b "")
          unless (equal av bv) return (string< av bv))))

(defun gateway-live-tls-material (controller reference live-materials)
  "Reuse parsed, verified content. LIVE-MATERIALS retains only this pass's references.
Authorization belongs to the caller and is never cached with the material."
  (when reference
    (handler-case
        (let* ((secret (get-core-resource (gateway-controller-store controller)
                                          "secrets" (car reference) (cdr reference)))
               (data (gethash "data" secret))
               (certificate (ag-grpc:base64-decode (gethash "tls.crt" data)))
               (key (ag-grpc:base64-decode (gethash "tls.key" data)))
               (identity (list (ironclad:byte-array-to-hex-string
                                (ironclad:digest-sequence :sha256 certificate))
                               (ironclad:byte-array-to-hex-string
                                (ironclad:digest-sequence :sha256 key))))
               (material (or (gethash identity live-materials)
                             (gethash identity (gateway-controller-tls-materials controller))
                             (multiple-value-bind (valid chain parsed-key)
                                 (gateway-check-tls-material certificate key)
                               (when valid
                                 (make-gateway-tls-binding :certificate chain :key parsed-key))))))
          (when material
            (setf (gethash identity live-materials) material)
            (values material (list (gethash "uid" (gethash "metadata" secret))
                                   (gethash "resourceVersion" (gethash "metadata" secret)) identity))))
      (error () nil))))

(defun gateway-reusable-tls-binding (controller entry secret-identity)
  "Reuse installed bindings only when a ListenerSet-only batch leaves them intact."
  (let* ((listener (gateway-listener-entry-listener entry))
         (port (gethash "port" listener))
         (key (gateway-listener-installation-key entry))
         (records (gethash port (gateway-controller-installed-listeners controller)))
         (installed (and records (fset:lookup records key)))
         (snapshot (gethash port (if (equal "HTTP" (gethash "protocol" listener))
                                    (gateway-controller-http-snapshots controller)
                                    (gateway-controller-tls-snapshots controller))))
         (binding (and snapshot
                       (gateway-certificate-for-host (gateway-tls-snapshot-index snapshot)
                                                     (gethash "hostname" listener)))))
    (when (and installed binding
               (equal key (gateway-listener-installation-key (gateway-tls-binding-entry binding)))
               (gateway-listener-installation-matches-p installed entry secret-identity))
      binding)))

(defun gateway-build-tls-snapshot (controller entries live-materials &optional reuse-bindings-p)
  "Build certificate and owner-scoped routing bindings for admitted HTTPS entries.
Invalid or unauthorized Secrets contribute neither a certificate nor routes.
REUSE-BINDINGS-P requires a ListenerSet-only batch: routes and other inputs must
be unchanged. Full reconciliation deliberately rebuilds backend routing state."
  (let ((bindings nil) (bootstrap nil) (parents (make-hash-table :test 'equal))
        (secrets (make-hash-table :test 'equal)))
    (dolist (entry entries)
      (when (and (null (gateway-listener-entry-error entry))
                 (equal "HTTPS" (gethash "protocol" (gateway-listener-entry-listener entry))))
        (multiple-value-bind (material secret-identity)
            (gateway-live-tls-material controller
                                       (gateway-listener-entry-tls-ref (gateway-controller-store controller) entry)
                                       live-materials)
          (when material
            (let ((reused (and reuse-bindings-p
                               (gateway-reusable-tls-binding controller entry secret-identity))))
              (multiple-value-bind (base table)
                  (unless reused (build-gateway-router (gateway-listener-entry-routes entry)))
                (let* ((logical (copy-gateway-listener-entry entry))
                       (router (if (gateway-controller-snapshot-resolvers-p controller)
                                 (bind-gateway-http-dispatcher base (gateway-controller-resolver controller))
                                 base))
                     (binding (or reused (make-gateway-tls-binding
                               :certificate (gateway-tls-binding-certificate material)
                               :key (gateway-tls-binding-key material) :router router
                               :entry logical :routing-table table :secret-identity secret-identity
                               :reference (gateway-listener-entry-tls-ref (gateway-controller-store controller) entry)))))
                (setf (gateway-listener-entry-routes logical) nil)
                (push binding (gethash (gateway-listener-owner-key entry) parents))
                (let ((reference (gateway-tls-binding-reference binding)))
                  (push binding (gethash (list (car reference) (cdr reference)) secrets)))
                (unless bootstrap (setf bootstrap binding))
                (push (list (gethash "hostname" (gateway-listener-entry-listener entry)) binding)
                      bindings))))))))
    (when bootstrap
      (let* ((port (gethash "port" (gateway-listener-entry-listener (gateway-tls-binding-entry bootstrap))))
             (old (and reuse-bindings-p (gethash port (gateway-controller-tls-snapshots controller))))
             (desired (nreverse bindings)))
        (make-gateway-tls-snapshot
         :bootstrap bootstrap
         :secrets (fset:convert 'fset:ch-map secrets :default nil)
         :parents (fset:convert 'fset:ch-map parents :default nil)
         :index (if old
                    (gateway-update-certificate-index (gateway-tls-snapshot-index old) desired)
                    (make-gateway-certificate-index desired)))))))

(defun gateway-http-route-content (routes)
  (gateway-routing-content
   (sort (copy-list routes) #'string<
         :key (lambda (route) (format nil "~A/~A" (gw-route-namespace route) (gw-route-name route))))))

(defun gateway-build-http-snapshot (controller entries &optional reuse-bindings-p)
  "Reuse unchanged logical HTTP tables while refreshing backend snapshots on repair."
  (let* ((port (and entries (gethash "port" (gateway-listener-entry-listener (first entries)))))
         (old (gethash port (gateway-controller-http-snapshots controller)))
         (bindings nil) (parents (make-hash-table :test 'equal)))
    (dolist (entry entries)
      (when (and (null (gateway-listener-entry-error entry))
                 (equal "HTTP" (gethash "protocol" (gateway-listener-entry-listener entry))))
        (let* ((previous (gateway-reusable-tls-binding controller entry nil))
               (unchanged (and previous
                               (or reuse-bindings-p
                                   (equal (gateway-http-route-content (gateway-listener-entry-routes entry))
                                          (gateway-http-route-content
                                           (gateway-listener-entry-routes (gateway-tls-binding-entry previous)))))))
               (reused (and unchanged
                            (or reuse-bindings-p (not (gateway-controller-snapshot-resolvers-p controller)))
                            previous)))
          (multiple-value-bind (base table)
              (unless reused
                (if unchanged
                    (values (gateway-router-from-table (gateway-tls-binding-routing-table previous))
                            (gateway-tls-binding-routing-table previous))
                    (build-gateway-router (gateway-listener-entry-routes entry))))
            (let* ((logical (copy-gateway-listener-entry entry))
                   (binding (or reused (make-gateway-tls-binding
                             :entry logical :routing-table table
                             :router (if (gateway-controller-snapshot-resolvers-p controller)
                                         (bind-gateway-http-dispatcher base (gateway-controller-resolver controller)) base)))))
              (push binding (gethash (gateway-listener-owner-key entry) parents))
              (push (list (gethash "hostname" (gateway-listener-entry-listener entry)) binding) bindings))))))
    (let* ((desired (nreverse bindings))
           (index (if old (gateway-update-certificate-index (gateway-tls-snapshot-index old) desired)
                      (make-gateway-certificate-index desired))))
      (if (and old (eq index (gateway-tls-snapshot-index old))) old
          (make-gateway-tls-snapshot :index index :parents (fset:convert 'fset:ch-map parents :default nil))))))

(defun gateway-http-snapshot-router (snapshot)
  "Select the most specific logical listener before considering any route."
  (lambda (host path method headers)
    (let ((binding (gateway-certificate-for-host (gateway-tls-snapshot-index snapshot) host)))
      (when binding
        (funcall (gateway-tls-binding-router binding) host path method headers)))))

(defun gateway-tls-route-for-entry (view entry object parsed)
  "Restrict a changed route to this logical listener's parent and permissions."
  (when (and object parsed)
    (destructuring-bind (group kind namespace name) (gateway-listener-owner-key entry)
      (let* ((listener (gateway-listener-entry-listener entry))
             (hosts (gateway-listener-route-hostnames object listener)))
        (when (and hosts
                   (gateway-listener-allows-route-p view object namespace listener)
                   (some (lambda (ref)
                           (gateway-parent-matches-p
                            ref (gethash "namespace" (gethash "metadata" object)) namespace name
                            (gethash "name" listener) (gethash "port" listener) kind group))
                         (gethash "parentRefs" (gethash "spec" object) #())))
          (let ((route (copy-gw-route parsed)))
            (setf (gw-route-hostnames route) (unless (member nil hosts) hosts))
            route))))))

(defun gateway-snapshot-replace-binding (snapshot old replacement)
  "Replace one binding in a copied snapshot, sharing all unrelated index branches."
  (let* ((entry (gateway-tls-binding-entry old))
         (parent (gateway-listener-owner-key entry))
         (reference (gateway-tls-binding-reference old))
         (secret (list (car reference) (cdr reference))))
    (setf (gateway-tls-snapshot-index snapshot)
          (gateway-replace-certificate-binding
           (gateway-tls-snapshot-index snapshot) (gethash "hostname" (gateway-listener-entry-listener entry)) replacement)
          (gateway-tls-snapshot-parents snapshot)
          (fset:with (gateway-tls-snapshot-parents snapshot) parent
                     (substitute replacement old (fset:lookup (gateway-tls-snapshot-parents snapshot) parent) :test #'eq))
          (gateway-tls-snapshot-secrets snapshot)
          (fset:with (gateway-tls-snapshot-secrets snapshot) secret
                     (substitute replacement old (fset:lookup (gateway-tls-snapshot-secrets snapshot) secret) :test #'eq)))
    (when (eq old (gateway-tls-snapshot-bootstrap snapshot))
      (setf (gateway-tls-snapshot-bootstrap snapshot) replacement)))
  snapshot)

(defun gateway-tls-material-use-counts (controller)
  (let ((counts (make-hash-table :test 'equal)))
    (maphash (lambda (port snapshot)
               (declare (ignore port))
               (fset:do-map (reference bindings (gateway-tls-snapshot-secrets snapshot))
                 (declare (ignore reference))
                 (dolist (binding bindings)
                   (incf (gethash (third (gateway-tls-binding-secret-identity binding)) counts 0)))))
             (gateway-controller-tls-snapshots controller))
    counts))

(defun converge-gateway-secret-changes (controller keys)
  "Swap valid shared-TLS material without parsing routes. NIL requests full recovery.
Stage every replacement first, so missing/invalid material cannot partially publish."
  (let ((by-port (make-hash-table)) (materials (make-hash-table :test 'equal))
        (publications nil))
    (dolist (key keys)
      (dolist (port (gethash (rest key) (gateway-controller-secret-ports controller)))
        (pushnew (rest key) (gethash port by-port) :test #'equal)))
    (maphash
     (lambda (port secrets)
       (let* ((current (gethash port (gateway-controller-tls-snapshots controller)))
              (next (and current (copy-gateway-tls-snapshot current)))
              (records (gethash port (gateway-controller-installed-listeners controller)))
              (replacements nil))
         (unless (and next records (gethash port (gateway-controller-listeners controller)))
           (return-from converge-gateway-secret-changes nil))
         (dolist (secret secrets)
           (let ((bindings (fset:lookup (gateway-tls-snapshot-secrets current) secret)))
             (unless bindings (return-from converge-gateway-secret-changes nil))
             (dolist (old bindings)
               (let* ((entry (gateway-tls-binding-entry old))
                      (reference (gateway-listener-entry-tls-ref (gateway-controller-store controller) entry)))
                 (unless (equal reference (gateway-tls-binding-reference old))
                   (return-from converge-gateway-secret-changes nil))
                 (multiple-value-bind (material identity) (gateway-live-tls-material controller reference materials)
                   (unless material (return-from converge-gateway-secret-changes nil))
                   (let ((replacement (copy-gateway-tls-binding old)))
                     (setf (gateway-tls-binding-certificate replacement) (gateway-tls-binding-certificate material)
                           (gateway-tls-binding-key replacement) (gateway-tls-binding-key material)
                           (gateway-tls-binding-secret-identity replacement) identity
                           records (fset:with records (gateway-listener-installation-key entry)
                                              (gateway-listener-installation-value entry identity)))
                     (gateway-snapshot-replace-binding next old replacement)
                     (push (cons old replacement) replacements)))))))
         (push (list port next records replacements) publications))) by-port)
    (dolist (publication publications)
      (destructuring-bind (port snapshot records replacements) publication
        (funcall (gateway-controller-tls-swap-fn controller)
                 (car (gethash port (gateway-controller-listeners controller))) snapshot)
        (setf (gethash port (gateway-controller-tls-snapshots controller)) snapshot
              (gethash port (gateway-controller-installed-listeners controller)) records)
        (dolist (pair replacements)
          (let ((old (third (gateway-tls-binding-secret-identity (car pair))))
                (new (third (gateway-tls-binding-secret-identity (cdr pair))))
                (users (gateway-controller-tls-material-users controller))
                (cache (gateway-controller-tls-materials controller)))
            (unless (equal old new)
              (when (zerop (decf (gethash old users)))
                (remhash old users) (remhash old cache))
              (incf (gethash new users 0)))
            (setf (gethash new cache) (gethash new materials))))))
    t))

(defun gateway-logical-candidate-before-p (left right)
  "Within one logical listener, equal matches follow namespace/name source order.
Other parents of a route cannot change its priority inside this listener."
  (cond ((gw-key> (gw-candidate-key left) (gw-candidate-key right)) t)
        ((gw-key> (gw-candidate-key right) (gw-candidate-key left)) nil)
        ((equal (gw-candidate-source-key left) (gw-candidate-source-key right)) nil)
        (t (string< (gw-candidate-route-key left) (gw-candidate-route-key right)))))

(defun gateway-update-tls-routes (controller snapshot old-store changes)
  "Replace only affected logical bindings, preserving untouched snapshot branches.
CHANGES contains (old-object old-parsed new-object new-parsed) tuples."
  (let ((affected (make-hash-table :test 'eq))
        (next (copy-gateway-tls-snapshot snapshot))
        (store (gateway-controller-store controller)))
    (dolist (change changes)
      (dolist (object (list (first change) (third change)))
        (when object
          (maphash (lambda (parent routes)
                     (declare (ignore routes))
                     (dolist (binding (fset:lookup (gateway-tls-snapshot-parents snapshot) parent))
                       (pushnew change (gethash binding affected) :test #'eq)))
                   (gateway-route-parent-index (list object))))))
    (maphash
     (lambda (binding deltas)
       (let ((entry (gateway-tls-binding-entry binding)) (removed nil) (added nil))
         (dolist (delta deltas)
           (destructuring-bind (old old-parsed new new-parsed) delta
             (let ((before (gateway-tls-route-for-entry old-store entry old old-parsed))
                   (after (gateway-tls-route-for-entry store entry new new-parsed)))
               (when before (push before removed))
               (when after (push after added)))))
         (when (or removed added)
           (let* ((table (update-gateway-routing-table
                          (gateway-tls-binding-routing-table binding) removed added
                          #'gateway-logical-candidate-before-p))
                  (base (gateway-router-from-table table))
                  (replacement (copy-gateway-tls-binding binding)))
             ;; HTTP keeps parsed route identities for no-op full reconciliation.
             ;; TLS bindings deliberately retain only their compiled tables.
             (when (equal "HTTP" (gethash "protocol" (gateway-listener-entry-listener entry)))
               (let ((logical (copy-gateway-listener-entry entry)))
                 (flet ((same-route-p (a b)
                          (and (eq (gw-route-kind a) (gw-route-kind b))
                               (equal (gw-route-namespace a) (gw-route-namespace b))
                               (equal (gw-route-name a) (gw-route-name b)))))
                   (setf (gateway-listener-entry-routes logical)
                         (append added
                                 (remove-if (lambda (route)
                                              (or (find route removed :test #'same-route-p)
                                                  (find route added :test #'same-route-p)))
                                            (gateway-listener-entry-routes entry)))))
                 (setf (gateway-tls-binding-entry replacement) logical)))
             (setf (gateway-tls-binding-routing-table replacement) table
                   (gateway-tls-binding-router replacement)
                   (if (gateway-controller-snapshot-resolvers-p controller)
                       (bind-gateway-http-dispatcher base (gateway-controller-resolver controller)) base))
             (gateway-snapshot-replace-binding next binding replacement)))))
     affected)
    next))

(defun gateway-listener-entries (view gateway listener-sets)
  "Merge admitted owners in precedence order, retaining conflicts for status.
Only winning entries reserve a port/hostname; lookup is linear after sorting."
  (let ((ports (make-hash-table)) (entries nil))
    (dolist (owner (cons gateway
                        (sort (remove-if-not
                               (lambda (set) (gateway-listenerset-admitted-p view gateway set))
                               listener-sets)
                              #'listenerset-precedes-p)))
      (loop for listener across (gethash "listeners" (gethash "spec" owner) #())
            for port = (gethash "port" listener)
            for protocol = (gethash "protocol" listener)
            for hostname = (gethash "hostname" listener)
            for state = (gethash port ports)
            for protocol-conflict = (and state (not (equal protocol (car state))))
            for hostname-conflict = (and state (gethash hostname (cdr state)))
            for conflict = (cond ((and protocol-conflict hostname-conflict) "ListenerConflict")
                                 (protocol-conflict "ProtocolConflict")
                                 (hostname-conflict "HostnameConflict"))
            do (push (make-gateway-listener-entry :gateway gateway :owner owner
                                                  :listener listener :conflict conflict) entries)
               (unless (or conflict (not (gateway-listener-port-supported-p listener)))
                 (unless state
                   (setf state (cons protocol (make-hash-table :test 'equalp))
                         (gethash port ports) state))
                 (setf (gethash hostname (cdr state)) t))))
    (nreverse entries)))

(defun listenerset-parent-matches-p (listener-set gateway)
  "Match a ListenerSet's parent without changing its namespace or API group."
  (let* ((metadata (gethash "metadata" listener-set))
         (gateway-metadata (gethash "metadata" gateway))
         (spec (gethash "spec" listener-set))
         (parent (and spec (gethash "parentRef" spec))))
    (and parent
         (equal (or (gethash "group" parent) "gateway.networking.k8s.io")
                "gateway.networking.k8s.io")
         (equal (or (gethash "kind" parent) "Gateway") "Gateway")
         (equal (gethash "name" parent) (gethash "name" gateway-metadata))
         (equal (or (gethash "namespace" parent) (gethash "namespace" metadata))
                (gethash "namespace" gateway-metadata)))))

(defun gateway-listenerset-admitted-p (view gateway listener-set)
  "Require a matching parent and explicit allowedListeners namespace admission."
  (let* ((spec (gethash "spec" gateway))
         (allowed (and spec (gethash "allowedListeners" spec)))
         (namespaces (and allowed (gethash "namespaces" allowed)))
         (from (and namespaces (gethash "from" namespaces)))
         (namespace (gethash "namespace" (gethash "metadata" listener-set))))
    (and (listenerset-parent-matches-p listener-set gateway)
         (cond ((equal from "All") t)
               ((equal from "Same")
                (equal namespace (gethash "namespace" (gethash "metadata" gateway))))
               ((equal from "Selector")
                (let ((selector (gethash "selector" namespaces))
                      (object (and view (ignore-errors
                                          (get-core-resource view "namespaces" nil namespace)))))
                  (and selector object
                       (gr8s.resources::workload-selector-matches-p
                        selector (gethash "labels" (gethash "metadata" object))))))
               (t nil)))))
