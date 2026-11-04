;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; The Gateway controller (podster-43k.3). It reconciles the durable Gateway
;;;; and HTTPRoute objects into the per-node data-plane desired state: for each
;;;; HTTP listener on a Gateway this controller owns, which listener port runs
;;;; and which HTTPRoutes (parentRef-attached) compile into its router. The pure
;;;; planner (gateway-listener-plan) maps the stored objects to port -> routes;
;;;; convergence starts, hot-swaps and stops L7 proxy listeners (gateway-proxy)
;;;; to match, recompiling each port's router when its routes change.

(in-package #:gr8s)

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
  (let* ((metadata (gethash "metadata" httproute))
         (route-namespace (gethash "namespace" metadata))
         (spec (gethash "spec" httproute))
         (parent-refs (and spec (gethash "parentRefs" spec))))
    (and parent-refs
         (some (lambda (ref)
                 (gateway-parent-matches-p ref route-namespace
                                           gateway-namespace gateway-name listener-name listener-port))
               (coerce parent-refs 'list)))))

(defun gateway-listener-tls-ref (gateway-namespace listener)
  "Return (namespace . secret-name) for an HTTPS listener's first Secret
   certificateRef, defaulting the namespace to the Gateway's, or NIL."
  (let* ((tls (gethash "tls" listener))
         (refs (and tls (gethash "certificateRefs" tls))))
    (when (and refs (plusp (length refs)))
      (let* ((ref (aref refs 0))
             (kind (or (gethash "kind" ref) "Secret"))
             (name (gethash "name" ref)))
        (when (and (equal kind "Secret") name)
          (cons (or (gethash "namespace" ref) gateway-namespace) name))))))

(defun gateway-listener-plan (gateways httproutes controlled-p)
  "Pure planner: return a list of per-port plists
   (:port P :protocol \"HTTP\"|\"HTTPS\" :tls (ns . secret)|NIL :routes (GW-ROUTE...))
   for every HTTP/HTTPS listener on a controlled Gateway, with each parentRef-
   attached HTTPRoute parsed into a GW-ROUTE. Unparseable HTTPRoutes are dropped
   (fail closed); routes attached via several listeners on one port are
   de-duplicated. The first listener seen on a port fixes its protocol/TLS."
  (let ((objects-by-port (make-hash-table))        ; port -> list of stored HTTPRoute objects
        (listener-by-port (make-hash-table)))       ; port -> (protocol . tls-ref)
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
                                                     (gateway-listener-tls-ref gns listener)))))
                         (dolist (route httproutes)
                           (when (gateway-route-attaches-p route gns gname lname port)
                             (push route (gethash port objects-by-port))))))))))
    (loop for port being the hash-keys of objects-by-port using (hash-value objects)
          for listener = (gethash port listener-by-port)
          collect (list :port port
                        :protocol (car listener)
                        :tls (cdr listener)
                        :routes (loop for object in (remove-duplicates (nreverse objects))
                                      for route = (ignore-errors (parse-httproute object))
                                      when route collect route)))))

;;; ---------------------------------------------------------------------------
;;; Convergence. Side effects (start/stop/swap) are injectable for testing.

(defstruct (gateway-controller (:constructor %make-gateway-controller))
  store resolver cert-dir
  (listeners (make-hash-table))         ; port -> (handle . tls-signature)
  start-fn stop-fn swap-fn)

(defun gateway-write-octets (path octets)
  (with-open-file (stream path :direction :output :element-type '(unsigned-byte 8)
                               :if-exists :supersede :if-does-not-exist :create)
    (write-sequence octets stream)))

(defun gateway-resolve-listener-tls (store tls-ref cert-dir)
  "Materialize an HTTPS listener's certificate. TLS-REF is (namespace . secret);
   write the kubernetes.io/tls Secret's cert/key under CERT-DIR and return a
   (:certificate PATH :key PATH) plist, or NIL when unresolvable."
  (when (and tls-ref cert-dir)
    (let* ((namespace (car tls-ref))
           (name (cdr tls-ref))
           (secret (ignore-errors (get-core-resource store "secrets" namespace name)))
           (data (and secret (gethash "data" secret)))
           (crt (and data (gethash "tls.crt" data)))
           (key (and data (gethash "tls.key" data))))
      (when (and crt key)
        (let* ((dir (uiop:ensure-directory-pathname cert-dir))
               (cert-path (merge-pathnames (format nil "~A-~A.crt" namespace name) dir))
               (key-path (merge-pathnames (format nil "~A-~A.key" namespace name) dir)))
          (ensure-directories-exist dir)
          (gateway-write-octets cert-path (ag-grpc:base64-decode crt))
          (gateway-write-octets key-path (ag-grpc:base64-decode key))
          (list :certificate (namestring cert-path) :key (namestring key-path)))))))

(defun make-gateway-controller (store &key resolver cert-dir start-fn stop-fn swap-fn)
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
                (lambda (handle router) (setf (gateway-acceptor-router handle) router)))))

(defun gateway-listener-signature (protocol tls-paths)
  "Transport identity of a listener; a change forces a restart (a router change
   alone only hot-swaps)."
  (list protocol tls-paths))

(defun converge-gateway-listeners (controller)
  "Reconcile running L7 proxy listeners to match the plan derived from the store:
   start listeners for new ports, hot-swap the compiled router when only routes
   change, restart when the transport (HTTP/HTTPS or cert) changes, and stop
   listeners whose ports are no longer desired. An HTTPS listener whose cert is
   unresolvable is not started (never served as plaintext)."
  (let* ((store (gateway-controller-store controller))
         (resolver (gateway-controller-resolver controller))
         (cert-dir (gateway-controller-cert-dir controller))
         (start-fn (gateway-controller-start-fn controller))
         (stop-fn (gateway-controller-stop-fn controller))
         (swap-fn (gateway-controller-swap-fn controller))
         (plan (gateway-listener-plan (list-core-resources store "gateways")
                                      (list-core-resources store "httproutes")
                                      (lambda (gateway) (gateway-controlled-p store gateway))))
         (running (gateway-controller-listeners controller))
         (desired-ports '()))
    (dolist (entry plan)
      (destructuring-bind (&key port protocol tls routes) entry
        (let* ((router (compile-gateway-router routes))
               (tls-paths (when (equal protocol "HTTPS")
                            (gateway-resolve-listener-tls store tls cert-dir)))
               (existing (gethash port running)))
          (cond
            ;; HTTPS with no resolvable cert: leave undesired so it is torn down.
            ((and (equal protocol "HTTPS") (null tls-paths)) nil)
            (t
             (push port desired-ports)
             (let ((signature (gateway-listener-signature protocol tls-paths)))
               (if (and existing (equal (cdr existing) signature))
                   (funcall swap-fn (car existing) router)
                   (progn
                     (when existing (funcall stop-fn (car existing)))
                     (setf (gethash port running)
                           (cons (funcall start-fn port router resolver tls-paths) signature))))))))))
    (dolist (port (loop for p being the hash-keys of running collect p))
      (unless (member port desired-ports)
        (funcall stop-fn (car (gethash port running)))
        (remhash port running)))
    (gateway-controller-listeners controller)))

(defun stop-gateway-controller (controller)
  "Stop every running listener this controller owns (node shutdown)."
  (let ((running (gateway-controller-listeners controller)))
    (maphash (lambda (port entry)
               (declare (ignore port))
               (ignore-errors (funcall (gateway-controller-stop-fn controller) (car entry))))
             running)
    (clrhash running)))
