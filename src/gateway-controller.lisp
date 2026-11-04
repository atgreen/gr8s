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

(defun gateway-listener-plan (gateways httproutes controlled-p)
  "Pure planner: return an alist of (port . list-of-GW-ROUTE) for every HTTP
   listener on a controlled Gateway, with each parentRef-attached HTTPRoute
   parsed into a GW-ROUTE. Unparseable HTTPRoutes are dropped (fail closed).
   Routes attached to several listeners on one port are de-duplicated."
  (let ((objects-by-port (make-hash-table)))       ; port -> list of stored HTTPRoute objects
    (dolist (gateway gateways)
      (when (funcall controlled-p gateway)
        (let* ((metadata (gethash "metadata" gateway))
               (gns (gethash "namespace" metadata))
               (gname (gethash "name" metadata))
               (spec (gethash "spec" gateway))
               (listeners (and spec (gethash "listeners" spec))))
          (when listeners
            (loop for listener across listeners
                  when (equal "HTTP" (gethash "protocol" listener))
                    do (let ((port (gethash "port" listener))
                             (lname (gethash "name" listener)))
                         (dolist (route httproutes)
                           (when (gateway-route-attaches-p route gns gname lname port)
                             (push route (gethash port objects-by-port))))))))))
    (loop for port being the hash-keys of objects-by-port using (hash-value objects)
          collect (cons port
                        (loop for object in (remove-duplicates (nreverse objects))
                              for route = (ignore-errors (parse-httproute object))
                              when route collect route)))))

;;; ---------------------------------------------------------------------------
;;; Convergence. Side effects (start/stop/swap) are injectable for testing.

(defstruct (gateway-controller (:constructor %make-gateway-controller))
  store resolver
  (listeners (make-hash-table))         ; port -> listener handle
  start-fn stop-fn swap-fn)

(defun make-gateway-controller (store &key resolver start-fn stop-fn swap-fn)
  "A controller over STORE. RESOLVER maps a GW-BACKEND to an address (defaults to
   the ClusterIP service resolver). START-FN/STOP-FN/SWAP-FN manage listener
   lifecycle and default to the real Hunchentoot gateway acceptors."
  (%make-gateway-controller
   :store store
   :resolver (or resolver (make-service-backend-resolver store))
   :start-fn (or start-fn
                 (lambda (port router resolver)
                   (start-gateway-listener :port port :router router :resolver resolver)))
   :stop-fn (or stop-fn #'stop-gateway-listener)
   :swap-fn (or swap-fn
                (lambda (handle router) (setf (gateway-acceptor-router handle) router)))))

(defun converge-gateway-listeners (controller)
  "Reconcile running L7 proxy listeners to match the plan derived from the store:
   start listeners for new ports, hot-swap the compiled router for existing
   ports, and stop listeners whose ports are no longer desired."
  (let* ((store (gateway-controller-store controller))
         (plan (gateway-listener-plan (list-core-resources store "gateways")
                                      (list-core-resources store "httproutes")
                                      (lambda (gateway) (gateway-controlled-p store gateway))))
         (running (gateway-controller-listeners controller))
         (desired-ports '()))
    (dolist (entry plan)
      (destructuring-bind (port . routes) entry
        (push port desired-ports)
        (let ((router (compile-gateway-router routes))
              (handle (gethash port running)))
          (if handle
              (funcall (gateway-controller-swap-fn controller) handle router)
              (setf (gethash port running)
                    (funcall (gateway-controller-start-fn controller)
                             port router (gateway-controller-resolver controller)))))))
    (dolist (port (loop for p being the hash-keys of running collect p))
      (unless (member port desired-ports)
        (funcall (gateway-controller-stop-fn controller) (gethash port running))
        (remhash port running)))
    (gateway-controller-listeners controller)))

(defun stop-gateway-controller (controller)
  "Stop every running listener this controller owns (node shutdown)."
  (let ((running (gateway-controller-listeners controller)))
    (maphash (lambda (port handle)
               (declare (ignore port))
               (ignore-errors (funcall (gateway-controller-stop-fn controller) handle)))
             running)
    (clrhash running)))
