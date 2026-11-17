;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Exercise the Gateway controller: GatewayClass ownership, parentRef-based
;;;; HTTPRoute attachment, the pure port->routes planner, and the start/hot-swap
;;;; /stop convergence of L7 proxy listeners (with injected lifecycle to avoid
;;;; binding real ports).

(in-package #:gr8s/tests)
(def-suite gateway-controller :in gr8s)
(in-suite gateway-controller)

(test gateway-l4-readiness-requires-installed-generation
  (with-temporary-store (store directory)
    (declare (ignore directory))
    (gwc-seed store)
    (let* ((objects (make-hash-table :test #'equal))
           (gateway (gr8s.resources::get-core-resource store "gateways" "default" "web"))
           (listener (aref (gethash "listeners" (gethash "spec" gateway)) 0))
           (entry (gr8s.controllers::make-gateway-listener-entry
                   :gateway gateway :owner gateway :listener listener)))
      (setf (gethash "protocol" listener) "TCP"
            (gethash '("gateways" "default" "web") objects) gateway
            (gethash '("gatewayclasses" nil "gr8s") objects)
            (gr8s.resources::get-core-resource store "gatewayclasses" nil "gr8s"))
      (let ((controller (gr8s.controllers::make-gateway-controller
                         (gr8s.agent::make-gateway-projection-store (gr8s.agent::gateway-resource-index objects))
                         :l4-start-fn (lambda (&rest args) (declare (ignore args)) :socket)
                         :l4-swap-fn (lambda (&rest args) (declare (ignore args)))
                         :l4-stop-fn (lambda (&rest args) (declare (ignore args))))))
        (is (not (gr8s.controllers::gateway-listener-entry-programmed-p controller entry)))
        (gr8s.controllers::converge-gateway-l4-listeners controller)
        (is (gr8s.controllers::gateway-listener-entry-programmed-p controller entry))
        (incf (gethash "generation" (gethash "metadata" gateway)))
        (is (not (gr8s.controllers::gateway-listener-entry-programmed-p controller entry)))
        (gr8s.controllers::converge-gateway-l4-listeners controller)
        (is (gr8s.controllers::gateway-listener-entry-programmed-p controller entry))
        (gr8s.controllers::stop-gateway-controller controller)
        (is (not (gr8s.controllers::gateway-listener-entry-programmed-p controller entry)))))))

(test listener-readiness-compares-selector-values-case-sensitively
  (let* ((gateway (gw-parse "{\"metadata\":{\"uid\":\"gateway-uid\"},\"spec\":{}}"))
         (listener (gw-parse "{\"name\":\"http\",\"port\":8080,\"protocol\":\"HTTP\",\"allowedRoutes\":{\"namespaces\":{\"from\":\"Selector\",\"selector\":{\"matchLabels\":{\"team\":\"Blue\"}}}}}"))
         (entry (gr8s.controllers::make-gateway-listener-entry
                 :gateway gateway :owner gateway :listener listener))
         (controller (gr8s.controllers::make-gateway-controller nil))
         (labels (gethash "matchLabels" (gethash "selector" (gethash "namespaces"
                           (gethash "allowedRoutes" listener))))))
    (setf (gethash 8080 (gr8s.controllers::gateway-controller-listeners controller)) '(:listener)
          (gethash 8080 (gr8s.controllers::gateway-controller-installed-listeners controller))
          (gr8s.controllers::gateway-installed-listener-records (list entry) nil))
    (is (gr8s.controllers::gateway-listener-entry-programmed-p controller entry))
    ;; Labels are case-sensitive; both values are valid API input.
    (setf (gethash "team" labels) "blue")
    (is (not (gr8s.controllers::gateway-listener-entry-programmed-p controller entry)))
    (setf (gethash "team" labels) "Blue")
    (is (gr8s.controllers::gateway-listener-entry-programmed-p controller entry))
    (setf (gethash "uid" (gethash "metadata" gateway)) "GATEWAY-UID")
    (is (not (gr8s.controllers::gateway-listener-entry-programmed-p controller entry)))))

(test stopping-gateway-controller-releases-tls-state
  (let ((controller (gr8s.controllers::make-gateway-controller nil)))
    (setf (gethash "material" (gr8s.controllers::gateway-controller-tls-materials controller)) :key
          (gethash 443 (gr8s.controllers::gateway-controller-tls-snapshots controller)) :snapshot)
    (gr8s.controllers::stop-gateway-controller controller)
    (is (zerop (hash-table-count (gr8s.controllers::gateway-controller-tls-materials controller))))
    (is (zerop (hash-table-count (gr8s.controllers::gateway-controller-tls-snapshots controller))))))

(defun check-listenerset-route-delta-equivalence (controller gateway owners template objects make-view)
  "Exercise a repeatable mixed sequence with at most three routes and two owners."
  (let ((seed 1729))
    (labels ((choose (limit)
               (setf seed (mod (+ (* seed 1103515245) 12345) 2147483648))
               (mod (floor seed 65536) limit))
             (results (snapshot)
               (loop for host in '("a.test" "b.test") append
                 (loop for path in '("/" "/only" "/only/child")
                       for binding = (gr8s.controllers::gateway-certificate-for-host
                                      (gr8s.controllers::gateway-tls-snapshot-index snapshot) host)
                       for dispatch = (funcall (gr8s.controllers::gateway-tls-binding-router binding)
                                               host path "GET" nil)
                       collect (when dispatch
                                 (gr8s.controllers::gw-backend-name
                                  (gr8s.controllers::gw-dispatch-backend dispatch)))))))
      (dotimes (iteration 24)
        (let* ((name (format nil "mixed-~D" (choose 3)))
               (key (list "httproutes" "apps" name))
               (action (choose 4))
               (old (gr8s.controllers::gateway-controller-store controller))
               (previous (gethash 443 (gr8s.controllers::gateway-controller-tls-snapshots controller)))
               (prior-results (results previous))
               (route (unless (zerop action) (gr8s.resources::copy-core-object template))))
          (when route
            (setf (gethash "name" (gethash "metadata" route)) name
                  (gethash "hostnames" (gethash "spec" route)) #("a.test" "b.test")
                  (gethash "parentRefs" (gethash "spec" route))
                  (coerce (loop for parent in (if (= action 3) '("a" "b") (list (if (= action 1) "a" "b")))
                                collect (let ((reference (gr8s.resources::copy-core-object
                                                          (aref (gethash "parentRefs" (gethash "spec" template)) 0))))
                                          (setf (gethash "name" reference) parent) reference)) 'vector))
            (let ((rule (aref (gethash "rules" (gethash "spec" route)) 0)))
              (setf (gethash "matches" rule)
                    (vector (gr8s.resources::core-object "path"
                             (gr8s.resources::core-object "type" "PathPrefix" "value" (if (zerop (choose 2)) "/" "/only"))))
                    (gethash "name" (aref (gethash "backendRefs" rule) 0)) (format nil "backend-~D" iteration))))
          (if route (setf (gethash key objects) route) (remhash key objects))
          (setf (gr8s.controllers::gateway-controller-store controller) (funcall make-view))
          (gr8s.controllers::converge-gateway-http-route-changes controller old (list (cons key route)))
          (let* ((view (gr8s.controllers::gateway-controller-store controller))
                 (plan (gr8s.controllers::gateway-listener-plan
                        (list gateway) (gr8s.resources::list-core-resources view "httproutes")
                        (constantly t) view owners))
                 (port (find 443 plan :key (lambda (entry) (getf entry :port))))
                 (rebuilt (gr8s.controllers::gateway-build-tls-snapshot
                           controller (getf port :logical-listeners) (make-hash-table :test 'equal))))
            (is (equal (results rebuilt)
                       (results (gethash 443 (gr8s.controllers::gateway-controller-tls-snapshots controller)))))
            (is (equal prior-results (results previous)))))))))

(test listenerset-convergence-updates-shared-tls-without-restarting
 (dolist (api '(("gateway.networking.k8s.io" "v1" "ListenerSet")
                ("gateway.networking.x-k8s.io" "v1alpha1" "XListenerSet")))
  (with-temporary-store (store directory)
    (gwc-seed store)
    (let* ((objects (make-hash-table :test 'equal))
           (gateway (gr8s.resources::get-core-resource store "gateways" "default" "web"))
           (a (listenerset-test-owner "a" "a" "2026-01-01T00:00:00Z" "a.test"))
           (b (listenerset-test-owner "b" "b" "2026-01-02T00:00:00Z" "b.test"))
           (secret-a (gateway-test-tls-secret "a"))
           (secret-b (gateway-test-tls-secret "b"))
           (route (gw-parse "{\"metadata\":{\"namespace\":\"apps\",\"name\":\"route\"},\"spec\":{\"parentRefs\":[{\"kind\":\"ListenerSet\",\"name\":\"a\"}],\"hostnames\":[\"a.test\"],\"rules\":[{\"backendRefs\":[{\"name\":\"old\",\"port\":80}]}]}}"))
           (starts 0) (stops 0))
      (let ((parent (aref (gethash "parentRefs" (gethash "spec" route)) 0)))
        (setf (gethash "group" parent) (first api)
              (gethash "kind" parent) (third api)))
      (setf (gethash "allowedListeners" (gethash "spec" gateway))
            (gw-parse "{\"namespaces\":{\"from\":\"All\"}}")
            (gethash '("gateways" "default" "web") objects) gateway
            (gethash '("httproutes" "apps" "route") objects) route
            (gethash '("gatewayclasses" nil "gr8s") objects)
            (gr8s.resources::get-core-resource store "gatewayclasses" nil "gr8s"))
      (loop for owner in (list a b) for secret in (list secret-a secret-b)
            for name in '("a" "b") do
        (setf (gethash "apiVersion" owner) (format nil "~A/~A" (first api) (second api))
              (gethash "kind" owner) (third api)
              (gethash "parentRef" (gethash "spec" owner))
              (gw-parse "{\"namespace\":\"default\",\"name\":\"web\"}")
              (gethash "tls" (aref (gethash "listeners" (gethash "spec" owner)) 0))
              (gr8s.resources::core-object "certificateRefs"
                                          (vector (gr8s.resources::core-object "name" name)))
              (gethash "namespace" (gethash "metadata" secret)) "apps"
              (gethash (list "listenersets" "apps" name) objects) owner
              (gethash (list "secrets" "apps" name) objects) secret))
      (flet ((view () (gr8s.agent::make-gateway-projection-store
                      (gr8s.agent::gateway-resource-index objects)))
             (snapshot-view ()
               (let ((source (gr8s.resources::make-foreign-resource-view nil)))
                 (maphash (lambda (key object)
                            (gr8s.resources::foreign-view-note source (first key) :added "unused" object)) objects)
                 (gr8s.resources::foreign-view-snapshot source))))
        (let ((controller (gr8s.controllers::make-gateway-controller
                           (view) :cert-dir directory
                           :start-fn (lambda (port router resolver tls)
                                       (declare (ignore resolver)) (incf starts)
                                       (if tls
                                           (make-instance 'gr8s.controllers::gateway-tls-acceptor
                                                          :port port :router router
                                                          :tls-snapshot (getf tls :snapshot))
                                           (make-instance 'gr8s.controllers::gateway-acceptor
                                                          :port port :router router)))
                           :stop-fn (lambda (handle) (declare (ignore handle)) (incf stops)))))
          (gr8s.controllers::converge-gateway-listeners controller)
          (is (equal '(443) (gethash '("apps" "a")
                                     (gr8s.controllers::gateway-controller-secret-ports controller))))
          (is (equal '(443) (gethash '("apps" "b")
                                     (gr8s.controllers::gateway-controller-secret-ports controller))))
          (let* ((handle (car (gethash 443 (gr8s.controllers::gateway-controller-listeners controller))))
                 (snapshot (and handle (gr8s.controllers::gateway-acceptor-tls-snapshot handle))))
            (is (not (null snapshot)))
            ;; Shared TLS dispatch is entirely owned by the selected binding.
            (is (null (gr8s.controllers::gateway-acceptor-router handle)))
            (is (null (gethash 443 (gr8s.controllers::gateway-controller-routing-indices controller))))
            (when snapshot
              (let ((entry (find a (gr8s.controllers::gateway-listener-entries
                                    (gr8s.controllers::gateway-controller-store controller) gateway (list a b))
                                 :key #'gr8s.controllers::gateway-listener-entry-owner :test #'eq)))
                (is (gr8s.controllers::gateway-listener-entry-programmed-p controller entry))
                (setf (gethash "uid" (gethash "metadata" a)) "replacement")
                (is (not (gr8s.controllers::gateway-listener-entry-programmed-p controller entry)))
                (setf (gethash "uid" (gethash "metadata" a)) "a"
                      (gethash "generation" (gethash "metadata" a)) 2)
                (is (not (gr8s.controllers::gateway-listener-entry-programmed-p controller entry)))
                (remhash "generation" (gethash "metadata" a))
                (setf (gethash "resourceVersion" (gethash "metadata" secret-a)) "new-version")
                (is (not (gr8s.controllers::gateway-listener-entry-programmed-p controller entry)))
                (remhash "resourceVersion" (gethash "metadata" secret-a))
                (is (gr8s.controllers::gateway-listener-entry-programmed-p controller entry)))
              (let* ((old-view (gr8s.controllers::gateway-controller-store controller))
                     (new-route (gw-parse (com.inuoe.jzon:stringify route)))
                     (old-a (gr8s.controllers::gateway-certificate-for-host
                             (gr8s.controllers::gateway-tls-snapshot-index snapshot) "a.test"))
                     (old-b (gr8s.controllers::gateway-certificate-for-host
                             (gr8s.controllers::gateway-tls-snapshot-index snapshot) "b.test")))
                (setf (gethash "name" (aref (gethash "backendRefs"
                                                    (aref (gethash "rules" (gethash "spec" new-route)) 0)) 0)) "new"
                      (gethash '("httproutes" "apps" "route") objects) new-route
                      (gr8s.controllers::gateway-controller-store controller) (view))
                (gr8s.controllers::converge-gateway-http-route-changes
                 controller old-view (list (cons '("httproutes" "apps" "route") new-route)))
                (is (null (gr8s.controllers::gateway-acceptor-router handle)))
                (is (null (gethash 443 (gr8s.controllers::gateway-controller-routing-indices controller))))
                (let* ((next (gr8s.controllers::gateway-acceptor-tls-snapshot handle))
                       (new-a (gr8s.controllers::gateway-certificate-for-host
                               (gr8s.controllers::gateway-tls-snapshot-index next) "a.test")))
                  (flet ((backend (binding)
                           (gr8s.controllers::gw-backend-name
                            (gr8s.controllers::gw-dispatch-backend
                             (funcall (gr8s.controllers::gateway-tls-binding-router binding)
                                      "a.test" "/" "GET" nil)))))
                    (is (equal "new" (backend new-a)))
                    (is (equal "old" (backend old-a))))
                  (is (eq old-b (gr8s.controllers::gateway-certificate-for-host
                                 (gr8s.controllers::gateway-tls-snapshot-index next) "b.test")))
                  (is (eq (gr8s.controllers::gateway-tls-binding-certificate old-a)
                          (gr8s.controllers::gateway-tls-binding-certificate new-a))))
                ;; Reparenting must withdraw the old owner's routing before publishing the new one.
                (let ((before (gr8s.controllers::gateway-controller-store controller))
                      (moved (gw-parse (com.inuoe.jzon:stringify new-route))))
                  (setf (gethash "name" (aref (gethash "parentRefs" (gethash "spec" moved)) 0)) "b"
                        (gethash "hostnames" (gethash "spec" moved)) #("b.test")
                        (gethash '("httproutes" "apps" "route") objects) moved
                        (gr8s.controllers::gateway-controller-store controller) (view))
                  (gr8s.controllers::converge-gateway-http-route-changes
                   controller before (list (cons '("httproutes" "apps" "route") moved)))
                  (let* ((next (gr8s.controllers::gateway-acceptor-tls-snapshot handle))
                         (index (gr8s.controllers::gateway-tls-snapshot-index next)))
                    (is (null (funcall (gr8s.controllers::gateway-tls-binding-router
                                        (gr8s.controllers::gateway-certificate-for-host index "a.test"))
                                       "a.test" "/" "GET" nil)))
                    (is (funcall (gr8s.controllers::gateway-tls-binding-router
                                  (gr8s.controllers::gateway-certificate-for-host index "b.test"))
                                 "b.test" "/" "GET" nil)))
                  (let ((before-delete (gr8s.controllers::gateway-controller-store controller)))
                    (remhash '("httproutes" "apps" "route") objects)
                    (setf (gr8s.controllers::gateway-controller-store controller) (view))
                    (gr8s.controllers::converge-gateway-http-route-changes
                     controller before-delete (list (cons '("httproutes" "apps" "route") nil)))
                    (let ((next (gr8s.controllers::gateway-acceptor-tls-snapshot handle)))
                      (is (null (funcall (gr8s.controllers::gateway-tls-binding-router
                                          (gr8s.controllers::gateway-certificate-for-host
                                           (gr8s.controllers::gateway-tls-snapshot-index next) "b.test"))
                                         "b.test" "/" "GET" nil)))))))
              (check-listenerset-route-delta-equivalence controller gateway (list a b) route objects #'view)
              (let ((new-host-route (gr8s.resources::copy-core-object route)))
                (setf (gethash "name" (gethash "metadata" new-host-route)) "new-host"
                      (gethash "hostnames" (gethash "spec" new-host-route)) #("changed.test")
                      (gethash '("httproutes" "apps" "new-host") objects) new-host-route))
              (let ((sibling (gr8s.resources::copy-core-object route)))
                (setf (gethash "name" (gethash "metadata" sibling)) "sibling"
                      (gethash "name" (aref (gethash "parentRefs" (gethash "spec" sibling)) 0)) "b"
                      (gethash "hostnames" (gethash "spec" sibling)) #("b.test")
                      (gethash '("httproutes" "apps" "sibling") objects) sibling
                      (gr8s.controllers::gateway-controller-store controller) (view))
                (gr8s.controllers::converge-gateway-listeners controller))
              (let* ((before (gr8s.controllers::gateway-acceptor-tls-snapshot handle))
                     (old-b (gr8s.controllers::gateway-certificate-for-host
                             (gr8s.controllers::gateway-tls-snapshot-index before) "b.test"))
                     (changed (gr8s.resources::copy-core-object a))
                     (old-view (snapshot-view)))
                (setf (gethash "hostname" (aref (gethash "listeners" (gethash "spec" changed)) 0)) "changed.test"
                      (gethash '("listenersets" "apps" "a") objects) changed)
                (let ((manager (gr8s.controllers::make-foreign-gateway-controllers
                                :view old-view :snapshot old-view :revision 1
                                :ingress (gr8s.controllers::make-gateway-controller old-view))))
                  (setf (gethash (gr8s.controllers::foreign-gateway-key gateway)
                                 (gr8s.controllers::foreign-gateway-controllers-gateways manager)) controller)
                  (let ((parser (symbol-function 'gr8s.controllers::parse-httproute))
                        (list-resources (symbol-function 'gr8s.resources::list-core-resources))
                        (route-lists 0)
                        (parsed nil))
                    (unwind-protect
                         (progn
                           (setf (symbol-function 'gr8s.controllers::parse-httproute)
                                 (lambda (object)
                                   (push (gethash "name" (gethash "metadata" object)) parsed)
                                   (funcall parser object))
                                 (symbol-function 'gr8s.resources::list-core-resources)
                                 (lambda (store resource &optional namespace)
                                   (when (equal resource "httproutes") (incf route-lists))
                                   (funcall list-resources store resource namespace)))
                           (is (gr8s.controllers::converge-foreign-gateway-snapshot
                                manager (snapshot-view) 2 (list (cons '("listenersets" "apps" "a") changed)) nil))
                           (is (zerop route-lists))
                           (is (not (member "sibling" parsed :test #'equal)))
                           (is (not (null (member "new-host" parsed :test #'equal)))))
                      (setf (symbol-function 'gr8s.controllers::parse-httproute) parser
                            (symbol-function 'gr8s.resources::list-core-resources) list-resources))))
                (let ((after (gr8s.controllers::gateway-acceptor-tls-snapshot handle)))
                  (let ((new-binding (gr8s.controllers::gateway-certificate-for-host
                                      (gr8s.controllers::gateway-tls-snapshot-index after) "changed.test")))
                    (is (not (null new-binding)))
                    (when new-binding
                      (is (not (null (funcall (gr8s.controllers::gateway-tls-binding-router new-binding)
                                             "changed.test" "/" "GET" nil))))))
                  (is (eq old-b (gr8s.controllers::gateway-certificate-for-host
                                 (gr8s.controllers::gateway-tls-snapshot-index after) "b.test")))
                  (is (null (gr8s.controllers::gateway-certificate-for-host
                             (gr8s.controllers::gateway-tls-snapshot-index after) "a.test")))
                  (is (not (null (gr8s.controllers::gateway-certificate-for-host
                                  (gr8s.controllers::gateway-tls-snapshot-index before) "a.test")))))
                (remhash '("httproutes" "apps" "sibling") objects)
                (remhash '("httproutes" "apps" "new-host") objects)
                (setf (gethash '("listenersets" "apps" "a") objects) a
                      (gr8s.controllers::gateway-controller-store controller) (view))
                (gr8s.controllers::converge-gateway-listeners controller))
              (let* ((before (gr8s.controllers::gateway-acceptor-tls-snapshot handle))
                     (old-view (let ((copy (make-hash-table :test 'equal)))
                                 (maphash (lambda (key value)
                                            (setf (gethash key copy) (gr8s.resources::copy-core-object value))) objects)
                                 (gr8s.agent::make-gateway-projection-store
                                  (gr8s.agent::gateway-resource-index copy))))
                     (old-a (gr8s.controllers::gateway-certificate-for-host
                             (gr8s.controllers::gateway-tls-snapshot-index before) "a.test"))
                     (old-b (gr8s.controllers::gateway-certificate-for-host
                             (gr8s.controllers::gateway-tls-snapshot-index before) "b.test")))
                (setf (gethash "resourceVersion" (gethash "metadata" secret-a)) "rotated"
                      (gr8s.controllers::gateway-controller-store controller) (view))
                (let ((manager (gr8s.controllers::make-foreign-gateway-controllers
                                :view old-view :snapshot old-view :revision 1
                                :ingress (gr8s.controllers::make-gateway-controller old-view))))
                  (setf (gethash (gr8s.controllers::foreign-gateway-key gateway)
                                 (gr8s.controllers::foreign-gateway-controllers-gateways manager)) controller)
                  (is (gr8s.controllers::converge-foreign-gateway-snapshot
                       manager (view) 2 (list (cons '("secrets" "apps" "a") secret-a)) nil)))
                (let* ((after (gr8s.controllers::gateway-acceptor-tls-snapshot handle))
                       (new-a (gr8s.controllers::gateway-certificate-for-host
                               (gr8s.controllers::gateway-tls-snapshot-index after) "a.test")))
                  (is (equal "rotated" (second (gr8s.controllers::gateway-tls-binding-secret-identity new-a))))
                  (is (not (equal "rotated" (second (gr8s.controllers::gateway-tls-binding-secret-identity old-a)))))
                  (is (eq (gr8s.controllers::gateway-tls-binding-router old-a)
                          (gr8s.controllers::gateway-tls-binding-router new-a)))
                  (is (eq (gr8s.controllers::gateway-tls-binding-routing-table old-a)
                          (gr8s.controllers::gateway-tls-binding-routing-table new-a)))
                  (is (eq old-b (gr8s.controllers::gateway-certificate-for-host
                                 (gr8s.controllers::gateway-tls-snapshot-index after) "b.test")))
                  (is (gr8s.controllers::gateway-listener-entry-programmed-p
                       controller (gr8s.controllers::gateway-tls-binding-entry new-a)))))
              ;; Distinct valid PEM content exercises material reference retirement.
              ;; Both listeners initially share the fixture's parsed material.
              (let* ((original (gethash "tls.crt" (gethash "data" secret-a)))
                     (changed (ag-grpc:base64-encode
                               (concatenate '(vector (unsigned-byte 8))
                                            (ag-grpc:base64-decode original) #(10)))))
                (setf (gethash "tls.crt" (gethash "data" secret-a)) changed
                      (gr8s.controllers::gateway-controller-store controller) (view))
                (is (gr8s.controllers::converge-gateway-secret-changes controller '(("secrets" "apps" "a"))))
                (is (= 2 (hash-table-count (gr8s.controllers::gateway-controller-tls-materials controller))))
                (setf (gethash "tls.crt" (gethash "data" secret-b)) changed
                      (gr8s.controllers::gateway-controller-store controller) (view))
                (is (gr8s.controllers::converge-gateway-secret-changes controller '(("secrets" "apps" "b"))))
                (is (= 1 (hash-table-count (gr8s.controllers::gateway-controller-tls-materials controller))))
                (is (= 2 (first (alexandria:hash-table-values
                                 (gr8s.controllers::gateway-controller-tls-material-users controller))))))
              (is (gr8s.controllers::gateway-certificate-for-host
                   (gr8s.controllers::gateway-tls-snapshot-index snapshot) "b.test"))
              (setf (gethash "tls.key" (gethash "data" secret-a)) "SGVsbG8="
                    (gr8s.controllers::gateway-controller-store controller) (view))
              (is (not (gr8s.controllers::converge-gateway-secret-changes controller '(("secrets" "apps" "a")))))
              (gr8s.controllers::converge-gateway-listeners controller)
              (is (= 2 starts))
              (is (zerop stops))
              (is (eq handle (car (gethash 443 (gr8s.controllers::gateway-controller-listeners controller)))))
              (let ((next (gr8s.controllers::gateway-acceptor-tls-snapshot handle)))
                (is (null (gr8s.controllers::gateway-certificate-for-host
                           (gr8s.controllers::gateway-tls-snapshot-index next) "a.test")))
                (is (gr8s.controllers::gateway-certificate-for-host
                     (gr8s.controllers::gateway-tls-snapshot-index next) "b.test")))
              (remhash "allowedListeners" (gethash "spec" gateway))
              (setf (gr8s.controllers::gateway-controller-store controller) (view))
              (gr8s.controllers::converge-gateway-listeners controller)
              (is (= 1 stops))
              (is (zerop (hash-table-count (gr8s.controllers::gateway-controller-tls-materials controller))))))))))))

(test listenerset-snapshots-reuse-live-material-and-withdraw-invalid-secrets
  (with-temporary-store (store directory)
    (values directory)
    (gr8s.resources::create-core-resource store "secrets" (gateway-test-tls-secret "cert") "apps")
    (let* ((controller (gr8s.controllers::make-gateway-controller store))
           (owners (list (listenerset-test-owner "a" "a" "2026-01-01T00:00:00Z" "a.test")
                         (listenerset-test-owner "b" "b" "2026-01-02T00:00:00Z" "b.test")))
           (entries (loop for owner in owners
                          for listener = (aref (gethash "listeners" (gethash "spec" owner)) 0)
                          do (setf (gethash "tls" listener)
                                   (gw-parse "{\"certificateRefs\":[{\"name\":\"cert\"}]}"))
                          collect (gr8s.controllers::make-gateway-listener-entry
                                   :owner owner :listener listener)))
           (live (make-hash-table :test 'equal))
           (snapshot (gr8s.controllers::gateway-build-tls-snapshot controller entries live)))
      (is (not (null snapshot)))
      (is (= 1 (hash-table-count live)))
      (when snapshot
        (let* ((index (gr8s.controllers::gateway-tls-snapshot-index snapshot))
               (a (gr8s.controllers::gateway-certificate-for-host index "a.test"))
               (b (gr8s.controllers::gateway-certificate-for-host index "b.test")))
          (is (not (eq a b)))
          (is (eq (gr8s.controllers::gateway-tls-binding-certificate a)
                  (gr8s.controllers::gateway-tls-binding-certificate b)))
          (setf (gr8s.controllers::gateway-controller-tls-materials controller) live)
          (let* ((next-live (make-hash-table :test 'equal))
                 (next (gr8s.controllers::gateway-build-tls-snapshot controller entries next-live)))
            (is (= 1 (hash-table-count next-live)))
            (is (eq (gr8s.controllers::gateway-tls-binding-key a)
                    (gr8s.controllers::gateway-tls-binding-key
                     (gr8s.controllers::gateway-tls-snapshot-bootstrap next)))))))
      (gr8s.resources::update-core-resource
       store "secrets" "apps" "cert"
       (lambda (secret) (setf (gethash "tls.key" (gethash "data" secret)) "SGVsbG8=") secret))
      (let ((next-live (make-hash-table :test 'equal)))
        (is (null (gr8s.controllers::gateway-build-tls-snapshot controller entries next-live)))
        (is (zerop (hash-table-count next-live)))))))

(test listenerset-plan-parses-a-shared-route-once
  (let* ((gateway (gw-parse "{\"metadata\":{\"namespace\":\"edge\",\"name\":\"public\"},\"spec\":{\"allowedListeners\":{\"namespaces\":{\"from\":\"All\"}},\"listeners\":[]}}"))
         (a (listenerset-test-owner "a" "a" "2026-01-01T00:00:00Z" "a.test"))
         (b (listenerset-test-owner "b" "b" "2026-01-02T00:00:00Z" "b.test"))
         (route (gw-parse "{\"metadata\":{\"namespace\":\"apps\",\"name\":\"route\"},\"spec\":{\"parentRefs\":[{\"kind\":\"ListenerSet\",\"name\":\"a\"},{\"kind\":\"ListenerSet\",\"name\":\"b\"}],\"rules\":[{\"backendRefs\":[{\"name\":\"backend\",\"port\":80}]}]}}"))
         (original (symbol-function 'gr8s.controllers::parse-httproute))
         (calls 0))
    (unwind-protect
         (progn
           (setf (symbol-function 'gr8s.controllers::parse-httproute)
                 (lambda (object) (incf calls) (funcall original object)))
           (let* ((plan (gr8s.controllers::gateway-listener-plan
                         (list gateway) (list route) (constantly t) nil (list a b)))
                  (entries (getf (first plan) :logical-listeners))
                  (routes (mapcar (lambda (entry)
                                    (first (gr8s.controllers::gateway-listener-entry-routes entry))) entries)))
             (is (= 1 calls))
             (is (= 2 (length routes)))
             (is (equal '(("a.test") ("b.test"))
                        (mapcar #'gr8s.controllers::gw-route-hostnames routes)))
             (is (not (eq (first routes) (second routes))))
             (is (equal '("a.test" "b.test")
                        (sort (copy-list (gr8s.controllers::gw-route-hostnames
                                          (first (getf (first plan) :routes)))) #'string<)))))
      (setf (symbol-function 'gr8s.controllers::parse-httproute) original))))

(test listenerset-tls-plan-retains-separate-logical-listeners
  (let* ((gateway (gw-parse "{\"metadata\":{\"namespace\":\"edge\",\"name\":\"public\"},\"spec\":{\"allowedListeners\":{\"namespaces\":{\"from\":\"All\"}},\"listeners\":[]}}"))
         (a (listenerset-test-owner "a" "a-uid" "2026-01-01T00:00:00Z" "a.test"))
         (b (listenerset-test-owner "b" "b-uid" "2026-01-02T00:00:00Z" "b.test"))
         (route (gw-parse "{\"metadata\":{\"namespace\":\"apps\",\"name\":\"app\"},\"spec\":{\"parentRefs\":[{\"kind\":\"ListenerSet\",\"name\":\"b\"}],\"hostnames\":[\"b.test\"],\"rules\":[{\"backendRefs\":[{\"name\":\"backend\",\"port\":80}]}]}}"))
         (plan (gr8s.controllers::gateway-listener-plan
                (list gateway) (list route) (constantly t) nil (list a b)))
         (listeners (getf (first plan) :logical-listeners)))
    (is (= 2 (length listeners)))
    (when (= 2 (length listeners))
      (is (eq a (gr8s.controllers::gateway-listener-entry-owner (first listeners))))
      (is (null (gr8s.controllers::gateway-listener-entry-routes (first listeners))))
      (is (= 1 (length (gr8s.controllers::gateway-listener-entry-routes (second listeners)))))
      (is (equal '("b.test")
                 (gr8s.controllers::gw-route-hostnames
                  (first (gr8s.controllers::gateway-listener-entry-routes (second listeners)))))))))

(defun listenerset-test-owner (name uid created host &optional (protocol "HTTPS"))
  (gr8s.resources::core-object
   "apiVersion" "gateway.networking.k8s.io/v1" "kind" "ListenerSet"
   "metadata" (gr8s.resources::core-object "namespace" "apps" "name" name "uid" uid
                                          "creationTimestamp" created)
   "spec" (gr8s.resources::core-object
           "parentRef" (gr8s.resources::core-object "name" "public" "namespace" "edge")
           "listeners" (vector (gr8s.resources::core-object
                                "name" "https" "port" 443 "protocol" protocol "hostname" host)))))

(test listenerset-route-planning-keeps-parent-kind-group-and-owner-namespace
  (let* ((gateway (com.inuoe.jzon:parse
                   "{\"metadata\":{\"name\":\"public\",\"namespace\":\"edge\"},\"spec\":{\"listeners\":[],\"allowedListeners\":{\"namespaces\":{\"from\":\"All\"}}}}"))
         (owner (listenerset-test-owner "tenant" "set-1" "2026-01-01T00:00:00Z" "tenant.example" "HTTP"))
         (route (com.inuoe.jzon:parse
                 "{\"apiVersion\":\"gateway.networking.k8s.io/v1\",\"kind\":\"HTTPRoute\",\"metadata\":{\"name\":\"route\",\"namespace\":\"apps\"},\"spec\":{\"parentRefs\":[{\"kind\":\"ListenerSet\",\"name\":\"tenant\"}],\"hostnames\":[\"tenant.example\"],\"rules\":[{\"backendRefs\":[{\"name\":\"backend\",\"port\":80}]}]}}"))
         (parent (aref (gethash "parentRefs" (gethash "spec" route)) 0)))
    (labels ((plan () (gr8s.controllers::gateway-listener-plan
                      (list gateway) (list route) (constantly t) nil (list owner)))
             (routes () (getf (first (plan)) :routes)))
      (is (= 1 (length (routes))))
      (is (equal '("tenant.example") (gr8s.controllers::gw-route-hostnames (first (routes)))))
      (setf (gethash "kind" parent) "Gateway")
      (is (null (routes)))
      (setf (gethash "kind" parent) "ListenerSet"
            (gethash "group" parent) "gateway.networking.x-k8s.io")
      (is (null (routes)))
      (setf (gethash "apiVersion" owner) "gateway.networking.x-k8s.io/v1alpha1")
      (is (= 1 (length (routes))))
      (setf (gethash "namespace" (gethash "metadata" route)) "edge"
            (gethash "namespace" parent) "apps")
      (is (null (routes)))
      (remhash "allowedListeners" (gethash "spec" gateway))
      (is (null (plan))))))

(test listenerset-convergence-publishes-and-withdraws-admitted-routes
  (with-temporary-store (store path)
    (values path)
    (gwc-seed store)
    (let* ((objects (make-hash-table :test 'equal))
           (gateway (gr8s.resources::get-core-resource store "gateways" "default" "web"))
           (owner (listenerset-test-owner "tenant" "set-1" "2026-01-01T00:00:00Z" "tenant.example" "HTTP"))
           (route (gr8s.resources::get-core-resource store "httproutes" "default" "app"))
           (stopped nil))
      (setf (gethash "allowedListeners" (gethash "spec" gateway))
            (com.inuoe.jzon:parse "{\"namespaces\":{\"from\":\"All\"}}")
            (gethash "parentRef" (gethash "spec" owner))
            (com.inuoe.jzon:parse "{\"namespace\":\"default\",\"name\":\"web\"}")
            (gethash "namespace" (gethash "metadata" route)) "apps"
            (gethash "parentRefs" (gethash "spec" route))
            (vector (com.inuoe.jzon:parse "{\"kind\":\"ListenerSet\",\"name\":\"tenant\"}"))
            (gethash "hostnames" (gethash "spec" route)) #("tenant.example")
            (gethash '("gateways" "default" "web") objects) gateway
            (gethash '("gatewayclasses" nil "gr8s") objects)
            (gr8s.resources::get-core-resource store "gatewayclasses" nil "gr8s")
            (gethash '("listenersets" "apps" "tenant") objects) owner
            (gethash '("httproutes" "apps" "app") objects) route)
      (labels ((snapshot () (gr8s.agent::make-gateway-projection-store
                            (gr8s.agent::gateway-resource-index objects))))
        (let ((controller (gr8s.controllers::make-gateway-controller
                           (snapshot)
                           :start-fn (lambda (port &rest arguments) (declare (ignore arguments)) port)
                           :stop-fn (lambda (handle) (push handle stopped))
                           :swap-fn (lambda (&rest arguments) (declare (ignore arguments))))))
          (gr8s.controllers::converge-gateway-listeners controller)
          (let ((router (gethash 443 (gr8s.controllers::gateway-controller-routing-bases controller))))
            (is (functionp router))
            (when router (is (funcall router "tenant.example" "/" "GET" nil))))
          (is (gethash 443 (gr8s.controllers::gateway-route-port-ranks controller route)))
          (remhash "allowedListeners" (gethash "spec" gateway))
          (setf (gr8s.controllers::gateway-controller-store controller) (snapshot))
          (gr8s.controllers::converge-gateway-listeners controller)
          (is (null (gethash 443 (gr8s.controllers::gateway-controller-routing-bases controller))))
          (is (member 443 stopped))
          (is (gethash 8080 (gr8s.controllers::gateway-controller-listeners controller))))))))

(test listenerset-http-removal-preserves-gateway-routes
  (with-temporary-store (store directory)
    (declare (ignore directory))
    (gwc-seed store)
    (let* ((objects (make-hash-table :test 'equal))
           (gateway (gr8s.resources::get-core-resource store "gateways" "default" "web"))
           (owner (listenerset-test-owner "child" "child" "2026-01-01T00:00:00Z" "child.example.test" "HTTP")))
      (setf (gethash "allowedListeners" (gethash "spec" gateway))
            (gr8s.resources::core-object "namespaces" (gr8s.resources::core-object "from" "All"))
            (gethash "port" (aref (gethash "listeners" (gethash "spec" gateway)) 0)) 443
            (gethash "parentRef" (gethash "spec" owner))
            (gr8s.resources::core-object "namespace" "default" "name" "web")
            (gethash '("gateways" "default" "web") objects) gateway
            (gethash '("gatewayclasses" nil "gr8s") objects)
            (gr8s.resources::get-core-resource store "gatewayclasses" nil "gr8s")
            (gethash '("httproutes" "default" "app") objects)
            (gr8s.resources::get-core-resource store "httproutes" "default" "app")
            (gethash '("listenersets" "apps" "child") objects) owner)
      (flet ((view () (gr8s.agent::make-gateway-projection-store (gr8s.agent::gateway-resource-index objects))))
        (let ((controller (gr8s.controllers::make-gateway-controller
                           (view) :start-fn (lambda (&rest args) (declare (ignore args)) :http)
                           :swap-fn (lambda (&rest args) (declare (ignore args)))
                           :stop-fn (lambda (&rest args) (declare (ignore args))))))
          (gr8s.controllers::converge-gateway-listeners controller)
          (flet ((serves () (funcall (gethash 443 (gr8s.controllers::gateway-controller-routing-bases controller))
                                    "app.example.com" "/" "GET" nil)))
            (is (serves))
            (remhash '("listenersets" "apps" "child") objects)
            (setf (gr8s.controllers::gateway-controller-store controller) (view))
            (gr8s.controllers::converge-gateway-listeners controller :reuse-tls-bindings-p t)
            (is (serves))))))))

(test listenerset-http-selects-logical-host-before-route
  (with-temporary-store (store path)
    (declare (ignore path))
    (gwc-seed store)
    (let* ((objects (make-hash-table :test 'equal))
           (gateway (gr8s.resources::get-core-resource store "gateways" "default" "web"))
           (a (listenerset-test-owner "a" "a" "2026-01-01T00:00:00Z" "*.example.test" "HTTP"))
           (b (listenerset-test-owner "b" "b" "2026-01-02T00:00:00Z" "app.example.test" "HTTP"))
           (route (gr8s.resources::get-core-resource store "httproutes" "default" "app")))
      (setf (gethash "allowedListeners" (gethash "spec" gateway))
            (gr8s.resources::core-object "namespaces" (gr8s.resources::core-object "from" "All"))
            (gethash "namespace" (gethash "metadata" route)) "apps"
            (gethash "hostnames" (gethash "spec" route)) #("*.example.test")
            (gethash "parentRefs" (gethash "spec" route))
            (vector (gr8s.resources::core-object "kind" "ListenerSet" "name" "a"))
            (gethash "matches" (aref (gethash "rules" (gethash "spec" route)) 0))
            (vector (gr8s.resources::core-object "path" (gr8s.resources::core-object "type" "PathPrefix" "value" "/private")))
            (gethash '("gateways" "default" "web") objects) gateway
            (gethash '("gatewayclasses" nil "gr8s") objects)
            (gr8s.resources::get-core-resource store "gatewayclasses" nil "gr8s")
            (gethash '("listenersets" "apps" "a") objects) a
            (gethash '("listenersets" "apps" "b") objects) b
            (gethash '("httproutes" "apps" "app") objects) route)
      (dolist (owner (list a b))
        (setf (gethash "parentRef" (gethash "spec" owner))
              (gr8s.resources::core-object "namespace" "default" "name" "web")))
      (labels ((view () (gr8s.agent::make-gateway-projection-store (gr8s.agent::gateway-resource-index objects))))
        (let ((controller (gr8s.controllers::make-gateway-controller
                           (view) :start-fn (lambda (&rest args) (declare (ignore args)) :http)
                           :swap-fn (lambda (&rest args) (declare (ignore args)))
                           :stop-fn (lambda (&rest args) (declare (ignore args))))))
          (gr8s.controllers::converge-gateway-listeners controller)
          (flet ((router () (gethash 443 (gr8s.controllers::gateway-controller-routing-bases controller))))
            (let ((before (router)) (old (gr8s.controllers::gateway-controller-store controller)))
              (gr8s.controllers::converge-gateway-listeners controller)
              (is (eq before (router)))
              (is (null (funcall before "app.example.test" "/private" "GET" nil)))
              (is (funcall before "other.example.test" "/private" "GET" nil))
              (setf (gethash "matches" (aref (gethash "rules" (gethash "spec" route)) 0))
                    (vector (gr8s.resources::core-object "path" (gr8s.resources::core-object "type" "PathPrefix" "value" "/changed")))
                    (gr8s.controllers::gateway-controller-store controller) (view))
              (gr8s.controllers::converge-gateway-http-route-changes
               controller old (list (cons '("httproutes" "apps" "app") route)))
              (is (null (funcall (router) "app.example.test" "/changed" "GET" nil)))
              (is (funcall (router) "other.example.test" "/changed" "GET" nil))
              (is (null (funcall (router) "other.example.test" "/private" "GET" nil)))
              (is (funcall before "other.example.test" "/private" "GET" nil))
              (let ((updated (router)))
                (gr8s.controllers::converge-gateway-listeners controller)
                (is (eq updated (router))))
              (flet ((binding (host)
                       (gr8s.controllers::gateway-certificate-for-host
                        (gr8s.controllers::gateway-tls-snapshot-index
                         (gethash 443 (gr8s.controllers::gateway-controller-http-snapshots controller))) host)))
                (let ((unchanged (binding "other.example.test"))
                      (changed (binding "app.example.test")))
                  (setf (gethash "generation" (gethash "metadata" b)) 2
                        (gr8s.controllers::gateway-controller-store controller) (view))
                  (gr8s.controllers::converge-gateway-listeners controller :reuse-tls-bindings-p t)
                  (is (eq unchanged (binding "other.example.test")))
                  (is (not (eq changed (binding "app.example.test"))))
                  (is (funcall (router) "other.example.test" "/changed" "GET" nil))
                  (is (null (funcall (router) "app.example.test" "/changed" "GET" nil))))))))))))

(test listenerset-listener-order-preserves-owners-and-resolves-conflicts
  (let* ((gateway (com.inuoe.jzon:parse
                   "{\"apiVersion\":\"gateway.networking.k8s.io/v1\",\"kind\":\"Gateway\",\"metadata\":{\"namespace\":\"edge\",\"name\":\"public\",\"uid\":\"gw-1\"},\"spec\":{\"allowedListeners\":{\"namespaces\":{\"from\":\"All\"}},\"listeners\":[{\"name\":\"https\",\"port\":443,\"protocol\":\"HTTPS\",\"hostname\":\"parent.example\"}]}}"))
         (old (listenerset-test-owner "a" "set-a" "2026-01-01T00:00:00Z" "tenant.example"))
         (tie (listenerset-test-owner "b" "set-b" "2026-01-01T00:00:00Z" "tenant.example"))
         (new (listenerset-test-owner "c" "set-c" "2026-01-02T00:00:00Z" "parent.example"))
         (plain (listenerset-test-owner "d" "set-d" "2026-01-03T00:00:00Z" "plain.example" "HTTP"))
         (entries (gr8s.controllers::gateway-listener-entries nil gateway (list plain new tie old))))
    (is (equal (list gateway old tie new plain)
               (mapcar #'gr8s.controllers::gateway-listener-entry-owner entries)))
    (is (every (lambda (entry) (eq gateway (gr8s.controllers::gateway-listener-entry-gateway entry))) entries))
    (is (equal '(nil nil "HostnameConflict" "HostnameConflict" "ProtocolConflict")
               (mapcar #'gr8s.controllers::gateway-listener-entry-conflict entries)))
    ;; Same listener names in different resources are valid and retain UID identity.
    (is (equal '("gw-1" "set-a" "set-b" "set-c" "set-d")
               (mapcar (lambda (entry)
                         (gethash "uid" (gethash "metadata"
                                                (gr8s.controllers::gateway-listener-entry-owner entry)))) entries)))
    (remhash "allowedListeners" (gethash "spec" gateway))
    (is (= 1 (length (gr8s.controllers::gateway-listener-entries nil gateway (list old tie)))))))

(test listenerset-admission-defaults-to-deny-and-checks-parent-identity
  (let* ((gateway (com.inuoe.jzon:parse
                   "{\"metadata\":{\"namespace\":\"edge\",\"name\":\"public\"},\"spec\":{}}"))
         (set (com.inuoe.jzon:parse
               "{\"metadata\":{\"namespace\":\"apps\",\"name\":\"tenant\"},\"spec\":{\"parentRef\":{\"name\":\"public\",\"namespace\":\"edge\"}}}"))
         (parent (gethash "parentRef" (gethash "spec" set))))
    (is (not (gr8s.controllers::gateway-listenerset-admitted-p nil gateway set)))
    (setf (gethash "allowedListeners" (gethash "spec" gateway))
          (com.inuoe.jzon:parse "{\"namespaces\":{\"from\":\"All\"}}"))
    (is (gr8s.controllers::gateway-listenerset-admitted-p nil gateway set))
    (dolist (entry '(("name" . "other") ("namespace" . "other")
                     ("kind" . "Service") ("group" . "other.example")))
      (let ((old (gethash (car entry) parent)))
        (setf (gethash (car entry) parent) (cdr entry))
        (is (not (gr8s.controllers::gateway-listenerset-admitted-p nil gateway set)))
        (if old (setf (gethash (car entry) parent) old) (remhash (car entry) parent))))
    ;; Missing parent namespace is relative to the ListenerSet, not the Gateway.
    (remhash "namespace" parent)
    (is (not (gr8s.controllers::gateway-listenerset-admitted-p nil gateway set)))
    (setf (gethash "namespace" (gethash "metadata" set)) "edge")
    (is (gr8s.controllers::gateway-listenerset-admitted-p nil gateway set))
    (setf (gethash "allowedListeners" (gethash "spec" gateway))
          (com.inuoe.jzon:parse "{\"namespaces\":{\"from\":\"Same\"}}"))
    (is (gr8s.controllers::gateway-listenerset-admitted-p nil gateway set))
    (setf (gethash "namespace" parent) "edge"
          (gethash "namespace" (gethash "metadata" set)) "apps")
    (is (not (gr8s.controllers::gateway-listenerset-admitted-p nil gateway set)))))

(test listenerset-admission-observes-namespace-selector-revocation
  (with-temporary-store (store path)
    (values path)
    (gr8s.resources::create-core-resource
     store "namespaces"
     (com.inuoe.jzon:parse "{\"metadata\":{\"name\":\"apps\",\"labels\":{\"team\":\"trusted\"}}}") nil)
    (let ((gateway (com.inuoe.jzon:parse
                    "{\"metadata\":{\"namespace\":\"edge\",\"name\":\"public\"},\"spec\":{\"allowedListeners\":{\"namespaces\":{\"from\":\"Selector\",\"selector\":{\"matchLabels\":{\"team\":\"trusted\"}}}}}}"))
          (set (com.inuoe.jzon:parse
                "{\"metadata\":{\"namespace\":\"apps\",\"name\":\"tenant\"},\"spec\":{\"parentRef\":{\"name\":\"public\",\"namespace\":\"edge\"}}}")))
      (is (gr8s.controllers::gateway-listenerset-admitted-p store gateway set))
      (gr8s.resources::update-core-resource
       store "namespaces" nil "apps"
       (lambda (object) (remhash "labels" (gethash "metadata" object)) object))
      (is (not (gr8s.controllers::gateway-listenerset-admitted-p store gateway set))))))

(test listenerset-secret-grants-use-the-owning-kind-group-and-namespace
  (let* ((objects (make-hash-table :test 'equal))
         (owner (listenerset-test-owner "tenant" "set-1" "2026-01-01T00:00:00Z" "tenant.example"))
         (listener (aref (gethash "listeners" (gethash "spec" owner)) 0))
         (entry (gr8s.controllers::make-gateway-listener-entry :owner owner :listener listener))
         (grant (com.inuoe.jzon:parse
                 "{\"spec\":{\"from\":[{\"group\":\"gateway.networking.k8s.io\",\"kind\":\"Gateway\",\"namespace\":\"apps\"}],\"to\":[{\"group\":\"\",\"kind\":\"Secret\",\"name\":\"cert\"}]}}")))
    (setf (gethash "tls" listener)
          (com.inuoe.jzon:parse "{\"certificateRefs\":[{\"name\":\"cert\",\"namespace\":\"certs\"}]}")
          (gethash '("referencegrants" "certs" "allow") objects) grant)
    (labels ((reference ()
               (gr8s.controllers::gateway-listener-entry-tls-ref
                (gr8s.agent::make-gateway-projection-store (gr8s.agent::gateway-resource-index objects)) entry)))
      (is (null (reference)))
      (setf (gethash "kind" (aref (gethash "from" (gethash "spec" grant)) 0)) "ListenerSet")
      (is (equal '("certs" . "cert") (reference)))
      (setf (gethash "apiVersion" owner) "gateway.networking.x-k8s.io/v1alpha1")
      (is (null (reference)))
      (setf (gethash "group" (aref (gethash "from" (gethash "spec" grant)) 0))
            "gateway.networking.x-k8s.io")
      (is (equal '("certs" . "cert") (reference)))
      (remhash '("referencegrants" "certs" "allow") objects)
      (is (null (reference)))
      (remhash "namespace" (aref (gethash "certificateRefs" (gethash "tls" listener)) 0))
      (is (equal '("apps" . "cert") (reference))))))

(defun gateway-test-tls-secret (name)
  (let ((root (asdf:system-relative-pathname "gr8s" "tests/fixtures/gateway-tls/")))
    (gr8s.resources::core-object
     "apiVersion" "v1" "kind" "Secret" "metadata" (gr8s.resources::core-object "name" name)
     "type" "kubernetes.io/tls"
     "data" (gr8s.resources::core-object
             "tls.crt" (ag-grpc:base64-encode (alexandria:read-file-into-byte-vector (merge-pathnames "server.crt" root)))
             "tls.key" (ag-grpc:base64-encode (alexandria:read-file-into-byte-vector (merge-pathnames "server.key" root)))))))

(defun gwc-seed (store)
  "Seed a store with an owned and an unowned GatewayClass, two Gateways and one
   attached HTTPRoute."
  (flet ((create (resource namespace json)
           (gr8s.resources::create-core-resource store resource (com.inuoe.jzon:parse json) namespace)))
    (create "gatewayclasses" nil
            "{\"apiVersion\":\"gateway.networking.k8s.io/v1\",\"kind\":\"GatewayClass\",\"metadata\":{\"name\":\"gr8s\"},\"spec\":{\"controllerName\":\"gr8s.io/gateway-controller\"}}")
    (create "gatewayclasses" nil
            "{\"apiVersion\":\"gateway.networking.k8s.io/v1\",\"kind\":\"GatewayClass\",\"metadata\":{\"name\":\"other\"},\"spec\":{\"controllerName\":\"someone.else/controller\"}}")
    (create "gateways" "default"
            "{\"apiVersion\":\"gateway.networking.k8s.io/v1\",\"kind\":\"Gateway\",\"metadata\":{\"name\":\"web\",\"namespace\":\"default\"},\"spec\":{\"gatewayClassName\":\"gr8s\",\"listeners\":[{\"name\":\"http\",\"port\":8080,\"protocol\":\"HTTP\"}]}}")
    (create "gateways" "default"
            "{\"apiVersion\":\"gateway.networking.k8s.io/v1\",\"kind\":\"Gateway\",\"metadata\":{\"name\":\"unmanaged\",\"namespace\":\"default\"},\"spec\":{\"gatewayClassName\":\"other\",\"listeners\":[{\"name\":\"http\",\"port\":9090,\"protocol\":\"HTTP\"}]}}")
    (create "httproutes" "default"
            "{\"apiVersion\":\"gateway.networking.k8s.io/v1\",\"kind\":\"HTTPRoute\",\"metadata\":{\"name\":\"app\",\"namespace\":\"default\"},\"spec\":{\"parentRefs\":[{\"name\":\"web\"}],\"hostnames\":[\"app.example.com\"],\"rules\":[{\"backendRefs\":[{\"name\":\"app-svc\",\"port\":80}]}]}}")))

(test gateway-controller-ownership-and-attachment
  (with-temporary-store (store directory)
    (values directory)
    (gwc-seed store)
    (is (gr8s.controllers::gateway-controlled-p store (gr8s.resources::get-core-resource store "gateways" "default" "web")))
    (is (not (gr8s.controllers::gateway-controlled-p store (gr8s.resources::get-core-resource store "gateways" "default" "unmanaged"))))
    ;; A parentRef naming a different Gateway does not attach.
    (let ((route (gr8s.resources::get-core-resource store "httproutes" "default" "app")))
      (is (gr8s.controllers::gateway-route-attaches-p route "default" "web" "http" 8080))
      (is (not (gr8s.controllers::gateway-route-attaches-p route "default" "other-gw" "http" 8080)))
      ;; No sectionName -> attaches to every listener on the Gateway.
      (is (gr8s.controllers::gateway-route-attaches-p route "default" "web" "any-listener" 8080)))
    ;; An explicit sectionName/port must equal the listener's.
    (let ((pinned (com.inuoe.jzon:parse
                   "{\"metadata\":{\"namespace\":\"default\"},\"spec\":{\"parentRefs\":[{\"name\":\"web\",\"sectionName\":\"https\",\"port\":8443}],\"rules\":[]}}")))
      (is (gr8s.controllers::gateway-route-attaches-p pinned "default" "web" "https" 8443))
      (is (not (gr8s.controllers::gateway-route-attaches-p pinned "default" "web" "http" 8080))))))

(test gateway-controller-plans-port-to-routes
  (with-temporary-store (store directory)
    (values directory)
    (gwc-seed store)
    (let ((plan (gr8s.controllers::gateway-listener-plan
                 (gr8s.resources::list-core-resources store "gateways")
                 (gr8s.resources::list-core-resources store "httproutes")
                 (lambda (gw) (gr8s.controllers::gateway-controlled-p store gw)))))
      ;; Only the owned Gateway's HTTP port is planned.
      (is (= 1 (length plan)))
      (is (equal 8080 (getf (first plan) :port)))
      (is (equal "HTTP" (getf (first plan) :protocol)))
      (is (null (getf (first plan) :tls)))
      (is (= 1 (length (getf (first plan) :routes))))
      (is (equal '("app.example.com") (gr8s.controllers::gw-route-hostnames (first (getf (first plan) :routes))))))))

(test gateway-controller-converges-start-swap-stop
  (with-temporary-store (store directory)
    (values directory)
    (gwc-seed store)
    (let* ((actions '())
           (controller (gr8s.controllers::make-gateway-controller
                        store
                        :resolver (lambda (b) (declare (ignore b)) nil)
                        :start-fn (lambda (port router resolver tls)
                                    (declare (ignore router resolver tls))
                                    (push (list :start port) actions)
                                    (list :handle port))
                        :stop-fn (lambda (handle) (push (list :stop handle) actions))
                        :swap-fn (lambda (handle router)
                                   (declare (ignore router))
                                   (push (list :swap handle) actions)))))
      ;; First convergence starts the listener on 8080.
      (gr8s.controllers::converge-gateway-listeners controller)
      (is (equal '((:start 8080)) actions))
      ;; An unchanged plan leaves the published router untouched.
      (setf actions '())
      (gr8s.controllers::converge-gateway-listeners controller)
      (is (null actions))
      ;; Removing the Gateway stops the listener.
      (setf actions '())
      (gr8s.resources::delete-core-resource store "gateways" "default" "web")
      (gr8s.controllers::converge-gateway-listeners controller)
      (is (equal '((:stop (:handle 8080))) actions))
      (is (zerop (hash-table-count (gr8s.controllers::gateway-controller-listeners controller)))))))

(test gateway-listeners-exist-without-attached-routes
  (with-temporary-store (store directory)
    (values directory)
    (gwc-seed store)
    (gr8s.resources::delete-core-resource store "httproutes" "default" "app")
    (let ((plan (gr8s.controllers::gateway-listener-plan
                 (gr8s.resources::list-core-resources store "gateways") nil
                 (lambda (gateway) (gr8s.controllers::gateway-controlled-p store gateway)))))
      (is (= 1 (length plan)))
      (is (eql 8080 (getf (first plan) :port)))
      (is (null (getf (first plan) :routes))))
    (let* ((starts 0) (stops 0)
           (controller (gr8s.controllers::make-gateway-controller
                        store :start-fn (lambda (&rest ignored)
                                          (declare (ignore ignored)) (incf starts))
                        :stop-fn (lambda (handle) (declare (ignore handle)) (incf stops))
                        :swap-fn (lambda (&rest ignored) (declare (ignore ignored))))))
      (gr8s.controllers::converge-gateway-listeners controller)
      (is (= 1 starts))
      (gr8s.resources::create-core-resource store "httproutes"
                                           (com.inuoe.jzon:parse *httproute-json*) "default")
      (gr8s.controllers::converge-gateway-listeners controller)
      (gr8s.resources::delete-core-resource store "httproutes" "default" "app")
      (gr8s.controllers::converge-gateway-listeners controller)
      (is (= 1 starts))
      (is (zerop stops)))))

(test gateway-empty-tcp-listener-retains-its-protocol
  (with-temporary-store (store directory)
    (values directory)
    (gwc-seed store)
    (gr8s.resources::update-core-resource
     store "gateways" "default" "web"
     (lambda (gateway)
       (setf (gethash "protocol" (aref (gethash "listeners" (gethash "spec" gateway)) 0)) "TCP")
       gateway))
    (let ((plan (gr8s.controllers::gateway-l4-plan
                 (gr8s.resources::list-core-resources store "gateways") nil nil nil
                 (lambda (gateway) (gr8s.controllers::gateway-controlled-p store gateway)))))
      (is (= 1 (length plan)))
      (is (eq :tcp (getf (first plan) :mode)))
      (is (null (getf (first plan) :tcp-routes))))))

(test gateway-listener-observations-reflect-current-running-listeners
  (with-temporary-store (store directory)
    (values directory)
    (gwc-seed store)
    (let* ((controller (gr8s.controllers::make-gateway-controller
                        store :start-fn (lambda (&rest ignored) (declare (ignore ignored)) :listener)
                        :stop-fn (lambda (handle) (declare (ignore handle)))
                        :swap-fn (lambda (&rest ignored) (declare (ignore ignored)))))
           (before (first (gr8s.controllers::gateway-controller-observations controller))))
      (is (equal "web" (slot-value before 'gr8s.node.v1::name)))
      (is-false (slot-value (first (slot-value before 'gr8s.node.v1::listeners))
                            'gr8s.node.v1::programmed))
      (gr8s.controllers::converge-gateway-listeners controller)
      (let* ((after (first (gr8s.controllers::gateway-controller-observations controller)))
             (roundtrip (roundtrip-node-message
                         (make-instance 'gr8s.node.v1::node-status
                                        :gateway-report-present t :gateways (list after))
                         'gr8s.node.v1::node-status)))
        (is (slot-value roundtrip 'gr8s.node.v1::gateway-report-present))
        (is (= 1 (length (slot-value roundtrip 'gr8s.node.v1::gateways))))
        (is (slot-value (first (slot-value after 'gr8s.node.v1::listeners))
                        'gr8s.node.v1::programmed)))
      (gr8s.controllers::stop-gateway-controller controller)
      (is-false (slot-value
                 (first (slot-value
                         (first (gr8s.controllers::gateway-controller-observations controller))
                         'gr8s.node.v1::listeners)) 'gr8s.node.v1::programmed)))))

(defun gateway-test-condition (object type)
  (find type (gethash "conditions" (gethash "status" object) #())
        :test #'equal :key (lambda (condition) (gethash "type" condition))))

(test gateway-attached-route-counts-follow-listener-selection
  (with-temporary-store (store directory)
    (values directory)
    (gwc-seed store)
    (gr8s.resources::create-core-resource
     store "namespaces"
     (gw-parse "{\"apiVersion\":\"v1\",\"kind\":\"Namespace\",\"metadata\":{\"name\":\"tenant\",\"labels\":{\"team\":\"blue\"}}}") nil)
    (let ((route (gw-parse *httproute-json*)))
      (setf (gethash "parentRefs" (gethash "spec" route))
            (vector (gr8s.resources::core-object "name" "web" "namespace" "default")
                    (gr8s.resources::core-object "name" "web" "namespace" "default")))
      (gr8s.resources::create-core-resource store "httproutes" route "tenant"))
    (let* ((gateway (gr8s.resources::get-core-resource store "gateways" "default" "web"))
           (listener (aref (gethash "listeners" (gethash "spec" gateway)) 0)))
      (labels ((count-routes ()
                 (gr8s.apiserver::gateway-listener-attached-routes
                  store gateway listener (gr8s.apiserver::gateway-listener-supported-kinds listener))))
        (is (= 1 (count-routes)))
        (setf (gethash "allowedRoutes" listener)
              (gw-parse "{\"namespaces\":{\"from\":\"All\"}}"))
        (is (= 2 (count-routes)))
        (setf (gethash "allowedRoutes" listener)
              (gw-parse "{\"namespaces\":{\"from\":\"Selector\",\"selector\":{\"matchLabels\":{\"team\":\"blue\"}}}}"))
        (is (= 1 (count-routes)))
        (setf (gethash "kinds" (gethash "allowedRoutes" listener))
              (vector (gr8s.resources::core-object "kind" "TCPRoute")))
        (is (zerop (count-routes)))))))

(test gateway-status-rejects-unsupported-route-kind-references
  (with-temporary-store (store directory)
    (values directory)
    (gwc-seed store)
    (let* ((gateway (gr8s.resources::get-core-resource store "gateways" "default" "web"))
           (listener (aref (gethash "listeners" (gethash "spec" gateway)) 0)))
      (setf (gethash "allowedRoutes" listener)
            (gw-parse "{\"kinds\":[{\"group\":\"gateway.networking.k8s.io\",\"kind\":\"TCPRoute\"}]}"))
      (let* ((status (gr8s.apiserver::gateway-listener-status-object
                      store gateway listener nil (gr8s.resources::core-object)))
             (condition (find "ResolvedRefs" (gethash "conditions" status) :test #'equal
                              :key (lambda (entry) (gethash "type" entry)))))
        (is (equal "False" (gethash "status" condition)))
        (is (equal "InvalidRouteKinds" (gethash "reason" condition)))
        (is (zerop (length (gethash "supportedKinds" status))))))))

(test malformed-gateway-status-input-does-not-starve-other-gateways
  (with-temporary-store (store directory)
    (values directory)
    (gwc-seed store)
    (gr8s.resources::create-core-resource
     store "gateways" (gw-parse "{\"apiVersion\":\"gateway.networking.k8s.io/v1\",\"kind\":\"Gateway\",\"metadata\":{\"name\":\"malformed\"},\"spec\":{\"gatewayClassName\":\"gr8s\",\"listeners\":[{\"name\":\"http\",\"port\":8181,\"protocol\":\"HTTP\",\"allowedRoutes\":\"invalid\"}]}}") "default")
    (gr8s.apiserver::reconcile-gateway-status (gr8s.apiserver::%make-node-grpc-server :store store))
    (dolist (name '("web" "malformed"))
      (let ((gateway (gr8s.resources::get-core-resource store "gateways" "default" name)))
        (is (equal "False" (gethash "status" (gateway-test-condition gateway "Programmed"))))))))

(test gateway-observations-do-not-reuse-a-replaced-tls-secret
  (with-temporary-store (store directory)
    (gwc-seed store)
    (gr8s.resources::create-core-resource
     store "secrets" (gateway-test-tls-secret "tls") "default")
    (gr8s.resources::update-core-resource
     store "gateways" "default" "web"
     (lambda (gateway)
       (let ((listener (aref (gethash "listeners" (gethash "spec" gateway)) 0)))
         (setf (gethash "protocol" listener) "HTTPS"
               (gethash "tls" listener)
               (gr8s.resources::core-object "certificateRefs"
                                            (vector (gr8s.resources::core-object "name" "tls")))))
       gateway))
    (let ((controller (gr8s.controllers::make-gateway-controller
                       store :cert-dir directory
                       :start-fn (lambda (&rest ignored) (declare (ignore ignored)) :tls-listener)
                       :stop-fn (lambda (handle) (declare (ignore handle)))
                       :swap-fn (lambda (&rest ignored) (declare (ignore ignored))))))
      (labels ((programmed ()
                 (slot-value (first (slot-value (first (gr8s.controllers::gateway-controller-observations controller))
                                                'gr8s.node.v1::listeners)) 'gr8s.node.v1::programmed))
               (installed ()
                 (let ((gateway (gr8s.resources::get-core-resource store "gateways" "default" "web")))
                   (gr8s.controllers::gateway-listener-entry-programmed-p
                    controller (gr8s.controllers::make-gateway-listener-entry
                                :gateway gateway :owner gateway
                                :listener (aref (gethash "listeners" (gethash "spec" gateway)) 0))))))
        (gr8s.controllers::converge-gateway-listeners controller)
        (is (programmed))
        (is (installed))
        (gr8s.resources::update-core-resource
         store "secrets" "default" "tls"
         (lambda (secret)
           (setf (gethash "tls.crt" (gethash "data" secret))
                 (ag-grpc:base64-encode
                  (concatenate '(vector (unsigned-byte 8))
                               (ag-grpc:base64-decode (gethash "tls.crt" (gethash "data" secret)))
                               #(10))))
           secret))
        (is-false (programmed))
        (is-false (installed))
        (gr8s.controllers::converge-gateway-listeners controller)
        (is (programmed))
        (is (installed))))))

(test gateway-failed-registration-closes-the-unpublished-listener
  (with-temporary-store (store directory)
    (values directory)
    (gwc-seed store)
    (let* ((stops 0)
           (controller (gr8s.controllers::make-gateway-controller
                        store :start-fn (lambda (&rest ignored) (declare (ignore ignored)) :listener)
                        :stop-fn (lambda (handle) (declare (ignore handle)) (incf stops))
                        :register-fn (lambda (&rest ignored) (declare (ignore ignored)) (error "injected registration failure")))))
      (signals error (gr8s.controllers::converge-gateway-listeners controller))
      (is (= 1 stops))
      (is (zerop (hash-table-count (gr8s.controllers::gateway-controller-listeners controller)))))))

(test gateway-status-requires-fresh-current-session-listener-evidence
  (with-temporary-store (store directory)
    (values directory)
    (gwc-seed store)
    (let* ((now 1000)
           (server (gr8s.apiserver::%make-node-grpc-server
                    :store store :clock (lambda () now) :heartbeat-timeout-seconds 30))
           (session (gr8s.apiserver::make-node-agent-session nil))
           (controller (gr8s.controllers::make-gateway-controller
                        store :start-fn (lambda (&rest ignored) (declare (ignore ignored)) :listener)
                        :stop-fn (lambda (handle) (declare (ignore handle)))
                        :swap-fn (lambda (&rest ignored) (declare (ignore ignored))))))
      (gr8s.controllers::register-node
       store (gr8s.model::make-node-record :id "worker" :name "worker"
                                          :underlay-address "192.0.2.10" :pod-cidr "10.88.0.0/24"))
      (gr8s.controllers::mark-node-ready store "worker" now :lease-duration 1000)
      (setf (gr8s.apiserver::node-agent-session-node-id session) "worker"
            (gethash "worker" (gr8s.apiserver::node-grpc-server-sessions server)) session)
      (labels ((gateway () (gr8s.resources::get-core-resource store "gateways" "default" "web"))
               (reconcile () (gr8s.apiserver::reconcile-gateway-status server))
               (report (&optional (sender session))
                 (gr8s.apiserver::note-node-gateway-status
                  server "worker" (make-instance
                                   'gr8s.node.v1::node-status :gateway-report-present t
                                   :gateways (gr8s.controllers::gateway-controller-observations controller)) sender))
               (programmed () (gethash "status" (gateway-test-condition (gateway) "Programmed"))))
        (let ((projection (gr8s.kubelet::service-discovery-projection store)))
          (reconcile)
          (is (equalp projection (gr8s.kubelet::service-discovery-projection store))
              "Controller status changes must not invalidate the node's desired projection"))
        (is (equal "False" (programmed)))
        (is (zerop (length (gethash "addresses" (gethash "status" (gateway))))))
        (gr8s.controllers::converge-gateway-listeners controller)
        (report)
        (reconcile)
        (is (equal "True" (programmed)))
        (is (equal "192.0.2.10" (gethash "value" (aref (gethash "addresses" (gethash "status" (gateway))) 0))))
        (is (= 1 (gethash "attachedRoutes" (aref (gethash "listeners" (gethash "status" (gateway))) 0))))
        (let ((revision (gr8s.resources::pod-store-resource-revision store)))
          (reconcile)
          (is (= revision (gr8s.resources::pod-store-resource-revision store))))
        (gr8s.resources::delete-core-resource store "httproutes" "default" "app")
        (reconcile)
        (is (= 0 (gethash "attachedRoutes" (aref (gethash "listeners" (gethash "status" (gateway))) 0))))
        (is (equal "True" (programmed)))
        ;; A spec change cannot inherit an older generation's programmed report.
        (gr8s.resources::update-core-resource
         store "gateways" "default" "web"
         (lambda (current)
           (setf (gethash "port" (aref (gethash "listeners" (gethash "spec" current)) 0)) 8081)
           current))
        (reconcile)
        (is (equal "False" (programmed)))
        (gr8s.controllers::converge-gateway-listeners controller)
        (report)
        (reconcile)
        (is (equal "True" (programmed)))
        (incf now 31)
        (reconcile)
        (is (equal "False" (programmed)))
        (report)
        (reconcile)
        (is (equal "True" (programmed)))
        ;; An old connection cannot refresh readiness after a reconnect.
        (setf (gethash "worker" (gr8s.apiserver::node-grpc-server-sessions server))
              (gr8s.apiserver::make-node-agent-session nil))
        (report session)
        (reconcile)
        (is (equal "False" (programmed)))
        (is-false (gethash "status" (gr8s.resources::get-core-resource store "gateways" "default" "unmanaged")))))))

(test gateway-controller-plans-and-converges-l4-listeners
  (with-temporary-store (store directory)
    (values directory)
    (flet ((create (resource namespace json)
             (gr8s.resources::create-core-resource store resource (com.inuoe.jzon:parse json) namespace)))
      (create "gatewayclasses" nil
              "{\"apiVersion\":\"gateway.networking.k8s.io/v1\",\"kind\":\"GatewayClass\",\"metadata\":{\"name\":\"gr8s\"},\"spec\":{\"controllerName\":\"gr8s.io/gateway-controller\"}}")
      (create "gateways" "default"
              "{\"apiVersion\":\"gateway.networking.k8s.io/v1\",\"kind\":\"Gateway\",\"metadata\":{\"name\":\"l4gw\",\"namespace\":\"default\"},\"spec\":{\"gatewayClassName\":\"gr8s\",\"listeners\":[{\"name\":\"db\",\"port\":3306,\"protocol\":\"TCP\"},{\"name\":\"sni\",\"port\":8443,\"protocol\":\"TLS\"}]}}")
      (create "tcproutes" "default"
              "{\"apiVersion\":\"gateway.networking.k8s.io/v1\",\"kind\":\"TCPRoute\",\"metadata\":{\"name\":\"db\",\"namespace\":\"default\"},\"spec\":{\"parentRefs\":[{\"name\":\"l4gw\",\"sectionName\":\"db\"}],\"rules\":[{\"backendRefs\":[{\"name\":\"mysql\",\"port\":3306}]}]}}")
      (create "tlsroutes" "default"
              "{\"apiVersion\":\"gateway.networking.k8s.io/v1\",\"kind\":\"TLSRoute\",\"metadata\":{\"name\":\"edge\",\"namespace\":\"default\"},\"spec\":{\"parentRefs\":[{\"name\":\"l4gw\",\"sectionName\":\"sni\"}],\"hostnames\":[\"secure.example.com\"],\"rules\":[{\"backendRefs\":[{\"name\":\"tls-svc\",\"port\":8443}]}]}}"))
    (let ((plan (gr8s.controllers::gateway-l4-plan
                 (gr8s.resources::list-core-resources store "gateways")
                 (gr8s.resources::list-core-resources store "tcproutes")
                 (gr8s.resources::list-core-resources store "tlsroutes")
                 (gr8s.resources::list-core-resources store "grpcroutes")
                 (lambda (gw) (gr8s.controllers::gateway-controlled-p store gw)))))
      (is (= 2 (length plan)))
      (let ((tcp (find :tcp plan :key (lambda (e) (getf e :mode))))
            (tls (find :tls plan :key (lambda (e) (getf e :mode)))))
        (is (equal 3306 (getf tcp :port)))
        (is (= 1 (length (getf tcp :tcp-routes))))
        (is (equal 8443 (getf tls :port)))
        (is (= 1 (length (getf tls :sni-routes))))
        (is (equal '("secure.example.com")
                   (gr8s.controllers::l4-sni-route-hostnames (first (getf tls :sni-routes)))))))
    (let* ((actions '())
           (controller (gr8s.controllers::make-gateway-controller
                        store :resolver (lambda (b) (declare (ignore b)) nil)
                        :l4-start-fn (lambda (port mode dispatcher resolver)
                                       (declare (ignore dispatcher resolver))
                                       (push (list :start port mode) actions) (list :l4 port))
                        :l4-stop-fn (lambda (handle) (push (list :stop handle) actions))
                        :l4-swap-fn (lambda (handle dispatcher)
                                      (declare (ignore dispatcher))
                                      (push (list :swap handle) actions)))))
      (gr8s.controllers::converge-gateway-l4-listeners controller)
      (is (= 2 (count :start actions :key #'first)))
      ;; Second convergence hot-swaps both dispatchers (no new starts).
      (setf actions '())
      (gr8s.controllers::converge-gateway-l4-listeners controller)
      (is (= 2 (count :swap actions :key #'first)))
      (is (= 0 (count :start actions :key #'first))))))

(test gateway-controller-starts-https-listener-with-secret-cert
  (with-temporary-store (store directory)
    (flet ((create (resource namespace json)
             (gr8s.resources::create-core-resource store resource (com.inuoe.jzon:parse json) namespace)))
      (create "gatewayclasses" nil
              "{\"apiVersion\":\"gateway.networking.k8s.io/v1\",\"kind\":\"GatewayClass\",\"metadata\":{\"name\":\"gr8s\"},\"spec\":{\"controllerName\":\"gr8s.io/gateway-controller\"}}")
      (gr8s.resources::create-core-resource store "secrets"
                                            (gateway-test-tls-secret "web-cert") "default")
      (create "gateways" "default"
              "{\"apiVersion\":\"gateway.networking.k8s.io/v1\",\"kind\":\"Gateway\",\"metadata\":{\"name\":\"tls-gw\",\"namespace\":\"default\"},\"spec\":{\"gatewayClassName\":\"gr8s\",\"listeners\":[{\"name\":\"https\",\"port\":8443,\"protocol\":\"HTTPS\",\"tls\":{\"certificateRefs\":[{\"kind\":\"Secret\",\"name\":\"web-cert\"}]}}]}}")
      (create "httproutes" "default"
              "{\"apiVersion\":\"gateway.networking.k8s.io/v1\",\"kind\":\"HTTPRoute\",\"metadata\":{\"name\":\"secure\",\"namespace\":\"default\"},\"spec\":{\"parentRefs\":[{\"name\":\"tls-gw\"}],\"hostnames\":[\"secure.example.com\"],\"rules\":[{\"backendRefs\":[{\"name\":\"app-svc\",\"port\":443}]}]}}"))
    (let ((plan (gr8s.controllers::gateway-listener-plan
                 (gr8s.resources::list-core-resources store "gateways")
                 (gr8s.resources::list-core-resources store "httproutes")
                 (lambda (gw) (gr8s.controllers::gateway-controlled-p store gw)))))
      (is (equal 8443 (getf (first plan) :port)))
      (is (equal "HTTPS" (getf (first plan) :protocol)))
      (is (equal '("default" . "web-cert") (getf (first plan) :tls))))
    (let* ((started '())
           (cert-dir (merge-pathnames "certs/" directory))
           (controller (gr8s.controllers::make-gateway-controller
                        store :cert-dir cert-dir
                        :start-fn (lambda (port router resolver tls)
                                    (declare (ignore router resolver))
                                    (push (cons port tls) started) (list :handle port))
                        :stop-fn (lambda (handle) (declare (ignore handle)))
                        :swap-fn (lambda (handle router) (declare (ignore handle router))))))
      (gr8s.controllers::converge-gateway-listeners controller)
      (is (= 1 (length started)))
      (is (equal 8443 (car (first started))))
      (let ((tls (cdr (first started))))
        (is (stringp (getf tls :certificate)))
        (is (probe-file (getf tls :certificate)))        ; cert materialized on disk
        (is (probe-file (getf tls :key)))))))

(test gateway-controller-reuses-only-unchanged-routing-content
  (with-temporary-store (store directory)
    (values directory)
    (gwc-seed store)
    (let* ((published nil) (swaps 0)
           (controller (gr8s.controllers::make-gateway-controller
                        store
                        :start-fn (lambda (port router resolver tls)
                                    (declare (ignore port resolver tls))
                                    (setf published router) :listener)
                        :swap-fn (lambda (handle router)
                                   (declare (ignore handle))
                                   (incf swaps) (setf published router))
                        :stop-fn (lambda (handle) (declare (ignore handle))))))
      (gr8s.controllers::converge-gateway-listeners controller)
      (let ((old published))
        (gr8s.controllers::converge-gateway-listeners controller)
        (is (= 0 swaps))
        (is (eq old published))
        ;; Resource metadata changes do not change matching content.
        (gr8s.resources::update-core-resource
         store "httproutes" "default" "app"
         (lambda (route) (setf (gethash "status" route) (make-hash-table)) route))
        (gr8s.controllers::converge-gateway-listeners controller)
        (is (= 0 swaps))
        (flet ((set-path (path)
                 (gr8s.resources::update-core-resource
                  store "httproutes" "default" "app"
                  (lambda (route)
                    (setf (gethash "matches" (aref (gethash "rules" (gethash "spec" route)) 0))
                          (vector (let ((match (make-hash-table)) (value (make-hash-table)))
                                    (setf (gethash "type" value) "Exact"
                                          (gethash "value" value) path
                                          (gethash "path" match) value)
                                    match)))
                    route))))
          (set-path "/UP")
          (gr8s.controllers::converge-gateway-listeners controller)
          (is (= 1 swaps))
          (is (not (eq old published)))
          (is (null (funcall published "app.example.com" "/up" "GET" nil)))
          (is (funcall old "app.example.com" "/up" "GET" nil))
          ;; EQUALP on normalized structs would incorrectly reuse this table.
          (set-path "/up")
          (gr8s.controllers::converge-gateway-listeners controller)
          (is (= 2 swaps))
          (is (funcall published "app.example.com" "/up" "GET" nil))
          (is (null (funcall published "app.example.com" "/UP" "GET" nil))))))))

(test gateway-controller-retries-failed-router-publication
  (with-temporary-store (store directory)
    (values directory)
    (gwc-seed store)
    (let* ((fail t) (attempts 0) (published nil)
           (controller (gr8s.controllers::make-gateway-controller
                        store
                        :start-fn (lambda (port router resolver tls)
                                    (declare (ignore port resolver tls))
                                    (setf published router) :listener)
                        :stop-fn (lambda (handle) (declare (ignore handle)))
                        :swap-fn (lambda (handle router)
                                   (declare (ignore handle))
                                   (incf attempts)
                                   (when fail (error "injected publication failure"))
                                   (setf published router)))))
      (gr8s.controllers::converge-gateway-listeners controller)
      (let ((old published))
        (gr8s.resources::delete-core-resource store "httproutes" "default" "app")
        (signals error (gr8s.controllers::converge-gateway-listeners controller))
        (is (eq old published))
        (setf fail nil)
        (gr8s.controllers::converge-gateway-listeners controller)
        (is (= 2 attempts))
        (is (null (funcall published "app.example.com" "/" "GET" nil)))))))

(test gateway-planner-intersects-route-and-listener-hostnames
  (dolist (case '(("foo.example.com" nil "foo.example.com" "bar.example.com")
                  ("*.example.com" ("foo.example.com") "foo.example.com" "bar.example.com")
                  ("foo.example.com" ("*.example.com") "foo.example.com" "bar.example.com")
                  ("*.example.com" ("*.sub.example.com") "a.sub.example.com" "a.example.com")
                  ("*.sub.example.com" ("*.example.com") "a.sub.example.com" "a.example.com")))
    (destructuring-bind (hostname route-hosts accepted denied) case
      (let* ((gateway (gr8s.resources::core-object
                       "metadata" (gr8s.resources::core-object "namespace" "infra" "name" "web")
                       "spec" (gr8s.resources::core-object
                               "listeners" (vector (gr8s.resources::core-object
                                                    "name" "http" "protocol" "HTTP" "port" 8080
                                                    "hostname" hostname)))))
             (route (gr8s.resources::core-object
                     "metadata" (gr8s.resources::core-object "namespace" "infra" "name" "app")
                     "spec" (gr8s.resources::core-object
                             "hostnames" (coerce route-hosts 'vector)
                             "parentRefs" (vector (gr8s.resources::core-object "name" "web"))
                             "rules" (vector (gr8s.resources::core-object
                                              "backendRefs" (vector (gr8s.resources::core-object "name" "backend" "port" 80)))))))
             (plan (gr8s.controllers::gateway-listener-plan (list gateway) (list route) (constantly t)))
             (router (gr8s.controllers::build-gateway-router (getf (first plan) :routes))))
        (is (not (null (funcall router accepted "/" "GET" nil))))
        (is (null (funcall router denied "/" "GET" nil)))))))

(test gateway-allowed-routes-controls-namespace-and-kind-admission
  (with-temporary-store (store directory)
    (declare (ignore directory))
    (gwc-seed store)
    (gr8s.resources::create-core-resource
     store "namespaces" (com.inuoe.jzon:parse
                         "{\"metadata\":{\"name\":\"tenant\",\"labels\":{\"team\":\"blue\"}}}") nil)
    (let ((route (gr8s.resources::copy-core-object
                  (gr8s.resources::get-core-resource store "httproutes" "default" "app"))))
      (setf (gethash "namespace" (gethash "metadata" route)) "tenant"
            (gethash "namespace" (aref (gethash "parentRefs" (gethash "spec" route)) 0)) "default")
      (remhash "resourceVersion" (gethash "metadata" route))
      (remhash "uid" (gethash "metadata" route))
      (gr8s.resources::create-core-resource store "httproutes" route "tenant"))
    (gr8s.resources::delete-core-resource store "httproutes" "default" "app")
    (let ((controller (gr8s.controllers::make-gateway-controller
                       store :start-fn (lambda (&rest args) (declare (ignore args)) :listener)
                       :swap-fn (lambda (&rest args) (declare (ignore args)))
                       :stop-fn (lambda (&rest args) (declare (ignore args))))))
      (dolist (case '(("{}" nil)
                      ("{\"namespaces\":{\"from\":\"All\"}}" t)
                      ("{\"namespaces\":{\"from\":\"Selector\",\"selector\":{\"matchLabels\":{\"team\":\"blue\"}}}}" t)
                      ("{\"namespaces\":{\"from\":\"Selector\",\"selector\":{\"matchLabels\":{\"team\":\"red\"}}}}" nil)
                      ("{\"namespaces\":{\"from\":\"Selector\",\"selector\":{\"matchExpressions\":[{\"key\":\"team\",\"operator\":\"In\",\"values\":[\"blue\"]}]}}}" t)
                      ("{\"namespaces\":{\"from\":\"All\"},\"kinds\":[{\"kind\":\"TCPRoute\"}]}" nil)
                      ("{\"namespaces\":{\"from\":\"All\"},\"kinds\":[{\"kind\":\"HTTPRoute\",\"group\":\"example.com\"}]}" nil)
                      ("{\"namespaces\":{\"from\":\"All\"},\"kinds\":[{\"kind\":\"HTTPRoute\"}]}" t)))
        (destructuring-bind (policy expected) case
          (gr8s.resources::update-core-resource
           store "gateways" "default" "web"
           (lambda (gateway)
             (setf (gethash "allowedRoutes" (aref (gethash "listeners" (gethash "spec" gateway)) 0))
                   (com.inuoe.jzon:parse policy))
             gateway))
          (gr8s.controllers::converge-gateway-listeners controller)
          (let ((router (gethash 8080 (gr8s.controllers::gateway-controller-routing-bases controller))))
            (is (eq expected (not (null (funcall router "app.example.com" "/" "GET" nil)))))))))))

(test gateway-tls-secret-grant-controls-planning-and-projection
  (let* ((objects (make-hash-table :test #'equal))
         (gateway (com.inuoe.jzon:parse
                   "{\"metadata\":{\"name\":\"web\",\"namespace\":\"source\"},\"spec\":{\"listeners\":[{\"name\":\"https\",\"protocol\":\"HTTPS\",\"port\":443,\"tls\":{\"certificateRefs\":[{\"name\":\"cert\",\"namespace\":\"target\"}]}}]}}"))
         (grant (com.inuoe.jzon:parse
                 "{\"spec\":{\"from\":[{\"group\":\"gateway.networking.k8s.io\",\"kind\":\"Gateway\",\"namespace\":\"source\"}],\"to\":[{\"group\":\"\",\"kind\":\"Secret\",\"name\":\"cert\"}]}}")))
    (setf (gethash '("gateways" "source" "web") objects) gateway
          (gethash '("secrets" "target" "cert") objects)
          (com.inuoe.jzon:parse "{\"kind\":\"Secret\",\"metadata\":{\"name\":\"cert\",\"namespace\":\"target\"},\"type\":\"kubernetes.io/tls\",\"data\":{\"tls.crt\":\"Y2VydA==\",\"tls.key\":\"a2V5\"}}"))
    (dolist (allowed '(nil t nil))
      (if allowed
          (setf (gethash '("referencegrants" "target" "allow") objects) grant)
          (remhash '("referencegrants" "target" "allow") objects))
      (let* ((view (gr8s.agent::make-gateway-projection-store (gr8s.agent::gateway-resource-index objects)))
             (plan (gr8s.controllers::gateway-listener-plan (list gateway) nil (constantly t) view)))
        (is (eq allowed (not (null (getf (first plan) :tls)))))
        (is (= (if allowed 1 0) (length (gr8s.kubelet::gateway-referenced-tls-secrets view))))))))

(test gateway-tls-material-requires-a-usable-matching-key
  (let* ((root (asdf:system-relative-pathname "gr8s" "tests/fixtures/gateway-tls/"))
         (cert (uiop:read-file-string (merge-pathnames "server.crt" root)))
         (key (uiop:read-file-string (merge-pathnames "server.key" root)))
         (other (uiop:read-file-string (merge-pathnames "other.key" root))))
    (flet ((valid (certificate private-key)
             (gr8s.controllers::gateway-tls-material-valid-p
              (ag-grpc:base64-encode (babel:string-to-octets certificate :encoding :utf-8))
              (ag-grpc:base64-encode (babel:string-to-octets private-key :encoding :utf-8)))))
      (is (valid cert key))
      (is (not (valid cert other)))
      (is (not (valid "Hello world" key)))
      (is (not (valid cert "Hello world")))
      (is (not (valid (concatenate 'string cert (format nil "-----BEGIN CERTIFICATE-----~%broken~%-----END CERTIFICATE-----~%")) key)))
      (is (not (valid "-----BEGIN CERTIFICATE-----" key)))
      (is (valid cert key)))))

(test gateway-invalid-tls-material-is-neither-ready-nor-materialized
  (with-temporary-store (store directory)
    (let* ((secret (gw-parse "{\"apiVersion\":\"v1\",\"kind\":\"Secret\",\"metadata\":{\"name\":\"tls\"},\"type\":\"kubernetes.io/tls\",\"data\":{\"tls.crt\":\"SGVsbG8gd29ybGQK\",\"tls.key\":\"SGVsbG8gd29ybGQK\"}}"))
           (listener (gw-parse "{\"name\":\"https\",\"protocol\":\"HTTPS\",\"port\":443,\"tls\":{\"certificateRefs\":[{\"name\":\"tls\"}]}}")))
      (gr8s.resources::create-core-resource store "secrets" secret "default")
      (is (equal "InvalidCertificateRef"
                 (gr8s.controllers::foreign-gateway-listener-tls-error store "default" listener)))
      (is (null (gr8s.controllers::gateway-resolve-listener-tls store '("default" . "tls") directory)))
      (is (not (probe-file (merge-pathnames "default-tls.crt" directory)))))))

(test gateway-invalid-tls-replacement-stops-the-old-listener
  (with-temporary-store (store directory)
    (gwc-seed store)
    (gr8s.resources::create-core-resource store "secrets" (gateway-test-tls-secret "tls") "default")
    (gr8s.resources::update-core-resource
     store "gateways" "default" "web"
     (lambda (gateway)
       (let ((listener (aref (gethash "listeners" (gethash "spec" gateway)) 0)))
         (setf (gethash "protocol" listener) "HTTPS"
               (gethash "tls" listener) (gr8s.resources::core-object
                                        "certificateRefs" (vector (gr8s.resources::core-object "name" "tls")))))
       gateway))
    (let* ((starts 0) (stops 0)
           (controller (gr8s.controllers::make-gateway-controller
                        store :cert-dir directory
                        :start-fn (lambda (&rest args) (declare (ignore args)) (incf starts) :listener)
                        :stop-fn (lambda (handle) (declare (ignore handle)) (incf stops))
                        :swap-fn (lambda (&rest args) (declare (ignore args))))))
      (gr8s.controllers::converge-gateway-listeners controller)
      (is (= 1 starts))
      (gr8s.resources::update-core-resource
       store "secrets" "default" "tls"
       (lambda (secret) (setf (gethash "tls.key" (gethash "data" secret)) "SGVsbG8=") secret))
      (gr8s.controllers::converge-gateway-listeners controller)
      (is (= 1 stops))
      (is (= 1 starts))
      (is (= 0 (hash-table-count (gr8s.controllers::gateway-controller-listeners controller)))))))

(test gateway-tls-material-cache-skips-repeated-crypto
  (let* ((secret (gateway-test-tls-secret "tls"))
         (data (gethash "data" secret))
         (check (symbol-function 'gr8s.controllers::gateway-check-tls-material))
         (calls 0)
         (gr8s.controllers::*gateway-tls-material-cache* (make-hash-table :test 'equal)))
    (unwind-protect
         (progn
           (setf (symbol-function 'gr8s.controllers::gateway-check-tls-material)
                 (lambda (&rest args) (incf calls) (apply check args)))
           (dotimes (i 3)
             (is (gr8s.controllers::gateway-tls-material-valid-p (gethash "tls.crt" data) (gethash "tls.key" data))))
           (is (= 1 calls)))
      (setf (symbol-function 'gr8s.controllers::gateway-check-tls-material) check))))

(test gateway-l4-planning-respects-route-admission
  (dolist (protocol '("TCP" "TLS"))
    (let* ((kind (if (equal protocol "TCP") "TCPRoute" "TLSRoute"))
           (listener (gr8s.resources::core-object "name" "listener" "port" 8443 "protocol" protocol))
           (gateway (gr8s.resources::core-object
                     "metadata" (gr8s.resources::core-object "name" "web" "namespace" "infra")
                     "spec" (gr8s.resources::core-object "listeners" (vector listener))))
           (route (gr8s.resources::core-object
                   "kind" kind "metadata" (gr8s.resources::core-object "name" "route" "namespace" "apps")
                   "spec" (gr8s.resources::core-object
                           "parentRefs" (vector (gr8s.resources::core-object "name" "web" "namespace" "infra"))
                           "hostnames" (vector "example.test") "rules" #()))))
      (flet ((routes ()
               (let ((plan (gr8s.controllers::gateway-l4-plan
                            (list gateway) (when (equal protocol "TCP") (list route))
                            (when (equal protocol "TLS") (list route)) nil (constantly t))))
                 (getf (first plan) (if (equal protocol "TCP") :tcp-routes :sni-routes)))))
        (is (null (routes)))
        (setf (gethash "allowedRoutes" listener)
              (gr8s.resources::core-object "namespaces" (gr8s.resources::core-object "from" "All")))
        (is (= 1 (length (routes))))
        (setf (gethash "kinds" (gethash "allowedRoutes" listener))
              (vector (gr8s.resources::core-object "kind" "HTTPRoute")))
        (is (null (routes)))
        (setf (gethash "kinds" (gethash "allowedRoutes" listener))
              (vector (gr8s.resources::core-object "kind" kind)))
        (is (= 1 (length (routes))))))))

(test gateway-full-reconciliation-refreshes-backend-validity
  (with-temporary-store (store directory)
    (declare (ignore directory))
    (gwc-seed store)
    (let* ((published nil)
           (controller (gr8s.controllers::make-gateway-controller
                        store
                        :start-fn (lambda (port router resolver tls)
                                    (declare (ignore port resolver tls)) (setf published router) :listener)
                        :swap-fn (lambda (handle router) (declare (ignore handle)) (setf published router))
                        :stop-fn (lambda (handle) (declare (ignore handle))))))
      (dolist (kind '("Service" "WrongKind" "Service"))
        (gr8s.resources::update-core-resource
         store "httproutes" "default" "app"
         (lambda (route)
           (setf (gethash "kind" (aref (gethash "backendRefs" (aref (gethash "rules" (gethash "spec" route)) 0)) 0)) kind)
           route))
        (gr8s.controllers::converge-gateway-listeners controller)
        (let* ((action (funcall published "app.example.com" "/up" "GET" nil))
               (backend (gr8s.controllers::gw-dispatch-backend action)))
          (is (not (null backend)))
          (is (equal (unless (equal kind "Service") "InvalidKind")
                     (gr8s.controllers::gw-backend-invalid-reason backend))))))))
