;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; The loopback listener that serves the embedded dashboard.
;;;;
;;;; gr8s's API listeners are mutually authenticated (client certificates on the
;;;; in-cluster TLS port), which a browser cannot present. The dashboard instead
;;;; gets its own plain-HTTP listener bound to loopback only: a local browser
;;;; reaches it with no certificate, and the Headlamp frontend's Kubernetes calls
;;;; (proxied internally through /dashboard/clusters/<name>/) run under a
;;;; loopback-admin identity -- the same local-trust model as a loopback
;;;; kubeconfig. Nothing off-host can reach it.

(in-package #:gr8s.apiserver)

(defparameter +dashboard-default-port+ 8080
  "Default loopback port for the dashboard listener.")

(defvar *dashboard-server* nil
  "The running dashboard acceptor, or NIL.")

(defclass gr8s-dashboard-acceptor (gr8s-acceptor) ()
  (:documentation "Loopback-only plain-HTTP listener for the embedded dashboard."))

(defun dashboard-admin-identity ()
  "The loopback-admin identity that proxied dashboard API calls run under, so a
local browser reaches the cluster with full read/write like a loopback kubeconfig."
  (make-api-user-identity :username "system:admin" :groups #("system:masters")))

(defmethod hunchentoot:acceptor-dispatch-request ((acceptor gr8s-dashboard-acceptor) request)
  "Serve only the dashboard mount, under a loopback-admin identity so the proxied
Kubernetes calls authorize without a client certificate."
  (let ((*authenticated-api-identity* (dashboard-admin-identity)))
    (or (dashboard-response (acceptor-store acceptor)
                            (acceptor-runtime acceptor)
                            (acceptor-reconciler acceptor)
                            request)
        (progn
          (setf (hunchentoot:return-code*) hunchentoot:+http-not-found+
                (hunchentoot:content-type*) "text/plain")
          "gr8s dashboard: not a dashboard path"))))

(defun start-dashboard-server (&key (address "127.0.0.1") (port +dashboard-default-port+)
                                    store runtime reconciler)
  "Start the loopback dashboard listener, record it in *dashboard-server*, and
return it. Refuses a non-loopback ADDRESS: the listener grants loopback-admin
access, so it must never be reachable off-host."
  (unless (member address '("127.0.0.1" "::1") :test #'equal)
    (error "the gr8s dashboard listener only binds loopback"))
  (setf *dashboard-server*
        (hunchentoot:start
         (make-instance 'gr8s-dashboard-acceptor :address address :port port
                        :store store :runtime runtime :reconciler reconciler))))

(defun stop-dashboard-server (&optional (server *dashboard-server*))
  "Stop the dashboard listener SERVER (default the running one)."
  (when server
    (hunchentoot:stop server)
    (when (eq server *dashboard-server*)
      (setf *dashboard-server* nil))))
