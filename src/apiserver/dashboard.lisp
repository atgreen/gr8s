;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Serve a Kubernetes dashboard (the Headlamp frontend) straight from gr8s.
;;;;
;;;; The Headlamp frontend is a reverse-proxy client of the Kubernetes API: it
;;;; speaks native Kubernetes (same paths, verbs, bodies and watch semantics as
;;;; kubectl) but prefixes every apiserver call with /clusters/<name>/, and it
;;;; fetches a /config document at boot and lists /plugins. gr8s IS the apiserver,
;;;; so rather than run Headlamp's Go backend (headlamp-server) we implement the
;;;; small subset of its contract the frontend needs, dispatching the proxied
;;;; apiserver calls internally -- no second process, no network hop. The whole
;;;; mount lives under /dashboard/ (the frontend is built with base-url
;;;; /dashboard) so it never collides with gr8s's own API at /api and /apis.
;;;;
;;;; This is the read path (podster-9rh): /config, /plugins, the
;;;; /clusters/<name>/ apiserver proxy, and the static SPA. Live updates over the
;;;; /wsMultiplexer WebSocket are a separate increment.

(in-package #:gr8s.apiserver)

(defparameter *dashboard-enabled* (dashboard-assets-present-p)
  "When true, the API acceptor serves the dashboard under /dashboard/. Defaults to
whether a Headlamp frontend build was baked into this image.")

(defparameter *dashboard-static-root* nil
  "Optional development override: a directory of built Headlamp frontend assets to
serve instead of the ones embedded in the image. NIL serves the embedded assets.")

(defparameter +dashboard-base+ "/dashboard"
  "URL mount point for the dashboard; must match the frontend bundle's base-url.")

(defparameter +dashboard-cluster-name+ "gr8s"
  "The single cluster name the dashboard advertises; it appears in the frontend's
/clusters/<name>/ request URLs and is discarded when proxying (gr8s is that one
cluster).")

(defun dashboard-path (&rest segments)
  "Return the dashboard URL for SEGMENTS, e.g. (dashboard-path \"config\")."
  (format nil "~A~{/~A~}" +dashboard-base+ segments))

(defun dashboard-request-p (path)
  "True when PATH addresses the dashboard mount (/dashboard or /dashboard/...)."
  (or (string= path +dashboard-base+)
      (uiop:string-prefix-p (concatenate 'string +dashboard-base+ "/") path)))

(defun dashboard-cluster-proxy-target-path (path)
  "Return the bare apiserver path for a dashboard cluster-scoped PATH
(/dashboard/clusters/<name>/<api...>), or NIL when PATH is not one. The <name>
segment is discarded -- this backend serves exactly one cluster -- so
/dashboard/clusters/gr8s/api/v1/pods yields /api/v1/pods, and a bare
/dashboard/clusters/<name> yields /."
  (let ((prefix (concatenate 'string +dashboard-base+ "/clusters/")))
    (when (uiop:string-prefix-p prefix path)
      (let* ((rest (subseq path (length prefix)))
             (slash (position #\/ rest)))
        (if (and slash (< (1+ slash) (length rest)))
            (subseq rest slash)
            "/")))))

(defun dashboard-config-json ()
  "The boot /config document the Headlamp frontend fetches first. The snake_case
keys meta_data and auth_type are load-bearing: the frontend reads them verbatim."
  (com.inuoe.jzon:stringify
   (core-object
    "clusters" (vector (core-object
                        "name" +dashboard-cluster-name+
                        "auth_type" ""
                        "meta_data" (core-object "source" "kubeconfig"
                                                 "namespace" "default")))
    "isDynamicClusterEnabled" nil
    "allowKubeconfigChanges" nil
    "defaultPodDebugImage" ""
    "defaultNodeShellImage" ""
    "defaultNodeShellNamespace" ""
    "oidcAutoLogin" nil)))

(defun dashboard-rewrite-index (bytes)
  "Apply Headlamp's base-url substitutions to the index.html BYTES for the
/dashboard base, exactly as headlamp-server's makeBaseURLReplacements does: set
the headlampBaseUrl script variable and rebase the relative asset and CSS-url
references under /dashboard. Returns the rewritten bytes."
  (flet ((literal (needle replacement text)
           (cl-ppcre:regex-replace-all (cl-ppcre:quote-meta-chars needle) text replacement)))
    (let ((text (trivial-utf-8:utf-8-bytes-to-string bytes)))
      (setf text (literal "headlampBaseUrl = __baseUrl__"
                          (format nil "headlampBaseUrl = '~A'" +dashboard-base+) text)
            text (literal "./" (concatenate 'string +dashboard-base+ "/") text)
            text (literal "url(" (concatenate 'string "url(" +dashboard-base+ "/") text))
      (trivial-utf-8:string-to-utf-8-bytes text))))

(defun dashboard-safe-asset-path (relative)
  "Resolve RELATIVE under the development override *dashboard-static-root*, or NIL
if it escapes the root or does not exist. Refuses path traversal."
  (let ((root (ignore-errors (truename (uiop:ensure-directory-pathname *dashboard-static-root*)))))
    (when root
      (let ((candidate (ignore-errors (truename (merge-pathnames relative root)))))
        (when (and candidate (uiop:subpathp candidate root))
          candidate)))))

(defun dashboard-static-response (path)
  "Serve the Headlamp frontend for the dashboard PATH. A missing asset falls back
to index.html (Headlamp is a single-page app with client-side routing). Assets
come from the image embed, unless the development override *dashboard-static-root*
is set. index.html is rewritten for the /dashboard base on the way out."
  (let ((relative (string-left-trim "/" (subseq path (length +dashboard-base+)))))
    (when (zerop (length relative))
      (setf relative "index.html"))
    (if *dashboard-static-root*
        ;; Development override: serve from disk (index.html still rebased).
        (let ((asset (or (dashboard-safe-asset-path relative)
                         (dashboard-safe-asset-path "index.html"))))
          (if asset
              (progn
                (setf (hunchentoot:content-type*)
                      (dashboard-content-type (file-namestring asset)))
                (let ((bytes (with-open-file (in asset :element-type '(unsigned-byte 8))
                               (let ((b (make-array (file-length in)
                                                    :element-type '(unsigned-byte 8))))
                                 (read-sequence b in) b))))
                  (if (string= (file-namestring asset) "index.html")
                      (dashboard-rewrite-index bytes)
                      bytes)))
              (dashboard-not-found)))
        ;; Default: serve the assets baked into the image.
        (let ((bytes (or (gethash relative *dashboard-assets*)
                         (gethash "index.html" *dashboard-assets*))))
          (if bytes
              (let ((index-p (or (string= relative "index.html")
                                 (null (gethash relative *dashboard-assets*)))))
                (setf (hunchentoot:content-type*)
                      (dashboard-content-type (if index-p "index.html" relative)))
                (if index-p (dashboard-rewrite-index bytes) bytes))
              (dashboard-not-found))))))

(defun dashboard-not-found ()
  (setf (hunchentoot:return-code*) hunchentoot:+http-not-found+
        (hunchentoot:content-type*) "text/plain")
  "gr8s dashboard assets are not embedded in this build")

(defun dashboard-response (store runtime reconciler request)
  "Serve the dashboard mount when enabled, returning the response body, or NIL to
let normal API routing proceed (when the dashboard is disabled or PATH is not a
dashboard path). Implements the read subset of the headlamp-server contract: the
boot /config, an empty /plugins, the /clusters/<name>/ apiserver proxy (dispatched
internally through the full request pipeline), and the static SPA. /wsMultiplexer
is answered 501 until the live-update multiplexer lands."
  (let ((path (request-route-path (hunchentoot:script-name request))))
    (when (and *dashboard-enabled* (dashboard-request-p path))
      (cond
        ((string= path (dashboard-path "config"))
         (setf (hunchentoot:content-type*) "application/json")
         (dashboard-config-json))
        ((string= path (dashboard-path "plugins"))
         (setf (hunchentoot:content-type*) "application/json")
         "[]")
        ((string= path (dashboard-path "wsMultiplexer"))
         (setf (hunchentoot:return-code*) hunchentoot:+http-not-implemented+
               (hunchentoot:content-type*) "text/plain")
         "gr8s dashboard live-update multiplexer is not yet implemented")
        ((dashboard-cluster-proxy-target-path path)
         (handle-http-request store runtime reconciler request
                              :path (request-route-path
                                     (dashboard-cluster-proxy-target-path path))))
        (t
         (dashboard-static-response path))))))
