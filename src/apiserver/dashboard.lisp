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

(defparameter *dashboard-base* "/dashboard"
  "URL mount point for the dashboard, applied to the frontend as its base-url. The
`gr8s dashboard' command sets it to /dashboard/<session-token> so the UI lives at
an unguessable loopback path (as ICL's browser does), keeping other local
processes out.")

(defvar *dashboard-proxy-fn* nil
  "Function (METHOD TARGET REQUEST) that answers a proxied Kubernetes call
(TARGET is the bare apiserver path+query). The `gr8s dashboard' command binds it
to an mTLS reverse-proxy to the running cluster's API; NIL means no upstream.")

(defvar *dashboard-multiplexer-fn* nil
  "Function (REQUEST) that serves the /wsMultiplexer WebSocket: upgrade the
connection and relay the frontend's watch subscriptions to the upstream cluster.
The `gr8s dashboard' command binds it to an mTLS watch relay; NIL answers 501.")

(defparameter +dashboard-cluster-name+ "gr8s"
  "The single cluster name the dashboard advertises; it appears in the frontend's
/clusters/<name>/ request URLs and is discarded when proxying (gr8s is that one
cluster).")

(defun dashboard-path (&rest segments)
  "Return the dashboard URL for SEGMENTS, e.g. (dashboard-path \"config\")."
  (format nil "~A~{/~A~}" *dashboard-base* segments))

(defun dashboard-request-p (path)
  "True when PATH addresses the dashboard mount (/dashboard or /dashboard/...)."
  (or (string= path *dashboard-base*)
      (uiop:string-prefix-p (concatenate 'string *dashboard-base* "/") path)))

(defun dashboard-cluster-proxy-target-path (path)
  "Return the bare apiserver path for a dashboard cluster-scoped PATH
(/dashboard/clusters/<name>/<api...>), or NIL when PATH is not one. The <name>
segment is discarded -- this backend serves exactly one cluster -- so
/dashboard/clusters/gr8s/api/v1/pods yields /api/v1/pods, and a bare
/dashboard/clusters/<name> yields /."
  (let ((prefix (concatenate 'string *dashboard-base* "/clusters/")))
    (when (uiop:string-prefix-p prefix path)
      (let* ((rest (subseq path (length prefix)))
             (slash (position #\/ rest)))
        (if (and slash (< (1+ slash) (length rest)))
            (subseq rest slash)
            "/")))))

(defun dashboard-proxy-target-with-query (path request)
  "The bare apiserver path+query to proxy for a dashboard cluster-scoped PATH:
strip the /dashboard[/<token>]/clusters/<name> prefix and re-attach REQUEST's
query string (so ?watch=1, labelSelector, resourceVersion, etc. survive)."
  (let* ((api (request-route-path (dashboard-cluster-proxy-target-path path)))
         (uri (hunchentoot:request-uri request))
         (mark (position #\? uri))
         (query (and mark (subseq uri (1+ mark)))))
    (if (and query (plusp (length query)))
        (concatenate 'string api "?" query)
        api)))

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
                          (format nil "headlampBaseUrl = '~A'" *dashboard-base*) text)
            text (literal "./" (concatenate 'string *dashboard-base* "/") text)
            text (literal "url(" (concatenate 'string "url(" *dashboard-base* "/") text))
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
  (let ((relative (string-left-trim "/" (subseq path (length *dashboard-base*)))))
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
                ;; index.html is stored raw (it is rewritten per session); every
                ;; other asset may be gzip in the image and is served accordingly.
                (if index-p
                    (dashboard-rewrite-index bytes)
                    (dashboard-serve-asset-bytes relative bytes)))
              (dashboard-not-found))))))

(defun dashboard-not-found ()
  (setf (hunchentoot:return-code*) hunchentoot:+http-not-found+
        (hunchentoot:content-type*) "text/plain")
  "gr8s dashboard assets are not embedded in this build")

;;; The /wsMultiplexer live-update protocol.
;;;
;;; The Headlamp frontend opens a single WebSocket (subprotocol
;;; headlamp.multiplexer.k8s.io) and multiplexes every resource watch over it. A
;;; client control message is JSON {clusterId, path, query, userId, type}: type
;;; REQUEST starts a watch of the apiserver PATH?QUERY (QUERY already carries
;;; watch=1 and a resourceVersion), CLOSE stops it. The server streams each watch
;;; event back as a frame {clusterId, path, query, userId, type:"DATA", data} whose
;;; data field is the watch-event JSON as a string. The frontend keys its
;;; listeners on clusterId:path:query, so a DATA/COMPLETE/ERROR frame MUST echo
;;; those three fields from the REQUEST verbatim or the update is dropped.
;;;
;;; These pieces are transport-agnostic (no sockets, no WebSocket framing) so they
;;; can be unit-tested; the `gr8s dashboard' command drives them over the real
;;; WebSocket and the mTLS watch stream via *DASHBOARD-MULTIPLEXER-FN*.

(defparameter +dashboard-multiplexer-protocol+ "headlamp.multiplexer.k8s.io"
  "The WebSocket subprotocol the Headlamp multiplexer negotiates.")

(defstruct dashboard-mux-message
  "One parsed /wsMultiplexer client control message."
  cluster-id path query user-id type)

(defun dashboard-parse-multiplexer-message (text)
  "Parse a client multiplexer control message TEXT (JSON) into a
DASHBOARD-MUX-MESSAGE, or NIL when it is not valid JSON or is missing a required
routing field -- mirroring headlamp-server, which drops a message unless
clusterId, path, userId and type are all present and non-empty."
  (let ((json (ignore-errors (com.inuoe.jzon:parse text))))
    (when (hash-table-p json)
      (flet ((field (key) (let ((value (gethash key json)))
                            (and (stringp value) value))))
        (let ((cluster-id (field "clusterId"))
              (path (field "path"))
              (query (or (field "query") ""))
              (user-id (field "userId"))
              (type (field "type")))
          (when (and cluster-id path user-id type
                     (plusp (length cluster-id)) (plusp (length path))
                     (plusp (length user-id)) (plusp (length type)))
            (make-dashboard-mux-message
             :cluster-id cluster-id :path path :query query
             :user-id user-id :type type)))))))

(defun dashboard-multiplexer-key (message)
  "The connection key for MESSAGE: clusterId, path and userId, matching
headlamp-server's createConnectionKey. Query is intentionally excluded so a fresh
REQUEST (a newer resourceVersion) replaces the same watch rather than duplicating it."
  (format nil "~A~C~A~C~A"
          (dashboard-mux-message-cluster-id message) #\Nul
          (dashboard-mux-message-path message) #\Nul
          (dashboard-mux-message-user-id message)))

(defun dashboard-multiplexer-frame (message type &optional data)
  "Build a server->client multiplexer frame (a JSON string) of the given TYPE
(DATA, COMPLETE or ERROR), echoing MESSAGE's routing fields verbatim so the
frontend's clusterId:path:query listener matches. DATA (and ERROR) carry the
payload string in the data field; the frontend JSON-parses it."
  (com.inuoe.jzon:stringify
   (apply #'core-object
          "clusterId" (dashboard-mux-message-cluster-id message)
          "path" (dashboard-mux-message-path message)
          "query" (dashboard-mux-message-query message)
          "userId" (dashboard-mux-message-user-id message)
          "type" type
          (when data (list "data" data)))))

(defun dashboard-watch-upstream-target (path query)
  "The bare apiserver path+query to watch upstream for a REQUEST's PATH and QUERY.
PATH is normally already bare (e.g. /api/v1/pods); defensively strip an optional
dashboard-base prefix and an optional /clusters/<name> prefix, then re-attach
QUERY (which the frontend fills with watch=1 and a resourceVersion)."
  (let* ((unbased (if (uiop:string-prefix-p *dashboard-base* path)
                      (subseq path (length *dashboard-base*))
                      path))
         (clusters "/clusters/")
         (bare (if (uiop:string-prefix-p clusters unbased)
                   (let* ((rest (subseq unbased (length clusters)))
                          (slash (position #\/ rest)))
                     (if slash (subseq rest slash) "/"))
                   unbased)))
    (when (zerop (length bare)) (setf bare "/"))
    (if (and query (plusp (length query)))
        (concatenate 'string bare "?" query)
        bare)))

(defun dashboard-response (request)
  "Serve the dashboard mount, returning the response body, or NIL when PATH is not
a dashboard request. Implements the read subset of the headlamp-server contract:
the boot /config, an empty /plugins, the static SPA, and the /clusters/<name>/
apiserver proxy -- which is handed to *dashboard-proxy-fn* (the `gr8s dashboard'
command's mTLS reverse-proxy to the running cluster; /healthz rides the same
path). /wsMultiplexer is handed to *DASHBOARD-MULTIPLEXER-FN* (the command's
mTLS watch relay), or answered 501 when no relay is installed."
  (let ((path (request-route-path (hunchentoot:script-name request))))
    (when (dashboard-request-p path)
      (cond
        ((string= path (dashboard-path "config"))
         (setf (hunchentoot:content-type*) "application/json")
         (dashboard-config-json))
        ((string= path (dashboard-path "plugins"))
         (setf (hunchentoot:content-type*) "application/json")
         "[]")
        ((string= path (dashboard-path "wsMultiplexer"))
         (if *dashboard-multiplexer-fn*
             ;; The fn upgrades the connection and takes over the stream; its
             ;; return value is unused (the 101 response is already on the wire).
             (funcall *dashboard-multiplexer-fn* request)
             (progn
               (setf (hunchentoot:return-code*) hunchentoot:+http-not-implemented+
                     (hunchentoot:content-type*) "text/plain")
               "gr8s dashboard live-update multiplexer is not yet implemented")))
        ((dashboard-cluster-proxy-target-path path)
         (if *dashboard-proxy-fn*
             (funcall *dashboard-proxy-fn*
                      (hunchentoot:request-method request)
                      (dashboard-proxy-target-with-query path request)
                      request)
             (progn
               (setf (hunchentoot:return-code*) hunchentoot:+http-bad-gateway+
                     (hunchentoot:content-type*) "text/plain")
               "gr8s dashboard has no upstream cluster API configured")))
        (t
         (dashboard-static-response path))))))
