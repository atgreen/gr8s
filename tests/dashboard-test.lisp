;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Pin the pure routing/boot-config logic of the embedded dashboard backend
;;;; (the headlamp-server-compatible contract gr8s serves under /dashboard/).

(in-package #:gr8s/tests)
(def-suite dashboard :in gr8s)
(in-suite dashboard)

(test dashboard-request-p-matches-only-the-mount
  (is-true (gr8s.apiserver::dashboard-request-p "/dashboard"))
  (is-true (gr8s.apiserver::dashboard-request-p "/dashboard/config"))
  (is-true (gr8s.apiserver::dashboard-request-p "/dashboard/clusters/gr8s/api/v1/pods"))
  ;; A sibling path that merely starts with the word must not match.
  (is-false (gr8s.apiserver::dashboard-request-p "/dashboards"))
  (is-false (gr8s.apiserver::dashboard-request-p "/api/v1/pods"))
  (is-false (gr8s.apiserver::dashboard-request-p "/")))

(test dashboard-cluster-proxy-strips-the-cluster-prefix
  ;; /dashboard/clusters/<name>/<api...> -> /<api...>, discarding <name>.
  (is (equal "/api/v1/pods"
             (gr8s.apiserver::dashboard-cluster-proxy-target-path
              "/dashboard/clusters/gr8s/api/v1/pods")))
  (is (equal "/apis/apps/v1/namespaces/default/deployments"
             (gr8s.apiserver::dashboard-cluster-proxy-target-path
              "/dashboard/clusters/anything/apis/apps/v1/namespaces/default/deployments")))
  ;; A bare cluster path has no api part.
  (is (equal "/" (gr8s.apiserver::dashboard-cluster-proxy-target-path "/dashboard/clusters/gr8s")))
  (is (equal "/" (gr8s.apiserver::dashboard-cluster-proxy-target-path "/dashboard/clusters/gr8s/")))
  ;; Non cluster-scoped dashboard paths are not proxied.
  (is (null (gr8s.apiserver::dashboard-cluster-proxy-target-path "/dashboard/config")))
  (is (null (gr8s.apiserver::dashboard-cluster-proxy-target-path "/api/v1/pods"))))

(test dashboard-config-has-the-fields-the-frontend-requires
  (let* ((json (gr8s.apiserver::dashboard-config-json))
         (config (com.inuoe.jzon:parse json))
         (clusters (gethash "clusters" config)))
    ;; Boot config exposes exactly one cluster with the load-bearing snake_case keys.
    (is (vectorp clusters))
    (is (= 1 (length clusters)))
    (let ((cluster (aref clusters 0)))
      (is (equal "gr8s" (gethash "name" cluster)))
      ;; auth_type and meta_data must be spelled snake_case for the frontend.
      (is-true (nth-value 1 (gethash "auth_type" cluster)))
      (is (equal "kubeconfig" (gethash "source" (gethash "meta_data" cluster)))))
    ;; The boolean toggles the frontend checks at boot are present and false
    ;; (jzon parses JSON false to NIL).
    (dolist (key '("isDynamicClusterEnabled" "allowKubeconfigChanges" "oidcAutoLogin"))
      (is-true (nth-value 1 (gethash key config)) "~A present" key)
      (is-false (gethash key config) "~A is false" key))))

(test dashboard-negotiates-gzip-assets
  ;; A text asset embedded gzip is passed through to a gzip-accepting client with
  ;; Content-Encoding gzip, and decompressed for a client that does not accept it.
  (let* ((plain (trivial-utf-8:string-to-utf-8-bytes
                 "(()=>{for(let i=0;i<10;i++)console.log('headlamp',i)})();"))
         (gz (salza2:compress-data plain 'salza2:gzip-compressor))
         (gr8s.apiserver::*dashboard-asset-encodings* (make-hash-table :test 'equal)))
    (setf (gethash "static/js/app.js" gr8s.apiserver::*dashboard-asset-encodings*) "gzip")
    ;; gzip-accepting client: bytes pass through, encoding is gzip.
    (multiple-value-bind (out encoding)
        (gr8s.apiserver::dashboard-negotiate-asset "static/js/app.js" gz "gzip, deflate, br")
      (is (equalp gz out))
      (is (equal "gzip" encoding)))
    ;; non-accepting client: bytes are decompressed, no encoding set.
    (multiple-value-bind (out encoding)
        (gr8s.apiserver::dashboard-negotiate-asset "static/js/app.js" gz nil)
      (is-false encoding)
      (is (equalp plain out)))
    ;; an asset with no stored encoding is returned verbatim regardless.
    (multiple-value-bind (out encoding)
        (gr8s.apiserver::dashboard-negotiate-asset "favicon.ico" plain "gzip")
      (is-false encoding)
      (is (equalp plain out)))))

(test dashboard-content-type-maps-extensions
  (is (equal "text/javascript; charset=utf-8" (gr8s.apiserver::dashboard-content-type "main.js")))
  (is (equal "text/html; charset=utf-8" (gr8s.apiserver::dashboard-content-type "index.html")))
  (is (equal "text/css; charset=utf-8" (gr8s.apiserver::dashboard-content-type "static/css/a.b.css")))
  (is (equal "font/woff2" (gr8s.apiserver::dashboard-content-type "x.woff2")))
  (is (equal "application/octet-stream" (gr8s.apiserver::dashboard-content-type "noext"))))

(test dashboard-index-rewrite-applies-the-base-url
  ;; Mirrors headlamp-server's makeBaseURLReplacements for base /dashboard.
  ;; Headlamp's own replacements assume url() imports have no "./" in them (its
  ;; comment says so), so the test mirrors that: "./" on script refs, bare url().
  (let* ((in (trivial-utf-8:string-to-utf-8-bytes
              "headlampBaseUrl = __baseUrl__; <script src=\"./static/x.js\"></script> url(fonts/f.woff2)"))
         (out (trivial-utf-8:utf-8-bytes-to-string (gr8s.apiserver::dashboard-rewrite-index in))))
    (is-true (search "headlampBaseUrl = '/dashboard'" out))
    (is-false (search "__baseUrl__" out))
    (is-true (search "\"/dashboard/static/x.js\"" out))
    (is-true (search "url(/dashboard/fonts/f.woff2)" out))))

(test dashboard-session-token-is-unguessable-and-unique
  ;; icl-style URL-path secret: long hex, fresh each call.
  (let ((a (gr8s.server::dashboard-session-token))
        (b (gr8s.server::dashboard-session-token)))
    (is (>= (length a) 32))
    (is (every (lambda (c) (digit-char-p c 16)) a))
    (is (not (equal a b)))))

;;;; /wsMultiplexer protocol (the pure, transport-agnostic pieces).

(test dashboard-multiplexer-parses-a-valid-request
  (let ((message (gr8s.apiserver::dashboard-parse-multiplexer-message
                  "{\"clusterId\":\"gr8s\",\"path\":\"/api/v1/pods\",\"query\":\"watch=1&resourceVersion=42\",\"userId\":\"u1\",\"type\":\"REQUEST\"}")))
    (is-true message)
    (is (equal "gr8s" (gr8s.apiserver::dashboard-mux-message-cluster-id message)))
    (is (equal "/api/v1/pods" (gr8s.apiserver::dashboard-mux-message-path message)))
    (is (equal "watch=1&resourceVersion=42" (gr8s.apiserver::dashboard-mux-message-query message)))
    (is (equal "u1" (gr8s.apiserver::dashboard-mux-message-user-id message)))
    (is (equal "REQUEST" (gr8s.apiserver::dashboard-mux-message-type message))))
  ;; A missing query defaults to the empty string (a bare watch is legal).
  (let ((message (gr8s.apiserver::dashboard-parse-multiplexer-message
                  "{\"clusterId\":\"gr8s\",\"path\":\"/api/v1/pods\",\"userId\":\"u1\",\"type\":\"CLOSE\"}")))
    (is-true message)
    (is (equal "" (gr8s.apiserver::dashboard-mux-message-query message)))))

(test dashboard-multiplexer-rejects-malformed-or-incomplete-messages
  ;; Not JSON, not an object, and each missing/empty required routing field.
  (is-false (gr8s.apiserver::dashboard-parse-multiplexer-message "not json"))
  (is-false (gr8s.apiserver::dashboard-parse-multiplexer-message "[1,2,3]"))
  (is-false (gr8s.apiserver::dashboard-parse-multiplexer-message
             "{\"path\":\"/api/v1/pods\",\"userId\":\"u1\",\"type\":\"REQUEST\"}"))
  (is-false (gr8s.apiserver::dashboard-parse-multiplexer-message
             "{\"clusterId\":\"gr8s\",\"userId\":\"u1\",\"type\":\"REQUEST\"}"))
  (is-false (gr8s.apiserver::dashboard-parse-multiplexer-message
             "{\"clusterId\":\"gr8s\",\"path\":\"/api/v1/pods\",\"userId\":\"\",\"type\":\"REQUEST\"}"))
  (is-false (gr8s.apiserver::dashboard-parse-multiplexer-message
             "{\"clusterId\":\"gr8s\",\"path\":\"/api/v1/pods\",\"userId\":\"u1\"}")))

(test dashboard-multiplexer-key-excludes-query
  ;; The connection key is clusterId:path:userId -- query is excluded, so a newer
  ;; resourceVersion for the same resource replaces rather than duplicates.
  (flet ((key (query)
           (gr8s.apiserver::dashboard-multiplexer-key
            (gr8s.apiserver::make-dashboard-mux-message
             :cluster-id "gr8s" :path "/api/v1/pods" :query query
             :user-id "u1" :type "REQUEST"))))
    (is (equal (key "watch=1&resourceVersion=1") (key "watch=1&resourceVersion=2")))
    (is (not (equal (key "") (gr8s.apiserver::dashboard-multiplexer-key
                              (gr8s.apiserver::make-dashboard-mux-message
                               :cluster-id "gr8s" :path "/api/v1/nodes" :query ""
                               :user-id "u1" :type "REQUEST")))))))

(test dashboard-multiplexer-frame-echoes-routing-fields
  ;; A DATA frame must echo clusterId/path/query verbatim (the frontend matches on
  ;; them) and carry the watch event as a JSON *string* in data.
  (let* ((message (gr8s.apiserver::make-dashboard-mux-message
                   :cluster-id "gr8s" :path "/api/v1/pods" :query "watch=1&resourceVersion=42"
                   :user-id "u1" :type "REQUEST"))
         (event "{\"type\":\"ADDED\",\"object\":{\"kind\":\"Pod\"}}")
         (frame (com.inuoe.jzon:parse
                 (gr8s.apiserver::dashboard-multiplexer-frame message "DATA" event))))
    (is (equal "gr8s" (gethash "clusterId" frame)))
    (is (equal "/api/v1/pods" (gethash "path" frame)))
    (is (equal "watch=1&resourceVersion=42" (gethash "query" frame)))
    (is (equal "u1" (gethash "userId" frame)))
    (is (equal "DATA" (gethash "type" frame)))
    ;; data is the event *string*, which the frontend JSON-parses back.
    (is (equal event (gethash "data" frame)))
    (is (equal "ADDED" (gethash "type" (com.inuoe.jzon:parse (gethash "data" frame))))))
  ;; A COMPLETE frame carries no data key at all.
  (let* ((message (gr8s.apiserver::make-dashboard-mux-message
                   :cluster-id "gr8s" :path "/api/v1/pods" :query ""
                   :user-id "u1" :type "REQUEST"))
         (frame (com.inuoe.jzon:parse
                 (gr8s.apiserver::dashboard-multiplexer-frame message "COMPLETE"))))
    (is (equal "COMPLETE" (gethash "type" frame)))
    (is-false (nth-value 1 (gethash "data" frame)))))

(test dashboard-watch-upstream-target-strips-prefixes
  (let ((gr8s.apiserver::*dashboard-base* "/dashboard/tok"))
    ;; A bare apiserver path (what the frontend normally sends) passes through,
    ;; with the watch query re-attached.
    (is (equal "/api/v1/pods?watch=1&resourceVersion=5"
               (gr8s.apiserver::dashboard-watch-upstream-target
                "/api/v1/pods" "watch=1&resourceVersion=5")))
    ;; No query -> bare path.
    (is (equal "/api/v1/nodes"
               (gr8s.apiserver::dashboard-watch-upstream-target "/api/v1/nodes" "")))
    ;; A dashboard-base prefix is stripped.
    (is (equal "/api/v1/pods?watch=1"
               (gr8s.apiserver::dashboard-watch-upstream-target
                "/dashboard/tok/api/v1/pods" "watch=1")))
    ;; A /clusters/<name> prefix is stripped (name discarded).
    (is (equal "/apis/apps/v1/deployments?watch=1"
               (gr8s.apiserver::dashboard-watch-upstream-target
                "/dashboard/tok/clusters/gr8s/apis/apps/v1/deployments" "watch=1")))))

(defun %chunk (string)
  "Encode STRING as one HTTP chunk (hex length, CRLF, data, CRLF) as octets."
  (flexi-streams:string-to-octets
   (format nil "~X~C~C~A~C~C" (length string) #\Return #\Linefeed
           string #\Return #\Linefeed)
   :external-format :utf-8))

(test dashboard-watch-event-stream-reassembles-chunks
  ;; STREAM-WATCH-EVENTS must split a chunked watch body into newline-delimited
  ;; events regardless of chunk boundaries: one event split across two chunks, and
  ;; two events packed into one chunk, then the terminating zero chunk.
  (let* ((body (apply #'concatenate '(vector (unsigned-byte 8))
                      (list (%chunk "{\"type\":\"ADDED\",")       ; event 1, part 1
                            (%chunk "\"object\":{\"n\":1}}
")                                                                  ; event 1, part 2 + LF
                            (%chunk "{\"type\":\"MODIFIED\",\"object\":{\"n\":2}}
{\"type\":\"DELETED\",\"object\":{\"n\":3}}
")                                                                  ; events 2 and 3
                            (flexi-streams:string-to-octets
                             (format nil "0~C~C~C~C" #\Return #\Linefeed #\Return #\Linefeed)))))
         (stream (flexi-streams:make-in-memory-input-stream body))
         (events '()))
    (gr8s.server::stream-watch-events
     stream '((:transfer-encoding . "chunked"))
     (lambda (event) (push event events))
     (constantly t))
    (setf events (nreverse events))
    (is (= 3 (length events)))
    (is (equal "{\"type\":\"ADDED\",\"object\":{\"n\":1}}" (first events)))
    (is (equal "MODIFIED" (gethash "type" (com.inuoe.jzon:parse (second events)))))
    (is (equal "DELETED" (gethash "type" (com.inuoe.jzon:parse (third events)))))))

(test the-dashboard-command-logs-requests-only-when-asked
  (let ((quiet (gr8s.server::parse-dashboard-options '("--no-launch")))
        (verbose (gr8s.server::parse-dashboard-options '("--verbose" "--port" "8193"))))
    (is-false (getf quiet :verbose))
    (is-true (getf verbose :verbose))
    (is (= 8193 (getf verbose :port))))
  (signals error (gr8s.server::parse-dashboard-options '("--verbose" "extra"))))

(test the-agent-tab-keeps-the-readers-own-agents
  ;; podster-9et: agents the reader defines persist, and a bad one is refused or skipped.
  (let* ((directory (uiop:ensure-directory-pathname
                     (sb-posix:mkdtemp (namestring (merge-pathnames "gr8s-agents-XXXXXX" (uiop:temporary-directory))))))
         (file (merge-pathnames "gr8s/dashboard-agents.json" directory)))
    (unwind-protect
         (progn
           (is (null (gr8s.server::read-custom-agents file)))
           (gr8s.server::write-custom-agents '(("aider" "Aider" ("aider" "--read" "{guide-file}"))
                                               ("goose" "Goose" ("goose" "session")))
                                             file)
           (is (equal '(("aider" "Aider" ("aider" "--read" "{guide-file}")) ("goose" "Goose" ("goose" "session")))
                      (gr8s.server::read-custom-agents file)))
           (is (= #o600 (logand #o777 (sb-posix:stat-mode (sb-posix:stat (namestring file))))))
           ;; One unsound entry, edited in by hand, is left out; the rest survive.
           (alexandria:write-string-into-file
            "[{\"id\":\"ok\",\"label\":\"OK\",\"command\":[\"ok\"]},{\"id\":\"Bad Id\",\"label\":\"x\",\"command\":[\"x\"]},{\"id\":\"none\",\"label\":\"No command\",\"command\":[]}]"
            file :if-exists :supersede)
           (is (equal '(("ok" "OK" ("ok"))) (gr8s.server::read-custom-agents file)))
           (flet ((problem (id label command &optional taken)
                    (gr8s.server::custom-agent-problem id label command taken)))
             (is (null (problem "my-agent" "My agent" '("prog" "--flag"))))
             (is (search "lowercase" (problem "My Agent" "x" '("prog"))))
             (is (search "built-in" (problem "claude" "x" '("prog"))))
             (is (search "built-in" (problem "shell" "x" '("prog"))))
             (is (search "two agents" (problem "a" "x" '("prog") '("a"))))
             (is (search "name" (problem "a" "" '("prog"))))
             (is (search "name" (problem "a" (format nil "two~%lines") '("prog"))))
             (is (search "command" (problem "a" "A" '())))
             (is (search "command" (problem "a" "A" '(""))))))
      (uiop:delete-directory-tree directory :validate t))))

(test the-agent-tab-fills-in-a-readers-agents-placeholders
  ;; podster-9et: a command line of the reader's names the guide, gr8s mcp, the kubeconfig
  ;; and gr8s; each is replaced, files in a private directory the tab removes when it stops.
  (let* ((directory (uiop:ensure-directory-pathname
                     (sb-posix:mkdtemp (namestring (merge-pathnames "gr8s-agents-XXXXXX" (uiop:temporary-directory))))))
         (agent (gr8s.server::make-dashboard-agent "/home/u/kc.yaml" :gr8s "/opt/gr8s"
                                                   :agents-file (merge-pathnames "agents.json" directory))))
    (unwind-protect
         (let ((argv (gr8s.server::choice-argv
                      agent (list :id "mine" :label "Mine" :program "/usr/bin/mine" :builtin nil
                                  :command '("mine" "--guide={guide-file}" "--mcp" "{mcp-config-file}"
                                             "--kc" "{kubeconfig}" "{gr8s} mcp" "{mcp-config}" "a\\b {nothing}")))))
           (is (equal "/usr/bin/mine" (first argv)))
           (let ((guide (subseq (second argv) (length "--guide="))))
             (is (uiop:string-prefix-p "# gr8s operator and agent guide" (uiop:read-file-string guide)))
             (is (= #o700 (logand #o777 (sb-posix:stat-mode (sb-posix:stat (directory-namestring guide)))))))
           (let ((server (gethash "gr8s" (gethash "mcpServers" (com.inuoe.jzon:parse (pathname (fourth argv)))))))
             (is (equal "/opt/gr8s" (gethash "command" server)))
             (is (equalp #("mcp" "--kubeconfig" "/home/u/kc.yaml") (gethash "args" server))))
           (is (equal '("--kc" "/home/u/kc.yaml" "/opt/gr8s mcp") (subseq argv 4 7)))
           (is (equal (uiop:read-file-string (fourth argv)) (eighth argv)))
           ;; Text that names no placeholder, backslashes included, is passed as it is.
           (is (equal "a\\b {nothing}" (ninth argv)))
           (let ((context (gr8s.server::dashboard-agent-context-directory agent)))
             (gr8s.server::stop-dashboard-agents agent)
             (is (null (probe-file context)))))
      (uiop:delete-directory-tree directory :validate t))))
