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

;;;; The Network tab's graph (podster-5hv)

(defun network-test-topology ()
  (flet ((objects (text) (coerce (com.inuoe.jzon:parse text) 'list)))
    (gr8s.server::build-network-topology
     (objects "[{\"metadata\":{\"namespace\":\"cave\",\"name\":\"cave-runner-b4-x\",
                \"ownerReferences\":[{\"kind\":\"ReplicaSet\",\"name\":\"cave-runner-b4\"}]},
                \"spec\":{\"containers\":[{\"image\":\"registry.lab.example:30500/cave-runner:k8sjobs3\"}]},\"status\":{\"podIP\":\"10.80.16.4\"}},
               {\"metadata\":{\"namespace\":\"cave\",\"name\":\"cave-pg-0\",
                \"ownerReferences\":[{\"kind\":\"StatefulSet\",\"name\":\"cave-pg\"}]},
                \"spec\":{\"containers\":[{\"image\":\"docker.io/library/postgres:17\"}]},\"status\":{\"podIP\":\"10.80.0.4\"}},
               {\"metadata\":{\"namespace\":\"cave\",\"name\":\"lonely\"},
                \"spec\":{\"containers\":[{\"image\":\"busybox\"}]},\"status\":{\"podIP\":\"10.80.0.9\"}},
               {\"metadata\":{\"namespace\":\"monitoring\",\"name\":\"exporter-a\",
                \"ownerReferences\":[{\"kind\":\"DaemonSet\",\"name\":\"node-exporter\"}]},
                \"spec\":{\"hostNetwork\":true,\"containers\":[{\"image\":\"quay.io/prometheus/node-exporter\"}]},
                \"status\":{\"podIP\":\"10.77.77.21\"}}]")
     (objects "[{\"metadata\":{\"namespace\":\"cave\",\"name\":\"cave-runner-b4\",
                \"ownerReferences\":[{\"kind\":\"Deployment\",\"name\":\"cave-runner\"}]}}]")
     (objects "[{\"metadata\":{\"namespace\":\"cave\",\"name\":\"cave\"},\"spec\":{\"clusterIP\":\"10.96.0.20\"}}]")
     (objects "[{\"metadata\":{\"name\":\"gvision\"},\"spec\":{\"podCIDR\":\"10.80.0.0/20\"},
                \"status\":{\"addresses\":[{\"type\":\"InternalIP\",\"address\":\"10.77.77.21\"}]}}]"))))

(defun network-test-flow (&rest pairs)
  (let ((flow (gr8s.resources::core-object "time" "2026-11-25T12:00:00Z" "verdict" "FORWARDED" "direction" "egress"
                                           "protocol" "TCP" "namespace" "cave" "pod" "cave-runner-b4-x"
                                           "podPort" 41000 "length" 100)))
    (loop for (key value) on pairs by #'cddr do (setf (gethash key flow) value))
    flow))

(test network-topology-resolves-workloads-services-and-nodes
  (let ((topology (network-test-topology)))
    (flet ((pod (namespace name) (gethash (cons namespace name) (gr8s.server::network-topology-pods topology))))
      (is (equal '("cave" "Deployment" "cave-runner") (pod "cave" "cave-runner-b4-x")) "through its ReplicaSet")
      (is (equal '("cave" "StatefulSet" "cave-pg") (pod "cave" "cave-pg-0")))
      (is (equal '("cave" "Pod" "lonely") (pod "cave" "lonely")) "a Pod nothing owns")
      (is (equal '("cave" "StatefulSet" "cave-pg") (gethash "10.80.0.4" (gr8s.server::network-topology-addresses topology))))
      (is (null (gethash "10.77.77.21" (gr8s.server::network-topology-addresses topology)))
          "a host-network Pod's address stays its node's")
      (is (equal "gvision" (gethash "10.77.77.21" (gr8s.server::network-topology-nodes topology))))
      (is (equal "gvision" (gethash "10.80.0.0" (gr8s.server::network-topology-nodes topology))) "the Pod gateway")
      (is (equal '("cave" "Service" "cave") (gethash "10.96.0.20" (gr8s.server::network-topology-services topology))))
      (is (equal '("postgresql" "PostgreSQL")
                 (multiple-value-list (gr8s.server::network-workload-software topology '("cave" "StatefulSet" "cave-pg")))))
      (is (equal '("lucide-layers" nil)
                 (multiple-value-list (gr8s.server::network-workload-software topology '("cave" "Deployment" "cave-runner"))))
          "an image from a registry isn't a registry: the kind's icon"))))

(test network-graph-counts-each-connection-once
  (let ((graph (gr8s.server::make-network-graph))
        (now (encode-universal-time 30 0 12 25 11 2026 0)))
    (setf (gr8s.server::network-graph-topology graph) (network-test-topology))
    (flet ((note (&rest pairs) (gr8s.server::network-graph-note-flow graph (apply #'network-test-flow pairs)))
           (edge (source target)
             (find-if (lambda (e) (and (equal source (gethash "source" e)) (equal target (gethash "target" e))))
                      (coerce (gethash "edges" (gr8s.server::network-graph-object graph now)) 'list))))
      ;; The runner dials Postgres: seen leaving the runner, and arriving at cave-pg-0.
      (note "peerAddress" "10.80.0.4" "peerPort" 5432)
      (note "namespace" "cave" "pod" "cave-pg-0" "direction" "ingress" "podPort" 5432
            "peerAddress" "10.80.16.4" "peerPort" 41000)
      (let ((e (edge "cave/Deployment/cave-runner" "cave/StatefulSet/cave-pg")))
        (is (= 1 (gethash "flows" (gethash "m1" e))) "counted once, where it left")
        (is (equalp #("5432/TCP") (gethash "ports" e))))
      ;; A connection the destination's policy refused counts, and as dropped.
      (note "namespace" "cave" "pod" "cave-pg-0" "direction" "ingress" "verdict" "DROPPED" "podPort" 5432
            "peerAddress" "10.80.0.9" "peerPort" 41001 "policies" #("cave/cave-pg"))
      (let ((e (edge "cave/Pod/lonely" "cave/StatefulSet/cave-pg")))
        (is (= 1 (gethash "dropped" (gethash "m1" e)))))
      ;; Link-local neighbours are one LAN node; anything public is the world.
      (note "direction" "ingress" "peerAddress" "fe80::1d:9aff:fec9:7d4a" "podPort" 5353 "protocol" "UDP")
      (note "direction" "ingress" "peerAddress" "fe80::91:34ff:fe29:d9dd" "podPort" 3702 "protocol" "UDP")
      (is (= 2 (gethash "flows" (gethash "m1" (edge "LAN/link-local" "cave/Deployment/cave-runner")))))
      (note "peerAddress" "140.82.112.3" "peerPort" 443)
      (is (edge "cave/Deployment/cave-runner" "World/world"))
      ;; The node's Pod gateway is the node.
      (note "direction" "ingress" "peerAddress" "10.80.0.0" "podPort" 8080)
      (is (edge "Node/gvision" "cave/Deployment/cave-runner"))
      ;; A Gateway request with HTTP 502, and its latency.
      (note "peerAddress" "10.96.0.20" "peerPort" 8080
            "l7" (gr8s.resources::core-object "method" "GET" "path" "/" "code" 502 "latencyNs" 4000000))
      (let ((e (edge "cave/Deployment/cave-runner" "cave/Service/cave")))
        (is (= 1 (gethash "errors" (gethash "m1" e))))
        (is (= 4 (gethash "latencyMs" e))))
      (is (= 1 (length (gr8s.server::network-graph-edge-flows
                        graph "cave/Deployment/cave-runner>cave/StatefulSet/cave-pg")))
          "the edge's flows show the connection once too"))))

(test network-graph-windows-and-expiry
  (let* ((graph (gr8s.server::make-network-graph))
         (now (encode-universal-time 0 30 12 25 11 2026 0))
         (stamp (lambda (seconds-ago)
                  (multiple-value-bind (s m h d mo y) (decode-universal-time (- now seconds-ago) 0)
                    (format nil "~4,'0D-~2,'0D-~2,'0DT~2,'0D:~2,'0D:~2,'0DZ" y mo d h m s)))))
    (setf (gr8s.server::network-graph-topology graph) (network-test-topology))
    (dolist (ago '(5 30 200 600 1200))
      (gr8s.server::network-graph-note-flow
       graph (network-test-flow "time" (funcall stamp ago) "peerAddress" "10.80.0.4" "peerPort" 5432)))
    (let ((e (aref (gethash "edges" (gr8s.server::network-graph-object graph now)) 0)))
      (is (= 2 (gethash "flows" (gethash "m1" e))))
      (is (= 3 (gethash "flows" (gethash "m5" e))))
      (is (= 4 (gethash "flows" (gethash "m15" e))) "the 20-minute-old flow is outside every window"))
    (gr8s.server::network-graph-expire graph (+ now 3600))
    (let ((object (gr8s.server::network-graph-object graph (+ now 3600))))
      (is (zerop (length (gethash "edges" object))))
      (is (zerop (length (gethash "nodes" object))) "and its nodes with it"))))

(test network-graph-keeps-the-latest-flows-with-their-edges
  (let ((graph (gr8s.server::make-network-graph)))
    (setf (gr8s.server::network-graph-topology graph) (network-test-topology))
    (gr8s.server::network-graph-note-flow graph (network-test-flow "peerAddress" "10.80.0.4" "peerPort" 5432))
    ;; ICMP has no port, and a flow may name no protocol: no empty port entry results.
    (gr8s.server::network-graph-note-flow graph (network-test-flow "peerAddress" "140.82.112.3" "protocol" "" "peerPort" nil))
    (let ((latest (gr8s.server::network-graph-latest-flows graph)))
      (is (= 2 (length latest)))
      (is (equal "cave/Deployment/cave-runner>World/world" (gethash "edge" (first latest))) "newest first")
      (is (equal "cave/Deployment/cave-runner>cave/StatefulSet/cave-pg" (gethash "edge" (second latest)))))
    (let ((world (find "World/world" (coerce (gethash "edges" (gr8s.server::network-graph-object graph)) 'list)
                       :key (lambda (e) (gethash "target" e)) :test #'equal)))
      (is (zerop (length (gethash "ports" world)))))))

;;; Favicons (podster-5hv)

(defparameter *network-test-png*
  (coerce #(#x89 #x50 #x4e #x47 #x0d #x0a #x1a #x0a 0 0 0 13 #x49 #x48 #x44 #x52) '(simple-array (unsigned-byte 8) (*))))

(test network-favicon-pieces
  (is (equal "image/png" (gr8s.server::network-image-type *network-test-png*)))
  (is (equal "image/x-icon" (gr8s.server::network-image-type (coerce #(0 0 1 0 1 0) '(vector (unsigned-byte 8))))))
  (is (equal "image/svg+xml" (gr8s.server::network-image-type
                                (trivial-utf-8:string-to-utf-8-bytes "<?xml version=\"1.0\"?>
<svg xmlns=\"http://www.w3.org/2000/svg\"/>")))
      "an SVG, which the page shows in an <img> and the dashboard serves sandboxed")
  (is (null (gr8s.server::network-image-type (trivial-utf-8:string-to-utf-8-bytes "<html><script>alert(1)</script>")))
      "not an image at all")
  (is (equal '("/static/fav32.png" "favicon.ico" "/logo.svg")
             (gr8s.server::network-page-icon-links
              "<html><head><link rel=\"stylesheet\" href=\"/a.css\"><link rel=\"icon\" type=\"image/png\" href=\"/static/fav32.png\">
               <LINK REL='shortcut icon' HREF='favicon.ico'><link rel=\"icon\" href=\"/logo.svg\"></head></html>")))
  (let ((base "/api/v1/namespaces/cave/services/cave:8080/proxy"))
    (is (equal (concatenate 'string base "/static/i.png") (gr8s.server::network-proxy-target base "/login" "/static/i.png")))
    (is (equal (concatenate 'string base "/app/i.png") (gr8s.server::network-proxy-target base "/app/login" "i.png")))
    (is (null (gr8s.server::network-proxy-target base "/" "https://cdn.example/i.png")) "a link off the app is not followed"))
  (flet ((ports (text) (gr8s.server::network-service-web-ports (com.inuoe.jzon:parse text))))
    (is (equal '((9444 nil) (8080 nil))
               (ports "{\"spec\":{\"ports\":[{\"name\":\"grpc\",\"port\":9444,\"appProtocol\":\"http\"},{\"name\":\"metrics\",\"port\":9100},{\"name\":\"http\",\"port\":8080}]}}"))
        "named or app-protocolled http first, in order; an unknown port is not a web UI")
    (is (equal '((443 t)) (ports "{\"spec\":{\"ports\":[{\"name\":\"https\",\"port\":443}]}}")))))

(defvar *network-favicon-test-requests* nil)

(defclass network-favicon-api (hunchentoot:acceptor) ()
  (:default-initargs :access-log-destination nil :message-log-destination nil))

(defmethod hunchentoot:acceptor-dispatch-request ((acceptor network-favicon-api) request)
  ;; Plays the cluster API's Service proxy for two apps: cave (an icon link behind a redirect)
  ;; and plain (only an SVG link, and no /favicon.ico).
  (let ((path (hunchentoot:script-name request))
        (cave "/api/v1/namespaces/cave/services/cave:8080/proxy")
        (plain "/api/v1/namespaces/cave/services/plain:80/proxy"))
    (push path *network-favicon-test-requests*)
    (cond ((equal path (concatenate 'string cave "/"))
           (hunchentoot:redirect (concatenate 'string cave "/login") :code 302))
          ((equal path (concatenate 'string cave "/login"))
           "<html><head><link rel=\"icon\" href=\"/static/cave.png\"></head></html>")
          ((equal path (concatenate 'string cave "/static/cave.png"))
           (setf (hunchentoot:content-type*) "image/png") *network-test-png*)
          ((equal path (concatenate 'string plain "/")) "<link rel=icon href=/logo.svg>")
          ((equal path (concatenate 'string plain "/logo.svg"))
           (setf (hunchentoot:content-type*) "image/svg+xml") "<svg xmlns=\"http://www.w3.org/2000/svg\"/>")
          (t (setf (hunchentoot:return-code*) 404) ""))))

(test network-favicon-is-read-through-the-service-proxy
  (let ((api (hunchentoot:start (make-instance 'network-favicon-api :address "127.0.0.1" :port 0))))
    (unwind-protect
         (let ((config (list :server (format nil "http://127.0.0.1:~D" (hunchentoot:acceptor-port api)))))
           (setf *network-favicon-test-requests* nil)
           (multiple-value-bind (octets type) (gr8s.server::fetch-network-favicon config '("cave" "cave" 8080 nil))
             (is (equal "image/png" type) "the page's icon link, after the redirect to /login")
             (is (equalp *network-test-png* octets)))
           (is (equal "image/svg+xml" (nth-value 1 (gr8s.server::fetch-network-favicon config '("cave" "plain" 80 nil))))
               "an app whose only icon is an SVG, as cave's is")
           (is (every (lambda (path) (uiop:string-prefix-p "/api/v1/namespaces/cave/services/" path))
                      *network-favicon-test-requests*)
               "only ever through the Service proxy"))
      (hunchentoot:stop api))))

(test network-graph-draws-the-gateway-between-clients-and-backends
  ;; podster-5hv: traffic a Gateway relays reads client -> Gateway -> backend, not node -> backend.
  (let* ((graph (gr8s.server::make-network-graph))
         (topology (flet ((objects (text) (coerce (com.inuoe.jzon:parse text) 'list)))
                     (gr8s.server::build-network-topology
                      (objects "[{\"metadata\":{\"namespace\":\"cave\",\"name\":\"cave-0\",\"labels\":{\"app\":\"cave\"},
                                 \"ownerReferences\":[{\"kind\":\"StatefulSet\",\"name\":\"cave\"}]},
                                 \"spec\":{\"containers\":[{\"image\":\"cave:1\"}]},\"status\":{\"podIP\":\"10.80.32.5\"}}]")
                      nil
                      (objects "[{\"metadata\":{\"namespace\":\"cave\",\"name\":\"cave\"},
                                 \"spec\":{\"clusterIP\":\"10.96.0.26\",\"selector\":{\"app\":\"cave\"},
                                          \"ports\":[{\"name\":\"http\",\"port\":8080,\"targetPort\":8080}]}}]")
                      (objects "[{\"metadata\":{\"name\":\"gvision\"},\"spec\":{\"podCIDR\":\"10.80.0.0/20\"},
                                 \"status\":{\"addresses\":[{\"type\":\"InternalIP\",\"address\":\"10.77.77.21\"}]}},
                                {\"metadata\":{\"name\":\"gr8s-local\"},\"spec\":{\"podCIDR\":\"10.80.32.0/20\"},
                                 \"status\":{\"addresses\":[{\"type\":\"InternalIP\",\"address\":\"10.77.77.10\"}]}}]")
                      (objects "[{\"metadata\":{\"namespace\":\"cave\",\"name\":\"cave\"},
                                 \"spec\":{\"parentRefs\":[{\"name\":\"labdroid\",\"namespace\":\"gateway\"}],
                                          \"rules\":[{\"backendRefs\":[{\"name\":\"cave\",\"port\":8080}]}]}}]")))))
    (setf (gr8s.server::network-graph-topology graph) topology)
    (flet ((note (&rest pairs)
             (let ((flow (gr8s.resources::core-object "time" "2026-11-25T12:00:00Z" "verdict" "FORWARDED" "protocol" "TCP")))
               (loop for (key value) on pairs by #'cddr do (setf (gethash key flow) value))
               (gr8s.server::network-graph-note-flow graph flow)))
           (edge (source target)
             (find-if (lambda (e) (and (equal source (gethash "source" e)) (equal target (gethash "target" e))))
                      (coerce (gethash "edges" (gr8s.server::network-graph-object graph (encode-universal-time 30 0 12 25 11 2026 0))) 'list))))
      ;; The Gateway's record of a request from the laptop, which failed upstream.
      (note "direction" "ingress" "peerAddress" "10.77.77.10" "namespace" "cave" "service" "cave"
            "l7" (gr8s.resources::core-object "method" "GET" "path" "/" "code" 502 "latencyNs" 3000000
                                              "listenerPort" 443 "route" "cave/cave"))
      ;; The same request arriving at cave-0, from gvision's host across the overlay.
      (note "direction" "ingress" "namespace" "cave" "pod" "cave-0" "podPort" 8080 "peerAddress" "10.80.0.0" "peerPort" 40000)
      ;; gvision's host on another port of cave-0: the node itself, not the Gateway.
      (note "direction" "ingress" "namespace" "cave" "pod" "cave-0" "podPort" 9090 "peerAddress" "10.80.0.0" "peerPort" 40001)
      (let ((in (edge "Clients/LAN clients" "gateway/Gateway/labdroid")))
        (is (not (null in)) "LAN clients -> Gateway, from the request record, though the laptop is also a node")
        (is (equalp #("443/TCP") (gethash "ports" in)))
        (is (= 1 (gethash "errors" (gethash "m1" in))))
        (is (= 3 (gethash "latencyMs" in))))
      (note "direction" "ingress" "peerAddress" "140.82.112.3" "namespace" "cave" "service" "cave"
            "l7" (gr8s.resources::core-object "method" "GET" "path" "/" "code" 200 "latencyNs" 1000000
                                              "listenerPort" 443 "route" "cave/cave"))
      (is (edge "World/world" "gateway/Gateway/labdroid") "an internet client is the world")
      (is (edge "gateway/Gateway/labdroid" "cave/StatefulSet/cave") "Gateway -> backend, not gvision -> backend")
      (is (null (edge "Node/gvision" "cave/StatefulSet/cave-8080"))
          "no stray node edge")
      (is (edge "Node/gvision" "cave/StatefulSet/cave") "the node's own traffic to another port stays the node's")
      (let ((gateway (find "gateway/Gateway/labdroid" (coerce (gethash "nodes" (gr8s.server::network-graph-object graph)) 'list)
                           :key (lambda (n) (gethash "id" n)) :test #'equal)))
        (is (equal "lucide-door-open" (gethash "icon" gateway)))))))

(test network-graph-explains-an-edges-connections-under-policy
  ;; podster-5hv.3: an edge's connections, explained by the policies the dataplane reads,
  ;; and a workload's card names the policies that isolate it.
  (flet ((objects (text) (coerce (com.inuoe.jzon:parse text) 'list)))
    (let* ((topology (gr8s.server::build-network-topology
                      (objects "[{\"metadata\":{\"namespace\":\"cave\",\"name\":\"cave-0\",\"labels\":{\"app\":\"cave\"},
                                   \"ownerReferences\":[{\"kind\":\"StatefulSet\",\"name\":\"cave\"}]},
                                  \"spec\":{\"containers\":[]},\"status\":{\"podIP\":\"10.80.0.5\"}},
                                 {\"metadata\":{\"namespace\":\"cave\",\"name\":\"lonely\",\"labels\":{\"app\":\"lonely\"}},
                                  \"spec\":{\"containers\":[]},\"status\":{\"podIP\":\"10.80.0.9\"}}]")
                      '() '() '() '()
                      (objects "[{\"metadata\":{\"namespace\":\"cave\",\"name\":\"cave\"},
                                  \"spec\":{\"podSelector\":{\"matchLabels\":{\"app\":\"cave\"}},
                                            \"ingress\":[{\"ports\":[{\"port\":8080}]}]}},
                                 {\"metadata\":{\"namespace\":\"cave\",\"name\":\"bad\"},
                                  \"spec\":{\"podSelector\":{},\"ingress\":[{\"ports\":[{\"protocol\":\"BOGUS\"}]}]}}]")
                      (objects "[{\"metadata\":{\"name\":\"cave\",\"labels\":{\"kubernetes.io/metadata.name\":\"cave\"}}}]")))
           (graph (gr8s.server::make-network-graph)))
      (is (= 1 (length (gr8s.server::network-topology-policies topology))) "an unparsable policy is skipped")
      (setf (gr8s.server::network-graph-topology graph) topology)
      (dolist (port '(5432 5432 8080))
        (gr8s.server::network-graph-note-flow
         graph (network-test-flow "pod" "lonely" "peerPod" "cave-0" "peerNamespace" "cave"
                                  "peerAddress" "10.80.0.5" "peerPort" port
                                  "verdict" (if (= port 5432) "DROPPED" "FORWARDED"))))
      (let* ((object (gr8s.server::network-graph-object graph))
             (edge (gethash "id" (aref (gethash "edges" object) 0)))
             (explained (gr8s.server::network-graph-edge-explanation graph edge)))
        (flet ((node (name) (find name (gethash "nodes" object) :key (lambda (node) (gethash "name" node)) :test #'equal)))
          (is (equalp #("cave/cave") (gethash "ingress" (gethash "isolation" (node "cave")))))
          (is (equalp #() (gethash "ingress" (gethash "isolation" (node "lonely"))))))
        ;; Two distinct connections: 5432 (twice, dropped) and 8080.
        (is (= 2 (length explained)))
        (let ((denied (find 5432 explained :key (lambda (entry) (gethash "port" entry))))
              (allowed (find 8080 explained :key (lambda (entry) (gethash "port" entry)))))
          (is (equal "cave/lonely" (gethash "source" denied)))
          (is (equal "cave/cave-0" (gethash "destination" denied)))
          (is (= 2 (gethash "dropped" denied)))
          (let ((explanation (gethash "explanation" denied)))
            (is (equal "denied" (gethash "verdict" explanation)))
            (is (search "app: lonely" (gethash "suggestion" (gethash "ingress" explanation)))))
          (is (equal "allowed" (gethash "verdict" (gethash "explanation" allowed))))
          (is (= 1 (gethash "rule" (aref (gethash "allowedBy" (gethash "ingress" (gethash "explanation" allowed))) 0))))))
      (is (null (gr8s.server::network-graph-edge-explanation graph "no-such-edge")))
      ;; A drop the dataplane made for another reason than policy says so, with no verdict.
      (gr8s.server::network-graph-note-flow
       graph (network-test-flow "pod" "lonely" "peerPod" "cave-0" "peerNamespace" "cave" "peerAddress" "10.80.0.5"
                                "peerPort" 8080 "verdict" "DROPPED" "reason" "spoof"))
      (let* ((edge (gethash "id" (aref (gethash "edges" (gr8s.server::network-graph-object graph)) 0)))
             (spoofed (find "spoof" (gr8s.server::network-graph-edge-explanation graph edge)
                            :key (lambda (entry) (gethash "dropReason" entry)) :test #'equal)))
        (is (= 1 (gethash "dropped" spoofed)))
        (is (eq 'null (gethash "explanation" spoofed)))))))

(test network-health-maps-the-doctors-problems-onto-the-map
  ;; podster-5hv.4: a problem marks the nodes it is about, its Pods as their workloads, and
  ;; the nodes it holds up; drops, which the map draws already, are left out.
  (let* ((topology (network-test-topology))
         (report (com.inuoe.jzon:parse
                  "{\"problems\":[
                     {\"rule\":\"crash-loop\",\"title\":\"Pod cave-runner-b4-x keeps restarting\",
                      \"resources\":[\"Pod/cave/cave-runner-b4-x\"],\"owner\":\"Deployment/cave/cave-runner\",
                      \"impact\":[{\"target\":\"Service/cave/cave\",\"certain\":true},
                                  {\"target\":\"Pod/cave/cave-runner-b4-x\",\"certain\":true}]},
                     {\"rule\":\"node-not-ready\",\"title\":\"Node gvision is not ready\",
                      \"resources\":[\"Node/gvision\"],\"owner\":false,\"impact\":[]},
                     {\"rule\":\"network-policy-drops\",\"title\":\"drops\",
                      \"resources\":[\"Pod/cave/cave-pg-0\"],\"owner\":\"StatefulSet/cave/cave-pg\",\"impact\":[]}]}"))
         (problems (gr8s.server::network-health-problems topology report))
         (summaries (gr8s.server::network-health-summaries problems)))
    (is (= 2 (length problems)) "drops are left to the edges")
    (is (equalp #("cave/Deployment/cave-runner") (gethash "nodes" (first problems))) "a Pod is drawn as its workload")
    (is (equalp #("cave/Service/cave") (gethash "affectedNodes" (first problems))) "the problem's own node isn't also affected")
    (is (equalp #("Node/gvision") (gethash "nodes" (second problems))))
    (let ((runner (gethash "cave/Deployment/cave-runner" summaries))
          (service (gethash "cave/Service/cave" summaries)))
      (is (= 1 (gethash "problems" runner)))
      (is (equal "Pod cave-runner-b4-x keeps restarting" (gethash "title" runner)))
      (is (= 0 (gethash "problems" service)))
      (is (= 1 (gethash "affectedBy" service))))
    (is (null (gethash "cave/StatefulSet/cave-pg" summaries))))
  (is (equal "Node/gvision" (gr8s.server::network-target-node-id (gr8s.server::make-network-topology) "Node/gvision"))))

(test network-graph-names-outside-peers-by-dns
  ;; podster-5hv.8: a peer outside the cluster is drawn as the name a Pod looked up.
  (let ((graph (gr8s.server::make-network-graph)))
    (setf (gr8s.server::network-graph-topology graph) (network-test-topology))
    (gr8s.server::network-graph-note-flow graph (network-test-flow "peerAddress" "192.0.73.2" "peerPort" 443
                                                                   "peerName" "secure.gravatar.com"))
    (gr8s.server::network-graph-note-flow graph (network-test-flow "peerAddress" "203.0.113.9" "peerPort" 443))
    (gr8s.server::network-graph-note-flow graph (network-test-flow "peerAddress" "192.168.1.10" "peerPort" 8080
                                                                   "peerName" "h3.labdroid.net"))
    (let ((names (map 'list (lambda (node) (list (gethash "kind" node) (gethash "name" node)))
                      (gethash "nodes" (gr8s.server::network-graph-object graph)))))
      (is (member '("World" "secure.gravatar.com") names :test #'equal))
      (is (member '("World" "world") names :test #'equal) "an address no Pod looked up stays the world")
      (is (member '("External" "h3.labdroid.net") names :test #'equal))))
  (is (equal "secure.gravatar.com (192.0.73.2)"
             (gr8s.server::network-end-name '(:address "192.0.73.2")
                                            (gr8s.resources::core-object "peerAddress" "192.0.73.2"
                                                                         "peerName" "secure.gravatar.com")))))

(test network-graph-lists-a-gateway-request-on-its-backend-edge
  ;; podster-krg.3: a slow backend's edge has the requests the Gateway sent it, and their
  ;; traces, though the request was counted on the client's edge.
  (let* ((graph (gr8s.server::make-network-graph))
         (topology (flet ((objects (text) (coerce (com.inuoe.jzon:parse text) 'list)))
                     (gr8s.server::build-network-topology
                      (objects "[{\"metadata\":{\"namespace\":\"cave\",\"name\":\"cave-0\",\"labels\":{\"app\":\"cave\"},
                                 \"ownerReferences\":[{\"kind\":\"StatefulSet\",\"name\":\"cave\"}]},
                                 \"spec\":{\"containers\":[{\"image\":\"cave:1\"}]},\"status\":{\"podIP\":\"10.80.32.5\"}}]")
                      nil
                      (objects "[{\"metadata\":{\"namespace\":\"cave\",\"name\":\"cave\"},
                                 \"spec\":{\"clusterIP\":\"10.96.0.26\",\"selector\":{\"app\":\"cave\"},
                                          \"ports\":[{\"name\":\"http\",\"port\":8080,\"targetPort\":8080}]}}]")
                      (objects "[{\"metadata\":{\"name\":\"gvision\"},\"spec\":{\"podCIDR\":\"10.80.0.0/20\"},
                                 \"status\":{\"addresses\":[{\"type\":\"InternalIP\",\"address\":\"10.77.77.21\"}]}},
                                {\"metadata\":{\"name\":\"gr8s-local\"},\"spec\":{\"podCIDR\":\"10.80.32.0/20\"},
                                 \"status\":{\"addresses\":[{\"type\":\"InternalIP\",\"address\":\"10.77.77.10\"}]}}]")
                      (objects "[{\"metadata\":{\"namespace\":\"cave\",\"name\":\"cave\"},
                                 \"spec\":{\"parentRefs\":[{\"name\":\"labdroid\",\"namespace\":\"gateway\"}],
                                          \"rules\":[{\"backendRefs\":[{\"name\":\"cave\",\"port\":8080}]}]}}]")))))
    (setf (gr8s.server::network-graph-topology graph) topology)
    (flet ((note (&rest pairs)
             (let ((flow (gr8s.resources::core-object "time" "2026-11-25T12:00:00Z" "verdict" "FORWARDED" "protocol" "TCP")))
               (loop for (key value) on pairs by #'cddr do (setf (gethash key flow) value))
               (gr8s.server::network-graph-note-flow graph flow)))
           (edge (source target)
             (find-if (lambda (e) (and (equal source (gethash "source" e)) (equal target (gethash "target" e))))
                      (coerce (gethash "edges" (gr8s.server::network-graph-object graph (encode-universal-time 30 0 12 25 11 2026 0))) 'list))))
      ;; The Gateway's own connection to cave-0 draws Gateway -> cave.
      (note "direction" "ingress" "namespace" "cave" "pod" "cave-0" "podPort" 8080 "peerAddress" "10.80.0.0" "peerPort" 40000)
      (let ((before (gethash "flows" (gethash "m1" (edge "gateway/Gateway/labdroid" "cave/StatefulSet/cave")))))
        ;; A traced request the Gateway sent to cave-0.
        (note "direction" "ingress" "peerAddress" "10.77.77.10" "namespace" "cave" "service" "cave"
              "podAddress" "10.80.32.5" "podPort" 8080
              "l7" (gr8s.resources::core-object "method" "GET" "path" "/slow" "code" 200 "latencyNs" 742000000
                                                "listenerPort" 443 "route" "cave/cave"
                                                "traceId" "5da861bf3c5419a485b367745c0597f6"))
        (let* ((backend (edge "gateway/Gateway/labdroid" "cave/StatefulSet/cave"))
               (flows (gr8s.server::network-graph-edge-flows graph (gethash "id" backend))))
          (is (= before (gethash "flows" (gethash "m1" backend))) "not counted twice")
          (is (= 742 (gethash "latencyMs" backend)) "the backend's edge has the request's latency")
          (is (find "5da861bf3c5419a485b367745c0597f6" flows
                    :key (lambda (f) (let ((l7 (gethash "l7" f))) (and (hash-table-p l7) (gethash "traceId" l7))))
                    :test #'equal)))
        (is (= 1 (gethash "flows" (gethash "m1" (edge "Clients/LAN clients" "gateway/Gateway/labdroid"))))
            "counted once, on the client's edge")))))

(test a-second-dashboard-points-at-the-one-already-running
  ;; `gr8s dashboard' on a port a dashboard already serves names that dashboard's URL
  ;; instead of failing on ADDRESS-IN-USE; another program's port is named as such.
  (let* ((directory (uiop:ensure-directory-pathname
                     (sb-posix:mkdtemp (namestring (merge-pathnames "gr8s-runtime-XXXXXX" (uiop:temporary-directory))))))
         (saved (uiop:getenv "XDG_RUNTIME_DIR"))
         (kubeconfig (merge-pathnames "kc.yaml" directory)))
    (unwind-protect
         (progn
           (sb-posix:setenv "XDG_RUNTIME_DIR" (namestring directory) 1)
           (with-open-file (out kubeconfig :direction :output) (write-string "x" out))
           (is (null (gr8s.server::running-dashboard-session 18555)) "no record, nothing running")
           (gr8s.server::record-dashboard-session 18555 "http://127.0.0.1:18555/ui/tok/" kubeconfig)
           (let ((file (gr8s.server::dashboard-session-file 18555)))
             (is (= #o600 (logand #o777 (sb-posix:stat-mode (sb-posix:stat (namestring file))))) "private to this user"))
           (is (equal "http://127.0.0.1:18555/ui/tok/"
                      (gethash "url" (gr8s.server::running-dashboard-session 18555))))
           (is (null (gr8s.server::running-dashboard-session 18556)) "a record is for its own port")
           (let ((text (with-output-to-string (*standard-output*)
                         (is (= 0 (gr8s.server::report-dashboard-port-in-use 18555 '(:no-launch t) kubeconfig))))))
             (is (search "gr8s dashboard is already running at http://127.0.0.1:18555/ui/tok/" text))
             (is (null (search "--port" text)) "same kubeconfig: no advice"))
           (let ((text (with-output-to-string (*standard-output*)
                         (gr8s.server::report-dashboard-port-in-use 18555 '(:no-launch t) "/elsewhere/kc.yaml"))))
             (is (search "start another with --port" text) "another cluster's dashboard"))
           ;; A record whose process is gone is no dashboard: the port is another program's.
           (let ((file (gr8s.server::dashboard-session-file 18555)))
             (with-open-file (out file :direction :output :if-exists :supersede)
               (write-string "{\"pid\":999999999,\"port\":18555,\"url\":\"http://x/\",\"kubeconfig\":\"k\"}" out)))
           (is (null (gr8s.server::running-dashboard-session 18555)))
           (let ((*error-output* (make-broadcast-stream)))
             (is (= 1 (gr8s.server::report-dashboard-port-in-use 18555 '(:no-launch t) kubeconfig))))
           ;; Leaving removes the record, but only one this process wrote.
           (gr8s.server::forget-dashboard-session 18555)
           (is (probe-file (gr8s.server::dashboard-session-file 18555)) "another process's record stays")
           (gr8s.server::record-dashboard-session 18555 "http://127.0.0.1:18555/ui/tok/" kubeconfig)
           (gr8s.server::forget-dashboard-session 18555)
           (is (null (probe-file (gr8s.server::dashboard-session-file 18555)))))
      (if saved (sb-posix:setenv "XDG_RUNTIME_DIR" saved 1) (sb-posix:unsetenv "XDG_RUNTIME_DIR"))
      (uiop:delete-directory-tree directory :validate t))))

(test network-graph-draws-proxied-egress-by-name
  ;; A captured Pod's connections are reported by the egress proxy under the name
  ;; they went to; its packets to the proxy address draw nothing (podster-wv1w.6).
  (let ((graph (gr8s.server::make-network-graph))
        (now (encode-universal-time 30 0 12 25 11 2026 0)))
    (setf (gr8s.server::network-graph-topology graph) (network-test-topology))
    (flet ((note (flow) (gr8s.server::network-graph-note-flow graph flow))
           (edge (source target)
             (find-if (lambda (e) (and (equal source (gethash "source" e)) (equal target (gethash "target" e))))
                      (coerce (gethash "edges" (gr8s.server::network-graph-object graph now)) 'list))))
      (note (network-test-flow "peerAddress" "169.254.1.2" "peerPort" 443))
      (is (zerop (length (gethash "edges" (gr8s.server::network-graph-object graph now)))))
      (let ((request (gr8s.controllers::egress-request-flow-object
                      "10.80.16.4" "api.anthropic.com" "160.79.104.10" 443 "POST" "/v1/messages?beta=true" 200
                      "gr8/claude-anthropic/anthropic-api-key"))
            (refused (gr8s.controllers::egress-flow-object
                      "10.80.16.4" "evil.example.com" "203.0.113.5" 443 nil nil)))
        (dolist (flow (list request refused))
          (setf (gethash "time" flow) "2026-11-25T12:00:00Z" (gethash "namespace" flow) "cave"
                (gethash "pod" flow) "cave-runner-b4-x")
          (note flow))
        (is (equal "/v1/messages" (gethash "path" (gethash "l7" request))) "no query string")
        (is (equal "gr8/claude-anthropic/anthropic-api-key" (gethash "injected" (gethash "l7" request))))
        (is (= 1 (gethash "flows" (gethash "m1" (edge "cave/Deployment/cave-runner" "World/api.anthropic.com")))))
        (is (= 1 (gethash "dropped" (gethash "m1" (edge "cave/Deployment/cave-runner" "World/evil.example.com"))))))
      ;; A refused lookup is drawn to the site it names, though no connection follows.
      (let ((lookup (gr8s.controllers::egress-dns-flow-object "10.80.16.4" "exfil.example" nil)))
        (setf (gethash "time" lookup) "2026-11-25T12:00:00Z" (gethash "namespace" lookup) "cave"
              (gethash "pod" lookup) "cave-runner-b4-x")
        (note lookup)
        (is (= 1 (gethash "dropped" (gethash "m1" (edge "cave/Deployment/cave-runner" "World/exfil.example")))))
        ;; A lookup, not a connection to the site's port 53.
        (is (equalp #("DNS") (gethash "ports" (edge "cave/Deployment/cave-runner" "World/exfil.example"))))))))

(test network-explains-egress-proxy-decisions-by-name
  (let ((refused (gr8s.server::network-egress-proxy-explanation
                  (gr8s.controllers::egress-dns-flow-object "10.80.16.4" "www.youtube.com" nil)))
        (admitted (gr8s.server::network-egress-proxy-explanation
                   (gr8s.controllers::egress-flow-object "10.80.16.4" "api.github.com" "140.82.112.5" 443 t
                                                         "gr8-allow"))))
    (is (equal "DNS" (gethash "label" refused)))
    (is (equal "denied" (gethash "verdict" refused)))
    (is (search "refused the lookup of www.youtube.com" (gethash "text" refused)))
    (is (equal "443/TCP" (gethash "label" admitted)))
    (is (equal "allowed" (gethash "verdict" admitted)))
    (is (search "admitted the connection to api.github.com by name (rule gr8-allow)"
                (gethash "text" admitted))))
  (is (null (gr8s.server::network-egress-proxy-explanation
             (gr8s.resources::core-object "verdict" "DROPPED" "protocol" "TCP")))))
