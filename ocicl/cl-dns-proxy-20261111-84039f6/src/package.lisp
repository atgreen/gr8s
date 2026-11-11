;;;; SPDX-FileCopyrightText: 2026 Anthony Green <green@moxielogic.com>
;;;; SPDX-License-Identifier: MIT

(defpackage #:cl-dns-proxy
  (:use #:cl)
  (:export
   #:answer-dns-query
   #:cached-dns-forward
   #:call-with-dns-server
   #:dns-forward-cache
   #:dns-metrics
   #:dns-metrics-text
   #:dns-response-code
   #:dns-server
   #:dns-server-port
   #:dns-upstreams-for-packet
   #:forward-dns-tcp
   #:forward-dns-udp
   #:host-dns-upstreams
   #:make-dns-forward-cache
   #:make-dns-metrics
   #:parse-resolv-conf-upstreams
   #:start-dns-server
   #:stop-dns-server))
