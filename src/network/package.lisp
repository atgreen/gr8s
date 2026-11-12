;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Package boundary for CNI and the node networking dataplane.

(defpackage #:gr8s.network
  (:use #:cl)
  (:export #:validate-network-policy-spec))

(eval-when (:compile-toplevel :load-toplevel :execute)
  (let ((network (find-package '#:gr8s.network))
        (composition (find-package '#:gr8s)))
    ;; Bootstrap code validates the default NetworkPolicy before this module is
    ;; loaded.  Establish that forward reference with the symbol this package
    ;; will define.
    (let ((symbol (find-symbol "VALIDATE-NETWORK-POLICY-SPEC" network)))
      (shadowing-import symbol composition))))

;;; The rtnetlink dataplane primitives -- the Linux UAPI wire codec, the private
;;; per-thread socket transaction, and the link/address/route/neighbor
;;; operations built on them -- now live in the standalone cl-rtnetlink library
;;; (installed via ocicl).  gr8s keeps its own node-gateway, routed-veth, link
;;; ownership and forwarding helpers (in network/rtnetlink.lisp) layered over
;;; those primitives, and several network files (wireguard, vxlan, routed-cni,
;;; node-ipam, ...) call the primitives directly, so we re-home the library's
;;; public API -- plus the two internals gr8s still calls, FAIL-RTNETLINK and
;;; NETLINK-NEIGHBOR-MESSAGE -- into gr8s.network and the composition package
;;; here, before any network file that references them.
(eval-when (:compile-toplevel :load-toplevel :execute)
  (let ((symbols (mapcar (lambda (name)
                           (or (find-symbol name '#:cl-rtnetlink)
                               (error "cl-rtnetlink does not provide ~A, which gr8s requires." name)))
                         '("RTNETLINK-ERROR" "RTNETLINK-ERROR-ERRNO" "RTNETLINK-ERROR-MESSAGE"
                           "RTNETLINK-PROTOCOL-ERROR"
                           "NETLINK-OCTETS" "NETLINK-INTEGER" "NETLINK-READ-INTEGER" "NETLINK-ALIGN"
                           "NETLINK-STRING" "NETLINK-ATTRIBUTE" "NETLINK-MESSAGE" "NETLINK-ATTRIBUTES"
                           "NETLINK-INTERFACE-MESSAGE" "NETLINK-NEIGHBOR-MESSAGE"
                           "PARSE-NETLINK-REPLY" "CALL-RTNETLINK" "FAIL-RTNETLINK"
                           "INTERFACE-INDEX" "VALIDATE-NETWORK-INTERFACE-NAME"
                           "NETWORK-LINK-ATTRIBUTES" "NETWORK-LINK-ATTRIBUTES-BY-INDEX"
                           "NETWORK-OCTETS-INTEGER" "NETWORK-PREFIX-OCTETS-INTEGER"
                           "SET-NETWORK-LINK-MTU" "SET-NETWORK-LINK-UP" "DELETE-NETWORK-LINK"
                           "IPV4-NETWORK-OCTETS" "NETWORK-ADDRESS-WIRE-VALUES"
                           "ADD-NETWORK-ADDRESS" "REMOVE-NETWORK-ADDRESS" "NETWORK-ADDRESS-PRESENT-P"
                           "REPLACE-NETWORK-ROUTE" "REMOVE-NETWORK-ROUTE" "NETWORK-ROUTE-PRESENT-P"
                           "REPLACE-PERMANENT-NETWORK-NEIGHBOR" "PERMANENT-NETWORK-NEIGHBOR-P"))))
    (shadowing-import symbols '#:gr8s.network)
    (export symbols '#:gr8s.network)
    (shadowing-import symbols '#:gr8s)))

;;; The WireGuard overlay path model -- per-endpoint observations, passive
;;; telemetry folding, MTU black-hole discovery, path health/score and the
;;; trial-gated selection of a next hop -- now lives in the standalone
;;; cl-wireguard-overlay library (installed via ocicl).  gr8s keeps its own
;;; persistence (object <-> struct) and route-endpoint helpers layered over the
;;; library structs, so we re-home the library's path API -- structs, their
;;; constructors and every slot accessor the serialization reads -- into
;;; gr8s.network and the composition package here, before any network file that
;;; references them.
(eval-when (:compile-toplevel :load-toplevel :execute)
  (let ((symbols (mapcar (lambda (name)
                           (or (find-symbol name '#:cl-wireguard-overlay)
                               (error "cl-wireguard-overlay does not provide ~A, which gr8s requires." name)))
                         (list
                          "APPLY-WIREGUARD-PATH-TELEMETRY"
                          "COPY-WIREGUARD-PATH-OBSERVATION"
                          "COPY-WIREGUARD-PATH-STATE"
                          "COPY-WIREGUARD-PATH-TELEMETRY"
                          "COPY-WIREGUARD-PEER-PATH-STATE"
                          "DISCOVER-WIREGUARD-PATH-MTU"
                          "MAKE-WIREGUARD-PATH-OBSERVATION"
                          "MAKE-WIREGUARD-PATH-STATE"
                          "MAKE-WIREGUARD-PATH-TELEMETRY"
                          "MAKE-WIREGUARD-PEER-PATH-STATE"
                          "SELECT-WIREGUARD-PATH"
                          "UPDATE-WIREGUARD-PATH-MTU"
                          "WIREGUARD-PATH-HEALTHY-P"
                          "WIREGUARD-PATH-LESS-P"
                          "WIREGUARD-PATH-OBSERVATION"
                          "WIREGUARD-PATH-OBSERVATION-ADDRESS"
                          "WIREGUARD-PATH-OBSERVATION-CONSECUTIVE-FAILURES"
                          "WIREGUARD-PATH-OBSERVATION-CONSECUTIVE-SUCCESSES"
                          "WIREGUARD-PATH-OBSERVATION-HANDSHAKE-AGE-SECONDS"
                          "WIREGUARD-PATH-OBSERVATION-LAST-MTU-PROBE-AT"
                          "WIREGUARD-PATH-OBSERVATION-LATEST-HANDSHAKE-SECONDS"
                          "WIREGUARD-PATH-OBSERVATION-MTU-CHANGED-AT"
                          "WIREGUARD-PATH-OBSERVATION-MTU-REASON"
                          "WIREGUARD-PATH-OBSERVATION-MTU-UPGRADE-CANDIDATE"
                          "WIREGUARD-PATH-OBSERVATION-MTU-UPGRADE-SUCCESSES"
                          "WIREGUARD-PATH-OBSERVATION-NAME"
                          "WIREGUARD-PATH-OBSERVATION-P"
                          "WIREGUARD-PATH-OBSERVATION-PASSIVE-ACTIVE-FLOWS"
                          "WIREGUARD-PATH-OBSERVATION-PASSIVE-BYTES-PER-SECOND"
                          "WIREGUARD-PATH-OBSERVATION-PASSIVE-CONGESTION-WINDOW"
                          "WIREGUARD-PATH-OBSERVATION-PASSIVE-RETRANSMITS"
                          "WIREGUARD-PATH-OBSERVATION-PASSIVE-RTT-MICROSECONDS"
                          "WIREGUARD-PATH-OBSERVATION-PASSIVE-TCP-SAMPLES"
                          "WIREGUARD-PATH-OBSERVATION-PORT"
                          "WIREGUARD-PATH-OBSERVATION-SAFE-MTU"
                          "WIREGUARD-PATH-OBSERVATION-TRANSFERRED-BYTES-DELTA"
                          "WIREGUARD-PATH-OBSERVATION-TRANSFERRED-BYTES-TOTAL"
                          "WIREGUARD-PATH-OBSERVATION-TRIAL-LATENCY-MILLISECONDS"
                          "WIREGUARD-PATH-SCORE"
                          "WIREGUARD-PATH-STATE"
                          "WIREGUARD-PATH-STATE-HISTORY"
                          "WIREGUARD-PATH-STATE-P"
                          "WIREGUARD-PATH-STATE-PEERS"
                          "WIREGUARD-PATH-TELEMETRY"
                          "WIREGUARD-PATH-TELEMETRY-ACTIVE-FLOWS"
                          "WIREGUARD-PATH-TELEMETRY-BYTES"
                          "WIREGUARD-PATH-TELEMETRY-CONGESTION-WINDOW"
                          "WIREGUARD-PATH-TELEMETRY-INTERVAL-MILLISECONDS"
                          "WIREGUARD-PATH-TELEMETRY-P"
                          "WIREGUARD-PATH-TELEMETRY-RETRANSMITS"
                          "WIREGUARD-PATH-TELEMETRY-RTT-MICROSECONDS"
                          "WIREGUARD-PATH-TELEMETRY-TCP-SAMPLES"
                          "WIREGUARD-PATH-TRIAL-ALLOWED-P"
                          "WIREGUARD-PEER-PATH-STATE"
                          "WIREGUARD-PEER-PATH-STATE-CHANGED-AT"
                          "WIREGUARD-PEER-PATH-STATE-LAST-TRIAL-AT"
                          "WIREGUARD-PEER-PATH-STATE-OBSERVATIONS"
                          "WIREGUARD-PEER-PATH-STATE-P"
                          "WIREGUARD-PEER-PATH-STATE-PEER-ID"
                          "WIREGUARD-PEER-PATH-STATE-PREVIOUS"
                          "WIREGUARD-PEER-PATH-STATE-REASON"
                          "WIREGUARD-PEER-PATH-STATE-SELECTED"
))))
    (shadowing-import symbols '#:gr8s.network)
    (export symbols '#:gr8s.network)
    (shadowing-import symbols '#:gr8s)))
