;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Whistler source forms for passive, per-remote-Pod TCP path telemetry.

(in-package #:whistler)

(defparameter gr8s.network::*wireguard-path-telemetry-map-forms*
  '((defmap gr8s-path-tcp-v4 :type :lru-hash
      :key-size 4 :value-size 48 :max-entries 4096)
    (defmap gr8s-path-flows-v4 :type :lru-hash
      :key-size 8 :value-size 16 :max-entries 65536)))

(defun gr8s.network::wireguard-path-telemetry-program-forms
    (probe-offsets retransmit-offsets)
  "Build target-kernel-specialized Whistler forms from tracepoint OFFSETS."
  (flet ((at (name offsets)
           (or (getf offsets name)
               (error "Missing ~S WireGuard telemetry tracepoint field" name)))
         (ipv4-at (offset)
           ;; Tracepoint byte arrays are not guaranteed to be naturally aligned.
           ;; Assemble the host-order scalar whose little-endian stack image is
           ;; the original network-order address, so it remains a valid map key.
           `(logior (ctx-load u8 ,offset)
                    (logior (<< (ctx-load u8 ,(+ offset 1)) 8)
                            (logior (<< (ctx-load u8 ,(+ offset 2)) 16)
                                    (<< (ctx-load u8 ,(+ offset 3)) 24))))))
    (let ((destination (at :destination probe-offsets))
          (family (at :family probe-offsets))
          (bytes (at :bytes probe-offsets))
          (cwnd (at :cwnd probe-offsets))
          (ssthresh (at :ssthresh probe-offsets))
          (rtt (at :rtt probe-offsets))
          (cookie (at :cookie probe-offsets))
          (retransmit-destination (at :destination retransmit-offsets))
          (retransmit-family (at :family retransmit-offsets)))
      `((defstruct gr8s-path-tcp-value
          (bytes u64) (samples u64) (rtt-sum u64) (retransmits u64)
          (cwnd u32) (ssthresh u32) (last-nanoseconds u64))
        (defstruct gr8s-path-flow-value
          (destination u32) (padding u32) (last-nanoseconds u64))
        (defstruct gr8s-path-ipv4-key (destination u32))
        (defstruct gr8s-path-cookie-key (cookie u64))
        (defprog gr8s-path-tcp-sample
            (:type :tracepoint :section "tracepoint/tcp/tcp_probe" :license "GPL")
          (let* ((destination u32 ,(ipv4-at destination))
                 (cookie u64 (ctx-load u64 ,cookie))
                 (destination-key (make-gr8s-path-ipv4-key))
                 (cookie-key (make-gr8s-path-cookie-key)))
            (setf (gr8s-path-ipv4-key-destination destination-key) destination
                  (gr8s-path-cookie-key-cookie cookie-key) cookie)
            (when (and (= (ctx-load u16 ,family) 2) (> destination 0))
              (unless (map-lookup-ptr gr8s-path-tcp-v4 destination-key)
                (let ((initial (make-gr8s-path-tcp-value)))
                  (map-update-ptr gr8s-path-tcp-v4 destination-key initial 0)))
              (when-let ((stats (map-lookup-ptr gr8s-path-tcp-v4 destination-key)))
                (atomic-add stats 0 (ctx-load u16 ,bytes))
                (atomic-add stats 8 1)
                (atomic-add stats 16 (ctx-load u32 ,rtt))
                (store u32 stats 32 (ctx-load u32 ,cwnd))
                (store u32 stats 36 (ctx-load u32 ,ssthresh))
                (store u64 stats 40 (ktime-get-ns)))
              (when (> cookie 0)
                (let ((flow (make-gr8s-path-flow-value)))
                  (setf (gr8s-path-flow-value-destination flow) destination
                        (gr8s-path-flow-value-last-nanoseconds flow) (ktime-get-ns))
                  (map-update-ptr gr8s-path-flows-v4 cookie-key flow 0)))))
          0)
        (defprog gr8s-path-tcp-retransmit
            (:type :tracepoint :section "tracepoint/tcp/tcp_retransmit_skb" :license "GPL")
          (let ((destination u32 ,(ipv4-at retransmit-destination))
                (destination-key (make-gr8s-path-ipv4-key)))
            (when (= (ctx-load u16 ,retransmit-family) 2)
              (setf (gr8s-path-ipv4-key-destination destination-key) destination)
              (when-let ((stats (map-lookup-ptr gr8s-path-tcp-v4 destination-key)))
                (atomic-add stats 24 1))))
          0)))))
