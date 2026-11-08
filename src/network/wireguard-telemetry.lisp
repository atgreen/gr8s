;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Runtime-specialized JIT compilation for passive WireGuard path telemetry.

(in-package #:gr8s.network)

(defvar *wireguard-path-telemetry-map-forms* nil)

(defstruct (wireguard-path-telemetry-dataplane
            (:constructor %make-wireguard-path-telemetry-dataplane))
  "Loaded passive path telemetry programs and their bounded maps."
  maps programs attachments
  (previous (make-hash-table :test #'equal)))

(defun stop-wireguard-path-telemetry-dataplane
    (dataplane &key (detach #'whistler/loader:detach)
                    (close #'sb-posix:close))
  "Detach DATAPLANE and close every program and map descriptor. Idempotent."
  (dolist (attachment (wireguard-path-telemetry-dataplane-attachments dataplane))
    (ignore-errors (funcall detach attachment)))
  (setf (wireguard-path-telemetry-dataplane-attachments dataplane) nil)
  (dolist (entry (wireguard-path-telemetry-dataplane-programs dataplane))
    (let ((fd (whistler/loader:prog-info-fd (cdr entry))))
      (when (and (integerp fd) (plusp fd)) (ignore-errors (funcall close fd)))))
  (setf (wireguard-path-telemetry-dataplane-programs dataplane) nil)
  (dolist (entry (wireguard-path-telemetry-dataplane-maps dataplane))
    (let ((fd (whistler/loader:map-info-fd (cdr entry))))
      (when (and (integerp fd) (plusp fd)) (ignore-errors (funcall close fd)))))
  (setf (wireguard-path-telemetry-dataplane-maps dataplane) nil)
  nil)

(defun start-wireguard-path-telemetry-dataplane
    (&key (compile #'compile-wireguard-path-telemetry)
          (create-maps #'whistler/loader::session-create-maps)
          (load-programs #'whistler/loader::session-load-progs)
          (attach (lambda (fd section)
                    (whistler/loader:attach-tracepoint fd section))))
  "JIT, load, and attach the passive TCP path telemetry programs.
Any partial start is completely unwound before the error is re-signalled."
  (multiple-value-bind (map-specs program-specs) (funcall compile)
    (let ((dataplane (%make-wireguard-path-telemetry-dataplane)))
      (handler-case
          (progn
            (setf (wireguard-path-telemetry-dataplane-maps dataplane)
                  (funcall create-maps map-specs)
                  (wireguard-path-telemetry-dataplane-programs dataplane)
                  (funcall load-programs
                           program-specs
                           (wireguard-path-telemetry-dataplane-maps dataplane)))
            (dolist (entry (wireguard-path-telemetry-dataplane-programs dataplane))
              (let ((program (cdr entry)))
                (push (funcall attach
                               (whistler/loader:prog-info-fd program)
                               (whistler/loader::prog-info-section-name program))
                      (wireguard-path-telemetry-dataplane-attachments dataplane))))
            dataplane)
        (error (condition)
          (stop-wireguard-path-telemetry-dataplane dataplane)
          (error condition))))))

(defun try-start-wireguard-path-telemetry-dataplane (&key (log *error-output*))
  "Start passive telemetry fail-soft; path safety never depends on eBPF."
  (handler-case (start-wireguard-path-telemetry-dataplane)
    (error (condition)
      (format log "~&gr8s: passive WireGuard path telemetry unavailable: ~A~%"
              condition)
      nil)))

(defstruct wireguard-path-telemetry-counters
  (bytes 0)
  (samples 0)
  (rtt-sum-microseconds 0)
  (retransmits 0)
  congestion-window
  (active-flows 0)
  (sampled-at-milliseconds 0))

(defun wireguard-telemetry-counter-delta (current previous)
  "Return a monotonic counter delta, treating a map reset as a new baseline."
  (if (>= current previous) (- current previous) current))

(defun wireguard-path-telemetry-ipv4 (bytes &optional (offset 0))
  "Render four network-order octets in BYTES at OFFSET as IPv4 text."
  (unless (>= (length bytes) (+ offset 4))
    (error "short WireGuard path telemetry IPv4 value"))
  (format nil "~D.~D.~D.~D"
          (aref bytes offset) (aref bytes (+ offset 1))
          (aref bytes (+ offset 2)) (aref bytes (+ offset 3))))

(defun decode-wireguard-path-telemetry-entry (key value)
  "Decode one gr8s_path_tcp_v4 map KEY/VALUE pair."
  (unless (and (= 4 (length key)) (= 48 (length value)))
    (error "invalid WireGuard path telemetry map entry"))
  (cons
   (wireguard-path-telemetry-ipv4 key)
   (make-wireguard-path-telemetry-counters
    :bytes (netlink-read-integer value 0 8)
    :samples (netlink-read-integer value 8 8)
    :rtt-sum-microseconds (netlink-read-integer value 16 8)
    :retransmits (netlink-read-integer value 24 8)
    :congestion-window (netlink-read-integer value 32 4))))

(defun decode-wireguard-path-flow-entry
    (value now-nanoseconds &key (maximum-age-nanoseconds 60000000000))
  "Return a recent flow's remote IPv4, or NIL when VALUE is stale/malformed."
  (when (= 16 (length value))
    (let ((seen (netlink-read-integer value 8 8)))
      (when (and (<= seen now-nanoseconds)
                 (<= (- now-nanoseconds seen) maximum-age-nanoseconds))
        (wireguard-path-telemetry-ipv4 value)))))

(defun wireguard-path-telemetry-map (dataplane name)
  (or (cdr (assoc name (wireguard-path-telemetry-dataplane-maps dataplane)
                  :test #'string=))
      (error "WireGuard path telemetry map ~A is missing" name)))

(defun wireguard-path-telemetry-map-keys (map)
  (loop for key = (whistler/loader::map-get-next-key map nil)
          then (whistler/loader::map-get-next-key map key)
        while key collect key))

(defun linux-boot-nanoseconds ()
  "Read the monotonic-since-boot clock used by bpf_ktime_get_ns."
  (with-open-file (stream "/proc/uptime")
    (floor (* 1000000000 (read stream)))))

(defun poll-wireguard-path-telemetry
    (dataplane network
     &key (keys #'wireguard-path-telemetry-map-keys)
       (lookup #'whistler/loader:map-lookup)
       (now-milliseconds
         (floor (* 1000 (get-internal-real-time))
                internal-time-units-per-second))
       (now-nanoseconds (linux-boot-nanoseconds)))
  "Read both bounded BPF maps and return authenticated per-peer deltas."
  (let* ((stats-map (wireguard-path-telemetry-map dataplane "gr8s_path_tcp_v4"))
         (flows-map (wireguard-path-telemetry-map dataplane "gr8s_path_flows_v4"))
         (entries
           (loop for key in (funcall keys stats-map)
                 collect (decode-wireguard-path-telemetry-entry
                          key (funcall lookup stats-map key))))
         (flows
           (loop for key in (funcall keys flows-map)
                 for address = (decode-wireguard-path-flow-entry
                                (funcall lookup flows-map key) now-nanoseconds)
                 when address collect address)))
    (wireguard-path-telemetry-samples
     network entries flows
     (wireguard-path-telemetry-dataplane-previous dataplane)
     now-milliseconds)))

(defun aggregate-wireguard-path-telemetry-counters (entries flows cidr now)
  "Aggregate per-destination ENTRIES and recent flow addresses inside CIDR."
  (let ((result (make-wireguard-path-telemetry-counters
                 :sampled-at-milliseconds now))
        (window nil))
    (dolist (entry entries)
      (when (ipv4-cidr-contains-p cidr (car entry))
        (let ((counters (cdr entry)))
          (incf (wireguard-path-telemetry-counters-bytes result)
                (wireguard-path-telemetry-counters-bytes counters))
          (incf (wireguard-path-telemetry-counters-samples result)
                (wireguard-path-telemetry-counters-samples counters))
          (incf (wireguard-path-telemetry-counters-rtt-sum-microseconds result)
                (wireguard-path-telemetry-counters-rtt-sum-microseconds counters))
          (incf (wireguard-path-telemetry-counters-retransmits result)
                (wireguard-path-telemetry-counters-retransmits counters))
          (let ((candidate
                  (wireguard-path-telemetry-counters-congestion-window counters)))
            (when (and candidate (plusp candidate))
              (setf window (if window (min window candidate) candidate)))))))
    (setf (wireguard-path-telemetry-counters-congestion-window result) window
          (wireguard-path-telemetry-counters-active-flows result)
          (count-if (lambda (address) (ipv4-cidr-contains-p cidr address)) flows))
    result))

(defun aggregate-wireguard-peer-telemetry-counters (entries flows cidrs now)
  "Aggregate disjoint destination CIDRS assigned to one authenticated next hop."
  (let ((result (make-wireguard-path-telemetry-counters
                 :sampled-at-milliseconds now))
        (window nil))
    (loop for cidr across cidrs
          for counters = (aggregate-wireguard-path-telemetry-counters
                          entries flows cidr now)
          do (incf (wireguard-path-telemetry-counters-bytes result)
                   (wireguard-path-telemetry-counters-bytes counters))
             (incf (wireguard-path-telemetry-counters-samples result)
                   (wireguard-path-telemetry-counters-samples counters))
             (incf (wireguard-path-telemetry-counters-rtt-sum-microseconds result)
                   (wireguard-path-telemetry-counters-rtt-sum-microseconds counters))
             (incf (wireguard-path-telemetry-counters-retransmits result)
                   (wireguard-path-telemetry-counters-retransmits counters))
             (incf (wireguard-path-telemetry-counters-active-flows result)
                   (wireguard-path-telemetry-counters-active-flows counters))
             (let ((candidate
                     (wireguard-path-telemetry-counters-congestion-window counters)))
               (when (and candidate (plusp candidate))
                 (setf window (if window (min window candidate) candidate)))))
    (setf (wireguard-path-telemetry-counters-congestion-window result) window)
    result))

(defun wireguard-path-telemetry-samples
    (network entries flows previous now)
  "Turn cumulative per-Pod counters into bounded interval samples per peer.
Only Pod CIDRs assigned to authenticated NETWORK next hops are eligible."
  (let ((samples (make-hash-table :test #'equal)))
    (loop for route in (wireguard-peer-routes network)
          for peer-id = (gethash "nodeID" route)
          for cidrs = (gethash "podCIDRs" route)
          when (and (stringp peer-id) (vectorp cidrs))
            do (let* ((current
                        (aggregate-wireguard-peer-telemetry-counters
                         entries flows cidrs now))
                      (old (gethash peer-id previous))
                      (old-bytes (if old (wireguard-path-telemetry-counters-bytes old) 0))
                      (old-samples (if old (wireguard-path-telemetry-counters-samples old) 0))
                      (old-rtt (if old
                                   (wireguard-path-telemetry-counters-rtt-sum-microseconds old)
                                   0))
                      (old-retransmits
                        (if old (wireguard-path-telemetry-counters-retransmits old) 0))
                      (sample-count
                        (wireguard-telemetry-counter-delta
                         (wireguard-path-telemetry-counters-samples current)
                         old-samples))
                      (rtt-sum
                        (wireguard-telemetry-counter-delta
                         (wireguard-path-telemetry-counters-rtt-sum-microseconds current)
                         old-rtt))
                      (interval
                        (max 1 (- now (if old
                                         (wireguard-path-telemetry-counters-sampled-at-milliseconds old)
                                         now)))))
              (setf (gethash peer-id samples)
                    (make-wireguard-path-telemetry
                     :rtt-microseconds (if (plusp sample-count)
                                           (floor rtt-sum sample-count)
                                           0)
                     :tcp-samples sample-count
                     :retransmits
                     (wireguard-telemetry-counter-delta
                      (wireguard-path-telemetry-counters-retransmits current)
                      old-retransmits)
                     :congestion-window
                     (or (wireguard-path-telemetry-counters-congestion-window current) 0)
                     :active-flows
                     (wireguard-path-telemetry-counters-active-flows current)
                     :bytes
                     (wireguard-telemetry-counter-delta
                      (wireguard-path-telemetry-counters-bytes current) old-bytes)
                     :interval-milliseconds interval)
                    (gethash peer-id previous) current)))
    samples))

(defun wireguard-telemetry-tracepoint-offsets (category event fields)
  "Read FIELD offsets from the running kernel's CATEGORY/EVENT schema."
  (let* ((path (format nil "/sys/kernel/tracing/events/~A/~A/format" category event))
         (records (whistler::parse-tracepoint-format path)))
    (loop for (keyword . field) in fields
          for record = (find field records :key #'first :test #'string=)
          unless record do (error "Tracepoint ~A/~A has no ~A field" category event field)
          append (list keyword (second record)))))

(defun wireguard-tcp-probe-ipv4-offsets (offsets)
  "Translate tcp_probe's sockaddr byte array offset to its IPv4 address bytes."
  (let ((normalized (copy-list offsets)))
    (incf (getf normalized :destination) 4)
    normalized))

(defun compile-wireguard-path-telemetry
    (&key
       (probe-offsets
         (wireguard-tcp-probe-ipv4-offsets
          (wireguard-telemetry-tracepoint-offsets
           "tcp" "tcp_probe"
           '((:destination . "daddr") (:family . "family")
             (:bytes . "data_len") (:cwnd . "snd_cwnd")
             (:ssthresh . "ssthresh") (:rtt . "srtt")
             (:cookie . "sock_cookie")))))
       (retransmit-offsets
         (wireguard-telemetry-tracepoint-offsets
          "tcp" "tcp_retransmit_skb"
          '((:destination . "daddr") (:family . "family")))))
  "JIT-compile passive TCP path telemetry for the running kernel.
The tracepoint layout is resolved now—not when the native image was built."
  (compile-whistler-program
   *wireguard-path-telemetry-map-forms*
   (wireguard-path-telemetry-program-forms probe-offsets retransmit-offsets)))
