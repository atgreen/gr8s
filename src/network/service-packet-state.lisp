;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Bounded maintenance of pinned packet Service state. Userspace only enumerates
;;;; keys; the BPF collector rechecks ownership/lifetime under tuple reservations.

(in-package #:gr8s.network)

(defun run-service-packet-gc-key (program-fd direction key)
  "Run one maintenance transaction without injecting a live network packet.
DIRECTION is 0 for forward, 1 for reverse; KEY is the canonical 16-byte tuple.
BPF_PROG_TEST_RUN executes all acquire/mutate/release operations in one kernel
invocation, even if the requesting agent exits while the syscall is running."
  (check-type direction (integer 0 1))
  (unless (= (length key) 16) (error "Invalid packet Service GC key width"))
  (let ((packet (make-array 52 :element-type '(unsigned-byte 8) :initial-element 0))
        (attribute (whistler/loader::make-attr-buf)))
    ;; Ethernet + IPv4 envelope, followed by kind, padding, and tuple. No live
    ;; frame flags are set, no interface is attached, and the program does no I/O.
    (setf (aref packet 12) 8 (aref packet 14) #x45 (aref packet 17) 38
          (aref packet 22) 64 (aref packet 23) 253 (aref packet 34) direction)
    (replace packet key :start1 36)
    (whistler/loader::put-u32 attribute 0 program-fd)
    (whistler/loader::put-u32 attribute 8 (length packet))
    (whistler/loader::put-u32 attribute 32 1)
    (sb-sys:with-pinned-objects (packet)
      (whistler/loader::put-ptr attribute 16 (sb-sys:vector-sap packet))
      (whistler/loader::%bpf 10 attribute 80 "packet Service GC"))
    (netlink-read-integer attribute 4 4)))

(defun packet-program-map-ids (program-id)
  "Read a program's actual kernel map IDs, never trusting its display name."
  (let ((attribute (whistler/loader::make-attr-buf)))
    (whistler/loader::put-u32 attribute 0 program-id)
    (let ((fd (whistler/loader::%bpf 13 attribute 12 "packet program by ID")))
      (unwind-protect
           (let* ((count (netlink-read-integer (bpf-object-kernel-info fd) 52 4))
                  (ids (make-array (* count 4) :element-type '(unsigned-byte 8) :initial-element 0))
                  (info (make-array 256 :element-type '(unsigned-byte 8) :initial-element 0)))
             (whistler/loader::put-u32 info 52 count)
             (whistler/loader::put-u32 attribute 0 fd)
             (whistler/loader::put-u32 attribute 4 (length info))
             (sb-sys:with-pinned-objects (info ids)
               (whistler/loader::put-ptr info 56 (sb-sys:vector-sap ids))
               (whistler/loader::put-ptr attribute 8 (sb-sys:vector-sap info))
               (whistler/loader::%bpf 15 attribute 16 "packet program map IDs"))
             (loop for offset from 0 below (length ids) by 4
                   collect (netlink-read-integer ids offset 4)))
        (sb-posix:close fd)))))

(defun packet-stage-map-ids (path)
  "Return map IDs used by both NAT continuations of an existing endpoint."
  (let ((fd (whistler/loader:open-pinned-object (namestring path))))
    (unwind-protect
         (let ((map (cni-policy-map-info fd "gr8s_pkt_stages")))
           (loop for index in '(0 2)
                 for value = (whistler/loader:map-lookup map (service-lb-bytes index 4))
                 for id = (and value (netlink-read-integer value 0 4))
                 do (unless (and id (plusp id)) (error "Endpoint ~A has an incomplete Service stage" path))
                 collect (packet-program-map-ids id)))
      (sb-posix:close fd))))

(defun service-packet-gc-compatible-p
    (dataplane &key
                 (paths (lambda ()
                          (directory (merge-pathnames "*/gr8s_pkt_stages"
                                      (uiop:pathname-parent-directory-pathname
                                       (service-lb-dataplane-pin-directory dataplane))))))
                 (map-id (lambda (map)
                           (netlink-read-integer (bpf-object-kernel-info
                                                 (whistler/loader:map-info-fd map)) 4 4)))
                 (stage-map-ids #'packet-stage-map-ids))
  "Enable collection only after retained endpoint programs use current locks/maps.
A pre-reservation experimental endpoint may still execute after an upgrade.
Defer GC with a diagnostic until it is refreshed/recreated; never race its writes.
New endpoints installed by this agent use the current compiled guard variant."
  (bt:with-lock-held ((service-lb-dataplane-lock dataplane))
    (when (assoc "gr8s_packet_gc" (service-lb-dataplane-programs dataplane) :test #'equal)
      (or (service-lb-dataplane-gc-compatible-p dataplane)
          (handler-case
              (let ((required
                      (loop for name in '("gr8s_pkt_forward" "gr8s_pkt_reverse"
                                          "gr8s_pkt_fwd_lock" "gr8s_pkt_rev_lock")
                            collect (funcall map-id (or (service-lb-map dataplane name)
                                                       (error "Missing Service state map ~A" name))))))
                (dolist (path (funcall paths))
                  (let ((stages (funcall stage-map-ids path)))
                    (unless (and (= 2 (length stages))
                                 (every (lambda (ids) (subsetp required ids)) stages))
                      (error "Endpoint ~A lacks the current tuple reservations/state maps" path))))
                (setf (service-lb-dataplane-gc-warning dataplane) nil
                      (service-lb-dataplane-gc-compatible-p dataplane) t))
            (error (condition)
              (let ((message (princ-to-string condition)))
                (unless (equal message (service-lb-dataplane-gc-warning dataplane))
                  (format *error-output* "gr8s: Service flow GC deferred: ~A~%" message)
                  (setf (service-lb-dataplane-gc-warning dataplane) message)))
              nil))))))

(defun sweep-service-packet-state
    (dataplane &key (budget 128)
                   (next-key #'whistler/loader:map-get-next-key)
                   (run #'run-service-packet-gc-key))
  "Visit at most BUDGET keys in each flow map, resuming at the next key next tick.
Maintenance never takes a tuple reservation in userspace. A busy key is deferred,
not waited on. Errors advance the cursor so one failing key cannot starve the
rest of the map. The dataplane lock protects descriptors from concurrent close."
  (check-type budget (integer 1 65536))
  (bt:with-lock-held ((service-lb-dataplane-lock dataplane))
    (let ((program (cdr (assoc "gr8s_packet_gc" (service-lb-dataplane-programs dataplane)
                               :test #'equal)))
          (scanned 0) (reclaimed 0) (deferred 0))
      (when program
        (loop for name in '("gr8s_pkt_forward" "gr8s_pkt_reverse") for direction from 0
              for map = (service-lb-map dataplane name)
              do (unless map (error "Packet Service maintenance map ~A is unavailable" name))
                 (let ((key (or (gethash name (service-lb-dataplane-gc-cursors dataplane))
                                (funcall next-key map nil))))
                   (loop repeat budget while key
                         for next = (funcall next-key map key)
                         do (setf (gethash name (service-lb-dataplane-gc-cursors dataplane)) next)
                            (handler-case
                                (let ((result (funcall run (whistler/loader:prog-info-fd program)
                                                       direction key)))
                                  (incf scanned)
                                  (incf (service-lb-dataplane-gc-scanned dataplane))
                                  (case result
                                    (0 nil)
                                    (1 (incf reclaimed)
                                       (incf (service-lb-dataplane-gc-reclaimed dataplane)))
                                    (2 (incf deferred)
                                       (incf (service-lb-dataplane-gc-deferred dataplane)))
                                    (otherwise (error "Invalid packet Service GC result ~A" result))))
                              (error (condition)
                                (incf (service-lb-dataplane-gc-failures dataplane))
                                (error condition)))
                            (setf key next)))))
      (values scanned reclaimed deferred))))
