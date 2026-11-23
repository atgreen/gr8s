;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Verify the node's flow-event ring without CAP_BPF: event decoding against
;;;; the guards' FLOW-EVENT layout, creating or reopening the pinned ring, and the
;;;; CNI passing it to every endpoint's guards instead of pinning one per Pod.
;;;; Root VM runs check that the guards really write to it.

(in-package #:gr8s/tests)
(def-suite flow-events :in gr8s)
(in-suite flow-events)

(defun flow-event-octets (&key (ifindex 7) (endpoint 0) (kind 1) (reason 4) (direction 1) (family 4)
                            (protocol 6) (pod-port '(#x1f #x90)) (peer-port '(#x01 #xbb)) (length 74)
                            (peer '(10 88 2 9)))
  "Build a ring event as the guards lay it out."
  (let ((octets (make-array gr8s.network::+flow-event-size+ :element-type '(unsigned-byte 8)
                                                            :initial-element 0)))
    (flet ((u32le (offset value) (replace octets (cl-rtnetlink::netlink-integer value 4) :start1 offset)))
      (u32le 0 ifindex) (u32le 4 endpoint)
      (setf (aref octets 8) kind (aref octets 9) reason (aref octets 10) direction
            (aref octets 11) family (aref octets 12) protocol)
      (replace octets pod-port :start1 14)
      (replace octets peer-port :start1 16)
      (u32le 20 length)
      (replace octets peer :start1 24))
    octets))

(test flow-events-decode-the-guards-layout
  (let ((record (gr8s.network::decode-flow-event
                 (flow-event-octets :endpoint #x0a580105))))
    (is (= 7 (gr8s.network::flow-record-ifindex record)))
    (is (equal "10.88.1.5" (gr8s.network::flow-record-endpoint record)))
    (is (eq :drop (gr8s.network::flow-record-kind record)))
    (is (eq :policy (gr8s.network::flow-record-reason record)))
    (is (eq :egress (gr8s.network::flow-record-direction record)))
    (is (eq :ipv4 (gr8s.network::flow-record-family record)))
    (is (= 6 (gr8s.network::flow-record-protocol record)))
    (is (= 8080 (gr8s.network::flow-record-pod-port record)))
    (is (equal "10.88.2.9" (gr8s.network::flow-record-peer record)))
    (is (= 443 (gr8s.network::flow-record-peer-port record)))
    (is (= 74 (gr8s.network::flow-record-length record))))
  (let ((record (gr8s.network::decode-flow-event
                 (flow-event-octets :kind 2 :reason 0 :direction 2 :family 6 :protocol 17
                                    :peer '(#xfd 0 0 #x88 0 0 0 0 0 0 0 0 0 0 0 #x12)))))
    (is (eq :allowed (gr8s.network::flow-record-kind record)))
    (is (null (gr8s.network::flow-record-reason record)))
    (is (eq :ingress (gr8s.network::flow-record-direction record)))
    (is (null (gr8s.network::flow-record-endpoint record)))
    (is (equal "fd00:88:0:0:0:0:0:12" (gr8s.network::flow-record-peer record))))
  ;; A drop before the packet was parsed names no flow.
  (let ((record (gr8s.network::decode-flow-event
                 (flow-event-octets :reason 2 :family 0 :protocol 0 :pod-port '(0 0)
                                    :peer-port '(0 0) :peer '(0 0 0 0)))))
    (is (eq :malformed (gr8s.network::flow-record-reason record)))
    (is (null (gr8s.network::flow-record-family record)))
    (is (null (gr8s.network::flow-record-peer record)))
    (is (null (gr8s.network::flow-record-protocol record))))
  (is (null (gr8s.network::decode-flow-event (make-array 12 :element-type '(unsigned-byte 8))))))

(test flow-events-ring-is-reopened-created-or-refused
  (let ((ring-info (make-array 24 :element-type '(unsigned-byte 8) :initial-element 0)))
    (flet ((put (offset value) (replace ring-info (cl-rtnetlink::netlink-integer value 4) :start1 offset))
           (info-of (fd) (declare (ignore fd)) ring-info))
      (put 0 27) (put 16 gr8s.network::+flow-events-bytes+)
      ;; An existing pin is reused, never recreated.
      (let ((info (gr8s.network::open-flow-events-ring
                   "/bpf/" :create t
                   :path-exists-p (lambda (path) (equal "/bpf/flow_events" path))
                   :open-pinned (constantly 31)
                   :check (lambda (fd) (gr8s.network::check-flow-events-ring fd :object-info #'info-of))
                   :create-map (lambda (info) (declare (ignore info)) (fail "recreated a pinned ring")))))
        (is (= 31 (whistler/loader:map-info-fd info)))
        (is (= gr8s.network::+flow-events-bytes+ (whistler/loader::map-info-max-entries info))))
      ;; The agent creates and pins a missing one; the CNI, without CREATE, doesn't.
      (let ((pinned nil))
        (let ((info (gr8s.network::open-flow-events-ring
                     "/bpf" :create t :path-exists-p (constantly nil)
                     :create-map (lambda (info) (setf (whistler/loader:map-info-fd info) 32))
                     :pin-object (lambda (fd path) (push (list fd path) pinned)))))
          (is (= 32 (whistler/loader:map-info-fd info)))
          (is (= 27 (whistler/loader::map-info-type info)))
          (is (equal '((32 "/bpf/flow_events")) pinned))))
      (is (null (gr8s.network::open-flow-events-ring "/bpf/" :path-exists-p (constantly nil))))
      ;; A pin of the wrong size would be read with the wrong mask.
      (put 16 4096)
      (let ((closed nil))
        (signals gr8s.network::cni-error
          (gr8s.network::open-flow-events-ring
           "/bpf/" :path-exists-p (constantly t) :open-pinned (constantly 33)
           :check (lambda (fd) (gr8s.network::check-flow-events-ring fd :object-info #'info-of))
           :close-fd (lambda (fd) (push fd closed))))
        (is (equal '(33) closed))))))

(test cni-passes-the-node-flow-ring-to-the-guards-and-closes-it-once
  (let* ((configuration (gr8s.network::parse-cni-configuration *valid-cni-config*))
         (names (mapcar #'first (gr8s.network::cni-local-policy-map-specs configuration)))
         (maps (loop for name in (list* "flow_events" "flow_config" names) for fd from 100
                     collect (cons name (whistler/loader::make-map-info :name name :fd fd))))
         (ring (cdr (assoc "flow_events" maps :test #'equal)))
         (config (cdr (assoc "flow_config" maps :test #'equal)))
         (closed nil) (pins nil) (reused nil))
    (flet ((map-for (name) (cdr (assoc name maps :test #'equal))))
      (gr8s.network::install-cni-policy
       configuration (gr8s.network::make-cni-context :netns "/fake/netns" :interface-name "eth0")
       "/pins/rejected_spoofs" "/pins/tcx-ingress"
       :ensure-directory (constantly nil) :path-exists-p (constantly nil)
       :open-flow-events (lambda (root)
                           (is (equal (gr8s.network::cni-configuration-map-pin-root configuration) root))
                           ring)
       :open-flow-config (lambda (root) (declare (ignore root)) config)
       :open-pinned (lambda (path) (whistler/loader:map-info-fd (map-for (file-namestring path))))
       :validate-map (lambda (fd name) (declare (ignore fd)) (map-for name))
       :open-object (constantly :object)
       :load-object (lambda (object replacements) (declare (ignore object)) (setf reused replacements))
       :object-map (lambda (object name) (declare (ignore object)) (map-for name))
       :object-program (constantly :program) :program-fd (constantly 71)
       :initialize-identity (constantly nil)
       :pin-object (lambda (fd path) (declare (ignore fd)) (push path pins))
       :rename-pin (constantly nil) :staged-links (constantly nil)
       :call-in-netns (lambda (path operation) (declare (ignore path)) (funcall operation))
       :interface-index (constantly 9) :attach-tcx (constantly 81)
       :close-fd (lambda (fd) (push fd closed))
       :close-object (lambda (object) (declare (ignore object))
                       (dolist (entry maps) (push (whistler/loader:map-info-fd (cdr entry)) closed)))))
    (is (equal (cons "flow_events" (whistler/loader:map-info-fd ring))
               (assoc "flow_events" reused :test #'equal)))
    (is (= 1 (count (whistler/loader:map-info-fd ring) closed)))
    (is-false (member "flow_events" pins :key #'file-namestring :test #'equal))
    ;; The node's settings ride along the same way.
    (is (equal (cons "flow_config" (whistler/loader:map-info-fd config))
               (assoc "flow_config" reused :test #'equal)))
    (is (= 1 (count (whistler/loader:map-info-fd config) closed)))
    (is-false (member "flow_config" pins :key #'file-namestring :test #'equal))))

(test flow-settings-are-reopened-created-checked-and-set
  (let ((array-info (make-array 24 :element-type '(unsigned-byte 8) :initial-element 0)))
    (flet ((put (offset value) (replace array-info (cl-rtnetlink::netlink-integer value 4) :start1 offset)))
      (put 0 2) (put 8 4) (put 12 4) (put 16 1)
      (let ((info (gr8s.network::open-flow-config
                   "/bpf/" :create t :path-exists-p (lambda (path) (equal "/bpf/flow_config" path))
                   :open-pinned (constantly 41) :object-info (constantly array-info)
                   :create-map (lambda (info) (declare (ignore info)) (fail "recreated pinned settings")))))
        (is (= 41 (whistler/loader:map-info-fd info))))
      (let* ((pinned nil)
             (info (gr8s.network::open-flow-config
                    "/bpf" :create t :path-exists-p (constantly nil)
                    :create-map (lambda (info) (setf (whistler/loader:map-info-fd info) 42))
                    :pin-object (lambda (fd path) (push (list fd path) pinned))))
             (written nil))
        (is (equal '((42 "/bpf/flow_config")) pinned))
        (gr8s.network::set-flow-reporting info t :update (lambda (map key value) (declare (ignore map)) (push (list key value) written)))
        (gr8s.network::set-flow-reporting info nil :update (lambda (map key value) (declare (ignore map)) (push (list key value) written)))
        (is (equalp '((#(0 0 0 0) #(0 0 0 0)) (#(0 0 0 0) #(1 0 0 0))) written)))
      (is (null (gr8s.network::open-flow-config "/bpf/" :path-exists-p (constantly nil))))
      ;; Some other map pinned under the name is refused, and closed.
      (put 16 2)
      (let ((closed nil))
        (signals gr8s.network::cni-error
          (gr8s.network::open-flow-config "/bpf/" :path-exists-p (constantly t) :open-pinned (constantly 43)
                                          :object-info (constantly array-info)
                                          :close-fd (lambda (fd) (push fd closed))))
        (is (equal '(43) closed))))))
