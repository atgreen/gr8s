;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Prove the per-endpoint guards JIT-compile in-process to the policy maps
;;;; and classifier programs the CNI path expects, with no ELF, and guard
;;;; against drift between the in-image source and the legacy standalone source
;;;; until the latter is removed (podster-7q2.5c).

(in-package #:gr8s/tests)
(def-suite egress-guard :in gr8s)
(in-suite egress-guard)

(defun egress-map-spec (specs name)
  (find name specs :key (lambda (s) (getf s :name)) :test #'string=))

(test egress-guard-compiles-in-process-to-the-policy-maps
  (multiple-value-bind (map-specs prog-specs) (gr8s::compile-egress-guard)
    ;; The maps the CNI pins, with the schemas endpoint-policy checks: the three guard
    ;; maps, the NetworkPolicy maps the agent writes, and the redirect tables.
    (is (= (length gr8s::+cni-policy-map-specs+) (length map-specs)))
    (loop for (name type key-size value-size max-entries flags) in gr8s::+cni-policy-map-specs+
          for spec = (egress-map-spec map-specs name)
          do (is (and spec
                      (= type (whistler/compiler:resolve-map-type (getf spec :type)))
                      (= key-size (getf spec :key-size)) (= value-size (getf spec :value-size))
                      (= max-entries (getf spec :max-entries)) (= flags (or (getf spec :flags) 0)))
                 "~A does not match the CNI's schema" name))
    ;; Two TC classifiers over those maps: the egress guard and the ingress guard, with
    ;; real, 8-byte-aligned instructions and the map-fd relocations the loader patches in.
    (is (equal '("gr8s_egress_guard" "gr8s_ingress_guard") (mapcar (lambda (spec) (getf spec :name)) prog-specs)))
    (dolist (spec prog-specs)
      (let ((insns (getf spec :insns)))
        (is (string= "classifier" (getf spec :section)))
        (is (plusp (length insns)))
        (is (zerop (mod (length insns) 8)))
        (is (>= (length (getf spec :relocs)) 3))))))

(test egress-guard-publishes-ipv6-policy-and-flow-maps
  (multiple-value-bind (map-specs prog-specs) (gr8s::compile-egress-guard)
    (declare (ignore prog-specs))
    (dolist (expected '("netpol_egress_cidr_v6" "netpol_ingress_cidr_v6"
                        "netpol_egress_ports_v6" "netpol_ingress_ports_v6"
                        "netpol_flows_v6"))
      (is (egress-map-spec map-specs expected) "missing ~A" expected))
    (let ((egress (egress-map-spec map-specs "netpol_egress_cidr_v6"))
          (flows (egress-map-spec map-specs "netpol_flows_v6")))
      (is (= 20 (getf egress :key-size)))
      (is (= 24 (getf flows :key-size))))))

;;; In-process policy object for the CNI installer.  create-map and the program
;;; loader are injected, so the create/reuse/load orchestration runs rootless.

(test egress-guard-dns-redirect-constant-tracks-the-node-dns-address
  ;; The guard's DNS redirect-to-lo clause hardcodes the node gateway/DNS
  ;; address as a BPF constant (#xa9fe0101). If the Lisp address ever changes,
  ;; this fails loudly so the program constant is updated in lockstep.
  (is (string= "169.254.1.1" gr8s::+dns-pod-server-address+))
  (is (= #xa9fe0101 (gr8s::parse-ipv4-integer gr8s::+dns-pod-server-address+))))

(test egress-policy-object-reuses-pinned-maps-and-creates-the-rest
  (let ((object (gr8s::compile-egress-policy-object "/ignored/path.o"))
        (created nil) (loaded-with nil))
    (gr8s::load-egress-policy-object
     object
     ;; endpoint_identity is already pinned (fd 555); the others are created.
     '(("endpoint_identity" . 555))
     :create-map (lambda (info)
                   (push (whistler/loader:map-info-name info) created)
                   (setf (whistler/loader:map-info-fd info) 900)
                   info)
     :load-programs (lambda (specs maps)
                      (declare (ignore specs))
                      (setf loaded-with maps)
                      (loop for (name fd) in '(("gr8s_egress_guard" 901) ("gr8s_ingress_guard" 902))
                            collect (cons name (whistler/loader::make-prog-info
                                                :name name :section-name "classifier"
                                                :type 3 :insns #() :fd fd)))))
    ;; Every map except the reused endpoint_identity was created.
    (is (= (1- (length gr8s::+cni-policy-map-specs+)) (length created)))
    (is (not (member "endpoint_identity" created :test #'string=)))
    (is (member "rejected_spoofs" created :test #'string=))
    (is (member "traffic_stats" created :test #'string=))
    (is (member "netpol_egress_cidr" created :test #'string=))
    (is (member "netpol_flows" created :test #'string=))
    (is (member "host_redirect_v4" created :test #'string=))
    ;; The reused map keeps its pinned fd; both programs load against every map.
    (is (= 555 (whistler/loader:map-info-fd
                (gr8s::egress-policy-object-find-map object "endpoint_identity"))))
    (is (= (length gr8s::+cni-policy-map-specs+) (length loaded-with)))
    (is (= 901 (whistler/loader:prog-info-fd
                (gr8s::egress-policy-object-find-program object "gr8s_egress_guard"))))
    (is (= 902 (whistler/loader:prog-info-fd
                (gr8s::egress-policy-object-find-program object "gr8s_ingress_guard"))))))

;; podster-uqb.97: this took 0.53s of the 0.58s of agent CNI handling for each Pod.
(test egress-policy-objects-compile-the-guard-once
  (let ((saved gr8s::*egress-guard-specs*)
        (compiles 0))
    (setf gr8s::*egress-guard-specs* nil)
    (sb-int:encapsulate 'gr8s::compile-egress-guard 'count-compiles
                        (lambda (function &rest arguments)
                          (incf compiles)
                          (apply function arguments)))
    (unwind-protect
         (let* ((threads (loop repeat 4
                               collect (bt:make-thread #'gr8s::compile-egress-policy-object)))
                (objects (mapcar #'bt:join-thread threads)))
           (is (= 1 compiles))
           (is (eq (gr8s::egress-policy-object-program-specs (first objects))
                   (gr8s::egress-policy-object-program-specs (second objects))))
           ;; Each Pod still gets its own object for its own map and program fds.
           (is (not (eq (first objects) (second objects))))
           (is (plusp (length (gr8s::egress-policy-object-map-specs (first objects))))))
      (sb-int:unencapsulate 'gr8s::compile-egress-guard 'count-compiles)
      (setf gr8s::*egress-guard-specs* saved))))

(test egress-policy-object-close-releases-all-fds
  (let ((object (gr8s::compile-egress-policy-object))
        (closed nil))
    (gr8s::load-egress-policy-object
     object '()
     :create-map (lambda (info) (setf (whistler/loader:map-info-fd info) 900) info)
     :load-programs (lambda (specs maps) (declare (ignore specs maps))
                      (loop for (name fd) in '(("gr8s_egress_guard" 901) ("gr8s_ingress_guard" 902))
                            collect (cons name (whistler/loader::make-prog-info
                                                :name name :section-name "classifier"
                                                :type 3 :insns #() :fd fd)))))
    (gr8s::close-egress-policy-object object :close-fd (lambda (fd) (push fd closed)))
    ;; Both program fds and every map fd are closed.
    (is (member 901 closed))
    (is (member 902 closed))
    (is (= (+ 2 (length gr8s::+cni-policy-map-specs+)) (length closed)))))
