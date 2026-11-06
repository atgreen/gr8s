;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Prove the per-endpoint egress guard JIT-compiles in-process to the policy
;;;; maps and classifier program the CNI path expects, with no ELF, and guard
;;;; against drift between the in-image source and the legacy standalone source
;;;; until the latter is removed (podster-7q2.5c).

(in-package #:gr8s/tests)
(def-suite egress-guard :in gr8s)
(in-suite egress-guard)

(defun egress-map-spec (specs name)
  (find name specs :key (lambda (s) (getf s :name)) :test #'string=))

(test egress-guard-compiles-in-process-to-the-policy-maps
  (multiple-value-bind (map-specs prog-specs) (gr8s::compile-egress-guard)
    ;; The policy maps the CNI pins, with the sizes endpoint-policy checks: the
    ;; three guard maps, the three map-driven NetworkPolicy maps, and the
    ;; same-node Pod delivery table.
    (is (= 7 (length map-specs)))
    (let ((spoofs (egress-map-spec map-specs "rejected_spoofs"))
          (identity (egress-map-spec map-specs "endpoint_identity"))
          (stats (egress-map-spec map-specs "traffic_stats"))
          (mode (egress-map-spec map-specs "netpol_egress_mode"))
          (cidr (egress-map-spec map-specs "netpol_egress_cidr"))
          (port (egress-map-spec map-specs "netpol_egress_port"))
          (local-pod (egress-map-spec map-specs "local_pod_v4")))
      (is (and spoofs (= 4 (getf spoofs :key-size)) (= 8 (getf spoofs :value-size))
               (= 1 (getf spoofs :max-entries)) (= 0 (getf spoofs :flags))))
      (is (and identity (= 4 (getf identity :key-size)) (= 16 (getf identity :value-size))
               (= 1 (getf identity :max-entries)) (= 128 (getf identity :flags))))
      (is (and stats (= 4 (getf stats :key-size)) (= 8 (getf stats :value-size))
               (= 7 (getf stats :max-entries)) (= 0 (getf stats :flags))))
      (is (and mode (= 4 (getf mode :key-size)) (= 4 (getf mode :value-size))
               (= 1 (getf mode :max-entries))))
      (is (and cidr (= 8 (getf cidr :key-size)) (= 4 (getf cidr :value-size))
               (= 1 (getf cidr :flags))))                 ; LPM_TRIE, NO_PREALLOC
      (is (and port (= 8 (getf port :key-size)) (= 1 (getf port :value-size))))
      (is (and local-pod (= 8 (getf local-pod :key-size)) (= 16 (getf local-pod :value-size))
               (= 4096 (getf local-pod :max-entries)) (= 1 (getf local-pod :flags)))))
    ;; One TC classifier with real, 8-byte-aligned instructions and the map-fd
    ;; relocations the loader patches in.
    (is (= 1 (length prog-specs)))
    (let ((insns (getf (first prog-specs) :insns)))
      (is (string= "classifier" (getf (first prog-specs) :section)))
      (is (plusp (length insns)))
      (is (zerop (mod (length insns) 8)))
      (is (>= (length (getf (first prog-specs) :relocs)) 3)))))

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
                      (list (cons "gr8s_egress_guard"
                                  (whistler/loader::make-prog-info
                                   :name "gr8s_egress_guard" :section-name "classifier"
                                   :type 3 :insns #() :fd 901)))))
    ;; Every map except the reused endpoint_identity was created (7 maps total:
    ;; the 3 guard maps, the 3 NetworkPolicy maps, and local_pod_v4).
    (is (= 6 (length created)))
    (is (not (member "endpoint_identity" created :test #'string=)))
    (is (member "rejected_spoofs" created :test #'string=))
    (is (member "traffic_stats" created :test #'string=))
    (is (member "netpol_egress_cidr" created :test #'string=))
    ;; The reused map keeps its pinned fd; the program loads against all 7 maps.
    (is (= 555 (whistler/loader:map-info-fd
                (gr8s::egress-policy-object-find-map object "endpoint_identity"))))
    (is (= 7 (length loaded-with)))
    (is (= 901 (whistler/loader:prog-info-fd
                (gr8s::egress-policy-object-find-program object "gr8s_egress_guard"))))))

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
                      (list (cons "gr8s_egress_guard"
                                  (whistler/loader::make-prog-info
                                   :name "gr8s_egress_guard" :section-name "classifier"
                                   :type 3 :insns #() :fd 901)))))
    (gr8s::close-egress-policy-object object :close-fd (lambda (fd) (push fd closed)))
    ;; Program fd plus all seven map fds are closed.
    (is (member 901 closed))
    (is (= 8 (length closed)))))
