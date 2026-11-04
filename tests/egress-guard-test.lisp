;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
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
    ;; The three policy maps the CNI pins, with the sizes endpoint-policy checks.
    (is (= 3 (length map-specs)))
    (let ((spoofs (egress-map-spec map-specs "rejected_spoofs"))
          (identity (egress-map-spec map-specs "endpoint_identity"))
          (stats (egress-map-spec map-specs "traffic_stats")))
      (is (and spoofs (= 4 (getf spoofs :key-size)) (= 8 (getf spoofs :value-size))
               (= 1 (getf spoofs :max-entries)) (= 0 (getf spoofs :flags))))
      (is (and identity (= 4 (getf identity :key-size)) (= 16 (getf identity :value-size))
               (= 1 (getf identity :max-entries)) (= 128 (getf identity :flags))))
      (is (and stats (= 4 (getf stats :key-size)) (= 8 (getf stats :value-size))
               (= 6 (getf stats :max-entries)) (= 0 (getf stats :flags)))))
    ;; One TC classifier with real, 8-byte-aligned instructions and the map-fd
    ;; relocations the loader patches in.
    (is (= 1 (length prog-specs)))
    (let ((insns (getf (first prog-specs) :insns)))
      (is (string= "classifier" (getf (first prog-specs) :section)))
      (is (plusp (length insns)))
      (is (zerop (mod (length insns) 8)))
      (is (>= (length (getf (first prog-specs) :relocs)) 3)))))

(defun compile-legacy-egress-guard ()
  "Compile the standalone network/gr8s-egress-guard.lisp forms in-process."
  (let ((map-forms nil) (prog-forms nil))
    (with-open-file (stream "network/gr8s-egress-guard.lisp")
      (let ((*package* (find-package :whistler)))
        (loop for form = (read stream nil :eof) until (eq form :eof)
              do (case (and (consp form) (car form))
                   (whistler::defmap (push form map-forms))
                   (whistler::defprog (push form prog-forms))))))
    (gr8s::compile-whistler-program (nreverse map-forms) (nreverse prog-forms))))

(test egress-guard-in-image-source-matches-legacy
  ;; The in-image forms and the legacy standalone source must compile to the
  ;; exact same bytecode and map specs, so neither drifts before the legacy
  ;; source is removed.
  (multiple-value-bind (image-maps image-progs) (gr8s::compile-egress-guard)
    (multiple-value-bind (legacy-maps legacy-progs) (compile-legacy-egress-guard)
      (is (equalp image-maps legacy-maps))
      (is (equalp (getf (first image-progs) :insns) (getf (first legacy-progs) :insns))))))
