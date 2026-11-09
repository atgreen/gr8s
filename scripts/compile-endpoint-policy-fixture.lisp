;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Emit the endpoint guards fixture the endpoint-policy test consumes, by
;;;; JIT-compiling the program in-process (no ELF).  The output is a small JSON
;;;; document: each program's raw bytecode and map-fd relocation sites, and
;;;; the map descriptors they share.  scripts/test-endpoint-policy.py reads this in place of
;;;; parsing an ELF object.
;;;;
;;;; Usage: sbcl --script scripts/compile-endpoint-policy-fixture.lisp OUTPUT [service-lb|service-packet-lb]
;;;; The optional selector emits the Service socket or packet programs instead of endpoint guards.

(require :asdf)
(let ((project (truename (merge-pathnames "../" (uiop:pathname-directory-pathname *load-truename*)))))
  (asdf:initialize-source-registry
   `(:source-registry
     (:directory ,project)
     (:tree ,(merge-pathnames "ocicl/" project))
     :inherit-configuration)))
(asdf:load-system :gr8s)
(in-package #:gr8s)

(let ((arguments (uiop:command-line-arguments)))
  (unless (and (<= 1 (length arguments) 2)
               (or (= 1 (length arguments))
                   (member (second arguments) '("service-lb" "service-packet-lb" "service-packet-guard") :test #'equal)))
    (error "usage: sbcl --script compile-endpoint-policy-fixture.lisp OUTPUT [service-lb|service-packet-lb]"))
  (multiple-value-bind (map-specs program-specs)
      (cond ((equal "service-packet-guard" (second arguments))
             (compile-egress-guard :service-packets t))
            ((equal "service-packet-lb" (second arguments))
             (gr8s.network::compile-service-packet-lb))
            ((second arguments) (compile-service-lb))
            (t (compile-egress-guard)))
    (flet ((program-document (program)
             (let ((code (copy-seq (getf program :insns)))
                   (relocations (getf program :relocs)))
               ;; Each map reference is a 16-byte ld_imm64 (opcode 0x18).  The in-process
               ;; compiler leaves the pseudo source register for the loader to set; set
               ;; BPF_PSEUDO_MAP_FD (src_reg = 1) here so the artifact matches what an ELF
               ;; would carry and the kernel test-run path can find the sites.
               (dolist (relocation relocations)
                 (let ((offset (first relocation)))
                   (setf (aref code (+ offset 1))
                         (logior (logand (aref code (+ offset 1)) #x0f) #x10))))
               (core-object "name" (getf program :name)
                            "section" (getf program :section)
                            "code" (coerce code 'list)
                            "relocations" (mapcar (lambda (relocation)
                                                    (list (first relocation) (second relocation)))
                                                  relocations)))))
      (let ((document (core-object
                       "programs" (mapcar #'program-document program-specs)
                       "maps" (mapcar (lambda (spec)
                                        (core-object
                                         "name" (getf spec :name)
                                         "type" (whistler/compiler:resolve-map-type (getf spec :type))
                                         "key_size" (getf spec :key-size)
                                         "value_size" (getf spec :value-size)
                                         "max_entries" (getf spec :max-entries)
                                         "flags" (getf spec :flags)))
                                      map-specs))))
        (ensure-directories-exist (first arguments))
        (with-open-file (stream (first arguments) :direction :output
                                                  :if-exists :supersede :if-does-not-exist :create)
          (com.inuoe.jzon:stringify document :stream stream))
        (format t "~&wrote ~A: ~{~A~^, ~} over ~D maps~%"
                (first arguments)
                (mapcar (lambda (program) (format nil "~A (~D instructions)" (getf program :name)
                                                  (/ (length (getf program :insns)) 8)))
                        program-specs)
                (length map-specs))))))
