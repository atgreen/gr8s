;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Emit the egress-guard fixture the endpoint-policy test consumes, by
;;;; JIT-compiling the program in-process (no ELF).  The output is a small JSON
;;;; document: the raw program bytecode, the map descriptors, and the map-fd
;;;; relocation sites.  scripts/test-endpoint-policy.py reads this in place of
;;;; parsing an ELF object.
;;;;
;;;; Usage:  sbcl --script scripts/compile-endpoint-policy-fixture.lisp OUTPUT

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
  (unless (= 1 (length arguments))
    (error "usage: sbcl --script compile-endpoint-policy-fixture.lisp OUTPUT"))
  (multiple-value-bind (map-specs program-specs) (compile-egress-guard)
    (let* ((program (first program-specs))
           (code (copy-seq (getf program :insns)))
           (relocations (getf program :relocs)))
      ;; Each map reference is a 16-byte ld_imm64 (opcode 0x18).  The in-process
      ;; compiler leaves the pseudo source register for the loader to set; set
      ;; BPF_PSEUDO_MAP_FD (src_reg = 1) here so the artifact matches what an ELF
      ;; would carry and the kernel test-run path can find the sites.
      (dolist (relocation relocations)
        (let ((offset (first relocation)))
          (setf (aref code (+ offset 1))
                (logior (logand (aref code (+ offset 1)) #x0f) #x10))))
      (let ((document (core-object
                       "code" (coerce code 'list)
                       "maps" (mapcar (lambda (spec)
                                        (core-object
                                         "name" (getf spec :name)
                                         "type" (whistler/compiler:resolve-map-type (getf spec :type))
                                         "key_size" (getf spec :key-size)
                                         "value_size" (getf spec :value-size)
                                         "max_entries" (getf spec :max-entries)
                                         "flags" (getf spec :flags)))
                                      map-specs)
                       "relocations" (mapcar (lambda (relocation)
                                               (list (first relocation) (second relocation)))
                                             relocations))))
        (ensure-directories-exist (first arguments))
        (with-open-file (stream (first arguments) :direction :output
                                                  :if-exists :supersede :if-does-not-exist :create)
          (com.inuoe.jzon:stringify document :stream stream))
        (format t "~&wrote ~A: ~D-instruction program, ~D maps, ~D relocations~%"
                (first arguments) (/ (length code) 8) (length map-specs) (length relocations))))))
