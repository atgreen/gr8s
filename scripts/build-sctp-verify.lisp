;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;; Build unprivileged, then run build/sctp-verify as root in a disposable VM.
;;;; Creates the SCTP NAT maps and loads the two TC classifiers, so the kernel
;;;; verifier runs on each. No attachments, pins, or retained state are changed.
(require :asdf)
(asdf:load-asd (truename "gr8s.asd"))
(asdf:load-system "gr8s")

(defun sctp-verify-main ()
  (unless (zerop (sb-posix:geteuid))
    (error "Run this kernel probe as root in a disposable VM"))
  (multiple-value-bind (map-specs program-specs)
      (gr8s.network::compile-service-sctp-nat)
    (let* ((maps (whistler/loader::session-create-maps map-specs))
           (descriptors (mapcar (lambda (e) (cons (car e) (whistler/loader:map-info-fd (cdr e)))) maps))
           (ok t))
      (dolist (spec program-specs)
        (let ((instructions (copy-seq (getf spec :insns)))
              (name (getf spec :name)))
          ;; Apply map relocations exactly as load-service-lb-programs does.
          (loop for (offset index) in (getf spec :relocs)
                for descriptor = (cdr (assoc (car (nth index maps)) descriptors :test #'string=))
                do (setf (aref instructions (+ offset 1))
                         (logior (logand (aref instructions (+ offset 1)) #x0f) (ash 1 4)))
                   (loop for byte from 0 below 4
                         do (setf (aref instructions (+ offset 4 byte))
                                  (ldb (byte 8 (* 8 byte)) descriptor))))
          (handler-case
              (let ((fd (whistler/loader::load-program
                         instructions
                         whistler/loader::+bpf-prog-type-sched-cls+
                         (getf spec :license))))
                (sb-posix:close fd)
                (format t "~&PROG ~A: VERIFIER-OK (~D insns)~%" name (length instructions)))
            (error (e)
              (setf ok nil)
              (format t "~&PROG ~A: VERIFIER-FAIL~%~A~%" name e)
              (when (typep e 'whistler/loader:bpf-program-load-error)
                (format t "~&--- verifier log ---~%~A~%--- end log ---~%"
                        (whistler/loader:bpf-program-load-error-log e)))))))
      (if ok
          (format t "~&SCTP-VERIFY: ALL PROGRAMS LOADED~%")
          (progn (format t "~&SCTP-VERIFY: FAILED~%") (sb-ext:exit :code 1))))))

(ensure-directories-exist #P"build/")
(sb-ext:save-lisp-and-die #P"build/sctp-verify"
                          :toplevel #'sctp-verify-main :executable t :compression t)
