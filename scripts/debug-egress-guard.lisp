;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Diagnostic (root): exercise the EXACT in-process CNI load path for the
;;;; egress guard and run real packets through BPF_PROG_TEST_RUN, to tell
;;;; whether load-egress-policy-object + session-load-progs produce a program
;;;; that reads the endpoint_identity map that was initialized.  The packet and
;;;; identity bytes mirror what the (passing) kernel fixture test uses.
;;;;
;;;; Run:  sudo sbcl --noinform --script scripts/debug-egress-guard.lisp

(require :asdf)
(let ((project (truename (merge-pathnames "../" (uiop:pathname-directory-pathname *load-truename*)))))
  (asdf:initialize-source-registry
   `(:source-registry (:directory ,project) (:tree ,(merge-pathnames "ocicl/" project))
     :inherit-configuration)))
(asdf:load-system :gr8s)
(in-package #:gr8s.network)

(defun octets (&rest bytes) (make-array (length bytes) :element-type '(unsigned-byte 8)
                                        :initial-contents bytes))

;; Identity for 10.88.1.2 / 02:11:22:33:44:55, schema version 1, in the exact
;; little-endian layout the fixture's KernelMachine writes.
(defparameter +identity+
  (octets #x02 #x01 #x58 #x0a  #x33 #x22 #x11 #x02  #x55 #x44 #x00 #x00  #x01 #x00 #x00 #x00))

(defun ipv4-frame (src-d)
  ;; eth(dst,src=id MAC,0x0800) + 20-byte IPv4 (src=10.88.1.SRC-D, total len 20).
  (octets #x00 #x00 #x00 #x00 #x00 #x00  #x02 #x11 #x22 #x33 #x44 #x55  #x08 #x00
          #x45 #x00 #x00 #x14 #x00 #x00 #x00 #x00 #x40 #x01 #x00 #x00
          #x0a #x58 #x01 src-d  #xa9 #xfe #x01 #x01))

(defun prog-test-run (prog-fd packet)
  "Run PROG-FD once on PACKET via BPF_PROG_TEST_RUN; return (values retval errno)."
  (let ((in (make-array (length packet) :element-type '(unsigned-byte 8) :initial-contents (coerce packet 'list)))
        (out (make-array 256 :element-type '(unsigned-byte 8) :initial-element 0))
        (attr (whistler/loader::make-attr-buf)))
    (sb-sys:with-pinned-objects (in out)
      (whistler/loader::put-u32 attr 0 prog-fd)
      (whistler/loader::put-u32 attr 8 (length in))
      (whistler/loader::put-u32 attr 12 (length out))
      (whistler/loader::put-ptr attr 16 (sb-sys:vector-sap in))
      (whistler/loader::put-ptr attr 24 (sb-sys:vector-sap out))
      (whistler/loader::put-u32 attr 32 1)
      (handler-case
          (progn (whistler/loader::%bpf 10 attr 80 "prog-test-run")
                 (values (logior (aref attr 4) (ash (aref attr 5) 8)
                                 (ash (aref attr 6) 16) (ash (aref attr 7) 24))
                         nil))
        (error (c) (values nil (princ-to-string c)))))))

(defun run ()
  (unless (zerop (sb-posix:geteuid)) (error "needs root"))
  (let* ((object (compile-egress-policy-object))
         (_ (load-egress-policy-object object nil))
         (identity-map (egress-policy-object-find-map object "endpoint_identity"))
         (stats-map (egress-policy-object-find-map object "traffic_stats"))
         (spoofs-map (egress-policy-object-find-map object "rejected_spoofs"))
         (program (egress-policy-object-find-program object "gr8s_egress_guard"))
         (key0 (octets 0 0 0 0)))
    (declare (ignore _))
    ;; Dump the maps the kernel actually created via my load path.
    (dolist (name '("rejected_spoofs" "endpoint_identity" "traffic_stats"))
      (let* ((m (egress-policy-object-find-map object name)))
        (format t "~&map ~A: fd=~A type=~A key=~A value=~A entries=~A flags=~A~%"
                name (whistler/loader:map-info-fd m)
                (ignore-errors (whistler/loader::map-info-type m))
                (whistler/loader::map-info-key-size m) (whistler/loader::map-info-value-size m)
                (whistler/loader::map-info-max-entries m)
                (ignore-errors (whistler/loader::map-info-flags m)))))
    ;; Initialize identity, then read it back from the SAME map-info.
    (whistler/loader:map-update identity-map key0 +identity+)
    (let ((readback (whistler/loader:map-lookup identity-map key0)))
      (format t "identity written=~A readback=~A match=~A~%"
              +identity+ readback (equalp +identity+ readback)))
    ;; Run a legitimate and a spoofed packet.
    (multiple-value-bind (legit err1) (prog-test-run (whistler/loader:prog-info-fd program) (ipv4-frame #x02))
      (multiple-value-bind (spoof err2) (prog-test-run (whistler/loader:prog-info-fd program) (ipv4-frame #x03))
        (format t "legit packet verdict=~A (expect 0 ALLOW) err=~A~%" legit err1)
        (format t "spoof packet verdict=~A (expect 2 SHOT) err=~A~%" spoof err2)
        (format t "traffic_stats[0] allowed_packets=~A  rejected_spoofs[0]=~A~%"
                (ignore-errors (whistler/loader:map-lookup-int stats-map 0))
                (ignore-errors (whistler/loader:map-lookup-int spoofs-map 0)))
        (if (and (eql legit 0) (eql spoof 2))
            (format t "~&RESULT: my load path is CORRECT in-kernel (allow+drop work)~%")
            (format t "~&RESULT: my load path MISBEHAVES (legit should ALLOW, spoof should SHOT)~%"))))))

(run)
