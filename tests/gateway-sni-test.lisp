;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Exercise the TLS ClientHello SNI peek: extract the host_name from a real
;;;; ClientHello, and fail closed (NIL) on absent SNI, truncation and non-TLS
;;;; records.

(in-package #:gr8s/tests)
(def-suite gateway-sni :in gr8s)
(in-suite gateway-sni)

(defun gwsni-bytes (&rest parts)
  "Flatten integers and byte sequences into one (unsigned-byte 8) vector."
  (let ((out (make-array 0 :element-type '(unsigned-byte 8) :adjustable t :fill-pointer 0)))
    (labels ((emit (x)
               (cond ((integerp x) (vector-push-extend x out))
                     ((stringp x) (loop for c across x do (vector-push-extend (char-code c) out)))
                     (t (map nil #'emit x)))))
      (mapc #'emit parts))
    (coerce out '(simple-array (unsigned-byte 8) (*)))))

(defun gwsni-u16 (n) (list (ldb (byte 8 8) n) (ldb (byte 8 0) n)))

(defun gwsni-client-hello (&key server-name)
  "Build a minimal TLS ClientHello record, optionally carrying an SNI extension."
  (let* ((sni-ext
           (when server-name
             (let* ((name (gwsni-bytes server-name))
                    (entry (gwsni-bytes 0 (gwsni-u16 (length name)) name)) ; type host_name + len + name
                    (list-body (gwsni-bytes (gwsni-u16 (length entry)) entry)))
               (gwsni-bytes (gwsni-u16 0)                     ; ext_type server_name
                            (gwsni-u16 (length list-body))    ; ext_len
                            list-body))))
         (extensions (or sni-ext (gwsni-bytes)))
         (body (gwsni-bytes
                #x03 #x03                                     ; client_version
                (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0) ; random
                0                                             ; session_id length
                (gwsni-u16 2) #x00 #x2f                       ; cipher_suites
                1 0                                           ; compression_methods
                (gwsni-u16 (length extensions)) extensions))
         (handshake (gwsni-bytes 1 (list (ldb (byte 8 16) (length body))
                                         (ldb (byte 8 8) (length body))
                                         (ldb (byte 8 0) (length body)))
                                 body)))
    (gwsni-bytes #x16 #x03 #x01 (gwsni-u16 (length handshake)) handshake)))

(test gateway-sni-extracts-host-name
  (is (equal "app.example.com"
             (gr8s.controllers::parse-tls-client-hello-sni (gwsni-client-hello :server-name "app.example.com"))))
  (is (equal "a.b.c.example.io"
             (gr8s.controllers::parse-tls-client-hello-sni (gwsni-client-hello :server-name "a.b.c.example.io")))))

(test gateway-sni-fails-closed
  ;; No SNI extension.
  (is (null (gr8s.controllers::parse-tls-client-hello-sni (gwsni-client-hello))))
  ;; Not a TLS handshake record.
  (is (null (gr8s.controllers::parse-tls-client-hello-sni (gwsni-bytes #x17 #x03 #x03 (gwsni-u16 4) 0 0 0 0))))
  ;; Truncated ClientHello (cut mid-extension).
  (let* ((full (gwsni-client-hello :server-name "truncated.example.com"))
         (cut (subseq full 0 (- (length full) 8))))
    (is (null (gr8s.controllers::parse-tls-client-hello-sni cut))))
  ;; Too short to be a ClientHello at all.
  (is (null (gr8s.controllers::parse-tls-client-hello-sni (gwsni-bytes #x16 #x03 #x01 0 5)))))
