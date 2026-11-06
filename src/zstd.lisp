;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Streaming zstd decompression via a minimal CFFI binding to the system
;;;; libzstd. libzstd is dual-licensed BSD-3-Clause OR GPL-2.0; gr8s links it
;;;; under the BSD-3-Clause option, which is compatible with gr8s's Apache-2.0
;;;; licence. Only the decompression streaming API is bound -- enough to unpack
;;;; the zstd-compressed runtime bundles (gVisor, Kata) that `gr8s runtime
;;;; install` downloads. The library is opened lazily at runtime (not baked into
;;;; the saved image), so a build host without libzstd still produces a binary;
;;;; the dependency is needed only when a runtime is actually installed.

(in-package #:gr8s)

(cffi:define-foreign-library libzstd
  (:unix (:or "libzstd.so.1" "libzstd.so"))
  (t (:default "libzstd")))

(defvar *libzstd-loaded* nil
  "True once libzstd has been dlopen'd in this process. The library is opened on
   first use rather than at load/build time so the saved image carries no handle.")

(defun ensure-libzstd ()
  (unless *libzstd-loaded*
    (cffi:use-foreign-library libzstd)
    (setf *libzstd-loaded* t)))

;;; ZSTD_inBuffer { const void *src; size_t size; size_t pos; }
;;; ZSTD_outBuffer { void *dst; size_t size; size_t pos; }
(cffi:defcstruct zstd-in-buffer
  (src :pointer) (size :size) (pos :size))
(cffi:defcstruct zstd-out-buffer
  (dst :pointer) (size :size) (pos :size))

(cffi:defcfun ("ZSTD_createDStream" %zstd-create-dstream) :pointer)
(cffi:defcfun ("ZSTD_freeDStream" %zstd-free-dstream) :size (zds :pointer))
(cffi:defcfun ("ZSTD_initDStream" %zstd-init-dstream) :size (zds :pointer))
(cffi:defcfun ("ZSTD_decompressStream" %zstd-decompress-stream) :size
  (zds :pointer) (output :pointer) (input :pointer))
(cffi:defcfun ("ZSTD_isError" %zstd-is-error) :unsigned-int (code :size))
(cffi:defcfun ("ZSTD_getErrorName" %zstd-get-error-name) :string (code :size))
(cffi:defcfun ("ZSTD_DStreamInSize" %zstd-dstream-in-size) :size)
(cffi:defcfun ("ZSTD_DStreamOutSize" %zstd-dstream-out-size) :size)

(define-condition zstd-error (error)
  ((message :initarg :message :reader zstd-error-message))
  (:report (lambda (condition stream)
             (format stream "zstd: ~A" (zstd-error-message condition)))))

(defun zstd-decompress-file (input-path output-path)
  "Stream-decompress the zstd file at INPUT-PATH to OUTPUT-PATH, returning
   OUTPUT-PATH. Memory is bounded: input is read in libzstd-recommended chunks
   and each is decompressed into a reused buffer, so the whole payload is never
   held at once (a multi-GB tarball decompresses in constant space)."
  (ensure-libzstd)
  (let* ((in-cap (%zstd-dstream-in-size))
         (out-cap (%zstd-dstream-out-size))
         (zds (%zstd-create-dstream)))
    (when (cffi:null-pointer-p zds)
      (error 'zstd-error :message "ZSTD_createDStream returned NULL"))
    (unwind-protect
         (let ((init (%zstd-init-dstream zds))
               (inbuf-lisp (make-array in-cap :element-type '(unsigned-byte 8)))
               (outbuf-lisp (make-array out-cap :element-type '(unsigned-byte 8))))
           (when (plusp (%zstd-is-error init))
             (error 'zstd-error :message (%zstd-get-error-name init)))
           (cffi:with-foreign-objects ((inbuf '(:struct zstd-in-buffer))
                                       (outbuf '(:struct zstd-out-buffer)))
             (with-open-file (in input-path :element-type '(unsigned-byte 8))
               (with-open-file (out output-path :element-type '(unsigned-byte 8)
                                                 :direction :output
                                                 :if-exists :supersede
                                                 :if-does-not-exist :create)
                 (loop for n = (read-sequence inbuf-lisp in)
                       while (plusp n) do
                   (cffi:with-pointer-to-vector-data (in-ptr inbuf-lisp)
                     (setf (cffi:foreign-slot-value inbuf '(:struct zstd-in-buffer) 'src) in-ptr
                           (cffi:foreign-slot-value inbuf '(:struct zstd-in-buffer) 'size) n
                           (cffi:foreign-slot-value inbuf '(:struct zstd-in-buffer) 'pos) 0)
                     ;; Drain this input chunk; loop because one chunk can yield
                     ;; several output-buffer-fulls.
                     (loop while (< (cffi:foreign-slot-value inbuf '(:struct zstd-in-buffer) 'pos) n) do
                       (let ((before-in (cffi:foreign-slot-value inbuf '(:struct zstd-in-buffer) 'pos)))
                         (cffi:with-pointer-to-vector-data (out-ptr outbuf-lisp)
                           (setf (cffi:foreign-slot-value outbuf '(:struct zstd-out-buffer) 'dst) out-ptr
                                 (cffi:foreign-slot-value outbuf '(:struct zstd-out-buffer) 'size) out-cap
                                 (cffi:foreign-slot-value outbuf '(:struct zstd-out-buffer) 'pos) 0)
                           (let ((rc (%zstd-decompress-stream zds outbuf inbuf)))
                             (when (plusp (%zstd-is-error rc))
                               (error 'zstd-error :message (%zstd-get-error-name rc)))
                             (let ((produced (cffi:foreign-slot-value outbuf '(:struct zstd-out-buffer) 'pos)))
                               (when (plusp produced)
                                 (write-sequence outbuf-lisp out :end produced))
                               ;; Guard against a no-progress spin on a truncated
                               ;; stream: if a call neither consumed input nor
                               ;; produced output, stop.
                               (when (and (zerop produced)
                                          (= before-in
                                             (cffi:foreign-slot-value inbuf '(:struct zstd-in-buffer) 'pos)))
                                 (return))))))))))))
           output-path)
      (%zstd-free-dstream zds))))
