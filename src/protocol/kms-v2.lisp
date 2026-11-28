;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Speak the Kubernetes KMS v2 plugin protocol (podster-qyp9): the gRPC service
;;;; v2.KeyManagementService from k8s.io/kms, over a Unix socket, as kube-apiserver
;;;; does. A plugin holds or reaches a key-encryption key (a cloud KMS, Vault or
;;;; OpenBao Transit, an HSM, a TPM) and wraps the data keys gr8s encrypts Secrets with;
;;;; gr8s never sees that key. Replies are checked as kube-apiserver checks them.

(in-package #:gr8s.protocol)

(defparameter +kms-v2-service+ "/v2.KeyManagementService/")

(defparameter +kms-maximum-key-id-length+ 1024
  "kube-apiserver's limit on a plugin's key_id.")

(defparameter +kms-maximum-ciphertext-length+ 1024
  "kube-apiserver's limit on a wrapped data key, which is all gr8s sends a plugin.")

(defstruct (kms-plugin (:constructor %make-kms-plugin))
  "A KMS v2 plugin gr8s wraps its Secret data keys with. NAME is how stored keys refer
to it; ENDPOINT its socket, unix:///path or a path. TRANSPORT, for tests, stands in for
the socket: (method request) -> the response object."
  name endpoint (timeout 3) transport)

(defun make-kms-plugin (name endpoint &key (timeout 3) transport)
  (unless (and (stringp name) (plusp (length name)) (every (lambda (c) (or (alphanumericp c) (find c "-_."))) name))
    (error "KMS plugin name ~S must be letters, digits, - _ or ." name))
  (unless (or transport (and (stringp endpoint) (plusp (length endpoint))))
    (error "KMS plugin ~A needs an endpoint" name))
  (%make-kms-plugin :name name :endpoint endpoint :timeout timeout :transport transport))

(defun kms-plugin-socket-path (plugin)
  (let ((endpoint (kms-plugin-endpoint plugin)))
    (if (eql 0 (search "unix://" endpoint)) (subseq endpoint 7) endpoint)))

(defun kms-plugin-call (plugin method request response-type)
  "Call METHOD of PLUGIN's KeyManagementService with REQUEST, returning the response."
  (if (kms-plugin-transport plugin)
      (funcall (kms-plugin-transport plugin) method request)
      (let ((channel (make-unix-grpc-channel (kms-plugin-socket-path plugin) :timeout (kms-plugin-timeout plugin))))
        (unwind-protect
             (let ((call (ag-grpc:call-unary channel (concatenate 'string +kms-v2-service+ method) request
                                             :timeout (kms-plugin-timeout plugin) :response-type response-type)))
               (unless (= ag-grpc:+grpc-status-ok+ (ag-grpc:call-status call))
                 (error "KMS plugin ~A: ~A failed with gRPC status ~A: ~A" (kms-plugin-name plugin) method
                        (ag-grpc:call-status call) (ag-grpc::call-status-message call)))
               (ag-grpc:call-response call))
          (ag-grpc:channel-close channel)))))

(defun kms-valid-key-id-p (key-id)
  (and (stringp key-id) (plusp (length key-id)) (<= (length key-id) +kms-maximum-key-id-length+)))

(defun kms-plugin-status (plugin)
  "PLUGIN's status: (values healthy-p key-id why), healthy when it speaks v2, reports
healthz ok, and names its current key."
  (handler-case
      (let* ((response (kms-plugin-call plugin "Status" (make-instance 'gr8s.kms.v2::status-request)
                                        'gr8s.kms.v2::status-response))
             (version (gr8s.kms.v2::version response))
             (healthz (gr8s.kms.v2::healthz response))
             (key-id (gr8s.kms.v2::key-id response)))
        (cond ((not (equal version "v2")) (values nil nil (format nil "speaks ~S, not v2" version)))
              ((not (equal healthz "ok")) (values nil nil (format nil "reports healthz ~S" healthz)))
              ((not (kms-valid-key-id-p key-id)) (values nil nil "reports no valid key_id"))
              (t (values t key-id nil))))
    (error (condition) (values nil nil (princ-to-string condition)))))

(defun kms-plugin-encrypt (plugin plaintext uid)
  "Have PLUGIN wrap PLAINTEXT (octets). Returns (values ciphertext key-id annotations),
ANNOTATIONS an alist of (name . octets)."
  (let* ((response (kms-plugin-call plugin "Encrypt"
                                    (make-instance 'gr8s.kms.v2::encrypt-request :plaintext plaintext :uid uid)
                                    'gr8s.kms.v2::encrypt-response))
         (ciphertext (gr8s.kms.v2::ciphertext response))
         (key-id (gr8s.kms.v2::key-id response)))
    (unless (and ciphertext (plusp (length ciphertext)) (<= (length ciphertext) +kms-maximum-ciphertext-length+))
      (error "KMS plugin ~A returned an invalid ciphertext" (kms-plugin-name plugin)))
    (unless (kms-valid-key-id-p key-id)
      (error "KMS plugin ~A returned an invalid key_id" (kms-plugin-name plugin)))
    (values ciphertext key-id (gr8s.kms.v2::annotations response))))

(defun kms-plugin-decrypt (plugin ciphertext uid key-id annotations)
  "Have PLUGIN unwrap CIPHERTEXT, which it wrapped under KEY-ID with ANNOTATIONS."
  (let ((plaintext (gr8s.kms.v2::plaintext
                    (kms-plugin-call plugin "Decrypt"
                                     (make-instance 'gr8s.kms.v2::decrypt-request
                                                    :ciphertext ciphertext :uid uid :key-id key-id
                                                    :annotations annotations)
                                     'gr8s.kms.v2::decrypt-response))))
    (unless (and plaintext (plusp (length plaintext)))
      (error "KMS plugin ~A returned no plaintext" (kms-plugin-name plugin)))
    plaintext))
