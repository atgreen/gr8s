;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0

(in-package #:gr8s.server)

(defun parse-secrets-encrypt-options (arguments)
  "Parse the explicit Secret encryption-at-rest management workflow."
  (let* ((stage (first arguments))
         (command (cdr (assoc stage
                              '(("status" . :secrets-encrypt-status)
                                ("enable" . :secrets-encrypt-enable)
                                ("disable" . :secrets-encrypt-disable)
                                ("prepare" . :secrets-encrypt-prepare)
                                ("promote" . :secrets-encrypt-promote)
                                ("reencrypt" . :secrets-encrypt-reencrypt)
                                ("finalize" . :secrets-encrypt-finalize))
                              :test #'equal))))
    (unless command
      (error "unknown secrets-encrypt subcommand: ~A" (or stage "")))
    (let ((options (list :command command
                         :state-directory (namestring (default-state-directory))))
          (arguments (rest arguments)))
      (loop while arguments
            for option = (first arguments)
            do (cond
                 ((string= option "--state-directory")
                  (setf (getf options :state-directory) (option-value arguments option)
                        arguments (cddr arguments)))
                 (t (error "unknown secrets-encrypt option: ~A" option))))
      options)))

(defun secret-encryption-status-json (store)
  "Return the stable, non-key-material operator view of encryption state."
  (let ((status (secret-encryption-status store)))
    (core-object
     "enabled" (if (gethash "enabled" status) t nil)
     "phase" (gethash "phase" status "disabled")
     "activeKeyId" (gethash "activeKeyId" status)
     "preparedKeyId" (gethash "preparedKeyId" status)
     "reencryptedKeyId" (gethash "reencryptedKeyId" status)
     "keyCount" (length (gethash "keys" status #())))))

(defun run-secrets-encrypt-command (options &optional (output *standard-output*))
  "Apply one offline state-directory Secret-encryption operation and print status."
  (let ((store (open-store (getf options :state-directory))))
    (case (getf options :command)
      (:secrets-encrypt-status)
      (:secrets-encrypt-enable (enable-secret-encryption store))
      (:secrets-encrypt-disable (disable-secret-encryption store))
      (:secrets-encrypt-prepare (prepare-secret-encryption-key store))
      (:secrets-encrypt-promote (promote-secret-encryption-key store))
      (:secrets-encrypt-reencrypt (reencrypt-secrets store))
      (:secrets-encrypt-finalize (finalize-secret-encryption-key store))
      (otherwise (error "invalid secrets-encrypt command")))
    (com.inuoe.jzon:stringify (secret-encryption-status-json store) :stream output)
    (terpri output)
    (finish-output output)
    0))
