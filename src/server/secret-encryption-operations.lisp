;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0

(in-package #:gr8s.server)

(defun parse-kms-plugin-option (value)
  "A KMS v2 plugin from --kms-plugin NAME=ENDPOINT (podster-qyp9)."
  (let ((separator (position #\= value)))
    (unless (and separator (plusp separator) (< (1+ separator) (length value)))
      (error "--kms-plugin wants NAME=ENDPOINT, as gr8s=unix:///run/gr8s/kms.sock, not ~S" value))
    (gr8s.protocol::make-kms-plugin (subseq value 0 separator) (subseq value (1+ separator)))))

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
                         :state-directory (namestring (default-state-directory))
                         :kms-plugins '() :kms nil))
          (arguments (rest arguments)))
      (loop while arguments
            for option = (first arguments)
            do (cond
                 ((string= option "--state-directory")
                  (setf (getf options :state-directory) (option-value arguments option)
                        arguments (cddr arguments)))
                 ;; The plugins the store's keys need, and the one a new key should use.
                 ((string= option "--kms-plugin")
                  (push (parse-kms-plugin-option (option-value arguments option)) (getf options :kms-plugins))
                  (setf arguments (cddr arguments)))
                 ((string= option "--kms")
                  (setf (getf options :kms) (option-value arguments option)
                        arguments (cddr arguments)))
                 (t (error "unknown secrets-encrypt option: ~A" option))))
      (when (and (getf options :kms)
                 (not (find (getf options :kms) (getf options :kms-plugins)
                            :key #'gr8s.protocol::kms-plugin-name :test #'equal)))
        (error "--kms ~A names no --kms-plugin" (getf options :kms)))
      (when (and (getf options :kms) (not (member command '(:secrets-encrypt-enable :secrets-encrypt-prepare))))
        (error "--kms is for enable and prepare"))
      options)))

(defun secret-encryption-status-json (store)
  "Return the stable, non-key-material operator view of encryption state."
  (let* ((status (secret-encryption-status store))
         (active (and (gethash "activeKeyId" status)
                      (gr8s.resources::secret-encryption-key-record status (gethash "activeKeyId" status)))))
    (core-object
     "activeKeyProvider" (and active (if (gr8s.resources::kms-key-record-p active)
                                         (format nil "kms-v2:~A" (gethash "kmsName" active))
                                         "cluster-identity"))
     "activeKmsKeyId" (and active (gethash "kmsKeyId" active))
     "enabled" (if (gethash "enabled" status) t nil)
     "phase" (gethash "phase" status "disabled")
     "activeKeyId" (gethash "activeKeyId" status)
     "preparedKeyId" (gethash "preparedKeyId" status)
     "reencryptedKeyId" (gethash "reencryptedKeyId" status)
     "keyCount" (length (gethash "keys" status #())))))

(defun run-secrets-encrypt-command (options &optional (output *standard-output*))
  "Apply one offline state-directory Secret-encryption operation and print status."
  (mapc #'gr8s.resources::register-kms-plugin (getf options :kms-plugins))
  (let ((store (open-store (getf options :state-directory))))
    (case (getf options :command)
      (:secrets-encrypt-status)
      (:secrets-encrypt-enable (enable-secret-encryption store :kms (getf options :kms)))
      (:secrets-encrypt-disable (disable-secret-encryption store))
      (:secrets-encrypt-prepare (prepare-secret-encryption-key store :kms (getf options :kms)))
      (:secrets-encrypt-promote (promote-secret-encryption-key store))
      (:secrets-encrypt-reencrypt (reencrypt-secrets store))
      (:secrets-encrypt-finalize (finalize-secret-encryption-key store))
      (otherwise (error "invalid secrets-encrypt command")))
    (com.inuoe.jzon:stringify (secret-encryption-status-json store) :stream output)
    (terpri output)
    (finish-output output)
    0))

(defparameter +kms-maintenance-seconds+ 60
  "How often serve asks its KMS plugins how they are, as kube-apiserver does.")

(defun start-kms-maintenance (store ha)
  "When serve has KMS plugins, check them every minute (the kms-providers health check
reads what was found) and, on a standalone server or the HA leader, follow a rotated
KMS key with a new data key (podster-qyp9). Returns the thread, or NIL."
  (when (plusp (hash-table-count gr8s.resources::*kms-plugins*))
    (gr8s.resources::refresh-kms-plugin-health)
    (bt:make-thread
     (lambda ()
       (loop
         (sleep +kms-maintenance-seconds+)
         (handler-case
             (progn
               (gr8s.resources::refresh-kms-plugin-health)
               (when (or (null ha) (gr8s.ha::ha-control-plane-leader-p ha))
                 (let ((rotated (gr8s.resources::rotate-kms-secret-key store)))
                   (when rotated
                     (format *error-output* "gr8s: the KMS key changed; Secrets are now written with key ~A~%" rotated)))))
           (error (condition)
             (format *error-output* "gr8s: KMS upkeep failed: ~A~%" condition)))))
     :name "gr8s KMS upkeep")))

(defparameter +kms-plugin-wait-seconds+ 60
  "How long a new cluster waits for its KMS plugin to answer before refusing to start.")

(defun new-cluster-store-p (store)
  "True when STORE has never been written: no checkpoint and no journal."
  (not (or (probe-file (gr8s.resources::core-resource-state-path store))
           (probe-file (gr8s.resources::core-journal-path store)))))

(defun encrypt-new-cluster-secrets (store options)
  "With --encrypt-secrets-with NAME, have a new standalone cluster encrypt its Secrets
from the start with KMS plugin NAME (podster-wsmz). An existing cluster is left as it
is, and so is one joining or starting HA, whose members must all reach the same KMS
first. A plugin that doesn't answer stops the start: a new cluster never writes a
Secret in plaintext because its plugin was late."
  (let ((name (getf options :encrypt-secrets-with)))
    (when (and name (new-cluster-store-p store)
               (not (getf options :raft-init)) (not (getf options :raft-join))
               (not (gr8s.resources::secret-encryption-enabled-p store)))
      (let ((plugin (gr8s.resources::kms-plugin-named name)))
        (loop with deadline = (+ (get-universal-time) +kms-plugin-wait-seconds+)
              for (healthy key-id why) = (multiple-value-list (gr8s.protocol::kms-plugin-status plugin))
              until healthy
              do (when (> (get-universal-time) deadline)
                   (error "KMS plugin ~A at ~A didn't answer (~A); a new cluster encrypts its Secrets with it, so start it first (systemctl start gr8s-kms)"
                          name (gr8s.protocol::kms-plugin-endpoint plugin) why))
                 (sleep 1)
              finally (gr8s.resources::enable-secret-encryption store :kms name)
                      (format t "gr8s: Secrets are encrypted at rest with KMS plugin ~A (key ~A)~%" name key-id))))))
