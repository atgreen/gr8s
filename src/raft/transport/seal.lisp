;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Keep the content of the log from a witness (podster-00c).
;;;;
;;;; A witness must store the entries it acknowledges. A write is committed once
;;;; the leader and the witness hold it, so if that leader then fails the witness
;;;; has the only other copy, and hands it to the surviving voter (podster-f15).
;;;; But a witness is meant to run on a machine that is trusted less than a
;;;; control-plane node, such as a firewall, and a log entry is a store write in
;;;; full: Secret contents and signing keys among them.
;;;;
;;;; So a leader sends a witness each command encrypted under a key that only
;;;; members holding the cluster CA key can derive. Voters hold that key and
;;;; witnesses are never given it. The witness stores and counts the entry as
;;;; before, and can return it, but cannot read it. A voter that receives a sealed
;;;; entry opens it before the entry reaches its log.
;;;;
;;;; The seal is AES-256-GCM over the command as printed on the wire, bound to the
;;;; entry's index and term. A voter therefore knows that an entry a witness hands
;;;; it is one that a voter sealed for exactly that position, and accepts nothing
;;;; else from a witness except the barrier a witness appends when it leads.
;;;;
;;;; Membership changes and barriers stay readable: a witness has to follow the
;;;; membership, and neither carries application data.

(in-package #:gr8s.raft.transport)

(defparameter +raft-seal-context+ "gr8s raft log entries sealed against witnesses v1")

(define-condition raft-seal-error (error)
  ((reason :initarg :reason :reader raft-seal-error-reason))
  (:report (lambda (condition stream)
             (format stream "gr8s raft: ~A" (raft-seal-error-reason condition)))))

(defstruct (raft-seal-key (:constructor %make-raft-seal-key))
  octets
  ;; Names the key without revealing it, so that a seal made under another key
  ;; is reported as that and not as a corrupt entry.
  id)

(defmethod print-object ((key raft-seal-key) stream)
  (print-unreadable-object (key stream :type t) (format stream "~A" (raft-seal-key-id key))))

(defun make-raft-seal-key (secret)
  "Derive the sealing key from SECRET, the text of the cluster CA private key.
Every member that holds the CA key derives the same key; a witness holds neither."
  (let ((hmac (ironclad:make-hmac
               (babel:string-to-octets
                (remove-if (lambda (character) (member character '(#\Space #\Tab #\Newline #\Return)))
                           secret)
                :encoding :utf-8)
               :sha256)))
    (ironclad:update-hmac hmac (babel:string-to-octets +raft-seal-context+ :encoding :utf-8))
    (let ((octets (ironclad:hmac-digest hmac)))
      (%make-raft-seal-key
       :octets octets
       :id (subseq (ironclad:byte-array-to-hex-string (ironclad:digest-sequence :sha256 octets)) 0 16)))))

(defun raft-credentials-seal-key (credentials)
  "The sealing key of a member whose CREDENTIALS include the cluster CA key, else NIL."
  (let ((pki (and credentials (gr8s.security::raft-credentials-pki credentials))))
    (when pki
      (make-raft-seal-key
       (uiop:read-file-string (gr8s.security::cluster-pki-ca-private-key-path pki))))))

(defun raft-sealed-command-p (command)
  (and (consp command) (eq :sealed (first command))))

(defun raft-readable-by-witness-p (command)
  "True for the commands a witness is sent as they are."
  (or (equal command '(:raft-barrier))
      (and (consp command) (eq :raft-config (first command)))))

(defun raft-seal-associated-data (index term)
  (babel:string-to-octets (format nil "~D ~D" index term) :encoding :utf-8))

(defun raft-seal-command (key index term command)
  "Return COMMAND sealed for the entry at INDEX and TERM: (:sealed key-id text)."
  (let* ((nonce (ironclad:random-data 12))
         (mode (ironclad:make-authenticated-encryption-mode
                :gcm :cipher-name :aes :key (raft-seal-key-octets key) :initialization-vector nonce))
         (plaintext (with-standard-io-syntax
                      (let ((*print-readably* nil) (*print-circle* nil) (*print-pretty* nil))
                        (babel:string-to-octets (prin1-to-string command) :encoding :utf-8))))
         (ciphertext (ironclad:encrypt-message
                      mode plaintext :associated-data (raft-seal-associated-data index term)))
         (tag (ironclad:produce-tag mode)))
    (list :sealed (raft-seal-key-id key)
          (ag-grpc:base64-encode (concatenate '(vector (unsigned-byte 8)) nonce ciphertext tag)))))

(defun raft-unseal-command (key index term sealed)
  "Return the command SEALED holds, or signal RAFT-SEAL-ERROR unless it was sealed
under KEY for the entry at INDEX and TERM."
  (flet ((refuse (control &rest arguments)
           (error 'raft-seal-error
                  :reason (format nil "entry ~D of term ~D ~?" index term control arguments))))
    (destructuring-bind (&optional marker id text &rest more) sealed
      (unless (and (eq :sealed marker) (stringp id) (stringp text) (null more))
        (refuse "is not a sealed command"))
      (unless (equal id (raft-seal-key-id key))
        (refuse "was sealed under key ~A; this member derives key ~A from its cluster CA key"
                id (raft-seal-key-id key)))
      (let ((octets (handler-case (ag-grpc:base64-decode text)
                      (error () (refuse "has a seal that is not base64")))))
        (unless (>= (length octets) 28) (refuse "has a seal that is too short"))
        (let* ((end (- (length octets) 16))
               (mode (ironclad:make-authenticated-encryption-mode
                      :gcm :cipher-name :aes :key (raft-seal-key-octets key)
                      :initialization-vector (subseq octets 0 12)
                      :tag (subseq octets end)))
               (plaintext (handler-case
                              (ironclad:decrypt-message
                               mode (subseq octets 12 end)
                               :associated-data (raft-seal-associated-data index term))
                            (error () (refuse "has a seal that does not verify")))))
          (with-standard-io-syntax
            (let ((*read-eval* nil))
              (values (read-from-string (babel:octets-to-string plaintext :encoding :utf-8))))))))))

(defun raft-map-message-commands (message function)
  "MESSAGE with each entry's command replaced by (FUNCTION entry), sharing what is unchanged."
  (let* ((entries (getf message :entries))
         (mapped (mapcar (lambda (entry)
                           (let ((command (funcall function entry)))
                             (if (eq command (raft-entry-command entry))
                                 entry
                                 (make-raft-entry :index (raft-entry-index entry)
                                                  :term (raft-entry-term entry) :command command))))
                         entries)))
    (if (every #'eq entries mapped)
        message
        (let ((copy (copy-list message)))
          (setf (getf copy :entries) mapped)
          copy))))

(defun raft-seal-message (key message)
  "MESSAGE as a member without the sealing key may receive it."
  (if (and key (eq :append-entries (getf message :type)) (getf message :entries))
      (raft-map-message-commands
       message
       (lambda (entry)
         (let ((command (raft-entry-command entry)))
           (if (or (raft-readable-by-witness-p command) (raft-sealed-command-p command))
               command
               (raft-seal-command key (raft-entry-index entry) (raft-entry-term entry) command)))))
      message))

(defun raft-open-message (key message from-witness)
  "MESSAGE as this member's log may hold it. A member with no KEY is a witness and
keeps what it is given. A member with one opens every sealed command, and from a
witness accepts only sealed commands and barriers: a witness has nothing of its
own to say, so anything else it sends was not written by a voter."
  (if (and key (eq :append-entries (getf message :type)) (getf message :entries))
      (raft-map-message-commands
       message
       (lambda (entry)
         (let ((command (raft-entry-command entry)))
           (cond ((raft-sealed-command-p command)
                  (raft-unseal-command key (raft-entry-index entry) (raft-entry-term entry) command))
                 ((and from-witness (not (equal command '(:raft-barrier))))
                  (error 'raft-seal-error
                         :reason (format nil "witness ~A sent entry ~D of term ~D unsealed; only a voter's sealed entries are accepted from a witness"
                                         (getf message :from) (raft-entry-index entry) (raft-entry-term entry))))
                 (t command)))))
      message))

(defun raft-peer-holds-seal-key-p (node id)
  "True when member ID was given the cluster CA key: a voter, or a learner that
joined to become one. A witness, and a learner that joined as one, were not."
  (let ((role (or (gethash id (raft-node-roles node)) (gethash id (raft-node-pending-members node)))))
    (or (eq role :voter)
        (and (eq role :learner) (eq :voter (gethash id (raft-node-promotion-intents node)))))))
