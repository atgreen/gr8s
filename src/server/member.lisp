;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; `gr8s member`: the HA control-plane membership for operators (podster-9x6).
;;;; `list` shows every durable member with its role, address and contact state
;;;; -- a voter that has never been heard from is a ghost, holding a quorum
;;;; vote it can never cast. `remove NAME` proposes dropping a member through
;;;; the leader; it commits once the remaining voters acknowledge it, so it
;;;; cures a ghost only while the survivors still hold a quorum. When they do
;;;; not, `gr8s serve --cluster-reset` is the remaining escape hatch (see
;;;; docs/backup-restore.md).

(in-package #:gr8s.server)

(defun parse-member-subcommand-options (arguments command)
  (let ((options (list :command command
                       :kubeconfig (default-client-kubeconfig)
                       :output "text")))
    (loop while arguments
          for option = (first arguments)
          do (cond
               ((string= option "--kubeconfig")
                (setf (getf options :kubeconfig) (option-value arguments option)
                      arguments (cddr arguments)))
               ((string= option "--output")
                (let ((value (option-value arguments option)))
                  (unless (member value '("text" "json") :test #'equal)
                    (error "member --output must be text or json"))
                  (setf (getf options :output) value arguments (cddr arguments))))
               (t (error "unknown member option: ~A" option))))
    options))

(defun parse-member-options (arguments)
  "Parse `gr8s member' ARGUMENTS: `list' (the default) or `remove NAME'."
  (let ((action (first arguments)))
    (cond
      ((or (null action) (string= action "list"))
       (parse-member-subcommand-options (rest arguments) :member-list))
      ((string= action "remove")
       (let ((name (second arguments)))
         (unless (and (stringp name) (plusp (length name))
                      (not (uiop:string-prefix-p "--" name)))
           (error "member remove requires a member name"))
         (let ((options (parse-member-subcommand-options (cddr arguments) :member-remove)))
           (setf (getf options :name) name)
           options)))
      (t (error "unknown member command: ~A" action)))))

(defun member-api-error-message (body status)
  (or (and (hash-table-p body)
           (let ((message (gethash "message" body)))
             (and (stringp message) (plusp (length message)) message)))
      (format nil "the API returned HTTP ~D" status)))

(defun run-member-list-command (options &optional (output *standard-output*))
  "Print the control-plane membership; exit 0, or 1 when any member is a ghost."
  (let ((config (read-debug-kubeconfig (getf options :kubeconfig))))
    (multiple-value-bind (body status)
        (debug-api-request-json config "GET" "/apis/gr8s.io/v1/controlplanemembers")
      (unless (= status 200)
        (error (if (= status 404)
                   "this cluster has no HA control plane (serve runs without --raft-init or --join)"
                   (member-api-error-message body status))))
      (if (equal "json" (getf options :output))
          (progn (com.inuoe.jzon:stringify body :stream output)
                 (terpri output) (finish-output output) 0)
          (let ((items (coerce (gethash "items" body #()) 'list))
                (ghosts 0))
            (format output "~&~12A ~8A ~22A ~12A ~A~%" "MEMBER" "ROLE" "ADDRESS" "CONTACT" "LEADER")
            (dolist (item items)
              (let* ((spec (gethash "spec" item))
                     (item-status (gethash "status" item))
                     (contact (gethash "contact" item-status)))
                (when (equal contact "never-heard") (incf ghosts))
                (format output "~12A ~8A ~22A ~12A ~A~%"
                        (gethash "name" (gethash "metadata" item))
                        (gethash "role" spec)
                        (or (gethash "address" spec) "-")
                        contact
                        (if (eq t (gethash "leader" item-status)) "yes" ""))))
            (when (plusp ghosts)
              (format output "~%~D member~:P never heard from: if permanently gone, remove with `gr8s member remove NAME`; without a quorum of live voters, see --cluster-reset in docs/backup-restore.md~%"
                      ghosts))
            (finish-output output)
            (if (plusp ghosts) 1 0))))))

(defun run-member-remove-command (options &optional (output *standard-output*))
  "Propose removing a member; follows one leader redirect. Exit 0 once proposed."
  (let ((config (read-debug-kubeconfig (getf options :kubeconfig)))
        (target (format nil "/apis/gr8s.io/v1/controlplanemembers/~A" (getf options :name))))
    (multiple-value-bind (body status headers) (debug-api-request-json config "DELETE" target)
      (when (member status '(307 308))
        ;; A follower redirects writes to the leader; retry there once with
        ;; the same credentials -- the cluster CA already vouches for every
        ;; member's API certificate.
        (let ((location (cdr (assoc :location headers))))
          (unless location
            (error "this member is not the Raft leader and named no leader to retry at"))
          (let ((follow (copy-list config)))
            (setf (getf follow :server) location)
            (multiple-value-setq (body status) (debug-api-request-json follow "DELETE" "")))))
      (unless (= status 200)
        (error (if (= status 404)
                   (format nil "control-plane member ~A was not found" (getf options :name))
                   (member-api-error-message body status))))
      (if (equal "json" (getf options :output))
          (progn (com.inuoe.jzon:stringify body :stream output)
                 (terpri output))
          (format output "~A~%" (member-api-error-message body status)))
      (finish-output output)
      0)))
