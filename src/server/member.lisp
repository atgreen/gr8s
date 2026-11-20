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
;;;; docs/backup-restore.md). `transfer-leadership NAME` has the leader hand its
;;;; leadership to voter NAME, so that the leader can be restarted without the
;;;; cluster waiting out an election (podster-f9u).

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

(defun parse-named-member-options (arguments command)
  "Parse `gr8s member ACTION NAME [OPTIONS]', where ARGUMENTS begin at ACTION."
  (let ((name (second arguments)))
    (unless (and (stringp name) (plusp (length name))
                 (not (uiop:string-prefix-p "--" name)))
      (error "member ~A requires a member name" (first arguments)))
    (let ((options (parse-member-subcommand-options (cddr arguments) command)))
      (setf (getf options :name) name)
      options)))

(defun parse-member-options (arguments)
  "Parse `gr8s member' ARGUMENTS: `list' (the default), `remove NAME' or
   `transfer-leadership NAME'."
  (let ((action (first arguments)))
    (cond
      ((or (null action) (string= action "list"))
       (parse-member-subcommand-options (rest arguments) :member-list))
      ((string= action "remove")
       (parse-named-member-options arguments :member-remove))
      ((string= action "transfer-leadership")
       (parse-named-member-options arguments :member-transfer-leadership))
      (t (error "unknown member command: ~A" action)))))

(defun member-api-error-message (body status)
  (or (and (hash-table-p body)
           (let ((message (gethash "message" body)))
             (and (stringp message) (plusp (length message)) message)))
      (format nil "the API returned HTTP ~D" status)))

(defun run-member-list-command (options &optional (output *standard-output*))
  "Print the control-plane membership; exit 0, or 1 when any member is a ghost."
  (call-with-debug-kubeconfig
   (getf options :kubeconfig)
   (lambda (config)
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
                (ghosts 0)
                (unknowns 0))
            (format output "~&~12A ~8A ~22A ~12A ~A~%" "MEMBER" "ROLE" "ADDRESS" "CONTACT" "LEADER")
            (dolist (item items)
              (let* ((spec (gethash "spec" item))
                     (item-status (gethash "status" item))
                     (contact (gethash "contact" item-status)))
                (when (equal contact "never-heard") (incf ghosts))
                (when (equal contact "unknown") (incf unknowns))
                (format output "~12A ~8A ~22A ~12A ~A~%"
                        (gethash "name" (gethash "metadata" item))
                        (gethash "role" spec)
                        (or (gethash "address" spec) "-")
                        contact
                        (if (eq t (gethash "leader" item-status)) "yes" ""))))
            (when (plusp unknowns)
              (format output "~%contact is visible only from the leader~@[ (~A)~]; query it for ghost detection~%"
                      (let ((leader (gethash "leader" body)))
                        (and (stringp leader) leader))))
            (when (plusp ghosts)
              (format output "~%~D member~:P never heard from: if permanently gone, remove with `gr8s member remove NAME`; without a quorum of live voters, see --cluster-reset in docs/backup-restore.md~%"
                      ghosts))
            (finish-output output)
            (if (plusp ghosts) 1 0)))))))

(defun member-leader-request (config method target)
  "Send METHOD to TARGET, which only the leader serves; return the parsed body and
   the status. A follower carries the request to the leader itself; one that
   cannot speak for this caller redirects instead, and the request is sent once
   more to where it points, with the same credentials -- the cluster CA already
   vouches for every member's API certificate."
  (multiple-value-bind (body status headers) (debug-api-request-json config method target)
    (when (member status '(307 308))
      (let ((location (cdr (assoc :location headers))))
        (unless location
          (error "this member is not the Raft leader and named no leader to retry at"))
        (let ((follow (copy-list config)))
          (setf (getf follow :server) location)
          (multiple-value-setq (body status) (debug-api-request-json follow method "")))))
    (values body status)))

(defun print-member-api-answer (options body status output)
  (if (equal "json" (getf options :output))
      (progn (com.inuoe.jzon:stringify body :stream output)
             (terpri output))
      (format output "~A~%" (member-api-error-message body status)))
  (finish-output output))

(defun run-member-remove-command (options &optional (output *standard-output*))
  "Propose removing a member; follows one leader redirect. Exit 0 once proposed."
  (call-with-debug-kubeconfig
   (getf options :kubeconfig)
   (lambda (config)
     (multiple-value-bind (body status)
         (member-leader-request config "DELETE"
                                (format nil "/apis/gr8s.io/v1/controlplanemembers/~A" (getf options :name)))
       (unless (= status 200)
         (error (if (= status 404)
                    (format nil "control-plane member ~A was not found" (getf options :name))
                    (member-api-error-message body status))))
       (print-member-api-answer options body status output)
       0))))

(defparameter *member-leadership-wait-seconds* 10
  "How long `gr8s member transfer-leadership` waits for the named member to lead.
A handover takes well under a second; a leader that gives up on one does so after
an election timeout, of at most two seconds.")

(defun member-await-leader (config name)
  "Wait until the membership names NAME the leader. Returns true if it did;
   otherwise NIL and the member that leads instead, if any is known."
  (loop with deadline = (+ (get-internal-real-time)
                           (* *member-leadership-wait-seconds* internal-time-units-per-second))
        for leader = (multiple-value-bind (body status)
                         (ignore-errors
                          (debug-api-request-json config "GET" "/apis/gr8s.io/v1/controlplanemembers"))
                       (and (eql status 200) (hash-table-p body) (gethash "leader" body)))
        when (equal leader name) return t
        when (>= (get-internal-real-time) deadline) return (values nil leader)
        do (sleep 0.2)))

(defun run-member-transfer-leadership-command (options &optional (output *standard-output*))
  "Have the leader hand its leadership to the named voter, and wait until that
   member leads. Exit 0 once it does."
  (call-with-debug-kubeconfig
   (getf options :kubeconfig)
   (lambda (config)
     (let ((name (getf options :name)))
       (multiple-value-bind (body status)
           (member-leader-request config "POST"
                                  (format nil "/apis/gr8s.io/v1/controlplanemembers/~A/leadership" name))
         (unless (member status '(200 202))
           (error (member-api-error-message body status)))
         ;; 202: the handover has only started, and the leader abandons one that
         ;; the member does not take up.
         (when (= status 202)
           (multiple-value-bind (leads leader) (member-await-leader config name)
             (unless leads
               (error "control-plane member ~A did not take the leadership within ~D seconds~@[; ~A leads~]"
                      name *member-leadership-wait-seconds* leader))))
         (if (equal "json" (getf options :output))
             (print-member-api-answer options body status output)
             (format output "control-plane member ~A ~:[now~;already~] leads~%" name (= status 200)))
         (finish-output output)
         0)))))
