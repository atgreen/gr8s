;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; The HA control-plane membership as an API surface (podster-9x6):
;;;;   GET    /apis/gr8s.io/v1/controlplanemembers       the membership, with
;;;;          each member's role, address, API URL, leadership and contact state
;;;;   DELETE /apis/gr8s.io/v1/controlplanemembers/<id>  propose removing a
;;;;          member (the usual cure for a ghost: a member whose host and state
;;;;          are gone while a quorum of the remaining voters is still alive)
;;;; Followers redirect the DELETE to the leader through the ordinary mutating
;;;; redirect; a cluster whose quorum is gone cannot commit the removal, and
;;;; that is what `serve --cluster-reset` is for.

(in-package #:gr8s.apiserver)

(defun control-plane-membership-fn-or-404 ()
  (let ((acceptor hunchentoot:*acceptor*))
    (or (and (typep acceptor 'gr8s-acceptor)
             (acceptor-control-plane-membership-fn acceptor))
        (core-resource-error 404 "NotFound" "this cluster has no HA control-plane members"))))

(defun control-plane-member-object (entry)
  "One ControlPlaneMember object from a gr8s.ha membership :MEMBERS entry."
  (let ((address (getf entry :address)))
    (core-object
     "apiVersion" "gr8s.io/v1" "kind" "ControlPlaneMember"
     "metadata" (core-object "name" (getf entry :id))
     "spec" (let ((spec (core-object "role" (string-downcase (symbol-name (getf entry :role))))))
              (when address
                (setf (gethash "address" spec) (format nil "~A:~D" (first address) (second address))))
              (when (getf entry :api-url)
                (setf (gethash "apiURL" spec) (getf entry :api-url)))
              spec)
     "status" (let ((status (core-object
                             "contact" (ecase (getf entry :contact)
                                         (:self "self")
                                         (:in-contact "in-contact")
                                         (:never-heard "never-heard")
                                         (:unknown "unknown")))))
                (when (getf entry :leader) (setf (gethash "leader" status) t))
                status))))

(defun serve-control-plane-members-list ()
  "Answer GET /apis/gr8s.io/v1/controlplanemembers."
  (unless *authenticated-api-identity*
    (core-resource-error 403 "Forbidden" "control-plane membership requires authenticated Kubernetes API access"))
  (let* ((membership (funcall (control-plane-membership-fn-or-404) :list))
         (list-object (core-object
                       "apiVersion" "gr8s.io/v1" "kind" "ControlPlaneMemberList"
                       "items" (map 'vector #'control-plane-member-object
                                    (getf membership :members)))))
    (when (getf membership :leader)
      (setf (gethash "leader" list-object) (getf membership :leader)))
    (json-response list-object)))

(defun serve-control-plane-member-delete (path)
  "Answer DELETE /apis/gr8s.io/v1/controlplanemembers/<id>: propose the removal
   on the leader. The change commits once a quorum of the REMAINING voters
   acknowledges it, so removing a dead member needs the survivors to still hold
   a quorum."
  (unless *authenticated-api-identity*
    (core-resource-error 403 "Forbidden" "control-plane membership requires authenticated Kubernetes API access"))
  (let* ((membership-fn (control-plane-membership-fn-or-404))
         (id (first (last (remove "" (uiop:split-string path :separator '(#\/)) :test #'equal))))
         (membership (funcall membership-fn :list)))
    (unless (find id (getf membership :members)
                  :key (lambda (entry) (getf entry :id)) :test #'equal)
      (core-resource-error 404 "NotFound" "control-plane member ~A was not found" id))
    (multiple-value-bind (proposed reason) (funcall membership-fn :remove id)
      (cond
        (proposed
         (json-response
          (core-object "apiVersion" "v1" "kind" "Status" "status" "Success"
                       "message" (format nil "removal of control-plane member ~A proposed; it completes when the remaining voters commit it" id))))
        ((eq reason :cannot-remove-self)
         (core-resource-error 400 "BadRequest"
                              "a member cannot remove itself; run the removal from another member"))
        (t
         (core-resource-error 409 "Conflict" "cannot remove ~A right now: ~A~@[~A~]"
                              id (string-downcase (symbol-name (or reason :unavailable)))
                              (when (eq reason :change-in-flight)
                                " (another membership change has not committed yet)")))))))
