;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Order a cluster's hosts for a rolling upgrade, and refuse one that isn't safe
;;;; (podster-igs.7). A host is one gr8s process: a control-plane member, which may
;;;; run its node's agent too, or a worker's agent. The order is the one an operator
;;;; follows by hand: the voters one at a time, the leader last, after handing its
;;;; leadership to an upgraded voter; then the workers.
;;;;
;;;; Votes decide what is safe. While a voter restarts it doesn't vote, so a voter is
;;;; upgraded only if the votes still cast without it make a quorum: with three votes
;;;; and one voter already down, upgrading another would stop the cluster. The
;;;; witness votes too, but has no API to upgrade it through: it is upgraded by hand,
;;;; and it applies no log, so a release's formats don't concern it. A worker that is
;;;; away is upgraded when it comes back (podster-igs.8).

(in-package #:gr8s.upgrade)

(defun host-votes-p (host) (member (getf host :role) '("voter" "witness") :test #'equal))

(defun host-voting-p (host)
  "Whether HOST, a voter or witness, is voting now: the leader hears from it."
  (and (host-votes-p host) (member (getf host :contact) '("self" "in-contact") :test #'equal)))

(defun host-at-version-p (host target)
  (equal (getf host :version) target))

(defun plan-cluster-upgrade (hosts target &key allow-downgrade allow-quorum-loss)
  "Order HOSTS for an upgrade to release TARGET. A host is a plist: :name; :role
\"voter\", \"witness\" or NIL for a worker; :leader; :contact, as the leader sees a
member; :ready, whether its node is Ready (T for a member without one); :version,
NIL when it can't say. Return (values steps problems). A step is a plist of :host
and :action -- :upgrade, :skip, :manual or :on-reconnect -- with :transfer-to, the
voter to hand the leadership to first, and :reason. PROBLEMS are why the upgrade
should not start; none means it may."
  (let* ((target-version (or (parse-gr8s-version target) (upgrade-fail "~S is not a gr8s version" target)))
         (votes (count-if #'host-votes-p hosts))
         (quorum (1+ (floor votes 2)))
         (voting (count-if #'host-voting-p hosts))
         (steps nil) (problems nil))
    (flet ((add-step (host action &rest more)
             (push (list* :host (getf host :name) :action action more) steps))
           (problem (control &rest arguments)
             (push (apply #'format nil control arguments) problems)))
      (when (gr8s-version-dev-p target-version)
        (problem "~A is not a release" target))
      (dolist (host hosts)
        (when (and (not allow-downgrade) (eql 1 (compare-gr8s-versions (getf host :version) target)))
          (problem "~A runs ~A, newer than ~A; a downgrade is a rollback" (getf host :name) (getf host :version) target)))
      (when (and (plusp votes) (< voting quorum))
        (problem "only ~D of ~D votes are cast, and quorum needs ~D: the control plane can't commit anything now"
                 voting votes quorum))
      (let* ((voters (remove-if-not (lambda (host) (equal "voter" (getf host :role))) hosts))
             (followers (sort (remove-if (lambda (host) (getf host :leader)) voters) #'string< :key (lambda (host) (getf host :name))))
             (leader (find-if (lambda (host) (getf host :leader)) voters))
             (upgraded-voter nil))
        (dolist (host (append followers (and leader (list leader))))
          (cond
            ((host-at-version-p host target)
             (add-step host :skip :reason "runs the release already")
             (setf upgraded-voter (or upgraded-voter host)))
            ((not (host-voting-p host))
             (add-step host :manual :reason (format nil "the leader can't reach it (~A)" (getf host :contact))))
            (t
             (when (and (< (1- voting) quorum) (not allow-quorum-loss))
               (problem "upgrading ~A would leave ~D of ~D votes while it restarts, and quorum needs ~D"
                        (getf host :name) (1- voting) votes quorum))
             (if (eq host leader)
                 (let ((successor (or upgraded-voter
                                      (find-if #'host-voting-p followers))))
                   (if successor
                       (add-step host :upgrade :transfer-to (getf successor :name))
                       (add-step host :upgrade :reason "the only voter: the API is away while it restarts")))
                 (add-step host :upgrade))
             (unless (eq host leader) (setf upgraded-voter (or upgraded-voter host)))))))
      (let ((voter-steps (nreverse steps)) (witness-steps nil) (agent-steps nil))
        (setf steps nil)
        (dolist (host (remove-if-not (lambda (host) (equal "witness" (getf host :role))) hosts))
          (add-step host :manual :reason "a witness, with no API to upgrade it through"))
        (setf witness-steps (nreverse steps) steps nil)
        (dolist (host (sort (remove-if (lambda (host) (getf host :role)) (copy-list hosts)) #'string<
                            :key (lambda (host) (getf host :name))))
          (cond ((host-at-version-p host target) (add-step host :skip :reason "runs the release already"))
                ((not (getf host :ready)) (add-step host :on-reconnect :reason "its node is not Ready: it upgrades when it returns"))
                (t (add-step host :upgrade))))
        (setf agent-steps (nreverse steps))
        ;; Agents follow the control plane up, and lead it down: a newer control plane
        ;; works with older agents, and an older one can't send an upgrade at all.
        (values (if (some (lambda (host) (eql 1 (compare-gr8s-versions (getf host :version) target))) hosts)
                    (append agent-steps witness-steps voter-steps)
                    (append voter-steps witness-steps agent-steps))
                (nreverse problems))))))
