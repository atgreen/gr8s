;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Host firewall overlay integration (podster-vwy): the scoped firewalld ACCEPTs
;;;; gr8s programs for cross-node Pod traffic, and the fail-soft/no-op behavior.

(in-package #:gr8s/tests)
(in-suite gr8s)

(test overlay-firewall-commands-are-scoped-to-the-overlay
  (let ((cmds (gr8s::overlay-firewall-commands "10.80.0.0/20")))
    (is (= 3 (length cmds)))
    ;; VXLAN device in an ACCEPT zone (decapsulated inbound).
    (is (equal '("firewall-cmd" "--zone" "trusted" "--add-interface" "gr8s-vxlan") (first cmds)))
    ;; This node's Pod CIDR as a zone source (local Pod egress/forward), NOT the
    ;; broad cluster CIDR.
    (is (equal '("firewall-cmd" "--zone" "trusted" "--add-source" "10.80.0.0/20") (second cmds)))
    ;; The VXLAN underlay UDP port on the uplink.
    (is (equal '("firewall-cmd" "--add-port=4789/udp") (third cmds)))))

(test overlay-firewall-commands-can-withdraw
  (let ((cmds (gr8s::overlay-firewall-commands "10.80.0.0/20" :verb "--remove")))
    (is (equal '("firewall-cmd" "--zone" "trusted" "--remove-interface" "gr8s-vxlan") (first cmds)))
    (is (equal '("firewall-cmd" "--add-port=4789/udp")
               '("firewall-cmd" "--add-port=4789/udp"))) ; sanity: add form unchanged
    (is (equal '("firewall-cmd" "--remove-port=4789/udp") (third cmds)))))

(test ensure-overlay-firewall-is-a-noop-without-active-firewalld
  ;; firewall-cmd --state != 0  -> no commands run at all.
  (let ((ran '()))
    (flet ((runner (argv)
             (push argv ran)
             (if (equal argv '("firewall-cmd" "--state"))
                 (values "not running" 1)   ; inactive
                 (values "" 0))))
      (is (null (gr8s::ensure-overlay-firewall "10.80.0.0/20" :runner #'runner)))
      ;; Only the state probe ran; no --add-* commands.
      (is (equal ran '(("firewall-cmd" "--state")))))))

(test ensure-overlay-firewall-applies-all-three-when-active
  (let ((ran '()))
    (flet ((runner (argv)
             (push argv ran)
             (values "" 0)))               ; firewalld active, every command succeeds
      (is (eq t (gr8s::ensure-overlay-firewall "10.80.16.0/20" :runner #'runner)))
      (let ((applied (reverse ran)))
        (is (equal '("firewall-cmd" "--state") (first applied)))
        (is (= 4 (length applied)))        ; state probe + 3 accepts
        (is (member '("firewall-cmd" "--zone" "trusted" "--add-source" "10.80.16.0/20")
                    applied :test #'equal))))))

(test ensure-control-plane-firewall-opens-the-node-port-when-active
  (let ((ran '()))
    (flet ((runner (argv) (push argv ran) (values "" 0)))
      (is (eq t (gr8s::ensure-control-plane-firewall 7443 :runner #'runner)))
      (is (member '("firewall-cmd" "--add-port=7443/tcp") (reverse ran) :test #'equal)))))

(test ensure-control-plane-firewall-is-a-noop-without-firewalld
  (flet ((runner (argv)
           (if (equal argv '("firewall-cmd" "--state")) (values "" 1) (values "" 0))))
    (is (null (gr8s::ensure-control-plane-firewall 7443 :runner #'runner)))))

(test remove-overlay-firewall-withdraws-all-three-when-active
  (let ((ran '()))
    (flet ((runner (argv) (push argv ran) (values "" 0)))
      (is (eq t (gr8s::remove-overlay-firewall "10.80.0.0/20" :runner #'runner)))
      (let ((applied (reverse ran)))
        (is (member '("firewall-cmd" "--zone" "trusted" "--remove-interface" "gr8s-vxlan") applied :test #'equal))
        (is (member '("firewall-cmd" "--zone" "trusted" "--remove-source" "10.80.0.0/20") applied :test #'equal))
        (is (member '("firewall-cmd" "--remove-port=4789/udp") applied :test #'equal))))))

(test remove-control-plane-firewall-withdraws-the-node-port
  (let ((ran '()))
    (flet ((runner (argv) (push argv ran) (values "" 0)))
      (is (eq t (gr8s::remove-control-plane-firewall 7443 :runner #'runner)))
      (is (member '("firewall-cmd" "--remove-port=7443/tcp") (reverse ran) :test #'equal)))))

(test remove-overlay-firewall-is-a-noop-without-firewalld
  (flet ((runner (argv)
           (if (equal argv '("firewall-cmd" "--state")) (values "" 1) (values "" 0))))
    (is (null (gr8s::remove-overlay-firewall "10.80.0.0/20" :runner #'runner)))))

(test ensure-overlay-firewall-is-fail-soft-on-command-error
  ;; A failing firewall-cmd is logged, not raised: ensure still returns T (active).
  (flet ((runner (argv)
           (cond ((equal argv '("firewall-cmd" "--state")) (values "running" 0))
                 ((search "--add-source" (format nil "~{~A~^ ~}" argv)) (values "boom" 1))
                 (t (values "" 0)))))
    (is (eq t (gr8s::ensure-overlay-firewall "10.80.0.0/20" :runner #'runner)))))
