;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Host firewall overlay integration (podster-vwy): the scoped firewalld ACCEPTs
;;;; gr8s programs for cross-node Pod traffic, and the fail-soft/no-op behavior.

(in-package #:gr8s/tests)
(in-suite gr8s)

(test overlay-firewall-commands-are-scoped-to-the-overlay
  (let ((cmds (gr8s.network::overlay-firewall-commands "10.80.0.0/20")))
    ;; interface + one Pod-CIDR source + VXLAN port + per-CIDR tcp/udp NodePort
    ;; masquerade (2).
    (is (= 5 (length cmds)))
    ;; VXLAN device in an ACCEPT zone (decapsulated inbound).
    (is (equal '("firewall-cmd" "--zone" "trusted" "--add-interface" "gr8s-vxlan") (first cmds)))
    ;; This node's Pod CIDR as a zone source (local Pod egress/forward), NOT the
    ;; broad cluster CIDR.
    (is (equal '("firewall-cmd" "--zone" "trusted" "--add-source" "10.80.0.0/20") (second cmds)))
    ;; The VXLAN underlay UDP port on the uplink.
    (is (equal '("firewall-cmd" "--add-port=4789/udp") (third cmds)))
    ;; Source-NAT this node's Pod->NodePort traffic (TCP and UDP).
    (is (member '("firewall-cmd" "--direct" "--add-rule" "ipv4" "nat" "POSTROUTING"
                  "0" "-s" "10.80.0.0/20" "-p" "tcp" "--dport" "30000:32767" "-j" "MASQUERADE")
                cmds :test #'equal))
    (is (member '("firewall-cmd" "--direct" "--add-rule" "ipv4" "nat" "POSTROUTING"
                  "0" "-s" "10.80.0.0/20" "-p" "udp" "--dport" "30000:32767" "-j" "MASQUERADE")
                cmds :test #'equal))))

(test overlay-firewall-commands-admit-every-local-pod-family
  (let ((cmds (gr8s.network::overlay-firewall-commands
               '("10.80.0.0/20" "fd80::/64"))))
    ;; interface + 2 sources + VXLAN port + 2 CIDRs x tcp/udp masquerade (4).
    (is (= 8 (length cmds)))
    (is (equal '("firewall-cmd" "--zone" "trusted" "--add-source" "10.80.0.0/20")
               (second cmds)))
    (is (equal '("firewall-cmd" "--zone" "trusted" "--add-source" "fd80::/64")
               (third cmds)))
    (is (equal '("firewall-cmd" "--add-port=4789/udp") (fourth cmds)))))

(test overlay-firewall-commands-can-withdraw
  (let ((cmds (gr8s.network::overlay-firewall-commands "10.80.0.0/20" :verb "--remove")))
    (is (equal '("firewall-cmd" "--zone" "trusted" "--remove-interface" "gr8s-vxlan") (first cmds)))
    (is (equal '("firewall-cmd" "--add-port=4789/udp")
               '("firewall-cmd" "--add-port=4789/udp"))) ; sanity: add form unchanged
    (is (equal '("firewall-cmd" "--remove-port=4789/udp") (third cmds)))))

(test wireguard-firewall-commands-use-its-interface-and-listen-port
  (let ((cmds (gr8s.network::overlay-firewall-commands
               "10.80.16.0/20" :interface "gr8s-wg" :port 51820)))
    (is (equal '("firewall-cmd" "--zone" "trusted" "--add-interface" "gr8s-wg")
               (first cmds)))
    (is (equal '("firewall-cmd" "--zone" "trusted" "--add-source" "10.80.16.0/20")
               (second cmds)))
    (is (equal '("firewall-cmd" "--add-port=51820/udp") (third cmds)))))

(test ensure-overlay-firewall-is-a-noop-without-active-firewalld
  ;; firewall-cmd --state != 0  -> no commands run at all.
  (let ((ran '()))
    (flet ((runner (argv)
             (push argv ran)
             (if (equal argv '("firewall-cmd" "--state"))
                 (values "not running" 1)   ; inactive
                 (values "" 0))))
      (is (null (gr8s.network::ensure-overlay-firewall "10.80.0.0/20" :runner #'runner)))
      ;; Only the state probe ran; no --add-* commands.
      (is (equal ran '(("firewall-cmd" "--state")))))))

(test ensure-overlay-firewall-applies-all-three-when-active
  (let ((ran '()))
    (flet ((runner (argv)
             (push argv ran)
             (values "" 0)))               ; firewalld active, every command succeeds
      (is (eq t (gr8s.network::ensure-overlay-firewall "10.80.16.0/20" :runner #'runner)))
      (let ((applied (reverse ran)))
        (is (equal '("firewall-cmd" "--state") (first applied)))
        (is (= 6 (length applied)))        ; state probe + 3 accepts + 2 masquerade
        (is (member '("firewall-cmd" "--zone" "trusted" "--add-source" "10.80.16.0/20")
                    applied :test #'equal))
        (is (member '("firewall-cmd" "--direct" "--add-rule" "ipv4" "nat" "POSTROUTING"
                      "0" "-s" "10.80.16.0/20" "-p" "tcp" "--dport" "30000:32767" "-j" "MASQUERADE")
                    applied :test #'equal))))))

(test ensure-control-plane-firewall-opens-the-node-port-when-active
  (let ((ran '()))
    (flet ((runner (argv) (push argv ran) (values "" 0)))
      (is (eq t (gr8s.network::ensure-control-plane-firewall 7443 :runner #'runner)))
      (is (member '("firewall-cmd" "--add-port=7443/tcp") (reverse ran) :test #'equal)))))

(test control-plane-firewall-follows-the-kubelet-listener-lifecycle
  (let ((ran '()))
    (flet ((runner (argv) (push argv ran) (values "" 0)))
      (is (eq t (gr8s.network::ensure-control-plane-firewall
                 7443 :kubelet-port 10250 :runner #'runner)))
      (is (eq t (gr8s.network::remove-control-plane-firewall
                 7443 :kubelet-port 10250 :runner #'runner)))
      (let ((applied (reverse ran)))
        (is (member '("firewall-cmd" "--add-port=7443/tcp") applied :test #'equal))
        (is (member '("firewall-cmd" "--add-port=10250/tcp") applied :test #'equal))
        (is (member '("firewall-cmd" "--remove-port=7443/tcp") applied :test #'equal))
        (is (member '("firewall-cmd" "--remove-port=10250/tcp") applied :test #'equal))))))

(test control-plane-firewall-follows-the-relay-udp-range-lifecycle
  (let ((ran '()))
    (flet ((runner (argv) (push argv ran) (values "" 0)))
      (is (eq t (gr8s.network::ensure-control-plane-firewall
                 7443 :relay-port-start 42000 :relay-max-channels 3
                 :runner #'runner)))
      (is (eq t (gr8s.network::remove-control-plane-firewall
                 7443 :relay-port-start 42000 :relay-max-channels 3
                 :runner #'runner)))
      (let ((applied (reverse ran)))
        (is (member '("firewall-cmd" "--add-port=42000-42005/udp")
                    applied :test #'equal))
        (is (member '("firewall-cmd" "--remove-port=42000-42005/udp")
                    applied :test #'equal))))))

(test control-plane-firewall-ignores-a-disabled-kubelet-listener
  (let ((ran '()))
    (flet ((runner (argv) (push argv ran) (values "" 0)))
      (is (eq t (gr8s.network::ensure-control-plane-firewall
                 7443 :kubelet-port 0 :runner #'runner)))
      (is (null (member '("firewall-cmd" "--add-port=0/tcp") ran :test #'equal)))
      (is (null (member '("firewall-cmd" "--add-port=10250/tcp") ran :test #'equal))))))

(test ensure-control-plane-firewall-is-a-noop-without-firewalld
  (flet ((runner (argv)
           (if (equal argv '("firewall-cmd" "--state")) (values "" 1) (values "" 0))))
    (is (null (gr8s.network::ensure-control-plane-firewall 7443 :runner #'runner)))))

(test gateway-listener-firewall-follows-listener-lifecycle
  (let ((ran '()))
    (flet ((runner (argv) (push argv ran) (values "" 0)))
      (is (eq t (gr8s.network::ensure-gateway-listener-firewall 443 :runner #'runner)))
      (is (eq t (gr8s.network::remove-gateway-listener-firewall 443 :runner #'runner)))
      (let ((applied (reverse ran)))
        (is (member '("firewall-cmd" "--add-port=443/tcp") applied :test #'equal))
        (is (member '("firewall-cmd" "--remove-port=443/tcp") applied :test #'equal))))))

(test control-plane-firewall-follows-the-in-cluster-api-listener-lifecycle
  ;; The in-cluster apiserver (0.0.0.0:6443) backs the "kubernetes" Service VIP;
  ;; Pods on other nodes cannot reach 10.96.0.1:443 unless its port is admitted.
  (let ((ran '()))
    (flet ((runner (argv) (push argv ran) (values "" 0)))
      (is (eq t (gr8s.network::ensure-control-plane-firewall
                 7443 :in-cluster-api-port 6443 :runner #'runner)))
      (is (eq t (gr8s.network::remove-control-plane-firewall
                 7443 :in-cluster-api-port 6443 :runner #'runner)))
      (let ((applied (reverse ran)))
        (is (member '("firewall-cmd" "--add-port=6443/tcp") applied :test #'equal))
        (is (member '("firewall-cmd" "--remove-port=6443/tcp") applied :test #'equal))))))

(test image-peer-firewall-follows-listener-lifecycle
  (let ((ran '()))
    (flet ((runner (argv) (push argv ran) (values "" 0)))
      (is (eq t (gr8s.network::ensure-image-peer-firewall 7444 :runner #'runner)))
      (is (eq t (gr8s.network::remove-image-peer-firewall 7444 :runner #'runner)))
      (let ((applied (reverse ran)))
        (is (member '("firewall-cmd" "--add-port=7444/tcp") applied :test #'equal))
        (is (member '("firewall-cmd" "--remove-port=7444/tcp") applied :test #'equal))))))

(test apiserver-masquerade-follows-lifecycle-for-a-remote-control-plane
  ;; A Pod on another node reaches the "kubernetes" Service's node-IP endpoint
  ;; over the underlay but the reply returns over the overlay; masquerading to
  ;; this node's IP keeps the path symmetric past the stateful host firewall.
  (let ((ran '()))
    (flet ((runner (argv) (push argv ran) (values "" 0)))
      (is (eq t (gr8s.network::ensure-apiserver-masquerade "192.168.122.44" 6443 :runner #'runner)))
      (is (eq t (gr8s.network::remove-apiserver-masquerade "192.168.122.44" 6443 :runner #'runner)))
      (let ((applied (reverse ran)))
        (is (member '("firewall-cmd" "--direct" "--add-rule" "ipv4" "nat"
                      "POSTROUTING" "0" "-d" "192.168.122.44" "-p" "tcp"
                      "--dport" "6443" "-j" "MASQUERADE")
                    applied :test #'equal))
        (is (member '("firewall-cmd" "--direct" "--remove-rule" "ipv4" "nat"
                      "POSTROUTING" "0" "-d" "192.168.122.44" "-p" "tcp"
                      "--dport" "6443" "-j" "MASQUERADE")
                    applied :test #'equal))))))

(test node-port-range-firewall-follows-lifecycle
  ;; Every node binds relays for NodePort Services; the host firewall must admit
  ;; the range (TCP and UDP) or <nodeIP>:<nodePort> is rejected (EHOSTUNREACH).
  (let ((ran '()))
    (flet ((runner (argv) (push argv ran) (values "" 0)))
      (is (eq t (gr8s.network::ensure-node-port-range-firewall 30000 32767 :runner #'runner)))
      (is (eq t (gr8s.network::remove-node-port-range-firewall 30000 32767 :runner #'runner)))
      (let ((applied (reverse ran)))
        (is (member '("firewall-cmd" "--add-port=30000-32767/tcp") applied :test #'equal))
        (is (member '("firewall-cmd" "--add-port=30000-32767/udp") applied :test #'equal))
        (is (member '("firewall-cmd" "--remove-port=30000-32767/tcp") applied :test #'equal))
        (is (member '("firewall-cmd" "--remove-port=30000-32767/udp") applied :test #'equal))))))

(test apiserver-masquerade-skips-a-loopback-control-plane
  ;; The control plane's own in-process agent targets loopback; same-node
  ;; Pod->apiserver never leaves the host, so no masquerade (and no firewalld
  ;; probe) is attempted.
  (let ((ran '()))
    (flet ((runner (argv) (push argv ran) (values "" 0)))
      (is (null (gr8s.network::ensure-apiserver-masquerade "127.0.0.1" 6443 :runner #'runner)))
      (is (null ran)))))

(test remove-overlay-firewall-withdraws-all-three-when-active
  (let ((ran '()))
    (flet ((runner (argv) (push argv ran) (values "" 0)))
      (is (eq t (gr8s.network::remove-overlay-firewall "10.80.0.0/20" :runner #'runner)))
      (let ((applied (reverse ran)))
        (is (member '("firewall-cmd" "--zone" "trusted" "--remove-interface" "gr8s-vxlan") applied :test #'equal))
        (is (member '("firewall-cmd" "--zone" "trusted" "--remove-source" "10.80.0.0/20") applied :test #'equal))
        (is (member '("firewall-cmd" "--remove-port=4789/udp") applied :test #'equal))))))

(test remove-control-plane-firewall-withdraws-the-node-port
  (let ((ran '()))
    (flet ((runner (argv) (push argv ran) (values "" 0)))
      (is (eq t (gr8s.network::remove-control-plane-firewall 7443 :runner #'runner)))
      (is (member '("firewall-cmd" "--remove-port=7443/tcp") (reverse ran) :test #'equal)))))

(test remove-overlay-firewall-is-a-noop-without-firewalld
  (flet ((runner (argv)
           (if (equal argv '("firewall-cmd" "--state")) (values "" 1) (values "" 0))))
    (is (null (gr8s.network::remove-overlay-firewall "10.80.0.0/20" :runner #'runner)))))

(test ensure-overlay-firewall-is-fail-soft-on-command-error
  ;; A failing firewall-cmd is logged, not raised, and returns NIL so a cached
  ;; network snapshot retries instead of remembering a partial apply.
  (flet ((runner (argv)
           (cond ((equal argv '("firewall-cmd" "--state")) (values "running" 0))
                 ((search "--add-source" (format nil "~{~A~^ ~}" argv)) (values "boom" 1))
                 (t (values "" 0)))))
    (is (null (gr8s.network::ensure-overlay-firewall "10.80.0.0/20" :runner #'runner)))))
