;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Host firewall integration for the overlay (epic podster-pnd, podster-vwy).
;;;;
;;;; gr8s steers same-node Pod->Pod and Pod->host traffic around netfilter with
;;;; eBPF (the egress guard's redirect-to-veth and redirect-to-loopback). Cross-
;;;; NODE traffic cannot be handled that way cleanly: the encapsulated VXLAN
;;;; packet is host-forwarded, and a redirect on the send side would bypass the
;;;; sender's conntrack and make the reply arrive as ct-state INVALID. So gr8s
;;;; lets the kernel route cross-node traffic normally (conntrack sees both
;;;; directions) and, when an active host firewalld would otherwise drop it,
;;;; programs a small, overlay-scoped set of ACCEPTs -- the same coexistence
;;;; approach other eBPF CNIs take with their forward-accept rules, but narrower:
;;;;
;;;;   * the selected overlay device in an ACCEPT zone -> decrypted/decapsulated traffic
;;;;   * this node's Pod CIDR as a zone source -> local Pod egress/forward (NEW)
;;;;   * the selected overlay's UDP port on the uplink -> tunnel traffic
;;;;
;;;; This replaces the blunt "trust the whole cluster Pod/Service CIDR" firewalld
;;;; workaround with rules scoped to this node's overlay. Conntrack admits the
;;;; return traffic as ESTABLISHED, so only the NEW direction needs a rule. On a
;;;; host with no active firewalld (or a permissive forward policy) nothing is
;;;; programmed; every step is idempotent and fail-soft.

(in-package #:gr8s.network)

(defparameter +node-vxlan-udp-port+ 4789
  "The VXLAN underlay UDP port gr8s uses (see create-node-vxlan's #(18 181)).")

(defun host-firewall-run (argv)
  "Run ARGV, returning (values stdout exit-code), or (values \"\" nil) if the tool
   is missing. Mirrors doctor-run; kept local so load order does not couple the
   agent to the doctor command."
  (handler-case
      (multiple-value-bind (out err code)
          (uiop:run-program argv :output '(:string :stripped t)
                                 :ignore-error-status t :error-output nil)
        (declare (ignore err))
        (values out code))
    (error () (values "" nil))))

(defun host-firewalld-active-p (&key (runner #'host-firewall-run))
  "True when an active firewalld is managing this host (firewall-cmd --state = 0)."
  (multiple-value-bind (out code) (funcall runner '("firewall-cmd" "--state"))
    (declare (ignore out))
    (and code (zerop code))))

(defun overlay-firewall-commands
    (node-pod-cidr &key (interface +node-vxlan-interface+)
                        (port +node-vxlan-udp-port+)
                        (zone "trusted") (verb "--add"))
  "The firewall-cmd argv lists that admit (VERB \"--add\") or withdraw (VERB
   \"--remove\") gr8s overlay traffic through firewalld, scoped to the overlay.
   Idempotent at firewalld: --add-* / --remove-* is a no-op when already in the
   wanted state.

   Also source-NATs this node's Pod->NodePort traffic to the node's address. A
   Pod reaching a NodePort on another node arrives there over the underlay with
   its Pod source address, which the remote node cannot route a reply to
   symmetrically, so its stateful firewall drops the connection. Masquerading
   restores a symmetric path, exactly as kube-proxy does for the default
   externalTrafficPolicy. Scoped to NODE-POD-CIDR so an external client's source
   address at a Local-policy NodePort is left untouched."
  (let ((cidrs (if (stringp node-pod-cidr) (list node-pod-cidr) node-pod-cidr))
        (rule-verb (if (string= verb "--add") "--add-rule" "--remove-rule"))
        (ports (format nil "~D:~D" gr8s.controllers::+node-port-minimum+
                       gr8s.controllers::+node-port-maximum+)))
    (append
     (list (list "firewall-cmd" "--zone" zone
                 (format nil "~A-interface" verb) interface))
     (loop for cidr in cidrs
           collect (list "firewall-cmd" "--zone" zone
                         (format nil "~A-source" verb) cidr))
     (list (list "firewall-cmd" (format nil "~A-port=~D/udp" verb port)))
     (loop for cidr in cidrs
           nconc (loop for protocol in '("tcp" "udp")
                       collect (list "firewall-cmd" "--direct" rule-verb
                                     "ipv4" "nat" "POSTROUTING" "0"
                                     "-s" cidr "-p" protocol "--dport" ports
                                     "-j" "MASQUERADE"))))))

(defun apply-overlay-firewall-commands (commands &key (runner #'host-firewall-run))
  "Run each firewall-cmd in COMMANDS, logging (not raising on) any failure.
   Returns T if all succeeded."
  (let ((ok t))
    (dolist (argv commands ok)
      (multiple-value-bind (out code) (funcall runner argv)
        (unless (and code (zerop code))
          (setf ok nil)
          (format *error-output* "gr8s: overlay firewall command failed (~{~A~^ ~}): ~A~%"
                  argv out))))))

(defun ensure-overlay-firewall
    (node-pod-cidr &key (runner #'host-firewall-run)
                        (interface +node-vxlan-interface+)
                        (port +node-vxlan-udp-port+))
  "When an active firewalld is present, admit this node's overlay traffic through
   it (idempotent). A no-op otherwise: a host with no firewalld, or one whose
   forward policy already permits the overlay, needs nothing. Fail-soft. Returns
   T when rules were applied, NIL when no active firewalld."
  (when (and node-pod-cidr (host-firewalld-active-p :runner runner))
    (apply-overlay-firewall-commands
     (overlay-firewall-commands node-pod-cidr :interface interface
                                              :port port :verb "--add")
     :runner runner)))

(defun control-plane-firewall-commands (verb &rest ports)
  "Return firewall-cmd ARGV lists applying VERB to each positive TCP PORT."
  (loop for port in ports
        when (and port (plusp port))
          collect (list "firewall-cmd" (format nil "~A-port=~D/tcp" verb port))))

(defun ensure-control-plane-firewall
    (node-port &key kubelet-port in-cluster-api-port relay-port-start relay-max-channels
                      (runner #'host-firewall-run))
  "Open routable control-plane TCP listeners in an active firewalld. NODE-PORT
   admits agent enrollment; KUBELET-PORT admits the authenticated kubelet proxy
   used by metrics, logs, exec, and related node APIs; IN-CLUSTER-API-PORT admits
   the in-cluster apiserver that backs the \"kubernetes\" Service VIP, so Pods on
   other nodes can reach it. A NIL or zero port is disabled. No-op without
   firewalld; fail-soft. Returns T when rules were attempted."
  (let ((commands
          (append
           (control-plane-firewall-commands "--add" node-port kubelet-port
                                            in-cluster-api-port)
           (when (and relay-port-start relay-max-channels)
             (list
              (list "firewall-cmd"
                    (format nil "--add-port=~D-~D/udp"
                            relay-port-start
                            (+ relay-port-start (* 2 relay-max-channels) -1))))))))
    (when (and commands (host-firewalld-active-p :runner runner))
      (apply-overlay-firewall-commands
       commands
       :runner runner)
      t)))

(defun ensure-gateway-listener-firewall (port &key (runner #'host-firewall-run))
  "Admit TCP traffic to a live Gateway or Ingress listener through firewalld."
  (when (and port (plusp port) (host-firewalld-active-p :runner runner))
    (apply-overlay-firewall-commands
     (list (list "firewall-cmd" (format nil "--add-port=~D/tcp" port)))
     :runner runner)
    t))

(defun ensure-image-peer-firewall (port &key (runner #'host-firewall-run))
  "Admit TCP traffic to this node's mTLS image-peer (BitTorrent) listener so
   peers on other nodes can fetch blobs from it. No-op without firewalld;
   fail-soft. Returns T when a rule was attempted."
  (when (and port (plusp port) (host-firewalld-active-p :runner runner))
    (apply-overlay-firewall-commands
     (list (list "firewall-cmd" (format nil "--add-port=~D/tcp" port)))
     :runner runner)
    t))

(defun remove-image-peer-firewall (port &key (runner #'host-firewall-run))
  "Withdraw the rule opened by ENSURE-IMAGE-PEER-FIREWALL. No-op without
   firewalld; fail-soft."
  (when (and port (plusp port) (host-firewalld-active-p :runner runner))
    (apply-overlay-firewall-commands
     (list (list "firewall-cmd" (format nil "--remove-port=~D/tcp" port)))
     :runner runner)
    t))

(defun node-port-range-firewall-commands (verb minimum maximum)
  "firewall-cmd argv admitting the Service NodePort range for TCP and UDP."
  (when (and (integerp minimum) (integerp maximum) (<= 1 minimum maximum 65535))
    (list (list "firewall-cmd" (format nil "~A-port=~D-~D/tcp" verb minimum maximum))
          (list "firewall-cmd" (format nil "~A-port=~D-~D/udp" verb minimum maximum)))))

(defun ensure-node-port-range-firewall (minimum maximum &key (runner #'host-firewall-run))
  "Admit the Service NodePort range so Pods and off-node clients can reach
   <nodeIP>:<nodePort>. Every node binds a userspace relay for each NodePort
   Service that has endpoints; without this rule the stateful host firewall
   rejects the port (EHOSTUNREACH) and NodePort Services -- and their
   conformance tests -- fail. No-op without firewalld; fail-soft. Returns T when
   rules were attempted."
  (let ((commands (node-port-range-firewall-commands "--add" minimum maximum)))
    (when (and commands (host-firewalld-active-p :runner runner))
      (apply-overlay-firewall-commands commands :runner runner)
      t)))

(defun remove-node-port-range-firewall (minimum maximum &key (runner #'host-firewall-run))
  "Withdraw ENSURE-NODE-PORT-RANGE-FIREWALL's rules. No-op without firewalld;
   fail-soft."
  (let ((commands (node-port-range-firewall-commands "--remove" minimum maximum)))
    (when (and commands (host-firewalld-active-p :runner runner))
      (apply-overlay-firewall-commands commands :runner runner)
      t)))

(defun routable-masquerade-address-p (address)
  "True for an apiserver address worth masquerading toward: a non-empty, non-
   loopback host. The control plane's own in-process agent targets loopback and
   needs no rule (same-node Pod->apiserver never leaves the host)."
  (and (stringp address) (plusp (length address))
       (not (uiop:string-prefix-p "127." address))
       (not (string= "localhost" address))))

(defun apiserver-masquerade-command (verb address port)
  "firewall-cmd direct-rule argv masquerading Pod->apiserver traffic to this
   node's IP in nat POSTROUTING."
  (list "firewall-cmd" "--direct" (format nil "~A-rule" verb) "ipv4" "nat"
        "POSTROUTING" "0" "-d" address "-p" "tcp"
        "--dport" (format nil "~D" port) "-j" "MASQUERADE"))

(defun ensure-apiserver-masquerade
    (address port &key (runner #'host-firewall-run))
  "Source-NAT this node's Pod->in-cluster-apiserver traffic to the node's own
   address. The \"kubernetes\" Service endpoint is the control-plane node's
   underlay IP, so a Pod on another node reaches it over the underlay while the
   reply returns over the overlay; that asymmetry makes the stateful host
   firewall drop the follow-up packets as ct-invalid and the TLS handshake times
   out. Masquerading restores a symmetric path. A loopback ADDRESS (the control
   plane's own agent) is skipped. No-op without firewalld; fail-soft. Returns T
   when a rule was attempted."
  (when (and (routable-masquerade-address-p address)
             (typep port '(integer 1 65535))
             (host-firewalld-active-p :runner runner))
    (apply-overlay-firewall-commands
     (list (apiserver-masquerade-command "--add" address port))
     :runner runner)
    t))

(defun remove-apiserver-masquerade
    (address port &key (runner #'host-firewall-run))
  "Withdraw ENSURE-APISERVER-MASQUERADE's rule. No-op without firewalld;
   fail-soft."
  (when (and (routable-masquerade-address-p address)
             (typep port '(integer 1 65535))
             (host-firewalld-active-p :runner runner))
    (apply-overlay-firewall-commands
     (list (apiserver-masquerade-command "--remove" address port))
     :runner runner)
    t))

(defun remove-overlay-firewall
    (node-pod-cidr &key (runner #'host-firewall-run)
                        (interface +node-vxlan-interface+)
                        (port +node-vxlan-udp-port+))
  "Withdraw this node's overlay ACCEPTs from an active firewalld, the inverse of
   ensure-overlay-firewall. Called when the node's dataplane is torn down (no
   remaining Pods), so the host firewall returns to its prior state rather than
   keeping orphaned rules. No-op without firewalld; fail-soft."
  (when (and node-pod-cidr (host-firewalld-active-p :runner runner))
    (apply-overlay-firewall-commands
     (overlay-firewall-commands node-pod-cidr :interface interface
                                              :port port :verb "--remove")
     :runner runner)))

(defun remove-control-plane-firewall
    (node-port &key kubelet-port in-cluster-api-port relay-port-start relay-max-channels
                      (runner #'host-firewall-run))
  "Withdraw the TCP listeners opened by ENSURE-CONTROL-PLANE-FIREWALL. No-op
   without firewalld; fail-soft."
  (let ((commands
          (append
           (control-plane-firewall-commands "--remove" node-port kubelet-port
                                            in-cluster-api-port)
           (when (and relay-port-start relay-max-channels)
             (list
              (list "firewall-cmd"
                    (format nil "--remove-port=~D-~D/udp"
                            relay-port-start
                            (+ relay-port-start (* 2 relay-max-channels) -1))))))))
    (when (and commands (host-firewalld-active-p :runner runner))
      (apply-overlay-firewall-commands
       commands
       :runner runner)
      t)))

(defun remove-gateway-listener-firewall (port &key (runner #'host-firewall-run))
  "Withdraw the TCP port opened by ENSURE-GATEWAY-LISTENER-FIREWALL."
  (when (and port (plusp port) (host-firewalld-active-p :runner runner))
    (apply-overlay-firewall-commands
     (list (list "firewall-cmd" (format nil "--remove-port=~D/tcp" port)))
     :runner runner)
    t))

(defun overlay-firewall-present-p
    (node-pod-cidr &key (runner #'host-firewall-run)
                        (interface +node-vxlan-interface+)
                        (port +node-vxlan-udp-port+))
  "True when firewalld already carries all three overlay ACCEPTs for this node.
   Used by the doctor check."
  (flet ((q (argv) (multiple-value-bind (out code) (funcall runner argv)
                     (declare (ignore out)) (and code (zerop code)))))
    (and (q (list "firewall-cmd" "--zone" "trusted" "--query-interface" interface))
         (every (lambda (cidr)
                  (q (list "firewall-cmd" "--zone" "trusted" "--query-source" cidr)))
                (if (stringp node-pod-cidr) (list node-pod-cidr) node-pod-cidr))
         (q (list "firewall-cmd" (format nil "--query-port=~D/udp" port))))))
