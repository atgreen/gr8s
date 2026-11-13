;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Isolated privileged probe (root) for the NetworkPolicy compiled firewall
;;;; (podster-10p.7). It JIT-compiles gr8s-netpol-egress for a sample egress
;;;; policy -- "allow UDP to 169.254.9.9:9999, deny everything else" -- attaches
;;;; it at a throwaway host-veth ingress, and sends UDP from the Pod netns to
;;;; three destinations, confirming only the allowed (addr,port) tuple is
;;;; delivered to a host listener while the others are dropped (TC_ACT_SHOT).
;;;; Touches nothing in gr8s's real dataplane. High ports (>1024) are used so
;;;; the host firewall permits the delivered packet; the only filter under test
;;;; is the compiled classifier.
;;;;
;;;; Run:  sudo sbcl --noinform --script scripts/probe-network-policy.lisp

(require :asdf)
(let ((project (truename (merge-pathnames "../" (uiop:pathname-directory-pathname *load-truename*)))))
  (asdf:initialize-source-registry
   `(:source-registry (:directory ,project) (:tree ,(merge-pathnames "ocicl/" project))
     :inherit-configuration)))
(asdf:load-system :gr8s)
(in-package #:gr8s.network)

(defvar *ns* "gr8snpprobe")
(defvar *host-veth* "gnpvh")
(defvar *pod-veth* "gnpvp")
(defvar *gw-link* "gnpgw")
(defvar *allow-addr* "169.254.9.9")     ; allowed destination (on the dummy gw)
(defvar *deny-addr* "169.254.9.10")     ; a second host-local addr, not allowed
(defvar *allow-port* 9999)
(defvar *deny-port* 7777)

;; A real networking.k8s.io/v1 manifest, driven through the full pipeline
;; (parse -> resolve for this Pod -> compile -> attach) so the privileged run
;; validates the whole stack, not just a hand-built policy.
(defparameter *policy-manifest*
  "{\"apiVersion\":\"networking.k8s.io/v1\",\"kind\":\"NetworkPolicy\",
    \"metadata\":{\"namespace\":\"default\",\"name\":\"probe\"},
    \"spec\":{\"podSelector\":{\"matchLabels\":{\"app\":\"web\"}},
             \"policyTypes\":[\"Egress\"],
             \"egress\":[{\"to\":[{\"ipBlock\":{\"cidr\":\"169.254.9.9/32\"}}],
                          \"ports\":[{\"protocol\":\"UDP\",\"port\":9999}]}]}}")

(defun sh (fmt &rest args)
  (nth-value 2 (uiop:run-program (list "sh" "-c" (apply #'format nil fmt args))
                                 :output *standard-output* :error-output *standard-output*
                                 :ignore-error-status t)))

(defun setup-gw ()
  (sh "sysctl -qw net.ipv4.ip_forward=1")
  (sh "ip link add ~A type dummy" *gw-link*)
  (sh "ip addr add ~A/32 dev ~A" *allow-addr* *gw-link*)
  (sh "ip addr add ~A/32 dev ~A" *deny-addr* *gw-link*)
  (sh "ip link set ~A up" *gw-link*))

(defun setup-pod ()
  (sh "ip netns add ~A" *ns*)
  (sh "ip link add ~A type veth peer name ~A" *host-veth* *pod-veth*)
  (sh "ip link set ~A netns ~A" *pod-veth* *ns*)
  (sh "ip link set ~A up" *host-veth*)
  ;; Reverse path for the Pod source so it is not dropped by rp_filter when it
  ;; arrives on the host veth, and take firewalld out of the picture -- neither
  ;; is the filter under test; the compiled classifier is.
  (sh "ip route add 10.99.0.2/32 dev ~A" *host-veth*)
  (sh "sysctl -qw net.ipv4.conf.~A.rp_filter=0 >/dev/null 2>&1" *host-veth*)
  (sh "firewall-cmd --zone=trusted --change-interface=~A >/dev/null 2>&1" *host-veth*)
  (let ((mac (string-trim '(#\Newline #\Space)
                          (uiop:run-program (list "cat" (format nil "/sys/class/net/~A/address" *host-veth*))
                                            :output '(:string)))))
    (sh "ip -n ~A addr add 10.99.0.2/32 dev ~A" *ns* *pod-veth*)
    (sh "ip -n ~A link set ~A up" *ns* *pod-veth*)
    (sh "ip -n ~A link set lo up" *ns*)
    (sh "ip -n ~A route add ~A/32 dev ~A" *ns* *allow-addr* *pod-veth*)
    (sh "ip -n ~A neigh add ~A lladdr ~A dev ~A nud permanent" *ns* *allow-addr* mac *pod-veth*)
    (sh "ip -n ~A route add default via ~A" *ns* *allow-addr*)))

(defun teardown ()
  (sh "firewall-cmd --zone=trusted --remove-interface=~A 2>/dev/null" *host-veth*)
  (sh "ip netns del ~A 2>/dev/null" *ns*)
  (sh "ip link del ~A 2>/dev/null" *host-veth*)
  (sh "ip link del ~A 2>/dev/null" *gw-link*))

(defun start-listener (address port)
  "UDP listener on ADDRESS:PORT; returns a thunk giving its packet count."
  (let ((socket (make-instance 'sb-bsd-sockets:inet-socket :type :datagram :protocol :udp))
        (count 0) (lock (bt:make-lock)))
    (setf (sb-bsd-sockets:sockopt-reuse-address socket) t)
    (sb-bsd-sockets:socket-bind socket (sb-bsd-sockets:make-inet-address address) port)
    (bt:make-thread (lambda ()
                      (loop (handler-case
                                (progn (sb-bsd-sockets:socket-receive
                                        socket (make-array 32 :element-type '(unsigned-byte 8)) 32)
                                       (bt:with-lock-held (lock) (incf count)))
                              (error () (return)))))
                    :name (format nil "np probe ~A:~D" address port))
    (lambda () (bt:with-lock-held (lock) count))))

(defun send-udp (address port &optional from-pod)
  "Send one UDP datagram to ADDRESS:PORT, from the Pod netns when FROM-POD."
  (flet ((send ()
           (let ((s (make-instance 'sb-bsd-sockets:inet-socket :type :datagram :protocol :udp)))
             (handler-case
                 (progn (sb-bsd-sockets:socket-connect s (sb-bsd-sockets:make-inet-address address) port)
                        (sb-bsd-sockets:socket-send s (make-array 4 :element-type '(unsigned-byte 8)
                                                                    :initial-element 9) 4))
               (error () nil))
             (ignore-errors (sb-bsd-sockets:socket-close s)))))
    (if from-pod
        (call-with-cni-network-namespace (format nil "/run/netns/~A" *ns*) #'send)
        (send)))
  (sleep 0.3))

(defun firewalld-active-p ()
  (or (eql 0 (nth-value 2 (uiop:run-program '("systemctl" "is-active" "--quiet" "firewalld")
                                            :ignore-error-status t :output nil :error-output nil)))
      (and (probe-file "/run/firewalld/") t)))

(defun attach-policy (policy)
  (multiple-value-bind (map-specs prog-specs) (compile-network-policy-egress policy)
    (let* ((maps (whistler/loader::session-create-maps map-specs))
           (progs (whistler/loader::session-load-progs prog-specs maps))
           (program (cdr (first progs))))
      (whistler/loader:attach-tcx (whistler/loader:prog-info-fd program)
                                  (cni-interface-index *host-veth*) :direction "ingress"))))

(defun run ()
  (unless (zerop (sb-posix:geteuid)) (error "needs root"))
  (format t "~&firewalld active: ~A~%" (if (firewalld-active-p) "yes" "no"))
  (teardown)
  (unwind-protect
       (progn
         (setup-gw)
         (setup-pod)
         ;; Self-diagnosis: if delivery still fails, this pinpoints the host path.
         (format t "--- probe network state ---~%")
         (format t "pod routes:~%")   (sh "ip -n ~A route" *ns*)
         (format t "pod neighbors:~%") (sh "ip -n ~A neigh" *ns*)
         (format t "host route to pod: ") (sh "ip route show 10.99.0.2/32 || echo '(none)'")
         (format t "rp_filter all/~A: " *host-veth*)
         (sh "sysctl -n net.ipv4.conf.all.rp_filter net.ipv4.conf.~A.rp_filter 2>/dev/null | tr '\\n' ' '; echo" *host-veth*)
         (format t "---~%")
         (let ((allow (start-listener *allow-addr* *allow-port*))
               (deny-port (start-listener *allow-addr* *deny-port*))
               (deny-addr (start-listener *deny-addr* *allow-port*)))
           ;; (1) Sanity: a host-local send to the allow listener must arrive, or
           ;; the listener/address wiring is broken and nothing else is meaningful.
           (send-udp *allow-addr* *allow-port*)
           (let ((sanity (funcall allow)))
             (format t "[sanity  host-local -> ~A:~D] delivered=~D (expect >= 1)~%"
                     *allow-addr* *allow-port* sanity)
             (when (zerop sanity)
               (format t "~%RESULT: listener setup broken (host-local send never arrived) -- cannot judge~%")
               (teardown) (sb-ext:exit :code 0)))
           ;; (2) Baseline: the allowed tuple from the Pod netns WITHOUT any policy
           ;; attached. This isolates environment/forwarding/firewalld from the
           ;; compiled program: if this is 0, the packet never reaches the host at
           ;; all and the program can't be blamed.
           (send-udp *allow-addr* *allow-port* t)
           (let ((baseline (- (funcall allow) 1)))   ; minus the sanity packet
             (format t "[baseline Pod->~A:~D, no policy] delivered=~D (expect >= 1)~%"
                     *allow-addr* *allow-port* baseline)
             ;; (3) Attach the compiled policy from the real manifest and resend all three.
             (let* ((spec (parse-network-policy *policy-manifest*))
                    (pod (make-np-pod :name "probe" :namespace "default"
                                      :labels (np-labels "app" "web") :ip "10.99.0.2")))
               (multiple-value-bind (isolated policy) (resolve-pod-policy pod (list spec) (list pod) :egress)
                 (unless isolated (error "policy did not select the probe Pod"))
                 (attach-policy policy)))
             (let ((allow0 (funcall allow)) (dp0 (funcall deny-port)) (da0 (funcall deny-addr)))
               (send-udp *allow-addr* *allow-port* t)
               (send-udp *allow-addr* *deny-port* t)
               (send-udp *deny-addr* *allow-port* t)
               (let ((a (- (funcall allow) allow0))
                     (dp (- (funcall deny-port) dp0))
                     (da (- (funcall deny-addr) da0)))
                 (format t "~%[with policy] allow ~A:~D delivered=~D (expect >= 1)~%" *allow-addr* *allow-port* a)
                 (format t "[with policy] deny-port ~A:~D delivered=~D (expect 0)~%" *allow-addr* *deny-port* dp)
                 (format t "[with policy] deny-addr ~A:~D delivered=~D (expect 0)~%" *deny-addr* *allow-port* da)
                 (cond
                   ((zerop baseline)
                    (format t "~%RESULT: environment blocks Pod->host:~D even with NO policy (firewalld/forwarding) -- not a program verdict; inspect the host path~%" *allow-port*))
                   ((and (>= a 1) (zerop dp) (zerop da))
                    (format t "~%RESULT: compiled firewall ENFORCES -- allowed tuple passes, others dropped~%"))
                   ((zerop a)
                    (format t "~%RESULT: policy WRONGLY DROPS the allowed tuple (baseline passed, with-policy did not) -- compiler/offset bug~%"))
                   (t
                    (format t "~%RESULT: unexpected (allow=~D deny-port=~D deny-addr=~D) -- inspect~%" a dp da))))))))
    (teardown))
  (sb-ext:exit :code 0))

(run)
