;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Isolated probe (root) for podster-sp5: does bpf_redirect(lo, BPF_F_INGRESS)
;;;; at a veth TC ingress let a Pod's DNS packet reach a host-local :53 listener
;;;; despite firewalld rejecting it on the normal INPUT path?  Touches nothing
;;;; in gr8s's real dataplane; sets up a throwaway veth/netns/dummy, sends a UDP
;;;; packet to 169.254.9.9:53 with and without the redirect program, and reports
;;;; whether a host listener received it.
;;;;
;;;; Run:  sudo sbcl --noinform --script scripts/probe-dns-redirect.lisp

(require :asdf)
(let ((project (truename (merge-pathnames "../" (uiop:pathname-directory-pathname *load-truename*)))))
  (asdf:initialize-source-registry
   `(:source-registry (:directory ,project) (:tree ,(merge-pathnames "ocicl/" project))
     :inherit-configuration)))
(asdf:load-system :gr8s)
(in-package #:gr8s)

(defvar *ns* "gr8sprobe")
(defvar *gw* "169.254.9.9")       ; host-local gateway address carrying the DNS listener
(defvar *host-veth* "gpvh")
(defvar *pod-veth* "gpvp")
(defvar *gw-link* "gr8sprobegw")

;; TC classifier: redirect UDP -> 169.254.9.9:53 to loopback ingress; pass the
;; rest.  Authored in the WHISTLER package so the DSL symbols resolve there.
(in-package #:whistler)
(defparameter gr8s::*redirect-forms*
  '((defprog dns-redirect-probe (:type :tc :section "classifier" :license "GPL")
      (let ((data u64 (tc-data)) (data-end u64 (tc-data-end)))
        (if (> (+ data 42) data-end)
            TC_ACT_OK
            (if (and (= (eth-type data) #x0800)
                     (= (load u8 data 23) 17)                  ; IPv4 proto = UDP
                     (= (ntohl (load u32 data 30)) #xa9fe0909) ; dst 169.254.9.9
                     (= (ntohs (load u16 data 36)) 53))        ; UDP dport 53
                (redirect 1 1)                                 ; lo (ifindex 1), BPF_F_INGRESS
                TC_ACT_OK))))))

;; Variant: zero the 6-byte destination MAC before redirecting, so lo's
;; eth_type_trans sees dst == lo's all-zero address (PACKET_HOST) instead of
;; PACKET_OTHERHOST, which would drop the frame before it reaches INPUT.
(defparameter gr8s::*redirect-mac-forms*
  '((defprog dns-redirect-probe-mac (:type :tc :section "classifier" :license "GPL")
      (let ((data u64 (tc-data)) (data-end u64 (tc-data-end)))
        (if (> (+ data 42) data-end)
            TC_ACT_OK
            (if (and (= (eth-type data) #x0800)
                     (= (load u8 data 23) 17)
                     (= (ntohl (load u32 data 30)) #xa9fe0909)
                     (= (ntohs (load u16 data 36)) 53))
                (progn (store u32 data 0 0)                    ; dst MAC bytes 0-3 = 0
                       (store u16 data 4 0)                    ; dst MAC bytes 4-5 = 0
                       (redirect 1 1))
                TC_ACT_OK))))))
(in-package #:gr8s)

(defun sh (fmt &rest args)
  (let ((cmd (apply #'format nil fmt args)))
    (nth-value 2 (uiop:run-program (list "sh" "-c" cmd)
                                   :output *standard-output* :error-output *standard-output*
                                   :ignore-error-status t))))

(defun setup-gw ()
  "Persistent bits: the host-local dummy gateway carrying the :53 listener."
  (sh "sysctl -qw net.ipv4.ip_forward=1")
  (sh "ip link add ~A type dummy" *gw-link*)
  (sh "ip addr add ~A/32 dev ~A" *gw* *gw-link*)
  (sh "ip link set ~A up" *gw-link*))

(defun setup-pod ()
  "Per-trial bits: a fresh netns + veth whose Pod end sends to *gw*:53."
  (sh "ip netns add ~A" *ns*)
  (sh "ip link add ~A type veth peer name ~A" *host-veth* *pod-veth*)
  (sh "ip link set ~A netns ~A" *pod-veth* *ns*)
  (sh "ip link set ~A up" *host-veth*)
  (let ((mac (string-trim '(#\Newline #\Space)
                          (uiop:run-program (list "cat" (format nil "/sys/class/net/~A/address" *host-veth*))
                                            :output '(:string)))))
    (sh "ip -n ~A addr add 10.99.0.2/32 dev ~A" *ns* *pod-veth*)
    (sh "ip -n ~A link set ~A up" *ns* *pod-veth*)
    (sh "ip -n ~A link set lo up" *ns*)
    (sh "ip -n ~A route add ~A/32 dev ~A" *ns* *gw* *pod-veth*)
    (sh "ip -n ~A neigh add ~A lladdr ~A dev ~A nud permanent" *ns* *gw* mac *pod-veth*)
    (sh "ip -n ~A route add default via ~A" *ns* *gw*)))

(defun teardown-pod ()
  (sh "ip netns del ~A 2>/dev/null" *ns*)
  (sh "ip link del ~A 2>/dev/null" *host-veth* ))

(defun teardown-all ()
  (teardown-pod)
  (sh "ip link del ~A 2>/dev/null" *gw-link*))

(defvar *rpf-saved* nil "Saved (all . lo) rp_filter values to restore on exit.")

(defun sysctl-get (key)
  (ignore-errors
   (parse-integer
    (string-trim '(#\Newline #\Space)
                 (uiop:run-program (list "sysctl" "-n" key) :output '(:string)
                                                            :ignore-error-status t)))))

(defun set-rp-filter (v)
  "Set rp_filter to V on all, lo and the host veth; remember originals once."
  (unless *rpf-saved*
    (setf *rpf-saved* (cons (sysctl-get "net.ipv4.conf.all.rp_filter")
                            (sysctl-get "net.ipv4.conf.lo.rp_filter"))))
  (sh "sysctl -qw net.ipv4.conf.all.rp_filter=~D" v)
  (sh "sysctl -qw net.ipv4.conf.lo.rp_filter=~D" v)
  (sh "sysctl -qw net.ipv4.conf.~A.rp_filter=~D" *host-veth* v))

(defun restore-rp-filter ()
  (when *rpf-saved*
    (when (car *rpf-saved*) (sh "sysctl -qw net.ipv4.conf.all.rp_filter=~D" (car *rpf-saved*)))
    (when (cdr *rpf-saved*) (sh "sysctl -qw net.ipv4.conf.lo.rp_filter=~D" (cdr *rpf-saved*)))))

(defun netstat-ipext (name)
  "Read a named IpExt counter from /proc/net/netstat, or NIL."
  (ignore-errors
   (with-open-file (s "/proc/net/netstat")
     (loop for header = (read-line s nil) while header
           for values = (read-line s nil) while values
           when (and (>= (length header) 6) (string= (subseq header 0 6) "IpExt:"))
             do (let* ((hs (remove "" (uiop:split-string header :separator " ") :test #'string=))
                       (vs (remove "" (uiop:split-string values :separator " ") :test #'string=))
                       (pos (position name hs :test #'string=)))
                  (when pos (return (parse-integer (nth pos vs)))))))))

(defun start-listener ()
  "UDP listener on *gw*:53; returns (values socket counter-fn)."
  (let ((socket (make-instance 'sb-bsd-sockets:inet-socket :type :datagram :protocol :udp))
        (count 0) (lock (bt:make-lock)))
    (setf (sb-bsd-sockets:sockopt-reuse-address socket) t)
    (sb-bsd-sockets:socket-bind socket (sb-bsd-sockets:make-inet-address *gw*) 53)
    (bt:make-thread (lambda () (loop (handler-case
                                         (progn (sb-bsd-sockets:socket-receive
                                                 socket (make-array 64 :element-type '(unsigned-byte 8)) 64)
                                                (bt:with-lock-held (lock) (incf count)))
                                       (error () (return)))))
                    :name "probe dns listener")
    (values socket (lambda () (bt:with-lock-held (lock) count)))))

(defun send-to-gw (&optional netns-path)
  "Send one UDP packet to *gw*:53, optionally from within NETNS-PATH."
  (flet ((send ()
           (let ((s (make-instance 'sb-bsd-sockets:inet-socket :type :datagram :protocol :udp)))
             (handler-case
                 (progn (sb-bsd-sockets:socket-connect s (sb-bsd-sockets:make-inet-address *gw*) 53)
                        (sb-bsd-sockets:socket-send s (make-array 5 :element-type '(unsigned-byte 8) :initial-element 7) 5)
                        (format t "    send ok~@[ (netns ~A)~]~%" netns-path))
               (error (e) (format t "    send error~@[ (netns ~A)~]: ~A~%" netns-path e)))
             (ignore-errors (sb-bsd-sockets:socket-close s)))))
    (if netns-path (call-with-cni-network-namespace netns-path #'send) (send)))
  (sleep 0.3))

(defun attach-program (forms)
  "JIT-compile and attach FORMS at *host-veth* ingress."
  (multiple-value-bind (map-specs prog-specs) (compile-whistler-program nil forms)
    (let* ((maps (whistler/loader::session-create-maps map-specs))
           (progs (whistler/loader::session-load-progs prog-specs maps))
           (program (cdr (first progs))))
      (whistler/loader:attach-tcx (whistler/loader:prog-info-fd program)
                                  (cni-interface-index *host-veth*) :direction "ingress"))))

(defvar *counter* nil "Thunk returning the listener's running packet count.")

(defun trial (label forms &key relax-rp)
  "One fresh netns/veth; optionally loosen rp_filter and attach FORMS; send one
Pod-netns packet to *gw*:53 and report how many reached the host listener,
plus any rp_filter drops the kernel recorded for this send.  Returns delivered."
  (setup-pod)
  (when relax-rp (set-rp-filter 2))
  (when forms (attach-program forms))
  (let ((base (funcall *counter*))
        (rpf0 (or (netstat-ipext "IPReversePathFilter") 0)))
    (send-to-gw "/run/netns/gr8sprobe")
    (let ((got (- (funcall *counter*) base))
          (rpf (- (or (netstat-ipext "IPReversePathFilter") 0) rpf0)))
      (format t "[~A] delivered=~D  rp_filter_drops+=~D~%" label got rpf)
      (teardown-pod)
      got)))

(defun run ()
  (unless (zerop (sb-posix:geteuid)) (error "needs root"))
  (format t "~&firewalld active: ~A~%" (if (firewalld-active-p) "yes" "no"))
  (format t "rp_filter: all=~A lo=~A~%"
          (sysctl-get "net.ipv4.conf.all.rp_filter") (sysctl-get "net.ipv4.conf.lo.rp_filter"))
  (teardown-all)
  (unwind-protect
       (progn
         (setup-gw)
         (multiple-value-bind (socket counter) (start-listener)
           (setf *counter* counter)
           ;; Sanity: a host-local send (iif=lo, trusted) must reach the listener.
           (send-to-gw)
           (let ((sanity (funcall counter)))
             (format t "[sanity] host-local send -> listener received ~D packet(s) (expect >= 1)~%" sanity)
             (if (zerop sanity)
                 (format t "~%RESULT: listener setup broken (host-local send never arrived) -- probe cannot judge~%")
                 (let ((control  (trial "control (no redirect)"             nil))
                       (plain    (trial "redirect-to-lo"                     *redirect-forms*))
                       (looserp  (trial "redirect-to-lo + rp_filter=loose"   *redirect-forms* :relax-rp t))
                       (maczero  (trial "redirect-to-lo + zero-dst-mac + rp_filter=loose"
                                        *redirect-mac-forms* :relax-rp t)))
                   (format t "~%")
                   (cond
                     ((> control 0)
                      (format t "RESULT: firewall did NOT block the control send (delivered=~D); test on a host that blocks :53~%" control))
                     ((> plain 0)
                      (format t "RESULT: plain redirect-to-lo DELIVERS -> Option D viable as-is~%"))
                     ((> looserp 0)
                      (format t "RESULT: redirect-to-lo delivers ONLY with rp_filter loosened -> Option D viable; egress guard must set rp_filter loose on lo~%"))
                     ((> maczero 0)
                      (format t "RESULT: redirect-to-lo delivers with dst-MAC zeroed + rp_filter loose -> Option D viable; egress guard must rewrite dst MAC and set rp_filter~%"))
                     (t
                      (format t "RESULT: redirect-to-lo did NOT deliver under any variant -> Option D (redirect-to-lo) NOT viable; pivot needed~%")))))
             (ignore-errors (sb-bsd-sockets:socket-close socket)))))
    (restore-rp-filter)
    (teardown-all))
  (sb-ext:exit :code 0))

(defun firewalld-active-p ()
  "Robustly detect firewalld regardless of sudo's PATH: prefer a running
unit per systemd, fall back to the runtime state dir."
  (or (eql 0 (nth-value 2 (uiop:run-program '("systemctl" "is-active" "--quiet" "firewalld")
                                            :ignore-error-status t :output nil :error-output nil)))
      (and (probe-file "/run/firewalld/") t)))

(run)
