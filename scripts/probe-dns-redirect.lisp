;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
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
(in-package #:gr8s)

(defun sh (fmt &rest args)
  (let ((cmd (apply #'format nil fmt args)))
    (nth-value 2 (uiop:run-program (list "sh" "-c" cmd)
                                   :output *standard-output* :error-output *standard-output*
                                   :ignore-error-status t))))

(defun setup ()
  (sh "sysctl -qw net.ipv4.ip_forward=1")
  (sh "ip link add ~A type dummy" *gw-link*)
  (sh "ip addr add ~A/32 dev ~A" *gw* *gw-link*)
  (sh "ip link set ~A up" *gw-link*)
  (sh "ip netns add ~A" *ns*)
  (sh "ip link add ~A type veth peer name ~A" *host-veth* *pod-veth*)
  (sh "ip link set ~A netns ~A" *pod-veth* *ns*)
  (sh "ip link set ~A up" *host-veth*)
  (let ((mac (string-trim '(#\Newline #\Space)
                          (uiop:run-program (list "cat" (format nil "/sys/class/net/~A/address" *host-veth*))
                                            :output '(:string)))))
    (sh "ip route add 10.99.0.2/32 dev ~A" *host-veth*)
    (sh "ip -n ~A addr add 10.99.0.2/32 dev ~A" *ns* *pod-veth*)
    (sh "ip -n ~A link set ~A up" *ns* *pod-veth*)
    (sh "ip -n ~A link set lo up" *ns*)
    (sh "ip -n ~A route add ~A/32 dev ~A" *ns* *gw* *pod-veth*)
    (sh "ip -n ~A neigh add ~A lladdr ~A dev ~A nud permanent" *ns* *gw* mac *pod-veth*)
    (sh "ip -n ~A route add default via ~A" *ns* *gw*)))

(defun teardown ()
  (sh "ip netns del ~A 2>/dev/null" *ns*)
  (sh "ip link del ~A 2>/dev/null" *host-veth*)
  (sh "ip link del ~A 2>/dev/null" *gw-link*))

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

(defun send-from-pod ()
  (sh "ip netns exec ~A sh -c 'echo -n probe > /dev/udp/~A/53' 2>/dev/null" *ns* *gw*)
  (sleep 0.3))

(defun attach-redirect ()
  "JIT-compile and attach the redirect program at *host-veth* ingress."
  (multiple-value-bind (map-specs prog-specs) (compile-whistler-program nil *redirect-forms*)
    (let* ((maps (whistler/loader::session-create-maps map-specs))
           (progs (whistler/loader::session-load-progs prog-specs maps))
           (program (cdr (first progs))))
      (whistler/loader:attach-tcx (whistler/loader:prog-info-fd program)
                                  (cni-interface-index *host-veth*) :direction "ingress"))))

(defun run ()
  (unless (zerop (sb-posix:geteuid)) (error "needs root"))
  (let ((firewall (nth-value 1 (uiop:run-program '("firewall-cmd" "--state")
                                                 :ignore-error-status t :output nil :error-output nil))))
    (format t "~&firewalld active: ~A~%" (and firewall (zerop firewall))))
  (teardown)
  (unwind-protect
       (progn
         (setup)
         (multiple-value-bind (socket counter) (start-listener)
           (declare (ignorable socket))
           ;; Control: no redirect program -> firewalld should drop it at INPUT.
           (send-from-pod)
           (let ((before (funcall counter)))
             (format t "~&[control] listener received ~D packet(s) (expect 0 if firewalld blocks)~%" before)
             ;; Attach the redirect-to-lo program and resend.
             (attach-redirect)
             (send-from-pod)
             (let ((after (funcall counter)))
               (format t "[redirect] listener received ~D packet(s) total (expect > ~D)~%" after before)
               (if (and (= before 0) (> after before))
                   (format t "~%RESULT: redirect-to-lo DELIVERS past the firewall -> Option D is viable~%")
                   (format t "~%RESULT: inconclusive (before=~D after=~D) -- inspect manually~%" before after)))
             (ignore-errors (sb-bsd-sockets:socket-close socket)))))
    (teardown))
  (sb-ext:exit :code 0))

(run)
