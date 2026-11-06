;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Spike (podster-43k.5): prove eBPF INBOUND STEERING for the Gateway API.
;;;;
;;;; The gr8s Gateway thesis is "the agent IS the gateway -- no Envoy, no
;;;; kube-proxy, no iptables." For that to hold, an inbound TCP connection to a
;;;; *gateway port* must land on the agent's own listening socket even though
;;;; the agent never bound that port. This spike proves exactly that, with the
;;;; same mechanism the real dataplane will use:
;;;;
;;;;   * a BPF_PROG_TYPE_SK_LOOKUP program, compiled from the Whistler Lisp DSL
;;;;     (no C, no LLVM, no ELF), that fires in the kernel's listener-lookup path;
;;;;   * a BPF_MAP_TYPE_SOCKMAP holding the agent's listening socket;
;;;;   * bpf_sk_assign() steering the connection to that socket.
;;;;
;;;; Method: create a throwaway network namespace (unshare CLONE_NEWNET), bind a
;;;; listener on 127.0.0.1:<LISTEN_PORT>, and connect to 127.0.0.1:<GATEWAY_PORT>
;;;; (a port NOTHING is bound to). Baseline (no program): the connect is
;;;; refused. With the sk_lookup program attached: the connect is accepted by the
;;;; listener -- the kernel steered a connection for a port the listener never
;;;; bound. That is the whole mechanism.
;;;;
;;;; Requires root (BPF load + attach, unshare). Run:
;;;;
;;;;   sudo sbcl --noinform --script scripts/spike-gateway-sklookup.lisp
;;;;
;;;; Exit 0 = all checks passed.

(require :asdf)
(require :sb-bsd-sockets)
(require :sb-posix)
(let ((project (truename (merge-pathnames "../" (uiop:pathname-directory-pathname *load-truename*)))))
  (asdf:initialize-source-registry
   `(:source-registry (:directory ,project) (:tree ,(merge-pathnames "ocicl/" project))
     :inherit-configuration)))
(handler-bind ((warning #'muffle-warning))
  (asdf:load-system :whistler/loader :verbose nil))

(defpackage #:gw-sklookup-spike (:use #:cl))
(in-package #:gw-sklookup-spike)

;;; ---------------------------------------------------------------------------
;;; Netns + libc glue.

(sb-alien:define-alien-routine ("unshare" %unshare) sb-alien:int
  (flags sb-alien:int))

(defconstant +clone-newnet+ #x40000000)

(defun enter-fresh-netns ()
  "Move the calling thread into a brand-new empty network namespace."
  (unless (zerop (%unshare +clone-newnet+))
    (error "unshare(CLONE_NEWNET) failed -- need root and CONFIG_NET_NS")))

(defun bring-loopback-up ()
  "A fresh netns has lo DOWN; loopback traffic needs it UP. The `ip' child
   forks from this (already-unshared) thread, so it acts on the new netns."
  (let ((p (sb-ext:run-program "ip" '("link" "set" "lo" "up")
                               :search t :wait t :output nil :error nil)))
    (unless (and p (eql 0 (sb-ext:process-exit-code p)))
      (error "could not bring lo up in the netns (is `ip' installed?)"))))

;;; ---------------------------------------------------------------------------
;;; The gateway port we steer, and the port the agent listener actually binds.

(defconstant +gateway-port+ 8089)       ; inbound clients target this
(defconstant +listen-port+  9099)       ; the agent listener actually binds this
(defparameter *loopback* #(127 0 0 1))

;;; ---------------------------------------------------------------------------
;;; The sk_lookup program, in the Whistler Lisp DSL.
;;;
;;; Fires in the kernel's listener-lookup path for every inbound TCP connection
;;; in this netns. If the destination port is the gateway port, pull the agent's
;;; listening socket out of the sockmap and assign the connection to it.

(defparameter *map-forms*
  '((whistler:defmap gw-listener-sock
      :type :sockmap :key-size 4 :value-size 4 :max-entries 1)))

(defparameter *prog-forms*
  '((whistler:defprog gw-sk-lookup
        (:type :sk-lookup :section "sk_lookup" :license "GPL")
      ;; protocol == IPPROTO_TCP (6) and local (destination) port is the gateway
      ;; port. bpf_sk_lookup->local_port is in host byte order.
      (when (and (= (ctx protocol) 6)
                 (= (ctx local-port) #.+gateway-port+))
        (let ((sk (map-lookup gw-listener-sock 0)))
          (when (/= sk 0)
            ;; A SOCKMAP lookup in sk_lookup context yields a refcounted
            ;; socket. Assign it, then release the reference before exit or
            ;; the verifier rejects the program for a reference leak.
            (sk-assign (ctx-ptr) sk 0)
            (sk-release sk))))
      SK_PASS)))

;;; ---------------------------------------------------------------------------
;;; Socket helpers (sb-bsd-sockets: we need the raw fd for the sockmap).

(defun make-listener (port)
  (let ((s (make-instance 'sb-bsd-sockets:inet-socket :type :stream :protocol :tcp)))
    (setf (sb-bsd-sockets:sockopt-reuse-address s) t)
    (sb-bsd-sockets:socket-bind s *loopback* port)
    (sb-bsd-sockets:socket-listen s 8)
    s))

(defun try-connect (port)
  "Attempt a TCP connect to 127.0.0.1:PORT. Return T on success, NIL on refusal."
  (let ((s (make-instance 'sb-bsd-sockets:inet-socket :type :stream :protocol :tcp)))
    (unwind-protect
         (handler-case
             (sb-ext:with-timeout 3
               (sb-bsd-sockets:socket-connect s *loopback* port)
               t)
           (sb-bsd-sockets:connection-refused-error () nil)
           (sb-ext:timeout () nil))
      (ignore-errors (sb-bsd-sockets:socket-close s)))))

;;; ---------------------------------------------------------------------------
;;; Checks.

(defvar *failures* 0)
(defun check (label got expected)
  (if (equal got expected)
      (format t "  ok   ~A -> ~S~%" label got)
      (progn (incf *failures*)
             (format t "  FAIL ~A -> got ~S, expected ~S~%" label got expected))))

(defun run ()
  (format t "~%=== sk_lookup inbound steering spike ===~%")
  (enter-fresh-netns)
  (bring-loopback-up)
  (format t "entered fresh netns, lo is up~%")

  (let ((listener (make-listener +listen-port+))
        (accepted nil)
        (session-maps nil)
        (session-progs nil)
        (attachment nil))
    (unwind-protect
         (progn
           ;; Baseline: nothing steers :gateway-port, so a connect is refused.
           (format t "--- baseline (no program) ---~%")
           (check (format nil "connect :~D refused (nothing bound)" +gateway-port+)
                  (try-connect +gateway-port+) nil)
           (check (format nil "connect :~D accepted (listener bound here)" +listen-port+)
                  (progn
                    (let ((th (sb-thread:make-thread
                               (lambda ()
                                 (ignore-errors
                                  (sb-ext:with-timeout 3
                                    (sb-bsd-sockets:socket-close
                                     (sb-bsd-sockets:socket-accept listener))))))))
                      (prog1 (try-connect +listen-port+)
                        (ignore-errors (sb-thread:join-thread th :timeout 3)))))
                  t)

           ;; Compile, load, and attach the sk_lookup program.
           (format t "--- compile + load sk_lookup (Whistler DSL -> native eBPF) ---~%")
           (multiple-value-bind (map-specs prog-specs)
               (whistler/loader::compile-bpf-forms *map-forms* *prog-forms*)
             (setf session-maps (whistler/loader::session-create-maps map-specs))
             (setf session-progs (whistler/loader::session-load-progs prog-specs session-maps))
             (format t "  compiled ~D map(s), ~D prog(s)~%"
                     (length session-maps) (length session-progs))
             (let ((sockmap (cdr (first session-maps)))
                   (prog-fd (whistler/loader:prog-info-fd (cdr (first session-progs))))
                   (lfd (sb-bsd-sockets:socket-file-descriptor listener)))
               ;; Register the agent's listening socket into the sockmap at key 0.
               (whistler/loader:map-update-int sockmap 0 lfd)
               (format t "  registered listener fd ~D into sockmap, prog fd ~D~%" lfd prog-fd)
               ;; Attach to THIS thread's netns (the one we unshared into).
               (setf attachment
                     (whistler/loader:attach-sk-lookup prog-fd
                                                       :netns-path "/proc/self/ns/net"))
               (format t "  attached sk_lookup to /proc/self/ns/net~%")))

           ;; With the program attached, a connect to the gateway port must now
           ;; be accepted by the listener -- a port it never bound.
           (format t "--- with sk_lookup attached ---~%")
           (let ((th (sb-thread:make-thread
                      (lambda ()
                        (ignore-errors
                         (sb-ext:with-timeout 3
                           (let ((peer (sb-bsd-sockets:socket-accept listener)))
                             (when peer
                               (setf accepted t)
                               (sb-bsd-sockets:socket-close peer)))))))))
             (check (format nil "connect :~D now ACCEPTED (steered to listener)" +gateway-port+)
                    (try-connect +gateway-port+) t)
             (ignore-errors (sb-thread:join-thread th :timeout 3)))
           (check "listener actually accepted the steered connection" accepted t))

      ;; Cleanup.
      (ignore-errors (when attachment (whistler/loader:detach attachment)))
      (dolist (e session-progs)
        (ignore-errors (sb-posix:close (whistler/loader:prog-info-fd (cdr e)))))
      (dolist (e session-maps)
        (ignore-errors (sb-posix:close (whistler/loader:map-info-fd (cdr e)))))
      (ignore-errors (sb-bsd-sockets:socket-close listener)))

    (format t "~%RESULT: ~:[ALL CHECKS PASSED~;~:*~D CHECK(S) FAILED~]~%"
            (when (plusp *failures*) *failures*))
    (sb-ext:exit :code (if (plusp *failures*) 1 0))))

(run)
