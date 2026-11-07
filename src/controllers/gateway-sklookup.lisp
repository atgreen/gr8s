;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; eBPF inbound steering for the Gateway data plane (podster-43k.5). An
;;;; sk_lookup program -- compiled from the Whistler Lisp DSL, no C/LLVM/ELF --
;;;; steers an inbound TCP connection destined for a *gateway port* onto the
;;;; agent's own listening socket, even though the agent never bound that port:
;;;; the agent IS the gateway, with no kube-proxy and no iptables. A SOCKMAP keyed
;;;; by destination port holds the listener sockets; bpf_sk_assign selects one.
;;;;
;;;; Proven end to end in scripts/spike-gateway-sklookup.lisp; this is the
;;;; reusable module it became. Ports are added/removed by updating the map (no
;;;; recompile); the program and its netns link are created once.
;;;;
;;;; Gotcha baked in here: a SOCKMAP lookup in sk_lookup context returns a
;;;; refcounted socket, so the program releases it after assigning or the verifier
;;;; rejects the load (see [[whistler-sk-lookup-a-sockmap-lookup-inside-a]]).

(in-package #:gr8s.controllers)

(defparameter *gateway-steering-map-forms*
  '((whistler:defmap gw-listener-sock
      :type :sockhash :key-size 4 :value-size 4 :max-entries 1024))
  "A SOCKHASH keyed by destination port (u32) -> listening socket. SOCKHASH (not
   SOCKMAP) because the key is an arbitrary port number, not an array index.")

(defparameter *gateway-steering-prog-forms*
  '((whistler:defprog gw-sk-lookup
        (:type :sk-lookup :section "sk_lookup" :license "GPL")
      ;; TCP only; steer to the listener registered for this destination port.
      (when (= (ctx protocol) 6)
        (let ((sk (map-lookup gw-listener-sock (ctx local-port))))
          (when (/= sk 0)
            (sk-assign (ctx-ptr) sk 0)
            (sk-release sk))))
      SK_PASS))
  "The sk_lookup program: dest-port -> SOCKMAP socket -> sk_assign.")

(defstruct gateway-steering
  sockmap                               ; whistler/loader map-info for gw-listener-sock
  prog-fd                               ; loaded sk_lookup program fd
  attachment                            ; netns BPF_LINK attachment
  (ports (make-hash-table) :type hash-table))  ; port -> socket fd (registered)

(defun gateway-steering-supported-p ()
  "True when this kernel/build supports loading and attaching sk_lookup."
  (and (find-symbol "ATTACH-SK-LOOKUP" '#:whistler/loader) t))

(defun gateway-listener-socket-fd (listener)
  "Return the kernel descriptor for an L7 or L4 Gateway listening socket."
  (typecase listener
    (gateway-acceptor
     (sb-bsd-sockets:socket-file-descriptor
      (usocket:socket (hunchentoot::acceptor-listen-socket listener))))
    (l4-listener
     (sb-bsd-sockets:socket-file-descriptor (l4-listener-socket listener)))
    (t (error "Unsupported Gateway listener handle ~S" listener))))

(defun start-gateway-steering (&key (netns-path "/proc/self/ns/net"))
  "Compile and load the sk_lookup program, create the port->socket SOCKMAP, and
   attach the program to NETNS-PATH. Returns a GATEWAY-STEERING handle, or signals
   on failure (callers that treat steering as best-effort should wrap this)."
  (multiple-value-bind (map-specs prog-specs)
      (whistler/loader::compile-bpf-forms *gateway-steering-map-forms*
                                          *gateway-steering-prog-forms*)
    (let* ((maps (whistler/loader::session-create-maps map-specs))
           (progs (whistler/loader::session-load-progs prog-specs maps))
           (sockmap (cdr (first maps)))
           (prog-fd (whistler/loader:prog-info-fd (cdr (first progs))))
           (attachment (whistler/loader:attach-sk-lookup prog-fd :netns-path netns-path)))
      (make-gateway-steering :sockmap sockmap :prog-fd prog-fd :attachment attachment))))

(defun gateway-steering-register (steering port socket-fd)
  "Register SOCKET-FD as the listener for destination PORT (host byte order)."
  (whistler/loader:map-update-int (gateway-steering-sockmap steering) port socket-fd)
  (setf (gethash port (gateway-steering-ports steering)) socket-fd))

(defun gateway-steering-unregister (steering port)
  "Stop steering PORT (removes the SOCKMAP entry)."
  (ignore-errors
   (whistler/loader:map-delete-int (gateway-steering-sockmap steering) port))
  (remhash port (gateway-steering-ports steering)))

(defun stop-gateway-steering (steering)
  "Detach the program and close its fds."
  (when steering
    (ignore-errors (whistler/loader:detach (gateway-steering-attachment steering)))
    (ignore-errors (sb-posix:close (gateway-steering-prog-fd steering)))
    (ignore-errors (sb-posix:close (whistler/loader:map-info-fd (gateway-steering-sockmap steering))))
    (clrhash (gateway-steering-ports steering))))
