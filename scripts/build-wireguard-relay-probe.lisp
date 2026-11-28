;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0

(require :asdf)
(asdf:load-asd (truename "gr8s.asd"))
(asdf:load-system :gr8s)

(defun wireguard-relay-probe-main ()
  (destructuring-bind (address port-text) (uiop:command-line-arguments)
    (let* ((port (parse-integer port-text :junk-allowed nil))
           (server (gr8s.network::start-wireguard-relay-server
                    :address address :port-start port :max-channels 1
                    :idle-seconds 3600)))
      (unwind-protect
           (let ((channel
                   (gr8s.network::ensure-wireguard-relay-server-channel
                    server "node-a" "node-b" (get-universal-time))))
             ;; No pre-authorization: the relay learns each side's source from its
             ;; first packet (first-seen, sticky; #345).
             (format t "relay-ready ~{~D~^ ~}~%"
                     (gr8s.network::wireguard-relay-channel-ports channel))
             (finish-output)
             (loop (sleep 1)))
        (gr8s.network::stop-wireguard-relay-server server)))))

(ensure-directories-exist #P"build/")

#+sbcl
(sb-ext:save-lisp-and-die
 #P"build/wireguard-relay-probe"
 :toplevel #'wireguard-relay-probe-main
 :executable t
 :save-runtime-options :accept-runtime-options
 :compression t
 :purify t)

#-sbcl
(error "The relay probe build requires SBCL")
