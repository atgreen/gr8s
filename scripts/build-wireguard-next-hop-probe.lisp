;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0

(require :asdf)
(asdf:load-asd (truename "gr8s.asd"))
(asdf:load-system :gr8s)

(defun wireguard-next-hop-probe-main ()
  (destructuring-bind (node-id public-key address port-text pod-cidr)
      (uiop:command-line-arguments)
    (let ((peer (gr8s.foundation::json-object
                 "nodeID" node-id
                 "underlayAddress" address
                 "wireguardPublicKey" public-key
                 "wireguardListenPort"
                 (parse-integer port-text :junk-allowed nil)
                 "probeCIDR" pod-cidr)))
      (gr8s.network::trial-wireguard-next-hop peer)
      (format t "authenticated-next-hop=~A probe=~A~%" node-id pod-cidr)
      (finish-output))))

(ensure-directories-exist #P"build/")

#+sbcl
(sb-ext:save-lisp-and-die
 #P"build/wireguard-next-hop-probe"
 :toplevel #'wireguard-next-hop-probe-main
 :executable t
 :save-runtime-options :accept-runtime-options
 :compression t
 :purify t)

#-sbcl
(error "The WireGuard next-hop probe build requires SBCL")
