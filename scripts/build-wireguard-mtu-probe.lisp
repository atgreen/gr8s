;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0

(require :asdf)
(asdf:load-asd (truename "gr8s.asd"))
(asdf:load-system :gr8s)

(defun wireguard-mtu-probe-main ()
  (destructuring-bind (pod-cidr maximum-text) (uiop:command-line-arguments)
    (let ((route (gr8s.foundation::json-object "podCIDR" pod-cidr)))
      (multiple-value-bind (mtu reason)
          (gr8s.network::discover-wireguard-path-mtu
           (lambda (size)
             (gr8s.network::probe-wireguard-route-mtu route size))
           :minimum 576 :maximum (parse-integer maximum-text :junk-allowed nil))
        (format t "mtu=~A reason=~(~A~)~%" mtu reason)
        (finish-output)
        (uiop:quit (if mtu 0 1))))))

(ensure-directories-exist #P"build/")

#+sbcl
(sb-ext:save-lisp-and-die
 #P"build/wireguard-mtu-probe"
 :toplevel #'wireguard-mtu-probe-main
 :executable t
 :save-runtime-options :accept-runtime-options
 :compression t
 :purify t)

#-sbcl
(error "The WireGuard MTU probe build requires SBCL")
