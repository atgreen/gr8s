(load (merge-pathnames "network-test-support.lisp" *load-truename*))
(in-package #:gr8s.network)

(let ((nodes nil) (pods nil))
  (unwind-protect
       (progn
         (enable-node-ipv4-forwarding)
         (dotimes (index 2)
           (let* ((node-fd (test-network-namespace))
                  (pod-fd (test-network-namespace))
                  (node-path (format nil "/proc/self/fd/~D" node-fd))
                  (pod-path (format nil "/proc/self/fd/~D" pod-fd))
                  (host (format nil "test-underlay-~D" index))
                  (gateway (format nil "192.0.~D.1" (+ index 2)))
                  (local (format nil "192.0.~D.2" (+ index 2)))
                  (cidr (format nil "10.88.~D.0/24" (1+ index)))
                  (remote-cidr (format nil "10.88.~D.0/24" (- 2 index)))
                  (remote-underlay (format nil "192.0.~D.2" (- 3 index)))
                  (context (make-cni-context
                            :container-id (format nil "vxlan-pod-~D" index)
                            :interface-name "eth0" :netns pod-path)))
             (push node-fd nodes) (push pod-fd pods)
             (create-routed-veth host "underlay0" node-path :mtu 1500)
             (add-network-address host gateway 24)
             (set-network-link-up host)
             (call-with-cni-network-namespace
              node-path
              (lambda ()
                (set-network-link-up "lo")
                (add-network-address "underlay0" local 24)
                (set-network-link-up "underlay0")
                (replace-network-route "0.0.0.0" 0 "underlay0" :gateway gateway)
                (configure-routed-veth context (format nil "10.88.~D.1" (1+ index)))
                (ensure-node-vxlan local cidr 42 1450)
                (replace-vxlan-peer remote-cidr remote-underlay)
                ;; Recovery must reuse the same interface and static entries.
                (let ((before (native-interface-index +node-vxlan-interface+)))
                  (ensure-node-vxlan local cidr 42 1450)
                  (replace-vxlan-peer remote-cidr remote-underlay)
                  (assert (= before (native-interface-index +node-vxlan-interface+))))))))
         (dolist (pair (list (cons (first pods) "10.88.1.1")
                            (cons (second pods) "10.88.2.1")))
           (call-with-cni-network-namespace
            (format nil "/proc/self/fd/~D" (car pair))
            (lambda ()
              ;; A full-size 1450-byte inner IPv4 packet checks VXLAN MTU too.
              (uiop:run-program
               (list "ping" "-n" "-c" "2" "-W" "2" "-M" "do" "-s" "1422" (cdr pair))
               :output *standard-output* :error-output *error-output*))))
         (call-with-cni-network-namespace
          (format nil "/proc/self/fd/~D" (second nodes))
          (lambda ()
            (remove-vxlan-peer "10.88.2.0/24" "192.0.3.2")
            (remove-vxlan-peer "10.88.2.0/24" "192.0.3.2")
            ;; Assert stale routes are gone before a peer is reintroduced.
            (let ((routes (uiop:run-program '("ip" "-4" "route" "show" "dev" "gr8s-vxlan")
                                            :output :string)))
              (assert (not (search "10.88.2." routes))))
            (replace-vxlan-peer "10.88.2.0/24" "192.0.3.2")))
         (format t "gr8s two-node VXLAN connectivity test passed~%"))
    (dolist (fd pods) (ignore-errors (sb-posix:close fd)))
    (dolist (fd nodes) (ignore-errors (sb-posix:close fd)))))
