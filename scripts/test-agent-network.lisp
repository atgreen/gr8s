(load (merge-pathnames "network-test-support.lisp" *load-truename*))
(in-package #:gr8s.network)
;; Import the sibling-module symbols the removed #:gr8s facade used to expose
;; (podster-yjf / podster-oed).
(import '(gr8s.kubelet::make-managed-containerd
          gr8s.kubelet::managed-containerd-cni-config-text
          gr8s.agent::make-node-runtime
          gr8s.agent::node-runtime-network
          gr8s.agent::node-runtime-ipam
          gr8s.agent::node-runtime-cni-operations
          gr8s.agent::apply-node-runtime-network
          gr8s.agent::call-with-agent-cni-server
          gr8s.agent::call-with-dns-server
          cl-dns-proxy::read-dns-frame
          cl-dns-proxy::write-dns-frame
          gr8s.runtime::make-fake-runtime
          gr8s.foundation::+dns-kubernetes-service+))

(defun test-agent-network-policy ()
  ;; User namespaces cannot load privileged BPF programs. This test substitutes
  ;; only the policy operations; CNI IPC, IPAM, links, routes, and DNS are real.
  (make-cni-operations
   :add (constantly nil) :check (constantly nil)
   :delete (constantly nil) :status (constantly nil)))

(defun test-agent-cni-invocation (manager context command)
  (let* ((conflist (com.inuoe.jzon:parse (managed-containerd-cni-config-text manager)))
         (configuration (aref (gethash "plugins" conflist) 0))
         (output (make-string-output-stream))
         (environment
           (list (cons "CNI_COMMAND" command)
                 (cons "CNI_CONTAINERID" (cni-context-container-id context))
                 (cons "CNI_IFNAME" (cni-context-interface-name context))
                 (cons "CNI_NETNS" (cni-context-netns context)))))
    (setf (gethash "cniVersion" configuration) "1.0.0"
          (gethash "name" configuration) "gr8s")
    (let* ((status (cni-main
                    :input (make-string-input-stream
                            (com.inuoe.jzon:stringify configuration))
                    :output output
                    :environment (lambda (key) (cdr (assoc key environment :test #'string=)))))
           (text (get-output-stream-string output)))
      (unless (zerop status) (error "CNI ~A failed: ~A" command text))
      (unless (zerop (length text)) (com.inuoe.jzon:parse text)))))

(defun test-pod-dns-query (protocol)
  (let* ((query (0conf:encode-message
                 (0conf:make-dns-message
                  :id 1234 :flags #x100
                  :questions (list (0conf:make-question
                                    :name +dns-kubernetes-service+
                                    :qtype 0conf:+type-a+ :qclass 0conf:+class-in+)))))
         (socket (make-instance 'sb-bsd-sockets:inet-socket
                                :type (if (eq protocol :udp) :datagram :stream)
                                :protocol protocol))
         (stream nil))
    (unwind-protect
         (sb-ext:with-timeout 3
           (sb-bsd-sockets:socket-connect socket #(169 254 1 1) 53)
           (let ((response
                   (if (eq protocol :udp)
                       (let ((buffer (make-array 4096 :element-type '(unsigned-byte 8))))
                         (sb-bsd-sockets:socket-send socket query (length query))
                         (multiple-value-bind (ignored size)
                             (sb-bsd-sockets:socket-receive socket buffer (length buffer))
                           (declare (ignore ignored))
                           (subseq buffer 0 size)))
                       (progn
                         (setf stream (sb-bsd-sockets:socket-make-stream
                                       socket :input t :output t :buffering :none
                                       :element-type '(unsigned-byte 8)))
                         (write-dns-frame stream query)
                         (read-dns-frame stream)))))
             (assert (equalp #(10 96 0 1)
                             (0conf:a-address
                              (first (0conf:dns-message-answers
                                      (0conf:decode-message response))))))))
      (if stream (ignore-errors (close stream))
          (ignore-errors (sb-bsd-sockets:socket-close socket))))))

(let* ((directory (merge-pathnames
                   (format nil "gr8s-agent-network-~36R/" (random (expt 36 8)))
                   (uiop:temporary-directory)))
       (manager (make-managed-containerd
                 :state-directory directory :executable "/unused/containerd"
                 :oci-runtime "/unused/runc" :cni-bin-directory "/unused/"))
       (state (merge-pathnames "runtime/" directory))
       (runtime (make-node-runtime state (make-fake-runtime) manager))
       (fd (test-network-namespace))
       (context (make-cni-context :container-id "agent-network-pod"
                                  :interface-name "eth0"
                                  :netns (format nil "/proc/self/fd/~D" fd))))
  (labels ((policy-for (node)
             (setf (node-runtime-cni-operations node)
                   (make-routed-cni-operations
                    (node-runtime-ipam node) :policy (test-agent-network-policy)))))
    (unwind-protect
         (progn
           (apply-node-runtime-network
            runtime (make-instance
                     'gr8s.node.v1::desired-state-snapshot
                     :network (make-instance 'gr8s.node.v1::node-network-config
                                             :cluster-pod-cidr "10.88.0.0/16"
                                             :node-pod-cidr "10.88.13.0/24"
                                             :dns-address "169.254.1.1" :mtu 1450 :vni 42)))
           (policy-for runtime)
           (call-with-dns-server
            (lambda ()
              (call-with-agent-cni-server
               runtime
               (lambda ()
                 (let ((result (test-agent-cni-invocation manager context "ADD")))
                   (assert (string= "10.88.13.1/32"
                                    (gethash "address" (aref (gethash "ips" result) 0)))))
                 (test-agent-cni-invocation manager context "CHECK")
                 (call-with-cni-network-namespace
                  (cni-context-netns context)
                  (lambda () (test-pod-dns-query :udp) (test-pod-dns-query :tcp)))))
              ;; Recreate the agent runtime and socket while the endpoint stays
              ;; live, proving that IPAM is restored before accepting CNI.
              (let ((restarted (make-node-runtime state (make-fake-runtime) manager)))
                (policy-for restarted)
                (call-with-agent-cni-server
                 restarted
                 (lambda ()
                   (test-agent-cni-invocation manager context "CHECK")
                   (test-agent-cni-invocation manager context "ADD")
                   (setf (cni-context-netns context) "")
                   (test-agent-cni-invocation manager context "DEL")
                   (test-agent-cni-invocation manager context "DEL")))))
            :upstreams nil)
           (assert (zerop (native-interface-index (routed-cni-host-name context))))
           (let ((ipam (open-node-ipam (merge-pathnames "ipam/" state) "10.88.13.0/24")))
             (assert (zerop (hash-table-count (node-ipam-allocations ipam)))))
           (format t "gr8s agent Unix-socket CNI, IPAM recovery, and Pod DNS test passed~%"))
      (ignore-errors (remove-routed-cni-link context))
      (sb-posix:close fd)
      (uiop:delete-directory-tree directory :validate t))))
