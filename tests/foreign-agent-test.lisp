;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Exercise the foreign-cluster CNI agent end to end without privileges:
;;;; against gr8s's own API server it must find its Node's podCIDR, serve a CNI
;;;; ADD/CHECK/DEL over the real Unix socket protocol with addresses from that
;;;; CIDR, and converge NetworkPolicy for its endpoints when policies change --
;;;; with the link and map writes stubbed, since those need root.

(in-package #:gr8s/tests)
(def-suite foreign-cni-agent :in gr8s)
(in-suite foreign-cni-agent)

(defun foreign-agent-test-node (store name cidr)
  "Register NAME as a schedulable node whose API view carries CIDR."
  (gr8s.controllers::register-node
   store (gr8s.model::make-node-record :id name :name name :pod-cidr cidr
                                       :underlay-address "192.0.2.80")))

(defun foreign-agent-test-config (root)
  "A chained CNI configuration naming ROOT as the pin directory."
  (com.inuoe.jzon:stringify
   (gr8s.resources::core-object
    "cniVersion" "1.0.0" "name" "gr8s" "type" "gr8s"
    "mapPinRoot" (namestring root)
    "prevResult" (gr8s.resources::core-object "ips" #()))))

(defun foreign-agent-cni-call (socket-path command config container)
  "One CNI command through the real agent socket protocol."
  (gr8s.network::call-agent-cni
   socket-path
   (make-instance 'gr8s.node.v1::cni-request
                  :protocol-version gr8s.protocol::+node-protocol-version+
                  :command command
                  :container-id container
                  :network-namespace "/proc/self/ns/net"
                  :interface-name "eth0"
                  :network-configuration
                  (trivial-utf-8:string-to-utf-8-bytes config))))

(test foreign-cni-agent-serves-add-check-del-from-the-nodes-pod-cidr
  (with-core-api (store path)
    (foreign-agent-test-node store "worker-f" "10.88.7.0/24")
    (let* ((cluster (kube-test-cluster))
           (socket-path (namestring (merge-pathnames "cni.sock" path)))
           (root (merge-pathnames "bpf/" path))
           (links (make-hash-table :test 'equal))
           (converged nil) (converged-lock (bt:make-lock))
           (agent nil))
      (ensure-directories-exist root)
      (setf agent
            (gr8s.network::start-foreign-cni-agent
             cluster :node-name "worker-f"
             :state-directory (merge-pathnames "cni-agent/" path)
             :bpf-root (namestring root)
             :socket-path socket-path
             :operations-factory
             (lambda (ipam)
               (gr8s.network::make-routed-cni-operations
                ipam :node-id "worker-f"
                ;; The dataplane pieces that need root are stubbed; address
                ;; allocation, dispatch and result shaping stay real.
                :install-link (lambda (context addresses)
                                (setf (gethash (gr8s.network::cni-context-container-id context)
                                               links)
                                      addresses)
                                7)
                :host-index (constantly 7)
                :check-link (lambda (context address) (declare (ignore context address)) t)
                :remove-link (lambda (context)
                               (remhash (gr8s.network::cni-context-container-id context) links))
                :install-service-return (lambda (&rest arguments) (declare (ignore arguments)) nil)
                :check-service-return (lambda (&rest arguments) (declare (ignore arguments)) nil)
                :publish-service-owner (lambda (&rest arguments) (declare (ignore arguments)) nil)
                :check-service-owner (lambda (&rest arguments) (declare (ignore arguments)) nil)
                :withdraw-service-owner (lambda (&rest arguments) (declare (ignore arguments)) nil)
                :policy (gr8s.network::make-cni-operations
                         :add (lambda (&rest arguments) (declare (ignore arguments)) nil)
                         :check (lambda (&rest arguments) (declare (ignore arguments)) nil)
                         :delete (lambda (&rest arguments) (declare (ignore arguments)) nil))))
             :policy-converger
             (lambda (specs endpoints &key pod-finder directory-fn writer)
               (declare (ignore pod-finder directory-fn writer))
               (bt:with-lock-held (converged-lock)
                 (push (list (length specs) (mapcar #'first endpoints)) converged))
               nil)))
      (is (not (null agent)))
      (unwind-protect
           (let ((config (foreign-agent-test-config root)))
             ;; The agent's IPAM must be bound to the node's own CIDR.
             (let* ((response (foreign-agent-cni-call socket-path "ADD" config "sandbox-1"))
                    (result (com.inuoe.jzon:parse
                             (trivial-utf-8:utf-8-bytes-to-string
                              (slot-value response 'gr8s.node.v1::result-json))))
                    (address (gethash "address"
                                      (aref (gethash "ips" result) 0))))
               (is (slot-value response 'gr8s.node.v1::success))
               (is (uiop:string-prefix-p "10.88.7." address))
               (is (equal (first (gethash "sandbox-1" links))
                          (subseq address 0 (position #\/ address)))))
             (let ((response (foreign-agent-cni-call socket-path "CHECK" config "sandbox-1")))
               (is (slot-value response 'gr8s.node.v1::success)))
             ;; A NetworkPolicy arriving over the watch nudges convergence with
             ;; the live endpoint.
             (gr8s.kube-client:kube-create
              cluster (gr8s.kube-client:resource-path
                       "networking.k8s.io" "v1" "networkpolicies" :namespace "default")
              (gr8s.resources::core-object
               "apiVersion" "networking.k8s.io/v1" "kind" "NetworkPolicy"
               "metadata" (gr8s.resources::core-object "name" "deny-all")
               "spec" (gr8s.resources::core-object
                       "podSelector" (gr8s.resources::core-object)
                       "policyTypes" #("Ingress"))))
             (is (poll-until
                  (lambda ()
                    (bt:with-lock-held (converged-lock)
                      (member '(1 ("sandbox-1")) converged :test #'equal)))))
             (let ((response (foreign-agent-cni-call socket-path "DEL" config "sandbox-1")))
               (is (slot-value response 'gr8s.node.v1::success)))
             (is (null (gethash "sandbox-1" links))))
        (gr8s.network::stop-foreign-cni-agent agent)))))

(test foreign-cni-agent-waits-for-its-node-and-stops-cleanly-without-one
  (with-core-api (store path)
    (values store)
    (let* ((cluster (kube-test-cluster))
           (stop nil)
           (result :pending)
           (thread (bt:make-thread
                    (lambda ()
                      (setf result
                            (gr8s.network::start-foreign-cni-agent
                             cluster :node-name "never-arrives"
                             :state-directory (merge-pathnames "cni-agent/" path)
                             :bpf-root (namestring path)
                             :socket-path (namestring (merge-pathnames "cni.sock" path))
                             :stop-predicate (lambda () stop))))
                    :name "foreign agent waiting for node")))
      (sleep 1)
      (is (eq :pending result))
      (setf stop t)
      (bt:join-thread thread)
      (is (null result)))))
