;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; The HA acceptance smoke (podster-c2d.8): a three-member control plane, each
;;;; member serving the real HTTP API over its own Raft-replicated store. A
;;;; ConfigMap created through the leader's API is readable on every member;
;;;; killing the leader leaves the survivors serving the data with no loss, and a
;;;; new ConfigMap created on the new leader replicates to the other survivor.
;;;; This drives the whole c2d.7 stack end to end over HTTP.

(in-package #:gr8s/tests)
(def-suite ha-smoke :in gr8s)
(in-suite ha-smoke)

(defstruct smoke-node hcp store server port)

(defun smoke-get-configmap-value (port name)
  "GET a ConfigMap over HTTP; return its data \"k\" value, or NIL on 404."
  (multiple-value-bind (body status)
      (drakma:http-request
       (format nil "http://127.0.0.1:~D/api/v1/namespaces/default/configmaps/~A" port name)
       :method :get :redirect nil)
    (when (= status 200)
      (gethash "k" (gethash "data" (com.inuoe.jzon:parse body))))))

(defun smoke-post-configmap (port name value)
  "POST a ConfigMap to PORT; return the HTTP status."
  (nth-value 1 (drakma:http-request
                (format nil "http://127.0.0.1:~D/api/v1/namespaces/default/configmaps" port)
                :method :post :redirect nil
                :content-type "application/json"
                :content (format nil "{\"apiVersion\":\"v1\",\"kind\":\"ConfigMap\",\"metadata\":{\"name\":\"~A\",\"namespace\":\"default\"},\"data\":{\"k\":\"~A\"}}"
                                 name value))))

(defun smoke-leader (nodes)
  (find-if (lambda (n) (gr8s::ha-control-plane-leader-p (smoke-node-hcp n))) nodes))

(test three-member-control-plane-survives-leader-loss
  (let ((base-http 18093) (nodes '()))
    (with-temporary-store (s1 p1)
      (with-temporary-store (s2 p2)
        (with-temporary-store (s3 p3)
          (declare (ignore p1 p2 p3))
          (unwind-protect
               (labels ((bring-up (store id http-port hcp)
                          (let ((server (gr8s::start-server
                                         :address "127.0.0.1" :port http-port
                                         :store store
                                         :leader-status-fn (lambda () (gr8s::ha-control-plane-leader-status hcp)))))
                            (push (make-smoke-node :hcp hcp :store store :server server :port http-port) nodes)))
                        (store-for (node) (smoke-node-store node)))
                 (declare (ignore #'store-for))
                 ;; Found cp1, then join cp2 and cp3, each with its API URL.
                 (let* ((h1 (gr8s::start-ha-control-plane
                             s1 :id "cp1" :init t
                             :api-url (format nil "http://127.0.0.1:~D" base-http))))
                   (bring-up s1 "cp1" base-http h1)
                   (is (poll-until (lambda () (gr8s::ha-control-plane-leader-p h1))))
                   (let ((lp (gr8s::raft-member-port (gr8s::ha-control-plane-member h1))))
                     (let ((h2 (gr8s::start-ha-control-plane
                                s2 :id "cp2" :join-host "127.0.0.1" :join-port lp
                                :api-url (format nil "http://127.0.0.1:~D" (+ base-http 1)))))
                       (bring-up s2 "cp2" (+ base-http 1) h2))
                     (let ((h3 (gr8s::start-ha-control-plane
                                s3 :id "cp3" :join-host "127.0.0.1" :join-port lp
                                :api-url (format nil "http://127.0.0.1:~D" (+ base-http 2)))))
                       (bring-up s3 "cp3" (+ base-http 2) h3))))
                 (is (poll-until
                      (lambda ()
                        (let ((l (smoke-leader nodes)))
                          (and l (= 3 (length (gr8s::raft-cluster-members
                                               (gr8s::ha-control-plane-member (smoke-node-hcp l))))))))
                      :timeout 15)
                     "all three members are in the configuration")

                 ;; Create a ConfigMap through the leader's HTTP API.
                 (let ((leader (smoke-leader nodes)))
                   (is (= 201 (smoke-post-configmap (smoke-node-port leader) "cm1" "v1"))
                       "the leader's API creates the ConfigMap"))
                 ;; It is readable on every member (replicated to each store).
                 (is (poll-until
                      (lambda () (every (lambda (n) (equal "v1" (smoke-get-configmap-value
                                                                 (smoke-node-port n) "cm1")))
                                        nodes))
                      :timeout 10)
                     "the ConfigMap is served by every member")

                 ;; Kill the leader.
                 (let* ((old-leader (smoke-leader nodes)))
                   (gr8s::stop-ha-control-plane (smoke-node-hcp old-leader))
                   (gr8s::stop-server (smoke-node-server old-leader))
                   (setf nodes (remove old-leader nodes))
                   (is (poll-until (lambda () (smoke-leader nodes)) :timeout 20)
                       "a survivor becomes the new leader")
                   ;; No data loss: a survivor still serves cm1.
                   (is (poll-until
                        (lambda () (equal "v1" (smoke-get-configmap-value
                                                (smoke-node-port (first nodes)) "cm1")))
                        :timeout 10)
                       "the surviving members still serve the committed ConfigMap")
                   ;; The cluster keeps serving writes under the new leader.
                   (let ((new-leader (smoke-leader nodes)))
                     (is (= 201 (smoke-post-configmap (smoke-node-port new-leader) "cm2" "w1"))
                         "the new leader's API accepts a write")
                     (is (poll-until
                          (lambda () (every (lambda (n) (equal "w1" (smoke-get-configmap-value
                                                                     (smoke-node-port n) "cm2")))
                                            nodes))
                          :timeout 10)
                         "the new write replicates to every survivor"))))
            (dolist (n nodes)
              (ignore-errors (gr8s::stop-server (smoke-node-server n)))
              (ignore-errors (gr8s::stop-ha-control-plane (smoke-node-hcp n))))))))))
