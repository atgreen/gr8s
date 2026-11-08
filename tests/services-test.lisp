;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Verify durable Service IP allocation and immutable identities, namespace-
;;;; scoped endpoint selection, and real TCP forwarding including client half-close.

(in-package #:gr8s/tests)
(def-suite services :in gr8s)
(in-suite services)

(defun service-test-object (name &optional (target 80))
  "Create a simple selector-based TCP ClusterIP Service request."
  (gr8s::core-object "apiVersion" "v1" "kind" "Service"
                     "metadata" (gr8s::core-object "name" name)
                     "spec" (gr8s::core-object "selector" (gr8s::core-object "app" "web")
                                               "ports" (vector (gr8s::core-object "port" 8080 "targetPort" target)))))

(test service-ipv6-formatting-is-rfc5952-canonical
  (is (equal "::" (gr8s::format-ipv6-integer 0)))
  (is (equal "::1" (gr8s::format-ipv6-integer 1)))
  (is (equal "2001:db8::1" (gr8s::format-ipv6-integer (gr8s::ipv6-integer "2001:0db8:0:0:0:0:0:1"))))
  ;; RFC 5952 compresses the first run when equal-length zero runs tie.
  (is (equal "2001::1:0:0:1:1"
             (gr8s::format-ipv6-integer (gr8s::ipv6-integer "2001:0:0:1:0:0:1:1")))))

(test services-accept-preferdualstack-and-allocate-single-stack-ipv4
  ;; PreferDualStack is best-effort; on a single-stack cluster it allocates IPv4
  ;; (controller-generated Services such as ate's api set it). RequireDualStack
  ;; and IPv6-only are refused. The allocated family is IPv4, while Kubernetes
  ;; preserves the client's best-effort policy on the stored Service.
  (with-temporary-store (store directory)
    (flet ((svc (name policy &optional families)
             (let ((s (service-test-object name)))
               (setf (gethash "ipFamilyPolicy" (gethash "spec" s)) policy)
               (when families (setf (gethash "ipFamilies" (gethash "spec" s)) families))
               s)))
      (let ((created (gr8s::create-core-resource store "services" (svc "pref" "PreferDualStack") "alpha")))
        (is (equalp #("IPv4") (gethash "ipFamilies" (gethash "spec" created))))
        (is (equal "PreferDualStack" (gethash "ipFamilyPolicy" (gethash "spec" created)))))
      (finishes (gr8s::create-core-resource store "services" (svc "pref2" "PreferDualStack" #("IPv4" "IPv6")) "alpha"))
      (signals gr8s:kubernetes-error (gr8s::create-core-resource store "services" (svc "req" "RequireDualStack") "alpha"))
      (signals gr8s:kubernetes-error (gr8s::create-core-resource store "services" (svc "v6" "SingleStack" #("IPv6")) "alpha")))))

(test services-allocate-ipv6-only-and-dual-stack-addresses-durably
  (with-temporary-store (store directory)
    (values directory)
    (gr8s::ensure-default-service-cidr store)
    (gr8s::create-core-resource
     store "servicecidrs"
     (gr8s::core-object "metadata" (gr8s::core-object "name" "v6")
                        "spec" (gr8s::core-object "cidrs" #("fd00:96::/112")))
     nil)
    (flet ((svc (name policy families)
             (let ((service (service-test-object name))
                   (spec nil))
               (setf spec (gethash "spec" service)
                     (gethash "ipFamilyPolicy" spec) policy
                     (gethash "ipFamilies" spec) families)
               service)))
      (let* ((v6 (gr8s::create-core-resource
                  store "services" (svc "v6" "SingleStack" #("IPv6")) "alpha"))
             (spec (gethash "spec" v6)))
        (is (equal "fd00:96::1" (gethash "clusterIP" spec)))
        (is (equalp #("fd00:96::1") (gethash "clusterIPs" spec)))
        (is (equalp #("IPv6") (gethash "ipFamilies" spec)))
        (is (equal "SingleStack" (gethash "ipFamilyPolicy" spec)))
        (is (equal '("alpha" "v6")
                   (gr8s::ip-address-parent-service
                    (gr8s::get-core-resource store "ipaddresses" nil "fd00:96::1")))))
      (let* ((dual (gr8s::create-core-resource
                    store "services" (svc "dual" "RequireDualStack" #("IPv4" "IPv6")) "alpha"))
             (spec (gethash "spec" dual))
             (addresses (gethash "clusterIPs" spec)))
        (is (= 2 (length addresses)))
        (is (equal "10.96.0.10" (aref addresses 0)))
        (is (equal "fd00:96::2" (aref addresses 1)))
        (is (equal (aref addresses 0) (gethash "clusterIP" spec)))
        (is (equalp #("IPv4" "IPv6") (gethash "ipFamilies" spec)))
        (is (equal "RequireDualStack" (gethash "ipFamilyPolicy" spec)))
        (loop for address across addresses
              for family across (gethash "ipFamilies" spec)
              for claim = (gr8s::get-core-resource store "ipaddresses" nil address)
              do (is (equal '("alpha" "dual") (gr8s::ip-address-parent-service claim)))
                 (is (equal family
                            (gethash "ipaddress.kubernetes.io/ip-family"
                                     (gethash "labels" (gethash "metadata" claim))))))
        ;; Deletion leaves allocator-owned claims for the repair pass, which
        ;; must collect both families rather than only the legacy primary.
        (gr8s::delete-core-resource store "services" "alpha" "dual")
        (gr8s::reconcile-service-ip-addresses store)
        (loop for address across addresses
              do (signals gr8s:kubernetes-error
                   (gr8s::get-core-resource store "ipaddresses" nil address)))))))

(test services-upgrade-and-downgrade-dual-stack-without-changing-the-primary
  (with-temporary-store (store directory)
    (values directory)
    (gr8s::ensure-default-service-cidr store)
    (gr8s::create-core-resource
     store "servicecidrs"
     (gr8s::core-object "metadata" (gr8s::core-object "name" "v6")
                        "spec" (gr8s::core-object "cidrs" #("fd00:96::/112")))
     nil)
    (let* ((single (gr8s::create-core-resource store "services" (service-test-object "mutable") "alpha"))
           (primary (gethash "clusterIP" (gethash "spec" single)))
           (dual (gr8s::update-core-resource
                  store "services" "alpha" "mutable"
                  (lambda (object)
                    (let ((spec (gethash "spec" object)))
                      (setf (gethash "ipFamilyPolicy" spec) "RequireDualStack"
                            (gethash "ipFamilies" spec) #("IPv4" "IPv6")))
                    object)))
           (dual-addresses (gethash "clusterIPs" (gethash "spec" dual))))
      (is (= 2 (length dual-addresses)))
      (is (equal primary (aref dual-addresses 0)))
      (is (equal "fd00:96::1" (aref dual-addresses 1)))
      (let* ((downgraded (gr8s::update-core-resource
                          store "services" "alpha" "mutable"
                          (lambda (object)
                            (setf (gethash "ipFamilyPolicy" (gethash "spec" object)) "SingleStack")
                            object)))
             (spec (gethash "spec" downgraded)))
        (is (equalp (vector primary) (gethash "clusterIPs" spec)))
        (is (equalp #("IPv4") (gethash "ipFamilies" spec)))
        (is (equal "SingleStack" (gethash "ipFamilyPolicy" spec)))))))

(test services-allocate-durably-without-consuming-dry-run-addresses
  (with-temporary-store (store directory)
    (let* ((one (gr8s::create-core-resource store "services" (service-test-object "one") "alpha"))
           (two (gr8s::create-core-resource store "services" (service-test-object "two") "beta")))
      (is (equal "10.96.0.10" (gethash "clusterIP" (gethash "spec" one))))
      (is (equal "10.96.0.11" (gethash "clusterIP" (gethash "spec" two))))
      (let ((reopened (open-store directory)))
        (let* ((preview (gr8s::create-core-resource reopened "services" (service-test-object "preview") "alpha" :dry-run t))
               (three (gr8s::create-core-resource reopened "services" (service-test-object "three") "alpha")))
          (is (equal "10.96.0.12" (gethash "clusterIP" (gethash "spec" preview))))
          (is (equal "10.96.0.12" (gethash "clusterIP" (gethash "spec" three))))
          (is (= 3 (length (gr8s::list-core-resources reopened "services"))))))
      (let ((duplicate (service-test-object "duplicate")))
        (setf (gethash "clusterIP" (gethash "spec" duplicate)) "10.96.0.10")
        (signals kubernetes-error (gr8s::create-core-resource store "services" duplicate "alpha")))
      (signals kubernetes-error
        (gr8s::update-core-resource store "services" "alpha" "one"
          (lambda (object) (setf (gethash "clusterIP" (gethash "spec" object)) "10.96.0.20") object)))
      (is (equal "10.96.0.10" (gethash "clusterIP" (gethash "spec" (gr8s::get-core-resource store "services" "alpha" "one"))))))))

(test services-resolve-only-live-matching-pods-in-their-namespace
  (with-temporary-store (store directory)
    (values directory)
    (gr8s:register-node store (gr8s:make-node-record :id "worker-id" :name "worker-a" :pod-cidr "10.88.0.0/24"))
    (gr8s:mark-node-ready store "worker-a" (get-universal-time))
    (let ((service (gr8s::create-core-resource store "services" (service-test-object "web" "http") "alpha")))
      (dolist (namespace '("alpha" "beta"))
        (let* ((object (com.inuoe.jzon:parse *valid-pod-json*))
               (metadata (gethash "metadata" object))
               (container (aref (gethash "containers" (gethash "spec" object)) 0)))
          (setf (gethash "namespace" metadata) namespace
                (gethash "labels" metadata) (gr8s::core-object "app" "web")
                (gethash "ports" container) (vector (gr8s::core-object "name" "http" "containerPort" 7777)))
          (let ((pod (create-pod store (parse-pod object))))
            (gr8s::persist-pod-assignment store pod "worker-a")
            (gr8s::update-pod-observed-status store pod
             (gr8s::core-object "phase" "Running" "podIP" "192.0.2.5"
                                "conditions" (vector (gr8s::core-object "type" "Ready" "status" "True")))))))
      (let ((port (aref (gethash "ports" (gethash "spec" service)) 0)))
        (is (equal '(("192.0.2.5" 7777)) (gr8s::service-pod-endpoints store service port)))
        (let* ((pod (get-pod store "alpha" "hello"))
               (status (gr8s::copy-core-object (gr8s::pod-observed-status store pod))))
          (setf (gethash "status" (aref (gethash "conditions" status) 0)) "False")
          (gr8s::update-pod-observed-status store pod status)
          (is (null (gr8s::service-pod-endpoints store service port)))
          (setf (gethash "status" (aref (gethash "conditions" status) 0)) "True")
          (gr8s::update-pod-observed-status store pod status))
        (gr8s::mark-pod-deleting store "alpha" "hello")
        (is (null (gr8s::service-pod-endpoints store service port)))))))
