;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0

(in-package #:gr8s/tests)

(def-suite gr8-tenancy :in gr8s)
(in-suite gr8-tenancy)

(defparameter *gr8-tenancy-pod-fixture*
  (asdf:system-relative-pathname :gr8s "tests/fixtures/gr8-pod.json")
  "gr8's own Pod for alice, UID 1000 in groups 1000 and 10, as gr8's Go tests write it,
so a client change the server would refuse fails here.")

(defun gr8-tenancy-pod (&optional (edit #'identity))
  "gr8's Pod for alice, changed by EDIT, as the API server's model returns it."
  (let ((object (com.inuoe.jzon:parse *gr8-tenancy-pod-fixture*)))
    (setf (gethash "apiVersion" object) "v1" (gethash "kind" object) "Pod")
    (funcall edit object)
    (gr8s.kubelet::pod-to-object (gr8s.kubelet::parse-pod (com.inuoe.jzon:stringify object)))))

(defun gr8-tenancy-container-context (object)
  (gethash "securityContext" (aref (gethash "containers" (gethash "spec" object)) 0)))

(test gr8-pods-run-as-their-namespaces-owner-and-gain-no-privilege
  ;; podster-tcr8: gr8 namespaces admit the privileged Pods gr8 makes, so the UID is
  ;; what confines a run. gr8's own Pod passes; each way out of the owner's UID fails.
  (flet ((violations (&optional (edit #'identity))
           (gr8s.resources::gr8-pod-violations (gr8-tenancy-pod edit) 1000 '(1000 10))))
    (is (null (violations)))
    (dolist (case (list (lambda (o) (setf (gethash "runAsUser" (gethash "securityContext" (gethash "spec" o))) 0))
                        (lambda (o) (remhash "runAsUser" (gethash "securityContext" (gethash "spec" o))))
                        (lambda (o) (setf (gethash "supplementalGroups" (gethash "securityContext" (gethash "spec" o))) #(6)))
                        (lambda (o) (setf (gethash "runAsUser" (gr8-tenancy-container-context o)) 0))
                        (lambda (o) (setf (gethash "privileged" (gr8-tenancy-container-context o)) t))
                        (lambda (o) (remhash "allowPrivilegeEscalation" (gr8-tenancy-container-context o)))
                        (lambda (o) (setf (gethash "allowPrivilegeEscalation" (gr8-tenancy-container-context o)) t))
                        (lambda (o) (remhash "capabilities" (gr8-tenancy-container-context o)))
                        (lambda (o) (setf (gethash "capabilities" (gr8-tenancy-container-context o))
                                          (com.inuoe.jzon:parse "{\"drop\":[\"ALL\"],\"add\":[\"SYS_ADMIN\"]}")))
                        (lambda (o) (setf (gethash "hostPID" (gethash "spec" o)) t))
                        (lambda (o) (setf (gethash "hostNetwork" (gethash "spec" o)) t))
                        (lambda (o) (setf (gethash "sysctls" (gethash "securityContext" (gethash "spec" o)))
                                          (com.inuoe.jzon:parse "[{\"name\":\"kernel.shm_rmid_forced\",\"value\":\"1\"}]")))
                        (lambda (o) (setf (gethash "ports" (aref (gethash "containers" (gethash "spec" o)) 0))
                                          (com.inuoe.jzon:parse "[{\"containerPort\":80,\"hostPort\":80}]")))))
      (is (violations case) "a Pod that escapes the owner's UID was admitted: ~S"
          (com.inuoe.jzon:stringify (gr8-tenancy-pod case))))))

(defun gr8-tenancy-namespace (store name owner uid gids)
  (gr8s.resources::create-core-resource
   store "namespaces"
   (com.inuoe.jzon:parse
    (format nil "{\"metadata\":{\"name\":\"~A\",\"labels\":{\"pod-security.kubernetes.io/enforce\":\"privileged\"},\"annotations\":{\"gr8s.io/gr8-owner\":\"~A\",\"gr8s.io/gr8-uid\":\"~D\",\"gr8s.io/gr8-gids\":\"~A\"}}}"
            name owner uid gids))
   nil))

(test a-gr8-users-namespace-refuses-a-pod-that-would-run-as-someone-else
  (with-temporary-store (store path)
    (values path)
    (gr8-tenancy-namespace store "gr8-alice" "gr8:alice" 1000 "1000,10")
    (gr8s.resources::create-core-resource store "namespaces" (com.inuoe.jzon:parse "{\"metadata\":{\"name\":\"plain\"}}") nil)
    (let ((root (gr8-tenancy-pod (lambda (o) (setf (gethash "runAsUser" (gethash "securityContext" (gethash "spec" o))) 0)))))
      (finishes (gr8s.resources::admit-gr8-namespace-pod store "gr8-alice" (gr8-tenancy-pod)))
      (signals gr8s.model::kubernetes-error (gr8s.resources::admit-gr8-namespace-pod store "gr8-alice" root))
      ;; Namespaces gr8 --setup didn't make are Pod Security's alone, as before.
      (finishes (gr8s.resources::admit-gr8-namespace-pod store "plain" root)))))

(defun gr8-tenancy-allow-policy (namespace &optional (name (format nil "gr8-curl-~A" namespace)))
  (com.inuoe.jzon:parse
   (format nil "{\"apiVersion\":\"policy.networking.k8s.io/v1alpha2\",\"kind\":\"ClusterNetworkPolicy\",\"metadata\":{\"name\":\"~A\"},\"spec\":{\"tier\":\"Admin\",\"priority\":10,\"subject\":{\"pods\":{\"namespaceSelector\":{\"matchLabels\":{\"kubernetes.io/metadata.name\":\"~A\"}},\"podSelector\":{\"matchLabels\":{\"gr8s.io/gr8-run\":\"gr8-curl-x\"}}}},\"egress\":[{\"name\":\"gr8-allow\",\"action\":\"Accept\",\"to\":[{\"domainNames\":[\"example.com\"]}]}]}}"
           name namespace)))

(defun gr8-tenancy-sandbox-profile (name selector)
  (com.inuoe.jzon:parse
   (format nil "{\"apiVersion\":\"gr8.gr8s.io/v1alpha1\",\"kind\":\"SandboxProfile\",\"metadata\":{\"name\":\"~A\"},\"spec\":{\"commands\":[\"claude\"]~@[,\"namespaceSelector\":{\"matchLabels\":{\"kubernetes.io/metadata.name\":\"~A\"}}~]}}"
           name selector)))

(test gr8-users-make-cluster-wide-objects-only-for-their-own-pods
  ;; podster-tcr8: ClusterNetworkPolicies and SandboxProfiles are cluster-scoped, so a
  ;; gr8 user may make one only for their own namespace's Pods.
  (with-temporary-store (store path)
    (values path)
    (gr8-tenancy-namespace store "gr8-alice" "gr8:alice" 1000 "1000")
    (gr8-tenancy-namespace store "gr8-bob" "gr8:bob" 1001 "1001")
    (let ((bob (gr8s.resources::make-api-user-identity :username "gr8:bob" :groups #("system:authenticated")))
          (admin (gr8s.resources::make-api-user-identity :username "system:admin"
                                                         :groups #("system:masters" "system:authenticated"))))
      (flet ((create (identity resource object)
               (let ((gr8s.resources::*authenticated-api-identity* identity))
                 (gr8s.resources::create-core-resource store resource object nil))))
        (finishes (create bob "clusternetworkpolicies" (gr8-tenancy-allow-policy "gr8-bob")))
        (signals gr8s.model::kubernetes-error (create bob "clusternetworkpolicies" (gr8-tenancy-allow-policy "gr8-alice")))
        (finishes (create bob "sandboxprofiles" (gr8-tenancy-sandbox-profile "bobs" "gr8-bob")))
        (signals gr8s.model::kubernetes-error (create bob "sandboxprofiles" (gr8-tenancy-sandbox-profile "alices" "gr8-alice")))
        ;; One without a namespace would apply to every namespace's runs, alice's among them.
        (signals gr8s.model::kubernetes-error (create bob "sandboxprofiles" (gr8-tenancy-sandbox-profile "everyone" nil)))
        ;; An administrator's are as before.
        (finishes (create admin "sandboxprofiles" (gr8-tenancy-sandbox-profile "site-wide" nil)))))))

(test a-gr8-user-cannot-repoint-or-delete-another-users-cluster-objects
  ;; podster-tcr8: RBAC lets a gr8 user update and delete ClusterNetworkPolicies, so the
  ;; one they change or delete must be theirs too, or bob could break alice's runs.
  (with-temporary-store (store path)
    (values path)
    (gr8-tenancy-namespace store "gr8-alice" "gr8:alice" 1000 "1000")
    (gr8-tenancy-namespace store "gr8-bob" "gr8:bob" 1001 "1001")
    (let ((alice (gr8s.resources::make-api-user-identity :username "gr8:alice" :groups #("system:authenticated")))
          (bob (gr8s.resources::make-api-user-identity :username "gr8:bob" :groups #("system:authenticated"))))
      (let ((gr8s.resources::*authenticated-api-identity* alice))
        (gr8s.resources::create-core-resource store "clusternetworkpolicies" (gr8-tenancy-allow-policy "gr8-alice") nil))
      ;; Replacing alice's with one for bob's own Pods is still taking hers.
      (signals gr8s.model::kubernetes-error
        (gr8s.store:with-store-lock (store)
          (gr8s.resources::admit-gr8-user-cluster-object
           store "clusternetworkpolicies" (gr8-tenancy-allow-policy "gr8-bob" "gr8-curl-gr8-alice") bob)))
      (signals gr8s.model::kubernetes-error
        (gr8s.resources::admit-gr8-user-cluster-delete store "clusternetworkpolicies" "gr8-curl-gr8-alice" bob))
      (finishes
        (gr8s.resources::admit-gr8-user-cluster-delete store "clusternetworkpolicies" "gr8-curl-gr8-alice" alice)))))
