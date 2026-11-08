;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Materialize Pod ResourceClaimTemplate references before scheduling. The
;;;; generated claim is owned by the exact Pod UID, and its name is checkpointed
;;;; in Pod status. Owner/annotation rediscovery closes the create-before-status
;;;; crash window and makes every reconciliation pass idempotent.

(in-package #:gr8s.controllers)

(defparameter +pod-resource-claim-annotation+ "resource.kubernetes.io/pod-claim-name")

(defun generated-claim-for-pod-p (claim pod reference-name)
  "Return whether CLAIM is the generated dependent for POD's REFERENCE-NAME."
  (let* ((metadata (gethash "metadata" claim))
         (annotations (gethash "annotations" metadata (core-object))))
    (and (equal reference-name (gethash +pod-resource-claim-annotation+ annotations))
         (find (pod-uid pod) (gethash "ownerReferences" metadata #())
               :test #'equal
               :key (lambda (owner)
                      (and (equal "v1" (gethash "apiVersion" owner))
                           (equal "Pod" (gethash "kind" owner))
                           (equal (pod-name pod) (gethash "name" owner))
                           (eq t (gethash "controller" owner))
                           (gethash "uid" owner)))))))

(defun pod-resource-claim-status (store pod reference-name)
  "Return POD's persisted generated-claim status for REFERENCE-NAME."
  (find reference-name
        (gethash "resourceClaimStatuses"
                 (gethash (pod-uid pod) (pod-store-pod-client-statuses store)
                          (core-object))
                 #())
        :test #'equal :key (lambda (status) (gethash "name" status))))

(defun recorded-generated-claim (store pod reference-name)
  "Return POD's recorded generated claim when it still has the expected ownership."
  (let* ((status (pod-resource-claim-status store pod reference-name))
         (name (and status (gethash "resourceClaimName" status))))
    (and name
         (handler-case
             (let ((claim (get-core-resource store "resourceclaims" (pod-namespace pod) name)))
               (and (generated-claim-for-pod-p claim pod reference-name) claim))
           (kubernetes-error (condition)
             (unless (= 404 (kubernetes-error-status-code condition)) (error condition))
             nil)))))

(defun orphaned-generated-claim (store pod reference-name)
  "Find a claim created for POD before its status mapping was checkpointed."
  (find-if (lambda (claim) (generated-claim-for-pod-p claim pod reference-name))
           (list-core-resources store "resourceclaims" (pod-namespace pod))))

(defun claim-generate-name (pod-name reference-name)
  "Build upstream's DNS-label-sized base for a generated ResourceClaim name."
  (let* ((base (format nil "~A-~A-" pod-name reference-name))
         (maximum-base-length 57))
    (if (<= (length base) maximum-base-length)
        base
        (format nil "~A-~A"
                (subseq pod-name 0
                        (floor (* (length pod-name) maximum-base-length)
                               (length base)))
                (subseq reference-name 0
                        (floor (* (length reference-name) maximum-base-length)
                               (length base)))))))

(defun create-generated-claim (store pod reference)
  "Create the ResourceClaim described by REFERENCE's template for POD."
  (let* ((reference-name (gethash "name" reference))
         (template-name (gethash "resourceClaimTemplateName" reference))
         (template (get-core-resource store "resourceclaimtemplates"
                                      (pod-namespace pod) template-name))
         (template-spec (gethash "spec" template))
         (template-metadata (gethash "metadata" template-spec (core-object)))
         (annotations (copy-core-object (gethash "annotations" template-metadata
                                                 (core-object)))))
    (setf (gethash +pod-resource-claim-annotation+ annotations) reference-name)
    (create-core-resource
     store "resourceclaims"
     (core-object
      "apiVersion" "resource.k8s.io/v1" "kind" "ResourceClaim"
      "metadata"
      (core-object
       "generateName" (claim-generate-name (pod-name pod) reference-name)
       "labels" (copy-core-object (gethash "labels" template-metadata (core-object)))
       "annotations" annotations
       "ownerReferences"
       (vector (core-object "apiVersion" "v1" "kind" "Pod"
                            "name" (pod-name pod) "uid" (pod-uid pod)
                            "controller" t)))
      "spec" (copy-core-object (gethash "spec" template-spec)))
     (pod-namespace pod))))

(defun save-generated-claim-status (store pod reference-name claim-name)
  "Merge REFERENCE-NAME -> CLAIM-NAME into POD's durable controller status."
  (gr8s.apiserver::update-pod-client-status
   store pod
   (lambda (checkpoint)
     (let ((recorded (find reference-name
                           (gethash "resourceClaimStatuses" checkpoint #())
                           :test #'equal
                           :key (lambda (status) (gethash "name" status)))))
       (unless (and recorded
                    (equal claim-name (gethash "resourceClaimName" recorded)))
         (let ((statuses (remove reference-name
                                 (coerce (gethash "resourceClaimStatuses" checkpoint #()) 'list)
                                 :test #'equal
                                 :key (lambda (status) (gethash "name" status)))))
           (push (core-object "name" reference-name "resourceClaimName" claim-name) statuses)
           (setf (gethash "resourceClaimStatuses" checkpoint)
                 (coerce (sort statuses #'string<
                               :key (lambda (status) (gethash "name" status)))
                         'vector))
           checkpoint))))))

(defun reconcile-pod-resource-claims (store pod)
  "Create and record every ResourceClaimTemplate dependent needed by POD."
  (unless (deletion-requested-p pod)
    (loop for reference across (gethash "resourceClaims" (gethash "spec" (pod-to-object pod)) #())
          for template = (gethash "resourceClaimTemplateName" reference)
          when template
            do (let* ((reference-name (gethash "name" reference))
                      (claim (or (recorded-generated-claim store pod reference-name)
                                 (orphaned-generated-claim store pod reference-name)
                                 (create-generated-claim store pod reference))))
                 (save-generated-claim-status
                  store pod reference-name (gethash "name" (gethash "metadata" claim))))))
  pod)
