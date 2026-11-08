(in-package #:gr8s/tests)

(in-suite gr8s)

(defun make-test-node (name id cidr)
  (gr8s:make-node-record :name name :id id :pod-cidr cidr))

(test node-identity-and-pod-cidr-survive-a-store-restart
  (with-temporary-store (store path)
    (gr8s:register-node store
                        (make-test-node "worker-a" "node-a" "10.64.0.0/20"))
    (gr8s:mark-node-ready store "worker-a" 100)
    (let* ((pod (create-pod store (parse-pod *valid-pod-json*)))
           (assigned (gr8s:schedule-pod store pod))
           (reopened (open-store path))
           (node (gr8s:get-node reopened "worker-a"))
           (restored-pod (get-pod reopened "default" "hello")))
      (is (string= "worker-a" (gr8s:node-record-name assigned)))
      (is (string= "node-a" (gr8s:node-record-id node)))
      (is (string= "10.64.0.0/20" (gr8s:node-record-pod-cidr node)))
      (is-false (gr8s:node-record-ready-p node))
      (is (string= "worker-a" (gr8s:pod-node-name restored-pod))))))

(test duplicate-node-identities-and-pod-cidrs-are-rejected
  (with-temporary-store (store path)
    (gr8s:register-node store
                        (make-test-node "worker-a" "node-a" "10.64.0.0/20"))
    (dolist (duplicate
             (list (make-test-node "worker-a" "node-b" "10.64.16.0/20")
                   (make-test-node "worker-b" "node-a" "10.64.16.0/20")
                   (make-test-node "worker-b" "node-b" "10.64.0.0/20")))
      (handler-case
          (progn
            (gr8s:register-node store duplicate)
            (fail "duplicate node claim must fail"))
        (kubernetes-error (condition)
          (is (string= "Conflict" (kubernetes-error-reason condition))))))))

(test pod-cidr-allocation-is-deterministic-and-skips-claimed-blocks
  (with-temporary-store (store path)
    (is (string= "10.64.0.0/20"
                 (gr8s:allocate-node-pod-cidr store "10.64.0.0/12" 20)))
    (gr8s:register-node store
                        (make-test-node "worker-a" "node-a" "10.64.0.0/20"))
    (is (string= "10.64.16.0/20"
                 (gr8s:allocate-node-pod-cidr store "10.64.0.0/12" 20)))))

(test scheduler-leaves-pods-pending-until-a-node-is-ready
  (with-temporary-store (store path)
    (let ((pod (create-pod store (parse-pod *valid-pod-json*))))
      (is (null (gr8s:schedule-pod store pod)))
      (is (null (gr8s:pod-node-name pod)))
      (is (string= "Pending" (gr8s:pod-scheduling-phase store pod))))))

(test scheduler-uses-fewest-nonterminal-assignments-and-breaks-ties-by-name
  (with-temporary-store (store path)
    (dolist (node (list (make-test-node "worker-b" "node-b" "10.64.16.0/20")
                        (make-test-node "worker-a" "node-a" "10.64.0.0/20")))
      (gr8s:register-node store node)
      (gr8s:mark-node-ready store (gr8s:node-record-name node) 100))
    (let ((first (create-pod store (parse-pod *valid-pod-json*))))
      (is (string= "worker-a"
                   (gr8s:node-record-name (gr8s:schedule-pod store first))))
      (let* ((object (com.inuoe.jzon:parse *valid-pod-json*))
             (metadata (gethash "metadata" object)))
        (setf (gethash "name" metadata) "second")
        (let ((second (create-pod store (parse-pod object))))
          (is (string= "worker-b"
                       (gr8s:node-record-name
                        (gr8s:schedule-pod store second))))
          (gr8s:update-pod-observed-phase store first "Succeeded")
          (let* ((third-object (com.inuoe.jzon:parse *valid-pod-json*))
                 (third-metadata (gethash "metadata" third-object)))
            (setf (gethash "name" third-metadata) "third")
            (is (string= "worker-a"
                         (gr8s:node-record-name
                          (gr8s:schedule-pod
                           store (create-pod store (parse-pod third-object))))))))))))

(defun dra-test-pod (name claim-name)
  "Build a Pod that directly references CLAIM-NAME through DRA."
  (parse-pod
   (gr8s::core-object
    "apiVersion" "v1" "kind" "Pod"
    "metadata" (gr8s::core-object "name" name "namespace" "default")
    "spec" (gr8s::core-object
            "resourceClaims" (vector (gr8s::core-object "name" "device"
                                                         "resourceClaimName" claim-name))
            "containers" (vector (gr8s::core-object "name" "c" "image" "busybox"
                                                      "resources" (gr8s::core-object
                                                                   "claims" (vector (gr8s::core-object "name" "device")))))))))

(defun create-allocated-dra-claim (store name node-name)
  "Create a ResourceClaim whose allocation is available only on NODE-NAME."
  (gr8s::create-core-resource
   store "resourceclaims"
   (gr8s::core-object
    "apiVersion" "resource.k8s.io/v1" "kind" "ResourceClaim"
    "metadata" (gr8s::core-object "name" name)
    "spec" (gr8s::core-object "devices" (gr8s::core-object "requests" #())))
   "default")
  (allocate-dra-claim store name node-name))

(defun allocate-dra-claim (store name node-name)
  "Record NAME's test allocation as available only on NODE-NAME."
  (let ((gr8s::*typed-api-status-write* t))
    (gr8s::update-core-resource
     store "resourceclaims" "default" name
     (lambda (claim)
       (setf (gethash "status" claim)
             (gr8s::core-object
              "allocation"
              (gr8s::core-object
               "devices" (gr8s::core-object "results" #())
               "nodeSelector"
               (gr8s::core-object
                "nodeSelectorTerms"
                (vector (gr8s::core-object
                         "matchFields"
                         (vector (gr8s::core-object "key" "metadata.name" "operator" "In"
                                                    "values" (vector node-name)))))))))
       claim))))

(test resource-claim-templates-create-one-owned-claim-and-persist-pod-status
  (with-temporary-store (store path)
    (let* ((pod-name (make-string 50 :initial-element #\p))
           (reference-name (make-string 20 :initial-element #\r))
           (full-length (+ (length pod-name) (length reference-name) 2)))
      (is (equal (format nil "~A-~A"
                         (subseq pod-name 0 (floor (* (length pod-name) 57) full-length))
                         (subseq reference-name 0
                                 (floor (* (length reference-name) 57) full-length)))
                 (gr8s.controllers::claim-generate-name pod-name reference-name))
          "long generated names use upstream's proportional truncation"))
    (gr8s::create-core-resource
     store "resourceclaimtemplates"
     (gr8s::core-object
      "apiVersion" "resource.k8s.io/v1" "kind" "ResourceClaimTemplate"
      "metadata" (gr8s::core-object "name" "accelerator-template")
      "spec" (gr8s::core-object
               "metadata" (gr8s::core-object
                            "labels" (gr8s::core-object "pool" "fast")
                            "annotations" (gr8s::core-object "example.com/source" "template"))
               "spec" (gr8s::core-object "devices" (gr8s::core-object "requests" #()))))
     "default")
    (let* ((pod
             (create-pod
              store
              (parse-pod
               (gr8s::core-object
                "apiVersion" "v1" "kind" "Pod"
                "metadata" (gr8s::core-object "name" "consumer" "namespace" "default")
                "spec" (gr8s::core-object
                         "resourceClaims"
                         (vector (gr8s::core-object
                                  "name" "device"
                                  "resourceClaimTemplateName" "accelerator-template"))
                         "containers"
                         (vector (gr8s::core-object
                                  "name" "c" "image" "busybox"
                                  "resources" (gr8s::core-object
                                               "claims" (vector (gr8s::core-object "name" "device"))))))))))
           (reconcile (lambda (current)
                        (gr8s.controllers::reconcile-pod-resource-claims store current))))
      (funcall reconcile pod)
      ;; Repeating the pass must rediscover the generated claim rather than
      ;; creating another one, including after reopening the durable store.
      (let ((checkpoint (gethash (pod-uid pod) (gr8s::pod-store-pod-client-statuses store))))
        (funcall reconcile pod)
        (is (eq checkpoint
                (gethash (pod-uid pod) (gr8s::pod-store-pod-client-statuses store)))
            "an unchanged pass does not rewrite the durable Pod status checkpoint"))
      (let* ((claims (gr8s::list-core-resources store "resourceclaims" "default"))
             (claim (first claims))
             (metadata (and claim (gethash "metadata" claim)))
             (status (gethash (pod-uid pod) (gr8s::pod-store-pod-client-statuses store)))
             (claim-status (and status (aref (gethash "resourceClaimStatuses" status) 0))))
        (is (= 1 (length claims)))
        (is (uiop:string-prefix-p "consumer-device-" (gethash "name" metadata)))
        (is (equal "fast" (gethash "pool" (gethash "labels" metadata))))
        (is (equal "template" (gethash "example.com/source" (gethash "annotations" metadata))))
        (is (equal "device" (gethash "resource.kubernetes.io/pod-claim-name"
                                      (gethash "annotations" metadata))))
        (let ((owner (aref (gethash "ownerReferences" metadata) 0)))
          (is (equal "Pod" (gethash "kind" owner)))
          (is (equal (pod-uid pod) (gethash "uid" owner)))
          (is-true (gethash "controller" owner)))
        (is (equal "device" (gethash "name" claim-status)))
        (is (equal (gethash "name" metadata) (gethash "resourceClaimName" claim-status)))
        (let ((published (gr8s::apply-pod-client-status
                          store pod (gr8s::core-object "conditions" #()))))
          (is (equal (gethash "name" metadata)
                     (gethash "resourceClaimName"
                              (aref (gethash "resourceClaimStatuses" published) 0))))))
      (let* ((reopened (open-store path))
             (restored (get-pod reopened "default" "consumer")))
        (gr8s.controllers::reconcile-pod-resource-claims reopened restored)
        (is (= 1 (length (gr8s::list-core-resources reopened "resourceclaims" "default"))))
        (is (= 1
               (length
                (gethash "resourceClaimStatuses"
                         (gethash (pod-uid restored)
                                  (gr8s::pod-store-pod-client-statuses reopened))))))
        (let ((reconciler (make-reconciler reopened (make-fake-runtime))))
          (gr8s::delete-reconciled-pod reconciler "default" "consumer")
          (gr8s::collect-orphaned-api-objects reconciler)
          (is (null (gr8s::list-core-resources reopened "resourceclaims" "default"))
              "the generated claim is collected with its owning Pod"))))))

(test generated-dra-claims-constrain-placement-and-are-reserved
  (with-temporary-store (store path)
    (declare (ignore path))
    (dolist (node (list (make-test-node "worker-a" "node-a" "10.64.0.0/20")
                        (make-test-node "worker-b" "node-b" "10.64.16.0/20")))
      (gr8s:register-node store node)
      (gr8s:mark-node-ready store (gr8s:node-record-name node) 100))
    (gr8s::create-core-resource
     store "resourceclaimtemplates"
     (gr8s::core-object
      "apiVersion" "resource.k8s.io/v1" "kind" "ResourceClaimTemplate"
      "metadata" (gr8s::core-object "name" "template")
      "spec" (gr8s::core-object
               "metadata" (gr8s::core-object)
               "spec" (gr8s::core-object "devices" (gr8s::core-object "requests" #()))))
     "default")
    (let* ((pod
             (create-pod
              store
              (parse-pod
               (gr8s::core-object
                "apiVersion" "v1" "kind" "Pod"
                "metadata" (gr8s::core-object "name" "templated" "namespace" "default")
                "spec" (gr8s::core-object
                         "resourceClaims"
                         (vector (gr8s::core-object "name" "device"
                                                    "resourceClaimTemplateName" "template"))
                         "containers"
                         (vector (gr8s::core-object
                                  "name" "c" "image" "busybox"
                                  "resources" (gr8s::core-object
                                               "claims" (vector (gr8s::core-object "name" "device"))))))))))
           (_ (gr8s.controllers::reconcile-pod-resource-claims store pod))
           (pod-status (gethash (pod-uid pod) (gr8s::pod-store-pod-client-statuses store)))
           (claim-name (gethash "resourceClaimName"
                                (aref (gethash "resourceClaimStatuses" pod-status) 0))))
      (declare (ignore _))
      (allocate-dra-claim store claim-name "worker-b")
      (let* ((node (gr8s:schedule-pod store pod))
             (claim (gr8s::get-core-resource store "resourceclaims" "default" claim-name))
             (reserved (gethash "reservedFor" (gethash "status" claim))))
        (is (equal "worker-b" (gr8s:node-record-name node)))
        (is (= 1 (length reserved)))
        (is (equal (pod-uid pod) (gethash "uid" (aref reserved 0))))))))

(test scheduler-allocates-an-unallocated-dra-claim-from-a-node-resource-slice
  (with-temporary-store (store path)
    (declare (ignore path))
    (dolist (node (list (make-test-node "worker-a" "node-a" "10.64.0.0/20")
                        (make-test-node "worker-b" "node-b" "10.64.16.0/20")))
      (gr8s:register-node store node)
      (gr8s:mark-node-ready store (gr8s:node-record-name node) 100))
    (gr8s::create-core-resource
     store "deviceclasses"
     (gr8s::core-object
      "apiVersion" "resource.k8s.io/v1" "kind" "DeviceClass"
      "metadata" (gr8s::core-object "name" "accelerator")
      "spec" (gr8s::core-object "selectors" #()))
     nil)
    (gr8s::create-core-resource
     store "resourceslices"
     (gr8s::core-object
      "apiVersion" "resource.k8s.io/v1" "kind" "ResourceSlice"
      "metadata" (gr8s::core-object "name" "worker-b-devices")
      "spec"
      (gr8s::core-object
       "driver" "devices.example.com"
       "pool" (gr8s::core-object "name" "worker-b" "generation" 1
                                  "resourceSliceCount" 1)
       "nodeName" "worker-b"
       "devices" (vector (gr8s::core-object "name" "gpu-0"))))
     nil)
    (gr8s::create-core-resource
     store "resourceclaims"
     (gr8s::core-object
      "apiVersion" "resource.k8s.io/v1" "kind" "ResourceClaim"
      "metadata" (gr8s::core-object "name" "device")
      "spec"
      (gr8s::core-object
       "devices"
       (gr8s::core-object
        "requests"
        (vector
         (gr8s::core-object
          "name" "gpu"
          "exactly" (gr8s::core-object "deviceClassName" "accelerator"
                                        "allocationMode" "ExactCount" "count" 1))))))
     "default")
    (let* ((pod (create-pod store (dra-test-pod "consumer" "device")))
           (node (gr8s:schedule-pod store pod))
           (claim (gr8s::get-core-resource store "resourceclaims" "default" "device"))
           (status (gethash "status" claim (gr8s::core-object)))
           (allocation (gethash "allocation" status (gr8s::core-object)))
           (results (gethash "results" (gethash "devices" allocation (gr8s::core-object)) #())))
      (is (equal "worker-b" (and node (gr8s:node-record-name node))))
      (is (= 1 (length results)))
      (when (= 1 (length results))
        (let ((result (aref results 0)))
          (is (equal "gpu" (gethash "request" result)))
          (is (equal "devices.example.com" (gethash "driver" result)))
          (is (equal "worker-b" (gethash "pool" result)))
          (is (equal "gpu-0" (gethash "device" result)))))
      (is (find (pod-uid pod) (gethash "reservedFor" status #())
                :test #'equal :key (lambda (consumer) (gethash "uid" consumer)))))))

(test scheduler-uses-the-first-satisfiable-dra-subrequest
  (with-temporary-store (store path)
    (declare (ignore path))
    (let ((node (make-test-node "worker-a" "node-a" "10.64.0.0/20")))
      (gr8s:register-node store node)
      (gr8s:mark-node-ready store "worker-a" 100))
    (gr8s::create-core-resource
     store "deviceclasses"
     (gr8s::core-object
      "apiVersion" "resource.k8s.io/v1" "kind" "DeviceClass"
      "metadata" (gr8s::core-object "name" "accelerator")
      "spec" (gr8s::core-object "selectors" #()))
     nil)
    (gr8s::create-core-resource
     store "resourceslices"
     (gr8s::core-object
      "apiVersion" "resource.k8s.io/v1" "kind" "ResourceSlice"
      "metadata" (gr8s::core-object "name" "devices")
      "spec" (gr8s::core-object
              "driver" "devices.example.com"
              "pool" (gr8s::core-object "name" "pool" "generation" 1
                                         "resourceSliceCount" 1)
              "nodeName" "worker-a"
              "devices" (vector (gr8s::core-object "name" "gpu-0"))))
     nil)
    (gr8s::create-core-resource
     store "resourceclaims"
     (gr8s::core-object
      "apiVersion" "resource.k8s.io/v1" "kind" "ResourceClaim"
      "metadata" (gr8s::core-object "name" "device")
      "spec" (gr8s::core-object
              "devices" (gr8s::core-object
                         "requests"
                         (vector
                          (gr8s::core-object
                           "name" "device"
                           "firstAvailable"
                           (vector
                            (gr8s::core-object "name" "cpu" "deviceClassName" "cpu"
                                               "allocationMode" "ExactCount" "count" 1)
                            (gr8s::core-object "name" "gpu" "deviceClassName" "accelerator"
                                               "allocationMode" "ExactCount" "count" 1)))))))
     "default")
    (let* ((pod (create-pod store (dra-test-pod "consumer" "device")))
           (node (gr8s:schedule-pod store pod))
           (claim (gr8s::get-core-resource store "resourceclaims" "default" "device"))
           (results (gethash "results"
                             (gethash "devices"
                                      (gethash "allocation"
                                               (gethash "status" claim (gr8s::core-object))
                                               (gr8s::core-object))
                                      (gr8s::core-object))
                             #())))
      (is (equal "worker-a" (and node (gr8s:node-record-name node))))
      (is (= 1 (length results)))
      (when (= 1 (length results))
        (is (equal "device/gpu" (gethash "request" (aref results 0))))))))

(test scheduler-skips-untolerated-dra-device-taints
  (with-temporary-store (store path)
    (declare (ignore path))
    (let ((node (make-test-node "worker-a" "node-a" "10.64.0.0/20")))
      (gr8s:register-node store node)
      (gr8s:mark-node-ready store "worker-a" 100))
    (gr8s::create-core-resource
     store "deviceclasses"
     (gr8s::core-object
      "apiVersion" "resource.k8s.io/v1" "kind" "DeviceClass"
      "metadata" (gr8s::core-object "name" "accelerator")
      "spec" (gr8s::core-object "selectors" #()))
     nil)
    (gr8s::create-core-resource
     store "resourceslices"
     (gr8s::core-object
      "apiVersion" "resource.k8s.io/v1" "kind" "ResourceSlice"
      "metadata" (gr8s::core-object "name" "devices")
      "spec" (gr8s::core-object
              "driver" "devices.example.com"
              "pool" (gr8s::core-object "name" "pool" "generation" 1
                                         "resourceSliceCount" 1)
              "nodeName" "worker-a"
              "devices"
              (vector
               (gr8s::core-object
                "name" "gpu-0"
                "taints" (vector (gr8s::core-object
                                   "key" "maintenance" "value" "true"
                                   "effect" "NoSchedule")))
               (gr8s::core-object "name" "gpu-1"))))
     nil)
    (flet ((claim (name &optional tolerations)
             (gr8s::create-core-resource
              store "resourceclaims"
              (gr8s::core-object
               "apiVersion" "resource.k8s.io/v1" "kind" "ResourceClaim"
               "metadata" (gr8s::core-object "name" name)
               "spec"
               (gr8s::core-object
                "devices"
                (gr8s::core-object
                 "requests"
                 (vector
                  (gr8s::core-object
                   "name" "gpu"
                   "exactly"
                   (gr8s::core-object
                    "deviceClassName" "accelerator"
                    "allocationMode" "ExactCount" "count" 1
                    "tolerations" (or tolerations #())))))))
              "default")))
      (claim "ordinary")
      (claim "tolerating"
             (vector (gr8s::core-object
                      "key" "maintenance" "operator" "Equal" "value" "true"
                      "effect" "NoSchedule"))))
    (flet ((allocated-device (claim-name)
             (let* ((pod (create-pod store (dra-test-pod claim-name claim-name)))
                    (node (gr8s:schedule-pod store pod))
                    (claim (gr8s::get-core-resource
                            store "resourceclaims" "default" claim-name))
                    (results (gethash "results"
                                      (gethash "devices"
                                               (gethash "allocation"
                                                        (gethash "status" claim
                                                                 (gr8s::core-object))
                                                        (gr8s::core-object))
                                               (gr8s::core-object))
                                      #())))
               (is (equal "worker-a" (and node (gr8s:node-record-name node))))
               (and (= 1 (length results)) (gethash "device" (aref results 0))))))
      (is (equal "gpu-1" (allocated-device "ordinary")))
      (is (equal "gpu-0" (allocated-device "tolerating"))))))

(test dra-device-tolerations-follow-upstream-matching-rules
  (let ((no-execute (gr8s::core-object
                     "key" "maintenance" "value" "true"
                     "effect" "NoExecute")))
    (is (gr8s.controllers::dra-device-tolerates-taint-p
         (gr8s::core-object "key" "maintenance" "operator" "Exists")
         no-execute))
    (is (gr8s.controllers::dra-device-tolerates-taint-p
         (gr8s::core-object "operator" "Exists") no-execute))
    (is-false (gr8s.controllers::dra-device-tolerates-taint-p
               (gr8s::core-object "key" "maintenance" "operator" "Equal"
                                  "value" "false" "effect" "NoExecute")
               no-execute)))
  (is-false
   (gr8s.controllers::dra-device-tolerated-p
    (gr8s::core-object
     "taints" (vector (gr8s::core-object "effect" "NoExecute")))
    (gr8s::core-object)))
  (is
   (gr8s.controllers::dra-device-tolerated-p
    (gr8s::core-object
     "taints" (vector (gr8s::core-object "effect" "None")
                      (gr8s::core-object "effect" "FutureEffect")))
    (gr8s::core-object))))

(test scheduler-allocates-all-matching-dra-devices-from-one-pool
  (with-temporary-store (store path)
    (declare (ignore path))
    (let ((node (make-test-node "worker-a" "node-a" "10.64.0.0/20")))
      (gr8s:register-node store node)
      (gr8s:mark-node-ready store "worker-a" 100))
    (gr8s::create-core-resource
     store "deviceclasses"
     (gr8s::core-object
      "apiVersion" "resource.k8s.io/v1" "kind" "DeviceClass"
      "metadata" (gr8s::core-object "name" "accelerator")
      "spec" (gr8s::core-object "selectors" #()))
     nil)
    (gr8s::create-core-resource
     store "resourceslices"
     (gr8s::core-object
      "apiVersion" "resource.k8s.io/v1" "kind" "ResourceSlice"
      "metadata" (gr8s::core-object "name" "devices")
      "spec" (gr8s::core-object
              "driver" "devices.example.com"
              "pool" (gr8s::core-object "name" "pool" "generation" 1
                                         "resourceSliceCount" 1)
              "nodeName" "worker-a"
              "devices" (vector (gr8s::core-object "name" "gpu-0")
                                (gr8s::core-object "name" "gpu-1"))))
     nil)
    (gr8s::create-core-resource
     store "resourceclaims"
     (gr8s::core-object
      "apiVersion" "resource.k8s.io/v1" "kind" "ResourceClaim"
      "metadata" (gr8s::core-object "name" "devices")
      "spec" (gr8s::core-object
              "devices" (gr8s::core-object
                         "requests"
                         (vector (gr8s::core-object
                                  "name" "gpus"
                                  "exactly" (gr8s::core-object
                                             "deviceClassName" "accelerator"
                                             "allocationMode" "All"))))))
     "default")
    (let* ((pod (create-pod store (dra-test-pod "consumer" "devices")))
           (node (gr8s:schedule-pod store pod))
           (claim (gr8s::get-core-resource store "resourceclaims" "default" "devices"))
           (results (gethash "results"
                             (gethash "devices"
                                      (gethash "allocation"
                                               (gethash "status" claim (gr8s::core-object))
                                               (gr8s::core-object))
                                      (gr8s::core-object))
                             #())))
      (is (equal "worker-a" (and node (gr8s:node-record-name node))))
      (is (= 2 (length results)))
      (is (equal '("gpu-0" "gpu-1")
                 (sort (map 'list (lambda (result) (gethash "device" result)) results)
                       #'string<))))))

(test scheduler-applies-device-class-cel-selectors
  (with-temporary-store (store path)
    (declare (ignore path))
    (let ((node (make-test-node "worker-a" "node-a" "10.64.0.0/20")))
      (gr8s:register-node store node)
      (gr8s:mark-node-ready store "worker-a" 100))
    (gr8s::create-core-resource
     store "deviceclasses"
     (gr8s::core-object
      "apiVersion" "resource.k8s.io/v1" "kind" "DeviceClass"
      "metadata" (gr8s::core-object "name" "accelerator")
      "spec" (gr8s::core-object
              "selectors"
              (vector (gr8s::core-object
                       "cel" (gr8s::core-object
                              "expression"
                              "device.attributes[\"devices.example.com\"].kind == \"gpu\"")))))
     nil)
    (gr8s::create-core-resource
     store "resourceslices"
     (gr8s::core-object
      "apiVersion" "resource.k8s.io/v1" "kind" "ResourceSlice"
      "metadata" (gr8s::core-object "name" "devices")
      "spec" (gr8s::core-object
              "driver" "devices.example.com"
              "pool" (gr8s::core-object "name" "pool" "generation" 1
                                         "resourceSliceCount" 1)
              "nodeName" "worker-a"
              "devices"
              (vector
               (gr8s::core-object
                "name" "cpu-0"
                "attributes" (gr8s::core-object
                              "kind" (gr8s::core-object "string" "cpu")))
               (gr8s::core-object
                "name" "gpu-0"
                "attributes" (gr8s::core-object
                              "kind" (gr8s::core-object "string" "gpu"))))))
     nil)
    (gr8s::create-core-resource
     store "resourceclaims"
     (gr8s::core-object
      "apiVersion" "resource.k8s.io/v1" "kind" "ResourceClaim"
      "metadata" (gr8s::core-object "name" "device")
      "spec" (gr8s::core-object
              "devices" (gr8s::core-object
                         "requests"
                         (vector (gr8s::core-object
                                  "name" "gpu"
                                  "exactly" (gr8s::core-object
                                             "deviceClassName" "accelerator"
                                             "allocationMode" "ExactCount"
                                             "count" 1))))))
     "default")
    (let* ((pod (create-pod store (dra-test-pod "consumer" "device")))
           (node (gr8s:schedule-pod store pod))
           (claim (gr8s::get-core-resource store "resourceclaims" "default" "device"))
           (results (gethash "results"
                             (gethash "devices"
                                      (gethash "allocation"
                                               (gethash "status" claim (gr8s::core-object))
                                               (gr8s::core-object))
                                      (gr8s::core-object))
                             #())))
      (is (equal "worker-a" (and node (gr8s:node-record-name node))))
      (is (= 1 (length results)))
      (when (= 1 (length results))
        (is (equal "gpu-0" (gethash "device" (aref results 0))))))))

(test scheduler-honors-per-device-dra-node-selection
  (with-temporary-store (store path)
    (declare (ignore path))
    (dolist (node (list (make-test-node "worker-a" "node-a" "10.64.0.0/20")
                        (make-test-node "worker-b" "node-b" "10.64.16.0/20")))
      (gr8s:register-node store node)
      (gr8s:mark-node-ready store (gr8s:node-record-name node) 100))
    (gr8s::create-core-resource
     store "deviceclasses"
     (gr8s::core-object
      "apiVersion" "resource.k8s.io/v1" "kind" "DeviceClass"
      "metadata" (gr8s::core-object "name" "accelerator")
      "spec" (gr8s::core-object "selectors" #()))
     nil)
    (gr8s::create-core-resource
     store "resourceslices"
     (gr8s::core-object
      "apiVersion" "resource.k8s.io/v1" "kind" "ResourceSlice"
      "metadata" (gr8s::core-object "name" "partitioned-devices")
      "spec" (gr8s::core-object
              "driver" "devices.example.com"
              "pool" (gr8s::core-object "name" "pool" "generation" 1
                                         "resourceSliceCount" 1)
              "perDeviceNodeSelection" t
              "devices" (vector (gr8s::core-object "name" "gpu-b" "nodeName" "worker-b")
                                (gr8s::core-object "name" "gpu-a" "nodeName" "worker-a"))))
     nil)
    (gr8s::create-core-resource
     store "resourceclaims"
     (gr8s::core-object
      "apiVersion" "resource.k8s.io/v1" "kind" "ResourceClaim"
      "metadata" (gr8s::core-object "name" "device")
      "spec" (gr8s::core-object
              "devices" (gr8s::core-object
                         "requests"
                         (vector (gr8s::core-object
                                  "name" "gpu"
                                  "exactly" (gr8s::core-object
                                             "deviceClassName" "accelerator"
                                             "allocationMode" "ExactCount"
                                             "count" 1))))))
     "default")
    (let* ((pod (create-pod store (dra-test-pod "consumer" "device")))
           (node (gr8s:schedule-pod store pod))
           (claim (gr8s::get-core-resource store "resourceclaims" "default" "device"))
           (results (gethash "results"
                             (gethash "devices"
                                      (gethash "allocation"
                                               (gethash "status" claim (gr8s::core-object))
                                               (gr8s::core-object))
                                      (gr8s::core-object))
                             #())))
      (is (equal "worker-a" (and node (gr8s:node-record-name node))))
      (is (= 1 (length results)))
      (when (= 1 (length results))
        (is (equal "gpu-a" (gethash "device" (aref results 0))))))))

(test dra-candidate-combination-search-stops-at-the-first-solution
  (let ((visits 0) (selected nil))
    (is (gr8s::dra-map-candidate-combinations
         (lambda (combination)
           (incf visits)
           (setf selected combination)
           t)
         (loop for index below 40 collect index)
         20))
    (is (= 1 visits))
    (is (equal (loop for index below 20 collect index) selected))))

(test scheduler-copies-dra-class-and-claim-configuration-into-the-allocation
  (with-temporary-store (store path)
    (declare (ignore path))
    (let ((node (make-test-node "worker-a" "node-a" "10.64.0.0/20")))
      (gr8s:register-node store node)
      (gr8s:mark-node-ready store "worker-a" 100))
    (gr8s::create-core-resource
     store "deviceclasses"
     (gr8s::core-object
      "apiVersion" "resource.k8s.io/v1" "kind" "DeviceClass"
      "metadata" (gr8s::core-object "name" "accelerator")
      "spec" (gr8s::core-object
              "selectors" #()
              "config" (vector
                        (gr8s::core-object
                         "opaque" (gr8s::core-object
                                   "driver" "devices.example.com"
                                   "parameters" (gr8s::core-object "source" "class"))))))
     nil)
    (gr8s::create-core-resource
     store "resourceslices"
     (gr8s::core-object
      "apiVersion" "resource.k8s.io/v1" "kind" "ResourceSlice"
      "metadata" (gr8s::core-object "name" "devices")
      "spec" (gr8s::core-object
              "driver" "devices.example.com"
              "pool" (gr8s::core-object "name" "pool" "generation" 1
                                         "resourceSliceCount" 1)
              "nodeName" "worker-a"
              "devices" (vector (gr8s::core-object "name" "gpu-0"))))
     nil)
    (gr8s::create-core-resource
     store "resourceclaims"
     (gr8s::core-object
      "apiVersion" "resource.k8s.io/v1" "kind" "ResourceClaim"
      "metadata" (gr8s::core-object "name" "device")
      "spec" (gr8s::core-object
              "devices" (gr8s::core-object
                         "requests"
                         (vector (gr8s::core-object
                                  "name" "gpu"
                                  "exactly" (gr8s::core-object
                                             "deviceClassName" "accelerator"
                                             "allocationMode" "ExactCount"
                                             "count" 1)))
                         "config"
                         (vector (gr8s::core-object
                                  "requests" (vector "gpu")
                                  "opaque" (gr8s::core-object
                                            "driver" "devices.example.com"
                                            "parameters" (gr8s::core-object
                                                          "source" "claim")))))))
     "default")
    (let* ((pod (create-pod store (dra-test-pod "consumer" "device")))
           (node (gr8s:schedule-pod store pod))
           (claim (gr8s::get-core-resource store "resourceclaims" "default" "device"))
           (config (gethash "config"
                            (gethash "devices"
                                     (gethash "allocation"
                                              (gethash "status" claim (gr8s::core-object))
                                              (gr8s::core-object))
                                     (gr8s::core-object))
                            #())))
      (is (equal "worker-a" (and node (gr8s:node-record-name node))))
      (is (= 2 (length config)))
      (when (= 2 (length config))
        (is (equal "FromClass" (gethash "source" (aref config 0))))
        (is (equalp #("gpu") (gethash "requests" (aref config 0))))
        (is (equal "class" (gethash "source"
                                     (gethash "parameters"
                                              (gethash "opaque" (aref config 0))))))
        (is (equal "FromClaim" (gethash "source" (aref config 1))))
        (is (equalp #("gpu") (gethash "requests" (aref config 1))))
        (is (equal "claim" (gethash "source"
                                     (gethash "parameters"
                                              (gethash "opaque" (aref config 1))))))))))

(test scheduler-backtracks-to-satisfy-dra-match-attribute-constraints
  (with-temporary-store (store path)
    (declare (ignore path))
    (let ((node (make-test-node "worker-a" "node-a" "10.64.0.0/20")))
      (gr8s:register-node store node)
      (gr8s:mark-node-ready store "worker-a" 100))
    (dolist (class '("gpu" "nic"))
      (gr8s::create-core-resource
       store "deviceclasses"
       (gr8s::core-object
        "apiVersion" "resource.k8s.io/v1" "kind" "DeviceClass"
        "metadata" (gr8s::core-object "name" class)
        "spec" (gr8s::core-object
                "selectors"
                (vector (gr8s::core-object
                         "cel" (gr8s::core-object
                                "expression"
                                (format nil
                                        "device.attributes[\"devices.example.com\"].kind == \"~A\""
                                        class))))))
       nil))
    (flet ((device (name kind numa)
             (gr8s::core-object
              "name" name
              "attributes" (gr8s::core-object
                            "kind" (gr8s::core-object "string" kind)
                            "numa" (gr8s::core-object "int" numa)))))
      (gr8s::create-core-resource
       store "resourceslices"
       (gr8s::core-object
        "apiVersion" "resource.k8s.io/v1" "kind" "ResourceSlice"
        "metadata" (gr8s::core-object "name" "devices")
        "spec" (gr8s::core-object
                "driver" "devices.example.com"
                "pool" (gr8s::core-object "name" "pool" "generation" 1
                                           "resourceSliceCount" 1)
                "nodeName" "worker-a"
                "devices" (vector (device "gpu-a" "gpu" 0)
                                  (device "gpu-b" "gpu" 1)
                                  (device "nic-a" "nic" 1))))
       nil))
    (gr8s::create-core-resource
     store "resourceclaims"
     (gr8s::core-object
      "apiVersion" "resource.k8s.io/v1" "kind" "ResourceClaim"
      "metadata" (gr8s::core-object "name" "devices")
      "spec" (gr8s::core-object
              "devices" (gr8s::core-object
                         "requests"
                         (vector
                          (gr8s::core-object
                           "name" "gpu"
                           "exactly" (gr8s::core-object "deviceClassName" "gpu"
                                                        "allocationMode" "ExactCount"
                                                        "count" 1))
                          (gr8s::core-object
                           "name" "nic"
                           "exactly" (gr8s::core-object "deviceClassName" "nic"
                                                        "allocationMode" "ExactCount"
                                                        "count" 1)))
                         "constraints"
                         (vector (gr8s::core-object
                                  "requests" (vector "gpu" "nic")
                                  "matchAttribute" "devices.example.com/numa")))))
     "default")
    (let* ((pod (create-pod store (dra-test-pod "consumer" "devices")))
           (node (gr8s:schedule-pod store pod))
           (claim (gr8s::get-core-resource store "resourceclaims" "default" "devices"))
           (results (gethash "results"
                             (gethash "devices"
                                      (gethash "allocation"
                                               (gethash "status" claim (gr8s::core-object))
                                               (gr8s::core-object))
                                      (gr8s::core-object))
                             #())))
      (is (equal "worker-a" (and node (gr8s:node-record-name node))))
      (is (= 2 (length results)))
      (when (= 2 (length results))
        (is (equal '("gpu-b" "nic-a")
                   (map 'list (lambda (result) (gethash "device" result)) results)))))))

(test scheduler-backtracks-to-satisfy-dra-distinct-attribute-constraints
  (with-temporary-store (store path)
    (declare (ignore path))
    (let ((node (make-test-node "worker-a" "node-a" "10.64.0.0/20")))
      (gr8s:register-node store node)
      (gr8s:mark-node-ready store "worker-a" 100))
    (gr8s::create-core-resource
     store "deviceclasses"
     (gr8s::core-object
      "apiVersion" "resource.k8s.io/v1" "kind" "DeviceClass"
      "metadata" (gr8s::core-object "name" "nic")
      "spec" (gr8s::core-object "selectors" #()))
     nil)
    (flet ((device (name uplink)
             (gr8s::core-object
              "name" name
              "attributes" (gr8s::core-object
                            "uplink" (gr8s::core-object "string" uplink)))))
      (gr8s::create-core-resource
       store "resourceslices"
       (gr8s::core-object
        "apiVersion" "resource.k8s.io/v1" "kind" "ResourceSlice"
        "metadata" (gr8s::core-object "name" "devices")
        "spec" (gr8s::core-object
                "driver" "devices.example.com"
                "pool" (gr8s::core-object "name" "pool" "generation" 1
                                           "resourceSliceCount" 1)
                "nodeName" "worker-a"
                "devices" (vector (device "nic-a" "physical-a")
                                  (device "nic-b" "physical-a")
                                  (device "nic-c" "physical-b"))))
       nil))
    (gr8s::create-core-resource
     store "resourceclaims"
     (gr8s::core-object
      "apiVersion" "resource.k8s.io/v1" "kind" "ResourceClaim"
      "metadata" (gr8s::core-object "name" "devices")
      "spec" (gr8s::core-object
              "devices" (gr8s::core-object
                         "requests"
                         (vector
                          (gr8s::core-object
                           "name" "first"
                           "exactly" (gr8s::core-object "deviceClassName" "nic"
                                                        "allocationMode" "ExactCount"
                                                        "count" 1))
                          (gr8s::core-object
                           "name" "second"
                           "exactly" (gr8s::core-object "deviceClassName" "nic"
                                                        "allocationMode" "ExactCount"
                                                        "count" 1)))
                         "constraints"
                         (vector (gr8s::core-object
                                  "requests" (vector "first" "second")
                                  "distinctAttribute" "devices.example.com/uplink")))))
     "default")
    (let* ((pod (create-pod store (dra-test-pod "consumer" "devices")))
           (node (gr8s:schedule-pod store pod))
           (claim (gr8s::get-core-resource store "resourceclaims" "default" "devices"))
           (results (gethash "results"
                             (gethash "devices"
                                      (gethash "allocation"
                                               (gethash "status" claim (gr8s::core-object))
                                               (gr8s::core-object))
                                      (gr8s::core-object))
                             #())))
      (is (equal "worker-a" (and node (gr8s:node-record-name node))))
      (is (= 2 (length results)))
      (when (= 2 (length results))
        (is (equal '("nic-a" "nic-c")
                   (map 'list (lambda (result) (gethash "device" result)) results)))))))

(test scheduler-advances-first-available-after-constraint-rejection
  (with-temporary-store (store path)
    (declare (ignore path))
    (let ((node (make-test-node "worker-a" "node-a" "10.64.0.0/20")))
      (gr8s:register-node store node)
      (gr8s:mark-node-ready store "worker-a" 100))
    (dolist (class '(("wrong-gpu" . "wrong") ("right-gpu" . "right") ("nic" . "nic")))
      (gr8s::create-core-resource
       store "deviceclasses"
       (gr8s::core-object
        "apiVersion" "resource.k8s.io/v1" "kind" "DeviceClass"
        "metadata" (gr8s::core-object "name" (car class))
        "spec" (gr8s::core-object
                "selectors"
                (vector (gr8s::core-object
                         "cel" (gr8s::core-object
                                "expression"
                                (format nil
                                        "device.attributes[\"devices.example.com\"].kind == \"~A\""
                                        (cdr class)))))))
       nil))
    (flet ((device (name kind numa)
             (gr8s::core-object
              "name" name
              "attributes" (gr8s::core-object
                            "kind" (gr8s::core-object "string" kind)
                            "numa" (gr8s::core-object "int" numa)))))
      (gr8s::create-core-resource
       store "resourceslices"
       (gr8s::core-object
        "apiVersion" "resource.k8s.io/v1" "kind" "ResourceSlice"
        "metadata" (gr8s::core-object "name" "devices")
        "spec" (gr8s::core-object
                "driver" "devices.example.com"
                "pool" (gr8s::core-object "name" "pool" "generation" 1
                                           "resourceSliceCount" 1)
                "nodeName" "worker-a"
                "devices" (vector (device "gpu-wrong" "wrong" 0)
                                  (device "gpu-right" "right" 1)
                                  (device "nic-a" "nic" 1))))
       nil))
    (gr8s::create-core-resource
     store "resourceclaims"
     (gr8s::core-object
      "apiVersion" "resource.k8s.io/v1" "kind" "ResourceClaim"
      "metadata" (gr8s::core-object "name" "devices")
      "spec" (gr8s::core-object
              "devices" (gr8s::core-object
                         "requests"
                         (vector
                          (gr8s::core-object
                           "name" "gpu"
                           "firstAvailable"
                           (vector
                            (gr8s::core-object "name" "wrong"
                                               "deviceClassName" "wrong-gpu"
                                               "allocationMode" "ExactCount"
                                               "count" 1)
                            (gr8s::core-object "name" "right"
                                               "deviceClassName" "right-gpu"
                                               "allocationMode" "ExactCount"
                                               "count" 1)))
                          (gr8s::core-object
                           "name" "nic"
                           "exactly" (gr8s::core-object "deviceClassName" "nic"
                                                        "allocationMode" "ExactCount"
                                                        "count" 1)))
                         "constraints"
                         (vector (gr8s::core-object
                                  "requests" (vector "gpu" "nic")
                                  "matchAttribute" "devices.example.com/numa")))))
     "default")
    (let* ((pod (create-pod store (dra-test-pod "consumer" "devices")))
           (node (gr8s:schedule-pod store pod))
           (claim (gr8s::get-core-resource store "resourceclaims" "default" "devices"))
           (results (gethash "results"
                             (gethash "devices"
                                      (gethash "allocation"
                                               (gethash "status" claim (gr8s::core-object))
                                               (gr8s::core-object))
                                      (gr8s::core-object))
                             #())))
      (is (equal "worker-a" (and node (gr8s:node-record-name node))))
      (is (= 2 (length results)))
      (when (= 2 (length results))
        (is (equal '("gpu-right" "nic-a")
                   (map 'list (lambda (result) (gethash "device" result)) results)))))))

(test dra-claims-constrain-placement-and-are-reserved-for-the-pod
  (with-temporary-store (store path)
    (dolist (node (list (make-test-node "worker-a" "node-a" "10.64.0.0/20")
                        (make-test-node "worker-b" "node-b" "10.64.16.0/20")))
      (gr8s:register-node store node)
      (gr8s:mark-node-ready store (gr8s:node-record-name node) 100))
    (let ((missing (create-pod store (dra-test-pod "missing" "not-created"))))
      (is-false (gr8s:schedule-pod store missing))
      (is-false (gr8s:pod-node-name missing)))
    (create-allocated-dra-claim store "accelerator" "worker-b")
    (let* ((pod (create-pod store (dra-test-pod "consumer" "accelerator")))
           (node (gr8s:schedule-pod store pod))
           (claim (gr8s::get-core-resource store "resourceclaims" "default" "accelerator"))
           (reserved (gethash "reservedFor" (gethash "status" claim))))
      (is (equal "worker-b" (gr8s:node-record-name node)))
      (is (= 1 (length reserved)))
      (is (equal (gr8s:pod-uid pod) (gethash "uid" (aref reserved 0)))))))

(test scheduler-respects-an-explicit-existing-node-name
  (with-temporary-store (store path)
    (gr8s:register-node store
                        (make-test-node "worker-a" "node-a" "10.64.0.0/20"))
    (let* ((object (com.inuoe.jzon:parse *valid-pod-json*))
           (spec (gethash "spec" object)))
      (setf (gethash "nodeName" spec) "worker-a")
      (let ((pod (create-pod store (parse-pod object))))
        (is (string= "worker-a"
                     (gr8s:node-record-name (gr8s:schedule-pod store pod))))
        (is (string= "Unknown" (gr8s:pod-scheduling-phase store pod)))))))

(test losing-node-readiness-marks-its-assigned-pods-unknown-without-moving-them
  (with-temporary-store (store path)
    (gr8s:register-node store
                        (make-test-node "worker-a" "node-a" "10.64.0.0/20"))
    (gr8s:mark-node-ready store "worker-a" 100)
    (let ((pod (create-pod store (parse-pod *valid-pod-json*))))
      (gr8s:schedule-pod store pod)
      (gr8s:update-pod-observed-phase store pod "Running")
      (is (string= "Running" (gr8s:pod-scheduling-phase store pod)))
      (gr8s:mark-node-not-ready store "worker-a")
      (is (string= "Unknown" (gr8s:pod-scheduling-phase store pod)))
      (is (string= "worker-a" (gr8s:pod-node-name pod))))))

(test heartbeat-expiry-makes-only-stale-nodes-not-ready
  (with-temporary-store (store path)
    (gr8s:register-node store
                        (make-test-node "worker-a" "node-a" "10.64.0.0/20"))
    (gr8s:register-node store
                        (make-test-node "worker-b" "node-b" "10.64.16.0/20"))
    (gr8s:mark-node-ready store "worker-a" 100)
    (gr8s:mark-node-ready store "worker-b" 200)
    (let ((expired (gr8s:expire-node-heartbeats store 150)))
      (is (= 1 (length expired)))
      (is (string= "worker-a" (gr8s:node-record-name (first expired))))
      (is-false (gr8s:node-record-ready-p (gr8s:get-node store "worker-a")))
      (is-true (gr8s:node-record-ready-p (gr8s:get-node store "worker-b"))))))

(test pod-updates-preserve-and-cannot-move-a-scheduled-assignment
  (with-temporary-store (store path)
    (gr8s:register-node store
                        (make-test-node "worker-a" "node-a" "10.64.0.0/20"))
    (gr8s:mark-node-ready store "worker-a" 100)
    (let ((pod (create-pod store (parse-pod *valid-pod-json*))))
      (gr8s:schedule-pod store pod)
      ;; Revisions are shared with Node changes, so read the Pod's rather than count them.
      (let ((updated (update-pod store (parse-pod *valid-pod-json*)
                                 (pod-resource-version (get-pod store "default" (gr8s:pod-name pod))))))
        (is (string= "worker-a" (gr8s:pod-node-name updated)))
        (is (string= "worker-a"
                     (gethash "nodeName"
                              (gethash "spec" (gr8s:pod-to-object updated))))))
      (let* ((object (com.inuoe.jzon:parse *valid-pod-json*))
             (spec (gethash "spec" object)))
        (setf (gethash "nodeName" spec) "worker-b")
        (handler-case
            (progn
              (update-pod store (parse-pod object)
                          (pod-resource-version (get-pod store "default" (gr8s:pod-name pod))))
              (fail "a scheduled Pod must not move through an update"))
          (kubernetes-error (condition)
            (is (string= "Conflict" (kubernetes-error-reason condition)))))))))

(defun capacity-test-pod (name &key cpu memory node init-cpu)
  "Build a Pod requesting CPU and MEMORY, optionally pinned to NODE or with an init container."
  (let* ((requests (gr8s::core-object)) (spec (gr8s::core-object
                                               "containers"
                                               (vector (gr8s::core-object "name" "c" "image" "busybox"
                                                                          "resources" (gr8s::core-object "requests" requests))))))
    (when cpu (setf (gethash "cpu" requests) cpu))
    (when memory (setf (gethash "memory" requests) memory))
    (when node (setf (gethash "nodeName" spec) node))
    (when init-cpu
      (setf (gethash "initContainers" spec)
            (vector (gr8s::core-object "name" "i" "image" "busybox"
                                       "resources" (gr8s::core-object "requests" (gr8s::core-object "cpu" init-cpu))))))
    (parse-pod (gr8s::core-object "apiVersion" "v1" "kind" "Pod" "spec" spec
                                  "metadata" (gr8s::core-object "name" name "namespace" "default")))))

(defun register-capacity-node (store name id cidr cpu memory &optional (pods "110"))
  "Register a ready node whose agent reported CPU, MEMORY and PODS capacity."
  (gr8s:register-node store (make-test-node name id cidr))
  (gr8s::update-node-capacity store name (gr8s::core-object "cpu" cpu "memory" memory "pods" pods))
  (gr8s:mark-node-ready store name 100))

(test requests-keep-pods-within-a-nodes-capacity
  (with-temporary-store (store path)
    (register-capacity-node store "worker-a" "node-a" "10.64.0.0/20" "2" "1Gi")
    (let ((first (create-pod store (capacity-test-pod "first" :cpu "1500m")))
          (second (create-pod store (capacity-test-pod "second" :cpu "1")))
          (third (create-pod store (capacity-test-pod "third" :memory "2Gi")))
          (free (create-pod store (capacity-test-pod "free"))))
      (is (gr8s:schedule-pod store first))
      (is-false (gr8s:schedule-pod store second))
      (is-false (gr8s:pod-node-name second))
      (is-false (gr8s:schedule-pod store third))
      (is (search "1 Insufficient cpu"
                  (gr8s::with-store-lock (store) (gr8s::pod-unschedulable-message store second))))
      (is (search "1 Insufficient memory"
                  (gr8s::with-store-lock (store) (gr8s::pod-unschedulable-message store third))))
      ;; A Pod that requests nothing fits however full the node is.
      (is (gr8s:schedule-pod store free))
      ;; A finished Pod no longer holds what it requested.
      (gr8s::update-pod-observed-phase store first "Succeeded")
      (is (gr8s:schedule-pod store second)))))

(test the-largest-init-container-request-counts-against-capacity
  (with-temporary-store (store path)
    (register-capacity-node store "worker-a" "node-a" "10.64.0.0/20" "2" "1Gi")
    (let ((large (create-pod store (capacity-test-pod "large" :cpu "100m" :init-cpu "3")))
          (small (create-pod store (capacity-test-pod "small" :cpu "1" :init-cpu "500m"))))
      (is-false (gr8s:schedule-pod store large))
      (is (gr8s:schedule-pod store small)))))

(test a-node-accepts-only-as-many-pods-as-it-reports
  (with-temporary-store (store path)
    (register-capacity-node store "worker-a" "node-a" "10.64.0.0/20" "2" "1Gi" "1")
    (let ((first (create-pod store (capacity-test-pod "first")))
          (second (create-pod store (capacity-test-pod "second"))))
      (is (gr8s:schedule-pod store first))
      (is-false (gr8s:schedule-pod store second))
      (is (search "1 Too many pods"
                  (gr8s::with-store-lock (store) (gr8s::pod-unschedulable-message store second)))))))

(test a-second-node-takes-a-pod-the-first-has-no-room-for
  (with-temporary-store (store path)
    (register-capacity-node store "worker-a" "node-a" "10.64.0.0/20" "1" "1Gi")
    (register-capacity-node store "worker-b" "node-b" "10.64.16.0/20" "4" "1Gi")
    (let ((pod (create-pod store (capacity-test-pod "wide" :cpu "2"))))
      (is (string= "worker-b" (gr8s:node-record-name (gr8s:schedule-pod store pod)))))))

(defun host-port-test-pod (name port &key ip node)
  "Build a Pod claiming host PORT, optionally on one address IP or pinned to NODE."
  (let ((declared (gr8s::core-object "containerPort" 80 "hostPort" port))
        (spec (gr8s::core-object)))
    (when ip (setf (gethash "hostIP" declared) ip))
    (when node (setf (gethash "nodeName" spec) node))
    (setf (gethash "containers" spec)
          (vector (gr8s::core-object "name" "c" "image" "busybox" "ports" (vector declared))))
    (parse-pod (gr8s::core-object "apiVersion" "v1" "kind" "Pod" "spec" spec
                                  "metadata" (gr8s::core-object "name" name "namespace" "default")))))

(test host-ports-are-validated-and-only-tcp-is-accepted
  (is (equal '(("TCP" "" . 8080)) (gr8s::pod-host-ports (host-port-test-pod "a" 8080))))
  (is (equal '(("TCP" "" . 8080)) (gr8s::pod-host-ports (host-port-test-pod "a" 8080 :ip "0.0.0.0"))))
  (is (equal '(("TCP" "10.0.0.1" . 8080)) (gr8s::pod-host-ports (host-port-test-pod "a" 8080 :ip "10.0.0.1"))))
  (signals gr8s::kubernetes-error (host-port-test-pod "a" 70000))
  (signals gr8s::kubernetes-error (host-port-test-pod "a" 8080 :ip "not-an-address"))
  (is (gr8s::host-ports-conflict-p '("TCP" "" . 1) '("TCP" "10.0.0.1" . 1)))
  (is-false (gr8s::host-ports-conflict-p '("TCP" "10.0.0.2" . 1) '("TCP" "10.0.0.1" . 1)))
  (is-false (gr8s::host-ports-conflict-p '("TCP" "" . 1) '("TCP" "" . 2)))
  (is-false (gr8s::host-ports-conflict-p '("TCP" "" . 1) '("UDP" "" . 1))))

(test the-scheduler-will-not-place-two-pods-on-one-host-port
  (with-temporary-store (store path)
    (register-capacity-node store "worker-a" "node-a" "10.64.0.0/20" "2" "1Gi")
    (let ((first (create-pod store (host-port-test-pod "first" 8080)))
          (second (create-pod store (host-port-test-pod "second" 8080)))
          (other (create-pod store (host-port-test-pod "other" 8081))))
      (is (gr8s:schedule-pod store first))
      (is (gr8s:schedule-pod store other))
      (is-false (gr8s:schedule-pod store second))
      (is (search "didn't have free ports"
                  (gr8s::with-store-lock (store) (gr8s::pod-unschedulable-message store second)))))))

(test a-node-refuses-a-pod-that-named-it-when-a-host-port-is-taken
  (with-temporary-store (store path)
    (register-capacity-node store "worker-a" "node-a" "10.64.0.0/20" "2" "1Gi")
    (let ((holder (create-pod store (host-port-test-pod "a-holder" 8080 :node "worker-a")))
          (refused (create-pod store (host-port-test-pod "refused" 8080 :node "worker-a"))))
      (is-false (gr8s::admit-assigned-pod store refused))
      (is-true (gr8s::admit-assigned-pod store holder))
      (gr8s::update-pod-observed-phase store holder "Running")
      (let ((status (gr8s::pod-observed-status store refused)))
        (is (equal "Failed" (gethash "phase" status)))
        (is (equal "NodePorts" (gethash "reason" status)))
        (is (search "free ports" (gethash "message" status))))
      ;; Admission does not depend on the order it is asked in: the holder is older.
      (is-true (gr8s::admit-assigned-pod store holder))
      ;; Refusal is final even once the port frees up, and the Pod is never published.
      (gr8s::update-pod-observed-phase store holder "Succeeded")
      (is-false (gr8s::admit-assigned-pod store refused))
      (let ((snapshot (gr8s::node-desired-state-snapshot store "worker-a")))
        (is (equal '("a-holder") (mapcar (lambda (assignment) (slot-value assignment 'gr8s.node.v1::name))
                                       (slot-value snapshot 'gr8s.node.v1::pods)))))
      ;; A replacement admitted after the holder finished may start.
      (let ((replacement (create-pod store (host-port-test-pod "replacement" 8080 :node "worker-a"))))
        (is-true (gr8s::admit-assigned-pod store replacement))))))

(test a-node-refuses-a-pod-that-named-it-when-it-is-full
  (with-temporary-store (store path)
    (register-capacity-node store "worker-a" "node-a" "10.64.0.0/20" "1" "1Gi")
    (let ((refused (create-pod store (capacity-test-pod "big" :cpu "2" :node "worker-a"))))
      (is-false (gr8s::admit-assigned-pod store refused))
      (is (equal "OutOfcpu" (gethash "reason" (gr8s::pod-observed-status store refused))))
      (is (equal "Failed" (gr8s::pod-scheduling-phase store refused))))))

(test a-refused-pod-can-be-deleted-without-its-agent
  (with-temporary-store (store path)
    (register-capacity-node store "worker-a" "node-a" "10.64.0.0/20" "1" "1Gi")
    (let* ((runtime (gr8s::make-control-plane-runtime store nil))
           (pod (create-pod store (capacity-test-pod "big" :cpu "2" :node "worker-a"))))
      (is-false (gr8s::admit-assigned-pod store pod))
      (is-true (gr8s::with-store-lock (store) (gr8s::pod-admission-rejected-p store pod)))
      (let ((deleted (gr8s::mark-pod-deleting store "default" "big" :uid (pod-uid pod))))
        (is-false (gr8s::admit-assigned-pod store deleted))
        (handler-case (is-true (gr8s::runtime-delete-pod runtime deleted))
          ;; This test has no node server to tell, and the Pod's refusal must not need one.
          (error (condition) (fail "A refused Pod needed its agent: ~A" condition)))))))

(test a-host-port-relays-a-tcp-connection-both-ways
  (let ((upstream (make-instance 'sb-bsd-sockets:inet-socket :type :stream :protocol :tcp))
        (forwarder nil))
    (unwind-protect
         (progn
           (setf (sb-bsd-sockets:sockopt-reuse-address upstream) t)
           (sb-bsd-sockets:socket-bind upstream #(127 0 0 1) 0)
           (sb-bsd-sockets:socket-listen upstream 5)
           (let* ((upstream-port (nth-value 1 (sb-bsd-sockets:socket-name upstream)))
                  (echo (bt:make-thread
                         (lambda ()
                           (let ((connection (sb-bsd-sockets:socket-accept upstream))
                                 (buffer (make-array 16 :element-type '(unsigned-byte 8))))
                             (multiple-value-bind (data length) (sb-bsd-sockets:socket-receive connection buffer nil)
                               (declare (ignore data))
                               (sb-bsd-sockets:socket-send connection (subseq buffer 0 length) length))
                             (sb-bsd-sockets:socket-shutdown connection :direction :output)
                             (sb-bsd-sockets:socket-close connection)))))
                  (client (make-instance 'sb-bsd-sockets:inet-socket :type :stream :protocol :tcp)))
             (setf forwarder (gr8s::start-host-port-forwarder "127.0.0.1" 0 (cons "127.0.0.1" upstream-port)))
             (sb-bsd-sockets:socket-connect client #(127 0 0 1)
                                            (nth-value 1 (sb-bsd-sockets:socket-name (gr8s::host-port-forwarder-listener forwarder))))
             (let ((message (coerce #(1 2 3) '(vector (unsigned-byte 8))))
                   (buffer (make-array 16 :element-type '(unsigned-byte 8))))
               (sb-bsd-sockets:socket-send client message 3)
               (multiple-value-bind (data length) (sb-bsd-sockets:socket-receive client buffer nil)
                 (declare (ignore data))
                 (is (= 3 length))
                 (is (equalp #(1 2 3) (subseq buffer 0 3)))))
             (bt:join-thread echo)
             (sb-bsd-sockets:socket-close client)))
      (when forwarder (gr8s::stop-host-port-forwarder forwarder))
      (sb-bsd-sockets:socket-close upstream))))

(test the-host-port-table-follows-the-pods
  (with-temporary-store (store path)
    (let* ((forwarders (make-hash-table :test #'equal))
           (pod (create-pod store (host-port-test-pod "web" 0)))
           ;; A host port is the Pod's choice, so take one the kernel just found free.
           (host-port (let ((probe (usocket:socket-listen "127.0.0.1" 0)))
                        (prog1 (usocket:get-local-port probe) (usocket:socket-close probe)))))
      (declare (ignorable pod))
      (let* ((declared (gr8s::core-object "containerPort" 80 "hostPort" host-port "hostIP" "127.0.0.1"))
             (input (gr8s::core-object "apiVersion" "v1" "kind" "Pod"
                                       "metadata" (gr8s::core-object "name" "served" "namespace" "default")
                                       "spec" (gr8s::core-object "containers"
                                                                 (vector (gr8s::core-object "name" "c" "image" "busybox"
                                                                                            "ports" (vector declared))))))
             (served (create-pod store (parse-pod input))))
        (unwind-protect
             (progn
               (gr8s::converge-host-port-forwarders forwarders store)
               (is (zerop (hash-table-count forwarders)) "A Pod with no address has nothing to relay to")
               (gr8s::update-pod-observed-status store served (gr8s::core-object "phase" "Running" "podIP" "10.1.2.3"))
               (gr8s::converge-host-port-forwarders forwarders store)
               (let ((forwarder (gethash (list* "TCP" "127.0.0.1" host-port) forwarders)))
                 (is (equal '("10.1.2.3" . 80) (gr8s::host-port-forwarder-target forwarder))))
               (gr8s::update-pod-observed-status store served (gr8s::core-object "phase" "Failed" "podIP" "10.1.2.3"))
               (gr8s::converge-host-port-forwarders forwarders store)
               (is (zerop (hash-table-count forwarders))))
          (gr8s::stop-host-port-forwarders forwarders))))))
