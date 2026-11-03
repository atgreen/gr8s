(defpackage #:gr8s/tests
  (:use #:cl #:fiveam)
  (:import-from #:gr8s
                #:create-pod
                #:container-spec-args
                #:container-spec-command
                #:container-spec-env
                #:container-spec-image
                #:container-spec-name
                #:container-spec-ports
                #:kubernetes-error
                #:kubernetes-error-reason
                #:delete-pod
                #:fake-runtime-ensure-count
                #:get-pod
                #:list-pods
                #:make-fake-runtime
                #:make-podman-runtime
                #:make-reconciler
                #:mark-pod-deleting
                #:open-store
                #:parse-pod
                #:pod-containers
                #:pod-name
                #:pod-namespace
                #:pod-restart-policy
                #:podman-create-plan
                #:parse-cli-options
                #:pod-resource-version
                #:pod-to-object
                #:pod-uid
                #:reconcile-all
                #:reconcile-pod
                #:reconciler-logs
                #:runtime-observe
                #:runtime-delete
                #:runtime-ensure
                #:runtime-error
                #:runtime-error-message
                #:runtime-logs
                #:runtime-pod-resource-version
                #:runtime-pod-phase
                #:runtime-pod-uid
                #:set-fake-runtime-failure
                #:start-server
                #:start-reconciliation-worker
                #:stop-reconciliation-worker
                #:stop-server
                #:update-pod))

(in-package #:gr8s/tests)

(def-suite gr8s)
(in-suite gr8s)
