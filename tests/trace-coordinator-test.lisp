(in-package #:gr8s/tests)

(in-suite gr8s)

(test trace-coordinator-groups-only-running-scheduled-selector-matches
  (with-temporary-store (store path)
    (declare (ignore path))
    (flet ((add (name uid node phase app)
             (let ((pod (gr8s.model::make-pod
                         :name name :namespace "alpha" :uid uid :node-name node
                         :containers #()
                         :object (gr8s.resources::core-object
                                  "metadata" (gr8s.resources::core-object
                                              "name" name "namespace" "alpha"
                                              "uid" uid "labels" (gr8s.resources::core-object "app" app))
                                  "spec" (gr8s.resources::core-object "containers" #() "nodeName" node)
                                  "status" (gr8s.resources::core-object "phase" phase)))))
               (gr8s.agent::put-assigned-pod store pod))))
      (add "a" "uid-a" "node-2" "Running" "api")
      (add "b" "uid-b" "node-1" "Running" "api")
      (add "c" "uid-c" "node-1" "Pending" "api")
      (add "d" "uid-d" "node-1" "Running" "other")
      (is (equal '(("node-1" "uid-b") ("node-2" "uid-a"))
                 (mapcar (lambda (entry) (cons (car entry) (cdr entry)))
                         (gr8s.apiserver::trace-node-groups store "alpha" "app=api")))))))

(test trace-coordinator-rejects-an-empty-selection
  (with-temporary-store (store path)
    (declare (ignore path))
    (signals gr8s.runtime:runtime-error
      (gr8s.apiserver::start-trace-coordinator
       nil store "alpha" "app=missing" "kprobe:vfs_read { @=count(); }" 1000))))

(test trace-websocket-get-authorizes-as-create-on-the-virtual-resource
  (multiple-value-bind (verb group resource name namespace)
      (gr8s.apiserver::kubernetes-authorization-target
       "/apis/gr8s.io/v1/namespaces/alpha/traces" :get)
    (is (string= "create" verb))
    (is (string= "gr8s.io" group))
    (is (string= "traces" resource))
    (is (null name))
    (is (string= "alpha" namespace))))

(test trace-request-frame-enforces-source-selector-and-duration-limits
  (let ((request
          (gr8s.apiserver::parse-trace-request-frame
           (trivial-utf-8:string-to-utf-8-bytes
            "{\"source\":\"kprobe:vfs_read { @=count(); }\",\"selector\":\"app=api\",\"durationMilliseconds\":1000}"))))
    (is (string= "app=api" (getf request :selector)))
    (is (= 1000 (getf request :duration-milliseconds))))
  (signals gr8s.model::kubernetes-error
    (gr8s.apiserver::parse-trace-request-frame
     (trivial-utf-8:string-to-utf-8-bytes
      "{\"source\":\"\",\"selector\":\"app=api\",\"durationMilliseconds\":1000}")))
  (signals gr8s.model::kubernetes-error
    (gr8s.apiserver::parse-trace-request-frame
     (trivial-utf-8:string-to-utf-8-bytes
      "{\"source\":\"kprobe:vfs_read { @=count(); }\",\"selector\":\"app=api\",\"durationMilliseconds\":300001}"))))
