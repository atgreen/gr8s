(in-package #:gr8s/tests)
(def-suite core-resources :in gr8s)
(in-suite core-resources)

(defun core-fixture (kind name &rest fields)
  (apply #'gr8s::core-object "apiVersion" "v1" "kind" kind
         "metadata" (gr8s::core-object "name" name) fields))

(defun core-resource-status (function)
  (handler-case (progn (funcall function) nil)
    (kubernetes-error (condition) (gr8s::kubernetes-error-status-code condition))))

(test core-resources-survive-restart-and-isolate-namespaces-and-returned-values
  (with-temporary-store (store path)
    (let* ((created (gr8s::create-core-resource store "configmaps"
                     (core-fixture "ConfigMap" "settings" "data" (gr8s::core-object "key" "one")) "alpha"))
           (uid (gethash "uid" (gethash "metadata" created))))
      (gr8s::create-core-resource store "configmaps" (core-fixture "ConfigMap" "settings") "beta")
      (setf (gethash "key" (gethash "data" created)) "not stored")
      (let* ((reopened (open-store path))
             (read (gr8s::get-core-resource reopened "configmaps" "alpha" "settings")))
        (is (string= uid (gethash "uid" (gethash "metadata" read))))
        (is (string= "one" (gethash "key" (gethash "data" read)))))
      (is (= 1 (length (gr8s::list-core-resources store "configmaps" "alpha"))))
      (is (= 2 (length (gr8s::list-core-resources store "configmaps"))))
      (is (= 404 (core-resource-status (lambda () (gr8s::get-core-resource store "secrets" "alpha" "settings")))))
      (is (= 409 (core-resource-status (lambda () (gr8s::create-core-resource store "configmaps" (core-fixture "ConfigMap" "settings") "alpha"))))))))

(test core-resource-updates-and-deletes-enforce-concurrency-and-preconditions
  (with-temporary-store (store path)
    (values path)
    (let* ((created (gr8s::create-core-resource store "configmaps" (core-fixture "ConfigMap" "settings") "default"))
           (first-version (gethash "resourceVersion" (gethash "metadata" created)))
           (updated (gr8s::update-core-resource store "configmaps" "default" "settings"
                      (lambda (old) (setf (gethash "data" old) (gr8s::core-object "x" "y")) old))))
      (is (not (string= first-version (gethash "resourceVersion" (gethash "metadata" updated)))))
      (is (= 409 (core-resource-status
                  (lambda () (gr8s::update-core-resource store "configmaps" "default" "settings"
                               (lambda (old) (declare (ignore old)) created))))))
      (is (= 409 (core-resource-status
                  (lambda () (gr8s::delete-core-resource store "configmaps" "default" "settings" :uid "wrong")))))
      (gr8s::delete-core-resource store "configmaps" "default" "settings"
                                 :uid (gethash "uid" (gethash "metadata" updated))
                                 :resource-version (gethash "resourceVersion" (gethash "metadata" updated)))
      (is (null (gr8s::list-core-resources (open-store path) "configmaps"))))))

(test secrets-merge-string-data-on-write-and-store-only-base64
  (with-temporary-store (store path)
    (let ((secret (gr8s::create-core-resource store "secrets"
                    (core-fixture "Secret" "credentials"
                                  "data" (gr8s::core-object "password" "b2xk" "bytes" "AP8=")
                                  "stringData" (gr8s::core-object "password" "new")) "default")))
      (is (string= "Opaque" (gethash "type" secret)))
      (is (null (gethash "stringData" secret)))
      (is (string= "bmV3" (gethash "password" (gethash "data" secret))))
      (is (string= "AP8=" (gethash "bytes" (gethash "data" secret))))
      (is (null (search "stringData" (uiop:read-file-string (gr8s::core-resource-state-path store)))))
      (is (= #o600 (logand #o777 (sb-posix:stat-mode (sb-posix:stat (gr8s::core-resource-state-path store)))))))))

(test invalid-core-resource-input-is-rejected-without-changing-state
  (with-temporary-store (store path)
    (values path)
    (dolist (fixture
              (list (list "configmaps" (core-fixture "ConfigMap" "bad" "data" (gr8s::core-object "same" "plain")
                                                      "binaryData" (gr8s::core-object "same" "Yg==")) 422)
                    (list "secrets" (core-fixture "Secret" "bad" "data" (gr8s::core-object "password" "!!!")) 400)
                    (list "secrets" (core-fixture "Secret" "bad" "data" (gr8s::core-object "../key" "Yg==")) 422)
                    (list "secrets" (core-fixture "Secret" "bad" "type" "kubernetes.io/tls") 422)
                    (list "configmaps" (core-fixture "ConfigMap" "bad" "immutable" "true") 422)
                    (list "configmaps" (core-fixture "ConfigMap" "bad" "data" (gr8s::core-object "huge" (make-string (1+ (* 1024 1024)) :initial-element #\x))) 422)))
      (is (= (third fixture) (core-resource-status
                             (lambda () (gr8s::create-core-resource store (first fixture) (second fixture) "default"))))))
    (is (zerop (gr8s::pod-store-resource-revision store)))
    (is (zerop (hash-table-count (gr8s::pod-store-resources store))))))

(test immutable-core-resources-permit-only-metadata-updates
  (with-temporary-store (store path)
    (values path)
    (gr8s::create-core-resource store "configmaps"
                               (core-fixture "ConfigMap" "fixed" "immutable" t "data" (gr8s::core-object "key" "fixed")) "default")
    (gr8s::update-core-resource store "configmaps" "default" "fixed"
      (lambda (old) (setf (gethash "labels" (gethash "metadata" old)) (gr8s::core-object "app" "test")) old))
    (is (= 422 (core-resource-status
                (lambda () (gr8s::update-core-resource store "configmaps" "default" "fixed"
                             (lambda (old) (setf (gethash "key" (gethash "data" old)) "changed") old))))))
    (is (= 422 (core-resource-status
                (lambda () (gr8s::update-core-resource store "configmaps" "default" "fixed"
                             (lambda (old) (remhash "immutable" old) old))))))))

(test dry-run-core-resource-writes-do-not-persist-or-consume-revisions
  (with-temporary-store (store path)
    (values path)
    (gr8s::create-core-resource store "configmaps" (core-fixture "ConfigMap" "dry") "default" :dry-run t)
    (is (null (gr8s::list-core-resources store "configmaps")))
    (gr8s::create-core-resource store "configmaps" (core-fixture "ConfigMap" "dry") "default")
    (gr8s::delete-core-resource store "configmaps" "default" "dry" :dry-run t)
    (is (= 1 (length (gr8s::list-core-resources store "configmaps"))))
    (is (= 1 (gr8s::pod-store-resource-revision store)))))

(test maximum-size-secret-survives-the-json-storage-roundtrip
  (with-temporary-store (store path)
    (let* ((bytes (make-array (* 1024 1024) :element-type '(unsigned-byte 8) :initial-element 255))
           (encoded (ag-grpc:base64-encode bytes)))
      (gr8s::create-core-resource store "secrets"
                                 (core-fixture "Secret" "large" "data" (gr8s::core-object "payload" encoded)) "default")
      (let ((loaded (gr8s::get-core-resource (open-store path) "secrets" "default" "large")))
        (is (string= encoded (gethash "payload" (gethash "data" loaded))))))))

(in-suite gr8s)
