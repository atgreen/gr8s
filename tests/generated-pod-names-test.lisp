;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Verify generated Pod names across JSON/protobuf admission, collisions,
;;;; concurrent creates, persistence and ServiceAccount credential injection.

(in-package #:gr8s/tests)
(in-suite gr8s)

(defun generated-pod-input (&optional (prefix "generated-"))
  "Build a fresh unnamed Pod request with PREFIX."
  (let* ((object (com.inuoe.jzon:parse *valid-pod-json*))
         (metadata (gethash "metadata" object)))
    (remhash "name" metadata)
    (setf (gethash "generateName" metadata) prefix)
    object))

(test generated-pod-names-have-server-identity-and-survive-reopen
  (with-temporary-store (store path)
    (let ((created (create-pod store (parse-pod (generated-pod-input) :allow-generate-name t))))
      (is (uiop:string-prefix-p "generated-" (pod-name created)))
      (is (= 15 (length (pod-name created))))
      (is (equal "generated-" (gethash "generateName" (gethash "metadata" (pod-to-object created)))))
      (is (equal (pod-uid created) (pod-uid (get-pod (open-store path) "default" (pod-name created))))))))

(test long-pod-names-keep-full-cri-identity-with-a-bounded-hostname
  (let ((prefix (make-string 62 :initial-element #\a)))
    (dolist (name (list (make-string 253 :initial-element #\a)
                        (concatenate 'string prefix "--tail")
                        (concatenate 'string prefix ".tail")))
      (let* ((config (gr8s::make-cri-pod-sandbox-config name "uid" "default" 0 "/tmp/logs" nil))
             (hostname (gr8s.cri.v1::hostname config)))
        (is (<= (length hostname) 63))
        (is (not (find (char hostname (1- (length hostname))) "-.")))
        (is (equal name (gr8s.cri.v1::name (gr8s.cri.v1::metadata config))))))))

(test pod-name-generation-validates-prefix-and-preserves-explicit-name
  (with-temporary-store (store path)
    (dolist (prefix '("Bad-" "a/b" "-bad" "-" "foo." "" 7))
      (signals kubernetes-error (parse-pod (generated-pod-input prefix) :allow-generate-name t)))
    (signals kubernetes-error (parse-pod (generated-pod-input)))
    (let ((input (generated-pod-input))
          (gr8s::*pod-name-generator* (lambda (prefix) (declare (ignore prefix)) (error "must not generate"))))
      (setf (gethash "name" (gethash "metadata" input)) "explicit")
      (is (equal "explicit" (pod-name (create-pod store (parse-pod input :allow-generate-name t))))))
    ;; Kubernetes DNS-subdomain names allow a 253-byte label; Namespace and
    ;; container names still use their separate 63-byte DNS-label validator.
    (let ((long (make-string 253 :initial-element #\a)))
      (let ((input (generated-pod-input long)))
        (let ((pod (create-pod store (parse-pod input :allow-generate-name t))))
          (is (= 63 (length (pod-name pod))))
          (is (equal (subseq long 0 58) (subseq (pod-name pod) 0 58)))))
      (let ((input (generated-pod-input)))
        (setf (gethash "name" (gethash "metadata" input)) long)
        (is (equal long (pod-name (create-pod store (parse-pod input)))))))
    (signals kubernetes-error
      (parse-pod (generated-pod-input (make-string 254 :initial-element #\a)) :allow-generate-name t))))

(test generated-pod-name-collisions-retry-without-overwriting-existing-uid
  (with-temporary-store (store path)
    (let* ((existing (create-pod store (parse-pod *valid-pod-json*)))
           (calls 0)
           (gr8s::*pod-name-generator* (lambda (prefix) (declare (ignore prefix))
                                        (if (= 1 (incf calls)) "hello" "generated-fresh")))
           (created (create-pod store (parse-pod (generated-pod-input) :allow-generate-name t))))
      (is (= 2 calls))
      (is (equal "generated-fresh" (pod-name created)))
      (is (equal (pod-uid existing) (pod-uid (get-pod store "default" "hello"))))
      (let* ((input (parse-pod (generated-pod-input) :allow-generate-name t))
             (attempts 0)
             (gr8s::*pod-name-generator* (lambda (prefix) (declare (ignore prefix)) (incf attempts) "hello")))
        (handler-case
            (progn (create-pod store input) (fail "Expected generated name exhaustion"))
          (kubernetes-error (error)
            (is (= 409 (gr8s::kubernetes-error-status-code error)))
            (is (equal "AlreadyExists" (kubernetes-error-reason error)))))
        (is (= 8 attempts))
        (is (null (pod-name input)))
        (is (= 2 (length (list-pods (open-store path)))))))))

(test concurrent-generated-pod-creates-remain-distinct
  (with-temporary-store (store path)
    (let* ((results (make-array 12))
           (threads (loop for index below 12 collect
                       (let ((slot index))
                         (bt:make-thread
                          (lambda ()
                            (setf (aref results slot)
                                  (create-pod store (parse-pod (generated-pod-input) :allow-generate-name t)))))))))
      (mapc #'bt:join-thread threads)
      (is (= 12 (length (remove-duplicates (map 'list #'pod-name results) :test #'equal))))
      (is (= 12 (length (remove-duplicates (map 'list #'pod-uid results) :test #'equal))))
      (is (= 12 (length (list-pods (open-store path))))))))

(test generated-pods-pass-service-account-admission-before-name-assignment
  (with-temporary-store (store path)
    (service-account-test-store store "default" "default")
    (let* ((unnamed (parse-pod (generated-pod-input) :allow-generate-name t))
           (admitted (gr8s::admit-in-cluster-pod store unnamed))
           (created (create-pod store admitted))
           (spec (gethash "spec" (pod-to-object created))))
      (is (uiop:string-prefix-p "generated-" (pod-name created)))
      (is (equal "default" (gethash "serviceAccountName" spec)))
      (is (plusp (length (gethash "volumes" spec)))))))

(test generated-pod-http-supports-json-and-typed-protobuf
  (with-core-api (store path)
    (values path)
    (let* ((collection "/api/v1/namespaces/alpha/pods")
           (created (check-core-status 201 collection :method :post :object (generated-pod-input)))
           (name (gethash "name" (gethash "metadata" created)))
           (item (concatenate 'string collection "/" name)))
      (is (uiop:string-prefix-p "generated-" name))
      (is (equal "alpha" (gethash "namespace" (gethash "metadata" created))))
      (check-core-status 200 item)
      ;; Generation is allowed only on create. PUT still requires a name.
      (check-core-status 422 item :method :put :object (generated-pod-input))
      (let* ((metadata (core-test-protobuf '((1 "") (2 "wire-generated-"))))
             (container (core-test-protobuf '((1 "main") (2 "busybox"))))
             (spec (core-test-protobuf (list (list 2 container))))
             (input (core-test-protobuf-envelope "Pod" (list (list 1 metadata) (list 2 spec))))
             (wire (check-core-status 201 collection :method :post
                     :content-type "application/vnd.kubernetes.protobuf" :octets input)))
        (is (uiop:string-prefix-p "wire-generated-" (gethash "name" (gethash "metadata" wire)))))
      (is (= 2 (length (list-pods store "alpha")))))))

(test http-resource-names-distinguish-subdomains-from-service-and-namespace-labels
  (with-core-api (store path)
    (values store path)
    (let* ((long (make-string 253 :initial-element #\a))
           (collection "/api/v1/namespaces/alpha/configmaps")
           (created (check-core-status 201 collection :method :post
                      :object (core-fixture "ConfigMap" long "data" (gr8s::core-object "key" "value")))))
      (is (equal long (gethash "name" (gethash "metadata" created))))
      (check-core-status 200 (concatenate 'string collection "/" long)))
    (dolist (name (list (make-string 64 :initial-element #\a) "has.dots"))
      (check-core-status 422 "/api/v1/namespaces/alpha/services" :method :post :object (service-test-object name))
      (check-core-status 422 "/api/v1/namespaces" :method :post
                         :object (gr8s::core-object "metadata" (gr8s::core-object "name" name))))
    (check-core-status 201 "/api/v1/namespaces/alpha/services" :method :post :object (service-test-object "123-service"))))
