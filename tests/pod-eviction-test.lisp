;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Verify the policy/v1 Eviction subresource of Pods: it marks the DisruptionTarget
;;;; condition, then deletes gracefully, honoring its preconditions and names.

(in-package #:gr8s/tests)
(def-suite pod-eviction :in gr8s)
(in-suite pod-eviction)

(defun evict-pod-request (name &optional (body (format nil "{\"apiVersion\":\"policy/v1\",\"kind\":\"Eviction\",\"metadata\":{\"name\":~S,\"namespace\":\"default\"}}" name)))
  "POST an Eviction for the Pod NAME in the default namespace."
  (pod-api (format nil "/~A/eviction" name) :method :post :content body))

(test eviction-marks-the-disruption-and-deletes-the-pod
  (with-core-api (store path)
    (values path)
    (let ((object (pod-to-object (status-test-pod store "web"))))
      ;; A finalizer keeps the deleted Pod readable after its containers stop.
      (setf (gethash "finalizers" (gethash "metadata" object)) #("example.com/hold"))
      (update-pod store (parse-pod object) (gethash "resourceVersion" (gethash "metadata" object)))
      (is (= 201 (nth-value 1 (evict-pod-request "web"))))
      (let ((object (pod-api "/web")))
        (is (equal "True" (pod-condition-status object "DisruptionTarget")))
        (is (stringp (gethash "deletionTimestamp" (gethash "metadata" object))))))))

(test eviction-of-an-absent-pod-is-not-found
  (with-core-api (store path)
    (values path store)
    (is (= 404 (nth-value 1 (evict-pod-request "absent"))))))

(test eviction-checks-its-uid-precondition-and-name
  (with-core-api (store path)
    (values path)
    (status-test-pod store "web")
    (is (= 409 (nth-value 1 (evict-pod-request "web" "{\"metadata\":{\"name\":\"web\"},\"deleteOptions\":{\"preconditions\":{\"uid\":\"other\"}}}"))))
    (is (= 400 (nth-value 1 (evict-pod-request "web" "{\"metadata\":{\"name\":\"other\"}}"))))
    (is (null (gethash "deletionTimestamp" (gethash "metadata" (pod-to-object (get-pod store "default" "web"))))))))

(test eviction-decodes-the-typed-wire-form
  ;; Field 1 is metadata holding name "web"; field 2 is empty DeleteOptions.
  (let* ((meta (coerce (append '(10 3) (map 'list #'char-code "web")) 'list))
         (eviction (append (list 10 (length meta)) meta (list 18 0)))
         (bytes (coerce (append '(107 56 115 0) (list 18 (length eviction)) eviction)
                        '(vector (unsigned-byte 8))))
         (object (gr8s::decode-eviction-protobuf bytes)))
    (is (equal "web" (gethash "name" (gethash "metadata" object))))))
