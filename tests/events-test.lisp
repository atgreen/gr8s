;;;; SPDX-FileCopyrightText: 2026 gr8s contributors
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Verify shared Event identities across API versions, typed MicroTime input,
;;;; selectors, collection deletion, watch projection, TTL and atomic failures.

(in-package #:gr8s/tests)
(def-suite events :in gr8s)
(in-suite events)

(defun event-fixture (name &optional modern)
  "Return a modern or legacy Event without depending on an executable Pod."
  (let ((object (gr8s::core-object "apiVersion" "v1" "kind" "Event"
                                  "metadata" (gr8s::core-object "name" name "labels" (gr8s::core-object "test" "event"))
                                  "involvedObject" (gr8s::core-object "namespace" "alpha" "kind" "Pod" "name" "worker")
                                  "eventTime" "2017-09-19T14:42:36.000000Z"
                                  "message" "Observed worker" "reason" "Test" "action" "Observe" "type" "Normal"
                                  "reportingComponent" "test-controller" "reportingInstance" "test-node" "count" 1)))
    (if modern (gr8s::convert-event-fields object t) object)))

(test event-versions-share-identity-selectors-patches-and-unconditional-updates
  (with-core-api (store path)
    (let* ((core "/api/v1/namespaces/alpha/events") (modern "/apis/events.k8s.io/v1/namespaces/alpha/events")
           (created (check-core-status 201 modern :method :post :object (event-fixture "shared" t)))
           (metadata (gethash "metadata" created))
           (core-item (concatenate 'string core "/shared")) (modern-item (concatenate 'string modern "/shared")))
      (is (equal "events.k8s.io/v1" (gethash "apiVersion" created)))
      (let ((legacy (check-core-status 200 core-item)))
        (is (equal "Observed worker" (gethash "message" legacy)))
        (is (equal (gethash "uid" metadata) (gethash "uid" (gethash "metadata" legacy)))))
      (dolist (url (list core "/api/v1/events"))
        (let ((page (check-core-status 200 url :parameters '(("fieldSelector" . "source=test-controller")))))
          (is (= 1 (length (gethash "items" page))))))
      (let ((page (check-core-status 200 modern :parameters '(("fieldSelector" . "reportingController=test-controller,regarding.name=worker")))))
        (is (= 1 (length (gethash "items" page)))))
      (check-core-status 200 core-item :method :patch :content-type "application/merge-patch+json"
                         :object (gr8s::core-object "message" "Patched through core"))
      (is (equal "Patched through core" (gethash "note" (check-core-status 200 modern-item))))
      (check-core-status 200 modern-item :method :patch :content-type "application/strategic-merge-patch+json"
                         :object (gr8s::core-object "series" (gr8s::core-object "count" 2 "lastObservedTime" "2017-09-19T14:42:31Z")))
      (let* ((current (check-core-status 200 modern-item)) (series (gethash "series" current)))
        (setf (gethash "count" series) 100 (gethash "resourceVersion" (gethash "metadata" current)) "")
        (check-core-status 200 modern-item :method :put :object current)
        (is (= 100 (gethash "count" (gethash "series" (check-core-status 200 core-item))))))
      (is (= 1 (length (gr8s::list-core-resources (open-store path) "events" "alpha"))))
      (check-core-status 409 modern-item :method :put :object created)
      (check-core-status 400 modern :parameters '(("fieldSelector" . "spec.fake=x")))
      (check-core-status 200 modern-item :method :delete)
      (check-core-status 404 core-item))))

(test event-collection-delete-is-scoped-and-patch-failures-are-atomic
  (with-core-api (store path)
    (values path)
    (let ((core "/api/v1/namespaces/alpha/events") (modern "/apis/events.k8s.io/v1/namespaces/alpha/events"))
      (check-core-status 201 core :method :post :object (event-fixture "selected"))
      (let ((other (event-fixture "other")))
        (setf (gethash "test" (gethash "labels" (gethash "metadata" other))) "other")
        (check-core-status 201 core :method :post :object other))
      (let* ((item (concatenate 'string core "/selected"))
             (before (com.inuoe.jzon:stringify (gr8s::get-core-resource store "events" "alpha" "selected"))))
        (check-core-status 422 item :method :patch :content-type "application/merge-patch+json"
                           :object (gr8s::core-object "series" (gr8s::core-object "count" 1)))
        (check-core-status 422 item :method :patch :content-type "application/merge-patch+json"
                           :object (gr8s::core-object "reason" "Changed identity"))
        (check-core-status 200 (concatenate 'string item "?dryRun=All") :method :patch :content-type "application/merge-patch+json"
                           :object (gr8s::core-object "message" "Preview only"))
        (is (equal before (com.inuoe.jzon:stringify (gr8s::get-core-resource store "events" "alpha" "selected")))))
      (check-core-status 200 modern :method :delete :parameters '(("labelSelector" . "test=event") ("dryRun" . "All")))
      (check-core-status 200 (concatenate 'string core "/selected"))
      (check-core-status 200 modern :method :delete :parameters '(("labelSelector" . "test=event")))
      (check-core-status 404 (concatenate 'string core "/selected"))
      (check-core-status 200 (concatenate 'string core "/other")))))

(test typed-event-versions-preserve-microseconds-and-reject-wrong-envelopes
  (with-core-api (store path)
    (values store path)
    (let* ((metadata (core-test-protobuf '((1 "wire"))))
           (reference (core-test-protobuf '((1 "Pod") (2 "alpha") (3 "worker"))))
           (timestamp (core-test-protobuf '((1 1505828956) (2 123456000))))
           (core (core-test-protobuf-envelope "Event" (list (list 1 metadata) (list 2 reference) (list 3 "Test")
                         (list 4 "Wire note") (list 8 1) (list 9 "Normal") (list 10 timestamp)
                         (list 12 "Observe") (list 14 "test-controller") (list 15 "test-node"))))
           (created (check-core-status 201 "/api/v1/namespaces/alpha/events" :method :post
                                     :content-type "application/vnd.kubernetes.protobuf" :octets core)))
      (is (equal "2017-09-19T13:49:16.123456Z" (gethash "eventTime" created)))
      (check-core-status 200 "/api/v1/namespaces/alpha/events/wire" :method :delete)
      (let* ((input (core-test-protobuf-envelope "Event" (list (list 1 metadata) (list 2 timestamp)
                          (list 4 "test-controller") (list 5 "test-node") (list 6 "Observe") (list 7 "Test")
                          (list 8 reference) (list 10 "Modern note") (list 11 "Normal")) "events.k8s.io/v1"))
             (created (check-core-status 201 "/apis/events.k8s.io/v1/namespaces/alpha/events" :method :post
                                       :content-type "application/vnd.kubernetes.protobuf" :octets input)))
        (is (equal "Modern note" (gethash "note" created)))
        (is (equal "2017-09-19T13:49:16.123456Z" (gethash "eventTime" created)))
        (check-core-status 400 "/api/v1/namespaces/alpha/events" :method :post
                           :content-type "application/vnd.kubernetes.protobuf" :octets input)))))

(test modern-event-watch-projects-real-core-mutations
  (with-core-api (store path)
    (values path)
    (gr8s::create-core-resource store "events" (event-fixture "watched") "alpha")
    (sb-sys:with-deadline (:seconds 10)
      (multiple-value-bind (stream code)
          (drakma:http-request "http://127.0.0.1:18089/apis/events.k8s.io/v1/namespaces/alpha/events" :want-stream t
            :parameters '(("watch" . "true") ("resourceVersion" . "0") ("timeoutSeconds" . "2")))
        (unwind-protect
             (progn
               (is (= 200 code))
               (let* ((event (read-template-watch-event stream)) (object (gethash "object" event)))
                 (is (equal "ADDED" (gethash "type" event)))
                 (is (equal "events.k8s.io/v1" (gethash "apiVersion" object)))
                 (is (equal "Observed worker" (gethash "note" object))))
               (gr8s::delete-core-resource store "events" "alpha" "watched")
               (is (equal "DELETED" (gethash "type" (read-template-watch-event stream)))))
          (close stream))))))

(test event-ttl-survives-restart-refreshes-on-write-and-emits-deletion
  (with-temporary-store (store path)
    (let* ((now 1000) (gr8s::*event-clock* (lambda () now))
           (event (gr8s::create-core-resource store "events" (event-fixture "expires") "alpha"))
           (revision (parse-integer (gethash "resourceVersion" (gethash "metadata" event)))))
      (setf now 4000)
      (gr8s::update-core-resource store "events" "alpha" "expires"
        (lambda (object) (setf (gethash "message" object) "Refreshed") object))
      (setf now 5000)
      (let ((reopened (open-store path)))
        (is (equal "Refreshed" (gethash "message" (gr8s::get-core-resource reopened "events" "alpha" "expires"))))
        (setf now 7600)
        (is (= 404 (core-resource-status (lambda () (gr8s::get-core-resource reopened "events" "alpha" "expires")))))
        (multiple-value-bind (events watermark) (gr8s::template-watch-events reopened "alpha" "" "" revision :resource "events")
          (declare (ignore watermark))
          (is (equal '("MODIFIED" "DELETED") (mapcar (lambda (item) (gethash "type" item)) events))))))))

(test event-time-normalization-checks-calendar-offsets-and-precision
  (is (equal "2017-09-19T14:42:36.123456Z" (gr8s::normalize-event-time "2017-09-19T16:42:36.123456789+02:00" :micro t)))
  (dolist (invalid '("2017-02-30T10:00:00Z" "2017-09-19T25:00:00Z" "2017-09-19T10:00:00.1234567890Z" "invalid"))
    (is (= 422 (core-resource-status (lambda () (gr8s::normalize-event-time invalid :micro t)))))))

(test event-api-versions-enforce-distinct-rbac-groups
  (with-core-api (store directory)
    (let* ((pki (gr8s:ensure-cluster-pki (merge-pathnames "pki/" directory)))
           (runtime (make-fake-runtime)) (reconciler (make-reconciler store runtime)) (tls-server nil))
      (service-account-test-store store)
      (let* ((secret (gr8s::ensure-service-account-credential store "alpha" "reader"))
             (token (service-account-test-token secret)))
        (gr8s::create-core-resource store "roles"
          (gr8s::core-object "metadata" (gr8s::core-object "name" "events")
                            "rules" (vector (gr8s::core-object "apiGroups" #("") "resources" #("events") "verbs" #("list")))) "alpha")
        (gr8s::create-core-resource store "rolebindings"
          (gr8s::core-object "metadata" (gr8s::core-object "name" "events")
                            "roleRef" (gr8s::core-object "apiGroup" "rbac.authorization.k8s.io" "kind" "Role" "name" "events")
                            "subjects" (vector (gr8s::core-object "kind" "ServiceAccount" "name" "reader" "namespace" "alpha"))) "alpha")
        (unwind-protect
             (progn
               (setf tls-server (gr8s::start-in-cluster-api store runtime reconciler pki :address "127.0.0.1" :port 18091))
               (is (= 200 (service-account-tls-status pki "/api/v1/namespaces/alpha/events" token)))
               (is (= 403 (service-account-tls-status pki "/apis/events.k8s.io/v1/namespaces/alpha/events" token)))
               (is (= 403 (service-account-tls-status pki "/api/v1/namespaces/beta/events" token))))
          (when tls-server (stop-server tls-server)))))))

(test expired-events-cannot-be-revived-by-an-update
  (with-temporary-store (store path)
    (values path)
    (let* ((now 1000) (gr8s::*event-clock* (lambda () now))
           (created (gr8s::create-core-resource store "events" (event-fixture "expires") "alpha"))
           (uid (gethash "uid" (gethash "metadata" created))))
      (setf now 4600)
      (is (= 404 (core-resource-status
                   (lambda () (gr8s::update-core-resource store "events" "alpha" "expires" #'identity)))))
      (let ((new (gr8s::create-core-resource store "events" (event-fixture "expires") "alpha")))
        (is (not (equal uid (gethash "uid" (gethash "metadata" new)))))))))

(test event-openapi-advertises-strict-request-validation
  (with-core-api (store path)
    (values store path)
    (let* ((api (check-core-status 200 "/openapi/v3/apis/events.k8s.io/v1"))
           (operation (gethash "post" (gethash "/apis/events.k8s.io/v1/namespaces/{namespace}/events" (gethash "paths" api)))))
      (is (equal "fieldValidation" (gethash "name" (aref (gethash "parameters" operation) 0)))))))

(in-suite gr8s)
