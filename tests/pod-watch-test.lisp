;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Verify Pod watch events come from real mutations in revision order, that
;;;; resumption is exact or explicitly expired, and that status-only revisions
;;;; never change the desired revision agents acknowledge.

(in-package #:gr8s/tests)
(def-suite pod-watch :in gr8s)
(in-suite pod-watch)

(defun watch-test-pod (name &optional (labels "{}"))
  "Return an unsaved Pod called NAME with the LABELS JSON object."
  (parse-pod (format nil "{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"name\":~S,\"namespace\":\"default\",\"labels\":~A},\"spec\":{\"containers\":[{\"name\":\"c\",\"image\":\"busybox:latest\"}]}}" name labels)))

(defun watch-events (store revision &key namespace (labels "") (fields ""))
  "Return (type name resourceVersion) for events after REVISION."
  (mapcar (lambda (event)
            (let ((metadata (gethash "metadata" (gethash "object" event))))
              (list (gethash "type" event) (gethash "name" metadata)
                    (parse-integer (gethash "resourceVersion" metadata)))))
          (gr8s::pod-watch-events store namespace labels fields revision)))

(defun observe-status (store pod status)
  "Publish STATUS for POD through the same funnel as reconciliation."
  (gr8s::with-store-lock (store) (gr8s::publish-pod-status-unlocked store pod status)))

(test pod-mutations-produce-ordered-events-with-one-global-revision
  (with-temporary-store (store directory)
    (declare (ignorable directory))
    (let* ((first (create-pod store (watch-test-pod "first")))
           (second (create-pod store (watch-test-pod "second")))
           (replacement (parse-pod (com.inuoe.jzon:stringify (pod-to-object first)))))
      (is (< (parse-integer (pod-resource-version first)) (parse-integer (pod-resource-version second))))
      (update-pod store replacement (pod-resource-version first))
      (gr8s::mark-pod-deleting store "default" "second")
      (gr8s::remove-pod store "default" "second")
      (let ((events (watch-events store 0)))
        (is (equal '(("ADDED" "first") ("ADDED" "second") ("MODIFIED" "first")
                     ("MODIFIED" "second") ("DELETED" "second"))
                   (mapcar (lambda (event) (subseq event 0 2)) events)))
        (is (apply #'< (mapcar #'third events)))))))

(test resuming-returns-exactly-the-later-events
  (with-temporary-store (store directory)
    (declare (ignorable directory))
    (create-pod store (watch-test-pod "first"))
    (let ((checkpoint (gr8s::pod-store-pod-revision store)))
      (create-pod store (watch-test-pod "second"))
      (is (equal '("second") (mapcar #'second (watch-events store checkpoint))))
      (multiple-value-bind (events watermark)
          (gr8s::pod-watch-events store nil "" "" (gr8s::pod-store-pod-revision store))
        (is (null events))
        (is (= watermark (gr8s::pod-store-pod-revision store))))
      (signals kubernetes-error (gr8s::pod-watch-events store nil "" "" (+ 100 checkpoint))))))

(test status-changes-emit-once-without-moving-the-agent-acknowledged-revision
  (with-temporary-store (store directory)
    (declare (ignorable directory))
    (let* ((pod (create-pod store (watch-test-pod "first")))
           (desired (pod-resource-version pod))
           (running (gr8s::core-object "phase" "Running")))
      (observe-status store pod running)
      ;; Periodic reconciliation repeats unchanged status; clients must not hear it.
      (observe-status store pod (gr8s::core-object "phase" "Running"))
      (let ((events (watch-events store (parse-integer desired))))
        (is (equal '(("MODIFIED" "first")) (mapcar (lambda (event) (subseq event 0 2)) events)))
        (is (equal desired (pod-resource-version pod)))
        (is (equal desired (gethash "resourceVersion" (gethash "metadata" (pod-to-object pod)))))
        ;; Clients do see the newer revision on an ordinary read.
        (is (= (third (first events))
               (parse-integer (gethash "resourceVersion"
                                       (gethash "metadata" (gr8s::pod-response-object pod running))))))))))

(test watch-events-carry-the-published-status
  (with-temporary-store (store directory)
    (declare (ignorable directory))
    (let ((pod (create-pod store (watch-test-pod "first"))))
      (let ((created (first (gr8s::pod-watch-events store nil "" "" 0))))
        (is (equal "Pending" (gethash "phase" (gethash "status" (gethash "object" created))))))
      (observe-status store pod (gr8s::core-object "phase" "Succeeded"))
      (let ((events (gr8s::pod-watch-events store nil "" "" (parse-integer (pod-resource-version pod)))))
        (is (equal "Succeeded" (gethash "phase" (gethash "status" (gethash "object" (first events))))))))))

(test selectors-turn-transitions-into-added-and-deleted
  (with-temporary-store (store directory)
    (declare (ignorable directory))
    (let* ((pod (create-pod store (watch-test-pod "first" "{\"tier\":\"a\"}")))
           (object (gr8s::copy-json-object (pod-to-object pod))))
      (create-pod store (watch-test-pod "other" "{\"tier\":\"b\"}"))
      (setf (gethash "tier" (gethash "labels" (gethash "metadata" object))) "c")
      (let ((left (update-pod store (parse-pod (com.inuoe.jzon:stringify object)) (pod-resource-version pod))))
        (let ((types (mapcar #'first (watch-events store 0 :labels "tier=a"))))
          (is (equal '("ADDED" "DELETED") types)))
        (observe-status store left (gr8s::core-object "phase" "Running"))
        (is (equal '(("ADDED" "first"))
                   (mapcar (lambda (event) (subseq event 0 2))
                           (watch-events store (parse-integer (pod-resource-version left))
                                         :fields "status.phase=Running")))))
      (is (equal '("ADDED" "DELETED") (mapcar #'first (watch-events store 0 :fields "metadata.name=first"
                                                                             :labels "tier=a")))))))

(test namespace-scoping-excludes-other-namespaces
  (with-temporary-store (store directory)
    (declare (ignorable directory))
    (create-pod store (watch-test-pod "first"))
    (is (= 1 (length (watch-events store 0 :namespace "default"))))
    (is (null (watch-events store 0 :namespace "elsewhere")))))

(test preconditions-tolerate-status-revisions-but-reject-stale-specs
  (with-temporary-store (store directory)
    (declare (ignorable directory))
    (let* ((pod (create-pod store (watch-test-pod "first")))
           (original (pod-resource-version pod))
           (copy (lambda (source) (parse-pod (com.inuoe.jzon:stringify (pod-to-object source))))))
      (observe-status store pod (gr8s::core-object "phase" "Running"))
      (let* ((seen (write-to-string (gr8s::pod-store-pod-revision store)))
             (updated (update-pod store (funcall copy pod) seen)))
        ;; The read predates a real spec write, so it is now truly stale.
        (signals kubernetes-error (update-pod store (funcall copy updated) original))
        (signals kubernetes-error (update-pod store (funcall copy updated) "not-a-revision"))
        (signals kubernetes-error (update-pod store (funcall copy updated) "999999999"))
        (signals kubernetes-error (gr8s::mark-pod-deleting store "default" "first" :resource-version original))
        (is (not (null (gr8s::mark-pod-deleting store "default" "first"
                                                :resource-version (pod-resource-version updated)))))))))

(test restart-expires-old-watches-and-never-reuses-a-revision
  (with-temporary-store (store directory)
    (let ((pod (create-pod store (watch-test-pod "first"))))
      (observe-status store pod (gr8s::core-object "phase" "Running"))
      (gr8s::mark-pod-deleting store "default" "first")
      (gr8s::remove-pod store "default" "first")
      (let* ((issued (gr8s::pod-store-pod-revision store))
             (reopened (open-store directory)))
        (is (>= (gr8s::pod-store-pod-revision reopened) issued))
        (let ((created (create-pod reopened (watch-test-pod "next"))))
          (is (> (parse-integer (pod-resource-version created)) issued))
          (let ((failure (handler-case (gr8s::pod-watch-events reopened nil "" "" issued)
                           (kubernetes-error (condition) condition))))
            (is (typep failure 'kubernetes-error))
            (is (= 410 (gr8s::kubernetes-error-status-code failure))))
          (is (equal '("next")
                     (mapcar #'second (watch-events reopened (gr8s::pod-store-pod-watch-floor reopened))))))))))

(test journal-compaction-expires-only-events-it-dropped
  (with-temporary-store (store directory)
    (declare (ignorable directory))
    (let ((gr8s::*pod-watch-journal-limit* 4))
      (let ((pod (create-pod store (watch-test-pod "first"))))
        (loop for count from 1 to 12
              do (observe-status store pod (gr8s::core-object "phase" (format nil "P~D" count))))
        (let ((floor (gr8s::pod-store-pod-watch-floor store)))
          (is (plusp floor))
          (is (<= (gr8s::pod-store-pod-watch-journal-length store) 8))
          (let ((events (watch-events store floor)))
            (is (= (- (gr8s::pod-store-pod-revision store) floor) (length events))))
          (signals kubernetes-error (gr8s::pod-watch-events store nil "" "" (1- floor))))))))

(test pod-journal-keeps-its-time-window-past-the-old-event-count
  (with-temporary-store (store directory)
    (declare (ignorable directory))
    (let* ((now 1000) (gr8s::*podtemplate-clock* (lambda () now)) (revision 0))
      (flet ((record (count)
               (loop repeat count
                     do (gr8s::record-pod-watch-event-unlocked store (incf revision) nil nil))))
        (record 9000)
        (is (= 0 (gr8s::pod-store-pod-watch-floor store)))
        (is (= 9000 (gr8s::pod-store-pod-watch-journal-length store)))
        ;; A quiet cluster's few old events stay, however old.
        (setf now (+ 1000 gr8s::*watch-history-seconds* 1))
        (record 216)
        (let ((length (gr8s::pod-store-pod-watch-journal-length store)))
          (is (= gr8s::+pod-watch-journal-minimum+ length))
          (is (= (- revision length) (gr8s::pod-store-pod-watch-floor store))))
        ;; However recent, events stop at the limit.
        (let ((gr8s::*pod-watch-journal-limit* 5000))
          (record 3000)
          (is (<= (gr8s::pod-store-pod-watch-journal-length store)
                  (+ 5000 gr8s::+revision-journal-trim-interval+))))))))

(test node-journal-keeps-its-time-window-past-the-old-event-count
  (with-temporary-store (store directory)
    (declare (ignorable directory))
    (let* ((now 1000) (gr8s::*podtemplate-clock* (lambda () now)))
      (loop for revision from 1 to 3000
            do (gr8s::record-node-watch-event-unlocked store revision nil nil))
      (is (= 0 (gr8s::pod-store-node-watch-floor store)))
      (is (= 3000 (gr8s::pod-store-node-watch-journal-length store)))
      (setf now (+ 1000 gr8s::*watch-history-seconds* 1))
      (loop for revision from 3001 to 4096
            do (gr8s::record-node-watch-event-unlocked store revision nil nil))
      ;; The 1096 events inside the window are more than the minimum, so only those stay.
      (is (= 1096 (gr8s::pod-store-node-watch-journal-length store)))
      (is (= 3000 (gr8s::pod-store-node-watch-floor store))))))

(defun journal-test-view (uid phase)
  "Return a Pod API view of a realistic size for UID in PHASE."
  (gr8s::core-object "metadata" (gr8s::core-object "uid" uid "name" uid "namespace" "default"
                                                   "annotations" (gr8s::core-object "note" (make-string 4000 :initial-element #\n)))
                     "status" (gr8s::core-object "phase" phase)))

(test pod-journal-stops-at-its-memory-limit-however-recent
  (with-temporary-store (store directory)
    (declare (ignorable directory))
    (let ((gr8s::*pod-watch-journal-bytes* (* 1024 1024)))
      (loop for revision from 1 to 400
            do (gr8s::record-pod-watch-event-unlocked
                store revision nil (journal-test-view (format nil "pod-~D" revision) "Running")))
      (setf (gr8s::pod-store-pod-revision store) 400)
      (let ((length (gr8s::pod-store-pod-watch-journal-length store))
            (journal (gr8s::pod-store-pod-watch-journal store)))
        (is (< 20 length 100))
        (is (= length (length journal)))
        (is (<= (gr8s::pod-store-pod-watch-journal-bytes store) (* 1024 1024)))
        (is (= (gr8s::pod-store-pod-watch-journal-bytes store) (reduce #'+ journal :key #'fifth)))
        ;; What it dropped is expired, and what it kept is all still readable.
        (is (= (- 400 length) (gr8s::pod-store-pod-watch-floor store)))
        (signals kubernetes-error (gr8s::pod-watch-events store nil "" "" (1- (gr8s::pod-store-pod-watch-floor store))))
        (is (= length (length (gr8s::pod-watch-events store nil "" "" (gr8s::pod-store-pod-watch-floor store)))))))))

(test pod-journal-events-share-the-view-their-predecessor-ended-with
  (with-temporary-store (store directory)
    (declare (ignorable directory))
    (let ((pod (create-pod store (watch-test-pod "first"))))
      (observe-status store pod (gr8s::core-object "phase" "Running"))
      (observe-status store pod (gr8s::core-object "phase" "Succeeded"))
      (destructuring-bind (newest older &rest rest) (gr8s::pod-store-pod-watch-journal store)
        (declare (ignore rest))
        (is (eq (third older) (second newest)))
        ;; A shared view costs nothing more, and events still read as before.
        (is (= (fifth newest) (+ 64 (gr8s::approximate-heap-bytes (third newest)))))
        (is (equal '("ADDED" "MODIFIED" "MODIFIED")
                   (mapcar #'first (watch-events store 0))))))))

(test an-unwatched-store-keeps-no-journal-but-expires-old-revisions
  (with-temporary-store (store directory)
    (declare (ignorable directory))
    (setf (gr8s::pod-store-watch-journal-p store) nil)
    (let ((pod (create-pod store (watch-test-pod "first"))))
      (observe-status store pod (gr8s::core-object "phase" "Running"))
      (gr8s::record-node-watch-event-unlocked store (gr8s::pod-store-pod-revision store) nil nil)
      (is (null (gr8s::pod-store-pod-watch-journal store)))
      (is (null (gr8s::pod-store-node-watch-journal store)))
      (is (= (gr8s::pod-store-pod-revision store) (gr8s::pod-store-pod-watch-floor store)))
      (signals kubernetes-error (gr8s::pod-watch-events store nil "" "" 0)))))

(test an-agent-store-keeps-no-watch-journal
  (let ((directory (uiop:ensure-directory-pathname
                    (sb-posix:mkdtemp (namestring (merge-pathnames "gr8s-test-XXXXXX" (uiop:temporary-directory)))))))
    (unwind-protect
         (let ((runtime (gr8s::make-node-runtime directory (gr8s::make-fake-runtime) nil)))
           (is (not (gr8s::pod-store-watch-journal-p (gr8s::node-runtime-store runtime)))))
      (uiop:delete-directory-tree directory :validate t :if-does-not-exist :ignore))))

(test page-selects-start-revision-and-validates-it
  (with-temporary-store (store directory)
    (declare (ignorable directory))
    (create-pod store (watch-test-pod "first"))
    (let ((page (gr8s::pod-watch-page store nil "" "" "0" nil)))
      (is (= 1 (length (gethash "items" page))))
      (is (equal (write-to-string (gr8s::pod-store-pod-revision store))
                 (gethash "resourceVersion" (gethash "metadata" page)))))
    (signals kubernetes-error (gr8s::pod-watch-page store nil "" "" "12345" nil))))

;;; WatchList, as client-go's reflector asks for it.

(defvar *watch-test-server* "http://127.0.0.1:18089" "The server COLLECT-WATCH-STREAM asks.")

(defun collect-watch-stream (path &rest parameters)
  "Read a watch at PATH until the server's timeoutSeconds ends it, returning its events."
  (sb-sys:with-deadline (:seconds 20)
    (multiple-value-bind (stream code)
        (drakma:http-request (concatenate 'string *watch-test-server* path) :want-stream t
                             :parameters (append '(("watch" . "true") ("timeoutSeconds" . "1")) parameters))
      (unwind-protect
           (progn
             (is (= 200 code) "~A answered ~A" path code)
             (when (= 200 code)
               (loop for event = (handler-case (read-template-watch-event stream)
                                   (end-of-file () nil))
                     while event collect event)))
        (close stream)))))

(defun watch-list-parameters ()
  (list '("sendInitialEvents" . "true") '("resourceVersionMatch" . "NotOlderThan") '("allowWatchBookmarks" . "true")))

(defun check-watch-list-events (events kind added)
  "Require ADDED names of KIND, then only the bookmark that ends the initial events."
  (is (equal added (loop for event in (butlast events)
                         do (is (equal "ADDED" (gethash "type" event)))
                         collect (gethash "name" (gethash "metadata" (gethash "object" event))))))
  (let* ((bookmark (first (last events)))
         (object (and bookmark (gethash "object" bookmark)))
         (metadata (and object (gethash "metadata" object))))
    (is (equal "BOOKMARK" (and bookmark (gethash "type" bookmark))))
    (is (equal kind (and object (gethash "kind" object))))
    (is (and metadata (plusp (length (gethash "resourceVersion" metadata)))))
    (is (equal "true" (and metadata (gethash "annotations" metadata)
                           (gethash "k8s.io/initial-events-end" (gethash "annotations" metadata)))))))

;; podster-uqb.122: RetryWatcher gives up on this event, where it retried the same
;; HTTP 410 once a second for the rest of the spec.
(test too-old-a-revision-ends-the-watch-with-an-expired-event-on-every-storage-path
  (with-core-api (store path)
    (values path)
    ;; Twice, since one below the floor must not be revision 0, which asks for the latest.
    (dolist (name '("web" "api"))
      (gr8s::create-core-resource store "replicasets" (durable-watch-fixture "replicasets" name) "alpha"))
    (gr8s:register-node store (gr8s:make-node-record :id "node-a" :name "node-a" :pod-cidr "10.88.0.0/24"))
    (create-pod store (watch-test-pod "web"))
    (setf (gr8s::pod-store-template-history-floor store) (gr8s::pod-store-resource-revision store)
          (gr8s::pod-store-pod-watch-floor store) (gr8s::pod-store-pod-revision store)
          (gr8s::pod-store-node-watch-floor store) (gr8s::pod-store-pod-revision store))
    (loop for (collection floor)
            in `(("/apis/apps/v1/namespaces/alpha/replicasets" ,(gr8s::pod-store-template-history-floor store))
                 ("/api/v1/pods" ,(gr8s::pod-store-pod-watch-floor store))
                 ("/api/v1/nodes" ,(gr8s::pod-store-node-watch-floor store)))
          do (let* ((events (collect-watch-stream collection (cons "resourceVersion" (write-to-string (1- floor)))))
                    (event (first events))
                    (status (and event (gethash "object" event))))
               (is (= 1 (length events)) "~A sent ~A" collection events)
               (is (equal "ERROR" (and event (gethash "type" event))))
               (is (equal "v1" (and status (gethash "apiVersion" status))))
               (is (equal "Status" (and status (gethash "kind" status))))
               (is (equal "Failure" (and status (gethash "status" status))))
               (is (equal "Expired" (and status (gethash "reason" status))))
               (is (eql 410 (and status (gethash "code" status))))
               (is (hash-table-p (and status (gethash "metadata" status))))))
    ;; What is wrong with the request itself is still an HTTP error.
    (is (= 400 (nth-value 1 (drakma:http-request "http://127.0.0.1:18089/api/v1/pods"
                                                 :parameters '(("watch" . "true") ("resourceVersion" . "x"))))))))

(test watch-list-ends-initial-events-with-a-bookmark-on-every-storage-path
  (with-core-api (store path)
    (values path)
    (gr8s::create-core-resource store "configmaps" (gr8s::core-object "metadata" (gr8s::core-object "name" "one")) "alpha")
    (gr8s::create-core-resource store "configmaps" (gr8s::core-object "metadata" (gr8s::core-object "name" "two")) "alpha")
    (gr8s:register-node store (gr8s:make-node-record :id "node-a" :name "node-a" :pod-cidr "10.88.0.0/24"))
    (create-pod store (watch-test-pod "web"))
    (check-watch-list-events (apply #'collect-watch-stream "/api/v1/namespaces/alpha/configmaps" (watch-list-parameters))
                             "ConfigMap" '("one" "two"))
    (check-watch-list-events (apply #'collect-watch-stream "/api/v1/configmaps" (watch-list-parameters))
                             "ConfigMap" '("one" "two"))
    (check-watch-list-events (apply #'collect-watch-stream "/api/v1/nodes" (watch-list-parameters)) "Node" '("node-a"))
    (check-watch-list-events (apply #'collect-watch-stream "/api/v1/pods" (watch-list-parameters)) "Pod" '("web"))
    ;; The other projections each rewrite what they serve, which must leave the bookmark readable.
    (check-watch-list-events (apply #'collect-watch-stream "/apis/events.k8s.io/v1/events" (watch-list-parameters)) "Event" nil)
    (check-watch-list-events (apply #'collect-watch-stream "/apis/autoscaling/v1/horizontalpodautoscalers" (watch-list-parameters))
                             "HorizontalPodAutoscaler" nil)
    (check-watch-list-events (apply #'collect-watch-stream "/apis/apps/v1/deployments" (watch-list-parameters)) "Deployment" nil)))

(test watch-list-sees-changes-after-the-bookmark
  (with-core-api (store path)
    (values path)
    (gr8s::create-core-resource store "configmaps" (gr8s::core-object "metadata" (gr8s::core-object "name" "one")) "alpha")
    (sb-sys:with-deadline (:seconds 10)
      (multiple-value-bind (stream code)
          (drakma:http-request "http://127.0.0.1:18089/api/v1/configmaps" :want-stream t
                               :parameters (append '(("watch" . "true") ("timeoutSeconds" . "3")) (watch-list-parameters)))
        (unwind-protect
             (progn
               (is (= 200 code))
               (is (equal "ADDED" (gethash "type" (read-template-watch-event stream))))
               (is (equal "BOOKMARK" (gethash "type" (read-template-watch-event stream))))
               (gr8s::create-core-resource store "configmaps" (gr8s::core-object "metadata" (gr8s::core-object "name" "two")) "alpha")
               (let ((event (read-template-watch-event stream)))
                 (is (equal "ADDED" (gethash "type" event)))
                 (is (equal "two" (gethash "name" (gethash "metadata" (gethash "object" event)))))))
          (close stream))))))

(test watch-options-follow-upstream-validation
  (with-core-api (store path)
    (values path)
    (gr8s::create-core-resource store "configmaps" (gr8s::core-object "metadata" (gr8s::core-object "name" "one")) "alpha")
    (flet ((status (&rest parameters)
             (nth-value 1 (drakma:http-request "http://127.0.0.1:18089/api/v1/configmaps" :want-stream nil
                                               :parameters (append '(("watch" . "true") ("timeoutSeconds" . "1")) parameters)))))
      (is (= 400 (status '("sendInitialEvents" . "true"))))
      (is (= 400 (status '("sendInitialEvents" . "false"))))
      (is (= 400 (status '("resourceVersionMatch" . "NotOlderThan"))))
      (is (= 400 (status '("sendInitialEvents" . "true") '("resourceVersionMatch" . "Exact"))))
      (is (= 200 (status '("sendInitialEvents" . "true") '("resourceVersionMatch" . "NotOlderThan") '("resourceVersion" . "0")))))
    ;; An explicit false starts at the latest state with no synthetic events, and no bookmark nobody asked for.
    (is (null (collect-watch-stream "/api/v1/configmaps" '("sendInitialEvents" . "false") '("resourceVersionMatch" . "NotOlderThan"))))
    (is (equal '("ADDED")
               (mapcar (lambda (event) (gethash "type" event))
                       (collect-watch-stream "/api/v1/configmaps" '("sendInitialEvents" . "true")
                                             '("resourceVersionMatch" . "NotOlderThan")))))))
