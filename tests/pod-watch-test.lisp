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

(test page-selects-start-revision-and-validates-it
  (with-temporary-store (store directory)
    (declare (ignorable directory))
    (create-pod store (watch-test-pod "first"))
    (let ((page (gr8s::pod-watch-page store nil "" "" "0" nil)))
      (is (= 1 (length (gethash "items" page))))
      (is (equal (write-to-string (gr8s::pod-store-pod-revision store))
                 (gethash "resourceVersion" (gethash "metadata" page)))))
    (signals kubernetes-error (gr8s::pod-watch-page store nil "" "" "12345" nil))))
