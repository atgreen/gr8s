;;;; SPDX-License-Identifier: MIT
(require :asdf)
(load (merge-pathnames "load.lisp" *load-truename*))
(defpackage #:gr8s-diagnose-tests
  (:use #:cl)
  (:export #:run-tests))
(in-package #:gr8s-diagnose-tests)

(defun json (text) (com.inuoe.jzon:parse text))
(defun pod ()
  (json "{\"metadata\":{\"uid\":\"pod-1\",\"name\":\"web\",\"namespace\":\"test\",\"resourceVersion\":\"1\"},\"spec\":{\"containers\":[{\"name\":\"api\",\"env\":[{\"name\":\"PASSWORD\",\"valueFrom\":{\"secretKeyRef\":{\"name\":\"db\",\"key\":\"password\"}}}]}]}}"))

(defun check (object state)
  (gr8s-diagnose:diagnose-pod
   "web" "test"
   (lambda (kind namespace name)
     (declare (ignore namespace name))
     (if (equal kind "Pod") (values (pod) :present)
         (values object state)))))

(defun run-tests ()
  (let ((report (check nil :absent)))
    (assert (equal "findings" (gethash "status" report)))
    (assert (= 1 (length (gethash "findings" report)))))
  (let ((report (check (json "{\"data\":{\"password\":\"DO-NOT-PRINT\"}}") :present)))
    (assert (equal "no-findings" (gethash "status" report)))
    (assert (not (search "DO-NOT-PRINT" (com.inuoe.jzon:stringify report)))))
  (let ((report (check (json "{\"data\":{\"other\":\"DO-NOT-PRINT\"}}") :present)))
    (assert (equal "missing-key" (gethash "code" (aref (gethash "findings" report) 0))))
    (assert (search "password" (with-output-to-string (out) (gr8s-diagnose:print-report report out)))))
  (let ((report (check nil :unknown)))
    (assert (equal "incomplete" (gethash "status" report)))
    (assert (zerop (length (gethash "findings" report)))))
  ;; Optional references must neither be looked up nor diagnosed as missing.
  (let ((target (pod)))
    (setf (gethash "optional"
                   (gr8s-diagnose::field
                    (aref (gr8s-diagnose::field (aref (gr8s-diagnose::field target "spec" "containers") 0)
                                              "env") 0)
                    "valueFrom" "secretKeyRef")) t)
    (let ((report (gr8s-diagnose:diagnose-pod
                   "web" "test" (lambda (kind ns name)
                                    (declare (ignore ns name))
                                    (assert (equal "Pod" kind))
                                    (values target :present)))))
      (assert (equal "no-findings" (gethash "status" report)))))
  ;; A replacement with the same name invalidates the earlier observations.
  (let ((calls 0))
    (let ((report (gr8s-diagnose:diagnose-pod
                   "web" "test"
                   (lambda (kind ns name)
                     (declare (ignore ns name))
                     (if (equal "Pod" kind)
                         (let ((target (pod)))
                           (when (> (incf calls) 1)
                             (setf (gethash "uid" (gethash "metadata" target)) "replacement"))
                           (values target :present))
                         (values nil :absent))))))
      (assert (equal "incomplete" (gethash "status" report)))
      (assert (zerop (length (gethash "findings" report))))))
  ;; binaryData keys are valid volume items but not configMapKeyRef env values.
  (let* ((target (pod))
         (value-from (gr8s-diagnose::field
                      (aref (gr8s-diagnose::field
                             (aref (gr8s-diagnose::field target "spec" "containers") 0) "env") 0)
                      "valueFrom"))
         (reference (gethash "secretKeyRef" value-from)))
    (remhash "secretKeyRef" value-from)
    (setf (gethash "configMapKeyRef" value-from) reference)
    (let ((report (gr8s-diagnose:diagnose-pod
                   "web" "test"
                   (lambda (kind ns name)
                     (declare (ignore ns name))
                     (if (equal "Pod" kind) (values target :present)
                         (values (json "{\"binaryData\":{\"password\":\"eA==\"}}") :present))))))
      (assert (= 1 (length (gethash "findings" report))))))
  ;; Shared keys must produce linear findings, not a Cartesian proof explosion.
  (let* ((target (pod))
         (container (aref (gr8s-diagnose::field target "spec" "containers") 0)))
    (setf (gethash "containers" (gethash "spec" target))
          (coerce (loop for i below 32 collect
                    (let ((copy (json (com.inuoe.jzon:stringify container))))
                      (setf (gethash "name" copy) (format nil "c~D" i)) copy)) 'vector))
    (let ((report (gr8s-diagnose:diagnose-pod
                   "web" "test" (lambda (kind ns name)
                     (declare (ignore ns name))
                     (if (equal kind "Pod") (values target :present)
                         (values (json "{\"data\":{}}") :present))))))
      (assert (= 32 (length (gethash "findings" report))))))
  (format t "Live diagnosis tests passed.~%"))

(run-tests)
