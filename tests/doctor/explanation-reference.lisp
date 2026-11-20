;;;; SPDX-License-Identifier: MIT
;;;; The search of rules/explanation.pl written in Lisp. The doctor does not
;;;; use it; the tests and the benchmark do, to check the rules and time them.
(in-package #:gr8s-diagnose)

(defun walked-verdicts (symptom-targets causes edges hints keys troubled)
  "The verdicts of verdict/2 in rules/explanation.pl, found by walking the
graph in Lisp: what the rules are checked against and measured by."
  (let ((loose (let ((all (make-hash-table :test #'equal)))
                 (dolist (table (list edges hints) all)
                   (maphash (lambda (from tos) (setf (gethash from all) (union tos (gethash from all) :test #'equal)))
                            table))))
        (verdicts (make-hash-table :test #'equal)))
    (flet ((within (target links)
             (cons target
                   (let ((key (gethash target keys)))
                     (when key
                       (mapcar #'key-target
                               (reachable key links (lambda (via) (or (gethash (key-target via) troubled)
                                                                      (pass-through-p via)))))))))
           (among (targets)
             (remove-if-not (lambda (cause) (member (car cause) targets :test #'equal)) causes)))
      (dolist (target symptom-targets verdicts)
        (let* ((near (within target edges)) (certain (among near)))
          (setf (gethash target verdicts)
                (cond (certain (cons :certain certain))
                      (t (let ((possible (among (within target loose))))
                           (if possible (cons :possible possible) (cons :unexplained near)))))))))))

(defun assert-verdicts-agree (proved walked)
  (assert (= (hash-table-count proved) (hash-table-count walked)))
  (maphash (lambda (target verdict)
             (let ((other (gethash target walked)))
               (assert (eq (car verdict) (car other)))
               (assert (null (set-exclusive-or (cdr verdict) (cdr other) :test #'equal)))))
           proved))
