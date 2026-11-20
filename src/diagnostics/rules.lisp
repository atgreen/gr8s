;;;; SPDX-License-Identifier: MIT
(in-package #:gr8s-diagnose)

;;; The doctor's knowledge is Prolog, in rules/*.pl. Those files are read when
;;; this one is compiled, so a syntax error stops the build, and their
;;; predicates are compiled when it is loaded, so a dumped image starts with
;;; them ready. Lisp collects facts, asks, and writes the answers out.

(eval-when (:compile-toplevel :load-toplevel :execute)
  (defun rule-file-text (name)
    "The text of rules/NAME.pl beside this file."
    (uiop:read-file-string
     (merge-pathnames (format nil "rules/~A.pl" name)
                      (or *compile-file-truename* *load-truename*
                          (error "Rule files are found relative to this source file."))))))

(eval-when (:compile-toplevel :load-toplevel :execute)
(defun load-rule-base (programs)
  "A database holding PROGRAMS, a list of (name . text), with every static
predicate compiled. An unknown predicate fails: a fact that was not observed
is simply absent."
  (let ((database (ag-prolog:make-database :unknown :fail))
        (*package* (find-package '#:gr8s-diagnose)))
    (loop for (name . text) in programs
          do (handler-case (ag-prolog/syntax:consult database text)
               (error (condition) (error "rules/~A.pl: ~A" name condition))))
    ;; ag-prolog compiles a predicate when it is first called. Do it now, so
    ;; that the cost is paid when the image is built and not on every run.
    (ag-prolog:compile-database database)
    database)))

(defmacro define-rule-base (variable &rest names)
  "Define VARIABLE as the database of the rule files NAMES, read now."
  (let ((programs (loop for name in names collect (cons name (rule-file-text name)))))
    ;; Fail the build, not the first diagnosis, on a rule file that does not load.
    (load-rule-base programs)
    `(defparameter ,variable (load-rule-base ',programs))))

(define-rule-base *rules*
  "catalog" "references" "pods" "scheduling" "applications" "logs" "access" "relations" "explanation" "impact")

(defvar *rules-lock* (sb-thread:make-mutex :name "gr8s doctor rules")
  "Facts are asserted into the one rule base, so one question is asked at a time.")

(defun prove (facts goals template &key (max-steps 1000000) (max-results 1000))
  "Answer GOALS, in ag-prolog's Lisp syntax, given FACTS, each a list of a
predicate and its arguments. The facts last only for this question. Return
the distinct instances of TEMPLATE. Running past MAX-STEPS or MAX-RESULTS is
an error, never a partial answer."
  (sb-thread:with-recursive-lock (*rules-lock*)
    (unwind-protect
         (progn
           (dolist (fact facts) (ag-prolog:add-clause *rules* (list fact)))
           (multiple-value-bind (answers completion)
               (ag-prolog:query *rules* goals template :max-steps max-steps :max-results max-results)
             (unless (eq completion :complete) (error "Diagnostic result limit reached."))
             (remove-duplicates answers :test #'equal)))
      (let ((predicates (remove-duplicates (mapcar (lambda (fact) (cons (first fact) (length (rest fact)))) facts)
                                           :test #'equal)))
        (when predicates
          (ag-prolog:query *rules*
                           (loop for (name . arity) in predicates
                                 collect `(retractall (,name ,@(make-list arity :initial-element '?))))
                           'done))))))

(defun known (goal template)
  "What the rule base itself says of GOAL, with no facts asserted."
  (prove nil (list goal) template))

(defun truth (value)
  "A JSON boolean as the atom the rules use; anything else unchanged."
  (case value ((t) 'true) (:false 'false) (t value)))
