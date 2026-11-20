;;;; SPDX-License-Identifier: MIT
;;;; Time verdict/2 in rules/explanation.pl against the same search written in
;;;; Lisp, on synthetic clusters of a few thousand resources, and check that
;;;; they agree. Run: sbcl --script tests/doctor/explanation-benchmark.lisp
(require :asdf)
(load (merge-pathnames "load.lisp" *load-truename*))
(load (merge-pathnames "explanation-reference.lisp" *load-truename*))
(in-package #:gr8s-diagnose)

(defun thing (kind name &key (ns "test") spec status owner labels)
  (object "kind" kind
          "metadata" (apply #'object "name" name "uid" name "resourceVersion" "1"
                            (append (when ns (list "namespace" ns))
                                    (when labels (list "labels" labels))
                                    (when owner (list "ownerReferences"
                                                      (vector (object "kind" (first owner) "name" (second owner)
                                                                      "uid" (second owner) "controller" t))))))
          "spec" (or spec (object)) "status" (or status (object))))

(defun cluster (deployments pods-each nodes failing-p node-down-p)
  "DEPLOYMENTS workloads of PODS-EACH Pods over NODES nodes, each with a Service.
FAILING-P says whether a deployment's Pods crash; NODE-DOWN-P whether a node is not ready."
  (let ((things nil))
    (dotimes (n nodes)
      (push (thing "Node" (format nil "n~D" n) :ns nil
                   :status (object "conditions"
                                   (vector (object "type" "Ready" "status" (if (funcall node-down-p n) "False" "True")))))
            things))
    (dotimes (d deployments)
      (let* ((name (format nil "web~D" d)) (set (format nil "web~D-1" d)) (failing (funcall failing-p d))
             (labels (object "app" name)) (down 0))
        (dotimes (p pods-each)
          (let* ((node (mod (+ d p) nodes))
                 (broken (or failing (funcall node-down-p node))))
            (when broken (incf down))
            (push (thing "Pod" (format nil "~A-~D" set p) :owner (list "ReplicaSet" set) :labels labels
                         :spec (object "nodeName" (format nil "n~D" node))
                         :status (object "conditions" (vector (object "type" "Ready" "status" (if broken "False" "True")))
                                         "containerStatuses"
                                         (vector (if failing
                                                     (object "name" "api" "state"
                                                             (object "waiting" (object "reason" "CrashLoopBackOff")))
                                                     (object "name" "api" "state" (object "running" (object)))))))
                  things)))
        (let ((status (object "readyReplicas" (- pods-each down) "availableReplicas" (- pods-each down))))
          (push (thing "ReplicaSet" set :owner (list "Deployment" name) :spec (object "replicas" pods-each) :status status)
                things)
          (push (thing "Deployment" name :spec (object "replicas" pods-each) :status status) things))
        (push (thing "Service" name :spec (object "selector" labels)) things)))
    (nreverse things)))

(defun reader (things)
  "A getter over THINGS, indexed so that the reader is not what is measured."
  (let ((by-kind (make-hash-table :test #'equal)) (by-name (make-hash-table :test #'equal)))
    (dolist (item things)
      (push item (gethash (field item "kind") by-kind))
      (setf (gethash (list (field item "kind") (field item "metadata" "name")) by-name) item))
    (lambda (kind ns name)
      (declare (ignore ns))
      (if name
          (let ((item (gethash (list kind name) by-name)))
            (values item (if item :present :absent)))
          (values (object "items" (coerce (reverse (gethash kind by-kind)) 'vector)) :present)))))

(defun seconds (function)
  (let ((start (get-internal-real-time)))
    (values (funcall function) (/ (- (get-internal-real-time) start) (float internal-time-units-per-second)))))

(defun measure (label things)
  (let ((arguments nil) (report nil) (total nil))
    ;; One survey, capturing what the explanation step is asked.
    (let ((*verdicts* (lambda (&rest all) (setf arguments all) (apply #'proved-verdicts all))))
      (multiple-value-setq (report total) (seconds (lambda () (checkup nil (reader things) :max-resources 1000000)))))
    (multiple-value-bind (proved proved-time) (seconds (lambda () (apply #'proved-verdicts arguments)))
      (multiple-value-bind (walked walked-time) (seconds (lambda () (apply #'walked-verdicts arguments)))
        (assert-verdicts-agree proved walked)
        (format t "~A~%  ~D resources, ~D symptom targets, ~D causes, ~D problems~%  whole survey ~,2Fs; verdicts in Prolog ~,3Fs, in Lisp ~,3Fs~%"
                label (length things) (length (first arguments)) (length (second arguments))
                (length (gethash "problems" report)) total proved-time walked-time)))))

(measure "Healthy but for one workload in ten"
         (cluster 300 8 50 (lambda (d) (zerop (mod d 10))) (constantly nil)))
(measure "One node in ten not ready"
         (cluster 300 8 50 (constantly nil) (lambda (n) (zerop (mod n 10)))))
(measure "Everything failing"
         (cluster 300 8 50 (constantly t) (constantly nil)))
(measure "Twice the size, everything failing"
         (cluster 600 8 100 (constantly t) (constantly nil)))
(measure "Five times the size, one workload in ten failing"
         (cluster 1500 8 250 (lambda (d) (zerop (mod d 10))) (constantly nil)))
