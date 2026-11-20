;;;; SPDX-License-Identifier: MIT
(in-package #:gr8s-diagnose)

;;; The facts behind rules/scheduling.pl: the nodes, and what a Pod that waits
;;; for one asks of them.

(defun quantity-thousandths (text)
  "A Kubernetes quantity such as 100m, 2, 1.5 or 256Mi in thousandths, or NIL."
  (when (integerp text) (return-from quantity-thousandths (* 1000 text)))
  (when (and (stringp text) (plusp (length text)))
    (let* ((end (or (position-if-not (lambda (c) (or (digit-char-p c) (char= c #\.))) text) (length text)))
           (digits (subseq text 0 end)) (suffix (subseq text end))
           (scale (cdr (assoc suffix '(("" . 1) ("m" . 1/1000) ("k" . 1000) ("M" . 1000000) ("G" . 1000000000)
                                       ("T" . 1000000000000) ("Ki" . 1024) ("Mi" . 1048576)
                                       ("Gi" . 1073741824) ("Ti" . 1099511627776))
                              :test #'string=)))
           (point (position #\. digits)))
      (when (and scale (plusp end) (<= (count #\. digits) 1) (some #'digit-char-p digits))
        (let ((number (if point
                          (+ (if (zerop point) 0 (parse-integer digits :end point))
                             (/ (if (= (1+ point) (length digits)) 0 (parse-integer digits :start (1+ point)))
                                (expt 10 (- (length digits) point 1))))
                          (parse-integer digits))))
          (ceiling (* 1000 number scale)))))))

(defun quantity-text (resource thousandths)
  "THOUSANDTHS of RESOURCE as a person writes it."
  (cond ((equal resource "cpu")
         (if (zerop (mod thousandths 1000)) (format nil "~D" (floor thousandths 1000)) (format nil "~Dm" thousandths)))
        ((member resource '("memory" "ephemeral-storage") :test #'equal)
         (let ((bytes (max 0 (floor thousandths 1000))))
           (cond ((>= bytes 1073741824) (format nil "~,1FGi" (/ bytes 1073741824.0)))
                 (t (format nil "~DMi" (round bytes 1048576))))))
        (t (format nil "~D" (floor thousandths 1000)))))

(defun pod-requests (pod)
  "What POD asks of a node, as (resource . thousandths): the greater of its
containers together and its largest init container, and one Pod slot."
  (let ((totals (make-hash-table :test #'equal)))
    (flet ((requests (container)
             (let ((table (field container "resources" "requests")))
               (when (hash-table-p table)
                 (loop for resource being the hash-keys of table using (hash-value text)
                       for amount = (quantity-thousandths text)
                       when amount collect (cons resource amount))))))
      (loop for container across (or (field pod "spec" "containers") #())
            do (loop for (resource . amount) in (requests container)
                     do (incf (gethash resource totals 0) amount)))
      (loop for container across (or (field pod "spec" "initContainers") #())
            do (loop for (resource . amount) in (requests container)
                     do (setf (gethash resource totals) (max amount (gethash resource totals 0))))))
    (setf (gethash "pods" totals) 1000)
    (loop for resource being the hash-keys of totals using (hash-value amount)
          collect (cons resource amount))))

(defun waiting-for-a-node-p (pod)
  (and (equal "Pending" (field pod "status" "phase"))
       (not (stringp (field pod "spec" "nodeName")))
       (not (field pod "metadata" "deletionTimestamp"))
       (let ((gates (field pod "spec" "schedulingGates"))) (or (null gates) (equalp gates #())))))

(defun placement-facts (pod nodes pods)
  "NODES is every node. PODS is every Pod, or :UNKNOWN when they could not be read."
  (let ((facts nil) (used (make-hash-table :test #'equal)))
    (flet ((fact (&rest fact) (push fact facts)))
      (if (eq pods :unknown)
          (fact 'usage_unknown)
          (loop for other across pods
                for node = (field other "spec" "nodeName")
                when (and (stringp node) (not (member (field other "status" "phase") '("Succeeded" "Failed") :test #'equal)))
                  do (loop for (resource . amount) in (pod-requests other)
                           do (incf (gethash (list node resource) used 0) amount))))
      (maphash (lambda (key amount) (fact 'used (first key) (second key) amount)) used)
      (loop for node across nodes
            for name = (field node "metadata" "name")
            when (stringp name)
              do (fact 'node name)
                 (when (eq t (field node "spec" "unschedulable")) (fact 'cordoned name))
                 (when (or (condition-p node "Ready" "False") (condition-p node "Ready" "Unknown"))
                   (fact 'not_ready name))
                 (loop for taint across (or (field node "spec" "taints") #())
                       do (fact 'taint name (or (field taint "key") "") (or (field taint "value") "")
                                (or (field taint "effect") "")))
                 (let ((labels (field node "metadata" "labels")))
                   (when (hash-table-p labels)
                     (loop for key being the hash-keys of labels using (hash-value value)
                           when (stringp value) do (fact 'label name key value))))
                 (let ((allocatable (field node "status" "allocatable")))
                   (when (hash-table-p allocatable)
                     (loop for resource being the hash-keys of allocatable using (hash-value text)
                           for amount = (quantity-thousandths text)
                           when amount do (fact 'allocatable name resource amount)))))
      (loop for toleration across (or (field pod "spec" "tolerations") #())
            do (fact 'tolerates (or (field toleration "key") "") (or (field toleration "operator") "Equal")
                     (or (field toleration "value") "") (or (field toleration "effect") "")))
      (let ((selector (field pod "spec" "nodeSelector")))
        (when (hash-table-p selector)
          (loop for key being the hash-keys of selector using (hash-value value)
                when (stringp value) do (fact 'selects key value))))
      (loop for (resource . amount) in (pod-requests pod) do (fact 'asks_for resource amount))
      (loop for term across (or (field pod "spec" "affinity" "nodeAffinity"
                                       "requiredDuringSchedulingIgnoredDuringExecution" "nodeSelectorTerms")
                                #())
            for index from 0
            do (fact 'term index)
               (loop for expression across (or (field term "matchExpressions") #())
                     do (fact 'expression index (or (field expression "key") "")
                              (or (field expression "operator") "")
                              (coerce (or (field expression "values") #()) 'list)))))
    (nreverse facts)))

(defun rejection-text (reason)
  "REASON, a term of rejects/2, in words."
  (destructuring-bind (text arguments)
      (first (known `(reason_text ,reason ?text ?arguments) '(?text ?arguments)))
    (apply #'format nil text
           (mapcar (lambda (argument)
                     (if (and (simple-vector-p argument) (string= "AMOUNT" (symbol-name (svref argument 0))))
                         (quantity-text (svref argument 1) (svref argument 2))
                         argument))
                   arguments))))

(defun augment-pod-placement (report pod kind getter)
  "Say why a Pod that waits for a node has none, when every node is ruled out."
  (when (and (equal kind "Pod") (hash-table-p pod) (waiting-for-a-node-p pod)
             (plusp (length (gethash "evidence" report)))
             (equal "present" (field (aref (gethash "evidence" report) 0) "result")))
    (multiple-value-bind (nodes state) (funcall getter "Node" nil nil)
      (when (and (complete-list-p nodes state) (plusp (length (field nodes "items"))))
        (multiple-value-bind (pods pods-state) (funcall getter "Pod" nil nil)
          (let* ((verdict (first (prove (placement-facts pod (field nodes "items")
                                                         (if (complete-list-p pods pods-state)
                                                             (field pods "items")
                                                             :unknown))
                                        '((placement ?verdict)) '?verdict)))
                 (rejections (and verdict (svref verdict 1))))
            (when rejections
              (destructuring-bind (code summary step)
                  (first (known '(placement_explanation ?code ?summary ?step) '(?code ?summary ?step)))
                (let ((groups nil) (id (format nil "n~D" (1+ (length (gethash "evidence" report))))))
                  ;; Nodes ruled out the same way share a line.
                  (loop for (node reason) in rejections
                        for text = (rejection-text reason)
                        do (push node (cdr (or (assoc text groups :test #'equal)
                                               (first (push (list text) groups))))))
                  (setf (gethash "evidence" report)
                        (concatenate 'vector (gethash "evidence" report)
                                     (vector (object "id" id "kind" "Node" "name" "*" "result" "listed"
                                                     "observedAt" (timestamp) "detail" "Every node, and the Pods on them"))))
                  (setf (gethash "findings" report)
                        (concatenate 'vector (gethash "findings" report)
                                     (vector (object "code" code "rule" code "severity" "warning"
                                                     "summary" (format nil summary (field pod "metadata" "name")
                                                                       (length rejections) (length rejections))
                                                     "detailHeading" "What rules each node out:"
                                                     "detail" (format nil "~{~A~^~%~}"
                                                                      (loop for (text . nodes) in (reverse groups)
                                                                            collect (format nil "~{~A~^, ~} ~A"
                                                                                            (reverse nodes) text)))
                                                     "nextStep" step
                                                     "evidence" (vector (field (aref (gethash "evidence" report) 0) "id") id)))))
                  (unless (equal "incomplete" (gethash "status" report))
                    (setf (gethash "status" report) "findings"))))))))))
  report)
