;;;; SPDX-License-Identifier: MIT
(in-package #:gr8s-diagnose)

;;; Recent NetworkPolicy drops as evidence (podster-e9a.4). A gr8s cluster serves
;;; its nodes' flow events at /apis/gr8s.io/v1/flows; on any other cluster that
;;; read fails, and a Pod's report simply has no flow evidence.

(defun flows-list-from-text (text)
  "The flow events in TEXT, one JSON object per line, as a list object whose items
carry their Pod's namespace as metadata, the way the snapshot getter indexes lists."
  (object "items"
          (coerce (loop for line in (uiop:split-string text :separator '(#\Newline))
                        for flow = (and (plusp (length (string-trim " " line)))
                                        (ignore-errors (com.inuoe.jzon:parse line)))
                        when (and (hash-table-p flow) (not (gethash "error" flow)))
                          do (setf (gethash "metadata" flow)
                                   (object "namespace" (gethash "namespace" flow)))
                          and collect flow)
                  'vector)))

(defun flows-raw-path (namespace)
  (format nil "/apis/gr8s.io/v1/~@[namespaces/~A/~]flows" namespace))

(defun pod-policy-drops (pod ns flows)
  "POD's recent policy drops among FLOWS, grouped as ((direction peer port protocol
policies) . count) in order of first appearance."
  (let ((name (field pod "metadata" "name")) (groups nil))
    (loop for flow across flows
          when (and (equal ns (gethash "namespace" flow)) (equal name (gethash "pod" flow))
                    (equal "DROPPED" (gethash "verdict" flow)) (equal "policy" (gethash "reason" flow)))
            do (let* ((peer (if (gethash "peerPod" flow)
                                (format nil "~A/~A" (gethash "peerNamespace" flow) (gethash "peerPod" flow))
                                (gethash "peerAddress" flow "an unknown address")))
                      (key (list (gethash "direction" flow "egress") peer
                                 (if (equal "ingress" (gethash "direction" flow))
                                     (gethash "podPort" flow) (gethash "peerPort" flow))
                                 (gethash "protocol" flow)
                                 (coerce (gethash "policies" flow #()) 'list)))
                      (entry (assoc key groups :test #'equal)))
                 (if entry (incf (cdr entry)) (push (cons key 1) groups))))
    (nreverse groups)))

(defun policy-drop-finding (pod ns group evidence)
  (destructuring-bind ((direction peer port protocol policies) . count) group
    (let ((ingress (equal direction "ingress")))
      (object "code" "network-policy-drops" "rule" "network-policy-drops" "severity" "warning"
              "summary" (format nil "Pod ~A: NetworkPolicy dropped ~D recent ~A ~A ~A~@[ over ~A~]~@[ on port ~D~].~
~@[ It is isolated by ~A, which allow~:[s~;~] none of this.~]"
                                (field pod "metadata" "name") count
                                (if (> count 1) "connections" "connection") (if ingress "from" "to")
                                peer protocol port
                                (and policies (format nil "~{~A~^, ~}" policies))
                                (rest policies))
              "detailHeading" "Isolating NetworkPolicies"
              "detail" (if policies
                           (format nil "~{~A/~A~^, ~}" (loop for policy in policies collect ns collect policy))
                           "The Pod's isolating policies weren't known when the drop was seen.")
              "nextStep" (format nil "If this traffic should pass, add an ~:[egress~;ingress~] rule allowing ~A~@[ on port ~D~] ~
to one of these policies, or check that the peer's labels and namespace match an existing rule. ~
gr8s doctor observe --namespace ~A --pod ~A --verdict dropped shows the drops as they happen."
                                 ingress peer port ns (field pod "metadata" "name"))
              "evidence" (vector evidence)))))

(defun augment-pod-flows (report pod kind ns getter)
  "Add to a Pod's REPORT a finding for each kind of recent NetworkPolicy drop of it."
  (when (and (equal kind "Pod") (hash-table-p pod)
             (plusp (length (gethash "evidence" report)))
             (equal "present" (field (aref (gethash "evidence" report) 0) "result")))
    (multiple-value-bind (list state observed-at) (funcall getter "Flows" ns nil)
      (when (and (eq state :present) (json-array-p (field list "items")))
        (let ((groups (pod-policy-drops pod ns (field list "items"))))
          (when groups
            (let ((id (format nil "f~D" (1+ (length (gethash "evidence" report))))))
              (setf (gethash "evidence" report)
                    (concatenate 'vector (gethash "evidence" report)
                                 (vector (object "id" id "kind" "Flows" "namespace" ns "name" "*"
                                                 "result" "present" "observedAt" (or observed-at (timestamp)))))
                    (gethash "findings" report)
                    (concatenate 'vector (gethash "findings" report)
                                 (map 'vector (lambda (group) (policy-drop-finding pod ns group id)) groups))
                    (gethash "status" report) "findings"))))))))
