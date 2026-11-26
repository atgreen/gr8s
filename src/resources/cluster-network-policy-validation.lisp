;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Validate policy.networking.k8s.io/v1alpha2 ClusterNetworkPolicy as the
;;;; network-policy-api CRD's schema and CEL rules do (podster-wv1w.1), so a policy
;;;; gr8s accepts is one upstream implementations accept too. gr8s serves the group
;;;; natively; installing the upstream CRDs on top registers it twice.

(in-package #:gr8s.resources)

(defparameter +cnp-domain-name-scanner+
  (cl-ppcre:create-scanner
   "^(\\*\\.)?([a-zA-Z0-9]([-a-zA-Z0-9_]*[a-zA-Z0-9])?\\.)+[a-zA-Z0-9]([-a-zA-Z0-9_]*[a-zA-Z0-9])?\\.?$")
  "The DomainName pattern: a name of two or more labels, optionally led by a *. wildcard.")

(defun %cnp-invalid (control &rest arguments)
  (apply #'core-resource-error 422 "Invalid" (concatenate 'string "ClusterNetworkPolicy " control) arguments))

(defun %cnp-object (value path)
  (unless (hash-table-p value) (%cnp-invalid "~A must be an object" path))
  value)

(defun %cnp-list (value path &key (min 0) (max 25))
  (unless (and (vectorp value) (not (stringp value))) (%cnp-invalid "~A must be a list" path))
  (unless (<= min (length value) max) (%cnp-invalid "~A must have ~D to ~D items" path min max))
  (coerce value 'list))

(defun %cnp-one-of (object keys path)
  "The one key of KEYS OBJECT sets; anything else, or not exactly one, is invalid."
  (let ((present (loop for key being the hash-keys of object collect key)))
    (dolist (key present)
      (unless (member key keys :test #'equal) (%cnp-invalid "~A.~A is not supported" path key)))
    (unless (= 1 (length present)) (%cnp-invalid "~A must set exactly one of ~{~A~^, ~}" path keys))
    (first present)))

(defun %cnp-selector (value path)
  (%cnp-object value path)
  (validate-workload-selector value :allow-empty t))

(defun %cnp-namespaced-pod (value path)
  (%cnp-object value path)
  (dolist (key (loop for key being the hash-keys of value collect key))
    (unless (member key '("namespaceSelector" "podSelector") :test #'equal)
      (%cnp-invalid "~A.~A is not supported" path key)))
  (multiple-value-bind (selector present) (gethash "podSelector" value)
    (unless present (%cnp-invalid "~A.podSelector is required" path))
    (%cnp-selector selector (format nil "~A.podSelector" path)))
  (multiple-value-bind (selector present) (gethash "namespaceSelector" value)
    (when present (%cnp-selector selector (format nil "~A.namespaceSelector" path)))))

(defun %cnp-port-number (value path)
  (unless (and (integerp value) (<= 1 value 65535)) (%cnp-invalid "~A must be 1 to 65535" path))
  value)

(defun %cnp-protocol (value path)
  "Validate one ClusterNetworkPolicyProtocol; return its key."
  (%cnp-object value path)
  (let ((key (%cnp-one-of value '("tcp" "udp" "sctp" "destinationNamedPort") path)))
    (if (equal key "destinationNamedPort")
        (unless (and (stringp (gethash key value)) (plusp (length (gethash key value))))
          (%cnp-invalid "~A.destinationNamedPort must be a port name" path))
        (let ((body (%cnp-object (gethash key value) (format nil "~A.~A" path key))))
          (dolist (field (loop for field being the hash-keys of body collect field))
            (unless (equal field "destinationPort") (%cnp-invalid "~A.~A.~A is not supported" path key field)))
          (unless (plusp (hash-table-count body)) (%cnp-invalid "~A.~A must set destinationPort" path key))
          (let* ((port-path (format nil "~A.~A.destinationPort" path key))
                 (port (%cnp-object (gethash "destinationPort" body) port-path)))
            (if (equal (%cnp-one-of port '("number" "range") port-path) "number")
                (%cnp-port-number (gethash "number" port) (format nil "~A.number" port-path))
                (let* ((range (%cnp-object (gethash "range" port) (format nil "~A.range" port-path)))
                       (start (%cnp-port-number (gethash "start" range) (format nil "~A.range.start" port-path)))
                       (end (%cnp-port-number (gethash "end" range) (format nil "~A.range.end" port-path))))
                  (unless (< start end) (%cnp-invalid "~A.range: start port must be less than end port" port-path)))))))
    key))

(defun %cnp-cidr (value path)
  (progn
    (unless (and (stringp value) (networking-cidr-p value) (<= (length value) 43))
      (%cnp-invalid "~A: invalid CIDR format provided" path))))

(defun %cnp-peer (value path direction)
  "Validate one peer; return its kind."
  (%cnp-object value path)
  (let ((kind (%cnp-one-of value (if (eq direction :egress)
                                     '("namespaces" "pods" "nodes" "networks" "domainNames")
                                     '("namespaces" "pods"))
                           path))
        (field (format nil "~A.~A" path (first (loop for key being the hash-keys of value collect key)))))
    (cond ((member kind '("namespaces" "nodes") :test #'equal) (%cnp-selector (gethash kind value) field))
          ((equal kind "pods") (%cnp-namespaced-pod (gethash kind value) field))
          ((equal kind "networks")
           (loop for cidr in (%cnp-list (gethash kind value) field :min 1)
                 for index from 0 do (%cnp-cidr cidr (format nil "~A[~D]" field index))))
          ((equal kind "domainNames")
           (loop for name in (%cnp-list (gethash kind value) field :min 1)
                 for index from 0
                 unless (and (stringp name) (cl-ppcre:scan +cnp-domain-name-scanner+ name))
                   do (%cnp-invalid "~A[~D]: ~S is not a domain name" field index name))))
    kind))

(defun %cnp-rule (rule path direction)
  (%cnp-object rule path)
  (let ((peers-key (if (eq direction :egress) "to" "from")))
    (dolist (key (loop for key being the hash-keys of rule collect key))
      (unless (member key (list "name" "action" peers-key "protocols") :test #'equal)
        (%cnp-invalid "~A.~A is not supported" path key)))
    (multiple-value-bind (name present) (gethash "name" rule)
      (when (and present (not (and (stringp name) (<= (length name) 100))))
        (%cnp-invalid "~A.name must be a string of at most 100 characters" path)))
    (let ((action (gethash "action" rule)))
      (unless (member action '("Accept" "Deny" "Pass") :test #'equal)
        (%cnp-invalid "~A.action must be Accept, Deny or Pass" path))
      (let* ((peer-kinds (loop for peer in (%cnp-list (gethash peers-key rule) (format nil "~A.~A" path peers-key) :min 1)
                               for index from 0
                               collect (%cnp-peer peer (format nil "~A.~A[~D]" path peers-key index) direction)))
             (protocols (multiple-value-bind (value present) (gethash "protocols" rule)
                          (when present
                            (loop for protocol in (%cnp-list value (format nil "~A.protocols" path) :min 1)
                                  for index from 0
                                  collect (%cnp-protocol protocol (format nil "~A.protocols[~D]" path index)))))))
        (when (and (member "destinationNamedPort" protocols :test #'equal)
                   (intersection peer-kinds '("networks" "nodes" "domainNames") :test #'equal))
          (%cnp-invalid "~A: networks/nodes/domainNames peer cannot be set with namedPorts since there are no namedPorts for networks/nodes/domainNames" path))
        (when (and (member "domainNames" peer-kinds :test #'equal) (not (equal action "Accept")))
          (%cnp-invalid "~A: domainNames is only supported for Accept rules" path))))))

(defun validate-cluster-network-policy (object)
  "Validate ClusterNetworkPolicy OBJECT's spec; signal a 422 naming the first problem."
  (let ((spec (%cnp-object (gethash "spec" object) "spec")))
    (dolist (key (loop for key being the hash-keys of spec collect key))
      (unless (member key '("tier" "priority" "subject" "ingress" "egress") :test #'equal)
        (%cnp-invalid "spec.~A is not supported" key)))
    (unless (member (gethash "tier" spec) '("Admin" "Baseline") :test #'equal)
      (%cnp-invalid "spec.tier must be Admin or Baseline"))
    (let ((priority (gethash "priority" spec)))
      (unless (and (integerp priority) (<= 0 priority 1000))
        (%cnp-invalid "spec.priority must be an integer from 0 to 1000")))
    (let* ((subject (%cnp-object (gethash "subject" spec) "spec.subject"))
           (kind (%cnp-one-of subject '("namespaces" "pods") "spec.subject")))
      (if (equal kind "namespaces")
          (%cnp-selector (gethash kind subject) "spec.subject.namespaces")
          (%cnp-namespaced-pod (gethash kind subject) "spec.subject.pods")))
    (dolist (direction '(:ingress :egress))
      (let ((key (if (eq direction :egress) "egress" "ingress")))
        (multiple-value-bind (rules present) (gethash key spec)
          (when present
            (loop for rule in (%cnp-list rules (format nil "spec.~A" key))
                  for index from 0
                  do (%cnp-rule rule (format nil "spec.~A[~D]" key index) direction))))))))
