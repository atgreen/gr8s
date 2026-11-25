;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Explain a connection under networking.k8s.io/v1 NetworkPolicy (podster-5hv.3): for
;;;; each end -- the source leaving, the destination arriving -- whether a policy isolates
;;;; it, which rule of which policy allows the connection, and, when none does, the
;;;; smallest rule that would. It reads the same parsed policies the dataplane enforces,
;;;; with Kubernetes' semantics: an end no policy selects for a direction is open in that
;;;; direction; an isolated end admits what any rule of any policy isolating it allows.
;;;;
;;;; An end is (:pod np-pod) or (:address "ip"); only a Pod can be isolated, and only a
;;;; Pod's labels can be selected.

(in-package #:gr8s.network)

(defparameter +np-identity-label-keys+
  '(("app.kubernetes.io/name" "app.kubernetes.io/component" "app.kubernetes.io/instance")
    ("app") ("k8s-app") ("name"))
  "The label sets that say what a Pod is, best first, for a suggested rule's selector.")

(defparameter +np-per-pod-label-keys+
  '("pod-template-hash" "pod-template-generation" "controller-revision-hash"
    "statefulset.kubernetes.io/pod-name" "apps.kubernetes.io/pod-index"
    "controller-uid" "batch.kubernetes.io/controller-uid" "batch.kubernetes.io/job-completion-index")
  "Labels that tell one replica from another, which a rule shouldn't select on.")

(defun np-protocol-keyword (protocol)
  "A flow's protocol name as policy's keyword: :tcp, :udp, :sctp, or NIL for one policy
can't name (ICMP), which only a rule with no ports admits."
  (cond ((string-equal protocol "TCP") :tcp)
        ((string-equal protocol "UDP") :udp)
        ((string-equal protocol "SCTP") :sctp)))

(defun np-end-pod (end) (and (eq (first end) :pod) (second end)))

(defun np-end-addresses (end)
  (if (eq (first end) :pod) (np-pod-addresses (second end)) (list (second end))))

(defun np-port-matches-p (port number protocol destination)
  "Whether policy PORT admits NUMBER over PROTOCOL to DESTINATION (an end), resolving a
named port against the destination Pod's containers."
  (and protocol (eq protocol (np-port-protocol port))
       (let ((wanted (np-port-port port)))
         (cond ((null wanted) t)
               ((null number) nil)
               ((stringp wanted)
                (let ((pod (np-end-pod destination)))
                  (and pod (eql number (np-pod-named-port pod wanted protocol)))))
               ((np-port-end-port port) (<= wanted number (np-port-end-port port)))
               (t (eql wanted number))))))

(defun np-rule-ports-match-p (rule number protocol destination)
  (let ((ports (np-rule-ports rule)))
    (or (null ports)
        (some (lambda (port) (np-port-matches-p port number protocol destination)) ports))))

(defun np-peer-matches-p (peer end policy-namespace namespace-labels)
  "Whether policy PEER selects END."
  (if (np-peer-cidr peer)
      (some (lambda (address)
              (and (network-address-in-cidr-p (np-peer-cidr peer) address)
                   (notany (lambda (except) (network-address-in-cidr-p except address)) (np-peer-except peer))))
            (np-end-addresses end))
      (let ((pod (np-end-pod end))
            (namespace-selector (np-peer-namespace-selector peer))
            (pod-selector (np-peer-pod-selector peer)))
        (and pod
             (if namespace-selector
                 (np-selector-matches-p namespace-selector (gethash (np-pod-namespace pod) namespace-labels))
                 (equal (np-pod-namespace pod) policy-namespace))
             (or (null pod-selector) (np-selector-matches-p pod-selector (np-pod-labels pod)))))))

(defun np-rule-peers-match-p (rule end policy-namespace namespace-labels)
  (let ((peers (np-rule-peers rule)))
    (or (eq peers :all)
        (some (lambda (peer) (np-peer-matches-p peer end policy-namespace namespace-labels)) peers))))

(defun np-spec-qualified-name (spec)
  (format nil "~A/~A" (np-spec-namespace spec) (np-spec-name spec)))

(defun np-identity-labels (pod)
  "The labels that say what POD is, for a suggested selector: the first of
+NP-IDENTITY-LABEL-KEYS+'s sets it carries, else every label but the per-replica ones."
  (let ((labels (np-pod-labels pod)))
    (flet ((pick (keys) (loop for key in keys
                              for value = (and (hash-table-p labels) (gethash key labels))
                              when value collect (cons key value))))
      (or (some #'pick +np-identity-label-keys+)
          (and (hash-table-p labels)
               (sort (loop for key being the hash-keys of labels using (hash-value value)
                           unless (member key +np-per-pod-label-keys+ :test #'equal)
                             collect (cons key value))
                     #'string< :key #'car))))))

(defun np-suggested-rule-yaml (direction policy peer-end subject number protocol)
  "YAML for the rule to add to POLICY's DIRECTION rules to admit PEER-END on NUMBER over
PROTOCOL; SUBJECT is the isolated end."
  (with-output-to-string (out)
    (format out "# Add to ~A, under spec.~(~A~):~%" (np-spec-qualified-name policy) direction)
    (format out "- ~A:~%" (if (eq direction :ingress) "from" "to"))
    (let ((pod (np-end-pod peer-end)))
      (if pod
          (progn
            (format out "    - podSelector:~%        matchLabels:~%")
            (loop for (key . value) in (np-identity-labels pod)
                  do (format out "          ~A: ~A~%" key value))
            (unless (equal (np-pod-namespace pod) (np-pod-namespace (np-end-pod subject)))
              (format out "      namespaceSelector:~%        matchLabels:~%          kubernetes.io/metadata.name: ~A~%"
                      (np-pod-namespace pod))))
          (let ((address (second peer-end)))
            (format out "    - ipBlock:~%        cidr: ~A/~D~%" address (if (find #\: address) 128 32)))))
    (if (and protocol number)
        (format out "  ports:~%    - protocol: ~A~%      port: ~D~%" (string-upcase (symbol-name protocol)) number)
        (format out "  # No ports: NetworkPolicy can't name this protocol, so only a rule~%  # without ports admits it.~%"))))

(defun explain-network-side (specs direction subject other number protocol namespace-labels)
  "How the DIRECTION policies of SUBJECT (the end they would select) treat the connection
with OTHER: an object with \"verdict\" -- \"not-a-pod\", \"open\", \"allowed\" or
\"denied\" -- the policies that isolate SUBJECT, the rules that allow it (each a policy
and its 1-based rule number), and for a denied one a suggested rule."
  (let ((pod (np-end-pod subject))
        (destination (if (eq direction :ingress) subject other)))
    (unless pod
      (return-from explain-network-side (core-object "verdict" "not-a-pod")))
    (let* ((type (if (eq direction :ingress) "Ingress" "Egress"))
           (isolating (remove-if-not (lambda (spec)
                                       (and (member type (np-spec-policy-types spec) :test #'equal)
                                            (np-spec-selects-pod-p spec pod)))
                                     specs))
           (allowing (loop for spec in isolating
                           append (loop for rule in (if (eq direction :ingress) (np-spec-ingress spec) (np-spec-egress spec))
                                        for index from 1
                                        when (and (np-rule-peers-match-p rule other (np-spec-namespace spec) namespace-labels)
                                                  (np-rule-ports-match-p rule number protocol destination))
                                          collect (core-object "policy" (np-spec-qualified-name spec) "rule" index)))))
      (let ((result (core-object "verdict" (cond ((null isolating) "open") (allowing "allowed") (t "denied"))
                                 "isolatedBy" (coerce (mapcar #'np-spec-qualified-name isolating) 'vector)
                                 "allowedBy" (coerce allowing 'vector))))
        (when (and isolating (null allowing))
          (setf (gethash "suggestion" result)
                (np-suggested-rule-yaml direction (first isolating) other subject number protocol)))
        result))))

(defun explain-network-connection (specs source destination number protocol namespace-labels)
  "Explain a connection from SOURCE to DESTINATION (ends) on port NUMBER over PROTOCOL (a
flow's protocol name) under SPECS (np-specs): its \"egress\" side, leaving SOURCE, and its
\"ingress\" side, arriving at DESTINATION. NAMESPACE-LABELS maps namespaces to labels."
  (let* ((protocol (np-protocol-keyword protocol))
         (egress (explain-network-side specs :egress source destination number protocol namespace-labels))
         (ingress (explain-network-side specs :ingress destination source number protocol namespace-labels)))
    (core-object "egress" egress "ingress" ingress
                 "verdict" (if (or (equal "denied" (gethash "verdict" egress))
                                   (equal "denied" (gethash "verdict" ingress)))
                               "denied" "allowed"))))

(defun np-pod-isolation (specs pod)
  "The policies that isolate POD, as (values ingress egress) lists of namespace/name."
  (flet ((isolating (type)
           (loop for spec in specs
                 when (and (member type (np-spec-policy-types spec) :test #'equal) (np-spec-selects-pod-p spec pod))
                   collect (np-spec-qualified-name spec))))
    (values (isolating "Ingress") (isolating "Egress"))))
