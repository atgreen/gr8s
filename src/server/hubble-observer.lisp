;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; `gr8s doctor observe --serve' (podster-e9a.5): serve Hubble's Observer gRPC API on this
;;;; machine, from the cluster's flow events, so the stock `hubble' CLI and UI can
;;;; read them, as `cilium hubble port-forward' serves Hubble Relay. It reads
;;;; /apis/gr8s.io/v1/flows with the kubeconfig's credentials, so it adds nothing
;;;; to the cluster and shows only what those credentials may list. Flows become
;;;; flow.Flow messages; the request's FlowFilters are applied here, as Hubble
;;;; applies them server-side, and a filter gr8s can't apply is refused.

(in-package #:gr8s.server)

(defparameter +hubble-default-listen+ "127.0.0.1:4245"
  "Where the hubble CLI looks by default.")

;;; Flow events as flow.Flow messages

(defun hubble-timestamp (text)
  "A Timestamp for the RFC 3339 TEXT gr8s writes, or NIL."
  (handler-case
      (let* ((seconds (- (encode-universal-time (parse-integer text :start 17 :end 19)
                                                (parse-integer text :start 14 :end 16)
                                                (parse-integer text :start 11 :end 13)
                                                (parse-integer text :start 8 :end 10)
                                                (parse-integer text :start 5 :end 7)
                                                (parse-integer text :start 0 :end 4) 0)
                         (encode-universal-time 0 0 0 1 1 1970 0)))
             (dot (position #\. text))
             (end (and dot (or (position-if-not #'digit-char-p text :start (1+ dot)) (length text))))
             (digits (if dot (min 9 (- end dot 1)) 0))
             (fraction (if (plusp digits) (parse-integer text :start (1+ dot) :end (+ dot 1 digits)) 0)))
        (make-instance 'gr8s.hubble.observer::timestamp :seconds seconds
                                                        :nanos (* fraction (expt 10 (- 9 digits)))))
    (error () nil)))

(defun hubble-timestamp-seconds (timestamp)
  "TIMESTAMP as a real number of Unix seconds, or NIL without one."
  (and timestamp
       (+ (slot-value timestamp 'gr8s.hubble.observer::seconds)
          (/ (slot-value timestamp 'gr8s.hubble.observer::nanos) 1000000000))))

(defparameter +hubble-per-pod-label-keys+
  '("pod-template-hash" "pod-template-generation" "controller-revision-hash"
    "statefulset.kubernetes.io/pod-name" "apps.kubernetes.io/pod-index"
    "controller-uid" "batch.kubernetes.io/controller-uid" "batch.kubernetes.io/job-completion-index")
  "Labels that tell one replica from another, which Cilium leaves out of an identity.")

(defun hubble-labels (namespace labels)
  "Cilium-style k8s: labels for a Pod in NAMESPACE with LABELS: those of its identity,
without the labels that differ between replicas."
  (sort (append (when namespace (list (format nil "k8s:io.kubernetes.pod.namespace=~A" namespace)))
                (when (hash-table-p labels)
                  (loop for key being the hash-keys of labels using (hash-value value)
                        unless (member key +hubble-per-pod-label-keys+ :test #'equal)
                          collect (format nil "k8s:~A=~A" key value))))
        #'string<))

(defun hubble-identity (namespace labels)
  "A stable numeric identity, past Cilium's reserved range, for Pods in NAMESPACE with
LABELS. As Cilium's, it follows the label set, not the Pod: a workload's replicas share
one, and so one card in Hubble UI (podster-u0e)."
  (+ 256 (mod (sxhash (format nil "~{~A~^,~}" (hubble-labels namespace labels))) 65000)))

(defun hubble-service-identity (namespace service)
  "A stable numeric identity for Service NAMESPACE/SERVICE seen without its Pod."
  (+ 256 (mod (sxhash (format nil "~A/service/~A" namespace service)) 65000)))

(defun hubble-endpoint (namespace pod labels &optional service)
  "A flow's side: a Pod; a Service whose Pod isn't known by address (a Gateway's
host-network backend), as a Service workload in its namespace; or, for an address gr8s
doesn't know at all, Cilium's world endpoint (identity 2, reserved:world), as Hubble
shows traffic leaving the cluster."
  (cond (pod
         (make-instance 'gr8s.hubble.observer::endpoint
                        :identity (hubble-identity namespace labels)
                        :namespace (or namespace "") :pod-name pod
                        :labels (hubble-labels namespace labels)))
        ((and namespace service)
         (make-instance 'gr8s.hubble.observer::endpoint
                        :identity (hubble-service-identity namespace service)
                        :namespace namespace
                        :labels (hubble-labels namespace nil)
                        :workloads (list (make-instance 'gr8s.hubble.observer::workload
                                                        :name service :kind "Service"))))
        (t (make-instance 'gr8s.hubble.observer::endpoint :identity 2 :labels (list "reserved:world")))))

(defun hubble-l4 (protocol source-port destination-port)
  "The Layer4 message for PROTOCOL, a gr8s protocol name, or NIL."
  (flet ((ports (class) (make-instance class :source-port (or source-port 0)
                                             :destination-port (or destination-port 0)))
         (layer4 (case initarg value)
           ;; A oneof is written only for the variant its case slot names.
           (let ((l4 (make-instance 'gr8s.hubble.observer::layer4 initarg value)))
             (setf (gr8s.hubble.observer::protocol-case l4) case)
             l4)))
    (cond ((equal protocol "TCP") (layer4 :tcp :tcp (ports 'gr8s.hubble.observer::tcp)))
          ((equal protocol "UDP") (layer4 :udp :udp (ports 'gr8s.hubble.observer::udp)))
          ((equal protocol "SCTP") (layer4 :sctp :sctp (ports 'gr8s.hubble.observer::sctp)))
          ((equal protocol "ICMP")
           (layer4 :icmpv4 :icmpv4 (make-instance 'gr8s.hubble.observer::icm-pv4)))
          ((equal protocol "ICMPv6")
           (layer4 :icmpv6 :icmpv6 (make-instance 'gr8s.hubble.observer::icm-pv6))))))

(defun hubble-drop-reason (reason)
  (cond ((equal reason "policy") gr8s.hubble.observer::+dropreason-policy_denied+)
        ((equal reason "spoof") gr8s.hubble.observer::+dropreason-invalid_source_ip+)
        ((equal reason "malformed") gr8s.hubble.observer::+dropreason-invalid_packet_dropped+)
        ((equal reason "unsupported") gr8s.hubble.observer::+dropreason-unsupported_l3_protocol+)
        (t gr8s.hubble.observer::+dropreason-drop_reason_unknown+)))

(defun hubble-l7 (l7)
  "The flow.Layer7 record of a Gateway request's L7, a response as Cilium's proxy reports it."
  (let ((record (make-instance 'gr8s.hubble.observer::layer7
                               :type gr8s.hubble.observer::+l7flowtype-response+
                               :latency-ns (gethash "latencyNs" l7 0)
                               :http (make-instance 'gr8s.hubble.observer::http
                                                    :code (gethash "code" l7 0) :method (gethash "method" l7 "")
                                                    :url (format nil "http://~A~A" (gethash "host" l7 "") (gethash "path" l7 ""))
                                                    :protocol "HTTP/1.1"))))
    (setf (slot-value record 'gr8s.hubble.observer::record-case) :http)
    record))

(defun hubble-flow (flow)
  "The flow.Flow message for FLOW, a gr8s flow event. The Pod is the source of traffic
it sends and the destination of traffic it receives."
  (let* ((ingress (equal "ingress" (gethash "direction" flow)))
         (pod (hubble-endpoint (gethash "namespace" flow) (gethash "pod" flow) (gethash "podLabels" flow)
                               (gethash "service" flow)))
         (peer (hubble-endpoint (gethash "peerNamespace" flow) (gethash "peerPod" flow) (gethash "peerLabels" flow)))
         (pod-address (gethash "podAddress" flow ""))
         (peer-address (gethash "peerAddress" flow ""))
         (address (or (find-if #'plusp (list (length pod-address) (length peer-address))) 0))
         (ipv6 (or (find #\: pod-address) (find #\: peer-address)))
         (policies (map 'list (lambda (name)
                                (make-instance 'gr8s.hubble.observer::policy
                                               :name name :namespace (gethash "namespace" flow "")
                                               :kind "NetworkPolicy"))
                        (gethash "policies" flow #())))
         (dropped (equal "DROPPED" (gethash "verdict" flow)))
         (reason (hubble-drop-reason (gethash "reason" flow)))
         (l7 (gethash "l7" flow))
         ;; An agent names the protocols it knows and gives the others' numbers.
         (protocol (let ((protocol (gethash "protocol" flow "")))
                     (if (stringp protocol) protocol (princ-to-string protocol)))))
    (make-instance
     'gr8s.hubble.observer::flow
     :time (hubble-timestamp (gethash "time" flow ""))
     :verdict (if dropped gr8s.hubble.observer::+verdict-dropped+ gr8s.hubble.observer::+verdict-forwarded+)
     :drop-reason-desc (if dropped reason gr8s.hubble.observer::+dropreason-drop_reason_unknown+)
     ;; A drop is a drop notification with its reason; an isolated Pod's new connection,
     ;; the policy verdict that allowed it. Every gr8s event is of the flow's own
     ;; direction, never a reply: the hubble CLI draws -> and Hubble UI's reply filter
     ;; passes it.
     ;; A Gateway request is an access log record (129), as Cilium's proxy makes one.
     :event-type (make-instance 'gr8s.hubble.observer::cilium-event-type
                                :type (cond (l7 129) (dropped 1) (t 5)) :sub-type (if dropped reason 0))
     :policy-match-type (if (or dropped l7) 0 2)
     :is-reply (make-instance 'gr8s.hubble.observer::bool-value :value nil)
     :ip (when (plusp address)
           (make-instance 'gr8s.hubble.observer::ip
                          :source (if ingress peer-address pod-address)
                          :destination (if ingress pod-address peer-address)
                          :ipversion (if ipv6 gr8s.hubble.observer::|+IPVERSION-IPv6+|
                                         gr8s.hubble.observer::|+IPVERSION-IPv4+|)))
     :l4 (if ingress
             (hubble-l4 (gethash "protocol" flow) (gethash "peerPort" flow) (gethash "podPort" flow))
             (hubble-l4 (gethash "protocol" flow) (gethash "podPort" flow) (gethash "peerPort" flow)))
     :source (if ingress peer pod)
     :destination (if ingress pod peer)
     :type (if l7 gr8s.hubble.observer::+flowtype-l7+ gr8s.hubble.observer::+flowtype-l3_l4+)
     ;; What `hubble observe' prints in parentheses: Cilium's HTTP response summary,
     ;; or for L3/L4 just the protocol, since gr8s records no TCP flags.
     :summary (if l7
                  (format nil "HTTP/1.1 ~D ~Dms (~A http://~A~A)" (gethash "code" l7 0)
                          (floor (gethash "latencyNs" l7 0) 1000000)
                          (gethash "method" l7 "") (gethash "host" l7 "") (gethash "path" l7 ""))
                  protocol)
     :l7 (and l7 (hubble-l7 l7))
     :node-name (gethash "node" flow "")
     :traffic-direction (if ingress gr8s.hubble.observer::+trafficdirection-ingress+
                            gr8s.hubble.observer::+trafficdirection-egress+)
     :egress-denied-by (and dropped (not ingress) policies)
     :ingress-denied-by (and dropped ingress policies))))

;;; FlowFilters, as Hubble applies them: a flow passes a filter when every field the
;;; filter sets has a value that matches, and a request's flows are those matching
;;; any whitelist filter (or all, with none) and no blacklist filter.

(defparameter +hubble-unsupported-filter-fields+
  '(gr8s.hubble.observer::source-service gr8s.hubble.observer::destination-service)
  "Filter fields gr8s can't apply: it doesn't know which Service a flow was sent to.
Fields about DNS names it can: no gr8s flow has any, so they match none.")

(defparameter +hubble-unmatched-filter-fields+
  '(gr8s.hubble.observer::source-fqdn gr8s.hubble.observer::destination-fqdn
    gr8s.hubble.observer::dns-query)
  "Filter fields no gr8s flow matches, since gr8s flows carry no DNS names.")

(define-condition hubble-unsupported-filter (error)
  ((field :initarg :field :reader hubble-unsupported-filter-field))
  (:report (lambda (condition stream)
             (format stream "gr8s can't filter flows by ~(~A~)"
                     (substitute #\_ #\- (symbol-name (hubble-unsupported-filter-field condition)))))))

(defun check-hubble-filter (filter)
  "Refuse FILTER when it sets a field gr8s can't apply, or an HTTP value Hubble would refuse."
  (dolist (field +hubble-unsupported-filter-fields+)
    (when (slot-value filter field)
      (error 'hubble-unsupported-filter :field field)))
  (dolist (code (slot-value filter 'gr8s.hubble.observer::http-status-code))
    (unless (or (cl-ppcre:scan "^[1-5][0-9]{2}$" code) (cl-ppcre:scan "^[1-5][0-9]?\\+$" code))
      (error "invalid http_status_code ~S: use a code, or a prefix such as 4+" code)))
  (dolist (path (slot-value filter 'gr8s.hubble.observer::http-path))
    (handler-case (cl-ppcre:create-scanner path)
      (error () (error "invalid http_path regular expression ~S" path)))))

(defun hubble-http-matches-p (filter flow)
  "Whether FLOW's HTTP record passes FILTER's status code, method and path fields, as
Hubble applies them. A flow without one passes none of them."
  (let* ((l7 (slot-value flow 'gr8s.hubble.observer::l7))
         (http (and l7 (slot-value l7 'gr8s.hubble.observer::http)))
         (codes (slot-value filter 'gr8s.hubble.observer::http-status-code))
         (methods (slot-value filter 'gr8s.hubble.observer::http-method))
         (paths (slot-value filter 'gr8s.hubble.observer::http-path)))
    (or (not (or codes methods paths))
        (and http
             (or (null codes)
                 (let ((code (princ-to-string (slot-value http 'gr8s.hubble.observer::code))))
                   (some (lambda (want)
                           (if (uiop:string-suffix-p want "+")
                               (uiop:string-prefix-p (string-right-trim "+" want) code)
                               (equal want code)))
                         codes)))
             (or (null methods)
                 (member (slot-value http 'gr8s.hubble.observer::proto-method) methods :test #'string-equal))
             (or (null paths)
                 (let* ((url (slot-value http 'gr8s.hubble.observer::url))
                        (start (or (search "://" url) -3))
                        (slash (or (position #\/ url :start (+ start 3)) (length url)))
                        (path (subseq url slash)))
                   (some (lambda (pattern) (cl-ppcre:scan pattern path)) paths)))))))

(defun hubble-address-matches-p (address patterns)
  "Whether ADDRESS matches one of PATTERNS, each an address or a CIDR."
  (and (plusp (length address))
       (some (lambda (pattern)
               (if (find #\/ pattern)
                   (gr8s.network::network-address-in-cidr-p pattern address)
                   (equal pattern address)))
             patterns)))

(defun hubble-pod-matches-p (endpoint patterns)
  "Whether ENDPOINT matches one of PATTERNS, each NAMESPACE/ or NAMESPACE/POD-PREFIX."
  (let ((namespace (slot-value endpoint 'gr8s.hubble.observer::namespace))
        (pod (slot-value endpoint 'gr8s.hubble.observer::pod-name)))
    (and (plusp (length namespace))
         (some (lambda (pattern)
                 (let* ((slash (position #\/ pattern))
                        (want-namespace (if slash (subseq pattern 0 slash) "default"))
                        (prefix (if slash (subseq pattern (1+ slash)) pattern)))
                   (and (equal namespace want-namespace) (uiop:string-prefix-p prefix pod))))
               patterns))))

(defun hubble-label-term-matches-p (term labels)
  "Whether LABELS, Cilium-style SOURCE:KEY=VALUE strings, satisfy one label selector TERM:
KEY=VALUE, KEY!=VALUE, KEY or !KEY, where KEY may carry a SOURCE: prefix."
  (let* ((negated (uiop:string-prefix-p "!" term))
         (term (string-trim " " (if negated (subseq term 1) term)))
         (not-equal (search "!=" term))
         (equal-at (or not-equal (position #\= term)))
         (key (if equal-at (subseq term 0 equal-at) term))
         (value (and equal-at (subseq term (+ equal-at (if not-equal 2 1)))))
         (colon (position #\: key))
         (source (and colon (subseq key 0 colon)))
         (key (if colon (subseq key (1+ colon)) key)))
    (flet ((present (label)
             (let* ((label-colon (position #\: label))
                    (label-source (and label-colon (subseq label 0 label-colon)))
                    (rest (if label-colon (subseq label (1+ label-colon)) label))
                    (label-equal (position #\= rest)))
               (and (or (null source) (equal source label-source))
                    (equal key (if label-equal (subseq rest 0 label-equal) rest))
                    (if label-equal (subseq rest (1+ label-equal)) "")))))
      (let ((found (some #'present labels)))
        (cond (negated (not found))
              (not-equal (not (equal found value)))
              (value (equal found value))
              (t (and found t)))))))

(defun hubble-labels-match-p (labels selectors)
  "Whether LABELS satisfy one of SELECTORS, each a comma-separated list of terms."
  (some (lambda (selector)
          (every (lambda (term) (hubble-label-term-matches-p term labels))
                 (remove "" (mapcar (lambda (term) (string-trim " " term))
                                    (uiop:split-string selector :separator ","))
                         :test #'equal)))
        selectors))

(defun hubble-flow-ports (flow)
  "(values protocol-name source-port destination-port) of FLOW's Layer4."
  (let ((l4 (slot-value flow 'gr8s.hubble.observer::l4)))
    (if (null l4)
        (values nil nil nil)
        (loop for (slot name) in '((gr8s.hubble.observer::tcp "tcp") (gr8s.hubble.observer::udp "udp")
                                   (gr8s.hubble.observer::sctp "sctp"))
              for ports = (slot-value l4 slot)
              when ports
                return (values name (slot-value ports 'gr8s.hubble.observer::source-port)
                               (slot-value ports 'gr8s.hubble.observer::destination-port))
              finally (return (values (cond ((slot-value l4 'gr8s.hubble.observer::icmpv4) "icmpv4")
                                            ((slot-value l4 'gr8s.hubble.observer::icmpv6) "icmpv6"))
                                      nil nil))))))

(defun hubble-filter-matches-p (filter flow)
  "Whether FLOW passes every field FILTER sets."
  (let ((ip (slot-value flow 'gr8s.hubble.observer::ip))
        (source (slot-value flow 'gr8s.hubble.observer::source))
        (destination (slot-value flow 'gr8s.hubble.observer::destination)))
    (multiple-value-bind (protocol source-port destination-port) (hubble-flow-ports flow)
      (flet ((field (name) (slot-value filter name))
             (ip-of (slot) (if ip (slot-value ip slot) "")))
        (and (notany #'field +hubble-unmatched-filter-fields+)
             (hubble-http-matches-p filter flow)
             (or (null (field 'gr8s.hubble.observer::source-label))
                 (hubble-labels-match-p (slot-value source 'gr8s.hubble.observer::labels)
                                        (field 'gr8s.hubble.observer::source-label)))
             (or (null (field 'gr8s.hubble.observer::destination-label))
                 (hubble-labels-match-p (slot-value destination 'gr8s.hubble.observer::labels)
                                        (field 'gr8s.hubble.observer::destination-label)))
             (or (null (field 'gr8s.hubble.observer::source-identity))
                 (member (slot-value source 'gr8s.hubble.observer::identity)
                         (field 'gr8s.hubble.observer::source-identity)))
             (or (null (field 'gr8s.hubble.observer::destination-identity))
                 (member (slot-value destination 'gr8s.hubble.observer::identity)
                         (field 'gr8s.hubble.observer::destination-identity)))
             ;; Every gr8s event is of the flow's own direction, never a reply.
             (or (null (field 'gr8s.hubble.observer::reply))
                 (member nil (field 'gr8s.hubble.observer::reply)))
             (or (null (field 'gr8s.hubble.observer::source-ip))
                 (hubble-address-matches-p (ip-of 'gr8s.hubble.observer::source)
                                           (field 'gr8s.hubble.observer::source-ip)))
             (or (null (field 'gr8s.hubble.observer::destination-ip))
                 (hubble-address-matches-p (ip-of 'gr8s.hubble.observer::destination)
                                           (field 'gr8s.hubble.observer::destination-ip)))
             (or (null (field 'gr8s.hubble.observer::source-pod))
                 (hubble-pod-matches-p (slot-value flow 'gr8s.hubble.observer::source)
                                       (field 'gr8s.hubble.observer::source-pod)))
             (or (null (field 'gr8s.hubble.observer::destination-pod))
                 (hubble-pod-matches-p (slot-value flow 'gr8s.hubble.observer::destination)
                                       (field 'gr8s.hubble.observer::destination-pod)))
             (or (null (field 'gr8s.hubble.observer::verdict))
                 (member (slot-value flow 'gr8s.hubble.observer::verdict) (field 'gr8s.hubble.observer::verdict)))
             (or (null (field 'gr8s.hubble.observer::traffic-direction))
                 (member (slot-value flow 'gr8s.hubble.observer::traffic-direction)
                         (field 'gr8s.hubble.observer::traffic-direction)))
             (or (null (field 'gr8s.hubble.observer::drop-reason-desc))
                 (member (slot-value flow 'gr8s.hubble.observer::drop-reason-desc)
                         (field 'gr8s.hubble.observer::drop-reason-desc)))
             (or (null (field 'gr8s.hubble.observer::ip-version))
                 (and ip (member (slot-value ip 'gr8s.hubble.observer::ipversion)
                                 (field 'gr8s.hubble.observer::ip-version))))
             (or (null (field 'gr8s.hubble.observer::protocol))
                 (and protocol (member protocol (field 'gr8s.hubble.observer::protocol) :test #'string-equal)))
             (or (null (field 'gr8s.hubble.observer::source-port))
                 (and source-port (member (princ-to-string source-port) (field 'gr8s.hubble.observer::source-port)
                                          :test #'equal)))
             (or (null (field 'gr8s.hubble.observer::destination-port))
                 (and destination-port (member (princ-to-string destination-port)
                                               (field 'gr8s.hubble.observer::destination-port) :test #'equal)))
             (or (null (field 'gr8s.hubble.observer::node-name))
                 (let ((node (slot-value flow 'gr8s.hubble.observer::node-name)))
                   (some (lambda (pattern)
                           (let ((name (subseq pattern (1+ (or (position #\/ pattern) -1)))))
                             (if (uiop:string-suffix-p name "*")
                                 (uiop:string-prefix-p (subseq name 0 (1- (length name))) node)
                                 (equal name node))))
                         (field 'gr8s.hubble.observer::node-name)))))))))

(defun hubble-request-selects-p (request flow)
  "Whether REQUEST's filters and time bounds let FLOW through."
  (let ((whitelist (slot-value request 'gr8s.hubble.observer::whitelist))
        (blacklist (slot-value request 'gr8s.hubble.observer::blacklist))
        (time (hubble-timestamp-seconds (slot-value flow 'gr8s.hubble.observer::proto-time)))
        (since (hubble-timestamp-seconds (slot-value request 'gr8s.hubble.observer::since)))
        (until (hubble-timestamp-seconds (slot-value request 'gr8s.hubble.observer::until))))
    (and (or (null whitelist) (some (lambda (filter) (hubble-filter-matches-p filter flow)) whitelist))
         (notany (lambda (filter) (hubble-filter-matches-p filter flow)) blacklist)
         (or (null since) (and time (>= time since)))
         (or (null until) (and time (<= time until))))))

;;; The Observer service

(defun hubble-flows-response (flow)
  (let ((response (make-instance 'gr8s.hubble.observer::get-flows-response
                                 :flow flow
                                 :node-name (slot-value flow 'gr8s.hubble.observer::node-name)
                                 :time (slot-value flow 'gr8s.hubble.observer::proto-time))))
    (setf (gr8s.hubble.observer::response-types-case response) :flow)
    response))

(defun hubble-api-flows (config namespace follow function &key on-open)
  "Call FUNCTION with (values flow line) for each flow event the API sends."
  (call-with-api-flows
   config namespace follow
   (lambda (line)
     (let ((object (ignore-errors (com.inuoe.jzon:parse line))))
       (when (and (hash-table-p object) (not (gethash "error" object)))
         (funcall function (hubble-flow object) line))))
   :on-open on-open))

(defun serve-hubble-get-flows (config namespace request send cancelled-p)
  "Answer GetFlows: the recent flows REQUEST selects, the last NUMBER of them (the first,
with FIRST; all, with neither a NUMBER nor FOLLOW), then with FOLLOW new ones until
CANCELLED-P. SEND takes each response."
  (dolist (filter (append (slot-value request 'gr8s.hubble.observer::whitelist)
                          (slot-value request 'gr8s.hubble.observer::blacklist)))
    (check-hubble-filter filter))
  (let* ((number (slot-value request 'gr8s.hubble.observer::proto-number))
         (first (slot-value request 'gr8s.hubble.observer::proto-first))
         (follow (slot-value request 'gr8s.hubble.observer::follow))
         (recent nil) (seen (make-hash-table :test #'equal)))
    (hubble-api-flows config namespace nil
                      (lambda (flow line)
                        (setf (gethash line seen) t)
                        (when (hubble-request-selects-p request flow) (push flow recent))))
    (setf recent (nreverse recent))
    (when (plusp number)
      (setf recent (if first
                       (subseq recent 0 (min number (length recent)))
                       (last recent number))))
    (dolist (flow recent) (funcall send (hubble-flows-response flow)))
    (when follow
      ;; A followed stream begins with the recent events again; skip the ones already read.
      (let ((closer nil) (done nil))
        (let ((watcher (bt:make-thread
                        (lambda ()
                          (loop until done
                                do (sleep 0.5)
                                   (when (and closer (funcall cancelled-p))
                                     (funcall closer)
                                     (return))))
                        :name "gr8s hubble follower")))
          (unwind-protect
               (hubble-api-flows config namespace t
                                 (lambda (flow line)
                                   (unless (gethash line seen)
                                     (when (hubble-request-selects-p request flow)
                                       (funcall send (hubble-flows-response flow)))))
                                 :on-open (lambda (function) (setf closer function)))
            (setf done t)
            (ignore-errors (bt:join-thread watcher))))))))

(defun hubble-cluster-nodes (config)
  "The cluster's Nodes as (name ready-p address) lists."
  (loop for node across (or (gethash "items" (debug-api-get-json config "/api/v1/nodes")) #())
        collect (list (gethash "name" (gethash "metadata" node))
                      (some (lambda (condition)
                              (and (equal "Ready" (gethash "type" condition))
                                   (equal "True" (gethash "status" condition))))
                            (coerce (gethash "conditions" (gethash "status" node) #()) 'list))
                      (let ((address (find "InternalIP" (gethash "addresses" (gethash "status" node) #())
                                           :key (lambda (entry) (gethash "type" entry)) :test #'equal)))
                        (if address (gethash "address" address) "")))))

(defun register-hubble-observer (server config namespace)
  "Register the Observer service on gRPC SERVER, reading the cluster with CONFIG."
  (let ((started (get-universal-time)))
  (gr8s.hubble.observer::register-observer-service
   server
   :get-flows-handler
   (lambda (request context stream)
     (handler-case
         (serve-hubble-get-flows
          ;; ag-gRPC starts a server-streaming handler before the request's DATA frame,
          ;; and queues the request on the stream instead (podster-bk9); a request
          ;; with every field at its default arrives as none at all.
          config namespace (or request (ag-grpc:stream-recv stream)
                               (make-instance 'gr8s.hubble.observer::get-flows-request))
          (lambda (response) (ag-grpc:stream-send stream response))
          (lambda () (handler-case (progn (ag-grpc::context-check-cancelled context) nil)
                       (error () t))))
       (hubble-unsupported-filter (condition)
         (error 'ag-grpc:grpc-status-error :code ag-grpc::+grpc-status-invalid-argument+
                                           :message (princ-to-string condition)))))
   :get-nodes-handler
   (lambda (request context)
     (declare (ignore request context))
     (make-instance 'gr8s.hubble.observer::get-nodes-response
                    :nodes (loop for (name ready address) in (hubble-cluster-nodes config)
                                 collect (make-instance 'gr8s.hubble.observer::node
                                                        :name name :version +gr8s-version+ :address address
                                                        :state (if ready gr8s.hubble.observer::+nodestate-node_connected+
                                                                   gr8s.hubble.observer::+nodestate-node_unavailable+)))))
   :server-status-handler
   (lambda (request context)
     (declare (ignore request context))
     (let ((nodes (hubble-cluster-nodes config)) (count 0))
       (hubble-api-flows config namespace nil (lambda (flow line) (declare (ignore flow line)) (incf count)))
       (make-instance 'gr8s.hubble.observer::server-status-response
                      :num-flows count :max-flows (* (max 1 (length nodes)) 4096) :seen-flows count
                      :uptime-ns (* (max 1 (- (get-universal-time) started)) 1000000000)
                      :num-connected-nodes (make-instance 'gr8s.hubble.observer::u-int32value
                                                          :value (count-if #'second nodes))
                      :num-unavailable-nodes (make-instance 'gr8s.hubble.observer::u-int32value
                                                            :value (count-if-not #'second nodes))
                      :unavailable-nodes (loop for (name ready) in nodes unless ready collect name)
                      :version (format nil "gr8s ~A" +gr8s-version+)))))))

(defun parse-hubble-listen (options)
  "Add the :host and :port of OPTIONS' :listen, HOST:PORT, for `gr8s doctor observe --serve'."
  (let* ((listen (getf options :listen +hubble-default-listen+))
         (colon (position #\: listen :from-end t)))
    (unless (and colon (parse-integer listen :start (1+ colon) :junk-allowed t))
      (error "--listen must be HOST:PORT"))
    (list* :host (subseq listen 0 colon) :port (parse-integer listen :start (1+ colon)) options)))

(defun run-hubble-serve (options)
  "Serve the Observer API until interrupted."
  (call-with-debug-kubeconfig
   (getf options :kubeconfig)
   (lambda (config)
     (let ((server (ag-grpc:make-grpc-server (getf options :port) :host (getf options :host))))
       (register-hubble-observer server config (getf options :namespace))
       ;; hubble status asks whether the Observer service is serving before ServerStatus.
       (ag-grpc:health-set-status (ag-grpc::server-enable-health-checking server)
                                  "hubble.server.Observer" ag-grpc::+health-serving+)
       (let ((thread (bt:make-thread (lambda () (ag-grpc:server-start server)) :name "gr8s hubble server")))
         (format t "Serving Hubble's Observer API at ~A for ~A.~%Point hubble at it: hubble observe --server ~A~%"
                 (getf options :listen) (getf config :server) (getf options :listen))
         (finish-output)
         (unwind-protect (bt:join-thread thread)
           (ignore-errors (ag-grpc:server-stop server)))))))
  0)
