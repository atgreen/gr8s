;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; `gr8s dashboard''s Hubble tab (podster-e9a.6): serve Hubble UI's embedded frontend on this
;;;; machine, as `gr8s dashboard' serves Headlamp, with its backend in gr8s itself.
;;;; The backend reads the cluster's flow events with the kubeconfig's credentials
;;;; and speaks the UI's own protocol: each POST to <base>/api/ROUTE carries one
;;;; customprotocol Message and gets one back, and a stream is a channel the client
;;;; polls. Two routes exist. control-stream sends the namespaces, then a status
;;;; every few seconds; service-map-stream sends the flows a GetEventsRequest
;;;; selects, with the services (cards) and links (arrows) they make, derived as
;;;; Hubble UI's Go backend derives them.

(in-package #:gr8s.server)

(defparameter +hubble-ui-poll-delay-ms+ 500
  "How long the client waits before polling a channel with nothing queued.")

(defparameter +hubble-ui-busy-poll-delay-ms+ 200
  "How long it waits when more is queued.")

(defparameter +hubble-ui-channel-idle-seconds+ 10
  "A channel unpolled this long is dropped, as Hubble UI's backend drops it.")

(defstruct (hubble-ui-channel (:constructor %make-hubble-ui-channel (id route)))
  "One stream a Hubble UI client polls: what its handler has queued, oldest first."
  id route
  (queue nil) (tail nil)
  (finished nil)                        ; the handler is done
  (stopping nil)                        ; the client closed it, or it went idle
  (closer nil)                          ; ends the handler's flow stream
  (seen (get-universal-time))
  (lock (bt:make-lock "gr8s hubble ui channel")))

(defun hubble-ui-enqueue (channel payload)
  "Queue PAYLOAD, a message's serialized bytes, for CHANNEL's next poll."
  (bt:with-lock-held ((hubble-ui-channel-lock channel))
    (let ((cell (list payload)))
      (if (hubble-ui-channel-tail channel)
          (setf (cdr (hubble-ui-channel-tail channel)) cell)
          (setf (hubble-ui-channel-queue channel) cell))
      (setf (hubble-ui-channel-tail channel) cell))))

(defun hubble-ui-dequeue (channel)
  "Return (values payload more-p): the oldest queued payload, or NIL, and whether more wait."
  (bt:with-lock-held ((hubble-ui-channel-lock channel))
    (let ((payload (pop (hubble-ui-channel-queue channel))))
      (unless (hubble-ui-channel-queue channel) (setf (hubble-ui-channel-tail channel) nil))
      (values payload (and (hubble-ui-channel-queue channel) t)))))

(defun stop-hubble-ui-channel (channel)
  (setf (hubble-ui-channel-stopping channel) t)
  (let ((closer (hubble-ui-channel-closer channel)))
    (when closer (funcall closer))))

;;; Services and links, as Hubble UI's backend derives them from flows
;;; (backend/domain/service/service.go and link/link.go in cilium/hubble-ui)

(defun hubble-ui-world-p (endpoint)
  (member "reserved:world" (slot-value endpoint 'gr8s.hubble.observer::labels) :test #'equal))

(defun hubble-ui-service-id (endpoint side)
  "One card per identity; the world has one card for each side."
  (let ((identity (slot-value endpoint 'gr8s.hubble.observer::identity)))
    (if (and (plusp identity) (not (hubble-ui-world-p endpoint)))
        (princ-to-string identity)
        (format nil "world-~(~A~)" side))))

(defun hubble-ui-service-name (endpoint id)
  "The app label Hubble UI names a card by, or ID."
  (or (loop for label in (slot-value endpoint 'gr8s.hubble.observer::labels)
            for plain = (cl-ppcre:regex-replace-all "k8s:|io\\.kubernetes\\.pod\\.|app\\.kubernetes\\.io/" label "")
            for equal-at = (position #\= plain)
            when (and equal-at (member (subseq plain 0 equal-at) '("app" "name" "functionName" "k8s-app")
                                       :test #'equal))
              return (subseq plain (1+ equal-at)))
      ;; A Service endpoint has no labels to name it, only its workload.
      (let ((workload (first (slot-value endpoint 'gr8s.hubble.observer::workloads))))
        (and workload (slot-value workload 'gr8s.hubble.observer::name)))
      id))

(defun hubble-ui-service (endpoint id)
  (make-instance 'gr8s.hubble.observer::service
                 :id id :name (hubble-ui-service-name endpoint id)
                 :namespace (slot-value endpoint 'gr8s.hubble.observer::namespace)
                 :labels (slot-value endpoint 'gr8s.hubble.observer::labels)
                 ;; Hubble UI titles a card with no app label by its workload.
                 :workloads (slot-value endpoint 'gr8s.hubble.observer::workloads)
                 :identity (slot-value endpoint 'gr8s.hubble.observer::identity)
                 :creation-timestamp (hubble-now)))

(defun hubble-now ()
  (multiple-value-bind (seconds microseconds) (sb-ext:get-time-of-day)
    (make-instance 'gr8s.hubble.observer::timestamp :seconds seconds :nanos (* microseconds 1000))))

(defun hubble-ui-link-parts (flow)
  "(values protocol port), the IPProtocol and destination port a link of FLOW is keyed by."
  (multiple-value-bind (protocol source-port destination-port) (hubble-flow-ports flow)
    (declare (ignore source-port))
    (cond ((equal protocol "tcp") (values gr8s.hubble.observer::+ipprotocol-tcp+ destination-port))
          ((equal protocol "udp") (values gr8s.hubble.observer::+ipprotocol-udp+ destination-port))
          ((equal protocol "icmpv4") (values gr8s.hubble.observer::+ipprotocol-icmp_v4+ 0))
          ((equal protocol "icmpv6") (values gr8s.hubble.observer::+ipprotocol-icmp_v6+ 0))
          (t (values gr8s.hubble.observer::+ipprotocol-unknown_ip_protocol+ (or destination-port 0))))))

(defun hubble-ui-protocol-name (protocol)
  (cond ((= protocol gr8s.hubble.observer::+ipprotocol-tcp+) "TCP")
        ((= protocol gr8s.hubble.observer::+ipprotocol-udp+) "UDP")
        ((= protocol gr8s.hubble.observer::+ipprotocol-icmp_v4+) "ICMP_V4")
        ((= protocol gr8s.hubble.observer::+ipprotocol-icmp_v6+) "ICMP_V6")
        (t "UNKNOWN_IP_PROTOCOL")))

(defstruct (hubble-ui-map (:constructor make-hubble-ui-map ()))
  "What one service-map stream has sent: services by id, and links by id to their verdict."
  (services (make-hash-table :test #'equal))
  (links (make-hash-table :test #'equal)))

(defun hubble-ui-event (initarg value case)
  ;; A oneof is written only for the variant its case slot names.
  (let ((event (make-instance 'gr8s.hubble.observer::event initarg value)))
    (setf (gr8s.hubble.observer::event-case event) case)
    event))

(defun hubble-ui-map-changes (map flow)
  "The ServiceState and ServiceLinkState events FLOW brings to MAP: a service or link the
first time it's seen, and a link again when its verdict changes."
  (let ((events nil)
        (source (slot-value flow 'gr8s.hubble.observer::source))
        (destination (slot-value flow 'gr8s.hubble.observer::destination)))
    (when (and source destination)
      (let ((source-id (hubble-ui-service-id source :sender))
            (destination-id (hubble-ui-service-id destination :receiver)))
        (loop for (endpoint id) in (list (list source source-id) (list destination destination-id))
              unless (gethash id (hubble-ui-map-services map))
                do (setf (gethash id (hubble-ui-map-services map)) t)
                   (push (hubble-ui-event
                          :service-state
                          (make-instance 'gr8s.hubble.observer::service-state
                                         :service (hubble-ui-service endpoint id)
                                         :type gr8s.hubble.observer::+statechange-added+)
                          :service-state)
                         events))
        (when (slot-value flow 'gr8s.hubble.observer::l4)
          (multiple-value-bind (protocol port) (hubble-ui-link-parts flow)
            (let* ((id (format nil "~A ~A ~A:~D" source-id (hubble-ui-protocol-name protocol) destination-id port))
                   (verdict (slot-value flow 'gr8s.hubble.observer::verdict))
                   (before (gethash id (hubble-ui-map-links map))))
              (unless (eql before verdict)
                (setf (gethash id (hubble-ui-map-links map)) verdict)
                (push (hubble-ui-event
                       :service-link-state
                       (make-instance 'gr8s.hubble.observer::service-link-state
                                      :service-link (make-instance 'gr8s.hubble.observer::service-link
                                                                   :id id :source-id source-id
                                                                   :destination-id destination-id
                                                                   :destination-port port :ip-protocol protocol
                                                                   :verdict verdict)
                                      :type (if before gr8s.hubble.observer::+statechange-modified+
                                                gr8s.hubble.observer::+statechange-added+))
                       :service-link-state)
                      events)))))))
    (nreverse events)))

(defun hubble-ui-events-response (map flows)
  "One GetEventsResponse for a batch of FLOWS: the flows, then what they change in MAP."
  (make-instance 'gr8s.hubble.observer::get-events-response
                 :timestamp (hubble-now)
                 :events (cons (hubble-ui-event :flows (make-instance 'gr8s.hubble.observer::flows :flows flows)
                                                :flows)
                               (loop for flow in flows append (hubble-ui-map-changes map flow)))))

;;; The two routes

(defun hubble-ui-flow-filters (event-filters)
  (loop for filter in event-filters
        for flow-filter = (slot-value filter 'gr8s.hubble.observer::flow-filter)
        when flow-filter collect flow-filter))

(defun run-hubble-ui-service-map (channel config body)
  "Answer a service-map-stream: the flows BODY's GetEventsRequest selects, in batches,
until the channel stops."
  (let* ((request (and body (plusp (length body))
                       (ag-proto:deserialize-from-bytes 'gr8s.hubble.observer::get-events-request body)))
         (selection (make-instance 'gr8s.hubble.observer::get-flows-request
                                   :whitelist (and request (hubble-ui-flow-filters
                                                            (slot-value request 'gr8s.hubble.observer::whitelist)))
                                   :blacklist (and request (hubble-ui-flow-filters
                                                            (slot-value request 'gr8s.hubble.observer::blacklist)))))
         (map (make-hubble-ui-map))
         (batch nil) (lock (bt:make-lock "gr8s hubble ui batch")))
    (dolist (filter (append (slot-value selection 'gr8s.hubble.observer::whitelist)
                            (slot-value selection 'gr8s.hubble.observer::blacklist)))
      (check-hubble-filter filter))
    (flet ((flush ()
             (let ((flows (bt:with-lock-held (lock) (prog1 (nreverse batch) (setf batch nil)))))
               (when flows
                 (hubble-ui-enqueue channel (ag-proto:serialize-to-bytes (hubble-ui-events-response map flows)))))))
      ;; Batches go out every 50ms, as Hubble UI's backend sends them, or at 500 flows.
      (let ((flusher (bt:make-thread
                      (lambda ()
                        (loop until (or (hubble-ui-channel-stopping channel) (hubble-ui-channel-finished channel))
                              do (sleep 0.05) (flush)))
                      :name "gr8s hubble ui batches")))
        (unwind-protect
             (unless (hubble-ui-channel-stopping channel)
               (hubble-api-flows config nil t
                                 (lambda (flow line)
                                   (declare (ignore line))
                                   (when (hubble-request-selects-p selection flow)
                                     (when (>= (bt:with-lock-held (lock) (length (push flow batch))) 500)
                                       (flush))))
                                 :on-open (lambda (closer)
                                            (setf (hubble-ui-channel-closer channel) closer)
                                            (when (hubble-ui-channel-stopping channel) (funcall closer)))))
          (flush)
          (setf (hubble-ui-channel-finished channel) t)
          (ignore-errors (bt:join-thread flusher)))))))

(defun hubble-ui-namespaces-response (config)
  "The cluster's namespaces, ADDED, as control-stream first sends them. Hubble UI lists
only a namespace with an id."
  (let ((response
          (make-instance
           'gr8s.hubble.observer::get-control-stream-response
           :namespaces
           (make-instance
            'gr8s.hubble.observer::namespace-states
            :namespaces
            (loop for namespace across (or (gethash "items" (debug-api-get-json config "/api/v1/namespaces")) #())
                  for metadata = (gethash "metadata" namespace)
                  collect (make-instance 'gr8s.hubble.observer::namespace-state
                                         :namespace (make-instance
                                                     'gr8s.hubble.observer::namespace-descriptor
                                                     :id (gethash "uid" metadata "") :name (gethash "name" metadata "")
                                                     :creation-timestamp (hubble-timestamp
                                                                          (gethash "creationTimestamp" metadata "")))
                                         :type gr8s.hubble.observer::+statechange-added+))))))
    (setf (gr8s.hubble.observer::event-case response) :namespaces)
    response))

(defun hubble-ui-status-response (config started)
  "A status notification: the nodes, and the flows seen since STARTED."
  (let* ((nodes (hubble-cluster-nodes config))
         (count 0)
         (uptime (max 1 (- (get-universal-time) started))))
    (hubble-api-flows config nil nil (lambda (flow line) (declare (ignore flow line)) (incf count)))
    (let ((notification
            (make-instance
             'gr8s.hubble.observer::notification
             :status (make-instance
                      'gr8s.hubble.observer::get-status-response
                      :nodes (make-instance 'gr8s.hubble.observer::get-nodes-response
                                            :nodes (loop for (name ready address) in nodes
                                                         collect (make-instance
                                                                  'gr8s.hubble.observer::node
                                                                  :name name :version +gr8s-version+ :address address
                                                                  :state (if ready gr8s.hubble.observer::+nodestate-node_connected+
                                                                             gr8s.hubble.observer::+nodestate-node_unavailable+))))
                      :server-status (make-instance
                                      'gr8s.hubble.observer::server-status-response
                                      :num-flows count :max-flows (* (max 1 (length nodes)) 4096) :seen-flows count
                                      :uptime-ns (* uptime 1000000000)
                                      :num-connected-nodes (make-instance 'gr8s.hubble.observer::u-int32value
                                                                          :value (count-if #'second nodes))
                                      :num-unavailable-nodes (make-instance 'gr8s.hubble.observer::u-int32value
                                                                            :value (count-if-not #'second nodes))
                                      :version (format nil "gr8s ~A" +gr8s-version+))
                      :flows (make-instance 'gr8s.hubble.observer::flow-stats
                                            :per-second (coerce (/ count uptime) 'single-float)))))
          (response (make-instance 'gr8s.hubble.observer::get-control-stream-response)))
      (setf (gr8s.hubble.observer::notification-case notification) :status
            (slot-value response 'gr8s.hubble.observer::notification) notification
            (gr8s.hubble.observer::event-case response) :notification)
      response)))

(defun run-hubble-ui-control (channel config)
  "Answer a control-stream: the namespaces, then a status every 5 seconds."
  (let ((started (get-universal-time)))
    (unwind-protect
         (progn
           (hubble-ui-enqueue channel (ag-proto:serialize-to-bytes (hubble-ui-namespaces-response config)))
           (loop until (hubble-ui-channel-stopping channel)
                 do (hubble-ui-enqueue channel (ag-proto:serialize-to-bytes
                                                (hubble-ui-status-response config started)))
                    (loop repeat 50 until (hubble-ui-channel-stopping channel) do (sleep 0.1))))
      (setf (hubble-ui-channel-finished channel) t))))

;;; The polling protocol (backend/internal/customprotocol in cilium/hubble-ui)

(defstruct (hubble-ui-backend (:constructor make-hubble-ui-backend (config)))
  config
  (channels (make-hash-table :test #'equal))
  (lock (bt:make-lock "gr8s hubble ui channels")))

(defun new-hubble-ui-channel-id ()
  "A new channel id: 8 random bytes in hex, as Hubble UI's backend makes them."
  (format nil "~(~{~2,'0X~}~)" (coerce (secure-random-octets 8) 'list)))

(defun start-hubble-ui-channel (backend route body &optional id)
  "Open a channel for ROUTE and start its handler, or return NIL for a route that isn't one."
  (let ((channel (%make-hubble-ui-channel (if (plusp (length id)) id (new-hubble-ui-channel-id)) route))
        (config (hubble-ui-backend-config backend)))
    (flet ((run (function)
             (bt:make-thread
              (lambda ()
                (handler-case (funcall function)
                  (error (condition)
                    ;; Most are a browser leaving the page; only --verbose wants them.
                    (when *dashboard-verbose*
                      (format *error-output* "gr8s hubble ui: ~A stream: ~A~%" route condition))))
                (setf (hubble-ui-channel-finished channel) t))
              :name (format nil "gr8s hubble ui ~A" route))))
      (cond ((equal route "control-stream") (run (lambda () (run-hubble-ui-control channel config))))
            ((equal route "service-map-stream")
             (run (lambda () (run-hubble-ui-service-map channel config body))))
            (t (return-from start-hubble-ui-channel nil))))
    (bt:with-lock-held ((hubble-ui-backend-lock backend))
      (setf (gethash (hubble-ui-channel-id channel) (hubble-ui-backend-channels backend)) channel))))

(defun expire-hubble-ui-channels (backend)
  "Drop the channels no client has polled for a while."
  (let ((expired (bt:with-lock-held ((hubble-ui-backend-lock backend))
                   (loop for channel being the hash-values of (hubble-ui-backend-channels backend)
                         when (> (- (get-universal-time) (hubble-ui-channel-seen channel))
                                 +hubble-ui-channel-idle-seconds+)
                           collect channel
                           and do (remhash (hubble-ui-channel-id channel) (hubble-ui-backend-channels backend))))))
    (mapc #'stop-hubble-ui-channel expired)))

(defun hubble-ui-reply (request channel &key payload more terminated)
  "The Message answering REQUEST on CHANNEL."
  (let ((meta (slot-value request 'gr8s.hubble.observer::meta)))
    (make-instance
     'gr8s.hubble.observer::message
     :meta (make-instance 'gr8s.hubble.observer::meta
                          :trace-id (if meta (slot-value meta 'gr8s.hubble.observer::trace-id) "")
                          :channel-id (hubble-ui-channel-id channel)
                          :route-name (hubble-ui-channel-route channel)
                          :is-not-ready (null payload) :is-empty (not more) :is-terminated terminated
                          ;; Never 0: the client then polls again at once.
                          :poll-delay-ms (if more +hubble-ui-busy-poll-delay-ms+ +hubble-ui-poll-delay-ms+))
     :body (make-instance 'gr8s.hubble.observer::body
                          :content (or payload (make-array 0 :element-type '(unsigned-byte 8)))))))

(defun answer-hubble-ui-request (backend route octets)
  "Answer one POST of OCTETS, a serialized Message, to ROUTE, returning the reply's bytes,
or NIL for a route that isn't one."
  (let* ((request (if (plusp (length octets))
                      (ag-proto:deserialize-from-bytes 'gr8s.hubble.observer::message octets)
                      (make-instance 'gr8s.hubble.observer::message)))
         (meta (or (slot-value request 'gr8s.hubble.observer::meta)
                   (make-instance 'gr8s.hubble.observer::meta)))
         (id (slot-value meta 'gr8s.hubble.observer::channel-id))
         (body (let ((body (slot-value request 'gr8s.hubble.observer::body)))
                 (and body (slot-value body 'gr8s.hubble.observer::content))))
         (channel (or (bt:with-lock-held ((hubble-ui-backend-lock backend))
                        (gethash id (hubble-ui-backend-channels backend)))
                      ;; A new stream, or one that expired: start it again.
                      (start-hubble-ui-channel backend route body id))))
    (when channel
      (setf (hubble-ui-channel-seen channel) (get-universal-time))
      (ag-proto:serialize-to-bytes
       (if (slot-value meta 'gr8s.hubble.observer::is-terminated)
           (progn
             (bt:with-lock-held ((hubble-ui-backend-lock backend))
               (remhash (hubble-ui-channel-id channel) (hubble-ui-backend-channels backend)))
             (stop-hubble-ui-channel channel)
             (hubble-ui-reply request channel :terminated t))
           (multiple-value-bind (payload more) (hubble-ui-dequeue channel)
             (unless payload
               ;; A newly opened stream usually has something within a moment.
               (loop repeat 2 until payload
                     do (sleep 0.005) (multiple-value-setq (payload more) (hubble-ui-dequeue channel))))
             (hubble-ui-reply request channel :payload payload :more more
                                              :terminated (and (hubble-ui-channel-finished channel)
                                                               (not more)))))))))

;;; The command

(defclass hubble-ui-acceptor (hunchentoot:acceptor)
  ((backend :initarg :backend :reader hubble-ui-acceptor-backend)
   (base :initarg :base :reader hubble-ui-acceptor-base))
  (:default-initargs :access-log-destination nil :message-log-destination nil))

(defmethod hunchentoot:acceptor-dispatch-request ((acceptor hubble-ui-acceptor) request)
  (hubble-ui-dispatch (hubble-ui-acceptor-backend acceptor) (hubble-ui-acceptor-base acceptor) request))

(defun hubble-ui-dispatch (backend base request)
  "Answer REQUEST for Hubble UI served under BASE: its app, and its backend's API from BACKEND."
  (let ((path (hunchentoot:script-name request)))
    (cond
      ((not (uiop:string-prefix-p base path))
       (setf (hunchentoot:return-code*) hunchentoot:+http-not-found+ (hunchentoot:content-type*) "text/plain")
       "Not found")
      ((and (eq (hunchentoot:request-method request) :post)
            (uiop:string-prefix-p (concatenate 'string base "api/") path))
       (let ((reply (answer-hubble-ui-request
                     backend
                     (subseq path (length (concatenate 'string base "api/")))
                     (or (hunchentoot:raw-post-data :request request :force-binary t)
                         (make-array 0 :element-type '(unsigned-byte 8))))))
         (setf (hunchentoot:content-type*) "application/octet-stream"
               (hunchentoot:header-out :x-content-type-options) "nosniff")
         (or reply
             (progn (setf (hunchentoot:return-code*) hunchentoot:+http-not-found+)
                    (make-array 0 :element-type '(unsigned-byte 8))))))
      (t (gr8s.apiserver::hubble-ui-asset-response (subseq path (length base)) base)))))
