(in-package #:gr8s/tests)

(in-suite gr8s)

(defparameter *valid-cni-config*
  "{\"cniVersion\":\"1.0.0\",\"name\":\"gr8s\",\"type\":\"gr8s\",\"socket\":\"/run/gr8s/agent-cni.sock\",\"direction\":\"egress\",\"program\":\"/runtime/gr8s-whistler.bpf.o\",\"mapPinRoot\":\"/run/gr8s/bpf\",\"prevResult\":{\"cniVersion\":\"1.0.0\",\"interfaces\":[]}}")

(test agent-cni-unix-socket-roundtrips-a-typed-request
  (let* ((directory
           (merge-pathnames
            (format nil "gr8s-agent-cni-~36R/" (random (expt 36 8)))
            (uiop:temporary-directory)))
         (socket-path (namestring (merge-pathnames "agent.sock" directory)))
         (seen nil)
         (peer-credentials nil)
         (server nil))
    (unwind-protect
         (progn
           (setf server
                 (gr8s::start-agent-cni-server
                  socket-path
                  (lambda (request)
                    (setf seen request)
                    (make-instance
                     'gr8s.node.v1::cni-response
                     :protocol-version gr8s::+node-protocol-version+
                     :success t
                     :result-json
                     (trivial-utf-8:string-to-utf-8-bytes
                      "{\"cniVersion\":\"1.1.0\",\"marker\":\"agent\"}")))
                  :peer-authorizer
                  (lambda (pid uid gid)
                    (setf peer-credentials (list pid uid gid))
                    t)))
           (is (= #o600
                  (logand #o777
                          (sb-posix:stat-mode (sb-posix:stat socket-path)))))
           (let ((response
                   (gr8s::call-agent-cni
                    socket-path
                    (make-instance
                     'gr8s.node.v1::cni-request
                     :protocol-version gr8s::+node-protocol-version+
                     :command "ADD"
                     :network-configuration
                     (trivial-utf-8:string-to-utf-8-bytes
                      *valid-cni-config*)
                     :container-id "sandbox-typed"
                     :network-namespace "/proc/42/ns/net"
                     :interface-name "eth0"
                     :arguments "K8S_POD_NAMESPACE=default"
                     :plugin-path "/opt/cni/bin")
                    :timeout 1)))
             (is-true (slot-value response 'gr8s.node.v1::success))
             (is (string= "ADD"
                          (slot-value seen 'gr8s.node.v1::command)))
             (is (string= "sandbox-typed"
                          (slot-value seen 'gr8s.node.v1::container-id)))
             (is (plusp (first peer-credentials)))
             (is (= (sb-posix:geteuid) (second peer-credentials)))
             (is (= (sb-posix:getegid) (third peer-credentials)))
             (is (string= "/proc/42/ns/net"
                          (slot-value seen
                                      'gr8s.node.v1::network-namespace)))
             (let ((result
                     (com.inuoe.jzon:parse
                      (trivial-utf-8:utf-8-bytes-to-string
                       (slot-value response 'gr8s.node.v1::result-json)))))
               (is (string= "agent" (gethash "marker" result)))))
      (when server (gr8s::stop-agent-cni-server server))
      (when (probe-file directory)
        (uiop:delete-directory-tree directory :validate t))))))

(defun agent-cni-request-for-test (command &optional (configuration *valid-cni-config*))
  (make-instance
   'gr8s.node.v1::cni-request
   :protocol-version gr8s::+node-protocol-version+
   :command command
   :network-configuration
   (trivial-utf-8:string-to-utf-8-bytes configuration)
   :container-id "sandbox-agent"
   :network-namespace "/proc/42/ns/net"
   :interface-name "eth0"
   :arguments "K8S_POD_NAME=example"
   :plugin-path "/opt/cni/bin"))

(test agent-cni-handler-owns-command-execution-and-error-mapping
  (let* ((calls nil)
        (operations
          (gr8s::make-cni-operations
           :add (lambda (&rest arguments)
                  (declare (ignore arguments))
                  (push :add calls))
           :check (lambda (&rest arguments)
                    (declare (ignore arguments))
                    (push :check calls))
           :delete (lambda (&rest arguments)
                     (declare (ignore arguments))
                     (push :delete calls)))))
    (dolist (command '("ADD" "CHECK" "DEL"))
      (let ((response
              (gr8s::handle-agent-cni-request
               (agent-cni-request-for-test command)
               :operations operations)))
        (is-true (slot-value response 'gr8s.node.v1::success))
        (is (zerop (slot-value response 'gr8s.node.v1::error-code)))
        (if (string= command "ADD")
            (let ((result
                    (com.inuoe.jzon:parse
                     (trivial-utf-8:utf-8-bytes-to-string
                      (slot-value response 'gr8s.node.v1::result-json)))))
              (is (string= "1.0.0" (gethash "cniVersion" result))))
            (is (zerop (length
                        (slot-value response 'gr8s.node.v1::result-json)))))))
    (is (equal '(:delete :check :add) calls))
    (let ((response
            (gr8s::handle-agent-cni-request
             (agent-cni-request-for-test "ADD" "not-json")
             :operations operations)))
      (is-false (slot-value response 'gr8s.node.v1::success))
      (is (= 100 (slot-value response 'gr8s.node.v1::error-code)))
      (is (search "invalid network configuration"
                  (slot-value response 'gr8s.node.v1::error-message))))))

(test agent-cni-client-bounds-unavailable-and-stalled-agents
  (let* ((directory
           (merge-pathnames
            (format nil "gr8s-agent-cni-timeout-~36R/"
                    (random (expt 36 8)))
            (uiop:temporary-directory)))
         (socket-path (namestring (merge-pathnames "agent.sock" directory)))
         (missing-path (namestring (merge-pathnames "missing.sock" directory)))
         (server nil))
    (unwind-protect
         (progn
           (signals gr8s::cni-error
             (gr8s::call-agent-cni
              missing-path (agent-cni-request-for-test "DEL") :timeout 0.05))
           (setf server
                 (gr8s::start-agent-cni-server
                  socket-path
                  (lambda (request)
                    (declare (ignore request))
                    (sleep 0.2)
                    (make-instance
                     'gr8s.node.v1::cni-response
                     :protocol-version gr8s::+node-protocol-version+
                     :success t))))
           (signals gr8s::cni-error
             (gr8s::call-agent-cni
              socket-path (agent-cni-request-for-test "DEL") :timeout 0.02)))
      (when server (gr8s::stop-agent-cni-server server))
      (when (probe-file directory)
        (uiop:delete-directory-tree directory :validate t)))))

(test agent-cni-server-rejects-an-unauthorized-peer
  (let* ((directory
           (merge-pathnames
            (format nil "gr8s-agent-cni-auth-~36R/"
                    (random (expt 36 8)))
            (uiop:temporary-directory)))
         (socket-path (namestring (merge-pathnames "agent.sock" directory)))
         (handler-called nil)
         (server nil))
    (unwind-protect
         (progn
           (setf server
                 (gr8s::start-agent-cni-server
                  socket-path
                  (lambda (request)
                    (declare (ignore request))
                    (setf handler-called t)
                    (make-instance
                     'gr8s.node.v1::cni-response
                     :protocol-version gr8s::+node-protocol-version+
                     :success t))
                  :peer-authorizer
                  (lambda (pid uid gid)
                    (declare (ignore pid uid gid))
                    nil)))
           (let ((response
                   (gr8s::call-agent-cni
                    socket-path (agent-cni-request-for-test "DEL")
                    :timeout 1)))
             (is-false (slot-value response 'gr8s.node.v1::success))
             (is (search "not authorized"
                         (slot-value response
                                     'gr8s.node.v1::error-message))))
           (is-false handler-called))
      (when server (gr8s::stop-agent-cni-server server))
      (when (probe-file directory)
        (uiop:delete-directory-tree directory :validate t)))))

(test cni-configuration-requires-absolute-paths-and-a-previous-result
  (let ((configuration (gr8s::parse-cni-configuration *valid-cni-config*
                                                       :require-previous t)))
    (is (string= "egress" (gr8s::cni-configuration-direction configuration)))
    (is (string= "gr8s" (gr8s::cni-configuration-type configuration))))
  ;; The egress guard is JIT-compiled in-process, so a config with no "program"
  ;; ELF path parses fine.
  (is (gr8s::parse-cni-configuration
       "{\"cniVersion\":\"1.0.0\",\"mapPinRoot\":\"/run/bpf\",\"prevResult\":{}}"
       :require-previous t))
  ;; mapPinRoot must still be an absolute path.
  (signals error
    (gr8s::parse-cni-configuration
     "{\"cniVersion\":\"1.0.0\",\"mapPinRoot\":\"relative-bpf\",\"prevResult\":{}}"
     :require-previous t))
  ;; A previous result is still required when chained.
  (signals error
    (gr8s::parse-cni-configuration
     "{\"cniVersion\":\"1.0.0\",\"mapPinRoot\":\"/run/bpf\"}"
     :require-previous t)))

(test cni-pin-paths-are-confined-to-the-sandbox-directory
  (multiple-value-bind (map-path link-path directory)
      (gr8s::cni-pin-paths "/run/gr8s/bpf" "pod_0123.example-4")
    (is (string= "/run/gr8s/bpf/pod_0123.example-4/rejected_spoofs" map-path))
    (is (string= "/run/gr8s/bpf/pod_0123.example-4/tcx-egress" link-path))
    (is (string= "/run/gr8s/bpf/pod_0123.example-4/" directory)))
  (dolist (unsafe '("" "." ".." "pod/name" "pod name"))
    (signals error (gr8s::cni-pin-paths "/run/gr8s/bpf" unsafe))))

(test cni-interface-index-uses-the-current-network-namespace
  (let ((resolved nil))
    (is (= 42
           (gr8s::cni-interface-index
            "eth0" :resolver (lambda (name)
                                (setf resolved name)
                                42))))
    (is (string= "eth0" resolved)))
  (signals error
    (gr8s::cni-interface-index "eth0" :resolver (lambda (name)
                                                  (declare (ignore name))
                                                  0))))

(test cni-add-runs-the-policy-operation-and-returns-the-chained-result
  (let* ((call nil)
        (operations
          (gr8s::make-cni-operations
           :add (lambda (configuration context map-path link-path)
                  (setf call (list configuration context map-path link-path))))))
    (let* ((context (gr8s::make-cni-context
                     :container-id "sandbox-1" :netns "/proc/42/ns/net"
                     :interface-name "eth0"))
           (result (gr8s::dispatch-cni-command
                    "ADD" *valid-cni-config* context operations)))
      (is (hash-table-p result))
      (is (string= "1.0.0" (gethash "cniVersion" result)))
      (is (eq context (second call)))
      (is (search "sandbox-1/rejected_spoofs" (third call)))
      (is (search "sandbox-1/tcx-egress" (fourth call))))))

(test cni-delete-does-not-require-a-network-namespace
  (let* ((removed nil)
        (operations
          (gr8s::make-cni-operations
           :delete (lambda (configuration context map-path link-path directory)
                     (declare (ignore configuration context))
                     (setf removed (list map-path link-path directory))))))
    (gr8s::dispatch-cni-command
     "DEL" *valid-cni-config*
     (gr8s::make-cni-context :container-id "sandbox-1") operations)
    (is (search "sandbox-1/rejected_spoofs" (first removed)))
    (is (search "sandbox-1/tcx-egress" (second removed)))
    (is (search "sandbox-1/" (third removed)))))

(test cni-version-advertises-the-supported-specifications
  (let ((result (gr8s::dispatch-cni-command
                 "VERSION" "" (gr8s::make-cni-context)
                 (gr8s::make-cni-operations))))
    (is (string= "1.1.0" (gethash "cniVersion" result)))
    (is (equalp #( "0.4.0" "1.0.0" "1.1.0")
                (gethash "supportedVersions" result)))))

(defun policy-map-fixture (name)
  (whistler/loader::make-map-info
   :name name :fd (+ 41 (position name '("rejected_spoofs" "endpoint_identity" "traffic_stats")
                                 :test #'string=))))

(test cni-policy-install-reuses-counters-and-atomically-replaces-the-link
  (let ((calls nil)
        (configuration (gr8s::parse-cni-configuration *valid-cni-config* :require-previous t))
        (context (gr8s::make-cni-context :container-id "sandbox-1"
                                        :netns "/proc/42/ns/net" :interface-name "eth0")))
    (setf (gr8s::cni-configuration-endpoint-address configuration) "10.88.1.2")
    (gr8s::install-cni-policy
     configuration context "/pins/rejected_spoofs" "/pins/tcx-egress"
     :ensure-directory (lambda (path) (push (list :mkdir path) calls))
     :path-exists-p (lambda (path)
                      (member path '("/pins/rejected_spoofs" "/pins/traffic_stats" "/pins/tcx-egress")
                              :test #'string=))
     :open-pinned (lambda (path)
                    (whistler/loader:map-info-fd
                     (policy-map-fixture (file-namestring path))))
     :validate-map (lambda (fd name) (push (list :validate fd name) calls) (policy-map-fixture name))
     :remove-path (lambda (path) (push (list :remove path) calls))
     :open-object (lambda (path) (declare (ignore path)) :object)
     :load-object (lambda (object replacements)
                    (push (list :load object (sort (copy-list replacements) #'string< :key #'car)) calls))
     :object-map (lambda (object name) (declare (ignore object)) (policy-map-fixture name))
     :object-program (lambda (object name) (declare (ignore object name)) :program)
     :program-fd (lambda (program) (declare (ignore program)) 71)
     :initialize-identity (lambda (map config ctx)
                            (declare (ignore ctx))
                            (push (list :identity (whistler/loader:map-info-fd map)
                                        (gr8s::cni-configuration-endpoint-address config)) calls))
     :pin-object (lambda (fd path) (push (list :pin fd path) calls))
     :rename-pin (lambda (from to) (push (list :rename from to) calls))
     :staged-links (constantly nil)
     :call-in-netns (lambda (path operation) (declare (ignore path)) (funcall operation))
     :interface-index (lambda (name) (declare (ignore name)) 9)
     :attach-tcx (lambda (fd index direction) (push (list :attach fd index direction) calls) 81)
     :close-fd (lambda (fd) (push (list :close fd) calls))
     :close-object (lambda (object) (declare (ignore object)) (push '(:close-object) calls)))
    (is (member '(:load :object (("rejected_spoofs" . 41) ("traffic_stats" . 43))) calls :test #'equal))
    (is (member '(:identity 42 "10.88.1.2") calls :test #'equal))
    (is (member '(:pin 42 "/pins/endpoint_identity") calls :test #'equal))
    (is-false (member '(:remove "/pins/tcx-egress") calls :test #'equal))
    (let* ((events (reverse calls))
           (attach (position :attach events :key #'first))
           (pin (position 81 events :key #'second))
           (rename (position :rename events :key #'first)))
      (is (< attach pin rename))
      (is (string= "/pins/tcx-egress" (third (nth rename events)))))))

(test failed-cni-link-pinning-leaves-the-old-policy-and-counters-in-place
  (let ((removed nil) (renamed nil)
        (configuration (gr8s::parse-cni-configuration *valid-cni-config*)))
    (signals error
      (gr8s::install-cni-policy
       configuration (gr8s::make-cni-context :netns "/fake/netns" :interface-name "eth0")
       "/pins/rejected_spoofs" "/pins/tcx-egress"
       :ensure-directory (constantly nil) :path-exists-p (constantly t)
       :open-pinned (lambda (path) (whistler/loader:map-info-fd (policy-map-fixture (file-namestring path))))
       :validate-map (lambda (fd name) (declare (ignore fd)) (policy-map-fixture name))
       :open-object (constantly :object) :load-object (constantly nil)
       :object-map (lambda (object name) (declare (ignore object)) (policy-map-fixture name))
       :object-program (constantly :program) :program-fd (constantly 71)
       :initialize-identity (constantly nil)
       :pin-object (lambda (fd path) (declare (ignore fd path)) (error "injected pin failure"))
       :rename-pin (lambda (&rest args) (declare (ignore args)) (setf renamed t))
       :remove-path (lambda (path) (push path removed))
       :call-in-netns (lambda (path function) (declare (ignore path)) (funcall function))
       :interface-index (constantly 9) :attach-tcx (constantly 81)
       :close-fd (constantly nil) :close-object (constantly nil)))
    (is-false renamed)
    (is-false (member "/pins/tcx-egress" removed :test #'string=))
    (is-false (member "/pins/rejected_spoofs" removed :test #'string=))
    (is-false (member "/pins/traffic_stats" removed :test #'string=))))

(test pinned-map-schemas-and-tcx-targets-are-validated-before-use
  (dolist (spec gr8s::+cni-policy-map-specs+)
    (let ((info (make-array 256 :element-type '(unsigned-byte 8) :initial-element 0)))
      (flet ((put (offset value) (replace info (gr8s::netlink-integer value 4) :start1 offset)))
        (put 0 2) (put 8 4) (put 12 (second spec)) (put 16 (third spec)) (put 20 (fourth spec))
        (is (= 42 (whistler/loader:map-info-fd
                   (gr8s::cni-policy-map-info 42 (first spec) :object-info (lambda (fd) (declare (ignore fd)) info)))))
        (put 12 (+ 8 (second spec)))
        (signals gr8s::cni-error
          (gr8s::cni-policy-map-info 42 (first spec) :object-info (lambda (fd) (declare (ignore fd)) info))))))
  (let ((info (make-array 256 :element-type '(unsigned-byte 8) :initial-element 0)))
    (replace info (gr8s::netlink-integer 11 4) :start1 0)
    (replace info (gr8s::netlink-integer 9 4) :start1 16)
    (replace info (gr8s::netlink-integer 47 4) :start1 20)
    (is (null (gr8s::check-cni-tcx-link 42 9 "egress" :object-info (lambda (fd) (declare (ignore fd)) info))))
    (signals gr8s::cni-error
      (gr8s::check-cni-tcx-link 42 10 "egress" :object-info (lambda (fd) (declare (ignore fd)) info)))))

(test cni-policy-removal-is-idempotent-without-a-network-namespace
  (let* ((root (merge-pathnames
                (format nil "gr8s-cni-delete-~36R/" (random (expt 36 8)))
                (uiop:temporary-directory)))
         (map-path (merge-pathnames "rejected_spoofs" root))
         (link-path (merge-pathnames "tcx-egress" root)))
    (unwind-protect
         (progn
           (ensure-directories-exist map-path)
           (with-open-file (stream map-path :direction :output
                                            :if-does-not-exist :create)
             (write-string "map" stream))
           (with-open-file (stream link-path :direction :output
                                             :if-does-not-exist :create)
             (write-string "link" stream))
           (gr8s::remove-cni-policy nil nil
                                    (namestring map-path)
                                    (namestring link-path)
                                    (namestring root))
           (is (not (probe-file map-path)))
           (is (not (probe-file link-path)))
           (is (not (probe-file root)))
           (gr8s::remove-cni-policy nil nil
                                    (namestring map-path)
                                    (namestring link-path)
                                    (namestring root)))
      (when (probe-file root)
        (uiop:delete-directory-tree root :validate t)))))

(test cni-main-speaks-json-on-standard-streams
  (let ((output (make-string-output-stream)))
    (is (zerop
         (gr8s::cni-main
          :input (make-string-input-stream "")
          :output output
          :environment (lambda (name)
                         (and (string= name "CNI_COMMAND") "VERSION")))))
    (let ((response (com.inuoe.jzon:parse (get-output-stream-string output))))
      (is (string= "1.1.0" (gethash "cniVersion" response)))
      (is (equalp #( "0.4.0" "1.0.0" "1.1.0")
                  (gethash "supportedVersions" response))))))

(test cni-main-forwards-standard-cni-input-to-the-agent
  (dolist (command '("ADD" "CHECK" "DEL"))
    (let ((output (make-string-output-stream))
          (seen-path nil)
          (seen-request nil)
          (seen-timeout nil))
      (is (zerop
           (gr8s::cni-main
            :input (make-string-input-stream *valid-cni-config*)
            :output output
            :environment
            (lambda (name)
              (cdr (assoc name
                          `(("CNI_COMMAND" . ,command)
                            ("CNI_CONTAINERID" . "sandbox-client")
                            ("CNI_NETNS" . "/proc/99/ns/net")
                            ("CNI_IFNAME" . "eth0")
                            ("CNI_ARGS" . "K8S_POD_NAME=example")
                            ("CNI_PATH" . "/opt/cni/bin"))
                          :test #'string=)))
            :timeout 0.25
            :agent-call
            (lambda (path request &key timeout)
              (setf seen-path path
                    seen-request request
                    seen-timeout timeout)
              (make-instance
               'gr8s.node.v1::cni-response
               :protocol-version gr8s::+node-protocol-version+
               :success t
               :result-json
               (if (string= command "ADD")
                   (trivial-utf-8:string-to-utf-8-bytes
                    "{\"cniVersion\":\"1.0.0\",\"from\":\"agent\"}")
                   (make-array 0 :element-type '(unsigned-byte 8))))))))
      (is (string= "/run/gr8s/agent-cni.sock" seen-path))
      (is (= 0.25 seen-timeout))
      (is (string= command
                   (slot-value seen-request 'gr8s.node.v1::command)))
      (is (string= "sandbox-client"
                   (slot-value seen-request 'gr8s.node.v1::container-id)))
      (is (string= "/proc/99/ns/net"
                   (slot-value seen-request
                               'gr8s.node.v1::network-namespace)))
      (is (string= "eth0"
                   (slot-value seen-request 'gr8s.node.v1::interface-name)))
      (is (string= "K8S_POD_NAME=example"
                   (slot-value seen-request 'gr8s.node.v1::arguments)))
      (is (string= "/opt/cni/bin"
                   (slot-value seen-request 'gr8s.node.v1::plugin-path)))
      (is (string= *valid-cni-config*
                   (trivial-utf-8:utf-8-bytes-to-string
                    (slot-value seen-request
                                'gr8s.node.v1::network-configuration))))
      (if (string= command "ADD")
          (let ((result
                  (com.inuoe.jzon:parse
                   (get-output-stream-string output))))
            (is (string= "agent" (gethash "from" result))))
          (is (string= "" (get-output-stream-string output)))))))

(test cni-main-returns-a-spec-shaped-error
  (let ((output (make-string-output-stream)))
    (is (= 1
           (gr8s::cni-main
            :input (make-string-input-stream *valid-cni-config*)
            :output output
            :environment (lambda (name)
                           (cond
                             ((string= name "CNI_COMMAND") "ADD")
                             ((string= name "CNI_CONTAINERID") "")
                             (t nil)))
            :agent-call
            (lambda (path request &key timeout)
              (declare (ignore path timeout))
              (gr8s::handle-agent-cni-request request)))))
    (let ((response (com.inuoe.jzon:parse (get-output-stream-string output))))
      (is (= 100 (gethash "code" response)))
      (is (string= "CNI_CONTAINERID is required" (gethash "msg" response))))))

(test cni-main-maps-malformed-unavailable-and-timeout-errors
  (labels ((environment (name)
             (cdr (assoc name
                         '(("CNI_COMMAND" . "ADD")
                           ("CNI_CONTAINERID" . "sandbox-errors")
                           ("CNI_NETNS" . "/proc/99/ns/net")
                           ("CNI_IFNAME" . "eth0"))
                         :test #'string=)))
           (invoke (configuration agent-call)
             (let ((output (make-string-output-stream)))
               (values
                (gr8s::cni-main
                 :input (make-string-input-stream configuration)
                 :output output
                 :environment #'environment
                 :agent-call agent-call)
                (com.inuoe.jzon:parse
                 (get-output-stream-string output))))))
    (multiple-value-bind (status response)
        (invoke
         "not-json"
         (lambda (&rest arguments)
           (declare (ignore arguments))
           (error "agent call must not run for malformed input")))
      (is (= 1 status))
      (is (= 100 (gethash "code" response)))
      (is (search "invalid network configuration" (gethash "msg" response))))
    (dolist (message '("gr8s agent CNI service is unavailable"
                       "timed out waiting for the gr8s agent CNI service"))
      (multiple-value-bind (status response)
          (invoke
           *valid-cni-config*
           (lambda (&rest arguments)
             (declare (ignore arguments))
             (gr8s::invalid-cni "~A" message)))
        (is (= 1 status))
        (is (= 100 (gethash "code" response)))
        (is (string= message (gethash "msg" response)))))))

(test endpoint-identity-encoding-matches-the-whistler-map-layout
  (let ((bytes (gr8s::encode-cni-endpoint-identity "10.88.1.2" #(2 17 34 51 68 85))))
    (is (= 16 (length bytes)))
    (is (= #x0a580102 (gr8s::netlink-read-integer bytes 0 4)))
    (is (= #x02112233 (gr8s::netlink-read-integer bytes 4 4)))
    (is (= #x4455 (gr8s::netlink-read-integer bytes 8 4)))
    (is (= 1 (gr8s::netlink-read-integer bytes 12 4)))))

(test routed-policy-selects-the-host-interface-without-entering-the-pod
  (let ((configuration (gr8s::make-cni-configuration :policy-interface-name "gr-owned"))
        (context (gr8s::make-cni-context :netns "/missing/pod" :interface-name "eth0")))
    (is (= 42 (gr8s::call-with-cni-policy-interface
               configuration context #'identity
               (lambda (&rest args) (declare (ignore args))
                 (error "host policy must not enter the Pod namespace"))
               (lambda (name) (is (string= "gr-owned" name)) 42))))))
