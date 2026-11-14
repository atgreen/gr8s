(in-package #:gr8s/tests)

(in-suite gr8s)

(test network-implementation-has-an-explicit-package-boundary
  (let ((network (find-package '#:gr8s.network)))
    (is-true network)
    (dolist (name '("CNI-MAIN"
                    "OPEN-NODE-IPAM"
                    "CALL-RTNETLINK"
                    "COMPILE-NETWORK-POLICY"
                    "START-SERVICE-LB-DATAPLANE"
                    "RECONCILE-NODE-VXLAN-NETWORK"
                    "START-AGENT-CNI-SERVER"
                    "MAKE-ROUTED-CNI-OPERATIONS"))
      (multiple-value-bind (implementation status)
          (find-symbol name network)
        (declare (ignore implementation))
        ;; Entry points resolve in the module's namespace; some (the rtnetlink
        ;; primitives) are re-homed library symbols, and the exported surface
        ;; is minimal, so presence is the boundary, not ownership or :EXTERNAL.
        (is (not (null status)))))
    ;; Reader-interned LOOP syntax is implementation detail, not public API.
    (is (not (eq :external
                 (nth-value 1 (find-symbol "FOR" network)))))))

(defparameter *valid-cni-config*
  "{\"cniVersion\":\"1.0.0\",\"name\":\"gr8s\",\"type\":\"gr8s\",\"socket\":\"/run/gr8s/agent-cni.sock\",\"direction\":\"egress\",\"program\":\"/runtime/gr8s-whistler.bpf.o\",\"mapPinRoot\":\"/run/gr8s/bpf\",\"prevResult\":{\"cniVersion\":\"1.0.0\",\"interfaces\":[]}}")

(test cni-service-stages-must-be-present-for-check-to-succeed
  (let ((seen nil))
    (gr8s.network::check-cni-service-stages
     :map :lookup (lambda (map key) (declare (ignore map)) (push key seen) #(1 0 0 0)))
    (is (equalp '(#(0 0 0 0) #(1 0 0 0) #(2 0 0 0)) (nreverse seen))))
  (signals gr8s.network::cni-error
    (gr8s.network::check-cni-service-stages :map :lookup (constantly nil)))
  (signals gr8s.network::cni-error
    (gr8s.network::check-cni-service-stages :map :lookup (constantly #(0 0 0 0)))))

(test cni-packet-service-root-is-explicit-and-absolute
  (let ((object (com.inuoe.jzon:parse *valid-cni-config*)))
    (setf (gethash "servicePacketRoot" object) "/pins/service-lb/")
    (let ((configuration (gr8s.network::parse-cni-configuration (com.inuoe.jzon:stringify object))))
      (is (equal "/pins/service-lb/" (gr8s.network::cni-configuration-service-packet-root configuration)))
      (is (= 17 (length (gr8s.network::cni-local-policy-map-specs configuration)))))
    (setf (gethash "servicePacketRoot" object) "relative/")
    (signals gr8s.network::cni-error
      (gr8s.network::parse-cni-configuration (com.inuoe.jzon:stringify object)))))

(test cni-v2-service-profile-has-separate-shared-and-local-schemas
  (let ((object (com.inuoe.jzon:parse *valid-cni-config*)))
    (setf (gethash "servicePacketProfile" object) "v2")
    (signals gr8s.network::cni-error
      (gr8s.network::parse-cni-configuration (com.inuoe.jzon:stringify object)))
    (setf (gethash "servicePacketRoot" object) "/pins/service-lb/")
    (let* ((configuration (gr8s.network::parse-cni-configuration (com.inuoe.jzon:stringify object)))
           (local (gr8s.network::cni-local-policy-map-specs configuration))
           (shared (gr8s.network::cni-shared-service-map-specs configuration)))
      (is (eq :v2 (gr8s.network::cni-configuration-service-packet-profile configuration)))
      (is (= 17 (length local)))
      (is (= 13 (length shared)))
      (is (= 48 (fourth (assoc "endpoint_identity" local :test #'equal))))
      (is (= 32 (third (assoc "netpol_flows_v2" local :test #'equal))))
      (is (equal '("gr8s_nat_stages" 3 4 4 16 0)
                 (assoc "gr8s_nat_stages" local :test #'equal)))
      (is (assoc "gr8s_nat_risk_v2" shared :test #'equal))
      (is (not (assoc "gr8s_nat_risk_v2" local :test #'equal)))
      (is (not (assoc "gr8s_pkt_stages" local :test #'equal))))
    (setf (gethash "servicePacketProfile" object) "v3")
    (signals gr8s.network::cni-error
      (gr8s.network::parse-cni-configuration (com.inuoe.jzon:stringify object)))))

(test cni-v2-map-schema-rejects-legacy-endpoint-identity
  (let ((info (make-array 256 :element-type '(unsigned-byte 8) :initial-element 0)))
    (flet ((put (offset value)
             (replace info (cl-rtnetlink::netlink-integer value 4) :start1 offset)))
      (put 0 2) (put 8 4) (put 12 48) (put 16 1) (put 20 128)
      (is (= 48 (whistler/loader::map-info-value-size
                 (gr8s.network::cni-policy-map-info 42 "endpoint_identity" :profile :v2
                                            :object-info (lambda (fd) (declare (ignore fd)) info)))))
      (signals gr8s.network::cni-error
        (gr8s.network::cni-policy-map-info 42 "endpoint_identity" :profile :v1
                                   :object-info (lambda (fd) (declare (ignore fd)) info)))
      (put 12 32)
      (signals gr8s.network::cni-error
        (gr8s.network::cni-policy-map-info 42 "endpoint_identity" :profile :v2
                                   :object-info (lambda (fd) (declare (ignore fd)) info))))))

(test cni-v2-attachment-requires-trusted-native-owner-before-map-access
  (let ((object (com.inuoe.jzon:parse *valid-cni-config*))
        (mutations nil))
    (setf (gethash "servicePacketRoot" object) "/pins/service-lb/"
          (gethash "servicePacketProfile" object) "v2")
    (signals gr8s.network::cni-error
      (gr8s.network::install-cni-policy
       (gr8s.network::parse-cni-configuration (com.inuoe.jzon:stringify object))
       (gr8s.network::make-cni-context) "/pins/rejected_spoofs" "/pins/tcx-ingress"
       :ensure-directory (lambda (&rest ignored) (declare (ignore ignored)) (push :ensure mutations))
       :open-pinned (lambda (&rest ignored) (declare (ignore ignored)) (push :open mutations))))
    (is (null mutations))
    (let ((configuration (gr8s.network::parse-cni-configuration
                          (com.inuoe.jzon:stringify object))))
      (setf (gr8s.network::cni-configuration-service-node-id configuration) "node-1"
            (gr8s.network::cni-configuration-service-return-address configuration) "10.88.0.9"
            (gr8s.network::cni-configuration-endpoint-addresses configuration) '("10.88.0.2"))
      (signals error
        (gr8s.network::install-cni-policy
         configuration (gr8s.network::make-cni-context)
         "/pins/rejected_spoofs" "/pins/tcx-ingress"
         :ensure-directory (lambda (&rest ignored)
                             (declare (ignore ignored)) (push :ensure mutations))
         :check-owner (lambda (&rest ignored)
                        (declare (ignore ignored)) (push :owner mutations))
         :open-pinned (lambda (&rest ignored)
                        (declare (ignore ignored)) (push :open mutations)
                        (error "shared map absent"))))
      (is (equal '(:owner :ensure :open) (reverse mutations))))))

(test cni-v2-stage-publication-requires-all-eight-programs
  (let* ((object (gr8s.network::%make-egress-policy-object nil nil))
         (map (whistler/loader::make-map-info :name "gr8s_nat_stages" :fd 500))
         (programs
           (loop for (index . name) in gr8s.network::*service-nat-stage-programs*
                 collect (cons name (whistler/loader::make-prog-info
                                     :name name :section-name "classifier"
                                     :type 3 :insns #() :fd (+ 700 index)))))
         (writes nil))
    (setf (gr8s.network::egress-policy-object-maps object) (list (cons "gr8s_nat_stages" map))
          (gr8s.network::egress-policy-object-programs object) programs)
    (gr8s.network::publish-egress-policy-stages
     object :update (lambda (target key value) (is (eq target map)) (push (cons key value) writes)))
    (is (= 8 (length writes)))
    (is (equalp (loop for index below 8 collect (gr8s.network::service-lb-bytes index 4))
                (mapcar #'car (nreverse writes))))
    (setf (gr8s.network::egress-policy-object-programs object) (butlast programs)
          writes nil)
    (signals gr8s.network::cni-error
      (gr8s.network::publish-egress-policy-stages
       object :update (lambda (&rest arguments) (push arguments writes))))
    (is (null writes))))

(test cni-v2-loader-reuses-node-maps-and-publishes-complete-graph
  ;; The standalone graph suite compiles and executes the bytecode. Exercise
  ;; CNI map reuse/publication here without recompiling that graph for every
  ;; ordinary make test run (the full compiler costs several minutes).
  (let* ((forms (gr8s.network::service-nat-guard-map-forms))
         (map-specs
           (mapcar (lambda (form)
                     (let ((options (cddr form)))
                       (list :name (substitute #\_ #\-
                                               (string-downcase (symbol-name (second form))))
                             :type (getf options :type)
                             :key-size (getf options :key-size)
                             :value-size (getf options :value-size)
                             :max-entries (getf options :max-entries)
                             :flags (or (getf options :map-flags) 0))))
                   forms))
         (program-specs
           (loop for name in (append '("gr8s_egress_guard" "gr8s_ingress_guard")
                                     (mapcar #'cdr gr8s.network::*service-nat-stage-programs*)
                                     '("gr8s_nat_gc"))
                 collect (list :name name :section "classifier")))
         (object (gr8s.network::%make-egress-policy-object map-specs program-specs))
         (shared (gr8s.network::service-nat-shared-map-specs))
         (replacements (loop for spec in shared for fd from 1000
                             collect (cons (first spec) fd)))
         (created nil) (writes nil))
    (unwind-protect
         (progn
           (is (= 30 (length (gr8s.network::egress-policy-object-map-specs object))))
           (is (= 11 (length (gr8s.network::egress-policy-object-program-specs object))))
           (signals gr8s.network::cni-error
             (gr8s.network::load-egress-policy-object object (rest replacements)
                                               :create-map (constantly nil)))
           (gr8s.network::load-egress-policy-object
            object replacements
            :create-map (lambda (map)
                          (push (whistler/loader:map-info-name map) created)
                          (setf (whistler/loader:map-info-fd map) (+ 2000 (length created)))
                          map)
            :load-programs
            (lambda (specs maps)
              (is (= 30 (length maps)))
              (loop for spec in specs for fd from 3000
                    for name = (getf spec :name)
                    collect (cons name (whistler/loader::make-prog-info
                                        :name name :section-name (getf spec :section)
                                        :type 3 :insns #() :fd fd))))
            :update (lambda (map key value)
                      (is (equal "gr8s_nat_stages" (whistler/loader:map-info-name map)))
                      (push (cons key value) writes)))
           (is (= 17 (length created)))
           (is (notany (lambda (name) (assoc name replacements :test #'equal)) created))
           (is (= 8 (length writes)))
           (is (equalp (loop for index below 8 collect (gr8s.network::service-lb-bytes index 4))
                       (mapcar #'car (nreverse writes)))))
      (gr8s.network::close-egress-policy-object object :close-fd (constantly nil)))))

(test cni-enabled-service-guard-never-creates-private-service-tables
  (let* ((configuration (gr8s.network::parse-cni-configuration *valid-cni-config*))
         (opened nil) (closed nil) (loaded nil))
    (setf (gr8s.network::cni-configuration-service-packet-root configuration) "/node/service-lb/")
    ;; Failure opening the second shared map must close the first and stop
    ;; before a guard object or any private map can be created.
    (signals error
      (gr8s.network::install-cni-policy
       configuration (gr8s.network::make-cni-context) "/pins/rejected_spoofs" "/pins/tcx-ingress"
       :ensure-directory (constantly nil)
       :open-pinned (lambda (path) (push path opened)
                      (when (= 2 (length opened)) (error "shared map unavailable")) 777)
       :validate-map (constantly :map)
       :open-object (lambda (&rest ignored) (declare (ignore ignored)) (setf loaded t))
       :close-fd (lambda (fd) (push fd closed))))
    (is (null loaded))
    (is (equal '(777) closed))
    (is (every (lambda (path) (search "/node/service-lb/" path)) opened))))

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
                 (gr8s.network::start-agent-cni-server
                  socket-path
                  (lambda (request)
                    (setf seen request)
                    (make-instance
                     'gr8s.node.v1::cni-response
                     :protocol-version gr8s.protocol::+node-protocol-version+
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
                   (gr8s.network::call-agent-cni
                    socket-path
                    (make-instance
                     'gr8s.node.v1::cni-request
                     :protocol-version gr8s.protocol::+node-protocol-version+
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
      (when server (gr8s.network::stop-agent-cni-server server))
      (when (probe-file directory)
        (uiop:delete-directory-tree directory :validate t))))))

(defun agent-cni-request-for-test (command &optional (configuration *valid-cni-config*))
  (make-instance
   'gr8s.node.v1::cni-request
   :protocol-version gr8s.protocol::+node-protocol-version+
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
          (gr8s.network::make-cni-operations
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
              (gr8s.network::handle-agent-cni-request
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
            (gr8s.network::handle-agent-cni-request
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
           (signals gr8s.network::cni-error
             (gr8s.network::call-agent-cni
              missing-path (agent-cni-request-for-test "DEL") :timeout 0.05))
           (setf server
                 (gr8s.network::start-agent-cni-server
                  socket-path
                  (lambda (request)
                    (declare (ignore request))
                    (sleep 0.2)
                    (make-instance
                     'gr8s.node.v1::cni-response
                     :protocol-version gr8s.protocol::+node-protocol-version+
                     :success t))))
           (signals gr8s.network::cni-error
             (gr8s.network::call-agent-cni
              socket-path (agent-cni-request-for-test "DEL") :timeout 0.02)))
      (when server (gr8s.network::stop-agent-cni-server server))
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
                 (gr8s.network::start-agent-cni-server
                  socket-path
                  (lambda (request)
                    (declare (ignore request))
                    (setf handler-called t)
                    (make-instance
                     'gr8s.node.v1::cni-response
                     :protocol-version gr8s.protocol::+node-protocol-version+
                     :success t))
                  :peer-authorizer
                  (lambda (pid uid gid)
                    (declare (ignore pid uid gid))
                    nil)))
           (let ((response
                   (gr8s.network::call-agent-cni
                    socket-path (agent-cni-request-for-test "DEL")
                    :timeout 1)))
             (is-false (slot-value response 'gr8s.node.v1::success))
             (is (search "not authorized"
                         (slot-value response
                                     'gr8s.node.v1::error-message))))
           (is-false handler-called))
      (when server (gr8s.network::stop-agent-cni-server server))
      (when (probe-file directory)
        (uiop:delete-directory-tree directory :validate t)))))

(test cni-configuration-requires-absolute-paths-and-a-previous-result
  (let ((configuration (gr8s.network::parse-cni-configuration *valid-cni-config*
                                                       :require-previous t)))
    (is (string= "egress" (gr8s.network::cni-configuration-direction configuration)))
    (is (string= "gr8s" (gr8s.network::cni-configuration-type configuration))))
  ;; The egress guard is JIT-compiled in-process, so a config with no "program"
  ;; ELF path parses fine.
  (is (gr8s.network::parse-cni-configuration
       "{\"cniVersion\":\"1.0.0\",\"mapPinRoot\":\"/run/bpf\",\"prevResult\":{}}"
       :require-previous t))
  ;; mapPinRoot must still be an absolute path.
  (signals error
    (gr8s.network::parse-cni-configuration
     "{\"cniVersion\":\"1.0.0\",\"mapPinRoot\":\"relative-bpf\",\"prevResult\":{}}"
     :require-previous t))
  ;; A previous result is still required when chained.
  (signals error
    (gr8s.network::parse-cni-configuration
     "{\"cniVersion\":\"1.0.0\",\"mapPinRoot\":\"/run/bpf\"}"
     :require-previous t)))

(test cni-pin-paths-are-confined-to-the-sandbox-directory
  (multiple-value-bind (map-path link-path directory)
      (gr8s.network::cni-pin-paths "/run/gr8s/bpf" "pod_0123.example-4")
    (is (string= "/run/gr8s/bpf/pod_0123.example-4/rejected_spoofs" map-path))
    (is (string= "/run/gr8s/bpf/pod_0123.example-4/tcx-egress" link-path))
    (is (string= "/run/gr8s/bpf/pod_0123.example-4/" directory)))
  (dolist (unsafe '("" "." ".." "pod/name" "pod name"))
    (signals error (gr8s.network::cni-pin-paths "/run/gr8s/bpf" unsafe))))

(test cni-interface-index-uses-the-current-network-namespace
  (let ((resolved nil))
    (is (= 42
           (gr8s.network::cni-interface-index
            "eth0" :resolver (lambda (name)
                                (setf resolved name)
                                42))))
    (is (string= "eth0" resolved)))
  (signals error
    (gr8s.network::cni-interface-index "eth0" :resolver (lambda (name)
                                                  (declare (ignore name))
                                                  0))))

(test cni-add-runs-the-policy-operation-and-returns-the-chained-result
  (let* ((call nil)
        (operations
          (gr8s.network::make-cni-operations
           :add (lambda (configuration context map-path link-path)
                  (setf call (list configuration context map-path link-path))))))
    (let* ((context (gr8s.network::make-cni-context
                     :container-id "sandbox-1" :netns "/proc/42/ns/net"
                     :interface-name "eth0"))
           (result (gr8s.network::dispatch-cni-command
                    "ADD" *valid-cni-config* context operations)))
      (is (hash-table-p result))
      (is (string= "1.0.0" (gethash "cniVersion" result)))
      (is (eq context (second call)))
      (is (search "sandbox-1/rejected_spoofs" (third call)))
      (is (search "sandbox-1/tcx-egress" (fourth call))))))

(test chained-cni-policy-uses-the-primary-plugins-ip-and-preserves-its-result
  (let* ((seen nil)
         (previous
           (gr8s.foundation::json-object
            "cniVersion" "1.0.0"
            "interfaces" (vector (gr8s.foundation::json-object "name" "eth0" "sandbox" "/proc/99/ns/net"))
            "ips" (vector (gr8s.foundation::json-object "interface" 0 "address" "10.244.7.19/24"))))
         (configuration
           (com.inuoe.jzon:stringify
            (gr8s.foundation::json-object
             "cniVersion" "1.0.0" "name" "external" "type" "gr8s"
             "socket" "/run/gr8s/cni.sock" "mapPinRoot" "/run/gr8s/bpf"
             "prevResult" previous)))
         (policy
           (gr8s.network::make-cni-operations
            :add (lambda (config context map-path link-path)
                   (declare (ignore context map-path link-path))
                   (setf seen (gr8s.network::cni-configuration-endpoint-address config)))))
         (result
           (gr8s.network::dispatch-cni-command
            "ADD" configuration
            (gr8s.network::make-cni-context :container-id "sandbox-external"
                                    :netns "/proc/99/ns/net" :interface-name "eth0")
            (gr8s.network::make-chained-cni-operations :policy policy))))
    (is (string= "10.244.7.19" seen))
    (is (string= (com.inuoe.jzon:stringify previous)
                 (com.inuoe.jzon:stringify result)))))

(test chained-cni-policy-rejects-a-result-without-an-ipv4-address
  (let ((configuration
          (com.inuoe.jzon:stringify
           (gr8s.foundation::json-object
            "cniVersion" "1.0.0" "mapPinRoot" "/run/gr8s/bpf"
            "prevResult" (gr8s.foundation::json-object "cniVersion" "1.0.0" "ips" #())))))
    (signals gr8s.network::cni-error
      (gr8s.network::dispatch-cni-command
       "ADD" configuration
       (gr8s.network::make-cni-context :container-id "sandbox-no-ip"
                               :netns "/proc/99/ns/net" :interface-name "eth0")
       (gr8s.network::make-chained-cni-operations)))))

(test chained-cni-delete-does-not-require-a-previous-result
  (let ((removed nil)
        (configuration
          "{\"cniVersion\":\"1.0.0\",\"mapPinRoot\":\"/run/gr8s/bpf\"}"))
    (gr8s.network::dispatch-cni-command
     "DEL" configuration
     (gr8s.network::make-cni-context :container-id "sandbox-external"
                             :interface-name "eth0")
     (gr8s.network::make-chained-cni-operations
      :policy
      (gr8s.network::make-cni-operations
       :delete (lambda (config context map-path link-path directory)
                 (declare (ignore config context map-path link-path directory))
                 (setf removed t)))))
    (is-true removed)))

(test cni-delete-does-not-require-a-network-namespace
  (let* ((removed nil)
        (operations
          (gr8s.network::make-cni-operations
           :delete (lambda (configuration context map-path link-path directory)
                     (declare (ignore configuration context))
                     (setf removed (list map-path link-path directory))))))
    (gr8s.network::dispatch-cni-command
     "DEL" *valid-cni-config*
     (gr8s.network::make-cni-context :container-id "sandbox-1") operations)
    (is (search "sandbox-1/rejected_spoofs" (first removed)))
    (is (search "sandbox-1/tcx-egress" (second removed)))
    (is (search "sandbox-1/" (third removed)))))

(test cni-version-advertises-the-supported-specifications
  (let ((result (gr8s.network::dispatch-cni-command
                 "VERSION" "" (gr8s.network::make-cni-context)
                 (gr8s.network::make-cni-operations))))
    (is (string= "1.1.0" (gethash "cniVersion" result)))
    (is (equalp #( "0.4.0" "1.0.0" "1.1.0")
                (gethash "supportedVersions" result)))))

(defun policy-map-fixture (name)
  (whistler/loader::make-map-info
   :name name :fd (+ 41 (position name (mapcar #'first gr8s.network::+cni-policy-map-specs+)
                                 :test #'string=))))

(test cni-policy-install-reuses-counters-and-atomically-replaces-the-link
  (let ((calls nil)
        (configuration (gr8s.network::parse-cni-configuration *valid-cni-config* :require-previous t))
        (context (gr8s.network::make-cni-context :container-id "sandbox-1"
                                        :netns "/proc/42/ns/net" :interface-name "eth0")))
    (setf (gr8s.network::cni-configuration-endpoint-address configuration) "10.88.1.2")
    (gr8s.network::install-cni-policy
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
                                        (gr8s.network::cni-configuration-endpoint-address config)) calls))
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
        (configuration (gr8s.network::parse-cni-configuration *valid-cni-config*)))
    (signals error
      (gr8s.network::install-cni-policy
       configuration (gr8s.network::make-cni-context :netns "/fake/netns" :interface-name "eth0")
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

(test cni-service-guard-pins-continuations-before-attachment-and-closes-shared-fds-once
  (let* ((configuration (gr8s.network::parse-cni-configuration *valid-cni-config*))
         (events nil) (closed nil) (reused nil))
    (setf (gr8s.network::cni-configuration-service-packet-root configuration) "/node/service-lb/")
    (let* ((names (mapcar #'first
                         (append (gr8s.network::cni-local-policy-map-specs configuration)
                                 (gr8s.network::service-packet-map-specs))))
           (maps (loop for name in names for fd from 100
                       collect (cons name (whistler/loader::make-map-info :name name :fd fd)))))
      (flet ((map-for (name) (cdr (assoc name maps :test #'equal))))
        (gr8s.network::install-cni-policy
         configuration (gr8s.network::make-cni-context :netns "/fake/netns" :interface-name "eth0")
         "/pins/rejected_spoofs" "/pins/tcx-ingress"
         :ensure-directory (constantly nil) :path-exists-p (constantly nil)
         :open-pinned (lambda (path) (whistler/loader:map-info-fd (map-for (file-namestring path))))
         :validate-map (lambda (fd name) (declare (ignore fd)) (map-for name))
         :open-object (lambda (&rest ignored)
                        (declare (ignore ignored))
                        (is-true gr8s.network::*cni-service-packets*) :object)
         :load-object (lambda (object replacements) (declare (ignore object)) (setf reused replacements))
         :object-map (lambda (object name) (declare (ignore object)) (map-for name))
         :object-program (constantly :program) :program-fd (constantly 71)
         :initialize-identity (constantly nil)
         :pin-object (lambda (fd path) (declare (ignore fd)) (push (list :pin path) events))
         :rename-pin (constantly nil) :staged-links (constantly nil)
         :call-in-netns (lambda (path operation) (declare (ignore path)) (funcall operation))
         :interface-index (constantly 9)
         :attach-tcx (lambda (&rest ignored) (declare (ignore ignored)) (push '(:attach) events) 81)
         :close-fd (lambda (fd) (push fd closed))
         :close-object (lambda (object) (declare (ignore object))
                         (dolist (entry maps) (push (whistler/loader:map-info-fd (cdr entry)) closed)))))
      (is (= 10 (length reused)))
      (dolist (entry maps)
        (is (= 1 (count (whistler/loader:map-info-fd (cdr entry)) closed))))
      (let ((ordered (reverse events)))
        (is (< (position '(:pin "/pins/gr8s_pkt_stages") ordered :test #'equal)
               (position :attach ordered :key #'first)))
        ;; Seventeen maps and two TCX links; no shared Service map is pinned here.
        (is (= 19 (count :pin ordered :key #'first)))
        (dolist (spec (gr8s.network::service-packet-map-specs))
          (is-false (member (list :pin (concatenate 'string "/pins/" (first spec)))
                            ordered :test #'equal)))))))

(test pinned-map-schemas-and-tcx-targets-are-validated-before-use
  (dolist (spec gr8s.network::+cni-policy-map-specs+)
    (let ((info (make-array 256 :element-type '(unsigned-byte 8) :initial-element 0)))
      (flet ((put (offset value) (replace info (cl-rtnetlink::netlink-integer value 4) :start1 offset)))
        ;; A spec is (name type key-size value-size max-entries flags).
        (put 0 (second spec)) (put 8 (third spec)) (put 12 (fourth spec))
        (put 16 (fifth spec)) (put 20 (sixth spec))
        (is (= 42 (whistler/loader:map-info-fd
                   (gr8s.network::cni-policy-map-info 42 (first spec) :object-info (lambda (fd) (declare (ignore fd)) info)))))
        (put 12 (+ 8 (fourth spec)))
        (signals gr8s.network::cni-error
          (gr8s.network::cni-policy-map-info 42 (first spec) :object-info (lambda (fd) (declare (ignore fd)) info))))))
  (let ((info (make-array 256 :element-type '(unsigned-byte 8) :initial-element 0)))
    (replace info (cl-rtnetlink::netlink-integer 11 4) :start1 0)
    (replace info (cl-rtnetlink::netlink-integer 9 4) :start1 16)
    (replace info (cl-rtnetlink::netlink-integer 47 4) :start1 20)
    (is (null (gr8s.network::check-cni-tcx-link 42 9 "egress" :object-info (lambda (fd) (declare (ignore fd)) info))))
    (signals gr8s.network::cni-error
      (gr8s.network::check-cni-tcx-link 42 10 "egress" :object-info (lambda (fd) (declare (ignore fd)) info)))))

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
           (gr8s.network::remove-cni-policy nil nil
                                    (namestring map-path)
                                    (namestring link-path)
                                    (namestring root) :retire-link (constantly nil))
           (is (not (probe-file map-path)))
           (is (not (probe-file link-path)))
           (is (not (probe-file root)))
           (gr8s.network::remove-cni-policy nil nil
                                    (namestring map-path)
                                    (namestring link-path)
                                    (namestring root)))
      (when (probe-file root)
        (uiop:delete-directory-tree root :validate t)))))

(test cni-main-speaks-json-on-standard-streams
  (let ((output (make-string-output-stream)))
    (is (zerop
         (gr8s.network::cni-main
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
           (gr8s.network::cni-main
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
               :protocol-version gr8s.protocol::+node-protocol-version+
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
           (gr8s.network::cni-main
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
              (gr8s.network::handle-agent-cni-request request)))))
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
                (gr8s.network::cni-main
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
             (gr8s.network::invalid-cni "~A" message)))
        (is (= 1 status))
        (is (= 100 (gethash "code" response)))
        (is (string= message (gethash "msg" response)))))))

(test endpoint-identity-encoding-matches-the-whistler-map-layout
  (let ((bytes (gr8s.network::encode-cni-endpoint-identity
                '("10.88.1.2" "fd88::102") #(2 17 34 51 68 85))))
    (is (= 32 (length bytes)))
    (is (= #x0a580102 (cl-rtnetlink::netlink-read-integer bytes 0 4)))
    (is (= #x02112233 (cl-rtnetlink::netlink-read-integer bytes 4 4)))
    (is (= #x4455 (cl-rtnetlink::netlink-read-integer bytes 8 4)))
    (is (= 1 (cl-rtnetlink::netlink-read-integer bytes 12 4)))
    (is (equalp (0conf:parse-ipv6 "fd88::102") (subseq bytes 16 32)))))

(test endpoint-identity-distinguishes-native-and-chained-policy-attachments
  (let ((native (gr8s.network::make-cni-configuration :policy-interface-name "gr-owned"))
        (chained (gr8s.network::make-cni-configuration)))
    (is (= 1 (gr8s.network::cni-policy-attachment-mode native)))
    (is (= 2 (gr8s.network::cni-policy-attachment-mode chained)))
    (is (= 2 (cl-rtnetlink::netlink-read-integer
              (gr8s.network::encode-cni-endpoint-identity
               "10.240.0.2" #(10 11 12 13 14 15)
               (gr8s.network::cni-policy-attachment-mode chained))
              12 4)))))

(test routed-policy-selects-the-host-interface-without-entering-the-pod
  (let ((configuration (gr8s.network::make-cni-configuration :policy-interface-name "gr-owned"))
        (context (gr8s.network::make-cni-context :netns "/missing/pod" :interface-name "eth0")))
    (is (= 42 (gr8s.network::call-with-cni-policy-interface
               configuration context #'identity
               (lambda (&rest args) (declare (ignore args))
                 (error "host policy must not enter the Pod namespace"))
               (lambda (name) (is (string= "gr-owned" name)) 42))))))

(test cni-check-rejects-interrupted-packet-upgrades-before-reporting-healthy
  (dolist (staged '(nil t))
    (signals gr8s.network::cni-error
      (gr8s.network::check-cni-policy
       (gr8s.network::make-cni-configuration) (gr8s.network::make-cni-context)
       "/pins/rejected_spoofs" "/pins/tcx-egress"
       :path-exists-p (lambda (path) (and (not staged) (search "gr8s_pkt_upgrade_ingress" path)))
       :staged-links (lambda (path) (when (and staged (search "gr8s_pkt_upgrade_ingress" path))
                                     '("/pins/gr8s_pkt_upgrade_ingress_pending_1")))
       :open-pinned (lambda (path) (declare (ignore path)) (error "must reject before opening maps"))))))

(test cni-delete-detaches-staged-and-canonical-guards-before-unpinning
  (let ((events nil))
    (gr8s.network::remove-cni-policy
     nil nil "/pins/rejected_spoofs" "/pins/tcx-egress" "/pins/"
     :path-exists-p (constantly t)
     :retire-link (lambda (path) (push (list :detach path) events))
     :remove-path (lambda (path) (push (list :unpin path) events))
     :staged-links (lambda (path) (list (concatenate 'string path "_pending_1")))
     :remove-directory (lambda (path) (push (list :directory path) events)))
    (let ((ordered (nreverse events)))
      (dolist (path '("/pins/tcx-egress" "/pins/tcx-ingress"
                      "/pins/gr8s_pkt_upgrade_ingress" "/pins/gr8s_pkt_upgrade_egress"))
        (let ((stage (concatenate 'string path "_pending_1")))
          (is (< (position (list :detach stage) ordered :test #'equal)
                 (position (list :unpin stage) ordered :test #'equal)))
          (is (< (position (list :unpin stage) ordered :test #'equal)
                 (position (list :detach path) ordered :test #'equal)))
          (is (< (position (list :detach path) ordered :test #'equal)
                 (position (list :unpin path) ordered :test #'equal)))))
      (is (equal '(:directory "/pins/") (car (last ordered)))))))
