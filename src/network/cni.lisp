;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; The gr8s CNI plugin and the node agent's eBPF policy datapath behind it.
;;;;
;;;; gr8s ships as a chained CNI plugin. The thin `gr8s` binary (CNI-MAIN) only
;;;; reads the CNI_* environment and the network configuration on stdin, relays
;;;; the request to the local node agent over the Unix socket named in the
;;;; config, and writes the agent's result (or a CNI error object) back to the
;;;; container runtime. All privileged datapath work runs in the agent, which
;;;; owns the pinned BPF maps and can enter a Pod's network namespace.
;;;;
;;;; On the agent side (INSTALL / CHECK / REMOVE-CNI-POLICY), gr8s compiles the
;;;; Whistler object in-process, attaches an egress and an ingress TCX program to
;;;; the Pod's interface (the guards enforce the per-Pod NetworkPolicy carried as
;;;; data in the netpol_* maps -- no program recompile), and pins the programs and
;;;; maps under a per-container directory keyed by CNI_CONTAINERID. Link pins are
;;;; swapped atomically: a replacement is pinned to a staging name and renamed
;;;; into place, so the old guard stays live until the new one is attached. Every
;;;; step is idempotent and cleans up its partial state on failure, so a repeated
;;;; ADD reconverges rather than failing.

(in-package #:gr8s.network)

#+sbcl
(sb-alien:define-alien-routine ("setns" %linux-setns) sb-alien:int
  (fd sb-alien:int)
  (namespace-type sb-alien:int))

#+sbcl
(sb-alien:define-alien-routine ("if_nametoindex" %linux-if-nametoindex)
    sb-alien:unsigned-int
  (name sb-alien:c-string))

(define-condition cni-error (error)
  ((message :initarg :message :reader cni-error-message))
  (:report (lambda (condition stream)
             (write-string (cni-error-message condition) stream))))

(defun invalid-cni (control &rest arguments)
  "Signal a CNI-ERROR whose message is CONTROL formatted with ARGUMENTS. Does not
   return."
  (error 'cni-error :message (apply #'format nil control arguments)))

(defparameter +cni-policy-map-specs+
  ;; (name bpf-map-type key-size value-size max-entries flags). Types: 2=ARRAY,
  ;; 9=LRU_HASH, 11=LPM_TRIE. The netpol_* maps hold the per-Pod NetworkPolicy and
  ;; are updated as data by the agent (no program recompile).
  '(("rejected_spoofs"      2 4  8  1     0)
    ("endpoint_identity"    2 4  32 1     128)
    ("traffic_stats"        2 4  8  7     0)
    ("netpol_mode"          2 4  4  2     0)
    ("netpol_egress_cidr"  11 8  4  16384 1)
    ("netpol_egress_ports" 11 12 1  4096  1)
    ("netpol_ingress_cidr" 11 8  4  16384 1)
    ("netpol_ingress_ports" 11 12 1 4096  1)
    ("netpol_flows"         9 12 8  4096  0)
    ("netpol_egress_cidr_v6" 11 20 4 16384 1)
    ("netpol_egress_ports_v6" 11 12 1 4096 1)
    ("netpol_ingress_cidr_v6" 11 20 4 16384 1)
    ("netpol_ingress_ports_v6" 11 12 1 4096 1)
    ("netpol_flows_v6"       9 24 8 4096 0)
    ;; Same-node Pod delivery table: dest Pod IPv4 (network order) -> 16-byte
    ;; {ifindex, Pod MAC, veth MAC}. Agent-populated on reconcile. LPM /32 keys,
    ;; NO_PREALLOC -- same shape as netpol_egress_cidr.
    ("local_pod_v4"        11 8  16 4096  1)
    ;; Host-local destinations (API server 10.96.0.1, node IP) -> presence byte.
    ;; Agent-populated on reconcile. HASH, NO_PREALLOC.
    ("host_redirect_v4"     1 4  1  64    1)))

(defparameter +cni-legacy-policy-maps+ '("netpol_egress_mode" "netpol_egress_port")
  "Pins that endpoints created by earlier agents may still hold, removed with the endpoint.")

(defun cni-opposite-direction (direction)
  "Return the complementary guard direction: \"ingress\" for \"egress\", and
   \"egress\" for anything else."
  (if (string= direction "egress") "ingress" "egress"))

(defun cni-ingress-guard-link-path (link-path direction)
  "Where the ingress guard's link is pinned, beside the egress guard's LINK-PATH."
  (namestring (merge-pathnames (concatenate 'string "tcx-" (cni-opposite-direction direction))
                               (uiop:pathname-directory-pathname link-path))))

(defstruct cni-configuration
  version name type direction program map-pin-root previous-result endpoint-address
  endpoint-addresses policy-interface-name service-packet-root service-packet-profile
  service-node-id service-return-address)

(defvar *cni-policy-update-lock* (bt:make-lock "gr8s endpoint policy updates")
  "Serialize agent CNI ADD/DEL with retained endpoint program migration.
All privileged plugin work is dispatched to this agent through its CNI socket.")

(defun cni-upgrade-block-paths (map-path)
  "Canonical fail-closed link pins left by an interrupted packet upgrade."
  (loop for direction in '("ingress" "egress")
        collect (namestring
                 (merge-pathnames (concatenate 'string "gr8s_pkt_upgrade_" direction)
                                  (uiop:pathname-directory-pathname map-path)))))

(defvar *cni-service-packets* nil
  "True while compiling an endpoint guard bound to the node's shared Service maps.")

(defvar *cni-policy-profile* :v1
  "Strict expected map profile while CNI ADD or CHECK validates pinned maps.")

(defun cni-service-profile (configuration)
  (when (cni-configuration-service-packet-root configuration)
    (or (cni-configuration-service-packet-profile configuration) :v1)))

(defun cni-shared-service-map-specs (configuration)
  (case (cni-service-profile configuration)
    (:v1 (service-packet-map-specs))
    (:v2 (service-nat-shared-map-specs))))

(defun cni-local-policy-map-specs (configuration)
  "Per-endpoint maps, including the pinned program table for Service stages."
  (if (eq (cni-service-profile configuration) :v2)
      (service-nat-local-map-specs)
      (append +cni-policy-map-specs+
              (when (cni-configuration-service-packet-root configuration)
                '(("gr8s_pkt_stages" 3 4 4 8 0))))))

(defun check-cni-service-stages (map &key (lookup #'whistler/loader:map-lookup))
  "Require every policy/NAT continuation before reporting a healthy endpoint."
  (loop for name in (if (equal "gr8s_nat_stages"
                              (ignore-errors (whistler/loader:map-info-name map)))
                        (mapcar #'cdr *service-nat-stage-programs*)
                        '("Service forward" "egress policy" "Service reverse"))
        for index from 0
        for value = (funcall lookup map (service-lb-bytes index 4))
        do (unless (and value (some #'plusp value))
             (invalid-cni "~A continuation is missing from the endpoint program table" name))))

(defstruct cni-context
  container-id netns interface-name)

(defstruct (cni-operations (:constructor make-cni-operations
                             (&key (add 'install-cni-policy)
                                   (check 'check-cni-policy)
                                   (delete 'remove-cni-policy)
                                   (status 'check-cni-status)
                                   (prepare (lambda (configuration context)
                                              (declare (ignore configuration context)))))))
  add check delete status prepare)

(defun required-cni-string (object key)
  "Return OBJECT's KEY as a non-empty string, or signal a CNI-ERROR when it is
   absent or not a non-empty string."
  (let ((value (gethash key object)))
    (unless (and (stringp value) (plusp (length value)))
      (invalid-cni "network configuration requires ~A" key))
    value))

(defun absolute-cni-path (object key)
  "Return OBJECT's KEY as a string naming an absolute path, signalling a
   CNI-ERROR when it is missing, empty, or relative."
  (let ((value (required-cni-string object key)))
    (unless (uiop:absolute-pathname-p (pathname value))
      (invalid-cni "~A must be an absolute path" key))
    value))

(defun parse-cni-configuration (text &key require-previous)
  "Parse the CNI network configuration TEXT (JSON) into a CNI-CONFIGURATION,
   defaulting name and type to \"gr8s\" and direction to \"egress\". Signals a
   CNI-ERROR on invalid JSON, a non-object, an unsupported direction, or -- when
   REQUIRE-PREVIOUS -- a missing prevResult (gr8s must be chained). A \"program\"
   ELF path is accepted but ignored."
  (let ((object (handler-case
                    (com.inuoe.jzon:parse text)
                  (error (condition)
                    (invalid-cni "invalid network configuration: ~A"
                                 condition)))))
    (unless (hash-table-p object)
      (invalid-cni "network configuration must be a JSON object"))
    (let* ((direction (gethash "direction" object "egress"))
           (previous (gethash "prevResult" object)))
      (unless (member direction '("ingress" "egress") :test #'string=)
        (invalid-cni "unsupported direction ~S" direction))
      (when (and require-previous (not (hash-table-p previous)))
        (invalid-cni "gr8s must be used as a chained CNI plugin"))
      (let ((profile (gethash "servicePacketProfile" object "v1")))
        (unless (member profile '("v1" "v2") :test #'equal)
          (invalid-cni "unsupported Service packet profile ~S" profile))
        (when (and (equal profile "v2") (not (gethash "servicePacketRoot" object)))
          (invalid-cni "v2 Service packet profile requires shared maps"))
      (make-cni-configuration
       :version (required-cni-string object "cniVersion")
       :name (gethash "name" object "gr8s")
       :type (gethash "type" object "gr8s")
       :direction direction
       ;; The egress guard is JIT-compiled in-process; a "program" ELF path, if
       ;; present in an older conflist, is accepted and ignored.
       :program (gethash "program" object)
       :map-pin-root (absolute-cni-path object "mapPinRoot")
       :service-packet-root (when (gethash "servicePacketRoot" object)
                              (absolute-cni-path object "servicePacketRoot"))
       :service-packet-profile (when (equal profile "v2") :v2)
       :previous-result previous)))))

(defun safe-cni-container-id-p (container-id)
  "True when CONTAINER-ID is safe to use as a BPF pin directory name: a non-empty
   string, neither \".\" nor \"..\", of alphanumerics and -_. only."
  (and (stringp container-id)
       (plusp (length container-id))
       (not (member container-id '("." "..") :test #'string=))
       (every (lambda (character)
                (or (alphanumericp character)
                    (find character "-_.")))
              container-id)))

(defun cni-pin-paths (root container-id &optional (direction "egress"))
  "Return (values MAP-PATH LINK-PATH DIRECTORY) for CONTAINER-ID's pins under
   ROOT: the rejected_spoofs map path, the tcx-DIRECTION link path, and the
   containing directory. Signals a CNI-ERROR when CONTAINER-ID is unsafe."
  (unless (safe-cni-container-id-p container-id)
    (invalid-cni "container ID ~S is unsafe for a BPF pin" container-id))
  (let ((directory
          (format nil "~A/~A/" (string-right-trim "/" root) container-id)))
    (values (concatenate 'string directory "rejected_spoofs")
            (concatenate 'string directory "tcx-" direction)
            directory)))

(defun cni-version-result ()
  "The CNI VERSION result object: cniVersion 1.1.0 and the supported version list."
  (json-object "cniVersion" "1.1.0"
               "supportedVersions" #( "0.4.0" "1.0.0" "1.1.0")))

(defun require-cni-context (context &key network-namespace)
  "Signal a CNI-ERROR unless CONTEXT carries a safe container ID, and -- when
   NETWORK-NAMESPACE -- a non-empty CNI_NETNS and CNI_IFNAME. Returns NIL when the
   context is complete."
  (unless (safe-cni-container-id-p (cni-context-container-id context))
    (invalid-cni "CNI_CONTAINERID is required"))
  (when network-namespace
    (unless (and (cni-context-netns context)
                 (plusp (length (cni-context-netns context))))
      (invalid-cni "CNI_NETNS is required"))
    (unless (and (cni-context-interface-name context)
                 (plusp (length (cni-context-interface-name context))))
      (invalid-cni "CNI_IFNAME is required"))))

(defun dispatch-cni-command (command input context operations &key (chained t))
  "Dispatch a CNI COMMAND against OPERATIONS, having parsed the configuration from
   INPUT. VERSION returns the version result; STATUS runs the status op; GC is a
   no-op; ADD, CHECK and DEL require CONTEXT, resolve the per-container pin paths,
   and invoke the matching operation (ADD returning the previous result, the
   others NIL). When CHAINED, ADD and CHECK require a prevResult. Signals a
   CNI-ERROR on an unsupported command."
  (when (string= command "VERSION")
    (return-from dispatch-cni-command (cni-version-result)))
  (let* ((require-previous (member command '("ADD" "CHECK") :test #'string=))
         (configuration
           (parse-cni-configuration input :require-previous (and chained require-previous))))
    (case (intern command :keyword)
      (:status
       (funcall (cni-operations-status operations) configuration)
       nil)
      (:gc nil)
      (otherwise
       (require-cni-context
        context :network-namespace (member command '("ADD" "CHECK")
                                           :test #'string=))
       (funcall (cni-operations-prepare operations) configuration context)
       (multiple-value-bind (map-path link-path directory)
           (cni-pin-paths (cni-configuration-map-pin-root configuration)
                          (cni-context-container-id context)
                          (cni-configuration-direction configuration))
         (cond
           ((string= command "ADD")
            (funcall (cni-operations-add operations)
                     configuration context map-path link-path)
            (cni-configuration-previous-result configuration))
           ((string= command "CHECK")
            (funcall (cni-operations-check operations)
                     configuration context map-path link-path)
            nil)
           ((string= command "DEL")
            (funcall (cni-operations-delete operations)
                     configuration context map-path link-path directory)
            nil)
           (t (invalid-cni "unsupported CNI command ~A" command))))))))

(defun chained-cni-addresses (previous-result)
  "Return every valid Pod address in a CNI PREVIOUS-RESULT, without prefixes."
  (let ((addresses (gethash "ips" previous-result #())))
    (let ((result
            (loop for entry across addresses
                  for cidr = (and (hash-table-p entry) (gethash "address" entry))
                  for slash = (and (stringp cidr) (position #\/ cidr))
                  for address = (and slash (subseq cidr 0 slash))
                  when (and address
                            (handler-case
                                (progn (network-address-wire-values address) t)
                              (error () nil)))
                    collect address)))
      (unless result (invalid-cni "the primary CNI result has no Pod address"))
      result)))

(defun chained-cni-ipv4-address (previous-result)
  "Return the first IPv4 Pod address in a CNI PREVIOUS-RESULT."
  (or (find-if-not (lambda (address) (find #\: address))
                   (chained-cni-addresses previous-result))
      (invalid-cni "the primary CNI result has no IPv4 Pod address")))

(defun make-chained-cni-operations (&key (policy (make-cni-operations)))
  "Wrap POLICY for use after an external primary CNI plugin.
The primary plugin owns links and IPAM; gr8s derives the endpoint identity from
prevResult and only installs, checks, or removes its policy datapath."
  (make-cni-operations
   :prepare
   (lambda (configuration context)
     ;; The runtime supplies prevResult for ADD and CHECK, but the CNI contract
     ;; permits DEL after partial setup and without any previous result. Policy
     ;; removal is keyed by container/interface pins and does not need an IP.
     (let ((previous (cni-configuration-previous-result configuration)))
       (when (hash-table-p previous)
         (let ((addresses (chained-cni-addresses previous)))
           (setf (cni-configuration-endpoint-addresses configuration) addresses
                 (cni-configuration-endpoint-address configuration)
                 (find-if-not (lambda (address) (find #\: address)) addresses)))))
     (funcall (cni-operations-prepare policy) configuration context))
   :add (cni-operations-add policy)
   :check (cni-operations-check policy)
   :delete (cni-operations-delete policy)
   :status (cni-operations-status policy)))

(defun ensure-cni-pin-directory (directory)
  "Ensure DIRECTORY exists, creating parents, and return it."
  (ensure-directories-exist (merge-pathnames ".pin" (pathname directory)))
  directory)

(defun remove-cni-path (path)
  "Delete the pin at PATH, ignoring a missing file. Always returns NIL."
  (handler-case (delete-file path)
    (file-error () nil))
  nil)

(defun remove-empty-cni-directory (directory)
  "Remove DIRECTORY when empty, ignoring the error when it is absent or not
   empty. Always returns NIL."
  (handler-case (sb-posix:rmdir directory)
    (sb-posix:syscall-error () nil))
  nil)

(defun call-with-cni-network-namespace (path operation)
  "Call OPERATION with the current thread moved into the network namespace at
   PATH, restoring the original namespace afterward even on a non-local exit.
   Signals when the namespace cannot be entered or restored. SBCL/Linux only;
   errors elsewhere."
  #+sbcl
  (let ((original (sb-posix:open "/proc/thread-self/ns/net" sb-posix:o-rdonly 0))
        (target nil))
    (unwind-protect
         (progn
           (setf target (sb-posix:open path sb-posix:o-rdonly 0))
           (unless (zerop (%linux-setns target 0))
             (error "could not enter network namespace ~A: ~A"
                    path (sb-int:strerror (sb-alien:get-errno))))
           (unwind-protect
                (funcall operation)
             (unless (zerop (%linux-setns original 0))
               (error "could not restore the original network namespace: ~A"
                      (sb-int:strerror (sb-alien:get-errno))))))
      (when target (sb-posix:close target))
      (sb-posix:close original)))
  #-sbcl
  (declare (ignore path operation))
  #-sbcl
  (error "CNI network namespaces currently require SBCL on Linux"))

(defun native-interface-index (name)
  "The kernel ifindex for interface NAME via if_nametoindex (0 when unknown, or
   on non-SBCL)."
  #+sbcl (%linux-if-nametoindex name)
  #-sbcl (declare (ignore name))
  #-sbcl 0)

(defun cni-interface-index (name &key (resolver #'native-interface-index))
  "Resolve interface NAME to its kernel ifindex via RESOLVER. Signals a CNI-ERROR
   when NAME is unsafe (empty, over 15 characters, or not alphanumeric/-_.), or
   when the interface is not found (index 0)."
  (unless (and (plusp (length name))
               (<= (length name) 15)
               (every (lambda (character)
                        (or (alphanumericp character)
                            (find character "-_.")))
                      name))
    (invalid-cni "unsafe CNI interface name ~S" name))
  (let ((index (funcall resolver name)))
    (when (zerop index)
      (invalid-cni "network interface ~A was not found" name))
    index))

(defun call-with-cni-policy-interface
    (configuration context operation call-in-netns interface-index)
  "Call OPERATION with the ifindex of the interface the guards attach to. When
   CONFIGURATION names a host policy interface (the routed agent's host veth),
   resolve it on the host; otherwise enter CONTEXT's Pod namespace via
   CALL-IN-NETNS and resolve CONTEXT's Pod interface there."
  ;; The routed agent sets this internal field from its host veth identity.
  ;; Chained callers still select their Pod interface inside its namespace.
  (let ((host-interface (cni-configuration-policy-interface-name configuration)))
    (if host-interface
        (funcall operation (funcall interface-index host-interface))
        (funcall call-in-netns (cni-context-netns context)
                 (lambda ()
                   (funcall operation
                            (funcall interface-index (cni-context-interface-name context))))))))

(defun install-cni-policy (&rest arguments)
  "Install policy while excluding endpoint upgrades and CNI deletion."
  (bt:with-lock-held (*cni-policy-update-lock*)
    (apply #'%install-cni-policy arguments)))

(defun %install-cni-policy
    (configuration context map-path link-path
     &key (ensure-directory #'ensure-cni-pin-directory)
       (path-exists-p #'probe-file)
       (open-pinned #'whistler/loader:open-pinned-object)
       (validate-map #'cni-policy-map-info)
       (remove-path #'remove-cni-path)
       (open-object #'compile-egress-policy-object)
       (load-object #'load-egress-policy-object)
       (object-map #'egress-policy-object-find-map)
       (object-program #'egress-policy-object-find-program)
       (map-fd #'whistler/loader:map-info-fd)
       (program-fd #'whistler/loader:prog-info-fd)
       (initialize-identity #'initialize-cni-identity)
       (check-owner #'check-cni-service-nat-owner)
       (mark-receiver #'mark-cni-service-nat-receiver-ready)
       (pin-object #'whistler/loader:pin-bpf-object)
       (rename-pin #'uiop:rename-file-overwriting-target)
       (staged-links #'cni-policy-staged-links)
       (call-in-netns #'call-with-cni-network-namespace)
       (interface-index #'cni-interface-index)
       (attach-tcx (lambda (fd index direction)
                     (whistler/loader:attach-tcx fd index :direction direction)))
       (close-fd #'sb-posix:close)
       (close-object #'close-egress-policy-object))
  "Install, or re-converge, this Pod's egress and ingress guards and their BPF
   maps. Opens and validates any already-pinned maps, compiles and loads the
   Whistler object, seeds the endpoint-identity map, pins the maps, and attaches
   each TCX guard -- pinning each replacement link to a staging name and renaming
   it into place so the previous guard stays live until the new one is attached.
   On any failure, new pins and staged links are removed (a guard already renamed
   into place is kept, and its maps stay pinned). Idempotent; returns NIL. The
   keyword arguments inject every external operation for testing."
  (let ((directory (namestring (uiop:pathname-directory-pathname map-path)))
        (opened nil) (object nil) (new-pins nil) (link-fd nil)
        (packet-root (cni-configuration-service-packet-root configuration))
        (*cni-policy-profile* (or (cni-service-profile configuration) :v1))
        ;; A link pinned but not yet renamed into place.
        (staging nil)
        (committed nil))
    ;; A v2 endpoint is explicitly opted in by the CNI profile. Only native
    ;; routed ADD can supply the trusted node ID and private return lease;
    ;; the external chained CNI path has no v2 owner publication yet.
    (when (eq (cni-service-profile configuration) :v2)
      (unless (and (stringp (cni-configuration-service-node-id configuration))
                   (plusp (length (cni-configuration-service-node-id configuration)))
                   (stringp (cni-configuration-service-return-address configuration))
                   (plusp (length (cni-configuration-service-return-address configuration)))
                   (find-if-not (lambda (address) (find #\: address))
                                (cni-configuration-endpoint-addresses configuration)))
        (invalid-cni "v2 Service endpoint requires a trusted native owner and return lease"))
      (funcall check-owner configuration context
               (cni-configuration-endpoint-addresses configuration)
               (cni-configuration-service-return-address configuration)))
    (funcall ensure-directory directory)
    (unwind-protect
         (progn
           ;; Shared Service maps are never created privately or pinned under
           ;; an endpoint. An explicitly enabled but unavailable dataplane makes
           ;; ADD fail visibly instead of installing disconnected empty tables.
           (when packet-root
             (dolist (spec (cni-shared-service-map-specs configuration))
               (let* ((name (first spec))
                      (fd (funcall open-pinned
                                   (namestring (merge-pathnames name (uiop:ensure-directory-pathname packet-root))))))
                 (push (cons name fd) opened)
                 (funcall validate-map fd name))))
           (dolist (spec (cni-local-policy-map-specs configuration))
             (let* ((name (first spec)) (path (cni-policy-map-path map-path name)))
               (when (funcall path-exists-p path)
                 (let ((fd (funcall open-pinned path)))
                   (push (cons name fd) opened)
                   (funcall validate-map fd name)))))
           (let ((*cni-service-packets* (cni-service-profile configuration)))
             (setf object (funcall open-object (cni-configuration-program configuration))))
           (funcall load-object object opened)
           (dolist (spec (cni-local-policy-map-specs configuration))
             (let* ((name (first spec)) (map (funcall object-map object name)))
               (unless map (invalid-cni "Whistler object has no ~A map" name))
               (funcall validate-map (funcall map-fd map) name)))
           (funcall initialize-identity (funcall object-map object "endpoint_identity")
                    configuration context)
           (dolist (spec (cni-local-policy-map-specs configuration))
             (let* ((name (first spec)) (path (cni-policy-map-path map-path name)))
               (unless (assoc name opened :test #'string=)
                 (funcall pin-object (funcall map-fd (funcall object-map object name)) path)
                 (push path new-pins))))
           ;; The egress guard runs where Pod traffic leaves (the configured
           ;; direction), the ingress guard where traffic to the Pod arrives.
           (loop for (name direction path) in
                 (list (list "gr8s_egress_guard" (cni-configuration-direction configuration) link-path)
                       (list "gr8s_ingress_guard" (cni-opposite-direction (cni-configuration-direction configuration))
                             (cni-ingress-guard-link-path link-path (cni-configuration-direction configuration))))
                 for program = (funcall object-program object name)
                 ;; bpffs rejects pin basenames containing a dot (EPERM).
                 for stage = (format nil "~A_pending_~36R" path (random (expt 36 12)))
                 do (unless program (invalid-cni "Whistler object has no ~A program" name))
                    (setf link-fd (call-with-cni-policy-interface
                                   configuration context
                                   (lambda (index) (funcall attach-tcx (funcall program-fd program) index direction))
                                   call-in-netns interface-index))
                    ;; Keep the old pinned link live until a replacement is attached
                    ;; and pinned. Atomic rename also preserves it if pinning fails.
                    (funcall pin-object link-fd stage)
                    (setf staging stage)
                    (funcall rename-pin stage path)
                    (setf staging nil
                          ;; A pinned link uses the maps, so they stay pinned from here.
                          committed t)
                    (funcall close-fd link-fd)
                    (setf link-fd nil)
                    (dolist (old (funcall staged-links path)) (funcall remove-path old))))
           (when (eq (cni-service-profile configuration) :v2)
             (funcall mark-receiver configuration context
                      (cni-configuration-endpoint-addresses configuration)
                      (cni-configuration-service-return-address configuration)))
      (when link-fd (funcall close-fd link-fd))
      (let ((owned (when object
                     (loop for spec in (append (cni-local-policy-map-specs configuration)
                                              (cni-shared-service-map-specs configuration))
                           for map = (ignore-errors (funcall object-map object (first spec)))
                           when map collect (funcall map-fd map)))))
        (when object (funcall close-object object))
        (dolist (entry opened)
          (unless (member (cdr entry) owned) (funcall close-fd (cdr entry)))))
      (when staging (funcall remove-path staging))
      (unless committed
        (dolist (path new-pins) (funcall remove-path path)))))
  nil)

(defun check-cni-policy
    (configuration context map-path link-path
     &key (open-pinned #'whistler/loader:open-pinned-object)
       (validate-map #'cni-policy-map-info)
       (check-identity #'check-cni-identity)
       (check-link #'check-cni-tcx-link)
       (check-stages #'check-cni-service-stages)
       (path-exists-p #'probe-file)
       (staged-links #'cni-policy-staged-links)
       (close-fd #'sb-posix:close)
       (call-in-netns #'call-with-cni-network-namespace)
       (interface-index #'cni-interface-index))
  "Verify this Pod's installed policy: open and validate each pinned map
   (checking the endpoint identity on endpoint_identity), then confirm each
   guard's TCX link is attached on the expected interface in the expected
   direction. Signals through its check/validate operations on any discrepancy;
   returns NIL when consistent."
  (let ((*cni-policy-profile* (or (cni-service-profile configuration) :v1)))
  (dolist (path (cni-upgrade-block-paths map-path))
    (when (or (funcall path-exists-p path) (funcall staged-links path))
      (invalid-cni "endpoint packet program upgrade is incomplete")))
  (dolist (spec (cni-local-policy-map-specs configuration))
    (let* ((name (first spec))
           (fd (funcall open-pinned (cni-policy-map-path map-path name))))
      (unwind-protect
           (let ((map (funcall validate-map fd name)))
             (when (string= name "endpoint_identity")
               (funcall check-identity map configuration context))
             (when (member name '("gr8s_pkt_stages" "gr8s_nat_stages") :test #'equal)
               (funcall check-stages map)))
        (funcall close-fd fd))))
  (when (cni-configuration-service-packet-root configuration)
    (dolist (spec (cni-shared-service-map-specs configuration))
      (let* ((name (first spec))
             (fd (funcall open-pinned
                          (namestring (merge-pathnames
                                       name (uiop:ensure-directory-pathname
                                             (cni-configuration-service-packet-root configuration)))))))
        (unwind-protect (funcall validate-map fd name) (funcall close-fd fd)))))
  (let ((direction (cni-configuration-direction configuration)))
    (loop for (path link-direction) in (list (list link-path direction)
                                             (list (cni-ingress-guard-link-path link-path direction)
                                                   (cni-opposite-direction direction)))
          do (let ((fd (funcall open-pinned path)))
               (unwind-protect
                    (call-with-cni-policy-interface
                     configuration context
                     (lambda (index) (funcall check-link fd index link-direction))
                     call-in-netns interface-index)
                 (funcall close-fd fd)))))
  nil))

(defun remove-cni-policy (&rest arguments)
  "Delete policy while excluding CNI installation and retained program upgrades."
  (bt:with-lock-held (*cni-policy-update-lock*)
    (apply #'%remove-cni-policy arguments)))

(defun %remove-cni-policy
    (configuration context map-path link-path directory
     &key (remove-path #'remove-cni-path)
       (path-exists-p #'probe-file)
       (retire-link #'retire-cni-tcx-link)
       (staged-links #'cni-policy-staged-links)
       (remove-directory #'remove-empty-cni-directory))
  "Remove this Pod's policy: unpin both guard links and any staged leftovers,
   delete every policy map (current and legacy), and remove the now-empty
   directory. Tolerates missing files, derives the guard direction from LINK-PATH
   when CONFIGURATION is NIL, and returns NIL."
  (declare (ignore context))
  (dolist (link (list link-path (cni-ingress-guard-link-path
                                 link-path (if configuration (cni-configuration-direction configuration)
                                               (subseq (file-namestring link-path) (length "tcx-"))))))
    ;; Retire staged entries first so removing the canonical guard cannot
    ;; expose an older pending program to fresh packets.
    (dolist (path (funcall staged-links link))
      (when (funcall path-exists-p path) (funcall retire-link path))
      (funcall remove-path path))
    (when (funcall path-exists-p link) (funcall retire-link link))
    (funcall remove-path link))
  (dolist (name (remove-duplicates
                 (append (mapcar #'first +cni-policy-map-specs+)
                         (mapcar #'first (service-nat-local-map-specs))
                         '("gr8s_pkt_stages") +cni-legacy-policy-maps+)
                 :test #'equal))
    (funcall remove-path (cni-policy-map-path map-path name)))
  ;; Keep blockers until all ordinary policy/map pins have been retired.
  (dolist (path (cni-upgrade-block-paths map-path))
    (dolist (stage (funcall staged-links path))
      (when (funcall path-exists-p stage) (funcall retire-link stage))
      (funcall remove-path stage))
    (when (funcall path-exists-p path) (funcall retire-link path))
    (funcall remove-path path))
  (funcall remove-directory directory)
  nil)

(defun check-cni-status (configuration)
  "Signal a CNI-ERROR unless CONFIGURATION's Whistler map pin root exists and is
   a directory; otherwise returns NIL."
  (let ((root (probe-file (cni-configuration-map-pin-root configuration))))
    (unless (and root (uiop:directory-pathname-p root))
      (invalid-cni "Whistler map pin root is unavailable")))
  nil)

(defun write-cni-json (object output)
  "Write OBJECT as JSON to OUTPUT followed by a newline, and flush."
  (com.inuoe.jzon:stringify object :stream output)
  (terpri output)
  (finish-output output))

(defun cni-error-result
    (message &optional (version "1.1.0") (code 100) (details ""))
  "Build a CNI error result object (cniVersion, code, msg, details) reporting
   MESSAGE. CODE defaults to 100."
  (json-object "cniVersion" version
               "code" code
               "msg" message
               "details" details))

(defun cni-agent-socket-path (configuration-text)
  "Parse CONFIGURATION-TEXT (JSON) and return its \"socket\" as an absolute path
   -- the Unix socket of the node agent to relay to. Signals a CNI-ERROR on
   invalid JSON, a non-object, or a missing/relative socket."
  (let ((configuration
          (handler-case
              (com.inuoe.jzon:parse configuration-text)
            (error (condition)
              (invalid-cni "invalid network configuration: ~A" condition)))))
    (unless (hash-table-p configuration)
      (invalid-cni "network configuration must be a JSON object"))
    (absolute-cni-path configuration "socket")))

(defun cni-request-from-environment (command configuration-text environment)
  "Build the node-agent CNI-REQUEST for COMMAND from CONFIGURATION-TEXT and the
   CNI_* variables read through ENVIRONMENT (each absent variable becomes \"\")."
  (make-instance
   'gr8s.node.v1::cni-request
   :protocol-version +node-protocol-version+
   :command command
   :network-configuration
   (trivial-utf-8:string-to-utf-8-bytes configuration-text)
   :container-id (or (funcall environment "CNI_CONTAINERID") "")
   :network-namespace (or (funcall environment "CNI_NETNS") "")
   :interface-name (or (funcall environment "CNI_IFNAME") "")
   :arguments (or (funcall environment "CNI_ARGS") "")
   :plugin-path (or (funcall environment "CNI_PATH") "")))

(defun write-agent-cni-result (response output)
  "Render the agent's RESPONSE to OUTPUT and return the process exit code: 0,
   writing the result JSON, on success; 1, writing a CNI error object, on
   failure. Signals when RESPONSE's protocol version is unsupported."
  (ensure-node-protocol-version
   (slot-value response 'gr8s.node.v1::protocol-version))
  (if (slot-value response 'gr8s.node.v1::success)
      (let ((result (slot-value response 'gr8s.node.v1::result-json)))
        (when (plusp (length result))
          (write-string (trivial-utf-8:utf-8-bytes-to-string result) output)
          (terpri output)
          (finish-output output))
        0)
      (progn
        (write-cni-json
         (cni-error-result
          (slot-value response 'gr8s.node.v1::error-message)
          "1.1.0"
          (let ((code (slot-value response 'gr8s.node.v1::error-code)))
            (if (zerop code) 100 code))
          (slot-value response 'gr8s.node.v1::error-details))
         output)
        1)))

(defun cni-main (&key (input *standard-input*)
                      (output *standard-output*)
                      (environment #'uiop:getenv)
                      (agent-call #'call-agent-cni)
                      (timeout 5))
  "The `gr8s` CNI binary entry point. Reads CNI_COMMAND and the configuration
   from INPUT, answers VERSION locally, and otherwise relays the request to the
   node agent at the configuration's socket via AGENT-CALL, writing the result to
   OUTPUT. Returns the process exit code; any error is reported as a CNI error
   object (code 100) with exit 1."
  (handler-case
      (let* ((command (or (funcall environment "CNI_COMMAND")
                          (invalid-cni "CNI_COMMAND is required")))
             (configuration-text (uiop:slurp-stream-string input)))
        (if (string= command "VERSION")
            (progn
              (write-cni-json (cni-version-result) output)
              0)
            (write-agent-cni-result
             (funcall agent-call
                      (cni-agent-socket-path configuration-text)
                      (cni-request-from-environment
                       command configuration-text environment)
                      :timeout timeout)
             output)))
    (error (condition)
      (write-cni-json (cni-error-result (princ-to-string condition)) output)
      1)))
