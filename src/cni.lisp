(in-package #:gr8s)

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
  (error 'cni-error :message (apply #'format nil control arguments)))

(defparameter +cni-policy-map-specs+
  ;; (name bpf-map-type key-size value-size max-entries flags). Types: 1=HASH,
  ;; 2=ARRAY, 11=LPM_TRIE. The netpol_* maps hold the per-Pod NetworkPolicy and
  ;; are updated as data by the agent (no program recompile).
  '(("rejected_spoofs"     2 4 8  1    0)
    ("endpoint_identity"   2 4 16 1    128)
    ("traffic_stats"       2 4 8  7    0)
    ("netpol_egress_mode"  2 4 4  1    0)
    ("netpol_egress_cidr" 11 8 4  1024 1)
    ("netpol_egress_port"  1 8 1  1024 0)
    ;; Same-node Pod delivery table: dest Pod IPv4 (network order) -> 16-byte
    ;; {ifindex, Pod MAC, veth MAC}. Agent-populated on reconcile. HASH.
    ("local_pod_v4"        1 4 16 4096 0)))

(defstruct cni-configuration
  version name type direction program map-pin-root previous-result endpoint-address policy-interface-name)

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
  (let ((value (gethash key object)))
    (unless (and (stringp value) (plusp (length value)))
      (invalid-cni "network configuration requires ~A" key))
    value))

(defun absolute-cni-path (object key)
  (let ((value (required-cni-string object key)))
    (unless (uiop:absolute-pathname-p (pathname value))
      (invalid-cni "~A must be an absolute path" key))
    value))

(defun parse-cni-configuration (text &key require-previous)
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
      (make-cni-configuration
       :version (required-cni-string object "cniVersion")
       :name (gethash "name" object "gr8s")
       :type (gethash "type" object "gr8s")
       :direction direction
       ;; The egress guard is JIT-compiled in-process; a "program" ELF path, if
       ;; present in an older conflist, is accepted and ignored.
       :program (gethash "program" object)
       :map-pin-root (absolute-cni-path object "mapPinRoot")
       :previous-result previous))))

(defun safe-cni-container-id-p (container-id)
  (and (stringp container-id)
       (plusp (length container-id))
       (not (member container-id '("." "..") :test #'string=))
       (every (lambda (character)
                (or (alphanumericp character)
                    (find character "-_.")))
              container-id)))

(defun cni-pin-paths (root container-id &optional (direction "egress"))
  (unless (safe-cni-container-id-p container-id)
    (invalid-cni "container ID ~S is unsafe for a BPF pin" container-id))
  (let ((directory
          (format nil "~A/~A/" (string-right-trim "/" root) container-id)))
    (values (concatenate 'string directory "rejected_spoofs")
            (concatenate 'string directory "tcx-" direction)
            directory)))

(defun cni-version-result ()
  (json-object "cniVersion" "1.1.0"
               "supportedVersions" #( "0.4.0" "1.0.0" "1.1.0")))

(defun require-cni-context (context &key network-namespace)
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

(defun ensure-cni-pin-directory (directory)
  (ensure-directories-exist (merge-pathnames ".pin" (pathname directory)))
  directory)

(defun remove-cni-path (path)
  (handler-case (delete-file path)
    (file-error () nil))
  nil)

(defun remove-empty-cni-directory (directory)
  (handler-case (sb-posix:rmdir directory)
    (sb-posix:syscall-error () nil))
  nil)

(defun call-with-cni-network-namespace (path operation)
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
  #+sbcl (%linux-if-nametoindex name)
  #-sbcl (declare (ignore name))
  #-sbcl 0)

(defun cni-interface-index (name &key (resolver #'native-interface-index))
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
  ;; The routed agent sets this internal field from its host veth identity.
  ;; Chained callers still select their Pod interface inside its namespace.
  (let ((host-interface (cni-configuration-policy-interface-name configuration)))
    (if host-interface
        (funcall operation (funcall interface-index host-interface))
        (funcall call-in-netns (cni-context-netns context)
                 (lambda ()
                   (funcall operation
                            (funcall interface-index (cni-context-interface-name context))))))))

(defun install-cni-policy
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
       (pin-object #'whistler/loader:pin-bpf-object)
       (rename-pin #'uiop:rename-file-overwriting-target)
       (staged-links #'cni-policy-staged-links)
       (call-in-netns #'call-with-cni-network-namespace)
       (interface-index #'cni-interface-index)
       (attach-tcx (lambda (fd index direction)
                     (whistler/loader:attach-tcx fd index :direction direction)))
       (close-fd #'sb-posix:close)
       (close-object #'close-egress-policy-object))
  (let ((directory (namestring (uiop:pathname-directory-pathname map-path)))
        (opened nil) (object nil) (new-pins nil) (link-fd nil)
        ;; bpffs rejects pin basenames containing a dot (EPERM).
        (staging (format nil "~A_pending_~36R" link-path (random (expt 36 12))))
        (committed nil))
    (funcall ensure-directory directory)
    (unwind-protect
         (progn
           (dolist (spec +cni-policy-map-specs+)
             (let* ((name (first spec)) (path (cni-policy-map-path map-path name)))
               (when (funcall path-exists-p path)
                 (let ((fd (funcall open-pinned path)))
                   (push (cons name fd) opened)
                   (funcall validate-map fd name)))))
           (setf object (funcall open-object (cni-configuration-program configuration)))
           (funcall load-object object opened)
           (dolist (spec +cni-policy-map-specs+)
             (let* ((name (first spec)) (map (funcall object-map object name)))
               (unless map (invalid-cni "Whistler object has no ~A map" name))
               (funcall validate-map (funcall map-fd map) name)))
           (funcall initialize-identity (funcall object-map object "endpoint_identity")
                    configuration context)
           (dolist (spec +cni-policy-map-specs+)
             (let* ((name (first spec)) (path (cni-policy-map-path map-path name)))
               (unless (assoc name opened :test #'string=)
                 (funcall pin-object (funcall map-fd (funcall object-map object name)) path)
                 (push path new-pins))))
           (let ((program (funcall object-program object "gr8s_egress_guard")))
             (unless program (invalid-cni "Whistler object has no gr8s_egress_guard program"))
             (setf link-fd
                   (call-with-cni-policy-interface
                    configuration context
                    (lambda (index)
                      (funcall attach-tcx (funcall program-fd program) index
                               (cni-configuration-direction configuration)))
                    call-in-netns interface-index))
             ;; Keep the old pinned link live until a replacement is attached
             ;; and pinned. Atomic rename also preserves it if pinning fails.
             (funcall pin-object link-fd staging)
             (funcall rename-pin staging link-path)
             (setf committed t)
             (dolist (old (funcall staged-links link-path)) (funcall remove-path old))))
      (when link-fd (funcall close-fd link-fd))
      (let ((owned (when object
                     (loop for spec in +cni-policy-map-specs+
                           for map = (ignore-errors (funcall object-map object (first spec)))
                           when map collect (funcall map-fd map)))))
        (when object (funcall close-object object))
        (dolist (entry opened)
          (unless (member (cdr entry) owned) (funcall close-fd (cdr entry)))))
      (unless committed
        (funcall remove-path staging)
        (dolist (path new-pins) (funcall remove-path path)))))
  nil)

(defun check-cni-policy
    (configuration context map-path link-path
     &key (open-pinned #'whistler/loader:open-pinned-object)
       (validate-map #'cni-policy-map-info)
       (check-identity #'check-cni-identity)
       (check-link #'check-cni-tcx-link)
       (close-fd #'sb-posix:close)
       (call-in-netns #'call-with-cni-network-namespace)
       (interface-index #'cni-interface-index))
  (dolist (spec +cni-policy-map-specs+)
    (let* ((name (first spec))
           (fd (funcall open-pinned (cni-policy-map-path map-path name))))
      (unwind-protect
           (let ((map (funcall validate-map fd name)))
             (when (string= name "endpoint_identity")
               (funcall check-identity map configuration context)))
        (funcall close-fd fd))))
  (let ((fd (funcall open-pinned link-path)))
    (unwind-protect
         (call-with-cni-policy-interface
          configuration context
          (lambda (index)
            (funcall check-link fd index (cni-configuration-direction configuration)))
          call-in-netns interface-index)
      (funcall close-fd fd)))
  nil)

(defun remove-cni-policy
    (configuration context map-path link-path directory
     &key (remove-path #'remove-cni-path)
       (staged-links #'cni-policy-staged-links)
       (remove-directory #'remove-empty-cni-directory))
  (declare (ignore configuration context))
  (funcall remove-path link-path)
  (dolist (path (funcall staged-links link-path)) (funcall remove-path path))
  (dolist (spec +cni-policy-map-specs+)
    (funcall remove-path (cni-policy-map-path map-path (first spec))))
  (funcall remove-directory directory)
  nil)

(defun check-cni-status (configuration)
  (let ((root (probe-file (cni-configuration-map-pin-root configuration))))
    (unless (and root (uiop:directory-pathname-p root))
      (invalid-cni "Whistler map pin root is unavailable")))
  nil)

(defun write-cni-json (object output)
  (com.inuoe.jzon:stringify object :stream output)
  (terpri output)
  (finish-output output))

(defun cni-error-result
    (message &optional (version "1.1.0") (code 100) (details ""))
  (json-object "cniVersion" version
               "code" code
               "msg" message
               "details" details))

(defun cni-agent-socket-path (configuration-text)
  (let ((configuration
          (handler-case
              (com.inuoe.jzon:parse configuration-text)
            (error (condition)
              (invalid-cni "invalid network configuration: ~A" condition)))))
    (unless (hash-table-p configuration)
      (invalid-cni "network configuration must be a JSON object"))
    (absolute-cni-path configuration "socket")))

(defun cni-request-from-environment (command configuration-text environment)
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
