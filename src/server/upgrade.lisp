;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; `gr8s upgrade': roll a cluster onto a signed gr8s release (podster-igs).
;;;;   plan      what would happen, and why it is safe or not; changes nothing
;;;;   apply     do it, host by host, recording each step in a ClusterUpgrade
;;;;   status    the latest ClusterUpgrade
;;;;   rollback  each host back to the release it ran before
;;;;   finalize  let the cluster use the release's formats, once every member runs it
;;;;   self      upgrade this host, as root, without the cluster
;;;;   publish   push release packages as a signed artifact (the release workflow)
;;;;   mirror    copy a release to another registry, as for an air-gapped cluster
;;;;
;;;; This command drives the rollout, not a controller: the leader restarts in the
;;;; middle of it, so the driver must be outside the cluster. It records progress in
;;;; a ClusterUpgrade, a custom resource every gr8s release can store, so `apply'
;;;; picks up where it stopped. Every host is sent the release by digest, checked
;;;; here first against the release keys this gr8s carries.

(in-package #:gr8s.server)

(defparameter +default-release-repository+ "ghcr.io/atgreen/gr8s-packages"
  "Where gr8s releases are published, and `--to VERSION' looks for them.")

(defparameter *upgrade-host-wait-seconds* 900
  "How long `apply' waits for a host to come back on the new release.")

(defparameter +cluster-version-config-map+ '("kube-system" "gr8s-cluster-version")
  "The ConfigMap holding the cluster's format level, which `finalize' raises.")

;;; Options.

(defun parse-upgrade-options (arguments)
  "Parse `gr8s upgrade SUBCOMMAND [OPTIONS] [FILES]'."
  (let* ((action (if (or (null arguments) (uiop:string-prefix-p "--" (first arguments)))
                     (progn (push "plan" arguments) "plan")
                     (first arguments)))
         (command (cdr (assoc action '(("plan" . :upgrade-plan) ("apply" . :upgrade-apply)
                                       ("status" . :upgrade-status) ("rollback" . :upgrade-rollback)
                                       ("finalize" . :upgrade-finalize) ("self" . :upgrade-self)
                                       ("publish" . :upgrade-publish) ("mirror" . :upgrade-mirror))
                              :test #'equal)))
         (options (list :command command :kubeconfig (default-client-kubeconfig)
                        :repository +default-release-repository+ :files nil))
         (arguments (rest arguments)))
    (unless command (error "unknown upgrade command: ~A" action))
    (loop while arguments
          for option = (pop arguments)
          do (flet ((value () (or (pop arguments) (error "~A requires a value" option))))
               (cond
                 ((string= option "--to") (setf (getf options :to) (value)))
                 ((string= option "--from") (setf (getf options :from) (value)))
                 ((string= option "--repository") (setf (getf options :repository) (value)))
                 ((string= option "--kubeconfig") (setf (getf options :kubeconfig) (value)))
                 ((string= option "--version") (setf (getf options :version) (value)))
                 ((string= option "--key-file") (setf (getf options :key-file) (value)))
                 ((string= option "--registry-ca")
                  (let* ((value (value)) (separator (position #\= value)))
                    (unless separator (error "--registry-ca needs HOST[:PORT]=FILE"))
                    (setf (getf options :registry-cas)
                          (add-registry-ca (getf options :registry-cas) value))))
                 ((string= option "--yes") (setf (getf options :yes) t))
                 ((string= option "--allow-quorum-loss") (setf (getf options :allow-quorum-loss) t))
                 ((string= option "--allow-downgrade") (setf (getf options :allow-downgrade) t))
                 ((string= option "--no-finalize") (setf (getf options :no-finalize) t))
                 ((uiop:string-prefix-p "--" option) (error "unknown upgrade option: ~A" option))
                 ((eq command :upgrade-publish) (push option (getf options :files)))
                 (t (error "unexpected argument: ~A" option)))))
    (setf (getf options :files) (reverse (getf options :files)))
    (when (and (member command '(:upgrade-plan :upgrade-apply :upgrade-self :upgrade-publish))
               (null (getf options :to)))
      (error "upgrade ~A needs --to VERSION (or --to REGISTRY/REPOSITORY:TAG)" action))
    options))

(defun release-reference (options &optional (to (getf options :to)))
  "The artifact reference --to names: as given when it names a registry, else the
release of that version in --repository."
  (if (find #\/ to) to (format nil "~A:~A" (getf options :repository) to)))

(defun call-with-upgrade-registry (options function)
  "Call FUNCTION trusting each --registry-ca, with the registry credentials, if any,
in GR8S_REGISTRY_USERNAME and GR8S_REGISTRY_PASSWORD."
  (let ((gr8s.image-distribution::*registry-ca-files*
          (append (getf options :registry-cas) gr8s.image-distribution::*registry-ca-files*)))
    (funcall function (uiop:getenv "GR8S_REGISTRY_USERNAME") (uiop:getenv "GR8S_REGISTRY_PASSWORD"))))

;;; publish, mirror, self.

(defun run-upgrade-publish-command (options &optional (output *standard-output*))
  "Push --to's release from the package files given, signed with --key-file or
GR8S_RELEASE_SIGNING_KEY."
  (let* ((reference (release-reference options))
         (key-text (if (getf options :key-file)
                       (uiop:read-file-string (getf options :key-file))
                       (or (uiop:getenv "GR8S_RELEASE_SIGNING_KEY")
                           (error "publish needs a signing key: --key-file PATH or GR8S_RELEASE_SIGNING_KEY"))))
         (key (gr8s.upgrade:read-release-signing-key key-text))
         (version (or (getf options :version) (nth-value 2 (gr8s.upgrade:parse-artifact-reference reference)))))
    (unless (getf options :files) (error "publish needs the package files to publish"))
    (call-with-upgrade-registry
     options
     (lambda (username password)
       (let ((digest (gr8s.upgrade:publish-release-artifact reference version (getf options :files) key
                                                            :username username :password password)))
         (format output "published ~A as ~A@~A, signed by release key ~A~%"
                 version reference digest (gr8s.upgrade:release-key-id key))
         0)))))

(defun run-upgrade-mirror-command (options &optional (output *standard-output*))
  "Copy the release --from names to --to, by digest."
  (unless (and (getf options :from) (getf options :to))
    (error "mirror needs --from REGISTRY/REPOSITORY:TAG and --to REGISTRY/REPOSITORY:TAG"))
  (call-with-upgrade-registry
   options
   (lambda (username password)
     (let ((digest (gr8s.upgrade:mirror-release-artifact (release-reference options (getf options :from))
                                                         (release-reference options (getf options :to))
                                                         :username username :password password)))
       (format output "mirrored ~A to ~A@~A~%" (getf options :from) (getf options :to) digest)
       0))))

(defun run-upgrade-self-command (options &optional (output *standard-output*))
  "Upgrade this host to --to's release, without the cluster: for a host the cluster
can't reach, or one too old to be upgraded through it."
  (unless (zerop (sb-posix:geteuid)) (error "upgrade self installs a package: run it as root"))
  (call-with-upgrade-registry
   options
   (lambda (username password)
     ;; The gr8s the services run, wherever this command runs from.
     (let* ((program (gr8s.upgrade:installed-gr8s-program))
            (prepared (gr8s.upgrade:prepare-host-upgrade (release-reference options)
                                                         :format (gr8s.upgrade:host-package-format program)
                                                         :username username :password password)))
       (format output "release ~A verified; installing its ~A package over ~A~%"
               (getf prepared :version) (getf prepared :format) program)
       (finish-output output)
       ;; Run here, not as a transient unit: this command isn't the service it restarts.
       (format output "~A" (gr8s.upgrade:install-host-upgrade prepared :unit nil :program program))
       (when (equal "binary" (getf prepared :format))
         ;; A package restarts the services itself; a bare executable doesn't.
         (uiop:run-program '("systemctl" "try-restart" "gr8s-server.service" "gr8s-agent.service")
                           :ignore-error-status t))
       (let ((installed (gr8s.upgrade:installed-program-version program)))
         (unless (equal installed (getf prepared :version))
           (error "~A still reports ~A after installing ~A" program installed (getf prepared :version)))
         (format output "~A is ~A~%" program installed))
       0))))

;;; Talking to the cluster through whichever member answers.

(defstruct (upgrade-api (:constructor make-upgrade-api (config)))
  "The cluster API as `apply' reaches it: the kubeconfig's server, and each member's
API, so that while one member restarts another answers."
  config (members nil))

(defun member-api-config (config api-url)
  (let ((member (copy-list config)))
    (setf (getf member :server) api-url)
    member))

(defun upgrade-api-call (api method target &key body avoid prefer (pass-statuses '()))
  "Send METHOD to TARGET through the first member that answers, the member named
PREFER first, never the one named AVOID; return (values body status headers). A member
that answers with one of PASS-STATUSES passes the request on to the next: during a
rollback, a member already on an older release doesn't know every route."
  (let* ((avoided (cdr (assoc avoid (upgrade-api-members api) :test #'equal)))
         (preferred (cdr (assoc prefer (upgrade-api-members api) :test #'equal)))
         (configs (remove-duplicates
                   (remove (and avoided (getf avoided :server))
                           (append (and preferred (list preferred))
                                   (list (upgrade-api-config api)) (mapcar #'cdr (upgrade-api-members api)))
                           :key (lambda (config) (getf config :server)) :test #'equal)
                   :key (lambda (config) (getf config :server)) :test #'equal :from-end t))
         (failure nil) (passed nil))
    (dolist (config configs (if passed
                                (values-list passed)
                                (error "no control-plane member answered ~A ~A: ~A" method target failure)))
      (handler-case
          (let ((answer (multiple-value-list (debug-api-request-json config method target :body body))))
            (if (member (second answer) pass-statuses)
                (setf passed answer)
                (return (values-list answer))))
        (error (condition) (setf failure condition))))))

(defun json-path (object &rest keys)
  (loop for key in keys
        while (hash-table-p object)
        do (setf object (gethash key object))
        finally (return object)))

(defun node-ready-p (node)
  (loop for condition across (or (json-path node "status" "conditions") #())
        thereis (and (equal "Ready" (gethash "type" condition)) (equal "True" (gethash "status" condition)))))

(defun node-internal-ip (node)
  (loop for address across (or (json-path node "status" "addresses") #())
        when (equal "InternalIP" (gethash "type" address)) return (gethash "address" address)))

(defun url-host (url)
  (ignore-errors (puri:uri-host (puri:parse-uri url))))

(defun member-version (config api-url)
  "What the member at API-URL says of itself: (values version format-level), or NIL."
  (multiple-value-bind (body status) (ignore-errors (debug-api-request-json (member-api-config config api-url) "GET" "/version"))
    (when (eql status 200)
      (values (gethash "gitVersion" body) (gethash "gr8sFormatLevel" body 1)))))

(defun gather-upgrade-hosts (api)
  "Every host of the cluster, as GR8S.UPGRADE:PLAN-CLUSTER-UPGRADE takes them, with
:node, its Node, :api-url, a member's API, and :format-level."
  (multiple-value-bind (nodes status) (upgrade-api-call api "GET" "/api/v1/nodes")
    (unless (eql status 200) (error "listing nodes failed: HTTP ~A" status))
    (let ((nodes (coerce (gethash "items" nodes #()) 'list))
          (members (multiple-value-bind (body status) (upgrade-api-call api "GET" "/apis/gr8s.io/v1/controlplanemembers")
                     (when (eql status 200) body))))
      ;; Contact is the leader's to know: ask it when another member answered.
      (when (and members (some (lambda (item) (equal "unknown" (json-path item "status" "contact")))
                               (coerce (gethash "items" members #()) 'list)))
        (let* ((leader (gethash "leader" members))
               (item (find leader (coerce (gethash "items" members #()) 'list)
                           :key (lambda (item) (json-path item "metadata" "name")) :test #'equal))
               (url (and item (json-path item "spec" "apiURL"))))
          (when url
            (multiple-value-bind (body status)
                (ignore-errors (debug-api-request-json (member-api-config (upgrade-api-config api) url)
                                                       "GET" "/apis/gr8s.io/v1/controlplanemembers"))
              (when (eql status 200) (setf members body))))))
      (let ((member-items (and members (coerce (gethash "items" members #()) 'list)))
            (claimed nil) (hosts nil))
        (setf (upgrade-api-members api)
              (loop for item in member-items
                    for url = (json-path item "spec" "apiURL")
                    when url collect (cons (json-path item "metadata" "name")
                                           (member-api-config (upgrade-api-config api) url))))
        (dolist (item member-items)
          (let* ((name (json-path item "metadata" "name"))
                 (url (json-path item "spec" "apiURL"))
                 (node (or (find name nodes :key (lambda (node) (json-path node "metadata" "name")) :test #'equal)
                           (and url (find (url-host url) nodes :key #'node-internal-ip :test #'equal)))))
            (when node (push node claimed))
            (multiple-value-bind (version level) (and url (member-version (upgrade-api-config api) url))
              (push (list :name name :role (json-path item "spec" "role")
                          :leader (eq t (json-path item "status" "leader"))
                          :contact (json-path item "status" "contact")
                          :ready (if node (node-ready-p node) t)
                          :version version :format-level level :api-url url
                          :node (and node (json-path node "metadata" "name"))
                          :architecture (and node (json-path node "status" "nodeInfo" "architecture")))
                    hosts))))
        (dolist (node nodes)
          (unless (member node claimed)
            (push (list :name (json-path node "metadata" "name") :ready (node-ready-p node)
                        :version (json-path node "status" "nodeInfo" "kubeletVersion")
                        :node (json-path node "metadata" "name")
                        :architecture (json-path node "status" "nodeInfo" "architecture"))
                  hosts)))
        (nreverse hosts)))))

;;; The plan.

(defun upgrade-step-text (step reference)
  (let ((transfer (getf step :transfer-to)))
    (ecase (getf step :action)
      (:skip "nothing: it runs the release")
      (:upgrade (if transfer (format nil "hand the leadership to ~A, then upgrade" transfer) "upgrade"))
      (:manual (format nil "~A; on its host: sudo gr8s upgrade self --to ~A" (getf step :reason) reference))
      (:on-reconnect "upgrade when its node returns"))))

(defun print-upgrade-plan (hosts steps problems artifact reference output)
  (format output "Target  ~A  ~A  (signature verified)~%~%"
          (gr8s.upgrade:release-artifact-version artifact) reference)
  (format output "~16A ~9A ~24A ~A~%" "HOST" "ROLE" "NOW" "STEP")
  (loop for step in steps
        for host = (find (getf step :host) hosts :key (lambda (host) (getf host :name)) :test #'equal)
        do (format output "~16A ~9A ~24A ~A~%" (getf step :host)
                   (cond ((getf host :leader) "leader") ((getf host :role)) (t "agent"))
                   (or (getf host :version) "-")
                   (upgrade-step-text step reference)))
  (when problems
    (format output "~%Not safe to start:~%~{  - ~A~%~}" problems))
  (finish-output output))

(defun plan-against-cluster (options api)
  "Fetch and verify the release; gather the cluster; plan. Return (values artifact
pinned-reference hosts steps problems)."
  (let* ((reference (release-reference options))
         (artifact (call-with-upgrade-registry
                    options (lambda (username password)
                              (gr8s.upgrade:fetch-release-artifact reference :username username :password password))))
         (target (gr8s.upgrade:release-artifact-version artifact))
         (pinned (format nil "~A@~A" (subseq reference 0 (position #\: reference :from-end t))
                         (gr8s.upgrade:release-artifact-digest artifact)))
         (hosts (gather-upgrade-hosts api)))
    (multiple-value-bind (steps problems)
        (gr8s.upgrade:plan-cluster-upgrade hosts target :allow-quorum-loss (getf options :allow-quorum-loss)
                                                        :allow-downgrade (getf options :allow-downgrade))
      (dolist (host hosts)
        (let ((architecture (getf host :architecture)))
          (when (and architecture
                     (notany (lambda (package) (equal architecture (getf package :architecture)))
                             (gr8s.upgrade:release-artifact-packages artifact)))
            (push (format nil "~A is ~A, and ~A has no package for it" (getf host :name) architecture target) problems))))
      (values artifact pinned hosts steps problems))))

(defun run-upgrade-plan-command (options &optional (output *standard-output*))
  "Print what `apply' would do; exit 2 when it would refuse."
  (call-with-debug-kubeconfig
   (getf options :kubeconfig)
   (lambda (config)
     (multiple-value-bind (artifact pinned hosts steps problems) (plan-against-cluster options (make-upgrade-api config))
       (print-upgrade-plan hosts steps problems artifact pinned output)
       (if problems 2 0)))))

;;; The ClusterUpgrade record.

(defparameter +cluster-upgrade-path+ "/apis/upgrade.gr8s.io/v1/clusterupgrades")

(defun cluster-upgrade-crd ()
  "The ClusterUpgrade custom resource. A custom resource, not a built-in kind: every
gr8s release stores custom resources, so a member not yet upgraded keeps working."
  (core-object
   "apiVersion" "apiextensions.k8s.io/v1" "kind" "CustomResourceDefinition"
   "metadata" (core-object "name" "clusterupgrades.upgrade.gr8s.io")
   "spec" (core-object
           "group" "upgrade.gr8s.io" "scope" "Cluster"
           "names" (core-object "kind" "ClusterUpgrade" "listKind" "ClusterUpgradeList"
                                "plural" "clusterupgrades" "singular" "clusterupgrade")
           "versions" (vector
                       (core-object
                        "name" "v1" "served" t "storage" t
                        "additionalPrinterColumns"
                        (vector (core-object "name" "Target" "type" "string" "jsonPath" ".spec.target")
                                (core-object "name" "Phase" "type" "string" "jsonPath" ".status.phase"))
                        "schema" (core-object
                                  "openAPIV3Schema"
                                  (core-object "type" "object" "x-kubernetes-preserve-unknown-fields" t)))))))

(defun ensure-cluster-upgrade-crd (api)
  (multiple-value-bind (body status)
      (upgrade-api-call api "GET" "/apis/apiextensions.k8s.io/v1/customresourcedefinitions/clusterupgrades.upgrade.gr8s.io")
    (declare (ignore body))
    (unless (eql status 200)
      (multiple-value-bind (body status)
          (upgrade-api-call api "POST" "/apis/apiextensions.k8s.io/v1/customresourcedefinitions" :body (cluster-upgrade-crd))
        (unless (member status '(200 201 409))
          (error "creating the ClusterUpgrade resource failed: ~A" (member-api-error-message body status))))
      (loop repeat 50
            until (eql 200 (nth-value 1 (ignore-errors (upgrade-api-call api "GET" +cluster-upgrade-path+))))
            do (sleep 0.2)))))

(defun load-cluster-upgrade (api name)
  (multiple-value-bind (body status) (upgrade-api-call api "GET" (format nil "~A/~A" +cluster-upgrade-path+ name))
    (and (eql status 200) body)))

(defun save-cluster-upgrade (api record)
  "Store RECORD, creating it the first time; a member restarting just now is no
reason to stop, so a failure is only reported."
  (let ((name (json-path record "metadata" "name")))
    (handler-case
        (multiple-value-bind (body status)
            (if (json-path record "metadata" "resourceVersion")
                (upgrade-api-call api "PUT" (format nil "~A/~A" +cluster-upgrade-path+ name) :body record)
                (upgrade-api-call api "POST" +cluster-upgrade-path+ :body record))
          (if (member status '(200 201))
              (setf (gethash "metadata" record) (gethash "metadata" body))
              (format *error-output* "gr8s: recording the upgrade failed: ~A~%" (member-api-error-message body status))))
      (error (condition) (format *error-output* "gr8s: recording the upgrade failed: ~A~%" condition)))
    record))

(defun cluster-upgrade-host (record name)
  (find name (json-path record "status" "hosts") :key (lambda (host) (gethash "name" host)) :test #'equal))

(defun note-host-state (api record name state &optional (message ""))
  (let ((host (cluster-upgrade-host record name)))
    (setf (gethash "state" host) state
          (gethash "message" host) message
          (gethash "updatedAt" host) (gr8s.store::current-timestamp)))
  (save-cluster-upgrade api record))

;;; Applying.

(defun await-host-on-release (api host target)
  "Wait until HOST runs TARGET and is back: its node Ready, a member in contact."
  (let ((deadline (+ (get-universal-time) *upgrade-host-wait-seconds*)))
    (loop
      (let ((current (ignore-errors
                      (find (getf host :name) (gather-upgrade-hosts api)
                            :key (lambda (host) (getf host :name)) :test #'equal))))
        (when (and current (equal target (getf current :version)) (getf current :ready)
                   (or (null (getf current :role)) (member (getf current :contact) '("self" "in-contact") :test #'equal)))
          (return t)))
      (when (> (get-universal-time) deadline)
        (error "~A did not come back on ~A within ~D seconds" (getf host :name) target *upgrade-host-wait-seconds*))
      (sleep 5))))

(defun upgrade-one-host (api host target reference output)
  "Have HOST install REFERENCE, and wait for it to run TARGET."
  (multiple-value-bind (body status)
      (upgrade-api-call api "POST"
                        (format nil "/apis/gr8s.io/v1/~:[nodes~;controlplanemembers~]/~A/upgrade"
                                (getf host :role) (if (getf host :role) (getf host :name) (getf host :node)))
                        :body (core-object "reference" reference)
                        ;; A member upgrades itself: it runs the release that knows how,
                        ;; and answers before it restarts.
                        :prefer (and (getf host :role) (getf host :name))
                        :pass-statuses '(404))
    (unless (eql status 200) (error "~A: ~A" (getf host :name) (member-api-error-message body status)))
    (format output "~{  ~A~%~}" (uiop:split-string (or (gethash "message" body) "") :separator '(#\Newline))))
  (finish-output output)
  (await-host-on-release api host target))

(defun run-upgrade-steps (api record steps hosts target reference output)
  "Carry out STEPS, recording each in RECORD; stop at the first that fails."
  (dolist (step steps)
    (let* ((name (getf step :host))
           (host (find name hosts :key (lambda (host) (getf host :name)) :test #'equal))
           (entry (cluster-upgrade-host record name)))
      (declare (ignore entry))
      ;; What each host runs now decides, not what the record says it did: a host
      ;; rolled back since is upgraded again, one at the release is a :skip.
      (progn
        (ecase (getf step :action)
          (:skip (note-host-state api record name "Done" "runs the release already"))
          (:manual (note-host-state api record name "Manual" (upgrade-step-text step reference))
           (format output "~A: ~A~%" name (upgrade-step-text step reference)))
          (:on-reconnect (note-host-state api record name "OnReconnect" "upgrades when its node returns")
           (format output "~A: away; it upgrades when its node returns~%" name))
          (:upgrade
           (when (getf step :transfer-to)
             (format output "~A: handing the leadership to ~A~%" name (getf step :transfer-to))
             (finish-output output)
             (multiple-value-bind (body status)
                 (member-leader-request (upgrade-api-config api) "POST"
                                        (format nil "/apis/gr8s.io/v1/controlplanemembers/~A/leadership" (getf step :transfer-to)))
               (unless (member status '(200 202)) (error "handing the leadership on failed: ~A" (member-api-error-message body status))))
             (unless (member-await-leader (upgrade-api-config api) (getf step :transfer-to))
               (error "~A did not take the leadership" (getf step :transfer-to))))
           (format output "~A: upgrading from ~A~%" name (or (getf host :version) "an unknown release"))
           (finish-output output)
           (note-host-state api record name "Upgrading")
           (handler-case (upgrade-one-host api host target reference output)
             (error (condition)
               (note-host-state api record name "Failed" (princ-to-string condition))
               (setf (gethash "phase" (gethash "status" record)) "Failed")
               (save-cluster-upgrade api record)
               (error condition)))
           (note-host-state api record name "Done" (format nil "runs ~A" target))
           (format output "~A: runs ~A~%" name target)))))))

(defun new-cluster-upgrade-record (target reference hosts steps)
  (core-object
   "apiVersion" "upgrade.gr8s.io/v1" "kind" "ClusterUpgrade"
   "metadata" (core-object "name" target)
   "spec" (core-object "target" target "reference" reference)
   "status" (core-object
             "phase" "Progressing" "startedAt" (gr8s.store::current-timestamp)
             "hosts" (coerce (loop for step in steps
                                   for host = (find (getf step :host) hosts :key (lambda (host) (getf host :name)) :test #'equal)
                                   collect (core-object "name" (getf step :host)
                                                        "role" (or (getf host :role) "agent")
                                                        "node" (or (getf host :node) 'null)
                                                        "from" (or (getf host :version) 'null)
                                                        "state" "Pending" "message" ""))
                             'vector))))

(defun apply-cluster-upgrade (options config &key (output *standard-output*) (allow-downgrade (getf options :allow-downgrade)))
  (let ((api (make-upgrade-api config)))
    (multiple-value-bind (artifact pinned hosts steps problems)
        (plan-against-cluster (list* :allow-downgrade allow-downgrade options) api)
      (print-upgrade-plan hosts steps problems artifact pinned output)
      (when problems (return-from apply-cluster-upgrade 2))
      (unless (or (getf options :yes)
                  (progn (format output "~%Proceed? [y/N] ") (finish-output output)
                         (member (string-trim " " (or (read-line *standard-input* nil) "")) '("y" "yes") :test #'string-equal)))
        (format output "Nothing changed.~%")
        (return-from apply-cluster-upgrade 1))
      (let* ((target (gr8s.upgrade:release-artifact-version artifact))
             (record (progn (ensure-cluster-upgrade-crd api)
                            (or (load-cluster-upgrade api target)
                                (save-cluster-upgrade api (new-cluster-upgrade-record target pinned hosts steps))))))
        ;; A host the earlier run hadn't planned gets an entry now.
        (dolist (step steps)
          (unless (cluster-upgrade-host record (getf step :host))
            (let ((fresh (new-cluster-upgrade-record target pinned hosts (list step))))
              (setf (gethash "hosts" (gethash "status" record))
                    (concatenate 'vector (json-path record "status" "hosts") (json-path fresh "status" "hosts"))))))
        (setf (gethash "phase" (gethash "status" record)) "Progressing")
        (save-cluster-upgrade api record)
        (format output "~%")
        (run-upgrade-steps api record steps hosts target pinned output)
        (let ((waiting (count-if (lambda (host) (member (gethash "state" host) '("Manual" "OnReconnect") :test #'equal))
                                 (json-path record "status" "hosts"))))
          (setf (gethash "phase" (gethash "status" record)) (if (plusp waiting) "Waiting" "Succeeded")
                (gethash "finishedAt" (gethash "status" record)) (gr8s.store::current-timestamp))
          (save-cluster-upgrade api record)
          (format output "~%~:[Every host runs ~A.~;~:*~D host~:P still to upgrade, as above; then: gr8s upgrade finalize.~]~%"
                  (and (plusp waiting) waiting) target)
          (when (and (zerop waiting) (not (getf options :no-finalize)))
            (finalize-cluster-format api output))
          0)))))

(defun run-upgrade-apply-command (options &optional (output *standard-output*))
  (call-with-debug-kubeconfig (getf options :kubeconfig)
                              (lambda (config) (apply-cluster-upgrade options config :output output))))

;;; status, rollback.

(defun latest-cluster-upgrade (api)
  (multiple-value-bind (body status) (upgrade-api-call api "GET" +cluster-upgrade-path+)
    (when (eql status 200)
      (first (sort (coerce (gethash "items" body #()) 'list) #'string>
                   :key (lambda (item) (or (json-path item "metadata" "creationTimestamp") "")))))))

(defun run-upgrade-status-command (options &optional (output *standard-output*))
  (call-with-debug-kubeconfig
   (getf options :kubeconfig)
   (lambda (config)
     (let ((record (latest-cluster-upgrade (make-upgrade-api config))))
       (if (null record)
           (format output "No upgrade has been made with gr8s upgrade.~%")
           (progn
             (format output "Upgrade to ~A: ~A (started ~A)~%~%" (json-path record "spec" "target")
                     (json-path record "status" "phase") (json-path record "status" "startedAt"))
             (format output "~16A ~9A ~24A ~12A ~A~%" "HOST" "ROLE" "FROM" "STATE" "")
             (loop for host across (or (json-path record "status" "hosts") #())
                   do (format output "~16A ~9A ~24A ~12A ~A~%" (gethash "name" host) (gethash "role" host)
                              (let ((from (gethash "from" host))) (if (stringp from) from "-"))
                              (gethash "state" host) (gethash "message" host "")))))
       (finish-output output)
       0))))

(defun run-upgrade-rollback-command (options &optional (output *standard-output*))
  "Upgrade back to the release the hosts ran before the latest upgrade."
  (call-with-debug-kubeconfig
   (getf options :kubeconfig)
   (lambda (config)
     (let* ((api (make-upgrade-api config))
            (record (or (latest-cluster-upgrade api) (error "there is no upgrade to roll back")))
            (froms (remove-duplicates (loop for host across (or (json-path record "status" "hosts") #())
                                            for from = (gethash "from" host)
                                            when (and (stringp from) (gr8s.upgrade:compare-gr8s-versions from from))
                                              collect from)
                                      :test #'equal)))
       (unless (= 1 (length froms))
         (error "the hosts ran ~:[no release gr8s can return to~;~:*~{~A~^, ~} before~]: roll back by hand with gr8s upgrade apply --to VERSION"
                froms))
       (when (> (current-cluster-format-level api) 1)
         (error "the cluster was finalized at format level ~D, which ~A can't read" (current-cluster-format-level api) (first froms)))
       (format output "Rolling back to ~A.~%~%" (first froms))
       (apply-cluster-upgrade (list* :to (first froms) :no-finalize t options) config
                              :output output :allow-downgrade t)))))

;;; The cluster's format level (podster-igs.9).

(defun current-cluster-format-level (api)
  (multiple-value-bind (body status)
      (upgrade-api-call api "GET" (format nil "/api/v1/namespaces/~A/configmaps/~A"
                                          (first +cluster-version-config-map+) (second +cluster-version-config-map+)))
    (or (and (eql status 200) (ignore-errors (parse-integer (json-path body "data" "formatLevel")))) 1)))

(defun finalize-cluster-format (api output)
  "Let the cluster use the newest formats every voter reads: raise its format level
to the least that any voter reports. A member that can't read the level the cluster
runs at refuses to start (CHECK-CLUSTER-FORMAT-LEVEL)."
  (let* ((voters (remove-if-not (lambda (host) (equal "voter" (getf host :role))) (gather-upgrade-hosts api)))
         (levels (mapcar (lambda (host) (getf host :format-level)) voters)))
    (when (or (null voters) (member nil levels))
      (error "every voter must answer for its format level: ~{~A~^, ~} didn't"
             (loop for host in voters unless (getf host :format-level) collect (getf host :name))))
    (let ((level (reduce #'min levels)) (current (current-cluster-format-level api)))
      (cond ((<= level current)
             (format output "The cluster's format level stays at ~D.~%" current))
            (t
             (multiple-value-bind (body status)
                 (upgrade-api-call api "PUT" (format nil "/api/v1/namespaces/~A/configmaps/~A"
                                                     (first +cluster-version-config-map+) (second +cluster-version-config-map+))
                                   :body (core-object "apiVersion" "v1" "kind" "ConfigMap"
                                                      "metadata" (core-object "name" (second +cluster-version-config-map+)
                                                                              "namespace" (first +cluster-version-config-map+))
                                                      "data" (core-object "formatLevel" (princ-to-string level))))
               (unless (member status '(200 201)) (error "raising the format level failed: ~A" (member-api-error-message body status))))
             (format output "The cluster's format level is now ~D.~%" level)))
      (finish-output output)
      level)))

(defun run-upgrade-finalize-command (options &optional (output *standard-output*))
  (call-with-debug-kubeconfig (getf options :kubeconfig)
                              (lambda (config) (finalize-cluster-format (make-upgrade-api config) output) 0)))

(defun check-cluster-format-level (store)
  "Refuse to run a member whose release can't read the format the cluster uses."
  (let* ((object (ignore-errors (gr8s.resources::get-core-resource store "configmaps" (first +cluster-version-config-map+)
                                                                    (second +cluster-version-config-map+))))
         (level (or (and object (ignore-errors (parse-integer (json-path object "data" "formatLevel")))) 1)))
    (when (> level gr8s.upgrade:+gr8s-format-level+)
      (error "this cluster stores format level ~D, and gr8s ~A reads only up to ~D: upgrade this host (sudo gr8s upgrade self --to VERSION)"
             level (gr8s.foundation::kubernetes-git-version) gr8s.upgrade:+gr8s-format-level+))))
