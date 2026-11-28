;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Give a local user gr8 without sudo (podster-7uof). gr8s-server, running as root,
;;;; listens on a Unix socket; whoever connects is the user the kernel says they are
;;;; (SO_PEERCRED), never what they claim. For them the server makes their own
;;;; namespace, recording who owns it, their UID and groups (what podster-tcr8 holds
;;;; every Pod there to), grants them what gr8 calls and no more, and answers with
;;;; their kubeconfig: a client certificate for gr8:USER, namespace gr8-USER. Root,
;;;; system accounts and nobody are refused (only UIDs 1000-60000, login.defs'
;;;; UID_MIN-UID_MAX); --gr8-users GROUP limits it to GROUP's members.

(in-package #:gr8s.server)

(defparameter +gr8-first-user-uid+ 1000
  "Accounts below this UID are the system's (login.defs UID_MIN), not people.")

(defparameter +gr8-last-user-uid+ 60000
  "Accounts above this UID (login.defs UID_MAX) aren't people either: nobody (65534),
and the ranges user namespaces map.")

(defparameter +gr8-user-namespace-verbs+ #("get" "list" "watch" "create" "update" "patch" "delete"))

(sb-alien:define-alien-routine ("getgrouplist" %getgrouplist) sb-alien:int
  (user sb-alien:c-string)
  (group sb-alien:unsigned-int)
  (groups (* sb-alien:unsigned-int))
  (count (* sb-alien:int)))

(defun gr8-user-groups (name gid)
  "NAME's groups, GID first, as the system's group database (NSS) has them."
  (sb-alien:with-alien ((count sb-alien:int 64))
    (loop
      (let ((buffer (sb-alien:make-alien sb-alien:unsigned-int count)))
        (unwind-protect
             (let ((wanted count))
               (if (>= (%getgrouplist name gid buffer (sb-alien:addr count)) 0)
                   (return (remove-duplicates
                            (cons gid (loop for i below count collect (sb-alien:deref buffer i)))
                            :from-end t))
                   (when (<= count wanted) (setf count (* 2 wanted)))))
          (sb-alien:free-alien buffer))))))

(defun gr8-user-name-p (name)
  "True for a login name gr8 can make a namespace and identity of."
  (and (stringp name) (<= 1 (length name) 32)
       (every (lambda (c) (or (char<= #\a c #\z) (digit-char-p c) (find c "_.-"))) name)
       (or (char<= #\a (char name 0) #\z) (char= #\_ (char name 0)))))

(defun gr8-user-namespace (name)
  "NAME's own namespace."
  (concatenate 'string "gr8-" (substitute #\- #\_ (substitute #\- #\. name))))

(defun gr8-user-rbac (identity namespace)
  "The Role, RoleBinding, ClusterRole and ClusterRoleBinding granting IDENTITY what gr8
calls, and no more: Pods, their exec, Secrets and SecurityProfiles in NAMESPACE, its
own; reading Nodes and NAMESPACE itself; and the cluster-scoped SandboxProfiles and
ClusterNetworkPolicies gr8 makes for a run, which podster-tcr8 holds to NAMESPACE."
  (let* ((name (concatenate 'string "gr8s:" identity))
         (labels (core-object "app.kubernetes.io/managed-by" "gr8"))
         (subjects (vector (core-object "kind" "User" "apiGroup" "rbac.authorization.k8s.io" "name" identity)))
         (verbs +gr8-user-namespace-verbs+))
    (flet ((rule (groups resources verbs &optional names)
             (let ((rule (core-object "apiGroups" groups "resources" resources "verbs" verbs)))
               (when names (setf (gethash "resourceNames" rule) names))
               rule))
           (meta (&optional namespace)
             (let ((metadata (core-object "name" name "labels" (gr8s.resources::copy-core-object labels))))
               (when namespace (setf (gethash "namespace" metadata) namespace))
               metadata)))
      (list
       (list "roles" namespace
             (core-object "apiVersion" "rbac.authorization.k8s.io/v1" "kind" "Role" "metadata" (meta namespace)
                          "rules" (vector (rule #("") #("pods" "secrets") verbs)
                                          (rule #("") #("pods/exec") #("get" "create"))
                                          (rule #("agents.kruise.io") #("securityprofiles") verbs))))
       (list "rolebindings" namespace
             (core-object "apiVersion" "rbac.authorization.k8s.io/v1" "kind" "RoleBinding" "metadata" (meta namespace)
                          "subjects" subjects
                          "roleRef" (core-object "apiGroup" "rbac.authorization.k8s.io" "kind" "Role" "name" name)))
       (list "clusterroles" nil
             (core-object "apiVersion" "rbac.authorization.k8s.io/v1" "kind" "ClusterRole" "metadata" (meta)
                          "rules" (vector (rule #("") #("nodes") #("get" "list"))
                                          (rule #("") #("namespaces") #("get") (vector namespace))
                                          (rule #("gr8.gr8s.io") #("sandboxprofiles") verbs)
                                          (rule #("policy.networking.k8s.io") #("clusternetworkpolicies") verbs))))
       (list "clusterrolebindings" nil
             (core-object "apiVersion" "rbac.authorization.k8s.io/v1" "kind" "ClusterRoleBinding" "metadata" (meta)
                          "subjects" subjects
                          "roleRef" (core-object "apiGroup" "rbac.authorization.k8s.io" "kind" "ClusterRole" "name" name)))))))

(defun gr8-user-namespace-object (namespace identity uid groups)
  (core-object
   "apiVersion" "v1" "kind" "Namespace"
   "metadata" (core-object
               "name" namespace
               "labels" (core-object "app.kubernetes.io/managed-by" "gr8"
                                     "pod-security.kubernetes.io/enforce" "privileged")
               "annotations" (core-object gr8s.resources::+gr8-owner-annotation+ identity
                                          gr8s.resources::+gr8-owner-uid-annotation+ (princ-to-string uid)
                                          gr8s.resources::+gr8-owner-gids-annotation+
                                          (format nil "~{~D~^,~}" groups)))))

(defun gr8-apply-object (store resource namespace object)
  "Create OBJECT, or bring the stored one's labels, annotations and content up to it."
  (let ((name (gethash "name" (gethash "metadata" object))))
    (handler-case (gr8s.resources::create-core-resource store resource (gr8s.resources::copy-core-object object) namespace)
      (gr8s.model:kubernetes-error (condition)
        (unless (equal "AlreadyExists" (gr8s.model:kubernetes-error-reason condition)) (error condition))
        (gr8s.resources::update-core-resource
         store resource namespace name
         (lambda (current)
           (let ((updated (gr8s.resources::copy-core-object current))
                 (wanted (gethash "metadata" object)))
             (loop for key being the hash-keys of object using (hash-value value)
                   unless (member key '("metadata" "status") :test #'equal)
                     do (setf (gethash key updated) (gr8s.resources::copy-core-object value)))
             (dolist (field '("labels" "annotations"))
               (let ((have (or (gethash field (gethash "metadata" updated)) (core-object))))
                 (loop for key being the hash-keys of (gethash field wanted (core-object)) using (hash-value value)
                       do (setf (gethash key have) value))
                 (setf (gethash field (gethash "metadata" updated)) have)))
             updated)))))))

(defun issue-gr8-user-kubeconfig (store pki server-url uid gid &key users-group)
  "Make the local user UID (primary group GID) a gr8 user and return their kubeconfig."
  (unless (<= +gr8-first-user-uid+ uid +gr8-last-user-uid+)
    (error "UID ~D is a system account; gr8 is for people (UID ~D to ~D)"
           uid +gr8-first-user-uid+ +gr8-last-user-uid+))
  (let* ((account (or (ignore-errors (sb-posix:getpwuid uid))
                      (error "UID ~D has no account on this machine" uid)))
         (name (sb-posix:passwd-name account)))
    (unless (gr8-user-name-p name)
      (error "the account name ~S can't name a gr8 user" name))
    (let ((groups (gr8-user-groups name gid)))
      (when users-group
        (let ((allowed (ignore-errors (sb-posix:group-gid (sb-posix:getgrnam users-group)))))
          (unless (and allowed (member allowed groups))
            (error "~A is not in group ~A, which this machine's gr8 is for" name users-group))))
      (let ((identity (concatenate 'string gr8s.resources::+gr8-user-prefix+ name))
            (namespace (gr8-user-namespace name)))
        (gr8-apply-object store "namespaces" nil (gr8-user-namespace-object namespace identity uid groups))
        (loop for (resource object-namespace object) in (gr8-user-rbac identity namespace)
              do (gr8-apply-object store resource object-namespace object))
        (multiple-value-bind (certificate key) (gr8s.apiserver::ensure-user-client-credentials pki identity)
          (with-output-to-string (stream)
            (print-kubeconfig stream server-url
                              :ca-certificates (cluster-pki-trust-certificates pki)
                              :client-certificate certificate :client-key key
                              :namespace namespace)))))))

(defun serve-gr8-user (store pki server-url users-group socket)
  "Answer one connection on SOCKET: the peer's kubeconfig, or why not, as JSON."
  (let ((stream (sb-bsd-sockets:socket-make-stream socket :output t :input t
                                                          :element-type 'character :external-format :utf-8
                                                          :buffering :full)))
    (unwind-protect
         (let ((reply (handler-case
                          (multiple-value-bind (pid uid gid) (gr8s.network::agent-cni-peer-credentials socket)
                            (declare (ignore pid))
                            (core-object "kubeconfig"
                                         (issue-gr8-user-kubeconfig store pki server-url uid gid
                                                                    :users-group users-group)))
                        (error (condition)
                          (core-object "error" (princ-to-string condition))))))
           (com.inuoe.jzon:stringify reply :stream stream)
           (finish-output stream))
      (ignore-errors (close stream)))))

(defstruct gr8-user-socket path socket thread (stopping nil))

(defun start-gr8-user-socket (path store pki server-url &key users-group)
  "Listen at PATH for local users wanting gr8: any local user, or USERS-GROUP's members."
  (let ((socket (make-instance 'sb-bsd-sockets:local-socket :type :stream :protocol 0))
        (directory (uiop:pathname-directory-pathname path)))
    (ensure-directories-exist directory :mode #o755)
    (ignore-errors (delete-file path))
    (sb-bsd-sockets:socket-bind socket path)
    (sb-bsd-sockets:socket-listen socket 16)
    ;; Anyone may connect; who they are, and so what they get, is the kernel's word.
    (sb-posix:chmod path #o666)
    (let ((server (make-gr8-user-socket :path path :socket socket)))
      (setf (gr8-user-socket-thread server)
            (bt:make-thread
             (lambda ()
               (loop until (gr8-user-socket-stopping server)
                     do (when (sb-sys:wait-until-fd-usable (sb-bsd-sockets:socket-file-descriptor socket) :input 0.2)
                          (handler-case
                              (let ((client (sb-bsd-sockets:socket-accept socket)))
                                (when client (serve-gr8-user store pki server-url users-group client)))
                            (error (condition)
                              (unless (gr8-user-socket-stopping server)
                                (format *error-output* "gr8s gr8 user socket: ~A~%" condition)))))))
             :name "gr8s gr8 user socket"))
      server)))

(defun stop-gr8-user-socket (server)
  (setf (gr8-user-socket-stopping server) t)
  (ignore-errors (sb-bsd-sockets:socket-close (gr8-user-socket-socket server)))
  (let ((thread (gr8-user-socket-thread server)))
    (when (and thread (not (eq thread (bt:current-thread))))
      (ignore-errors (bt:join-thread thread))))
  (ignore-errors (delete-file (gr8-user-socket-path server))))
