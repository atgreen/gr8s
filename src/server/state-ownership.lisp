;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
(in-package #:gr8s.server)

(defstruct serve-state-lease root fd device inode thread)
(defvar *serve-state-lease* nil)

(defun call-with-offline-state-ownership (state-directory function)
  "Run FUNCTION only while no serve or patch process owns STATE-DIRECTORY.
The stable serve lock is shared with startup so offline maintenance cannot
rewrite credentials or other state underneath a running control plane.
The independent patch lock also excludes agent and witness patch managers."
  (unless (and (functionp function) (or (stringp state-directory) (pathnamep state-directory)))
    (error "Invalid offline state ownership arguments"))
  (let* ((requested (uiop:ensure-directory-pathname state-directory))
         (root (progn (ensure-directories-exist (merge-pathnames ".gr8s-serve.lock" requested))
                      (truename requested)))
         (path (merge-pathnames ".gr8s-serve.lock" root))
         (fd nil))
    (unwind-protect
         (progn
           (setf fd (sb-posix:open (namestring path)
                                   (logior sb-posix:o-rdwr sb-posix:o-creat
                                           sb-posix:o-nofollow sb-posix:o-nonblock)
                                   #o600))
           (unless (zerop (cffi:foreign-funcall "fcntl" :int fd :int 2 :int 1 :int))
             (error "Cannot protect offline ownership across exec"))
           (let ((stat (sb-posix:fstat fd)))
             (unless (and (sb-posix:s-isreg (sb-posix:stat-mode stat))
                          (= 1 (sb-posix:stat-nlink stat))
                          (= (sb-posix:geteuid) (sb-posix:stat-uid stat))
                          (= #o600 (logand #o777 (sb-posix:stat-mode stat))))
               (error "Unsafe serve ownership file")))
           (unless (zerop (cffi:foreign-funcall "flock" :int fd :int 6 :int))
             (error "State directory ~A is in use; stop gr8s before offline maintenance" root))
           (funcall function))
      (when fd (sb-posix:close fd)))))

(defun require-serve-state-ownership (options)
  "Require this thread's live serve lease before opening application state."
  (let* ((lease *serve-state-lease*)
         (root (truename (uiop:ensure-directory-pathname (getf options :state-directory))))
         (stat (and lease (serve-state-lease-fd lease)
                    (sb-posix:fstat (serve-state-lease-fd lease)))))
    (unless (and lease (eq (bt:current-thread) (serve-state-lease-thread lease))
                 (equal root (serve-state-lease-root lease)) stat
                 (= (sb-posix:stat-dev stat) (serve-state-lease-device lease))
                 (= (sb-posix:stat-ino stat) (serve-state-lease-inode lease)))
      (error "Serve must own its state directory before opening application files"))
    lease))

(defun write-serve-state-record (path record)
  (let ((temporary (gr8s.security::private-temporary-path path)))
    (unwind-protect
         (progn
           (gr8s.security::write-private-text-exclusively
            temporary
            (lambda (stream)
              (com.inuoe.jzon:stringify
               record :stream stream)
              (finish-output stream)
              (sb-posix:fsync (sb-sys:fd-stream-fd stream))))
           (sb-posix:rename (namestring temporary) (namestring path))
           (gr8s.store::sync-store-generation-directory (uiop:pathname-directory-pathname path)))
      (when (gr8s.store::store-generation-stat temporary) (sb-posix:unlink (namestring temporary))))))

(defun write-serve-state-mode (path mode)
  (write-serve-state-record path
    (gr8s.resources::core-object "format" "gr8s-serve-mode" "version" (if (equal mode "ha") 2 1) "mode" mode)))

(defconstant +serve-raft-default-port+ 7000)

(defun serve-api-advertise-address (options)
  "Return the stable address clients should use for this API listener. Prefer the
operator's explicit choices -- --node-address, then a non-wildcard --listen (the
API is bound only there) -- and then --node-listen, the interface this node
presents to the cluster (e.g. a WireGuard address chosen for roaming). Only when
none is given fall back to the host's first non-loopback IPv4, which picks
whatever LAN address comes first and strands other members' redirects on a stale
address once the node roams off that network (podster-1ig)."
  (let ((listen (getf options :listen "0.0.0.0"))
        (node-listen (getf options :node-listen)))
    (flet ((wildcard-p (address) (member address '("0.0.0.0" "::" "[::]") :test #'equal)))
      (or (getf options :node-address)
          (unless (wildcard-p listen) listen)
          (and (stringp node-listen) (not (wildcard-p node-listen))
               (not (uiop:string-prefix-p "127." node-listen)) node-listen)
          (find-if-not (lambda (address) (uiop:string-prefix-p "127." address))
                       (ignore-errors (gr8s.network::host-ipv4-addresses)))
          "127.0.0.1"))))

(defun serve-local-kubeconfig-address (options)
  "Return the address the locally generated admin kubeconfig should target. Like
k3s, prefer loopback: the kubeconfig is written on the same host as the server
and used by its operator, so it should not depend on which external interface the
server happened to advertise (podster-1v6). Only a listener pinned to a specific
non-wildcard address makes loopback unreachable, so use that address then. For a
remote-usable kubeconfig, generate one with 'gr8s kubeconfig --server
https://ADDRESS:PORT' against an address the API certificate now covers."
  (let ((listen (getf options :listen "0.0.0.0")))
    (if (member listen '("0.0.0.0" "::" "[::]") :test #'equal)
        "127.0.0.1"
        listen)))

(defun external-api-covers-in-cluster-endpoint-p
    (listen-address listen-port advertise-address in-cluster-port)
  "True when the external control-plane API listener (LISTEN-ADDRESS:LISTEN-PORT)
   already serves the in-cluster apiserver endpoint (ADVERTISE-ADDRESS:IN-CLUSTER-PORT).
   It does when it listens on the in-cluster port and on either a wildcard address or
   exactly the advertised address -- in which case a second dedicated in-cluster
   listener on 0.0.0.0:IN-CLUSTER-PORT would only collide on the same port
   (podster-o2h). The external listener's certificate already covers the advertised
   address, so in-cluster clients reaching it through the Service DNAT still verify."
  (and (eql listen-port in-cluster-port)
       (or (member listen-address '("0.0.0.0" "::" "[::]") :test #'equal)
           (equal listen-address advertise-address))))

(defun serve-ha-endpoint-record (options)
  "Describe exactly the endpoint production will advertise, without binding it."
  (let* ((id (or (getf options :raft-id) (getf options :node-name) "gr8s-local"))
         (host (or (getf options :raft-listen) "127.0.0.1"))
         (port (or (getf options :raft-port) +serve-raft-default-port+))
         (api-host (serve-api-advertise-address options))
         (api-port (getf options :port 6443)))
    (unless (and (every (lambda (value) (and (stringp value) (<= 1 (length value) 256)
                                            (notany (lambda (char) (or (<= (char-code char) 32)
                                                                      (= (char-code char) 127))) value)))
                        (list id host api-host))
                 (not (member host '("0.0.0.0" "::" "[::]") :test #'equal))
                 (typep port '(integer 1 65535)) (typep api-port '(integer 1 65535)))
      (error "HA requires a member ID and a stable, non-wildcard Raft endpoint"))
    (let ((url (format nil "https://~A:~D" api-host api-port)))
      (unless (<= (length url) 256) (error "HA API URL is too long"))
      (gr8s.resources::core-object "format" "gr8s-serve-ha-endpoint" "version" 1
                                   "memberId" id "host" host "port" port "apiUrl" url))))

(defparameter +serve-ha-endpoint-identity-keys+
  '("format" "version" "memberId" "host" "port")
  "The persisted HA endpoint fields that pin a member's consensus identity and so
must not change on restart. The apiUrl is deliberately excluded: it is where
clients reach this member's API, which changes when the member roams to a new
address (podster-1ig), not part of its identity.")

(defun check-serve-ha-endpoint (root options &key (publish t))
  "Persist endpoint intent before opening application files or accepting RPCs. The
member id and Raft endpoint (host:port) are identity: a mismatch on restart is
refused. The advertised API URL is not -- a roamed member may now sit at a new
address -- so a changed URL is rewritten to the persisted record, and the HA
layer re-advertises it to the cluster once this member leads."
  (let* ((directory (merge-pathnames "metadata/" root))
         (path (merge-pathnames "server-ha-endpoint.json" directory))
         (requested (serve-ha-endpoint-record options)))
    (gr8s.store::ensure-store-generation-directory directory root :metadata t)
    (if (gr8s.store::store-generation-stat path)
        (let ((existing (gr8s.store::read-private-generation-json path)))
          (unless (and (hash-table-p existing) (= 6 (hash-table-count existing))
                       (every (lambda (key)
                                (equal (gethash key requested) (gethash key existing)))
                              +serve-ha-endpoint-identity-keys+))
            (error "Persisted HA member identity or Raft endpoint differs from startup options; restart with the original configuration"))
          (when (and publish
                     (not (equal (gethash "apiUrl" requested) (gethash "apiUrl" existing))))
            (write-serve-state-record path requested)))
        (when publish (write-serve-state-record path requested)))))

(defun check-serve-state-mode (root options)
  "Never silently open a Raft application's files as standalone state."
  (when (and (getf options :raft-init) (getf options :raft-join))
    (error "Serve cannot both found and join a Raft cluster"))
  (when (getf options :raft-join) (parse-agent-server (getf options :raft-join)))
  (when (gr8s.store::store-generation-stat (merge-pathnames "raft/witness.log" root))
    (error "Witness state cannot be opened by serve"))
  (let* ((directory (merge-pathnames "metadata/" root))
         (path (merge-pathnames "server-mode.json" directory))
         (requested (if (or (getf options :raft-init) (getf options :raft-join)) "ha" "standalone"))
         (existing-present (gr8s.store::store-generation-stat path))
         (existing (progn
                     (when (gr8s.store::store-generation-stat directory)
                       (gr8s.store::check-store-generation-directory directory :metadata t))
                     (when existing-present
                       (gr8s.store::read-private-generation-json path))))
         (legacy-ha (some (lambda (name) (gr8s.store::store-generation-stat (merge-pathnames name root)))
                          '("raft/control-plane.log" "raft/bootstrap.json" "pki/raft/" "metadata/server-ha-endpoint.json"))))
    (when existing-present
      (unless (and (hash-table-p existing) (= 3 (hash-table-count existing))
                   (equal "gr8s-serve-mode" (gethash "format" existing))
                   (or (eql 1 (gethash "version" existing))
                       (and (eql 2 (gethash "version" existing))
                            (equal "ha" (gethash "mode" existing))))
                   (member (gethash "mode" existing) '("ha" "standalone") :test #'equal))
        (error "Invalid persisted serve mode")))
    (when (and (equal requested "standalone")
               (or legacy-ha (and existing (equal "ha" (gethash "mode" existing)))))
      (error "HA state requires its Raft startup options; standalone fallback is refused"))
    ;; Version 2 records durable genesis intent before any credentials or
    ;; bootstrap journal are created. Version 1 HA roots may have belonged to
    ;; an in-memory multi-voter cluster: absence of a WAL is not fresh genesis.
    (when (and (equal requested "ha")
               (not (and existing (eql 2 (gethash "version" existing))))
               (or legacy-ha (and existing (equal "ha" (gethash "mode" existing))))
               (not (gr8s.store::store-generation-stat (merge-pathnames "raft/bootstrap.json" root))))
      (error "Legacy HA state has no durable bootstrap journal; explicit cluster migration is required"))
    (when (equal requested "ha") (check-serve-ha-endpoint root options :publish nil))
    ;; An explicit HA request can found a cluster from existing standalone data.
    ;; Persist intent before opening files, so interrupted HA startup cannot later
    ;; fall through to standalone merely because its flags were omitted.
    (unless (and existing (equal requested (gethash "mode" existing))
                 (or (equal requested "standalone") (eql 2 (gethash "version" existing))))
      (gr8s.store::ensure-store-generation-directory directory root :metadata t)
      (write-serve-state-mode path requested))
    (when (equal requested "ha") (check-serve-ha-endpoint root options))))

(defun call-with-serve-state-ownership (options function)
  "Own the canonical state directory across all initialization and teardown.
Do not remove the stable lock file on close: another opener may already hold it."
  (unless (and (functionp function) (or (stringp (getf options :state-directory))
                                      (pathnamep (getf options :state-directory))))
    (error "Invalid serve state ownership arguments"))
  (let* ((requested (uiop:ensure-directory-pathname (getf options :state-directory)))
         (root (progn (ensure-directories-exist (merge-pathnames ".gr8s-serve.lock" requested))
                      (truename requested)))
         (path (merge-pathnames ".gr8s-serve.lock" root))
         (fd nil) (lease nil))
    (gr8s.store::check-store-generation-directory root :metadata t)
    (unwind-protect
         (progn
           (setf fd (sb-posix:open (namestring path)
                                   (logior sb-posix:o-rdwr sb-posix:o-creat sb-posix:o-nofollow sb-posix:o-nonblock) #o600))
           (unless (zerop (cffi:foreign-funcall "fcntl" :int fd :int 2 :int 1 :int))
             (error "Cannot protect serve ownership across exec"))
           (let ((stat (sb-posix:fstat fd)))
             (unless (and (sb-posix:s-isreg (sb-posix:stat-mode stat))
                          (= 1 (sb-posix:stat-nlink stat))
                          (= (sb-posix:geteuid) (sb-posix:stat-uid stat))
                          (= #o600 (logand #o777 (sb-posix:stat-mode stat))))
               (error "Unsafe serve ownership file"))
             (unless (zerop (cffi:foreign-funcall "flock" :int fd :int 6 :int))
               (error "Another serve process owns state directory ~A" root))
             (setf lease (make-serve-state-lease :root root :fd fd
                          :device (sb-posix:stat-dev stat) :inode (sb-posix:stat-ino stat)
                          :thread (bt:current-thread))))
           (let ((*serve-state-lease* lease))
             (check-serve-state-mode root options)
             (funcall function)))
      (when lease (setf (serve-state-lease-fd lease) nil))
      (when fd (sb-posix:close fd)))))
