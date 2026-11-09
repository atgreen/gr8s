;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Mutually authenticate node-to-node BitTorrent streams before peer-wire data.

(in-package #:gr8s.security)

(defparameter +image-peer-alpn+ "gr8s-bittorrent/1")

(defun image-peer-certificate-pem (certificate)
  (pure-tls/acme::wrap-pem
   "CERTIFICATE" (pure-tls::x509-certificate-raw-der certificate)))

(defun authenticate-image-peer-stream (pki stream &optional expected-node-name)
  "Verify STREAM's peer as a cluster node and return its certificate node name."
  (let* ((certificate (pure-tls:tls-peer-certificate stream))
         (names (and certificate
                     (pure-tls:certificate-subject-common-names certificate)))
         (node-name (or expected-node-name
                        (and (= 1 (length names)) (first names)))))
    (unless (and certificate node-name)
      (pki-fail "unauthenticated-image-peer"
                "Image peers require one name-bound node certificate"))
    (verify-node-certificate pki (image-peer-certificate-pem certificate) node-name)
    (unless (equal +image-peer-alpn+ (pure-tls:tls-selected-alpn stream))
      (pki-fail "invalid-image-peer-protocol"
                "Image peer did not negotiate the private BitTorrent protocol"))
    node-name))

(defun make-image-peer-client-stream
    (host port expected-node-name pki certificate-path private-key-path
     &key (timeout 10))
  "Connect to EXPECTED-NODE-NAME and authenticate it before BitTorrent bytes."
  (let ((socket (usocket:socket-connect host port :timeout timeout
                                        :element-type '(unsigned-byte 8)))
        (tls nil))
    (handler-case
        (progn
          ;; Node certificates are symmetric cluster identities with clientAuth
          ;; policy. Pure TLS proves possession; the explicit verifier below
          ;; applies that node profile and tracker-supplied expected name.
          (setf tls (pure-tls:make-tls-client-stream
                     (usocket:socket-stream socket)
                     :verify pure-tls:+verify-none+
                     :client-certificate (namestring certificate-path)
                     :client-key (namestring private-key-path)
                     :alpn-protocols (list +image-peer-alpn+)))
          (authenticate-image-peer-stream pki tls expected-node-name)
          (values tls socket))
      (error (condition)
        (when tls (ignore-errors (close tls :abort t)))
        (ignore-errors (usocket:socket-close socket))
        (error condition)))))

(defun make-image-peer-server-stream
    (raw-stream pki certificate-path private-key-path)
  "Require and authenticate a node certificate before accepting peer-wire data."
  (let ((tls (pure-tls:make-tls-server-stream
              raw-stream :certificate (namestring certificate-path)
              :key (namestring private-key-path)
              :verify pure-tls:+verify-peer+
              :trust-store
              (pure-tls::make-trust-store
               :certificates (list (cluster-pki-ca-certificate pki)))
              :alpn-protocols (list +image-peer-alpn+))))
    (handler-case
        (values tls (authenticate-image-peer-stream pki tls))
      (error (condition)
        (ignore-errors (close tls :abort t))
        (error condition)))))

(defun download-image-from-peers
    (torrent store peer-id peers pki certificate-path private-key-path
     &key (pipeline-depth 8) (timeout 10))
  "Try authenticated tracker PEERS until STORE is complete, recovering from a
   corrupt or disconnected peer without publishing unverified data."
  (let ((failures nil))
    (dolist (peer peers)
      (when (gr8s.image-distribution::piece-store-complete-p store)
        (return-from download-image-from-peers t))
      (let ((tls nil) (socket nil))
        (handler-case
            (progn
              (multiple-value-setq (tls socket)
                (make-image-peer-client-stream
                 (gr8s.image-distribution::tracker-peer-address peer)
                 (gr8s.image-distribution::tracker-peer-port peer)
                 (gr8s.image-distribution::tracker-peer-node-name peer)
                 pki certificate-path private-key-path :timeout timeout))
              (gr8s.image-distribution::download-from-peer-stream
               tls torrent store peer-id :pipeline-depth pipeline-depth))
          (error (condition) (push condition failures)))
        (when tls (ignore-errors (close tls :abort t)))
        (when socket (ignore-errors (usocket:socket-close socket)))))
    (if (gr8s.image-distribution::piece-store-complete-p store)
        t
        (error "No authenticated image peer completed the blob: ~{~A~^; ~}"
               (nreverse failures)))))

(defstruct image-peer-swarm
  torrent pathname completed)

(defstruct (image-peer-server (:constructor %make-image-peer-server))
  pki certificate-path private-key-path peer-id listener thread
  (swarms (make-hash-table :test #'equalp))
  (clients nil)
  (client-threads nil)
  (lock (bt:make-lock "gr8s image peer server"))
  (stopping-p nil))

(defun image-peer-swarm-key (truncated-infohash)
  (ironclad:byte-array-to-hex-string truncated-infohash))

(defun register-image-peer-swarm (server torrent pathname completed)
  "Publish a verified local blob through SERVER. Reject truncated-hash collisions."
  (let ((key (image-peer-swarm-key
              (subseq (gr8s.image-distribution::blob-torrent-infohash torrent) 0 20))))
    (bt:with-lock-held ((image-peer-server-lock server))
      (let ((existing (gethash key (image-peer-server-swarms server))))
        (when (and existing
                   (not (and (equal pathname (image-peer-swarm-pathname existing))
                             (equalp (gr8s.image-distribution::blob-torrent-infohash torrent)
                                     (gr8s.image-distribution::blob-torrent-infohash
                                      (image-peer-swarm-torrent existing))))))
          (error "A BitTorrent swarm with the same truncated infohash is already served"))
        (unless existing
          (setf (gethash key (image-peer-server-swarms server))
                (make-image-peer-swarm :torrent torrent :pathname pathname
                                       :completed completed))))))
  server)

(defun unregister-image-peer-swarm (server torrent)
  (bt:with-lock-held ((image-peer-server-lock server))
    (remhash
     (image-peer-swarm-key
      (subseq (gr8s.image-distribution::blob-torrent-infohash torrent) 0 20))
     (image-peer-server-swarms server))))

(defun image-peer-server-client (server socket)
  (let ((tls nil))
    (unwind-protect
         (handler-case
             (progn
               (multiple-value-bind (stream node-name)
                   (make-image-peer-server-stream
                    (usocket:socket-stream socket)
                    (image-peer-server-pki server)
                    (image-peer-server-certificate-path server)
                    (image-peer-server-private-key-path server))
                 (declare (ignore node-name))
                 (setf tls stream))
               (let* ((handshake (gr8s.image-distribution::read-peer-handshake tls))
                      (swarm
                        (bt:with-lock-held ((image-peer-server-lock server))
                          (gethash
                           (image-peer-swarm-key
                            (gr8s.image-distribution::peer-handshake-infohash handshake))
                           (image-peer-server-swarms server)))))
                 (unless swarm (error "Requested BitTorrent swarm is not served"))
                 (gr8s.image-distribution::serve-peer-stream
                  tls (image-peer-swarm-torrent swarm)
                  (image-peer-swarm-pathname swarm)
                  (image-peer-server-peer-id server)
                  (image-peer-swarm-completed swarm) :handshake handshake)))
           (error () nil))
      (bt:with-lock-held ((image-peer-server-lock server))
        (setf (image-peer-server-clients server)
              (delete socket (image-peer-server-clients server) :test #'eq)))
      (when tls (ignore-errors (close tls :abort t)))
      (ignore-errors (usocket:socket-close socket)))))

(defun run-image-peer-server (server)
  (loop until (image-peer-server-stopping-p server)
        do (handler-case
               (let ((socket (usocket:socket-accept
                              (image-peer-server-listener server)
                              :element-type '(unsigned-byte 8)))
                     (accepted nil))
                 (bt:with-lock-held ((image-peer-server-lock server))
                   (unless (image-peer-server-stopping-p server)
                     (setf accepted t)
                     (push socket (image-peer-server-clients server))
                     (push (bt:make-thread
                            (lambda () (image-peer-server-client server socket))
                            :name "gr8s image peer connection")
                           (image-peer-server-client-threads server))))
                 (unless accepted (ignore-errors (usocket:socket-close socket))))
             (error ()
               (unless (image-peer-server-stopping-p server) (sleep 0.01))))))

(defun start-image-peer-server
    (pki certificate-path private-key-path peer-id &key (host "0.0.0.0") (port 0))
  "Start a private mTLS BitTorrent listener and return its lifecycle handle."
  (gr8s.image-distribution::require-peer-id peer-id)
  (let* ((listener (usocket:socket-listen
                    host port :reuse-address t :backlog 64
                    :element-type '(unsigned-byte 8)))
         (server (%make-image-peer-server
                  :pki pki :certificate-path certificate-path
                  :private-key-path private-key-path :peer-id (copy-seq peer-id)
                  :listener listener)))
    (setf (image-peer-server-thread server)
          (bt:make-thread (lambda () (run-image-peer-server server))
                          :name "gr8s image peer listener"))
    server))

(defun image-peer-server-port (server)
  (usocket:get-local-port (image-peer-server-listener server)))

(defun stop-image-peer-server (server)
  "Stop accepting, close live peer streams, and join every owned thread."
  (bt:with-lock-held ((image-peer-server-lock server))
    (setf (image-peer-server-stopping-p server) t))
  ;; Closing a descriptor in another thread does not wake Linux ACCEPT or
  ;; RECV. Shut down the socket first so blocked readers observe termination.
  (flet ((shutdown (socket)
           (ignore-errors
             (sb-bsd-sockets:socket-shutdown (usocket:socket socket) :direction :io))))
    (shutdown (image-peer-server-listener server))
    ;; No accepted connection can be added after this join. Take the client
    ;; snapshot afterwards so an ACCEPT racing shutdown cannot escape cleanup.
    (let ((thread (image-peer-server-thread server)))
      (when (and thread (not (eq thread (bt:current-thread))))
        (ignore-errors (bt:join-thread thread))))
    (ignore-errors (usocket:socket-close (image-peer-server-listener server)))
    (let ((clients nil) (threads nil))
      (bt:with-lock-held ((image-peer-server-lock server))
        (setf clients (copy-list (image-peer-server-clients server))
              threads (copy-list (image-peer-server-client-threads server)))
        ;; A worker unregisters before closing its stream. Holding the same
        ;; lock keeps SHUTDOWN from racing a close and descriptor reuse.
        (dolist (socket clients) (shutdown socket)))
      ;; Leave each descriptor open until its reader has observed EOF. Closing
      ;; it immediately can strand SBCL's buffered read on a recycled fd.
      (dolist (thread threads)
        (unless (eq thread (bt:current-thread))
          (ignore-errors (bt:join-thread thread))))
      (dolist (socket clients) (ignore-errors (usocket:socket-close socket)))))
  server)

(defun load-image-peer-pki (ca-certificate-path)
  "Build the verification-only PKI view a node needs for peer certificates."
  (gr8s.security::%make-cluster-pki
   :ca-certificate-path ca-certificate-path
   :ca-certificate (first (pure-tls:load-certificate-chain ca-certificate-path))))

(defun ensure-image-peer-id (directory)
  (let ((path (merge-pathnames "peer-id" (uiop:ensure-directory-pathname directory))))
    (if (probe-file path)
        (with-open-file (stream path :element-type '(unsigned-byte 8))
          (let ((id (make-array 20 :element-type '(unsigned-byte 8))))
            (unless (= 20 (read-sequence id stream))
              (error "Invalid image peer id in ~A" path))
            id))
        (let ((id (ironclad:random-data 20)))
          (ensure-directories-exist path)
          (with-open-file (stream path :direction :output
                                      :if-does-not-exist :create
                                      :if-exists :error
                                      :element-type '(unsigned-byte 8))
            (write-sequence id stream))
          (sb-posix:chmod path #o600)
          id))))

(defstruct node-image-distribution
  mirror peer-server tracker-call tracker-close advertise-address
  heartbeat-thread (stopping-p nil))

(defun tracker-plist-peer (peer)
  (gr8s.image-distribution::make-tracker-peer
   :node-name (getf peer :node-name) :address (getf peer :address)
   :port (getf peer :port) :peer-id (getf peer :peer-id)
   :complete-p (getf peer :complete)))

(defun image-peer-endpoint-arguments (peer-server peer-id advertise-address)
  (list :address advertise-address :port (image-peer-server-port peer-server)
        :peer-id peer-id :complete t))

(defun publish-node-image-swarm
    (peer-server peer-id advertise-address tracker-call path torrent token)
  (register-image-peer-swarm
   peer-server torrent path
   (make-array (gr8s.image-distribution::torrent-piece-count torrent)
               :element-type 'bit :initial-element 1))
  (let ((digest (gr8s.image-distribution::blob-torrent-oci-digest torrent))
        (endpoint (image-peer-endpoint-arguments
                   peer-server peer-id advertise-address)))
    (labels ((publish (lease-token)
               (apply tracker-call :publish digest
                      :token lease-token
                      :metainfo (gr8s.image-distribution::blob-torrent-metainfo torrent)
                      endpoint)))
      (if token
          (publish token)
          (handler-case
              (apply tracker-call :announce digest endpoint)
            (error ()
              (let ((lease (funcall tracker-call :acquire digest)))
                (when (eq :granted
                          (gr8s.image-distribution::tracker-status lease))
                  (publish (getf lease :token))))))))))

(defun run-node-image-announcements
    (distribution peer-server peer-id advertise-address tracker-call)
  (loop with elapsed = 0
        until (node-image-distribution-stopping-p distribution)
        do (sleep 1) (incf elapsed)
           (when (>= elapsed 60)
             (setf elapsed 0)
             (let ((torrents
                     (bt:with-lock-held ((image-peer-server-lock peer-server))
                       (loop for swarm being the hash-values
                               of (image-peer-server-swarms peer-server)
                             collect (image-peer-swarm-torrent swarm)))))
               (dolist (torrent torrents)
                 (ignore-errors
                   (apply tracker-call :announce
                          (gr8s.image-distribution::blob-torrent-oci-digest torrent)
                          (image-peer-endpoint-arguments
                           peer-server peer-id advertise-address))))))))

(defun start-node-image-distribution
    (directory tracker-call tracker-close ca-certificate-path certificate-path
     private-key-path advertise-address &key (peer-port 0) (mirror-port 0))
  "Start this node's mTLS BitTorrent seeder and loopback OCI mirror."
  (let* ((directory (uiop:ensure-directory-pathname directory))
         (pki (load-image-peer-pki ca-certificate-path))
         (peer-id (ensure-image-peer-id directory))
         (peer-server (start-image-peer-server
                       pki certificate-path private-key-path peer-id :port peer-port))
         (peer-fetch
           (lambda (temporary digest metainfo peers)
             (let* ((torrent (gr8s.image-distribution::parse-oci-blob-torrent
                              metainfo digest))
                    (store (gr8s.image-distribution::make-piece-store
                            torrent temporary)))
               (download-image-from-peers
                torrent store peer-id (mapcar #'tracker-plist-peer peers)
                pki certificate-path private-key-path))))
         (publish
           (lambda (path torrent token)
             (publish-node-image-swarm
              peer-server peer-id advertise-address tracker-call
              path torrent token)))
         (mirror
           (gr8s.image-distribution::make-oci-mirror
            (merge-pathnames "cache/" directory) tracker-call peer-fetch
            #'gr8s.image-distribution::fetch-oci-registry-blob publish
            #'gr8s.image-distribution::proxy-oci-registry-request)))
    (handler-case
        (progn
          (gr8s.image-distribution::start-oci-mirror mirror :port mirror-port)
          (let ((distribution
                  (make-node-image-distribution
                   :mirror mirror :peer-server peer-server
                   :tracker-call tracker-call :tracker-close tracker-close
                   :advertise-address advertise-address)))
            (setf (node-image-distribution-heartbeat-thread distribution)
                  (bt:make-thread
                   (lambda ()
                     (run-node-image-announcements
                      distribution peer-server peer-id advertise-address tracker-call))
                   :name "gr8s image peer announcements"))
            distribution))
      (error (condition)
        (stop-image-peer-server peer-server)
        (funcall tracker-close)
        (error condition)))))

(defun node-image-distribution-mirror-port (distribution)
  (hunchentoot:acceptor-port
   (gr8s.image-distribution::oci-mirror-acceptor
    (node-image-distribution-mirror distribution))))

(defun stop-node-image-distribution (distribution)
  (setf (node-image-distribution-stopping-p distribution) t)
  (let ((thread (node-image-distribution-heartbeat-thread distribution)))
    (when thread (bt:join-thread thread)))
  (let ((digests
          (bt:with-lock-held
              ((image-peer-server-lock
                (node-image-distribution-peer-server distribution)))
            (loop for swarm being the hash-values
                    of (image-peer-server-swarms
                        (node-image-distribution-peer-server distribution))
                  collect (gr8s.image-distribution::blob-torrent-oci-digest
                           (image-peer-swarm-torrent swarm))))))
    (dolist (digest digests)
      (ignore-errors
        (funcall (node-image-distribution-tracker-call distribution)
                 :withdraw digest))))
  (gr8s.image-distribution::stop-oci-mirror
   (node-image-distribution-mirror distribution))
  (stop-image-peer-server (node-image-distribution-peer-server distribution))
  (funcall (node-image-distribution-tracker-close distribution))
  distribution)
