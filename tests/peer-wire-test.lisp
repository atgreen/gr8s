;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0

(in-package #:gr8s/tests)

(test bittorrent-peer-handshake-is-the-standard-68-byte-form
  (let* ((infohash (make-array 32 :element-type '(unsigned-byte 8)
                                  :initial-contents (loop for i below 32 collect i)))
         (peer-id (bt-octets "-GR8001-ABCDEFGHIJKL"))
         (encoded (gr8s.image-distribution::encode-peer-handshake
                   infohash peer-id))
         (decoded (gr8s.image-distribution::decode-peer-handshake encoded)))
    (is (= 68 (length encoded)))
    (is (= 19 (aref encoded 0)))
    (is (equalp (bt-octets "BitTorrent protocol") (subseq encoded 1 20)))
    (is (equalp (subseq infohash 0 20)
                (gr8s.image-distribution::peer-handshake-infohash decoded)))
    (is (equalp peer-id
                (gr8s.image-distribution::peer-handshake-peer-id decoded)))))

(test bittorrent-peer-wire-roundtrips-standard-messages
  (dolist (message
           (list (gr8s.image-distribution::make-peer-message :kind :keepalive)
                 (gr8s.image-distribution::make-peer-message :kind :choke)
                 (gr8s.image-distribution::make-peer-message :kind :unchoke)
                 (gr8s.image-distribution::make-peer-message :kind :interested)
                 (gr8s.image-distribution::make-peer-message :kind :have :piece 7)
                 (gr8s.image-distribution::make-peer-message
                  :kind :bitfield :payload #(128 1))
                 (gr8s.image-distribution::make-peer-message
                  :kind :request :piece 2 :begin 16384 :length 4096)
                 (gr8s.image-distribution::make-peer-message
                  :kind :piece :piece 2 :begin 16384 :payload #(1 2 3 4))
                 (gr8s.image-distribution::make-peer-message
                  :kind :cancel :piece 2 :begin 16384 :length 4096)))
    (let ((decoded
            (gr8s.image-distribution::decode-peer-message
             (gr8s.image-distribution::encode-peer-message message))))
      (is (eq (gr8s.image-distribution::peer-message-kind message)
              (gr8s.image-distribution::peer-message-kind decoded)))
      (is (= (gr8s.image-distribution::peer-message-piece message)
             (gr8s.image-distribution::peer-message-piece decoded)))
      (is (= (gr8s.image-distribution::peer-message-begin message)
             (gr8s.image-distribution::peer-message-begin decoded)))
      (is (= (gr8s.image-distribution::peer-message-length message)
             (gr8s.image-distribution::peer-message-length decoded)))
      (is (equalp (gr8s.image-distribution::peer-message-payload message)
                  (gr8s.image-distribution::peer-message-payload decoded)))))
  (signals error
    (gr8s.image-distribution::encode-peer-message
     (gr8s.image-distribution::make-peer-message
      :kind :request :piece 0 :begin 0 :length 16385))))

(test bittorrent-rarest-first-prefers-the-least-available-missing-piece
  (is (= 2 (gr8s.image-distribution::rarest-missing-piece
            #(t nil nil nil) #(10 4 1 2) #(nil t t nil))))
  (is (null (gr8s.image-distribution::rarest-missing-piece
             #(t t) #(1 1) #(t t)))))

(test bittorrent-piece-store-publishes-only-hash-verified-pieces-and-resumes
  (let* ((bytes (make-array 20000 :element-type '(unsigned-byte 8)))
         (source nil)
         (destination nil))
    (loop for index below (length bytes)
          do (setf (aref bytes index) (mod index 251)))
    (setf source (bt-temp-file bytes)
          destination (merge-pathnames
                       (format nil "gr8s-peer-destination-~36R.blob"
                               (random most-positive-fixnum))
                       (uiop:temporary-directory)))
    (unwind-protect
         (let* ((digest (format nil "sha256:~A"
                                (ironclad:byte-array-to-hex-string
                                 (ironclad:digest-sequence :sha256 bytes))))
                (torrent (gr8s.image-distribution::make-oci-blob-torrent
                          source digest 16384))
                (store (gr8s.image-distribution::open-blob-store
                        torrent destination)))
           (is (eq :complete
                   (gr8s.image-distribution::accept-block
                    store 0 0 (subseq bytes 0 16384))))
           (is-true (aref (gr8s.image-distribution::completed-pieces store) 0))
           (let ((corrupt (copy-seq (subseq bytes 16384))))
             (setf (aref corrupt 0) (logxor #xff (aref corrupt 0)))
             (is (eq :corrupt
                     (gr8s.image-distribution::accept-block
                      store 1 0 corrupt))))
           (is (zerop (aref (gr8s.image-distribution::completed-pieces store) 1)))
           (is (eq :complete
                   (gr8s.image-distribution::accept-block
                    store 1 0 (subseq bytes 16384))))
           (is-true (gr8s.image-distribution::piece-store-complete-p store))
           (let ((resumed (gr8s.image-distribution::open-blob-store
                           torrent destination :resume-p t)))
             (is-true (gr8s.image-distribution::piece-store-complete-p resumed)))
           (is (equalp bytes
                       (with-open-file (stream destination :direction :input
                                                           :element-type '(unsigned-byte 8))
                         (let ((result (make-array (file-length stream)
                                                   :element-type '(unsigned-byte 8))))
                           (read-sequence result stream)
                           result)))))
      (when source (ignore-errors (delete-file source)))
      (when destination (ignore-errors (delete-file destination))))))

(test bittorrent-piece-store-verifies-a-short-piece-at-a-large-piece-length
  (let* ((bytes (bt-octets "short OCI config blob"))
         (source (bt-temp-file bytes))
         (destination (merge-pathnames
                       (format nil "gr8s-short-piece-~36R.blob"
                               (random most-positive-fixnum))
                       (uiop:temporary-directory))))
    (unwind-protect
         (let* ((digest (format nil "sha256:~A"
                                (ironclad:byte-array-to-hex-string
                                 (ironclad:digest-sequence :sha256 bytes))))
                (torrent (gr8s.image-distribution::make-oci-blob-torrent
                          source digest (* 1024 1024)))
                (store (gr8s.image-distribution::open-blob-store
                        torrent destination)))
           (is (eq :complete
                   (gr8s.image-distribution::accept-block
                    store 0 0 bytes)))
           (is-true (gr8s.image-distribution::piece-store-complete-p store)))
      (ignore-errors (delete-file source))
      (ignore-errors (delete-file destination)))))

(defun make-test-image-peer-identity (pki directory node-name)
  (let* ((key (merge-pathnames (format nil "~A.key" node-name) directory))
         (certificate (merge-pathnames (format nil "~A.crt" node-name) directory))
         (csr (gr8s:generate-node-key-and-csr node-name key))
         (pem (gr8s:enroll-node-csr
               pki node-name (gr8s:create-join-token pki node-name)
               (gr8s:cluster-pki-ca-fingerprint pki) csr)))
    (ensure-directories-exist certificate)
    (with-open-file (stream certificate :direction :output
                                        :if-exists :supersede
                                        :if-does-not-exist :create)
      (write-string pem stream))
    (values certificate key)))

(defun start-test-image-seeder
    (pki certificate key torrent pathname peer-id &key disconnect-before-handshake)
  (let* ((listener (usocket:socket-listen
                    "127.0.0.1" 0 :reuse-address t
                    :element-type '(unsigned-byte 8)))
         (thread
           (bt:make-thread
            (lambda ()
              (handler-case
                  (let ((socket nil) (tls nil))
                    (unwind-protect
                         (progn
                           (setf socket (usocket:socket-accept
                                         listener :element-type '(unsigned-byte 8)))
                           (multiple-value-bind (authenticated name)
                               (gr8s::make-image-peer-server-stream
                                (usocket:socket-stream socket) pki certificate key)
                             (declare (ignore name))
                             (setf tls authenticated)
                             (unless disconnect-before-handshake
                               (gr8s.image-distribution::serve-peer-stream
                                tls torrent pathname peer-id
                                (make-array
                                 (gr8s.image-distribution::torrent-piece-count torrent)
                                 :element-type 'bit :initial-element 1)))))
                      (when tls (ignore-errors (close tls :abort t)))
                      (when socket (ignore-errors (usocket:socket-close socket)))))
                ;; Recovery tests deliberately abandon bad peers mid-session.
                (error () nil)))
            :name "gr8s test image seeder")))
    (values listener thread)))

(test two-image-peers-transfer-a-blob-over-certificate-bound-mtls-bittorrent
  (let* ((directory (merge-pathnames
                     (format nil "gr8s-image-peer-~36R/"
                             (random most-positive-fixnum))
                     (uiop:temporary-directory)))
         (pki (gr8s:ensure-cluster-pki (merge-pathnames "pki/" directory)))
         (bytes (make-array 40000 :element-type '(unsigned-byte 8)))
         (source nil) (destination (merge-pathnames "download.blob" directory))
         (listener nil) (server-thread nil) (server-error nil))
    (loop for index below (length bytes)
          do (setf (aref bytes index) (mod (* index 17) 251)))
    (setf source (bt-temp-file bytes))
    (unwind-protect
         (multiple-value-bind (server-certificate server-key)
             (make-test-image-peer-identity pki directory "seed-node")
           (multiple-value-bind (client-certificate client-key)
               (make-test-image-peer-identity pki directory "leecher-node")
             (let* ((digest (format nil "sha256:~A"
                                    (ironclad:byte-array-to-hex-string
                                     (ironclad:digest-sequence :sha256 bytes))))
                    (torrent (gr8s.image-distribution::make-oci-blob-torrent
                              source digest 16384))
                    (store (gr8s.image-distribution::open-blob-store
                            torrent destination))
                    (seed-id (bt-octets "-GR8001-SEEDSEEDSEED"))
                    (leech-id (bt-octets "-GR8001-LEECHLEECHLE")))
               (setf listener
                     (usocket:socket-listen "127.0.0.1" 0 :reuse-address t
                                            :element-type '(unsigned-byte 8)))
               (setf server-thread
                     (bt:make-thread
                      (lambda ()
                        (handler-case
                            (let* ((socket (usocket:socket-accept
                                            listener :element-type '(unsigned-byte 8)))
                                   (raw (usocket:socket-stream socket)))
                              (unwind-protect
                                   (multiple-value-bind (tls node-name)
                                       (gr8s::make-image-peer-server-stream
                                        raw pki server-certificate server-key)
                                     (unless (string= "leecher-node" node-name)
                                       (error "TLS authenticated unexpected node ~A"
                                              node-name))
                                     (unwind-protect
                                          (gr8s.image-distribution::serve-peer-stream
                                           tls torrent source seed-id #*111)
                                       (ignore-errors (close tls :abort t))))
                                (ignore-errors (usocket:socket-close socket))))
                          (error (condition) (setf server-error condition))))
                      :name "gr8s test image seeder"))
               (multiple-value-bind (tls socket)
                   (gr8s::make-image-peer-client-stream
                    "127.0.0.1" (usocket:get-local-port listener) "seed-node"
                    pki client-certificate client-key :timeout 10)
                 (unwind-protect
                      (is-true
                       (gr8s.image-distribution::download-from-peer-stream
                        tls torrent store leech-id :pipeline-depth 4))
                   (ignore-errors (close tls :abort t))
                   (ignore-errors (usocket:socket-close socket))))
               (bt:join-thread server-thread)
               (is (null server-error) "~A" server-error)
               (is (equalp bytes
                           (with-open-file (stream destination :direction :input
                                                               :element-type '(unsigned-byte 8))
                             (let ((result (make-array (file-length stream)
                                                       :element-type '(unsigned-byte 8))))
                               (read-sequence result stream)
                               result)))))))
      (when listener (ignore-errors (usocket:socket-close listener)))
      (when (and server-thread (bt:thread-alive-p server-thread))
        (ignore-errors (bt:destroy-thread server-thread)))
      (when source (ignore-errors (delete-file source)))
      (uiop:delete-directory-tree directory :validate t :if-does-not-exist :ignore))))

(test image-download-recovers-from-disconnect-and-corrupt-peer
  (let* ((directory (merge-pathnames
                     (format nil "gr8s-image-recovery-~36R/"
                             (random most-positive-fixnum))
                     (uiop:temporary-directory)))
         (pki (gr8s:ensure-cluster-pki (merge-pathnames "pki/" directory)))
         (bytes (make-array 50000 :element-type '(unsigned-byte 8)))
         (source nil) (corrupt-source nil)
         (destination (merge-pathnames "download.blob" directory))
         (listeners nil) (threads nil))
    (loop for index below (length bytes)
          do (setf (aref bytes index) (mod (* index 29) 251)))
    (setf source (bt-temp-file bytes))
    (let ((corrupt (copy-seq bytes)))
      (setf (aref corrupt 0) (logxor #xff (aref corrupt 0)))
      (setf corrupt-source (bt-temp-file corrupt)))
    (unwind-protect
         (multiple-value-bind (leecher-certificate leecher-key)
             (make-test-image-peer-identity pki directory "leecher-node")
           (multiple-value-bind (dead-certificate dead-key)
               (make-test-image-peer-identity pki directory "dead-node")
             (multiple-value-bind (bad-certificate bad-key)
                 (make-test-image-peer-identity pki directory "bad-node")
               (multiple-value-bind (good-certificate good-key)
                   (make-test-image-peer-identity pki directory "good-node")
                 (let* ((digest (format nil "sha256:~A"
                                        (ironclad:byte-array-to-hex-string
                                         (ironclad:digest-sequence :sha256 bytes))))
                        (torrent (gr8s.image-distribution::make-oci-blob-torrent
                                  source digest 16384))
                        (store (gr8s.image-distribution::open-blob-store
                                torrent destination))
                        (seed-id (bt-octets "-GR8001-SEEDSEEDSEED"))
                        (leech-id (bt-octets "-GR8001-LEECHLEECHLE"))
                        (peers nil))
                   (flet ((add-seeder (name certificate key pathname &key disconnect)
                            (multiple-value-bind (listener thread)
                                (start-test-image-seeder
                                 pki certificate key torrent pathname seed-id
                                 :disconnect-before-handshake disconnect)
                              (push listener listeners)
                              (push thread threads)
                              (setf peers
                                    (nconc peers
                                           (list
                                            (gr8s.image-distribution::make-tracker-peer
                                             :node-name name :address "127.0.0.1"
                                             :port (usocket:get-local-port listener))))))))
                     (add-seeder "dead-node" dead-certificate dead-key source
                                 :disconnect t)
                     (add-seeder "bad-node" bad-certificate bad-key corrupt-source)
                     (add-seeder "good-node" good-certificate good-key source))
                   (is-true
                    (gr8s::download-image-from-peers
                     torrent store leech-id peers pki leecher-certificate leecher-key
                     :pipeline-depth 4 :timeout 10))
                   (is (equalp (ironclad:digest-sequence :sha256 bytes)
                               (ironclad:digest-file :sha256 destination))))))))
      (dolist (listener listeners) (ignore-errors (usocket:socket-close listener)))
      (dolist (thread threads)
        (when (bt:thread-alive-p thread) (ignore-errors (bt:destroy-thread thread)))
        (ignore-errors (bt:join-thread thread)))
      (when source (ignore-errors (delete-file source)))
      (when corrupt-source (ignore-errors (delete-file corrupt-source)))
      (uiop:delete-directory-tree directory :validate t :if-does-not-exist :ignore))))

(test image-peer-server-stops-its-listener-cleanly
  (let* ((directory (merge-pathnames
                     (format nil "gr8s-image-stop-~36R/"
                             (random most-positive-fixnum))
                     (uiop:temporary-directory)))
         (pki (gr8s:ensure-cluster-pki (merge-pathnames "pki/" directory)))
         (server nil))
    (unwind-protect
         (multiple-value-bind (certificate key)
             (make-test-image-peer-identity pki directory "stop-node")
           (setf server
                 (gr8s::start-image-peer-server
                  pki certificate key (bt-octets "-GR8001-STOPSTOPSTOP")
                  :host "127.0.0.1" :port 0))
           (is (plusp (gr8s::image-peer-server-port server)))
           (gr8s::stop-image-peer-server server)
           (is-false (bt:thread-alive-p (gr8s::image-peer-server-thread server))))
      (when (and server
                 (bt:thread-alive-p (gr8s::image-peer-server-thread server)))
        (ignore-errors (gr8s::stop-image-peer-server server)))
      (uiop:delete-directory-tree directory :validate t :if-does-not-exist :ignore))))

(test image-peer-server-stops-blocked-accept-and-tls-readers
  (let* ((directory (merge-pathnames
                     (format nil "gr8s-image-blocked-stop-~36R/" (random most-positive-fixnum))
                     (uiop:temporary-directory)))
         (pki (gr8s:ensure-cluster-pki (merge-pathnames "pki/" directory))))
    (unwind-protect
         (multiple-value-bind (certificate key)
             (make-test-image-peer-identity pki directory "blocked-stop-node")
           (dolist (half-open '(nil t))
             (let* ((server (gr8s::start-image-peer-server
                             pki certificate key (bt-octets "-GR8001-STOPSTOPSTOP")
                             :host "0.0.0.0" :port 0))
                    (port (gr8s::image-peer-server-port server))
                    (client nil) (stopper nil))
               (unwind-protect
                    (progn
                      (when half-open
                        (setf client (usocket:socket-connect
                                      "127.0.0.1" port :element-type '(unsigned-byte 8) :timeout 1))
                        ;; Leave a TLS reader waiting for the rest of its record.
                        (write-sequence #(22 3 3 0 20) (usocket:socket-stream client))
                        (force-output (usocket:socket-stream client))
                        (loop repeat 500
                              when (bt:with-lock-held ((gr8s.security::image-peer-server-lock server))
                                     (not (null (gr8s.security::image-peer-server-clients server))))
                                do (return)
                              do (sleep .01)
                              finally (error "Image peer listener did not accept the test client")))
                      ;; The old immediate-stop test often closes the socket
                      ;; before the listener enters ACCEPT and misses the hang.
                      (sleep .1)
                      (setf stopper
                            (bt:make-thread
                             (lambda () (gr8s::stop-image-peer-server server) :stopped)
                             :name "test image peer shutdown"))
                      (let ((result (sb-thread:join-thread stopper :timeout 5 :default :timed-out)))
                        (is (eq :stopped result))
                        (when (eq :timed-out result)
                          (let ((*print-level* 2) (*print-length* 3))
                            (gr8s::debug-backtraces "image peer" 1))))
                      (is-false (bt:thread-alive-p (gr8s::image-peer-server-thread server))))
                 (when client (ignore-errors (usocket:socket-close client)))
                 ;; Bound the regression even when testing the broken code:
                 ;; wake its blocked ACCEPT so it can observe the stop flag.
                 (when (and stopper (bt:thread-alive-p stopper))
                   (let ((wake (ignore-errors (usocket:socket-connect "127.0.0.1" port :timeout 1))))
                     (when wake (usocket:socket-close wake)))
                   (sb-thread:join-thread stopper :timeout 5 :default :still-blocked))))))
      (uiop:delete-directory-tree directory :validate t :if-does-not-exist :ignore))))
