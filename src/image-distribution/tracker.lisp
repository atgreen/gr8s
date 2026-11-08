;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Coordinate private OCI-blob swarms and serialize cold registry fetches.

(in-package #:gr8s.image-distribution)

(defstruct tracker-peer
  node-name address port peer-id complete-p last-seen)

(defstruct origin-lease
  node-name token expires-at)

(defstruct tracker-swarm
  digest metainfo infohash (peers (make-hash-table :test #'equal)))

(defstruct tracker-view
  status metainfo infohash peers origin-node origin-expires-at)

(defstruct (image-tracker (:constructor %make-image-tracker))
  (lock (bt:make-lock "gr8s image tracker"))
  (clock #'get-universal-time)
  (origin-lease-seconds 120)
  (peer-ttl-seconds 180)
  (origins (make-hash-table :test #'equal))
  (swarms (make-hash-table :test #'equal)))

(defun make-image-tracker (&key (clock #'get-universal-time)
                                (origin-lease-seconds 120)
                                (peer-ttl-seconds 180))
  (unless (and (plusp origin-lease-seconds) (plusp peer-ttl-seconds))
    (error "Image tracker lease and peer lifetimes must be positive"))
  (%make-image-tracker :clock clock
                       :origin-lease-seconds origin-lease-seconds
                       :peer-ttl-seconds peer-ttl-seconds))

(defun canonical-oci-digest (digest)
  (parse-oci-sha256 digest)
  (format nil "sha256:~A" (string-downcase (subseq digest 7))))

(defun new-origin-token ()
  (ironclad:random-data 32))

(defun origin-token= (left right)
  (and (typep left '(vector (unsigned-byte 8)))
       (typep right '(vector (unsigned-byte 8)))
       (= (length left) (length right))
       (ironclad:constant-time-equal left right)))

(defun live-origin-lease (tracker digest now)
  (let ((lease (gethash digest (image-tracker-origins tracker))))
    (when (and lease (<= (origin-lease-expires-at lease) now))
      (remhash digest (image-tracker-origins tracker))
      (setf lease nil))
    lease))

(defun tracker-acquire-origin (tracker digest node-name)
  "Grant NODE-NAME the exclusive cold-fetch lease, or report its current owner."
  (let ((digest (canonical-oci-digest digest)))
    (bt:with-lock-held ((image-tracker-lock tracker))
      (when (gethash digest (image-tracker-swarms tracker))
        (return-from tracker-acquire-origin (values :available nil nil nil)))
      (let* ((now (funcall (image-tracker-clock tracker)))
             (lease (live-origin-lease tracker digest now)))
        (if lease
            (if (string= node-name (origin-lease-node-name lease))
                (values :granted (copy-seq (origin-lease-token lease))
                        (origin-lease-expires-at lease) node-name)
                (values :waiting nil (origin-lease-expires-at lease)
                        (origin-lease-node-name lease)))
            (let ((lease (make-origin-lease
                          :node-name node-name
                          :token (new-origin-token)
                          :expires-at (+ now
                                         (image-tracker-origin-lease-seconds
                                          tracker)))))
              (setf (gethash digest (image-tracker-origins tracker)) lease)
              (values :granted (copy-seq (origin-lease-token lease))
                      (origin-lease-expires-at lease) node-name)))))))

(defun require-current-origin (tracker digest node-name token now)
  (let ((lease (live-origin-lease tracker digest now)))
    (unless (and lease
                 (string= node-name (origin-lease-node-name lease))
                 (origin-token= token (origin-lease-token lease)))
      (error "Node ~A does not hold the current origin lease for ~A"
             node-name digest))
    lease))

(defun tracker-renew-origin (tracker digest node-name token)
  (let ((digest (canonical-oci-digest digest)))
    (bt:with-lock-held ((image-tracker-lock tracker))
      (let* ((now (funcall (image-tracker-clock tracker)))
             (lease (require-current-origin tracker digest node-name token now)))
        (setf (origin-lease-expires-at lease)
              (+ now (image-tracker-origin-lease-seconds tracker)))))))

(defun validate-peer-endpoint (address port peer-id)
  (unless (and (stringp address) (plusp (length address)))
    (error "A tracker peer requires a non-empty address"))
  (unless (typep port '(integer 1 65535))
    (error "A tracker peer port must be between 1 and 65535"))
  (unless (and (typep peer-id '(vector (unsigned-byte 8)))
               (= 20 (length peer-id)))
    (error "A BitTorrent peer id must contain exactly 20 octets")))

(defun validated-metainfo-infohash (digest metainfo)
  "Validate canonical BEP 52 metadata and bind its single filename to DIGEST."
  (let* ((decoded (decode-bencode metainfo))
         (info (bencode-value decoded "info"))
         (name (bencode-value info "name"))
         (file-tree (bencode-value info "file tree"))
         (hex (subseq digest 7)))
    (unless (equalp metainfo (encode-bencode decoded))
      (error "Torrent metadata must use canonical bencoding"))
    (unless (= 2 (bencode-value info "meta version" 0))
      (error "OCI blob torrents must use BitTorrent v2 metadata"))
    (unless (and name (string= hex (trivial-utf-8:utf-8-bytes-to-string name))
                 (bencode-value file-tree hex))
      (error "Torrent metadata is not for OCI blob ~A" digest))
    (torrent-sha256 (encode-bencode info))))

(defun put-tracker-peer (tracker swarm node-name address port peer-id complete-p now)
  (validate-peer-endpoint address port peer-id)
  (setf (gethash node-name (tracker-swarm-peers swarm))
        (make-tracker-peer :node-name node-name :address address :port port
                           :peer-id (copy-seq peer-id) :complete-p complete-p
                           :last-seen now))
  tracker)

(defun tracker-publish-swarm
    (tracker digest node-name token metainfo address port peer-id)
  "Publish final metadata and announce the origin as the first complete peer."
  (let ((digest (canonical-oci-digest digest)))
    (bt:with-lock-held ((image-tracker-lock tracker))
      (when (gethash digest (image-tracker-swarms tracker))
        (error "A swarm already exists for ~A" digest))
      (let ((now (funcall (image-tracker-clock tracker))))
        (require-current-origin tracker digest node-name token now)
        (let* ((infohash (validated-metainfo-infohash digest metainfo))
               (swarm (make-tracker-swarm
                       :digest digest :metainfo (copy-seq metainfo)
                       :infohash infohash)))
          (put-tracker-peer tracker swarm node-name address port peer-id t now)
          (setf (gethash digest (image-tracker-swarms tracker)) swarm)
          (remhash digest (image-tracker-origins tracker))
          (copy-seq infohash))))))

(defun tracker-announce-peer
    (tracker digest node-name address port peer-id &key complete-p)
  (let ((digest (canonical-oci-digest digest)))
    (bt:with-lock-held ((image-tracker-lock tracker))
      (let ((swarm (or (gethash digest (image-tracker-swarms tracker))
                       (error "No published swarm exists for ~A" digest))))
        (put-tracker-peer tracker swarm node-name address port peer-id
                          complete-p (funcall (image-tracker-clock tracker)))))))

(defun expire-swarm-peers (tracker swarm now)
  (let ((deadline (- now (image-tracker-peer-ttl-seconds tracker))))
    (maphash (lambda (node-name peer)
               (when (< (tracker-peer-last-seen peer) deadline)
                 (remhash node-name (tracker-swarm-peers swarm))))
             (tracker-swarm-peers swarm))))

(defun copy-tracker-peer-for-view (peer)
  (let ((copy (copy-tracker-peer peer)))
    (setf (tracker-peer-peer-id copy) (copy-seq (tracker-peer-peer-id peer)))
    copy))

(defun tracker-lookup (tracker digest requesting-node &key peer-ranker (maximum-peers 8))
  "Return a bounded peer view, optionally ordered by PEER-RANKER.
PEER-RANKER receives the copied peer list, outside the tracker lock, and must
return a list.  This keeps network-policy decisions out of swarm mutation."
  (let ((digest (canonical-oci-digest digest)))
    (let ((view
            (bt:with-lock-held ((image-tracker-lock tracker))
              (let* ((now (funcall (image-tracker-clock tracker)))
                     (swarm (gethash digest (image-tracker-swarms tracker))))
                (if swarm
                    (progn
                      (expire-swarm-peers tracker swarm now)
                      (make-tracker-view
                       :status :available
                       :metainfo (copy-seq (tracker-swarm-metainfo swarm))
                       :infohash (copy-seq (tracker-swarm-infohash swarm))
                       :peers (loop for node-name being the hash-keys
                                      of (tracker-swarm-peers swarm)
                                    using (hash-value peer)
                                    unless (string= node-name requesting-node)
                                      collect (copy-tracker-peer-for-view peer))))
                    (let ((lease (live-origin-lease tracker digest now)))
                      (make-tracker-view
                       :status (if lease :waiting :missing)
                       :origin-node (and lease (origin-lease-node-name lease))
                       :origin-expires-at (and lease
                                               (origin-lease-expires-at lease)))))))))
      (when (eq :available (tracker-view-status view))
        (let* ((peers (tracker-view-peers view))
               (ranked (if peer-ranker (funcall peer-ranker peers) peers)))
          (setf (tracker-view-peers view)
                (subseq ranked 0 (min (length ranked)
                                      (max 1 (min maximum-peers 32)))))))
      view)))

(defun tracker-withdraw-peer (tracker digest node-name)
  (let ((digest (canonical-oci-digest digest)))
    (bt:with-lock-held ((image-tracker-lock tracker))
      (let ((swarm (gethash digest (image-tracker-swarms tracker))))
        (when swarm (remhash node-name (tracker-swarm-peers swarm)))))))

(defun tracker-remove-node (tracker node-name)
  "Withdraw NODE-NAME from every swarm and release any origin lease it owns."
  (bt:with-lock-held ((image-tracker-lock tracker))
    (maphash (lambda (digest lease)
               (when (string= node-name (origin-lease-node-name lease))
                 (remhash digest (image-tracker-origins tracker))))
             (image-tracker-origins tracker))
    (maphash (lambda (digest swarm)
               (declare (ignore digest))
               (remhash node-name (tracker-swarm-peers swarm)))
             (image-tracker-swarms tracker))))
