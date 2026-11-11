;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
(in-package #:gr8s.image-distribution)

(defparameter *image-tracker-snapshot-kinds*
  '("imageTrackerConfig" "imageTrackerOrigin" "imageTrackerSwarm" "imageTrackerPeer" "imageTrackerMetainfoChunk"))

(defun image-tracker-record-p (record)
  (member (gethash "kind" record) *image-tracker-snapshot-kinds* :test #'equal))

(defun image-tracker-object (&rest pairs)
  (let ((object (make-hash-table :test #'equal)))
    (loop for (key value) on pairs by #'cddr do (setf (gethash key object) value))
    object))

(defun freeze-image-tracker (tracker)
  "Copy mutable tracker containers without encoding or copying torrent payloads.
Published swarm metainfo/infohash are owned by the tracker and never modified;
public views return copies. Lease tokens may originate with a caller, so copy
those small vectors as well as peer identities. The result owns its own mutex."
  (bt:with-lock-held ((image-tracker-lock tracker))
    (let ((frozen (make-image-tracker
                   :origin-lease-seconds (image-tracker-origin-lease-seconds tracker)
                   :peer-ttl-seconds (image-tracker-peer-ttl-seconds tracker))))
      (maphash
       (lambda (digest lease)
         (let ((copy (copy-origin-lease lease)))
           (setf (origin-lease-token copy) (copy-seq (origin-lease-token lease))
                 (gethash digest (image-tracker-origins frozen)) copy)))
       (image-tracker-origins tracker))
      (maphash
       (lambda (digest swarm)
         (let ((copy (copy-tracker-swarm swarm))
               (peers (make-hash-table :test #'equal)))
           (maphash (lambda (node peer)
                      (setf (gethash node peers) (copy-tracker-peer-for-view peer)))
                    (tracker-swarm-peers swarm))
           (setf (tracker-swarm-peers copy) peers
                 (gethash digest (image-tracker-swarms frozen)) copy)))
       (image-tracker-swarms tracker))
      frozen)))

(defun map-image-tracker-records (tracker function)
  ;; Neither base64 encoding nor a potentially slow consumer holds the live
  ;; tracker mutex. All records describe the same frozen boundary.
  (map-frozen-image-tracker-records (freeze-image-tracker tracker) function))

(defun map-frozen-image-tracker-records (tracker function)
  (bt:with-lock-held ((image-tracker-lock tracker))
    (funcall function (image-tracker-object "kind" "imageTrackerConfig"
                                          "originLeaseSeconds" (image-tracker-origin-lease-seconds tracker)
                                          "peerTtlSeconds" (image-tracker-peer-ttl-seconds tracker)))
    (maphash (lambda (digest lease)
               (funcall function (image-tracker-object
                                  "kind" "imageTrackerOrigin" "digest" digest "node" (origin-lease-node-name lease)
                                  "token" (ag-grpc:base64-encode (origin-lease-token lease))
                                  "expiresAt" (origin-lease-expires-at lease))))
             (image-tracker-origins tracker))
    (maphash
     (lambda (digest swarm)
       (let ((metainfo (tracker-swarm-metainfo swarm)))
         (if (<= (length metainfo) +tracker-metainfo-inline-bytes+)
             (funcall function (image-tracker-object
                                "kind" "imageTrackerSwarm" "digest" digest
                                "metainfo" (ag-grpc:base64-encode metainfo)
                                "infohash" (ag-grpc:base64-encode (tracker-swarm-infohash swarm))))
             (progn
               (funcall function (image-tracker-object
                                  "kind" "imageTrackerSwarm" "digest" digest
                                  "metainfoFormat" "chunks-v1" "metainfoBytes" (length metainfo)
                                  "metainfoSha256" (ironclad:byte-array-to-hex-string
                                                    (ironclad:digest-sequence :sha256 metainfo))
                                  "infohash" (ag-grpc:base64-encode (tracker-swarm-infohash swarm))))
               (loop for offset from 0 below (length metainfo) by +tracker-metainfo-chunk-bytes+ do
                 (funcall function
                          (image-tracker-object
                           "kind" "imageTrackerMetainfoChunk" "digest" digest "offset" offset
                           "data" (ag-grpc:base64-encode
                                   (subseq metainfo offset
                                           (min (length metainfo) (+ offset +tracker-metainfo-chunk-bytes+))))))))))
       (maphash (lambda (node peer)
                  (funcall function (image-tracker-object
                                     "kind" "imageTrackerPeer" "digest" digest "node" node
                                     "address" (tracker-peer-address peer) "port" (tracker-peer-port peer)
                                     "peerId" (ag-grpc:base64-encode (tracker-peer-peer-id peer))
                                     "complete" (tracker-peer-complete-p peer) "lastSeen" (tracker-peer-last-seen peer))))
                (tracker-swarm-peers swarm)))
     (image-tracker-swarms tracker))))

(defun tracker-record-octets (record key &optional length)
  (let* ((value (gethash key record)) (bytes (and (stringp value) (ag-grpc:base64-decode value))))
    (unless (and bytes (or (null length) (= length (length bytes)))
                 (equal value (ag-grpc:base64-encode bytes)))
      (error "Invalid snapshot tracker binary field ~A" key))
    bytes))

(defun validate-image-tracker-record (record)
  (flet ((positive (key) (let ((value (gethash key record)))
                          (and (realp value) (> value 0))))
         (time-value (key) (let ((value (gethash key record)))
                            (and (realp value) (>= value 0)))))
    (let ((kind (gethash "kind" record)))
      (unless (image-tracker-record-p record) (error "Unknown snapshot tracker kind"))
      (if (equal kind "imageTrackerConfig")
          (unless (and (positive "originLeaseSeconds") (positive "peerTtlSeconds"))
            (error "Invalid snapshot tracker policy"))
          (let ((digest (gethash "digest" record)) (node (gethash "node" record)))
            (unless (and (stringp digest) (equal digest (canonical-oci-digest digest)))
              (error "Invalid snapshot tracker digest"))
            (unless (or (member kind '("imageTrackerSwarm" "imageTrackerMetainfoChunk") :test #'equal)
                        (and (stringp node) (plusp (length node))))
              (error "Invalid snapshot tracker node"))
            (cond
              ((equal kind "imageTrackerOrigin")
               (tracker-record-octets record "token" 32)
               (unless (time-value "expiresAt") (error "Invalid snapshot tracker lease expiry")))
              ((equal kind "imageTrackerSwarm")
               (tracker-record-octets record "infohash" 32)
               (if (tracker-chunked-swarm-record-p record)
                   (unless (and (not (nth-value 1 (gethash "metainfo" record)))
                                (typep (gethash "metainfoBytes" record) '(integer 1 #.most-positive-fixnum))
                                (let ((hash (gethash "metainfoSha256" record)))
                                  (and (stringp hash) (= 64 (length hash))
                                       (every (lambda (char) (find char "0123456789abcdef")) hash))))
                     (error "Invalid chunked tracker metainfo header"))
                   (unless (equalp (tracker-record-octets record "infohash" 32)
                                   (validated-metainfo-infohash digest (tracker-record-octets record "metainfo")))
                     (error "Snapshot tracker metainfo/infohash mismatch"))))
              ((equal kind "imageTrackerMetainfoChunk")
               (unless (and (typep (gethash "offset" record) '(integer 0 #.most-positive-fixnum))
                            (let ((data (gethash "data" record)))
                              (and (stringp data) (<= (length data) (* 4 (ceiling +tracker-metainfo-chunk-bytes+ 3)))))
                            (<= 1 (length (tracker-record-octets record "data")) +tracker-metainfo-chunk-bytes+))
                 (error "Invalid tracker metainfo chunk")))
              ((equal kind "imageTrackerPeer")
               (validate-peer-endpoint (gethash "address" record) (gethash "port" record)
                                       (tracker-record-octets record "peerId" 20))
               (unless (and (member (gethash "complete" record) '(t nil)) (time-value "lastSeen"))
                 (error "Invalid snapshot tracker peer"))))))))
  record)

(defun clear-image-tracker-state (tracker)
  (bt:with-lock-held ((image-tracker-lock tracker))
    (setf (image-tracker-origins tracker) (make-hash-table :test #'equal)
          (image-tracker-swarms tracker) (make-hash-table :test #'equal)
          (image-tracker-origin-lease-seconds tracker) 120
          (image-tracker-peer-ttl-seconds tracker) 180))
  tracker)

(defun apply-image-tracker-record-unlocked (tracker record)
  (validate-image-tracker-record record)
  (let ((kind (gethash "kind" record)) (digest (gethash "digest" record)) (node (gethash "node" record)))
    (cond
      ((equal kind "imageTrackerConfig")
       (setf (image-tracker-origin-lease-seconds tracker) (gethash "originLeaseSeconds" record)
             (image-tracker-peer-ttl-seconds tracker) (gethash "peerTtlSeconds" record)))
      ((equal kind "imageTrackerOrigin")
       (setf (gethash digest (image-tracker-origins tracker))
             (make-origin-lease :node-name node :token (tracker-record-octets record "token" 32)
                                :expires-at (gethash "expiresAt" record))))
      ((equal kind "imageTrackerSwarm")
       (unless (tracker-chunked-swarm-record-p record)
         ;; A peer may occur before its swarm in the input.
         (let ((swarm (or (gethash digest (image-tracker-swarms tracker))
                          (setf (gethash digest (image-tracker-swarms tracker)) (make-tracker-swarm :digest digest)))))
           (setf (tracker-swarm-metainfo swarm) (tracker-record-octets record "metainfo")
                 (tracker-swarm-infohash swarm) (tracker-record-octets record "infohash" 32)))))
      ((equal kind "imageTrackerPeer")
       (let ((swarm (or (gethash digest (image-tracker-swarms tracker))
                        (setf (gethash digest (image-tracker-swarms tracker)) (make-tracker-swarm :digest digest)))))
         (put-tracker-peer tracker swarm node (gethash "address" record) (gethash "port" record)
                           (tracker-record-octets record "peerId" 20) (gethash "complete" record) (gethash "lastSeen" record))))))
  tracker)

(defun open-image-tracker-state (path)
  (let ((fd (sb-posix:open (namestring path) (logior sb-posix:o-rdonly sb-posix:o-nofollow sb-posix:o-nonblock) 0)))
    (handler-case
        (progn
          (let ((stat (sb-posix:fstat fd)))
            (unless (and (sb-posix:s-isreg (sb-posix:stat-mode stat))
                         (= 1 (sb-posix:stat-nlink stat)) (= (sb-posix:geteuid) (sb-posix:stat-uid stat))
                         (= #o600 (logand #o777 (sb-posix:stat-mode stat))) (plusp (sb-posix:stat-size stat)))
              (error "Unsafe image tracker state file")))
          (sb-sys:make-fd-stream fd :input t :element-type '(unsigned-byte 8) :auto-close t))
      (error (condition) (sb-posix:close fd) (error condition)))))

(defun install-streamed-tracker-metainfo (tracker header stream total)
  ;; Metainfo itself is live tracker state. Assemble it once, after validation;
  ;; validation and materialization never retain all swarm payloads together.
  (let* ((digest (gethash "digest" header))
         (bytes (make-array total :element-type '(unsigned-byte 8)))
         (swarm (or (gethash digest (image-tracker-swarms tracker))
                    (setf (gethash digest (image-tracker-swarms tracker))
                          (make-tracker-swarm :digest digest)))))
    (unless (= total (read-sequence bytes stream)) (error "Truncated tracker metainfo spool"))
    (setf (tracker-swarm-metainfo swarm) bytes
          (tracker-swarm-infohash swarm) (tracker-record-octets header "infohash" 32))))

(defun load-store-image-tracker (store)
  (let* ((tracker (gr8s.store:pod-store-image-tracker store))
         (path (merge-pathnames "image-tracker/state.jsonl" (gr8s.store:store-data-path store))))
    (clear-image-tracker-state tracker)
    (when (gr8s.store::store-generation-stat path)
      (let ((index (gr8s.resources::make-snapshot-validation-index
                    :tracker-metainfo-directory (uiop:pathname-directory-pathname path)
                    :tracker-metainfo-consumer
                    (lambda (header stream total) (install-streamed-tracker-metainfo tracker header stream total))))
            (buffer (make-array 4096 :element-type '(unsigned-byte 8) :adjustable t :fill-pointer 0)))
        (unwind-protect
             (bt:with-lock-held ((image-tracker-lock tracker))
               (with-open-stream (stream (open-image-tracker-state path))
                 (loop for record = (gr8s.resources::read-store-snapshot-record stream buffer (* 16 1024 1024))
                       while record do
                         (validate-image-tracker-record record)
                         (gr8s.resources::index-store-snapshot-record index record)
                         (apply-image-tracker-record-unlocked tracker record)))
               (gr8s.resources::finish-store-snapshot-index index)
               (unless (gr8s.resources::snapshot-validation-index-tracker-config-p index)
                 (error "Snapshot tracker file has no configuration")))
          (gr8s.resources::close-snapshot-validation-index index)))))
  store)
