;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
(in-package #:gr8s/tests)
(def-suite store-image-tracker-snapshot :in gr8s)
(in-suite store-image-tracker-snapshot)

(defun populate-snapshot-tracker (store)
  (let ((tracker (gr8s.store:pod-store-image-tracker store)))
    (setf (gr8s.image-distribution::image-tracker-clock tracker) (lambda () 1000)
          (gr8s.image-distribution::image-tracker-origin-lease-seconds tracker) 30
          (gr8s.image-distribution::image-tracker-peer-ttl-seconds tracker) 90)
    (gr8s.image-distribution::tracker-acquire-origin
     tracker "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" "origin")
    (multiple-value-bind (digest torrent) (tracker-test-torrent)
      (multiple-value-bind (status token)
          (gr8s.image-distribution::tracker-acquire-origin tracker digest "seed")
        (declare (ignore status))
        (gr8s.image-distribution::tracker-publish-swarm
         tracker digest "seed" token (gr8s.image-distribution::torrent-metainfo torrent)
         "10.0.0.1" 6881 (bt-octets "-GR8001-AAAAAAAAAAAA")))
      (gr8s.image-distribution::tracker-announce-peer
       tracker digest "downloader" "10.0.0.2" 6882 (bt-octets "-GR8001-BBBBBBBBBBBB") :complete-p nil))
    tracker))

(defun snapshot-tracker-records (tracker)
  (let ((records nil))
    (gr8s.image-distribution::map-image-tracker-records tracker (lambda (row) (push row records)))
    (sort records #'string< :key (lambda (row) (format nil "~A/~A/~A" (gethash "kind" row)
                                                       (gethash "digest" row) (gethash "node" row))))))

(test tracker-snapshot-consumer-runs-outside-live-lock-at-one-boundary
  (with-temporary-store (store root)
    (declare (ignore root))
    (let* ((tracker (populate-snapshot-tracker store))
           (expected (snapshot-tracker-records tracker))
           (records nil))
      (gr8s.image-distribution::map-image-tracker-records
       tracker
       (lambda (row)
         (is (not (sb-thread:holding-mutex-p
                   (gr8s.image-distribution::image-tracker-lock tracker))))
         ;; A real live-state mutation from the consumer would deadlock if the
         ;; mapper retained the live mutex. Frozen origins/swarms must survive.
         (unless records
           (gr8s.image-distribution::clear-image-tracker-state tracker))
         (push row records)))
      (is (equalp expected
                  (sort records #'string<
                        :key (lambda (row)
                               (format nil "~A/~A/~A" (gethash "kind" row)
                                       (gethash "digest" row) (gethash "node" row))))))
      (is (= 1 (length (snapshot-tracker-records tracker))))
      (signals error
        (gr8s.image-distribution::map-image-tracker-records
         tracker (lambda (row) (declare (ignore row)) (error "consumer failed"))))
      (is (= 1 (length (snapshot-tracker-records tracker)))))))

(test frozen-tracker-copies-mutable-state-and-shares-owned-payloads
  (with-temporary-store (store root)
    (declare (ignore root))
    (let* ((tracker (populate-snapshot-tracker store))
           (frozen (gr8s.image-distribution::freeze-image-tracker tracker))
           (expected (snapshot-tracker-records frozen)))
      (is (not (eq (gr8s.image-distribution::image-tracker-lock tracker)
                   (gr8s.image-distribution::image-tracker-lock frozen))))
      (maphash
       (lambda (digest lease)
         (let ((copy (gethash digest (gr8s.image-distribution::image-tracker-origins frozen))))
           (is (not (eq lease copy)))
           (is (not (eq (gr8s.image-distribution::origin-lease-token lease)
                        (gr8s.image-distribution::origin-lease-token copy))))
           (incf (gr8s.image-distribution::origin-lease-expires-at lease))
           (let ((token (gr8s.image-distribution::origin-lease-token lease)))
             (setf (aref token 0) (logxor 1 (aref token 0))))))
       (gr8s.image-distribution::image-tracker-origins tracker))
      (maphash
       (lambda (digest swarm)
         (let ((copy (gethash digest (gr8s.image-distribution::image-tracker-swarms frozen))))
           (is (not (eq swarm copy)))
           (is (eq (gr8s.image-distribution::tracker-swarm-metainfo swarm)
                   (gr8s.image-distribution::tracker-swarm-metainfo copy)))
           (is (eq (gr8s.image-distribution::tracker-swarm-infohash swarm)
                   (gr8s.image-distribution::tracker-swarm-infohash copy)))
           (maphash
            (lambda (node peer)
              (let ((peer-copy (gethash node (gr8s.image-distribution::tracker-swarm-peers copy))))
                (is (not (eq peer peer-copy)))
                (is (not (eq (gr8s.image-distribution::tracker-peer-peer-id peer)
                             (gr8s.image-distribution::tracker-peer-peer-id peer-copy))))
                (setf (gr8s.image-distribution::tracker-peer-last-seen peer) 99999)))
            (gr8s.image-distribution::tracker-swarm-peers swarm))
           (clrhash (gr8s.image-distribution::tracker-swarm-peers swarm))))
       (gr8s.image-distribution::image-tracker-swarms tracker))
      (setf (gr8s.image-distribution::image-tracker-peer-ttl-seconds tracker) 1)
      (is (equalp expected (snapshot-tracker-records frozen))))))

(test tracker-snapshot-restores-complete-state-with-existing-handle
  (with-temporary-store (store root)
    (let* ((tracker (populate-snapshot-tracker store))
           (clock (gr8s.image-distribution::image-tracker-clock tracker))
           (lock (gr8s.image-distribution::image-tracker-lock tracker))
           (expected (snapshot-tracker-records tracker))
           (source (merge-pathnames "tracker-source.jsonl" root)))
      (gr8s.resources::capture-store-snapshot store source 42 7)
      ;; Records may arrive in any order, including peers before their swarm.
      (let* ((records (read-store-snapshot-records source))
             (tracker-rows (remove-if-not #'gr8s.image-distribution::image-tracker-record-p records))
             (other-rows (remove-if #'gr8s.image-distribution::image-tracker-record-p records)))
        (write-snapshot-test-records source
                                    (append (butlast other-rows) (reverse tracker-rows) (last other-rows))))
      (multiple-value-bind (path descriptor)
          (materialize-live-test-snapshot store root source)
        (is (probe-file (merge-pathnames "image-tracker/state.jsonl" path)))
        (gr8s.image-distribution::tracker-acquire-origin
         tracker "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" "later")
        (gr8s.store::quiesce-store-access store :timeout 0)
        (gr8s.store::reload-store-application store (gethash "generation" descriptor))
        (is (eq tracker (gr8s.store:pod-store-image-tracker store)))
        (is (eq clock (gr8s.image-distribution::image-tracker-clock tracker)))
        (is (eq lock (gr8s.image-distribution::image-tracker-lock tracker)))
        (is (equalp expected (snapshot-tracker-records tracker)))
        (gr8s.store::resume-store-access store)
        (let ((reopened (gr8s.store::open-store root)))
          (is (equalp expected (snapshot-tracker-records (gr8s.store:pod-store-image-tracker reopened)))))))))

(test tracker-snapshot-rejects-duplicates-and-inconsistent-relationships
  (with-temporary-store (store root)
    (populate-snapshot-tracker store)
    (let ((source (merge-pathnames "tracker-source.jsonl" root)))
      (gr8s.resources::capture-store-snapshot store source 42 7)
      (dolist (kind '("imageTrackerConfig" "imageTrackerOrigin" "imageTrackerSwarm" "imageTrackerPeer"))
        (let* ((records (read-store-snapshot-records source))
               (duplicate (snapshot-index-copy (snapshot-index-row records kind))))
          (signals error
            (gr8s.resources::validate-store-snapshot
             (snapshot-index-records-path root (append (butlast records) (list duplicate (car (last records)))))))))
      (dolist (kind '("imageTrackerConfig" "imageTrackerSwarm"))
        (let ((records (remove kind (read-store-snapshot-records source) :test #'equal
                               :key (lambda (row) (gethash "kind" row)))))
          (signals error (gr8s.resources::validate-store-snapshot (snapshot-index-records-path root records)))))
      (dolist (field '("token" "infohash"))
        (let* ((records (read-store-snapshot-records source))
               (row (snapshot-index-row records (if (equal field "token") "imageTrackerOrigin" "imageTrackerSwarm"))))
          (setf (gethash field row) "invalid")
          (signals error (gr8s.resources::validate-store-snapshot (snapshot-index-records-path root records)))))
      (let* ((records (read-store-snapshot-records source))
             (origin (snapshot-index-row records "imageTrackerOrigin"))
             (swarm (snapshot-index-row records "imageTrackerSwarm")))
        (setf (gethash "digest" origin) (gethash "digest" swarm))
        (signals error (gr8s.resources::validate-store-snapshot (snapshot-index-records-path root records)))))))

(test legacy-snapshot-clears-tracker-state-without-replacing-handle
  (with-temporary-store (store root)
    (let* ((tracker (populate-snapshot-tracker store))
           (source (merge-pathnames "legacy-source.jsonl" root)))
      (gr8s.resources::capture-store-snapshot store source 42 7)
      (let* ((records (remove-if #'gr8s.image-distribution::image-tracker-record-p (read-store-snapshot-records source)))
             (legacy (snapshot-index-records-path root records)))
        (multiple-value-bind (path descriptor)
            (materialize-live-test-snapshot store root legacy)
          (is (not (probe-file (merge-pathnames "image-tracker/state.jsonl" path))))
          (gr8s.store::quiesce-store-access store :timeout 0)
          (gr8s.store::reload-store-application store (gethash "generation" descriptor))
          (is (eq tracker (gr8s.store:pod-store-image-tracker store)))
          (is (zerop (hash-table-count (gr8s.image-distribution::image-tracker-origins tracker))))
          (is (zerop (hash-table-count (gr8s.image-distribution::image-tracker-swarms tracker))))
          (is (= 120 (gr8s.image-distribution::image-tracker-origin-lease-seconds tracker)))
          (is (= 180 (gr8s.image-distribution::image-tracker-peer-ttl-seconds tracker)))
          (gr8s.store::resume-store-access store))))))

(test tracker-state-loader-rejects-unsafe-files
  (with-temporary-store (store root)
    (let ((path (merge-pathnames "image-tracker/state.jsonl" root)))
      (gr8s.security::write-private-text-exclusively
       path "{\"kind\":\"imageTrackerConfig\",\"originLeaseSeconds\":30,\"peerTtlSeconds\":90}")
      (sb-posix:chmod (namestring path) #o644)
      (signals error (gr8s.store::open-store root))
      (sb-posix:chmod (namestring path) #o600)
      (let ((link (merge-pathnames "tracker-link.jsonl" root)))
        (sb-posix:link (namestring path) (namestring link))
        (signals error (gr8s.store::open-store root))
        (delete-file link))
      (let ((target (merge-pathnames "tracker-target.jsonl" root)))
        (rename-file path target)
        (sb-posix:symlink (namestring target) (namestring path))
        (signals error (gr8s.store::open-store root))
        (delete-file path))
      (gr8s.security::write-private-text-exclusively path "")
      (signals error (gr8s.store::open-store root)))))


(test large-canonical-tracker-metainfo-survives-streamed-snapshot-and-reopen
  ;; A legitimate optional BEP52 field can cross the snapshot JSON string
  ;; limit while leaving the OCI filename and infohash unchanged.
  (dolist (padding-size '(1572600 1573000 3145728))
    (with-temporary-store (store root)
      (multiple-value-bind (digest torrent) (tracker-test-torrent)
        (let* ((tracker (gr8s.store:pod-store-image-tracker store))
               (decoded (gr8s.image-distribution::decode-bencode
                         (gr8s.image-distribution::torrent-metainfo torrent)))
               (metainfo
                 (gr8s.image-distribution::encode-bencode
                  (gr8s.image-distribution::bencode-dictionary
                   (acons "comment" (make-array padding-size :element-type '(unsigned-byte 8)
                                                            :initial-element 120)
                          (gr8s.image-distribution::bencode-map-entries decoded)))))
               (expected (ironclad:digest-sequence :sha256 metainfo))
               (source (merge-pathnames "large-tracker.jsonl" root)))
          (is (equalp (gr8s.image-distribution::torrent-infohash torrent)
                      (gr8s.image-distribution::validated-metainfo-infohash digest metainfo)))
          (multiple-value-bind (status token)
              (gr8s.image-distribution::tracker-acquire-origin tracker digest "seed")
            (declare (ignore status))
            (gr8s.image-distribution::tracker-publish-swarm
             tracker digest "seed" token metainfo "10.0.0.1" 6881
             (bt-octets "-GR8001-AAAAAAAAAAAA")))
          (gr8s.resources::capture-store-snapshot store source 42 7)
          (gr8s.resources::validate-store-snapshot source)
          (multiple-value-bind (path descriptor)
              (materialize-live-test-snapshot store root source)
            (declare (ignore path))
            (gr8s.store::quiesce-store-access store :timeout 0)
            (unwind-protect
                 (progn
                   (gr8s.store::reload-store-application store (gethash "generation" descriptor))
                   (is (equalp expected
                               (ironclad:digest-sequence
                                :sha256
                                (gr8s.image-distribution::tracker-swarm-metainfo
                                 (gethash digest (gr8s.image-distribution::image-tracker-swarms tracker)))))))
              (gr8s.store::resume-store-access store)))
          (let* ((reopened (gr8s.store::open-store root))
                 (swarm (gethash digest (gr8s.image-distribution::image-tracker-swarms
                                         (gr8s.store:pod-store-image-tracker reopened)))))
            (is (not (null swarm)))
            (is (equalp expected (ironclad:digest-sequence
                                 :sha256 (gr8s.image-distribution::tracker-swarm-metainfo swarm))))))))))


(test streamed-tracker-metainfo-checks-canonical-filename-and-infohash
  (with-temporary-store (store root)
    (declare (ignore store))
    (multiple-value-bind (digest torrent) (tracker-test-torrent)
      (let ((bytes (gr8s.image-distribution::torrent-metainfo torrent))
            (infohash (gr8s.image-distribution::torrent-infohash torrent))
            (path (merge-pathnames "metainfo.bin" root)))
        (with-open-file (output path :direction :output :if-exists :error
                                    :element-type '(unsigned-byte 8))
          (write-sequence bytes output))
        (with-open-file (input path :element-type '(unsigned-byte 8))
          (is-true (gr8s.image-distribution::validate-tracker-metainfo-stream
                    input (length bytes) digest infohash))
          (signals error
            (gr8s.image-distribution::validate-tracker-metainfo-stream
             input (length bytes) digest (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
          (signals error
            (gr8s.image-distribution::validate-tracker-metainfo-stream
             input (1- (length bytes)) digest infohash))
          (signals error
            (gr8s.image-distribution::validate-tracker-metainfo-stream
             input (length bytes)
             "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" infohash)))))))

(defun populate-large-snapshot-tracker (store &optional (padding-size 1600000))
  (multiple-value-bind (digest torrent) (tracker-test-torrent)
    (let* ((tracker (gr8s.store:pod-store-image-tracker store))
           (decoded (gr8s.image-distribution::decode-bencode
                     (gr8s.image-distribution::torrent-metainfo torrent)))
           (metainfo (gr8s.image-distribution::encode-bencode
                      (gr8s.image-distribution::bencode-dictionary
                       (acons "comment" (make-array padding-size :element-type '(unsigned-byte 8) :initial-element 120)
                              (gr8s.image-distribution::bencode-map-entries decoded))))))
      (multiple-value-bind (status token)
          (gr8s.image-distribution::tracker-acquire-origin tracker digest "seed")
        (declare (ignore status))
        (gr8s.image-distribution::tracker-publish-swarm
         tracker digest "seed" token metainfo "10.0.0.1" 6881 (bt-octets "-GR8001-AAAAAAAAAAAA"))))))

(test tracker-metainfo-chunks-reject-corruption-before-completion-and-close-spools
  (with-temporary-store (store root)
    (populate-large-snapshot-tracker store)
    (let ((source (merge-pathnames "chunked-tracker.jsonl" root))
          (original (symbol-function 'gr8s.image-distribution::start-tracker-metainfo-input))
          (opened nil))
      (gr8s.resources::capture-store-snapshot store source 42 7)
      (unwind-protect
           (progn
             (setf (symbol-function 'gr8s.image-distribution::start-tracker-metainfo-input)
                   (lambda (&rest arguments)
                     (let ((input (apply original arguments)))
                       (push input opened)
                       input)))
             (dolist (mutation '(:offset :duplicate :missing :bytes :checksum :infohash :length))
               (let* ((records (read-store-snapshot-records source))
                      (header (find "imageTrackerSwarm" records :key (lambda (row) (gethash "kind" row)) :test #'equal))
                      (chunks (remove-if-not (lambda (row) (equal "imageTrackerMetainfoChunk" (gethash "kind" row))) records))
                      (chunk (first chunks)))
                 (is (> (length chunks) 1))
                 (ecase mutation
                   (:offset (incf (gethash "offset" chunk)))
                   (:duplicate
                    (setf records (loop for row in records append (if (eq row chunk) (list row row) (list row)))))
                   (:missing (setf records (remove (car (last chunks)) records :test #'eq)))
                   (:bytes
                    (let ((bytes (ag-grpc:base64-decode (gethash "data" chunk))))
                      (setf (aref bytes 0) (logxor 1 (aref bytes 0))
                            (gethash "data" chunk) (ag-grpc:base64-encode bytes))))
                   (:checksum (setf (gethash "metainfoSha256" header) (make-string 64 :initial-element #\0)))
                   (:infohash (setf (gethash "infohash" header)
                                   (ag-grpc:base64-encode (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))))
                   (:length (incf (gethash "metainfoBytes" header))))
                 (let* ((reason (ecase mutation
                                  ((:offset :duplicate) "Out-of-order")
                                  ((:missing :length) "Incomplete tracker metainfo")
                                  ((:bytes :checksum) "checksum mismatch")
                                  (:infohash "infohash mismatch")))
                        (condition (handler-case
                                       (progn (gr8s.resources::validate-store-snapshot
                                               (snapshot-index-records-path root records)) nil)
                                     (error (failure) failure))))
                   (is (and condition (search reason (princ-to-string condition)))
                       "Expected ~A rejection, got ~A" reason condition))
                 (is-false (some #'gr8s.image-distribution::tracker-metainfo-input-stream opened))))
             ;; A staging consumer can fail after a non-final chunk. It must not
             ;; leave an open anonymous file or deliver the successful END row.
             (let ((ended nil))
               (let ((condition
                       (handler-case
                           (progn
                             (gr8s.resources::validate-store-snapshot
                              source :function (lambda (row)
                                                 (when (equal "end" (gethash "kind" row)) (setf ended t))
                                                 (when (equal "imageTrackerMetainfoChunk" (gethash "kind" row))
                                                   (error "Injected staging consumer failure"))))
                             nil)
                         (error (failure) failure))))
                 (is (and condition (search "Injected staging consumer failure" (princ-to-string condition)))))
               (is-false ended)
               (is-false (some #'gr8s.image-distribution::tracker-metainfo-input-stream opened))))
        (setf (symbol-function 'gr8s.image-distribution::start-tracker-metainfo-input) original)))))

(test streamed-tracker-metainfo-rejects-noncanonical-structure-with-unchanged-infohash
  ;; Mutations are outside `info`: an implementation that only checks the
  ;; filename and infohash would accept them. Canonical validation must reject.
  (with-temporary-store (store root)
    (declare (ignore store))
    (multiple-value-bind (digest torrent) (tracker-test-torrent)
      (let ((original (gr8s.image-distribution::torrent-metainfo torrent))
            (infohash (gr8s.image-distribution::torrent-infohash torrent))
            (path (merge-pathnames "canonical-metainfo.bin" root)))
        (labels ((check (prefix &optional trailing)
                   (let ((bytes (concatenate '(vector (unsigned-byte 8))
                                             (subseq original 0 1) (bt-octets prefix)
                                             (subseq original 1) (bt-octets (or trailing "")))))
                     (with-open-file (output path :direction :output :if-exists :supersede
                                                 :element-type '(unsigned-byte 8))
                       (write-sequence bytes output))
                     (with-open-file (input path :element-type '(unsigned-byte 8))
                       (gr8s.image-distribution::validate-tracker-metainfo-stream
                        input (length bytes) digest infohash)))))
          (is-true (check "1:ai0e"))
          (dolist (prefix '("1:ai02e" "1:ai-0e" "1:ai-e" "1:ai+2e"
                            "01:ai0e" "1:a01:x" "1:ai1e1:ai2e" "1:zi0e"))
            (signals error (check prefix)))
          (signals error (check "" "0"))
          ;; Equal prefixes spanning both fixed comparison buffers must retain
          ;; byte ordering without allocating a vector for each dictionary key.
          (let ((a (make-string 8193 :initial-element #\a))
                (b (concatenate 'string (make-string 8192 :initial-element #\a) "b")))
            (is-true (check (format nil "~D:~Ai0e~D:~Ai0e" (length a) a (length b) b)))
            (signals error (check (format nil "~D:~Ai0e~D:~Ai0e" (length b) b (length a) a)))))))))


(test tracker-metainfo-keeps-previously-supported-inline-representation
  (with-temporary-store (store root)
    (populate-large-snapshot-tracker store 100000)
    (let ((source (merge-pathnames "inline-tracker.jsonl" root)))
      (gr8s.resources::capture-store-snapshot store source 42 7)
      (let* ((records (read-store-snapshot-records source))
             (swarm (find "imageTrackerSwarm" records :key (lambda (row) (gethash "kind" row)) :test #'equal)))
        (is (stringp (gethash "metainfo" swarm)))
        (is-false (gethash "metainfoFormat" swarm))
        (is-false (find "imageTrackerMetainfoChunk" records :key (lambda (row) (gethash "kind" row)) :test #'equal))
        (gr8s.resources::validate-store-snapshot source)))))

(test tracker-publishes-the-owned-bytes-that-passed-validation
  (with-temporary-store (store root)
    (let ((tracker (gr8s.store:pod-store-image-tracker store))
          (validate (symbol-function 'gr8s.image-distribution::validated-metainfo-infohash)))
      (multiple-value-bind (digest torrent) (tracker-test-torrent)
        (let* ((caller (copy-seq (gr8s.image-distribution::torrent-metainfo torrent)))
               (expected (copy-seq caller))
               (source (merge-pathnames "owned-tracker.jsonl" root)))
          (multiple-value-bind (status token)
              (gr8s.image-distribution::tracker-acquire-origin tracker digest "seed")
            (declare (ignore status))
            (unwind-protect
                 (progn
                   (setf (symbol-function 'gr8s.image-distribution::validated-metainfo-infohash)
                         (lambda (incoming bytes)
                           (prog1 (funcall validate incoming bytes)
                             ;; Simulate caller mutation after successful
                             ;; validation but before publication can copy.
                             (setf (aref caller 0) (char-code #\e)))))
                   (gr8s.image-distribution::tracker-publish-swarm
                    tracker digest "seed" token caller "10.0.0.1" 6881 (bt-octets "-GR8001-AAAAAAAAAAAA")))
              (setf (symbol-function 'gr8s.image-distribution::validated-metainfo-infohash) validate)))
          (is (/= (aref caller 0) (aref expected 0)))
          (is (equalp expected (gr8s.image-distribution::tracker-swarm-metainfo
                               (gethash digest (gr8s.image-distribution::image-tracker-swarms tracker)))))
          (gr8s.resources::capture-store-snapshot store source 42 7)
          (gr8s.resources::validate-store-snapshot source))))))
