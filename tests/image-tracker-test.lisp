;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0

(in-package #:gr8s/tests)

(defun tracker-test-torrent ()
  (let* ((bytes (make-array 20000 :element-type '(unsigned-byte 8)
                                  :initial-element 42))
         (path (bt-temp-file bytes))
         (digest (format nil "sha256:~A"
                         (ironclad:byte-array-to-hex-string
                          (ironclad:digest-sequence :sha256 bytes)))))
    (unwind-protect
         (values digest
                 (gr8s.image-distribution::make-oci-blob-torrent
                  path digest 16384))
      (ignore-errors (delete-file path)))))

(test image-tracker-origin-lease-is-exclusive-renewable-and-fails-over
  (let* ((now 1000)
         (tracker (gr8s.image-distribution::make-image-tracker
                   :clock (lambda () now) :origin-lease-seconds 30)))
    (multiple-value-bind (status first-token expires owner)
        (gr8s.image-distribution::tracker-acquire-origin
         tracker "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
         "node-a")
      (is (eq :granted status))
      (is (= 1030 expires))
      (is (string= "node-a" owner))
      (multiple-value-bind (retry-status retry-token retry-expires retry-owner)
          (gr8s.image-distribution::tracker-acquire-origin
           tracker "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
           "node-a")
        (is (eq :granted retry-status))
        (is (equalp first-token retry-token))
        (is (= 1030 retry-expires))
        (is (string= "node-a" retry-owner)))
      (multiple-value-bind (waiting token waiting-expires waiting-owner)
          (gr8s.image-distribution::tracker-acquire-origin
           tracker "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
           "node-b")
        (is (eq :waiting waiting))
        (is (null token))
        (is (= 1030 waiting-expires))
        (is (string= "node-a" waiting-owner)))
      (incf now 10)
      (is (= 1040 (gr8s.image-distribution::tracker-renew-origin
                   tracker
                   "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                   "node-a" first-token)))
      (setf now 1041)
      (multiple-value-bind (status second-token expires owner)
          (gr8s.image-distribution::tracker-acquire-origin
           tracker "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
           "node-b")
        (is (eq :granted status))
        (is (= 1071 expires))
        (is (string= "node-b" owner))
        (is (not (equalp first-token second-token)))
        (signals error
          (gr8s.image-distribution::tracker-renew-origin
           tracker
           "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
           "node-a" first-token))))))

(test image-tracker-publish-rejects-stale-origin-and-enables-the-swarm
  (multiple-value-bind (digest torrent) (tracker-test-torrent)
    (let* ((now 1000)
           (tracker (gr8s.image-distribution::make-image-tracker
                     :clock (lambda () now) :origin-lease-seconds 10
                     :peer-ttl-seconds 20)))
      (multiple-value-bind (status stale-token)
          (gr8s.image-distribution::tracker-acquire-origin tracker digest "node-a")
        (is (eq :granted status))
        (setf now 1011)
        (multiple-value-bind (takeover-status current-token)
            (gr8s.image-distribution::tracker-acquire-origin tracker digest "node-b")
          (is (eq :granted takeover-status))
          (signals error
            (gr8s.image-distribution::tracker-publish-swarm
             tracker digest "node-a" stale-token
             (gr8s.image-distribution::blob-torrent-metainfo torrent)
             "10.0.0.1" 6881 (bt-octets "-GR8001-AAAAAAAAAAAA")))
          (gr8s.image-distribution::tracker-publish-swarm
           tracker digest "node-b" current-token
           (gr8s.image-distribution::blob-torrent-metainfo torrent)
           "10.0.0.2" 6881 (bt-octets "-GR8001-BBBBBBBBBBBB"))
          (let ((view (gr8s.image-distribution::tracker-lookup
                       tracker digest "node-a")))
            (is (eq :available
                    (gr8s.image-distribution::tracker-view-status view)))
            (is (equalp (gr8s.image-distribution::blob-torrent-infohash torrent)
                        (gr8s.image-distribution::tracker-view-infohash view)))
            (is (= 1 (length
                      (gr8s.image-distribution::tracker-view-peers view))))
            (is (string= "node-b"
                         (gr8s.image-distribution::tracker-peer-node-name
                          (first (gr8s.image-distribution::tracker-view-peers view)))))))))))

(test image-tracker-expires-peers-and-never-returns-the-requester
  (multiple-value-bind (digest torrent) (tracker-test-torrent)
    (let* ((now 20)
           (tracker (gr8s.image-distribution::make-image-tracker
                     :clock (lambda () now) :peer-ttl-seconds 5)))
      (multiple-value-bind (status token)
          (gr8s.image-distribution::tracker-acquire-origin tracker digest "node-a")
        (is (eq :granted status))
        (gr8s.image-distribution::tracker-publish-swarm
         tracker digest "node-a" token
         (gr8s.image-distribution::blob-torrent-metainfo torrent)
         "10.0.0.1" 6881 (bt-octets "-GR8001-AAAAAAAAAAAA")))
      (gr8s.image-distribution::tracker-announce-peer
       tracker digest "node-b" "10.0.0.2" 6881
       (bt-octets "-GR8001-BBBBBBBBBBBB") :complete-p t)
      (is (= 1 (length (gr8s.image-distribution::tracker-view-peers
                        (gr8s.image-distribution::tracker-lookup
                         tracker digest "node-a")))))
      (incf now 6)
      (is (null (gr8s.image-distribution::tracker-view-peers
                 (gr8s.image-distribution::tracker-lookup
                  tracker digest "node-c")))))))

(test image-tracker-lookup-applies-ranking-and-bounds-the-view
  (multiple-value-bind (digest torrent) (tracker-test-torrent)
    (let ((tracker (gr8s.image-distribution::make-image-tracker)))
      (multiple-value-bind (status token)
          (gr8s.image-distribution::tracker-acquire-origin tracker digest "node-0")
        (declare (ignore status))
        (gr8s.image-distribution::tracker-publish-swarm
         tracker digest "node-0" token
         (gr8s.image-distribution::blob-torrent-metainfo torrent)
         "10.0.0.1" 6881 (bt-octets "-GR8001-000000000000")))
      (loop for index from 1 to 12
            do (gr8s.image-distribution::tracker-announce-peer
                tracker digest (format nil "node-~D" index)
                (format nil "10.0.0.~D" (1+ index)) 6881
                (bt-octets (format nil "-GR8001-~12,'0D" index))))
      (let* ((view (gr8s.image-distribution::tracker-lookup
                    tracker digest "requester" :maximum-peers 3
                    :peer-ranker
                    (lambda (peers)
                      (sort peers #'string>
                            :key #'gr8s.image-distribution::tracker-peer-node-name))))
             (peers (gr8s.image-distribution::tracker-view-peers view)))
        (is (= 3 (length peers)))
        (is (string= "node-9"
                     (gr8s.image-distribution::tracker-peer-node-name
                      (first peers))))))))

(test image-tracker-rejects-metadata-for-another-oci-digest
  (multiple-value-bind (digest torrent) (tracker-test-torrent)
    (let ((tracker (gr8s.image-distribution::make-image-tracker)))
      (multiple-value-bind (status token)
          (gr8s.image-distribution::tracker-acquire-origin
           tracker "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
           "node-a")
        (is (eq :granted status))
        (signals error
          (gr8s.image-distribution::tracker-publish-swarm
           tracker
           "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
           "node-a" token
           (gr8s.image-distribution::blob-torrent-metainfo torrent)
           "10.0.0.1" 6881 (bt-octets "-GR8001-AAAAAAAAAAAA")))))))
