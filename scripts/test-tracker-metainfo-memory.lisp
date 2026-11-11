;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;; Run with cached FASLs and a 384 MiB heap, in two separate processes:
;;;; sbcl --dynamic-space-size 384 --non-interactive --load scripts/test-tracker-metainfo-memory.lisp -- capture NEW_ROOT
;;;; sbcl --dynamic-space-size 384 --non-interactive --load scripts/test-tracker-metainfo-memory.lisp -- verify NEW_ROOT
;;;; NEW_ROOT's parent must exist. Evidence is preserved for inspection.
(require :asdf)
(asdf:load-asd (truename "gr8s.asd"))
(asdf:load-system "gr8s")

(defun tracker-memory-inventory (store)
  (let ((rows nil))
    (maphash
     (lambda (digest swarm)
       (let ((bytes (gr8s.image-distribution::tracker-swarm-metainfo swarm)))
         (push (gr8s.resources::core-object
                "digest" digest "bytes" (length bytes)
                "sha256" (ironclad:byte-array-to-hex-string (ironclad:digest-sequence :sha256 bytes))) rows)))
     (gr8s.image-distribution::image-tracker-swarms (gr8s.store:pod-store-image-tracker store)))
    (coerce (sort rows #'string< :key (lambda (row) (gethash "digest" row))) 'vector)))

(defun tracker-memory-populate (store root)
  (let ((tracker (gr8s.store:pod-store-image-tracker store)))
    (dotimes (index 4)
      (let* ((payload (make-array 1 :element-type '(unsigned-byte 8) :initial-element index))
             (digest (concatenate 'string "sha256:" (ironclad:byte-array-to-hex-string
                                                   (ironclad:digest-sequence :sha256 payload))))
             (blob (merge-pathnames (format nil "blob-~D" index) root)))
        (with-open-file (output blob :direction :output :if-exists :error :element-type '(unsigned-byte 8))
          (write-sequence payload output))
        (let* ((torrent (gr8s.image-distribution::make-oci-blob-torrent blob digest 16384))
               (decoded (gr8s.image-distribution::decode-bencode
                         (gr8s.image-distribution::blob-torrent-metainfo torrent)))
               (metainfo (gr8s.image-distribution::encode-bencode
                          (gr8s.image-distribution::bencode-dictionary
                           (acons "comment" (make-array (* 16 1024 1024) :element-type '(unsigned-byte 8)
                                                                       :initial-element (+ 65 index))
                                  (gr8s.image-distribution::bencode-map-entries decoded))))))
          (multiple-value-bind (status token)
              (gr8s.image-distribution::tracker-acquire-origin tracker digest "seed")
            (declare (ignore status))
            (gr8s.image-distribution::tracker-publish-swarm
             tracker digest "seed" token metainfo "127.0.0.1" 6881
             (make-array 20 :element-type '(unsigned-byte 8) :initial-element index))))
        (format t "~&Fixture swarm ~D published~%" index)))))

(destructuring-bind (mode directory) (uiop:command-line-arguments)
  (unless (= (* 384 1024 1024) (sb-ext:dynamic-space-size)) (error "This probe requires a 384 MiB heap"))
  (let* ((root (uiop:ensure-directory-pathname directory))
         (expected-path (merge-pathnames "tracker-memory-expected.json" root))
         (artifact (merge-pathnames "tracker-memory-artifact.jsonl" root)))
    (unless (member mode '("capture" "verify") :test #'equal) (error "Expected capture or verify mode"))
    (when (equal mode "capture") (sb-posix:mkdir (namestring root) #o700))
    (let ((store (gr8s:open-store root)))
      (if (equal mode "capture")
          (progn
            (tracker-memory-populate store root)
            (sb-ext:gc :full t)
            (format t "~&Fixture complete: 64 MiB metainfo resident; capture begins~%")
            (let ((expected (tracker-memory-inventory store)))
              (with-open-file (output expected-path :direction :output :if-exists :error)
                (com.inuoe.jzon:stringify expected :stream output))
              (gr8s.resources::capture-store-snapshot store artifact 1 1)
              (gr8s.resources::validate-store-snapshot artifact :expected-index 1 :expected-term 1)
              (multiple-value-bind (path descriptor)
                  (gr8s.resources::materialize-store-snapshot
                   root artifact (gr8s.raft.transport::raft-snapshot-file-digest artifact)
                   :expected-index 1 :expected-term 1
                   :minimum-resource-revision (1+ (gr8s::pod-store-resource-revision store))
                   :minimum-pod-revision (1+ (gr8s::pod-store-pod-revision-ceiling store)))
                (declare (ignore path))
                (gr8s.store::quiesce-store-access store :timeout 0)
                (unwind-protect
                     (gr8s.store::reload-store-application store (gethash "generation" descriptor))
                  (gr8s.store::resume-store-access store)))
              (assert (equalp expected (tracker-memory-inventory store)))))
          (assert (equalp (com.inuoe.jzon:parse (uiop:read-file-string expected-path))
                          (tracker-memory-inventory store))))
      (sb-ext:gc :full t)
      (format t "~&TRACKER_MEMORY_PASS mode=~A heap=~D swarms=~D artifact=~D~%"
              mode (sb-kernel:dynamic-usage) (length (tracker-memory-inventory store))
              (sb-posix:stat-size (sb-posix:stat (namestring artifact)))))))
