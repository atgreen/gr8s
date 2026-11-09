;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
(in-package #:gr8s.patch)
(defun build-artifact (recipe private-key output)
  "Build a signed OCI layout from a data-only recipe and an Ed25519 key.
Each level's sourceDirectory supplies its declared files; prior sources are immutable."
  (let* ((root (uiop:ensure-directory-pathname output))
         (index (copy-json recipe)) (previous "") (descriptors nil))
    (labels ((put-blob (bytes media)
               (let* ((hash (digest bytes))
                      (file (merge-pathnames (format nil "blobs/sha256/~A" (subseq hash 7)) root)))
                 (durable-bytes file bytes)
                 (object "mediaType" media "digest" hash "size" (length bytes)))))
      (setf (gethash "format" index) 1 (gethash "buildID" index) *build-id*
            (gethash "patchABI" index) +patch-abi+ (gethash "baseRelease" index) gr8s:+gr8s-version+)
      (loop for level across (gethash "levels" index) for number from 1 do
        (let ((source (uiop:ensure-directory-pathname (gethash "sourceDirectory" level)))
              (files (gethash "files" level)))
          (remhash "sourceDirectory" level)
          (setf (gethash "level" level) number (gethash "previous" level) previous)
          (setf (gethash "files" level)
                (map 'vector
                     (lambda (name)
                       (unless (and (stringp name) (cl-ppcre:scan "^[a-zA-Z0-9_-]+[.](lisp|asd)$" name))
                         (error "Unsafe publisher source path"))
                       (let* ((bytes (alexandria:read-file-into-byte-vector (merge-pathnames name source)))
                              (descriptor (put-blob bytes "application/vnd.gr8s.patch.source.v1")))
                         (push descriptor descriptors)
                         (object "path" name "digest" (gethash "digest" descriptor)))) files))
          (remhash "chain" level)
          (setf previous (digest (octets (canonical-json level))) (gethash "chain" level) previous)))
      (validate-index index)
      (let* ((payload (octets (canonical-json index)))
             (envelope (object "keyID" (gethash "publisher" index) "payload" (ag-grpc:base64-encode payload)
                               "signature" (ag-grpc:base64-encode (ironclad:sign-message private-key payload))))
             (config (put-blob (octets (canonical-json envelope)) "application/vnd.gr8s.patch.index.v1+json"))
             (manifest (object "schemaVersion" 2 "mediaType" "application/vnd.oci.image.manifest.v1+json"
                               "artifactType" +artifact-type+ "config" config
                               "layers" (coerce (reverse descriptors) 'vector)))
             (descriptor (put-blob (octets (canonical-json manifest)) "application/vnd.oci.image.manifest.v1+json")))
        (durable-json (merge-pathnames "oci-layout" root) (object "imageLayoutVersion" "1.0.0"))
        (durable-json (merge-pathnames "index.json" root)
                      (object "schemaVersion" 2 "manifests" (vector descriptor)))
        (gethash "digest" descriptor)))))
