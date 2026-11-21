;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0

(in-package #:gr8s.image-distribution)

;;; Cluster registry trust.  A ClusterTrustBundle annotated
;;; gr8s.io/registries: "HOST[:PORT], ..." makes its trustBundle CAs that those
;;; registries are verified against.  Every node receives ClusterTrustBundles
;;; in its desired-state snapshot, so adding, rotating or removing a registry
;;; CA needs no restart.  A host trusts the union of every bundle naming it and
;;; the node's own --registry-ca, so a rotation can add the new CA before it
;;; removes the old; a host no source names is held to the system roots.

(defparameter +registry-trust-annotation+ "gr8s.io/registries")

(defvar *registry-ca-flag-files* '()
  "The node's --registry-ca entries: alist of registry host to PEM file.")

(defvar *registry-trust-directory* nil
  "Where this node keeps its registry trust files and the cluster trust it last
received, or NIL when only --registry-ca applies.")

(defvar *cluster-registry-trust* nil
  "The installed cluster trust: alist of lowercase registry host key to its
sorted PEM bundles, as CLUSTER-REGISTRY-TRUST returns it.")

(defvar *registry-trust-lock* (bt:make-lock "registry trust"))

(defun registry-trust-annotation-hosts (value)
  "The registries VALUE names: HOST or HOST:PORT entries separated by commas or
whitespace. Signals an error when it names none, a malformed host, or one twice."
  (let ((hosts (remove "" (uiop:split-string value :separator '(#\, #\Space #\Tab #\Newline))
                       :test #'string=)))
    (unless hosts
      (error "names no registry"))
    (dolist (host hosts)
      (unless (valid-registry-host-p host)
        (error "~S is not a registry HOST or HOST:PORT" host)))
    (let ((keys (mapcar #'registry-host-key hosts)))
      (unless (= (length keys) (length (remove-duplicates keys :test #'string-equal)))
        (error "names a registry twice")))
    hosts))

(defun cluster-registry-trust (bundles)
  "Alist of lowercase registry host key to the sorted PEM trustBundles of every
ClusterTrustBundle in BUNDLES whose gr8s.io/registries annotation names it.
The API server rejects a malformed annotation; one that reaches a node anyway
is skipped with a warning rather than trusted in part."
  (let ((trust '()))
    (dolist (bundle bundles)
      (let* ((metadata (gethash "metadata" bundle))
             (annotations (and (hash-table-p metadata) (gethash "annotations" metadata)))
             (value (and (hash-table-p annotations) (gethash +registry-trust-annotation+ annotations)))
             (spec (gethash "spec" bundle))
             (pem (and (hash-table-p spec) (gethash "trustBundle" spec))))
        (when (and (stringp value) (stringp pem))
          (handler-case
              (dolist (host (registry-trust-annotation-hosts value))
                (let* ((key (string-downcase (registry-host-key host)))
                       (entry (assoc key trust :test #'string=)))
                  (if entry
                      (pushnew pem (cdr entry) :test #'string=)
                      (push (list key pem) trust))))
            (error (condition)
              (format *error-output* "gr8s: ignoring registry trust in ClusterTrustBundle ~A: ~A~%"
                      (gethash "name" metadata) condition))))))
    (sort (mapcar (lambda (entry) (cons (car entry) (sort (copy-list (cdr entry)) #'string<)))
                  trust)
          #'string< :key #'car)))

(defun write-file-atomically (pathname contents)
  (let ((temporary (make-pathname :type "tmp" :defaults pathname)))
    (alexandria:write-string-into-file contents temporary :if-exists :supersede)
    (rename-file temporary pathname)))

(defun registry-trust-file (pem)
  "A file in the trust directory holding PEM, named by its digest: pure-tls
caches trust stores by file name and write date, so rewritten trust is a new file."
  (let ((pathname (merge-pathnames
                   (format nil "~A.pem" (ironclad:byte-array-to-hex-string
                                         (ironclad:digest-sequence
                                          :sha256 (trivial-utf-8:string-to-utf-8-bytes pem))))
                   *registry-trust-directory*)))
    (unless (probe-file pathname)
      (write-file-atomically pathname pem))
    pathname))

(defun registry-trust-ca-files (cluster-trust)
  "*REGISTRY-CA-FILES* for CLUSTER-TRUST and the node's --registry-ca: the
flag's file where the cluster names no CA for that host, else one file of the
flag's CAs followed by the cluster's."
  (let ((files (remove-if (lambda (entry)
                            (assoc (registry-host-key (car entry)) cluster-trust :test #'string-equal))
                          *registry-ca-flag-files*)))
    (loop for (host . pems) in cluster-trust
          for flag-file = (cdr (assoc host *registry-ca-flag-files*
                                      :key #'registry-host-key :test #'string-equal))
          for flag-pem = (and flag-file (alexandria:read-file-into-string flag-file))
          do (push (cons host (registry-trust-file
                               (format nil "~{~A~^~%~}" (if flag-pem (cons flag-pem pems) pems))))
                   files))
    files))

(defun registry-trust-state-file ()
  (merge-pathnames "cluster-trust.json" *registry-trust-directory*))

(defun install-cluster-registry-trust (trust)
  "Make TRUST, from CLUSTER-REGISTRY-TRUST, the cluster's part of registry
verification, and keep it so a restarted node verifies as before until its
first snapshot. Unchanged trust is left as it is. Without a trust directory
only --registry-ca applies."
  (when *registry-trust-directory*
    (bt:with-lock-held (*registry-trust-lock*)
      (unless (equal trust *cluster-registry-trust*)
        (ensure-directories-exist *registry-trust-directory*)
        (let ((files (registry-trust-ca-files trust)))
          (write-file-atomically
           (registry-trust-state-file)
           (com.inuoe.jzon:stringify
            (coerce (loop for (host . pems) in trust
                          collect (alexandria:plist-hash-table
                                   (list "registry" host "trustBundles" (coerce pems 'vector))
                                   :test 'equal))
                    'vector)))
          (setf *registry-ca-files* files
                *cluster-registry-trust* trust)
          ;; Trust a source no longer names stops here, not at the next restart.
          (let ((live (mapcar (lambda (entry) (namestring (cdr entry))) files)))
            (dolist (file (directory (merge-pathnames "*.pem" *registry-trust-directory*)))
              (unless (member (namestring file) live :test #'string=)
                (ignore-errors (delete-file file))))))))))

(defun persisted-cluster-registry-trust ()
  "The cluster trust this node last installed, or NIL when it has none."
  (let ((file (registry-trust-state-file)))
    (when (probe-file file)
      (handler-case
          (sort (loop for entry across (com.inuoe.jzon:parse (alexandria:read-file-into-string file))
                      collect (cons (gethash "registry" entry)
                                    (coerce (gethash "trustBundles" entry) 'list)))
                #'string< :key #'car)
        (error (condition)
          (format *error-output* "gr8s: ignoring unreadable registry trust ~A: ~A~%" file condition)
          nil)))))

(defun start-registry-trust (directory flag-files)
  "Verify registries against FLAG-FILES, the node's --registry-ca alist of host
to PEM file, and the cluster trust last received, kept in DIRECTORY."
  (bt:with-lock-held (*registry-trust-lock*)
    (setf *registry-trust-directory* (uiop:ensure-directory-pathname directory)
          *registry-ca-flag-files* flag-files
          *registry-ca-files* flag-files
          *cluster-registry-trust* nil))
  (install-cluster-registry-trust (persisted-cluster-registry-trust)))
