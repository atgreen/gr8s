;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Compute the files a ConfigMap, Secret, downwardAPI or projected volume should
;;;; contain, then reconcile them into its directory: changed files are replaced
;;;; atomically and vanished ones removed, so running containers see live updates.
;;;; Mounts are read-only, so only the agent ever writes these directories.

(in-package #:gr8s)

(defun go-quoted-string (text)
  "Quote TEXT as Go's %q does for the characters Kubernetes metadata can contain."
  (with-output-to-string (out)
    (write-char #\" out)
    (loop for character across text
          do (case character
               (#\" (write-string "\\\"" out))
               (#\\ (write-string "\\\\" out))
               (#\Newline (write-string "\\n" out))
               (#\Tab (write-string "\\t" out))
               (#\Return (write-string "\\r" out))
               (t (write-char character out))))
    (write-char #\" out)))

(defun format-downward-map (map)
  "Render labels or annotations as sorted key=\"value\" lines, as Kubernetes does."
  (let ((keys (sort (and map (loop for key being the hash-keys of map collect key)) #'string<)))
    (format nil "~{~A~^~%~}"
            (mapcar (lambda (key) (format nil "~A=~A" key (go-quoted-string (gethash key map)))) keys))))

(defun downward-field-value (pod path)
  "Return the text of a validated metadata field reference."
  (let ((metadata (gethash "metadata" (pod-to-object pod)))
        (subscript (pod-metadata-subscript-reference path)))
    (cond (subscript (gethash (cdr subscript) (gethash (car subscript) metadata (core-object)) ""))
          ((equal path "metadata.name") (pod-name pod))
          ((equal path "metadata.namespace") (pod-namespace pod))
          ((equal path "metadata.uid") (pod-uid pod))
          ((equal path "metadata.labels") (format-downward-map (gethash "labels" metadata)))
          ((equal path "metadata.annotations") (format-downward-map (gethash "annotations" metadata)))
          (t (error 'runtime-error :message (format nil "Unsupported downward field ~A" path))))))

(defun node-allocatable-cpu ()
  "Return this node's online CPU count."
  (sb-alien:alien-funcall
   (sb-alien:extern-alien "sysconf" (function sb-alien:long sb-alien:int)) 84))

(defun node-allocatable-memory ()
  "Return this node's total memory in bytes."
  (with-open-file (in #P"/proc/meminfo")
    (loop for line = (read-line in nil) while line
          when (uiop:string-prefix-p "MemTotal:" line)
            return (* 1024 (parse-integer line :start (length "MemTotal:") :junk-allowed t))
          finally (error 'runtime-error :message "Could not read node memory"))))

(defun container-quantity-nanos (quantity)
  "Return QUANTITY in exact billionths, large enough for any node's memory."
  (container-quantity-integer quantity :scale -9 :maximum (expt 10 40)))

(defun downward-resource-value (pod reference)
  "Return a resource value divided by its divisor and rounded up, as text.
An unset limit reports node allocatable, as a Pod with no limit can use all of it."
  (let* ((resource (gethash "resource" reference))
         (dot (position #\. resource))
         (kind (subseq resource 0 dot)) (name (subseq resource (1+ dot)))
         (spec (gethash "spec" (pod-to-object pod)))
         (container (find (gethash "containerName" reference)
                          (concatenate 'vector (gethash "initContainers" spec #()) (gethash "containers" spec))
                          :test #'equal :key (lambda (object) (gethash "name" object))))
         ;; A container without a limit of its own has the Pod's, as the kubelet merges them.
         (declared (and container (container-resource-quantity (container-with-pod-level-limits spec container) kind name)))
         (nanos (cond (declared (container-quantity-nanos declared))
                      ((equal kind "requests") 0)
                      ((equal name "cpu") (* (node-allocatable-cpu) (expt 10 9)))
                      ((equal name "ephemeral-storage") (* (or (filesystem-capacity-bytes "/var/lib") 0) (expt 10 9)))
                      (t (* (node-allocatable-memory) (expt 10 9)))))
         (text (gethash "divisor" reference))
         (divisor (and text (container-quantity-nanos (parse-container-quantity text)))))
    (write-to-string (ceiling nanos (if (member divisor '(nil 0)) (expt 10 9) divisor)))))

(defun downward-volume-files (pod items default-mode)
  "Return (path bytes mode) entries for downward API ITEMS."
  (loop for item across items
        for field = (gethash "fieldRef" item)
        for text = (if field
                       (downward-field-value pod (gethash "fieldPath" field))
                       (downward-resource-value pod (gethash "resourceFieldRef" item)))
        collect (list (gethash "path" item) (trivial-utf-8:string-to-utf-8-bytes text)
                      (gethash "mode" item default-mode))))

(defun object-volume-files (runtime pod resource source name default-mode)
  "Return (path bytes mode) entries for a ConfigMap or Secret source named NAME."
  (let* ((optional (eq t (gethash "optional" source)))
         (object (handler-case (get-core-resource (containerd-runtime-resource-store runtime)
                                                  resource (pod-namespace pod) name)
                   (kubernetes-error (condition)
                     (unless (and optional (= 404 (kubernetes-error-status-code condition)))
                       (error condition)))))
         (data (pod-volume-data resource object))
         (items (gethash "items" source))
         (selected (if (and items (plusp (length items)))
                       (coerce items 'list)
                       (loop for key being the hash-keys of data
                             collect (core-object "key" key "path" key)))))
    (loop for item in selected
          for key = (gethash "key" item)
          for bytes = (gethash key data)
          do (unless (or bytes optional)
               (error 'runtime-error :message (format nil "Volume ~A lacks key ~A" name key)))
          when bytes
            collect (list (gethash "path" item) bytes (gethash "mode" item default-mode)))))

;;; podCertificate projected source (KEP-4317). The node generates the pod's
;;; keypair locally, so the private key never leaves it, and reports only the
;;; public key to the control plane (in its NodeStatus) as a claim. The control
;;; plane turns each claim into a PodCertificateRequest, a signer fills
;;; status.certificateChain, and the signed request is projected back to the
;;; node, which then writes the credential bundle. Until the request is signed
;;; the volume stays unmaterialized, so the pod stays Pending and is retried.

(defparameter +pod-certificate-key-type+ "ECDSAP256"
  "The one podCertificate keyType gr8s can generate and serialize (KEP-4317).")

(defparameter +pod-certificate-default-max-expiration-seconds+ 86400
  "The lifetime a node requests when a podCertificate source names none. The
   kubelet always sets maxExpirationSeconds, and signers dereference it, so it
   must never be absent (the signer caps it to its own maximum).")

(defun build-pod-certificate-request (&key name namespace signer-name pkix-public-key stub-pkcs10-request
                                           pod-name pod-uid service-account-name service-account-uid
                                           node-name node-uid max-expiration-seconds
                                           unverified-user-annotations)
  "Build a PodCertificateRequest object (certificates.k8s.io/v1, GA in Kubernetes
   1.37) for a pod's podCertificate volume: the stub PKCS#10 request the pod's key
   signed (base64 DER), which carries the public key v1 signers read, plus the
   pod/SA/node identity the signer checks, and any signer-domain pod annotations
   the signer reads via unverifiedUserAnnotations. The PKIX public key is kept as
   well for v1beta1 signers, which may read it instead."
  ;; Every spec string must be a string, never NIL: gr8s serializes NIL as JSON
  ;; false, which a typed client (the signer's PodCertificateRequest watch)
  ;; cannot decode into a string field. The node often cannot resolve the SA or
  ;; node UID (ServiceAccounts are not projected to it), so coerce to "".
  (let ((spec (core-object "signerName" (or signer-name "")
                           "podName" (or pod-name "") "podUID" (or pod-uid "")
                           "serviceAccountName" (or service-account-name "")
                           "serviceAccountUID" (or service-account-uid "")
                           "nodeName" (or node-name "") "nodeUID" (or node-uid "")
                           "pkixPublicKey" (or pkix-public-key ""))))
    (when (plusp (length stub-pkcs10-request))
      (setf (gethash "stubPKCS10Request" spec) stub-pkcs10-request))
    (when max-expiration-seconds
      (setf (gethash "maxExpirationSeconds" spec) max-expiration-seconds))
    (when (and unverified-user-annotations (plusp (hash-table-count unverified-user-annotations)))
      (setf (gethash "unverifiedUserAnnotations" spec) unverified-user-annotations))
    (core-object "apiVersion" "certificates.k8s.io/v1" "kind" "PodCertificateRequest"
                 "metadata" (core-object "name" name "namespace" namespace)
                 "spec" spec)))

(defun ec-private-key-pkcs8-pem (private-key)
  "Encode an EC (P-256) PRIVATE-KEY as PKCS#8 with PEM block type \"PRIVATE KEY\"
   -- the form KEP-4317 credential bundles use. SEC1 (\"EC PRIVATE KEY\") is what
   the ACME helper emits, but strict loaders (Agent Substrate's credential
   reader) accept only PKCS#8, so build PrivateKeyInfo around the SEC1 blob."
  (let* ((key-data (ironclad:destructure-private-key private-key))
         (d-bytes (getf key-data :x))
         (public-point (getf key-data :y))
         ;; Inner SEC1 ECPrivateKey; the curve lives in the PKCS#8 algorithm, so
         ;; omit the [0] parameters and keep only the optional [1] public key.
         (sec1 (pure-tls/acme::encode-sequence
                (pure-tls/acme::encode-integer 1)
                (pure-tls/acme::encode-octet-string d-bytes)
                (pure-tls/acme::encode-context-tag 1 (pure-tls/acme::encode-bit-string public-point))))
         (pkcs8 (pure-tls/acme::encode-sequence
                 (pure-tls/acme::encode-integer 0)
                 (pure-tls/acme::encode-sequence
                  (pure-tls/acme::encode-oid pure-tls/acme::*oid-ec-public-key*)
                  (pure-tls/acme::encode-oid pure-tls/acme::*oid-secp256r1*))
                 (pure-tls/acme::encode-octet-string sec1))))
    (pure-tls/acme::wrap-pem "PRIVATE KEY" pkcs8)))

(defun pod-certificate-stub-pkcs10-request (private-key public-key)
  "The DER PKCS#10 request a kubelet sends as stubPKCS10Request: an empty subject
   and no attributes, carrying PUBLIC-KEY and signed with PRIVATE-KEY
   (ecdsa-with-SHA256), so a signer can read the key and check possession of it.
   Upstream's kubelet makes the same request from an empty template."
  (let ((info (pure-tls/acme::encode-sequence
               (pure-tls/acme::encode-integer 0)
               (pure-tls/acme::encode-sequence)
               (pure-tls/acme::encode-ec-public-key public-key)
               ;; attributes [0] IMPLICIT SET OF Attribute, here empty
               (pure-tls/acme::encode-context-tag 0 (make-array 0 :element-type '(unsigned-byte 8))))))
    (pure-tls/acme::encode-sequence
     info
     (pure-tls/acme::encode-sequence (pure-tls/acme::encode-oid pure-tls/acme::*oid-ecdsa-with-sha256*))
     (pure-tls/acme::encode-bit-string (ecdsa-sign-der private-key info)))))

(defun pod-certificate-credential-bundle (private-key-pem certificate-chain-pem)
  "The credentialBundlePath contents for a signed pod certificate: the PEM
   private key followed by the issued PEM certificate chain (KEP-4317)."
  (let ((key (if (uiop:string-suffix-p private-key-pem (string #\Newline))
                 private-key-pem
                 (concatenate 'string private-key-pem (string #\Newline)))))
    (concatenate 'string key certificate-chain-pem)))

(defun pod-certificate-request-name (pod source)
  "A deterministic PodCertificateRequest name for POD's podCertificate SOURCE,
   so retries reuse the one request rather than creating duplicates. It binds to
   this pod incarnation and the source's signer and output paths."
  (let ((digest (ironclad:byte-array-to-hex-string
                 (ironclad:digest-sequence
                  :sha256 (trivial-utf-8:string-to-utf-8-bytes
                           (format nil "~A|~A|~A|~A|~A"
                                   (pod-uid pod) (gethash "signerName" source "")
                                   (gethash "credentialBundlePath" source "")
                                   (gethash "keyPath" source "")
                                   (gethash "certificateChainPath" source "")))))))
    (format nil "~A-~A"
            (let ((name (pod-name pod)) (limit 200)) (if (> (length name) limit) (subseq name 0 limit) name))
            (subseq digest 0 16))))

(defun ensure-pod-certificate-key-material (store pod source)
  "Return the node-generated key material for POD's podCertificate SOURCE,
   generating an ECDSA P-256 keypair on first use and caching it so the private
   key stays on the node and the public key in its claim never changes. The
   cached entry also carries the control plane's PodCertificateRequest claim."
  (let* ((name (pod-certificate-request-name pod source))
         (cache-key (list (pod-uid pod) name))
         (cache (pod-store-pod-certificates store)))
    (or (bt:with-lock-held ((pod-store-credential-lock store)) (gethash cache-key cache))
        (multiple-value-bind (private-key public-key) (ironclad:generate-key-pair :secp256r1)
          (let* ((spec (gethash "spec" (pod-to-object pod)))
                 (sa-name (or (gethash "serviceAccountName" spec) "default"))
                 (sa (ignore-errors (get-core-resource store "serviceaccounts" (pod-namespace pod) sa-name)))
                 (material
                   (list :pod (pod-uid pod) :name name :namespace (pod-namespace pod)
                         :private-key-pem (ec-private-key-pkcs8-pem private-key)
                         :claim (list :name name :namespace (pod-namespace pod)
                                      :signer-name (gethash "signerName" source)
                                      :pkix-public-key (ag-grpc:base64-encode
                                                        (pure-tls/acme::encode-ec-public-key public-key))
                                      :stub-pkcs10-request (ag-grpc:base64-encode
                                                            (pod-certificate-stub-pkcs10-request private-key public-key))
                                      :pod-name (pod-name pod) :pod-uid (pod-uid pod)
                                      :service-account-name sa-name
                                      :service-account-uid (and sa (gethash "uid" (gethash "metadata" sa)))
                                      :max-expiration-seconds
                                      (gethash "maxExpirationSeconds" source
                                               +pod-certificate-default-max-expiration-seconds+)))))
            (bt:with-lock-held ((pod-store-credential-lock store))
              ;; Another thread may have generated one first; keep whichever is stored.
              (or (gethash cache-key cache) (setf (gethash cache-key cache) material))))))))

(defun pod-certificate-request-failure (pcr)
  "A human-readable message if PCR carries a True Denied or Failed condition, else NIL."
  (let ((status (gethash "status" pcr (core-object))))
    (dolist (type '("Denied" "Failed"))
      (let ((condition (find type (gethash "conditions" status #())
                             :test #'equal :key (lambda (c) (gethash "type" c)))))
        (when (and condition (equal "True" (gethash "status" condition)))
          (return (format nil "~A: ~A" type (gethash "message" condition ""))))))))

(defun pod-certificate-volume-files (runtime pod source default-mode)
  "Return the files for a podCertificate projected SOURCE (KEP-4317). The node
   caches the pod's keypair and leaves its PodCertificateRequest claim where the
   NodeStatus reporter will send it, then reads the request back from its local
   store. Until a signer has filled status.certificateChain it signals a
   runtime-error, so the volume stays unmaterialized and the pod stays Pending."
  (let ((key-type (gethash "keyType" source +pod-certificate-key-type+)))
    (unless (equal key-type +pod-certificate-key-type+)
      (error 'runtime-error
             :message (format nil "podCertificate keyType ~A is not supported (only ~A)"
                              key-type +pod-certificate-key-type+))))
  (let* ((store (containerd-runtime-resource-store runtime))
         (material (ensure-pod-certificate-key-material store pod source))
         (name (getf material :name))
         (pcr (ignore-errors (get-core-resource store "podcertificaterequests" (pod-namespace pod) name)))
         (failure (and pcr (pod-certificate-request-failure pcr)))
         (chain (and pcr (gethash "certificateChain" (gethash "status" pcr (core-object))))))
    (when failure
      (error 'runtime-error :message (format nil "PodCertificateRequest ~A/~A ~A"
                                             (pod-namespace pod) name failure)))
    (unless (and (stringp chain) (plusp (length chain)))
      (error 'runtime-error
             :message (format nil "PodCertificateRequest ~A/~A is awaiting signer ~A"
                              (pod-namespace pod) name (gethash "signerName" source))))
    (let ((files nil) (key-pem (getf material :private-key-pem)))
      (flet ((add (path text) (when path (push (list path (trivial-utf-8:string-to-utf-8-bytes text)
                                                     default-mode) files))))
        (add (gethash "credentialBundlePath" source) (pod-certificate-credential-bundle key-pem chain))
        (add (gethash "keyPath" source) key-pem)
        (add (gethash "certificateChainPath" source) chain))
      (nreverse files))))

(defun node-pending-pod-certificate-claims (store)
  "The claim plists the node reports so the control plane creates each pod's
   PodCertificateRequest. Resending a claim for a request that already exists is
   idempotent, so every cached material is reported until its pod is pruned."
  (bt:with-lock-held ((pod-store-credential-lock store))
    (loop for material being the hash-values of (pod-store-pod-certificates store)
          collect (getf material :claim))))

(defun cluster-trust-bundle-matches-p (bundle signer selector)
  "True when BUNDLE has SIGNER and satisfies the label SELECTOR. As in the kubelet,
   an absent selector matches nothing and an empty one matches every bundle of the
   signer; matchExpressions apply as in any LabelSelector."
  (and (hash-table-p selector)
       (equal signer (gethash "signerName" (gethash "spec" bundle (core-object))))
       (workload-selector-matches-p selector (gethash "labels" (gethash "metadata" bundle)))))

(defun cluster-trust-bundle-volume-files (store source default-mode)
  "Resolve a clusterTrustBundle projected SOURCE against STORE's projected
   ClusterTrustBundles and return a single (path PEM-bytes mode) entry. Selects
   by name, or by signerName (optionally narrowed by labelSelector), with the
   matching bundles' PEMs concatenated in stable name order (KEP-4317)."
  (let* ((path (gethash "path" source))
         (name (gethash "name" source))
         (signer (gethash "signerName" source))
         (selector (gethash "labelSelector" source))
         (optional (eq t (gethash "optional" source)))
         (bundles
           (if name
               (let ((bundle (ignore-errors (get-core-resource store "clustertrustbundles" nil name))))
                 (cond (bundle (list bundle))
                       (optional nil)
                       ;; As for the kubelet, a mount that cannot be made yet keeps the
                       ;; Pod waiting and is retried; it is not an invalid Pod.
                       (t (error 'runtime-error
                                 :message (format nil "clusterTrustBundle ~A not found" name)))))
               (sort (remove-if-not (lambda (bundle)
                                      (cluster-trust-bundle-matches-p bundle signer selector))
                                    (list-core-resources store "clustertrustbundles"))
                     #'string< :key (lambda (bundle) (gethash "name" (gethash "metadata" bundle)))))))
    (when (and (not name) (null bundles) (not optional))
      (error 'runtime-error
             :message (format nil "combination of signerName ~A and labelSelector matched zero ClusterTrustBundles"
                              signer)))
    (let ((pem (with-output-to-string (out)
                 (dolist (bundle bundles)
                   (let ((trust (gethash "trustBundle" (gethash "spec" bundle (core-object)))))
                     (when (and (stringp trust) (plusp (length trust)))
                       (write-string trust out)
                       (unless (uiop:string-suffix-p trust (string #\Newline)) (terpri out))))))))
      (list (list path (trivial-utf-8:string-to-utf-8-bytes pem) default-mode)))))

(defun pod-volume-desired-files (runtime pod volume)
  "Return VOLUME's (path bytes mode) entries and whether it is a projection at all."
  (let ((mode (lambda (source) (gethash "defaultMode" source #o644))))
    (cond
      ((gethash "configMap" volume)
       (let ((source (gethash "configMap" volume)))
         (values (object-volume-files runtime pod "configmaps" source (gethash "name" source)
                                      (funcall mode source)) t)))
      ((gethash "secret" volume)
       (let ((source (gethash "secret" volume)))
         (values (object-volume-files runtime pod "secrets" source (gethash "secretName" source)
                                      (funcall mode source)) t)))
      ((gethash "downwardAPI" volume)
       (let ((source (gethash "downwardAPI" volume)))
         (values (downward-volume-files pod (gethash "items" source #()) (funcall mode source)) t)))
      ((gethash "projected" volume)
       (let* ((projected (gethash "projected" volume)) (default-mode (funcall mode projected)))
         (values
          (loop for source across (gethash "sources" projected #())
                append (cond
                         ((gethash "configMap" source)
                          (let ((part (gethash "configMap" source)))
                            (object-volume-files runtime pod "configmaps" part (gethash "name" part) default-mode)))
                         ((gethash "secret" source)
                          (let ((part (gethash "secret" source)))
                            (object-volume-files runtime pod "secrets" part (gethash "name" part) default-mode)))
                         ((gethash "downwardAPI" source)
                          (downward-volume-files pod (gethash "items" (gethash "downwardAPI" source) #())
                                                 default-mode))
                         ((gethash "serviceAccountToken" source)
                          (projected-token-volume-files runtime pod (gethash "serviceAccountToken" source) default-mode))
                         ((gethash "clusterTrustBundle" source)
                          (cluster-trust-bundle-volume-files
                           (containerd-runtime-resource-store runtime)
                           (gethash "clusterTrustBundle" source) default-mode))
                         ((gethash "podCertificate" source)
                          (pod-certificate-volume-files
                           runtime pod (gethash "podCertificate" source) default-mode))))
          t)))
      (t (values nil nil)))))

(defun volume-file-pathname (directory relative)
  "Resolve a validated relative path beneath DIRECTORY without treating it as a wildcard."
  (unless (safe-volume-relative-path-p relative) (invalid-pod "unsafe volume projection path"))
  (merge-pathnames (uiop:parse-native-namestring relative) directory))

(defun volume-file-current-p (target bytes mode &optional owner)
  "Report whether TARGET already has exactly BYTES, permission MODE and, when given, OWNER."
  (and (probe-file target)
       (let ((stat (sb-posix:stat (uiop:native-namestring target))))
         (and (= mode (logand #o777 (sb-posix:stat-mode stat)))
              (or (null owner) (= owner (sb-posix:stat-uid stat)))))
       (equalp bytes (read-file-octets target))))

(defun volume-directory-files (directory)
  "List every file beneath DIRECTORY without following links."
  (append (uiop:directory-files directory)
          (loop for child in (uiop:subdirectories directory)
                append (volume-directory-files child))))

(defun publish-pod-volume-files (directory files group)
  "Make DIRECTORY hold exactly FILES, (path bytes mode [owner]) entries, with GROUP readable when an
fsGroup applies and a file given an OWNER owned by that user."
  (let ((wanted nil))
    (loop for (relative bytes mode owner) in files
          do (let ((target (volume-file-pathname directory relative))
                   (actual (if group (logior mode #o440) mode)))
               (push (uiop:native-namestring target) wanted)
               (unless (volume-file-current-p target bytes actual owner)
                 (write-projected-volume-file target bytes actual group owner))))
    (dolist (path (volume-directory-files directory))
      (unless (member (uiop:native-namestring path) wanted :test #'equal)
        (delete-file path)))))

(defun refresh-pod-projected-volumes (runtime pod)
  "Bring POD's existing projected volumes up to date, keeping old content on any failure."
  (loop for volume across (gethash "volumes" (gethash "spec" (pod-to-object pod)) #())
        for directory = (pod-volume-directory runtime pod (gethash "name" volume))
        when (uiop:directory-exists-p directory)
          do (handler-case
                 (multiple-value-bind (files projection) (pod-volume-desired-files runtime pod volume)
                   (when projection
                     (publish-pod-volume-files directory files (pod-fs-group pod))))
               ((or runtime-error kubernetes-error file-error sb-posix:syscall-error) (condition)
                 (format *error-output* "gr8s Pod ~A/~A volume ~A refresh: ~A~%" (pod-namespace pod)
                         (pod-name pod) (gethash "name" volume) condition)))))
