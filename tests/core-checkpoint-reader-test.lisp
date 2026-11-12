;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
(in-package #:gr8s/tests)
(def-suite core-checkpoint-reader :in gr8s)
(in-suite core-checkpoint-reader)

(defun checkpoint-reader-object (revision value &optional (kind "ConfigMap"))
  (gr8s.resources::core-object "apiVersion" "v1" "kind" kind
    "metadata" (gr8s.resources::core-object "name" "sample" "namespace" "default" "uid" "fixture"
                 "resourceVersion" (write-to-string revision))
    "data" (gr8s.resources::core-object "key" value)))

(defun checkpoint-reader-entry (revision old new &optional (resource "configmaps"))
  (gr8s.resources::core-object "revision" revision "time" 10 "resource" resource
    "namespace" "default" "name" "sample" "old" old "new" new "bytes" 512))

(defun checkpoint-reader-state (revision history items &optional (version 2))
  (gr8s.resources::core-object "version" version "revision" revision "resourceHistoryStart" 0
    "templateHistoryFloor" 0 "templateHistory" history "items" items
    "templateTokenKey" "continuation-fixture" "workloadDeletions" (gr8s.resources::core-object "uid" "intent")
    "jobControllerStates" (gr8s.resources::core-object "uid" "controller") "eventExpirations" (gr8s.resources::core-object)
    "secretsEncryption" 'null "customResourceItems" #()))

(defun write-checkpoint-reader-fixture (path state first-fields)
  (with-open-file (out path :direction :output :if-exists :supersede :external-format :utf-8)
    (let ((first t))
      (write-char #\{ out)
      (labels ((emit (key value)
                 (unless first (write-char #\, out)) (setf first nil)
                 (com.inuoe.jzon:stringify key :stream out) (write-char #\: out)
                 (com.inuoe.jzon:stringify value :stream out)))
        (dolist (key first-fields) (emit key (gethash key state)))
        (maphash (lambda (key value) (unless (member key first-fields :test #'equal) (emit key value))) state))
      (write-char #\} out))))

(test checkpoint-metadata-rewrite-streams-all-values-and-preserves-the-journal
  (with-temporary-store (store root)
    (declare (ignore root))
    (let* ((path (gr8s.resources::core-resource-state-path store))
           (journal (gr8s.resources::core-journal-path store))
           (config (gr8s.resources::core-object "enabled" nil "phase" "metadata-fixture"))
           (payload (ag-grpc:base64-encode
                     (make-array (* 1024 1024) :element-type '(unsigned-byte 8) :initial-element 17)))
           (state (checkpoint-reader-state 2 #() (vector (checkpoint-reader-object 2 payload "Secret"))))
           (parse (symbol-function 'com.inuoe.jzon:parse))
           (parse-element (symbol-function 'com.inuoe.jzon:parse-next-element)))
      (ensure-directories-exist path)
      (setf (gethash "future" state)
            (vector t nil 'null 1.25d0 #() (gr8s.resources::core-object "escaped" (format nil "λ魚~%\"\\"))))
      (with-open-file (out journal :direction :output :if-exists :supersede)
        (write-line "{\"revision\":3,\"time\":10,\"changes\":[]}" out))
      (let ((journal-bytes (pure-tls::read-file-bytes journal)))
        (dolist (order '(("secretsEncryption" "items") ("items" "secretsEncryption") ("items")))
          (when (= 1 (length order)) (remhash "secretsEncryption" state))
          (write-checkpoint-reader-fixture path state order)
          (unwind-protect
               (progn
                 (setf (symbol-function 'com.inuoe.jzon:parse)
                       (lambda (&rest args) (declare (ignore args)) (error "Aggregate parse forbidden"))
                       (symbol-function 'com.inuoe.jzon:parse-next-element)
                       (lambda (&rest args) (declare (ignore args)) (error "Container parse forbidden")))
                 (gr8s.resources::persist-secret-encryption-metadata-unlocked store config))
            (setf (symbol-function 'com.inuoe.jzon:parse) parse
                  (symbol-function 'com.inuoe.jzon:parse-next-element) parse-element))
          (let ((parsed (com.inuoe.jzon:parse path :max-string-length (* 2 1024 1024))))
            (is (gr8s.store::json-value-equal-p config (gethash "secretsEncryption" parsed)))
            (remhash "secretsEncryption" parsed)
            (let ((expected (gr8s.resources::copy-core-object state)))
              (remhash "secretsEncryption" expected)
              (is (gr8s.store::json-value-equal-p expected parsed))))
          (is (eq config (gr8s.store::pod-store-secret-encryption-config store)))
          (is (equalp journal-bytes (pure-tls::read-file-bytes journal))))))))

(test checkpoint-metadata-malformed-input-does-not-publish-or-change-config
  (with-temporary-store (store root)
    (declare (ignore root))
    (let* ((path (gr8s.resources::core-resource-state-path store))
           (journal (gr8s.resources::core-journal-path store))
           (old (gr8s.resources::core-object "enabled" nil))
           (next (gr8s.resources::core-object "enabled" nil "phase" "next")))
      (ensure-directories-exist path)
      (setf (gr8s.store::pod-store-secret-encryption-config store) old)
      (with-open-file (out journal :direction :output :if-exists :supersede) (write-string "journal-sentinel" out))
      (dolist (json '("[]" "{\"version\":2,\"version\":2}"
                      "{\"secretsEncryption\":null,\"secretsEncryption\":{}}"
                      "{\"items\":[{\"value\":\"truncated" "{\"items\":[true,]}" "{} {}"))
        (with-open-file (out path :direction :output :if-exists :supersede) (write-string json out))
        (let ((files (uiop:directory-files (uiop:pathname-directory-pathname path))))
          (signals error (gr8s.resources::persist-secret-encryption-metadata-unlocked store next))
          (is (equal json (uiop:read-file-string path)))
          (is (eq old (gr8s.store::pod-store-secret-encryption-config store)))
          (is (equal "journal-sentinel" (uiop:read-file-string journal)))
          (is (equal (sort files #'string< :key #'namestring)
                     (sort (uiop:directory-files (uiop:pathname-directory-pathname path)) #'string< :key #'namestring))))))))

(test checkpoint-metadata-rename-failure-and-initial-rewrite-failure-keep-config
  (with-temporary-store (store root)
    (declare (ignore root))
    (let* ((path (gr8s.resources::core-resource-state-path store))
           (config (gr8s.resources::core-object "enabled" nil))
           (rename (symbol-function 'uiop:rename-file-overwriting-target))
           (checkpoint (symbol-function 'gr8s.resources::write-core-checkpoint)))
      ;; No existing checkpoint: the encryption shadow must not leak its new
      ;; config or token key when the initial checkpoint cannot be written.
      (unwind-protect
           (progn
             (setf (symbol-function 'gr8s.resources::write-core-checkpoint)
                   (lambda (&rest args) (declare (ignore args)) (error "Injected checkpoint failure")))
             (signals error (gr8s.resources::persist-secret-encryption-metadata-unlocked store config))
             (is (null (gr8s.store::pod-store-secret-encryption-config store)))
             (is (null (gr8s.store::pod-store-template-token-key store))))
        (setf (symbol-function 'gr8s.resources::write-core-checkpoint) checkpoint))
      (ensure-directories-exist path)
      (write-checkpoint-reader-fixture path (checkpoint-reader-state 0 #() #()) nil)
      (let ((before (pure-tls::read-file-bytes path)))
        (unwind-protect
             (progn
               (setf (symbol-function 'uiop:rename-file-overwriting-target)
                     (lambda (&rest args) (declare (ignore args)) (error "Injected publication failure")))
               (signals error (gr8s.resources::persist-secret-encryption-metadata-unlocked store config))
               (is (equalp before (pure-tls::read-file-bytes path)))
               (is (null (gr8s.store::pod-store-secret-encryption-config store))))
          (setf (symbol-function 'uiop:rename-file-overwriting-target) rename))))))

(test checkpoint-metadata-directory-sync-failure-does-not-acknowledge-new-config
  (with-temporary-store (store root)
    (declare (ignore root))
    (let* ((path (gr8s.resources::core-resource-state-path store))
           (journal (gr8s.resources::core-journal-path store))
           (old (gr8s.resources::core-object "enabled" nil))
           (next (gr8s.resources::core-object "enabled" nil "phase" "next"))
           (sync (symbol-function 'gr8s.store::sync-store-generation-directory)))
      (ensure-directories-exist path)
      (write-checkpoint-reader-fixture path (checkpoint-reader-state 0 #() #()) nil)
      (with-open-file (out journal :direction :output :if-exists :supersede) (write-string "journal-sentinel" out))
      (setf (gr8s.store::pod-store-secret-encryption-config store) old)
      (unwind-protect
           (progn
             (setf (symbol-function 'gr8s.store::sync-store-generation-directory)
                   (lambda (&rest args) (declare (ignore args)) (error "Injected directory sync failure")))
             (signals error (gr8s.resources::persist-secret-encryption-metadata-unlocked store next))
             (is (eq old (gr8s.store::pod-store-secret-encryption-config store)))
             ;; Rename has already published a complete file; failed directory
             ;; durability cannot promise rollback. Do not acknowledge success
             ;; or publish the new config in RAM, and keep the journal intact.
             (is (gr8s.store::json-value-equal-p next (gethash "secretsEncryption" (com.inuoe.jzon:parse path))))
             (is (equal "journal-sentinel" (uiop:read-file-string journal))))
        (setf (symbol-function 'gr8s.store::sync-store-generation-directory) sync)))))

(test checkpoint-reader-preserves-schema-order-independent-sharing-and-metadata
  (with-temporary-store (store root)
    (dolist (version '(1 2))
      (dolist (order '(("templateHistory" "items") ("items" "templateHistory")))
        (let* ((one (checkpoint-reader-object 1 "λ魚-one")) (two (checkpoint-reader-object 2 "λ魚-two"))
               (state (checkpoint-reader-state 2
                        (vector (checkpoint-reader-entry 1 'null one) (checkpoint-reader-entry 2 one two))
                        (vector two) version))
               (path (merge-pathnames "checkpoint-fixture.json" root))
               (original (symbol-function 'com.inuoe.jzon:parse)))
          (setf (gethash "customResourceItems" state)
                (vector (gr8s.resources::core-object "resource" "custom:example.com/gadgets"
                          "object" (checkpoint-reader-object 2 "custom" "Gadget"))))
          (write-checkpoint-reader-fixture path state order)
          (unwind-protect
               (progn
                 (setf (symbol-function 'com.inuoe.jzon:parse)
                       (lambda (&rest args) (declare (ignore args)) (error "Aggregate parse forbidden")))
                 (let* ((parsed (gr8s.resources::read-core-checkpoint store path))
                        (history (gethash "templateHistory" parsed)) (items (gethash "items" parsed)))
                   (is (= version (gethash "version" parsed)))
                   (is (= 2 (length history)))
                   (is (eq (gethash "new" (aref history 0)) (gethash "old" (aref history 1))))
                   (is (eq (aref items 0) (gethash "new" (aref history 1))))
                   (is (equal "λ魚-two" (gethash "key" (gethash "data" (aref items 0)))))
                   (dolist (field '("templateTokenKey" "workloadDeletions" "jobControllerStates" "eventExpirations"
                                    "customResourceItems"))
                     (is (gr8s.store::json-value-equal-p (gethash field state) (gethash field parsed))))))
            (setf (symbol-function 'com.inuoe.jzon:parse) original)))))))

(test checkpoint-reader-bounds-legacy-history-and-keeps-whole-transactions
  (with-temporary-store (store root)
    (let* ((path (merge-pathnames "bounded-checkpoint.json" root))
           (gr8s.resources::*resource-watch-history-bytes* (* 4 sb-vm:gencgc-page-bytes))
           (history (loop for i below 8 for revision = (1+ (* i 2))
                          for object = (checkpoint-reader-object revision
                                         (make-array 65536 :element-type 'base-char :initial-element #\x))
                          append (list (checkpoint-reader-entry revision 'null object)
                                       (checkpoint-reader-entry (1+ revision) object 'null))))
           (state (checkpoint-reader-state 16 (coerce history 'vector) #())))
      (write-checkpoint-reader-fixture path state '("templateHistory"))
      (let* ((parsed (gr8s.resources::read-core-checkpoint store path)) (kept (gethash "templateHistory" parsed)))
        (is (= 2 (length kept)))
        (is (= 14 (gethash "templateHistoryFloor" parsed)))
        (is (<= (reduce #'+ kept :key #'gr8s.resources::template-history-entry-bytes) gr8s.resources::*resource-watch-history-bytes*))
        (is (eq (gethash "new" (aref kept 0)) (gethash "old" (aref kept 1)))))
      ;; A single transaction too large for history must be removed in full.
      (dolist (entry history) (setf (gethash "revision" entry) 16))
      (write-checkpoint-reader-fixture path state '("templateHistory"))
      (let ((parsed (gr8s.resources::read-core-checkpoint store path)))
        (is (zerop (length (gethash "templateHistory" parsed))))
        (is (= 16 (gethash "templateHistoryFloor" parsed)))))))

(test checkpoint-reader-keeps-legacy-podtemplate-history-without-a-resource-field
  (with-temporary-store (store root)
    (let* ((object (gr8s.resources::core-object "apiVersion" "v1" "kind" "PodTemplate"
                     "metadata" (gr8s.resources::core-object "name" "sample" "namespace" "default" "resourceVersion" "1")
                     "template" (gr8s.resources::core-object "spec" (gr8s.resources::core-object "containers"
                       (vector (gr8s.resources::core-object "name" "pause" "image" "example.invalid/pause:1"))))))
           (entry (checkpoint-reader-entry 1 'null object "podtemplates"))
           (state (checkpoint-reader-state 1 (vector entry) (vector object) 1))
           (path (merge-pathnames "legacy-checkpoint.json" root)))
      (remhash "resource" entry)
      (remhash "resourceHistoryStart" state)
      (write-checkpoint-reader-fixture path state '("items" "templateHistory"))
      (let* ((parsed (gr8s.resources::read-core-checkpoint store path))
             (history (gethash "templateHistory" parsed)))
        (is (= 1 (length history)))
        (is (eq (aref (gethash "items" parsed) 0) (gethash "new" (aref history 0))))
        (is (not (nth-value 1 (gethash "resource" (aref history 0)))))
        (is (gethash '("podtemplates" "default" "sample") (gr8s.resources::core-state-index parsed)))))))

(test checkpoint-reader-authenticates-expiring-secrets-with-late-encryption-metadata
  (with-temporary-store (store root)
    (gr8s.security::ensure-cluster-pki root)
    (let* ((config (gr8s.resources::new-secret-encryption-config))
           (object (checkpoint-reader-object 1 "c2VudGluZWw=" "Secret"))
           (path (merge-pathnames "encrypted-checkpoint.json" root)))
      (setf (gr8s.store::pod-store-secret-encryption-config store) config)
      (let* ((one (gr8s.resources::encrypt-secret-object store "secrets" object))
             (two (gr8s.resources::encrypt-secret-object store "secrets" object))
             (state (checkpoint-reader-state 2
                      (vector (checkpoint-reader-entry 1 'null one "secrets")
                              (checkpoint-reader-entry 2 two 'null "secrets")) #())))
        (setf (gethash "secretsEncryption" state) config
              (gr8s.store::pod-store-secret-encryption-config store) nil)
        (write-checkpoint-reader-fixture path state '("templateHistory" "secretsEncryption"))
        (let* ((parsed (gr8s.resources::read-core-checkpoint store path)) (history (gethash "templateHistory" parsed)))
          (is (equal "c2VudGluZWw=" (gethash "key" (gethash "data" (gethash "new" (aref history 0))))))
          (is (eq (gethash "new" (aref history 0)) (gethash "old" (aref history 1))))
          (is (null (gr8s.store::pod-store-secret-encryption-config store))))
        (let* ((envelope (gethash gr8s.resources::+secret-encrypted-data-field+ two))
               (tag (ag-grpc:base64-decode (gethash "tag" envelope))))
          (setf (aref tag 0) (logxor 1 (aref tag 0))
                (gethash "tag" envelope) (ag-grpc:base64-encode tag)))
        (write-checkpoint-reader-fixture path state '("templateHistory" "secretsEncryption"))
        (let ((gr8s.resources::*resource-watch-history-bytes* 1))
          (signals error (gr8s.resources::read-core-checkpoint store path)))
        (is (null (gr8s.store::pod-store-secret-encryption-config store)))
        (let ((foreign (gr8s.resources::copy-core-object one)))
          (setf (gethash "kind" foreign) "ConfigMap"
                (gethash "items" state) (vector foreign) (gethash "templateHistory" state) #())
          (write-checkpoint-reader-fixture path state '("items" "secretsEncryption"))
          (signals error (gr8s.resources::read-core-checkpoint store path)))))))

(test checkpoint-reader-rejects-malformed-truncated-and-duplicate-content
  (with-temporary-store (store root)
    (let ((path (merge-pathnames "bad-checkpoint.json" root)))
      (dolist (json '("[]" "{\"version\":2,\"revision\":0,\"templateHistory\":["
                      "{\"version\":1,\"version\":1,\"revision\":0}"
                      "{\"version\":1,\"revision\":0} true"
                      "{\"version\":1,\"revision\":0,\"items\":{}}"
                      "{\"version\":99,\"revision\":0}"))
        (with-open-file (out path :direction :output :if-exists :supersede) (write-string json out))
        (signals error (gr8s.resources::read-core-checkpoint store path))))))

(in-suite gr8s)
