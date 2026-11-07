;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Maintain a bounded, durable journal for stored Kubernetes resources. Reads
;;;; reconstruct an exact revision by undoing later mutations. Signed key-based
;;;; continuation tokens survive restart and support honest expiry/recovery.

(in-package #:gr8s.resources)

(defparameter *podtemplate-history-seconds* 300
  "How much history a commit writes to disk, and how long a continue token lasts.
Every commit rewrites this history, so it is kept shorter than the watch history in memory.")
(defparameter *podtemplate-history-limit* 4096
  "The most history entries a commit writes to disk.")
(defparameter *resource-watch-history-limit* 16384
  "The most stored-resource history entries kept in memory, whatever their age.
An entry only refers to objects, most of which the store or a neighbouring entry also holds.")
(defparameter *resource-watch-history-bytes* (* 96 1024 1024)
  "The most memory, by APPROXIMATE-HEAP-BYTES, that stored-resource history may hold in all.
At a write a second this keeps the full window; a burst of writes keeps less of it.")
(defparameter +template-watch-maintenance-interval+ internal-time-units-per-second
  "Least time between the journal and Event expiry checks that watches perform.")

(defun template-history-old-bytes (old)
  "Return the memory a history entry whose old object is OLD alone keeps alive.
That is OLD: the store or the next change of the same object holds the new one."
  (+ 512 (if (hash-table-p old) (approximate-heap-bytes old) 0)))

(defun template-history-entry-bytes (entry)
  "Return the memory ENTRY alone keeps alive. Entries are never changed once published,
since watches read them unlocked, so one written by an older version is measured each time."
  (or (gethash "bytes" entry) (template-history-old-bytes (gethash "old" entry))))

(defun trim-template-history (history floor now seconds limit &optional byte-limit)
  "Drop entries older than SECONDS, beyond the newest LIMIT, or beyond the newest BYTE-LIMIT
of memory, returning those left and their floor."
  (let ((excess (max 0 (- (length history) limit))))
    (loop repeat excess
          do (setf floor (max floor (gethash "revision" (pop history)))))
    (loop while (and history (> (- now (gethash "time" (first history))) seconds))
          do (setf floor (max floor (gethash "revision" (pop history)))))
    (when byte-limit
      (let ((bytes (reduce #'+ history :key #'template-history-entry-bytes)))
        (loop while (and history (> bytes byte-limit))
              do (let ((entry (pop history)))
                   (decf bytes (template-history-entry-bytes entry))
                   (setf floor (max floor (gethash "revision" entry)))))))
    ;; Never retain half of a transaction (for example a large DeleteCollection).
    (values (remove-if (lambda (entry) (<= (gethash "revision" entry) floor)) history) floor)))

(defun next-template-history (store resources revision)
  "Compute journal changes and retention floor before committing any state.
Also returns this commit's new entries, newest first."
  (let ((history (copy-list (pod-store-template-history store))) (added nil)
        (floor (pod-store-template-history-floor store))
        (now (funcall *podtemplate-clock*)) (keys (make-hash-table :test #'equal)))
    (dolist (index (list (pod-store-resources store) resources))
      (maphash (lambda (key object) (declare (ignore object))
                 (setf (gethash key keys) t)) index))
    (maphash (lambda (key present)
               (declare (ignore present))
               (let ((old (gethash key (pod-store-resources store))) (new (gethash key resources)))
                 (unless (eq old new)
                   (let ((entry (core-object "revision" revision "time" now "resource" (first key)
                                             "namespace" (second key) "name" (third key)
                                             "old" (or old 'null) "new" (or new 'null)
                                             "bytes" (template-history-old-bytes old))))
                     (push entry added)
                     (setf history (nconc history (list entry))))))) keys)
    (multiple-value-bind (history floor)
        (trim-template-history history floor now *watch-history-seconds* *resource-watch-history-limit*
                               *resource-watch-history-bytes*)
      (values history floor added))))

(defun durable-template-history (history floor)
  "Return the part of HISTORY a commit writes to disk, and the floor a restart resumes from."
  (trim-template-history history floor (funcall *podtemplate-clock*)
                         *podtemplate-history-seconds* *podtemplate-history-limit*))

(defun template-history-after (store revision)
  "Return journal entries newer than REVISION, oldest first, cheaply when they are recent.
The lists are replaced rather than changed by commits, so a caller may read them unlocked."
  (let ((entries nil))
    (dolist (entry (pod-store-template-history-recent store)
                   ;; Every recent entry is newer, so older ones may exist too.
                   (remove-if-not (lambda (entry) (> (gethash "revision" entry) revision))
                                  (pod-store-template-history store)))
      (when (<= (gethash "revision" entry) revision) (return entries))
      (push entry entries))))

(defun compact-template-history-unlocked (store &key checkpoint)
  "Durably compact expired history, optionally recording an expired-token checkpoint."
  (expire-core-events-unlocked store)
  ;; The oldest entry is first, and every open watch comes here once a second.
  (when (or checkpoint
            (let ((oldest (first (pod-store-template-history store))))
              (and oldest (> (- (funcall *podtemplate-clock*) (gethash "time" oldest))
                             *watch-history-seconds*))))
    (commit-core-resources store (copy-core-resource-index store) (1+ (pod-store-resource-revision store)))))

(defun check-template-revision-unlocked (store revision &optional (resource "podtemplates"))
  "Reject a revision that is in the future or that the journal has compacted."
  (when (> revision (pod-store-resource-revision store))
    (core-resource-error 504 "Timeout" "Requested resourceVersion is newer than the storage revision"))
  (when (< revision (max (pod-store-template-history-floor store)
                         (if (equal resource "podtemplates") 0 (pod-store-resource-history-start store))))
    (core-resource-error 410 "Expired" "The requested resourceVersion has been compacted")))

(defun template-index-at-revision-unlocked (store revision &optional (resource "podtemplates"))
  "Reconstruct a real historical view; reject future or compacted revisions."
  (check-template-revision-unlocked store revision resource)
  (let ((index (copy-core-resource-index store)))
    (dolist (entry (reverse (pod-store-template-history store)))
      (when (> (gethash "revision" entry) revision)
        (let ((key (core-resource-key (gethash "resource" entry "podtemplates") (gethash "namespace" entry) (gethash "name" entry)))
              (old (gethash "old" entry)))
          (if (eq old 'null) (remhash key index) (setf (gethash key index) old)))))
    index))

(defun template-object-key (object)
  "Return the namespace/name storage ordering key for an object."
  (let ((metadata (gethash "metadata" object)))
    (format nil "~A/~A" (gethash "namespace" metadata) (gethash "name" metadata))))

(defun template-token-signature (store payload)
  "Authenticate a continuation payload with the private persisted store key."
  (let ((hmac (ironclad:make-hmac (pod-store-template-token-key store) :sha256)))
    (ironclad:update-hmac hmac (trivial-utf-8:string-to-utf-8-bytes payload))
    (ag-grpc:base64-encode (ironclad:hmac-digest hmac))))

(defun encode-template-token (store namespace labels fields revision last-key &optional (resource "podtemplates"))
  "Encode a query-bound continuation after LAST-KEY at an exact revision."
  (let ((payload (ag-grpc:base64-encode
                  (trivial-utf-8:string-to-utf-8-bytes
                   (com.inuoe.jzon:stringify
                    (core-object "resource" resource "definitionUID" (if (custom-resource-key-p resource) (crd-definition-uid-unlocked store resource) 'null) "namespace" (or namespace 'null) "labels" labels "fields" fields
                                 "revision" revision "lastKey" last-key "issuedAt" (funcall *podtemplate-clock*)))))))
    (concatenate 'string payload "." (template-token-signature store payload))))

(defun decode-template-token (store value namespace labels fields &optional (resource "podtemplates"))
  "Verify a continuation token and its original scope and selectors."
  (handler-case
      (let* ((parts (uiop:split-string value :separator '(#\.)))
             (payload (first parts)))
        (unless (and (< (length value) 8192) (= 2 (length parts))
                     (equal (second parts) (template-token-signature store payload)))
          (error "Invalid token signature"))
        (let ((token (com.inuoe.jzon:parse (trivial-utf-8:utf-8-bytes-to-string (core-base64-bytes payload "continue")))))
          (unless (and (hash-table-p token) (equal resource (gethash "resource" token "podtemplates"))
                       (equal (or namespace 'null) (gethash "namespace" token))
                       (equal labels (gethash "labels" token)) (equal fields (gethash "fields" token))
                       (typep (gethash "revision" token) '(integer 0 *))
                       (typep (gethash "issuedAt" token) '(integer 0 *)) (stringp (gethash "lastKey" token)))
            (error "Invalid token scope"))
          (when (and (custom-resource-key-p resource)
                     (not (equal (gethash "definitionUID" token) (crd-definition-uid-unlocked store resource))))
            (core-resource-error 410 "Expired" "Continue token belongs to an older custom definition"))
          token))
    (kubernetes-error (condition) (error condition))
    (error () (core-resource-error 400 "BadRequest" "Invalid or mismatched resource continue token"))))

(defun template-list-page (store namespace labels fields &key limit continuation resource-version match (resource "podtemplates"))
  "List a consistent revision; return a replacement continuation when history expires."
  (unless (or (null limit) (typep limit '(integer 0 *))) (core-resource-error 400 "BadRequest" "Invalid limit"))
  (unless (member match '(nil "" "Exact" "NotOlderThan") :test #'equal) (core-resource-error 400 "BadRequest" "Invalid resourceVersionMatch"))
  (let ((label-test (core-selector-predicate labels)) (field-test (crd-field-selector-test resource fields)))
    (crd-prepare-selector-views store resource namespace fields)
    (with-crd-deferred-conversions
     (with-store-lock (store)
      (check-crd-resource-context-unlocked store resource)
      (compact-template-history-unlocked store)
      (let* ((token (when (and continuation (plusp (length continuation)))
                      (decode-template-token store continuation namespace labels fields resource)))
             (requested (unless (member resource-version '(nil "" "0") :test #'equal)
                          (unless (and (stringp resource-version) (every #'digit-char-p resource-version))
                            (core-resource-error 400 "BadRequest" "Invalid resourceVersion"))
                          (parse-integer resource-version)))
             (revision (or (and token (gethash "revision" token))
                           (and requested (not (equal match "NotOlderThan")) requested)
                           (pod-store-resource-revision store)))
             (last-key (and token (gethash "lastKey" token))))
        (check-crd-resource-context-unlocked store resource revision)
        (when (and token requested) (core-resource-error 400 "BadRequest" "resourceVersion cannot be combined with continue"))
        (when (and match (not (equal match "")) (null requested) (not (equal resource-version "0")))
          (core-resource-error 400 "BadRequest" "resourceVersionMatch requires resourceVersion"))
        (when (and requested (> requested (pod-store-resource-revision store)))
          (core-resource-error 504 "Timeout" "Requested resourceVersion is newer than storage"))
        (when (and token (or (< revision (max (pod-store-template-history-floor store)
                         (if (equal resource "podtemplates") 0 (pod-store-resource-history-start store))))
                             (> (- (funcall *podtemplate-clock*) (gethash "issuedAt" token)) *podtemplate-history-seconds*)))
          ;; Expiration checkpoints advance durable storage metadata even when
          ;; objects have not changed. A resumed list is explicitly a new view.
          (compact-template-history-unlocked store :checkpoint t)
          (return-from template-list-page
            (values (core-object "apiVersion" "v1" "kind" "Status" "status" "Failure" "code" 410 "reason" "Expired"
                                 "message" "Resource list snapshot expired; continue at a newer revision or restart for a consistent full list"
                                 "metadata" (core-object "continue" (encode-template-token store namespace labels fields
                                                                             (pod-store-resource-revision store) last-key resource))) 410)))
        (let* ((index (template-index-at-revision-unlocked store revision resource))
               (items (sort (loop for key being the hash-keys of index using (hash-value object)
                                 when (and (equal resource (first key)) (or (null namespace) (equal namespace (second key)))
                                           (or (null last-key) (string> (template-object-key object) last-key))
                                           (funcall label-test object) (funcall field-test object))
                                   collect object) #'string< :key #'template-object-key))
               (end (if (and limit (plusp limit)) (min limit (length items)) (length items)))
               (metadata (core-object "resourceVersion" (write-to-string revision) "continue" "")))
          (when (< end (length items))
            (setf (gethash "continue" metadata) (encode-template-token store namespace labels fields revision
                                                                 (template-object-key (nth (1- end) items)) resource))
            (when (and (equal labels "") (equal fields ""))
              (setf (gethash "remainingItemCount" metadata) (- (length items) end))))
          (values (core-object "apiVersion" (core-resource-api-version resource) "kind" (concatenate 'string (core-resource-kind resource) "List") "metadata" metadata
                               "items" (map 'vector #'copy-core-object (subseq items 0 end))) 200)))))))
