;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Read-only operational inventory for every locally persisted cluster
;;;; certificate and signing key. Stable names and machine fields are the
;;;; foundation for rotation gates; absence is reported without creating PKI.

(in-package #:gr8s.server)

(defparameter +certificate-warning-seconds+ (* 120 86400))

(defparameter +local-certificate-paths+
  '(("agent-kubelet-client" "agent/kubelet-client.crt")
    ("agent-kubelet-serving" "agent/kubelet.crt")
    ("agent-node-client" "agent/node.crt")
    ("agent-standalone-trust-anchor" "ca.crt")
    ("agent-trust-anchor" "agent/ca.crt")
    ("apiserver-kubelet-client" "apiserver-kubelet-client.crt")
    ("cluster-ca" "pki/cluster-ca.crt")
    ("front-proxy-ca" "front-proxy-ca.crt")
    ("front-proxy-client" "front-proxy-client.crt")
    ("kubernetes-api" "kubernetes-api.crt")
    ("node-client" "node.crt")
    ("node-server" "pki/server.crt")
    ("raft-member" "raft/member.crt")))

(defun certificate-status-duration (text)
  "Parse an operator duration such as 45d, 12h, 30m or 90s into seconds."
  (unless (and (stringp text) (> (length text) 1))
    (error "invalid certificate duration: ~S" text))
  (let* ((suffix (char-downcase (char text (1- (length text)))))
         (multiplier (case suffix (#\d 86400) (#\h 3600) (#\m 60) (#\s 1)
                       (otherwise (error "invalid certificate duration: ~A" text))))
         (number (parse-integer text :end (1- (length text)) :junk-allowed t)))
    (unless (and number (plusp number)
                 (string= (write-to-string number) (subseq text 0 (1- (length text)))))
      (error "invalid certificate duration: ~A" text))
    (* number multiplier)))

(defun parse-certificate-options (arguments)
  "Parse certificate inventory and staged ServiceAccount signing-key operations."
  (let* ((subcommand (first arguments))
         (rotation-p (string= subcommand "service-account-key"))
         (stage (and rotation-p (second arguments)))
         (command (cond
                    ((string= subcommand "status") :certificate-status)
                    ((and rotation-p (string= stage "prepare")) :certificate-service-account-key-prepare)
                    ((and rotation-p (string= stage "promote")) :certificate-service-account-key-promote)
                    ((and rotation-p (string= stage "finalize")) :certificate-service-account-key-finalize)
                    (t (error "unknown certificate subcommand: ~{~A~^ ~}" arguments)))))
    (let ((options (list :command command
                       :state-directory (namestring (default-state-directory))
                       :output-format :table
                       :warn-within +certificate-warning-seconds+))
          (arguments (nthcdr (if rotation-p 2 1) arguments)))
      (loop while arguments
          for option = (first arguments)
          do (cond
               ((string= option "--state-directory")
                (setf (getf options :state-directory) (option-value arguments option)
                      arguments (cddr arguments)))
               ((and (eq command :certificate-status) (string= option "--warn-within"))
                (setf (getf options :warn-within)
                      (certificate-status-duration (option-value arguments option))
                      arguments (cddr arguments)))
               ((and (eq command :certificate-status) (string= option "--output"))
                (let ((value (option-value arguments option)))
                  (setf (getf options :output-format)
                        (cond ((string= value "table") :table)
                              ((string= value "json") :json)
                              (t (error "certificate status output must be table or json")))
                        arguments (cddr arguments))))
               (t (error "unknown certificate option: ~A" option))))
      options)))

(defun certificate-status-stamp (universal-time)
  "Format UNIVERSAL-TIME as a deterministic UTC RFC3339 timestamp."
  (multiple-value-bind (second minute hour day month year)
      (decode-universal-time universal-time 0)
    (format nil "~4,'0D-~2,'0D-~2,'0DT~2,'0D:~2,'0D:~2,'0DZ"
            year month day hour minute second)))

(defun load-bounded-certificate-chain (path)
  "Load a small, structurally valid certificate-only PEM chain from PATH."
  (let ((bytes (read-bounded-credential-file path)))
    (let ((blocks (gr8s.security::csr-pem-blocks bytes)))
      (unless (and blocks
                   (every (lambda (block)
                            (and (string= "CERTIFICATE" (car block))
                                 (gr8s.security::der-well-formed-p (cdr block))))
                          blocks))
        (error "expected a well-formed CERTIFICATE PEM chain")))
    (pure-tls:load-certificate-chain path)))

(defun read-bounded-credential-file (path &optional (limit (* 1024 1024)))
  "Read at most LIMIT octets from PATH, rejecting oversized or short reads."
  (with-open-file (stream path :direction :input :element-type '(unsigned-byte 8))
    (let ((length (file-length stream)))
      (when (> length limit)
        (error "credential file exceeds ~D bytes" limit))
      (let ((bytes (make-array length :element-type '(unsigned-byte 8))))
        (unless (= length (read-sequence bytes stream))
          (error "short credential read"))
        bytes))))

(defun certificate-record (name path now warn-within)
  "Return the inventory plist for certificate PATH without modifying it."
  (if (not (probe-file path))
      (list :name name :kind :certificate :path (namestring path) :severity :missing)
      (handler-case
          (let* ((chain (load-bounded-certificate-chain path))
                 (leaf (or (first chain) (error "empty certificate chain")))
                 (not-before (pure-tls:certificate-not-before leaf))
                 (not-after (pure-tls:certificate-not-after leaf))
                 (remaining (- not-after now))
                 (severity (cond ((< now not-before) :not-yet-valid)
                                 ((minusp remaining) :expired)
                                 ((<= remaining warn-within) :warning)
                                 (t :healthy))))
            (list :name name :kind :certificate :path (namestring path)
                  :severity severity :not-before not-before :not-after not-after
                  :remaining-seconds remaining
                  :fingerprint (octets-to-hex (pure-tls:certificate-fingerprint leaf))
                  :issuer-fingerprint
                  (octets-to-hex (pure-tls:certificate-fingerprint (or (second chain) leaf)))))
        (error (condition)
          (list :name name :kind :certificate :path (namestring path)
                :severity :invalid :error (princ-to-string condition))))))

(defun service-account-key-record (root)
  "Return the local ServiceAccount signing-key inventory record without generating a key."
  (let ((path (merge-pathnames "pki/service-account-signing-key.json" root)))
    (if (not (probe-file path))
        (list :name "service-account-signing-key" :kind :key
              :path (namestring path) :severity :missing)
        (handler-case
            (let* ((json (trivial-utf-8:utf-8-bytes-to-string
                          (read-bounded-credential-file path)))
                   (key (service-account-signing-key-from-record
                         (com.inuoe.jzon:parse json))))
              (list :name "service-account-signing-key" :kind :key
                    :path (namestring path) :severity :healthy
                    :fingerprint (service-account-key-id key)))
          (error (condition)
            (list :name "service-account-signing-key" :kind :key
                  :path (namestring path) :severity :invalid
                  :error (princ-to-string condition)))))))

(defun certificate-inventory (state-directory &key (now (get-universal-time))
                                                   (warn-within +certificate-warning-seconds+))
  "Return a deterministic read-only inventory of local cluster credentials."
  (let ((root (uiop:ensure-directory-pathname state-directory)))
    (append
     (loop for (name relative) in +local-certificate-paths+
           collect (certificate-record name (merge-pathnames relative root) now warn-within))
     (list (service-account-key-record root)))))

(defun certificate-record-json (record)
  "Convert one inventory plist into its stable public JSON object."
  (let ((object (core-object "name" (getf record :name)
                             "kind" (string-downcase (string (getf record :kind)))
                             "path" (getf record :path)
                             "severity" (string-downcase (string (getf record :severity))))))
    (dolist (field '((:not-before "notBefore") (:not-after "notAfter")))
      (when (getf record (first field))
        (setf (gethash (second field) object)
              (certificate-status-stamp (getf record (first field))))))
    (dolist (field '((:remaining-seconds "remainingSeconds")
                     (:fingerprint "fingerprint")
                     (:issuer-fingerprint "issuerFingerprint")
                     (:error "error")))
      (when (getf record (first field))
        (setf (gethash (second field) object) (getf record (first field)))))
    object))

(defun certificate-inventory-json (records)
  "Serialize RECORDS as deterministic machine-readable inventory JSON."
  (com.inuoe.jzon:stringify (coerce (mapcar #'certificate-record-json records) 'vector)))

(defun write-certificate-inventory-table (records &optional (stream *standard-output*))
  "Write a compact stable certificate inventory table to STREAM."
  (format stream "~28A  ~11A  ~20A  ~A~%" "NAME" "STATUS" "EXPIRES" "PATH")
  (dolist (record records)
    (format stream "~28A  ~11A  ~20A  ~A~%"
            (getf record :name)
            (string-downcase (string (getf record :severity)))
            (if (getf record :not-after)
                (certificate-status-stamp (getf record :not-after)) "-")
            (getf record :path))))

(defun run-certificate-status (options)
  "Print certificate status in the selected format and return warning-sensitive status."
  (let ((records (certificate-inventory (getf options :state-directory)
                                        :warn-within (getf options :warn-within))))
    (ecase (getf options :output-format)
      (:table (write-certificate-inventory-table records))
      (:json (write-line (certificate-inventory-json records))))
    (if (find-if (lambda (record)
                   (member (getf record :severity)
                           '(:warning :expired :not-yet-valid :invalid)))
                 records)
        1 0)))

(defun run-service-account-signing-key-rotation (options)
  "Run one staged signing-key transition and print the resulting active or prepared key id."
  (let* ((store (open-store (getf options :state-directory)))
         (kid (ecase (getf options :command)
                (:certificate-service-account-key-prepare
                 (prepare-service-account-signing-key-rotation store))
                (:certificate-service-account-key-promote
                 (promote-service-account-signing-key-rotation store))
                (:certificate-service-account-key-finalize
                 (finalize-service-account-signing-key-rotation store)))))
    (format t "~A~%" kid)
    0))
