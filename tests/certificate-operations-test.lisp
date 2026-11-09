;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Contract tests for read-only certificate inventory and expiry reporting.

(in-package #:gr8s/tests)

(in-suite gr8s)

(test certificate-status-cli-options-are-explicit
  (let ((options (parse-cli-options
                  '("certificate" "status" "--state-directory" "/srv/gr8s"
                    "--output" "json" "--warn-within" "45d"))))
    (is (eq :certificate-status (getf options :command)))
    (is (equal "/srv/gr8s" (getf options :state-directory)))
    (is (eq :json (getf options :output-format)))
    (is (= (* 45 86400) (getf options :warn-within))))
  (signals error (parse-cli-options '("certificate" "unknown")))
  (signals error (parse-cli-options '("certificate" "status" "--warn-within" "soon")))
  (signals error (parse-cli-options '("certificate" "status" "--output" "yaml"))))

(test certificate-inventory-is-read-only-deterministic-and-classifies-expiry
  (with-temporary-store (store directory)
    (declare (ignore store))
    (let* ((pki (gr8s:ensure-cluster-pki directory))
           (ca-path (gr8s:cluster-pki-ca-certificate-path pki))
           (ca (first (pure-tls:load-certificate-chain ca-path)))
           (not-before (pure-tls:certificate-not-before ca))
           (not-after (pure-tls:certificate-not-after ca))
           (before (uiop:read-file-string ca-path))
           (healthy (gr8s.server::certificate-inventory directory :now (get-universal-time)
                                                   :warn-within 1))
           (warning (gr8s.server::certificate-inventory directory :now (get-universal-time)
                                                   :warn-within (* 11 365 86400)))
           (expired (gr8s.server::certificate-inventory directory :now (1+ not-after)
                                                   :warn-within 1))
           (future (gr8s.server::certificate-inventory directory :now (1- not-before)
                                                  :warn-within 1)))
      (flet ((ca-record (records)
               (find "cluster-ca" records :key (lambda (record) (getf record :name))
                                         :test #'string=)))
        (is (eq :healthy (getf (ca-record healthy) :severity)))
        (is (eq :warning (getf (ca-record warning) :severity)))
        (is (eq :expired (getf (ca-record expired) :severity)))
        (is (eq :not-yet-valid (getf (ca-record future) :severity)))
        (is (eq :missing (getf (find "kubernetes-api" healthy
                                          :key (lambda (record) (getf record :name))
                                          :test #'string=)
                                    :severity))))
      (is (string= before (uiop:read-file-string ca-path)))
      (is (equal (mapcar (lambda (record) (getf record :name)) healthy)
                 (sort (copy-list (mapcar (lambda (record) (getf record :name)) healthy))
                       #'string<)))
      (is (string= (gr8s.server::certificate-inventory-json healthy)
                   (gr8s.server::certificate-inventory-json healthy))))))

(test certificate-inventory-reports-invalid-certificates-and-signing-key
  (with-temporary-store (store directory)
    (gr8s::load-service-account-signing-key store)
    (let ((bad (merge-pathnames "kubernetes-api.crt" directory)))
      (with-open-file (stream bad :direction :output :if-exists :supersede)
        (write-line "not a certificate" stream))
      (let* ((records (gr8s.server::certificate-inventory directory))
             (api (find "kubernetes-api" records :key (lambda (record) (getf record :name))
                                                   :test #'string=))
             (signer (find "service-account-signing-key" records
                           :key (lambda (record) (getf record :name)) :test #'string=)))
        (is (eq :invalid (getf api :severity)))
        (is (eq :key (getf signer :kind)))
        (is (stringp (getf signer :fingerprint)))))))

(test certificate-inventory-covers-standalone-agent-layout
  (with-temporary-store (store directory)
    (declare (ignore store))
    (let* ((pki (gr8s:ensure-cluster-pki directory))
           (ca-path (gr8s:cluster-pki-ca-certificate-path pki)))
      (uiop:copy-file ca-path (merge-pathnames "ca.crt" directory))
      (uiop:copy-file ca-path (merge-pathnames "node.crt" directory))
      (let ((records (gr8s.server::certificate-inventory directory)))
        (is (eq :healthy
                (getf (find "agent-standalone-trust-anchor" records
                            :key (lambda (record) (getf record :name)) :test #'string=)
                      :severity)))
        (is (eq :healthy
                (getf (find "node-client" records
                            :key (lambda (record) (getf record :name)) :test #'string=)
                      :severity)))))))

(test certificate-inventory-covers-combined-agent-trust-anchor
  (with-temporary-store (store directory)
    (declare (ignore store))
    (let* ((pki (gr8s:ensure-cluster-pki directory))
           (ca-path (gr8s:cluster-pki-ca-certificate-path pki))
           (agent-ca (merge-pathnames "agent/ca.crt" directory)))
      (ensure-directories-exist agent-ca)
      (uiop:copy-file ca-path agent-ca)
      (let* ((records (gr8s.server::certificate-inventory directory))
             (anchor (find "agent-trust-anchor" records
                           :key (lambda (record) (getf record :name)) :test #'string=)))
        (is (eq :healthy (getf anchor :severity)))
        (is (string= (namestring agent-ca) (getf anchor :path)))))))

(test certificate-inventory-bounds-signing-key-input
  (with-temporary-store (store directory)
    (declare (ignore store))
    (let ((path (merge-pathnames "pki/service-account-signing-key.json" directory)))
      (ensure-directories-exist path)
      (with-open-file (stream path :direction :output :if-exists :supersede)
        (write-string (make-string (1+ (* 1024 1024)) :initial-element #\x) stream))
      (let* ((records (gr8s.server::certificate-inventory directory))
             (signer (find "service-account-signing-key" records
                           :key (lambda (record) (getf record :name)) :test #'string=)))
        (is (eq :invalid (getf signer :severity)))
        (is (search "exceeds" (getf signer :error)))))))

(test certificate-status-table-and-json-have-stable-machine-fields
  (with-temporary-store (store directory)
    (declare (ignore store))
    (gr8s:ensure-cluster-pki directory)
    (let* ((records (gr8s.server::certificate-inventory directory))
           (table (with-output-to-string (stream)
                    (gr8s.server::write-certificate-inventory-table records stream)))
           (json (gr8s.server::certificate-inventory-json records))
           (parsed (com.inuoe.jzon:parse json)))
      (is (search "NAME" table))
      (is (search "cluster-ca" table))
      (is (vectorp parsed))
      (let ((ca (find "cluster-ca" parsed :key (lambda (record) (gethash "name" record))
                                           :test #'string=)))
        (is (equal "certificate" (gethash "kind" ca)))
        (is (gethash "notAfter" ca))
        (is (gethash "severity" ca))))))

(test certificate-status-dispatches-through-the-public-cli
  (with-temporary-store (store directory)
    (declare (ignore store))
    (let* ((arguments (list "certificate" "status" "--state-directory"
                            (namestring directory) "--output" "json"))
           (before (directory (merge-pathnames "**/*" directory)))
           (output (with-output-to-string (*standard-output*)
                     (is (= 0 (gr8s::main-with-environment
                               arguments (constantly nil) (constantly 99)))))))
      (is (search "service-account-signing-key" output))
      (is (search "missing" output))
      (is (equal before (directory (merge-pathnames "**/*" directory)))))))
