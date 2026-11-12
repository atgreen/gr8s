;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0

(in-package #:gr8s/tests)
(in-suite gr8s)

(test secrets-encrypt-cli-options-are-explicit
  (dolist (entry '(("status" :secrets-encrypt-status)
                   ("enable" :secrets-encrypt-enable)
                   ("disable" :secrets-encrypt-disable)
                   ("prepare" :secrets-encrypt-prepare)
                   ("promote" :secrets-encrypt-promote)
                   ("reencrypt" :secrets-encrypt-reencrypt)
                   ("finalize" :secrets-encrypt-finalize)))
    (let ((options (parse-cli-options
                    (list "secrets-encrypt" (first entry)
                          "--state-directory" "/srv/gr8s"))))
      (is (eq (second entry) (getf options :command)))
      (is (equal "/srv/gr8s" (getf options :state-directory)))))
  (signals error (parse-cli-options '("secrets-encrypt" "rotate")))
  (signals error (parse-cli-options '("secrets-encrypt" "status" "--bogus"))))

(test secrets-encrypt-lifecycle-dispatches-through-the-public-cli
  (with-temporary-store (store directory)
    (gr8s.resources::create-core-resource
     store "secrets"
     (gr8s.resources::core-object
      "apiVersion" "v1" "kind" "Secret"
      "metadata" (gr8s.resources::core-object "name" "cli" "namespace" "default")
      "data" (gr8s.resources::core-object "value" "Y2xpLXNlbnRpbmVs"))
     "default")
    (dolist (stage '("enable" "prepare" "promote" "reencrypt" "finalize" "status"))
      (let ((result nil)
            (output nil))
        (setf output
              (with-output-to-string (*standard-output*)
                (setf result
                      (gr8s.server::main-with-environment
                       (list "secrets-encrypt" stage "--state-directory"
                             (namestring directory))
                       (constantly nil) (constantly 99)))))
        (let ((status (com.inuoe.jzon:parse output)))
          (is (= 0 result))
          (is-true (gethash "enabled" status))
          (is (plusp (gethash "keyCount" status))))))
    (let ((result nil)
          (output nil))
      (setf output
            (with-output-to-string (*standard-output*)
              (setf result
                    (gr8s.server::main-with-environment
                     (list "secrets-encrypt" "disable" "--state-directory"
                           (namestring directory))
                     (constantly nil) (constantly 99)))))
      (is (= 0 result))
      (is-false (gethash "enabled" (com.inuoe.jzon:parse output)))
      (is (search "Y2xpLXNlbnRpbmVs"
                  (uiop:read-file-string
                   (gr8s.resources::core-resource-state-path store)))))))
