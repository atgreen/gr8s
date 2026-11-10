;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;; Instrumented native acceptance harness, not the production serve entry point.
(in-package #:cl-user)

(defun learner-native-seed (store count)
  ;; Keep the seeded table out of the main stack frame across restore/full GC.
  (dotimes (i count)
    (let ((name (format nil "config-~D" i)))
      (setf (gethash (list "configmaps" "default" name) (gr8s::pod-store-resources store))
            (gr8s::core-object "apiVersion" "v1" "kind" "ConfigMap"
              "metadata" (gr8s::core-object "name" name "namespace" "default" "resourceVersion" "1")
              "data" (gr8s::core-object "payload" (make-string 65536 :element-type 'base-char :initial-element #\x))))))
  (setf (gethash (list "namespaces" nil "default") (gr8s::pod-store-resources store))
        (gr8s::core-object "apiVersion" "v1" "kind" "Namespace"
          "metadata" (gr8s::core-object "name" "default" "uid" (gr8s::generate-uid) "resourceVersion" "1"))
        (gr8s::pod-store-resource-revision store) 1))

(defun learner-native-write-json (path value)
  (gr8s::write-private-text-atomically path (com.inuoe.jzon:stringify value)))

(defun learner-native-status (member store count)
  (let ((status
          (bt:with-lock-held ((gr8s::raft-member-lock member))
            (let ((node (gr8s::raft-member-node member)))
              (gr8s::core-object "role" (string-downcase (symbol-name (gr8s::raft-node-role node)))
                "selfRole" (string-downcase (symbol-name (gr8s::raft-node-self-role node)))
                "mutualTls" (if (gr8s.raft.transport::raft-member-credentials member) t nil)
                "term" (gr8s::raft-node-current-term node) "quorumMembers" (gr8s::raft-cluster-size node)
                "commit" (gr8s::raft-node-commit-index node) "applied" (gr8s::raft-node-last-applied node)
                "lastIndex" (gr8s::raft-last-log-index node)
                "members" (mapcar (lambda (entry) (gr8s::core-object "id" (car entry) "role" (string-downcase (symbol-name (cdr entry)))))
                                   (gr8s::raft-current-config node)))))))
    (setf (gethash "blocked" status) (if (gr8s.store::store-access-blocked-p store) t nil)
          (gethash "heapLimitMiB" status) (/ (sb-ext:dynamic-space-size) (* 1024 1024)))
    (unless (gr8s.store::store-access-blocked-p store)
      (let ((object (gr8s::get-core-resource store "configmaps" "default" (format nil "config-~D" (1- count)))))
        (setf (gethash "resources" status) (hash-table-count (gr8s::pod-store-resources store))
              (gethash "lastPayloadBytes" status) (length (gethash "payload" (gethash "data" object))))))
    status))

(defun learner-native-prepare-tls (base-text ids)
  "Offline test fixtures: distinct identities, one CA; never enrolls live members."
  (let* ((base (uiop:ensure-directory-pathname base-text))
         (founder-root (merge-pathnames (format nil "~A/tls/" (first ids)) base))
         (founder (gr8s::ensure-raft-founder-credentials founder-root (first ids))))
    (dolist (id (rest ids))
      (let* ((root (merge-pathnames (format nil "~A/tls/" id) base))
             (key (gr8s.security::raft-member-key-path root)))
        (gr8s::write-private-text-atomically
         (gr8s.security::raft-ca-certificate-path root)
         (uiop:read-file-string (gr8s::raft-credentials-ca-path founder)))
        (gr8s::write-private-text-atomically
         (gr8s.security::raft-member-certificate-path root)
         (gr8s::issue-raft-member-certificate
          (gr8s::raft-credentials-pki founder) id (gr8s::generate-node-key-and-csr id key)))))))

(defun learner-native-main ()
  (when (equal "--prepare-tls" (first (uiop:command-line-arguments)))
    (let ((arguments (rest (uiop:command-line-arguments))))
      (learner-native-prepare-tls (first arguments) (rest arguments))
      (return-from learner-native-main)))
  (handler-case
      (destructuring-bind (root-text id mode port-text records-text delay-text &optional tls-flag)
          (uiop:command-line-arguments)
        (let* ((root (uiop:ensure-directory-pathname root-text))
               (count (parse-integer records-text)) (delay (read-from-string delay-text))
               (request-path (merge-pathnames "harness/request.json" root))
               (response-path (merge-pathnames "harness/response.json" root))
               (credentials (when (equal tls-flag "--tls")
                              (gr8s.security::load-raft-credentials (merge-pathnames "tls/" root))))
               (store (gr8s:open-store root)) (member nil) (last-request nil)
               (original (symbol-function 'gr8s.raft.transport::raft-link-deliver-message)))
          (when (equal mode "founder") (learner-native-seed store count))
          (when (plusp delay)
            (setf (symbol-function 'gr8s.raft.transport::raft-link-deliver-message)
                  (lambda (stub message)
                    (when (eq :snapshot-chunk (getf message :type))
                      (when (zerop (mod (getf message :offset) (* 16 65536)))
                        (learner-native-write-json (merge-pathnames "harness/transfer.json" root)
                          (gr8s::core-object "offset" (getf message :offset) "total" (getf message :total)
                                             "token" (getf message :token))))
                      (sleep delay))
                    (funcall original stub message))))
          (unwind-protect
               (progn
                 (setf member (gr8s.resources::start-store-member-from-wal
                                store id (merge-pathnames "raft/control-plane.log" root)
                                :bootstrap-role (cond ((equal mode "founder") :founder) ((equal mode "learner") :learner))
                                :credentials credentials :host "127.0.0.1" :port (parse-integer port-text)))
                 (gr8s::raft-member-start member)
                 (learner-native-write-json (merge-pathnames "harness/ready.json" root) (gr8s::core-object "port" (gr8s::raft-member-port member)))
                 (loop
                   (when (probe-file request-path)
                     (let* ((request (with-open-file (stream request-path)
                                       (com.inuoe.jzon:parse stream :max-depth 8 :max-string-length 512)))
                            (nonce (gethash "nonce" request)) (command (gethash "command" request)))
                       (delete-file request-path)
                       (unless (equal nonce last-request)
                         (setf last-request nonce)
                         (let ((result
                                 (handler-case
                                     (cond
                                       ((equal command "status") (learner-native-status member store count))
                                       ((equal command "join")
                                        (gr8s::core-object "accepted" (if (gr8s::raft-cluster-join member "127.0.0.1" (gethash "port" request)) t nil)))
                                       ((equal command "write")
                                        (gr8s::create-core-resource store "configmaps"
                                          (gr8s::core-object "apiVersion" "v1" "kind" "ConfigMap"
                                            "metadata" (gr8s::core-object "name" (gethash "name" request))
                                            "data" (gr8s::core-object "value" (gethash "value" request))) "default")
                                        (gr8s::core-object "committed" t))
                                       ((equal command "read")
                                        (gr8s::core-object "value" (gethash "value" (gethash "data"
                                          (gr8s::get-core-resource store "configmaps" "default" (gethash "name" request))))))
                                       ((equal command "stop") (gr8s::core-object "stopped" t))
                                       (t (error "Unknown harness command")))
                                   (error (condition) (gr8s::core-object "error" (princ-to-string condition))))))
                           (setf (gethash "nonce" result) nonce)
                           (learner-native-write-json response-path result))
                         (when (equal command "stop") (return)))))
                   (sleep 0.02)))
            (when member (gr8s::stop-raft-member member))
            (setf (symbol-function 'gr8s.raft.transport::raft-link-deliver-message) original))))
    (error (condition) (format *error-output* "Native learner harness failed: ~A~%" condition) (uiop:quit 1))))
