;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Upgrade one host to a signed gr8s release (podster-igs.3, podster-igs.4):
;;;;   POST /apis/gr8s.io/v1/nodes/<name>/upgrade                 through its agent
;;;;   POST /apis/gr8s.io/v1/controlplanemembers/<id>/upgrade     on that member
;;;; with {"reference": "REGISTRY/REPOSITORY:TAG"}. The host fetches the release,
;;;; checks it against the release keys it carries, installs it and restarts on it;
;;;; the answer is what it said up to the restart. That the host now runs the release
;;;; shows in its next hello, which `gr8s upgrade' waits for. Authorization is RBAC's
;;;; create on the subresource, as for nodes/slynk: it is root on the host.

(in-package #:gr8s.apiserver)

(defparameter *host-upgrade-timeout-seconds* 900
  "How long an upgrade request waits for its host to fetch and start installing a release.")

(defun start-member-upgrade-operation (payload emit)
  "Upgrade this member's host as PAYLOAD, an UPGRADE operation relayed from another
member, asks, emitting each step and the outcome through EMIT."
  (let ((id (slot-value payload 'gr8s.node.v1::operation-id))
        (sequence 0))
    (funcall emit :operation-response
             (make-instance 'gr8s.node.v1::operation-response :operation-id id
                            :status gr8s.node.v1::+operationstatus-operation_status_accepted+))
    (bt:make-thread
     (lambda ()
       (flet ((respond (status &optional (message ""))
                (funcall emit :operation-response
                         (make-instance 'gr8s.node.v1::operation-response
                                        :operation-id id :status status
                                        :exit-code (if (equal message "") 0 1) :error-message message))))
         (handler-case
             (progn
               (gr8s.upgrade:run-host-upgrade
                (slot-value payload 'gr8s.node.v1::upgrade-reference)
                (lambda (line)
                  (funcall emit :operation-stream
                           (make-instance 'gr8s.node.v1::operation-stream
                                          :operation-id id :sequence (incf sequence)
                                          :channel gr8s.node.v1::+streamchannel-stream_channel_stdout+
                                          :data (trivial-utf-8:string-to-utf-8-bytes (format nil "~A~%" line))))))
               (respond gr8s.node.v1::+operationstatus-operation_status_complete+))
           (error (condition)
             (respond gr8s.node.v1::+operationstatus-operation_status_failed+ (princ-to-string condition))))))
     :name "gr8s member upgrade")
    t))

(defun upgrade-request-reference ()
  "The release the current request names, checked to be an artifact reference."
  (let* ((body (ignore-errors (com.inuoe.jzon:parse (hunchentoot:raw-post-data :force-binary t))))
         (reference (and (hash-table-p body) (gethash "reference" body))))
    (unless (stringp reference)
      (core-resource-error 400 "BadRequest" "an upgrade names its release: {\"reference\": \"REGISTRY/REPOSITORY:TAG\"}"))
    (handler-case (gr8s.upgrade:parse-artifact-reference reference)
      (gr8s.upgrade:upgrade-error (condition)
        (core-resource-error 400 "BadRequest" "~A" condition)))
    reference))

(defun host-upgrade-response (host lines)
  (json-response
   (core-object "apiVersion" "v1" "kind" "Status" "status" "Success"
                "message" (format nil "~{~A~^~%~}" lines)
                "details" (core-object "name" host))))

(defun operation-stdout-lines (operation)
  (let ((text (trivial-utf-8:utf-8-bytes-to-string
               (apply #'concatenate '(vector (unsigned-byte 8))
                      (loop for message in (pending-node-operation-stream-messages operation)
                            collect (slot-value message 'gr8s.node.v1::data))))))
    (remove "" (uiop:split-string text :separator '(#\Newline)) :test #'equal)))

(defun await-host-upgrade (server host operation reference)
  "Wait for OPERATION, an upgrade sent to HOST, and answer with what it said."
  (handler-case
      (progn
        (wait-for-node-operation server operation :timeout *host-upgrade-timeout-seconds*)
        (host-upgrade-response host (operation-stdout-lines operation)))
    (runtime-error (condition)
      (if (search "Unsupported node operation" (runtime-error-message condition))
          (core-resource-error 501 "NotImplemented"
                               "~A runs a gr8s that predates remote upgrades; on that host, run: sudo gr8s upgrade self --to ~A"
                               host reference)
          (core-resource-error 502 "BadGateway" "upgrading ~A failed: ~A" host (runtime-error-message condition))))))

(defun serve-host-upgrade (store runtime path)
  "Answer POST nodes/<name>/upgrade or controlplanemembers/<id>/upgrade."
  (declare (ignore store))
  (unless *authenticated-api-identity*
    (core-resource-error 403 "Forbidden" "upgrading a host requires authenticated Kubernetes API access"))
  (unless (typep runtime 'gr8s.controllers::control-plane-runtime)
    (core-resource-error 503 "ServiceUnavailable" "this server can't reach its hosts"))
  (let* ((parts (remove "" (uiop:split-string path :separator '(#\/)) :test #'equal))
         (kind (fourth parts))
         (name (fifth parts))
         (reference (upgrade-request-reference))
         (server (gr8s.controllers::control-plane-runtime-node-server runtime))
         (request (make-instance 'gr8s.node.v1::operation-request
                                 :operation-id (generate-uid)
                                 :kind gr8s.node.v1::+operationkind-operation_kind_upgrade+
                                 :upgrade-reference reference)))
    (unless (path-segment-name-p name)
      (core-resource-error 400 "BadRequest" "invalid upgrade target"))
    ;; Fetching a release takes a while, and the client hears nothing until it's done.
    (extend-api-connection-idle-timeout (+ 60 *host-upgrade-timeout-seconds*))
    (if (equal kind "nodes")
        (await-host-upgrade server name (queue-node-operation server name request) reference)
        (let ((resolver (acceptor-debug-member-resolver (hunchentoot:request-acceptor hunchentoot:*request*))))
          (unless resolver
            (core-resource-error 404 "NotFound" "this cluster has no HA control-plane members"))
          (multiple-value-bind (local-p api-url exists-p) (funcall resolver name)
            (declare (ignore api-url))
            (unless exists-p (core-resource-error 404 "NotFound" "control-plane member ~A was not found" name))
            (if local-p
                (let ((lines nil))
                  (handler-case (gr8s.upgrade:run-host-upgrade reference (lambda (line) (push line lines)))
                    (error (condition)
                      (core-resource-error 502 "BadGateway" "upgrading ~A failed: ~A" name condition)))
                  (host-upgrade-response name (reverse lines)))
                (await-host-upgrade server name
                                    (handler-case (queue-member-operation server name request)
                                      (runtime-error (condition)
                                        (core-resource-error 503 "ServiceUnavailable" "~A" condition)))
                                    reference)))))))

;;; A worker that was away during an upgrade is upgraded when it comes back
;;; (podster-igs.8): `gr8s upgrade apply' leaves its host OnReconnect in the
;;; ClusterUpgrade, and the member that takes the node's session sends it the
;;; release. Rerunning `apply' then records it as done.

(defparameter +cluster-upgrade-resource+ "custom:upgrade.gr8s.io/clusterupgrades"
  "Where the store keeps ClusterUpgrades, a custom resource.")

(defun node-awaited-release (store node-name agent-version)
  "The release reference an unfinished ClusterUpgrade holds for NODE-NAME, waiting for
it to return, unless its agent runs that release already."
  (with-store-lock (store)
    (loop for key being the hash-keys of (pod-store-resources store) using (hash-value upgrade)
          when (and (equal (first key) +cluster-upgrade-resource+)
                    (member (gethash "phase" (gethash "status" upgrade (core-object))) '("Progressing" "Waiting") :test #'equal)
                    (not (equal agent-version (gethash "target" (gethash "spec" upgrade (core-object)))))
                    (find-if (lambda (host)
                               (and (hash-table-p host)
                                    (equal "OnReconnect" (gethash "state" host))
                                    (or (equal node-name (gethash "node" host)) (equal node-name (gethash "name" host)))))
                             (gethash "hosts" (gethash "status" upgrade (core-object)) #())))
            return (gethash "reference" (gethash "spec" upgrade)))))

(defun upgrade-returning-node (server node-name agent-version)
  "Send NODE-NAME, just connected, the release an upgrade it missed is waiting with."
  (let ((reference (ignore-errors (node-awaited-release (node-grpc-server-store server) node-name agent-version))))
    (when reference
      (bt:make-thread
       (lambda ()
         (handler-case
             (let ((operation (queue-node-operation
                               server node-name
                               (make-instance 'gr8s.node.v1::operation-request
                                              :operation-id (generate-uid)
                                              :kind gr8s.node.v1::+operationkind-operation_kind_upgrade+
                                              :upgrade-reference reference))))
               (wait-for-node-operation server operation :timeout *host-upgrade-timeout-seconds*)
               (format *error-output* "gr8s: node ~A returned and is upgrading to ~A~%" node-name reference))
           (error (condition)
             (format *error-output* "gr8s: node ~A returned but could not be upgraded to ~A: ~A~%"
                     node-name reference condition))))
       :name "gr8s returning node upgrade"))))
