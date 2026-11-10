;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;; Private identities for packet Service source translation. The checkpoint is
;;;; part of the ordinary Pod observation transaction, never public Pod status.
(in-package #:gr8s.network)

(defun service-translation-status-addresses (status)
  (remove-duplicates
   (append (when (stringp (gethash "podIP" status)) (list (gethash "podIP" status)))
           (let ((plural (gethash "podIPs" status)))
             (when (and (vectorp plural) (not (stringp plural)))
               (loop for item across plural
                     for address = (and (hash-table-p item) (gethash "ip" item))
                     when (stringp address) collect address))))
   :test #'equal))

(defun service-translation-string (object key)
  (let ((value (and (hash-table-p object) (gethash key object))))
    (unless (and (stringp value) (<= 1 (length value) 256)
                 (not (find #\Null value)))
      (error "Invalid Service translation identity field ~A" key))
    value))

(defun canonical-service-translation-ipv4 (address)
  (let ((numeric (parse-ipv4-integer address)))
    (unless (equal address (format-pod-address :ipv4 numeric))
      (error "Service translation addresses must be canonical IPv4"))
    numeric))

(defun service-translation-address-key (address)
  (handler-case (node-ipam-address-identity address) (error () address)))

(defun current-service-translation-unlocked (store pod status)
  "Read a record only while its Pod and node incarnations still own it."
  (let* ((record (and status (gethash "gr8sServiceTranslation" status)))
         (node (gethash (pod-node-name pod) (pod-store-nodes store))))
    (when (and (hash-table-p record) node
               (equal (pod-uid pod) (gethash "podUID" record))
               (equal (pod-node-name pod) (gethash "nodeName" record))
               (equal (node-record-id node) (gethash "nodeID" record)))
      record)))

(defun normalize-node-service-translation (store node-name pod status &key (check-owners t))
  "Validate an authenticated node claim against assignment and all other owners.
Caller holds STORE's lock through the subsequent observation commit."
  (let ((claim (gethash "gr8sServiceTranslation" status)))
    (when check-owners
      (let ((incoming (mapcar #'service-translation-address-key (service-translation-status-addresses status))))
        (dolist (other (loop for value being the hash-values of (pod-store-pods store) collect value))
          (unless (equal (pod-uid other) (pod-uid pod))
            (let* ((observed (gethash (pod-uid other) (pod-store-pod-observed-statuses store)))
                   (record (current-service-translation-unlocked store other observed))
                   (alias (and (hash-table-p record) (gethash "address" record))))
              (when (member alias incoming :test #'equal)
                (error "Pod address conflicts with another Pod's Service translation identity")))))))
    (when claim
      (unless (and (current-status-pod-p store pod)
                   (equal node-name (pod-node-name pod)) (not (pod-host-network-p pod)))
        (error "Service translation identity does not belong to this node's current Pod"))
      (let* ((address (service-translation-string claim "address"))
             (primary (service-translation-string claim "podIP"))
             (sandbox (service-translation-string claim "sandboxID"))
             (interface (service-translation-string claim "interfaceName"))
             (alias-number (canonical-service-translation-ipv4 address))
             (pod-number (canonical-service-translation-ipv4 primary))
             (node (or (gethash node-name (pod-store-nodes store))
                       (error "Service translation node was removed")))
             (cidr (find-if (lambda (value) (not (find #\: value)))
                            (coerce (node-record-all-pod-cidrs node) 'list))))
        (unless (equal (service-translation-string claim "nodeID") (node-record-id node))
          (error "Service translation claim belongs to a replaced node record"))
        (unless (and cidr (/= alias-number pod-number)
                     (member primary (mapcar #'service-translation-address-key
                                             (service-translation-status-addresses status)) :test #'equal))
          (error "Service translation identity lacks its assigned IPv4 Pod address"))
        (multiple-value-bind (family network prefix bits) (parse-pod-cidr cidr)
          (declare (ignore family bits))
          (unless (and (usable-node-ipam-address-p alias-number network prefix 32)
                       (usable-node-ipam-address-p pod-number network prefix 32))
            (error "Service translation identity is outside this node's usable Pod CIDR")))
        (when check-owners (dolist (other (loop for value being the hash-values of (pod-store-pods store) collect value))
          (unless (equal (pod-uid other) (pod-uid pod))
            (let ((observed (gethash (pod-uid other) (pod-store-pod-observed-statuses store))))
              (when observed
                (let* ((other-claim (current-service-translation-unlocked store other observed))
                       (other-alias (and (hash-table-p other-claim) (gethash "address" other-claim))))
                  (when (or (member address (mapcar #'service-translation-address-key
                                                   (service-translation-status-addresses observed)) :test #'equal)
                            (member primary (mapcar #'service-translation-address-key
                                                    (service-translation-status-addresses observed)) :test #'equal)
                            (equal address other-alias) (equal primary other-alias))
                    (error "Service translation identity conflicts with another Pod"))))))))
        ;; Node and Pod identity come from the authenticated assignment, never
        ;; from mutable client annotations or the inner JSON claim.
        (json-object "address" address "podIP" primary "sandboxID" sandbox
                     "interfaceName" interface "podUID" (pod-uid pod) "nodeName" node-name
                     "nodeID" (node-record-id node))))))

(defun service-translation-identity-messages (store)
  "Project retained trusted observations, including temporarily unready nodes."
  (with-store-lock (store)
    (loop for pod in (sort (loop for value being the hash-values of (pod-store-pods store) collect value)
                          #'string< :key #'pod-uid)
          for status = (gethash (pod-uid pod) (pod-store-pod-observed-statuses store))
          for claim = (current-service-translation-unlocked store pod status)
          when claim collect
          (let ((record (normalize-node-service-translation store (pod-node-name pod) pod status :check-owners nil)))
            (make-instance 'gr8s.node.v1::service-translation-identity
                           :pod-uid (gethash "podUID" record) :node-name (gethash "nodeName" record)
                           :node-id (gethash "nodeID" record)
                           :pod-ip (gethash "podIP" record) :translation-ip (gethash "address" record)
                           :sandbox-id (gethash "sandboxID" record) :interface-name (gethash "interfaceName" record))))))

(defun validate-service-translation-network (network)
  "Check a received/restored identity inventory before any dataplane consumer."
  (let ((records (gethash "serviceTranslations" network #()))
        (aliases (make-hash-table :test #'equal))
        (pods (make-hash-table :test #'equal))
        (owners (make-hash-table :test #'equal))
        (cidrs (or (gethash "clusterPodCIDRs" network)
                   (vector (gethash "clusterPodCIDR" network)))))
    (unless (and (vectorp records) (not (stringp records)))
      (invalid-cni "Service translation identities must be an array"))
    (handler-case
        (progn
          (loop for record across records
                for alias = (service-translation-string record "address")
                for primary = (service-translation-string record "podIP")
                for owner = (service-translation-string record "podUID")
                do (dolist (key '("sandboxID" "interfaceName" "nodeName" "nodeID"))
                     (service-translation-string record key))
                   (when (or (gethash alias aliases) (gethash primary pods) (gethash owner owners))
                     (error "Duplicate Service translation identity"))
                   (dolist (address (list alias primary))
                     (let ((numeric (canonical-service-translation-ipv4 address)))
                       (unless (loop for cidr across cidrs
                                     thereis (multiple-value-bind (family base prefix bits) (parse-pod-cidr cidr)
                                               (declare (ignore bits))
                                               (and (eq family :ipv4)
                                                    (usable-node-ipam-address-p numeric base prefix 32))))
                         (error "Service translation identity is outside the cluster Pod pool"))))
                   (setf (gethash alias aliases) t (gethash primary pods) t (gethash owner owners) t))
          (maphash (lambda (alias value)
                     (declare (ignore value))
                     (when (gethash alias pods)
                       (error "Service translation address aliases a configured Pod address"))) aliases))
      (error (condition) (invalid-cni "invalid Service translation inventory: ~A" condition))))
  network)
