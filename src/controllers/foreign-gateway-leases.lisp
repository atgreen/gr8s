;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
(in-package #:gr8s.controllers)

(defconstant +foreign-gateway-first-port+ 20000)
(defconstant +foreign-gateway-last-port+ 29999)

(defstruct foreign-gateway-port-leases
  cluster node-name identity-path (namespace "kube-system")
  (first-port +foreign-gateway-first-port+) (last-port +foreign-gateway-last-port+))

(defun validate-foreign-gateway-port-range (ephemeral-range)
  "The private listener range must remain outside automatic host allocation."
  (let ((bounds (mapcar #'parse-integer
                        (cl-ppcre:split "\\s+" (string-trim '(#\Space #\Tab #\Newline #\Return)
                                                           ephemeral-range)))))
    (unless (and (= 2 (length bounds)) (<= 1 (first bounds) (second bounds) 65535)
                 (or (> (first bounds) +foreign-gateway-last-port+)
                     (< (second bounds) +foreign-gateway-first-port+)))
      (error "Host ephemeral range ~A overlaps or cannot validate Gateway ports ~D-~D"
             ephemeral-range +foreign-gateway-first-port+ +foreign-gateway-last-port+))
    t))

(defun foreign-gateway-lease-digest (value)
  (ironclad:byte-array-to-hex-string
   (ironclad:digest-sequence :sha256 (trivial-utf-8:string-to-utf-8-bytes value))))

(defun foreign-gateway-validate-lease-data (leases data)
  "Reject duplicate assignments or a counter that could reassign an old port."
  (let ((next (parse-integer (gethash "next-port" data)))
        (seen (make-hash-table))
        (first (foreign-gateway-port-leases-first-port leases))
        (last (foreign-gateway-port-leases-last-port leases)))
    (unless (<= first next (1+ last)) (error "Invalid Gateway port allocation counter"))
    (maphash
     (lambda (key value)
       (unless (equal key "next-port")
         (let ((port (parse-integer value)))
           (unless (and (<= first port last) (< port next) (not (gethash port seen)))
             (error "Invalid or duplicate Gateway port assignment ~A" value))
           (setf (gethash port seen) t))))
     data)
    next))

(defun foreign-gateway-check-lease-identity (leases object)
  "Pin the ledger UID locally before any port can be advertised."
  (let* ((path (foreign-gateway-port-leases-identity-path leases))
         (saved (and path (probe-file path) (uiop:read-file-string path)))
         (uid (and object (gethash "uid" (gethash "metadata" object)))))
    (when path
      (cond
        (saved
         (unless (and (plusp (length saved)) (equal saved uid))
           (error "Gateway port ledger disappeared or changed identity; refusing to reuse ports")))
        (object
         (unless (and (stringp uid) (plusp (length uid)))
           (error "Gateway port ledger has no UID"))
         (gr8s.store::write-text-atomically path uid))))))

(defun foreign-gateway-reserve-port-once (leases gateway-key public-port)
  "Durably reserve a TCP port. Leases are never recycled after Gateway deletion.
The caller must bind the returned port successfully before publishing it."
  (let* ((cluster (foreign-gateway-port-leases-cluster leases))
         (node (foreign-gateway-port-leases-node-name leases))
         (namespace (foreign-gateway-port-leases-namespace leases))
         (name (concatenate 'string "gr8s-gateway-ports-"
                            (subseq (foreign-gateway-lease-digest node) 0 32)))
         (path (gr8s.kube-client:resource-path nil "v1" "configmaps" :namespace namespace :name name))
         (current (foreign-gateway-get cluster path))
         (key (concatenate 'string "g-" (foreign-gateway-lease-digest
                                        (let ((uid (third gateway-key)))
                                          (unless (and (stringp uid) (plusp (length uid)))
                                            (error "Gateway port allocation requires a UID"))
                                          (format nil "~A/~D" uid public-port)))))
         (data (if current (gethash "data" current)
                   (gr8s.resources::core-object
                    "next-port" (write-to-string (foreign-gateway-port-leases-first-port leases)))))
         (existing (gethash key data)))
    (when (and current
               (not (equal node (gethash "gr8s.io/gateway-node"
                                         (gethash "annotations" (gethash "metadata" current)
                                                  (make-hash-table))))))
      (error "Refusing unrelated Gateway port lease ConfigMap ~A" path))
    (foreign-gateway-check-lease-identity leases current)
    (foreign-gateway-validate-lease-data leases data)
    (when existing
      (let ((port (parse-integer existing)))
        (unless (<= (foreign-gateway-port-leases-first-port leases) port
                    (foreign-gateway-port-leases-last-port leases))
          (error "Invalid Gateway port lease ~A in ~A" existing path))
        (return-from foreign-gateway-reserve-port-once port)))
    (let ((port (parse-integer (gethash "next-port" data))))
      (unless (<= (foreign-gateway-port-leases-first-port leases) port
                  (foreign-gateway-port-leases-last-port leases))
        (error "Gateway private port leases exhausted on node ~A" node))
      (setf (gethash key data) (write-to-string port)
            (gethash "next-port" data) (write-to-string (1+ port)))
      (let ((saved
              (if current
                  (gr8s.kube-client:kube-replace cluster path current)
                  (gr8s.kube-client:kube-create
                   cluster (gr8s.kube-client:resource-path nil "v1" "configmaps" :namespace namespace)
                   (gr8s.resources::core-object
                    "apiVersion" "v1" "kind" "ConfigMap"
                    "metadata" (gr8s.resources::core-object
                                "name" name "namespace" namespace
                                "annotations" (gr8s.resources::core-object "gr8s.io/gateway-node" node))
                    "data" data)))))
        (foreign-gateway-check-lease-identity leases saved))
      port)))

(defun foreign-gateway-port-for (leases gateway-key public-port)
  "Retry optimistic API conflicts using a fresh allocation map each time."
  (loop repeat 16 do
    (handler-case
        (return-from foreign-gateway-port-for
          (foreign-gateway-reserve-port-once leases gateway-key public-port))
      (gr8s.kube-client:kube-error (condition)
        (unless (= 409 (gr8s.kube-client:kube-error-status condition))
          (error condition)))))
  (error "Gateway port allocation repeatedly conflicted on node ~A"
         (foreign-gateway-port-leases-node-name leases)))
