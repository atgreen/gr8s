(in-package #:gr8s)

(defun cni-policy-map-path (map-path name)
  (if (string= name "rejected_spoofs") map-path
      (namestring (merge-pathnames name (uiop:pathname-directory-pathname map-path)))))

(defun bpf-object-kernel-info (fd)
  ;; BPF_OBJ_GET_INFO_BY_FD. Validate pinned map sizes before passing buffers to
  ;; map-lookup/update: the kernel copies its actual value_size, not ours.
  (let ((attribute (whistler/loader::make-attr-buf))
        (info (make-array 256 :element-type '(unsigned-byte 8) :initial-element 0)))
    (whistler/loader::put-u32 attribute 0 fd)
    (whistler/loader::put-u32 attribute 4 (length info))
    (sb-sys:with-pinned-objects (info)
      (whistler/loader::put-ptr attribute 8 (sb-sys:vector-sap info))
      (whistler/loader::%bpf 15 attribute 16 "gr8s object-info"))
    info))

(defun cni-policy-map-info (fd name &key (object-info #'bpf-object-kernel-info))
  (let* ((spec (assoc name +cni-policy-map-specs+ :test #'string=))
         (info (funcall object-info fd)))
    (unless (and spec (>= (length info) 24)
                 (= 2 (netlink-read-integer info 0 4)) ; ARRAY
                 (= 4 (netlink-read-integer info 8 4))
                 (= (second spec) (netlink-read-integer info 12 4))
                 (= (third spec) (netlink-read-integer info 16 4))
                 (= (fourth spec) (netlink-read-integer info 20 4)))
      (invalid-cni "pinned Whistler map ~A has an incompatible schema" name))
    (whistler/loader::make-map-info
     :name name :type 2 :key-size 4 :value-size (second spec)
     :max-entries (third spec) :flags (fourth spec) :fd fd)))

(defun encode-cni-endpoint-identity (address mac)
  (unless (and mac (= 6 (length mac)))
    (invalid-cni "the Pod interface has no Ethernet identity"))
  (netlink-octets
   (netlink-integer (parse-ipv4-integer address) 4)
   (netlink-integer (loop for index below 4 sum (ash (aref mac index) (- 24 (* index 8)))) 4)
   (netlink-integer (+ (ash (aref mac 4) 8) (aref mac 5)) 4)
   (netlink-integer 1 4)))

(defun cni-endpoint-identity (configuration context)
  (let ((address (cni-configuration-endpoint-address configuration)))
    (unless address (invalid-cni "the agent has not assigned an endpoint address"))
    (encode-cni-endpoint-identity
     address
     (call-with-cni-network-namespace
      (cni-context-netns context)
      (lambda () (gethash 1 (network-link-attributes (cni-context-interface-name context))))))))

(defun initialize-cni-identity (map configuration context)
  (whistler/loader:map-update map (netlink-integer 0 4)
                              (cni-endpoint-identity configuration context)))

(defun check-cni-identity (map configuration context)
  (unless (equalp (whistler/loader:map-lookup map (netlink-integer 0 4))
                  (cni-endpoint-identity configuration context))
    (invalid-cni "Whistler endpoint identity does not match agent IPAM and the Pod link")))

(defun check-cni-tcx-link (fd index direction &key (object-info #'bpf-object-kernel-info))
  (let ((info (funcall object-info fd)))
    (unless (and (>= (length info) 24)
                 (= 11 (netlink-read-integer info 0 4)) ; TCX
                 (= index (netlink-read-integer info 16 4))
                 (= (if (string= direction "egress") 47 46)
                    (netlink-read-integer info 20 4)))
      (invalid-cni "pinned TCX link does not enforce the selected Pod interface"))))

(defun cni-policy-staged-links (link-path)
  (directory (concatenate 'string link-path "_pending_*")))

(defun read-cni-policy-counters (root sandbox-id)
  (multiple-value-bind (map-path link-path directory) (cni-pin-paths root sandbox-id)
    (declare (ignore link-path directory))
    (let ((result (make-hash-table :test #'equal)))
      (dolist (name '("rejected_spoofs" "traffic_stats"))
        (let* ((path (cni-policy-map-path map-path name))
               (fd (whistler/loader:open-pinned-object path)))
          (unwind-protect
               (let ((map (cni-policy-map-info fd name)))
                 (if (string= name "rejected_spoofs")
                     (setf (gethash "rejectedSpoofs" result) (whistler/loader:map-lookup-int map 0))
                     (loop for key in '("allowedPackets" "allowedBytes" "droppedPackets"
                                        "droppedBytes" "malformedPackets" "unsupportedPackets")
                           for index from 0
                           do (setf (gethash key result)
                                    (whistler/loader:map-lookup-int map index)))))
            (sb-posix:close fd))))
      result)))
