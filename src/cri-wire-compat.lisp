;;;; SPDX-FileCopyrightText: 2026 gr8s contributors
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Accept both legal protobuf encodings of CRI supplemental groups. The pinned
;;;; ag-proto generator emits only unpacked numeric-field decoders; containerd
;;;; sends packed groups in LinuxContainerUser responses, including group zero.
;;;; Keep this compatibility method outside regenerated bindings.

(in-package #:gr8s)

(defmethod ag-proto:deserialize-from-bytes
    ((type (eql 'gr8s.cri.v1::linux-container-user)) data)
  "Decode CRI Linux identities, accepting packed, unpacked and mixed group fields."
  (declare (ignore type))
  (let ((object (make-instance 'gr8s.cri.v1::linux-container-user))
        (buffer (cons data 0)) (groups nil))
    (labels ((signed-value (source)
               (let ((value (ag-proto::read-varint source)))
                 (if (>= value (ash 1 63)) (- value (ash 1 64)) value))))
      (loop while (< (cdr buffer) (length data))
            for tag = (ag-proto::read-varint buffer)
            for field = (ash tag -3)
            for wire = (logand tag 7)
            do (case field
                 ((1 2)
                  (unless (zerop wire) (error "Invalid CRI user identity wire type"))
                  (setf (slot-value object (if (= field 1) 'gr8s.cri.v1::uid 'gr8s.cri.v1::gid))
                        (signed-value buffer)))
                 (3
                  (case wire
                    (0 (push (signed-value buffer) groups))
                    (2 (let* ((packed (ag-proto::read-length-delimited buffer))
                              (source (cons packed 0)))
                         (loop while (< (cdr source) (length packed))
                               do (push (signed-value source) groups))))
                    (otherwise (error "Invalid CRI supplemental groups wire type"))))
                 (otherwise (ag-proto::skip-field buffer wire)))))
    (setf (gr8s.cri.v1::supplemental-groups object) (nreverse groups))
    object))
