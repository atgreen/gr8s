(in-package #:gr8s)

(defconstant +node-protocol-version+ 1)

(define-condition unsupported-node-protocol-version (error)
  ((received
    :initarg :received
    :reader unsupported-node-protocol-version-received)
   (supported
    :initarg :supported
    :reader unsupported-node-protocol-version-supported))
  (:report
   (lambda (condition stream)
     (format stream "Unsupported gr8s node protocol version ~D (supported: ~D)"
             (unsupported-node-protocol-version-received condition)
             (unsupported-node-protocol-version-supported condition)))))

(defun ensure-node-protocol-version (version)
  (unless (= version +node-protocol-version+)
    (error 'unsupported-node-protocol-version
           :received version
           :supported +node-protocol-version+))
  version)

(defparameter +agent-envelope-variants+
  '((:hello . gr8s.node.v1::node-hello)
    (:heartbeat . gr8s.node.v1::heartbeat)
    (:snapshot-ack . gr8s.node.v1::snapshot-ack)
    (:status . gr8s.node.v1::node-status)
    (:operation-response . gr8s.node.v1::operation-response)
    (:operation-stream . gr8s.node.v1::operation-stream)))

(defparameter +server-envelope-variants+
  '((:hello . gr8s.node.v1::server-hello)
    (:desired-state . gr8s.node.v1::desired-state-snapshot)
    (:operation-request . gr8s.node.v1::operation-request)
    (:operation-input . gr8s.node.v1::operation-input)
    (:operation-cancel . gr8s.node.v1::operation-cancel)
    (:protocol-error . gr8s.node.v1::protocol-error)))

(defun make-node-envelope (class variants variant payload sequence protocol-version)
  (ensure-node-protocol-version protocol-version)
  (let ((payload-type (cdr (assoc variant variants))))
    (unless payload-type
      (error "Unknown ~A payload variant ~S" class variant))
    (unless (typep payload payload-type)
      (error "Payload for ~S must be a ~S, not ~S"
             variant payload-type (type-of payload)))
    (let ((envelope
            (apply #'make-instance class
                   :protocol-version protocol-version
                   :sequence sequence
                   (list variant payload))))
      (setf (slot-value envelope 'gr8s.node.v1::payload-case) variant)
      envelope)))

(defun make-agent-envelope (variant payload
                            &key
                              (sequence 0)
                              (protocol-version +node-protocol-version+))
  (make-node-envelope 'gr8s.node.v1::agent-envelope
                      +agent-envelope-variants+
                      variant payload sequence protocol-version))

(defun make-server-envelope (variant payload
                             &key
                               (sequence 0)
                               (protocol-version +node-protocol-version+))
  (make-node-envelope 'gr8s.node.v1::server-envelope
                      +server-envelope-variants+
                      variant payload sequence protocol-version))
