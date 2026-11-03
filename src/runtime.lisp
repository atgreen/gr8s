(in-package #:gr8s)

(defparameter +gr8s-managed-label+ "io.gr8s.managed")
(defparameter +gr8s-uid-label+ "io.gr8s.uid")
(defparameter +gr8s-resource-version-label+ "io.gr8s.resource-version")
(defparameter +gr8s-container-label+ "io.gr8s.container")

(define-condition runtime-error (error)
  ((message :initarg :message :reader runtime-error-message))
  (:report (lambda (condition stream)
             (write-string (runtime-error-message condition) stream))))

(defstruct runtime-pod
  uid
  resource-version
  (phase "Running")
  (pod-ip "")
  status
  (logs (make-hash-table :test #'equal)))

(defgeneric runtime-network-metrics (runtime))
(defmethod runtime-network-metrics ((runtime t)) (declare (ignore runtime)) "")

(defgeneric runtime-observe (runtime uid))
(defgeneric runtime-ensure (runtime pod))
(defgeneric runtime-delete (runtime uid))
(defgeneric runtime-logs (runtime uid container &key tail))
(defgeneric runtime-exec-url
    (runtime uid container command &key stdin stdout stderr tty))
(defgeneric runtime-exec-sync
    (runtime uid container command &key timeout))
(defgeneric runtime-start-exec-session
    (runtime uid container command &key stdin stdout stderr tty))
(defgeneric runtime-send-exec-session-input
    (runtime session channel data &key rows columns eof))
(defgeneric runtime-next-exec-session-output
    (runtime session cursor &key timeout))
(defgeneric runtime-exec-session-exit-code (runtime session))
(defgeneric runtime-cancel-exec-session (runtime session reason))
(defgeneric runtime-release-exec-session (runtime session))

(defstruct runtime-exec-result
  (stdout (make-array 0 :element-type '(unsigned-byte 8)))
  (stderr (make-array 0 :element-type '(unsigned-byte 8)))
  (exit-code 0))

(defmethod runtime-exec-url
    ((runtime t) uid container command &key stdin stdout stderr tty)
  (declare (ignore runtime uid container command stdin stdout stderr tty))
  (error 'runtime-error :message "This runtime does not support Pod exec"))

(defmethod runtime-exec-sync
    ((runtime t) uid container command &key timeout)
  (declare (ignore runtime uid container command timeout))
  (error 'runtime-error :message "This runtime does not support synchronous Pod exec"))

(defmethod runtime-start-exec-session
    ((runtime t) uid container command &key stdin stdout stderr tty)
  (declare (ignore runtime uid container command stdin stdout stderr tty))
  (error 'runtime-error :message "This runtime does not support interactive Pod exec"))

(defstruct (fake-runtime (:constructor make-fake-runtime ()))
  (pods (make-hash-table :test #'equal))
  (ensure-count 0)
  exec-url
  exec-result
  last-exec
  failure)

(defun set-fake-runtime-failure (runtime message)
  (setf (fake-runtime-failure runtime) message))

(defun set-fake-runtime-exec-url (runtime url)
  (setf (fake-runtime-exec-url runtime) url))

(defun set-fake-runtime-exec-result (runtime result)
  (setf (fake-runtime-exec-result runtime) result))

(defun fail-if-requested (runtime)
  (when (fake-runtime-failure runtime)
    (let ((message (fake-runtime-failure runtime)))
      (setf (fake-runtime-failure runtime) nil)
      (error 'runtime-error :message message))))

(defmethod runtime-observe ((runtime fake-runtime) uid)
  (gethash uid (fake-runtime-pods runtime)))

(defmethod runtime-ensure ((runtime fake-runtime) pod)
  (fail-if-requested runtime)
  (incf (fake-runtime-ensure-count runtime))
  (let ((runtime-pod
          (make-runtime-pod :uid (pod-uid pod)
                            :resource-version (pod-resource-version pod))))
    (setf (gethash (pod-uid pod) (fake-runtime-pods runtime)) runtime-pod)
    runtime-pod))

(defmethod runtime-delete ((runtime fake-runtime) uid)
  (fail-if-requested runtime)
  (remhash uid (fake-runtime-pods runtime)))

(defmethod runtime-logs ((runtime fake-runtime) uid container &key tail)
  (declare (ignore tail))
  (fail-if-requested runtime)
  (let ((pod (runtime-observe runtime uid)))
    (and pod (gethash container (runtime-pod-logs pod) ""))))

(defmethod runtime-exec-url
    ((runtime fake-runtime) uid container command
     &key stdin stdout stderr tty)
  (setf (fake-runtime-last-exec runtime)
        (list uid container command stdin stdout stderr tty))
  (or (fake-runtime-exec-url runtime)
      (call-next-method)))

(defmethod runtime-exec-sync
    ((runtime fake-runtime) uid container command &key timeout)
  (setf (fake-runtime-last-exec runtime)
        (list uid container command :sync timeout))
  (or (fake-runtime-exec-result runtime)
      (call-next-method)))
