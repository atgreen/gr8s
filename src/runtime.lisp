(in-package #:gr8s)

(defparameter +gr8s-managed-label+ "io.gr8s.managed")
(defparameter +gr8s-uid-label+ "io.gr8s.uid")
(defparameter +gr8s-resource-version-label+ "io.gr8s.resource-version")
(defparameter +gr8s-container-label+ "io.gr8s.container")
(defparameter +gr8s-spec-fingerprint-label+ "io.gr8s.spec-fingerprint")
(defparameter +gr8s-host-network-label+ "io.gr8s.host-network")

(define-condition runtime-error (error)
  ((message :initarg :message :reader runtime-error-message))
  (:report (lambda (condition stream)
             (write-string (runtime-error-message condition) stream))))

(defstruct runtime-pod
  uid
  resource-version
  spec-fingerprint
  (phase "Running")
  (pod-ip "")
  status
  container-details
  (logs (make-hash-table :test #'equal)))

(defun canonical-workload-json (object)
  "Encode a JSON value with sorted object keys and preserved array ordering."
  (with-output-to-string (out)
    (labels ((emit (value)
               (cond
                 ((hash-table-p value)
                  (write-char #\{ out)
                  (loop for key in (sort (loop for key being the hash-keys of value collect key) #'string<)
                        for first = t then nil
                        do (unless first (write-char #\, out))
                           (write-string (com.inuoe.jzon:stringify key) out) (write-char #\: out)
                           (emit (gethash key value)))
                  (write-char #\} out))
                 ((and (vectorp value) (not (stringp value)))
                  (write-char #\[ out)
                  (loop for item across value for first = t then nil
                        do (unless first (write-char #\, out)) (emit item))
                  (write-char #\] out))
                 (t (write-string (com.inuoe.jzon:stringify value) out)))))
      (emit object))))

(defun pod-runtime-spec-fingerprint (pod)
  "Identify container-affecting Pod spec content independently of metadata revisions."
  (let ((spec (com.inuoe.jzon:parse (com.inuoe.jzon:stringify
                                   (gethash "spec" (pod-to-object pod))))))
    ;; Grace affects shutdown, never the running workload. Excluding the new
    ;; default also preserves adoption of containers created by older gr8s.
    (remhash "terminationGracePeriodSeconds" spec)
    ;; A lowered active deadline changes when the Pod stops, never what runs.
    (remhash "activeDeadlineSeconds" spec)
    (octets-to-hex (ironclad:digest-sequence :sha256
                  (trivial-utf-8:string-to-utf-8-bytes
                   (canonical-workload-json spec))))))

(defgeneric runtime-runs-containers-p (runtime)
  (:documentation "Return whether RUNTIME itself stops containers, rather than delegating to a node.")
  (:method (runtime) (declare (ignore runtime)) t))

(defgeneric runtime-ephemeral-usage (runtime pod)
  (:documentation "Return POD's writable-layer bytes as (container . bytes) entries and its emptyDir bytes, or NIL when unmeasurable.")
  (:method (runtime pod) (declare (ignore runtime pod)) nil))

(defgeneric runtime-events (runtime uid)
  (:documentation "Return actual runtime event occurrences for the assigned Pod transport."))
(defmethod runtime-events ((runtime t) uid) (declare (ignore runtime uid)) nil)

(defgeneric runtime-network-metrics (runtime))
(defmethod runtime-network-metrics ((runtime t)) (declare (ignore runtime)) "")

(defgeneric runtime-observe (runtime uid))
(defgeneric runtime-ensure (runtime pod))
(defgeneric runtime-reconcile-containers (runtime pod observed)
  (:documentation "Advance container lifecycle in POD, preserving healthy siblings in native runtimes."))
(defmethod runtime-reconcile-containers ((runtime t) pod observed)
  "Provide whole-Pod restart fallback for simple runtime adapters."
  (let ((policy (pod-restart-policy pod)) (phase (runtime-pod-phase observed)))
    (if (or (and (equal policy "Always") (not (equal phase "Running")))
            (and (equal policy "OnFailure") (equal phase "Failed")))
        (runtime-ensure runtime pod)
        observed)))
(defgeneric runtime-delete (runtime uid))
(defgeneric runtime-delete-pod (runtime pod)
  (:documentation "Advance durable Pod shutdown; return true only when deletion is complete."))
(defmethod runtime-delete-pod ((runtime t) pod)
  (runtime-delete runtime (pod-uid pod))
  t)
(defgeneric runtime-forget-pod-finalization (runtime uid)
  (:documentation "Forget retained native terminal history after finalizers release an API Pod."))
(defmethod runtime-forget-pod-finalization ((runtime t) uid)
  (declare (ignore runtime uid)) nil)

(defgeneric stop-runtime-deletions (runtime)
  (:documentation "Cancel and join background deletion operations before runtime services stop."))
(defmethod stop-runtime-deletions ((runtime t)) nil)
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
                            :resource-version (pod-resource-version pod)
                            :spec-fingerprint (pod-runtime-spec-fingerprint pod))))
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
