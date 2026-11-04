(in-package #:gr8s)

(defparameter +podman-command-timeout-seconds+ 30)

(defun run-podman-program (argv)
  "Run a bounded Podman command and make deletion jobs able to cancel its process."
  (uiop:with-temporary-file (:pathname stdout)
    (uiop:with-temporary-file (:pathname stderr)
      (let ((process (uiop:launch-program
                      (append (list "timeout" "--signal=TERM" "--kill-after=2s"
                                    (format nil "~Ds" +podman-command-timeout-seconds+)) argv)
                      :output stdout :error-output stderr
                      :if-output-exists :supersede :if-error-output-exists :supersede)))
        (unwind-protect
             (progn
               (register-runtime-deletion-cancel
                (lambda () (when (uiop:process-alive-p process) (uiop:terminate-process process))))
               (let ((status (uiop:wait-process process)))
                 (values (uiop:read-file-string stdout) (uiop:read-file-string stderr) status)))
          (when (uiop:process-alive-p process)
            (uiop:terminate-process process)
            (uiop:wait-process process)))))))

(defstruct (podman-runtime (:constructor %make-podman-runtime))
  executable
  runner
  (deletions (make-deletion-controller)))

(defun make-podman-runtime (&key (executable "podman")
                                 (runner #'run-podman-program))
  (%make-podman-runtime :executable executable :runner runner))

(defun safe-runtime-name (value)
  (string-downcase
   (map 'string
        (lambda (character)
          (if (or (alphanumericp character) (char= character #\-))
              character
              #\-))
        value)))

(defun podman-pod-name (uid)
  (format nil "gr8s-~A" (safe-runtime-name uid)))

(defun podman-container-name (uid container)
  (format nil "~A-~A"
          (podman-pod-name uid)
          (safe-runtime-name container)))

(defun ownership-labels (pod)
  (list "--label" (format nil "~A=true" +gr8s-managed-label+)
        "--label" (format nil "~A=~A" +gr8s-uid-label+ (pod-uid pod))))

(defun pod-labels (pod)
  (append (ownership-labels pod)
          (list "--label"
                (format nil "~A=~A"
                        +gr8s-resource-version-label+
                        (pod-resource-version pod)))))

(defun container-options (pod container)
  (append
   (ownership-labels pod)
   (list "--label"
         (format nil "~A=~A"
                 +gr8s-container-label+ (container-spec-name container))
         "--restart"
         (cond
           ((string= "Always" (pod-restart-policy pod)) "always")
           ((string= "OnFailure" (pod-restart-policy pod)) "on-failure")
           (t "no")))
   (loop for (name . value) in (container-spec-env container)
         append (list "--env" (format nil "~A=~A" name value)))
   (loop for port in (container-spec-ports container)
         append (list "--expose" (write-to-string port)))))

(defun podman-container-create-command (executable pod container)
  (append
   (list executable "create"
         "--pod" (podman-pod-name (pod-uid pod))
         "--name" (podman-container-name
                    (pod-uid pod) (container-spec-name container)))
   (container-options pod container)
   (list (container-spec-image container))
   (coerce (container-spec-command container) 'list)
   (coerce (container-spec-args container) 'list)))

(defun podman-create-plan (pod &optional (executable "podman"))
  (let ((pod-name (podman-pod-name (pod-uid pod))))
    (append
     (list (append (list executable "pod" "create" "--name" pod-name)
                   (pod-labels pod)))
     (loop for container across (pod-containers pod)
           collect (podman-container-create-command executable pod container))
     (list (list executable "pod" "start" pod-name)))))

(defun podman-command (runtime argv)
  (multiple-value-bind (stdout stderr status)
      (funcall (podman-runtime-runner runtime) argv)
    (unless (eql 0 status)
      (error 'runtime-error
             :message
             (if (eql 124 status)
                 (format nil "Podman command timed out after ~D seconds"
                         +podman-command-timeout-seconds+)
                 (format nil "Podman command failed (~A): ~A"
                         status
                         (string-trim '(#\Space #\Tab #\Newline #\Return)
                                      (or stderr ""))))))
    (or stdout "")))

(defun podman-pod-records (runtime uid)
  (let* ((output
           (podman-command
            runtime
            (list (podman-runtime-executable runtime)
                  "pod" "ps" "--filter"
                  (format nil "label=~A=~A" +gr8s-uid-label+ uid)
                  "--format" "json")))
         (records (com.inuoe.jzon:parse output)))
    (unless (vectorp records)
      (error 'runtime-error :message "Podman returned a non-array pod listing"))
    records))

(defun owned-pod-record (runtime uid)
  (find-if
   (lambda (record)
     (let ((labels (gethash "Labels" record)))
       (and (hash-table-p labels)
            (string= "true" (gethash +gr8s-managed-label+ labels ""))
            (string= uid (gethash +gr8s-uid-label+ labels "")))))
   (podman-pod-records runtime uid)))

(defun podman-phase (status)
  (cond
    ((member status '("running" "paused") :test #'string-equal) "Running")
    ((string-equal status "exited") "Succeeded")
    ((string-equal status "degraded") "Failed")
    (t "Pending")))

(defmethod runtime-observe ((runtime podman-runtime) uid)
  (let ((record (owned-pod-record runtime uid)))
    (when record
      (make-runtime-pod
       :uid uid
       :resource-version
       (gethash +gr8s-resource-version-label+
                (gethash "Labels" record) "")
       :phase (podman-phase (gethash "Status" record ""))))))

(defmethod runtime-delete ((runtime podman-runtime) uid)
  (cancel-runtime-pod-deletion (podman-runtime-deletions runtime) uid)
  (let ((record (owned-pod-record runtime uid)))
    (when record
      (podman-command
       runtime
       (list (podman-runtime-executable runtime)
             "pod" "rm" "--force" (gethash "Id" record)))))
  nil)

(defmethod runtime-terminate-pod ((runtime podman-runtime) pod deadline)
  "Ask Podman to stop all containers with the remaining grace before removal."
  (let ((record (owned-pod-record runtime (pod-uid pod)))
        (remaining (max 0 (- deadline (funcall *pod-deletion-clock*)))))
    (when record
      (let ((+podman-command-timeout-seconds+ (+ remaining 30)))
        (podman-command runtime (list (podman-runtime-executable runtime) "pod" "stop"
                                     "--time" (write-to-string remaining) (gethash "Id" record))))
      (podman-command runtime (list (podman-runtime-executable runtime) "pod" "rm"
                                   "--force" (gethash "Id" record))))))

(defmethod runtime-delete-pod ((runtime podman-runtime) pod)
  "Poll Podman shutdown without blocking API or snapshot processing."
  (poll-runtime-pod-deletion (podman-runtime-deletions runtime) runtime pod))

(defmethod stop-runtime-deletions ((runtime podman-runtime))
  "Cancel and join owned Podman deletion commands."
  (stop-runtime-deletion-controller (podman-runtime-deletions runtime)))

(defmethod runtime-ensure ((runtime podman-runtime) pod)
  (runtime-delete runtime (pod-uid pod))
  (handler-case
      (progn
        (dolist (command (podman-create-plan
                          pod (podman-runtime-executable runtime)))
          (podman-command runtime command))
        (or (runtime-observe runtime (pod-uid pod))
            (error 'runtime-error
                   :message "Podman did not report the newly created pod")))
    (runtime-error (error)
      (ignore-errors (runtime-delete runtime (pod-uid pod)))
      (error error))))

(defmethod runtime-logs ((runtime podman-runtime) uid container &key tail)
  (unless (owned-pod-record runtime uid)
    (error 'runtime-error :message (format nil "Pod ~A is not owned by gr8s" uid)))
  (podman-command
   runtime
   (append
    (list (podman-runtime-executable runtime) "logs")
    (when tail (list "--tail" (write-to-string tail)))
    (list (podman-container-name uid container)))))
