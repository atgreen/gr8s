;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
(in-package #:gr8s.store)

(defvar *store-request-lease* nil
  "The store whose routed request may finish while new access is blocked.")

(defvar *store-request-release* nil
  "Inside a routed request, a function that gives its lease up early; NIL elsewhere.")

(defvar *store-request-description* nil
  "What the current routed request is, for drain diagnostics: the API layer
binds it (method and path) before taking the request lease (podster-urj).")

(defun store-access-unavailable (message)
  (error 'kubernetes-error :status-code 503 :reason "ServiceUnavailable" :message message))

(defun ensure-store-available (store)
  "Called under the raw store lock. Existing request leases may finish draining."
  (when (and (pod-store-access-blocked store)
             (not (and (eq :draining (pod-store-access-blocked store))
                       (eq store *store-request-lease*))))
    (store-access-unavailable "Application restore is blocking store access")))

(defparameter *store-quiesce-patience-seconds* 20
  "How long a new request waits for a checkpoint's quiesce to end before it is
told to come back.")

(defun await-brief-store-quiesce-unlocked (store)
  "Wait, under the store lock, while a checkpoint has the store quiesced. A
checkpoint closes the store for well under a second as a rule; a request that
arrives then is held rather than failed, because a client such as Helm does not
retry a 503 and the user re-runs the whole apply (podster-j76). Past
*STORE-QUIESCE-PATIENCE-SECONDS* the request is refused with 429, which clients
do retry. A store closed for a restore is not waited on: that stays a 503."
  (loop with deadline = (+ (get-internal-real-time)
                           (* *store-quiesce-patience-seconds* internal-time-units-per-second))
        while (and (pod-store-access-blocked store) (pod-store-access-block-brief-p store))
        do (let ((remaining (/ (- deadline (get-internal-real-time)) internal-time-units-per-second)))
             (unless (plusp remaining)
               (error 'kubernetes-error :status-code 429 :reason "TooManyRequests"
                                        :message "A checkpoint is holding the application store; retry shortly"))
             (bt:condition-wait (pod-store-access-reopened store) (pod-store-lock store)
                                :timeout (min 1d0 (float remaining 1d0))))))

(defun end-brief-store-quiesce (store)
  "Stop treating the current block as a checkpoint's: what holds the store
closed from here on is a restore, and requests waiting on it must fail closed."
  (bt:with-lock-held ((pod-store-lock store))
    (setf (pod-store-access-block-brief-p store) nil)
    (sb-thread:condition-broadcast (pod-store-access-reopened store))))

(defun call-with-store-request (store function)
  "Lease application access across a routed request, including nested routing.
Unwinding the request releases its lease even when a handler signals an error."
  (if (eq store *store-request-lease*) (funcall function)
      (let ((entered nil))
        (unwind-protect
             (progn
               (bt:with-lock-held ((pod-store-lock store))
                 (await-brief-store-quiesce-unlocked store)
                 (when (pod-store-access-blocked store)
                   (store-access-unavailable "Application restore is blocking new requests"))
                 (sb-sys:without-interrupts
                   (incf (pod-store-active-requests store))
                   (setf (gethash (bt:current-thread) (pod-store-active-request-registry store))
                         (cons *store-request-description* (get-universal-time))
                         entered t)))
               (flet ((release ()
                        (when entered
                          (bt:with-lock-held ((pod-store-lock store))
                            (sb-sys:without-interrupts
                              (setf entered nil)
                              (decf (pod-store-active-requests store))
                              (remhash (bt:current-thread) (pod-store-active-request-registry store))
                              (when (zerop (pod-store-active-requests store))
                                (bt:condition-notify (pod-store-access-condition store))))))))
                 (unwind-protect
                      (let ((*store-request-lease* store)
                            (*store-request-release*
                              (lambda ()
                                (release)
                                ;; No longer one of the requests a drain lets finish.
                                (setf *store-request-lease* nil))))
                        (funcall function))
                   (release))))
          ;; Entered but unwound before the inner cleanup form was established.
          (when entered
            (bt:with-lock-held ((pod-store-lock store))
              (sb-sys:without-interrupts
                (setf entered nil)
                (decf (pod-store-active-requests store))
                (remhash (bt:current-thread) (pod-store-active-request-registry store))
                (when (zerop (pod-store-active-requests store))
                  (bt:condition-notify (pod-store-access-condition store))))))))))

(defun release-store-request ()
  "Give up the current routed request's lease now, before the handler returns.
For a request that stays open for as long as its client likes -- a followed
log, an exec session, a port-forward -- once it has read what it needs: a
checkpoint drains every lease before it can proceed, so one such request held
the store closed for the full drain limit on every attempt, and with it the
whole API (podster-cwj). What the handler reads from the store afterwards it
reads like any unleased caller: refused while the store is closed. A no-op
outside a routed request or when already released."
  (when *store-request-release*
    (funcall *store-request-release*)
    t))

(defun describe-active-store-requests-unlocked (store)
  "The leased requests as \"what (age)\" strings, oldest first; caller holds the
store lock. What a failed drain names (podster-urj)."
  (let ((now (get-universal-time)) (rows nil))
    (maphash (lambda (thread entry)
               (push (list (or (car entry) (bt:thread-name thread) "unnamed request")
                           (- now (cdr entry)))
                     rows))
             (pod-store-active-request-registry store))
    (mapcar (lambda (row) (format nil "~A (~Ds)" (first row) (second row)))
            (sort rows #'> :key #'second))))

(defun quiesce-store-access (store &key (timeout 30) brief)
  "Reject new access and drain routed requests before a caller attempts live reload.
BRIEF marks a checkpoint's quiesce, which reopens in a moment: new requests wait
for it instead of being refused.
This does NOT acquire the consensus/member locks or stop non-HTTP ingress.
Timeout or failure before draining reopens access; no application data is changed."
  (unless (typep timeout '(real 0 *)) (error "Invalid application quiescence timeout"))
  (when (eq store *store-request-lease*)
    (store-access-unavailable "Cannot quiesce application access from its own routed request"))
  ;; Log the onset so a block with no matching "resumed" line is diagnosable (podster-7l9).
  (format *error-output* "~&gr8s: blocking application store access for restore/checkpoint (drain <= ~Ds).~%"
          (round timeout))
  (let ((deadline (+ (get-internal-real-time) (* timeout internal-time-units-per-second)))
        (slow (+ (get-internal-real-time) (* 5 internal-time-units-per-second)))
        (drained nil) (blocked nil))
    (unwind-protect
         (bt:with-lock-held ((pod-store-lock store))
           (when (pod-store-access-blocked store)
             (store-access-unavailable "Application access is already blocked"))
           (setf (pod-store-access-blocked store) :draining blocked t
                 (pod-store-access-block-brief-p store) (and brief t))
           (loop while (plusp (pod-store-active-requests store)) do
             (let ((remaining (/ (- deadline (get-internal-real-time)) internal-time-units-per-second)))
               (unless (plusp remaining)
                 ;; Name the holders: a drain that cannot finish is otherwise
                 ;; undiagnosable from outside (podster-urj).
                 (format *error-output*
                         "~&gr8s: application drain timed out after ~Ds; ~D request~:P still active:~{ ~A~^;~}~%"
                         (round timeout) (pod-store-active-requests store)
                         (describe-active-store-requests-unlocked store))
                 (store-access-unavailable "Timed out draining active API requests before application restore"))
               ;; A drain this slow closes the API for as long: say once who it waits on.
               (when (and slow (> (get-internal-real-time) slow))
                 (setf slow nil)
                 (format *error-output*
                         "~&gr8s: application drain still waiting after 5s; ~D request~:P active:~{ ~A~^;~}~%"
                         (pod-store-active-requests store)
                         (describe-active-store-requests-unlocked store)))
               (bt:condition-wait (pod-store-access-condition store) (pod-store-lock store)
                                  :timeout (min 1d0 (float remaining 1d0)))))
           (setf (pod-store-access-blocked store) :blocked drained t)
           store)
      (when (and blocked (not drained))
        (bt:with-lock-held ((pod-store-lock store))
          (setf (pod-store-access-blocked store) nil
                (pod-store-access-block-brief-p store) nil)
          (sb-thread:condition-broadcast (pod-store-access-reopened store)))))))

(defun resume-store-access (store)
  "Caller has completed live reload/recovery; never reopen over a pending intent."
  (bt:with-lock-held ((pod-store-lock store))
    (when (eq :draining (pod-store-access-blocked store))
      (store-access-unavailable "Application requests are still draining"))
    (unless (pod-store-application-loaded-p store)
      (store-access-unavailable "Application reload has not completed successfully"))
    (when (read-store-restore-intent (pod-store-path store))
      (store-access-unavailable "Application restore intent is still pending"))
    (unless (equal (store-data-path store)
                   (or (selected-store-generation-root (pod-store-path store)) (pod-store-path store)))
      (store-access-unavailable "Store indexes still belong to another application generation"))
    (setf (pod-store-access-blocked store) nil
          (pod-store-access-block-brief-p store) nil)
    (sb-thread:condition-broadcast (pod-store-access-reopened store)))
  (format *error-output* "~&gr8s: application store access resumed.~%")
  store)

(defun store-access-blocked-p (store)
  (bt:with-lock-held ((pod-store-lock store))
    (not (null (pod-store-access-blocked store)))))
