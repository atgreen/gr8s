;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
(in-package #:gr8s.store)

(defvar *store-request-lease* nil
  "The store whose routed request may finish while new access is blocked.")

(defun store-access-unavailable (message)
  (error 'kubernetes-error :status-code 503 :reason "ServiceUnavailable" :message message))

(defun ensure-store-available (store)
  "Called under the raw store lock. Existing request leases may finish draining."
  (when (and (pod-store-access-blocked store)
             (not (and (eq :draining (pod-store-access-blocked store))
                       (eq store *store-request-lease*))))
    (store-access-unavailable "Application restore is blocking store access")))

(defun call-with-store-request (store function)
  "Lease application access across a routed request, including nested routing.
Unwinding the request releases its lease even when a handler signals an error."
  (if (eq store *store-request-lease*) (funcall function)
      (let ((entered nil))
        (unwind-protect
             (progn
               (bt:with-lock-held ((pod-store-lock store))
                 (when (pod-store-access-blocked store)
                   (store-access-unavailable "Application restore is blocking new requests"))
                 (sb-sys:without-interrupts
                   (incf (pod-store-active-requests store))
                   (setf entered t)))
               (let ((*store-request-lease* store)) (funcall function)))
          (when entered
            (bt:with-lock-held ((pod-store-lock store))
              (sb-sys:without-interrupts
                (decf (pod-store-active-requests store))
                (when (zerop (pod-store-active-requests store))
                  (bt:condition-notify (pod-store-access-condition store))))))))))

(defun quiesce-store-access (store &key (timeout 30))
  "Reject new access and drain routed requests before a caller attempts live reload.
This does NOT acquire the consensus/member locks or stop non-HTTP ingress.
Timeout or failure before draining reopens access; no application data is changed."
  (unless (typep timeout '(real 0 *)) (error "Invalid application quiescence timeout"))
  (when (eq store *store-request-lease*)
    (store-access-unavailable "Cannot quiesce application access from its own routed request"))
  (let ((deadline (+ (get-internal-real-time) (* timeout internal-time-units-per-second)))
        (drained nil) (blocked nil))
    (unwind-protect
         (bt:with-lock-held ((pod-store-lock store))
           (when (pod-store-access-blocked store)
             (store-access-unavailable "Application access is already blocked"))
           (setf (pod-store-access-blocked store) :draining blocked t)
           (loop while (plusp (pod-store-active-requests store)) do
             (let ((remaining (/ (- deadline (get-internal-real-time)) internal-time-units-per-second)))
               (unless (plusp remaining)
                 (store-access-unavailable "Timed out draining active API requests before application restore"))
               (bt:condition-wait (pod-store-access-condition store) (pod-store-lock store)
                                  :timeout (float remaining 1d0))))
           (setf (pod-store-access-blocked store) :blocked drained t)
           store)
      (when (and blocked (not drained))
        (bt:with-lock-held ((pod-store-lock store))
          (setf (pod-store-access-blocked store) nil))))))

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
    (setf (pod-store-access-blocked store) nil))
  store)

(defun store-access-blocked-p (store)
  (bt:with-lock-held ((pod-store-lock store))
    (not (null (pod-store-access-blocked store)))))
