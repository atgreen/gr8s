;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Persist Kubernetes Pod deletion deadlines independently of runtime jobs.
;;;; Repeated deletes may shorten the original grace period, never restart it;
;;;; the same timestamp travels to agents and survives either side restarting.

(in-package #:gr8s)

(defparameter *pod-deletion-clock* #'get-universal-time)

(defun pod-deletion-time (timestamp)
  "Decode an internally generated UTC deletion TIMESTAMP into universal time."
  (unless (and (stringp timestamp) (= 20 (length timestamp))
               (every (lambda (pair) (char= (char timestamp (car pair)) (cdr pair)))
                      '((4 . #\-) (7 . #\-) (10 . #\T) (13 . #\:) (16 . #\:) (19 . #\Z))))
    (invalid-pod "metadata.deletionTimestamp must be a UTC timestamp"))
  (flet ((part (start end) (parse-integer timestamp :start start :end end)))
    (encode-universal-time (part 17 19) (part 14 16) (part 11 13)
                           (part 8 10) (part 5 7) (part 0 4) 0)))

(defun pod-deletion-deadline (pod)
  "Return POD's persisted absolute shutdown deadline, defaulting to now."
  (let ((timestamp (gethash "deletionTimestamp" (gethash "metadata" (pod-to-object pod)))))
    (if timestamp (pod-deletion-time timestamp) (funcall *pod-deletion-clock*))))

(defun pod-remaining-deletion-grace (pod)
  "Return nonnegative seconds remaining until POD's persisted shutdown deadline."
  (max 0 (- (pod-deletion-deadline pod) (funcall *pod-deletion-clock*))))

(defun prepare-pod-deletion (store pod requested supplied-p)
  "Update a private POD copy's deletion metadata under STORE's lock; report change."
  (when supplied-p
    (unless (and (integerp requested) (<= (- (expt 2 63)) requested (1- (expt 2 63))))
      (invalid-pod "DeleteOptions.gracePeriodSeconds must be an int64"))
    ;; Match the upstream deletion path's compatibility treatment of negatives.
    (when (minusp requested) (setf requested 1)))
  (let* ((metadata (gethash "metadata" (pod-to-object pod)))
         (timestamp (gethash "deletionTimestamp" metadata))
         (old-grace (gethash "deletionGracePeriodSeconds" metadata 0))
         (now (funcall *pod-deletion-clock*)))
    (when timestamp
      (unless (and supplied-p (< requested old-grace))
        (return-from prepare-pod-deletion nil))
      ;; Shortening is relative to the original deletion start, not this DELETE.
      (let ((deadline (+ (- (pod-deletion-time timestamp) old-grace) requested)))
        (when (< deadline now)
          (setf deadline now)
          (unless (zerop requested) (setf requested 1)))
        (setf (gethash "deletionTimestamp" metadata) (current-timestamp deadline)
              (gethash "deletionGracePeriodSeconds" metadata) requested))
      (return-from prepare-pod-deletion t))
    (let* ((status (gethash (pod-uid pod) (pod-store-pod-observed-statuses store)))
           (grace (if supplied-p requested
                      (gethash "terminationGracePeriodSeconds" (gethash "spec" (pod-to-object pod)) 30))))
      (when (or (not (pod-node-name pod))
                (member (and status (gethash "phase" status)) '("Succeeded" "Failed") :test #'equal))
        (setf grace 0))
      (setf (gethash "deletionTimestamp" metadata) (current-timestamp (+ now grace))
            (gethash "deletionGracePeriodSeconds" metadata) grace
            (gethash "generation" metadata) (1+ (gethash "generation" metadata 1))))
    t))
