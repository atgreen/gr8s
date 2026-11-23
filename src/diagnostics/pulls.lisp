;;;; SPDX-License-Identifier: MIT
(in-package #:gr8s-diagnose)

;;; The facts behind rules/pulls.pl: which containers wait for an image that
;;; would not pull, and the errors the kubelet reported for them.

(defparameter +pull-waiting-reasons+ '("ImagePullBackOff" "ErrImagePull"))

(defun pull-waiting-containers (pod)
  "(NAME . MESSAGE) for each of POD's containers that waits on a failed pull,
MESSAGE NIL when the kubelet gave none."
  (loop for section in '("initContainerStatuses" "containerStatuses")
        append (loop for status across (or (field pod "status" section) #())
                     for waiting = (field status "state" "waiting")
                     when (member (field waiting "reason") +pull-waiting-reasons+ :test #'equal)
                       collect (cons (field status "name")
                                     (let ((message (field waiting "message")))
                                       (and (stringp message) (plusp (length message)) message))))))

(defun pull-event-container (event)
  "The container a pull-failure EVENT is about, from its fieldPath, or NIL."
  (let ((path (field event "involvedObject" "fieldPath"))
        (message (field event "message")))
    (when (and (equal "Failed" (field event "reason"))
               (stringp message) (uiop:string-prefix-p "Failed to pull image" message)
               (stringp path))
      (let ((open (position #\{ path)) (close (position #\} path :from-end t)))
        (and open close (< open close) (subseq path (1+ open) close))))))

(defun pull-findings (pod events evidence-id)
  "Findings that name why POD's images would not pull, from its waiting
containers' messages and its EVENTS."
  (let* ((waiting (pull-waiting-containers pod))
         (facts (append
                 (loop for (container . message) in waiting
                       collect (list 'pull_container container)
                       when message collect (list 'pull_failed container message))
                 (loop for event in events
                       for container = (pull-event-container event)
                       when (and container (assoc container waiting :test #'equal))
                         collect (list 'pull_failed container (field event "message"))))))
    (loop for (code container details)
            in (prove facts '((pull_finding ?code ?container ?details)) '(?code ?container ?details))
          for (summary step) = (first (known `(pull_explanation ,code ?summary ?step) '(?summary ?step)))
          for error = (first (prove facts `((pull_failed ,container ?error) (pull_cause ,code ?error ?details))
                                    '?error))
          collect (object "code" code "rule" code "severity" (catalog-severity "waiting-ImagePullBackOff")
                          "container" container
                          "summary" (apply #'format nil summary (field pod "metadata" "name") container details)
                          "detailHeading" "The kubelet reported:" "detail" error
                          "nextStep" step "evidence" (vector evidence-id)))))
