;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; gr8s versions, as `gr8s version' prints them: a release is the Kubernetes API
;;;; version with a gr8s suffix, v1.37.2-gr8s.7; any other build carries its commit,
;;;; v1.37.2-g1a2b3c4, and may say +dirty. Releases order by their numbers; a build
;;;; between releases has no place in that order.

(in-package #:gr8s.upgrade)

(defparameter +gr8s-format-level+ 1
  "The newest store and Raft log format this release can read and, once the cluster
is finalized at it, write. A release that changes a format raises it, and writes the
new format only when the cluster's format level -- which `gr8s upgrade finalize'
raises once every voter runs a release that reads it -- has come up to it.")

(defun cluster-format-level-allows-p (cluster-level level)
  "Whether a cluster at CLUSTER-LEVEL may be written in the format of LEVEL."
  (<= level cluster-level))

(define-condition upgrade-error (error)
  ((message :initarg :message :reader upgrade-error-message))
  (:report (lambda (condition stream) (write-string (upgrade-error-message condition) stream))))

(defun upgrade-fail (control &rest arguments)
  (error 'upgrade-error :message (apply #'format nil control arguments)))

(defstruct (gr8s-version (:constructor make-gr8s-version (text major minor patch release dev-p)))
  "A parsed gr8s version: the Kubernetes API version, and the gr8s release number of
a release build (NIL for any other build, which is DEV-P)."
  text major minor patch release dev-p)

(defun parse-gr8s-version (text)
  "TEXT, as `gr8s version' prints it, as a GR8S-VERSION, or NIL when it isn't one:
an agent too old to report its version says just \"gr8s\"."
  (when (stringp text)
    (multiple-value-bind (match groups)
        (cl-ppcre:scan-to-strings "^v?(\\d+)\\.(\\d+)\\.(\\d+)(?:-gr8s\\.(\\d+))?(.*)$" text)
      (when match
        (let ((release (and (aref groups 3) (parse-integer (aref groups 3))))
              (rest (aref groups 4)))
          (make-gr8s-version text (parse-integer (aref groups 0)) (parse-integer (aref groups 1))
                             (parse-integer (aref groups 2)) release
                             (or (null release) (plusp (length rest)))))))))

(defun compare-gr8s-versions (left right)
  "-1, 0 or 1 as release LEFT is older than, the same as, or newer than RIGHT, both
strings or GR8S-VERSIONs; NIL when either is not a release, so has no place in the order."
  (let ((left (if (stringp left) (parse-gr8s-version left) left))
        (right (if (stringp right) (parse-gr8s-version right) right)))
    (when (and left right (not (gr8s-version-dev-p left)) (not (gr8s-version-dev-p right)))
      (let ((a (list (gr8s-version-major left) (gr8s-version-minor left) (gr8s-version-patch left)
                     (gr8s-version-release left)))
            (b (list (gr8s-version-major right) (gr8s-version-minor right) (gr8s-version-patch right)
                     (gr8s-version-release right))))
        (loop for x in a for y in b
              when (< x y) return -1
              when (> x y) return 1
              finally (return 0))))))
