;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Validate the string formats Kubernetes executes for custom resources, after
;;;; kube-openapi's strfmt registry. A format outside the registry validates
;;;; nothing upstream either, so it is admitted and ignored rather than refused.

(in-package #:gr8s)

(defun crd-format-pattern-p (pattern text)
  "Test TEXT against an RE2 PATTERN."
  (re2-match-p (re2-compiled pattern) text))

(defun crd-format-isbn10-p (text)
  "Check an ISBN-10, hyphens and spaces aside, as govalidator does."
  (let ((digits (remove-if (lambda (character) (find character " -")) text)))
    (and (crd-format-pattern-p "^[0-9]{9}[0-9X]$" digits)
         (zerop (mod (loop for index from 0 below 10
                           sum (* (- 10 index)
                                  (if (char= #\X (char digits index)) 10 (digit-char-p (char digits index)))))
                     11)))))

(defun crd-format-isbn13-p (text)
  "Check an ISBN-13, hyphens and spaces aside, as govalidator does."
  (let ((digits (remove-if (lambda (character) (find character " -")) text)))
    (and (crd-format-pattern-p "^[0-9]{13}$" digits)
         (zerop (mod (loop for index from 0 below 13
                           sum (* (if (evenp index) 1 3) (digit-char-p (char digits index))))
                     10)))))

(defun crd-format-luhn-p (digits)
  "Apply the Luhn checksum to a string of digits."
  (zerop (mod (loop for character across (reverse digits)
                    for index from 0
                    for digit = (digit-char-p character)
                    sum (if (oddp index)
                            (let ((doubled (* 2 digit))) (if (> doubled 9) (- doubled 9) doubled))
                            digit))
              10)))

(defun crd-format-base64-p (text)
  "Check standard padded base64."
  (crd-format-pattern-p "^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})$" text))

(defun crd-format-hostname-p (text)
  "Check a hostname as strfmt's IsHostname does."
  (and (crd-format-pattern-p
        "^([a-zA-Z0-9\\p{S}\\p{L}]((-?[a-zA-Z0-9\\p{S}\\p{L}]{0,62})?)|([a-zA-Z0-9\\p{S}\\p{L}](([a-zA-Z0-9-\\p{S}\\p{L}]{0,61}[a-zA-Z0-9\\p{S}\\p{L}])?)(\\.)){1,}([a-zA-Z\\p{L}]){2,63})$"
        text)
       (<= (length (trivial-utf-8:string-to-utf-8-bytes text)) 255)
       (every (lambda (part) (<= (length part) 63)) (uiop:split-string text :separator '(#\.)))))

(defun crd-format-duration-p (text)
  "Check a duration as strfmt's IsDuration does: Go syntax, or spelled-out units."
  (or (and (cel-parse-duration text) t)
      (crd-format-pattern-p
       "^[0-9]+\\s*(ns|nanoseconds?|us|microseconds?|ms|milliseconds?|s|sec|secs|seconds?|m|min|mins|minutes?|h|hr|hrs|hours?|d|day|days|w|wk|wks|week|weeks)(\\s*[0-9]+\\s*(ns|nanoseconds?|us|microseconds?|ms|milliseconds?|s|sec|secs|seconds?|m|min|mins|minutes?|h|hr|hrs|hours?|d|day|days|w|wk|wks|week|weeks))*$"
       text)))

(defun crd-format-date-p (text)
  "Check a full-date, including that the day exists."
  (and (crd-format-pattern-p "^[0-9]{4}-[0-9]{2}-[0-9]{2}$" text)
       (cel-parse-rfc3339 (concatenate 'string text "T00:00:00Z"))
       t))

(defun crd-format-datetime-p (text)
  "Check a date-time as strfmt does, accepting its RFC 3339 variants."
  (and (or (cel-parse-rfc3339 text)
           (cel-parse-rfc3339 (cl-ppcre:regex-replace "([+-][0-9]{2})([0-9]{2})$" text "\\1:\\2"))
           (cel-parse-rfc3339 (concatenate 'string text "Z")))
       t))

(defun crd-format-valid-p (format text)
  "Validate TEXT against the normalized FORMAT name; a name the registry lacks accepts anything."
  (flet ((pattern (expression) (crd-format-pattern-p expression text)))
    (cond
      ((equal format "bsonobjectid") (pattern "^[0-9a-fA-F]{24}$"))
      ((equal format "uri")
       (and (plusp (length text)) (not (find #\Space text))
            (or (char= #\/ (char text 0)) (pattern "^[A-Za-z][A-Za-z0-9+.-]*:"))))
      ((equal format "email")
       (pattern "^[^\\s@<>()\\[\\]\\\\,;:\"]+@[^\\s@<>()\\[\\]\\\\,;:\"]+$"))
      ((equal format "hostname") (crd-format-hostname-p text))
      ((equal format "ipv4") (and (cel-parse-ipv4 text) t))
      ((equal format "ipv6") (and (find #\: text) (handler-case (and (0conf:parse-ipv6 text) t) (error () nil))))
      ((equal format "cidr") (and (cel-parse-cidr text) t))
      ((equal format "mac")
       (pattern "^(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}$|^(?:[0-9a-fA-F]{2}[:-]){7}[0-9a-fA-F]{2}$|^(?:[0-9a-fA-F]{4}\\.){2}[0-9a-fA-F]{4}$|^(?:[0-9a-fA-F]{4}\\.){3}[0-9a-fA-F]{4}$"))
      ((equal format "uuid") (pattern "(?i)^[0-9a-f]{8}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{12}$"))
      ((equal format "uuid3") (pattern "(?i)^[0-9a-f]{8}-?[0-9a-f]{4}-?3[0-9a-f]{3}-?[0-9a-f]{4}-?[0-9a-f]{12}$"))
      ((equal format "uuid4") (pattern "(?i)^[0-9a-f]{8}-?[0-9a-f]{4}-?4[0-9a-f]{3}-?[89ab][0-9a-f]{3}-?[0-9a-f]{12}$"))
      ((equal format "uuid5") (pattern "(?i)^[0-9a-f]{8}-?[0-9a-f]{4}-?5[0-9a-f]{3}-?[89ab][0-9a-f]{3}-?[0-9a-f]{12}$"))
      ((equal format "isbn") (or (crd-format-isbn10-p text) (crd-format-isbn13-p text)))
      ((equal format "isbn10") (crd-format-isbn10-p text))
      ((equal format "isbn13") (crd-format-isbn13-p text))
      ((equal format "creditcard")
       (let ((digits (remove-if (lambda (character) (find character " -")) text)))
         (and (pattern "^[0-9 -]+$") (crd-format-pattern-p "^[0-9]{13,19}$" digits) (crd-format-luhn-p digits))))
      ((equal format "ssn") (pattern "^\\d{3}[- ]?\\d{2}[- ]?\\d{4}$"))
      ((equal format "hexcolor") (pattern "^#?([0-9a-fA-F]{3}|[0-9a-fA-F]{6})$"))
      ((equal format "rgbcolor") (pattern "^rgb\\(\\s*(0|[1-9]\\d?|1\\d\\d?|2[0-4]\\d|25[0-5])\\s*,\\s*(0|[1-9]\\d?|1\\d\\d?|2[0-4]\\d|25[0-5])\\s*,\\s*(0|[1-9]\\d?|1\\d\\d?|2[0-4]\\d|25[0-5])\\s*\\)$"))
      ((equal format "byte") (crd-format-base64-p text))
      ((equal format "date") (crd-format-date-p text))
      ((equal format "duration") (crd-format-duration-p text))
      ((equal format "datetime") (crd-format-datetime-p text))
      (t t))))

(defun crd-check-string-format (format value path)
  "Refuse VALUE when the declared FORMAT, normalized as upstream does, rejects it."
  (when (and (stringp format) (plusp (length format)))
    (let ((normalized (string-downcase (remove #\- format))))
      (unless (crd-format-valid-p normalized value)
        (crd-schema-error path "must be of type ~A: ~S" format value)))))
