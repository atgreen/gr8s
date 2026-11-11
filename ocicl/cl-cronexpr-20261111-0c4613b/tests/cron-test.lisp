;;;; SPDX-FileCopyrightText: 2026 Anthony Green <green@moxielogic.com>
;;;; SPDX-License-Identifier: MIT

(in-package #:cl-cronexpr/tests)
(def-suite cron-schedule :in cl-cronexpr)
(in-suite cron-schedule)

(defun cron-at (year month day hour minute &optional (second 0))
  "Return the universal time of a UTC calendar moment."
  (encode-universal-time second minute hour day month year 0))

(defun synthetic-tzif (transition)
  "Build a version 1 TZif image: UTC+1 until the Unix TRANSITION time, then UTC+2."
  (let ((bytes (make-array (+ 44 4 1 12 4) :element-type '(unsigned-byte 8) :initial-element 0)))
    (replace bytes #(84 90 105 102))
    (setf (aref bytes 35) 1 (aref bytes 39) 2 (aref bytes 43) 4)
    (loop for shift from 24 downto 0 by 8 for index from 44
          do (setf (aref bytes index) (ldb (byte 8 shift) transition)))
    (setf (aref bytes 48) 1)
    ;; Offsets are big-endian seconds: 3600 and 7200.
    (setf (aref bytes 51) #x0e (aref bytes 52) #x10
          (aref bytes 57) #x1c (aref bytes 58) #x20)
    bytes))

(test cron-parser-accepts-common-forms
  (dolist (text '("*/1 * * * ?" "* */1 * * ?" "0 0 1 1 *" "5,10 1-3 * JAN-MAR mon-fri" "@hourly" "@daily"
                  "@every 1h30m" "  0   0 * * *  "))
    (is (cl-cronexpr:parse-cron text))))

(test cron-parser-refuses-invalid-forms
  (dolist (text '("" "* * * *" "* * * * * *" "60 * * * *" "* 24 * * *" "* * 0 * *" "* * * 13 *" "* * * * 7"
                  "*/0 * * * *" "5-1 * * * *" "x * * * *" "TZ=UTC * * * * *" "CRON_TZ=UTC * * * * *"
                  "@every" "@every 1" "@every 100ms" "@unknown"))
    (signals cl-cronexpr:invalid-cron-schedule (cl-cronexpr:parse-cron text))))

(test next-time-steps-through-fields
  (flet ((next (text after) (cl-cronexpr:next-cron-time (cl-cronexpr:parse-cron text) after)))
    (is (= (cron-at 2026 11 4 10 31) (next "*/1 * * * ?" (cron-at 2026 11 4 10 30 15))))
    (is (= (cron-at 2026 11 4 10 31) (next "*/1 * * * ?" (cron-at 2026 11 4 10 30))))
    (is (= (cron-at 2026 11 4 11 0) (next "@hourly" (cron-at 2026 11 4 10 30))))
    (is (= (cron-at 2027 1 1 0 0) (next "0 0 1 1 *" (cron-at 2026 11 4 10 30))))
    (is (= (cron-at 2026 11 4 10 30 30) (next "@every 30s" (cron-at 2026 11 4 10 30))))
    ;; An impossible date yields nothing rather than looping for ever.
    (is (null (next "0 0 30 2 *" (cron-at 2026 11 4 10 30))))))

(test restricted-day-fields-match-either-and-a-star-requires-both
  ;; 2026-11-04 is a Wednesday; the 5th is a Thursday.
  (flet ((next (text) (cl-cronexpr:next-cron-time (cl-cronexpr:parse-cron text) (cron-at 2026 11 3 23 59))))
    (is (= (cron-at 2026 11 4 0 0) (next "0 0 4 * *")))
    (is (= (cron-at 2026 11 4 0 0) (next "0 0 * * wed")))
    (is (= (cron-at 2026 11 4 0 0) (next "0 0 20 * wed")))
    (is (= (cron-at 2026 11 20 0 0) (next "0 0 20 * */1")))
    (is (= (cron-at 2026 11 4 0 0) (next "0 0 */2 * wed")))))

(test most-recent-time-jumps-over-long-outages
  (flet ((recent (text earliest now) (cl-cronexpr:most-recent-cron-time (cl-cronexpr:parse-cron text) earliest now)))
    (let ((now (cron-at 2026 11 4 10 30 20)))
      (is (= (cron-at 2026 11 4 10 30) (recent "* * * * *" (cron-at 2026 11 1 0 0) now)))
      (is (= (cron-at 2026 11 4 10 0) (recent "@hourly" (cron-at 2025 1 1 0 0) now)))
      (is (= (cron-at 2026 1 1 0 0) (recent "0 0 1 1 *" (cron-at 2020 6 1 0 0) now)))
      (is (null (recent "* * * * *" (cron-at 2026 11 4 10 30) now)))
      (is (null (recent "0 0 1 1 *" (cron-at 2026 6 1 0 0) now)))
      (is (= (+ (cron-at 2026 11 4 10 0) 1800) (recent "@every 30m" (cron-at 2026 11 4 10 0) now))))))

(test tzif-offsets-follow-the-table-and-drive-the-schedule
  (let* ((switch (cron-at 2026 3 1 0 0))
         (zone (cl-cronexpr:parse-tzif (synthetic-tzif (- switch cl-cronexpr:+unix-epoch-universal+)) switch)))
    (is (= 3600 (cl-cronexpr:cron-zone-offset zone (1- switch))))
    (is (= 7200 (cl-cronexpr:cron-zone-offset zone switch)))
    (is (= 0 (cl-cronexpr:cron-zone-offset nil switch)))
    ;; Midnight local is 23:00 UTC before the change and 22:00 UTC after it.
    (let ((daily (cl-cronexpr:parse-cron "@daily")))
      (is (= (cron-at 2026 2 10 23 0) (cl-cronexpr:next-cron-time daily (cron-at 2026 2 10 12 0) zone)))
      (is (= (cron-at 2026 3 10 22 0) (cl-cronexpr:next-cron-time daily (cron-at 2026 3 10 12 0) zone))))
    (is (equal "2026-03-01T02:00:00+02:00" (cl-cronexpr:format-cron-time switch zone)))
    (is (equal "2026-03-01T00:00:00Z" (cl-cronexpr:format-cron-time switch nil)))))

(test time-zone-names-are-validated
  (is (null (cl-cronexpr:load-cron-zone "UTC")))
  (is (null (cl-cronexpr:load-cron-zone "Etc/UTC")))
  (dolist (name '("bad-time-zone" "Local" "../../etc/passwd" "/etc/passwd" "Not/AZone"))
    (signals cl-cronexpr:invalid-cron-schedule (cl-cronexpr:load-cron-zone name))))

(test slim-time-zone-rules-expand-into-future-offset-changes
  (multiple-value-bind (transitions offsets)
      (cl-cronexpr:extend-zone-transitions (vector) (vector) "EST5EDT,M3.2.0,M11.1.0" (cron-at 2026 11 4 12 0))
    (let ((zone (cl-cronexpr:make-cron-zone :transitions transitions :offsets offsets :initial -18000)))
      ;; US rules: 2026 changes on March 8 and November 1, at 02:00 local.
      (is (= -18000 (cl-cronexpr:cron-zone-offset zone (cron-at 2027 1 15 12 0))))
      (is (= -18000 (cl-cronexpr:cron-zone-offset zone (1- (cron-at 2027 3 14 7 0)))))
      (is (= -14400 (cl-cronexpr:cron-zone-offset zone (cron-at 2027 3 14 7 0))))
      (is (= -14400 (cl-cronexpr:cron-zone-offset zone (1- (cron-at 2027 11 7 6 0)))))
      (is (= -18000 (cl-cronexpr:cron-zone-offset zone (cron-at 2027 11 7 6 0))))))
  ;; A southern zone with a named offset, a last-week rule and explicit change times.
  (multiple-value-bind (transitions offsets)
      (cl-cronexpr:extend-zone-transitions (vector) (vector) "<+1030>-10:30<+11>-11,M10.1.0,M4.1.0" (cron-at 2026 11 4 12 0))
    (let ((zone (cl-cronexpr:make-cron-zone :transitions transitions :offsets offsets :initial 37800)))
      (is (= 39600 (cl-cronexpr:cron-zone-offset zone (cron-at 2027 1 15 12 0))))
      (is (= 37800 (cl-cronexpr:cron-zone-offset zone (cron-at 2027 7 15 12 0))))))
  (signals cl-cronexpr:invalid-cron-schedule
    (cl-cronexpr:extend-zone-transitions (vector) (vector) "EST5EDT,J60,J300" (cron-at 2026 11 4 12 0))))

