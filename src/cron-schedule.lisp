;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Parse five-field cron schedules with the semantics of the robfig/cron parser
;;;; that Kubernetes uses, including descriptors and @every, and find the times
;;;; they name. Named time zones come from the host's zoneinfo TZif files; a zone
;;;; whose future offsets a file does not list is refused rather than guessed at.

(in-package #:gr8s)

(defstruct cron-schedule
  "Bit sets of matching field values, or EVERY seconds for a constant-delay schedule."
  minutes hours days months weekdays any-day any-weekday every)

(define-condition invalid-cron-schedule (error)
  ((text :initarg :text :reader invalid-cron-schedule-text))
  (:report (lambda (condition stream) (write-string (invalid-cron-schedule-text condition) stream)))
  (:documentation "A schedule or time zone that cannot be run as written."))

(defun cron-schedule-error (control &rest arguments)
  "Signal that a cron schedule is invalid."
  (error 'invalid-cron-schedule :text (apply #'format nil control arguments)))

(defparameter +cron-month-names+ '("jan" "feb" "mar" "apr" "may" "jun" "jul" "aug" "sep" "oct" "nov" "dec")
  "Month names, whose values start at 1.")

(defparameter +cron-weekday-names+ '("sun" "mon" "tue" "wed" "thu" "fri" "sat")
  "Weekday names, whose values start at 0.")

(defun cron-field-number (text names base)
  "Read a field value as a name from NAMES or a nonnegative number."
  (let ((position (position (string-downcase text) names :test #'string=)))
    (cond (position (+ position base))
          ((and (plusp (length text)) (every #'digit-char-p text)) (parse-integer text))
          (t (cron-schedule-error "Invalid cron field value ~S" text)))))

(defun parse-cron-range (text low high names base)
  "Return the bits of one range[/step] term and whether it was a star without a real step."
  (let* ((parts (uiop:split-string text :separator '(#\/)))
         (bounds (uiop:split-string (first parts) :separator '(#\-)))
         (star (member (first bounds) '("*" "?") :test #'string=))
         (start (if star low (cron-field-number (first bounds) names base)))
         (end (cond (star high)
                    ((= 1 (length bounds)) start)
                    ((= 2 (length bounds)) (cron-field-number (second bounds) names base))
                    (t (cron-schedule-error "Too many hyphens in cron term ~S" text))))
         (step 1))
    (when (and star (> (length bounds) 1)) (cron-schedule-error "Invalid cron term ~S" text))
    (case (length parts)
      (1)
      (2 (setf step (cron-field-number (second parts) nil 0))
       (when (= 1 (length bounds)) (setf end high))
       (when (> step 1) (setf star nil)))
      (t (cron-schedule-error "Too many slashes in cron term ~S" text)))
    (when (or (< start low) (> end high) (> start end) (zerop step))
      (cron-schedule-error "Cron term ~S is out of range ~D-~D" text low high))
    (values (loop with bits = 0
                  for value from start to end by step
                  do (setf bits (logior bits (ash 1 value)))
                  finally (return bits))
            (and star t))))

(defun parse-cron-field (text low high &optional names (base 0))
  "Return a comma separated field's bits and whether any term was a star."
  (let ((bits 0) (any nil))
    (dolist (term (uiop:split-string text :separator '(#\,)) (values bits any))
      (multiple-value-bind (term-bits term-star) (parse-cron-range term low high names base)
        (setf bits (logior bits term-bits) any (or any term-star))))))

(defun parse-cron-duration (text)
  "Read a whole-second Go duration such as 1h30m; finer units are refused."
  (let ((seconds 0) (position 0))
    (when (zerop (length text)) (cron-schedule-error "@every requires a duration"))
    (loop while (< position (length text))
          do (let* ((end (or (position-if-not #'digit-char-p text :start position)
                             (cron-schedule-error "Duration ~S has no unit" text)))
                    (unit (and (> end position) (char text end)))
                    (factor (case unit (#\h 3600) (#\m 60) (#\s 1)
                              (t (cron-schedule-error "@every supports only whole h, m and s units, not ~S" text)))))
               (when (and (< (1+ end) (length text)) (char= unit #\m) (char= (char text (1+ end)) #\s))
                 (cron-schedule-error "@every supports only whole h, m and s units, not ~S" text))
               (incf seconds (* factor (parse-integer text :start position :end end)))
               (setf position (1+ end))))
    (when (< seconds 1) (cron-schedule-error "@every requires at least one second"))
    seconds))

(defun parse-cron (text)
  "Parse a schedule as cron.ParseStandard does, signalling INVALID-CRON-SCHEDULE otherwise."
  (unless (stringp text) (cron-schedule-error "A CronJob schedule must be a string"))
  (when (or (uiop:string-prefix-p "TZ=" text) (uiop:string-prefix-p "CRON_TZ=" text))
    (cron-schedule-error "Use spec.timeZone rather than TZ or CRON_TZ in the schedule"))
  (let* ((fields (remove "" (uiop:split-string text :separator '(#\Space #\Tab)) :test #'string=))
         (descriptor (and fields (char= #\@ (char (first fields) 0))
                          (assoc (first fields)
                                 '(("@yearly" . "0 0 1 1 *") ("@annually" . "0 0 1 1 *") ("@monthly" . "0 0 1 * *")
                                   ("@weekly" . "0 0 * * 0") ("@daily" . "0 0 * * *") ("@midnight" . "0 0 * * *")
                                   ("@hourly" . "0 * * * *"))
                                 :test #'string=))))
    (cond
      ((and (equal (first fields) "@every") (= 2 (length fields)))
       (make-cron-schedule :every (parse-cron-duration (second fields))))
      ((and descriptor (= 1 (length fields))) (parse-cron (cdr descriptor)))
      ((/= 5 (length fields)) (cron-schedule-error "A cron schedule has five fields, not ~S" text))
      (t
       (multiple-value-bind (days any-day) (parse-cron-field (third fields) 1 31)
         (multiple-value-bind (weekdays any-weekday)
             (parse-cron-field (fifth fields) 0 6 +cron-weekday-names+)
           (make-cron-schedule :minutes (parse-cron-field (first fields) 0 59)
                               :hours (parse-cron-field (second fields) 0 23)
                               :months (parse-cron-field (fourth fields) 1 12 +cron-month-names+ 1)
                               :days days :any-day any-day :weekdays weekdays :any-weekday any-weekday)))))))

(defun cron-day-matches-p (schedule day weekday)
  "Apply cron's rule: two restricted day fields match if either does."
  (let ((in-month (logbitp day (cron-schedule-days schedule)))
        (in-week (logbitp weekday (cron-schedule-weekdays schedule))))
    (if (or (cron-schedule-any-day schedule) (cron-schedule-any-weekday schedule))
        (and in-month in-week)
        (or in-month in-week))))

(defun next-cron-time (schedule after &optional zone)
  "Return the first universal time past AFTER that SCHEDULE names in ZONE, or NIL within five years.
Stepping forward through absolute time rereads wall-clock fields, so offset changes cannot skip a match."
  (let ((every (cron-schedule-every schedule)))
    (when every (return-from next-cron-time (+ after every))))
  (loop with limit = (+ after (* 5 366 86400))
        with time = (1+ after)
        while (< time limit)
        do (let ((local (+ time (cron-zone-offset zone time))))
             (multiple-value-bind (second minute hour day month year weekday) (decode-universal-time local 0)
               (declare (ignore year))
               (cond
                 ((plusp second) (incf time (- 60 second)))
                 ((not (and (logbitp month (cron-schedule-months schedule))
                            (cron-day-matches-p schedule day (mod (1+ weekday) 7))
                            (logbitp hour (cron-schedule-hours schedule))))
                  (incf time (* 60 (- 60 minute))))
                 ((not (logbitp minute (cron-schedule-minutes schedule))) (incf time 60))
                 (t (return time)))))))

(defun most-recent-cron-time (schedule earliest now &optional zone)
  "Return the latest time SCHEDULE names in the interval (EARLIEST, NOW], or NIL.
The search widens backward from NOW so a long-idle object costs little to catch up."
  (let ((every (cron-schedule-every schedule)))
    (when every
      (return-from most-recent-cron-time
        (let ((elapsed (floor (- now earliest) every)))
          (and (plusp elapsed) (+ earliest (* elapsed every)))))))
  (let ((first (next-cron-time schedule earliest zone)))
    (when (and first (<= first now))
      (loop with window = 3600
            for from = (max earliest (- now window))
            for found = (next-cron-time schedule from zone)
            when (and found (<= found now))
              do (return (loop for next = (next-cron-time schedule found zone)
                               while (and next (<= next now))
                               do (setf found next)
                               finally (return found)))
            do (setf window (* 2 window))))))

;;; Time zones: an offset table read from a compiled TZif file.

(defstruct cron-zone
  "Transition times in universal time, with the UTC offset each begins and the offset before the first."
  transitions offsets initial)

(defparameter +unix-epoch-universal+ 2208988800
  "The universal time of the Unix epoch.")

(defvar *cron-zones* (make-hash-table :test #'equal)
  "Time zones already loaded, by name.")

(defvar *cron-zones-lock* (bt:make-lock "gr8s cron zones")
  "Guards *CRON-ZONES*.")

(defparameter *zoneinfo-directory* "/usr/share/zoneinfo/"
  "The host's compiled time zone database.")

(defun cron-zone-offset (zone time)
  "Return the seconds east of UTC in ZONE at universal TIME; a NIL ZONE is UTC."
  (if (null zone)
      0
      (let* ((transitions (cron-zone-transitions zone)) (low 0) (high (length transitions)))
        (loop while (< low high)
              do (let ((middle (floor (+ low high) 2)))
                   (if (<= (aref transitions middle) time) (setf low (1+ middle)) (setf high middle))))
        (if (zerop low) (cron-zone-initial zone) (aref (cron-zone-offsets zone) (1- low))))))

(defun tzif-integer (bytes start size)
  "Read a signed big-endian integer of SIZE bytes."
  (let ((value (loop with total = 0
                     for index from start below (+ start size)
                     do (setf total (+ (* total 256) (aref bytes index)))
                     finally (return total))))
    (if (logbitp (1- (* 8 size)) value) (- value (ash 1 (* 8 size))) value)))

(defun posix-tz-offset-end (text start)
  "Parse a POSIX TZ [+-]hh[:mm[:ss]] at START, returning its seconds and where it ends."
  (let* ((sign (case (and (< start (length text)) (char text start)) (#\- -1) (t 1)))
         (position (if (and (< start (length text)) (find (char text start) "+-")) (1+ start) start))
         (total 0))
    (loop for unit in '(3600 60 1)
          do (multiple-value-bind (value end) (parse-integer text :start position :junk-allowed t)
               (unless value (cron-schedule-error "Malformed time zone rule"))
               (incf total (* unit value))
               (setf position end)
               (if (and (< position (length text)) (char= #\: (char text position)))
                   (incf position)
                   (return))))
    (values (* sign total) position)))

(defun posix-tz-name-end (text start)
  "Return where the POSIX TZ zone name at START ends: quoted in angle brackets, or letters."
  (if (and (< start (length text)) (char= #\< (char text start)))
      (1+ (or (position #\> text :start start) (cron-schedule-error "Malformed time zone rule")))
      (or (position-if-not #'alpha-char-p text :start start) (length text))))

(defun parse-posix-tz-rule (text)
  "Parse a Mm.w.d[/time] date rule into (month week weekday seconds).
The other two POSIX date forms name fixed days, which no recurring zone in the database uses."
  (let* ((slash (position #\/ text))
         (parts (uiop:split-string (subseq text 1 slash) :separator '(#\.)))
         (fields (mapcar (lambda (part) (parse-integer part :junk-allowed t)) parts)))
    (unless (and (char= #\M (char text 0)) (= 3 (length fields)) (every #'identity fields))
      (cron-schedule-error "Unsupported time zone rule ~S" text))
    (append fields (list (if slash (posix-tz-offset-end text (1+ slash)) 7200)))))

(defun posix-tz-rule-time (rule year offset)
  "Return the universal time RULE falls on in YEAR, where clocks read OFFSET seconds east of UTC."
  (destructuring-bind (month week weekday seconds) rule
    (let* ((first (encode-universal-time 0 0 0 1 month year 0))
           (first-weekday (mod (1+ (nth-value 6 (decode-universal-time first 0))) 7))
           (next-month (if (= month 12)
                           (encode-universal-time 0 0 0 1 1 (1+ year) 0)
                           (encode-universal-time 0 0 0 1 (1+ month) year 0)))
           (day (+ (mod (- weekday first-weekday) 7) (* 7 (1- week)))))
      (loop while (>= (+ first (* day 86400)) next-month) do (decf day 7))
      (- (+ first (* day 86400) seconds) offset))))

(defun extend-zone-transitions (transitions offsets footer now)
  "Append the changes FOOTER's recurring rule makes through decades past NOW to the zone's tables."
  (let* ((std-end (posix-tz-name-end footer 0)))
    (multiple-value-bind (std-west std-next) (posix-tz-offset-end footer std-end)
      (let* ((dst-end (posix-tz-name-end footer std-next))
             (comma (position #\, footer))
             (std (- std-west))
             (dst (if (< dst-end comma) (- (posix-tz-offset-end footer dst-end)) (+ std 3600)))
             (rules (uiop:split-string (subseq footer (1+ comma)) :separator '(#\,)))
             (times (length transitions))
             (last (if (plusp times) (aref transitions (1- times)) (- now (* 366 86400))))
             (first-year (nth-value 5 (decode-universal-time last 0)))
             (last-year (+ 25 (nth-value 5 (decode-universal-time now 0))))
             (added nil))
        (unless (= 2 (length rules)) (cron-schedule-error "Malformed time zone rule"))
        (let ((start (parse-posix-tz-rule (first rules))) (end (parse-posix-tz-rule (second rules))))
          (loop for year from first-year to last-year
                do (let ((to-dst (posix-tz-rule-time start year std))
                         (to-std (posix-tz-rule-time end year dst)))
                     (when (> to-dst last) (push (cons to-dst dst) added))
                     (when (> to-std last) (push (cons to-std std) added)))))
        (let ((sorted (sort added #'< :key #'car)))
          (values (concatenate 'vector transitions (mapcar #'car sorted))
                  (concatenate 'vector offsets (mapcar #'cdr sorted))))))))

(defun parse-tzif (bytes now)
  "Build a CRON-ZONE from TZif BYTES, refusing one whose rules for times past its table are unread."
  (flet ((check (start)
           (unless (and (>= (length bytes) (+ start 44))
                        (equalp (subseq bytes start (+ start 4)) #(84 90 105 102)))
             (cron-schedule-error "Malformed time zone file")))
         (count-at (start index) (tzif-integer bytes (+ start 20 (* 4 index)) 4)))
    (check 0)
    (let* ((version2 (plusp (aref bytes 4))) (start 0) (size 4))
      (when version2
        (setf start (+ 44 (* 4 (count-at 0 3)) (* 1 (count-at 0 3)) (* 6 (count-at 0 4)) (count-at 0 5)
                       (* 8 (count-at 0 2)) (count-at 0 1) (count-at 0 0))
              size 8)
        (check start))
      (let* ((times (count-at start 3)) (types (count-at start 4)) (chars (count-at start 5))
             (leaps (count-at start 2)) (standard (count-at start 1)) (universal (count-at start 0))
             (time-base (+ start 44)) (index-base (+ time-base (* size times)))
             (type-base (+ index-base times))
             (end (+ type-base (* 6 types) chars (* (+ size 4) leaps) standard universal))
             (footer (if (and version2 (< (1+ end) (length bytes)))
                         (map 'string #'code-char (subseq bytes (1+ end) (max (1+ end) (1- (length bytes)))))
                         ""))
             (transitions (make-array times)) (offsets (make-array times)))
        (when (or (zerop types) (> end (length bytes))) (cron-schedule-error "Malformed time zone file"))
        (dotimes (position times)
          (setf (aref transitions position)
                (+ +unix-epoch-universal+ (tzif-integer bytes (+ time-base (* size position)) size))
                (aref offsets position)
                (tzif-integer bytes (+ type-base (* 6 (aref bytes (+ index-base position)))) 4)))
        ;; Slim zone files stop listing changes once a recurring rule covers them.
        (when (and (find #\, footer) (or (zerop times) (< (aref transitions (1- times)) (+ now (* 366 86400)))))
          (multiple-value-setq (transitions offsets) (extend-zone-transitions transitions offsets footer now)))
        (make-cron-zone :transitions transitions :offsets offsets
                        :initial (tzif-integer bytes type-base 4))))))

(defun load-cron-zone (name)
  "Return NAME's zone, NIL for UTC, signalling INVALID-CRON-SCHEDULE for one that cannot be used."
  (when (member name '("UTC" "Etc/UTC") :test #'equal) (return-from load-cron-zone nil))
  (bt:with-lock-held (*cron-zones-lock*)
    (or (gethash name *cron-zones*)
        (progn
          (unless (and (stringp name) (<= 1 (length name) 255)
                       (not (search ".." name)) (not (char= #\/ (char name 0))) (not (equal name "Local"))
                       (every (lambda (character) (or (alphanumericp character) (find character "/_+-"))) name))
            (cron-schedule-error "Invalid time zone name ~S" name))
          (let ((path (concatenate 'string *zoneinfo-directory* name)))
            (unless (and (probe-file path) (pathname-name (probe-file path)))
              (cron-schedule-error "Unknown time zone ~S" name))
            (setf (gethash name *cron-zones*)
                  (parse-tzif (handler-case
                                  (with-open-file (stream path :element-type '(unsigned-byte 8))
                                    (let ((bytes (make-array (file-length stream) :element-type '(unsigned-byte 8))))
                                      (read-sequence bytes stream)
                                      bytes))
                                (error () (cron-schedule-error "Cannot read time zone ~S" name)))
                              (get-universal-time))))))))

(defun format-cron-time (time zone)
  "Write universal TIME as RFC 3339 with ZONE's offset."
  (let ((offset (cron-zone-offset zone time)))
    (multiple-value-bind (second minute hour day month year) (decode-universal-time (+ time offset) 0)
      (format nil "~4,'0D-~2,'0D-~2,'0DT~2,'0D:~2,'0D:~2,'0D~A" year month day hour minute second
              (if (zerop offset) "Z"
                  (format nil "~A~2,'0D:~2,'0D" (if (minusp offset) "-" "+")
                          (floor (abs offset) 3600) (floor (mod (abs offset) 3600) 60)))))))
