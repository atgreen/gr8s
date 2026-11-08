;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0

(in-package #:gr8s.image-distribution)

(defstruct (bencode-map (:constructor %make-bencode-map (entries)))
  "A bencoded dictionary whose keys remain arbitrary byte strings."
  entries)

(defun bencode-octets (value)
  "Return VALUE as an octet vector, encoding Lisp strings as UTF-8."
  (etypecase value
    (string (trivial-utf-8:string-to-utf-8-bytes value))
    (vector
     (unless (every (lambda (byte) (typep byte '(unsigned-byte 8))) value)
       (error "Bencode byte strings contain only octets"))
     (coerce value '(vector (unsigned-byte 8))))))

(defun bencode-key< (left right)
  "Order byte-string keys lexicographically as required by bencoding."
  (let ((left (bencode-octets left)) (right (bencode-octets right)))
    (loop for index below (min (length left) (length right))
          for a = (aref left index) for b = (aref right index)
          when (< a b) return t
          when (> a b) return nil
          finally (return (< (length left) (length right))))))

(defun bencode-key= (left right)
  (equalp (bencode-octets left) (bencode-octets right)))

(defun bencode-dictionary (entries)
  "Construct a dictionary from ENTRIES, an alist with string or octet keys."
  (let ((keys (mapcar (lambda (entry) (bencode-octets (car entry))) entries)))
    (loop for tail on keys
          when (find (first tail) (rest tail) :test #'equalp)
            do (error "Duplicate bencode dictionary key"))
    (%make-bencode-map entries)))

(defun bencode-value (dictionary key &optional default)
  "Return KEY's binary value from DICTIONARY, or DEFAULT when absent."
  (unless (bencode-map-p dictionary)
    (error "Expected a bencode dictionary"))
  (let ((entry (find key (bencode-map-entries dictionary)
                     :test #'bencode-key= :key #'car)))
    (if entry (cdr entry) default)))

(defun bencode-push-octets (octets output)
  (loop for byte across octets do (vector-push-extend byte output)))

(defun bencode-push-ascii (text output)
  (bencode-push-octets (trivial-utf-8:string-to-utf-8-bytes text) output))

(defun encode-bencode (value)
  "Encode VALUE into canonical bencoding and return a fresh octet vector."
  (let ((output (make-array 128 :element-type '(unsigned-byte 8)
                                :adjustable t :fill-pointer 0)))
    (labels ((emit-string (string)
               (let ((octets (bencode-octets string)))
                 (bencode-push-ascii (format nil "~D:" (length octets)) output)
                 (bencode-push-octets octets output)))
             (emit (item)
               (typecase item
                 (integer
                  (bencode-push-ascii (format nil "i~De" item) output))
                 (string (emit-string item))
                 (vector (emit-string item))
                 (bencode-map
                  (vector-push-extend (char-code #\d) output)
                  (let ((entries (stable-sort (copy-list (bencode-map-entries item))
                                              #'bencode-key< :key #'car)))
                    (loop for previous = nil then key
                          for entry in entries
                          for key = (bencode-octets (car entry))
                          do (when (and previous (equalp previous key))
                               (error "Duplicate bencode dictionary key"))
                             (emit-string key)
                             (emit (cdr entry))))
                  (vector-push-extend (char-code #\e) output))
                 (list
                  (vector-push-extend (char-code #\l) output)
                  (mapc #'emit item)
                  (vector-push-extend (char-code #\e) output))
                 (t (error "Cannot bencode ~S" item)))))
      (emit value)
      (copy-seq output))))

(defun decode-bencode (octets)
  "Decode canonical bencoded OCTETS, rejecting ambiguous or trailing input."
  (let ((octets (bencode-octets octets)) (position 0))
    (labels ((peek ()
               (when (< position (length octets)) (aref octets position)))
             (ascii-number (terminator &key allow-negative)
               (let ((start position))
                 (loop for byte = (peek)
                       until (or (null byte) (= byte terminator))
                       do (unless (or (and allow-negative (= position start)
                                               (= byte (char-code #\-)))
                                      (<= (char-code #\0) byte (char-code #\9)))
                            (error "Invalid number in bencoded input"))
                          (incf position))
                 (unless (peek) (error "Unterminated number in bencoded input"))
                 (let ((text (trivial-utf-8:utf-8-bytes-to-string
                              (subseq octets start position))))
                   (incf position)
                   (when (or (zerop (length text))
                             (and (> (length text) 1) (char= (char text 0) #\0))
                             (string= text "-0"))
                     (error "Noncanonical number in bencoded input"))
                   (parse-integer text))))
             (parse-string ()
               (let ((length (ascii-number (char-code #\:))))
                 (when (> (+ position length) (length octets))
                   (error "Bencoded string exceeds input"))
                 (prog1 (subseq octets position (+ position length))
                   (incf position length))))
             (parse-value ()
               (let ((byte (peek)))
                 (cond
                   ((null byte) (error "Unexpected end of bencoded input"))
                   ((= byte (char-code #\i))
                    (incf position)
                    (ascii-number (char-code #\e) :allow-negative t))
                   ((= byte (char-code #\l))
                    (incf position)
                    (loop until (eql (peek) (char-code #\e)) collect (parse-value)
                          finally (incf position)))
                   ((= byte (char-code #\d))
                    (incf position)
                    (let ((entries nil) (previous nil))
                      (loop until (eql (peek) (char-code #\e))
                            for key = (parse-string)
                            do (when (and previous (not (bencode-key< previous key)))
                                 (error "Bencode dictionary keys are not strictly sorted"))
                               (push (cons key (parse-value)) entries)
                               (setf previous key)
                            finally (incf position))
                      (%make-bencode-map (nreverse entries))))
                   ((<= (char-code #\0) byte (char-code #\9)) (parse-string))
                   (t (error "Invalid bencode token ~D" byte))))))
      (let ((value (parse-value)))
        (unless (= position (length octets))
          (error "Trailing bytes after bencoded value"))
        value))))
