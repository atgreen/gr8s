;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Bounded, deterministic ranking shared by Service and image-peer steering.

(in-package #:gr8s.foundation)

(defun steering-bounded-integer (value maximum &optional (default 0))
  (if (and (integerp value) (not (minusp value)))
      (min value maximum)
      default))

(defun node-steering-capacity-score (capacity)
  "Return a bounded CPU-capacity hint in millicores, or zero when unavailable."
  (let ((cpu (and (hash-table-p capacity) (gethash "cpu" capacity))))
    (handler-case
        (cond
          ((not (stringp cpu)) 0)
          ((and (plusp (length cpu)) (char= #\m (char cpu (1- (length cpu)))))
           (steering-bounded-integer
            (parse-integer cpu :end (1- (length cpu)) :junk-allowed nil) 100000))
          (t
           (steering-bounded-integer
            (* 1000 (parse-integer cpu :junk-allowed nil)) 100000)))
      (error () 0))))

(defun network-steering-score (candidate)
  "Return a lower-is-better bounded score for one trusted candidate plist.
All remotely influenced numeric evidence is clamped before it contributes."
  (let* ((same-node (getf candidate :same-node))
         (same-zone (getf candidate :same-zone))
         (same-region (getf candidate :same-region))
         (locality (cond (same-node 0) (same-zone 200) (same-region 1000) (t 5000)))
         (healthy (not (eq nil (getf candidate :healthy t))))
         (path (steering-bounded-integer (getf candidate :path-score) 10000 10000))
         (link (* 20 (steering-bounded-integer (getf candidate :link-cost) 100 100)))
         (capacity (steering-bounded-integer (getf candidate :capacity) 100000 0))
         (capacity-penalty (- 1000 (min 1000 (floor capacity 100))))
         (load (* 10 (steering-bounded-integer (getf candidate :active-flows) 1000 0))))
    (+ (if healthy 0 1000000) locality path link capacity-penalty load)))

(defun network-steering-candidate-less-p (left right)
  (let ((left-score (network-steering-score left))
        (right-score (network-steering-score right)))
    (or (< left-score right-score)
        (and (= left-score right-score)
             (string< (or (getf left :node-name) "")
                      (or (getf right :node-name) ""))))))

(defun rank-network-steering-candidates (candidates)
  "Rank CANDIDATES deterministically and diversify the second healthy choice."
  (let* ((ordered (stable-sort (copy-list candidates)
                               #'network-steering-candidate-less-p))
         (first (first ordered))
         (first-domain (and first (getf first :failure-domain)))
         (diverse
           (and first-domain
                (find-if (lambda (candidate)
                           (and (getf candidate :healthy t)
                                (not (equal first-domain
                                            (getf candidate :failure-domain)))))
                         (rest ordered)))))
    (if diverse
        (cons first (cons diverse (remove diverse (rest ordered) :test #'eq)))
        ordered)))
