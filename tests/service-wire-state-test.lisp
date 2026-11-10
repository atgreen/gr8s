;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
(in-package #:gr8s/tests)
(def-suite service-wire-state :in gr8s)
(in-suite service-wire-state)

(defun service-wire-gc-fixture ()
  (let ((keys (make-hash-table :test #'equal))
        (names '("gr8s_nat_rx_v2" "gr8s_nat_ri_v3")))
    (loop for name in names for count in '(4 3)
          do (setf (gethash name keys)
                   (loop for i from 1 to count
                         collect (let ((key (make-array (if (equal name "gr8s_nat_ri_v3") 64 16)
                                                          :element-type '(unsigned-byte 8)
                                                          :initial-element i)))
                                   (let ((offset (if (= (length key) 64) 48 0)))
                                     (setf (aref key (+ offset 12)) 17
                                           (aref key (+ offset 13)) 0
                                           (aref key (+ offset 14)) 0
                                           (aref key (+ offset 15)) 0)) key))))
    (values
     (gr8s::%make-service-lb-dataplane
      :programs (list (cons "gr8s_wire_gc" (fake-lb-program 900151)))
      :maps (loop for name in names for fd from 900152 collect (fake-lb-map name fd)))
     keys
     (lambda (map previous)
       (let ((entries (gethash (whistler/loader:map-info-name map) keys)))
         (if previous (second (member previous entries :test #'equalp)) (first entries)))))))

(test receiver-gc-is-bounded-and-resumes-both-map-cursors
  (multiple-value-bind (dataplane keys next-key) (service-wire-gc-fixture)
    (let ((seen nil))
      (dotimes (tick 5)
        (declare (ignore tick))
        (multiple-value-bind (scanned reclaimed deferred)
            (gr8s.network::sweep-service-wire-state
             dataplane :budget 1 :next-key next-key
             :run (lambda (fd direction key)
                    (is (= fd 900151))
                    (is (= (if (= direction 0) 16 64) (length key)))
                    (push (list direction (aref key 0)) seen)
                    (let ((name (nth direction '("gr8s_nat_rx_v2" "gr8s_nat_ri_v3"))))
                      (setf (gethash name keys) (remove key (gethash name keys) :test #'equalp)))
                    1))
          (is (<= scanned 2))
          (is (= scanned reclaimed))
          (is (zerop deferred))))
      (is (equal '((0 1) (1 1) (0 2) (1 2) (0 3) (1 3) (0 4)) (nreverse seen)))
      (is (= 7 (gr8s::service-lb-dataplane-gc-scanned dataplane)))
      (is (= 7 (gr8s::service-lb-dataplane-gc-reclaimed dataplane)))
      (is (every #'null (loop for value being the hash-values of keys collect value))))))

(test receiver-gc-advances-after-failure-and-defers-busy-keys
  (multiple-value-bind (dataplane keys next-key) (service-wire-gc-fixture)
    (declare (ignore keys))
    (let ((seen nil))
      (signals simple-error
        (gr8s.network::sweep-service-wire-state
         dataplane :budget 1 :next-key next-key
         :run (lambda (&rest ignored) (declare (ignore ignored)) (error "collector interrupted"))))
      (is (= 1 (gr8s::service-lb-dataplane-gc-failures dataplane)))
      (multiple-value-bind (scanned reclaimed deferred)
          (gr8s.network::sweep-service-wire-state
           dataplane :budget 1 :next-key next-key
           :run (lambda (fd direction key)
                  (declare (ignore fd)) (push (list direction (aref key 0)) seen) 2))
        (is (= scanned 2))
        (is (zerop reclaimed))
        (is (= deferred 2)))
      (is (equal '((1 1) (0 2)) seen))
      (is (= 2 (gr8s::service-lb-dataplane-gc-deferred dataplane)))
      (signals simple-error
        (gr8s.network::sweep-service-wire-state
         dataplane :budget 1 :next-key next-key
         :run (lambda (&rest ignored) (declare (ignore ignored)) 3)))
      (is (= 2 (gr8s::service-lb-dataplane-gc-failures dataplane)))
      (signals type-error (gr8s.network::sweep-service-wire-state dataplane :budget 0)))))

(test receiver-gc-does-not-use-a-legacy-maintenance-program
  (multiple-value-bind (dataplane keys next-key) (service-nat-gc-fixture)
    (declare (ignore keys next-key))
    (let ((called nil))
      (is (zerop (gr8s.network::sweep-service-wire-state
                  dataplane :next-key (lambda (&rest ignored) (declare (ignore ignored)) (setf called t))
                  :run (lambda (&rest ignored) (declare (ignore ignored)) (setf called t)))))
      (is-false called))))

(test receiver-gc-rejects-other-key-widths-and-directions
  (signals type-error (gr8s.network::run-service-wire-gc-key 0 2 (make-array 16)))
  (signals type-error (gr8s.network::run-service-wire-gc-key 0 -1 (make-array 16)))
  (signals simple-error (gr8s.network::run-service-wire-gc-key 0 0 (make-array 32)))
  (signals simple-error (gr8s.network::run-service-wire-gc-key 0 1 (make-array 16))))
