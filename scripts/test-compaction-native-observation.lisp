;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
(require :asdf)
(asdf:load-system "gr8s")
(load "scripts/compaction-cluster-native-harness.lisp")
(let ((member (bt:make-lock "observer member")) (store (bt:make-lock "observer store"))
      (checks 0))
  (flet ((check (value) (incf checks) (unless value (error "Observation check ~D failed" checks))))
    (dolist (which '("member" "store"))
      (let* ((held (bt:make-semaphore)) (release (bt:make-semaphore))
             (observed (bt:make-semaphore)) (observer nil) (value nil) (failure nil)
             (owner (bt:make-thread
                     (lambda ()
                       (bt:with-lock-held ((if (equal which "member") member store))
                         (bt:signal-semaphore held)
                         (bt:wait-on-semaphore release))))))
        (unwind-protect
             (progn
               (check (bt:wait-on-semaphore held :timeout 10))
               ;; Join remains pending: observation must return without waiting
               ;; for either real held mutex, and must never run the sampler.
               (setf observer
                     (bt:make-thread
                      (lambda ()
                        (unwind-protect
                             (handler-case
                                 (setf value (compaction-native-try-sample
                                              member store (lambda () (error "Busy sample executed"))))
                               (error (condition) (setf failure condition)))
                          (bt:signal-semaphore observed)))))
               (check (bt:wait-on-semaphore observed :timeout 10))
               (when failure (error failure))
               (check (gethash "busy" value))
               (check (gethash "blocked" value))
               (check (equal which (gethash "busyLock" value)))
               (check (not (nth-value 1 (gethash "applied" value))))
               (check (not (nth-value 1 (gethash "term" value))))
               (check (bt:thread-alive-p owner)))
          (bt:signal-semaphore release)
          (bt:join-thread owner)
          (when observer (bt:join-thread observer)))))
    (let ((value (compaction-native-try-sample
                  member store (lambda ()
                                 (check (sb-thread:holding-mutex-p member))
                                 (check (sb-thread:holding-mutex-p store))
                                 (gr8s.resources::core-object "busy" nil "applied" 17)))))
      (check (= 17 (gethash "applied" value))))
    (handler-case (compaction-native-try-sample member store (lambda () (error "Expected")))
      (simple-error () (check t)))
    (check (eq :left (catch 'leave
                       (compaction-native-try-sample member store (lambda () (throw 'leave :left))))))
    (check (eq :fresh (compaction-native-try-sample member store (constantly :fresh))))
    (format t "~&OBSERVATION-CHECKS-PASSED ~D~%" checks)))
