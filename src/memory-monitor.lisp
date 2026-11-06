;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Make memory visible. A server logs its heap and what its watch histories hold
;;;; once a minute, warns when the heap nears its limit, and says plainly why it
;;;; stops when the heap runs out, rather than leaving only a raw backtrace.

(in-package #:gr8s)

(defparameter *memory-report-interval* 60
  "Seconds between memory reports in the log.")

(defparameter +memory-warning-fraction+ 3/4
  "Warn when the heap left in use by a collection passes this fraction of its limit.")

(defvar *heap-after-gc* 0
  "Bytes of heap in use when the latest garbage collection finished.")

(defvar *memory-hooks-installed* nil
  "True once the collection and heap exhaustion hooks are in place.")

(defun mebibytes (bytes)
  "Return BYTES in whole mebibytes."
  (round bytes (* 1024 1024)))

(defun note-heap-after-gc ()
  "Record the heap left in use by the collection that just finished. It must not cons."
  (setf *heap-after-gc* (sb-kernel:dynamic-usage)))

(defun heap-exhausted-message (condition)
  "Explain CONDITION, a heap exhaustion, in one line."
  (format nil "gr8s FATAL: out of memory in thread ~S: ~A ~D MiB of the ~D MiB heap was in use ~
               (~D MiB after the last collection). gr8s is stopping; start it with ~
               --dynamic-space-size SIZE before its other arguments to give it more."
          (sb-thread:thread-name sb-thread:*current-thread*)
          (remove #\Newline (princ-to-string condition))
          (mebibytes (sb-kernel:dynamic-usage)) (mebibytes (sb-ext:dynamic-space-size))
          (mebibytes *heap-after-gc*)))

(defun install-memory-hooks ()
  "Track the heap after each collection, and log heap exhaustion clearly before the
debugger hook ends the process. The process still ends: after one thread runs out, others
are likely to fail in ways that leave the cluster wrong rather than visibly down."
  (unless *memory-hooks-installed*
    (setf *memory-hooks-installed* t)
    (push #'note-heap-after-gc sb-ext:*after-gc-hooks*)
    (let ((previous sb-ext:*invoke-debugger-hook*))
      (setf sb-ext:*invoke-debugger-hook*
            (lambda (condition hook)
              (when (typep condition 'sb-kernel::heap-exhausted-error)
                (ignore-errors
                 (format *error-output* "~&~A~%" (heap-exhausted-message condition))
                 (finish-output *error-output*)))
              (when previous (funcall previous condition hook)))))))

(defun watch-history-summary (store)
  "Return the entries and approximate bytes of STORE's Pod, resource and Node watch histories."
  (with-store-lock (store)
    (list (list (pod-store-pod-watch-journal-length store) (pod-store-pod-watch-journal-bytes store))
          (list (length (pod-store-template-history store))
                (reduce #'+ (pod-store-template-history store) :key #'template-history-entry-bytes))
          (list (pod-store-node-watch-journal-length store) (pod-store-node-watch-journal-bytes store)))))

(defun memory-report-line (store)
  "Describe the heap and STORE's watch histories in one log line."
  (destructuring-bind ((pods pod-bytes) (resources resource-bytes) (nodes node-bytes))
      (watch-history-summary store)
    (format nil "gr8s memory: ~D MiB of the ~D MiB heap in use, ~D MiB after the last collection; ~
                 watch history: Pods ~D events ~D MiB, resources ~D entries ~D MiB, Nodes ~D events ~D MiB"
            (mebibytes (sb-kernel:dynamic-usage)) (mebibytes (sb-ext:dynamic-space-size))
            (mebibytes *heap-after-gc*) pods (mebibytes pod-bytes) resources (mebibytes resource-bytes)
            nodes (mebibytes node-bytes))))

(defstruct memory-monitor
  "A thread that reports memory until stopped."
  thread
  (stop-requested nil))

(defun start-memory-monitor (store &key (interval *memory-report-interval*))
  "Log a memory report every INTERVAL seconds, and a warning when the heap nears its limit."
  (let ((monitor (make-memory-monitor)))
    (setf (memory-monitor-thread monitor)
          (bt:make-thread
           (lambda ()
             (loop with next = (+ (get-universal-time) interval)
                   until (memory-monitor-stop-requested monitor)
                   do (sleep 0.5)
                      (when (>= (get-universal-time) next)
                        (setf next (+ (get-universal-time) interval))
                        (handler-case
                            (progn
                              (format *error-output* "~A~%" (memory-report-line store))
                              (when (> *heap-after-gc* (* +memory-warning-fraction+ (sb-ext:dynamic-space-size)))
                                (format *error-output* "gr8s WARNING: the heap is nearly full after collection; ~
                                                        gr8s may run out of memory~%"))
                              (finish-output *error-output*))
                          (error (condition)
                            (format *error-output* "gr8s memory report failed: ~A~%" condition))))))
           :name "gr8s memory monitor"))
    monitor))

(defun stop-memory-monitor (monitor)
  "Stop MONITOR and wait for its thread."
  (setf (memory-monitor-stop-requested monitor) t)
  (let ((thread (memory-monitor-thread monitor)))
    (when (and thread (bt:thread-alive-p thread))
      (bt:join-thread thread))))
