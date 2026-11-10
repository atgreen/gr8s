;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Make memory visible. A server logs its heap and what its watch histories hold
;;;; once a minute, warns when the heap nears its limit, and says plainly why it
;;;; stops when the heap runs out, rather than leaving only a raw backtrace.

(in-package #:gr8s.server)

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

(defun memory-metrics-text (&optional store)
  "Render process-local Lisp memory and retained watch histories without collecting.
Use the raw store mutex: a scrape must neither propose a transaction nor fail
because application access is temporarily gated during snapshot publication."
  (let ((histories
          (when store
            (bt:with-lock-held ((pod-store-lock store))
              (list (list "pods" (pod-store-pod-watch-journal-length store)
                          (pod-store-pod-watch-journal-bytes store))
                    (list "resources" (length (pod-store-template-history store))
                          (reduce #'+ (pod-store-template-history store) :key #'template-history-entry-bytes))
                    (list "nodes" (pod-store-node-watch-journal-length store)
                          (pod-store-node-watch-journal-bytes store)))))))
    (with-output-to-string (out)
      (flet ((emit (name help type value)
               (gr8s.kubelet::write-prometheus-family out name help type (list (list nil value)))))
        (emit "gr8s_lisp_allocated_bytes_total" "Bytes allocated by Lisp since process startup." "counter"
              (sb-ext:get-bytes-consed))
        (emit "gr8s_lisp_gc_cpu_seconds_total" "CPU time spent in Lisp garbage collection since process startup." "counter"
              (/ sb-ext:*gc-run-time* internal-time-units-per-second 1d0))
        (when (plusp *heap-after-gc*)
          (emit "gr8s_lisp_heap_after_gc_bytes" "Dynamic heap usage after the latest observed garbage collection." "gauge"
                *heap-after-gc*))
        (emit "gr8s_lisp_heap_limit_bytes" "Lisp dynamic heap limit; excludes native allocations and thread stacks." "gauge"
              (sb-ext:dynamic-space-size))
        (emit "gr8s_lisp_heap_used_bytes" "Current Lisp dynamic heap usage, including uncollected garbage." "gauge"
              (sb-kernel:dynamic-usage)))
      (dolist (family '(("gr8s_watch_history_bytes" "Estimated retained watch-history bytes, including allocation overhead." 2)
                        ("gr8s_watch_history_entries" "Retained watch-history entries." 1)))
        (gr8s.kubelet::write-prometheus-family
         out (first family) (second family) "gauge"
         (loop for history in histories
               collect (list (list (cons "kind" (first history))) (nth (third family) history))))))))

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
