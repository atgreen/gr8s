;;;; SPDX-FileCopyrightText: 2026 Anthony Green <green@moxielogic.com>
;;;; SPDX-License-Identifier: MIT

(require "asdf")

(let ((root (uiop:pathname-parent-directory-pathname
             (uiop:pathname-directory-pathname *load-pathname*))))
  (asdf:initialize-source-registry
   `(:source-registry
     (:tree ,root)
     (:tree ,(merge-pathnames "ocicl/" root))
     :inherit-configuration)))

(asdf:load-system "cl-work-queue")

(let ((queue (cl-work-queue:make-work-queue
              :name "demo" :lane-limit (constantly 2)))
      (results nil)
      (lock (bt:make-lock)))
  (dotimes (index 4)
    (let ((input index))
      (cl-work-queue:work-queue-submit
       queue input (if (evenp input) "even" "odd")
       (lambda () (* input input))
       :on-done (lambda (value condition)
                  (declare (ignore condition))
                  (bt:with-lock-held (lock) (push value results))))))
  (cl-work-queue:work-queue-wait queue)
  (cl-work-queue:work-queue-stop queue)
  (format t "completed values: ~{~D~^, ~}~%" (sort results #'<)))
