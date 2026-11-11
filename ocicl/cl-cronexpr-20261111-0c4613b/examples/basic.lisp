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

(asdf:load-system "cl-cronexpr")

(let* ((schedule (cl-cronexpr:parse-cron "30 9 * * mon-fri"))
       (zone (cl-cronexpr:load-cron-zone "America/Toronto"))
       (after (encode-universal-time 0 0 12 10 11 2026 0))
       (next (cl-cronexpr:next-cron-time schedule after zone)))
  (format t "next weekday run: ~A~%"
          (cl-cronexpr:format-cron-time next zone)))
