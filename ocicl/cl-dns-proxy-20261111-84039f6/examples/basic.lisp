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

(asdf:load-system "cl-dns-proxy")

(let* ((query
         (0conf:make-dns-message
          :id 42 :flags #x0100
          :questions (list (0conf:make-question
                            :name "app.internal"
                            :qtype 0conf:+type-a+
                            :qclass 0conf:+class-in+))))
       (packet (0conf:encode-message query))
       (response
         (cl-dns-proxy:answer-dns-query
          packet
          (lambda (ignored)
            (declare (ignore ignored))
            (error "the local name must not be forwarded"))
          (lambda (question)
            (values
             (list (make-instance '0conf:a-record
                                  :name (0conf:question-name question)
                                  :address #(192 0 2 40) :ttl 30))
             t 0))))
       (answer
         (first (0conf:dns-message-answers
                 (0conf:decode-message response)))))
  (format t "app.internal -> ~{~D~^.~}~%"
          (coerce (0conf:a-address answer) 'list)))
