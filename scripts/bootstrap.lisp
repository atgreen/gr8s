;;;; SPDX-License-Identifier: Apache-2.0
;;;; Resolve source dependencies from this checkout's lock, independently of host ASDF configuration.
(require :asdf)

(let* ((root (uiop:pathname-parent-directory-pathname
              (uiop:pathname-directory-pathname *load-truename*)))
       (locked (make-hash-table :test 'equal)))
  (with-open-file (stream (merge-pathnames "ocicl.csv" root))
    (loop for line = (read-line stream nil) while line do
      (let* ((fields (mapcar (lambda (field) (string-trim '(#\Space #\Tab) field))
                            (uiop:split-string line :separator '(#\,))))
             (relative (third fields)))
        (unless (and (= 3 (length fields)) (plusp (length relative)))
          (error "Invalid dependency lock row: ~S" line))
        ;; OCI names encode characters such as '+'. ASDF names are the ASD basenames.
        (setf (gethash (pathname-name relative) locked)
              (merge-pathnames relative (merge-pathnames "ocicl/" root))))))
  (setf asdf:*central-registry* nil)
  (asdf:initialize-source-registry
   `(:source-registry (:directory ,root) :ignore-inherited-configuration))
  (push (lambda (name)
          (let ((path (gethash name locked)))
            (when path
              ;; The local cl+ssl system deliberately routes users to pure-tls.
              (or (and (equal name "cl+ssl") (probe-file (merge-pathnames "cl+ssl.asd" root)))
                  (probe-file path)
                  (error "Locked dependency ~A is missing at ~A; run ocicl install in ~A"
                         name path root)))))
        asdf:*system-definition-search-functions*))
