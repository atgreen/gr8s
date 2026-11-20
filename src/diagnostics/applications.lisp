;;;; SPDX-License-Identifier: MIT
(in-package #:gr8s-diagnose)

;;; The facts behind rules/applications.pl, which holds what the doctor knows
;;; about particular programs.

(defvar *known-applications* nil)

(defun known-applications ()
  "Each known program as (image-prefix command label-prefix name)."
  (or *known-applications*
      (setf *known-applications*
            (known '(known_application ?image ?command ?labels ?name) '(?image ?command ?labels ?name)))))

(defun container-application (container)
  "The known application a container's image names, if any."
  (let* ((image (or (field container "image") ""))
         (name (subseq image (1+ (or (position #\/ image :from-end t) -1)))))
    (find-if (lambda (application) (uiop:string-prefix-p (first application) name)) (known-applications))))

(defun status-table (text)
  "Key and value of each line of a two-column status listing."
  (loop for line in (uiop:split-string (or text "") :separator '(#\Newline))
        for gap = (search "  " line)
        for value = (and gap (string-trim " " (subseq line gap)))
        when (and gap (plusp gap) (plusp (length value)))
          collect (cons (subseq line 0 gap) value)))

(defun application-findings (pod namespace findings)
  "Findings that say what a known application's own report means. FINDINGS are
the Pod's findings so far; one that quotes a probe supplies the report."
  (let ((facts nil) (sources (make-hash-table :test #'equal)))
    (dolist (finding findings)
      (let* ((name (gethash "container" finding))
             (container (find name (or (field pod "spec" "containers") #()) :test #'equal
                              :key (lambda (c) (field c "name"))))
             (application (and container (gethash "detail" finding) (container-application container))))
        (when (and application (not (gethash name sources)))
          (setf (gethash name sources) finding)
          (push (list 'runs name (fourth application) (second application)) facts)
          (loop for (key . value) in (status-table (gethash "detail" finding))
                do (push (list 'reports name key value) facts)))))
    (loop for (code container name command)
            in (prove facts '((application_finding ?code ?container ?name ?command)) '(?code ?container ?name ?command))
          for (summary step arguments)
            = (first (known `(remedy ,code ?summary ?step ?arguments) '(?summary ?step ?arguments)))
          for source = (gethash container sources)
          collect (object "code" code "rule" code "severity" "warning" "container" container
                          "since" (gethash "since" source)
                          "summary" (format nil summary (field pod "metadata" "name") name container)
                          "detailHeading" (gethash "detailHeading" source) "detail" (gethash "detail" source)
                          "nextStep" step
                          "commands" (map 'vector
                                          (lambda (argument)
                                            (format nil "kubectl -n ~A exec -ti ~A -c ~A -- ~A ~A" namespace
                                                    (field pod "metadata" "name") container command argument))
                                          arguments)
                          "evidence" (gethash "evidence" source)))))

(defun configuration-mentions-p (pod configmaps word)
  "Whether a plain environment value or a mounted ConfigMap's data mentions WORD."
  (flet ((mentions (text) (and (stringp text) (search word text))))
    (or (loop for container across (or (field pod "spec" "containers") #())
                thereis (loop for variable across (or (field container "env") #())
                                thereis (mentions (field variable "value"))))
        (loop for configmap in configmaps
                thereis (and (hash-table-p (field configmap "data"))
                             (loop for text being the hash-values of (field configmap "data")
                                     thereis (mentions text)))))))
