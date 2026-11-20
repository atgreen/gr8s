;;;; SPDX-License-Identifier: MIT
(in-package #:gr8s-diagnose)

;;; A report is written as Markdown and rendered for whoever reads it: styled
;;; and wrapped to the terminal's width, or plain and unwrapped for a pipe, so
;;; that a phrase can still be searched for. cl-commonmark parses the Markdown;
;;; tuition measures, wraps and styles the text.

(defun markdown-text (text)
  "TEXT from the API as Markdown that renders as exactly that text."
  (let ((text (string-left-trim " " (safe-text text))))
    (with-output-to-string (out)
      (loop for character across text for index from 0
            do (when (or (find character "\\`*_[]<&")
                         ;; What would start a heading, a quote or a list at the start of a block.
                         (and (zerop index) (find character "#>+-="))
                         (and (plusp index) (find character ".)")
                              (every #'digit-char-p (subseq text 0 index))))
                 (write-char #\\ out))
               (write-char character out)))))

(defun markdown-block (lines &optional (info ""))
  "LINES as a fenced block that no line of theirs can close. INFO sh marks
commands, which are rendered unbroken so that they can be pasted."
  (let* ((lines (mapcar #'safe-text lines))
         (longest (let ((run 0) (longest 0))
                    (dolist (line lines longest)
                      (setf run 0)
                      (loop for character across line
                            do (setf run (if (char= character #\`) (1+ run) 0)
                                     longest (max longest run))))))
         (fence (make-string (max 3 (1+ longest)) :initial-element #\`)))
    (format nil "~A~A~%~{~A~%~}~A~%" fence info lines fence)))

(defvar *page-color* nil "Whether the page being rendered may use terminal styles.")

(defun styled (text &rest style)
  (if (and *page-color* (plusp (length text)))
      (tuition:render-styled (apply #'tuition:make-style style) text)
      text))

(defun wrapped (text width &rest options)
  "TEXT as lines no wider than WIDTH; WIDTH NIL breaks only where TEXT does."
  (uiop:split-string (if width (apply #'tuition:wrap-text text (max 20 width) options) text)
                     :separator '(#\Newline)))

(defgeneric inline-text (node)
  (:documentation "The text of an inline node, styled.")
  (:method ((node cl-commonmark:node)) "")
  (:method ((node cl-commonmark:leaf-node)) (cl-commonmark:node-literal node))
  (:method ((node cl-commonmark:container-node))
    (format nil "~{~A~}" (mapcar #'inline-text (cl-commonmark:node-children node))))
  (:method ((node cl-commonmark:soft-break)) " ")
  (:method ((node cl-commonmark:hard-break)) (string #\Newline))
  (:method ((node cl-commonmark:code-span))
    ;; Without styles the marks are what sets a command apart from the sentence.
    (if *page-color*
        (styled (cl-commonmark:node-literal node) :foreground tuition:*fg-yellow*)
        (format nil "`~A`" (cl-commonmark:node-literal node))))
  (:method ((node cl-commonmark:strong)) (styled (call-next-method) :bold t))
  (:method ((node cl-commonmark:emph)) (styled (call-next-method) :faint t))
  (:method ((node cl-commonmark:link))
    (format nil "~A (~A)" (call-next-method) (cl-commonmark:link-destination node))))

(defun blocks-lines (nodes width &optional tight)
  "The lines of NODES, with an empty line between blocks unless TIGHT."
  (loop for (node . more) on nodes
        append (block-lines node width)
        when (and more (not tight)) collect ""))

(defgeneric block-lines (node width)
  (:documentation "The lines of a block node, none wider than WIDTH when it is given.")
  (:method ((node cl-commonmark:node) width) (declare (ignore width)) nil)
  (:method ((node cl-commonmark:container-node) width)
    (blocks-lines (cl-commonmark:node-children node) width))
  (:method ((node cl-commonmark:paragraph) width)
    (wrapped (inline-text node) width))
  (:method ((node cl-commonmark:heading) width)
    ;; Styled a line at a time, so that a style never runs into an indent.
    (mapcar (lambda (line)
              (if (= 1 (cl-commonmark:heading-level node))
                  (styled line :bold t)
                  (styled line :bold t :foreground tuition:*fg-cyan*)))
            (let ((*page-color* nil)) (wrapped (inline-text node) width))))
  (:method ((node cl-commonmark:thematic-break) width)
    (list (make-string (or width 3) :initial-element (if *page-color* #\─ #\-))))
  (:method ((node cl-commonmark:block-quote) width)
    (mapcar (lambda (line) (concatenate 'string (if *page-color* "│ " "> ") line))
            (call-next-method node (and width (- width 2)))))
  (:method ((node cl-commonmark:code-block) width)
    (let ((command (plusp (length (cl-commonmark:code-block-info-string node)))))
      (loop for line in (uiop:split-string (string-right-trim '(#\Newline) (cl-commonmark:node-literal node))
                                           :separator '(#\Newline))
            append (mapcar (lambda (part)
                             (concatenate 'string "    "
                                          (if command
                                              (styled part :foreground tuition:*fg-yellow*)
                                              (styled part :faint t))))
                           (if command
                               (list line)
                               (wrapped line (and width (- width 4)) :break-words t :normalize-spaces nil
                                                                     :continuation-indent 2))))))
  (:method ((node cl-commonmark:list-block) width)
    (loop with tight = (cl-commonmark:list-block-tight-p node)
          for (item . more) on (cl-commonmark:node-children node)
          for number from (or (cl-commonmark:list-block-start node) 1)
          for marker = (cond ((cl-commonmark:list-block-ordered-p node) (format nil "~D. " number))
                             (*page-color* "• ")
                             (t "- "))
          for indent = (make-string (length marker) :initial-element #\Space)
          for body = (or (blocks-lines (cl-commonmark:node-children item) (and width (- width (length marker))) tight)
                         (list ""))
          collect (concatenate 'string marker (first body))
          append (mapcar (lambda (line) (if (string= line "") line (concatenate 'string indent line)))
                         (rest body))
          when (and more (not tight)) collect "")))

(defun render-markdown (markdown &key width color)
  "MARKDOWN as text for a terminal WIDTH columns wide, styled when COLOR."
  (let ((*page-color* color))
    (format nil "~{~A~%~}" (blocks-lines (cl-commonmark:node-children (cl-commonmark:parse-to-ast markdown)) width))))

(defun print-markdown (markdown &key source (stream *standard-output*))
  "Write MARKDOWN to STREAM: as it is when SOURCE, rendered otherwise. A
terminal gets lines wrapped to its width, at most 100 columns, and styles
unless NO_COLOR is set; anything else gets plain, unwrapped text."
  (write-string
   (cond (source markdown)
         ((terminal-p stream)
          (render-markdown markdown
                           :width (min 100 (max 40 (car (tuition:get-terminal-size))))
                           :color (not (plain-terminal-p))))
         (t (render-markdown markdown)))
   stream))
