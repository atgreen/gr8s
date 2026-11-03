(require :asdf)

(let* ((script-directory (uiop:pathname-directory-pathname *load-truename*))
       (project-directory (truename (merge-pathnames "../" script-directory))))
  (asdf:initialize-source-registry
   `(:source-registry
     (:tree ,(merge-pathnames "ocicl/" project-directory))
     :inherit-configuration)))

(asdf:load-system :whistler)

(let ((arguments (uiop:command-line-arguments)))
  (unless (= 2 (length arguments))
    (error "usage: sbcl --script build-whistler-program.lisp INPUT OUTPUT"))
  (destructuring-bind (input output) arguments
    (whistler:reset-compilation-state)
    (load input)
    (ensure-directories-exist output)
    (whistler:compile-to-elf output)))
