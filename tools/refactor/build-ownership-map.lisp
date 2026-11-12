;;;; Build the authoritative symbol-ownership map for the gr8s package refactor.
;;;; Run: sbcl --non-interactive --load tools/refactor/build-ownership-map.lisp
;;;; Emits (under tools/refactor/):
;;;;   gr8s-owners.sexp   -- ((NAME OWNER-PKG STATUS) ...) for every symbol
;;;;                         accessible in GR8S. STATUS is :CLEAN (homed in a
;;;;                         module/library) or :NEEDS-HOME (homed in GR8S).
;;;;   gr8s-exports.sexp  -- ((PKG NAME ...) ...) real definitions homed in
;;;;                         each GR8S.* module (the frozen public surface).

(require :asdf)
(asdf:load-system "gr8s")

(defun real-definition-p (s)
  (or (fboundp s) (boundp s) (find-class s nil)
      (and (fboundp 'sb-ext:defined-type-name-p)
           (funcall 'sb-ext:defined-type-name-p s))
      (macro-function s)))

(let* ((gr8s (find-package "GR8S"))
       (cl   (find-package "CL"))
       (kw   (find-package "KEYWORD"))
       (rows '())
       (junk '()))
  (do-symbols (s gr8s)
    (let ((home (symbol-package s)))
      (cond
        ((or (null home) (eq home cl) (eq home kw)))
        ((not (eq home gr8s))
         (push (list (symbol-name s) (package-name home) :clean) rows))
        ((real-definition-p s)
         (push (list (symbol-name s) "GR8S" :needs-home) rows))
        (t (push (symbol-name s) junk)))))
  (setf rows (sort (remove-duplicates rows :test #'equal)
                   #'string< :key #'first))
  (with-open-file (f "tools/refactor/gr8s-owners.sexp" :direction :output
                     :if-exists :supersede :if-does-not-exist :create)
    (let ((*package* kw)) (print rows f)))
  (format t "~%owners: ~D rows (~D needs-home, ~D junk-skipped)~%"
          (length rows)
          (count :needs-home rows :key #'third)
          (length junk)))

;; Per-module frozen export surface: real defs homed in each GR8S.* package.
(let ((modules '())
      (result '()))
  (dolist (p (list-all-packages))
    (let ((name (package-name p)))
      (when (and (>= (length name) 5) (string= "GR8S." name :end2 5))
        (push p modules))))
  (dolist (p (sort modules #'string< :key #'package-name))
    (let (names)
      (do-symbols (s p)
        (when (and (eq (symbol-package s) p) (real-definition-p s))
          (push (symbol-name s) names)))
      (push (cons (package-name p)
                  (sort (remove-duplicates names :test #'equal) #'string<))
            result)))
  (with-open-file (f "tools/refactor/gr8s-exports.sexp" :direction :output
                     :if-exists :supersede :if-does-not-exist :create)
    (let ((*package* (find-package "KEYWORD"))) (print (nreverse result) f)))
  (format t "module export snapshots: ~D packages~%" (length result)))

(format t "~%OWNERSHIP-MAP-DONE~%")
