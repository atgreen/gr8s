(require :asdf)

(asdf:load-asd (truename "gr8s.asd"))
(asdf:load-system :gr8s)
(gr8s::embed-runtime-assets #P"build/containerd/")

;; Bake the git-augmented version into the image. This build dumps with
;; save-lisp-and-die rather than asdf:program-op, so VERSION-STRING's program-op
;; hook never fires; set +GR8S-VERSION+ here instead, while the git repo is present.
(setf gr8s:+gr8s-version+ (version-string:make-version-string :gr8s :include-git-p t))

(defun gr8s-native-main ()
  (uiop:quit (gr8s:main (uiop:command-line-arguments))))

(ensure-directories-exist #P"build/")

#+sbcl
(sb-ext:save-lisp-and-die
 #P"build/gr8s.bin"
 :toplevel #'gr8s-native-main
 :executable t
 :compression t
 :purify t)

#-sbcl
(error "Native executable builds currently require SBCL")
