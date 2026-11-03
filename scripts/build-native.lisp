(require :asdf)

(asdf:load-asd (truename "gr8s.asd"))
(asdf:load-system :gr8s)
(gr8s::embed-runtime-assets #P"build/containerd/")

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
