(require :asdf)

(let ((root (uiop:pathname-directory-pathname
             (uiop:pathname-parent-directory-pathname *load-pathname*))))
  (asdf:load-system :ag-proto-cli)
  (load (merge-pathnames "src/package.lisp" root))
  (loop for (source output package) in '(("proto/csi-v1.proto" "src/csi-v1-generated.lisp" "GR8S.CSI.V1")
                                         ("proto/pluginregistration-v1.proto" "src/pluginregistration-v1-generated.lisp"
                                          "GR8S.PLUGINREGISTRATION.V1"))
        do (funcall (find-symbol "COMPILE-PROTO-TO-LISP" "AG-PROTO-CLI")
                    (merge-pathnames source root)
                    :output-file (merge-pathnames output root) :package package)))
