(require :asdf)

(let ((root (uiop:pathname-directory-pathname
             (uiop:pathname-parent-directory-pathname *load-pathname*))))
  (asdf:load-system :ag-proto-cli)
  ;; Protocol generation needs only the destination packages. Loading the
  ;; public GR8S facade here would also require every subsystem package that it
  ;; imports, making this standalone build step depend on the application load
  ;; order.
  (load (merge-pathnames "src/generated/package.lisp" root))
  (loop for (source output package) in '(("proto/csi-v1.proto" "src/generated/csi-v1-generated.lisp" "GR8S.CSI.V1")
                                         ("proto/pluginregistration-v1.proto" "src/generated/pluginregistration-v1-generated.lisp"
                                          "GR8S.PLUGINREGISTRATION.V1")
                                         ("proto/dra-v1.proto" "src/generated/dra-v1-generated.lisp" "GR8S.DRA.V1"))
        do (funcall (find-symbol "COMPILE-PROTO-TO-LISP" "AG-PROTO-CLI")
                    (merge-pathnames source root)
                    :output-file (merge-pathnames output root) :package package)))
