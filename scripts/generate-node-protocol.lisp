(require :asdf)

(let* ((root (uiop:pathname-directory-pathname
              (uiop:pathname-parent-directory-pathname *load-pathname*)))
       (source (merge-pathnames "proto/gr8s/node/v1/node.proto" root))
       (output (or (uiop:getenv "GR8S_NODE_PROTOCOL_OUTPUT")
                   (first (uiop:command-line-arguments))
                   (merge-pathnames "src/generated/node-v1-generated.lisp" root))))
  (asdf:load-system :ag-proto-cli)
  (load (merge-pathnames "src/generated/package.lisp" root))
  (funcall (find-symbol "COMPILE-PROTO-TO-LISP" "AG-PROTO-CLI")
           source :output-file output :package "GR8S.NODE.V1"))
