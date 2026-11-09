(require :asdf)
(asdf:load-system :ag-proto-cli)
(load "src/generated/package.lisp")
(uiop:symbol-call :ag-proto-cli :compile-proto-to-lisp
 #P"proto/podresources-v1.proto"
 :output-file #P"src/generated/podresources-v1-generated.lisp"
 :package "GR8S.PODRESOURCES.V1")
