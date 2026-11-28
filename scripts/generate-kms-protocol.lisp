(require :asdf)
(asdf:load-system :ag-proto-cli)
(load "src/generated/package.lisp")
(uiop:symbol-call :ag-proto-cli :compile-proto-to-lisp
 #P"proto/kms-v2.proto"
 :output-file #P"src/generated/kms-v2-generated.lisp"
 :package "GR8S.KMS.V2")
