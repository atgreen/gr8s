(require :asdf)
(asdf:load-system :ag-proto-cli)
(load "src/generated/package.lisp")
(uiop:symbol-call :ag-proto-cli :compile-proto-to-lisp
 #P"proto/deviceplugin-v1beta1.proto"
 :output-file #P"src/generated/deviceplugin-v1beta1-generated.lisp"
 :package "GR8S.DEVICEPLUGIN.V1BETA1")
