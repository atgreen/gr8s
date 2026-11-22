(require :asdf)
(asdf:load-system :ag-proto-cli)
(asdf:load-system :cl-ppcre)
(load "src/generated/package.lisp")
(defparameter *output* #P"src/generated/hubble-observer-v1-generated.lisp")
(uiop:symbol-call :ag-proto-cli :compile-proto-to-lisp
 #P"proto/hubble-observer-v1.proto"
 :output-file *output*
 :package "GR8S.HUBBLE.OBSERVER")
;; ag-proto reads a repeated varint field (an enum or integer list) only one value
;; per tag, but Go and protobuf-ts send them packed, as proto3 requires, which it
;; then misreads (podster-7i1). Read a packed block when the wire type says so.
(let* ((text (uiop:read-file-string *output*))
       (patched (cl-ppcre:regex-replace-all
                 "\\(PUSH\\s+\\(AG-PROTO::READ-VARINT AG-PROTO::BUFFER\\)\\s+\\(SLOT-VALUE AG-PROTO::OBJ '([A-Z0-9-]+)\\)\\)"
                 text
                 "(IF (= AG-PROTO::WIRE-TYPE 2)
                      (LET ((AG-PROTO::PACKED (CONS (AG-PROTO::READ-LENGTH-DELIMITED AG-PROTO::BUFFER) 0)))
                        (LOOP AG-PROTO::WHILE (< (CL:REST AG-PROTO::PACKED) (CL:LENGTH (CL:FIRST AG-PROTO::PACKED)))
                              DO (PUSH (AG-PROTO::READ-VARINT AG-PROTO::PACKED) (SLOT-VALUE AG-PROTO::OBJ '\\1))))
                      (PUSH (AG-PROTO::READ-VARINT AG-PROTO::BUFFER) (SLOT-VALUE AG-PROTO::OBJ '\\1)))")))
  ;; A repeated bool reads the same varints, as booleans.
  (setf patched
        (cl-ppcre:regex-replace-all
         "\\(PUSH\\s+\\(NOT \\(ZEROP \\(AG-PROTO::READ-VARINT AG-PROTO::BUFFER\\)\\)\\)\\s+\\(SLOT-VALUE AG-PROTO::OBJ '([A-Z0-9-]+)\\)\\)"
         patched
         "(IF (= AG-PROTO::WIRE-TYPE 2)
              (LET ((AG-PROTO::PACKED (CONS (AG-PROTO::READ-LENGTH-DELIMITED AG-PROTO::BUFFER) 0)))
                (LOOP AG-PROTO::WHILE (< (CL:REST AG-PROTO::PACKED) (CL:LENGTH (CL:FIRST AG-PROTO::PACKED)))
                      DO (PUSH (NOT (ZEROP (AG-PROTO::READ-VARINT AG-PROTO::PACKED))) (SLOT-VALUE AG-PROTO::OBJ '\\1))))
              (PUSH (NOT (ZEROP (AG-PROTO::READ-VARINT AG-PROTO::BUFFER))) (SLOT-VALUE AG-PROTO::OBJ '\\1)))"))
  (with-open-file (out *output* :direction :output :if-exists :supersede)
    (write-string patched out))
  (format t "~&patched ~D repeated varint fields to accept packed encoding~%"
          (/ (length (cl-ppcre:all-matches "AG-PROTO::PACKED \\(CONS" patched)) 2)))
