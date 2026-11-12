(in-package #:gr8s/tests)

(in-suite gr8s)

(defun websocket-roundtrip (payload &key masked-p (opcode 2))
  (let ((path (merge-pathnames
               (format nil "gr8s-websocket-~A.bin" (gr8s.store::generate-uid))
               #P"/tmp/")))
    (unwind-protect
         (progn
           (with-open-file (output path :direction :output
                                        :if-exists :supersede
                                        :element-type '(unsigned-byte 8))
             (gr8s.protocol::write-websocket-frame
              output opcode payload :masked-p masked-p))
           (with-open-file (input path :direction :input
                                      :element-type '(unsigned-byte 8))
             (gr8s.protocol::read-websocket-frame input)))
      (ignore-errors (delete-file path)))))

(test websocket-frames-roundtrip-short-extended-and-masked-payloads
  (dolist (size '(0 5 126 1024 65536))
    (let ((payload
            (make-array size :element-type '(unsigned-byte 8)
                             :initial-contents
                             (loop for index below size collect (mod index 251)))))
      (multiple-value-bind (opcode decoded fin-p)
          (websocket-roundtrip payload :masked-p (oddp size))
        (is (= 2 opcode))
        (is-true fin-p)
        (is (equalp payload decoded))))))

(test websocket-close-frame-roundtrips
  (multiple-value-bind (opcode payload fin-p)
      (websocket-roundtrip
       (make-array 0 :element-type '(unsigned-byte 8)) :opcode 8)
    (is (= 8 opcode))
    (is-true fin-p)
    (is (zerop (length payload)))))
