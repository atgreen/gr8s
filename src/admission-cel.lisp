;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Compile and evaluate the part of CEL that admission webhook matchConditions
;;;; use: the complete expression grammar, static result and operator type checks,
;;;; error-absorbing logic, macros and a bounded evaluation budget. Literals,
;;;; functions or variables outside this subset fail compilation with a clear
;;;; message rather than being accepted and evaluated incorrectly.

(in-package #:gr8s)

(define-condition cel-compile-error (error)
  ((message :initarg :message :reader cel-error-message))
  (:report (lambda (condition stream) (write-string (cel-error-message condition) stream)))
  (:documentation "An expression that is malformed, mistyped or outside the supported subset."))

(define-condition cel-evaluation-error (error)
  ((message :initarg :message :reader cel-error-message))
  (:report (lambda (condition stream) (write-string (cel-error-message condition) stream)))
  (:documentation "A runtime CEL error, which logical operators may absorb."))

(defparameter +cel-maximum-expression-length+ 100000
  "Largest expression accepted, matching the upstream parser's code point limit.")

(defparameter +cel-maximum-nesting+ 64
  "Deepest accepted expression nesting, bounding parser and evaluator recursion.")

(defparameter +cel-evaluation-budget+ 1000000
  "Evaluation steps one expression may use before it fails instead of running on.")

(defvar *cel-remaining-steps* 0
  "Steps left for the expression being evaluated.")

(defun cel-syntax-error (position control &rest arguments)
  "Signal a compile error at the zero-based POSITION of the expression."
  (error 'cel-compile-error
         :message (format nil "ERROR: <input>:1:~D: Syntax error: ~?" (1+ position) control arguments)))

(defun cel-check-error (control &rest arguments)
  "Signal a type or support error found after parsing."
  (error 'cel-compile-error :message (format nil "ERROR: <input>: ~?" control arguments)))

(defun cel-fail (control &rest arguments)
  "Signal a runtime evaluation error."
  (error 'cel-evaluation-error :message (format nil "~?" control arguments)))

;;; Lexer

(defparameter +cel-reserved-words+
  '("as" "break" "const" "continue" "else" "for" "function" "if" "import" "let" "loop"
    "package" "namespace" "return" "var" "void" "while")
  "Identifiers the CEL grammar reserves.")

(defun cel-identifier-start-p (character)
  "Match the first character of a CEL identifier."
  (or (char<= #\a character #\z) (char<= #\A character #\Z) (char= character #\_)))

(defun cel-identifier-part-p (character)
  "Match a later character of a CEL identifier."
  (or (cel-identifier-start-p character) (char<= #\0 character #\9)))

(defun cel-read-escape (text position)
  "Decode the escape after a backslash at POSITION, returning a character and the next position."
  (when (>= (1+ position) (length text)) (cel-syntax-error position "unterminated escape"))
  (let* ((start (1+ position)) (character (char text start)))
    (flet ((code (digits radix from)
             (let ((end (+ from digits)))
               (unless (and (<= end (length text))
                            (every (lambda (digit) (digit-char-p digit radix)) (subseq text from end)))
                 (cel-syntax-error position "invalid escape"))
               (let ((value (parse-integer text :start from :end end :radix radix)))
                 (unless (and (< value char-code-limit) (not (<= #xD800 value #xDFFF)))
                   (cel-syntax-error position "invalid escape"))
                 (values (code-char value) end)))))
      (case character
        (#\a (values (code-char 7) (1+ start))) (#\b (values (code-char 8) (1+ start)))
        (#\f (values (code-char 12) (1+ start))) (#\n (values (code-char 10) (1+ start)))
        (#\r (values (code-char 13) (1+ start))) (#\t (values (code-char 9) (1+ start)))
        (#\v (values (code-char 11) (1+ start)))
        ((#\\ #\' #\" #\`) (values character (1+ start)))
        ((#\x #\X) (code 2 16 (1+ start)))
        (#\u (code 4 16 (1+ start)))
        (#\U (code 8 16 (1+ start)))
        (t (if (char<= #\0 character #\3)
               (code 3 8 start)
               (cel-syntax-error position "invalid escape")))))))

(defun cel-read-string (text position)
  "Read a string literal at POSITION, handling raw and triple-quoted forms."
  (let* ((raw (char-equal (char text position) #\r))
         (open (if raw (1+ position) position))
         (quote-character (char text open))
         (triple (and (< (+ open 2) (length text))
                      (char= quote-character (char text (+ open 1)) (char text (+ open 2)))))
         (cursor (+ open (if triple 3 1))))
    (values
     (with-output-to-string (out)
       (loop
         (when (>= cursor (length text)) (cel-syntax-error position "unterminated string"))
         (let ((character (char text cursor)))
           (cond
             ((and triple (char= character quote-character) (< (+ cursor 2) (length text))
                   (char= quote-character (char text (+ cursor 1)) (char text (+ cursor 2))))
              (incf cursor 3) (return))
             ((and (not triple) (char= character quote-character)) (incf cursor) (return))
             ((and (not triple) (member character '(#\Newline #\Return)))
              (cel-syntax-error position "newline in string"))
             ((and (char= character #\\) (not raw))
              (multiple-value-bind (decoded next) (cel-read-escape text cursor)
                (write-char decoded out) (setf cursor next)))
             (t (write-char character out) (incf cursor))))))
     cursor)))

(defun cel-read-number (text position)
  "Read an int or double literal at POSITION, refusing the unsupported uint form."
  (let ((cursor position) (size (length text)) (double nil))
    (flet ((digits ()
             (loop while (and (< cursor size) (digit-char-p (char text cursor))) do (incf cursor))))
      (when (and (< (1+ position) size) (char= (char text position) #\0)
                 (char-equal (char text (1+ position)) #\x))
        (setf cursor (+ position 2))
        (loop while (and (< cursor size) (digit-char-p (char text cursor) 16)) do (incf cursor))
        (when (= cursor (+ position 2)) (cel-syntax-error position "invalid hexadecimal literal"))
        (when (and (< cursor size) (char-equal (char text cursor) #\u))
          (cel-check-error "uint literals are not supported"))
        (return-from cel-read-number
          (values (parse-integer text :start (+ position 2) :end cursor :radix 16) cursor :int)))
      (digits)
      (when (and (< (1+ cursor) size) (char= (char text cursor) #\.) (digit-char-p (char text (1+ cursor))))
        (setf double t) (incf cursor) (digits))
      (when (and (< cursor size) (char-equal (char text cursor) #\e))
        (let ((mark cursor))
          (incf cursor)
          (when (and (< cursor size) (find (char text cursor) "+-")) (incf cursor))
          (if (and (< cursor size) (digit-char-p (char text cursor)))
              (progn (setf double t) (digits))
              (setf cursor mark))))
      (when (and (not double) (< cursor size) (char-equal (char text cursor) #\u))
        (cel-check-error "uint literals are not supported"))
      (if double
          (let ((value (let ((*read-default-float-format* 'double-float) (*read-eval* nil))
                         (handler-case (read-from-string (subseq text position cursor))
                           (error () (cel-syntax-error position "invalid floating-point literal"))))))
            (values (coerce value 'double-float) cursor :double))
          (values (parse-integer text :start position :end cursor) cursor :int)))))

(defun cel-tokenize (text)
  "Split TEXT into a vector of (type value position) tokens."
  (let ((tokens (make-array 16 :adjustable t :fill-pointer 0)) (cursor 0) (size (length text)))
    (flet ((token (type value position) (vector-push-extend (list type value position) tokens)))
      (loop while (< cursor size)
            do (let ((character (char text cursor)))
                 (cond
                   ((member character '(#\Space #\Tab #\Newline #\Return #\Page)) (incf cursor))
                   ((and (char= character #\/) (< (1+ cursor) size) (char= (char text (1+ cursor)) #\/))
                    (setf cursor (or (position #\Newline text :start cursor) size)))
                   ((or (member character '(#\' #\"))
                        (and (char-equal character #\r) (< (1+ cursor) size)
                             (member (char text (1+ cursor)) '(#\' #\"))))
                    (multiple-value-bind (value next) (cel-read-string text cursor)
                      (token :string value cursor) (setf cursor next)))
                   ((and (char-equal character #\b) (< (1+ cursor) size)
                         (member (char text (1+ cursor)) '(#\' #\")))
                    (cel-check-error "bytes literals are not supported"))
                   ((or (digit-char-p character)
                        (and (char= character #\.) (< (1+ cursor) size) (digit-char-p (char text (1+ cursor)))))
                    (if (char= character #\.)
                        (multiple-value-bind (value next type)
                            (cel-read-number (concatenate 'string "0" (subseq text cursor)) 0)
                          (token type value cursor) (incf cursor (1- next)))
                        (multiple-value-bind (value next type) (cel-read-number text cursor)
                          (token type value cursor) (setf cursor next))))
                   ((cel-identifier-start-p character)
                    (let* ((end (or (position-if-not #'cel-identifier-part-p text :start cursor) size))
                           (word (subseq text cursor end)))
                      (cond ((equal word "true") (token :bool t cursor))
                            ((equal word "false") (token :bool nil cursor))
                            ((equal word "null") (token :null 'null cursor))
                            ((equal word "in") (token :op "in" cursor))
                            ((member word +cel-reserved-words+ :test #'equal)
                             (cel-syntax-error cursor "reserved identifier: ~A" word))
                            (t (token :identifier word cursor)))
                      (setf cursor end)))
                   (t
                    (let ((operator (find-if (lambda (candidate)
                                               (let ((end (+ cursor (length candidate))))
                                                 (and (<= end size) (string= candidate text :start2 cursor :end2 end))))
                                             '("||" "&&" "==" "!=" "<=" ">=" "<" ">" "+" "-" "*" "/" "%" "!"
                                               "?" ":" "." "," "(" ")" "[" "]" "{" "}"))))
                      (unless operator (cel-syntax-error cursor "token recognition error at: '~A'" character))
                      (token :op operator cursor)
                      (incf cursor (length operator)))))))
      (token :eof nil size))
    tokens))

;;; Parser: nodes are lists headed by a keyword.

(defstruct (cel-parser (:constructor make-cel-parser (tokens)))
  "Mutable cursor over one expression's tokens."
  tokens (position 0) (depth 0))

(defun cel-peek (parser)
  "Return the current token."
  (aref (cel-parser-tokens parser) (cel-parser-position parser)))

(defun cel-operator-p (parser operator)
  "Test whether the current token is OPERATOR."
  (let ((token (cel-peek parser)))
    (and (eq :op (first token)) (equal operator (second token)))))

(defun cel-accept (parser operator)
  "Consume OPERATOR when it is next, returning whether it was."
  (when (cel-operator-p parser operator)
    (incf (cel-parser-position parser))
    t))

(defun cel-expect (parser operator)
  "Consume the required OPERATOR."
  (unless (cel-accept parser operator)
    (cel-syntax-error (third (cel-peek parser)) "expected '~A'" operator)))

(defun cel-next-identifier (parser)
  "Consume and return a required identifier."
  (let ((token (cel-peek parser)))
    (unless (eq :identifier (first token))
      (cel-syntax-error (third token) "expected an identifier"))
    (incf (cel-parser-position parser))
    (second token)))

(defun cel-binary-levels (parser operators next)
  "Parse a left-associative chain of OPERATORS over NEXT."
  (let ((left (funcall next parser)))
    (loop
      (let ((operator (find-if (lambda (candidate) (cel-operator-p parser candidate)) operators)))
        (unless operator (return left))
        (incf (cel-parser-position parser))
        (setf left (list :call (concatenate 'string "_" operator "_") nil (list left (funcall next parser))))))))

(defun cel-parse-expression (parser)
  "Parse Expr, tracking nesting so hostile input cannot exhaust the stack."
  (when (> (incf (cel-parser-depth parser)) +cel-maximum-nesting+)
    (cel-syntax-error (third (cel-peek parser)) "expression nesting exceeds ~D" +cel-maximum-nesting+))
  (prog1
      (let ((condition (cel-parse-or parser)))
        (if (cel-accept parser "?")
            (let ((then (cel-parse-or parser)))
              (cel-expect parser ":")
              (list :cond condition then (cel-parse-expression parser)))
            condition))
    (decf (cel-parser-depth parser))))

(defun cel-parse-or (parser)
  "Parse ConditionalOr."
  (let ((left (cel-parse-and parser)))
    (loop while (cel-accept parser "||")
          do (setf left (list :or left (cel-parse-and parser))))
    left))

(defun cel-parse-and (parser)
  "Parse ConditionalAnd."
  (let ((left (cel-parse-relation parser)))
    (loop while (cel-accept parser "&&")
          do (setf left (list :and left (cel-parse-relation parser))))
    left))

(defun cel-parse-relation (parser)
  "Parse Relation."
  (cel-binary-levels parser '("<=" ">=" "==" "!=" "<" ">" "in") #'cel-parse-addition))

(defun cel-parse-addition (parser)
  "Parse Addition."
  (cel-binary-levels parser '("+" "-") #'cel-parse-multiplication))

(defun cel-parse-multiplication (parser)
  "Parse Multiplication."
  (cel-binary-levels parser '("*" "/" "%") #'cel-parse-unary))

(defun cel-parse-unary (parser)
  "Parse Unary, nesting repeated negation."
  (cond ((cel-accept parser "!") (list :call "!_" nil (list (cel-parse-unary parser))))
        ((cel-accept parser "-") (cel-negate (cel-parse-unary parser)))
        (t (cel-parse-member parser))))

(defun cel-negate (operand)
  "Fold negated number literals so the smallest int64 stays expressible."
  (if (and (eq :lit (first operand)) (member (third operand) '(:int :double)))
      (list :lit (- (second operand)) (third operand))
      (list :call "-_" nil (list operand))))

(defun cel-parse-arguments (parser)
  "Parse a call's arguments after its opening parenthesis."
  (let ((arguments nil))
    (unless (cel-accept parser ")")
      (loop
        (push (cel-parse-expression parser) arguments)
        (unless (cel-accept parser ",")
          (cel-expect parser ")")
          (return))))
    (nreverse arguments)))

(defun cel-comprehension-variable (parser node)
  "Require a macro's iteration variable to be a simple identifier."
  (unless (eq :ident (first node))
    (cel-syntax-error (third (cel-peek parser)) "argument must be a simple name"))
  (second node))

(defun cel-expand-method (parser target name arguments)
  "Expand comprehension macros, leaving ordinary method calls alone."
  (let ((count (length arguments)))
    (cond
      ((and (member name '("all" "exists" "exists_one" "filter") :test #'equal) (= count 2))
       (list :comprehension (intern (string-upcase name) :keyword) target
             (cel-comprehension-variable parser (first arguments)) (second arguments) nil))
      ((and (equal name "map") (= count 2))
       (list :comprehension :map target (cel-comprehension-variable parser (first arguments)) (second arguments) nil))
      ((and (equal name "map") (= count 3))
       (list :comprehension :map target (cel-comprehension-variable parser (first arguments))
             (third arguments) (second arguments)))
      (t (list :call name target arguments)))))

(defun cel-parse-member (parser)
  "Parse Member: selections, indexes and method calls on a Primary."
  (let ((node (cel-parse-primary parser)))
    (loop
      (cond
        ((cel-accept parser ".")
         (let ((name (cel-next-identifier parser)))
           (setf node (if (cel-accept parser "(")
                          (cel-expand-method parser node name (cel-parse-arguments parser))
                          (list :select node name)))))
        ((cel-accept parser "[")
         (let ((index (cel-parse-expression parser)))
           (cel-expect parser "]")
           (setf node (list :index node index))))
        ((cel-operator-p parser "{")
         (cel-check-error "message construction is not supported"))
        (t (return node))))))

(defun cel-parse-primary (parser)
  "Parse Primary: literals, identifiers, global calls, groups, lists and maps."
  (let* ((token (cel-peek parser)) (type (first token)) (value (second token)))
    (case type
      ((:int :double :string :bool :null)
       (incf (cel-parser-position parser))
       (when (and (eq type :int) (> value 9223372036854775808))
         (cel-syntax-error (third token) "integer literal is out of range"))
       (list :lit value type))
      (:identifier
       (incf (cel-parser-position parser))
       (if (cel-accept parser "(")
           (cel-expand-global parser value (cel-parse-arguments parser))
           (list :ident value)))
      (:op
       (cond
         ((cel-accept parser ".") (list :ident (cel-next-identifier parser)))
         ((cel-accept parser "(")
          (let ((inner (cel-parse-expression parser)))
            (cel-expect parser ")")
            inner))
         ((cel-accept parser "[") (list :list (cel-parse-elements parser "]")))
         ((cel-accept parser "{") (list :map (cel-parse-map parser)))
         (t (cel-syntax-error (third token) "mismatched input '~A'" value))))
      (t (cel-syntax-error (third token) "unexpected end of expression")))))

(defun cel-expand-global (parser name arguments)
  "Expand the has macro, leaving ordinary global calls alone."
  (if (equal name "has")
      (let ((selection (first arguments)))
        (unless (and (= 1 (length arguments)) (eq :select (first selection)))
          (cel-syntax-error (third (cel-peek parser)) "invalid argument to has() macro"))
        (list :has (second selection) (third selection)))
      (list :call name nil arguments)))

(defun cel-parse-elements (parser closer)
  "Parse list elements up to CLOSER, allowing a trailing comma."
  (let ((elements nil))
    (loop
      (when (cel-accept parser closer) (return))
      (push (cel-parse-expression parser) elements)
      (unless (cel-accept parser ",")
        (cel-expect parser closer)
        (return)))
    (nreverse elements)))

(defun cel-parse-map (parser)
  "Parse map initializers, allowing a trailing comma."
  (let ((pairs nil))
    (loop
      (when (cel-accept parser "}") (return))
      (let ((key (cel-parse-expression parser)))
        (cel-expect parser ":")
        (push (cons key (cel-parse-expression parser)) pairs))
      (unless (cel-accept parser ",")
        (cel-expect parser "}")
        (return)))
    (nreverse pairs)))

;;; Static checks. Types are :int :double :string :bool :null :list :map or :dyn.

(defparameter +cel-admission-request-fields+
  '("kind" "resource" "subResource" "requestKind" "requestResource" "requestSubResource"
    "name" "namespace" "operation" "userInfo" "dryRun" "options")
  "Fields the upstream admission environment declares on the request variable.")

(defun cel-compatible-p (type &rest accepted)
  "Test a static TYPE against ACCEPTED, where dyn is compatible with everything."
  (or (eq type :dyn) (member type accepted)))

(defun cel-overload-error (name types)
  "Report that no overload of NAME accepts TYPES."
  (cel-check-error "found no matching overload for '~A' applied to (~{~(~A~)~^, ~})" name types))

(defun cel-check-call (name target arguments scope)
  "Return the result type of a call, refusing mistyped and unsupported functions."
  (let* ((types (mapcar (lambda (argument) (cel-check argument scope)) arguments))
         (self (and target (cel-check target scope)))
         (first-type (first types)) (second-type (second types)) (count (length types)))
    (flet ((operands (&rest accepted)
             (unless (and (= 2 count) (apply #'cel-compatible-p first-type accepted)
                          (apply #'cel-compatible-p second-type accepted))
               (cel-overload-error name types)))
           (method-on (receiver &rest parameters)
             (unless (and target (cel-compatible-p self receiver) (= count (length parameters))
                          (every #'cel-compatible-p types parameters))
               (cel-overload-error name (if target (cons self types) types)))))
      (cond
        ((and (null target) (member name '("_==_" "_!=_") :test #'equal))
         (unless (or (eq first-type second-type) (member first-type '(:dyn :null)) (member second-type '(:dyn :null))
                     (and (member first-type '(:int :double)) (member second-type '(:int :double))))
           (cel-overload-error name types))
         :bool)
        ((and (null target) (member name '("_<_" "_<=_" "_>_" "_>=_") :test #'equal))
         (unless (or (and (cel-compatible-p first-type :int :double) (cel-compatible-p second-type :int :double))
                     (and (cel-compatible-p first-type :string) (cel-compatible-p second-type :string))
                     (and (cel-compatible-p first-type :bool) (cel-compatible-p second-type :bool)))
           (cel-overload-error name types))
         :bool)
        ((and (null target) (equal name "_in_"))
         (unless (cel-compatible-p second-type :list :map) (cel-overload-error name types))
         :bool)
        ((and (null target) (equal name "_+_"))
         (unless (or (eq first-type second-type) (eq first-type :dyn) (eq second-type :dyn))
           (cel-overload-error name types))
         (operands :int :double :string :list)
         (if (eq first-type :dyn) second-type first-type))
        ((and (null target) (member name '("_-_" "_*_" "_/_") :test #'equal))
         (unless (or (eq first-type second-type) (eq first-type :dyn) (eq second-type :dyn))
           (cel-overload-error name types))
         (operands :int :double)
         (if (eq first-type :dyn) second-type first-type))
        ((and (null target) (equal name "_%_")) (operands :int) :int)
        ((and (null target) (equal name "-_"))
         (unless (cel-compatible-p first-type :int :double) (cel-overload-error name types))
         first-type)
        ((and (null target) (equal name "!_"))
         (unless (cel-compatible-p first-type :bool) (cel-overload-error name types))
         :bool)
        ((equal name "size")
         (let ((operand (if target self first-type)))
           (unless (and (= count (if target 0 1)) (cel-compatible-p operand :string :list :map))
             (cel-overload-error name types)))
         :int)
        ((member name '("startsWith" "endsWith" "contains") :test #'equal) (method-on :string :string) :bool)
        ((member name '("lowerAscii" "upperAscii" "trim") :test #'equal) (method-on :string) :string)
        ((equal name "split") (method-on :string :string) :list)
        ((equal name "replace") (method-on :string :string :string) :string)
        ((equal name "join")
         (unless (and target (cel-compatible-p self :list) (<= count 1) (every (lambda (type) (cel-compatible-p type :string)) types))
           (cel-overload-error name types))
         :string)
        ((and (null target) (= 1 count) (equal name "int"))
         (unless (cel-compatible-p first-type :int :double :string) (cel-overload-error name types))
         :int)
        ((and (null target) (= 1 count) (equal name "double"))
         (unless (cel-compatible-p first-type :int :double :string) (cel-overload-error name types))
         :double)
        ((and (null target) (= 1 count) (equal name "string"))
         (unless (cel-compatible-p first-type :int :bool :string) (cel-overload-error name types))
         :string)
        ((and (null target) (= 1 count) (equal name "bool"))
         (unless (cel-compatible-p first-type :bool :string) (cel-overload-error name types))
         :bool)
        ((and (null target) (= 1 count) (equal name "dyn")) :dyn)
        ((equal name "matches")
         (cel-check-error "matches is not supported: its RE2 semantics cannot be guaranteed here"))
        (t (cel-check-error "undeclared reference to '~A', or a function gr8s does not support" name))))))

(defun cel-check (node scope)
  "Return NODE's static type, where SCOPE lists macro variables in force."
  (ecase (first node)
    (:lit
     (when (and (eq :int (third node)) (not (typep (second node) '(signed-byte 64))))
       (cel-check-error "integer literal is out of range"))
     (third node))
    (:ident
     (let ((name (second node)))
       (cond ((member name scope :test #'equal) :dyn)
             ((member name '("object" "oldObject" "request") :test #'equal) :dyn)
             ((equal name "authorizer") (cel-check-error "the authorizer variable is not supported"))
             (t (cel-check-error "undeclared reference to '~A'" name)))))
    (:select
     (destructuring-bind (operand field) (rest node)
       (when (and (equal '(:ident "request") operand) (not (member "request" scope :test #'equal))
                  (not (member field +cel-admission-request-fields+ :test #'equal)))
         (cel-check-error "undefined field '~A' on request" field))
       (unless (cel-compatible-p (cel-check operand scope) :map)
         (cel-check-error "type does not support field selection: ~A" field))
       :dyn))
    (:has
     (unless (cel-compatible-p (cel-check (second node) scope) :map)
       (cel-check-error "has() requires a map operand"))
     :bool)
    (:index
     (let ((operand (cel-check (second node) scope)) (index (cel-check (third node) scope)))
       (unless (or (eq operand :dyn)
                   (and (eq operand :list) (cel-compatible-p index :int))
                   (and (eq operand :map) (cel-compatible-p index :string)))
         (cel-overload-error "_[_]" (list operand index)))
       :dyn))
    (:call (destructuring-bind (name target arguments) (rest node)
             (cel-check-call name target arguments scope)))
    (:list (dolist (item (second node)) (cel-check item scope)) :list)
    (:map
     (dolist (pair (second node))
       (unless (cel-compatible-p (cel-check (car pair) scope) :string)
         (cel-check-error "map literals support only string keys"))
       (cel-check (cdr pair) scope))
     :map)
    (:cond
     (destructuring-bind (condition then else) (rest node)
       (unless (cel-compatible-p (cel-check condition scope) :bool)
         (cel-overload-error "_?_:_" (list (cel-check condition scope))))
       (let ((left (cel-check then scope)) (right (cel-check else scope)))
         (cond ((eq left right) left)
               ((or (eq left :dyn) (eq right :dyn) (eq left :null) (eq right :null)) :dyn)
               (t (cel-overload-error "_?_:_" (list left right)))))))
    ((:and :or)
     (let ((left (cel-check (second node) scope)) (right (cel-check (third node) scope)))
       (unless (and (cel-compatible-p left :bool) (cel-compatible-p right :bool))
         (cel-overload-error (if (eq :and (first node)) "_&&_" "_||_") (list left right)))
       :bool))
    (:comprehension
     (destructuring-bind (kind iterable variable body predicate) (rest node)
       (unless (cel-compatible-p (cel-check iterable scope) :list :map)
         (cel-check-error "expression of this type cannot be iterated"))
       (let* ((inner (cons variable scope)) (type (cel-check body inner)))
         (when predicate
           (unless (cel-compatible-p (cel-check predicate inner) :bool)
             (cel-check-error "map() predicate must be bool")))
         (ecase kind
           ((:all :exists :exists_one :filter)
            (unless (cel-compatible-p type :bool)
              (cel-check-error "comprehension predicate must be bool"))
            (if (eq kind :filter) :list :bool))
           (:map :list)))))))

(defun compile-cel-condition (expression)
  "Parse and check EXPRESSION, which must have the static result type bool."
  (when (> (length expression) +cel-maximum-expression-length+)
    (cel-check-error "expression exceeds ~D characters" +cel-maximum-expression-length+))
  (let* ((parser (make-cel-parser (cel-tokenize expression)))
         (node (cel-parse-expression parser))
         (token (cel-peek parser)))
    (unless (eq :eof (first token))
      (cel-syntax-error (third token) "extraneous input '~A'" (second token)))
    (let ((type (cel-check node nil)))
      (unless (eq type :bool)
        (cel-check-error "must evaluate to bool, found ~(~A~)" type)))
    node))

;;; Evaluation

(defun cel-list-p (value)
  "Recognize a CEL list, which JSON decoding represents as a non-string vector."
  (and (vectorp value) (not (stringp value))))

(defun cel-bool-p (value)
  "Recognize a CEL bool, which JSON decoding represents as T or NIL."
  (or (eq value t) (null value)))

(defun cel-int64 (value)
  "Return VALUE when it fits int64, or fail as CEL does on overflow."
  (unless (typep value '(signed-byte 64)) (cel-fail "integer overflow"))
  value)

(defun cel-equal (left right)
  "Apply CEL heterogeneous equality."
  (cond ((and (numberp left) (numberp right)) (= left right))
        ((and (stringp left) (stringp right)) (string= left right))
        ((and (cel-list-p left) (cel-list-p right))
         (and (= (length left) (length right)) (every #'cel-equal left right)))
        ((and (hash-table-p left) (hash-table-p right))
         (and (= (hash-table-count left) (hash-table-count right))
              (loop for key being the hash-keys of left using (hash-value value)
                    always (multiple-value-bind (other present) (gethash key right)
                             (and present (cel-equal value other))))))
        ((and (cel-bool-p left) (cel-bool-p right)) (eq left right))
        ((and (eq left 'null) (eq right 'null)) t)
        (t nil)))

(defun cel-compare (name left right)
  "Evaluate an ordering operator, failing on values with no ordering overload."
  (let ((order
          (cond ((and (realp left) (realp right)) (cond ((< left right) -1) ((> left right) 1) (t 0)))
                ((and (stringp left) (stringp right))
                 (cond ((string< left right) -1) ((string> left right) 1) (t 0)))
                ((and (cel-bool-p left) (cel-bool-p right))
                 (cond ((eq left right) 0) (left 1) (t -1)))
                (t (cel-fail "no such overload: ~A" name)))))
    (cond ((equal name "_<_") (< order 0)) ((equal name "_<=_") (<= order 0))
          ((equal name "_>_") (> order 0)) (t (>= order 0)))))

(defun cel-arithmetic (name left right)
  "Evaluate an arithmetic operator with CEL's overflow and zero-division errors."
  (cond
    ((and (integerp left) (integerp right))
     (cel-int64
      (cond ((equal name "_+_") (+ left right)) ((equal name "_-_") (- left right))
            ((equal name "_*_") (* left right))
            ((zerop right) (cel-fail "division by zero"))
            ((equal name "_/_") (truncate left right))
            (t (rem left right)))))
    ((and (floatp left) (floatp right) (not (equal name "_%_")))
     (handler-case
         (cond ((equal name "_+_") (+ left right)) ((equal name "_-_") (- left right))
               ((equal name "_*_") (* left right)) (t (/ left right)))
       (arithmetic-error () (cel-fail "floating-point result is out of range"))))
    ((and (equal name "_+_") (stringp left) (stringp right)) (concatenate 'string left right))
    ((and (equal name "_+_") (cel-list-p left) (cel-list-p right)) (concatenate 'vector left right))
    (t (cel-fail "no such overload: ~A" name))))

(defun cel-require-string (value name)
  "Return VALUE when it is a string, or fail the NAME overload."
  (unless (stringp value) (cel-fail "no such overload: ~A" name))
  value)

(defun cel-split (text separator)
  "Split TEXT on a nonempty SEPARATOR, as a vector of strings."
  (when (zerop (length separator)) (cel-fail "split requires a nonempty separator"))
  (coerce (loop with start = 0
                for found = (search separator text :start2 start)
                collect (subseq text start found)
                while found
                do (setf start (+ found (length separator))))
          'vector))

(defun cel-replace (text old new)
  "Replace every occurrence of a nonempty OLD in TEXT with NEW."
  (when (zerop (length old)) (cel-fail "replace requires a nonempty search string"))
  (with-output-to-string (out)
    (loop with start = 0
          for found = (search old text :start2 start)
          do (write-string text out :start start :end found)
          while found
          do (write-string new out)
             (setf start (+ found (length old))))))

(defun cel-ascii-case (text upcase)
  "Change the case of only the ASCII letters in TEXT."
  (map 'string (lambda (character)
                 (if (< (char-code character) 128)
                     (if upcase (char-upcase character) (char-downcase character))
                     character))
       text))

(defun cel-convert (name value)
  "Evaluate the int, double, string, bool and dyn conversions."
  (cond
    ((equal name "dyn") value)
    ((equal name "int")
     (cond ((integerp value) value)
           ((floatp value)
            (handler-case (cel-int64 (truncate value))
              (arithmetic-error () (cel-fail "integer overflow"))))
           ((and (stringp value) (plusp (length value))
                 (every #'digit-char-p (string-left-trim "-" value))
                 (<= (count #\- value) 1) (> (length value) (count #\- value)))
            (cel-int64 (parse-integer value)))
           (t (cel-fail "type conversion error to int"))))
    ((equal name "double")
     (cond ((floatp value) value)
           ((integerp value) (coerce value 'double-float))
           ((stringp value)
            (handler-case (multiple-value-bind (number next type)
                              (cel-read-number value 0)
                            (declare (ignore type))
                            (unless (= next (length value)) (error "trailing text"))
                            (coerce number 'double-float))
              (error () (cel-fail "type conversion error to double"))))
           (t (cel-fail "type conversion error to double"))))
    ((equal name "string")
     (cond ((stringp value) value)
           ((integerp value) (write-to-string value :base 10 :radix nil))
           ((eq value t) "true")
           ((null value) "false")
           (t (cel-fail "type conversion error to string"))))
    (t
     (cond ((cel-bool-p value) value)
           ((member value '("1" "t" "T" "true" "TRUE" "True") :test #'equal) t)
           ((member value '("0" "f" "F" "false" "FALSE" "False") :test #'equal) nil)
           (t (cel-fail "type conversion error to bool"))))))

(defun cel-apply (name target arguments)
  "Apply an evaluated function to evaluated TARGET and ARGUMENTS."
  (let ((first-argument (first arguments)) (second-argument (second arguments)))
    (cond
      ((equal name "_==_") (cel-equal first-argument second-argument))
      ((equal name "_!=_") (not (cel-equal first-argument second-argument)))
      ((member name '("_<_" "_<=_" "_>_" "_>=_") :test #'equal)
       (cel-compare name first-argument second-argument))
      ((member name '("_+_" "_-_" "_*_" "_/_" "_%_") :test #'equal)
       (cel-arithmetic name first-argument second-argument))
      ((equal name "-_")
       (cond ((integerp first-argument) (cel-int64 (- first-argument)))
             ((floatp first-argument) (- first-argument))
             (t (cel-fail "no such overload: -_"))))
      ((equal name "!_")
       (unless (cel-bool-p first-argument) (cel-fail "no such overload: !_"))
       (not first-argument))
      ((equal name "_in_")
       (cond ((cel-list-p second-argument)
              (and (find first-argument second-argument :test #'cel-equal) t))
             ((hash-table-p second-argument)
              (and (stringp first-argument) (nth-value 1 (gethash first-argument second-argument))))
             (t (cel-fail "no such overload: _in_"))))
      ((equal name "size")
       (let ((operand (if target (first target) first-argument)))
         (cond ((stringp operand) (length operand))
               ((cel-list-p operand) (length operand))
               ((hash-table-p operand) (hash-table-count operand))
               (t (cel-fail "no such overload: size")))))
      ((member name '("int" "double" "string" "bool" "dyn") :test #'equal) (cel-convert name first-argument))
      ((equal name "join")
       (let ((items (first target)) (separator (if arguments (cel-require-string first-argument name) "")))
         (unless (and (cel-list-p items) (every #'stringp items)) (cel-fail "no such overload: join"))
         (with-output-to-string (out)
           (loop for item across items for index from 0
                 do (when (plusp index) (write-string separator out))
                    (write-string item out)))))
      (t
       (let ((text (cel-require-string (first target) name)))
         (cond
           ((equal name "startsWith")
            (let ((prefix (cel-require-string first-argument name)))
              (and (>= (length text) (length prefix)) (string= prefix text :end2 (length prefix)))))
           ((equal name "endsWith")
            (let ((suffix (cel-require-string first-argument name)))
              (and (>= (length text) (length suffix))
                   (string= suffix text :start2 (- (length text) (length suffix))))))
           ((equal name "contains") (and (search (cel-require-string first-argument name) text) t))
           ((equal name "lowerAscii") (cel-ascii-case text nil))
           ((equal name "upperAscii") (cel-ascii-case text t))
           ((equal name "trim")
            (string-trim '(#\Space #\Tab #\Newline #\Return #\Page) text))
           ((equal name "split") (cel-split text (cel-require-string first-argument name)))
           ((equal name "replace")
            (cel-replace text (cel-require-string first-argument name) (cel-require-string second-argument name)))
           (t (cel-fail "no such function: ~A" name))))))))

(defun cel-capture (node bindings)
  "Evaluate NODE, returning its value and any error instead of unwinding."
  (handler-case (values (cel-evaluate node bindings) nil)
    (cel-evaluation-error (condition) (values nil condition))))

(defun cel-logical (absorbing left right bindings name)
  "Evaluate && or ||, where ABSORBING on either side wins over the other side's error."
  (multiple-value-bind (left-value left-error) (cel-capture left bindings)
    (when (and (null left-error) (not (cel-bool-p left-value))) (cel-fail "no such overload: ~A" name))
    (if (and (null left-error) (eq left-value absorbing))
        absorbing
        (multiple-value-bind (right-value right-error) (cel-capture right bindings)
          (when (and (null right-error) (not (cel-bool-p right-value))) (cel-fail "no such overload: ~A" name))
          (cond ((and (null right-error) (eq right-value absorbing)) absorbing)
                (left-error (error left-error))
                (right-error (error right-error))
                (t (not absorbing)))))))

(defun cel-iteration-items (value)
  "List a comprehension's iteration values: list elements or map keys."
  (cond ((cel-list-p value) (coerce value 'list))
        ((hash-table-p value) (loop for key being the hash-keys of value collect key))
        (t (cel-fail "expression of this type cannot be iterated"))))

(defun cel-comprehend (kind items variable body predicate bindings)
  "Evaluate a comprehension macro with its documented error absorption."
  (flet ((truth (item)
           (let ((value (cel-evaluate body (acons variable item bindings))))
             (unless (cel-bool-p value) (cel-fail "comprehension predicate must be bool"))
             value)))
    (ecase kind
      ((:all :exists)
       (let ((absorbing (if (eq kind :all) nil t)) (pending nil))
         (dolist (item items)
           (handler-case
               (when (eq (truth item) absorbing)
                 (return-from cel-comprehend absorbing))
             (cel-evaluation-error (condition) (setf pending (or pending condition)))))
         (when pending (error pending))
         (not absorbing)))
      (:exists_one (= 1 (count-if #'truth items)))
      (:filter (coerce (remove-if-not #'truth items) 'vector))
      (:map
       (coerce (loop for item in items
                     for scope = (acons variable item bindings)
                     when (or (null predicate)
                              (let ((keep (cel-evaluate predicate scope)))
                                (unless (cel-bool-p keep) (cel-fail "map() predicate must be bool"))
                                keep))
                       collect (cel-evaluate body scope))
               'vector)))))

(defun cel-evaluate (node bindings)
  "Evaluate NODE, where BINDINGS is an alist of variables to their values."
  (when (minusp (decf *cel-remaining-steps*))
    (cel-fail "expression evaluation exceeded its ~D step budget" +cel-evaluation-budget+))
  (ecase (first node)
    (:lit (second node))
    (:ident
     (let ((binding (assoc (second node) bindings :test #'equal)))
       (unless binding (cel-fail "no such attribute: ~A" (second node)))
       (cdr binding)))
    (:select
     (let ((operand (cel-evaluate (second node) bindings)))
       (unless (hash-table-p operand) (cel-fail "no such overload: selecting ~A" (third node)))
       (multiple-value-bind (value present) (gethash (third node) operand)
         (unless present (cel-fail "no such key: ~A" (third node)))
         value)))
    (:has
     (let ((operand (cel-evaluate (second node) bindings)))
       (unless (hash-table-p operand) (cel-fail "no such overload: has(~A)" (third node)))
       (and (nth-value 1 (gethash (third node) operand)) t)))
    (:index
     (let ((operand (cel-evaluate (second node) bindings)) (index (cel-evaluate (third node) bindings)))
       (cond ((and (cel-list-p operand) (integerp index))
              (unless (< -1 index (length operand)) (cel-fail "index out of bounds: ~D" index))
              (aref operand index))
             ((and (hash-table-p operand) (stringp index))
              (multiple-value-bind (value present) (gethash index operand)
                (unless present (cel-fail "no such key: ~A" index))
                value))
             (t (cel-fail "no such overload: _[_]")))))
    (:call
     (destructuring-bind (name target arguments) (rest node)
       (cel-apply name
                  (and target (list (cel-evaluate target bindings)))
                  (mapcar (lambda (argument) (cel-evaluate argument bindings)) arguments))))
    (:list (map 'vector (lambda (item) (cel-evaluate item bindings)) (second node)))
    (:map
     (let ((object (make-hash-table :test #'equal)))
       (dolist (pair (second node) object)
         (let ((key (cel-evaluate (car pair) bindings)))
           (unless (stringp key) (cel-fail "map literals support only string keys"))
           (when (nth-value 1 (gethash key object)) (cel-fail "repeated map key: ~A" key))
           (setf (gethash key object) (cel-evaluate (cdr pair) bindings))))))
    (:cond
     (let ((condition (cel-evaluate (second node) bindings)))
       (unless (cel-bool-p condition) (cel-fail "no such overload: _?_:_"))
       (cel-evaluate (if condition (third node) (fourth node)) bindings)))
    (:and (cel-logical nil (second node) (third node) bindings "_&&_"))
    (:or (cel-logical t (second node) (third node) bindings "_||_"))
    (:comprehension
     (destructuring-bind (kind iterable variable body predicate) (rest node)
       (cel-comprehend kind (cel-iteration-items (cel-evaluate iterable bindings))
                       variable body predicate bindings)))))

(defun evaluate-cel-condition (program bindings)
  "Run a compiled PROGRAM under a fresh step budget, signaling on any runtime error."
  (let* ((*cel-remaining-steps* +cel-evaluation-budget+)
         (value (cel-evaluate program bindings)))
    (unless (cel-bool-p value) (cel-fail "expression did not evaluate to bool"))
    value))
