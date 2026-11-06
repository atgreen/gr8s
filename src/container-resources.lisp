;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Preserve exact Kubernetes CPU/memory quantities, apply ResourceList rounding
;;;; and Pod-only request defaults, and share genuine resource values with CRI
;;;; enforcement and downward resource references. Decimal exponents remain
;;;; symbolic so an oversized declaration cannot allocate an enormous power.

(in-package #:gr8s)

(defstruct container-quantity
  "Represent an exact decimal coefficient times ten to SCALE, retaining its quantity format."
  (coefficient 0) (scale 0) (format :decimal))

(defparameter +container-quantity-decimal-suffixes+
  '(("n" . -9) ("u" . -6) ("m" . -3) ("" . 0) ("k" . 3) ("M" . 6)
    ("G" . 9) ("T" . 12) ("P" . 15) ("E" . 18)))

(defparameter +container-quantity-binary-suffixes+
  '(("Ki" . 10) ("Mi" . 20) ("Gi" . 30) ("Ti" . 40) ("Pi" . 50) ("Ei" . 60)))

(defun normalize-container-quantity (quantity)
  "Remove redundant decimal zeroes without changing the exact amount or its format."
  (let ((coefficient (container-quantity-coefficient quantity)))
    (if (zerop coefficient) (setf (container-quantity-scale quantity) 0)
        (loop while (zerop (mod coefficient 10))
              do (setf coefficient (/ coefficient 10)) (incf (container-quantity-scale quantity))))
    (setf (container-quantity-coefficient quantity) coefficient)
    quantity))

(defun container-quantity-round (quantity scale)
  "Round magnitude away from zero to SCALE, as Kubernetes Quantity.RoundUp does."
  (let ((result (copy-container-quantity quantity)))
    (when (< (container-quantity-scale result) scale)
      (let* ((amount (container-quantity-coefficient result)) (absolute (abs amount))
             (difference (- scale (container-quantity-scale result)))
             (rounded (if (>= difference (length (write-to-string absolute)))
                          (if (zerop absolute) 0 1)
                          (ceiling absolute (expt 10 difference)))))
        (setf (container-quantity-coefficient result) (* (signum amount) rounded)
              (container-quantity-scale result) scale)))
    (normalize-container-quantity result)))

(defun container-quantity-compare (left right)
  "Compare exact scaled quantities without expanding an unbounded exponent."
  (let* ((a (container-quantity-coefficient left)) (b (container-quantity-coefficient right))
         (sign-a (signum a)) (sign-b (signum b)))
    (cond ((< sign-a sign-b) -1) ((> sign-a sign-b) 1) ((zerop a) 0)
          (t
           (let* ((magnitude-a (+ (length (write-to-string (abs a))) (container-quantity-scale left)))
                  (magnitude-b (+ (length (write-to-string (abs b))) (container-quantity-scale right))))
             (* sign-a
                (cond ((< magnitude-a magnitude-b) -1) ((> magnitude-a magnitude-b) 1)
                      (t (let* ((scale (min (container-quantity-scale left) (container-quantity-scale right)))
                                (expanded-a (* (abs a) (expt 10 (- (container-quantity-scale left) scale))))
                                (expanded-b (* (abs b) (expt 10 (- (container-quantity-scale right) scale)))))
                           (cond ((< expanded-a expanded-b) -1) ((> expanded-a expanded-b) 1) (t 0)))))))))))

(defun parse-container-quantity (input &optional (context "container resource quantity"))
  "Decode genuine DecimalSI, BinarySI or decimal-exponent input, rounding nonzero sub-nano amounts up."
  (let ((text (cond ((stringp input) input) ((integerp input) (write-to-string input))
                    ((floatp input) (com.inuoe.jzon:stringify input))
                    (t (invalid-pod "~A must be a quantity string or number" context)))))
    (multiple-value-bind (match groups)
        (cl-ppcre:scan-to-strings "^([+-]?(?:[0-9]+(?:\\.[0-9]*)?|\\.[0-9]+))([eE][+-]?[0-9]+|[A-Za-z]*)$" text)
      (unless match (invalid-pod "Invalid quantity ~S for ~A" text context))
      (let* ((number (aref groups 0)) (suffix (aref groups 1))
             (negative (char= (char number 0) #\-))
             (unsigned (if (find (char number 0) "+-") (subseq number 1) number))
             (dot (position #\. unsigned))
             (coefficient (parse-integer (remove #\. unsigned)))
             (scale (if dot (- (1+ dot) (length unsigned)) 0))
             (decimal (assoc suffix +container-quantity-decimal-suffixes+ :test #'equal))
             (binary (assoc suffix +container-quantity-binary-suffixes+ :test #'equal))
             (format :decimal))
        (cond (decimal (incf scale (cdr decimal)))
              (binary (setf coefficient (ash coefficient (cdr binary)) format :binary))
              ((and (> (length suffix) 1) (find (char suffix 0) "eE"))
               (let ((exponent (parse-integer suffix :start 1)))
                 (unless (<= (- (expt 2 63)) exponent (1- (expt 2 63)))
                   (invalid-pod "Quantity exponent exceeds the upstream integer representation"))
                 (let ((signed (ldb (byte 32 0) exponent)))
                   (incf scale (if (logbitp 31 signed) (- signed (expt 2 32)) signed)))
                 (setf format :exponent)))
              (t (invalid-pod "Invalid quantity suffix ~S for ~A" suffix context)))
        (let* ((quantity (container-quantity-round
                           (make-container-quantity :coefficient coefficient :scale scale :format format) -9))
               (maximum (make-container-quantity :coefficient #x7fffffffffffffff)))
          (when (and binary (plusp (container-quantity-compare quantity maximum)))
            (setf quantity maximum (container-quantity-format quantity) :binary))
          (when negative (setf (container-quantity-coefficient quantity) (- (container-quantity-coefficient quantity))))
          (normalize-container-quantity quantity))))))

(defun container-quantity-integer (quantity &key (scale 0) (maximum #x7fffffffffffffff))
  "Return an away-from-zero scaled integer, rejecting overflow before producing a CRI or kernel value."
  (let* ((rounded (container-quantity-round quantity scale))
         (coefficient (container-quantity-coefficient rounded))
         (shift (- (container-quantity-scale rounded) scale))
         (limit (make-container-quantity :coefficient maximum :scale scale))
         (absolute (copy-container-quantity rounded)))
    (setf (container-quantity-coefficient absolute) (abs coefficient))
    (when (plusp (container-quantity-compare absolute limit))
      (invalid-pod "Resource quantity exceeds the supported runtime integer range"))
    (* coefficient (expt 10 shift))))

(defun container-quantity-string (quantity)
  "Render a semantically canonical quantity without floating point or expanding large exponent notation."
  (let* ((normalized (normalize-container-quantity (copy-container-quantity quantity)))
         (coefficient (container-quantity-coefficient normalized))
         (scale (container-quantity-scale normalized))
         (format (container-quantity-format normalized)))
    (when (zerop coefficient) (return-from container-quantity-string "0"))
    (when (and (eq format :binary) (>= scale 0))
      (let ((number (container-quantity-integer normalized)))
        (when (>= (abs number) 1024)
          (dolist (entry (reverse +container-quantity-binary-suffixes+))
            (when (zerop (mod number (ash 1 (cdr entry))))
              (return-from container-quantity-string (format nil "~D~A" (/ number (ash 1 (cdr entry))) (car entry))))))))
    (if (eq format :exponent)
        (let ((exponent (* 3 (floor scale 3))))
          (format nil "~D~A" (* coefficient (expt 10 (- scale exponent)))
                  (if (zerop exponent) "" (format nil "e~D" exponent))))
        (let ((entry (find-if (lambda (entry) (<= (cdr entry) scale))
                              (reverse +container-quantity-decimal-suffixes+))))
          (format nil "~D~A" (* coefficient (expt 10 (- scale (cdr entry)))) (car entry))))))

(defun extended-resource-name-p (name)
  "Return whether NAME is a domain-qualified extended resource, which only the scheduler accounts."
  (and (stringp name) (position #\/ name) (core-qualified-key-p name)
       (not (uiop:string-prefix-p "kubernetes.io/" name))
       (not (uiop:string-prefix-p "requests." name))))

(defun normalize-container-resources (container &key (default-requests t))
  "Validate compute and extended requirements and round ResourceLists; copy limits to missing requests only for Pods."
  (let ((resources (gethash "resources" container)))
    (unless resources (return-from normalize-container-resources nil))
    (when (eq resources 'null) (remhash "resources" container) (return-from normalize-container-resources nil))
    (reject-unsupported-fields resources '("limits" "requests" "claims") "container.resources")
    (when (and (gethash "claims" resources) (plusp (length (gethash "claims" resources))))
      (invalid-pod "Dynamic resource claims are not implemented"))
    (dolist (kind '("limits" "requests"))
      (let ((values (gethash kind resources)))
        (when (eq values 'null) (remhash kind resources) (setf values nil))
        (when values
          (require-object values (format nil "resources.~A" kind))
          (maphash (lambda (name value)
                     (unless (or (member name '("cpu" "memory" "ephemeral-storage") :test #'equal)
                                 (extended-resource-name-p name))
                       (invalid-pod "Resource ~S has no implemented enforcement" name))
                     (let ((quantity (container-quantity-round (parse-container-quantity value) -3)))
                       (when (minusp (container-quantity-coefficient quantity)) (invalid-pod "Resource quantities must be nonnegative"))
                       (when (and (extended-resource-name-p name) (minusp (container-quantity-scale quantity)))
                         (invalid-pod "Extended resource ~A must be a whole number" name))
                       (setf (gethash name values) (container-quantity-string quantity)))) values))))
    (let ((limits (gethash "limits" resources)) (requests (gethash "requests" resources)))
      (when (and default-requests limits)
        (unless requests (setf requests (make-hash-table :test #'equal) (gethash "requests" resources) requests))
        (maphash (lambda (name value) (unless (nth-value 1 (gethash name requests)) (setf (gethash name requests) value))) limits))
      (when requests
        (maphash (lambda (name value)
                   (when (and limits (nth-value 1 (gethash name limits))
                              (plusp (container-quantity-compare (parse-container-quantity value)
                                        (parse-container-quantity (gethash name limits)))))
                     (invalid-pod "Resource request ~A exceeds its limit" name))
                   ;; Extended resources cannot be overcommitted, as devices have no shares.
                   (when (extended-resource-name-p name)
                     (let ((limit (and limits (gethash name limits))))
                       (unless (and limit (zerop (container-quantity-compare (parse-container-quantity value)
                                                                             (parse-container-quantity limit))))
                         (invalid-pod "Extended resource ~A requires equal request and limit" name)))))
                 requests))
      (when limits
        (maphash (lambda (name value)
                   (declare (ignore value))
                   (when (and (extended-resource-name-p name)
                              (not (and requests (nth-value 1 (gethash name requests)))))
                     (invalid-pod "Extended resource ~A requires equal request and limit" name)))
                 limits)))
    resources))

(defun add-resource-list (totals values)
  "Add quantity strings in the resource list VALUES into the exact rational TOTALS table."
  (when values
    (maphash (lambda (name value)
               (incf (gethash name totals 0)
                     (let ((quantity (parse-container-quantity value)))
                       (* (container-quantity-coefficient quantity) (expt 10 (container-quantity-scale quantity))))))
             values))
  totals)

(defun pod-spec-resource-totals (spec &key (overhead t))
  "Return a Pod's exact effective requests and limits: containers summed, each init container a floor."
  (let ((requests (make-hash-table :test #'equal)) (limits (make-hash-table :test #'equal)))
    (flet ((list-of (container kind)
             (let ((resources (gethash "resources" container)))
               (and resources (gethash kind resources)))))
      (loop for container across (gethash "containers" spec #())
            do (add-resource-list requests (list-of container "requests"))
               (add-resource-list limits (list-of container "limits")))
      (loop for container across (gethash "initContainers" spec #())
            do (loop for (kind totals) in (list (list "requests" requests) (list "limits" limits))
                     do (let ((own (add-resource-list (make-hash-table :test #'equal) (list-of container kind))))
                          (maphash (lambda (name value)
                                     (when (> value (gethash name totals 0)) (setf (gethash name totals) value)))
                                   own)))))
    (when (and overhead (gethash "overhead" spec))
      (add-resource-list requests (gethash "overhead" spec))
      (maphash (lambda (name value)
                 (declare (ignore value))
                 (when (nth-value 1 (gethash name limits))
                   (add-resource-list limits (core-object name (gethash name (gethash "overhead" spec))))))
               (gethash "overhead" spec)))
    (values requests limits)))

(defun container-resource-quantity (container kind name)
  "Return CONTAINER's parsed KIND (limits or requests) quantity for resource NAME, if declared."
  (let* ((resources (gethash "resources" container))
         (values (and resources (gethash kind resources)))
         (value (and values (gethash name values))))
    (when value (parse-container-quantity value))))

(defun container-milli-cpu (quantity)
  "Return QUANTITY in whole millicores, rounding up as Kubernetes does."
  (container-quantity-integer quantity :scale -3))

(defun cri-linux-container-resources (container)
  "Derive actual CFS and memory cgroup settings with the kubelet's formulas.
A container without a CPU request gets the minimum share, as a kubelet gives it."
  (let* ((cpu-limit (container-resource-quantity container "limits" "cpu"))
         (cpu-request (container-resource-quantity container "requests" "cpu"))
         (memory-limit (container-resource-quantity container "limits" "memory"))
         (period 100000))
    (make-instance
     'gr8s.cri.v1::linux-container-resources
     :cpu-period (if cpu-limit period 0)
     :cpu-quota (if cpu-limit (max 1000 (floor (* (container-milli-cpu cpu-limit) period) 1000)) 0)
     ;; 1024 shares is one CPU, and the kernel's minimum is 2.
     :cpu-shares (max 2 (floor (* (if cpu-request (container-milli-cpu cpu-request) 0) 1024) 1000))
     :memory-limit-in-bytes (if memory-limit (container-quantity-integer memory-limit) 0))))
