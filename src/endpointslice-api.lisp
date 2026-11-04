;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Validate durable discovery.k8s.io/v1 EndpointSlices against pinned wire and
;;;; structural schemas. Manual slices remain writable independently of Services;
;;;; generated slices are ordinary API objects with exact Service UID ownership.

(in-package #:gr8s)

(defparameter *endpointslice-schema*
  (com.inuoe.jzon:parse (asdf:system-relative-pathname :gr8s "schema/endpointslices-v1.json")))

(eval-when (:load-toplevel :execute)
  (setf *stored-resource-types*
        (append (remove "endpointslices" *stored-resource-types* :key #'first :test #'equal)
                '(("endpointslices" "EndpointSlice" "discovery.k8s.io/v1" t))))
  (dolist (section '("definitions" "messages"))
    (maphash (lambda (name value) (setf (gethash name (gethash section *podtemplate-schema*)) value))
             (gethash section *endpointslice-schema*))))

(defun endpointslice-resource-p (resource)
  "Recognize the stable discovery EndpointSlice collection."
  (equal resource "endpointslices"))

(defun assign-generated-endpointslice-name-unlocked (store input namespace)
  "Allocate a bounded generated name inside the collection's existing transaction."
  (let* ((metadata (require-object (gethash "metadata" input) "metadata"))
         (prefix (pod-generate-name-prefix metadata)))
    (multiple-value-bind (name present) (gethash "name" metadata)
      (when (and present (not (or (stringp name) (eq name 'null))))
        (core-resource-error 422 "Invalid" "metadata.name must be a string"))
      (when (and (member name '(nil null "") :test #'equal) (plusp (length prefix)))
        (loop repeat 8 for candidate = (funcall *pod-name-generator* prefix)
              unless (gethash (core-resource-key "endpointslices" namespace candidate) (pod-store-resources store))
                do (setf (gethash "name" metadata) candidate) (return)
              finally (core-resource-error 409 "AlreadyExists" "Could not allocate a unique EndpointSlice name"))))))

(defun endpointslice-array (object field maximum)
  "Default an optional null array and enforce its actual Kubernetes collection bound."
  (multiple-value-bind (value present) (gethash field object)
    (when (or (not present) (eq value 'null)) (setf value #() (gethash field object) value))
    (unless (and (vectorp value) (not (stringp value)) (<= (length value) maximum))
      (core-resource-error 422 "Invalid" "~A must be an array with at most ~D entries" field maximum))
    value))

(defun endpointslice-address-p (address type)
  "Validate a usable endpoint IP or fully qualified DNS address without resolving it."
  (and (stringp address)
       (handler-case
           (cond ((equal type "FQDN")
                  (let ((name (string-right-trim "." address)))
                    (and (dns-subdomain-p name) (find #\. name))))
                 ((equal type "IPv4")
                  (let ((parts (uiop:split-string address :separator '(#\.))))
                    (and (= 4 (length parts))
                         (every (lambda (part) (and (plusp (length part)) (every #'digit-char-p part)
                                                    (<= (parse-integer part) 255))) parts)
                         (let ((bytes (0conf:parse-ipv4 address)))
                           (and (not (member (aref bytes 0) '(0 127))) (< (aref bytes 0) 224)
                                (not (and (= 169 (aref bytes 0)) (= 254 (aref bytes 1)))))))))
                 ((equal type "IPv6")
                  (let ((bytes (0conf:parse-ipv6 address)))
                    (and (find #\: address) (not (find #\% address))
                         (not (every #'zerop bytes))
                         (not (and (every #'zerop (subseq bytes 0 15)) (= 1 (aref bytes 15))))
                         (not (and (every #'zerop (subseq bytes 0 10)) (= #xff (aref bytes 10)) (= #xff (aref bytes 11))))
                         (/= #xff (aref bytes 0))
                         (not (and (= #xfe (aref bytes 0)) (= #x80 (logand #xc0 (aref bytes 1)))))))))
         (error () nil))))

(defun normalize-endpointslice-resource (input namespace name)
  "Admit complete typed EndpointSlices, preserving manual endpoints and optional conditions."
  (let* ((object (copy-core-object (require-object input "EndpointSlice")))
         (metadata (require-object (gethash "metadata" object) "metadata"))
         (type (gethash "addressType" object)))
    (unless (and (equal "EndpointSlice" (gethash "kind" object "EndpointSlice"))
                 (equal "discovery.k8s.io/v1" (gethash "apiVersion" object "discovery.k8s.io/v1")))
      (core-resource-error 400 "BadRequest" "Expected discovery.k8s.io/v1 EndpointSlice"))
    (validate-core-metadata metadata namespace name)
    (setf (gethash "apiVersion" object) "discovery.k8s.io/v1" (gethash "kind" object) "EndpointSlice"
          (gethash "namespace" metadata) namespace)
    (unless (member type '("IPv4" "IPv6" "FQDN") :test #'equal)
      (core-resource-error 422 "Invalid" "addressType must be IPv4, IPv6 or FQDN"))
    (let ((ports (endpointslice-array object "ports" 20000)) (names (make-hash-table :test #'equal)))
      (loop for port across ports
            for pname = (gethash "name" (require-object port "ports item"))
            do (when (or (not (nth-value 1 (gethash "name" port))) (eq pname 'null))
                 (setf pname "" (gethash "name" port) pname))
               (unless (and (stringp pname) (or (equal pname "") (dns-label-p pname)) (not (gethash pname names)))
                 (core-resource-error 422 "Invalid" "Endpoint port names must be unique DNS labels or empty"))
               (setf (gethash pname names) t)
               (when (or (not (nth-value 1 (gethash "protocol" port))) (eq (gethash "protocol" port) 'null))
                 (setf (gethash "protocol" port) "TCP"))
               (unless (member (gethash "protocol" port) '("TCP" "UDP" "SCTP") :test #'equal)
                 (core-resource-error 422 "Invalid" "Endpoint port protocol is invalid"))
               (let ((number (gethash "port" port)))
                 (unless (or (member number '(nil null)) (typep number '(integer 1 65535)))
                   (core-resource-error 422 "Invalid" "Endpoint port must be in 1..65535")))
               (when (and (gethash "appProtocol" port) (not (eq 'null (gethash "appProtocol" port)))
                          (not (core-qualified-key-p (gethash "appProtocol" port))))
                 (core-resource-error 422 "Invalid" "Endpoint appProtocol must be a qualified name"))))
    (loop for endpoint across (endpointslice-array object "endpoints" 1000)
          do (require-object endpoint "endpoint")
             (when (or (not (nth-value 1 (gethash "conditions" endpoint))) (eq 'null (gethash "conditions" endpoint)))
               (setf (gethash "conditions" endpoint) (core-object)))
             (let ((addresses (endpointslice-array endpoint "addresses" 100)))
               (unless (plusp (length addresses)) (core-resource-error 422 "Invalid" "Endpoint requires addresses"))
               (loop for address across addresses unless (endpointslice-address-p address type)
                     do (core-resource-error 422 "Invalid" "Invalid ~A endpoint address ~S" type address)))
             (dolist (field '("hostname" "nodeName"))
               (let ((value (gethash field endpoint)))
                 (when (and value (not (eq value 'null))
                            (not (if (equal field "hostname") (dns-label-p value) (dns-subdomain-p value))))
                   (core-resource-error 422 "Invalid" "Invalid endpoint ~A" field))))
             (let ((hints (gethash "hints" endpoint)))
               (when (and hints (not (eq hints 'null)))
                 (dolist (field '("forZones" "forNodes"))
                   (let ((seen (make-hash-table :test #'equal)))
                     (loop for hint across (endpointslice-array hints field 8)
                           for value = (gethash "name" (require-object hint "endpoint hint"))
                           do (unless (and (if (equal field "forNodes") (dns-subdomain-p value)
                                               (core-label-name-p value :empty t))
                                           (not (gethash value seen)))
                                (core-resource-error 422 "Invalid" "Endpoint hints require unique valid names"))
                              (setf (gethash value seen) t))))))
             ;; This deprecated v1beta1 topology map is not writable through v1.
             (remhash "deprecatedTopology" endpoint))
    (validate-template-shape object (template-schema "io.k8s.api.discovery.v1.EndpointSlice") "EndpointSlice")
    object))

(defun validate-endpointslice-update (old object)
  "Preserve the address-family identity of an existing EndpointSlice."
  (unless (equal (gethash "addressType" old) (gethash "addressType" object))
    (core-resource-error 422 "Invalid" "EndpointSlice addressType is immutable")))

(defun prepare-endpointslice-write (object old)
  "Own generation: endpoint/port/address-family or label changes advance it; annotations do not."
  (let ((changed (and old
                      (not (equal
                            (endpointslice-canonical-json
                             (core-object "addressType" (gethash "addressType" old) "ports" (gethash "ports" old)
                                          "endpoints" (gethash "endpoints" old) "labels" (gethash "labels" (gethash "metadata" old))))
                            (endpointslice-canonical-json
                             (core-object "addressType" (gethash "addressType" object) "ports" (gethash "ports" object)
                                          "endpoints" (gethash "endpoints" object) "labels" (gethash "labels" (gethash "metadata" object)))))))))
    (setf (gethash "generation" (gethash "metadata" object))
          (if old (+ (gethash "generation" (gethash "metadata" old) 1) (if changed 1 0)) 1)))
  object)
