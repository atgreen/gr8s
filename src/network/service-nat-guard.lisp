;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Complete, standalone v2 TC graph. CNI/agent publication is still gated on
;;;; inventory/readiness, migration and pinned-map validation integration.
(in-package #:gr8s.network)

(defparameter *service-nat-stage-map-form*
  '(whistler::defmap whistler::gr8s-nat-stages :type :prog-array
     :key-size 4 :value-size 4 :max-entries 16))

(defparameter *service-nat-stage-programs*
  '((0 . "gr8s_nat_generation") (1 . "gr8s_nat_select")
    (2 . "gr8s_v2_eg_policy") (3 . "gr8s_nat_commit")
    (4 . "gr8s_nat_deliver") (5 . "gr8s_nat_prepare")
    (6 . "gr8s_v2_in_policy") (7 . "gr8s_nat_restore")))

(defun service-nat-tail-form (index)
  `(progn (whistler::tail-call whistler::gr8s-nat-stages ,index)
          whistler::TC_ACT_SHOT))

(defun service-nat-stage-continue (form index)
  "Every successful path, including non-Service/other-family paths, must continue.
Missing continuations fail closed. This runs after NAT macros have expanded."
  (subst (service-nat-tail-form index) 'whistler::TC_ACT_OK form))

(defun service-nat-root-body (body)
  `(let ((whistler::dropped-packets (whistler::map-lookup whistler::traffic-stats 2))
         (whistler::dropped-bytes (whistler::map-lookup whistler::traffic-stats 3))
         (whistler::policy-drops (whistler::map-lookup whistler::traffic-stats 6))
         (whistler::unsupported (whistler::map-lookup whistler::traffic-stats 5))
         (whistler::local-identity (whistler::map-lookup whistler::endpoint-identity 0)))
     (whistler::nat-clear-context)
     (whistler::nat-policy-local whistler::local-identity)
     ;; Fragments must not leave hidden direct tuples behind a complete-history
     ;; claim. Reassembly/fragment ownership is not implemented in this profile.
     (let ((whistler::data (whistler::tc-data)) (whistler::data-end (whistler::tc-data-end)))
       (when (> (+ whistler::data 14) whistler::data-end) (return whistler::TC_ACT_SHOT))
       (when (= (whistler::eth-type whistler::data) #x0800)
         (when (> (+ whistler::data 34) whistler::data-end) (return whistler::TC_ACT_SHOT))
         (when (and (or (= (whistler::load whistler::u8 whistler::data 23) 6)
                        (= (whistler::load whistler::u8 whistler::data 23) 17))
                    (/= (logand (whistler::ntohs (whistler::load whistler::u16 whistler::data 20)) #x3fff) 0))
           (whistler::add-pod-counter whistler::dropped-packets 1)
           (whistler::add-pod-counter whistler::dropped-bytes (whistler::ctx whistler::u32 0))
           (whistler::add-pod-counter whistler::unsupported 1)
           (return whistler::TC_ACT_SHOT))))
     ,body))

(defun service-nat-egress-root-form ()
  (let ((anchor '(when (/= (whistler::ntohl (whistler::ipv4-src-addr whistler::ip))
                           (whistler::load whistler::u32 whistler::identity 0))
                   (whistler::drop-pod-packet :spoof)))
        (count 0))
    (labels ((walk (form)
               (cond
                 ((and (consp form) (eq (car form) 'let)
                       (position anchor (cddr form) :test #'equal))
                  (incf count)
                  `(let ,(second form)
                     ,@(subseq (cddr form) 0 (1+ (position anchor (cddr form) :test #'equal)))
                     (return ,(service-nat-tail-form 0))))
                 ((and (consp form) (eq (car form) 'cond)
                       (equal (caadr form) '(= whistler::protocol #x0800)))
                  `(cond ,(walk (second form)) (t (return ,(service-nat-tail-form 2)))))
                 ((consp form) (mapcar #'walk form))
                 (t form))))
      (let ((root (walk (copy-tree (first *egress-guard-program-forms*)))))
        (unless (= count 1) (error "Canonical source validation boundary changed"))
        (setf (fourth root) (service-nat-root-body (fourth root)))
        (expand-service-nat-form root)))))

(in-package #:whistler)

(defun gr8s.network::service-nat-delivery-form ()
  '(defprog gr8s-nat-deliver (:type :tc :section "classifier" :license "GPL")
     (let ((identity (map-lookup endpoint-identity 0))
           (data u64 (tc-data)) (data-end u64 (tc-data-end)))
       (when (= identity 0) (return TC_ACT_SHOT))
       (when (= (load u32 identity 12) 2) (return TC_ACT_OK))
       (when (/= (load u32 identity 12) 1) (return TC_ACT_SHOT))
       (when (> (+ data 14) data-end) (return TC_ACT_SHOT))
       (when (/= (eth-type data) #x0800) (return TC_ACT_OK))
       (when (> (+ data 34) data-end) (return TC_ACT_SHOT))
       (when (and (or (= (load u8 data 23) 6) (= (load u8 data 23) 17))
                  (= (logand (load u8 data 14) 15) 5)
                  (= (ntohl (load u32 data 30)) #xa9fe0101)
                  (<= (+ data 42) data-end) (= (ntohs (load u16 data 36)) 53))
         (store u32 data 0 0) (store u16 data 4 0)
         (return (redirect 1 1)))
       (let ((destination (make-local-pod-key)))
         (setf (local-pod-key-prefixlen destination) 32
               (local-pod-key-addr destination) (load u32 data 30))
         (when (/= (map-lookup-ptr host-redirect-v4 (+ destination 4)) 0)
           (when (> (+ data 14) data-end) (return TC_ACT_SHOT))
           (store u32 data 0 0) (store u16 data 4 0)
           (return (redirect 1 1)))
         (let ((endpoint (map-lookup-ptr local-pod-v4 destination)))
           (when (/= endpoint 0)
             (when (> (+ data 14) data-end) (return TC_ACT_SHOT))
             (store u32 data 0 (load u32 endpoint 4))
             (store u16 data 4 (load u16 endpoint 8))
             (store u32 data 6 (load u32 endpoint 10))
             (store u16 data 10 (load u16 endpoint 14))
             (return (redirect (load u32 endpoint 0) 0)))))
       TC_ACT_OK)))

(in-package #:gr8s.network)

(defun service-nat-guard-map-forms ()
  (remove-duplicates
   (append (service-nat-policy-map-forms)
           (subseq (service-packet-map-forms) 0 3)
           (list (find 'whistler::gr8s-pkt-affinity *service-packet-extra-map-forms* :key #'second))
           *service-nat-map-forms* (list *service-nat-stage-map-form*))
   :key #'second :test #'eq :from-end t))

(defun service-nat-guard-forms ()
  (let* ((policy (service-nat-policy-forms))
         (egress (copy-tree (second policy)))
         (ingress (copy-tree (third policy))))
    (setf (second egress) 'whistler::gr8s-v2-eg-policy
          (second ingress) 'whistler::gr8s-v2-in-policy)
    (append
     *service-packet-struct-forms* *service-nat-struct-forms*
     (list *service-nat-policy-key-form*
           (service-nat-egress-root-form)
           (expand-service-nat-form
            `(whistler::defprog whistler::gr8s-ingress-guard
                 (:type :tc :section "classifier" :license "GPL")
               ,(service-nat-root-body (service-nat-tail-form 5))))
           (service-nat-stage-continue egress 3)
           (service-nat-stage-continue ingress 7))
     (loop for (name body next full-parser) in
            (list (list 'whistler::gr8s-nat-generation (service-nat-generation-form) 1 t)
                  (list 'whistler::gr8s-nat-select (service-nat-select-form) 2 nil)
                  (list 'whistler::gr8s-nat-commit (service-nat-commit-form) 4 t)
                  (list 'whistler::gr8s-nat-prepare (service-nat-prepare-form) 6 nil)
                  (list 'whistler::gr8s-nat-restore (service-nat-restore-form) nil t))
           for form = (expand-service-nat-form
                       (if full-parser (service-packet-program-form name body)
                           (service-nat-program-form name body)))
           collect (if next (service-nat-stage-continue form next) form))
     (list (service-nat-delivery-form)
           (expand-service-nat-form (service-nat-gc-program-form))))))

(defun compile-service-nat-guard ()
  "Standalone v2 roots and trusted tail-call graph. Not yet installed by CNI."
  (compile-whistler-program (service-nat-guard-map-forms) (service-nat-guard-forms)))
