;;;; SPDX-License-Identifier: MIT
;;;; Recent NetworkPolicy drops as diagnosis evidence (podster-e9a.4).
(require :asdf)
(load (merge-pathnames "load.lisp" *load-truename*))
(in-package #:gr8s-diagnose)

(defun flow-line (&rest pairs) (com.inuoe.jzon:stringify (apply #'object pairs)))

;; The API's lines become a list whose items carry their Pod's namespace; a node's
;; error line and blank lines are not flows.
(let* ((text (format nil "~A~%~%~A~%~A~%"
                     (flow-line "namespace" "shop" "pod" "cart-0" "verdict" "DROPPED")
                     (flow-line "node" "n2" "error" "no collector")
                     (flow-line "namespace" "data" "pod" "db-0" "verdict" "FORWARDED")))
       (items (field (flows-list-from-text text) "items")))
  (assert (= 2 (length items)))
  (assert (equal "shop" (field (aref items 0) "metadata" "namespace"))))

(assert (equal "/apis/gr8s.io/v1/namespaces/shop/flows" (flows-raw-path "shop")))
(assert (equal "/apis/gr8s.io/v1/flows" (flows-raw-path nil)))

(let* ((pod (object "metadata" (object "name" "cart-0" "namespace" "shop" "uid" "u1")))
       (drop (lambda (&rest pairs)
               (apply #'object "namespace" "shop" "pod" "cart-0" "verdict" "DROPPED" "reason" "policy"
                      "direction" "egress" "protocol" "TCP" pairs)))
       (flows (vector (funcall drop "peerNamespace" "data" "peerPod" "db-0" "peerPort" 443
                               "policies" #("all-cart" "deny-egress"))
                      (funcall drop "peerNamespace" "data" "peerPod" "db-0" "peerPort" 443
                               "policies" #("all-cart" "deny-egress"))
                      (funcall drop "direction" "ingress" "peerAddress" "192.0.2.7" "podPort" 80
                               "policies" #("all-cart"))
                      ;; Not this Pod's, not a drop, or not a policy's.
                      (funcall drop "pod" "web-0")
                      (object "namespace" "shop" "pod" "cart-0" "verdict" "FORWARDED")
                      (funcall drop "reason" "spoof")))
       (groups (pod-policy-drops pod "shop" flows)))
  (assert (equal '((("egress" "data/db-0" 443 "TCP" ("all-cart" "deny-egress")) . 2)
                   (("ingress" "192.0.2.7" 80 "TCP" ("all-cart")) . 1))
                 groups))
  (let ((finding (policy-drop-finding pod "shop" (first groups) "f9")))
    (assert (equal "network-policy-drops" (gethash "code" finding)))
    (assert (equal "Pod cart-0: NetworkPolicy dropped 2 recent connections to data/db-0 over TCP on port 443. It is isolated by all-cart, deny-egress, which allow none of this."
                   (gethash "summary" finding)))
    (assert (search "add an egress rule allowing data/db-0 on port 443" (gethash "nextStep" finding)))
    (assert (equal "shop/all-cart, shop/deny-egress" (gethash "detail" finding))))
  (let ((summary (gethash "summary" (policy-drop-finding pod "shop" (second groups) "f9"))))
    (assert (search "from 192.0.2.7" summary))
    (assert (search "isolated by all-cart, which allows none of this." summary)))
  ;; A Pod's report gains a finding for each kind of drop, backed by the flows read.
  (let ((report (object "evidence" (vector (object "id" "e1" "result" "present")) "findings" #()
                        "status" "no-findings")))
    (augment-pod-flows report pod "Pod" "shop"
                       (lambda (kind ns name)
                         (assert (and (equal kind "Flows") (equal ns "shop") (null name)))
                         (values (object "items" flows) :present)))
    (assert (= 2 (length (gethash "findings" report))))
    (assert (equal "findings" (gethash "status" report)))
    (assert (equal "Flows" (field (aref (gethash "evidence" report) 1) "kind"))))
  ;; On a cluster that serves no flows the report is unchanged, and still complete.
  (let ((report (object "evidence" (vector (object "id" "e1" "result" "present")) "findings" #()
                        "status" "no-findings")))
    (augment-pod-flows report pod "Pod" "shop" (lambda (&rest arguments) (declare (ignore arguments)) (values nil :unknown)))
    (assert (zerop (length (gethash "findings" report))))
    (assert (equal "no-findings" (gethash "status" report)))
    (assert (= 1 (length (gethash "evidence" report))))))

(format t "Doctor flow evidence checks passed.~%")
