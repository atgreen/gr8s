;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Remember which DNS name each outside address was the answer for (podster-5hv.8), so a
;;;; flow to 192.0.73.2 can say it went to secure.gravatar.com. The node's DNS server
;;;; forwards its Pods' questions about names outside the cluster through
;;;; DNS-NAME-RECORDING-FORWARDER, which notes each A and AAAA answer under the name the
;;;; Pod asked for -- not the CNAME chain's last link, a CDN's name nobody asked for. An
;;;; address keeps the name it was last given for +DNS-NAME-SECONDS+, much longer than any
;;;; answer is cached, so lookups the cache answers keep their names; the table holds at
;;;; most +DNS-NAME-LIMIT+ addresses, forgetting the stalest first.

(in-package #:gr8s.network)

(defparameter +dns-name-seconds+ (* 6 3600) "How long an address keeps the name it was last given.")
(defparameter +dns-name-limit+ 4096 "The most addresses remembered.")

(defvar *dns-names* (make-hash-table :test #'equal)
  "Address text, as flow events write it -> (name . universal-time it was given).")
(defvar *dns-names-lock* (bt:make-lock "gr8s DNS names"))

(defun dns-answer-address-text (record)
  "RECORD's address as flow events write it, or NIL when it is no A or AAAA record."
  (typecase record
    (0conf:a-record (flow-event-ipv4-text (0conf:a-address record) 0))
    (0conf:aaaa-record (flow-event-ipv6-text (0conf:aaaa-address record) 0))))

(defun note-dns-response (octets &optional (now (get-universal-time)))
  "Remember the addresses the DNS response OCTETS gives for the name it was asked about."
  (let* ((message (0conf:decode-message octets))
         (question (first (0conf:dns-message-questions message))))
    (when question
      (let ((name (string-downcase (string-right-trim "." (0conf:question-name question))))
            (addresses (remove nil (mapcar #'dns-answer-address-text (0conf:dns-message-answers message)))))
        (when (and addresses (plusp (length name)))
          (bt:with-lock-held (*dns-names-lock*)
            (dolist (address addresses)
              (setf (gethash address *dns-names*) (cons name now)))
            (when (> (hash-table-count *dns-names*) +dns-name-limit+)
              (let ((stalest (sort (loop for address being the hash-keys of *dns-names* using (hash-value entry)
                                         collect (cons address (cdr entry)))
                                   #'< :key #'cdr)))
                (loop repeat (- (hash-table-count *dns-names*) +dns-name-limit+)
                      for (address) in stalest
                      do (remhash address *dns-names*))))))))))

(defun dns-name-for-address (address &optional (now (get-universal-time)))
  "The name ADDRESS was last given in answer to one of this node's Pods, or NIL."
  (bt:with-lock-held (*dns-names-lock*)
    (let ((entry (gethash address *dns-names*)))
      (when entry
        (if (< (- now (cdr entry)) +dns-name-seconds+)
            (car entry)
            (progn (remhash address *dns-names*) nil))))))

(defun dns-name-recording-forwarder (forwarder)
  "A cl-dns-proxy forwarder that forwards as FORWARDER does and notes each answer's names.
A response that can't be read is still returned as it came."
  (lambda (packet upstreams timeout)
    (let ((response (funcall forwarder packet upstreams timeout)))
      (when response
        (ignore-errors (note-dns-response response)))
      response)))

(defun start-name-recording-dns-server (&rest arguments)
  "Start cl-dns-proxy's DNS server with forwarders that note the names they answer for."
  (apply #'cl-dns-proxy:start-dns-server
         :udp-forwarder (dns-name-recording-forwarder #'cl-dns-proxy:forward-dns-udp)
         :tcp-forwarder (dns-name-recording-forwarder #'cl-dns-proxy:forward-dns-tcp)
         arguments))
