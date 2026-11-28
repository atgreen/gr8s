;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Policy DNS with synthetic addresses (podster-wv1w.8; the idea is OpenShell's,
;;;; rfc/0005). A Pod whose egress policy names hosts is answered, for each name it may
;;;; resolve, with an address from a reserved range that stands for the name, not
;;;; the name's own. Its connection to that address reaches the node egress proxy,
;;;; which reads the name back from this table and dials one of the real addresses
;;;; the trusted resolver returned. So a connection is admitted by the name the client
;;;; looked up, whatever protocol it speaks, and nothing re-resolves the name between
;;;; the answer and the connect.
;;;;
;;;; A synthetic address names a host for the whole node, not a grant to one Pod: every
;;;; connection is decided by the dialling Pod's policy as it stands, so a Pod that
;;;; guesses an address reaches nothing it couldn't reach by the real one. Addresses
;;;; outlive their mappings' TTLs, which bound only how long real addresses are used,
;;;; because clients cache answers; an address goes to another name only after it has
;;;; been idle long past any cached answer.

(in-package #:gr8s.network)

(defparameter +egress-synthetic-ttl+ 30
  "The most seconds a synthetic answer, and the real addresses behind it, are used
before the name is looked up again.")

(defparameter +egress-synthetic-reuse-grace+ 3600
  "Seconds a synthetic address must sit unused before it may stand for another name.")

(defparameter +egress-refresh-backoff+ 1
  "Seconds after a failed refresh before a connect tries the lookup again.")

(defun egress-synthetic-address-p (address)
  "True when ADDRESS, a dotted IPv4 string, is in the synthetic range."
  (and (stringp address) (not (find #\: address))
       (ignore-errors (network-address-in-cidr-p +egress-synthetic-cidr+ address))))

(defun egress-pinnable-address-p (address)
  "True when ADDRESS may stand behind a synthetic one: a public unicast IPv4 address.
The cluster's own ranges stay under address policy, outside the proxy."
  (and (stringp address) (not (find #\: address))
       (ignore-errors (ipv4-network-octets address))
       (notany (lambda (cidr) (network-address-in-cidr-p cidr address))
               (list* +egress-synthetic-cidr+ "0.0.0.0/8" "224.0.0.0/4" "240.0.0.0/4"
                      +egress-exempt-cidrs+))))

(defstruct (egress-name (:constructor make-egress-name (name address)))
  "One allocation: NAME stands at ADDRESS; ADDRESSES are its pinned real addresses,
used until EXPIRES."
  name address (addresses '()) (expires 0) (last-used 0) (failed-at nil)
  (lock (bt:make-lock "gr8s egress name")))

(defstruct (egress-name-table (:constructor %make-egress-name-table))
  "Synthetic allocations by name and by address. RESOLVE maps a name to (values
addresses ttl rcode); CLOCK gives the time in seconds."
  (lock (bt:make-lock "gr8s egress names"))
  (by-name (make-hash-table :test 'equal))
  (by-address (make-hash-table :test 'equal))
  (next 1) capacity resolve clock)

(defun make-egress-name-table (&key resolve (clock #'get-universal-time) (capacity (- (expt 2 17) 2)))
  "A table handing out up to CAPACITY addresses of the synthetic range, skipping its
first."
  (%make-egress-name-table :resolve resolve :clock clock :capacity capacity))

(defun %egress-synthetic-address (offset)
  (let ((base (ipv4-network-octets (subseq +egress-synthetic-cidr+ 0 (position #\/ +egress-synthetic-cidr+)))))
    (let ((value (+ (reduce (lambda (acc octet) (+ (* acc 256) octet)) base) offset)))
      (format nil "~{~D~^.~}" (loop for shift from 24 downto 0 by 8 collect (ldb (byte 8 shift) value))))))

(defun %egress-canonical-name (name)
  (string-downcase (string-right-trim "." name)))

(defun %egress-allocate (table name now)
  "The entry for NAME, allocating an address when it has none. NIL when the range is
full of addresses a client may still hold. Called with TABLE's lock held."
  (or (gethash name (egress-name-table-by-name table))
      (let ((address
              (if (<= (egress-name-table-next table) (egress-name-table-capacity table))
                  (prog1 (%egress-synthetic-address (egress-name-table-next table))
                    (incf (egress-name-table-next table)))
                  (let ((idle nil))
                    (loop for entry being the hash-values of (egress-name-table-by-name table)
                          when (and (> (- now (egress-name-last-used entry)) +egress-synthetic-reuse-grace+)
                                    (or (null idle) (< (egress-name-last-used entry) (egress-name-last-used idle))))
                            do (setf idle entry))
                    (when idle
                      (remhash (egress-name-name idle) (egress-name-table-by-name table))
                      (egress-name-address idle))))))
        (when address
          (setf (gethash name (egress-name-table-by-name table))
                (setf (gethash address (egress-name-table-by-address table))
                      (make-egress-name name address)))))))

(defun %egress-refresh (table entry now)
  "Look ENTRY's name up again and pin what passes. Returns (values ttl rcode): TTL
when it now has addresses, else NIL and the response code to give. Called with
ENTRY's lock held."
  (multiple-value-bind (addresses ttl rcode)
      (ignore-errors (funcall (egress-name-table-resolve table) (egress-name-name entry)))
    (let ((pinned (remove-if-not #'egress-pinnable-address-p addresses))
          (ttl (min +egress-synthetic-ttl+ (max 1 (or ttl 0)))))
      (cond (pinned
             (setf (egress-name-addresses entry) pinned
                   (egress-name-expires entry) (+ now ttl)
                   (egress-name-failed-at entry) nil)
             (values ttl 0))
            (t
             (setf (egress-name-addresses entry) '()
                   (egress-name-expires entry) 0
                   (egress-name-failed-at entry) now)
             ;; Answers that were all private are refused, not passed through: the
             ;; proxy would otherwise reach them past address policy.
             (values nil (cond (addresses 5) ((eql rcode 3) 3) (t 2))))))))

(defun egress-name-answer (table name)
  "Answer NAME for a synthetic-mode Pod. Returns (values address ttl), or (values NIL
rcode) when it has no public address: 3 for NXDOMAIN, 5 when every address was the
cluster's own, 2 when the lookup failed or no address is free."
  (let* ((name (%egress-canonical-name name))
         (now (funcall (egress-name-table-clock table)))
         (entry (bt:with-lock-held ((egress-name-table-lock table)) (%egress-allocate table name now))))
    (if (null entry)
        (values nil 2)
        (bt:with-lock-held ((egress-name-lock entry))
          (setf (egress-name-last-used entry) now)
          (if (< now (egress-name-expires entry))
              (values (egress-name-address entry) (- (egress-name-expires entry) now))
              (multiple-value-bind (ttl rcode) (%egress-refresh table entry now)
                (if ttl (values (egress-name-address entry) ttl) (values nil rcode))))))))

(defparameter +egress-ask-ttl+ 10
  "Seconds a reserved name's address is good for: brief, so a name the user didn't
allow isn't held long.")

(defun egress-name-reserve (table name)
  "A synthetic address for NAME without looking it up (podster-3zu0). A Pod in ask mode
is answered with one for a name its policy doesn't allow, so the name leaves the node
only once the user allows it, when the proxy resolves it. Returns (values address ttl),
or NIL when no address is free."
  (let* ((name (%egress-canonical-name name))
         (now (funcall (egress-name-table-clock table)))
         (entry (bt:with-lock-held ((egress-name-table-lock table)) (%egress-allocate table name now))))
    (when entry
      (bt:with-lock-held ((egress-name-lock entry))
        (setf (egress-name-last-used entry) now))
      (values (egress-name-address entry) +egress-ask-ttl+))))

(defun egress-name-at (table address)
  "The name synthetic ADDRESS stands for, without looking it up; NIL when none."
  (let ((entry (bt:with-lock-held ((egress-name-table-lock table))
                 (gethash address (egress-name-table-by-address table)))))
    (and entry (egress-name-name entry))))

(defun egress-name-for-connect (table address)
  "The name synthetic ADDRESS stands for and its pinned real addresses, refreshing
an expired mapping first: (values name addresses), or NIL when ADDRESS names nothing
or its name has no current address. Expired addresses are never returned."
  (let* ((now (funcall (egress-name-table-clock table)))
         (entry (bt:with-lock-held ((egress-name-table-lock table))
                  (gethash address (egress-name-table-by-address table)))))
    (when entry
      (bt:with-lock-held ((egress-name-lock entry))
        ;; A reallocated address no longer stands for this entry.
        (unless (eq entry (bt:with-lock-held ((egress-name-table-lock table))
                            (gethash (egress-name-name entry) (egress-name-table-by-name table))))
          (return-from egress-name-for-connect nil))
        (setf (egress-name-last-used entry) now)
        (when (or (< now (egress-name-expires entry))
                  (and (not (and (egress-name-failed-at entry)
                                 (< (- now (egress-name-failed-at entry)) +egress-refresh-backoff+)))
                       (%egress-refresh table entry now)))
          (values (egress-name-name entry) (egress-name-addresses entry)))))))

(defun pod-egress-synthetic-p (pod cnps)
  "True when POD is a gr8 sandbox or has a hostname allowlist, an egress Accept rule
naming domains among CNPS: its DNS is answered with synthetic addresses, for the names
allowed and no others. Other Pods, including those a SecurityProfile alone captures,
see real answers."
  (or (gr8-sandbox-pod-p pod) (and (pod-egress-allowed-domains pod cnps) t)))

(defun %egress-synthetic-route-message ()
  "The rtmsg for local 198.18.0.0/15 dev lo in the local table."
  (netlink-octets
   ;; family AF_INET, dst_len, src_len, tos, table RT_TABLE_LOCAL, RTPROT_STATIC,
   ;; RT_SCOPE_HOST, RTN_LOCAL; then rtm_flags.
   (vector 2 (parse-integer +egress-synthetic-cidr+ :start (1+ (position #\/ +egress-synthetic-cidr+)))
           0 0 255 4 254 2)
   (netlink-integer 0 4)
   (netlink-attribute 1 (ipv4-network-octets (subseq +egress-synthetic-cidr+ 0 (position #\/ +egress-synthetic-cidr+))))
   (netlink-attribute 4 (netlink-integer (cni-interface-index "lo") 4))))

(defun ensure-egress-synthetic-route ()
  "Deliver the synthetic range on this node, as `ip route add local 198.18.0.0/15 dev lo`
does, so a Pod's connection to a synthetic address reaches the egress proxy's sk_lookup
steering. Idempotent."
  (call-rtnetlink 24 #x500 (%egress-synthetic-route-message))) ; RTM_NEWROUTE, CREATE | REPLACE

(defun remove-egress-synthetic-route ()
  "Withdraw the synthetic range's local route. Best-effort."
  (ignore-errors (call-rtnetlink 25 0 (%egress-synthetic-route-message)))) ; RTM_DELROUTE
